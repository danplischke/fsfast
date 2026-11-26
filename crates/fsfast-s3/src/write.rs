//! Writes: single `PutObject` for small objects, concurrent multipart
//! uploads (`fsfast_engine::PartUploader`) for large ones, `If-None-Match:
//! *` for create-only writes, and s3fs's append (copy the existing object
//! as the first part(s) of a multipart upload).

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use fsfast_core::{Error, ErrorKind, Result, WriteHandle, WriteMode, WriteOptions};
use fsfast_engine::upload::{PartOutcome, PartSink, PartUploader, UploadConfig, UploadResult};
use fsfast_http_transport::Method;
use fsfast_http_transport::header::{HeaderMap, HeaderName, HeaderValue};
use futures::{StreamExt, stream};
use tokio::sync::OnceCell;

use crate::client::Call;
use crate::encode::uri_encode;
use crate::info::ObjectMeta;
use crate::params::{Op, Params};
use crate::path::split_path;
use crate::xml::{complete_multipart_body, parse_result_etag, parse_upload_id};
use crate::{S3FileSystem, State};

/// Largest object a single `PutObject` / part may carry (5 GiB).
pub(crate) const MAX_PART: u64 = 5 << 30;
/// Smallest part except the last (5 MiB).
pub(crate) const MIN_PART: u64 = 5 << 20;
/// Most parts in one upload.
pub(crate) const MAX_PARTS: u32 = 10_000;

/// Headers of an existing object that s3fs carries over when appending
/// (`_PRESERVE_KWARGS`).
const PRESERVED_HEADERS: &[&str] = &[
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-type",
    "expires",
    "x-amz-website-redirect-location",
    "x-amz-server-side-encryption",
    "x-amz-server-side-encryption-customer-algorithm",
    "x-amz-server-side-encryption-aws-kms-key-id",
    "x-amz-server-side-encryption-bucket-key-enabled",
    "x-amz-storage-class",
    "x-amz-object-lock-mode",
    "x-amz-object-lock-retain-until-date",
    "x-amz-object-lock-legal-hold",
];

/// Object headers (content type, user metadata, ...) of an existing object
/// to apply to a new version of it.
pub(crate) fn preserved_headers(meta: &ObjectMeta) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (name, value) in &meta.headers {
        let n = name.as_str();
        if PRESERVED_HEADERS.contains(&n) || n.starts_with("x-amz-meta-") {
            h.append(name.clone(), value.clone());
        }
    }
    h
}

/// Headers from `WriteOptions` (`content_type`, `metadata`).
fn option_headers(opts: &WriteOptions) -> Result<HeaderMap> {
    let mut h = HeaderMap::new();
    if let Some(ct) = &opts.content_type {
        h.insert(
            fsfast_http_transport::header::CONTENT_TYPE,
            HeaderValue::from_str(ct)
                .map_err(|_| Error::invalid_input(format!("invalid content type {ct:?}")))?,
        );
    }
    for (k, v) in &opts.metadata {
        let name =
            HeaderName::from_bytes(format!("x-amz-meta-{}", k.to_ascii_lowercase()).as_bytes())
                .map_err(|_| Error::invalid_input(format!("invalid metadata key {k:?}")))?;
        let value = HeaderValue::from_str(v)
            .map_err(|_| Error::invalid_input(format!("invalid metadata value for {k:?}")))?;
        h.insert(name, value);
    }
    Ok(h)
}

fn merge_headers(base: &mut HeaderMap, top: &HeaderMap) {
    for name in top.keys() {
        base.remove(name);
    }
    for (name, value) in top {
        base.append(name.clone(), value.clone());
    }
}

/// The destination of a multipart upload: creates it on the first part and
/// uploads parts (numbered after any copied parts of an append).
#[derive(Debug)]
pub(crate) struct S3PartSink {
    st: Arc<State>,
    bucket: String,
    key: String,
    path: String,
    /// Headers of `CreateMultipartUpload` (content type, metadata,
    /// preserved headers of an appended object).
    create_headers: HeaderMap,
    extra: Option<Params>,
    upload_id: OnceCell<String>,
    /// Part numbers already taken by copied parts (appends).
    part_offset: u32,
}

impl S3PartSink {
    async fn ensure_upload(&self) -> Result<&str> {
        self.upload_id
            .get_or_try_init(|| async {
                let mut call = Call::new(Op::CreateMultipartUpload, Method::POST, &self.path)
                    .bucket(&self.bucket)
                    .key(&self.key)
                    .query("uploads", "")
                    .extra(self.extra.as_ref())
                    // An orphaned upload from a lost response is harmless;
                    // botocore retries this too.
                    .retry_safe(true);
                call.headers = self.create_headers.clone();
                self.st
                    .client
                    .execute(call, |resp| async move {
                        let body = resp.bytes().await?;
                        parse_upload_id(&body)
                    })
                    .await
            })
            .await
            .map(String::as_str)
    }

    async fn upload_bytes(&self, part_number: u32, data: Bytes) -> Result<PartOutcome> {
        let upload_id = self.ensure_upload().await?.to_owned();
        let call = Call::new(Op::UploadPart, Method::PUT, &self.path)
            .bucket(&self.bucket)
            .key(&self.key)
            .query("partNumber", part_number.to_string())
            .query("uploadId", upload_id)
            .extra(self.extra.as_ref())
            .body(data);
        self.st
            .client
            .execute(call, |resp| async move {
                let etag = resp
                    .etag()
                    .map(str::to_owned)
                    .ok_or_else(|| Error::protocol("UploadPart response without ETag"))?;
                Ok(PartOutcome {
                    etag,
                    checksum: None,
                })
            })
            .await
    }

    /// `UploadPartCopy` of bytes `range` (inclusive end) of `source`.
    pub(crate) async fn copy_part(
        &self,
        part_number: u32,
        source: &str,
        range: Option<(u64, u64)>,
        source_headers: &HeaderMap,
    ) -> Result<String> {
        let upload_id = self.ensure_upload().await?.to_owned();
        let mut call = Call::new(Op::UploadPartCopy, Method::PUT, &self.path)
            .bucket(&self.bucket)
            .key(&self.key)
            .query("partNumber", part_number.to_string())
            .query("uploadId", upload_id)
            .extra(self.extra.as_ref())
            .header("x-amz-copy-source", source)?;
        if let Some((a, b)) = range {
            call = call.header("x-amz-copy-source-range", &format!("bytes={a}-{b}"))?;
        }
        merge_headers(&mut call.headers, source_headers);
        let path = self.path.clone();
        self.st
            .client
            .execute(call, |resp| {
                let path = path.clone();
                async move {
                    let status = resp.status().as_u16();
                    let body = resp.bytes().await?;
                    match parse_result_etag(&body) {
                        Ok(Some(etag)) => Ok(etag),
                        Ok(None) => Err(Error::protocol("UploadPartCopy result without ETag")),
                        Err(doc) => Err(crate::error::response_error(status, &doc, &path)),
                    }
                }
            })
            .await
    }

    pub(crate) async fn complete(&self, parts: &[(u32, String)], create_only: bool) -> Result<()> {
        let upload_id = self
            .upload_id
            .get()
            .ok_or_else(|| Error::new(ErrorKind::Other, "no multipart upload to complete"))?
            .clone();
        let body = complete_multipart_body(parts.iter().map(|(n, e)| (*n, e.as_str())));
        let mut call = Call::new(Op::CompleteMultipartUpload, Method::POST, &self.path)
            .bucket(&self.bucket)
            .key(&self.key)
            .query("uploadId", upload_id)
            .extra(self.extra.as_ref())
            .header("content-type", "application/xml")?
            .body(Bytes::from(body))
            .retry_safe(true);
        if create_only {
            call = call.header("if-none-match", "*")?;
        }
        let path = self.path.clone();
        self.st
            .client
            .execute(call, |resp| {
                let path = path.clone();
                async move {
                    let status = resp.status().as_u16();
                    // The result (or an error) can follow a 200 status after
                    // whitespace keep-alives.
                    let body = resp.bytes().await?;
                    match parse_result_etag(&body) {
                        Ok(_) => Ok(()),
                        Err(doc) => Err(crate::error::response_error(status, &doc, &path)),
                    }
                }
            })
            .await
            .map_err(|e| create_only_error(e, create_only, &self.path))
    }

    pub(crate) async fn abort(&self) -> Result<()> {
        let Some(upload_id) = self.upload_id.get().cloned() else {
            return Ok(());
        };
        let call = Call::new(Op::AbortMultipartUpload, Method::DELETE, &self.path)
            .bucket(&self.bucket)
            .key(&self.key)
            .query("uploadId", upload_id)
            .extra(self.extra.as_ref());
        match self.st.client.execute(call, |_| async { Ok(()) }).await {
            Ok(()) => Ok(()),
            // Already gone (completed elsewhere, expired): nothing to clean.
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[async_trait]
impl PartSink for S3PartSink {
    type Outcome = PartOutcome;

    async fn start(&self) -> Result<()> {
        self.ensure_upload().await.map(|_| ())
    }

    async fn upload_part(&self, part_number: u32, data: Bytes) -> Result<PartOutcome> {
        self.upload_bytes(part_number + self.part_offset, data)
            .await
    }
}

/// Fields of an [`S3PartSink`] for uploads without copied parts.
pub(crate) struct S3PartSinkBuilder {
    pub st: Arc<State>,
    pub bucket: String,
    pub key: String,
    pub path: String,
    pub create_headers: HeaderMap,
    pub extra: Option<Params>,
}

impl S3PartSinkBuilder {
    pub(crate) fn build(self) -> S3PartSink {
        S3PartSink {
            st: self.st,
            bucket: self.bucket,
            key: self.key,
            path: self.path,
            create_headers: self.create_headers,
            extra: self.extra,
            upload_id: OnceCell::new(),
            part_offset: 0,
        }
    }
}

/// A 412 on a create-only write means the object exists.
fn create_only_error(e: Error, create_only: bool, path: &str) -> Error {
    if create_only && e.kind() == ErrorKind::PreconditionFailed {
        Error::already_exists(path)
            .with_detail(fsfast_core::Detail::Http(412))
            .with_detail(fsfast_core::Detail::Code("PreconditionFailed".into()))
    } else {
        e
    }
}

/// A source object copied into the first parts of an append.
#[derive(Debug, Clone)]
struct AppendSource {
    copy_source: String,
    size: u64,
    parts: u32,
}

/// The copy-source parts of an object of `size` bytes: as few parts as
/// possible, each at most 5 GiB.
fn copy_ranges(size: u64, parts: u32) -> Vec<(u64, u64)> {
    let n = u64::from(parts.max(1));
    let part = size.div_ceil(n);
    (0..n)
        .map(|i| (i * part, ((i + 1) * part).min(size) - 1))
        .filter(|(a, b)| a <= b)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandleState {
    Open,
    Closed,
    Aborted,
}

/// An object being written. Data becomes visible on [`WriteHandle::close`];
/// [`WriteHandle::abort`] (or dropping the handle unclosed) aborts the
/// multipart upload.
#[derive(Debug)]
pub struct S3WriteHandle {
    sink: Arc<S3PartSink>,
    uploader: Option<PartUploader<S3PartSink>>,
    mode: WriteMode,
    /// Headers of a single `PutObject`.
    put_headers: HeaderMap,
    append: Option<AppendSource>,
    /// Copy-source headers (SSE-C of the source).
    source_headers: HeaderMap,
    /// Bytes accepted from the caller.
    written: u64,
    state: HandleState,
}

impl S3WriteHandle {
    async fn put_single(&self, data: Bytes) -> Result<()> {
        let s = &self.sink;
        let create_only = self.mode == WriteMode::CreateNew;
        let mut call = Call::new(Op::PutObject, Method::PUT, &s.path)
            .bucket(&s.bucket)
            .key(&s.key)
            .extra(s.extra.as_ref())
            .body(data);
        call.headers = self.put_headers.clone();
        if create_only {
            call = call.header("if-none-match", "*")?;
        }
        s.st.client
            .execute(call, |_resp| async { Ok(()) })
            .await
            .map_err(|e| create_only_error(e, create_only, &s.path))
    }

    async fn finish(&mut self) -> Result<()> {
        let uploader = self
            .uploader
            .take()
            .ok_or_else(|| Error::new(ErrorKind::Other, "write handle already finished"))?;
        let result = uploader.finish().await?;
        let create_only = self.mode == WriteMode::CreateNew;
        let (data_parts, single) = match result {
            UploadResult::Single(data) if self.append.is_none() => {
                return self.put_single(data).await;
            }
            UploadResult::Single(data) => (Vec::new(), Some(data)),
            UploadResult::Multipart(parts) => (parts, None),
        };
        let mut parts: Vec<(u32, String)> = Vec::new();
        if let Some(src) = &self.append {
            self.sink.ensure_upload().await?;
            let sink = &self.sink;
            let headers = &self.source_headers;
            let ranges = copy_ranges(src.size, src.parts);
            let single_range = ranges.len() == 1;
            let copied: Vec<Result<(u32, String)>> =
                stream::iter(ranges.into_iter().enumerate().map(|(i, r)| async move {
                    let n = i as u32 + 1;
                    let range = if single_range { None } else { Some(r) };
                    sink.copy_part(n, &src.copy_source, range, headers)
                        .await
                        .map(|e| (n, e))
                }))
                .buffer_unordered(4)
                .collect()
                .await;
            for c in copied {
                parts.push(c?);
            }
            if let Some(data) = single
                && !data.is_empty()
            {
                let n = src.parts + 1;
                let out = self.sink.upload_bytes(n, data).await?;
                parts.push((n, out.etag));
            }
        }
        parts.extend(
            data_parts
                .into_iter()
                .map(|p| (p.part_number + self.sink.part_offset, p.outcome.etag)),
        );
        parts.sort_by_key(|p| p.0);
        self.sink.complete(&parts, create_only).await
    }
}

#[async_trait]
impl WriteHandle for S3WriteHandle {
    async fn write(&mut self, data: Bytes) -> Result<()> {
        if self.state != HandleState::Open {
            return Err(Error::invalid_input("write to a closed file"));
        }
        let n = data.len() as u64;
        match self.uploader.as_mut() {
            Some(u) => {
                u.write(data).await?;
                self.written += n;
                Ok(())
            }
            None => Err(Error::invalid_input("write to a closed file")),
        }
    }

    async fn close(&mut self) -> Result<()> {
        match self.state {
            HandleState::Closed => return Ok(()),
            HandleState::Aborted => return Err(Error::invalid_input("close of an aborted file")),
            HandleState::Open => {}
        }
        let res = self.finish().await;
        match res {
            Ok(()) => {
                self.state = HandleState::Closed;
                Ok(())
            }
            Err(e) => {
                self.state = HandleState::Aborted;
                if let Err(a) = self.sink.abort().await {
                    tracing::warn!(path = %self.sink.path, error = %a, "aborting the multipart upload failed");
                }
                Err(e)
            }
        }
    }

    async fn abort(&mut self) -> Result<()> {
        if self.state != HandleState::Open {
            return Ok(());
        }
        self.state = HandleState::Aborted;
        if let Some(u) = self.uploader.take() {
            u.abort().await;
        }
        self.sink.abort().await
    }

    fn bytes_written(&self) -> u64 {
        self.written
    }
}

impl Drop for S3WriteHandle {
    fn drop(&mut self) {
        if self.state == HandleState::Open && self.sink.upload_id.get().is_some() {
            // Neither closed nor aborted: do not leave an incomplete upload
            // (it is billed until a lifecycle rule removes it).
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                let sink = self.sink.clone();
                let uploader = self.uploader.take();
                rt.spawn(async move {
                    if let Some(u) = uploader {
                        u.abort().await;
                    }
                    let _ = sink.abort().await;
                });
            }
        }
    }
}

impl S3FileSystem {
    fn write_params(&self, opts: &WriteOptions) -> Result<Option<Params>> {
        if opts.extra.is_empty() {
            return Ok(None);
        }
        Params::from_map(&opts.extra, "write options").map(Some)
    }

    fn upload_config(
        &self,
        st: &State,
        opts: &WriteOptions,
        expected: Option<u64>,
    ) -> UploadConfig {
        let o = &self.inner.opts;
        let part = opts
            .block_size
            .filter(|b| *b > 0)
            .unwrap_or(o.part_size)
            .clamp(MIN_PART as usize, MAX_PART as usize);
        UploadConfig {
            part_size: part,
            min_part_size: MIN_PART as usize,
            max_part_size: MAX_PART as usize,
            max_parts: MAX_PARTS,
            concurrency: o.max_concurrency,
            // `fixed_upload_size` (R2): every part the same size. Declaring
            // the largest object 10,000 such parts can hold keeps the part
            // sizer from growing parts.
            expected_size: if o.fixed_upload_size {
                Some(part as u64 * u64::from(MAX_PARTS))
            } else {
                expected
            },
            budget: Some(st.budget.clone()),
        }
    }

    /// Verify (once per filesystem) that the server enforces `If-None-Match:
    /// *`, with a probe object next to `key`: written, written again
    /// conditionally (must fail with 412), deleted.
    async fn ensure_conditional_writes(&self, st: &State, bucket: &str, key: &str) -> Result<()> {
        if !self.inner.opts.probe_conditional_writes {
            return Ok(());
        }
        let supported = self
            .inner
            .conditional_writes
            .get_or_try_init(|| async {
                match self.probe_conditional_writes(st, bucket, key).await {
                    Ok(v) => Ok(v),
                    Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                        // Not allowed to write the probe: trust the server.
                        tracing::debug!(error = %e, "conditional-write probe not permitted; assuming support");
                        Ok(true)
                    }
                    Err(e) => Err(e),
                }
            })
            .await?;
        if *supported {
            Ok(())
        } else {
            Err(Error::unsupported(
                "create-only writes (mode 'xb'): this S3 server does not enforce If-None-Match",
            ))
        }
    }

    async fn probe_conditional_writes(&self, st: &State, bucket: &str, key: &str) -> Result<bool> {
        let dir = match key.rfind('/') {
            Some(i) => &key[..=i],
            None => "",
        };
        let probe = format!(
            "{dir}.fsfast-conditional-write-probe-{:016x}",
            fastrand_u64()
        );
        let path = format!("{bucket}/{probe}");
        let put = |conditional: bool| {
            let path = path.clone();
            let probe = probe.clone();
            async move {
                let mut call = Call::new(Op::PutObject, Method::PUT, &path)
                    .bucket(bucket)
                    .key(&probe)
                    .body(Bytes::new())
                    .allow(412)
                    .allow(501);
                if conditional {
                    call = call.header("if-none-match", "*")?;
                }
                st.client
                    .execute(call, |resp| async move {
                        Ok((
                            resp.status().as_u16(),
                            resp.header_str("x-amz-version-id").map(str::to_owned),
                        ))
                    })
                    .await
            }
        };
        let (_, v1) = put(false).await?;
        let second = put(true).await;
        let mut versions = vec![v1];
        let supported = match &second {
            Ok((412, _)) => true,
            Ok((501, _)) => {
                tracing::warn!("S3 server rejects If-None-Match: * (501)");
                false
            }
            Ok((status, v2)) => {
                versions.push(v2.clone());
                tracing::warn!(
                    status,
                    "S3 server ignored If-None-Match: *; create-only writes are not atomic there"
                );
                false
            }
            // The server refuses the header itself. Any other failure (a
            // transient error after retries) proves nothing: it is returned
            // below and the probe runs again next time.
            Err(e)
                if e.kind() == ErrorKind::Unsupported
                    || matches!(
                        crate::error::error_code(e),
                        Some(
                            "NotImplemented"
                                | "InvalidArgument"
                                | "InvalidRequest"
                                | "InvalidHeader"
                        )
                    ) =>
            {
                tracing::warn!(error = %e, "S3 server rejected If-None-Match: *");
                false
            }
            Err(_) => true,
        };
        for v in versions {
            let mut call = Call::new(Op::DeleteObject, Method::DELETE, &path)
                .bucket(bucket)
                .key(&probe);
            if let Some(v) = v.filter(|v| v != "null") {
                call = call.query("versionId", v);
            }
            if let Err(e) = st.client.execute(call, |_| async { Ok(()) }).await {
                tracing::warn!(path = %path, error = %e, "could not delete the conditional-write probe object");
            }
        }
        if let Err(e) = second
            && supported
        {
            return Err(e);
        }
        Ok(supported)
    }

    pub(crate) async fn open_write_impl(
        &self,
        path: &str,
        opts: &WriteOptions,
    ) -> Result<S3WriteHandle> {
        self.open_writer(path, opts, None).await
    }

    /// A write handle; `expected` (the total size, when known) lets the part
    /// sizer pick parts that fit the 10,000-part limit.
    async fn open_writer(
        &self,
        path: &str,
        opts: &WriteOptions,
        expected: Option<u64>,
    ) -> Result<S3WriteHandle> {
        let sp = split_path(path, self.inner.opts.version_aware);
        if sp.key.is_empty() {
            return Err(Error::invalid_input(format!(
                "Attempt to open non key-like path: {path}"
            )));
        }
        let st = self.state().await?;
        let name = sp.full();
        let extra = self.write_params(opts)?;
        if opts.mode == WriteMode::CreateNew {
            self.ensure_conditional_writes(&st, &sp.bucket, &sp.key)
                .await?;
            // Fail fast at open, as local files do (and fsspec's abstract
            // `test_open_exclusive` expects), instead of after uploading
            // everything; the commit stays conditional (If-None-Match), so
            // a writer racing in after this check still loses.
            match self
                .head_object(&st, &sp.bucket, &sp.key, None, extra.as_ref(), &name)
                .await
            {
                Ok(_) => return Err(Error::already_exists(name.clone())),
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        let mut headers = option_headers(opts)?;
        let mut append = None;
        let mut prefix: Option<Bytes> = None;
        let mut source_headers = HeaderMap::new();
        if opts.mode == WriteMode::Append {
            match self
                .head_object(&st, &sp.bucket, &sp.key, None, extra.as_ref(), &name)
                .await
            {
                Ok(meta) => {
                    let mut preserved = preserved_headers(&meta);
                    merge_headers(&mut preserved, &headers);
                    headers = preserved;
                    source_headers = self.copy_source_sse_headers(extra.as_ref());
                    if meta.size < MIN_PART {
                        // Too small to be a part: download and rewrite it.
                        // (With the call's parameters: an SSE-C key or
                        // RequestPayer given per call applies to the GET
                        // as it did to the HEAD.)
                        prefix = Some(
                            self.cat_file_with(&name, fsfast_core::ByteRange::Full, extra.as_ref())
                                .await?,
                        );
                    } else {
                        // The copied part(s) must be the version this HEAD
                        // measured (see `cp_file`).
                        if let Some(etag) = meta.etag.as_deref().filter(|e| !e.is_empty())
                            && let Ok(v) = HeaderValue::from_str(etag)
                        {
                            source_headers
                                .insert(HeaderName::from_static("x-amz-copy-source-if-match"), v);
                        }
                        append = Some(AppendSource {
                            copy_source: copy_source(&sp.bucket, &sp.key, None),
                            size: meta.size,
                            parts: u32::try_from(meta.size.div_ceil(MAX_PART)).unwrap_or(u32::MAX),
                        });
                    }
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        let part_offset = append.as_ref().map_or(0, |a| a.parts);
        let sink = Arc::new(S3PartSink {
            st: st.clone(),
            bucket: sp.bucket.clone(),
            key: sp.key.clone(),
            path: name,
            create_headers: headers.clone(),
            extra,
            upload_id: OnceCell::new(),
            part_offset,
        });
        let mut cfg = self.upload_config(&st, opts, expected);
        cfg.max_parts = MAX_PARTS.saturating_sub(part_offset).max(1);
        let mut uploader = PartUploader::new(sink.clone(), cfg)?;
        if let Some(p) = prefix
            && !p.is_empty()
        {
            uploader.write(p).await?;
        }
        Ok(S3WriteHandle {
            sink,
            uploader: Some(uploader),
            mode: opts.mode,
            put_headers: headers,
            append,
            source_headers,
            written: 0,
            state: HandleState::Open,
        })
    }

    pub(crate) async fn pipe_file_impl(
        &self,
        path: &str,
        data: Bytes,
        opts: &WriteOptions,
    ) -> Result<()> {
        if opts.mode == WriteMode::Append {
            let mut w = self.open_write_impl(path, opts).await?;
            let res = async {
                if !data.is_empty() {
                    w.write(data).await?;
                }
                w.close().await
            }
            .await;
            if res.is_err() {
                let _ = w.abort().await;
            }
            return res;
        }
        let sp = split_path(path, self.inner.opts.version_aware);
        if sp.key.is_empty() {
            return Err(Error::invalid_input(format!(
                "Attempt to write non key-like path: {path}"
            )));
        }
        let st = self.state().await?;
        let cfg = self.upload_config(&st, opts, Some(data.len() as u64));
        if data.len() <= cfg.part_size {
            // Small objects: one PutObject, no handle machinery.
            let name = sp.full();
            if opts.mode == WriteMode::CreateNew {
                self.ensure_conditional_writes(&st, &sp.bucket, &sp.key)
                    .await?;
            }
            let extra = self.write_params(opts)?;
            let create_only = opts.mode == WriteMode::CreateNew;
            let mut call = Call::new(Op::PutObject, Method::PUT, &name)
                .bucket(&sp.bucket)
                .key(&sp.key)
                .extra(extra.as_ref())
                .body(data);
            call.headers = option_headers(opts)?;
            if create_only {
                call = call.header("if-none-match", "*")?;
            }
            return st
                .client
                .execute(call, |_resp| async { Ok(()) })
                .await
                .map_err(|e| create_only_error(e, create_only, &name));
        }
        // Large: concurrent multipart upload of zero-copy slices of `data`.
        let mut w = self
            .open_writer(path, opts, Some(data.len() as u64))
            .await?;
        let res = async {
            w.write(data).await?;
            w.close().await
        }
        .await;
        if res.is_err() {
            let _ = w.abort().await;
        }
        res
    }

    pub(crate) async fn put_file_impl(
        &self,
        local: &Path,
        remote: &str,
        opts: &WriteOptions,
    ) -> Result<()> {
        let meta = tokio::fs::metadata(local).await?;
        let sp = split_path(remote, self.inner.opts.version_aware);
        if meta.is_dir() {
            // s3fs: a local directory makes no remote "directory", except
            // at the bucket level.
            if sp.key.is_empty() {
                return self.mkdir_impl(&sp.bucket, true).await;
            }
            return Ok(());
        }
        let mut opts = opts.clone();
        if opts.content_type.is_none() {
            opts.content_type = crate::mime::guess(local).map(str::to_owned);
        }
        let size = meta.len();
        let st = self.state().await?;
        let cfg = self.upload_config(&st, &opts, Some(size));
        if size <= cfg.part_size as u64 {
            let data = tokio::fs::read(local).await?;
            return self.pipe_file_impl(remote, Bytes::from(data), &opts).await;
        }
        let mut w = self.open_writer(remote, &opts, Some(size)).await?;
        // Read in the uploader's part size so parts are zero-copy slices.
        let part = w
            .uploader
            .as_ref()
            .map_or(cfg.part_size as u64, |u| u.part_sizer().part_size(1));
        let file = Arc::new(std::fs::File::open(local)?);
        let res = async {
            let mut offset = 0u64;
            while offset < size {
                let n = part.min(size - offset);
                let f = file.clone();
                let chunk =
                    tokio::task::spawn_blocking(move || read_exact_at(&f, offset, n as usize))
                        .await
                        .map_err(|e| {
                            Error::new(ErrorKind::Other, format!("read task failed: {e}"))
                        })??;
                w.write(Bytes::from(chunk)).await?;
                offset += n;
            }
            w.close().await
        }
        .await;
        if res.is_err() {
            let _ = w.abort().await;
        }
        res
    }

    /// Copy-source SSE-C headers derived from the filesystem's (or the
    /// call's) `SSECustomer*` parameters, unless `CopySourceSSECustomer*`
    /// are configured explicitly: objects of an SSE-C filesystem are
    /// encrypted with its key, so server-side copies must present it for
    /// the source too.
    pub(crate) fn copy_source_sse_headers(&self, extra: Option<&Params>) -> HeaderMap {
        let mut out = HeaderMap::new();
        let params = match extra {
            Some(e) => self.inner.opts.params.merged(e),
            None => self.inner.opts.params.clone(),
        };
        if params.contains("CopySourceSSECustomerKey") {
            return out;
        }
        if let Some(headers) = params.sse_c_headers() {
            for (name, value) in headers {
                let n = format!(
                    "x-amz-copy-source-{}",
                    name.as_str().trim_start_matches("x-amz-")
                );
                if let Ok(n) = HeaderName::from_bytes(n.as_bytes()) {
                    out.insert(n, value);
                }
            }
            let alg = params.get("SSECustomerAlgorithm").unwrap_or("AES256");
            if let Ok(v) = HeaderValue::from_str(alg) {
                out.insert(
                    HeaderName::from_static(
                        "x-amz-copy-source-server-side-encryption-customer-algorithm",
                    ),
                    v,
                );
            }
        }
        out
    }

    pub(crate) async fn touch_impl(&self, path: &str, truncate: bool) -> Result<()> {
        let sp = split_path(path, self.inner.opts.version_aware);
        if sp.version_id.is_some() {
            return Err(Error::invalid_input(
                "S3 does not support touching existing versions of files",
            ));
        }
        if !truncate && self.exists_impl(path).await? {
            return Err(Error::unsupported(
                "S3 does not support touching existent files; touch",
            ));
        }
        self.pipe_file_impl(path, Bytes::new(), &WriteOptions::default())
            .await
    }
}

/// The `x-amz-copy-source` value: `bucket/key` percent-encoded (`/`
/// kept), with `?versionId=` (botocore's encoding).
pub(crate) fn copy_source(bucket: &str, key: &str, version: Option<&str>) -> String {
    let mut s = uri_encode(&format!("{bucket}/{key}"), true);
    if let Some(v) = version {
        s.push_str("?versionId=");
        s.push_str(&uri_encode(v, false));
    }
    s
}

/// Read exactly `len` bytes at `offset` (positional, so concurrent readers
/// of one file do not interfere).
fn read_exact_at(f: &std::fs::File, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        f.read_exact_at(&mut buf, offset)?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0;
        while done < len {
            let n = f.seek_read(&mut buf[done..], offset + done as u64)?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            done += n;
        }
    }
    Ok(buf)
}

fn fastrand_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_ranges_cover_the_object() {
        assert_eq!(copy_ranges(10, 1), vec![(0, 9)]);
        let r = copy_ranges(11 << 30, 3);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].0, 0);
        assert_eq!(r[2].1, (11 << 30) - 1);
        assert!(r.iter().all(|(a, b)| b - a < MAX_PART));
        for w in r.windows(2) {
            assert_eq!(w[0].1 + 1, w[1].0);
        }
    }

    #[test]
    fn copy_source_encoding() {
        assert_eq!(copy_source("b", "a b/ü+", None), "b/a%20b/%C3%BC%2B");
        assert_eq!(copy_source("b", "k", Some("v+1")), "b/k?versionId=v%2B1");
    }
}
