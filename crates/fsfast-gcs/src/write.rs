//! Uploads: one-request uploads for small objects, resumable upload
//! sessions for streams and large objects.
//!
//! # Why resumable sessions (and not the XML multipart API)
//!
//! `open_write` streams through a resumable upload session, as gcsfs does:
//! chunks are multiples of 256 KiB (`upload_chunk_size`, 16 MiB by
//! default) and must be sent in order, so one chunk is in flight while the
//! next one fills (the writer never waits for the network unless it is
//! two chunks ahead). The XML API's multipart uploads would allow parallel
//! parts through `fsfast_engine::PartUploader`, but they need XML-API
//! access the JSON API does not (and emulators lack: fake-gcs-server does
//! not implement them), produce objects without an MD5 hash, and leave
//! billed parts behind on failure. A single HTTP/2 stream to GCS sustains
//! hundreds of MB/s, and a 16 MiB chunk amortizes the per-chunk round trip;
//! the session survives connection failures and 5xx replies: the session
//! status is queried and only the bytes GCS has not persisted are sent
//! again (never data over persisted bytes).
//!
//! * Data from `write` is kept as the caller's `Bytes` and sent without
//!   concatenating (`RequestBody::Chunks`, split at 256 KiB boundaries by
//!   slicing).
//! * A file that ends below one chunk is uploaded with a single request
//!   when closed (`uploadType=media`, or `multipart` with a random
//!   boundary when there is metadata), as gcsfs's `_simple_upload`.
//! * `WriteMode::CreateNew` sends `ifGenerationMatch=0`; a 412 becomes
//!   `AlreadyExists` (gcsfs `FileExistsError`). Append is not supported by
//!   GCS: like gcsfs, mode `ab` overwrites, with a warning.
//! * `consistency` (`size`, `md5`, `crc32c`) checks the object GCS reports
//!   against what was sent, computed while writing.
//! * Chunks in flight are accounted against the global memory budget.

use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use fsfast_core::{Detail, Error, ErrorKind, Result, Value, WriteHandle, WriteMode, WriteOptions};
use fsfast_engine::concurrency::AbortOnDrop;
use fsfast_engine::retry::retry_with_stats;
use fsfast_http_transport::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use fsfast_http_transport::{Method, Request, RequestBody, Response};
use md5::Digest as _;
use serde_json::{Map, Value as Json};

use crate::GCSFileSystem;
use crate::client::{Query, parse_json_object};
use crate::options::{CHUNK_GRANULARITY, Consistency, round_chunk};
use crate::path::{check_object_name, split_path};

/// gcsfs `SUPPORTED_FIXED_KEY_METADATA`.
const FIXED_KEY_METADATA: &[(&str, &str)] = &[
    ("content_encoding", "contentEncoding"),
    ("cache_control", "cacheControl"),
    ("content_disposition", "contentDisposition"),
    ("content_language", "contentLanguage"),
    ("custom_time", "customTime"),
];

/// `fields` of upload responses: what `consistency` checks.
const UPLOAD_FIELDS: &str = "name,size,md5Hash,crc32c,generation";

/// gcsfs's `pipe_file` chunk for large in-memory uploads.
const PIPE_CHUNK: usize = 50 << 20;

/// What describes the object being written.
#[derive(Debug, Clone, Default)]
pub(crate) struct UploadMeta {
    pub content_type: String,
    pub metadata: BTreeMap<String, String>,
    /// Fixed-key metadata in GCS's names (`cacheControl`, ...).
    pub fixed: BTreeMap<String, String>,
    pub kms_key_name: Option<String>,
    pub create_new: bool,
    pub consistency: Consistency,
}

impl UploadMeta {
    /// The object resource sent with multipart / resumable uploads.
    fn resource(&self, key: &str) -> Json {
        let mut m = Map::new();
        m.insert("name".into(), Json::String(key.to_owned()));
        if !self.metadata.is_empty() {
            m.insert(
                "metadata".into(),
                Json::Object(
                    self.metadata
                        .iter()
                        .map(|(k, v)| (k.clone(), Json::String(v.clone())))
                        .collect(),
                ),
            );
        }
        for (k, v) in &self.fixed {
            m.insert(k.clone(), Json::String(v.clone()));
        }
        Json::Object(m)
    }

    fn needs_resource(&self) -> bool {
        !self.metadata.is_empty() || !self.fixed.is_empty()
    }

    /// The upload query (`name` goes in the resource for multipart).
    fn query(&self, upload_type: &str, key: &str) -> Query {
        let mut q = Query::new().with("uploadType", upload_type);
        if upload_type != "multipart" {
            q.push("name", key);
        }
        if self.create_new {
            q.push("ifGenerationMatch", "0");
        }
        q.opt("kmsKeyName", self.kms_key_name.as_deref());
        if upload_type != "resumable" {
            // Only what the consistency checks read, instead of the whole
            // object resource.
            q.push("fields", UPLOAD_FIELDS);
        }
        q
    }

    /// Map a 412 to `AlreadyExists` for create-only uploads.
    fn kinds(&self, req: Request) -> Request {
        if self.create_new {
            req.status_kind(412, ErrorKind::AlreadyExists)
        } else {
            req
        }
    }
}

fn string_map(v: &Value, what: &str) -> Result<BTreeMap<String, String>> {
    match v {
        Value::Null => Ok(BTreeMap::new()),
        Value::Map(m) => m
            .iter()
            .map(|(k, v)| match v {
                Value::Str(s) => Ok((k.clone(), s.clone())),
                Value::Int(i) => Ok((k.clone(), i.to_string())),
                Value::Float(f) => Ok((k.clone(), f.to_string())),
                Value::Bool(b) => Ok((k.clone(), if *b { "True" } else { "False" }.to_owned())),
                other => Err(Error::invalid_input(format!(
                    "gcs: {what} values must be strings, got {}",
                    other.type_name()
                ))),
            })
            .collect(),
        other => Err(Error::invalid_input(format!(
            "gcs: {what} must be a dict, got {}",
            other.type_name()
        ))),
    }
}

/// Hashes of the bytes written, for `consistency`.
#[derive(Clone)]
struct Hasher {
    mode: Consistency,
    crc: u32,
    md5: Option<md5::Md5>,
    size: u64,
}

impl Hasher {
    fn new(mode: Consistency) -> Self {
        Hasher {
            mode,
            crc: 0,
            md5: (mode == Consistency::Md5).then(md5::Md5::new),
            size: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.size += data.len() as u64;
        match self.mode {
            Consistency::Crc32c => self.crc = crc32c::crc32c_append(self.crc, data),
            Consistency::Md5 => {
                if let Some(m) = &mut self.md5 {
                    m.update(data);
                }
            }
            Consistency::Size | Consistency::None => {}
        }
    }

    /// gcsfs `validate_json_response`.
    fn validate(self, obj: &Map<String, Json>, path: &str) -> Result<()> {
        let fail = |what: String| {
            Err(Error::new(ErrorKind::Io, what)
                .with_path(path)
                .with_detail(Detail::Code("ChecksumError".into())))
        };
        match self.mode {
            Consistency::None => Ok(()),
            Consistency::Size => {
                let got = obj.get("size").and_then(|s| match s {
                    Json::String(s) => s.parse::<u64>().ok(),
                    Json::Number(n) => n.as_u64(),
                    _ => None,
                });
                if got == Some(self.size) {
                    Ok(())
                } else {
                    fail(format!(
                        "Size mismatch: wrote {} bytes, GCS reports {got:?}",
                        self.size
                    ))
                }
            }
            Consistency::Md5 => {
                let want = self
                    .md5
                    .map(|m| base64::engine::general_purpose::STANDARD.encode(m.finalize()))
                    .unwrap_or_default();
                match obj.get("md5Hash").and_then(Json::as_str) {
                    Some(h) if h == want => Ok(()),
                    Some(h) => fail(format!("MD5 checksum failed: sent {want}, GCS reports {h}")),
                    None => fail(
                        "MD5 checksum unavailable (GCS reports none, e.g. for composite objects)"
                            .into(),
                    ),
                }
            }
            Consistency::Crc32c => {
                let want = crate::read::crc32c_b64(self.crc);
                match obj.get("crc32c").and_then(Json::as_str) {
                    Some(h) if h == want => Ok(()),
                    Some(h) => fail(format!("Expected \"{h}\". Got \"{want}\"")),
                    None => fail("GCS reports no crc32c for the object".into()),
                }
            }
        }
    }
}

/// A random multipart boundary (128 bits): binary payloads are not
/// scanned, so the boundary must be unguessable rather than fixed (gcsfs's
/// fixed `==0==` breaks on payloads that contain it).
fn random_boundary() -> String {
    let mut b = [0u8; 16];
    let _ = aws_lc_rs::rand::fill(&mut b);
    format!("fsfast-{}", hex::encode(b))
}

/// Outcome of one resumable-upload request.
enum ChunkReply {
    /// More data expected; GCS has persisted this many bytes.
    Incomplete(u64),
    /// Finished: the object resource.
    Done(Map<String, Json>),
}

/// `Range: bytes=0-N` of a 308 reply: N + 1 bytes persisted.
fn persisted(resp: &Response) -> Result<u64> {
    match resp.header_str("range") {
        None => Ok(0),
        Some(r) => r
            .trim()
            .strip_prefix("bytes=")
            .and_then(|r| r.split_once('-'))
            .and_then(|(_, end)| end.trim().parse::<u64>().ok())
            .map(|e| e + 1)
            .ok_or_else(|| {
                Error::protocol(format!("invalid Range in a resumable upload reply: {r:?}"))
            }),
    }
}

/// Take exactly `n` bytes from the front of `pending` (slicing, no copy).
fn take_front(pending: &mut VecDeque<Bytes>, pending_len: &mut usize, n: usize) -> Vec<Bytes> {
    let mut out = Vec::new();
    let mut need = n;
    while need > 0 {
        let Some(mut b) = pending.pop_front() else {
            break;
        };
        if b.len() > need {
            let rest = b.split_off(need);
            pending.push_front(rest);
        }
        need -= b.len();
        out.push(b);
    }
    *pending_len -= n - need;
    out
}

/// Bytes `skip..` of `chunks` (slicing, no copy).
fn skip_front(chunks: &[Bytes], skip: usize) -> Vec<Bytes> {
    let mut out = Vec::new();
    let mut s = skip;
    for c in chunks {
        if s >= c.len() {
            s -= c.len();
            continue;
        }
        out.push(c.slice(s..));
        s = 0;
    }
    out
}

impl GCSFileSystem {
    /// Parse write options into upload metadata. `default_type` is used
    /// when no content type is given.
    pub(crate) fn upload_meta(
        &self,
        opts: &WriteOptions,
        default_type: impl FnOnce() -> String,
    ) -> Result<UploadMeta> {
        let mut meta = UploadMeta {
            content_type: String::new(),
            metadata: opts.metadata.clone(),
            fixed: BTreeMap::new(),
            kms_key_name: None,
            create_new: opts.mode == WriteMode::CreateNew,
            consistency: self.inner.opts.consistency,
        };
        let mut content_type = opts.content_type.clone();
        for (k, v) in &opts.extra {
            match k.as_str() {
                "metadata" => meta.metadata.extend(string_map(v, "metadata")?),
                "fixed_key_metadata" => {
                    for (fk, fv) in string_map(v, "fixed_key_metadata")? {
                        // gcsfs accepts snake_case names only.
                        if let Some((_, google)) = FIXED_KEY_METADATA.iter().find(|(s, _)| *s == fk)
                        {
                            meta.fixed.insert((*google).to_owned(), fv);
                        }
                    }
                }
                "kms_key_name" => match v {
                    Value::Str(s) => meta.kms_key_name = Some(s.clone()),
                    Value::Null => {}
                    other => {
                        return Err(Error::invalid_input(format!(
                            "gcs: kms_key_name must be a string, got {}",
                            other.type_name()
                        )));
                    }
                },
                "content_type" => match v {
                    Value::Str(s) => content_type = Some(s.clone()),
                    Value::Null => {}
                    other => {
                        return Err(Error::invalid_input(format!(
                            "gcs: content_type must be a string, got {}",
                            other.type_name()
                        )));
                    }
                },
                "consistency" => match v {
                    Value::Str(s) => meta.consistency = Consistency::parse(s),
                    Value::Null => {}
                    other => {
                        return Err(Error::invalid_input(format!(
                            "gcs: consistency must be a string, got {}",
                            other.type_name()
                        )));
                    }
                },
                // gcsfs accepts `acl` for files but does not apply it.
                "acl" => {}
                other => {
                    return Err(Error::invalid_input(format!(
                        "gcs: unsupported write option {other:?}"
                    )));
                }
            }
        }
        meta.content_type = content_type.unwrap_or_else(default_type);
        Ok(meta)
    }

    /// One-request upload (gcsfs `simple_upload`). Returns the object
    /// resource.
    pub(crate) async fn simple_upload(
        &self,
        bucket: &str,
        key: &str,
        data: Vec<Bytes>,
        meta: &UploadMeta,
        path: &str,
    ) -> Result<Map<String, Json>> {
        let c = &self.inner.client;
        let mut hasher = Hasher::new(meta.consistency);
        for d in &data {
            hasher.update(d);
        }
        let req = if meta.needs_resource() {
            let boundary = random_boundary();
            let head = format!(
                "--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{}\r\n--{boundary}\r\nContent-Type: {}\r\n\r\n",
                meta.resource(key),
                meta.content_type
            );
            let tail = format!("\r\n--{boundary}--\r\n");
            let mut parts = Vec::with_capacity(data.len() + 2);
            parts.push(Bytes::from(head));
            parts.extend(data);
            parts.push(Bytes::from(tail));
            let ctype = HeaderValue::try_from(format!("multipart/related; boundary={boundary}"))
                .map_err(|_| Error::invalid_input("invalid multipart boundary"))?;
            c.request(
                Method::POST,
                &c.upload_url(bucket),
                &meta.query("multipart", key),
            )?
            .header(CONTENT_TYPE, ctype)
            .body(RequestBody::chunks(parts))
        } else {
            let ctype = HeaderValue::try_from(meta.content_type.as_str()).map_err(|_| {
                Error::invalid_input(format!("invalid content type {:?}", meta.content_type))
            })?;
            c.request(
                Method::POST,
                &c.upload_url(bucket),
                &meta.query("media", key),
            )?
            .header(CONTENT_TYPE, ctype)
            .body(RequestBody::chunks(data))
        };
        // gcsfs retries uploads; resending the same object is harmless.
        let req = meta.kinds(req.retry_safe(true).path(path.to_owned()));
        let obj = c.json(req).await?;
        hasher.validate(&obj, path)?;
        Ok(obj)
    }

    /// Start a resumable upload session (gcsfs `initiate_upload`); returns
    /// the session URL.
    pub(crate) async fn initiate_upload(
        &self,
        bucket: &str,
        key: &str,
        meta: &UploadMeta,
        path: &str,
    ) -> Result<String> {
        let c = &self.inner.client;
        let body =
            serde_json::to_vec(&meta.resource(key)).map_err(|e| Error::protocol(e.to_string()))?;
        let utype = HeaderValue::try_from(meta.content_type.as_str()).map_err(|_| {
            Error::invalid_input(format!("invalid content type {:?}", meta.content_type))
        })?;
        let req = c
            .request(
                Method::POST,
                &c.upload_url(bucket),
                &meta.query("resumable", key),
            )?
            .header(
                CONTENT_TYPE,
                HeaderValue::from_static("application/json; charset=UTF-8"),
            )
            .header(HeaderName::from_static("x-upload-content-type"), utype)
            .body(Bytes::from(body))
            .retry_safe(true)
            .path(path.to_owned());
        let req = meta.kinds(req);
        c.execute(req, |resp| async move {
            let loc = resp
                .header_str("location")
                .map(str::to_owned)
                .ok_or_else(|| {
                    Error::protocol("resumable upload started without a Location header")
                })?;
            // Drain the (small) body so the connection is reused.
            let _ = resp.bytes().await;
            Ok(loc)
        })
        .await
    }

    /// Send `chunks` at `offset` to a session; `total` finalizes the upload.
    async fn put_chunk(
        &self,
        session: &str,
        chunks: Vec<Bytes>,
        offset: u64,
        total: Option<u64>,
        meta: &UploadMeta,
        path: &str,
    ) -> Result<ChunkReply> {
        let c = &self.inner.client;
        let len: u64 = chunks.iter().map(|b| b.len() as u64).sum();
        let range = match (len, total) {
            (0, Some(t)) => format!("bytes */{t}"),
            (0, None) => "bytes */*".to_owned(),
            (n, Some(t)) => format!("bytes {offset}-{}/{t}", offset + n - 1),
            (n, None) => format!("bytes {offset}-{}/*", offset + n - 1),
        };
        let ctype = HeaderValue::try_from(meta.content_type.as_str())
            .map_err(|_| Error::invalid_input("invalid content type"))?;
        let req = c
            .request(Method::PUT, session, &Query::new())?
            .header(
                HeaderName::from_static("content-range"),
                HeaderValue::try_from(range).map_err(|_| Error::invalid_input("invalid range"))?,
            )
            // gcsfs sends the content type with every chunk (emulators take
            // it from there).
            .header(CONTENT_TYPE, ctype)
            .body(RequestBody::chunks(chunks))
            // `upload_span` owns the retries: after a failure it asks GCS
            // what was persisted instead of re-sending blindly.
            .retry_safe(false)
            .allow_status(308)
            .op(fsfast_engine::stats::OpKind::Write)
            .path(path.to_owned());
        let req = meta.kinds(req);
        c.execute(req, |resp| async move {
            if resp.status().as_u16() == 308 {
                let n = persisted(&resp)?;
                let _ = resp.bytes().await;
                Ok(ChunkReply::Incomplete(n))
            } else {
                let p = resp.path().to_owned();
                let body = resp.bytes().await?;
                Ok(ChunkReply::Done(
                    parse_json_object(&body).map_err(|e| e.with_path(p))?,
                ))
            }
        })
        .await
    }

    /// Upload `chunks` (bytes `offset..offset+len`) until GCS has them all,
    /// re-sending any part it did not persist. `total` is the object size
    /// when known (sent in every `Content-Range`, as gcsfs does, so GCS can
    /// check the upload against it); when these bytes end at `total`, the
    /// upload is finalized and the object resource is returned.
    async fn upload_span(
        &self,
        session: &str,
        chunks: Vec<Bytes>,
        offset: u64,
        total: Option<u64>,
        meta: &UploadMeta,
        path: &str,
    ) -> Result<Option<Map<String, Json>>> {
        let len: u64 = chunks.iter().map(|b| b.len() as u64).sum();
        let end = offset + len;
        if total.is_some_and(|t| end > t) {
            return Err(Error::invalid_input(format!(
                "upload chunk ends at {end}, past the object size {total:?}"
            ))
            .with_path(path));
        }
        let finalizing = total == Some(end);
        // Bytes GCS has confirmed (`offset` until a reply says more).
        let pos = AtomicU64::new(offset);
        let interrupted = AtomicBool::new(false);
        // Data requests are never re-sent blindly by the transport: a request
        // that failed may still have persisted part of its bytes, so after a
        // transient failure the session status is queried first and only
        // the bytes GCS does not have are sent again (GCS's documented
        // resume procedure). The retries follow the client's policy.
        let policy = self.inner.client.http.retry_policy().clone();
        retry_with_stats(&policy, &self.inner.stats, || {
            let chunks = &chunks;
            let (pos, interrupted) = (&pos, &interrupted);
            async move {
                if interrupted.load(Ordering::Relaxed) {
                    // `bytes */total` also finalizes an upload whose bytes
                    // all arrived.
                    match self
                        .put_chunk(session, Vec::new(), end, total, meta, path)
                        .await?
                    {
                        ChunkReply::Done(obj) if finalizing => return Ok(Some(obj)),
                        ChunkReply::Done(_) => {
                            return Err(Error::protocol("upload finished before its last chunk")
                                .with_path(path));
                        }
                        ChunkReply::Incomplete(n) => {
                            if n < pos.load(Ordering::Relaxed) || n > end {
                                return Err(Error::protocol(format!(
                                    "resumable upload reports {n} bytes persisted, outside {}..{end}",
                                    pos.load(Ordering::Relaxed)
                                ))
                                .with_path(path));
                            }
                            tracing::debug!(
                                persisted = n,
                                sent_to = end,
                                "resuming an interrupted upload"
                            );
                            pos.store(n, Ordering::Relaxed);
                            if !finalizing && n == end {
                                return Ok(None);
                            }
                        }
                    }
                }
                interrupted.store(true, Ordering::Relaxed);
                let r = self
                    .send_span(session, chunks, offset, end, pos, total, meta, path)
                    .await;
                if r.is_ok() {
                    interrupted.store(false, Ordering::Relaxed);
                }
                r
            }
        })
        .await
    }

    /// Send bytes `pos..end` of `chunks` (which start at `offset`),
    /// following short writes; `pos` is updated with what GCS confirms.
    #[allow(clippy::too_many_arguments)]
    async fn send_span(
        &self,
        session: &str,
        chunks: &[Bytes],
        offset: u64,
        end: u64,
        pos: &AtomicU64,
        total: Option<u64>,
        meta: &UploadMeta,
        path: &str,
    ) -> Result<Option<Map<String, Json>>> {
        let finalizing = total == Some(end);
        for _ in 0..16 {
            let from = pos.load(Ordering::Relaxed);
            let rest = if from >= end {
                Vec::new()
            } else {
                skip_front(chunks, (from - offset) as usize)
            };
            if rest.is_empty() && !finalizing {
                return Ok(None);
            }
            match self
                .put_chunk(session, rest, from, total, meta, path)
                .await?
            {
                ChunkReply::Done(obj) => {
                    if !finalizing {
                        return Err(Error::protocol("upload finished before its last chunk")
                            .with_path(path));
                    }
                    return Ok(Some(obj));
                }
                ChunkReply::Incomplete(n) => {
                    if n < from || n > end {
                        return Err(Error::protocol(format!(
                            "resumable upload persisted {n} bytes, outside the chunk {from}..{end}"
                        ))
                        .with_path(path));
                    }
                    pos.store(n, Ordering::Relaxed);
                    if n == end && !finalizing {
                        return Ok(None);
                    }
                    if n < end {
                        tracing::debug!(
                            persisted = n,
                            sent_to = end,
                            "resumable upload short write; re-sending the rest"
                        );
                    }
                    // n == end while finalizing: everything persisted but
                    // not finalized; the next request (empty) finalizes.
                }
            }
        }
        Err(Error::protocol("resumable upload makes no progress").with_path(path))
    }

    /// Cancel a resumable session (gcsfs `discard`).
    pub(crate) async fn cancel_upload(&self, session: &str, path: &str) -> Result<()> {
        let c = &self.inner.client;
        let url = session.replace("&ifGenerationMatch=0", "");
        let req = c
            .request(Method::DELETE, &url, &Query::new())?
            .allow_status(499)
            .allow_status(404)
            .allow_status(410)
            .path(path.to_owned());
        c.send_ok(req).await
    }

    pub(crate) async fn open_write_impl(
        &self,
        path: &str,
        opts: &WriteOptions,
    ) -> Result<GcsWriteHandle> {
        let (bucket, key, name) = self.write_target(path)?;
        if opts.mode == WriteMode::Append {
            tracing::warn!(path = %name, "Append mode 'a' is not supported in GCS. Using overwrite mode instead.");
        }
        let meta = self.upload_meta(opts, || {
            crate::mime::guess(Path::new(&key))
                .unwrap_or("application/octet-stream")
                .to_owned()
        })?;
        let chunk = match opts.block_size.filter(|b| *b > 0) {
            Some(b) => round_chunk(b),
            None => self.inner.opts.upload_chunk_size,
        };
        if meta.create_new {
            // Fail fast at open, as local files do (and fsspec's abstract
            // `test_open_exclusive` expects), instead of after uploading
            // everything; the upload stays conditional (ifGenerationMatch=0),
            // so a writer racing in after this check still loses.
            match self.get_object(&bucket, &key, None).await {
                Ok(_) => return Err(Error::already_exists(name)),
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(GcsWriteHandle {
            fs: self.clone(),
            bucket,
            key,
            path: name,
            hasher: Hasher::new(meta.consistency),
            meta: Arc::new(meta),
            chunk,
            pending: VecDeque::new(),
            pending_len: 0,
            session: None,
            offset: 0,
            inflight: None,
            written: 0,
            state: State::Open,
        })
    }

    /// Bucket, key and full name of a write target.
    pub(crate) fn write_target(&self, path: &str) -> Result<(String, String, String)> {
        let sp = split_path(path, self.inner.opts.version_aware);
        if sp.generation.is_some() {
            return Err(Error::invalid_input(
                "Cannot write to specific object generation",
            ));
        }
        if sp.bucket.is_empty() || sp.key.is_empty() {
            return Err(Error::invalid_input(format!(
                "Attempt to write to a bucket, not an object: {path:?}"
            )));
        }
        let name = sp.full();
        check_object_name(&sp.key, &name)?;
        Ok((sp.bucket, sp.key, name))
    }

    pub(crate) async fn pipe_file_impl(
        &self,
        path: &str,
        data: Bytes,
        opts: &WriteOptions,
    ) -> Result<()> {
        let (bucket, key, name) = self.write_target(path)?;
        let meta = self.upload_meta(opts, || "application/octet-stream".to_owned())?;
        if data.len() <= self.inner.opts.simple_upload_threshold {
            self.simple_upload(&bucket, &key, vec![data], &meta, &name)
                .await?;
            return Ok(());
        }
        let session = self.initiate_upload(&bucket, &key, &meta, &name).await?;
        let total = data.len() as u64;
        let res = async {
            let mut hasher = Hasher::new(meta.consistency);
            hasher.update(&data);
            let chunk = round_chunk(PIPE_CHUNK.max(self.inner.opts.upload_chunk_size));
            let mut off = 0usize;
            let mut last = None;
            while off < data.len() {
                let end = (off + chunk).min(data.len());
                last = self
                    .upload_span(
                        &session,
                        vec![data.slice(off..end)],
                        off as u64,
                        Some(total),
                        &meta,
                        &name,
                    )
                    .await?;
                off = end;
            }
            let obj =
                last.ok_or_else(|| Error::protocol("upload did not finish").with_path(&name))?;
            hasher.validate(&obj, &name)
        }
        .await;
        if res.is_err() {
            let _ = self.cancel_upload(&session, &name).await;
        }
        res
    }

    pub(crate) async fn put_file_impl(
        &self,
        local: &Path,
        remote: &str,
        opts: &WriteOptions,
    ) -> Result<()> {
        let md = tokio::fs::metadata(local)
            .await
            .map_err(|e| Error::from(e).with_path(local.display().to_string()))?;
        if md.is_dir() {
            // gcsfs: uploading a directory does nothing.
            return Ok(());
        }
        let (bucket, key, name) = self.write_target(remote)?;
        let meta = self.upload_meta(opts, || {
            crate::mime::guess(local)
                .unwrap_or("application/octet-stream")
                .to_owned()
        })?;
        let size = md.len();
        if size <= self.inner.opts.simple_upload_threshold as u64
            && !meta.needs_resource()
            && meta.consistency == Consistency::None
        {
            // Streamed from disk in one request, without buffering it.
            let c = &self.inner.client;
            let ctype = HeaderValue::try_from(meta.content_type.as_str())
                .map_err(|_| Error::invalid_input("invalid content type"))?;
            let req = c
                .request(
                    Method::POST,
                    &c.upload_url(&bucket),
                    &meta.query("media", &key),
                )?
                .header(CONTENT_TYPE, ctype)
                .body(RequestBody::File {
                    path: local.to_owned(),
                    len: size,
                })
                .retry_safe(true)
                .path(name.clone());
            c.json(meta.kinds(req)).await?;
            return Ok(());
        }
        // Larger files stream through a write handle: the next chunk is
        // read from disk while the previous one uploads.
        let mut w = self.open_write_impl(remote, opts).await?;
        w.meta = Arc::new(meta);
        if opts.block_size.is_none() {
            // gcsfs `_put_file` uploads 50 MiB chunks: fewer round trips per
            // file (one file at a time, so the two chunks in memory are
            // affordable; open files keep the smaller default).
            w.chunk = round_chunk(PIPE_CHUNK.max(self.inner.opts.upload_chunk_size));
        }
        let res = async {
            use tokio::io::AsyncReadExt;
            let mut f = tokio::fs::File::open(local).await?;
            let chunk = w.chunk;
            loop {
                let mut buf = vec![0u8; chunk];
                let mut filled = 0;
                while filled < chunk {
                    let n = f.read(&mut buf[filled..]).await?;
                    if n == 0 {
                        break;
                    }
                    filled += n;
                }
                if filled == 0 {
                    break;
                }
                buf.truncate(filled);
                w.write(Bytes::from(buf)).await?;
                if filled < chunk {
                    break;
                }
            }
            w.close().await
        }
        .await;
        if res.is_err() {
            let _ = w.abort().await;
        }
        res
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Open,
    Closed,
    Aborted,
    Failed,
}

/// A streaming upload (gcsfs `GCSFile` in write mode).
pub struct GcsWriteHandle {
    fs: GCSFileSystem,
    bucket: String,
    key: String,
    path: String,
    meta: Arc<UploadMeta>,
    hasher: Hasher,
    chunk: usize,
    pending: VecDeque<Bytes>,
    pending_len: usize,
    session: Option<Arc<str>>,
    /// Bytes handed to chunk uploads.
    offset: u64,
    inflight: Option<AbortOnDrop<Result<()>>>,
    written: u64,
    state: State,
}

impl std::fmt::Debug for GcsWriteHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcsWriteHandle")
            .field("path", &self.path)
            .field("written", &self.written)
            .field("chunk", &self.chunk)
            .field("resumable", &self.session.is_some())
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl GcsWriteHandle {
    /// The resumable session URL, once the upload outgrew one chunk.
    pub fn session_url(&self) -> Option<&str> {
        self.session.as_deref()
    }

    /// The upload chunk size.
    pub fn chunk_size(&self) -> usize {
        self.chunk
    }

    fn check_open(&self) -> Result<()> {
        match self.state {
            State::Open => Ok(()),
            State::Closed => {
                Err(Error::invalid_input("I/O operation on a closed file").with_path(&self.path))
            }
            State::Aborted => Err(Error::invalid_input("write was aborted").with_path(&self.path)),
            State::Failed => Err(Error::new(
                ErrorKind::Io,
                "an earlier part of this upload failed",
            )
            .with_path(&self.path)),
        }
    }

    /// Wait for the chunk in flight (cancel-safe: the task keeps running
    /// if this future is dropped).
    async fn wait_inflight(&mut self) -> Result<()> {
        if let Some(t) = self.inflight.as_mut() {
            let r = t.await;
            self.inflight = None;
            let r =
                r.map_err(|e| Error::new(ErrorKind::Other, format!("upload task failed: {e}")))?;
            if r.is_err() {
                self.state = State::Failed;
            }
            r?;
        }
        Ok(())
    }

    async fn ensure_session(&mut self) -> Result<Arc<str>> {
        if let Some(s) = &self.session {
            return Ok(s.clone());
        }
        let s: Arc<str> = Arc::from(
            self.fs
                .initiate_upload(&self.bucket, &self.key, &self.meta, &self.path)
                .await?,
        );
        self.session = Some(s.clone());
        Ok(s)
    }

    /// Hand one full chunk to a background upload.
    async fn dispatch_chunk(&mut self) -> Result<()> {
        self.wait_inflight().await?;
        let session = self.ensure_session().await?;
        let guard = self.fs.inner.budget.acquire(self.chunk).await;
        let chunks = take_front(&mut self.pending, &mut self.pending_len, self.chunk);
        let len: u64 = chunks.iter().map(|b| b.len() as u64).sum();
        debug_assert_eq!(len as usize % CHUNK_GRANULARITY, 0);
        let offset = self.offset;
        self.offset += len;
        let fs = self.fs.clone();
        let meta = self.meta.clone();
        let path = self.path.clone();
        self.inflight = Some(AbortOnDrop::spawn(async move {
            let _guard = guard;
            fs.upload_span(&session, chunks, offset, None, &meta, &path)
                .await
                .map(|_| ())
        }));
        Ok(())
    }

    async fn finish(&mut self) -> Result<()> {
        self.wait_inflight().await?;
        let n = self.pending_len;
        let rest = take_front(&mut self.pending, &mut self.pending_len, n);
        let obj = match self.session.clone() {
            None => {
                self.fs
                    .simple_upload(&self.bucket, &self.key, rest, &self.meta, &self.path)
                    .await?
            }
            Some(session) => {
                let len: u64 = rest.iter().map(|b| b.len() as u64).sum();
                let total = self.offset + len;
                let obj = self
                    .fs
                    .upload_span(
                        &session,
                        rest,
                        self.offset,
                        Some(total),
                        &self.meta,
                        &self.path,
                    )
                    .await?
                    .ok_or_else(|| {
                        Error::protocol("upload did not finish").with_path(&self.path)
                    })?;
                self.offset = total;
                obj
            }
        };
        if self.session.is_some() {
            // simple_upload validated its own body already.
            self.hasher.clone().validate(&obj, &self.path)?;
        }
        Ok(())
    }
}

#[async_trait]
impl WriteHandle for GcsWriteHandle {
    async fn write(&mut self, data: Bytes) -> Result<()> {
        self.check_open()?;
        if data.is_empty() {
            return Ok(());
        }
        self.hasher.update(&data);
        self.written += data.len() as u64;
        self.pending_len += data.len();
        self.pending.push_back(data);
        while self.pending_len >= self.chunk {
            if let Err(e) = self.dispatch_chunk().await {
                self.state = State::Failed;
                return Err(e);
            }
        }
        Ok(())
    }

    /// Waits for the chunk in flight (surfacing its errors). Data below one
    /// chunk stays buffered: GCS accepts only 256 KiB multiples before the
    /// end, and nothing is visible before `close` anyway.
    async fn flush(&mut self) -> Result<()> {
        self.check_open()?;
        self.wait_inflight().await
    }

    async fn close(&mut self) -> Result<()> {
        if self.state == State::Closed {
            return Ok(());
        }
        self.check_open()?;
        // `finish` takes the buffered tail before it awaits: if this future
        // is cancelled half-way, those bytes are gone, so the upload must
        // not be committable any more (a later `close` fails; `abort` or
        // dropping the handle cancels the session).
        self.state = State::Failed;
        match self.finish().await {
            Ok(()) => {
                self.state = State::Closed;
                self.session = None;
                Ok(())
            }
            Err(e) => {
                self.state = State::Failed;
                Err(e)
            }
        }
    }

    async fn abort(&mut self) -> Result<()> {
        if matches!(self.state, State::Closed | State::Aborted) {
            return Ok(());
        }
        if let Some(t) = self.inflight.take() {
            t.abort();
        }
        self.pending.clear();
        self.pending_len = 0;
        self.state = State::Aborted;
        if let Some(s) = self.session.take() {
            self.fs.cancel_upload(&s, &self.path).await?;
        }
        Ok(())
    }

    fn bytes_written(&self) -> u64 {
        self.written
    }
}

impl Drop for GcsWriteHandle {
    fn drop(&mut self) {
        if matches!(self.state, State::Open | State::Failed)
            && let Some(s) = self.session.take()
            && let Ok(rt) = tokio::runtime::Handle::try_current()
        {
            // Neither closed nor aborted: cancel the session instead of
            // leaving it until it expires.
            if let Some(t) = self.inflight.take() {
                t.abort();
            }
            let fs = self.fs.clone();
            let path = self.path.clone();
            rt.spawn(async move {
                let _ = fs.cancel_upload(&s, &path).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_and_skip() {
        let mut q: VecDeque<Bytes> = vec![
            Bytes::from_static(b"abc"),
            Bytes::from_static(b"defgh"),
            Bytes::from_static(b"ij"),
        ]
        .into();
        let mut len = 10;
        let got = take_front(&mut q, &mut len, 4);
        assert_eq!(got.concat(), b"abcd");
        assert_eq!(len, 6);
        assert_eq!(
            q.iter().map(|b| b.to_vec()).collect::<Vec<_>>().concat(),
            b"efghij"
        );
        let got = take_front(&mut q, &mut len, 6);
        assert_eq!(got.concat(), b"efghij");
        assert_eq!(len, 0);
        assert!(q.is_empty());
        let chunks = vec![Bytes::from_static(b"abc"), Bytes::from_static(b"def")];
        assert_eq!(skip_front(&chunks, 0).concat(), b"abcdef");
        assert_eq!(skip_front(&chunks, 3).concat(), b"def");
        assert_eq!(skip_front(&chunks, 4).concat(), b"ef");
        assert!(skip_front(&chunks, 6).is_empty());
    }

    #[test]
    fn hashers() {
        let mut h = Hasher::new(Consistency::Crc32c);
        h.update(b"hello ");
        h.update(b"world");
        let mut obj = Map::new();
        obj.insert("crc32c".into(), Json::String("yZRlqg==".into()));
        assert!(h.clone().validate(&obj, "p").is_ok());
        obj.insert("crc32c".into(), Json::String("AAAAAA==".into()));
        assert!(h.validate(&obj, "p").is_err());

        let mut h = Hasher::new(Consistency::Md5);
        h.update(b"hello world");
        let mut obj = Map::new();
        obj.insert(
            "md5Hash".into(),
            Json::String("XrY7u+Ae7tCTyyK7j1rNww==".into()),
        );
        assert!(h.clone().validate(&obj, "p").is_ok());
        assert!(h.validate(&Map::new(), "p").is_err());

        let mut h = Hasher::new(Consistency::Size);
        h.update(b"hello world");
        let mut obj = Map::new();
        obj.insert("size".into(), Json::String("11".into()));
        assert!(h.clone().validate(&obj, "p").is_ok());
        obj.insert("size".into(), Json::String("12".into()));
        assert!(h.validate(&obj, "p").is_err());
        assert!(
            Hasher::new(Consistency::None)
                .validate(&Map::new(), "p")
                .is_ok()
        );
    }

    #[test]
    fn boundaries_are_random() {
        let a = random_boundary();
        assert_ne!(a, random_boundary());
        assert_eq!(a.len(), "fsfast-".len() + 32);
    }

    #[test]
    fn resources() {
        let mut meta = UploadMeta::default();
        assert!(!meta.needs_resource());
        meta.metadata.insert("k".into(), "v".into());
        meta.fixed.insert("cacheControl".into(), "no-cache".into());
        assert!(meta.needs_resource());
        assert_eq!(
            meta.resource("a/b").to_string(),
            r#"{"cacheControl":"no-cache","metadata":{"k":"v"},"name":"a/b"}"#
        );
        meta.create_new = true;
        meta.kms_key_name = Some("projects/p/keys/k".into());
        assert_eq!(
            meta.query("media", "a b").as_str(),
            "uploadType=media&name=a%20b&ifGenerationMatch=0&kmsKeyName=projects%2Fp%2Fkeys%2Fk&fields=name%2Csize%2Cmd5Hash%2Ccrc32c%2Cgeneration"
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Splitting the pending buffers at chunk boundaries (and skipping a
        /// persisted prefix) never loses, duplicates or reorders bytes.
        #[test]
        fn chunking_preserves_bytes(
            parts in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..50), 0..12),
            take in 0usize..400,
            skip in 0usize..400,
        ) {
            let all: Vec<u8> = parts.concat();
            let mut q: VecDeque<Bytes> = parts.into_iter().map(Bytes::from).collect();
            let mut len = all.len();
            let n = take.min(len);
            let got = take_front(&mut q, &mut len, n);
            prop_assert_eq!(got.concat(), &all[..n]);
            prop_assert_eq!(len, all.len() - n);
            let rest: Vec<u8> = q.iter().flat_map(|b| b.to_vec()).collect();
            prop_assert_eq!(&rest[..], &all[n..]);
            let s = skip.min(n);
            prop_assert_eq!(skip_front(&got, s).concat(), &all[s..n]);
        }
    }
}
