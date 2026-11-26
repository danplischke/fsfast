//! Reads: pinned ranged GETs, parallel ranged GETs for large reads,
//! `cat_file` and `get_file` without a preliminary `HEAD`.
//!
//! A read handle pins every GET to the object it opened: by `If-Match` on
//! the ETag (s3fs does the same for its file objects), or by `versionId` on
//! version-aware filesystems, so an object replaced while it is being read
//! fails with `PreconditionFailed` instead of returning mixed bytes. With
//! s3fs's `local_expiry_check` the ETag is compared locally instead (for
//! servers that do not support `If-Match`).
//!
//! `cat_file` and `get_file` start with one ranged GET of the first
//! `request_size` bytes: small objects are done in that single request,
//! and the `Content-Range` total of larger ones tells how many further
//! parts to fetch concurrently, pinned to the ETag of the first response.

use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use fsfast_core::{
    ByteRange, Error, ErrorKind, FileInfo, IoHints, ReadHandle, ReadOptions, Result,
};
use fsfast_engine::budget::MemoryBudget;
use fsfast_engine::parallel::{read_parallel, read_parallel_into};
use fsfast_http_transport::{Method, RangeBody};
use futures::{StreamExt, stream};

use crate::client::Call;
use crate::params::{Op, Params};
use crate::path::split_path;
use crate::{S3FileSystem, State};

/// How a handle's reads are tied to the object version it opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Pin {
    /// No pinning.
    None,
    /// `If-Match: <etag>`.
    IfMatch(String),
    /// `?versionId=<id>`.
    Version(String),
    /// Compare the response ETag locally (`local_expiry_check`).
    Local(String),
}

/// The response to one ranged GET.
pub(crate) struct Fetched {
    pub body: RangeBody,
    pub etag: Option<String>,
    pub version_id: Option<String>,
}

/// One ranged GET of `bucket/key`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn get_range(
    st: &State,
    bucket: &str,
    key: &str,
    range: ByteRange,
    pin: &Pin,
    extra: Option<&Params>,
    path: &str,
) -> Result<Fetched> {
    let mut call = Call::new(Op::GetObject, Method::GET, path)
        .bucket(bucket)
        .key(key)
        .extra(extra);
    if let Some(h) = range.to_http_header() {
        call = call.header("range", &h)?.allow(416);
    }
    match pin {
        Pin::IfMatch(e) => call = call.header("if-match", e)?,
        Pin::Version(v) => call = call.query("versionId", v.clone()),
        Pin::None | Pin::Local(_) => {}
    }
    st.client
        .execute(call, |resp| async move {
            let etag = resp.etag().map(str::to_owned);
            let version_id = resp.header_str("x-amz-version-id").map(str::to_owned);
            if let Pin::Local(expected) = pin
                && etag.as_deref() != Some(expected.as_str())
            {
                return Err(Error::new(
                    ErrorKind::PreconditionFailed,
                    format!(
                        "The remote file corresponding to filename {path} and Etag {expected} no longer exists."
                    ),
                )
                .with_path(path)
                .with_retryable(false));
            }
            let body = resp.range_bytes(range).await?;
            Ok(Fetched {
                body,
                etag,
                version_id,
            })
        })
        .await
}

/// A single-GET read handle (the engine's parallel reader splits large
/// reads into calls of this one).
#[derive(Debug)]
pub(crate) struct RangeReader {
    st: Arc<State>,
    bucket: String,
    key: String,
    path: String,
    info: FileInfo,
    pin: Pin,
    extra: Option<Params>,
    hints: IoHints,
}

#[async_trait]
impl ReadHandle for RangeReader {
    fn info(&self) -> &FileInfo {
        &self.info
    }

    fn io_hints(&self) -> IoHints {
        self.hints
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        let size = self.info.size;
        let end = offset.saturating_add(len as u64).min(size);
        if offset >= end {
            return Ok(Bytes::new());
        }
        let mut out: Option<Bytes> = None;
        let mut pos = offset;
        let mut parts: Vec<Bytes> = Vec::new();
        // A server may answer a range with fewer bytes than asked; ask again
        // for the rest (bounded, to never spin on a broken server).
        for _ in 0..8 {
            let f = get_range(
                &self.st,
                &self.bucket,
                &self.key,
                ByteRange::Bounded { start: pos, end },
                &self.pin,
                self.extra.as_ref(),
                &self.path,
            )
            .await?;
            let got = f.body.data;
            if got.is_empty() {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    format!(
                        "object ended at {pos} bytes, but it had {size} bytes when it was opened"
                    ),
                )
                .with_path(&self.path));
            }
            pos += got.len() as u64;
            if pos >= end && parts.is_empty() {
                out = Some(got);
                break;
            }
            parts.push(got);
            if pos >= end {
                break;
            }
        }
        if let Some(o) = out {
            return Ok(o);
        }
        if pos < end {
            return Err(
                Error::protocol("server keeps returning short ranges").with_path(&self.path)
            );
        }
        let mut buf = Vec::with_capacity((end - offset) as usize);
        for p in parts {
            buf.extend_from_slice(&p);
        }
        Ok(Bytes::from(buf))
    }
}

/// An open S3 object for reading.
///
/// `read_at` calls up to 2 × `request_size` are one ranged GET; larger ones
/// are split into concurrent `request_size` GETs assembled in one buffer
/// (`fsfast_engine::read_parallel`), within the global memory budget.
#[derive(Debug, Clone)]
pub struct S3ReadHandle {
    inner: Arc<RangeReader>,
    budget: MemoryBudget,
}

impl S3ReadHandle {
    /// The object's ETag observed at open time.
    pub fn etag(&self) -> Option<&str> {
        self.inner.info.version.as_deref()
    }

    /// Whether reads are pinned (by ETag or version id).
    pub fn is_pinned(&self) -> bool {
        self.inner.pin != Pin::None
    }

    fn dyn_inner(&self) -> Arc<dyn ReadHandle> {
        self.inner.clone()
    }
}

#[async_trait]
impl ReadHandle for S3ReadHandle {
    fn info(&self) -> &FileInfo {
        &self.inner.info
    }

    fn io_hints(&self) -> IoHints {
        self.inner.hints
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        let hints = self.inner.hints;
        let part = hints.request_size.max(1);
        let size = self.inner.info.size;
        let end = offset.saturating_add(len as u64).min(size);
        if offset >= end {
            return Ok(Bytes::new());
        }
        if (end - offset) as usize <= part.saturating_mul(2) {
            return self.inner.read_at(offset, len).await;
        }
        read_parallel(
            &self.dyn_inner(),
            offset..end,
            part,
            hints.max_concurrency,
            Some(&self.budget),
        )
        .await
    }

    async fn read_ranges(&self, ranges: &[Range<u64>]) -> Result<Vec<Bytes>> {
        fsfast_core::read_ranges_coalesced(self, ranges).await
    }
}

impl S3FileSystem {
    pub(crate) async fn open_read_impl(
        &self,
        path: &str,
        opts: &ReadOptions,
    ) -> Result<S3ReadHandle> {
        let o = &self.inner.opts;
        let sp = split_path(path, o.version_aware);
        if sp.key.is_empty() {
            return Err(Error::invalid_input(format!(
                "Attempt to open non key-like path: {path}"
            )));
        }
        if opts.version.is_some() && !o.version_aware {
            return Err(Error::invalid_input(
                "version_id cannot be specified if the filesystem is not version aware",
            ));
        }
        let version = match (&opts.version, &sp.version_id) {
            (Some(a), Some(b)) if a != b => {
                return Err(Error::invalid_input(format!(
                    "Cannot coalesce version_ids where more than one are defined, {{{a:?}, {b:?}}}"
                )));
            }
            (Some(a), _) => Some(a.clone()),
            (None, b) => b.clone(),
        };
        let extra = if opts.extra.is_empty() {
            None
        } else {
            Some(Params::from_map(&opts.extra, "open")?)
        };
        let st = self.state().await?;
        let name = format!("{}/{}", sp.bucket, sp.key);
        let meta = self
            .head_object(
                &st,
                &sp.bucket,
                &sp.key,
                version.as_deref(),
                extra.as_ref(),
                &name,
            )
            .await?;
        let etag = meta.etag.clone().filter(|e| !e.is_empty());
        let pin = match (&version, opts.pin_version) {
            (Some(v), _) => Pin::Version(v.clone()),
            (None, false) => Pin::None,
            (None, true) => match (o.version_aware, &meta.version_id, &etag) {
                (true, Some(v), _) if v != "null" => Pin::Version(v.clone()),
                (_, _, Some(e)) if o.local_expiry_check => Pin::Local(e.clone()),
                (_, _, Some(e)) => Pin::IfMatch(e.clone()),
                _ => Pin::None,
            },
        };
        let mut hints = self.inner.hints;
        if let Some(b) = opts.block_size.filter(|b| *b > 0) {
            hints.request_size = b;
        }
        Ok(S3ReadHandle {
            inner: Arc::new(RangeReader {
                st: st.clone(),
                bucket: sp.bucket,
                key: sp.key,
                path: name.clone(),
                info: meta.to_info(name),
                pin,
                extra,
                hints,
            }),
            budget: st.budget.clone(),
        })
    }

    /// Fetch `[start, end)` (`end` `None`: to the end of the object) with a
    /// first GET of up to `request_size` bytes, then the rest concurrently,
    /// pinned to the first response's ETag (or version id).
    #[allow(clippy::too_many_arguments)]
    async fn fetch_window(
        &self,
        st: &Arc<State>,
        bucket: &str,
        key: &str,
        version: Option<&str>,
        start: u64,
        end: Option<u64>,
        extra: Option<&Params>,
        path: &str,
    ) -> Result<Bytes> {
        let part = self.inner.hints.request_size.max(1) as u64;
        let first_end = start.saturating_add(part).min(end.unwrap_or(u64::MAX));
        if first_end <= start {
            return Ok(Bytes::new());
        }
        let first_pin = match version {
            Some(v) => Pin::Version(v.to_owned()),
            None => Pin::None,
        };
        let first = get_range(
            st,
            bucket,
            key,
            ByteRange::Bounded {
                start,
                end: first_end,
            },
            &first_pin,
            extra,
            path,
        )
        .await?;
        let data = first.body.data;
        if !first.body.ranged {
            // The server ignored the range and sent the whole object, of
            // which only the first part was kept: ask for the whole window
            // (cut out of the full body while streaming).
            if (data.len() as u64) < first_end - start {
                return Ok(data);
            }
            let window = match end {
                Some(e) => ByteRange::Bounded { start, end: e },
                None => ByteRange::From(start),
            };
            return Ok(get_range(st, bucket, key, window, &first_pin, extra, path)
                .await?
                .body
                .data);
        }
        let Some(total) = first.body.total else {
            if (data.len() as u64) < first_end - start {
                // Fewer bytes than asked and no size: that was the end.
                return Ok(data);
            }
            // No total size (`bytes a-b/*`): read the rest in one request.
            let rest = get_range(
                st,
                bucket,
                key,
                match end {
                    Some(e) => ByteRange::Bounded {
                        start: first_end,
                        end: e,
                    },
                    None => ByteRange::From(first_end),
                },
                &match &first.etag {
                    Some(e) => Pin::IfMatch(e.clone()),
                    None => first_pin,
                },
                extra,
                path,
            )
            .await?;
            let mut buf = Vec::with_capacity(data.len() + rest.body.data.len());
            buf.extend_from_slice(&data);
            buf.extend_from_slice(&rest.body.data);
            return Ok(Bytes::from(buf));
        };
        let want_end = end.unwrap_or(total).min(total);
        if start + data.len() as u64 >= want_end {
            return Ok(data);
        }
        let pin = match (version, &first.version_id, &first.etag) {
            (Some(v), _, _) => Pin::Version(v.to_owned()),
            (None, Some(v), _) if self.inner.opts.version_aware && v != "null" => {
                Pin::Version(v.clone())
            }
            (None, _, Some(e)) if self.inner.opts.local_expiry_check => Pin::Local(e.clone()),
            (None, _, Some(e)) => Pin::IfMatch(e.clone()),
            _ => Pin::None,
        };
        let reader: Arc<dyn ReadHandle> = Arc::new(RangeReader {
            st: st.clone(),
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            path: path.to_owned(),
            info: FileInfo::file(path, total),
            pin,
            extra: extra.cloned(),
            hints: self.inner.hints,
        });
        let len = usize::try_from(want_end - start).map_err(|_| {
            Error::new(ErrorKind::Io, "object too large for memory").with_path(path)
        })?;
        let mut buf = Vec::new();
        buf.try_reserve_exact(len).map_err(|_| {
            Error::new(ErrorKind::Io, format!("cannot allocate {len} bytes")).with_path(path)
        })?;
        buf.extend_from_slice(&data);
        buf.resize(len, 0);
        let got = read_parallel_into(
            &reader,
            start + data.len() as u64,
            &mut buf[data.len()..],
            part as usize,
            self.inner.hints.max_concurrency,
            Some(&st.budget),
        )
        .await?;
        buf.truncate(data.len() + got);
        Ok(Bytes::from(buf))
    }

    pub(crate) async fn cat_file_impl(&self, path: &str, range: ByteRange) -> Result<Bytes> {
        self.cat_file_with(path, range, None).await
    }

    /// `cat_file` with per-call parameters (SSE-C key, `RequestPayer`, ...)
    /// on every GET.
    pub(crate) async fn cat_file_with(
        &self,
        path: &str,
        range: ByteRange,
        extra: Option<&Params>,
    ) -> Result<Bytes> {
        let sp = split_path(path, self.inner.opts.version_aware);
        if sp.key.is_empty() {
            return Err(Error::is_a_directory(path));
        }
        if range.is_empty() {
            return Ok(Bytes::new());
        }
        let st = self.state().await?;
        let name = format!("{}/{}", sp.bucket, sp.key);
        let version = sp.version_id.as_deref();
        match range {
            ByteRange::Full => {
                self.fetch_window(&st, &sp.bucket, &sp.key, version, 0, None, extra, &name)
                    .await
            }
            ByteRange::From(s) => {
                self.fetch_window(&st, &sp.bucket, &sp.key, version, s, None, extra, &name)
                    .await
            }
            ByteRange::Bounded { start, end } => {
                self.fetch_window(
                    &st,
                    &sp.bucket,
                    &sp.key,
                    version,
                    start,
                    Some(end),
                    extra,
                    &name,
                )
                .await
            }
            ByteRange::Suffix(_) => {
                let pin = match version {
                    Some(v) => Pin::Version(v.to_owned()),
                    None => Pin::None,
                };
                Ok(
                    get_range(&st, &sp.bucket, &sp.key, range, &pin, extra, &name)
                        .await?
                        .body
                        .data,
                )
            }
        }
    }

    pub(crate) async fn get_file_impl(&self, remote: &str, local: &Path) -> Result<()> {
        if tokio::fs::metadata(local).await.is_ok_and(|m| m.is_dir()) {
            // s3fs: downloading onto an existing directory does nothing.
            return Ok(());
        }
        let sp = split_path(remote, self.inner.opts.version_aware);
        if sp.key.is_empty() {
            return Err(Error::is_a_directory(remote));
        }
        let st = self.state().await?;
        let name = format!("{}/{}", sp.bucket, sp.key);
        let part = self.inner.hints.request_size.max(1) as u64;
        let first_pin = match &sp.version_id {
            Some(v) => Pin::Version(v.clone()),
            None => Pin::None,
        };
        let first = get_range(
            &st,
            &sp.bucket,
            &sp.key,
            ByteRange::Bounded {
                start: 0,
                end: part,
            },
            &first_pin,
            None,
            &name,
        )
        .await?;
        // A server that ignores ranges sent the whole object, of which
        // only the first part was kept: fetch it whole.
        let first = if !first.body.ranged && first.body.data.len() as u64 >= part {
            get_range(
                &st,
                &sp.bucket,
                &sp.key,
                ByteRange::Full,
                &first_pin,
                None,
                &name,
            )
            .await?
        } else {
            first
        };
        let res = async {
            let total = match (first.body.ranged, first.body.total) {
                (true, Some(t)) => t,
                _ => first.body.data.len() as u64,
            };
            let file = Arc::new(tokio::fs::File::create(local).await?.into_std().await);
            let first_data = first.body.data.clone();
            {
                let f = file.clone();
                blocking(move || {
                    // Preallocate (sparse) like s3fs, then write the first
                    // part.
                    f.set_len(total)?;
                    write_all_at(&f, 0, &first_data)
                })
                .await?;
            }
            let done = first.body.data.len() as u64;
            if done < total {
                let pin = match (&sp.version_id, &first.etag) {
                    (Some(v), _) => Pin::Version(v.clone()),
                    (None, Some(e)) if self.inner.opts.local_expiry_check => Pin::Local(e.clone()),
                    (None, Some(e)) => Pin::IfMatch(e.clone()),
                    _ => Pin::None,
                };
                let reader = RangeReader {
                    st: st.clone(),
                    bucket: sp.bucket.clone(),
                    key: sp.key.clone(),
                    path: name.clone(),
                    info: FileInfo::file(name.clone(), total),
                    pin,
                    extra: None,
                    hints: self.inner.hints,
                };
                let reader = &reader;
                // Parts are fetched concurrently and written at their offsets
                // as they arrive (positional writes on a blocking thread, the
                // network buffer moved, not copied): no part waits for a
                // slower one before it, and memory stays bounded by
                // concurrency x request_size.
                let futs: Vec<_> = fsfast_core::split_range(done..total, part)
                    .into_iter()
                    .map(|r| {
                        let f = file.clone();
                        let budget = &st.budget;
                        async move {
                            // Each in-flight part holds a request_size
                            // buffer until it is written: count it against
                            // the global budget like every other bulk read.
                            let len = (r.end - r.start) as usize;
                            let guard = budget.acquire(len).await;
                            let data = reader.read_at(r.start, len).await?;
                            blocking(move || write_all_at(&f, r.start, &data)).await?;
                            drop(guard);
                            Ok::<_, Error>(())
                        }
                    })
                    .collect();
                let mut s =
                    stream::iter(futs).buffer_unordered(self.inner.hints.max_concurrency.max(1));
                while let Some(r) = s.next().await {
                    r?;
                }
            }
            Ok::<_, Error>(())
        }
        .await;
        if res.is_err() {
            let _ = tokio::fs::remove_file(local).await;
        }
        res
    }
}

/// Run blocking file I/O on tokio's blocking pool.
async fn blocking<F>(f: F) -> Result<()>
where
    F: FnOnce() -> std::io::Result<()> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("file task failed: {e}")))?
        .map_err(Error::from)
}

/// Write all of `data` at `offset` (positional: concurrent writers of one
/// file do not interfere).
fn write_all_at(f: &std::fs::File, offset: u64, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        f.write_all_at(data, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0;
        while done < data.len() {
            let n = f.seek_write(&data[done..], offset + done as u64)?;
            if n == 0 {
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            done += n;
        }
        Ok(())
    }
}
