//! Reads: pinned ranged GETs (`x-ms-range` + `If-Match` on the ETag, or
//! `versionid` on version-aware filesystems), parallel ranged GETs for large
//! reads, and `cat_file` without a metadata request first.
//!
//! * A read handle opens with `Get Blob Properties` and pins every GET to
//!   the ETag it saw, so a blob overwritten while it is read fails with
//!   `PreconditionFailed` (`ConditionNotMet`) instead of mixing versions.
//! * `cat_file` starts with one ranged GET of the first `request_size`
//!   bytes: small blobs are done in that single request; the `Content-Range`
//!   total and the ETag of larger ones drive further parts fetched
//!   concurrently, pinned to that ETag.
//! * Ranges use `x-ms-range` (signed as a canonical header) and an
//!   unsatisfiable range (416 `InvalidRange`, e.g. any range of an empty
//!   blob) reads as empty.

use std::ops::Range;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use fsfast_core::{
    ByteRange, Error, ErrorKind, FileInfo, IoHints, ReadHandle, ReadOptions, Result,
};
use fsfast_engine::parallel::{read_parallel, read_parallel_into};
use fsfast_engine::stats::OpKind;
use fsfast_http_transport::header::{HeaderName, HeaderValue, IF_MATCH};
use fsfast_http_transport::{Method, RangeBody};

use crate::client::Query;
use crate::info::BlobProps;
use crate::path::split_path;
use crate::{AzureBlobFileSystem, Shared};
use fsfast_core::FileSystem as _;

/// How a handle's reads are tied to the blob version it opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Pin {
    /// No pinning.
    None,
    /// `If-Match: <etag>`.
    IfMatch(String),
    /// `?versionid=<id>`.
    Version(String),
}

/// The response to one ranged GET.
pub(crate) struct Fetched {
    pub body: RangeBody,
    /// Blob properties from the response headers (`None` for 416).
    pub props: Option<BlobProps>,
}

/// `bytes=start-end` (inclusive) for `x-ms-range`.
fn range_header(range: ByteRange) -> Option<String> {
    match range {
        ByteRange::Full => None,
        ByteRange::Bounded { start, end } if end > start => {
            Some(format!("bytes={start}-{}", end - 1))
        }
        ByteRange::Bounded { start, .. } => Some(format!("bytes={start}-{start}")),
        ByteRange::From(s) => Some(format!("bytes={s}-")),
        // The Blob service has no suffix ranges; callers resolve them.
        ByteRange::Suffix(_) => None,
    }
}

/// `bytes a-b/total` → `(a, b, total)`.
fn parse_cr(v: &str) -> Option<(u64, u64, u64)> {
    let rest = v.trim().strip_prefix("bytes ")?;
    let (range, total) = rest.split_once('/')?;
    let (a, b) = range.split_once('-')?;
    Some((
        a.trim().parse().ok()?,
        b.trim().parse().ok()?,
        total.trim().parse().ok()?,
    ))
}

/// One ranged GET of `container/blob`.
pub(crate) async fn get_range(
    sh: &Shared,
    container: &str,
    blob: &str,
    range: ByteRange,
    pin: &Pin,
    path: &str,
) -> Result<Fetched> {
    let version = match pin {
        Pin::Version(v) => Some(v.as_str()),
        _ => None,
    };
    let q = Query::new().with_opt("versionid", version);
    let mut req = sh
        .client
        .request(Method::GET, &sh.client.blob_url(container, blob), &q)?
        .op(OpKind::Read)
        .path(path.to_owned());
    if let Some(h) = range_header(range) {
        req = req
            .header(
                HeaderName::from_static("x-ms-range"),
                HeaderValue::from_str(&h).expect("digits are a valid header value"),
            )
            .allow_status(416);
    }
    if let Pin::IfMatch(e) = pin {
        req = req.header(
            IF_MATCH,
            HeaderValue::from_str(e).map_err(|_| Error::protocol("invalid ETag"))?,
        );
    }
    let name = blob.to_owned();
    sh.client
        .execute(req, |resp| {
            let name = name.clone();
            async move {
                let props = if resp.status().as_u16() == 416 {
                    None
                } else {
                    Some(BlobProps::from_headers(&name, resp.headers())?)
                };
                // Azurite answers a range starting at the end with an empty
                // 206 and `Content-Range: bytes N-(N-1)/N` (the service sends
                // 416); read it as empty.
                if let Some((s, e, total)) = resp.header_str("content-range").and_then(parse_cr)
                    && e < s
                {
                    let offset = s.min(total);
                    return Ok(Fetched {
                        body: RangeBody {
                            data: Bytes::new(),
                            offset,
                            total: Some(total),
                            ranged: true,
                        },
                        props,
                    });
                }
                let body = resp.range_bytes(range).await?;
                Ok(Fetched { body, props })
            }
        })
        .await
}

/// Pinned single-request reads (the engine's parallel reader splits large
/// reads into calls of this).
#[derive(Debug)]
pub(crate) struct BlobReader {
    sh: Arc<Shared>,
    container: String,
    blob: String,
    path: String,
    info: FileInfo,
    pin: Pin,
    hints: IoHints,
}

#[async_trait]
impl ReadHandle for BlobReader {
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
        let mut pos = offset;
        let mut parts: Vec<Bytes> = Vec::new();
        // A server may answer with fewer bytes than asked; ask for the rest
        // (bounded, to never spin on a broken server).
        for _ in 0..8 {
            let f = get_range(
                &self.sh,
                &self.container,
                &self.blob,
                ByteRange::Bounded { start: pos, end },
                &self.pin,
                &self.path,
            )
            .await?;
            let got = f.body.data;
            if got.is_empty() {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    format!(
                        "blob ended at {pos} bytes, but it had {size} bytes when it was opened"
                    ),
                )
                .with_path(&self.path));
            }
            pos += got.len() as u64;
            if pos >= end && parts.is_empty() {
                return Ok(got);
            }
            parts.push(got);
            if pos >= end {
                break;
            }
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

/// An open blob for reading: reads up to 2 × `request_size` are one ranged
/// GET, larger ones are split into `request_size` parts fetched
/// concurrently (within the memory budget).
#[derive(Debug, Clone)]
pub struct AzureReadHandle {
    inner: Arc<BlobReader>,
}

impl AzureReadHandle {
    fn dyn_inner(&self) -> Arc<dyn ReadHandle> {
        self.inner.clone()
    }

    /// The ETag reads are pinned to, if any.
    pub fn pinned_etag(&self) -> Option<&str> {
        match &self.inner.pin {
            Pin::IfMatch(e) => Some(e),
            _ => None,
        }
    }
}

#[async_trait]
impl ReadHandle for AzureReadHandle {
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
            Some(&self.inner.sh.budget),
        )
        .await
    }

    async fn read_ranges(&self, ranges: &[Range<u64>]) -> Result<Vec<Bytes>> {
        fsfast_core::read_ranges_coalesced(self, ranges).await
    }
}

impl AzureBlobFileSystem {
    /// Resolve the version to read: explicit, from the path, or none.
    fn read_version<'a>(
        &self,
        path_version: Option<&'a str>,
        opts: &'a ReadOptions,
    ) -> Result<Option<&'a str>> {
        let explicit = opts.version.as_deref();
        if explicit.is_some() && !self.sh.cfg.version_aware {
            return Err(Error::invalid_input(
                "version_id cannot be specified if the filesystem is not version aware",
            ));
        }
        match (explicit, path_version) {
            (Some(a), Some(b)) if a != b => Err(Error::invalid_input(format!(
                "Cannot coalesce version_ids where more than one are defined, {{'{a}', '{b}'}}"
            ))),
            (Some(a), _) => Ok(Some(a)),
            (None, b) => Ok(b),
        }
    }

    pub(crate) async fn open_read_impl(
        &self,
        path: &str,
        opts: &ReadOptions,
    ) -> Result<AzureReadHandle> {
        if !opts.extra.is_empty() {
            let keys: Vec<_> = opts.extra.keys().cloned().collect();
            return Err(Error::invalid_input(format!(
                "abfs: unsupported read option(s): {}",
                keys.join(", ")
            )));
        }
        let p = split_path(path, self.sh.cfg.version_aware);
        let full = p.full();
        if p.blob.is_empty() {
            return Err(Error::is_a_directory(full));
        }
        let version = self.read_version(p.version_id, opts)?;
        let props = match self.head_blob(p.container, p.blob, version, &full).await {
            Ok(props) => props,
            Err(e) if e.kind() == ErrorKind::NotFound && version.is_none() => {
                if self.dir_exists(p.container, p.blob, &full).await? {
                    return Err(Error::is_a_directory(full));
                }
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        if props.is_dir_marker() {
            return Err(Error::is_a_directory(full));
        }
        let pin = match (version, &props.etag) {
            (Some(v), _) => Pin::Version(v.to_owned()),
            (None, Some(e)) if opts.pin_version => Pin::IfMatch(e.clone()),
            _ => Pin::None,
        };
        let mut hints = self.io_hints();
        if let Some(b) = opts.block_size {
            hints.request_size = b.max(1);
        }
        let info = props.to_info(p.container, self.sh.cfg.version_aware);
        Ok(AzureReadHandle {
            inner: Arc::new(BlobReader {
                sh: self.sh.clone(),
                container: p.container.to_owned(),
                blob: p.blob.to_owned(),
                path: full,
                info,
                pin,
                hints,
            }),
        })
    }

    /// `cat_file` without a metadata request: one ranged GET of the first
    /// part, then the rest in parallel, pinned to the first response's ETag.
    pub(crate) async fn cat_file_impl(&self, path: &str, range: ByteRange) -> Result<Bytes> {
        let p = split_path(path, self.sh.cfg.version_aware);
        let full = p.full();
        if p.blob.is_empty() {
            return Err(Error::is_a_directory(full));
        }
        if range.is_empty() {
            return Ok(Bytes::new());
        }
        let (start, end) = match range {
            ByteRange::Full => (0, None),
            ByteRange::From(s) => (s, None),
            ByteRange::Bounded { start, end } => (start, Some(end)),
            ByteRange::Suffix(_) => {
                // Needs the size first.
                let h = self.open_read_impl(path, &ReadOptions::default()).await?;
                let r = range.resolve(h.size());
                return h.read_at(r.start, (r.end - r.start) as usize).await;
            }
        };
        let part = self.sh.cfg.request_size as u64;
        let first_end = match end {
            Some(e) if e - start <= part * 2 => e,
            _ => start + part,
        };
        let pin = match p.version_id {
            Some(v) => Pin::Version(v.to_owned()),
            None => Pin::None,
        };
        let f = get_range(
            &self.sh,
            p.container,
            p.blob,
            ByteRange::Bounded {
                start,
                end: first_end,
            },
            &pin,
            &full,
        )
        .await?;
        let Some(props) = f.props else {
            // 416: the range starts at or beyond the end.
            return Ok(Bytes::new());
        };
        let total = props.size;
        let want_end = end.unwrap_or(total).min(total);
        let got = f.body.data;
        let have_end = start + got.len() as u64;
        if have_end >= want_end || got.is_empty() {
            let keep = (want_end.saturating_sub(start) as usize).min(got.len());
            return Ok(got.slice(..keep));
        }
        // Fetch the rest concurrently, pinned to the ETag just seen.
        let pin = match (&pin, &props.etag) {
            (Pin::Version(_), _) => pin.clone(),
            (_, Some(e)) => Pin::IfMatch(e.clone()),
            _ => Pin::None,
        };
        let hints = self.io_hints();
        let reader: Arc<dyn ReadHandle> = Arc::new(BlobReader {
            sh: self.sh.clone(),
            container: p.container.to_owned(),
            blob: p.blob.to_owned(),
            path: full,
            info: props.to_info(p.container, self.sh.cfg.version_aware),
            pin,
            hints,
        });
        let len = (want_end - start) as usize;
        // One buffer for the whole result: the first part is copied in, the
        // remaining parts are written straight into place.
        let mut buf = vec![0u8; len];
        buf[..got.len()].copy_from_slice(&got);
        let n = read_parallel_into(
            &reader,
            have_end,
            &mut buf[got.len()..],
            hints.request_size.max(1),
            hints.max_concurrency,
            Some(&self.sh.budget),
        )
        .await?;
        buf.truncate(got.len() + n);
        Ok(Bytes::from(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_headers() {
        assert_eq!(
            range_header(ByteRange::Bounded { start: 0, end: 10 }).as_deref(),
            Some("bytes=0-9")
        );
        assert_eq!(
            range_header(ByteRange::From(5)).as_deref(),
            Some("bytes=5-")
        );
        assert_eq!(range_header(ByteRange::Full), None);
    }
}
