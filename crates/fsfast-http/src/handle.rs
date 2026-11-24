//! Read handles.
//!
//! A handle reads with ranged GETs when the size is known and the server did
//! not refuse ranges (`Accept-Ranges: none`). Reads are pinned with
//! `If-Match` when the server gave a *strong* `ETag` (weak validators never
//! match `If-Match`), so a concurrent overwrite surfaces as
//! `PreconditionFailed` instead of mixed bytes; the `Content-Range` total is
//! checked as well, which also catches changes on servers without ETags.
//!
//! Without range support, or when a server answers a ranged GET with the
//! whole representation (200), the handle downloads the file once and serves
//! every read from that copy. Concurrent readers share the single download.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::{Bytes, BytesMut};
use fsfast_core::{
    ByteRange, Error, ErrorKind, FileInfo, IoHints, ReadHandle, Result, async_trait,
};
use fsfast_http_transport::header::{HeaderValue, IF_MATCH};
use fsfast_http_transport::{HttpClient, Request, Response};
use tokio::sync::OnceCell;

/// What one ranged attempt produced.
enum Got {
    Part(Bytes),
    Whole(Bytes),
}

/// An open HTTP(S) file.
pub struct HttpReadHandle {
    client: HttpClient,
    url: Arc<str>,
    info: FileInfo,
    /// `If-Match` value (a strong ETag) when reads are pinned.
    pin: Option<HeaderValue>,
    /// Treat a changed `Content-Range` total as `PreconditionFailed`.
    check_total: bool,
    hints: IoHints,
    /// Ranged GETs are used while this holds.
    ranged: AtomicBool,
    whole: OnceCell<Bytes>,
}

impl fmt::Debug for HttpReadHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpReadHandle")
            .field("url", &crate::log_url(&self.url))
            .field("size", &self.info.size)
            .field("pinned", &self.pin.is_some())
            .field("ranged", &self.ranged.load(Ordering::Relaxed))
            .field("downloaded", &self.whole.initialized())
            .finish()
    }
}

impl HttpReadHandle {
    /// A handle reading `info.size` bytes of `url`. `etag` pins reads when it
    /// is a strong validator and `pin` is set; `ranged == false` makes the
    /// first read download the whole file.
    pub(crate) fn new(
        client: HttpClient,
        url: Arc<str>,
        info: FileInfo,
        etag: Option<&str>,
        pin: bool,
        ranged: bool,
        hints: IoHints,
    ) -> Self {
        let pin_value = etag
            .filter(|e| pin && crate::info::is_strong_etag(e))
            .and_then(|e| HeaderValue::try_from(e).ok());
        HttpReadHandle {
            client,
            url,
            info,
            pin: pin_value,
            check_total: pin,
            hints,
            ranged: AtomicBool::new(ranged),
            whole: OnceCell::new(),
        }
    }

    /// A handle over content that has already been downloaded.
    pub(crate) fn from_bytes(
        client: HttpClient,
        url: Arc<str>,
        info: FileInfo,
        data: Bytes,
        hints: IoHints,
    ) -> Self {
        HttpReadHandle {
            client,
            url,
            info,
            pin: None,
            check_total: false,
            hints,
            ranged: AtomicBool::new(false),
            whole: OnceCell::new_with(Some(data)),
        }
    }

    /// Whether reads carry `If-Match`.
    pub fn is_pinned(&self) -> bool {
        self.pin.is_some()
    }

    /// Whether reads still use ranged GETs (false once the handle fell back
    /// to a full download).
    pub fn is_ranged(&self) -> bool {
        self.ranged.load(Ordering::Acquire) && !self.whole.initialized()
    }

    fn request(&self) -> Result<Request> {
        let mut req = Request::get(&self.url)?.path(&*self.url);
        if let Some(p) = &self.pin {
            req = req.header(IF_MATCH, p.clone());
        }
        Ok(req)
    }

    fn changed(&self, what: impl fmt::Display) -> Error {
        Error::new(
            ErrorKind::PreconditionFailed,
            format!("file changed since it was opened: {what}"),
        )
        .with_path(&*self.url)
    }

    /// Verify a full body: right size and, when pinned, the same ETag.
    fn check_whole(&self, data: &Bytes, etag: Option<&str>) -> Result<()> {
        if data.len() as u64 != self.info.size {
            return Err(self.changed(format_args!(
                "size {} is now {}",
                self.info.size,
                data.len()
            )));
        }
        if let (Some(pin), Some(etag)) = (&self.pin, etag)
            && pin.as_bytes() != etag.as_bytes()
        {
            return Err(self.changed(format_args!("ETag is now {etag}")));
        }
        Ok(())
    }

    /// Take a 200 answer to a ranged GET as the whole file.
    async fn adopt_whole(&self, resp: Response) -> Result<Bytes> {
        self.ranged.store(false, Ordering::Release);
        tracing::debug!(
            url = %crate::log_url(&self.url),
            "server ignored Range; using one full download"
        );
        let data = self
            .whole
            .get_or_try_init(|| async move {
                let etag = resp.etag().map(str::to_owned);
                let data = resp.bytes().await?;
                self.check_whole(&data, etag.as_deref())?;
                Ok::<_, Error>(data)
            })
            .await?;
        Ok(data.clone())
    }

    /// The whole file, downloaded once and shared by all readers.
    async fn whole(&self) -> Result<Bytes> {
        let data = self
            .whole
            .get_or_try_init(|| async {
                let req = self.request()?;
                self.client
                    .send_with(req, |resp| async move {
                        let etag = resp.etag().map(str::to_owned);
                        let data = resp.bytes().await?;
                        self.check_whole(&data, etag.as_deref())?;
                        Ok(data)
                    })
                    .await
            })
            .await?;
        Ok(data.clone())
    }

    async fn read_range(&self, start: u64, end: u64) -> Result<Bytes> {
        let mut parts: Vec<Bytes> = Vec::new();
        let mut pos = start;
        while pos < end {
            let r = ByteRange::Bounded { start: pos, end };
            let req = self.request()?.range(r);
            let got = self
                .client
                .send_with(req, |resp| async move {
                    match resp.status().as_u16() {
                        416 => {
                            Err(self
                                .changed(format_args!("it is now shorter than {} bytes", pos + 1)))
                        }
                        206 => {
                            let body = resp.range_bytes(r).await?;
                            if self.check_total
                                && let Some(t) = body.total
                                && t != self.info.size
                            {
                                return Err(self
                                    .changed(format_args!("size {} is now {t}", self.info.size)));
                            }
                            Ok(Got::Part(body.data))
                        }
                        _ => Ok(Got::Whole(self.adopt_whole(resp).await?)),
                    }
                })
                .await?;
            match got {
                Got::Whole(all) => return Ok(all.slice(start as usize..end as usize)),
                Got::Part(data) if data.is_empty() => {
                    return Err(Error::protocol(format!(
                        "server returned no data for bytes {pos}-{}",
                        end - 1
                    ))
                    .with_path(&*self.url));
                }
                Got::Part(data) => {
                    pos += data.len() as u64;
                    parts.push(data);
                }
            }
        }
        Ok(match parts.len() {
            1 => parts.pop().unwrap_or_default(),
            _ => {
                let mut buf = BytesMut::with_capacity((end - start) as usize);
                for p in &parts {
                    buf.extend_from_slice(p);
                }
                buf.freeze()
            }
        })
    }
}

#[async_trait]
impl ReadHandle for HttpReadHandle {
    fn info(&self) -> &FileInfo {
        &self.info
    }

    fn io_hints(&self) -> IoHints {
        self.hints
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        let size = self.info.size;
        if len == 0 || offset >= size {
            return Ok(Bytes::new());
        }
        let end = offset.saturating_add(len as u64).min(size);
        let slice = |all: &Bytes| all.slice(offset as usize..end as usize);
        if let Some(all) = self.whole.get() {
            return Ok(slice(all));
        }
        if !self.ranged.load(Ordering::Acquire) {
            return Ok(slice(&self.whole().await?));
        }
        self.read_range(offset, end).await
    }
}
