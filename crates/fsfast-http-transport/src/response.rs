//! Responses: status/headers access and efficient body collection.
//!
//! * [`Response::bytes`] collects a body with at most one copy: a body that
//!   arrives in a single chunk is returned as is; with a known
//!   `Content-Length` the chunks are copied into one pre-sized buffer;
//!   otherwise they are gathered and concatenated once at the end (no
//!   repeated regrowth).
//! * [`Response::range_bytes`] returns exactly the bytes of a requested range
//!   whether the server answered 206, 200 (range ignored: the window is cut
//!   out while streaming, and the connection is dropped as soon as the
//!   window is complete) or 416.
//! * [`Response::into_stream`] streams large bodies.
//!
//! A response holds its host's concurrency permit until the body has been
//! collected (so the limit reflects busy connections), except for
//! [`Response::into_stream`], which releases it immediately: a long-lived
//! stream must not starve other requests to the same host.

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use fsfast_core::{ByteRange, Error, ErrorKind, Result};
use fsfast_engine::aimd::AimdPermit;
use fsfast_engine::stats::Stats;
use futures::stream::BoxStream;
use futures::{Future, Stream, StreamExt};
use reqwest::header::{AsHeaderName, ETAG, HeaderMap};
use reqwest::{Method, StatusCode, Url};
use tokio::time::{Instant, Sleep};

use crate::error::from_reqwest;
use crate::idle::Elapsed;
use crate::range::{self, ContentRange, RangeReply};

/// A response whose status was accepted (below 400, or explicitly allowed).
pub struct Response {
    inner: reqwest::Response,
    permit: Option<AimdPermit>,
    stats: Arc<Stats>,
    path: Arc<str>,
    method: Method,
    /// Longest wait for the next body chunk.
    read_timeout: Option<Duration>,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.inner.status())
            .field("version", &self.inner.version())
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// The bytes of a requested range, see [`Response::range_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeBody {
    /// The bytes; shorter than requested at the end of the representation, or
    /// when a server sent fewer bytes than asked (callers loop if needed).
    pub data: Bytes,
    /// Absolute offset of `data[0]` in the representation.
    pub offset: u64,
    /// Size of the whole representation, if the server stated it.
    pub total: Option<u64>,
    /// Whether the server honoured the range (206/416) rather than sending
    /// the whole representation (200).
    pub ranged: bool,
}

impl Response {
    pub(crate) fn new(
        inner: reqwest::Response,
        permit: AimdPermit,
        stats: Arc<Stats>,
        path: Arc<str>,
        method: Method,
        read_timeout: Option<Duration>,
    ) -> Self {
        Response {
            inner,
            permit: Some(permit),
            stats,
            path,
            method,
            read_timeout,
        }
    }

    /// The status code.
    pub fn status(&self) -> StatusCode {
        self.inner.status()
    }

    /// The response headers.
    pub fn headers(&self) -> &HeaderMap {
        self.inner.headers()
    }

    /// The final URL, after redirects.
    pub fn url(&self) -> &Url {
        self.inner.url()
    }

    /// The HTTP version spoken.
    pub fn version(&self) -> reqwest::Version {
        self.inner.version()
    }

    /// The fsfast path errors from this response report.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// A header value as text (`None` if absent or not visible ASCII).
    pub fn header_str(&self, name: impl AsHeaderName) -> Option<&str> {
        self.inner.headers().get(name).and_then(|v| v.to_str().ok())
    }

    /// `Content-Length` from the header (also meaningful for HEAD responses).
    pub fn content_length(&self) -> Option<u64> {
        range::content_length(self.inner.headers())
    }

    /// The parsed `Content-Range` header.
    pub fn content_range(&self) -> Option<ContentRange> {
        range::content_range(self.inner.headers())
    }

    /// The `ETag` header.
    pub fn etag(&self) -> Option<&str> {
        self.header_str(ETAG)
    }

    /// Bytes the body will carry. fsfast never decompresses, so
    /// `Content-Length` is exact even with a content coding.
    fn body_len_hint(&self) -> Option<u64> {
        if self.method == Method::HEAD || matches!(self.inner.status().as_u16(), 204 | 304) {
            return None;
        }
        self.content_length()
    }

    /// Report the outcome to the concurrency limiter and release the permit.
    fn finish(&mut self, err: Option<&Error>) {
        if let Some(p) = self.permit.take() {
            match err {
                None => p.success(),
                Some(e) if matches!(e.kind(), ErrorKind::Timeout | ErrorKind::Throttled) => {
                    p.throttled()
                }
                Some(_) => p.dropped(),
            }
        }
    }

    /// The next chunk of the body, `None` at the end. Fails with `Timeout`
    /// when no data arrives within the client's `read_timeout`.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>> {
        let next = match self.read_timeout {
            None => self.inner.chunk().await,
            Some(t) => match tokio::time::timeout(t, self.inner.chunk()).await {
                Ok(next) => next,
                Err(_) => {
                    let err = Elapsed(t).into_error("reading the response body", &self.path);
                    self.finish(Some(&err));
                    return Err(err);
                }
            },
        };
        match next {
            Ok(Some(c)) => {
                self.stats.add_bytes_read(c.len() as u64);
                Ok(Some(c))
            }
            Ok(None) => {
                self.finish(None);
                Ok(None)
            }
            Err(e) => {
                let err = from_reqwest(e, &self.path);
                self.finish(Some(&err));
                Err(err)
            }
        }
    }

    /// Collect the whole body (see the module docs for the copy strategy).
    pub async fn bytes(mut self) -> Result<Bytes> {
        let hint = self.body_len_hint();
        let Some(first) = self.chunk().await? else {
            return Ok(Bytes::new());
        };
        if hint == Some(first.len() as u64) {
            // Whole body in one chunk: no copy. Drain the (empty) end so the
            // connection goes back to the pool and the permit is released.
            self.finish_drain().await?;
            return Ok(first);
        }
        let Some(second) = self.chunk().await? else {
            return Ok(first);
        };
        match hint {
            Some(len) => {
                let mut buf = presized(len, &self.path)?;
                buf.extend_from_slice(&first);
                buf.extend_from_slice(&second);
                while let Some(c) = self.chunk().await? {
                    buf.extend_from_slice(&c);
                }
                Ok(Bytes::from(buf))
            }
            None => {
                let mut parts = vec![first, second];
                while let Some(c) = self.chunk().await? {
                    parts.push(c);
                }
                Ok(concat(&parts))
            }
        }
    }

    /// Read past the end of a body whose bytes have all been received.
    async fn finish_drain(&mut self) -> Result<()> {
        while let Some(c) = self.chunk().await? {
            if !c.is_empty() {
                return Err(Error::protocol("response body longer than Content-Length")
                    .with_path(&*self.path));
            }
        }
        Ok(())
    }

    /// Collect at most `limit` bytes of the body; the rest is not read (the
    /// connection is then closed instead of reused).
    pub async fn bytes_truncated(self, limit: usize) -> Result<Bytes> {
        self.bytes_window(0, Some(limit as u64)).await
    }

    /// Skip `skip` bytes of the body and collect the next `take` bytes (all
    /// remaining bytes for `None`). Stops reading as soon as the window is
    /// complete.
    pub async fn bytes_window(mut self, skip: u64, take: Option<u64>) -> Result<Bytes> {
        if skip == 0 && take.is_none() {
            return self.bytes().await;
        }
        if take == Some(0) {
            return Ok(Bytes::new());
        }
        let mut to_skip = skip;
        let mut parts: Vec<Bytes> = Vec::new();
        let mut got = 0u64;
        while let Some(mut c) = self.chunk().await? {
            if to_skip > 0 {
                let n = to_skip.min(c.len() as u64);
                to_skip -= n;
                c = c.slice(n as usize..);
                if c.is_empty() {
                    continue;
                }
            }
            if let Some(t) = take {
                let left = t - got;
                if (c.len() as u64) >= left {
                    parts.push(c.slice(..left as usize));
                    break;
                }
            }
            got += c.len() as u64;
            parts.push(c);
        }
        // When the window completed before the end of the body, release the
        // permit now; dropping the response then closes the connection.
        self.finish(None);
        Ok(match parts.len() {
            0 => Bytes::new(),
            1 => parts.pop().unwrap_or_default(),
            _ => concat(&parts),
        })
    }

    /// The bytes `requested` selects, from the response to a GET that carried
    /// `Range: requested` (see [`Request::range`](crate::Request::range)).
    ///
    /// * 206: the body is validated against `Content-Range` and sliced to the
    ///   requested window (servers may return a larger range).
    /// * 200: the server ignored the range; the window is cut out of the full
    ///   body while streaming, without buffering what precedes it.
    /// * 416: the range starts at or beyond the end: empty.
    pub async fn range_bytes(self, requested: ByteRange) -> Result<RangeBody> {
        let reply = range::classify_range_response(self.status(), self.headers(), requested)
            .map_err(|e| e.with_path(&*self.path))?;
        match reply {
            RangeReply::NotSatisfiable { total } => {
                let offset = range::requested_window(requested, total).map_or(0, |w| w.start);
                Ok(RangeBody {
                    data: Bytes::new(),
                    offset,
                    total,
                    ranged: true,
                })
            }
            RangeReply::Partial { start, len, total } => {
                let path = self.path.clone();
                let body = self.bytes().await?;
                if len.is_some_and(|l| l != body.len() as u64) {
                    return Err(Error::protocol(format!(
                        "206 body has {} bytes but Content-Range announced {}",
                        body.len(),
                        len.unwrap_or(0)
                    ))
                    .with_path(&*path));
                }
                let served = start..start + body.len() as u64;
                let wanted = range::requested_window(requested, total).unwrap_or(served.clone());
                if wanted.start < served.start
                    || (wanted.start > served.end)
                    || (wanted.start == served.end && wanted.end > wanted.start && !body.is_empty())
                {
                    return Err(Error::protocol(format!(
                        "server returned bytes {}..{} for a request of {:?}",
                        served.start, served.end, requested
                    ))
                    .with_path(&*path));
                }
                let lo = (wanted.start - served.start) as usize;
                let hi = (wanted.end.min(served.end) - served.start) as usize;
                Ok(RangeBody {
                    data: body.slice(lo..hi.max(lo)),
                    offset: wanted.start,
                    total,
                    ranged: true,
                })
            }
            RangeReply::Full { total } => {
                let (skip, take) = match requested {
                    ByteRange::Full => (0, None),
                    ByteRange::Bounded { start, end } => (start, Some(end.saturating_sub(start))),
                    ByteRange::From(s) => (s, None),
                    ByteRange::Suffix(n) => match total {
                        Some(t) => (t.saturating_sub(n), None),
                        None => {
                            // Unknown size: keep the tail while streaming.
                            let body = self.bytes().await?;
                            let keep = (n as usize).min(body.len());
                            let offset = (body.len() - keep) as u64;
                            return Ok(RangeBody {
                                data: body.slice(body.len() - keep..),
                                offset,
                                total: Some(body.len() as u64),
                                ranged: false,
                            });
                        }
                    },
                };
                let data = self.bytes_window(skip, take).await?;
                Ok(RangeBody {
                    data,
                    offset: skip,
                    total,
                    ranged: false,
                })
            }
        }
    }

    /// Stream the body. Releases the host's concurrency permit right away.
    /// The stream fails with `Timeout` when no data arrives within the
    /// client's `read_timeout`.
    pub fn into_stream(mut self) -> BodyStream {
        self.finish(None);
        let path = self.path.clone();
        let stats = self.stats.clone();
        let idle = self
            .read_timeout
            .map(|t| (t, Box::pin(tokio::time::sleep(t))));
        BodyStream {
            inner: self.inner.bytes_stream().boxed(),
            stats,
            path,
            idle,
            done: false,
        }
    }
}

/// A buffer of exactly `len` bytes capacity, failing cleanly (instead of
/// aborting) when a bogus `Content-Length` asks for more memory than exists.
/// A `Vec` converts into `Bytes` without copying.
fn presized(len: u64, path: &str) -> Result<Vec<u8>> {
    let n = usize::try_from(len).map_err(|_| {
        Error::new(
            ErrorKind::Io,
            format!("response of {len} bytes does not fit in memory"),
        )
        .with_path(path)
    })?;
    let mut v: Vec<u8> = Vec::new();
    v.try_reserve_exact(n).map_err(|_| {
        Error::new(
            ErrorKind::Io,
            format!("cannot allocate {len} bytes for the response"),
        )
        .with_path(path)
    })?;
    Ok(v)
}

fn concat(parts: &[Bytes]) -> Bytes {
    let total: usize = parts.iter().map(Bytes::len).sum();
    let mut buf = BytesMut::with_capacity(total);
    for p in parts {
        buf.extend_from_slice(p);
    }
    buf.freeze()
}

/// A response body as a stream of chunks, see [`Response::into_stream`].
pub struct BodyStream {
    inner: BoxStream<'static, reqwest::Result<Bytes>>,
    stats: Arc<Stats>,
    path: Arc<str>,
    /// The read timeout and the timer of the current wait.
    idle: Option<(Duration, Pin<Box<Sleep>>)>,
    /// Ended (by a timeout): yields nothing more.
    done: bool,
}

impl fmt::Debug for BodyStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyStream")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Stream for BodyStream {
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        let this = &mut *self;
        match this.inner.poll_next_unpin(cx) {
            Poll::Pending => {
                // Only a wait for the server counts: a consumer that polls
                // late finds the data buffered and never times out.
                if let Some((t, timer)) = this.idle.as_mut()
                    && timer.as_mut().poll(cx).is_ready()
                {
                    let t = *t;
                    this.done = true;
                    return Poll::Ready(Some(Err(
                        Elapsed(t).into_error("reading the response body", &this.path)
                    )));
                }
                Poll::Pending
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Ok(c))) => {
                if let Some((t, timer)) = this.idle.as_mut() {
                    timer.as_mut().reset(Instant::now() + *t);
                }
                this.stats.add_bytes_read(c.len() as u64);
                Poll::Ready(Some(Ok(c)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(from_reqwest(e, &this.path)))),
        }
    }
}
