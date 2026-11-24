//! Requests and request bodies.

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use fsfast_core::{ByteRange, Error, ErrorKind, Result};
use fsfast_engine::stats::{OpKind, Stats};
use futures::stream::BoxStream;
use futures::{StreamExt, TryStreamExt};
use parking_lot::Mutex;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, RANGE};
use reqwest::{Method, Url};

use crate::error::ErrorParser;
use crate::idle::{self, Activity, Tracked};

/// Read size used when streaming a local file as a request body.
const FILE_CHUNK: usize = 1 << 20;

/// In-memory bodies up to this size go to reqwest as one reusable buffer,
/// which its redirect logic can resend on 307/308. Larger ones are fed in
/// slices (still without copies) so that the read timeout sees their
/// progress: only a stream body makes upload progress observable, and a
/// stream cannot be resent, so a redirect is then returned to the caller.
/// 16 MiB leave the client within the default read timeout above ~140 kB/s.
const REUSABLE_BYTES_MAX: usize = 16 << 20;

type OneShot = Arc<Mutex<Option<BoxStream<'static, io::Result<Bytes>>>>>;

/// A request body.
///
/// `Bytes`, `Chunks` and `File` are *replayable*: every retry sends them
/// again without copying (`Bytes` and `Chunks` share the caller's buffers).
/// `Stream` can be sent once, so requests carrying it are never retried.
#[derive(Clone, Default)]
pub enum RequestBody {
    /// No body.
    #[default]
    Empty,
    /// One buffer, sent as is.
    Bytes(Bytes),
    /// Several buffers sent back to back with an exact `Content-Length`
    /// (no concatenation copy).
    Chunks(Arc<[Bytes]>),
    /// A local file streamed from disk; `len` becomes the `Content-Length`.
    File {
        /// The file to send.
        path: PathBuf,
        /// Its size; the request fails if the file has a different length.
        len: u64,
    },
    /// A one-shot stream; `len` (if known) becomes the `Content-Length`,
    /// otherwise HTTP/1.1 uses chunked transfer encoding.
    Stream(OneShot, Option<u64>),
}

impl fmt::Debug for RequestBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestBody::Empty => f.write_str("Empty"),
            RequestBody::Bytes(b) => write!(f, "Bytes({} bytes)", b.len()),
            RequestBody::Chunks(c) => {
                write!(f, "Chunks({} chunks, {:?} bytes)", c.len(), self.len())
            }
            RequestBody::File { path, len } => write!(f, "File({path:?}, {len} bytes)"),
            RequestBody::Stream(_, len) => write!(f, "Stream({len:?} bytes)"),
        }
    }
}

impl From<Bytes> for RequestBody {
    fn from(b: Bytes) -> Self {
        RequestBody::Bytes(b)
    }
}

impl From<Vec<u8>> for RequestBody {
    fn from(v: Vec<u8>) -> Self {
        RequestBody::Bytes(Bytes::from(v))
    }
}

impl From<&'static [u8]> for RequestBody {
    fn from(v: &'static [u8]) -> Self {
        RequestBody::Bytes(Bytes::from_static(v))
    }
}

impl RequestBody {
    /// Several buffers sent without concatenating them.
    pub fn chunks(chunks: Vec<Bytes>) -> Self {
        match chunks.len() {
            0 => RequestBody::Empty,
            1 => RequestBody::Bytes(chunks.into_iter().next().unwrap_or_default()),
            _ => RequestBody::Chunks(chunks.into()),
        }
    }

    /// A one-shot body from a stream of buffers.
    pub fn stream<S>(stream: S, len: Option<u64>) -> Self
    where
        S: futures::Stream<Item = io::Result<Bytes>> + Send + 'static,
    {
        RequestBody::Stream(Arc::new(Mutex::new(Some(stream.boxed()))), len)
    }

    /// Body length, if known up front.
    pub fn len(&self) -> Option<u64> {
        match self {
            RequestBody::Empty => Some(0),
            RequestBody::Bytes(b) => Some(b.len() as u64),
            RequestBody::Chunks(c) => Some(c.iter().map(|b| b.len() as u64).sum()),
            RequestBody::File { len, .. } => Some(*len),
            RequestBody::Stream(_, len) => *len,
        }
    }

    /// Whether the body is known to be empty.
    pub fn is_empty(&self) -> bool {
        self.len() == Some(0)
    }

    /// Whether the body can be sent more than once.
    pub fn is_replayable(&self) -> bool {
        !matches!(self, RequestBody::Stream(..))
    }

    /// The reqwest body for one attempt, plus a `Content-Length` to set
    /// explicitly (for stream-backed bodies hyper cannot size on its own; it
    /// honours an explicit header instead of using chunked encoding).
    ///
    /// Sent bytes are counted into `stats`. Every chunk hyper takes from a
    /// stream body marks `activity` (the read timeout measures idleness, see
    /// [`crate::idle`]); chunks above [`idle::SLICE`] are handed over in
    /// zero-copy slices so progress stays visible.
    pub(crate) fn to_reqwest(
        &self,
        stats: &Arc<Stats>,
        activity: &Activity,
    ) -> Result<(Option<reqwest::Body>, Option<u64>)> {
        fn tracked<S>(s: S, stats: &Arc<Stats>, activity: &Activity) -> reqwest::Body
        where
            S: futures::Stream<Item = io::Result<Bytes>> + Send + 'static,
        {
            let stats = stats.clone();
            let sliced = s
                .map_ok(|b| futures::stream::iter(idle::slices(b).map(Ok::<_, io::Error>)))
                .try_flatten()
                .inspect_ok(move |b| stats.add_bytes_written(b.len() as u64))
                .boxed();
            reqwest::Body::wrap_stream(Tracked::new(sliced, activity.clone()))
        }
        Ok(match self {
            RequestBody::Empty => (None, None),
            RequestBody::Bytes(b) if b.len() <= REUSABLE_BYTES_MAX => {
                // One reusable buffer: the redirect logic can resend it.
                stats.add_bytes_written(b.len() as u64);
                (Some(reqwest::Body::from(b.clone())), None)
            }
            RequestBody::Bytes(b) => {
                let s = futures::stream::iter(std::iter::once(Ok::<_, io::Error>(b.clone())));
                (Some(tracked(s, stats, activity)), Some(b.len() as u64))
            }
            RequestBody::Chunks(c) => {
                let len = self.len();
                let chunks = c.clone();
                let s = futures::stream::iter(
                    (0..chunks.len()).map(move |i| Ok::<_, io::Error>(chunks[i].clone())),
                );
                (Some(tracked(s, stats, activity)), len)
            }
            RequestBody::File { path, len } => {
                let path = path.clone();
                let s = futures::stream::once(async move { tokio::fs::File::open(path).await })
                    .map_ok(|f| tokio_util::io::ReaderStream::with_capacity(f, FILE_CHUNK))
                    .try_flatten();
                (
                    Some(tracked(length_checked(s, *len), stats, activity)),
                    Some(*len),
                )
            }
            RequestBody::Stream(slot, len) => {
                let s = slot.lock().take().ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        "a streaming request body can only be sent once",
                    )
                    .with_retryable(false)
                })?;
                match *len {
                    Some(n) => (
                        Some(tracked(length_checked(s, n), stats, activity)),
                        Some(n),
                    ),
                    None => (Some(tracked(s, stats, activity)), None),
                }
            }
        })
    }
}

/// A body stream yielded a different number of bytes than the
/// `Content-Length` it was sent with (e.g. a file changed during upload).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyLengthMismatch {
    /// The declared length.
    pub expected: u64,
    /// Bytes produced before the mismatch was detected.
    pub actual: u64,
}

impl fmt::Display for BodyLengthMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "request body has {}{} bytes, but {} were declared",
            if self.actual > self.expected {
                "at least "
            } else {
                ""
            },
            self.actual,
            self.expected
        )
    }
}

impl std::error::Error for BodyLengthMismatch {}

/// Fail the stream instead of letting hyper silently cut a longer body to
/// the declared length (or hang up on a shorter one with a vague error).
///
/// hyper stops polling a body once it has written the declared length, so
/// the chunk that completes the length is only handed over after the inner
/// stream has been seen to end.
fn length_checked<S>(s: S, expected: u64) -> impl futures::Stream<Item = io::Result<Bytes>> + Send
where
    S: futures::Stream<Item = io::Result<Bytes>> + Send + 'static,
{
    let mismatch = move |actual| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            BodyLengthMismatch { expected, actual },
        )
    };
    futures::stream::unfold(
        (s.boxed(), 0u64, false),
        move |(mut s, mut seen, done)| async move {
            if done {
                return None;
            }
            // Empty chunks carry nothing: skip them.
            let b = loop {
                match s.next().await {
                    Some(Ok(b)) if b.is_empty() => continue,
                    Some(Ok(b)) => break b,
                    Some(Err(e)) => return Some((Err(e), (s, seen, true))),
                    None if seen != expected => {
                        return Some((Err(mismatch(seen)), (s, seen, true)));
                    }
                    None => return None,
                }
            };
            seen += b.len() as u64;
            if seen > expected {
                return Some((Err(mismatch(seen)), (s, seen, true)));
            }
            if seen == expected {
                // Confirm the end before releasing the final chunk.
                loop {
                    match s.next().await {
                        None => return Some((Ok(b), (s, seen, true))),
                        Some(Ok(extra)) if extra.is_empty() => continue,
                        Some(Ok(extra)) => {
                            let actual = seen + extra.len() as u64;
                            return Some((Err(mismatch(actual)), (s, actual, true)));
                        }
                        Some(Err(e)) => return Some((Err(e), (s, seen, true))),
                    }
                }
            }
            Some((Ok(b), (s, seen, false)))
        },
    )
}

/// One HTTP request plus the policy for sending it.
///
/// ```
/// use fsfast_core::ByteRange;
/// use fsfast_http_transport::Request;
///
/// let req = Request::get("https://example.com/data.bin")
///     .unwrap()
///     .range(ByteRange::Bounded { start: 0, end: 1024 })
///     .path("https://example.com/data.bin");
/// assert!(req.is_retry_safe());
/// ```
#[derive(Clone)]
pub struct Request {
    pub(crate) method: Method,
    pub(crate) url: Url,
    pub(crate) headers: HeaderMap,
    pub(crate) body: RequestBody,
    pub(crate) op: OpKind,
    pub(crate) retry: Option<bool>,
    pub(crate) pass: Vec<u16>,
    pub(crate) kinds: Vec<(u16, ErrorKind)>,
    pub(crate) timeout: Option<Duration>,
    pub(crate) path: Option<Arc<str>>,
    pub(crate) parser: Option<Arc<dyn ErrorParser>>,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("url", &redact_url(&self.url))
            .field("body", &self.body)
            .field("op", &self.op)
            .finish_non_exhaustive()
    }
}

/// The URL without credentials, query or fragment: safe for logs and
/// messages (user info and presigned-URL signatures are secrets).
pub fn redact_url(url: &Url) -> String {
    let mut u = url.clone();
    let _ = u.set_username("");
    let _ = u.set_password(None);
    u.set_query(None);
    u.set_fragment(None);
    u.to_string()
}

fn default_op(m: &Method) -> OpKind {
    match *m {
        Method::HEAD => OpKind::Info,
        Method::GET => OpKind::Read,
        Method::PUT | Method::POST | Method::PATCH => OpKind::Write,
        Method::DELETE => OpKind::Delete,
        _ => OpKind::Other,
    }
}

impl Request {
    /// A request for an absolute `http`/`https` URL.
    pub fn new(method: Method, url: &str) -> Result<Self> {
        let parsed = Url::parse(url).map_err(|e| {
            Error::invalid_input(format!("invalid URL: {e}")).with_path(url.to_owned())
        })?;
        Self::from_url(method, parsed)
    }

    /// A request for an already parsed URL (must be `http` or `https`).
    pub fn from_url(method: Method, url: Url) -> Result<Self> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(Error::invalid_input(format!(
                "unsupported URL scheme {:?} (expected http or https)",
                url.scheme()
            ))
            .with_path(url.to_string()));
        }
        Ok(Request {
            op: default_op(&method),
            method,
            url,
            headers: HeaderMap::new(),
            body: RequestBody::Empty,
            retry: None,
            pass: Vec::new(),
            kinds: Vec::new(),
            timeout: None,
            path: None,
            parser: None,
        })
    }

    /// `GET url`.
    pub fn get(url: &str) -> Result<Self> {
        Self::new(Method::GET, url)
    }

    /// `HEAD url`.
    pub fn head(url: &str) -> Result<Self> {
        Self::new(Method::HEAD, url)
    }

    /// `PUT url`.
    pub fn put(url: &str) -> Result<Self> {
        Self::new(Method::PUT, url)
    }

    /// `POST url`.
    pub fn post(url: &str) -> Result<Self> {
        Self::new(Method::POST, url)
    }

    /// `DELETE url`.
    pub fn delete(url: &str) -> Result<Self> {
        Self::new(Method::DELETE, url)
    }

    /// The method.
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// The URL.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Mutable access to the URL (e.g. to add query parameters).
    pub fn url_mut(&mut self) -> &mut Url {
        &mut self.url
    }

    /// The request headers (client defaults are added when sending).
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Mutable access to the request headers.
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    /// The body.
    pub fn body_ref(&self) -> &RequestBody {
        &self.body
    }

    /// Set a header (replacing any previous value).
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// Set a header from strings, validating both.
    pub fn try_header(self, name: &str, value: &str) -> Result<Self> {
        let n = HeaderName::try_from(name)
            .map_err(|e| Error::invalid_input(format!("invalid header name {name:?}: {e}")))?;
        let v = HeaderValue::try_from(value)
            .map_err(|e| Error::invalid_input(format!("invalid value for header {name:?}: {e}")))?;
        Ok(self.header(n, v))
    }

    /// Ask for a byte range. [`ByteRange::Full`] sends no `Range` header.
    /// A 416 response is then returned to the caller instead of an error, so
    /// range readers can treat "starts beyond the end" as empty.
    pub fn range(mut self, range: ByteRange) -> Self {
        match range.to_http_header() {
            Some(v) => {
                // Formatted from integers: always a valid header value.
                if let Ok(v) = HeaderValue::try_from(v) {
                    self.headers.insert(RANGE, v);
                }
                self.allow_status(416)
            }
            None => {
                self.headers.remove(RANGE);
                self
            }
        }
    }

    /// Set the body.
    pub fn body(mut self, body: impl Into<RequestBody>) -> Self {
        self.body = body.into();
        self
    }

    /// The operation kind used for latency statistics (default derived from
    /// the method: HEAD → Info, GET → Read, PUT/POST → Write, DELETE → Delete).
    pub fn op(mut self, op: OpKind) -> Self {
        self.op = op;
        self
    }

    /// Override whether the request may be retried. By default only
    /// idempotent methods (GET, HEAD, PUT, DELETE, OPTIONS, TRACE) are.
    /// Requests with a one-shot streaming body are never retried.
    pub fn retry_safe(mut self, safe: bool) -> Self {
        self.retry = Some(safe);
        self
    }

    /// Return responses with this (>= 400) status to the caller instead of
    /// turning them into errors.
    pub fn allow_status(mut self, status: u16) -> Self {
        if !self.pass.contains(&status) {
            self.pass.push(status);
        }
        self
    }

    /// Map an error status onto a specific kind for this request (e.g. 409 →
    /// `DirectoryNotEmpty` for a bucket deletion).
    pub fn status_kind(mut self, status: u16, kind: ErrorKind) -> Self {
        self.kinds.retain(|(s, _)| *s != status);
        self.kinds.push((status, kind));
        self
    }

    /// A per-request total timeout (overrides the client's).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// The fsfast path reported in errors. Defaults to the URL without
    /// credentials, query or fragment.
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(Arc::from(path.into()));
        self
    }

    /// Decode error bodies of this request with `parser` (overrides the
    /// client's parser).
    pub fn error_parser(mut self, parser: Arc<dyn ErrorParser>) -> Self {
        self.parser = Some(parser);
        self
    }

    /// Whether the request may be retried: idempotent (or explicitly marked
    /// safe) and with a replayable body.
    pub fn is_retry_safe(&self) -> bool {
        let idempotent = self.retry.unwrap_or(matches!(
            self.method,
            Method::GET
                | Method::HEAD
                | Method::PUT
                | Method::DELETE
                | Method::OPTIONS
                | Method::TRACE
        ));
        idempotent && self.body.is_replayable()
    }

    pub(crate) fn error_path(&self) -> Arc<str> {
        match &self.path {
            Some(p) => p.clone(),
            None => Arc::from(redact_url(&self.url)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_and_policy() {
        assert!(Request::get("ftp://x/y").is_err());
        assert!(Request::get("not a url").is_err());
        let r = Request::get("https://u:p@h/x?sig=secret#f").unwrap();
        assert!(r.is_retry_safe());
        assert_eq!(&*r.error_path(), "https://h/x");
        assert!(!format!("{r:?}").contains("secret"));
        let r = Request::post("http://h/x").unwrap();
        assert!(!r.is_retry_safe());
        assert!(r.clone().retry_safe(true).is_retry_safe());
        let r = Request::put("http://h/x")
            .unwrap()
            .body(RequestBody::stream(futures::stream::empty(), None));
        assert!(!r.is_retry_safe(), "one-shot bodies are never retried");
        let r = Request::put("http://h/x")
            .unwrap()
            .body(RequestBody::chunks(vec![
                Bytes::from_static(b"ab"),
                Bytes::from_static(b"c"),
            ]));
        assert!(r.is_retry_safe());
        assert_eq!(r.body_ref().len(), Some(3));
    }

    #[test]
    fn range_header_and_416() {
        let r = Request::get("http://h/x")
            .unwrap()
            .range(ByteRange::Bounded { start: 5, end: 10 });
        assert_eq!(r.headers()[RANGE], "bytes=5-9");
        assert!(r.pass.contains(&416));
        let r = r.range(ByteRange::Full);
        assert!(!r.headers().contains_key(RANGE));
    }

    async fn drain(expected: u64, chunks: &[&'static [u8]]) -> Vec<io::Result<Bytes>> {
        let s = futures::stream::iter(
            chunks
                .iter()
                .map(|c| Ok(Bytes::from_static(c)))
                .collect::<Vec<_>>(),
        );
        length_checked(s, expected).collect().await
    }

    #[tokio::test]
    async fn length_checker() {
        let ok = drain(3, &[b"ab", b"", b"c"]).await;
        assert_eq!(ok.len(), 2);
        assert!(ok.iter().all(|r| r.is_ok()));
        assert!(drain(0, &[]).await.is_empty());
        // Too short: error at the end.
        let short = drain(5, &[b"ab"]).await;
        assert!(short.last().unwrap().is_err());
        // Too long: the chunk completing the length is never released.
        let long = drain(2, &[b"ab", b"c"]).await;
        assert_eq!(long.len(), 1);
        let e = long[0].as_ref().unwrap_err();
        let m = e
            .get_ref()
            .unwrap()
            .downcast_ref::<BodyLengthMismatch>()
            .unwrap();
        assert_eq!((m.expected, m.actual), (2, 3));
        let long = drain(1, &[b"ab"]).await;
        assert!(long[0].is_err());
    }

    #[test]
    fn stream_body_is_one_shot() {
        let b = RequestBody::stream(
            futures::stream::iter([Ok(Bytes::from_static(b"x"))]),
            Some(1),
        );
        let stats = Arc::new(Stats::new());
        let activity = Activity::new();
        assert!(b.to_reqwest(&stats, &activity).is_ok());
        let e = b.to_reqwest(&stats, &activity).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput);
        assert!(!e.is_retryable());
    }
}
