//! Mapping HTTP failures onto fsfast [`Error`]s.
//!
//! * Status codes map onto the most precise [`ErrorKind`] ([`status_kind`]),
//!   with the status attached as [`Detail::Http`]. Requests can override the
//!   kind per status ([`Request::status_kind`](crate::Request::status_kind)),
//!   e.g. S3 maps 409 `BucketNotEmpty` to `DirectoryNotEmpty`.
//! * An [`ErrorParser`] lets a backend decode the service's error body (S3
//!   and Azure XML, GCS JSON) into a code ([`Detail::Code`]), a message and,
//!   if needed, a different kind or retry classification.
//! * `Retry-After` on 429/503 is attached as an
//!   [`fsfast_engine::retry::RetryAfter`] source so the retry loop honours it.
//! * Transport failures (`reqwest::Error`) become `Timeout`,
//!   `ConnectionFailed` (also for a body cut off mid-transfer, which is
//!   retried; TLS failures are not), `Protocol` (redirect errors) or
//!   `InvalidInput`.

use std::fmt;
use std::time::{Duration, SystemTime};

use fsfast_core::{Detail, Error, ErrorKind};
use fsfast_engine::retry::RetryAfter;
use reqwest::StatusCode;
use reqwest::header::{CONTENT_TYPE, HeaderMap, RETRY_AFTER};

/// What an [`ErrorParser`] extracted from a service error response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceError {
    /// Service error code (S3 `NoSuchKey`, Azure `BlobNotFound`, GCS
    /// `reason`), attached as [`Detail::Code`].
    pub code: Option<String>,
    /// Human-readable message, appended to the error message.
    pub message: Option<String>,
    /// Kind to use instead of the status-based one.
    pub kind: Option<ErrorKind>,
    /// Retry classification to use instead of the default.
    pub retryable: Option<bool>,
}

/// Decodes a service's error body. Implementations must be cheap and must not
/// panic on arbitrary input; the body is at most [`MAX_ERROR_BODY`] bytes.
pub trait ErrorParser: Send + Sync + fmt::Debug {
    /// Inspect an error response (status >= 400). Return `None` to keep the
    /// generic mapping.
    fn parse(&self, status: StatusCode, headers: &HeaderMap, body: &[u8]) -> Option<ServiceError>;
}

/// How much of an error response body is read for messages and parsing.
pub const MAX_ERROR_BODY: usize = 64 << 10;

/// The kind a status code maps to by default.
///
/// | status | kind |
/// |---|---|
/// | 400, 411, 413, 414, 416, 431 | `InvalidInput` |
/// | 401, 403 | `PermissionDenied` |
/// | 404, 410 | `NotFound` |
/// | 405, 501 | `Unsupported` |
/// | 408, 504 | `Timeout` |
/// | 409 | `AlreadyExists` (callers override where 409 means something else) |
/// | 412 | `PreconditionFailed` |
/// | 429, 503 | `Throttled` |
/// | other 4xx/5xx | `Io` |
pub fn status_kind(status: u16) -> ErrorKind {
    match status {
        400 | 411 | 413 | 414 | 416 | 431 => ErrorKind::InvalidInput,
        401 | 403 => ErrorKind::PermissionDenied,
        404 | 410 => ErrorKind::NotFound,
        405 | 501 => ErrorKind::Unsupported,
        408 | 504 => ErrorKind::Timeout,
        409 => ErrorKind::AlreadyExists,
        412 => ErrorKind::PreconditionFailed,
        429 | 503 => ErrorKind::Throttled,
        _ => ErrorKind::Io,
    }
}

/// Whether a status is worth retrying: request timeout, throttling, and
/// server errors except those that will not change on retry (501 Not
/// Implemented, 505 HTTP Version Not Supported, 506, 507 Insufficient
/// Storage, 508 Loop Detected, 510, 511 Network Authentication Required).
pub fn status_retryable(status: u16) -> bool {
    match status {
        408 | 429 => true,
        501 | 505..=508 | 510 | 511 => false,
        500..=599 => true,
        _ => false,
    }
}

/// Parse a `Retry-After` value: delta-seconds or an HTTP date (relative to
/// `now`; a date in the past means "retry now").
pub fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    let v = value.trim();
    if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) {
        return Some(Duration::from_secs(v.parse().unwrap_or(u64::MAX)));
    }
    let when = httpdate::parse_http_date(v).ok()?;
    Some(when.duration_since(now).unwrap_or(Duration::ZERO))
}

/// `err` for a log line: its message, details and source chain, but not its
/// path. Paths are URLs as the caller wrote them and may carry credentials
/// (`user:password@`, presigned query signatures), which must never be
/// logged; log [`redact_url`](crate::redact_url) of the URL next to it.
pub fn log_display(err: &Error) -> String {
    use std::fmt::Write as _;
    let mut out = err.message().to_owned();
    for d in err.details() {
        let _ = match d {
            Detail::Http(s) => write!(out, " (HTTP {s})"),
            Detail::Code(c) => write!(out, " ({c})"),
            other => write!(out, " ({other:?})"),
        };
    }
    let mut src = std::error::Error::source(err);
    while let Some(s) = src {
        let _ = write!(out, ": {s}");
        src = s.source();
    }
    out
}

/// Context about the request needed to build an error.
pub(crate) struct ErrorContext<'a> {
    pub path: &'a str,
    pub kinds: &'a [(u16, ErrorKind)],
    pub parser: Option<&'a dyn ErrorParser>,
}

/// Build the error for a response with status >= 400.
pub(crate) fn from_status(
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
    ctx: &ErrorContext<'_>,
) -> Error {
    let code = status.as_u16();
    let mut kind = ctx
        .kinds
        .iter()
        .find(|(s, _)| *s == code)
        .map(|(_, k)| *k)
        .unwrap_or_else(|| status_kind(code));
    let mut retryable = status_retryable(code);
    let mut message = match status.canonical_reason() {
        Some(r) => format!("HTTP {code} {r}"),
        None => format!("HTTP {code}"),
    };
    let parsed = ctx.parser.and_then(|p| p.parse(status, headers, body));
    let mut service_code = None;
    match parsed {
        Some(p) => {
            if let Some(k) = p.kind {
                kind = k;
            }
            if let Some(r) = p.retryable {
                retryable = r;
            }
            if let Some(m) = p.message.filter(|m| !m.is_empty()) {
                message.push_str(": ");
                message.push_str(&m);
            }
            service_code = p.code;
        }
        None => {
            if let Some(snippet) = body_snippet(headers, body) {
                message.push_str(": ");
                message.push_str(&snippet);
            }
        }
    }
    let mut err = Error::new(kind, message)
        .with_path(ctx.path)
        .with_detail(Detail::Http(code))
        .with_retryable(retryable);
    if let Some(c) = service_code {
        err = err.with_detail(Detail::Code(c));
    }
    if matches!(code, 429 | 503)
        && let Some(d) = headers
            .get(RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| parse_retry_after(v, SystemTime::now()))
    {
        err = err.with_source(RetryAfter(d));
    }
    err
}

/// A short, single-line excerpt of a textual error body (not HTML pages).
fn body_snippet(headers: &HeaderMap, body: &[u8]) -> Option<String> {
    const MAX_CHARS: usize = 300;
    if body.is_empty() {
        return None;
    }
    let ctype = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ctype.starts_with("text/html") {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;
    let mut out = String::new();
    for word in text.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
        if out.chars().count() > MAX_CHARS {
            let cut: String = out.chars().take(MAX_CHARS).collect();
            return Some(format!("{cut}..."));
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Map a transport failure.
pub(crate) fn from_reqwest(e: reqwest::Error, path: &str) -> Error {
    let e = e.without_url();
    if let Some(m) = find_in_chain::<crate::request::BodyLengthMismatch>(&e) {
        return Error::new(ErrorKind::Io, m.to_string())
            .with_path(path)
            .with_retryable(false)
            .with_source(e);
    }
    let (kind, retryable, what) = if e.is_timeout() {
        (ErrorKind::Timeout, None, "request timed out")
    } else if is_tls_error(&e) {
        (
            ErrorKind::ConnectionFailed,
            Some(false),
            "TLS handshake failed",
        )
    } else if e.is_connect() {
        (ErrorKind::ConnectionFailed, None, "connection failed")
    } else if e.is_builder() {
        (ErrorKind::InvalidInput, None, "invalid request")
    } else if e.is_redirect() {
        (ErrorKind::Protocol, Some(false), "redirect error")
    } else if e.is_decode() {
        // reqwest reports every failure while reading a response body as
        // "decode" (fsfast enables no decoders): a connection reset or a
        // server dying mid-transfer (hyper's IncompleteBody), an HTTP/2
        // stream reset, a broken chunked encoding. These are transport
        // failures, worth retrying like a failure before the response head.
        (
            ErrorKind::ConnectionFailed,
            None,
            "connection lost while reading the response body",
        )
    } else if e.is_body() || e.is_request() {
        (ErrorKind::ConnectionFailed, None, "connection error")
    } else {
        (ErrorKind::Io, None, "HTTP error")
    };
    let mut err = Error::new(kind, what).with_path(path).with_source(e);
    if let Some(r) = retryable {
        err = err.with_retryable(r);
    }
    err
}

/// Whether a rustls error (certificate, handshake) is in the source chain.
/// Those do not go away on retry.
fn is_tls_error(e: &(dyn std::error::Error + 'static)) -> bool {
    find_in_chain::<rustls::Error>(e).is_some()
}

/// The first `T` in `e`'s source chain. An `io::Error`'s `source()` skips
/// the error it wraps (and hyper/rustls nest them: `io::Error(Other,
/// io::Error(InvalidData, rustls::Error))`), so the walk descends into the
/// wrapped error instead.
fn find_in_chain<'a, T: std::error::Error + 'static>(
    e: &'a (dyn std::error::Error + 'static),
) -> Option<&'a T> {
    let mut cur: Option<&'a (dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = cur {
        if let Some(t) = err.downcast_ref::<T>() {
            return Some(t);
        }
        cur = match err.downcast_ref::<std::io::Error>() {
            Some(io) => io
                .get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static))
                .or_else(|| err.source()),
            None => err.source(),
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    #[test]
    fn kinds_and_retryability() {
        assert_eq!(status_kind(404), ErrorKind::NotFound);
        assert_eq!(status_kind(410), ErrorKind::NotFound);
        assert_eq!(status_kind(403), ErrorKind::PermissionDenied);
        assert_eq!(status_kind(401), ErrorKind::PermissionDenied);
        assert_eq!(status_kind(412), ErrorKind::PreconditionFailed);
        assert_eq!(status_kind(429), ErrorKind::Throttled);
        assert_eq!(status_kind(503), ErrorKind::Throttled);
        assert_eq!(status_kind(409), ErrorKind::AlreadyExists);
        assert_eq!(status_kind(405), ErrorKind::Unsupported);
        assert_eq!(status_kind(500), ErrorKind::Io);
        assert_eq!(status_kind(418), ErrorKind::Io);
        for s in [408, 429, 500, 502, 503, 504, 520, 599] {
            assert!(status_retryable(s), "{s}");
        }
        for s in [400, 401, 403, 404, 412, 416, 501, 505, 507] {
            assert!(!status_retryable(s), "{s}");
        }
    }

    #[test]
    fn retry_after_forms() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(784_111_777);
        assert_eq!(
            parse_retry_after("120", now),
            Some(Duration::from_secs(120))
        );
        assert_eq!(parse_retry_after(" 0 ", now), Some(Duration::ZERO));
        // RFC 9110 example date, 10 s after `now`.
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:49:47 GMT", now),
            Some(Duration::from_secs(10))
        );
        // A date in the past means "now".
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:49:00 GMT", now),
            Some(Duration::ZERO)
        );
        assert_eq!(parse_retry_after("-1", now), None);
        assert_eq!(parse_retry_after("soon", now), None);
    }

    #[derive(Debug)]
    struct XmlCode;
    impl ErrorParser for XmlCode {
        fn parse(&self, _: StatusCode, _: &HeaderMap, body: &[u8]) -> Option<ServiceError> {
            let s = std::str::from_utf8(body).ok()?;
            let code = s.split("<Code>").nth(1)?.split("</Code>").next()?;
            Some(ServiceError {
                code: Some(code.to_owned()),
                message: Some("parsed".into()),
                kind: (code == "BucketNotEmpty").then_some(ErrorKind::DirectoryNotEmpty),
                retryable: None,
            })
        }
    }

    #[test]
    fn status_errors_carry_details() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("3"));
        let ctx = ErrorContext {
            path: "bucket/key",
            kinds: &[],
            parser: None,
        };
        let e = from_status(
            StatusCode::SERVICE_UNAVAILABLE,
            &headers,
            b"slow down",
            &ctx,
        );
        assert_eq!(e.kind(), ErrorKind::Throttled);
        assert_eq!(e.http_status(), Some(503));
        assert!(e.is_retryable());
        assert_eq!(e.path(), Some("bucket/key"));
        assert_eq!(
            fsfast_engine::retry::retry_after_hint(&e),
            Some(Duration::from_secs(3))
        );
        assert!(e.message().contains("slow down"), "{}", e.message());

        let ctx = ErrorContext {
            path: "p",
            kinds: &[(409, ErrorKind::NotFound)],
            parser: Some(&XmlCode),
        };
        let e = from_status(
            StatusCode::CONFLICT,
            &HeaderMap::new(),
            b"<Error><Code>BucketNotEmpty</Code></Error>",
            &ctx,
        );
        assert_eq!(e.kind(), ErrorKind::DirectoryNotEmpty);
        assert!(e.details().contains(&Detail::Code("BucketNotEmpty".into())));
        let e = from_status(
            StatusCode::CONFLICT,
            &HeaderMap::new(),
            b"<Error><Code>Other</Code></Error>",
            &ctx,
        );
        assert_eq!(e.kind(), ErrorKind::NotFound, "per-request override");
        assert!(!e.is_retryable());
    }

    #[test]
    fn chain_search_descends_into_nested_io_errors() {
        #[derive(Debug)]
        struct Marker;
        impl std::fmt::Display for Marker {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("marker")
            }
        }
        impl std::error::Error for Marker {}
        let nested =
            std::io::Error::other(std::io::Error::new(std::io::ErrorKind::InvalidData, Marker));
        let top = Error::new(ErrorKind::Io, "x").with_source(nested);
        assert!(find_in_chain::<Marker>(&top).is_some());
        let plain = Error::new(ErrorKind::Io, "x").with_source(std::io::Error::other("no"));
        assert!(find_in_chain::<Marker>(&plain).is_none());
    }

    #[test]
    fn html_bodies_are_not_quoted() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        let ctx = ErrorContext {
            path: "p",
            kinds: &[],
            parser: None,
        };
        let e = from_status(StatusCode::NOT_FOUND, &headers, b"<html>nope</html>", &ctx);
        assert_eq!(e.message(), "HTTP 404 Not Found");
        let long = "x ".repeat(1000);
        let e = from_status(
            StatusCode::BAD_REQUEST,
            &HeaderMap::new(),
            long.as_bytes(),
            &ctx,
        );
        assert!(e.message().len() < 400 && e.message().ends_with("..."));
    }
}
