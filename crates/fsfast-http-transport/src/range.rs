//! Byte-range helpers: `Content-Range` parsing and classification of the
//! response to a ranged GET (RFC 9110 §14).
//!
//! A server may honour a `Range` header (206 Partial Content), ignore it (200
//! with the whole representation), or reject it as unsatisfiable (416).
//! [`classify_range_response`] tells these apart so callers can always return
//! the bytes that were asked for; [`Response::range_bytes`](crate::Response::range_bytes)
//! does the whole job.

use std::ops::Range;

use fsfast_core::{ByteRange, Error, Result};
use reqwest::StatusCode;
use reqwest::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, HeaderMap};

/// A parsed `Content-Range` header (`bytes` unit only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentRange {
    /// `bytes first-last/total` or `bytes first-last/*`.
    Bytes {
        /// Offset of the first byte.
        start: u64,
        /// Offset one past the last byte (exclusive).
        end: u64,
        /// Size of the whole representation, if the server knows it.
        total: Option<u64>,
    },
    /// `bytes */total`: sent with 416 Range Not Satisfiable.
    Unsatisfied {
        /// Size of the whole representation.
        total: u64,
    },
}

impl ContentRange {
    /// The total size, if stated.
    pub fn total(&self) -> Option<u64> {
        match *self {
            ContentRange::Bytes { total, .. } => total,
            ContentRange::Unsatisfied { total } => Some(total),
        }
    }
}

/// Parse a `Content-Range` value. Lenient about whitespace and the case of the
/// unit, strict about numbers (digits only, `first <= last < total`).
pub fn parse_content_range(value: &str) -> Option<ContentRange> {
    let v = value.trim();
    let split = v.find(|c: char| c.is_ascii_whitespace())?;
    let (unit, rest) = v.split_at(split);
    if !unit.eq_ignore_ascii_case("bytes") {
        return None;
    }
    let (range, total) = rest.trim().split_once('/')?;
    let total = match total.trim() {
        "*" => None,
        t => Some(parse_digits(t)?),
    };
    let range = range.trim();
    if range == "*" {
        return total.map(|total| ContentRange::Unsatisfied { total });
    }
    let (first, last) = range.split_once('-')?;
    let first = parse_digits(first.trim())?;
    let last = parse_digits(last.trim())?;
    if last < first || total.is_some_and(|t| last >= t) {
        return None;
    }
    Some(ContentRange::Bytes {
        start: first,
        end: last.checked_add(1)?,
        total,
    })
}

/// `u64::from_str` also accepts a leading `+`; HTTP numbers are digits only.
fn parse_digits(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Whether `Content-Range` states a total of zero bytes, however malformed
/// the rest of it is.
fn zero_total(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit_once('/'))
        .is_some_and(|(_, t)| t.trim() == "0")
}

/// The `Content-Range` header of a response, if present and valid.
pub fn content_range(headers: &HeaderMap) -> Option<ContentRange> {
    headers
        .get(CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_content_range)
}

/// `Content-Length` as a number, if present and valid.
pub fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| parse_digits(v.trim()))
}

/// Whether the body is sent with a content coding other than `identity`, in
/// which case `Content-Length` does not describe the representation's size
/// (fsspec's rule in `_file_info`).
pub fn has_content_coding(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_ENCODING)
        .is_some_and(|v| !matches!(v.to_str().map(str::trim), Ok("" | "identity")))
}

/// How a server answered a GET that carried a `Range` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeReply {
    /// 206: the body holds bytes `start..start + len` of the representation.
    Partial {
        /// Offset of the first byte of the body.
        start: u64,
        /// Body length, when known before reading it.
        len: Option<u64>,
        /// Size of the whole representation, when stated.
        total: Option<u64>,
    },
    /// 200 (or another 2xx): the server ignored the range and sends the whole
    /// representation.
    Full {
        /// Its size, when known (`Content-Length` without a content coding).
        total: Option<u64>,
    },
    /// 416: the range starts at or beyond the end of the representation.
    NotSatisfiable {
        /// The representation's size, when stated (`Content-Range: bytes */N`).
        total: Option<u64>,
    },
}

/// Classify the response to a GET sent with `Range: requested`.
///
/// A 206 must describe a single range: `multipart/byteranges` (never
/// requested by fsfast) is a protocol error. A 206 without `Content-Range` is
/// accepted the way fsspec does, assuming the body starts at the requested
/// offset (impossible to place for a suffix request, which is an error).
pub fn classify_range_response(
    status: StatusCode,
    headers: &HeaderMap,
    requested: ByteRange,
) -> Result<RangeReply> {
    match status.as_u16() {
        206 => {
            let is_multipart = headers
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| {
                    v.trim_start()
                        .to_ascii_lowercase()
                        .starts_with("multipart/byteranges")
                });
            if is_multipart {
                return Err(Error::protocol(
                    "server sent a multipart/byteranges response to a single-range request",
                ));
            }
            match content_range(headers) {
                Some(ContentRange::Bytes { start, end, total }) => Ok(RangeReply::Partial {
                    start,
                    len: Some(end - start),
                    total,
                }),
                Some(ContentRange::Unsatisfied { .. }) => Err(Error::protocol(
                    "206 Partial Content with an unsatisfied Content-Range",
                )),
                // `bytes 0-0/0` (tower-http's answer for an empty file) is
                // invalid, but a zero total unambiguously means "empty".
                None if zero_total(headers) => Ok(RangeReply::NotSatisfiable { total: Some(0) }),
                None if headers.contains_key(CONTENT_RANGE) => Err(Error::protocol(format!(
                    "invalid Content-Range header {:?}",
                    headers.get(CONTENT_RANGE)
                ))),
                None => {
                    let start = match requested {
                        ByteRange::Full => 0,
                        ByteRange::Bounded { start, .. } | ByteRange::From(start) => start,
                        ByteRange::Suffix(_) => {
                            return Err(Error::protocol(
                                "206 Partial Content without Content-Range for a suffix range",
                            ));
                        }
                    };
                    Ok(RangeReply::Partial {
                        start,
                        len: content_length(headers),
                        total: None,
                    })
                }
            }
        }
        416 => Ok(RangeReply::NotSatisfiable {
            total: content_range(headers).and_then(|c| c.total()),
        }),
        200..=299 => Ok(RangeReply::Full {
            total: if has_content_coding(headers) {
                None
            } else {
                content_length(headers)
            },
        }),
        s => Err(Error::protocol(format!(
            "unexpected HTTP status {s} for a ranged GET"
        ))),
    }
}

/// The absolute byte window `requested` selects in a representation of
/// `total` bytes; `None` for the end means "to the end" when the size is
/// unknown. A suffix with an unknown size has no known start (`None`).
pub fn requested_window(requested: ByteRange, total: Option<u64>) -> Option<Range<u64>> {
    let unknown_end = u64::MAX;
    match (requested, total) {
        (r, Some(t)) => Some(r.resolve(t)),
        (ByteRange::Full, None) => Some(0..unknown_end),
        (ByteRange::From(s), None) => Some(s..unknown_end),
        (ByteRange::Bounded { start, end }, None) => Some(start..end.max(start)),
        (ByteRange::Suffix(_), None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use reqwest::header::HeaderValue;

    #[test]
    fn content_range_forms() {
        assert_eq!(
            parse_content_range("bytes 0-499/1234"),
            Some(ContentRange::Bytes {
                start: 0,
                end: 500,
                total: Some(1234)
            })
        );
        assert_eq!(
            parse_content_range("  BYTES 5-5/*  "),
            Some(ContentRange::Bytes {
                start: 5,
                end: 6,
                total: None
            })
        );
        assert_eq!(
            parse_content_range("bytes */1234"),
            Some(ContentRange::Unsatisfied { total: 1234 })
        );
        assert_eq!(
            parse_content_range("bytes 1 - 2 / 3"),
            Some(ContentRange::Bytes {
                start: 1,
                end: 3,
                total: Some(3)
            })
        );
        for bad in [
            "",
            "bytes",
            "bytes */*",
            "items 0-1/2",
            "bytes 5-4/10",
            "bytes 0-10/10",
            "bytes +1-2/3",
            "bytes 1-2",
            "bytes -1-2/3",
            "bytes 0-18446744073709551615/*",
            "bytes0-1/2",
        ] {
            assert_eq!(parse_content_range(bad), None, "{bad:?}");
        }
    }

    proptest! {
        #[test]
        fn content_range_roundtrip(start in 0u64..1 << 50, len in 1u64..1 << 20, extra in 0u64..1 << 20, known in any::<bool>()) {
            let end = start + len;
            let total = known.then_some(end + extra);
            let s = format!(
                "bytes {}-{}/{}",
                start,
                end - 1,
                total.map_or("*".to_owned(), |t| t.to_string())
            );
            prop_assert_eq!(
                parse_content_range(&s),
                Some(ContentRange::Bytes { start, end, total })
            );
        }

        #[test]
        fn parser_never_panics(s in ".{0,40}") {
            let _ = parse_content_range(&s);
        }
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_static(v));
        }
        h
    }

    #[test]
    fn classification() {
        let r = ByteRange::Bounded { start: 10, end: 20 };
        let h = headers(&[
            ("content-range", "bytes 10-19/100"),
            ("content-length", "10"),
        ]);
        assert_eq!(
            classify_range_response(StatusCode::PARTIAL_CONTENT, &h, r).unwrap(),
            RangeReply::Partial {
                start: 10,
                len: Some(10),
                total: Some(100)
            }
        );
        let h = headers(&[("content-length", "100")]);
        assert_eq!(
            classify_range_response(StatusCode::OK, &h, r).unwrap(),
            RangeReply::Full { total: Some(100) }
        );
        let h = headers(&[("content-length", "40"), ("content-encoding", "gzip")]);
        assert_eq!(
            classify_range_response(StatusCode::OK, &h, r).unwrap(),
            RangeReply::Full { total: None }
        );
        let h = headers(&[("content-range", "bytes */5")]);
        assert_eq!(
            classify_range_response(StatusCode::RANGE_NOT_SATISFIABLE, &h, r).unwrap(),
            RangeReply::NotSatisfiable { total: Some(5) }
        );
        // 206 without Content-Range: assume the requested start.
        let h = headers(&[("content-length", "10")]);
        assert_eq!(
            classify_range_response(StatusCode::PARTIAL_CONTENT, &h, r).unwrap(),
            RangeReply::Partial {
                start: 10,
                len: Some(10),
                total: None
            }
        );
        assert!(
            classify_range_response(StatusCode::PARTIAL_CONTENT, &h, ByteRange::Suffix(3)).is_err()
        );
        let h = headers(&[("content-type", "multipart/byteranges; boundary=x")]);
        assert!(classify_range_response(StatusCode::PARTIAL_CONTENT, &h, r).is_err());
        let h = headers(&[("content-range", "bytes 9-1/100")]);
        assert!(classify_range_response(StatusCode::PARTIAL_CONTENT, &h, r).is_err());
        // tower-http's empty file: an invalid range, but surely empty.
        let h = headers(&[("content-range", "bytes 0-0/0"), ("content-length", "0")]);
        assert_eq!(
            classify_range_response(StatusCode::PARTIAL_CONTENT, &h, r).unwrap(),
            RangeReply::NotSatisfiable { total: Some(0) }
        );
        assert!(classify_range_response(StatusCode::FOUND, &HeaderMap::new(), r).is_err());
    }

    #[test]
    fn windows() {
        assert_eq!(
            requested_window(ByteRange::Suffix(4), Some(10)),
            Some(6..10)
        );
        assert_eq!(requested_window(ByteRange::Suffix(4), None), None);
        assert_eq!(
            requested_window(ByteRange::From(3), None),
            Some(3..u64::MAX)
        );
        assert_eq!(
            requested_window(ByteRange::Bounded { start: 3, end: 50 }, Some(10)),
            Some(3..10)
        );
    }
}
