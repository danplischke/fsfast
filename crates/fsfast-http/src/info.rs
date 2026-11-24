//! `info()` fields from response headers, following fsspec's `_file_info`.

use fsfast_core::{FileInfo, FileType, Value};
use fsfast_http_transport::header::{
    ACCEPT_RANGES, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, HeaderMap,
    HeaderName,
};
use fsfast_http_transport::range::{ContentRange, has_content_coding, parse_content_range};
use fsfast_http_transport::{Response, Url};

/// Header fields fsspec copies into `info()` verbatim (when non-empty).
pub const CHECKSUM_FIELDS: [&str; 4] = ["ETag", "Content-MD5", "Digest", "Last-Modified"];

/// What one HEAD/GET told us about a URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Probe {
    /// Size of the representation, if known.
    pub size: Option<u64>,
    /// `Content-Type` up to the first `;` (not trimmed, as in fsspec).
    pub mimetype: Option<String>,
    /// `Some(false)` when the server sent `Accept-Ranges: none`.
    pub partial: Option<bool>,
    /// The final URL after redirects.
    pub url: Option<String>,
    /// `(fsspec key, value)` of the checksum/validator headers.
    pub fields: Vec<(&'static str, String)>,
}

impl Probe {
    /// Merge a later probe into this one (fsspec's `info.update(...)`).
    pub fn update(&mut self, other: Probe) {
        if other.size.is_some() {
            self.size = other.size;
        }
        if other.mimetype.is_some() {
            self.mimetype = other.mimetype;
        }
        if other.partial.is_some() {
            self.partial = other.partial;
        }
        if other.url.is_some() {
            self.url = other.url;
        }
        for (k, v) in other.fields {
            self.fields.retain(|(n, _)| *n != k);
            self.fields.push((k, v));
        }
    }

    /// The `ETag` value, if any.
    pub fn etag(&self) -> Option<&str> {
        self.field("ETag")
    }

    /// A validator field by its fsspec key.
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }
}

fn header_text(
    h: &HeaderMap,
    name: impl fsfast_http_transport::header::AsHeaderName,
) -> Option<String> {
    h.get(name)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
}

/// Extract fsspec's fields from a response.
///
/// `requested_url` is the URL as the caller wrote it (see [`response_url`]).
pub fn probe_response(resp: &Response, requested_url: &str) -> Probe {
    let h = resp.headers();
    let ranged_reply = matches!(resp.status().as_u16(), 206 | 416);
    let size = if ranged_reply {
        // Our GET fallback asks for `bytes=0-0`: the total is in
        // Content-Range (Content-Length is the length of the part). fsspec's
        // fallback GET has no Range: it sees the full Content-Length, and
        // with a content coding reports no size (the coded total is not the
        // size of the content either).
        if has_content_coding(h) {
            None
        } else {
            h.get(CONTENT_RANGE)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_content_range)
                .and_then(|c| c.total())
        }
    } else {
        size_from_headers(h)
    };
    let mimetype = header_text(h, CONTENT_TYPE).map(|ct| match ct.find(';') {
        Some(i) => ct[..i].to_owned(),
        None => ct,
    });
    let partial = (h
        .get(ACCEPT_RANGES)
        .is_some_and(|v| v.as_bytes() == b"none"))
    .then_some(false);
    let url = response_url(resp.url(), requested_url);
    let mut fields = Vec::new();
    for key in CHECKSUM_FIELDS {
        let name = HeaderName::from_static(lower(key));
        if let Some(v) = header_text(h, name).filter(|v| !v.is_empty()) {
            fields.push((key, v));
        }
    }
    Probe {
        size,
        mimetype,
        partial,
        url: Some(url),
        fields,
    }
}

/// fsspec's `info()["url"]`: aiohttp's `str(r.url)` for the final URL,
/// as yarl normalizes it.
///
/// The WHATWG serialization of the url crate already agrees with yarl on
/// lower-cased scheme and host, removed default ports, resolved dot
/// segments and percent-encoded spaces and non-ASCII characters. On top of
/// that, aiohttp drops user info (it becomes the `Authorization` header) and
/// the fragment, and yarl requotes escapes (unreserved characters decoded,
/// other hex digits upper-cased) and keeps the empty path of a bare
/// `http://host`, which the url crate serializes as `http://host/`.
/// (yarl's query rules differ in rarer cases, e.g. a raw space becomes `+`.)
pub fn response_url(final_url: &Url, requested_url: &str) -> String {
    let mut u = final_url.clone();
    u.set_fragment(None);
    let _ = u.set_username("");
    let _ = u.set_password(None);
    let requested = Url::parse(requested_url).ok().map(|mut r| {
        r.set_fragment(None);
        let _ = r.set_username("");
        let _ = r.set_password(None);
        r
    });
    if requested.as_ref() == Some(&u)
        && u.path() == "/"
        && u.query().is_none()
        && has_empty_path(requested_url)
    {
        return u.origin().ascii_serialization();
    }
    requote(u.as_str())
}

/// Whether a URL string has neither a path nor a query (`http://host`,
/// `http://host#frag`): yarl then keeps the path empty.
fn has_empty_path(raw: &str) -> bool {
    let Some(i) = raw.find("://") else {
        return false;
    };
    let rest = &raw[i + 3..];
    let end = rest.find('#').unwrap_or(rest.len());
    !rest[..end].contains(['/', '\\', '?'])
}

/// yarl's requoting of percent-escapes: `%XX` of an unreserved character
/// (RFC 3986 §2.3) becomes the character, other escapes get upper-case hex.
/// The input is a serialized URL (ASCII).
fn requote(url: &str) -> String {
    let b = url.as_bytes();
    let mut out = String::with_capacity(url.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && b[i + 1].is_ascii_hexdigit()
            && b[i + 2].is_ascii_hexdigit()
        {
            let hex = &url[i + 1..i + 3];
            let byte = u8::from_str_radix(hex, 16).unwrap_or(b'%');
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                out.push(char::from(byte));
            } else {
                out.push('%');
                out.push_str(&hex.to_ascii_uppercase());
            }
            i += 3;
        } else {
            out.push(char::from(b[i]));
            i += 1;
        }
    }
    out
}

fn lower(key: &'static str) -> &'static str {
    match key {
        "ETag" => "etag",
        "Content-MD5" => "content-md5",
        "Digest" => "digest",
        "Last-Modified" => "last-modified",
        _ => unreachable!("not a checksum field: {key}"),
    }
}

/// fsspec's size rule for a full (HEAD or 200 GET) response: `Content-Length`
/// unless a content coding other than identity is in use, otherwise (only if
/// there is no Content-Length at all) the total of `Content-Range`.
pub fn size_from_headers(h: &HeaderMap) -> Option<u64> {
    if let Some(cl) = h.get(CONTENT_LENGTH) {
        let coded = h
            .get(CONTENT_ENCODING)
            .is_some_and(|v| !matches!(v.as_bytes(), b"identity" | b""));
        if coded {
            return None;
        }
        return cl.to_str().ok().and_then(|s| {
            let s = s.trim();
            (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .then(|| s.parse().ok())
                .flatten()
        });
    }
    match h
        .get(CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_content_range)
    {
        Some(ContentRange::Bytes { total, .. }) => total,
        Some(ContentRange::Unsatisfied { total }) => Some(total),
        None => None,
    }
}

/// Mark `info` as having an unknown size: fsspec reports `size: None`. The
/// Python layer builds `{"name", "size", "type", **extra}`, so an `extra`
/// entry `size = None` overrides the numeric field.
pub fn set_unknown_size(info: &mut FileInfo) {
    info.size = 0;
    info.extra.insert("size".to_owned(), Value::Null);
}

/// The size of `info`, honouring the unknown-size marker of
/// [`set_unknown_size`].
pub fn known_size(info: &FileInfo) -> Option<u64> {
    match info.extra.get("size") {
        Some(Value::Null) => None,
        _ => Some(info.size),
    }
}

/// Whether an `ETag` is a strong validator usable with `If-Match`
/// (RFC 9110 §8.8.3: quoted, without the `W/` prefix).
pub fn is_strong_etag(etag: &str) -> bool {
    etag.len() >= 2
        && etag.starts_with('"')
        && etag.ends_with('"')
        && etag[1..etag.len() - 1].bytes().all(|b| b != b'"')
}

/// Build the fsspec `info()` result: `{"name": url, "size": ..., **fields,
/// "type": "file"}`.
pub fn build_info(name: &str, probe: &Probe) -> FileInfo {
    let mut info = FileInfo {
        name: name.to_owned(),
        size: probe.size.unwrap_or(0),
        file_type: FileType::File,
        modified: probe
            .field("Last-Modified")
            .and_then(|v| httpdate::parse_http_date(v).ok()),
        created: None,
        version: probe.etag().map(str::to_owned),
        extra: Default::default(),
    };
    if probe.size.is_none() {
        set_unknown_size(&mut info);
    }
    if let Some(m) = &probe.mimetype {
        info.set("mimetype", m.clone());
    }
    if let Some(p) = probe.partial {
        info.set("partial", p);
    }
    if let Some(u) = &probe.url {
        info.set("url", u.clone());
    }
    for (k, v) in &probe.fields {
        info.set(*k, v.clone());
    }
    info
}

/// A listing entry: `{"name": u, "size": None, "type": "directory" if u
/// ends with "/" else "file"}`.
pub fn link_info(url: String) -> FileInfo {
    let file_type = if url.ends_with('/') {
        FileType::Directory
    } else {
        FileType::File
    };
    let mut info = FileInfo {
        name: url,
        size: 0,
        file_type,
        modified: None,
        created: None,
        version: None,
        extra: Default::default(),
    };
    set_unknown_size(&mut info);
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsfast_http_transport::header::HeaderValue;
    use std::time::SystemTime;

    fn h(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(*k, HeaderValue::from_static(v));
        }
        m
    }

    #[test]
    fn size_rules_follow_fsspec() {
        assert_eq!(size_from_headers(&h(&[("content-length", "42")])), Some(42));
        assert_eq!(
            size_from_headers(&h(&[
                ("content-length", "42"),
                ("content-encoding", "gzip")
            ])),
            None
        );
        assert_eq!(
            size_from_headers(&h(&[
                ("content-length", "42"),
                ("content-encoding", "identity")
            ])),
            Some(42)
        );
        // Content-Range only counts without any Content-Length (fsspec's elif).
        assert_eq!(
            size_from_headers(&h(&[
                ("content-length", "1"),
                ("content-encoding", "br"),
                ("content-range", "bytes 0-0/99")
            ])),
            None
        );
        assert_eq!(
            size_from_headers(&h(&[("content-range", "bytes 0-0/99")])),
            Some(99)
        );
        assert_eq!(size_from_headers(&h(&[("content-length", "x")])), None);
        assert_eq!(size_from_headers(&h(&[])), None);
    }

    /// Expected values: `str(yarl.URL(u).with_fragment(None).with_user(None))`
    /// with yarl 1.25 (what aiohttp reports as `r.url`).
    #[test]
    fn response_url_like_yarl() {
        let same = |u: &str| response_url(&Url::parse(u).unwrap(), u);
        for (given, want) in [
            ("http://h", "http://h"),
            ("http://h#f", "http://h"),
            ("http://h?x", "http://h/?x"),
            ("http://u:p@h", "http://h"),
            ("http://h:80", "http://h"),
            ("https://h:443", "https://h"),
            ("HTTP://H", "http://h"),
            ("http://h/", "http://h/"),
            ("http://H.Example/x", "http://h.example/x"),
            ("http://h:80/x", "http://h/x"),
            ("http://h/a%2fb%7e%41", "http://h/a%2Fb~A"),
            ("http://h/%e2%82%ac", "http://h/%E2%82%AC"),
            ("http://h/a%25b", "http://h/a%25b"),
            ("http://h/a;b=c", "http://h/a;b=c"),
            ("http://h/sp ace", "http://h/sp%20ace"),
            ("http://[::1]:8/x", "http://[::1]:8/x"),
            ("http://h/x#frag", "http://h/x"),
        ] {
            assert_eq!(same(given), want, "{given}");
        }
        // After a redirect the final URL is reported (normalized the same way).
        let final_url = Url::parse("http://other/%7efile#f").unwrap();
        assert_eq!(response_url(&final_url, "http://h"), "http://other/~file");
    }

    #[test]
    fn strong_etags() {
        assert!(is_strong_etag("\"abc\""));
        assert!(is_strong_etag("\"\""));
        assert!(!is_strong_etag("W/\"abc\""));
        assert!(!is_strong_etag("abc"));
        assert!(!is_strong_etag("\""));
        assert!(!is_strong_etag("\"a\"b\""));
    }

    #[test]
    fn info_dict_shape() {
        let probe = Probe {
            size: None,
            mimetype: Some("text/html".into()),
            partial: Some(false),
            url: Some("http://h/x".into()),
            fields: vec![
                ("ETag", "\"e\"".into()),
                ("Last-Modified", "Sun, 06 Nov 1994 08:49:37 GMT".into()),
            ],
        };
        let i = build_info("http://h/x", &probe);
        assert_eq!(known_size(&i), None);
        assert_eq!(i.extra["size"], Value::Null);
        assert_eq!(i.extra["mimetype"], Value::from("text/html"));
        assert_eq!(i.extra["partial"], Value::Bool(false));
        assert_eq!(i.extra["ETag"], Value::from("\"e\""));
        assert_eq!(i.version.as_deref(), Some("\"e\""));
        assert_eq!(
            i.modified,
            Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(784_111_777))
        );
        let i = build_info(
            "http://h/x",
            &Probe {
                size: Some(5),
                ..Probe::default()
            },
        );
        assert_eq!(known_size(&i), Some(5));
        assert!(!i.extra.contains_key("size"));
        assert!(link_info("http://h/d/".into()).is_dir());
        assert!(link_info("http://h/d".into()).is_file());
    }
}
