//! gcsfs path handling: `_strip_protocol`, `_split_path` (with object
//! generations when version aware), `_parent`, and URL quoting of bucket
//! and object names.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

/// fsspec protocol names served by this backend (gcsfs `protocol`).
pub const PROTOCOLS: &[&str] = &["gs", "gcs"];

/// Characters left as they are by Python's `urllib.parse.quote(s, safe="")`
/// (RFC 3986 unreserved): everything else, `/` included, is escaped.
const QUOTE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Like [`QUOTE`] but keeping `/` (google-cloud-storage's `_quote(name,
/// safe=b"/~")`, used for the resource of signed URLs).
const QUOTE_KEEP_SLASH: &AsciiSet = &QUOTE.remove(b'/');

/// gcsfs `quote`: percent-encode everything but unreserved characters,
/// including `/` (object names are one URL path segment in the JSON API).
pub fn quote(s: &str) -> String {
    utf8_percent_encode(s, QUOTE).to_string()
}

/// Percent-encode keeping `/` (signed URL resources).
pub fn quote_keep_slash(s: &str) -> String {
    utf8_percent_encode(s, QUOTE_KEEP_SLASH).to_string()
}

/// gcsfs `_strip_protocol`: remove each of `gs://`, `gs::`, `gcs://`,
/// `gcs::` in turn (so `gs://gcs://x` loses both prefixes, as in gcsfs).
/// Neither leading nor trailing slashes are touched.
pub fn strip_protocol(path: &str) -> &str {
    let mut p = path;
    for proto in PROTOCOLS {
        if let Some(rest) = p
            .strip_prefix(proto)
            .and_then(|r| r.strip_prefix("://").or_else(|| r.strip_prefix("::")))
        {
            p = rest;
        }
    }
    p
}

/// fsspec `_parent` with gcsfs's empty root marker: `"b/a/c" -> "b/a"`,
/// `"b/a/" -> "b/a"`, `"b" -> ""`. Trailing slashes are not stripped first.
pub fn parent(path: &str) -> &str {
    let p = strip_protocol(path);
    match p.rfind('/') {
        Some(i) => &p[..i],
        None => "",
    }
}

/// A path split into bucket, object name and (version-aware) generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcsPath {
    /// Bucket name (may be empty for the root).
    pub bucket: String,
    /// Object name ("key"); empty for a bucket.
    pub key: String,
    /// Object generation from `#<gen>` or `?generation=<gen>`, only parsed
    /// when version aware.
    pub generation: Option<String>,
}

impl GcsPath {
    /// `bucket/key` (or just `bucket`), without the generation.
    pub fn full(&self) -> String {
        if self.key.is_empty() {
            self.bucket.clone()
        } else {
            format!("{}/{}", self.bucket, self.key)
        }
    }
}

/// gcsfs `_split_path`.
///
/// `[gs|gcs://]bucket[/key][?generation=N][#N]`. With `version_aware`, a
/// fragment (priority) or a `generation` query parameter that Python's
/// `int()` accepts is taken as the generation and removed from the key;
/// otherwise `#` and `?` are part of the object name.
pub fn split_path(path: &str, version_aware: bool) -> GcsPath {
    let p = strip_protocol(path).trim_start_matches('/');
    let Some((bucket, keypart)) = p.split_once('/') else {
        return GcsPath {
            bucket: p.to_owned(),
            key: String::new(),
            generation: None,
        };
    };
    let mut key = keypart;
    let mut generation = None;
    if version_aware {
        // urllib.parse.urlsplit on a relative reference: the fragment
        // follows the first '#', the query the first '?' before it.
        let (before_frag, fragment) = match keypart.split_once('#') {
            Some((a, f)) => (a, Some(f)),
            None => (keypart, None),
        };
        let (url_path, query) = match before_frag.split_once('?') {
            Some((a, q)) => (a, Some(q)),
            None => (before_frag, None),
        };
        let candidate = match fragment.filter(|f| !f.is_empty()) {
            Some(f) => Some(f.to_owned()),
            None => query
                .filter(|q| !q.is_empty())
                .and_then(query_generation),
        };
        if let Some(g) = candidate.filter(|g| is_python_int(g)) {
            generation = Some(g);
            key = url_path;
        }
    }
    GcsPath {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        generation,
    }
}

/// The first non-empty `generation` value of a query string, decoded like
/// Python's `parse_qs` (`+` is a space, `%XX` escapes).
fn query_generation(query: &str) -> Option<String> {
    query
        .split(['&', ';'])
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (form_decode(k) == "generation" && !v.is_empty()).then(|| form_decode(v))
        })
        .next()
}

fn form_decode(s: &str) -> String {
    let plus = s.replace('+', " ");
    percent_encoding::percent_decode_str(&plus)
        .decode_utf8_lossy()
        .into_owned()
}

/// Whether Python's `int(s)` accepts `s`: optional surrounding whitespace,
/// an optional sign, ASCII digits with single underscores between digits.
pub(crate) fn is_python_int(s: &str) -> bool {
    let t = s.trim_matches(|c: char| c.is_ascii_whitespace());
    let t = t.strip_prefix(['+', '-']).unwrap_or(t);
    !t.is_empty()
        && !t.starts_with('_')
        && !t.ends_with('_')
        && !t.contains("__")
        && t.bytes().all(|b| b.is_ascii_digit() || b == b'_')
}

/// Reject object names that cannot be addressed in a URL path or that GCS
/// forbids (`.`, `..`, carriage return / line feed), before a request is
/// made with them.
pub(crate) fn check_object_name(key: &str, path: &str) -> fsfast_core::Result<()> {
    if key == "." || key == ".." {
        return Err(fsfast_core::Error::invalid_input(format!(
            "object names cannot be '.' or '..': {path:?}"
        ))
        .with_path(path));
    }
    if key.contains(['\r', '\n']) {
        return Err(fsfast_core::Error::invalid_input(
            "object names cannot contain carriage return or line feed characters",
        )
        .with_path(path));
    }
    if key.len() > 1024 {
        return Err(fsfast_core::Error::invalid_input(
            "object names are limited to 1024 bytes of UTF-8",
        )
        .with_path(path));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip() {
        assert_eq!(strip_protocol("gs://b/k"), "b/k");
        assert_eq!(strip_protocol("gcs://b/k/"), "b/k/");
        assert_eq!(strip_protocol("gs::b"), "b");
        assert_eq!(strip_protocol("gs://gcs://b"), "b");
        assert_eq!(strip_protocol("gcs://gs://b"), "gs://b");
        assert_eq!(strip_protocol("/b/k"), "/b/k");
        assert_eq!(strip_protocol("s3://b"), "s3://b");
        assert_eq!(strip_protocol(""), "");
    }

    #[test]
    fn parents() {
        assert_eq!(parent("b/a/c"), "b/a");
        assert_eq!(parent("b/a/"), "b/a");
        assert_eq!(parent("gs://b/a"), "b");
        assert_eq!(parent("b"), "");
        assert_eq!(parent("/b"), "");
        assert_eq!(parent("/a/b"), "/a");
    }

    #[test]
    fn split_basic() {
        let p = split_path("gs://bucket/dir/file.txt", false);
        assert_eq!(p.bucket, "bucket");
        assert_eq!(p.key, "dir/file.txt");
        assert_eq!(p.generation, None);
        assert_eq!(split_path("bucket", false).key, "");
        assert_eq!(split_path("/bucket/", false).key, "");
        assert_eq!(split_path("bucket/", false).bucket, "bucket");
        // Not version aware: '#' and '?' belong to the name.
        assert_eq!(split_path("b/k#123", false).key, "k#123");
        assert_eq!(split_path("b/k?generation=1", false).key, "k?generation=1");
    }

    #[test]
    fn split_generations() {
        let p = split_path("gs://b/k.txt#1700000000000000", true);
        assert_eq!(p.key, "k.txt");
        assert_eq!(p.generation.as_deref(), Some("1700000000000000"));
        let p = split_path("b/k?generation=42", true);
        assert_eq!((p.key.as_str(), p.generation.as_deref()), ("k", Some("42")));
        // The fragment wins over the query.
        let p = split_path("b/k?generation=1#2", true);
        assert_eq!((p.key.as_str(), p.generation.as_deref()), ("k", Some("2")));
        // Not an integer: part of the name.
        let p = split_path("b/tilde~hash#", true);
        assert_eq!((p.key.as_str(), p.generation), ("tilde~hash#", None));
        let p = split_path("b/a#b", true);
        assert_eq!((p.key.as_str(), p.generation), ("a#b", None));
        let p = split_path("b/a?x=1", true);
        assert_eq!((p.key.as_str(), p.generation), ("a?x=1", None));
        // Python int() forms.
        assert!(is_python_int(" 12 "));
        assert!(is_python_int("+1_000"));
        assert!(!is_python_int("1__0"));
        assert!(!is_python_int("_1"));
        assert!(!is_python_int(""));
        assert!(!is_python_int("0x10"));
    }

    #[test]
    fn quoting() {
        assert_eq!(quote("a/b c+d%e"), "a%2Fb%20c%2Bd%25e");
        assert_eq!(quote("A-Z_a.z~0"), "A-Z_a.z~0");
        assert_eq!(quote("ünï"), "%C3%BCn%C3%AF");
        assert_eq!(quote_keep_slash("a/b c"), "a/b%20c");
    }

    #[test]
    fn object_names() {
        assert!(check_object_name("a/./b", "x").is_ok());
        assert!(check_object_name(".", "x").is_err());
        assert!(check_object_name("..", "x").is_err());
        assert!(check_object_name("a\nb", "x").is_err());
        assert!(check_object_name(&"x".repeat(1025), "x").is_err());
    }
}
