//! Path rules of fsspec's `MemoryFileSystem`.

use std::borrow::Cow;

/// fsspec `MemoryFileSystem._strip_protocol` for string paths.
///
/// * a leading `memory://` is removed;
/// * chained / foreign URLs (containing `::` or `://`) only lose trailing
///   slashes;
/// * otherwise all leading and trailing slashes are removed and exactly one
///   leading `/` is added back; the root is the empty string.
///
/// Internal repeated slashes are kept, exactly like fsspec.
pub fn strip_protocol(path: &str) -> Cow<'_, str> {
    let p = path.strip_prefix("memory://").unwrap_or(path);
    if p.contains("::") || p.contains("://") {
        return Cow::Borrowed(p.trim_end_matches('/'));
    }
    let bytes = p.as_bytes();
    // Fast path: already canonical ("/x...", single leading slash, no trailing slash).
    if bytes.len() > 1 && bytes[0] == b'/' && bytes[1] != b'/' && bytes[bytes.len() - 1] != b'/' {
        return Cow::Borrowed(p);
    }
    let t = p.trim_start_matches('/').trim_end_matches('/');
    if t.is_empty() {
        Cow::Borrowed("")
    } else {
        Cow::Owned(format!("/{t}"))
    }
}

/// fsspec `AbstractFileSystem._parent` with the memory root marker `/`:
/// `"/a/b" -> "/a"`, `"/a" -> "/"`, `"" -> "/"`.
pub fn parent(path: &str) -> String {
    let p = strip_protocol(path);
    match p.rsplit_once('/') {
        Some((head, _)) => format!("/{}", head.trim_start_matches('/')),
        None => "/".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_matches_fsspec() {
        // Values recorded from fsspec 2026.9.0 MemoryFileSystem._strip_protocol.
        let cases = [
            ("a/b", "/a/b"),
            ("/a/b/", "/a/b"),
            ("/", ""),
            ("", ""),
            ("memory://x/y", "/x/y"),
            ("//a//b//", "/a//b"),
            ("memory:///z", "/z"),
            ("/a", "/a"),
            ("a", "/a"),
            ("memory://", ""),
            ("s3://bucket/key/", "s3://bucket/key"),
            ("memory://a::b/", "a::b"),
        ];
        for (input, want) in cases {
            assert_eq!(strip_protocol(input), want, "input {input:?}");
        }
    }

    #[test]
    fn parent_matches_fsspec() {
        assert_eq!(parent("/a/b/c"), "/a/b");
        assert_eq!(parent("/a"), "/");
        assert_eq!(parent(""), "/");
        assert_eq!(parent("/"), "/");
        assert_eq!(parent("a/b/"), "/a");
        assert_eq!(parent("/a//b"), "/a/");
    }

    #[test]
    fn strip_is_idempotent_on_plain_paths() {
        for p in ["x", "/x/", "//x//y", "/", "", "a/b/c/"] {
            let once = strip_protocol(p).into_owned();
            assert_eq!(strip_protocol(&once), once);
        }
    }
}
