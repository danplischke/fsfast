//! adlfs path handling: `_strip_protocol`, `split_path`,
//! `_get_kwargs_from_urls`, and URL encoding of container and blob names.
//!
//! Paths inside fsfast are adlfs's protocol-stripped form,
//! `container/path/to/blob`, optionally followed by `?versionid=<id>` on
//! version-aware filesystems.

use std::borrow::Cow;

/// The protocols adlfs registers (`AzureBlobFileSystem.protocol`).
pub const PROTOCOLS: &[&str] = &["abfs", "az", "abfss"];

/// The ADLS Gen2 endpoint suffix adlfs recognises in `abfs://` URLs.
const STORE_SUFFIX: &str = ".dfs.core.windows.net";

/// The parts of `scheme://netloc/path?query#fragment` that adlfs uses
/// (Python's `urlsplit` as consumed by fsspec's `infer_storage_options`).
#[derive(Debug, Default, PartialEq, Eq)]
struct UrlParts<'a> {
    host: Option<&'a str>,
    username: Option<&'a str>,
    path: &'a str,
    query: Option<&'a str>,
    fragment: Option<&'a str>,
}

fn split_url(url: &str) -> UrlParts<'_> {
    let rest = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => {
            return UrlParts {
                path: url,
                ..UrlParts::default()
            };
        }
    };
    let net_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let netloc = &rest[..net_end];
    let mut rest = &rest[net_end..];
    let mut fragment = None;
    if let Some(i) = rest.find('#') {
        fragment = Some(&rest[i + 1..]).filter(|f| !f.is_empty());
        rest = &rest[..i];
    }
    let mut query = None;
    if let Some(i) = rest.find('?') {
        query = Some(&rest[i + 1..]).filter(|q| !q.is_empty());
        rest = &rest[..i];
    }
    let (host, username) = if netloc.is_empty() {
        (None, None)
    } else {
        let (userinfo, hostport) = match netloc.rfind('@') {
            Some(i) => (Some(&netloc[..i]), &netloc[i + 1..]),
            None => (None, netloc),
        };
        let host = match hostport.rfind(':') {
            Some(i) => &hostport[..i],
            None => hostport,
        };
        let username = userinfo
            .map(|u| u.split_once(':').map_or(u, |(n, _)| n))
            .filter(|u| !u.is_empty());
        (Some(host), username)
    };
    UrlParts {
        host,
        username,
        path: rest,
        query,
        fragment,
    }
}

/// adlfs `AzureBlobFileSystem._strip_protocol`.
///
/// ```
/// use fsfast_azure::path::strip_protocol;
/// assert_eq!(strip_protocol("abfs://container/a/b"), "container/a/b");
/// assert_eq!(strip_protocol("az://container@acct.dfs.core.windows.net/a"), "container/a");
/// assert_eq!(strip_protocol("/container/a"), "container/a");
/// ```
pub fn strip_protocol(path: &str) -> String {
    let has_protocol = PROTOCOLS
        .iter()
        .any(|p| path.strip_prefix(p).is_some_and(|r| r.starts_with("://")));
    let url: Cow<'_, str> = if has_protocol {
        Cow::Borrowed(path)
    } else {
        Cow::Owned(format!("abfs://{}", path.trim_start_matches('/')))
    };
    let parts = split_url(&url);
    let mut out = String::with_capacity(url.len());
    let base_path = match parts.fragment {
        Some(f) => format!("{}#{f}", parts.path),
        None => parts.path.to_owned(),
    };
    if let Some(user) = parts.username {
        out.push_str(user);
        out.push_str(&base_path);
    } else if let Some(host) = parts.host.filter(|h| !h.is_empty()) {
        if host.contains(STORE_SUFFIX) {
            out.push_str(&base_path);
        } else {
            out.push_str(host);
            out.push_str(&base_path);
        }
    } else {
        out.push_str(&base_path);
    }
    if let Some(q) = parts.query {
        out.push('?');
        out.push_str(q);
    }
    out.trim_start_matches('/').to_owned()
}

/// adlfs `_get_kwargs_from_urls`: `account_name` from an
/// `{account}.(dfs|blob).core.windows.net` host, and `version_aware=True`
/// when the query has a `versionid`. Returns `(account_name, version_aware)`.
pub fn kwargs_from_url(url: &str) -> (Option<String>, bool) {
    let parts = split_url(url);
    let mut account = None;
    if let Some(host) = parts.host {
        for svc in [".dfs.core.windows.net", ".blob.core.windows.net"] {
            // `(?P<account_name>.+)\.(dfs|blob)\.core\.windows\.net` with
            // re.match: greedy, anchored at the start only.
            if let Some(i) = host.rfind(svc)
                && i > 0
            {
                account = Some(host[..i].to_owned());
                break;
            }
        }
    }
    let versioned = parts.query.is_some_and(|q| {
        q.split('&').any(|kv| {
            kv.split_once('=')
                .is_some_and(|(k, v)| k == "versionid" && !v.is_empty())
        })
    });
    (account, versioned)
}

/// A path split into its parts (adlfs `split_path`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobPath<'a> {
    /// Container name (empty for the account root).
    pub container: &'a str,
    /// Blob name (empty for the container itself).
    pub blob: &'a str,
    /// `?versionid=` value, only on version-aware filesystems.
    pub version_id: Option<&'a str>,
}

impl BlobPath<'_> {
    /// `container/blob` (or `container`), the name adlfs reports.
    pub fn full(&self) -> String {
        if self.blob.is_empty() {
            self.container.to_owned()
        } else {
            format!("{}/{}", self.container, self.blob)
        }
    }
}

/// adlfs `split_path` on an already protocol-stripped path. Leading slashes
/// are ignored; a trailing slash stays part of the blob name (adlfs writes
/// `name/` blobs for such paths), see [`split_dir_path`] for lookups. The
/// `?versionid=` suffix is always removed from the blob name; its value is
/// returned only when `version_aware`.
pub fn split_path(path: &str, version_aware: bool) -> BlobPath<'_> {
    let p = path.trim_start_matches('/');
    let Some((container, keypart)) = p.split_once('/') else {
        return BlobPath {
            container: p,
            blob: "",
            version_id: None,
        };
    };
    let (key, version) = match keypart.find("?versionid=") {
        Some(i) => (&keypart[..i], Some(&keypart[i + "?versionid=".len()..])),
        None => (keypart, None),
    };
    BlobPath {
        container,
        blob: key,
        version_id: version.filter(|v| version_aware && !v.is_empty()),
    }
}

/// [`split_path`] with trailing slashes removed from the blob name, for
/// lookups (`info`, `ls`, `find`, `rmdir`), which adlfs performs on the
/// stripped path.
pub fn split_dir_path(path: &str, version_aware: bool) -> BlobPath<'_> {
    let mut p = split_path(path, version_aware);
    p.blob = p.blob.trim_end_matches('/');
    p
}

/// Percent-encode everything but RFC 3986 unreserved characters (and `/`
/// when `keep_slash`), like Python's `quote(s, safe='~/')` used by the SDK
/// for blob names.
pub fn quote(s: &str, keep_slash: bool) -> Cow<'_, str> {
    let ok = |b: u8| {
        b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'.' | b'_' | b'~')
            || (keep_slash && b == b'/')
    };
    if s.bytes().all(ok) {
        return Cow::Borrowed(s);
    }
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if ok(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 15) as usize] as char);
        }
    }
    Cow::Owned(out)
}

/// Decode `%XX` escapes (invalid escapes are kept verbatim; the result is
/// UTF-8-lossy).
pub fn unquote(s: &str) -> Cow<'_, str> {
    if !s.contains('%') {
        return Cow::Borrowed(s);
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let h = |c: u8| (c as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (h(b[i + 1]), h(b[i + 2])) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_protocol_matches_adlfs() {
        // Expected values recorded from adlfs 2026.8.0.
        for (input, want) in [
            ("abfs://c/a/b", "c/a/b"),
            ("az://c/a/b/", "c/a/b/"),
            ("c/a", "c/a"),
            ("/c/a", "c/a"),
            ("abfs://c@acct.dfs.core.windows.net/a/b", "c/a/b"),
            ("abfss://c@acct.dfs.core.windows.net/a", "c/a"),
            ("abfs://acct.dfs.core.windows.net/c/a", "c/a"),
            ("abfs://c/a?versionid=x", "c/a?versionid=x"),
            ("abfs://c/a#frag", "c/a#frag"),
            ("abfs://user:pw@c/a", "user/a"),
            ("c/a:b", "c/a:b"),
            ("abfs://c:80/a", "c/a"),
            ("", ""),
            ("abfs://", ""),
            ("s3://c/a", "s3//c/a"),
            ("c/ a b", "c/ a b"),
            ("c/a%20b", "c/a%20b"),
            ("abfs://c/a?x=1&versionid=2", "c/a?x=1&versionid=2"),
        ] {
            assert_eq!(strip_protocol(input), want, "{input:?}");
        }
    }

    #[test]
    fn kwargs_from_urls() {
        assert_eq!(
            kwargs_from_url("abfs://c@acct.dfs.core.windows.net/a"),
            (Some("acct".to_owned()), false)
        );
        assert_eq!(
            kwargs_from_url("az://acct.blob.core.windows.net/c/a?versionid=1"),
            (Some("acct".to_owned()), true)
        );
        assert_eq!(kwargs_from_url("abfs://c/a"), (None, false));
    }

    #[test]
    fn split() {
        let p = split_path("c/a/b", false);
        assert_eq!((p.container, p.blob, p.version_id), ("c", "a/b", None));
        let p = split_path("c", false);
        assert_eq!((p.container, p.blob), ("c", ""));
        let p = split_path("/c/a/?versionid=v1", true);
        assert_eq!((p.container, p.blob, p.version_id), ("c", "a/", Some("v1")));
        assert_eq!(split_dir_path("c/a/", false).blob, "a");
        let p = split_path("c/a?versionid=v1", false);
        assert_eq!((p.blob, p.version_id), ("a", None));
        assert_eq!(split_path("", false).container, "");
        assert_eq!(split_path("c/a/b", false).full(), "c/a/b");
    }

    #[test]
    fn quoting() {
        assert_eq!(quote("a b/ü+%", true), "a%20b/%C3%BC%2B%25");
        assert_eq!(quote("a/b", false), "a%2Fb");
        assert_eq!(quote("plain-name_1.~", true), "plain-name_1.~");
        assert_eq!(unquote("a%20b%2"), "a b%2");
        assert_eq!(unquote("%C3%BC"), "ü");
    }

    proptest::proptest! {
        #[test]
        fn quote_roundtrip(s in "\\PC{0,40}") {
            let q = quote(&s, true);
            proptest::prop_assert_eq!(unquote(&q), s.as_str());
        }
    }
}
