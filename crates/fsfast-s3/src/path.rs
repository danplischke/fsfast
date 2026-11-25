//! s3fs path handling: `_strip_protocol`, `_parent`, `split_path` (with
//! access-point ARNs and `?versionId=` suffixes) and bucket-name rules.

use std::sync::OnceLock;

use regex::Regex;

/// The fsspec protocol names of S3 (`S3FileSystem.protocol`).
pub const PROTOCOLS: &[&str] = &["s3", "s3a"];

/// fsspec `AbstractFileSystem._strip_protocol` for s3fs: remove an `s3://`,
/// `s3a://`, `s3::` or `s3a::` prefix and trailing slashes (s3fs's
/// `root_marker` is empty).
pub fn strip_protocol(path: &str) -> String {
    let mut p = path;
    for proto in PROTOCOLS {
        if let Some(rest) = p.strip_prefix(proto) {
            if let Some(r) = rest.strip_prefix("://") {
                p = r;
            } else if let Some(r) = rest.strip_prefix("::") {
                p = r;
            }
        }
    }
    p.trim_end_matches('/').to_owned()
}

/// fsspec `_parent` for s3fs (`"b/k/x" -> "b/k"`, `"b" -> ""`).
pub fn parent(path: &str) -> String {
    let p = strip_protocol(path);
    match p.rfind('/') {
        Some(i) => p[..i].to_owned(),
        None => String::new(),
    }
}

/// A path split into bucket, key and version (s3fs `split_path`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Path {
    /// Bucket name (or access-point ARN).
    pub bucket: String,
    /// Object key (may be empty, may end with `/`).
    pub key: String,
    /// `?versionId=` of a version-aware filesystem.
    pub version_id: Option<String>,
}

impl S3Path {
    /// `bucket/key` (s3fs's `"/".join([bucket, key])`), or the bucket alone
    /// when the key is empty.
    pub fn full(&self) -> String {
        if self.key.is_empty() {
            self.bucket.clone()
        } else {
            format!("{}/{}", self.bucket, self.key)
        }
    }

    /// Whether the bucket is an access-point / outposts / object-lambda ARN.
    pub fn is_arn(&self) -> bool {
        self.bucket.starts_with("arn:")
    }
}

fn arn_patterns() -> &'static [Regex; 4] {
    static RE: OnceLock<[Regex; 4]> = OnceLock::new();
    RE.get_or_init(|| {
        [
            Regex::new(
                r"^(?P<bucket>arn:(aws).*:s3:[a-z\-0-9]*:[0-9]{12}:accesspoint[:/][^/]+)/?(?P<key>.*)$",
            ),
            Regex::new(
                r"^(?P<bucket>arn:(aws).*:s3-outposts:[a-z\-0-9]+:[0-9]{12}:outpost[/:][a-zA-Z0-9\-]{1,63}[/:](bucket|accesspoint)[/:][a-zA-Z0-9\-]{1,63})[/:]?(?P<key>.*)$",
            ),
            Regex::new(
                r"^(?P<bucket>arn:(aws).*:s3-outposts:[a-z\-0-9]+:[0-9]{12}:outpost[/:][a-zA-Z0-9\-]{1,63}[/:]bucket[/:][a-zA-Z0-9\-]{1,63})[/:]?(?P<key>.*)$",
            ),
            Regex::new(
                r"^(?P<bucket>arn:(aws).*:s3-object-lambda:[a-z\-0-9]+:[0-9]{12}:accesspoint[/:][a-zA-Z0-9\-]{1,63})[/:]?(?P<key>.*)$",
            ),
        ]
        .map(|r| r.expect("static regex"))
    })
}

/// s3fs `_find_bucket_key`.
fn find_bucket_key(path: &str) -> (String, String) {
    if path.starts_with("arn:") {
        for re in arn_patterns() {
            if let Some(c) = re.captures(path) {
                return (c["bucket"].to_owned(), c["key"].to_owned());
            }
        }
    }
    match path.split_once('/') {
        Some((b, k)) => (b.to_owned(), k.to_owned()),
        None => (path.to_owned(), String::new()),
    }
}

/// s3fs `split_path`: bucket, key (trailing slashes of the input are kept)
/// and, when `version_aware`, the `?versionId=` suffix.
pub fn split_path(path: &str, version_aware: bool) -> S3Path {
    let trimmed = path.trim_end_matches('/');
    let trail = &path[trimmed.len()..];
    let stripped = strip_protocol(path);
    let p = stripped.trim_start_matches('/');
    if !p.contains('/') {
        return S3Path {
            bucket: p.to_owned(),
            key: String::new(),
            version_id: None,
        };
    }
    let (bucket, keypart) = find_bucket_key(p);
    let (key, version) = match keypart.split_once("?versionId=") {
        Some((k, v)) => (k.to_owned(), v.to_owned()),
        None => (keypart, String::new()),
    };
    S3Path {
        bucket,
        key: key + trail,
        version_id: (version_aware && !version.is_empty()).then_some(version),
    }
}

/// Whether `bucket` can be the first label(s) of a virtual-hosted host name:
/// 3–63 characters of lower-case letters, digits, `-` (and `.` when
/// `allow_dots`), starting and ending with a letter or digit, not an IP
/// address, no empty labels.
pub fn is_virtual_hostable(bucket: &str, allow_dots: bool) -> bool {
    let b = bucket.as_bytes();
    if !(3..=63).contains(&b.len()) {
        return false;
    }
    let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    if !edge(b[0]) || !edge(b[b.len() - 1]) {
        return false;
    }
    if !b
        .iter()
        .all(|&c| edge(c) || c == b'-' || (allow_dots && c == b'.'))
    {
        return false;
    }
    if bucket.contains("..") || bucket.contains(".-") || bucket.contains("-.") {
        return false;
    }
    bucket.parse::<std::net::Ipv4Addr>().is_err()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_and_parent() {
        assert_eq!(strip_protocol("s3://bucket/key/"), "bucket/key");
        assert_eq!(strip_protocol("s3a://bucket"), "bucket");
        assert_eq!(strip_protocol("s3::bucket/x"), "bucket/x");
        assert_eq!(strip_protocol("bucket//"), "bucket");
        assert_eq!(strip_protocol(""), "");
        assert_eq!(parent("s3://b/k/x"), "b/k");
        assert_eq!(parent("b"), "");
    }

    #[test]
    fn split_like_s3fs() {
        let p = split_path("s3://mybucket/path/to/file", false);
        assert_eq!(
            (p.bucket.as_str(), p.key.as_str()),
            ("mybucket", "path/to/file")
        );
        let p = split_path(
            "s3://mybucket/path/to/versioned_file?versionId=some_version_id",
            true,
        );
        assert_eq!(p.key, "path/to/versioned_file");
        assert_eq!(p.version_id.as_deref(), Some("some_version_id"));
        let p = split_path("mybucket/f?versionId=v", false);
        assert_eq!((p.key.as_str(), p.version_id), ("f", None));
        let p = split_path("bucket/dir/", false);
        assert_eq!(p.key, "dir/");
        let p = split_path("/bucket/k", false);
        assert_eq!(p.bucket, "bucket");
        let p = split_path("bucket", false);
        assert_eq!((p.bucket.as_str(), p.key.as_str()), ("bucket", ""));
        let p = split_path("bucket/", false);
        assert_eq!((p.bucket.as_str(), p.key.as_str()), ("bucket", ""));
        assert_eq!(p.full(), "bucket");
    }

    #[test]
    fn access_point_arns() {
        let p = split_path(
            "arn:aws:s3:us-west-2:123456789012:accesspoint/my-ap/some/key.txt",
            false,
        );
        assert_eq!(
            p.bucket,
            "arn:aws:s3:us-west-2:123456789012:accesspoint/my-ap"
        );
        assert_eq!(p.key, "some/key.txt");
        assert!(p.is_arn());
    }

    #[test]
    fn virtual_host_rules() {
        assert!(is_virtual_hostable("my-bucket", false));
        assert!(!is_virtual_hostable("my.bucket", false));
        assert!(is_virtual_hostable("my.bucket", true));
        assert!(!is_virtual_hostable("MyBucket", true));
        assert!(!is_virtual_hostable("my_bucket", true));
        assert!(!is_virtual_hostable("ab", true));
        assert!(!is_virtual_hostable("-ab", true));
        assert!(!is_virtual_hostable("192.168.1.1", true));
        assert!(!is_virtual_hostable("a..b", true));
    }
}
