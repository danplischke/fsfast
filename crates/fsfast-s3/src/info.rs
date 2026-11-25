//! `FileInfo` values with exactly the keys s3fs puts in its dicts.
//!
//! The Python layer builds `{"name", "size", "type", **extra}`; the `extra`
//! keys below are the ones s3fs returns for each kind of entry:
//!
//! | entry | keys besides name/size/type |
//! |---|---|
//! | object from `HEAD` (`info` of a file) | `ETag`, `LastModified`, `StorageClass` (default `STANDARD`), `VersionId` (None), `ContentType` (None) |
//! | object from a listing (`ls`, `find`) | `Key`, `Size`, `LastModified`, `ETag`, `StorageClass`, and when the server sends them `ChecksumAlgorithm`, `ChecksumType`, `Owner`, `RestoreStatus`, `VersionId`, `IsLatest` |
//! | common prefix (`ls`) / inferred directory (`find(withdirs=True)`) | `Key`, `Size` (0), `StorageClass` (`DIRECTORY`) |
//! | directory from `info` | `StorageClass` (`DIRECTORY`) |
//! | bucket from `info` | `StorageClass` (`DIRECTORY`), `VersionId` (None) |
//! | bucket from `ls("")` | `Key`, `Size` (0), `StorageClass` (`BUCKET`), `CreationDate`, `BucketRegion` (if sent) |
//! | the root (`info("")`) | none |

use std::collections::BTreeMap;
use std::time::SystemTime;

use fsfast_core::{Error, FileInfo, Result, Value};
use fsfast_http_transport::header::HeaderMap;

use crate::encode::parse_http_date;
use crate::xml::{BucketEntry, ObjectEntry};

/// What `HEAD Object` tells about an object.
#[derive(Debug, Clone)]
pub struct ObjectMeta {
    /// `Content-Length`.
    pub size: u64,
    /// `ETag` (with quotes), if sent.
    pub etag: Option<String>,
    /// `x-amz-version-id`, if sent.
    pub version_id: Option<String>,
    /// `Last-Modified`.
    pub last_modified: Option<SystemTime>,
    /// `x-amz-storage-class`.
    pub storage_class: Option<String>,
    /// `Content-Type`.
    pub content_type: Option<String>,
    /// All response headers (metadata to carry over on append and
    /// multipart copy).
    pub headers: HeaderMap,
}

fn header(h: &HeaderMap, name: &str) -> Option<String> {
    h.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
}

impl ObjectMeta {
    /// Parse the headers of a `HEAD Object` response.
    pub fn from_headers(headers: &HeaderMap, path: &str) -> Result<ObjectMeta> {
        let size = header(headers, "content-length")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .ok_or_else(|| {
                Error::protocol("HEAD response without a valid Content-Length").with_path(path)
            })?;
        Ok(ObjectMeta {
            size,
            etag: header(headers, "etag"),
            version_id: header(headers, "x-amz-version-id"),
            last_modified: header(headers, "last-modified")
                .as_deref()
                .and_then(parse_http_date),
            storage_class: header(headers, "x-amz-storage-class"),
            content_type: header(headers, "content-type"),
            headers: headers.clone(),
        })
    }

    /// s3fs's `info()` dict of a file.
    pub fn to_info(&self, name: String) -> FileInfo {
        let mut i = FileInfo::file(name, self.size)
            .with_modified(self.last_modified)
            .with_version(self.etag.clone().filter(|e| !e.is_empty()));
        i.set("ETag", self.etag.clone().unwrap_or_default());
        i.set(
            "LastModified",
            match self.last_modified {
                Some(t) => Value::Time(t),
                None => Value::Str(String::new()),
            },
        );
        i.set(
            "StorageClass",
            self.storage_class
                .clone()
                .unwrap_or_else(|| "STANDARD".to_owned()),
        );
        i.set("VersionId", Value::from(self.version_id.clone()));
        i.set("ContentType", Value::from(self.content_type.clone()));
        i
    }
}

/// A listed object (`Contents` / `Version`) of `bucket`. With `versions`,
/// the name carries a `?versionId=` suffix (s3fs `_fill_info`).
pub fn object_info(bucket: &str, e: &ObjectEntry, versions: bool) -> FileInfo {
    let key = format!("{bucket}/{}", e.key);
    let mut name = key.clone();
    if versions
        && let Some(v) = e.version_id.as_deref()
        && v != "null"
    {
        name.push_str("?versionId=");
        name.push_str(v);
    }
    let mut i = FileInfo::file(name, e.size)
        .with_modified(e.last_modified)
        .with_version(e.etag.clone());
    i.set("Key", key);
    i.set("Size", e.size);
    if let Some(t) = e.last_modified {
        i.set("LastModified", t);
    }
    if let Some(etag) = &e.etag {
        i.set("ETag", etag.clone());
    }
    if let Some(sc) = &e.storage_class {
        i.set("StorageClass", sc.clone());
    }
    if !e.checksum_algorithms.is_empty() {
        i.set("ChecksumAlgorithm", e.checksum_algorithms.clone());
    }
    if let Some(ct) = &e.checksum_type {
        i.set("ChecksumType", ct.clone());
    }
    if let Some(o) = &e.owner {
        let mut m = BTreeMap::new();
        if let Some(d) = &o.display_name {
            m.insert("DisplayName".to_owned(), Value::Str(d.clone()));
        }
        if let Some(id) = &o.id {
            m.insert("ID".to_owned(), Value::Str(id.clone()));
        }
        i.set("Owner", m);
    }
    if let Some(r) = &e.restore_status {
        let mut m = BTreeMap::new();
        if let Some(p) = r.in_progress {
            m.insert("IsRestoreInProgress".to_owned(), Value::Bool(p));
        }
        if let Some(t) = r.expiry {
            m.insert("RestoreExpiryDate".to_owned(), Value::Time(t));
        }
        i.set("RestoreStatus", m);
    }
    if let Some(v) = &e.version_id {
        i.set("VersionId", v.clone());
    }
    if let Some(l) = e.is_latest {
        i.set("IsLatest", l);
    }
    i
}

/// A directory entry with `Key`/`Size`/`StorageClass` (common prefixes of
/// `ls` and directories inferred by `find`). `name` is `bucket/prefix`
/// without the trailing delimiter.
pub fn listed_dir_info(name: String) -> FileInfo {
    let mut i = FileInfo::directory(name.clone());
    i.set("Key", name);
    i.set("Size", 0u64);
    i.set("StorageClass", "DIRECTORY");
    i
}

/// `info()` of a directory (a prefix with keys below it).
pub fn dir_info(name: String) -> FileInfo {
    let mut i = FileInfo::directory(name);
    i.set("StorageClass", "DIRECTORY");
    i
}

/// `info()` of a bucket.
pub fn bucket_info(bucket: &str) -> FileInfo {
    let mut i = FileInfo::directory(bucket);
    i.set("StorageClass", "DIRECTORY");
    i.set("VersionId", Value::Null);
    i
}

/// `info("")`: the root.
pub fn root_info(name: &str) -> FileInfo {
    FileInfo::directory(name)
}

/// A bucket listed by `ls("")`.
pub fn listed_bucket_info(b: &BucketEntry) -> FileInfo {
    let mut i = FileInfo::directory(b.name.clone());
    i.created = b.creation_date;
    if let Some(t) = b.creation_date {
        i.set("CreationDate", t);
    }
    if let Some(r) = &b.region {
        i.set("BucketRegion", r.clone());
    }
    i.set("Key", b.name.clone());
    i.set("Size", 0u64);
    i.set("StorageClass", "BUCKET");
    i
}

#[cfg(test)]
mod tests {
    use fsfast_http_transport::header::HeaderValue;

    use super::*;

    #[test]
    fn head_info_has_s3fs_keys() {
        let mut h = HeaderMap::new();
        h.insert("content-length", HeaderValue::from_static("3"));
        h.insert("etag", HeaderValue::from_static("\"abc\""));
        h.insert(
            "last-modified",
            HeaderValue::from_static("Tue, 24 Nov 2026 17:27:28 GMT"),
        );
        h.insert("content-type", HeaderValue::from_static("text/plain"));
        let m = ObjectMeta::from_headers(&h, "b/k").unwrap();
        let i = m.to_info("b/k".into());
        let keys: Vec<_> = i.extra.keys().cloned().collect();
        assert_eq!(
            keys,
            vec![
                "ContentType",
                "ETag",
                "LastModified",
                "StorageClass",
                "VersionId"
            ]
        );
        assert_eq!(i.extra["StorageClass"], Value::Str("STANDARD".into()));
        assert_eq!(i.extra["VersionId"], Value::Null);
        assert_eq!(i.version.as_deref(), Some("\"abc\""));
        assert!(ObjectMeta::from_headers(&HeaderMap::new(), "b/k").is_err());
    }

    #[test]
    fn listing_info_and_versions() {
        let e = ObjectEntry {
            key: "dir/f".into(),
            size: 5,
            etag: Some("\"e\"".into()),
            version_id: Some("v1".into()),
            is_latest: Some(true),
            storage_class: Some("STANDARD".into()),
            ..ObjectEntry::default()
        };
        let i = object_info("b", &e, true);
        assert_eq!(i.name, "b/dir/f?versionId=v1");
        assert_eq!(i.extra["Key"], Value::Str("b/dir/f".into()));
        assert_eq!(i.extra["IsLatest"], Value::Bool(true));
        let i = object_info(
            "b",
            &ObjectEntry {
                version_id: Some("null".into()),
                ..e
            },
            true,
        );
        assert_eq!(i.name, "b/dir/f");
        let d = listed_dir_info("b/dir".into());
        assert!(d.is_dir());
        assert_eq!(d.extra["StorageClass"], Value::Str("DIRECTORY".into()));
    }
}
