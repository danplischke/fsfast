//! Blob and container properties → [`FileInfo`] with adlfs's `info()` keys.
//!
//! adlfs `_details` forwards these `BlobProperties` fields (when present):
//! `metadata`, `creation_time`, `deleted`, `deleted_time`, `last_modified`,
//! `content_settings`, `remaining_retention_days`, `archive_status`,
//! `last_accessed_on`, `etag` (normalised to `"0x..."` with quotes),
//! `tags`, `tag_count`, and on version-aware filesystems `version_id` and
//! `is_current_version`; then `name`, `size` and `type`. Directories have
//! `size: None` (stored here as an `extra["size"] = None` override, which the
//! Python layer applies after the typed size). A blob is a directory when
//! its metadata says `is_directory=true` or `hdi_isfolder=true` (ADLS Gen2
//! markers), and a file when `is_directory=false`.

use std::collections::BTreeMap;
use std::time::SystemTime;

use base64::Engine as _;
use fsfast_core::{Error, FileInfo, FileType, Result, Value};
use fsfast_http_transport::header::HeaderMap;

use crate::time::parse_rfc1123;
use crate::xml::Element;

/// adlfs's key order of the native fields (for the Python layer's registry).
pub const INFO_KEYS: &[&str] = &[
    "metadata",
    "creation_time",
    "deleted",
    "deleted_time",
    "last_modified",
    "content_time",
    "content_settings",
    "remaining_retention_days",
    "archive_status",
    "last_accessed_on",
    "etag",
    "tags",
    "tag_count",
    "version_id",
    "is_current_version",
];

/// Blob type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlobType {
    /// Block blob (the default).
    #[default]
    Block,
    /// Append blob.
    Append,
    /// Page blob.
    Page,
}

impl BlobType {
    fn parse(s: &str) -> Self {
        match s {
            "AppendBlob" => BlobType::Append,
            "PageBlob" => BlobType::Page,
            _ => BlobType::Block,
        }
    }
}

/// Content settings (`ContentSettings`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentSettings {
    /// Content-Type.
    pub content_type: Option<String>,
    /// Content-Encoding.
    pub content_encoding: Option<String>,
    /// Content-Language.
    pub content_language: Option<String>,
    /// Content-MD5 (decoded).
    pub content_md5: Option<Vec<u8>>,
    /// Content-Disposition.
    pub content_disposition: Option<String>,
    /// Cache-Control.
    pub cache_control: Option<String>,
}

impl ContentSettings {
    fn to_value(&self) -> Value {
        let s = |v: &Option<String>| v.clone().map_or(Value::Null, Value::Str);
        let mut m = BTreeMap::new();
        m.insert("content_type".into(), s(&self.content_type));
        m.insert("content_encoding".into(), s(&self.content_encoding));
        m.insert("content_language".into(), s(&self.content_language));
        m.insert(
            "content_md5".into(),
            self.content_md5.clone().map_or(Value::Null, Value::Bytes),
        );
        m.insert("content_disposition".into(), s(&self.content_disposition));
        m.insert("cache_control".into(), s(&self.cache_control));
        Value::Map(m)
    }
}

/// Properties of one blob (from `Get Blob Properties` headers or a listing).
#[derive(Debug, Clone, Default)]
pub struct BlobProps {
    /// Blob name within the container.
    pub name: String,
    /// Content length.
    pub size: u64,
    /// ETag as sent (listing: unquoted).
    pub etag: Option<String>,
    /// Last-Modified.
    pub last_modified: Option<SystemTime>,
    /// Creation time.
    pub creation_time: Option<SystemTime>,
    /// Blob type.
    pub blob_type: BlobType,
    /// Content settings.
    pub content: ContentSettings,
    /// User metadata.
    pub metadata: BTreeMap<String, String>,
    /// `Deleted` (listing) / `False` (properties).
    pub deleted: Option<bool>,
    /// Deleted time.
    pub deleted_time: Option<SystemTime>,
    /// Remaining retention days.
    pub remaining_retention_days: Option<i64>,
    /// Archive status.
    pub archive_status: Option<String>,
    /// Last access time.
    pub last_accessed_on: Option<SystemTime>,
    /// Tag count.
    pub tag_count: Option<i64>,
    /// Version id.
    pub version_id: Option<String>,
    /// Whether this is the current version.
    pub is_current_version: Option<bool>,
    /// Committed block count (append blobs).
    pub committed_block_count: Option<u64>,
}

/// `"0x..."` with exactly one pair of quotes (adlfs `_normalize_etag_quotes`).
pub fn normalize_etag(etag: &str) -> String {
    format!("\"{}\"", etag.trim_matches('"'))
}

fn t(v: Option<SystemTime>) -> Value {
    v.map_or(Value::Null, Value::Time)
}

impl BlobProps {
    /// Parse `Get Blob Properties` / `Get Blob` response headers.
    pub fn from_headers(name: &str, h: &HeaderMap) -> Result<Self> {
        let s = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let size = match h.get("content-range").and_then(|v| v.to_str().ok()) {
            // A ranged GET: the total is after the slash.
            Some(cr) => cr
                .rsplit('/')
                .next()
                .and_then(|n| n.trim().parse().ok())
                .ok_or_else(|| Error::protocol(format!("bad Content-Range {cr:?}")))?,
            None => s("content-length")
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| Error::protocol("response has no Content-Length"))?,
        };
        let mut metadata = BTreeMap::new();
        for (k, v) in h {
            if let Some(m) = k.as_str().strip_prefix("x-ms-meta-") {
                metadata.insert(
                    m.to_owned(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                );
            }
        }
        // On a ranged GET the whole blob's MD5 is in x-ms-blob-content-md5.
        let md5 = s("x-ms-blob-content-md5").or_else(|| {
            if h.contains_key("content-range") {
                None
            } else {
                s("content-md5")
            }
        });
        Ok(BlobProps {
            name: name.to_owned(),
            size,
            etag: s("etag"),
            last_modified: s("last-modified").as_deref().and_then(parse_rfc1123),
            creation_time: s("x-ms-creation-time").as_deref().and_then(parse_rfc1123),
            blob_type: s("x-ms-blob-type")
                .as_deref()
                .map(BlobType::parse)
                .unwrap_or_default(),
            content: ContentSettings {
                content_type: s("content-type"),
                content_encoding: s("content-encoding"),
                content_language: s("content-language"),
                content_md5: md5
                    .and_then(|m| base64::engine::general_purpose::STANDARD.decode(m).ok()),
                content_disposition: s("content-disposition"),
                cache_control: s("cache-control"),
            },
            metadata,
            deleted: Some(false),
            deleted_time: None,
            remaining_retention_days: None,
            archive_status: s("x-ms-archive-status"),
            last_accessed_on: s("x-ms-last-access-time")
                .as_deref()
                .and_then(parse_rfc1123),
            tag_count: s("x-ms-tag-count").and_then(|v| v.parse().ok()),
            version_id: s("x-ms-version-id"),
            is_current_version: s("x-ms-is-current-version")
                .map(|v| v.eq_ignore_ascii_case("true")),
            committed_block_count: s("x-ms-blob-committed-block-count")
                .and_then(|v| v.parse().ok()),
        })
    }

    /// Parse a `<Blob>` element of a List Blobs response.
    pub fn from_xml(el: &Element<'_>) -> Result<Self> {
        let name_el = el
            .child("Name")
            .ok_or_else(|| Error::protocol("listing entry without Name"))?;
        let name = decode_name(name_el);
        let props = el.child("Properties");
        let p = |k: &str| props.and_then(|p| p.child_nonempty(k)).map(str::to_owned);
        let size = p("Content-Length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut metadata = BTreeMap::new();
        if let Some(m) = el.child("Metadata") {
            for c in &m.children {
                metadata.insert(c.name.to_owned(), c.text.to_string());
            }
        }
        Ok(BlobProps {
            name,
            size,
            etag: p("Etag"),
            last_modified: p("Last-Modified").as_deref().and_then(parse_rfc1123),
            creation_time: p("Creation-Time").as_deref().and_then(parse_rfc1123),
            blob_type: p("BlobType")
                .as_deref()
                .map(BlobType::parse)
                .unwrap_or_default(),
            content: ContentSettings {
                content_type: p("Content-Type"),
                content_encoding: p("Content-Encoding"),
                content_language: p("Content-Language"),
                content_md5: p("Content-MD5")
                    .and_then(|m| base64::engine::general_purpose::STANDARD.decode(m).ok()),
                content_disposition: p("Content-Disposition"),
                cache_control: p("Cache-Control"),
            },
            metadata,
            deleted: el.child_nonempty("Deleted").map(|v| v == "true"),
            deleted_time: p("DeletedTime").as_deref().and_then(parse_rfc1123),
            remaining_retention_days: p("RemainingRetentionDays").and_then(|v| v.parse().ok()),
            archive_status: p("ArchiveStatus"),
            last_accessed_on: p("LastAccessTime").as_deref().and_then(parse_rfc1123),
            tag_count: p("TagCount").and_then(|v| v.parse().ok()),
            version_id: el.child_nonempty("VersionId").map(str::to_owned),
            is_current_version: el.child_nonempty("IsCurrentVersion").map(|v| v == "true"),
            committed_block_count: None,
        })
    }

    /// What adlfs's `_details` makes of the metadata: `Some(true)` for a
    /// directory marker, `Some(false)` for an explicit file, `None` otherwise.
    pub fn metadata_dir_flag(&self) -> Option<bool> {
        match self.metadata.get("is_directory").map(String::as_str) {
            Some("true") => return Some(true),
            Some("false") => return Some(false),
            _ => {}
        }
        let hdi = self
            .metadata
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("hdi_isfolder") && v == "true");
        hdi.then_some(true)
    }

    /// Whether adlfs reports this blob as a directory.
    pub fn is_dir_marker(&self) -> bool {
        self.metadata_dir_flag() == Some(true)
    }

    /// The [`FileInfo`] adlfs's `_details` builds, named `container/name`
    /// (trailing slashes removed).
    pub fn to_info(&self, container: &str, version_aware: bool) -> FileInfo {
        let name = format!("{container}/{}", self.name);
        let name = name.trim_end_matches('/').to_owned();
        let is_dir = self.is_dir_marker();
        let mut info = if is_dir {
            FileInfo::directory(name)
        } else {
            FileInfo::file(name, self.size)
        };
        info.modified = self.last_modified;
        info.created = self.creation_time;
        info.version = if version_aware && self.version_id.is_some() {
            self.version_id.clone()
        } else {
            self.etag.as_deref().map(normalize_etag)
        };
        let meta: BTreeMap<String, Value> = self
            .metadata
            .iter()
            .map(|(k, v)| (k.clone(), Value::Str(v.clone())))
            .collect();
        info.set("metadata", Value::Map(meta));
        info.set("creation_time", t(self.creation_time));
        info.set("deleted", self.deleted.map_or(Value::Null, Value::Bool));
        info.set("deleted_time", t(self.deleted_time));
        info.set("last_modified", t(self.last_modified));
        info.set("content_settings", self.content.to_value());
        info.set(
            "remaining_retention_days",
            self.remaining_retention_days
                .map_or(Value::Null, Value::Int),
        );
        info.set(
            "archive_status",
            self.archive_status.clone().map_or(Value::Null, Value::Str),
        );
        info.set("last_accessed_on", t(self.last_accessed_on));
        info.set(
            "etag",
            self.etag
                .as_deref()
                .map_or(Value::Null, |e| Value::Str(normalize_etag(e))),
        );
        info.set("tags", Value::Null);
        info.set("tag_count", self.tag_count.map_or(Value::Null, Value::Int));
        if version_aware {
            info.set(
                "version_id",
                self.version_id.clone().map_or(Value::Null, Value::Str),
            );
            info.set(
                "is_current_version",
                self.is_current_version.map_or(Value::Null, Value::Bool),
            );
        }
        if is_dir {
            info.set("size", Value::Null);
        }
        info
    }
}

/// A blob name from a listing (`Encoded="true"` names are percent-encoded).
pub fn decode_name(el: &Element<'_>) -> String {
    if el.attr("Encoded").as_deref() == Some("true") {
        crate::path::unquote(&el.text).into_owned()
    } else {
        el.text.to_string()
    }
}

/// A directory implied by a prefix (adlfs: name, `size: None`, type).
pub fn prefix_dir(name: impl Into<String>) -> FileInfo {
    let mut i = FileInfo::directory(name);
    i.set("size", Value::Null);
    i
}

/// A directory adlfs's `find` synthesises for intermediate paths (size 0).
pub fn synthetic_dir(name: impl Into<String>) -> FileInfo {
    FileInfo::directory(name)
}

/// Container properties.
#[derive(Debug, Clone, Default)]
pub struct ContainerProps {
    /// Container name.
    pub name: String,
    /// Last-Modified.
    pub last_modified: Option<SystemTime>,
    /// ETag.
    pub etag: Option<String>,
    /// Metadata.
    pub metadata: BTreeMap<String, String>,
    /// `Deleted` flag from listings with deleted containers.
    pub deleted: Option<bool>,
}

impl ContainerProps {
    /// From `Get Container Properties` headers.
    pub fn from_headers(name: &str, h: &HeaderMap) -> Self {
        let s = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let mut metadata = BTreeMap::new();
        for (k, v) in h {
            if let Some(m) = k.as_str().strip_prefix("x-ms-meta-") {
                metadata.insert(
                    m.to_owned(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                );
            }
        }
        ContainerProps {
            name: name.to_owned(),
            last_modified: s("last-modified").as_deref().and_then(parse_rfc1123),
            etag: s("etag"),
            metadata,
            deleted: None,
        }
    }

    /// From a `<Container>` element of List Containers.
    pub fn from_xml(el: &Element<'_>) -> Result<Self> {
        let name = el
            .child_text("Name")
            .ok_or_else(|| Error::protocol("container entry without Name"))?
            .to_owned();
        let props = el.child("Properties");
        let p = |k: &str| props.and_then(|p| p.child_nonempty(k)).map(str::to_owned);
        let mut metadata = BTreeMap::new();
        if let Some(m) = el.child("Metadata") {
            for c in &m.children {
                metadata.insert(c.name.to_owned(), c.text.to_string());
            }
        }
        Ok(ContainerProps {
            name,
            last_modified: p("Last-Modified").as_deref().and_then(parse_rfc1123),
            etag: p("Etag"),
            metadata,
            deleted: el.child_nonempty("Deleted").map(|v| v == "true"),
        })
    }

    /// adlfs's container entry: `metadata` (None when empty), `deleted`,
    /// `last_modified`, `etag`, `size: None`, type directory.
    pub fn to_info(&self) -> FileInfo {
        let mut info = FileInfo::directory(self.name.clone());
        info.modified = self.last_modified;
        info.version = self.etag.as_deref().map(normalize_etag);
        let meta = if self.metadata.is_empty() {
            Value::Null
        } else {
            Value::Map(
                self.metadata
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::Str(v.clone())))
                    .collect(),
            )
        };
        info.set("metadata", meta);
        info.set("deleted", self.deleted.map_or(Value::Null, Value::Bool));
        info.set("last_modified", t(self.last_modified));
        info.set(
            "etag",
            self.etag
                .as_deref()
                .map_or(Value::Null, |e| Value::Str(normalize_etag(e))),
        );
        info.set("size", Value::Null);
        info
    }
}

/// The account root (adlfs `info("")`).
pub fn root_info() -> FileInfo {
    prefix_dir("")
}

/// Whether `info` is a directory per its type.
pub fn is_dir(info: &FileInfo) -> bool {
    info.file_type == FileType::Directory
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsfast_http_transport::header::HeaderValue;

    #[test]
    fn from_headers() {
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("content-length", "2"),
            ("etag", "\"0x24C7D1836718C80\""),
            ("last-modified", "Wed, 25 Nov 2026 06:34:00 GMT"),
            ("x-ms-creation-time", "Wed, 25 Nov 2026 06:34:00 GMT"),
            ("x-ms-meta-m1", "v1"),
            ("x-ms-blob-type", "AppendBlob"),
            ("content-type", "application/octet-stream"),
            ("content-md5", "PkQQcXClIFgq3lIvpzwdFQ=="),
        ] {
            h.insert(k, HeaderValue::from_static(v));
        }
        let p = BlobProps::from_headers("a/b", &h).unwrap();
        assert_eq!(p.size, 2);
        assert_eq!(p.blob_type, BlobType::Append);
        let i = p.to_info("c", false);
        assert_eq!(i.name, "c/a/b");
        assert!(i.is_file());
        assert_eq!(i.extra["etag"], Value::Str("\"0x24C7D1836718C80\"".into()));
        assert_eq!(i.extra["deleted"], Value::Bool(false));
        assert!(!i.extra.contains_key("version_id"));
        let Value::Map(cs) = &i.extra["content_settings"] else {
            panic!()
        };
        assert_eq!(
            cs["content_md5"],
            Value::Bytes(
                base64::engine::general_purpose::STANDARD
                    .decode("PkQQcXClIFgq3lIvpzwdFQ==")
                    .unwrap()
            )
        );
    }

    #[test]
    fn markers() {
        let mut p = BlobProps {
            name: "d/".into(),
            ..BlobProps::default()
        };
        p.metadata.insert("Hdi_isfolder".into(), "true".into());
        let i = p.to_info("c", true);
        assert!(i.is_dir());
        assert_eq!(i.name, "c/d");
        assert_eq!(i.extra["size"], Value::Null);
        assert!(i.extra.contains_key("version_id"));
        p.metadata.insert("is_directory".into(), "false".into());
        assert!(p.to_info("c", false).is_file());
    }

    #[test]
    fn from_xml() {
        let doc = br#"<Blob><Name>top</Name><VersionId>2026-01-01T00:00:00.0000000Z</VersionId><IsCurrentVersion>true</IsCurrentVersion><Properties><Creation-Time>Wed, 25 Nov 2026 06:34:00 GMT</Creation-Time><Last-Modified>Wed, 25 Nov 2026 06:34:00 GMT</Last-Modified><Etag>0x1CEEED997B2A9C0</Etag><Content-Length>1</Content-Length><Content-Type>application/octet-stream</Content-Type><Content-MD5>ndTkYSaMgDT1yFZOFVxnpg==</Content-MD5><BlobType>BlockBlob</BlobType></Properties><Metadata><m1>v1</m1></Metadata></Blob>"#;
        let el = Element::parse(doc).unwrap();
        let p = BlobProps::from_xml(&el).unwrap();
        assert_eq!(p.size, 1);
        assert_eq!(p.metadata["m1"], "v1");
        assert_eq!(p.deleted, None);
        let i = p.to_info("c", true);
        assert_eq!(i.extra["etag"], Value::Str("\"0x1CEEED997B2A9C0\"".into()));
        assert_eq!(i.extra["is_current_version"], Value::Bool(true));
        assert_eq!(i.version.as_deref(), Some("2026-01-01T00:00:00.0000000Z"));
    }

    #[test]
    fn containers() {
        let el = Element::parse(b"<Container><Name>c</Name><Properties><Last-Modified>Wed, 25 Nov 2026 06:34:00 GMT</Last-Modified><Etag>\"0x1\"</Etag></Properties><Metadata/></Container>").unwrap();
        let i = ContainerProps::from_xml(&el).unwrap().to_info();
        assert_eq!(i.name, "c");
        assert!(i.is_dir());
        assert_eq!(i.extra["metadata"], Value::Null);
        assert_eq!(i.extra["etag"], Value::Str("\"0x1\"".into()));
    }
}
