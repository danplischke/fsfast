//! The compiled-in backends and the `make_filesystem` factory.
//!
//! [`BACKENDS`] is the one place that knows every backend. Each entry is
//! gated by a cargo feature of the same name (all on by default), so wiring
//! a new backend crate is one feature line in `Cargo.toml` plus one table
//! entry here (and, for backend-specific methods, a dispatcher in
//! [`crate::ext`]).

use std::any::Any;
use std::sync::Arc;

use fsfast_core::{DynFileSystem, Error, FileInfo, FileType, Options, Result};
use futures::future::BoxFuture;
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::PyString;

use crate::out::PyOut;

/// The concrete backend object behind a [`DynFileSystem`], for
/// backend-specific methods (`Arc<S3FileSystem>`, ...).
pub(crate) type AnyFs = Arc<dyn Any + Send + Sync>;

/// A built backend: the trait object plus the same instance as [`AnyFs`].
pub(crate) struct Built {
    /// The backend as a [`fsfast_core::FileSystem`].
    pub fs: DynFileSystem,
    /// The same backend, downcastable to its concrete type.
    pub any: AnyFs,
    /// The backend's own wire-request counters, for backends that keep
    /// them (network backends); `None` for in-process ones.
    pub wire: Option<Arc<fsfast_engine::Stats>>,
}

impl Built {
    /// Wrap a concrete backend.
    #[allow(dead_code)] // unused only in a build without any backend feature
    fn new<T: fsfast_core::FileSystem + Send + Sync + 'static>(fs: T) -> Built {
        let fs = Arc::new(fs);
        Built {
            fs: fs.clone(),
            any: fs,
            wire: None,
        }
    }

    /// Attach the backend's wire-request counters.
    #[allow(dead_code)] // unused only in a build without a network backend
    fn with_wire(mut self, stats: Arc<fsfast_engine::Stats>) -> Built {
        self.wire = Some(stats);
        self
    }
}

/// A backend-specific method: `(backend, method name, keyword arguments)`.
pub(crate) type ExtCall = fn(AnyFs, String, Options) -> BoxFuture<'static, Result<PyOut>>;

/// Static description of a backend.
pub(crate) struct Backend {
    /// fsspec protocol names; the first is canonical.
    pub protocols: &'static [&'static str],
    /// Build an instance from `storage_options` (the backend's strict
    /// `from_options`).
    pub build: fn(Options) -> Result<Built>,
    /// Whether a forked child must build a fresh instance instead of reusing
    /// the parent's (backends holding sockets or connection pools bound to
    /// the parent's runtime). Backends without such state keep theirs, which
    /// also preserves state like an isolated memory store.
    pub rebuild_after_fork: bool,
    /// Key orders of the reference implementation's info dicts. A layout
    /// lists `FileInfo::extra` keys and may also place `name`, `size` and
    /// `type` (otherwise those come first); extra keys not listed follow,
    /// sorted. Most backends have one layout; object stores whose reference
    /// builds differently ordered dicts for HEAD and listing results have
    /// several, chosen per entry by [`Backend::select`].
    pub layouts: &'static [&'static [&'static str]],
    /// Index into `layouts` for one entry.
    pub select: fn(&FileInfo) -> usize,
    /// Backend-specific methods (`RustFileSystem.call`).
    pub ext: Option<ExtCall>,
    /// Interned Python strings for each layout (built on first use).
    keys_cache: PyOnceLock<Vec<Vec<Py<PyString>>>>,
}

fn first_layout(_: &FileInfo) -> usize {
    0
}

impl Backend {
    // Unused only in a build without any backend feature.
    #[allow(dead_code)]
    const fn new(
        protocols: &'static [&'static str],
        build: fn(Options) -> Result<Built>,
        rebuild_after_fork: bool,
        layouts: &'static [&'static [&'static str]],
    ) -> Self {
        Backend {
            protocols,
            build,
            rebuild_after_fork,
            layouts,
            select: first_layout,
            ext: None,
            keys_cache: PyOnceLock::new(),
        }
    }

    #[allow(dead_code)]
    const fn with_select(mut self, select: fn(&FileInfo) -> usize) -> Self {
        self.select = select;
        self
    }

    #[allow(dead_code)]
    const fn with_ext(mut self, ext: ExtCall) -> Self {
        self.ext = Some(ext);
        self
    }

    /// Canonical protocol name.
    pub(crate) fn name(&self) -> &'static str {
        self.protocols[0]
    }

    /// The layout for `info` and its keys as interned Python strings.
    pub(crate) fn layout<'a>(
        &'a self,
        py: Python<'_>,
        info: &FileInfo,
    ) -> (&'static [&'static str], &'a [Py<PyString>]) {
        let cache = self.keys_cache.get_or_init(py, || {
            self.layouts
                .iter()
                .map(|l| l.iter().map(|k| PyString::intern(py, k).unbind()).collect())
                .collect()
        });
        if self.layouts.is_empty() {
            return (&[], &[]);
        }
        let i = (self.select)(info).min(self.layouts.len() - 1);
        (self.layouts[i], &cache[i])
    }
}

// ---------------------------------------------------------------------------
// builders

#[cfg(feature = "local")]
fn build_local(opts: Options) -> Result<Built> {
    Ok(Built::new(fsfast_local::LocalFileSystem::from_options(
        opts,
    )?))
}

#[cfg(feature = "memory")]
fn build_memory(opts: Options) -> Result<Built> {
    Ok(Built::new(fsfast_memory::MemoryFileSystem::from_options(
        opts,
    )?))
}

#[cfg(feature = "http")]
fn build_http(opts: Options) -> Result<Built> {
    let fs = fsfast_http::HttpFileSystem::from_options(opts)?;
    let wire = fs.client().stats().clone();
    Ok(Built::new(fs).with_wire(wire))
}

#[cfg(feature = "s3")]
fn build_s3(opts: Options) -> Result<Built> {
    let fs = fsfast_s3::S3FileSystem::from_options(opts)?;
    let wire = fs.stats().clone();
    Ok(Built::new(fs).with_wire(wire))
}

#[cfg(feature = "smb")]
fn build_smb(opts: Options) -> Result<Built> {
    let fs = fsfast_smb::SmbFileSystem::from_options(opts)?;
    let wire = fs.stats().clone();
    Ok(Built::new(fs).with_wire(wire))
}

#[cfg(feature = "sftp")]
fn build_sftp(opts: Options) -> Result<Built> {
    let fs = fsfast_sftp::SftpFileSystem::from_options(opts)?;
    let wire = fs.stats().clone();
    Ok(Built::new(fs).with_wire(wire))
}

#[cfg(feature = "gcs")]
fn build_gcs(opts: Options) -> Result<Built> {
    let fs = fsfast_gcs::GCSFileSystem::from_options(opts)?;
    let wire = fs.stats().clone();
    Ok(Built::new(fs).with_wire(wire))
}

#[cfg(feature = "azure")]
fn build_azure(opts: Options) -> Result<Built> {
    let fs = fsfast_azure::AzureBlobFileSystem::from_options(opts)?;
    let wire = fs.stats().clone();
    Ok(Built::new(fs).with_wire(wire))
}

// ---------------------------------------------------------------------------
// table

#[cfg(feature = "local")]
static LOCAL: Backend = Backend::new(
    &["file", "local"],
    build_local,
    false,
    // fsspec LocalFileSystem.info()
    &[&[
        "created",
        "islink",
        "mode",
        "uid",
        "gid",
        "mtime",
        "ino",
        "nlink",
        "destination",
    ]],
);

#[cfg(feature = "memory")]
static MEMORY: Backend = Backend::new(&["memory"], build_memory, false, &[&["created"]]);

#[cfg(feature = "http")]
static HTTP: Backend = Backend::new(
    &["http", "https"],
    build_http,
    true,
    // fsspec http `_info`: {"name": url, "size": None, **_file_info(),
    // "type": "file"}; `_file_info` adds mimetype, partial, url and the
    // checksum headers in this order.
    &[&[
        "name",
        "size",
        "mimetype",
        "partial",
        "url",
        "ETag",
        "Content-MD5",
        "Digest",
        "Last-Modified",
        "type",
    ]],
);

/// s3fs dict layouts: HEAD of a key, listing entries (boto's key order
/// followed by s3fs's `type`/`size`/`name`), `ls("")` bucket entries, and
/// directories found by probing.
#[cfg(feature = "s3")]
const S3_LAYOUTS: &[&[&str]] = &[
    // 0: head_object (s3fs `_info`)
    &[
        "ETag",
        "LastModified",
        "size",
        "name",
        "type",
        "StorageClass",
        "VersionId",
        "ContentType",
    ],
    // 1: list_objects_v2 / list_object_versions entries and CommonPrefixes
    &[
        "Key",
        "LastModified",
        "ETag",
        "ChecksumAlgorithm",
        "ChecksumType",
        "Size",
        "StorageClass",
        "Owner",
        "RestoreStatus",
        "VersionId",
        "IsLatest",
        "type",
        "size",
        "name",
    ],
    // 2: list_buckets entries (`ls("")`)
    &[
        "CreationDate",
        "Key",
        "Size",
        "StorageClass",
        "size",
        "type",
        "name",
    ],
    // 3: directories and buckets from `info` (head_bucket / list probe)
    &["name", "type", "size", "StorageClass", "VersionId"],
];

#[cfg(feature = "s3")]
fn s3_select(i: &FileInfo) -> usize {
    if i.extra.contains_key("CreationDate") {
        2
    } else if i.extra.contains_key("Key") {
        1
    } else if i.file_type == FileType::Directory {
        3
    } else {
        0
    }
}

#[cfg(feature = "s3")]
static S3: Backend = Backend::new(&["s3", "s3a"], build_s3, true, S3_LAYOUTS)
    .with_select(s3_select)
    .with_ext(crate::ext::s3);

#[cfg(feature = "smb")]
static SMB: Backend =
    Backend::new(&["smb"], build_smb, true, &[fsfast_smb::INFO_KEYS]).with_ext(crate::ext::smb);

#[cfg(feature = "sftp")]
static SFTP: Backend = Backend::new(
    &["sftp", "ssh"],
    build_sftp,
    true,
    &[fsfast_sftp::INFO_KEYS],
)
.with_ext(crate::ext::sftp);

/// gcsfs dict layouts. Object entries carry the JSON resource's fields in
/// the order the server sends them; fsfast cannot observe that order, so it
/// uses the order of Google's JSON API (`kind, id, selfLink, mediaLink,
/// name, bucket, ...`) followed by gcsfs's `type`, `mtime`, `ctime`.
#[cfg(feature = "gcs")]
const GCS_LAYOUTS: &[&[&str]] = &[
    // 0: objects
    &[
        "kind",
        "id",
        "selfLink",
        "mediaLink",
        "name",
        "bucket",
        "generation",
        "metageneration",
        "contentType",
        "storageClass",
        "size",
        "md5Hash",
        "contentEncoding",
        "contentDisposition",
        "contentLanguage",
        "cacheControl",
        "crc32c",
        "componentCount",
        "etag",
        "kmsKeyName",
        "temporaryHold",
        "eventBasedHold",
        "retentionExpirationTime",
        "timeCreated",
        "updated",
        "timeDeleted",
        "timeStorageClassUpdated",
        "customTime",
        "metadata",
        "acl",
        "owner",
        "customerEncryption",
        "timeFinalized",
        "softDeleteTime",
        "hardDeleteTime",
        "type",
        "mtime",
        "ctime",
    ],
    // 1: implied directories from ls / info
    &["bucket", "name", "size", "storageClass", "type"],
    // 2: directories derived by find(withdirs=True)
    &["Key", "Size", "name", "StorageClass", "type", "size"],
    // 3: buckets
    &[
        "kind",
        "selfLink",
        "id",
        "name",
        "projectNumber",
        "metageneration",
        "location",
        "storageClass",
        "etag",
        "defaultEventBasedHold",
        "timeCreated",
        "updated",
        "versioning",
        "locationType",
        "size",
        "type",
    ],
];

#[cfg(feature = "gcs")]
fn gcs_select(i: &FileInfo) -> usize {
    match i.extra.get("kind").and_then(|v| v.as_str()) {
        Some("storage#bucket") => 3,
        _ if i.file_type != FileType::Directory => 0,
        _ if i.extra.contains_key("Key") => 2,
        _ => 1,
    }
}

#[cfg(feature = "gcs")]
static GCS: Backend = Backend::new(&["gs", "gcs"], build_gcs, true, GCS_LAYOUTS)
    .with_select(gcs_select)
    .with_ext(crate::ext::gcs);

/// adlfs dict layouts: blob properties (adlfs `_details`) followed by
/// `name`, `size`, `type`; directory entries from `ls`/`info` (`size:
/// None`) and from `find` (`{"name", "type", "size": 0}`).
#[cfg(feature = "azure")]
const AZURE_LAYOUTS: &[&[&str]] = &[
    &[
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
        "name",
        "size",
        "type",
    ],
    &["name", "type", "size"],
];

#[cfg(feature = "azure")]
fn azure_select(i: &FileInfo) -> usize {
    // find() directories: no properties and a real size of 0.
    if i.file_type == FileType::Directory && i.extra.is_empty() {
        1
    } else {
        0
    }
}

#[cfg(feature = "azure")]
static AZURE: Backend = Backend::new(&["abfs", "az", "abfss"], build_azure, true, AZURE_LAYOUTS)
    .with_select(azure_select)
    .with_ext(crate::ext::azure);

/// Every compiled-in backend (add new backends here).
pub(crate) static BACKENDS: &[&Backend] = &[
    #[cfg(feature = "local")]
    &LOCAL,
    #[cfg(feature = "memory")]
    &MEMORY,
    #[cfg(feature = "http")]
    &HTTP,
    #[cfg(feature = "s3")]
    &S3,
    #[cfg(feature = "smb")]
    &SMB,
    #[cfg(feature = "sftp")]
    &SFTP,
    #[cfg(feature = "gcs")]
    &GCS,
    #[cfg(feature = "azure")]
    &AZURE,
];

/// The backend serving `protocol`.
pub(crate) fn lookup(protocol: &str) -> Result<&'static Backend> {
    BACKENDS
        .iter()
        .copied()
        .find(|b| b.protocols.contains(&protocol))
        .ok_or_else(|| {
            Error::unsupported(format!(
                "protocol {protocol:?} (compiled-in protocols: {})",
                available().join(", ")
            ))
        })
}

/// Every protocol name served by a compiled-in backend.
pub(crate) fn available() -> Vec<&'static str> {
    BACKENDS
        .iter()
        .flat_map(|b| b.protocols.iter().copied())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_by_any_alias() {
        #[cfg(feature = "local")]
        {
            assert_eq!(lookup("local").unwrap().name(), "file");
            assert_eq!(lookup("file").unwrap().name(), "file");
        }
        #[cfg(feature = "memory")]
        assert_eq!(lookup("memory").unwrap().name(), "memory");
        #[cfg(feature = "s3")]
        assert_eq!(lookup("s3a").unwrap().name(), "s3");
        #[cfg(feature = "sftp")]
        assert_eq!(lookup("ssh").unwrap().name(), "sftp");
        #[cfg(feature = "gcs")]
        assert_eq!(lookup("gcs").unwrap().name(), "gs");
        #[cfg(feature = "azure")]
        {
            assert_eq!(lookup("az").unwrap().name(), "abfs");
            assert_eq!(lookup("abfss").unwrap().name(), "abfs");
        }
        #[cfg(feature = "http")]
        assert_eq!(lookup("https").unwrap().name(), "http");
        let e = lookup("nope").err().unwrap();
        assert_eq!(e.kind(), fsfast_core::ErrorKind::Unsupported);
        assert!(e.to_string().contains("nope"));
    }

    #[test]
    fn protocols_match_the_backends() {
        // The table's protocol names must be the ones each backend reports.
        for b in BACKENDS {
            let mut o = Options::new();
            if b.name() == "smb" || b.name() == "sftp" {
                o.insert("host".into(), fsfast_core::Value::Str("127.0.0.1".into()));
            }
            if b.name() == "abfs" {
                o.insert(
                    "account_name".into(),
                    fsfast_core::Value::Str("devstoreaccount1".into()),
                );
                o.insert("anon".into(), fsfast_core::Value::Bool(true));
            }
            if b.name() == "gs" {
                o.insert("token".into(), fsfast_core::Value::Str("anon".into()));
            }
            if b.name() == "s3" {
                o.insert("anon".into(), fsfast_core::Value::Bool(true));
            }
            let built = (b.build)(o).unwrap_or_else(|e| panic!("{}: {e}", b.name()));
            assert_eq!(built.fs.protocols(), b.protocols, "{}", b.name());
        }
    }

    #[test]
    fn builders_are_strict() {
        for b in BACKENDS {
            let mut o = Options::new();
            o.insert("bogus_option_name".into(), fsfast_core::Value::Int(1));
            assert!(
                (b.build)(o).is_err(),
                "{} accepted an unknown option",
                b.name()
            );
        }
    }

    #[cfg(feature = "s3")]
    #[test]
    fn s3_layouts_follow_s3fs() {
        let mut head = FileInfo::file("b/k", 1);
        head.extra
            .insert("ETag".into(), fsfast_core::Value::Str("x".into()));
        assert_eq!(s3_select(&head), 0);
        let mut listed = head.clone();
        listed
            .extra
            .insert("Key".into(), fsfast_core::Value::Str("b/k".into()));
        assert_eq!(s3_select(&listed), 1);
        let mut bucket = FileInfo::directory("b");
        bucket
            .extra
            .insert("CreationDate".into(), fsfast_core::Value::Null);
        assert_eq!(s3_select(&bucket), 2);
        assert_eq!(s3_select(&FileInfo::directory("b/d")), 3);
    }
}
