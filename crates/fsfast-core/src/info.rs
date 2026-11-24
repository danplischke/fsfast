//! File metadata.

use std::collections::BTreeMap;
use std::time::SystemTime;

use crate::Value;

/// Kind of filesystem entry, using fsspec's vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    File,
    Directory,
    Symlink,
    Other,
}

impl FileType {
    /// The string fsspec puts in `info()["type"]`.
    pub fn as_fsspec_str(self) -> &'static str {
        match self {
            FileType::File => "file",
            FileType::Directory => "directory",
            FileType::Symlink => "link",
            FileType::Other => "other",
        }
    }

    pub fn is_dir(self) -> bool {
        self == FileType::Directory
    }

    pub fn is_file(self) -> bool {
        self == FileType::File
    }
}

/// Metadata for one entry, as returned by `info()`, `ls()` and `find()`.
///
/// The Python layer builds the fsspec `info()` dict as
/// `{"name": name, "size": size, "type": file_type, **extra}`.
/// Backends therefore put the *reference implementation's* native keys into
/// [`FileInfo::extra`] (s3fs: `ETag`, `LastModified`, `StorageClass`,
/// `VersionId`; local: `mtime`, `created`, `mode`, `islink`, `uid`, `gid`,
/// `ino`, `nlink`; ...) so that user code indexing those keys keeps working.
#[derive(Debug, Clone, PartialEq)]
pub struct FileInfo {
    /// Full path in fsspec form (protocol stripped), e.g. `bucket/dir/key`,
    /// `/abs/local/path`, `/share/dir/file` (SMB). Directories carry no
    /// trailing slash.
    pub name: String,
    /// Size in bytes; 0 for directories unless the backend reports otherwise.
    pub size: u64,
    pub file_type: FileType,
    /// Last modification time, used by `fs.modified()`.
    pub modified: Option<SystemTime>,
    /// Creation time, used by `fs.created()`.
    pub created: Option<SystemTime>,
    /// Opaque version token (ETag, generation, version id, change time ...).
    /// Read handles pin to it when the backend supports conditional reads, and
    /// `fs.ukey()` derives from it.
    pub version: Option<String>,
    /// Backend-native fields; see the type-level docs.
    pub extra: BTreeMap<String, Value>,
}

impl FileInfo {
    pub fn file(name: impl Into<String>, size: u64) -> Self {
        FileInfo {
            name: name.into(),
            size,
            file_type: FileType::File,
            modified: None,
            created: None,
            version: None,
            extra: BTreeMap::new(),
        }
    }

    pub fn directory(name: impl Into<String>) -> Self {
        FileInfo {
            name: name.into(),
            size: 0,
            file_type: FileType::Directory,
            modified: None,
            created: None,
            version: None,
            extra: BTreeMap::new(),
        }
    }

    pub fn is_dir(&self) -> bool {
        self.file_type.is_dir()
    }

    pub fn is_file(&self) -> bool {
        self.file_type.is_file()
    }

    pub fn with_modified(mut self, t: Option<SystemTime>) -> Self {
        self.modified = t;
        self
    }

    pub fn with_version(mut self, v: Option<String>) -> Self {
        self.version = v;
        self
    }

    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }

    /// Insert a native field.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<Value>) {
        self.extra.insert(key.into(), value.into());
    }
}
