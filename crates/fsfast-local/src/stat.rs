//! Building fsspec `LocalFileSystem.info()` results.
//!
//! fsspec reports `name`, `size`, `type`, `created`, `islink`, `mode`, `uid`,
//! `gid`, `mtime`, `ino`, `nlink` and, for symlinks, `destination`. Two
//! flavours exist and both are reproduced:
//!
//! * [`info_path`] (`info(str)`): a symlink is followed, so type, size and the
//!   stat fields describe the target (`islink` is true); a broken link is
//!   `NotFound`.
//! * [`info_entry`] (`info(DirEntry)`, used by `ls`/`find`): the stat fields
//!   come from `lstat`, a symlink's type is `"other"`, its size is the
//!   target's (0 if broken).
//!
//! `created` is `st_birthtime` where Python exposes it (macOS, BSD, Windows)
//! and `st_ctime` otherwise (Linux), as floats with the same arithmetic as
//! CPython (`sec + nsec * 1e-9`).

use std::fs::{self, DirEntry, File, Metadata};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fsfast_core::{Error, ErrorKind, FileInfo, FileType, Result, Value};

use crate::paths::join;

/// The [`ErrorKind`] for an I/O error, matching the exception class Python
/// raises for the same failure.
///
/// The core mapping follows `std::io::ErrorKind`, which turns `EINVAL` and
/// `ENAMETOOLONG` into `InvalidInput` (Python: `ValueError`) and
/// `EOPNOTSUPP` into `Unsupported` (`NotImplementedError`). For those errnos
/// Python raises a plain `OSError(errno, ...)` (PEP 3151 has no subclass for
/// them), and fsspec's local filesystem lets it through, so an OS error of
/// those kinds is reported as `Io` (the errno stays attached as a detail).
/// Errors fsfast synthesises itself keep their kind.
pub(crate) fn os_kind(e: &std::io::Error) -> ErrorKind {
    let kind = Error::from(std::io::Error::from(e.kind())).kind();
    match kind {
        ErrorKind::InvalidInput | ErrorKind::Unsupported if e.raw_os_error().is_some() => {
            ErrorKind::Io
        }
        k => k,
    }
}

/// Map an I/O error, naming the fsspec path.
pub(crate) fn io_err(e: std::io::Error, path: &str) -> Error {
    let kind = os_kind(&e);
    Error::from(e).with_kind(kind).with_path(path)
}

/// The subset of `os.stat_result` fsspec reports.
#[derive(Debug, Clone)]
pub(crate) struct Stat {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub ino: u64,
    pub nlink: u64,
    pub mtime: SystemTime,
    pub mtime_secs: f64,
    pub mtime_ns: i128,
    pub created: SystemTime,
    pub created_secs: f64,
}

fn system_time(sec: i64, nsec: i64) -> SystemTime {
    let nsec = nsec.clamp(0, 999_999_999) as u32;
    if sec >= 0 {
        UNIX_EPOCH + Duration::new(sec as u64, nsec)
    } else {
        UNIX_EPOCH - Duration::new(sec.unsigned_abs(), 0) + Duration::new(0, nsec)
    }
}

/// CPython's float timestamp: `sec + nsec * 1e-9`.
fn float_secs(sec: i64, nsec: i64) -> f64 {
    sec as f64 + nsec as f64 * 1e-9
}

#[cfg(windows)]
fn split_time(t: SystemTime) -> (i64, i64) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, i64::from(d.subsec_nanos())),
        Err(e) => {
            let d = e.duration();
            let mut sec = -(d.as_secs() as i64);
            let mut nsec = i64::from(d.subsec_nanos());
            if nsec > 0 {
                sec -= 1;
                nsec = 1_000_000_000 - nsec;
            }
            (sec, nsec)
        }
    }
}

#[cfg(unix)]
pub(crate) fn stat_of(meta: &Metadata) -> Stat {
    use std::os::unix::fs::MetadataExt;
    let (msec, mnsec) = (meta.mtime(), meta.mtime_nsec());
    // Linux/Android Python has no st_birthtime: fsspec falls back to st_ctime.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let (csec, cnsec) = (meta.ctime(), meta.ctime_nsec());
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let (csec, cnsec) = match meta
        .created()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
    {
        Some(d) => (d.as_secs() as i64, i64::from(d.subsec_nanos())),
        None => (meta.ctime(), meta.ctime_nsec()),
    };
    Stat {
        mode: meta.mode(),
        uid: meta.uid(),
        gid: meta.gid(),
        ino: meta.ino(),
        nlink: meta.nlink(),
        mtime: system_time(msec, mnsec),
        mtime_secs: float_secs(msec, mnsec),
        mtime_ns: i128::from(msec) * 1_000_000_000 + i128::from(mnsec),
        created: system_time(csec, cnsec),
        created_secs: float_secs(csec, cnsec),
    }
}

#[cfg(windows)]
pub(crate) fn stat_of(meta: &Metadata) -> Stat {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    // CPython's attributes_to_mode().
    let attrs = meta.file_attributes();
    let mut mode: u32 =
        if meta.file_type().is_symlink() && attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            0o120000
        } else if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
            0o040000 | 0o111
        } else {
            0o100000
        };
    mode |= if attrs & FILE_ATTRIBUTE_READONLY != 0 {
        0o444
    } else {
        0o666
    };
    let (msec, mnsec) = split_time(meta.modified().unwrap_or(UNIX_EPOCH));
    let (csec, cnsec) = split_time(meta.created().unwrap_or(UNIX_EPOCH));
    Stat {
        mode,
        uid: 0,
        gid: 0,
        // Stable Rust exposes neither the file index nor the link count
        // without opening the file; reported as 0 / 1.
        ino: 0,
        nlink: 1,
        mtime: system_time(msec, mnsec),
        mtime_secs: float_secs(msec, mnsec),
        mtime_ns: i128::from(msec) * 1_000_000_000 + i128::from(mnsec),
        created: system_time(csec, cnsec),
        created_secs: float_secs(csec, cnsec),
    }
}

fn type_of(meta: &Metadata) -> FileType {
    if meta.is_dir() {
        FileType::Directory
    } else if meta.is_file() {
        FileType::File
    } else {
        FileType::Other
    }
}

fn build(
    name: String,
    st: &Stat,
    file_type: FileType,
    size: u64,
    islink: bool,
    destination: Option<String>,
) -> FileInfo {
    let mut info = FileInfo {
        name,
        size,
        file_type,
        modified: Some(st.mtime),
        created: Some(st.created),
        version: Some(format!("{:x}-{:x}-{:x}", st.ino, st.mtime_ns, size)),
        extra: Default::default(),
    };
    info.set("created", Value::Float(st.created_secs));
    info.set("islink", islink);
    info.set("mode", st.mode);
    info.set("uid", st.uid);
    info.set("gid", st.gid);
    info.set("mtime", Value::Float(st.mtime_secs));
    info.set("ino", st.ino);
    info.set("nlink", st.nlink);
    if let Some(d) = destination {
        info.set("destination", d);
    }
    info
}

fn read_link(path: &str) -> Result<String> {
    fs::read_link(path)
        .map(|t| t.to_string_lossy().into_owned())
        .map_err(|e| io_err(e, path))
}

/// fsspec `info(path)` for a stripped path.
pub(crate) fn info_path(name: &str) -> Result<FileInfo> {
    let lmeta = fs::symlink_metadata(name).map_err(|e| io_err(e, name))?;
    let link = lmeta.file_type().is_symlink();
    let meta = if link {
        fs::metadata(name).map_err(|e| io_err(e, name))?
    } else {
        lmeta
    };
    let destination = if link { Some(read_link(name)?) } else { None };
    Ok(build(
        name.to_owned(),
        &stat_of(&meta),
        type_of(&meta),
        meta.len(),
        link,
        destination,
    ))
}

/// fsspec `info(DirEntry)`; `name` is the entry's stripped path.
pub(crate) fn info_entry(name: String, entry: &DirEntry) -> Result<FileInfo> {
    let lmeta = entry.metadata().map_err(|e| io_err(e, &name))?;
    let ft = lmeta.file_type();
    let link = ft.is_symlink();
    let file_type = if ft.is_dir() {
        FileType::Directory
    } else if ft.is_file() {
        FileType::File
    } else {
        FileType::Other
    };
    let (size, destination) = if link {
        // Use the OS path, not `name`: a non-UTF-8 file name is only
        // approximated by `name` (lossy) and would not resolve.
        let os_path = entry.path();
        let size = fs::metadata(&os_path).map(|m| m.len()).unwrap_or(0);
        let destination = fs::read_link(&os_path)
            .map(|t| t.to_string_lossy().into_owned())
            .map_err(|e| io_err(e, &name))?;
        (size, Some(destination))
    } else {
        (lmeta.len(), None)
    };
    Ok(build(
        name,
        &stat_of(&lmeta),
        file_type,
        size,
        link,
        destination,
    ))
}

/// Info for a file just opened at `name` (`fstat` of the handle, plus the
/// `islink`/`destination` of the path), consistent with [`info_path`].
pub(crate) fn info_open(name: &str, file: &File) -> Result<FileInfo> {
    let meta = file.metadata().map_err(|e| io_err(e, name))?;
    if meta.is_dir() {
        return Err(Error::is_a_directory(name));
    }
    let link = fs::symlink_metadata(name)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    let destination = if link { read_link(name).ok() } else { None };
    Ok(build(
        name.to_owned(),
        &stat_of(&meta),
        type_of(&meta),
        meta.len(),
        link,
        destination,
    ))
}

/// The entries of directory `dir` (a stripped path) as fsspec's `ls` reports
/// them; entries that vanish while listing are skipped, like fsspec does.
pub(crate) fn list_dir(dir: &str) -> Result<Vec<FileInfo>> {
    let rd = fs::read_dir(dir).map_err(|e| io_err(e, dir))?;
    let mut out = Vec::new();
    for entry in rd {
        let entry = entry.map_err(|e| io_err(e, dir))?;
        let file_name = entry.file_name();
        let name = match file_name.to_str() {
            Some(s) => join(dir, s),
            None => {
                // Python would carry surrogate escapes; Rust strings cannot.
                tracing::warn!(dir, name = ?file_name, "non-UTF-8 file name listed lossily");
                join(dir, &file_name.to_string_lossy())
            }
        };
        match info_entry(name, &entry) {
            Ok(i) => out.push(i),
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// fsspec `ls(path, detail=True)`, sorted by name.
pub(crate) fn ls(path: &str) -> Result<Vec<FileInfo>> {
    let info = info_path(path)?;
    if !info.is_dir() {
        return Ok(vec![info]);
    }
    let mut v = list_dir(path)?;
    v.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(v)
}

/// Whether `path` exists, following symlinks (`os.path.exists`: any error,
/// including a broken symlink or a permission problem, means "no").
pub(crate) fn exists(path: &Path) -> bool {
    fs::metadata(path).is_ok()
}

/// Whether `path` is a regular file or a directory (following symlinks), as
/// `os.path.isfile` / `os.path.isdir` see it. Errors other than "does not
/// exist" are returned so callers can report them precisely.
pub(crate) fn kind_of(path: &Path) -> std::io::Result<Option<FileType>> {
    match fs::metadata(path) {
        Ok(m) => Ok(Some(type_of(&m))),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_seconds_match_cpython_arithmetic() {
        // CPython: 1795515897 + 894360800 * 1e-9
        let f = float_secs(1_795_515_897, 894_360_800);
        assert_eq!(f, 1_795_515_897f64 + 894_360_800f64 * 1e-9);
        assert_eq!(system_time(1, 5), UNIX_EPOCH + Duration::new(1, 5));
        assert_eq!(system_time(-2, 0), UNIX_EPOCH - Duration::from_secs(2));
    }
}
