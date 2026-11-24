//! Blocking filesystem operations. Callers run these inside
//! `tokio::task::spawn_blocking`.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fsfast_core::WriteMode;

/// `os.makedirs(path, exist_ok)`, step for step: parents that do not exist
/// (following symlinks) are created first, then the leaf; with `exist_ok`
/// a failure is ignored only if the leaf is a directory afterwards. Error
/// kinds therefore match Python's (a file in the way of a parent gives
/// `NotADirectory` when creating the leaf, an existing leaf `AlreadyExists`).
pub(crate) fn makedirs(path: &Path, exist_ok: bool) -> io::Result<()> {
    // os.makedirs splits the path textually: for `x/new/.` it creates `x/new`
    // and stops there. `Path::parent` normalises the trailing `.` away (it
    // would return `x`), so handle that form first.
    if let Some(head) = path
        .to_str()
        .and_then(|s| s.strip_suffix("/."))
        .filter(|h| !h.is_empty())
        .map(Path::new)
        && !head.exists()
    {
        return match makedirs(head, exist_ok) {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            r => r,
        };
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        match makedirs(parent, exist_ok) {
            // Lost a race with a concurrent creator: fine.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            r => r?,
        }
    }
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(_) if exist_ok && path.is_dir() => Ok(()),
        Err(e) => Err(e),
    }
}

/// Whether two metadata records describe the same file (`os.path.samestat`).
#[cfg(unix)]
fn same_file(a: &Metadata, b: &Metadata, _pa: &Path, _pb: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(windows)]
fn same_file(_a: &Metadata, _b: &Metadata, pa: &Path, pb: &Path) -> bool {
    match (fs::canonicalize(pa), fs::canonicalize(pb)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

#[cfg(unix)]
fn is_fifo(m: &Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    m.file_type().is_fifo()
}

#[cfg(windows)]
fn is_fifo(_m: &Metadata) -> bool {
    false
}

/// Open `dst` for writing in `mode` (`wb`: create or truncate, `xb`: create
/// exclusively with `O_EXCL`, `ab`: create or append).
pub(crate) fn open_for_write(dst: &Path, mode: WriteMode) -> io::Result<File> {
    let mut oo = OpenOptions::new();
    match mode {
        WriteMode::Overwrite => oo.write(true).create(true).truncate(true),
        WriteMode::CreateNew => oo.write(true).create_new(true),
        WriteMode::Append => oo.append(true).create(true),
    };
    oo.open(dst)
}

/// `shutil.copyfile(src, dst)`: copy the content only (the destination gets
/// default permissions), refusing to copy a file onto itself or into a named
/// pipe. Uses `std::io::copy` between two `File`s, which the standard library
/// turns into `copy_file_range(2)` (reflink/in-kernel copy) or `sendfile` on
/// Linux, so the data never passes through user space. Returns the bytes
/// copied.
///
/// `mode` decides how an existing destination is treated (`wb`, `xb`, `ab`).
/// Unlike `shutil.copyfile`, a copy that fails half-way does not leave a
/// partial destination behind: a file this call created or truncated is
/// removed again, an appended-to file is cut back to its previous length.
pub(crate) fn copy_file(src: &Path, dst: &Path, mode: WriteMode) -> io::Result<u64> {
    let mut reader = File::open(src)?;
    let src_meta = reader.metadata()?;
    if src_meta.is_dir() {
        return Err(io::Error::from(io::ErrorKind::IsADirectory));
    }
    if let Ok(dst_meta) = fs::metadata(dst) {
        if same_file(&src_meta, &dst_meta, src, dst) {
            return Err(io::Error::other(format!(
                "{:?} and {:?} are the same file",
                src.display().to_string(),
                dst.display().to_string()
            )));
        }
        if is_fifo(&dst_meta) {
            return Err(io::Error::other(format!(
                "`{}` is a named pipe",
                dst.display()
            )));
        }
    }
    let mut writer = open_for_write(dst, mode)?;
    let original_len = if mode == WriteMode::Append {
        writer.metadata()?.len()
    } else {
        0
    };
    match io::copy(&mut reader, &mut writer) {
        Ok(n) => Ok(n),
        Err(e) => {
            let undo = match mode {
                WriteMode::Append => writer.set_len(original_len),
                WriteMode::Overwrite | WriteMode::CreateNew => {
                    drop(writer);
                    fs::remove_file(dst)
                }
            };
            if let Err(u) = undo {
                tracing::warn!(dst = %dst.display(), "cleaning up after a failed copy failed: {u}");
            }
            Err(e)
        }
    }
}

/// What `cp_file` found at the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Copied {
    /// A file; this many bytes were copied.
    File(u64),
    /// A directory: the destination directory was created (or existed).
    Directory,
}

/// fsspec `LocalFileSystem.cp_file` (also its `put_file` / `get_file`):
/// with `auto_mkdir` the destination's parent is created first; a file
/// (following symlinks) is copied with [`copy_file`], a directory becomes
/// `makedirs(dst, exist_ok=True)`, and anything else is `NotFound` (fsspec
/// raises `FileNotFoundError` unless `isfile` or `isdir`).
pub(crate) fn cp_file(
    src: &Path,
    dst: &Path,
    mode: WriteMode,
    auto_mkdir: bool,
) -> io::Result<Copied> {
    if auto_mkdir && let Some(parent) = dst.parent().filter(|p| !p.as_os_str().is_empty()) {
        makedirs(parent, true)?;
    }
    let kind = match crate::stat::kind_of(src) {
        Ok(k) => k,
        // fsspec decides with os.path.isfile/isdir, which treat any stat
        // error (permission, symlink loop, ...) as "no": FileNotFoundError.
        // The native error is kept as the source.
        Err(e) => return Err(io::Error::new(io::ErrorKind::NotFound, e)),
    };
    match kind {
        Some(fsfast_core::FileType::File) => copy_file(src, dst, mode).map(Copied::File),
        Some(fsfast_core::FileType::Directory) => makedirs(dst, true).map(|()| Copied::Directory),
        Some(_) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "not a regular file or directory",
        )),
        None => Err(io::Error::from(io::ErrorKind::NotFound)),
    }
}

/// Create the parent directory of `path` (`makedirs(_parent(path),
/// exist_ok=True)`), as fsspec does for every write when `auto_mkdir` is set.
pub(crate) fn ensure_parent(path: &Path) -> io::Result<()> {
    match path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(parent) => makedirs(parent, true),
        None => Ok(()),
    }
}

/// `shutil.copy2`: content, then timestamps, then permission bits.
fn copy2(src: &Path, dst: &Path) -> io::Result<()> {
    let src_meta = fs::metadata(src)?;
    let mut reader = File::open(src)?;
    let mut writer = open_for_write(dst, WriteMode::Overwrite)?;
    io::copy(&mut reader, &mut writer)?;
    copy_times(&src_meta, &writer)?;
    drop(writer);
    fs::set_permissions(dst, src_meta.permissions())
}

fn copy_times(src_meta: &Metadata, dst: &File) -> io::Result<()> {
    let mut times = fs::FileTimes::new();
    if let Ok(a) = src_meta.accessed() {
        times = times.set_accessed(a);
    }
    if let Ok(m) = src_meta.modified() {
        times = times.set_modified(m);
    }
    dst.set_times(times)
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

/// `shutil.copytree(src, dst, symlinks=True, copy_function=copy2)`.
fn copytree(src: &Path, dst: &Path) -> io::Result<()> {
    let src_meta = fs::metadata(src)?;
    fs::create_dir(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            symlink(&fs::read_link(&from)?, &to)?;
        } else if ft.is_dir() {
            copytree(&from, &to)?;
        } else {
            copy2(&from, &to)?;
        }
    }
    #[cfg(unix)]
    copy_times(&src_meta, &File::open(dst)?)?;
    fs::set_permissions(dst, src_meta.permissions())
}

fn is_empty_dir(path: &Path) -> io::Result<bool> {
    Ok(fs::read_dir(path)?.next().is_none())
}

/// A temporary name next to `dst` (same directory, hence same filesystem).
fn temp_sibling(dst: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let name = dst
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    dst.with_file_name(format!(
        ".{name}.fsfast-{}-{}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Move across filesystems (the fallback of `shutil.move`), keeping
/// `rename(2)` semantics for the destination: the source is copied to a
/// temporary sibling of `dst` and renamed over it, so an existing file (or
/// symlink) is replaced atomically and never written through; an existing
/// empty directory is replaced by a directory; a file never replaces a
/// directory (`IsADirectory`); a directory never replaces a file
/// (`AlreadyExists`, see [`dir_onto_file`]) or a non-empty directory
/// (`DirectoryNotEmpty`). The source is removed only once the copy is in
/// place.
pub(crate) fn move_across_devices(src: &Path, dst: &Path) -> io::Result<()> {
    let src_meta = fs::symlink_metadata(src)?;
    let dst_meta = fs::symlink_metadata(dst).ok();
    let dst_is_dir = dst_meta.as_ref().is_some_and(|m| m.is_dir());
    let tmp = temp_sibling(dst);

    if src_meta.is_dir() {
        if dst.starts_with(src) {
            // shutil.Error (an OSError) in fsspec: reported as `Io`.
            return Err(io::Error::other(format!(
                "cannot move a directory '{}' into itself '{}'",
                src.display(),
                dst.display()
            )));
        }
        match &dst_meta {
            Some(_) if !dst_is_dir => return Err(dir_onto_file(dst)),
            Some(_) if !is_empty_dir(dst)? => {
                return Err(io::Error::from(io::ErrorKind::DirectoryNotEmpty));
            }
            _ => {}
        }
        if let Err(e) = copytree(src, &tmp) {
            let _ = fs::remove_dir_all(&tmp);
            return Err(e);
        }
        if dst_is_dir {
            // Portable replacement of the empty directory (Windows cannot
            // rename onto an existing directory).
            fs::remove_dir(dst)?;
        }
        if let Err(e) = fs::rename(&tmp, dst) {
            let _ = fs::remove_dir_all(&tmp);
            return Err(e);
        }
        return fs::remove_dir_all(src);
    }

    if dst_is_dir {
        return Err(io::Error::from(io::ErrorKind::IsADirectory));
    }
    let copied = if src_meta.file_type().is_symlink() {
        fs::read_link(src).and_then(|target| symlink(&target, &tmp))
    } else {
        copy2(src, &tmp)
    };
    if let Err(e) = copied.and_then(|()| fs::rename(&tmp, dst)) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fs::remove_file(src)
}

/// The error for moving a directory onto an existing non-directory.
///
/// `rename(2)` reports `ENOTDIR`, but fsspec's `mv` (`shutil.move`) retries a
/// failed rename as `copytree`, whose `makedirs` raises `FileExistsError`;
/// fsfast reports what fsspec users see: `AlreadyExists`.
fn dir_onto_file(dst: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "destination '{}' exists and is not a directory",
            dst.display()
        ),
    )
}

/// `rename(2)`, falling back to copy + delete when source and destination are
/// on different filesystems (`EXDEV`), like `shutil.move`.
///
/// `shutil.move` retries *any* failed rename as a copy. Two outcomes of that
/// are visible to fsspec users and reproduced here without copying: a
/// directory moved to a destination whose parents are missing succeeds
/// (`copytree` creates them), and a directory moved onto a file is
/// `AlreadyExists`.
pub(crate) fn rename_or_move(src: &Path, dst: &Path) -> io::Result<()> {
    match fs::rename(src, dst) {
        Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
            tracing::debug!(src = %src.display(), dst = %dst.display(), "cross-device move: copying");
            move_across_devices(src, dst)
        }
        Err(e)
            if e.kind() == io::ErrorKind::NotFound
                && fs::symlink_metadata(src).is_ok_and(|m| m.is_dir())
                && dst
                    .parent()
                    .is_some_and(|p| !p.as_os_str().is_empty() && !p.exists()) =>
        {
            match ensure_parent(dst) {
                // The parent exists now, so this recurses at most once.
                Ok(()) => rename_or_move(src, dst),
                // Something that is not a directory (e.g. a dangling symlink)
                // is in the way: os.makedirs ignores that for intermediate
                // directories and its final mkdir fails like the rename did.
                Err(pe) if pe.kind() == io::ErrorKind::AlreadyExists => Err(e),
                Err(pe) => Err(pe),
            }
        }
        // The kernel resolves both parents before the source itself, so a
        // source that cannot be reached (missing, name too long, ...) can
        // surface as a destination error (`ENOTDIR`); shutil.move's copy
        // fallback opens the source first and reports the source's error.
        Err(e) if fs::symlink_metadata(src).is_err() => {
            Err(fs::symlink_metadata(src).err().unwrap_or(e))
        }
        Err(e)
            if e.kind() == io::ErrorKind::NotADirectory
                && fs::symlink_metadata(src).is_ok_and(|m| m.is_dir())
                && fs::symlink_metadata(dst).is_ok_and(|m| !m.is_dir()) =>
        {
            Err(dir_onto_file(dst))
        }
        r => r,
    }
}

/// Set both timestamps of `path` to now, following symlinks, with the
/// permission rules of `os.utime(path, None)` (write access suffices).
#[cfg(unix)]
fn utime_now(path: &Path) -> io::Result<()> {
    use rustix::fs::{AtFlags, CWD, Timespec, Timestamps, UTIME_NOW, utimensat};
    let now = Timespec {
        tv_sec: 0,
        tv_nsec: UTIME_NOW,
    };
    let times = Timestamps {
        last_access: now,
        last_modification: now,
    };
    utimensat(CWD, path, &times, AtFlags::empty()).map_err(io::Error::from)
}

#[cfg(windows)]
fn utime_now(path: &Path) -> io::Result<()> {
    let now = std::time::SystemTime::now();
    OpenOptions::new()
        .write(true)
        .open(path)?
        .set_times(fs::FileTimes::new().set_accessed(now).set_modified(now))
}

/// fsspec `LocalFileSystem.touch`: update the timestamps of an existing path
/// (or create an empty file), then truncate it when `truncate`.
pub(crate) fn touch(path: &Path, truncate: bool) -> io::Result<()> {
    if path.exists() {
        utime_now(path)?;
    } else {
        OpenOptions::new().append(true).create(true).open(path)?;
    }
    if truncate {
        truncate_path(path)?;
    }
    Ok(())
}

/// `os.truncate(path, 0)`. The file is opened non-blocking so that a named
/// pipe fails at once (`ftruncate` refuses anything but a regular file)
/// instead of blocking the thread until a reader appears.
fn truncate_path(path: &Path) -> io::Result<()> {
    let mut oo = OpenOptions::new();
    oo.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        oo.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    }
    oo.open(path)?.set_len(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn makedirs_like_python() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("a/b/c");
        makedirs(&p, false).unwrap();
        assert!(p.is_dir());
        assert_eq!(
            makedirs(&p, false).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        makedirs(&p, true).unwrap();
        let f = t.path().join("file");
        fs::write(&f, b"x").unwrap();
        assert_eq!(
            makedirs(&f, true).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            makedirs(&f.join("sub/leaf"), true).unwrap_err().kind(),
            io::ErrorKind::NotADirectory
        );
    }

    #[test]
    fn copy_refuses_same_file_and_keeps_data() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("f");
        fs::write(&f, b"precious").unwrap();
        let e = copy_file(&f, &f, WriteMode::Overwrite).unwrap_err();
        assert!(e.to_string().contains("same file"), "{e}");
        assert_eq!(fs::read(&f).unwrap(), b"precious");
        let g = t.path().join("g");
        assert_eq!(copy_file(&f, &g, WriteMode::CreateNew).unwrap(), 8);
        assert_eq!(
            copy_file(&f, &g, WriteMode::CreateNew).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        copy_file(&f, &g, WriteMode::Append).unwrap();
        assert_eq!(fs::read(&g).unwrap(), b"preciousprecious");
    }

    #[cfg(unix)]
    #[test]
    fn copy_file_does_not_copy_permissions_but_copy2_does() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("exec");
        fs::write(&f, b"#!/bin/sh").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o751)).unwrap();
        let plain = t.path().join("plain");
        copy_file(&f, &plain, WriteMode::Overwrite).unwrap();
        assert_ne!(
            fs::metadata(&plain).unwrap().permissions().mode() & 0o777,
            0o751
        );
        let full = t.path().join("full");
        copy2(&f, &full).unwrap();
        let m = fs::metadata(&full).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o751);
        assert_eq!(
            m.modified().unwrap(),
            fs::metadata(&f).unwrap().modified().unwrap()
        );
    }

    #[test]
    fn cross_device_fallback_keeps_rename_semantics() {
        // Exercise the fallback directly (same device here).
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        fs::create_dir_all(root.join("src/sub")).unwrap();
        fs::write(root.join("src/sub/f"), b"deep").unwrap();
        fs::write(root.join("src/top"), b"top").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("top", root.join("src/link")).unwrap();
        move_across_devices(&root.join("src"), &root.join("dst")).unwrap();
        assert!(!root.join("src").exists());
        assert_eq!(fs::read(root.join("dst/sub/f")).unwrap(), b"deep");
        #[cfg(unix)]
        assert_eq!(
            fs::read_link(root.join("dst/link")).unwrap(),
            Path::new("top")
        );

        // File onto file replaces; file onto directory fails.
        fs::write(root.join("a"), b"A").unwrap();
        fs::write(root.join("b"), b"B").unwrap();
        move_across_devices(&root.join("a"), &root.join("b")).unwrap();
        assert_eq!(fs::read(root.join("b")).unwrap(), b"A");
        assert_eq!(
            move_across_devices(&root.join("b"), &root.join("dst"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::IsADirectory
        );
        // Directory onto a non-empty directory / a file / into itself.
        fs::create_dir(root.join("d2")).unwrap();
        assert_eq!(
            move_across_devices(&root.join("d2"), &root.join("dst"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::DirectoryNotEmpty
        );
        assert_eq!(
            move_across_devices(&root.join("d2"), &root.join("b"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            rename_or_move(&root.join("d2"), &root.join("b"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            move_across_devices(&root.join("dst"), &root.join("dst/sub/x"))
                .unwrap_err()
                .kind(),
            // shutil.Error, an OSError, in fsspec.
            io::ErrorKind::Other
        );
        // Directory onto an empty directory replaces it.
        fs::create_dir(root.join("empty")).unwrap();
        move_across_devices(&root.join("dst"), &root.join("empty")).unwrap();
        assert_eq!(fs::read(root.join("empty/top")).unwrap(), b"top");
        // A symlink destination is replaced, not written through.
        #[cfg(unix)]
        {
            fs::write(root.join("target"), b"untouched").unwrap();
            std::os::unix::fs::symlink(root.join("target"), root.join("ln")).unwrap();
            fs::write(root.join("c"), b"C").unwrap();
            move_across_devices(&root.join("c"), &root.join("ln")).unwrap();
            assert_eq!(fs::read(root.join("target")).unwrap(), b"untouched");
            assert_eq!(fs::read(root.join("ln")).unwrap(), b"C");
            assert!(
                !fs::symlink_metadata(root.join("ln"))
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
        // No temporary files are left behind.
        let leftovers: Vec<_> = fs::read_dir(root)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".fsfast-"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        // Missing source.
        assert_eq!(
            move_across_devices(&root.join("nope"), &root.join("x"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn touch_like_fsspec() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("t");
        touch(&f, false).unwrap();
        assert_eq!(fs::metadata(&f).unwrap().len(), 0);
        fs::write(&f, b"keep").unwrap();
        let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        File::options()
            .write(true)
            .open(&f)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(old).set_accessed(old))
            .unwrap();
        touch(&f, false).unwrap();
        let m = fs::metadata(&f).unwrap();
        assert_eq!(m.len(), 4, "touch without truncate keeps the content");
        assert!(m.modified().unwrap() > old, "mtime was updated");
        touch(&f, true).unwrap();
        assert_eq!(fs::metadata(&f).unwrap().len(), 0);
        assert_eq!(
            touch(t.path(), true).unwrap_err().kind(),
            io::ErrorKind::IsADirectory
        );
        touch(t.path(), false).unwrap();
    }
}
