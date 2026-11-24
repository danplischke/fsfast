//! Local-disk filesystem with the semantics of fsspec's `LocalFileSystem`.
//!
//! * **Paths** follow `LocalFileSystem._strip_protocol`: `file://`, `file:`,
//!   `local://` and `local:` prefixes are removed, relative paths resolve
//!   against the current directory (`~` against the home directory), and
//!   paths are absolute POSIX strings (`/a/b`; on Windows `C:/a/b` or
//!   `//server/share/x`) without a trailing slash. See [`paths`].
//! * **`info()` keys** are exactly fsspec's: `name`, `size`, `type`,
//!   `created`, `islink`, `mode`, `uid`, `gid`, `mtime`, `ino`, `nlink`, plus
//!   `destination` for symlinks. `info(path)` follows symlinks (a broken one
//!   is `NotFound`); `ls`/`find` entries describe the link itself (type
//!   `"other"`, size of the target or 0 when broken), and `find` does not
//!   descend into symlinked directories, exactly like fsspec's `walk`.
//! * **No blocking on the runtime.** Every syscall runs in
//!   `tokio::task::spawn_blocking`, batched so one operation costs as few
//!   thread hops as possible (e.g. `cat_file` opens, stats and reads in one).
//! * **Performance.** `find` lists directories in parallel (one blocking task
//!   per directory, bounded by `io_hints().max_concurrency`); reads are
//!   positional (`pread`) on a shared descriptor, so concurrent `read_at`
//!   calls never serialise, and large reads are split across several
//!   blocking tasks into one buffer; `cp_file`, `put_file` and `get_file`
//!   copy in the kernel (`copy_file_range(2)`); `rm_files` deletes in batches.
//!
//! Deliberate differences from fsspec (documented on the methods):
//! `mv_file` renames to the exact destination (fsspec's `mv` moves *into* an
//! existing directory; the caller resolves that); `abort` of a write removes
//! the file the handle created or truncated; a failed copy does not leave a
//! partial destination.

mod handles;
mod ops;
pub mod paths;
mod stat;

use std::collections::VecDeque;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use fsfast_core::{
    ByteRange, Capabilities, Error, ErrorKind, FileInfo, FileSystem, FindOptions, IoHints,
    OptionReader, Options, ReadHandle, ReadOptions, Result, WriteHandle, WriteMode, WriteOptions,
};
use futures::stream::FuturesUnordered;
use futures::{StreamExt, stream};

pub use paths::{PathStyle, make_path_posix, parent, strip_protocol};

use crate::handles::{LocalReadHandle, LocalWriteHandle, read_parallel, read_range};
use crate::stat::io_err;

/// Options accepted by `AbstractFileSystem.__init__` that have no effect on
/// the local filesystem (instance and listing caches live in the Python
/// layer).
const IGNORED_BASE_OPTIONS: &[&str] = &[
    "skip_instance_cache",
    "use_listings_cache",
    "listings_expiry_time",
    "max_paths",
    "asynchronous",
    "loop",
];

/// Paths deleted per blocking task by `rm_files`: `unlink` costs about as
/// much as a thread hop, so deleting one path per task would double the cost.
const RM_BATCH: usize = 64;

/// Run blocking filesystem work off the async runtime.
pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(e) => Err(Error::new(
            ErrorKind::Cancelled,
            format!("blocking task cancelled: {e}"),
        )),
    }
}

/// An error of a two-path operation (rename, copy): the path is `src`, the
/// message also names `dst`; the kind (see [`stat::os_kind`]), the errno
/// detail and the `io::Error` source are preserved.
fn io_err2(e: std::io::Error, src: &str, dst: &str) -> Error {
    let mut out = Error::new(stat::os_kind(&e), format!("{e} (-> '{dst}')")).with_path(src);
    if let Some(code) = e.raw_os_error() {
        out = out.with_detail(fsfast_core::Detail::Errno(code));
    }
    out.with_source(e)
}

fn check_no_extra(extra: &Options, what: &str) -> Result<()> {
    if extra.is_empty() {
        Ok(())
    } else {
        let keys: Vec<&str> = extra.keys().map(String::as_str).collect();
        Err(Error::invalid_input(format!(
            "file: unknown or unsupported {what} option(s): {}",
            keys.join(", ")
        )))
    }
}

/// The fsspec `file` / `local` filesystem.
#[derive(Clone)]
pub struct LocalFileSystem {
    auto_mkdir: bool,
    hints: IoHints,
}

impl fmt::Debug for LocalFileSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalFileSystem")
            .field("auto_mkdir", &self.auto_mkdir)
            .finish_non_exhaustive()
    }
}

impl Default for LocalFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalFileSystem {
    /// I/O hints tuned for local disks: 4 MiB requests, 8 in flight (enough
    /// to keep an NVMe queue busy without oversubscribing the blocking pool),
    /// and a 64 KiB coalescing gap (reading a small gap is cheaper than a
    /// second syscall, reading a large one wastes page-cache bandwidth).
    pub const DEFAULT_IO_HINTS: IoHints = IoHints {
        request_size: 4 << 20,
        max_concurrency: 8,
        coalesce_gap: 64 << 10,
        max_coalesced: 16 << 20,
    };

    /// A local filesystem with fsspec's defaults (`auto_mkdir=False`).
    pub fn new() -> Self {
        LocalFileSystem {
            auto_mkdir: false,
            hints: Self::DEFAULT_IO_HINTS,
        }
    }

    /// Build from fsspec `storage_options`: `auto_mkdir` (bool, default
    /// false) plus the `AbstractFileSystem` base options, which have no
    /// effect here. Anything else is an error.
    pub fn from_options(opts: Options) -> Result<Self> {
        let mut r = OptionReader::new("file", opts);
        let auto_mkdir = r.bool("auto_mkdir")?.unwrap_or(false);
        r.accept_ignored(IGNORED_BASE_OPTIONS);
        r.finish()?;
        Ok(Self::new().with_auto_mkdir(auto_mkdir))
    }

    /// fsspec `auto_mkdir`: create the parent directory of the target of
    /// every write (`open` for writing, `pipe_file`, `cp_file`, `mv_file`,
    /// `put_file`, `get_file`, `touch`).
    pub fn with_auto_mkdir(mut self, auto_mkdir: bool) -> Self {
        self.auto_mkdir = auto_mkdir;
        self
    }

    /// Override the I/O hints (e.g. for network filesystems mounted locally).
    pub fn with_io_hints(mut self, hints: IoHints) -> Self {
        self.hints = hints;
        self
    }

    /// Whether `auto_mkdir` is enabled.
    pub fn auto_mkdir(&self) -> bool {
        self.auto_mkdir
    }

    fn os_path(path: &str) -> (String, PathBuf) {
        let p = strip_protocol(path).into_owned();
        let os = PathBuf::from(&p);
        (p, os)
    }
}

/// What `cat_file`'s first blocking step produced.
enum Opened {
    /// The (small) result itself.
    Data(Bytes),
    /// A large range to read in parallel.
    Large {
        file: Arc<std::fs::File>,
        start: u64,
        len: usize,
    },
}

/// Open `os` for reading and return the file with its metadata, mapping a
/// directory to `IsADirectory` on every platform.
fn open_file(os: &Path, name: &str) -> Result<(std::fs::File, std::fs::Metadata)> {
    let file = match std::fs::File::open(os) {
        Ok(f) => f,
        // Windows refuses to open a directory as a file with "access denied".
        Err(e)
            if e.kind() == std::io::ErrorKind::PermissionDenied
                && std::fs::metadata(os).is_ok_and(|m| m.is_dir()) =>
        {
            return Err(Error::is_a_directory(name));
        }
        Err(e) => return Err(io_err(e, name)),
    };
    let meta = file.metadata().map_err(|e| io_err(e, name))?;
    if meta.is_dir() {
        return Err(Error::is_a_directory(name));
    }
    Ok((file, meta))
}

#[async_trait::async_trait]
impl FileSystem for LocalFileSystem {
    fn protocols(&self) -> &'static [&'static str] {
        &["file", "local"]
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hierarchical: true,
            atomic_rename: true,
            // cp_file copies inside the kernel (copy_file_range / reflink):
            // no data passes through user space.
            server_side_copy: true,
            append: true,
            conditional_create: true,
            random_write: true,
            ..Capabilities::default()
        }
    }

    fn io_hints(&self) -> IoHints {
        self.hints
    }

    /// fsspec `info(path)`: symlinks are followed (`islink` and
    /// `destination` describe the link); a broken symlink is `NotFound`.
    async fn info(&self, path: &str) -> Result<FileInfo> {
        let p = strip_protocol(path).into_owned();
        blocking(move || stat::info_path(&p)).await
    }

    /// fsspec `ls(path, detail=True)`, sorted by name. Listing a file returns
    /// `[info(file)]`; entries vanishing during the listing are skipped.
    async fn ls(&self, path: &str) -> Result<Vec<FileInfo>> {
        let p = strip_protocol(path).into_owned();
        blocking(move || stat::ls(&p)).await
    }

    /// fsspec `find` (its generic `walk`-based implementation), sorted by
    /// name.
    ///
    /// Directories are listed in parallel: one blocking task per directory
    /// (`readdir` plus one `fstatat` per entry), at most
    /// `io_hints().max_concurrency` at a time. Like fsspec, symlinked
    /// directories are reported but not descended into, the root itself is
    /// included with `withdirs` when it is a directory, a file root returns
    /// `[info(file)]`, and a missing (or unreadable) root returns `[]`;
    /// sub-directories that cannot be listed are omitted (fsspec's
    /// `on_error="omit"`). `maxdepth=0` is `InvalidInput` (fsspec:
    /// `ValueError`).
    async fn find(&self, path: &str, opts: &FindOptions) -> Result<Vec<FileInfo>> {
        if opts.maxdepth == Some(0) {
            return Err(Error::invalid_input("maxdepth must be at least 1"));
        }
        let root = strip_protocol(path).into_owned();
        let r = root.clone();
        let root_info = match blocking(move || stat::info_path(&r)).await {
            Ok(i) => i,
            Err(e) => {
                tracing::debug!(path = %root, "find: root not listable, returning nothing: {e}");
                return Ok(Vec::new());
            }
        };
        if !root_info.is_dir() {
            return Ok(vec![root_info]);
        }
        let mut out = Vec::new();
        if opts.withdirs {
            out.push(root_info);
        }

        let concurrency = self.hints.max_concurrency.max(1);
        let mut pending: VecDeque<(String, usize)> = VecDeque::from([(root, 1)]);
        let mut running = FuturesUnordered::new();
        loop {
            while running.len() < concurrency {
                let Some((dir, depth)) = pending.pop_front() else {
                    break;
                };
                running.push(async move {
                    let d = dir.clone();
                    let listing = blocking(move || stat::list_dir(&d)).await;
                    (dir, depth, listing)
                });
            }
            let Some((dir, depth, listing)) = running.next().await else {
                break;
            };
            let entries = match listing {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(path = %dir, "find: omitting a directory that cannot be listed: {e}");
                    continue;
                }
            };
            for e in entries {
                if e.is_dir() {
                    if opts.maxdepth.is_none_or(|m| depth < m) {
                        pending.push_back((e.name.clone(), depth + 1));
                    }
                    if opts.withdirs {
                        out.push(e);
                    }
                } else {
                    out.push(e);
                }
            }
        }
        out.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// `os.path.exists` semantics, as fsspec's `exists` (`info()` succeeds):
    /// symlinks are followed and any error means `false`.
    async fn exists(&self, path: &str) -> Result<bool> {
        let (_, os) = Self::os_path(path);
        blocking(move || Ok(stat::exists(&os))).await
    }

    /// Opens the file once; reads are positional on the shared descriptor.
    /// `ReadOptions::block_size` sets the handle's request size. Reading a
    /// specific version is `Unsupported`; reads cannot be pinned (an open
    /// descriptor survives renames and deletion of the path, but sees
    /// in-place modifications).
    async fn open_read(&self, path: &str, opts: &ReadOptions) -> Result<Arc<dyn ReadHandle>> {
        check_no_extra(&opts.extra, "read")?;
        if opts.version.is_some() {
            return Err(Error::unsupported("file: reading a specific version"));
        }
        let mut hints = self.hints;
        if let Some(bs) = opts.block_size.filter(|&b| b > 0) {
            hints.request_size = bs;
        }
        let (p, os) = Self::os_path(path);
        let (file, info) = blocking(move || {
            let (file, _) = open_file(&os, &p)?;
            let info = stat::info_open(&p, &file)?;
            Ok((file, info))
        })
        .await?;
        Ok(Arc::new(LocalReadHandle::new(file, info, hints)))
    }

    /// fsspec `open(path, "wb" | "xb" | "ab")`. `xb` is atomic (`O_EXCL`):
    /// an existing path is `AlreadyExists`. Data reaches the file
    /// progressively (small writes are buffered up to 1 MiB). `abort`
    /// removes a file opened with `wb`/`xb` and cuts an `ab` file back to
    /// its length at open. `content_type` and `metadata` have no local
    /// equivalent and are ignored (fsspec ignores unknown `open` arguments).
    ///
    /// If a `write`, `flush` or `close` future is dropped before completing,
    /// its data may be missing from the file, so the handle then refuses
    /// further writes and only `abort` is accepted. A handle dropped without
    /// `close` finishes its pending writes in order in the background, on
    /// the runtime it was opened on (whichever thread drops it).
    async fn open_write(&self, path: &str, opts: &WriteOptions) -> Result<Box<dyn WriteHandle>> {
        check_no_extra(&opts.extra, "write")?;
        let (p, os) = Self::os_path(path);
        let (mode, auto_mkdir) = (opts.mode, self.auto_mkdir);
        let (pp, oo) = (p.clone(), os.clone());
        let (file, original_len) = blocking(move || {
            if auto_mkdir {
                ops::ensure_parent(&oo).map_err(|e| io_err(e, &pp))?;
            }
            let file = ops::open_for_write(&oo, mode).map_err(|e| io_err(e, &pp))?;
            let original_len = if mode == WriteMode::Append {
                file.metadata().map_err(|e| io_err(e, &pp))?.len()
            } else {
                0
            };
            Ok((file, original_len))
        })
        .await?;
        Ok(Box::new(LocalWriteHandle::new(
            p,
            os,
            file,
            mode,
            original_len,
        )))
    }

    /// One blocking task opens, stats and (for up to `2 × request_size`
    /// bytes) reads; larger ranges are read in parallel into one buffer.
    /// A directory is `IsADirectory`.
    async fn cat_file(&self, path: &str, range: ByteRange) -> Result<Bytes> {
        let (p, os) = Self::os_path(path);
        let hints = self.hints;
        let name = p.clone();
        let opened = blocking(move || {
            let (file, meta) = open_file(&os, &name)?;
            let r = range.resolve(meta.len());
            let len = (r.end - r.start) as usize;
            if len == 0 {
                return Ok(Opened::Data(Bytes::new()));
            }
            if len <= hints.request_size.saturating_mul(2) || hints.max_concurrency <= 1 {
                return read_range(&file, r.start, len)
                    .map(Opened::Data)
                    .map_err(|e| io_err(e, &name));
            }
            Ok(Opened::Large {
                file: Arc::new(file),
                start: r.start,
                len,
            })
        })
        .await?;
        match opened {
            Opened::Data(b) => Ok(b),
            Opened::Large { file, start, len } => {
                read_parallel(
                    file,
                    Arc::from(p.as_str()),
                    start,
                    len,
                    hints.request_size,
                    hints.max_concurrency,
                )
                .await
            }
        }
    }

    /// Opens and writes in one blocking task, straight from the caller's
    /// buffer. Honours `WriteOptions::mode`; a failed write removes the file
    /// it created or truncated (or cuts an appended file back).
    ///
    /// `CreateNew` is atomic (`O_EXCL`, like fsspec's `open(path, "xb")`).
    /// fsspec's `pipe_file(mode="create")` instead checks `exists()` and then
    /// writes with `"wb"`, which differs only for a dangling symlink: fsspec
    /// writes through it, fsfast reports `AlreadyExists`.
    async fn pipe_file(&self, path: &str, data: Bytes, opts: &WriteOptions) -> Result<()> {
        use std::io::Write as _;
        check_no_extra(&opts.extra, "write")?;
        let (p, os) = Self::os_path(path);
        let (mode, auto_mkdir) = (opts.mode, self.auto_mkdir);
        blocking(move || {
            if auto_mkdir {
                ops::ensure_parent(&os).map_err(|e| io_err(e, &p))?;
            }
            let mut file = ops::open_for_write(&os, mode).map_err(|e| io_err(e, &p))?;
            let original_len = if mode == WriteMode::Append {
                file.metadata().map_err(|e| io_err(e, &p))?.len()
            } else {
                0
            };
            if let Err(e) = file.write_all(&data) {
                let undo = match mode {
                    WriteMode::Append => file.set_len(original_len),
                    WriteMode::Overwrite | WriteMode::CreateNew => {
                        drop(file);
                        std::fs::remove_file(&os)
                    }
                };
                if let Err(u) = undo {
                    tracing::warn!(path = %p, "cleaning up after a failed write failed: {u}");
                }
                return Err(io_err(e, &p));
            }
            Ok(())
        })
        .await
    }

    /// `os.remove`: a directory is an error (`IsADirectory` on Linux), a
    /// symlink is removed itself.
    async fn rm_file(&self, path: &str) -> Result<()> {
        let (p, os) = Self::os_path(path);
        blocking(move || std::fs::remove_file(&os).map_err(|e| io_err(e, &p))).await
    }

    /// Deletes in batches of 64 paths per blocking task, several batches
    /// concurrently; one result per path, in order.
    async fn rm_files(&self, paths: &[String]) -> Vec<Result<()>> {
        let batches: Vec<Vec<(String, PathBuf)>> = paths
            .chunks(RM_BATCH)
            .map(|c| c.iter().map(|p| Self::os_path(p)).collect())
            .collect();
        let results: Vec<Result<Vec<Result<()>>>> =
            stream::iter(batches.into_iter().map(|batch| {
                blocking(move || {
                    Ok(batch
                        .into_iter()
                        .map(|(p, os)| std::fs::remove_file(&os).map_err(|e| io_err(e, &p)))
                        .collect())
                })
            }))
            .buffered(self.hints.max_concurrency.max(1))
            .collect()
            .await;
        let mut out = Vec::with_capacity(paths.len());
        for (batch, r) in paths.chunks(RM_BATCH).zip(results) {
            match r {
                Ok(v) => out.extend(v),
                // The batch task itself failed (cancelled): report per path.
                Err(e) => out.extend(batch.iter().map(|p| {
                    Err(Error::new(e.kind(), e.message().to_owned()).with_path(p.clone()))
                })),
            }
        }
        out
    }

    /// fsspec `mkdir`: an existing path (following symlinks) is
    /// `AlreadyExists`; with `create_parents` missing parents are created
    /// (`os.makedirs(exist_ok=True)`), otherwise `os.mkdir` (a missing parent
    /// is `NotFound`).
    async fn mkdir(&self, path: &str, create_parents: bool) -> Result<()> {
        let (p, os) = Self::os_path(path);
        blocking(move || {
            if stat::exists(&os) {
                return Err(Error::already_exists(p));
            }
            let r = if create_parents {
                ops::makedirs(&os, true)
            } else {
                std::fs::create_dir(&os)
            };
            r.map_err(|e| io_err(e, &p))
        })
        .await
    }

    /// `os.makedirs(path, exist_ok)`: `AlreadyExists` for an existing
    /// directory unless `exist_ok`, and always for an existing file.
    async fn makedirs(&self, path: &str, exist_ok: bool) -> Result<()> {
        let (p, os) = Self::os_path(path);
        blocking(move || ops::makedirs(&os, exist_ok).map_err(|e| io_err(e, &p))).await
    }

    /// `os.rmdir`: `DirectoryNotEmpty`, `NotADirectory` or `NotFound` as the
    /// OS reports.
    async fn rmdir(&self, path: &str) -> Result<()> {
        let (p, os) = Self::os_path(path);
        blocking(move || std::fs::remove_dir(&os).map_err(|e| io_err(e, &p))).await
    }

    /// fsspec `cp_file`: a file (following symlinks) is copied like
    /// `shutil.copyfile` (content only, in the kernel); a directory becomes
    /// `makedirs(dst, exist_ok=True)`; anything else is `NotFound`.
    async fn cp_file(&self, src: &str, dst: &str) -> Result<()> {
        let (s, s_os) = Self::os_path(src);
        let (d, d_os) = Self::os_path(dst);
        let auto_mkdir = self.auto_mkdir;
        blocking(move || {
            ops::cp_file(&s_os, &d_os, WriteMode::Overwrite, auto_mkdir)
                .map(|_| ())
                .map_err(|e| io_err2(e, &s, &d))
        })
        .await
    }

    /// `rename(2)` to the exact destination: atomic, replacing an existing
    /// file (or an empty directory, for a directory source). Across
    /// filesystems it falls back to copy + delete like `shutil.move`, keeping
    /// those replacement rules. Unlike fsspec's `mv`, an existing directory
    /// destination is not moved *into*: resolving that is the caller's job
    /// (a file onto a directory is `IsADirectory`). Moving a path onto itself
    /// is a no-op if it exists and `NotFound` otherwise, as with `os.rename`.
    async fn mv_file(&self, src: &str, dst: &str) -> Result<()> {
        let (s, s_os) = Self::os_path(src);
        let (d, d_os) = Self::os_path(dst);
        let auto_mkdir = self.auto_mkdir;
        blocking(move || {
            if auto_mkdir {
                ops::ensure_parent(&d_os).map_err(|e| io_err(e, &d))?;
            }
            ops::rename_or_move(&s_os, &d_os).map_err(|e| io_err2(e, &s, &d))
        })
        .await
    }

    /// fsspec `put_file` is `cp_file(local, remote)`: an in-kernel copy, a
    /// local directory becomes a directory. `WriteOptions::mode` is honoured
    /// (`CreateNew` fails with `AlreadyExists` on an existing target).
    async fn put_file(&self, local: &Path, remote: &str, opts: &WriteOptions) -> Result<()> {
        check_no_extra(&opts.extra, "write")?;
        let src = local.to_owned();
        let (d, d_os) = Self::os_path(remote);
        let (mode, auto_mkdir) = (opts.mode, self.auto_mkdir);
        blocking(move || {
            let s = src.to_string_lossy();
            ops::cp_file(&src, &d_os, mode, auto_mkdir)
                .map(|_| ())
                .map_err(|e| io_err2(e, &s, &d))
        })
        .await
    }

    /// fsspec `get_file` is `cp_file(remote, local)`: an in-kernel copy, a
    /// directory becomes a local directory. Nothing is left at `local` when
    /// the copy fails.
    async fn get_file(&self, remote: &str, local: &Path) -> Result<()> {
        let (s, s_os) = Self::os_path(remote);
        let dst = local.to_owned();
        let auto_mkdir = self.auto_mkdir;
        blocking(move || {
            let d = dst.to_string_lossy();
            ops::cp_file(&s_os, &dst, WriteMode::Overwrite, auto_mkdir)
                .map(|_| ())
                .map_err(|e| io_err2(e, &s, &d))
        })
        .await
    }

    /// fsspec `touch`: an existing path gets its access and modification
    /// times set to now (`os.utime(path, None)`, content kept); a missing one
    /// is created empty; then `truncate` empties it.
    async fn touch(&self, path: &str, truncate: bool) -> Result<()> {
        let (p, os) = Self::os_path(path);
        let auto_mkdir = self.auto_mkdir;
        blocking(move || {
            if auto_mkdir {
                ops::ensure_parent(&os).map_err(|e| io_err(e, &p))?;
            }
            ops::touch(&os, truncate).map_err(|e| io_err(e, &p))
        })
        .await
    }
}

#[cfg(test)]
mod tests;
