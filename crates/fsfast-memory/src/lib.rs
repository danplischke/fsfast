//! In-memory filesystem with the semantics of fsspec's `MemoryFileSystem`.
//!
//! * **Shared store.** Like fsspec (whose `store` and `pseudo_dirs` are class
//!   attributes), every [`MemoryFileSystem`] created with [`MemoryFileSystem::new`]
//!   or `from_options` without `global_store=False` shares one process-wide
//!   store. [`MemoryFileSystem::new_isolated`] (`global_store=False`) creates
//!   an independent one.
//! * **Paths** are normalised like `MemoryFileSystem._strip_protocol`: one
//!   leading `/`, no trailing `/`, root `""` ([`strip_protocol`]).
//! * **Directories** are explicit pseudo-directories (`mkdir`) plus implied
//!   parents of stored paths; `ls`, `find`, `info`, `mkdir`, `makedirs`,
//!   `rmdir`, `cp_file`, `rm_file`, `open` reproduce fsspec's behaviour and
//!   error types (see the [`store`](self) module docs and the tests).
//! * **`info()` keys** are fsspec's: `name`, `size`, `type`, and `created` for
//!   files — a `datetime` from `info()`, a float timestamp from
//!   `ls()`/`find()`, exactly as fsspec reports them.
//! * **Performance.** Contents are immutable [`Bytes`]: reads, `cat_ranges`,
//!   `cp_file` and `get_file` never copy file data; `pipe_file` stores the
//!   caller's buffer as is. Prefix scans use ordered maps under one
//!   `parking_lot::RwLock`, which is never held across an `.await`.
//!
//! Deliberate differences from fsspec (documented on the methods):
//! `mv_file` moves directory trees atomically (fsspec: recursive copy + rm);
//! written data becomes visible on `flush`/`close` rather than per `write`;
//! `abort` removes a file created by `open_write` (fsspec has no abort outside
//! transactions).

mod handles;
pub mod paths;
mod store;

use std::fmt;
use std::ops::Range;
use std::path::Path;
use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use fsfast_core::{
    ByteRange, Capabilities, Error, ErrorKind, FileInfo, FileSystem, FindOptions, IoHints,
    OptionReader, Options, ReadHandle, ReadOptions, Result, WriteHandle, WriteMode, WriteOptions,
};
use parking_lot::RwLock;

pub use paths::strip_protocol;

use crate::handles::{MemoryReadHandle, MemoryWriteHandle, clamped_slice};
use crate::store::{CreatedAs, Inner, file_info};

/// A store shared by filesystem instances.
#[derive(Debug, Default)]
pub(crate) struct Store {
    pub inner: RwLock<Inner>,
}

static GLOBAL_STORE: LazyLock<Arc<Store>> = LazyLock::new(|| Arc::new(Store::default()));

/// Options accepted by `AbstractFileSystem.__init__` that have no effect on
/// the memory filesystem (instance caching and listing caches live in the
/// Python layer).
const IGNORED_BASE_OPTIONS: &[&str] = &[
    "skip_instance_cache",
    "use_listings_cache",
    "listings_expiry_time",
    "max_paths",
    "asynchronous",
    "loop",
];

/// The fsspec `memory` filesystem.
#[derive(Clone)]
pub struct MemoryFileSystem {
    store: Arc<Store>,
    global: bool,
}

impl fmt::Debug for MemoryFileSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately does not lock the store (Debug may run while it is held).
        f.debug_struct("MemoryFileSystem")
            .field("global_store", &self.global)
            .finish()
    }
}

impl Default for MemoryFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

fn check_no_extra(extra: &Options, what: &str) -> Result<()> {
    if extra.is_empty() {
        Ok(())
    } else {
        let keys: Vec<&str> = extra.keys().map(String::as_str).collect();
        Err(Error::invalid_input(format!(
            "memory: unknown or unsupported {what} option(s): {}",
            keys.join(", ")
        )))
    }
}

/// An error of the local side of `put_file`/`get_file`. Python raises a
/// plain `OSError(errno)` for errnos such as `EINVAL` and `ENAMETOOLONG`,
/// which the core mapping would turn into `InvalidInput` (`ValueError`), so
/// OS errors of that kind (or `Unsupported`) are reported as `Io`.
fn local_io_error(e: std::io::Error, path: &Path) -> Error {
    let os_error = e.raw_os_error().is_some();
    let err = Error::from(e).with_path(path.display().to_string());
    match err.kind() {
        ErrorKind::InvalidInput | ErrorKind::Unsupported if os_error => {
            err.with_kind(ErrorKind::Io)
        }
        _ => err,
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(e) => Err(Error::new(
            ErrorKind::Cancelled,
            format!("blocking task cancelled: {e}"),
        )),
    }
}

impl MemoryFileSystem {
    /// A filesystem on the process-wide shared store (fsspec's default).
    pub fn new() -> Self {
        MemoryFileSystem {
            store: GLOBAL_STORE.clone(),
            global: true,
        }
    }

    /// A filesystem with its own, initially empty store (fsspec
    /// `global_store=False`). Clones share the store.
    pub fn new_isolated() -> Self {
        MemoryFileSystem {
            store: Arc::new(Store::default()),
            global: false,
        }
    }

    /// Build from fsspec `storage_options`: `global_store` (bool, default
    /// true) plus the `AbstractFileSystem` base options, which have no
    /// effect here. Anything else is an error.
    pub fn from_options(opts: Options) -> Result<Self> {
        let mut r = OptionReader::new("memory", opts);
        let global = r.bool("global_store")?.unwrap_or(true);
        r.accept_ignored(IGNORED_BASE_OPTIONS);
        r.finish()?;
        Ok(if global {
            Self::new()
        } else {
            Self::new_isolated()
        })
    }

    /// Whether this instance uses the process-wide store.
    pub fn is_global(&self) -> bool {
        self.global
    }

    /// Remove every file and directory from this instance's store (the shared
    /// one for global instances).
    pub fn clear(&self) {
        self.store.inner.write().clear();
    }

    /// Remove every file and directory from the process-wide store. Intended
    /// for tests; affects every global instance in the process.
    pub fn clear_global() {
        GLOBAL_STORE.inner.write().clear();
    }

    /// Number of stored files (diagnostics and tests).
    pub fn file_count(&self) -> usize {
        self.store.inner.read().files.len()
    }

    fn write_mode_check(opts: &WriteOptions) -> Result<()> {
        check_no_extra(&opts.extra, "write")
    }
}

#[async_trait::async_trait]
impl FileSystem for MemoryFileSystem {
    fn protocols(&self) -> &'static [&'static str] {
        &["memory"]
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hierarchical: true,
            atomic_rename: true,
            // Copies share the immutable buffer: no data moves at all.
            server_side_copy: true,
            append: true,
            conditional_create: true,
            ..Capabilities::default()
        }
    }

    fn io_hints(&self) -> IoHints {
        // Reads are slices of one buffer: no coalescing needed and request
        // size only matters to generic chunked copies.
        IoHints {
            request_size: 4 << 20,
            max_concurrency: 4,
            coalesce_gap: 0,
            max_coalesced: 64 << 20,
        }
    }

    async fn info(&self, path: &str) -> Result<FileInfo> {
        let p = strip_protocol(path);
        self.store.inner.read().info(&p)
    }

    async fn ls(&self, path: &str) -> Result<Vec<FileInfo>> {
        let p = strip_protocol(path);
        self.store.inner.read().ls(&p)
    }

    async fn find(&self, path: &str, opts: &FindOptions) -> Result<Vec<FileInfo>> {
        let p = strip_protocol(path);
        self.store.inner.read().find(&p, opts)
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        let p = strip_protocol(path);
        Ok(self.store.inner.read().exists(&p))
    }

    async fn open_read(&self, path: &str, opts: &ReadOptions) -> Result<Arc<dyn ReadHandle>> {
        check_no_extra(&opts.extra, "read")?;
        if opts.version.is_some() {
            return Err(Error::unsupported("memory: reading a specific version"));
        }
        let p = strip_protocol(path);
        let (info, data) = {
            let inner = self.store.inner.read();
            let f = inner.open_read(&p)?;
            (file_info(&p, f, CreatedAs::Datetime), f.data.clone())
        };
        Ok(Arc::new(MemoryReadHandle {
            info,
            data,
            hints: self.io_hints(),
        }))
    }

    /// fsspec `open(path, "wb" | "xb" | "ab")`. The file exists as soon as
    /// it is opened (empty, or with its previous content when appending);
    /// written data is published on `flush`, `close` or drop. `abort` removes
    /// a file the handle created, or restores the file it appended to.
    async fn open_write(&self, path: &str, opts: &WriteOptions) -> Result<Box<dyn WriteHandle>> {
        Self::write_mode_check(opts)?;
        let p = strip_protocol(path).into_owned();
        let slot = self.store.inner.write().open_write(&p, opts.mode)?;
        Ok(Box::new(MemoryWriteHandle::new(
            self.store.clone(),
            p,
            slot,
        )))
    }

    /// fsspec `cat_file`: a zero-copy slice. Directories are `NotFound`.
    async fn cat_file(&self, path: &str, range: ByteRange) -> Result<Bytes> {
        let p = strip_protocol(path);
        let data = {
            let inner = self.store.inner.read();
            match inner.files.get(p.as_ref()) {
                Some(f) => f.data.clone(),
                None => return Err(Error::not_found(p.as_ref())),
            }
        };
        let r = range.resolve(data.len() as u64);
        Ok(clamped_slice(&data, &r))
    }

    async fn cat_ranges(&self, path: &str, ranges: &[Range<u64>]) -> Result<Vec<Bytes>> {
        let p = strip_protocol(path);
        let data = {
            let inner = self.store.inner.read();
            match inner.files.get(p.as_ref()) {
                Some(f) => f.data.clone(),
                None => return Err(Error::not_found(p.as_ref())),
            }
        };
        Ok(ranges.iter().map(|r| clamped_slice(&data, r)).collect())
    }

    /// fsspec `pipe_file`: stores `data` itself (no copy).
    async fn pipe_file(&self, path: &str, data: Bytes, opts: &WriteOptions) -> Result<()> {
        Self::write_mode_check(opts)?;
        let p = strip_protocol(path);
        self.store.inner.write().put(&p, data, opts.mode)
    }

    async fn rm_file(&self, path: &str) -> Result<()> {
        let p = strip_protocol(path);
        self.store.inner.write().rm_file(&p)
    }

    /// All deletions under one lock.
    async fn rm_files(&self, paths: &[String]) -> Vec<Result<()>> {
        let mut inner = self.store.inner.write();
        paths
            .iter()
            .map(|p| inner.rm_file(&strip_protocol(p)))
            .collect()
    }

    /// fsspec `mkdir`: `AlreadyExists` for an existing file or
    /// pseudo-directory, `NotADirectory` below a file. Like fsspec, a missing
    /// parent is not an error without `create_parents` (it becomes implied).
    async fn mkdir(&self, path: &str, create_parents: bool) -> Result<()> {
        let p = strip_protocol(path);
        self.store.inner.write().mkdir(&p, create_parents)
    }

    /// fsspec `makedirs`: `mkdir(create_parents=True)`, ignoring
    /// `AlreadyExists` when `exist_ok`.
    async fn makedirs(&self, path: &str, exist_ok: bool) -> Result<()> {
        let p = strip_protocol(path);
        self.store.inner.write().makedirs(&p, exist_ok)
    }

    /// fsspec `rmdir`: only pseudo-directories can be removed (implied ones
    /// are `NotFound`), non-empty ones fail with `DirectoryNotEmpty`, the root
    /// is silently kept.
    async fn rmdir(&self, path: &str) -> Result<()> {
        let p = strip_protocol(path);
        self.store.inner.write().rmdir(&p)
    }

    /// fsspec `cp_file` (no data is copied: the buffer is shared).
    async fn cp_file(&self, src: &str, dst: &str) -> Result<()> {
        let (s, d) = (strip_protocol(src), strip_protocol(dst));
        self.store.inner.write().cp_file(&s, &d)
    }

    /// Atomic move to the final path `dst`; directories move as a whole
    /// tree. Equivalent to fsspec's `mv(src, dst, recursive=True)` once `dst`
    /// is resolved (moving *into* an existing directory is resolved by the
    /// caller, as fsspec's generic `copy`/`mv` do). Moving a file onto a
    /// directory is `IsADirectory`; a directory onto a file `NotADirectory`,
    /// onto a non-empty directory `DirectoryNotEmpty`.
    async fn mv_file(&self, src: &str, dst: &str) -> Result<()> {
        let (s, d) = (strip_protocol(src), strip_protocol(dst));
        self.store.inner.write().mv(&s, &d)
    }

    /// fsspec `put_file`: a local directory becomes `makedirs(remote)`; for a
    /// file, the remote parent directories are created (fsspec calls
    /// `mkdirs(parent, exist_ok=True)`) and the content is stored.
    async fn put_file(&self, local: &Path, remote: &str, opts: &WriteOptions) -> Result<()> {
        Self::write_mode_check(opts)?;
        let p = strip_protocol(remote).into_owned();
        if opts.mode == WriteMode::CreateNew && self.store.inner.read().exists(&p) {
            return Err(Error::already_exists(p));
        }
        let local = local.to_owned();
        let content = blocking(move || {
            let meta = std::fs::metadata(&local).map_err(|e| local_io_error(e, &local))?;
            if meta.is_dir() {
                return Ok(None);
            }
            std::fs::read(&local)
                .map(|v| Some(Bytes::from(v)))
                .map_err(|e| local_io_error(e, &local))
        })
        .await?;
        let mut inner = self.store.inner.write();
        match content {
            None => inner.makedirs(&p, true),
            Some(data) => {
                inner.makedirs(&strip_protocol(&paths::parent(&p)), true)?;
                inner.put(&p, data, opts.mode)
            }
        }
    }

    /// fsspec `get_file`: a remote directory becomes a local directory;
    /// otherwise the local parent directories are created and the file is
    /// written. A partially written local file is removed on failure.
    async fn get_file(&self, remote: &str, local: &Path) -> Result<()> {
        let p = strip_protocol(remote);
        let content = {
            let inner = self.store.inner.read();
            if inner.is_dir(&p) {
                None
            } else {
                Some(inner.open_read(&p)?.data.clone())
            }
        };
        let local = local.to_owned();
        blocking(move || match content {
            None => std::fs::create_dir_all(&local).map_err(|e| local_io_error(e, &local)),
            Some(data) => {
                if let Some(parent) = local.parent().filter(|p| !p.as_os_str().is_empty()) {
                    std::fs::create_dir_all(parent).map_err(|e| local_io_error(e, parent))?;
                }
                std::fs::write(&local, &data).map_err(|e| {
                    let _ = std::fs::remove_file(&local);
                    local_io_error(e, &local)
                })
            }
        })
        .await
    }

    /// fsspec's base `touch`: (re)create an empty file when `truncate` or when
    /// the path does not exist; otherwise `Unsupported` (fsspec raises
    /// `NotImplementedError`, it cannot update timestamps).
    async fn touch(&self, path: &str, truncate: bool) -> Result<()> {
        let p = strip_protocol(path);
        let mut inner = self.store.inner.write();
        if !truncate && inner.exists(&p) {
            return Err(Error::unsupported(
                "memory: touch without truncate on an existing file",
            ));
        }
        inner.put(&p, Bytes::new(), WriteMode::Overwrite)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsfast_core::Value;

    fn opts(pairs: &[(&str, Value)]) -> Options {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    #[test]
    fn from_options_is_strict() {
        let fs = MemoryFileSystem::from_options(Options::new()).unwrap();
        assert!(fs.is_global());
        let fs =
            MemoryFileSystem::from_options(opts(&[("global_store", Value::Bool(false))])).unwrap();
        assert!(!fs.is_global());
        MemoryFileSystem::from_options(opts(&[
            ("skip_instance_cache", Value::Bool(true)),
            ("use_listings_cache", Value::Bool(false)),
        ]))
        .unwrap();
        let e = MemoryFileSystem::from_options(opts(&[("bogus", Value::Int(1))])).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput);
        assert!(e.to_string().contains("bogus"), "{e}");
        let e =
            MemoryFileSystem::from_options(opts(&[("global_store", Value::Str("maybe".into()))]))
                .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn global_instances_share_state_isolated_do_not() {
        let a = MemoryFileSystem::new();
        let b = MemoryFileSystem::from_options(Options::new()).unwrap();
        let iso = MemoryFileSystem::new_isolated();
        let p = "/unit-tests/global_share/file";
        a.pipe_file(p, Bytes::from_static(b"shared"), &WriteOptions::default())
            .await
            .unwrap();
        assert_eq!(b.cat_file(p, ByteRange::Full).await.unwrap(), "shared");
        assert_eq!(
            iso.cat_file(p, ByteRange::Full).await.unwrap_err().kind(),
            ErrorKind::NotFound
        );
        let iso2 = iso.clone();
        iso.pipe_file("/x", Bytes::from_static(b"1"), &WriteOptions::default())
            .await
            .unwrap();
        assert!(iso2.exists("/x").await.unwrap());
        a.rm_file(p).await.unwrap();
    }

    #[tokio::test]
    async fn paths_are_normalised() {
        let fs = MemoryFileSystem::new_isolated();
        fs.pipe_file("a/b/", Bytes::from_static(b"x"), &WriteOptions::default())
            .await
            .unwrap();
        assert_eq!(fs.info("memory://a/b").await.unwrap().name, "/a/b");
        assert_eq!(fs.info("/a/b/").await.unwrap().name, "/a/b");
        assert_eq!(fs.ls("/").await.unwrap()[0].name, "/a");
        assert_eq!(fs.info("/").await.unwrap().name, "");
    }

    #[tokio::test]
    async fn pipe_and_cat_are_zero_copy() {
        let fs = MemoryFileSystem::new_isolated();
        let data = Bytes::from(vec![7u8; 1 << 20]);
        let ptr = data.as_ptr();
        fs.pipe_file("/z", data, &WriteOptions::default())
            .await
            .unwrap();
        let got = fs.cat_file("/z", ByteRange::Full).await.unwrap();
        assert_eq!(got.as_ptr(), ptr, "cat_file must return the stored buffer");
        let part = fs
            .cat_file("/z", ByteRange::Bounded { start: 10, end: 20 })
            .await
            .unwrap();
        assert_eq!(part.as_ptr(), offset_ptr(ptr, 10));
        fs.cp_file("/z", "/z2").await.unwrap();
        assert_eq!(
            fs.cat_file("/z2", ByteRange::Full).await.unwrap().as_ptr(),
            ptr
        );
        let h = fs.open_read("/z", &ReadOptions::default()).await.unwrap();
        assert_eq!(h.read_at(5, 3).await.unwrap().as_ptr(), offset_ptr(ptr, 5));
    }

    /// `ptr + n` computed through integers (no `unsafe` pointer arithmetic).
    fn offset_ptr(ptr: *const u8, n: usize) -> *const u8 {
        (ptr as usize + n) as *const u8
    }

    #[tokio::test]
    async fn write_handle_semantics() {
        let fs = MemoryFileSystem::new_isolated();
        let mut w = fs.open_write("/w", &WriteOptions::default()).await.unwrap();
        // Exists (empty) from open, like fsspec.
        assert_eq!(fs.info("/w").await.unwrap().size, 0);
        w.write(Bytes::from_static(b"ab")).await.unwrap();
        w.write(Bytes::new()).await.unwrap();
        w.write(Bytes::from_static(b"c")).await.unwrap();
        w.flush().await.unwrap();
        assert_eq!(fs.cat_file("/w", ByteRange::Full).await.unwrap(), "abc");
        w.write(Bytes::from_static(b"de")).await.unwrap();
        w.close().await.unwrap();
        w.close().await.unwrap();
        assert_eq!(w.bytes_written(), 5);
        assert_eq!(fs.cat_file("/w", ByteRange::Full).await.unwrap(), "abcde");
        assert_eq!(
            w.write(Bytes::from_static(b"x")).await.unwrap_err().kind(),
            ErrorKind::InvalidInput
        );

        // Abort of a new file removes it.
        let mut w = fs
            .open_write("/gone", &WriteOptions::default())
            .await
            .unwrap();
        w.write(Bytes::from_static(b"zz")).await.unwrap();
        w.abort().await.unwrap();
        assert!(!fs.exists("/gone").await.unwrap());
        assert_eq!(w.close().await.unwrap_err().kind(), ErrorKind::InvalidInput);

        // Abort of an append restores the original.
        let mut w = fs
            .open_write("/w", &WriteOptions::default().with_mode(WriteMode::Append))
            .await
            .unwrap();
        w.write(Bytes::from_static(b"!!")).await.unwrap();
        w.flush().await.unwrap();
        assert_eq!(fs.cat_file("/w", ByteRange::Full).await.unwrap(), "abcde!!");
        w.abort().await.unwrap();
        assert_eq!(fs.cat_file("/w", ByteRange::Full).await.unwrap(), "abcde");

        // Dropping without close publishes.
        {
            let mut w = fs
                .open_write("/dropped", &WriteOptions::default())
                .await
                .unwrap();
            w.write(Bytes::from_static(b"kept")).await.unwrap();
        }
        assert_eq!(
            fs.cat_file("/dropped", ByteRange::Full).await.unwrap(),
            "kept"
        );

        // A handle whose file was replaced does not clobber the new file.
        let mut w = fs
            .open_write("/race", &WriteOptions::default())
            .await
            .unwrap();
        fs.pipe_file(
            "/race",
            Bytes::from_static(b"winner"),
            &WriteOptions::default(),
        )
        .await
        .unwrap();
        w.write(Bytes::from_static(b"loser")).await.unwrap();
        w.close().await.unwrap();
        assert_eq!(
            fs.cat_file("/race", ByteRange::Full).await.unwrap(),
            "winner"
        );
    }

    #[tokio::test]
    async fn read_handle_is_a_snapshot() {
        let fs = MemoryFileSystem::new_isolated();
        fs.pipe_file("/s", Bytes::from_static(b"old"), &WriteOptions::default())
            .await
            .unwrap();
        let h = fs.open_read("/s", &ReadOptions::default()).await.unwrap();
        fs.pipe_file("/s", Bytes::from_static(b"newer"), &WriteOptions::default())
            .await
            .unwrap();
        assert_eq!(h.read_at(0, 100).await.unwrap(), "old");
        assert_eq!(h.size(), 3);
        assert!(matches!(
            h.info().extra.get("created"),
            Some(Value::Time(_))
        ));
        let mut ro = ReadOptions::default();
        ro.extra.insert("bogus".into(), Value::Int(1));
        assert_eq!(
            fs.open_read("/s", &ro).await.unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
    }

    #[tokio::test]
    async fn touch_semantics() {
        let fs = MemoryFileSystem::new_isolated();
        fs.touch("/t", false).await.unwrap();
        assert_eq!(fs.info("/t").await.unwrap().size, 0);
        fs.pipe_file("/t", Bytes::from_static(b"x"), &WriteOptions::default())
            .await
            .unwrap();
        assert_eq!(
            fs.touch("/t", false).await.unwrap_err().kind(),
            ErrorKind::Unsupported
        );
        fs.touch("/t", true).await.unwrap();
        assert_eq!(fs.info("/t").await.unwrap().size, 0);
    }

    #[tokio::test]
    async fn put_and_get_files() {
        let fs = MemoryFileSystem::new_isolated();
        let tmp = std::env::temp_dir().join(format!("fsfast-memory-unit-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join("srcdir")).unwrap();
        std::fs::write(tmp.join("src.bin"), b"payload").unwrap();

        fs.put_file(&tmp.join("src.bin"), "/up/load/f", &WriteOptions::default())
            .await
            .unwrap();
        assert_eq!(
            fs.cat_file("/up/load/f", ByteRange::Full).await.unwrap(),
            "payload"
        );
        // fsspec creates the parents as pseudo-directories.
        fs.rmdir("/up/load").await.unwrap_err();
        assert_eq!(
            fs.put_file(
                &tmp.join("src.bin"),
                "/up/load/f",
                &WriteOptions::default().with_mode(WriteMode::CreateNew)
            )
            .await
            .unwrap_err()
            .kind(),
            ErrorKind::AlreadyExists
        );
        fs.put_file(&tmp.join("srcdir"), "/up/dir", &WriteOptions::default())
            .await
            .unwrap();
        assert!(fs.info("/up/dir").await.unwrap().is_dir());

        fs.get_file("/up/load/f", &tmp.join("out/nested/f"))
            .await
            .unwrap();
        assert_eq!(std::fs::read(tmp.join("out/nested/f")).unwrap(), b"payload");
        fs.get_file("/up", &tmp.join("outdir")).await.unwrap();
        assert!(tmp.join("outdir").is_dir());
        assert_eq!(
            fs.get_file("/missing", &tmp.join("never"))
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::NotFound
        );
        assert!(!tmp.join("never").exists());
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    /// Regression: an over-long local name (`ENAMETOOLONG`) was reported as
    /// `InvalidInput` (Python `ValueError`); fsspec raises `OSError`.
    #[tokio::test]
    async fn local_os_errors_keep_python_classes() {
        let fs = MemoryFileSystem::new_isolated();
        fs.pipe_file("/f", Bytes::from_static(b"x"), &WriteOptions::default())
            .await
            .unwrap();
        let long = std::env::temp_dir().join("n".repeat(300));
        let e = fs.get_file("/f", &long).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Io, "{e}");
        let e = fs
            .put_file(&long, "/g", &WriteOptions::default())
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Io, "{e}");
        assert!(!fs.exists("/g").await.unwrap());
    }

    #[tokio::test]
    async fn clear_resets_store() {
        let fs = MemoryFileSystem::new_isolated();
        fs.mkdir("/d", true).await.unwrap();
        fs.pipe_file("/d/f", Bytes::from_static(b"x"), &WriteOptions::default())
            .await
            .unwrap();
        assert_eq!(fs.file_count(), 1);
        fs.clear();
        assert_eq!(fs.file_count(), 0);
        assert!(!fs.exists("/d").await.unwrap());
        assert!(fs.info("").await.unwrap().is_dir());
    }
}
