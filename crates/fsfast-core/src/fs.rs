//! The filesystem, read-handle and write-handle traits.
//!
//! Design notes (see docs/PLAN.md §4.3):
//! * The model is **handle-based**. Stateful protocols (SMB, SFTP, local) keep
//!   an open file handle and pipeline I/O on it; object stores implement a
//!   handle as "key + version token" and issue stateless ranged GETs.
//! * Everything is async. The Python layer drives futures on a shared tokio
//!   runtime with the GIL released.
//! * Default method bodies are correct but simple. Backends override them
//!   whenever the protocol can do better (server-side copy, batch delete,
//!   compounding, native suffix ranges, ...). `fsfast-engine` provides the
//!   heavy performance machinery (readahead, parallel ranged GET, retries,
//!   adaptive concurrency) that backends compose.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::{StreamExt, stream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::range::{ByteRange, coalesce_ranges, split_range};
use crate::{Error, ErrorKind, FileInfo, Options, Result, path};

/// What a backend can do natively. The engine and the Python layer pick
/// strategies from these flags instead of hard-coding backend names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capabilities {
    /// Real directories exist (local, SMB, SFTP, ADLS Gen2). `false` means
    /// directories are emulated from key prefixes (S3, GCS, Blob).
    pub hierarchical: bool,
    /// `mv_file` is a single atomic server operation.
    pub atomic_rename: bool,
    /// `cp_file` happens server-side without moving data through the client.
    pub server_side_copy: bool,
    /// Open mode `ab` is supported.
    pub append: bool,
    /// Open mode `xb` is atomic (create-if-not-exists enforced by the server).
    pub conditional_create: bool,
    /// Writes at arbitrary offsets are supported.
    pub random_write: bool,
    /// Object versions can be listed/read.
    pub versioning: bool,
    /// `sign()` can produce pre-signed URLs.
    pub signed_urls: bool,
    /// Reads can be pinned to the version observed at open time.
    pub pinned_reads: bool,
}

/// I/O sizing hints the engine uses for request sizing and concurrency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoHints {
    /// Preferred size of a single read/write request in bytes.
    pub request_size: usize,
    /// Maximum useful number of concurrent requests per handle / operation.
    pub max_concurrency: usize,
    /// Merge ranged reads whose gap is at most this many bytes.
    pub coalesce_gap: u64,
    /// Never merge ranges into a single request larger than this.
    pub max_coalesced: u64,
}

impl Default for IoHints {
    fn default() -> Self {
        IoHints {
            request_size: 8 << 20,
            max_concurrency: 16,
            coalesce_gap: 1 << 20,
            max_coalesced: 32 << 20,
        }
    }
}

/// How `open_write` treats an existing target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WriteMode {
    /// Mode `wb`: replace.
    #[default]
    Overwrite,
    /// Mode `xb`: fail with `AlreadyExists` if the target exists.
    CreateNew,
    /// Mode `ab`: append (only if `Capabilities::append`).
    Append,
}

/// Options for [`FileSystem::open_read`].
#[derive(Debug, Clone)]
pub struct ReadOptions {
    /// Hint for request size; `None` uses the backend default.
    pub block_size: Option<usize>,
    /// Read a specific version (S3 version id, GCS generation, ...).
    pub version: Option<String>,
    /// Pin all reads on the handle to the version observed at open time, so a
    /// concurrent overwrite surfaces as `PreconditionFailed` instead of mixed
    /// bytes. Default `true`; ignored when the backend cannot pin.
    pub pin_version: bool,
    /// Backend-specific extras (e.g. S3 `SSECustomerKey`).
    pub extra: Options,
}

impl Default for ReadOptions {
    fn default() -> Self {
        ReadOptions {
            block_size: None,
            version: None,
            pin_version: true,
            extra: Options::new(),
        }
    }
}

/// Options for [`FileSystem::open_write`] and [`FileSystem::pipe_file`].
#[derive(Debug, Clone, Default)]
pub struct WriteOptions {
    pub mode: WriteMode,
    /// Part / block size hint for multipart-style uploads.
    pub block_size: Option<usize>,
    pub content_type: Option<String>,
    /// User metadata (S3 `x-amz-meta-*`, GCS metadata, ...).
    pub metadata: BTreeMap<String, String>,
    /// Backend-specific extras (e.g. S3 `ServerSideEncryption`, `ACL`).
    pub extra: Options,
}

impl WriteOptions {
    pub fn with_mode(mut self, mode: WriteMode) -> Self {
        self.mode = mode;
        self
    }
}

/// Options for [`FileSystem::find`].
#[derive(Debug, Clone, Copy, Default)]
pub struct FindOptions {
    /// Maximum recursion depth below the root (1 = immediate children only).
    pub maxdepth: Option<usize>,
    /// Include directories in the result (fsspec `withdirs=True`); the root
    /// itself is included when it is a directory, matching fsspec.
    pub withdirs: bool,
}

/// An open file for reading.
///
/// Implementations must be safe to use concurrently: the engine issues many
/// `read_at` calls on one handle in parallel.
#[async_trait]
pub trait ReadHandle: Send + Sync + fmt::Debug {
    /// Metadata observed when the handle was opened.
    fn info(&self) -> &FileInfo;

    /// Size in bytes at open time.
    fn size(&self) -> u64 {
        self.info().size
    }

    fn io_hints(&self) -> IoHints {
        IoHints::default()
    }

    /// Read `len` bytes starting at `offset`.
    ///
    /// Must return exactly `min(len, size - offset)` bytes (empty at/after
    /// EOF). Implementations split internally if the protocol caps request
    /// sizes (e.g. SMB `MaxReadSize`).
    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes>;

    /// Read several ranges. The default coalesces nearby ranges using
    /// [`ReadHandle::io_hints`] and fetches the merged ranges concurrently.
    /// Returned buffers correspond 1:1 to `ranges`; ranges past EOF are
    /// truncated.
    async fn read_ranges(&self, ranges: &[Range<u64>]) -> Result<Vec<Bytes>> {
        read_ranges_coalesced(self, ranges).await
    }

    /// Release server-side resources. Dropping without `close` must not leak
    /// indefinitely, but `close` lets errors surface.
    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// An open file for writing.
///
/// Data becomes visible only after a successful [`WriteHandle::close`]
/// (object stores) or progressively (hierarchical filesystems); either way,
/// `close` must be called on success and `abort` on failure.
#[async_trait]
pub trait WriteHandle: Send + fmt::Debug {
    /// Append `data` to the stream. Backends may buffer and upload parts
    /// concurrently in the background.
    async fn write(&mut self, data: Bytes) -> Result<()>;

    /// Push buffered data to the server where the protocol allows it.
    async fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    /// Finish the write and make the data visible. Idempotent after success.
    async fn close(&mut self) -> Result<()>;

    /// Discard the write and clean up partial state (abort multipart upload,
    /// delete temp file, ...).
    async fn abort(&mut self) -> Result<()>;

    /// Bytes accepted by `write` so far.
    fn bytes_written(&self) -> u64;
}

/// A filesystem backend.
///
/// Paths are fsspec-style protocol-stripped strings (see [`crate::path`]).
#[async_trait]
pub trait FileSystem: Send + Sync + fmt::Debug + 'static {
    /// Protocol names this backend serves, first is canonical (e.g. `["s3", "s3a"]`).
    fn protocols(&self) -> &'static [&'static str];

    fn capabilities(&self) -> Capabilities;

    fn io_hints(&self) -> IoHints {
        IoHints::default()
    }

    /// Metadata for one path. `NotFound` if it does not exist.
    async fn info(&self, path: &str) -> Result<FileInfo>;

    /// Immediate children of a directory. Listing a file returns `[info(file)]`
    /// (fsspec behaviour). `NotFound` if the path does not exist.
    async fn ls(&self, path: &str) -> Result<Vec<FileInfo>>;

    /// Recursive listing, sorted by name. Object stores should override with a
    /// flat (delimiter-less) listing.
    async fn find(&self, path: &str, opts: &FindOptions) -> Result<Vec<FileInfo>> {
        find_bfs(self, path, opts).await
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        match self.info(path).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn open_read(&self, path: &str, opts: &ReadOptions) -> Result<Arc<dyn ReadHandle>>;

    async fn open_write(&self, path: &str, opts: &WriteOptions) -> Result<Box<dyn WriteHandle>>;

    /// Read a whole file or a byte range of it.
    async fn cat_file(&self, path: &str, range: ByteRange) -> Result<Bytes> {
        let h = self.open_read(path, &ReadOptions::default()).await?;
        let r = range.resolve(h.size());
        let out = if r.end > r.start {
            h.read_at(r.start, (r.end - r.start) as usize).await
        } else {
            Ok(Bytes::new())
        };
        let closed = h.close().await;
        let out = out?;
        closed?;
        Ok(out)
    }

    /// Read many ranges of one file (fsspec `cat_ranges` for a single path).
    async fn cat_ranges(&self, path: &str, ranges: &[Range<u64>]) -> Result<Vec<Bytes>> {
        let h = self.open_read(path, &ReadOptions::default()).await?;
        let out = h.read_ranges(ranges).await;
        let closed = h.close().await;
        let out = out?;
        closed?;
        Ok(out)
    }

    /// Write a whole file from memory.
    async fn pipe_file(&self, path: &str, data: Bytes, opts: &WriteOptions) -> Result<()> {
        let mut w = self.open_write(path, opts).await?;
        let res = async {
            if !data.is_empty() {
                w.write(data).await?;
            }
            w.close().await
        }
        .await;
        if res.is_err() {
            let _ = w.abort().await;
        }
        res
    }

    /// Delete one file. `NotFound` if missing.
    async fn rm_file(&self, path: &str) -> Result<()>;

    /// Delete many files; one result per input path, same order.
    async fn rm_files(&self, paths: &[String]) -> Vec<Result<()>> {
        let conc = self.io_hints().max_concurrency.max(1);
        let futs: Vec<_> = paths.iter().map(|p| self.rm_file(p.as_str())).collect();
        stream::iter(futs).buffered(conc).collect().await
    }

    /// Create a directory (or bucket/container at the top level of an object
    /// store; a no-op for emulated directories below that).
    async fn mkdir(&self, path: &str, create_parents: bool) -> Result<()>;

    /// `makedirs(path, exist_ok)`.
    async fn makedirs(&self, path: &str, exist_ok: bool) -> Result<()> {
        match self.info(path).await {
            Ok(i) if i.is_dir() => {
                if exist_ok {
                    Ok(())
                } else {
                    Err(Error::already_exists(path))
                }
            }
            Ok(_) => Err(Error::already_exists(path)),
            Err(e) if e.kind() == ErrorKind::NotFound => self.mkdir(path, true).await,
            Err(e) => Err(e),
        }
    }

    /// Remove an empty directory.
    async fn rmdir(&self, path: &str) -> Result<()>;

    /// Copy one file within this filesystem. Default streams data through the
    /// client; override for server-side copy.
    async fn cp_file(&self, src: &str, dst: &str) -> Result<()> {
        copy_via_stream(self, src, dst).await
    }

    /// Move one file. Default is copy + delete; override when the protocol
    /// can rename.
    async fn mv_file(&self, src: &str, dst: &str) -> Result<()> {
        if path::normalize(src) == path::normalize(dst) {
            return Ok(());
        }
        self.cp_file(src, dst).await?;
        self.rm_file(src).await
    }

    /// Upload a local file.
    async fn put_file(&self, local: &Path, remote: &str, opts: &WriteOptions) -> Result<()> {
        let mut f = tokio::fs::File::open(local).await?;
        let chunk = opts
            .block_size
            .unwrap_or(self.io_hints().request_size)
            .max(64 << 10);
        let mut w = self.open_write(remote, opts).await?;
        let res = async {
            loop {
                let mut buf = vec![0u8; chunk];
                let mut filled = 0;
                while filled < chunk {
                    let n = f.read(&mut buf[filled..]).await?;
                    if n == 0 {
                        break;
                    }
                    filled += n;
                }
                if filled == 0 {
                    break;
                }
                buf.truncate(filled);
                w.write(Bytes::from(buf)).await?;
                if filled < chunk {
                    break;
                }
            }
            w.close().await
        }
        .await;
        if res.is_err() {
            let _ = w.abort().await;
        }
        res
    }

    /// Download to a local file, fetching chunks concurrently and writing them
    /// in order. A partially written local file is removed on failure.
    async fn get_file(&self, remote: &str, local: &Path) -> Result<()> {
        let h = self.open_read(remote, &ReadOptions::default()).await?;
        let hints = h.io_hints();
        let size = h.size();
        let res = async {
            let mut f = tokio::fs::File::create(local).await?;
            let chunks = split_range(0..size, hints.request_size.max(1) as u64);
            let mut s = stream::iter(chunks.into_iter().map(|r| {
                let h = &h;
                async move { h.read_at(r.start, (r.end - r.start) as usize).await }
            }))
            .buffered(hints.max_concurrency.max(1));
            while let Some(chunk) = s.next().await {
                f.write_all(&chunk?).await?;
            }
            f.flush().await?;
            Ok::<_, Error>(())
        }
        .await;
        let _ = h.close().await;
        if res.is_err() {
            let _ = tokio::fs::remove_file(local).await;
        }
        res
    }

    /// Create an empty file, or truncate an existing one when `truncate`.
    /// Updating the timestamp of an existing file without truncation is only
    /// possible on hierarchical backends, which should override.
    async fn touch(&self, path: &str, truncate: bool) -> Result<()> {
        if !truncate && self.exists(path).await? {
            return Err(Error::unsupported(
                "touch without truncate on an existing file",
            ));
        }
        self.pipe_file(path, Bytes::new(), &WriteOptions::default())
            .await
    }

    /// Pre-signed URL valid for `expires`.
    async fn sign(&self, path: &str, expires: Duration) -> Result<String> {
        let _ = (path, expires);
        Err(Error::unsupported("sign"))
    }

    /// Drop cached listings/metadata for `path` (and its parents), or
    /// everything when `None`.
    fn invalidate_cache(&self, path: Option<&str>) {
        let _ = path;
    }

    /// Release pooled connections. The filesystem stays usable and reconnects
    /// lazily.
    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Default [`ReadHandle::read_ranges`] implementation: clamp to size,
/// coalesce with the handle's hints, fetch concurrently, slice results.
pub async fn read_ranges_coalesced<H: ReadHandle + ?Sized>(
    h: &H,
    ranges: &[Range<u64>],
) -> Result<Vec<Bytes>> {
    let hints = h.io_hints();
    let size = h.size();
    let clamped: Vec<Range<u64>> = ranges
        .iter()
        .map(|r| {
            let s = r.start.min(size);
            s..r.end.min(size).max(s)
        })
        .collect();
    let groups = coalesce_ranges(&clamped, hints.coalesce_gap, hints.max_coalesced.max(1));
    type Fetched = Result<(Vec<usize>, Range<u64>, Bytes)>;
    let fetched: Vec<Fetched> = stream::iter(groups.into_iter().map(|g| async move {
        let len = (g.range.end - g.range.start) as usize;
        let data = if len == 0 {
            Bytes::new()
        } else {
            h.read_at(g.range.start, len).await?
        };
        Ok((g.members, g.range, data))
    }))
    .buffer_unordered(hints.max_concurrency.max(1))
    .collect()
    .await;

    let mut out = vec![Bytes::new(); ranges.len()];
    for item in fetched {
        let (members, range, data) = item?;
        for i in members {
            let r = &clamped[i];
            if r.end <= r.start {
                continue;
            }
            let s = (r.start - range.start) as usize;
            let e = ((r.end - range.start) as usize).min(data.len());
            if s < e {
                out[i] = data.slice(s..e);
            }
        }
    }
    Ok(out)
}

/// Breadth-first recursive listing built on concurrent `ls` calls.
pub async fn find_bfs<F: FileSystem + ?Sized>(
    fs: &F,
    root: &str,
    opts: &FindOptions,
) -> Result<Vec<FileInfo>> {
    let root = path::normalize(root);
    let root_info = match fs.info(&root).await {
        Ok(i) => i,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    if !root_info.is_dir() {
        return Ok(vec![root_info]);
    }
    let conc = fs.io_hints().max_concurrency.max(1);
    let mut out = Vec::new();
    if opts.withdirs && !root.is_empty() {
        out.push(root_info);
    }
    let mut frontier = vec![root.clone()];
    let mut depth = 0usize;
    while !frontier.is_empty() {
        depth += 1;
        if opts.maxdepth.is_some_and(|m| depth > m) {
            break;
        }
        let dirs = std::mem::take(&mut frontier);
        let listings: Vec<(String, Result<Vec<FileInfo>>)> =
            stream::iter(dirs.into_iter().map(|d| async move {
                let r = fs.ls(&d).await;
                (d, r)
            }))
            .buffer_unordered(conc)
            .collect()
            .await;
        for (dir, listing) in listings {
            let entries = match listing {
                Ok(v) => v,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            for e in entries {
                if path::normalize(&e.name) == dir {
                    continue;
                }
                if e.is_dir() {
                    frontier.push(e.name.clone());
                    if opts.withdirs {
                        out.push(e);
                    }
                } else {
                    out.push(e);
                }
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Copy by streaming through the client, `request_size` at a time with a few
/// reads in flight.
pub async fn copy_via_stream<F: FileSystem + ?Sized>(fs: &F, src: &str, dst: &str) -> Result<()> {
    let h = fs.open_read(src, &ReadOptions::default()).await?;
    if h.info().is_dir() {
        return Err(Error::is_a_directory(src));
    }
    let hints = h.io_hints();
    let mut w = fs.open_write(dst, &WriteOptions::default()).await?;
    let res = async {
        let chunks = split_range(0..h.size(), hints.request_size.max(1) as u64);
        let mut s = stream::iter(chunks.into_iter().map(|r| {
            let h = &h;
            async move { h.read_at(r.start, (r.end - r.start) as usize).await }
        }))
        .buffered(hints.max_concurrency.clamp(1, 4));
        while let Some(chunk) = s.next().await {
            w.write(chunk?).await?;
        }
        w.close().await
    }
    .await;
    let _ = h.close().await;
    if res.is_err() {
        let _ = w.abort().await;
    }
    res
}
