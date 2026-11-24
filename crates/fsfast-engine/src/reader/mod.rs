//! [`FileReader`]: the engine behind Python file objects opened for reading.
//!
//! A `FileReader` wraps an `Arc<dyn ReadHandle>`, tracks a position and
//! serves `read`, `readinto`, `seek` and `tell` with one of the cache modes
//! of fsspec's `cache_type`:
//!
//! | [`CacheMode`] | fsspec names | behaviour |
//! |---|---|---|
//! | [`None`](CacheMode::None) | `none` | every read is fetched exactly |
//! | [`Readahead`](CacheMode::Readahead) (default) | `readahead`, `adaptive`, `bytes`, `first` | adaptive sequential readahead, see below |
//! | [`Blocks`](CacheMode::Blocks) | `blockcache`, `mmap`, `background` | LRU cache of aligned blocks, optional prefetch of the next block |
//! | [`Whole`](CacheMode::Whole) | `all` | the whole file is fetched on the first read |
//!
//! **Readahead** follows the Linux page-cache heuristics: a read is
//! sequential when it starts where the previous one ended (or within data
//! already prefetched); random reads fetch exactly what was asked. On
//! sequential access a window of prefetch requests (each up to the handle's
//! request size) is kept in flight as spawned tokio tasks; the window starts
//! at 2–4x the read size and doubles (quadruples while small) roughly every
//! half window consumed, up to `max_readahead`. A random seek cancels all
//! prefetches and resets the window.
//!
//! In every mode, a read of at least twice the request size that is not
//! already buffered is fetched with [`read_parallel`]
//! straight into the destination.
//!
//! Prefetched and cached data is accounted against a [`MemoryBudget`]:
//! optional prefetch only happens while budget is available; data the
//! caller asked for is always fetched. Background tasks are aborted when the
//! reader is dropped, closed, or seeks away, so no task outlives the reader.
//!
//! Zero-copy: `read(n)` returns a slice of a prefetched chunk or cached block
//! when the request falls inside one (such a slice keeps the whole chunk's
//! allocation alive while it exists); otherwise the result is assembled with
//! a single copy. `read_into` copies once into the caller's buffer.

mod blocks;
mod readahead;

use std::io::SeekFrom;
use std::ops::Range;
use std::sync::Arc;

use bytes::Bytes;
use fsfast_core::{Error, ErrorKind, ReadHandle, Result};
use futures::FutureExt;
use futures::future::{BoxFuture, Shared};

use crate::budget::{BudgetGuard, MemoryBudget};
use crate::concurrency::{AbortOnDrop, join_error};
use crate::parallel::{check_len, read_parallel, read_parallel_into};

use blocks::Blocks;
use readahead::Readahead;

/// Configuration of [`CacheMode::Blocks`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockCacheConfig {
    /// Block size; `None` uses the reader's request size.
    pub block_size: Option<usize>,
    /// Maximum number of cached blocks (fsspec `maxblocks`, default 32).
    pub max_blocks: usize,
    /// Fetch the block after the last one read in the background (fsspec
    /// `background` cache).
    pub prefetch: bool,
}

impl Default for BlockCacheConfig {
    fn default() -> Self {
        BlockCacheConfig {
            block_size: None,
            max_blocks: 32,
            prefetch: false,
        }
    }
}

/// Caching strategy of a [`FileReader`]; see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheMode {
    /// Exact reads, no caching.
    None,
    /// Adaptive sequential readahead (default).
    #[default]
    Readahead,
    /// LRU cache of aligned blocks.
    Blocks(BlockCacheConfig),
    /// Fetch the whole file on first read.
    Whole,
}

impl CacheMode {
    /// Translate fsspec's `cache_type` (with its `block_size` and
    /// `maxblocks` arguments for block caches).
    ///
    /// Every name registered in fsspec's `fsspec.caching.caches` is
    /// accepted except `parts`, which needs data supplied up front. `mmap`
    /// (a disk-backed block cache in fsspec) maps to an in-memory block
    /// cache, and `first` and `adaptive` (fsspec's adaptive readahead) to
    /// readahead; caching never changes the bytes returned, only how they
    /// are fetched.
    pub fn from_fsspec(
        cache_type: &str,
        block_size: Option<usize>,
        max_blocks: Option<usize>,
    ) -> Result<Self> {
        let blocks = |prefetch| {
            CacheMode::Blocks(BlockCacheConfig {
                block_size,
                max_blocks: max_blocks.unwrap_or(32),
                prefetch,
            })
        };
        Ok(match cache_type.to_ascii_lowercase().as_str() {
            "none" => CacheMode::None,
            "readahead" | "adaptive" | "bytes" | "first" => CacheMode::Readahead,
            "blockcache" | "mmap" => blocks(false),
            "background" => blocks(true),
            "all" => CacheMode::Whole,
            "parts" => return Err(Error::unsupported("cache_type 'parts'")),
            other => {
                return Err(Error::invalid_input(format!(
                    "unknown cache_type {other:?} (expected one of none, readahead, adaptive, bytes, first, blockcache, mmap, background, all)"
                )));
            }
        })
    }
}

/// Configuration of a [`FileReader`]. `None` fields derive from the
/// handle's [`IoHints`](fsfast_core::IoHints).
#[derive(Debug, Clone)]
pub struct ReaderConfig {
    /// Caching strategy.
    pub cache: CacheMode,
    /// Size of one request (prefetch chunk, parallel part); default
    /// `IoHints::request_size`.
    pub request_size: Option<usize>,
    /// Maximum requests in flight per reader; default
    /// `IoHints::max_concurrency`.
    pub concurrency: Option<usize>,
    /// Smallest readahead window (default 256 KiB).
    pub min_readahead: usize,
    /// Largest readahead window; default `8 x request_size` within
    /// `[1 MiB, 128 MiB]`.
    pub max_readahead: Option<usize>,
    /// Budget for prefetched and cached data; `None` uses
    /// [`MemoryBudget::global`].
    pub budget: Option<MemoryBudget>,
}

impl Default for ReaderConfig {
    fn default() -> Self {
        ReaderConfig {
            cache: CacheMode::Readahead,
            request_size: None,
            concurrency: None,
            min_readahead: 256 << 10,
            max_readahead: None,
            budget: None,
        }
    }
}

impl ReaderConfig {
    /// Default configuration with the given cache mode.
    pub fn with_cache(cache: CacheMode) -> Self {
        ReaderConfig {
            cache,
            ..ReaderConfig::default()
        }
    }
}

/// Resolved, shared parameters of a reader.
struct Ctx {
    handle: Arc<dyn ReadHandle>,
    size: u64,
    request_size: usize,
    concurrency: usize,
    budget: MemoryBudget,
}

impl Ctx {
    /// Reads this large bypass caches and go through `read_parallel`.
    fn is_large(&self, n: usize) -> bool {
        n as u64 >= (self.request_size as u64).saturating_mul(2)
    }

    /// Fetch exactly `[off, off + len)` (in bounds), in parallel when large,
    /// accounting the parts in flight against the reader's budget.
    async fn fetch(&self, off: u64, len: usize) -> Result<Bytes> {
        self.fetch_with(off, len, Some(&self.budget)).await
    }

    /// [`Ctx::fetch`] with an explicit budget for the parts in flight; `None`
    /// when the caller already accounts for every byte (accounting them
    /// twice would throttle the read against itself).
    async fn fetch_with(
        &self,
        off: u64,
        len: usize,
        budget: Option<&MemoryBudget>,
    ) -> Result<Bytes> {
        if self.is_large(len) {
            let b = read_parallel(
                &self.handle,
                off..off + len as u64,
                self.request_size,
                self.concurrency,
                budget,
            )
            .await?;
            check_len(off, len, b.len())?;
            Ok(b)
        } else {
            let b = self.handle.read_at(off, len).await?;
            check_len(off, len, b.len())?;
            Ok(b)
        }
    }

    /// Fill `dst` from `off` (in bounds), in parallel when large.
    async fn fetch_into(&self, off: u64, dst: &mut [u8]) -> Result<()> {
        if self.is_large(dst.len()) {
            let n = read_parallel_into(
                &self.handle,
                off,
                dst,
                self.request_size,
                self.concurrency,
                Some(&self.budget),
            )
            .await?;
            check_len(off, dst.len(), n)
        } else {
            let b = self.handle.read_at(off, dst.len()).await?;
            check_len(off, dst.len(), b.len())?;
            dst.copy_from_slice(&b);
            Ok(())
        }
    }
}

/// A background fetch whose result several [`Fetch`]es slice (errors are
/// shared behind an `Arc` because [`Error`] is not `Clone`).
type SharedFetch = Shared<BoxFuture<'static, std::result::Result<Bytes, Arc<Error>>>>;

enum FetchState {
    Pending(AbortOnDrop<Result<Bytes>>),
    /// Bytes `range` of a fetch shared with neighbouring blocks. The task is
    /// aborted when the last `Fetch` referring to it is dropped.
    Shared(SharedFetch, Range<usize>),
    Ready(Bytes),
}

/// One background fetch of `[start, end)` (a readahead chunk or a cached
/// block) and the budget its bytes hold. Dropping it aborts the task.
struct Fetch {
    start: u64,
    end: u64,
    state: FetchState,
    /// Shared by the pieces of one shared fetch: they are zero-copy slices
    /// of one buffer, which stays allocated (and accounted) until the last
    /// piece is dropped.
    _guard: Arc<BudgetGuard>,
}

impl Fetch {
    fn spawn_task(ctx: &Ctx, start: u64, len: usize) -> AbortOnDrop<Result<Bytes>> {
        let h = ctx.handle.clone();
        if ctx.is_large(len) {
            // Large blocks (fsspec users often pass block_size=50 MiB) are
            // fetched as parallel parts. No extra budget: the caller's guard
            // already accounts for every byte of the block.
            let (part, conc) = (ctx.request_size, ctx.concurrency);
            AbortOnDrop::spawn(async move {
                read_parallel(&h, start..start + len as u64, part, conc, None).await
            })
        } else {
            AbortOnDrop::spawn(async move { h.read_at(start, len).await })
        }
    }

    fn spawn(ctx: &Ctx, start: u64, len: usize, guard: BudgetGuard) -> Self {
        Fetch {
            start,
            end: start + len as u64,
            state: FetchState::Pending(Fetch::spawn_task(ctx, start, len)),
            _guard: Arc::new(guard),
        }
    }

    /// One request for the consecutive pieces `lens` starting at `start`,
    /// returned as one `Fetch` per piece; `guard` (for all of the bytes) is
    /// released when the last piece is dropped. Small cache blocks are
    /// fetched this way so a run of them costs one request instead of one
    /// request (and task) per block.
    fn spawn_shared(ctx: &Ctx, start: u64, lens: &[usize], guard: BudgetGuard) -> Vec<Fetch> {
        let total: usize = lens.iter().sum();
        if lens.len() == 1 {
            return vec![Fetch::spawn(ctx, start, total, guard)];
        }
        let task = Fetch::spawn_task(ctx, start, total);
        let shared = async move {
            match task.await {
                Ok(Ok(data)) => check_len(start, total, data.len())
                    .map(|()| data)
                    .map_err(Arc::new),
                Ok(Err(e)) => Err(Arc::new(e)),
                Err(e) => Err(Arc::new(join_error(e))),
            }
        }
        .boxed()
        .shared();
        let guard = Arc::new(guard);
        let mut off = 0usize;
        lens.iter()
            .map(|&len| {
                let fetch = Fetch {
                    start: start + off as u64,
                    end: start + (off + len) as u64,
                    state: FetchState::Shared(shared.clone(), off..off + len),
                    _guard: guard.clone(),
                };
                off += len;
                fetch
            })
            .collect()
    }

    /// Still running (not merely "not yet awaited").
    fn in_flight(&self) -> bool {
        match &self.state {
            FetchState::Pending(t) => !t.is_finished(),
            FetchState::Shared(f, _) => f.peek().is_none(),
            FetchState::Ready(_) => false,
        }
    }

    /// Wait for the data.
    ///
    /// After an error the fetch is spent and must be dropped (its task's
    /// output has been consumed).
    async fn ready(&mut self) -> Result<&Bytes> {
        match &mut self.state {
            FetchState::Pending(task) => {
                let data = task.await.map_err(join_error)??;
                check_len(self.start, (self.end - self.start) as usize, data.len())?;
                self.state = FetchState::Ready(data);
            }
            FetchState::Shared(fut, range) => {
                let range = range.clone();
                let data = fut.clone().await.map_err(unshare_error)?;
                self.state = FetchState::Ready(data.slice(range));
            }
            FetchState::Ready(_) => {}
        }
        match &self.state {
            FetchState::Ready(b) => Ok(b),
            _ => Err(Error::new(ErrorKind::Other, "fetch not completed")),
        }
    }

    /// Collect the result if the fetch has already finished, without
    /// waiting: `Some(true)` when the data is ready, `Some(false)` when the
    /// fetch failed (drop it), `None` while it is still running.
    fn settle(&mut self) -> Option<bool> {
        match self.ready().now_or_never() {
            Some(Ok(_)) => Some(true),
            Some(Err(_)) => Some(false),
            None => None,
        }
    }
}

/// An owned copy of a shared error (kind, message, path, details and retry
/// classification are kept; the source is folded into the message).
fn unshare_error(e: Arc<Error>) -> Error {
    Arc::try_unwrap(e).unwrap_or_else(|e| {
        let message = match std::error::Error::source(&*e) {
            Some(src) => format!("{}: {src}", e.message()),
            None => e.message().to_owned(),
        };
        let mut out = Error::new(e.kind(), message).with_retryable(e.is_retryable());
        if let Some(p) = e.path() {
            out = out.with_path(p);
        }
        for d in e.details() {
            out = out.with_detail(d.clone());
        }
        out
    })
}

struct Whole {
    data: Option<(Bytes, BudgetGuard)>,
}

impl Whole {
    async fn get(&mut self, ctx: &Ctx) -> Result<&Bytes> {
        if self.data.is_none() {
            let len = usize::try_from(ctx.size)
                .map_err(|_| Error::invalid_input("file too large to cache in memory"))?;
            // The caller asked for the whole file: account all of it (this may
            // over-commit the budget, which then throttles everyone's
            // speculative work until it is released).
            let guard = ctx.budget.force_acquire(len);
            // `guard` covers every byte, so the parts are not accounted again
            // (a file larger than the free budget would otherwise be fetched
            // one part at a time).
            let data = ctx.fetch_with(0, len, None).await?;
            self.data = Some((data, guard));
        }
        match &self.data {
            Some((b, _)) => Ok(b),
            None => Err(Error::new(ErrorKind::Other, "whole-file cache not filled")),
        }
    }
}

enum State {
    None,
    Readahead(Readahead),
    Blocks(Blocks),
    Whole(Whole),
}

/// Positioned, cached reader over a [`ReadHandle`]; see the module docs.
///
/// Methods take `&mut self`; wrap the reader in a mutex to share it. Read
/// futures may be dropped at any `.await` without corrupting the reader: the
/// position only advances when a read completes.
pub struct FileReader {
    ctx: Ctx,
    mode: CacheMode,
    pos: u64,
    state: State,
    closed: bool,
}

impl std::fmt::Debug for FileReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileReader")
            .field("path", &self.ctx.handle.info().name)
            .field("size", &self.ctx.size)
            .field("pos", &self.pos)
            .field("mode", &self.mode)
            .field("closed", &self.closed)
            .finish()
    }
}

impl FileReader {
    /// Wrap `handle`. Must be called within a tokio runtime context only if
    /// reads are issued (background prefetch uses `tokio::spawn`).
    pub fn new(handle: Arc<dyn ReadHandle>, cfg: ReaderConfig) -> Self {
        let hints = handle.io_hints();
        let request_size = cfg.request_size.unwrap_or(hints.request_size).max(1);
        let concurrency = cfg.concurrency.unwrap_or(hints.max_concurrency).max(1);
        let max_ra = cfg
            .max_readahead
            .unwrap_or_else(|| request_size.saturating_mul(8).clamp(1 << 20, 128 << 20))
            .max(1);
        let min_ra = cfg.min_readahead.clamp(1, max_ra);
        let ctx = Ctx {
            size: handle.size(),
            handle,
            request_size,
            concurrency,
            budget: cfg.budget.unwrap_or_else(|| MemoryBudget::global().clone()),
        };
        let state = match cfg.cache {
            CacheMode::None => State::None,
            CacheMode::Readahead => State::Readahead(Readahead::new(min_ra as u64, max_ra as u64)),
            CacheMode::Blocks(b) => State::Blocks(Blocks::new(
                b.block_size.unwrap_or(request_size).max(1) as u64,
                b.max_blocks.max(1),
                b.prefetch,
            )),
            CacheMode::Whole => State::Whole(Whole { data: None }),
        };
        FileReader {
            ctx,
            mode: cfg.cache,
            pos: 0,
            state,
            closed: false,
        }
    }

    /// The underlying handle.
    pub fn handle(&self) -> &Arc<dyn ReadHandle> {
        &self.ctx.handle
    }

    /// File size (as observed when the handle was opened).
    pub fn size(&self) -> u64 {
        self.ctx.size
    }

    /// Current position.
    pub fn tell(&self) -> u64 {
        self.pos
    }

    /// The cache mode.
    pub fn cache_mode(&self) -> CacheMode {
        self.mode
    }

    /// Whether [`FileReader::close`] was called.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    fn check_open(&self) -> Result<()> {
        if self.closed {
            Err(Error::invalid_input("I/O operation on closed file"))
        } else {
            Ok(())
        }
    }

    /// Move the position (Python `seek`). Positions past the end are allowed
    /// (reads there return nothing); negative positions are `InvalidInput`.
    pub fn seek(&mut self, to: SeekFrom) -> Result<u64> {
        self.check_open()?;
        let (base, delta) = match to {
            SeekFrom::Start(n) => {
                self.set_pos(n);
                return Ok(n);
            }
            SeekFrom::Current(d) => (self.pos, d),
            SeekFrom::End(d) => (self.ctx.size, d),
        };
        let new = base.checked_add_signed(delta).ok_or_else(|| {
            Error::invalid_input(format!(
                "invalid seek to {base} + {delta}: negative or overflowing position"
            ))
        })?;
        self.set_pos(new);
        Ok(new)
    }

    fn set_pos(&mut self, new: u64) {
        if new != self.pos
            && let State::Readahead(ra) = &mut self.state
        {
            ra.on_seek(new);
        }
        self.pos = new;
    }

    /// Read `n` bytes (`None`: to the end of the file) from the current
    /// position. Returns exactly `min(n, size - pos)` bytes (fsspec
    /// semantics: short only at EOF) and advances the position.
    pub async fn read(&mut self, n: Option<usize>) -> Result<Bytes> {
        self.check_open()?;
        let avail = self.ctx.size.saturating_sub(self.pos);
        let n = n.map_or(avail, |n| (n as u64).min(avail));
        let n =
            usize::try_from(n).map_err(|_| Error::invalid_input("read too large for memory"))?;
        if n == 0 {
            return Ok(Bytes::new());
        }
        let pos = self.pos;
        let ctx = &self.ctx;
        let out = match &mut self.state {
            State::None => ctx.fetch(pos, n).await?,
            State::Readahead(ra) => ra.read_bytes(ctx, pos, n).await?,
            State::Blocks(b) => b.read_bytes(ctx, pos, n).await?,
            State::Whole(w) => {
                let s = pos as usize;
                w.get(ctx).await?.slice(s..s + n)
            }
        };
        debug_assert_eq!(out.len(), n);
        self.pos += n as u64;
        Ok(out)
    }

    /// Fill `buf` from the current position (Python `readinto`). Returns
    /// `min(buf.len(), size - pos)` and advances the position.
    pub async fn read_into(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.check_open()?;
        let avail = self.ctx.size.saturating_sub(self.pos);
        let n = (buf.len() as u64).min(avail) as usize;
        if n == 0 {
            return Ok(0);
        }
        let pos = self.pos;
        let dst = &mut buf[..n];
        let ctx = &self.ctx;
        match &mut self.state {
            State::None => ctx.fetch_into(pos, dst).await?,
            State::Readahead(ra) => ra.read_into(ctx, pos, dst).await?,
            State::Blocks(b) => b.read_into(ctx, pos, dst).await?,
            State::Whole(w) => {
                let s = pos as usize;
                dst.copy_from_slice(&w.get(ctx).await?[s..s + n]);
            }
        }
        self.pos += n as u64;
        Ok(n)
    }

    /// Drop every cached or prefetched byte and cancel background fetches
    /// (the reader stays usable).
    pub fn clear_cache(&mut self) {
        match &mut self.state {
            State::None => {}
            State::Readahead(ra) => ra.clear(),
            State::Blocks(b) => b.clear(),
            State::Whole(w) => w.data = None,
        }
    }

    /// Cancel background work, release cached data and close the handle.
    /// Idempotent; later reads and seeks fail with `InvalidInput`.
    pub async fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.state = State::None;
        self.ctx.handle.close().await
    }
}

#[cfg(test)]
mod tests;
