//! Filesystem operations, each written once as a `'static` future that the
//! sync and async Python methods share (see [`crate::out`]).
//!
//! Batch operations (`*_many`, `cat_ranges`, `rm_files`, `cp_files`, ...)
//! run their items concurrently — at most `batch_size` at a time, by default
//! the backend's `IoHints::max_concurrency` — and either raise the first
//! error in input order (`on_error="raise"`) or return every item's value or
//! exception (`on_error="return"`). After a failure with `"raise"`, no new
//! item starts; reads still in flight are cancelled, but mutations still in
//! flight run to completion (see [`Effects`]).

use std::collections::HashMap;
use std::future::Future;
use std::io::SeekFrom;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use fsfast_core::{
    ByteRange, DynFileSystem, Error, ErrorKind, FindOptions, Options, ReadOptions, Result,
    WriteMode, WriteOptions,
};
use fsfast_engine::{CacheMode, FileReader, OpKind, ReaderConfig, Stats};
use futures::stream::{self, FuturesOrdered, StreamExt};

use crate::errors::invalid;
use crate::file::{RustReader, RustWriter};
use crate::out::{Item, PyOut};
use crate::registry::{AnyFs, Backend};

/// The backend instance together with the fork generation it was built in
/// (see [`crate::runtime::fork_generation`]).
struct FsSlot {
    generation: u64,
    fs: DynFileSystem,
    any: AnyFs,
}

/// Shared state of a `RustFileSystem`.
pub(crate) struct FsInner {
    pub backend: &'static Backend,
    pub protocol: String,
    pub options: Options,
    slot: ArcSwap<FsSlot>,
    pub stats: Arc<Stats>,
}

impl FsInner {
    /// Build the backend for `protocol` from `options`.
    pub(crate) fn new(protocol: &str, options: Options) -> Result<Self> {
        crate::runtime::watch_forks();
        let backend = crate::registry::lookup(protocol)?;
        let built = (backend.build)(options.clone())?;
        Ok(FsInner {
            backend,
            protocol: protocol.to_owned(),
            options,
            slot: ArcSwap::from_pointee(FsSlot {
                generation: crate::runtime::fork_generation(),
                fs: built.fs,
                any: built.any,
            }),
            stats: Arc::new(Stats::new()),
        })
    }

    /// The backend instance. In a forked child, backends that hold
    /// connections bound to the parent's runtime are rebuilt from the
    /// original options first (see `Backend::rebuild_after_fork`).
    pub(crate) fn fs(&self) -> Result<DynFileSystem> {
        Ok(self.slot()?.fs.clone())
    }

    /// The backend instance as its concrete type (for backend-specific
    /// methods), rebuilt after a fork like [`FsInner::fs`].
    pub(crate) fn any(&self) -> Result<AnyFs> {
        Ok(self.slot()?.any.clone())
    }

    fn slot(&self) -> Result<Arc<FsSlot>> {
        let slot = self.slot.load_full();
        let generation = crate::runtime::fork_generation();
        if slot.generation == generation || !self.backend.rebuild_after_fork {
            return Ok(slot);
        }
        let built = (self.backend.build)(self.options.clone())?;
        let fresh = Arc::new(FsSlot {
            generation,
            fs: built.fs,
            any: built.any,
        });
        self.slot.store(fresh.clone());
        Ok(fresh)
    }
}

/// How a batch operation reports per-item failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnError {
    /// Raise the first failure (in input order).
    Raise,
    /// Return an exception instance in place of each failed item.
    Return,
}

impl OnError {
    /// Parse fsspec's `on_error` (`"omit"` returns exceptions too; the Python
    /// layer drops them).
    pub(crate) fn parse(s: &str) -> Result<Self> {
        match s {
            "raise" => Ok(OnError::Raise),
            "return" | "omit" => Ok(OnError::Return),
            other => Err(invalid(format!(
                "on_error must be 'raise', 'return' or 'omit', got {other:?}"
            ))),
        }
    }
}

/// Items in flight for a batch: `batch_size` when positive, everything for
/// `-1`/`0` (fsspec's "no limit"), else the backend's preferred concurrency.
pub(crate) fn concurrency(fs: &DynFileSystem, batch_size: Option<i64>, items: usize) -> usize {
    match batch_size {
        Some(b) if b > 0 => b as usize,
        Some(_) => items.max(1),
        None => fs.io_hints().max_concurrency.max(1),
    }
}

/// Whether a batch's items change state, which decides what happens to the
/// items in flight when one fails (`on_error="raise"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Effects {
    /// Reads: items in flight are cancelled (dropped).
    ReadOnly,
    /// Writes, copies, moves: items in flight run to completion, because
    /// dropping one half-way leaves a truncated or partial target behind
    /// (a write handle dropped mid-stream). New items are not started.
    Mutating,
}

/// Run `n` item futures with bounded concurrency, preserving order. With
/// [`OnError::Raise`], the first failure in input order is returned and no
/// later item is started; in-flight items are cancelled or drained per
/// `effects`.
async fn run_batch<F, Fut>(
    n: usize,
    conc: usize,
    on_error: OnError,
    effects: Effects,
    mut f: F,
) -> Result<PyOut>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Result<PyOut>>,
{
    let conc = conc.max(1);
    let mut in_flight = FuturesOrdered::new();
    let mut next = 0usize;
    let mut items: Vec<Item> = Vec::with_capacity(n);
    let mut failed: Option<Error> = None;
    loop {
        while failed.is_none() && next < n && in_flight.len() < conc {
            in_flight.push_back(f(next));
            next += 1;
        }
        let Some(r) = in_flight.next().await else {
            break;
        };
        if failed.is_some() {
            continue; // draining mutations after a failure
        }
        match (r, on_error) {
            (Ok(v), _) => items.push(Ok(v)),
            (Err(e), OnError::Return) => items.push(Err(Arc::new(e))),
            (Err(e), OnError::Raise) => {
                if effects == Effects::ReadOnly {
                    return Err(e); // drops (cancels) the reads in flight
                }
                failed = Some(e);
            }
        }
    }
    match failed {
        Some(e) => Err(e),
        None => Ok(PyOut::Items(items)),
    }
}

/// Apply `on_error` to results computed elsewhere (backend-native batches).
fn finish_results(results: Vec<Result<()>>, on_error: OnError) -> Result<PyOut> {
    let mut items = Vec::with_capacity(results.len());
    for r in results {
        match r {
            Ok(()) => items.push(Ok(PyOut::None)),
            Err(e) if on_error == OnError::Raise => return Err(e),
            Err(e) => items.push(Err(Arc::new(e))),
        }
    }
    Ok(PyOut::Items(items))
}

fn check_same_len(a: usize, b: usize, what: &str) -> Result<()> {
    if a == b {
        Ok(())
    } else {
        Err(invalid(format!(
            "{what}: got {a} sources and {b} destinations"
        )))
    }
}

/// Parse a write mode: fsspec's `pipe_file`/`put_file` names
/// (`overwrite`, `create`) or open modes (`wb`, `xb`, `ab`).
pub(crate) fn write_mode(mode: &str) -> Result<WriteMode> {
    match mode {
        "overwrite" | "wb" | "w" => Ok(WriteMode::Overwrite),
        "create" | "xb" | "x" => Ok(WriteMode::CreateNew),
        "append" | "ab" | "a" => Ok(WriteMode::Append),
        other => Err(invalid(format!("unsupported write mode {other:?}"))),
    }
}

/// Whether [`resolve_range`] needs the file size for these arguments.
pub(crate) fn range_needs_size(start: Option<i64>, end: Option<i64>, seek_read: bool) -> bool {
    match (start, end) {
        (s, Some(e)) if seek_read => e < 0 || s.is_some_and(|s| s < 0),
        _ => ByteRange::fsspec_needs_size(start, end),
    }
}

/// Error of Python's `file.read(n)` for `n < -1`.
const NEGATIVE_READ: &str = "read length must be non-negative or -1";

/// fsspec `cat_file(path, start, end)` arguments → a [`ByteRange`].
///
/// Default (fsspec's `MemoryFileSystem`, Python slicing): negative values
/// count from the end, `end` is exclusive, `start > end` selects nothing.
///
/// `seek_read` reproduces fsspec's generic `AbstractFileSystem.cat_file`
/// (used by `LocalFileSystem`), which seeks to `start` (`max(0, size +
/// start)` when negative) and returns `f.read(end - f.tell())` with a
/// negative `end` taken as `size + end`. With a Python file object a count
/// of `-1` reads to EOF and anything below `-1` raises `ValueError`.
pub(crate) fn resolve_range(
    start: Option<i64>,
    end: Option<i64>,
    size: Option<u64>,
    seek_read: bool,
) -> Result<ByteRange> {
    if seek_read && let Some(e) = end {
        let need = || size.ok_or_else(|| invalid("file size required for a negative range"));
        let s_abs: u64 = match start {
            None => 0,
            Some(s) if s >= 0 => s as u64,
            Some(s) => need()?.saturating_sub(s.unsigned_abs()),
        };
        let e_abs: i128 = if e >= 0 {
            i128::from(e)
        } else {
            i128::from(need()?) + i128::from(e)
        };
        let count = e_abs - i128::from(s_abs);
        return match count {
            c if c >= 0 => Ok(ByteRange::Bounded {
                start: s_abs,
                end: e_abs as u64,
            }),
            -1 => Ok(ByteRange::From(s_abs)),
            _ => Err(invalid(NEGATIVE_READ)),
        };
    }
    ByteRange::from_fsspec(start, end, size)
}

/// A [`ByteRange`] as a half-open range for `cat_ranges`; open ends become
/// `u64::MAX` (backends clamp ranges to the file size).
fn to_range(r: ByteRange, size: Option<u64>) -> Range<u64> {
    match r {
        ByteRange::Full => 0..size.unwrap_or(u64::MAX),
        ByteRange::Bounded { start, end } => start..end.max(start),
        ByteRange::From(s) => s..size.unwrap_or(u64::MAX).max(s),
        ByteRange::Suffix(n) => {
            let z = size.unwrap_or(0);
            z.saturating_sub(n)..z
        }
    }
}

/// `info(path)`.
pub(crate) async fn info(fs: Arc<FsInner>, path: String) -> Result<PyOut> {
    let b = fs.fs()?;
    let i = fs.stats.measure(OpKind::Info, b.info(&path)).await?;
    Ok(PyOut::Info(Box::new(i)))
}

/// `(modified, created)` of a path (`FileInfo`'s typed timestamps). When
/// `info()` describes a directory without timestamps but a file can be
/// opened at the same path (fsspec's memory store can hold both), the file's
/// timestamps are returned.
pub(crate) async fn times(fs: Arc<FsInner>, path: String) -> Result<PyOut> {
    let b = fs.fs()?;
    let i = fs.stats.measure(OpKind::Info, b.info(&path)).await?;
    if i.is_dir()
        && i.modified.is_none()
        && i.created.is_none()
        && let Ok(h) = b.open_read(&path, &ReadOptions::default()).await
    {
        let fi = h.info().clone();
        let _ = h.close().await;
        return Ok(PyOut::Times(fi.modified, fi.created));
    }
    Ok(PyOut::Times(i.modified, i.created))
}

/// `info` of many paths.
pub(crate) async fn info_many(
    fs: Arc<FsInner>,
    paths: Vec<String>,
    on_error: OnError,
    batch_size: Option<i64>,
) -> Result<PyOut> {
    let b = fs.fs()?;
    let conc = concurrency(&b, batch_size, paths.len());
    run_batch(paths.len(), conc, on_error, Effects::ReadOnly, |i| {
        let (b, fs, p) = (&b, &fs, &paths[i]);
        async move {
            let r = fs.stats.measure(OpKind::Info, b.info(p)).await?;
            Ok(PyOut::Info(Box::new(r)))
        }
    })
    .await
}

/// `ls(path, detail)`.
pub(crate) async fn ls(fs: Arc<FsInner>, path: String, detail: bool) -> Result<PyOut> {
    let b = fs.fs()?;
    let v = fs.stats.measure(OpKind::List, b.ls(&path)).await?;
    Ok(if detail {
        PyOut::InfoList(v)
    } else {
        PyOut::Names(v.into_iter().map(|i| i.name).collect())
    })
}

/// `find(path, maxdepth, withdirs, detail)`.
pub(crate) async fn find(
    fs: Arc<FsInner>,
    path: String,
    maxdepth: Option<i64>,
    withdirs: bool,
    detail: bool,
    as_list: bool,
) -> Result<PyOut> {
    let maxdepth = match maxdepth {
        None => None,
        Some(d) if d >= 1 => Some(d as usize),
        Some(_) => return Err(invalid("maxdepth must be at least 1")),
    };
    let b = fs.fs()?;
    let opts = FindOptions { maxdepth, withdirs };
    let v = fs.stats.measure(OpKind::List, b.find(&path, &opts)).await?;
    Ok(if detail && as_list {
        PyOut::InfoList(v)
    } else if detail {
        PyOut::InfoMap(v)
    } else {
        PyOut::Names(v.into_iter().map(|i| i.name).collect())
    })
}

/// `exists(path)`.
pub(crate) async fn exists(fs: Arc<FsInner>, path: String) -> Result<PyOut> {
    let b = fs.fs()?;
    let e = fs.stats.measure(OpKind::Info, b.exists(&path)).await?;
    Ok(PyOut::Bool(e))
}

/// Surface the error a read of `path` would raise (missing path,
/// directory) with an empty read.
async fn probe(fs: &FsInner, b: &DynFileSystem, path: &str) -> Result<()> {
    fs.stats
        .measure(
            OpKind::Read,
            b.cat_file(path, ByteRange::Bounded { start: 0, end: 0 }),
        )
        .await
        .map(|_| ())
}

/// Size of the file a read of `path` sees, for resolving negative ranges.
///
/// `info()` answers for regular files. For anything else, the error a read
/// raises (missing path, directory: `cat_file`'s, which can differ from
/// `open_read`'s, as in fsspec's memory store) is surfaced first; a path
/// that still reads is opened and the handle's size used. That covers a
/// readable file that is also an implied directory (fsspec's memory store
/// allows both; `info()` then describes the directory, of size 0): ranges
/// resolve against the file's data, as fsspec's slicing does.
async fn readable_size(fs: &FsInner, b: &DynFileSystem, path: &str) -> Result<u64> {
    let i = fs.stats.measure(OpKind::Info, b.info(path)).await?;
    if i.is_file() {
        return Ok(i.size);
    }
    probe(fs, b, path).await?;
    let h = fs
        .stats
        .measure(OpKind::Open, b.open_read(path, &ReadOptions::default()))
        .await?;
    let size = h.size();
    let _ = h.close().await;
    Ok(size)
}

/// Read one range of one file, looking the size up only when needed.
async fn cat_one(
    fs: &FsInner,
    b: &DynFileSystem,
    path: &str,
    start: Option<i64>,
    end: Option<i64>,
    seek_read: bool,
) -> Result<Bytes> {
    // `known_file`: the path was found to be a readable file, so an empty
    // range needs no request.
    let (size, known_file) = if range_needs_size(start, end, seek_read) {
        (Some(readable_size(fs, b, path).await?), true)
    } else {
        (None, false)
    };
    let range = match resolve_range(start, end, size, seek_read) {
        Ok(r) => r,
        Err(e) => {
            // fsspec opens the file before reading: a missing path (or a
            // directory) wins over the argument error.
            probe(fs, b, path).await?;
            return Err(e);
        }
    };
    let data = if range.is_empty() {
        // Still fail like a read for a missing path or a directory.
        if !known_file {
            probe(fs, b, path).await?;
        }
        Bytes::new()
    } else {
        fs.stats
            .measure(OpKind::Read, b.cat_file(path, range))
            .await?
    };
    fs.stats.add_bytes_read(data.len() as u64);
    Ok(data)
}

/// `cat_file(path, start, end)`.
pub(crate) async fn cat_file(
    fs: Arc<FsInner>,
    path: String,
    start: Option<i64>,
    end: Option<i64>,
    seek_read: bool,
) -> Result<PyOut> {
    let b = fs.fs()?;
    let data = cat_one(&fs, &b, &path, start, end, seek_read).await?;
    Ok(PyOut::Bytes(data))
}

/// Whole contents of many files.
pub(crate) async fn cat_many(
    fs: Arc<FsInner>,
    paths: Vec<String>,
    on_error: OnError,
    batch_size: Option<i64>,
) -> Result<PyOut> {
    let b = fs.fs()?;
    let conc = concurrency(&b, batch_size, paths.len());
    run_batch(paths.len(), conc, on_error, Effects::ReadOnly, |i| {
        let (b, fs, p) = (&b, &fs, &paths[i]);
        async move {
            let data = fs
                .stats
                .measure(OpKind::Read, b.cat_file(p, ByteRange::Full))
                .await?;
            fs.stats.add_bytes_read(data.len() as u64);
            Ok(PyOut::Bytes(data))
        }
    })
    .await
}

/// Read all requested ranges of one file: one `cat_file` for a single
/// range, otherwise the backend's coalescing `cat_ranges`. The outer error
/// (missing file, ...) applies to every range; a range whose arguments are
/// invalid fails on its own.
async fn read_group(
    fs: &FsInner,
    b: &DynFileSystem,
    path: &str,
    specs: &[(Option<i64>, Option<i64>)],
    seek_read: bool,
) -> Result<Vec<Result<Bytes>>> {
    if let [(s, e)] = specs {
        return match cat_one(fs, b, path, *s, *e, seek_read).await {
            Ok(d) => Ok(vec![Ok(d)]),
            Err(err) if err.kind() == ErrorKind::InvalidInput => Ok(vec![Err(err)]),
            Err(err) => Err(err),
        };
    }
    let needs_size = specs.iter().any(|&(s, e)| {
        range_needs_size(s, e, seek_read) || matches!((s, e), (Some(s), None) if s < 0)
    });
    // A path that cannot be read (directory, missing) fails every range
    // here, as fsspec's per-range open() would.
    let size = if needs_size {
        Some(readable_size(fs, b, path).await?)
    } else {
        None
    };
    let resolved: Vec<Result<Range<u64>>> = specs
        .iter()
        .map(|&(s, e)| resolve_range(s, e, size, seek_read).map(|r| to_range(r, size)))
        .collect();
    let ranges: Vec<Range<u64>> = resolved
        .iter()
        .filter_map(|r| r.as_ref().ok().cloned())
        .collect();
    if ranges.is_empty() {
        probe(fs, b, path).await?;
        return Ok(resolved
            .into_iter()
            .map(|r| r.map(|_| Bytes::new()))
            .collect());
    }
    let mut data = fs
        .stats
        .measure(OpKind::Read, b.cat_ranges(path, &ranges))
        .await?
        .into_iter();
    if data.len() != ranges.len() {
        return Err(Error::protocol(format!(
            "backend returned {} buffers for {} ranges",
            data.len(),
            ranges.len()
        )));
    }
    let mut total = 0u64;
    let out = resolved
        .into_iter()
        .map(|r| {
            r.map(|_| {
                let d = data.next().unwrap_or_default();
                total += d.len() as u64;
                d
            })
        })
        .collect();
    fs.stats.add_bytes_read(total);
    Ok(out)
}

/// Item indices of one file in a `cat_ranges` call and their results.
type GroupResult = (Vec<usize>, Result<Vec<Result<Bytes>>>);

/// fsspec `cat_ranges(paths, starts, ends)`: ranges are grouped by path,
/// each file's ranges are fetched together (coalesced by the backend), and
/// files are read concurrently.
pub(crate) async fn cat_ranges(
    fs: Arc<FsInner>,
    paths: Vec<String>,
    starts: Vec<Option<i64>>,
    ends: Vec<Option<i64>>,
    on_error: OnError,
    batch_size: Option<i64>,
    seek_read: bool,
) -> Result<PyOut> {
    if starts.len() != paths.len() || ends.len() != paths.len() {
        return Err(invalid(format!(
            "cat_ranges: {} paths, {} starts and {} ends",
            paths.len(),
            starts.len(),
            ends.len()
        )));
    }
    let b = fs.fs()?;
    // Group item indices by path, in order of first appearance.
    let mut index: HashMap<&str, usize> = HashMap::new();
    let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
    for (i, p) in paths.iter().enumerate() {
        let g = *index.entry(p.as_str()).or_insert_with(|| {
            groups.push((p.clone(), Vec::new()));
            groups.len() - 1
        });
        groups[g].1.push(i);
    }
    let conc = concurrency(&b, batch_size, groups.len());
    let results: Vec<GroupResult> = stream::iter(groups.into_iter().map(|(path, idx)| {
        let (b, fs) = (&b, &fs);
        let specs: Vec<_> = idx.iter().map(|&i| (starts[i], ends[i])).collect();
        async move {
            let r = read_group(fs, b, &path, &specs, seek_read).await;
            (idx, r)
        }
    }))
    .buffer_unordered(conc)
    .collect()
    .await;

    let mut out: Vec<Option<Item>> = (0..paths.len()).map(|_| None).collect();
    for (idx, r) in results {
        match r {
            Ok(datas) => {
                for (i, d) in idx.into_iter().zip(datas) {
                    out[i] = Some(d.map(PyOut::Bytes).map_err(Arc::new));
                }
            }
            Err(e) => {
                let e = Arc::new(e);
                for i in idx {
                    out[i] = Some(Err(e.clone()));
                }
            }
        }
    }
    let items: Vec<Item> = out
        .into_iter()
        .map(|x| x.expect("every range has a result"))
        .collect();
    if on_error == OnError::Raise
        && let Some(Err(e)) = items.iter().find(|x| x.is_err())
    {
        return Err(clone_error(e));
    }
    Ok(PyOut::Items(items))
}

/// Re-create an error shared between items (`Error` is not `Clone`).
fn clone_error(e: &Arc<Error>) -> Error {
    let mut out = Error::new(e.kind(), e.message().to_owned());
    if let Some(p) = e.path() {
        out = out.with_path(p.to_owned());
    }
    for d in e.details() {
        out = out.with_detail(d.clone());
    }
    if let Some(src) = std::error::Error::source(&**e) {
        out = out.with_source(std::io::Error::other(src.to_string()));
    }
    out
}

/// `pipe_file(path, data, mode)`.
pub(crate) async fn pipe_file(
    fs: Arc<FsInner>,
    path: String,
    data: Bytes,
    mode: WriteMode,
    extra: Options,
) -> Result<PyOut> {
    let b = fs.fs()?;
    let n = data.len() as u64;
    let opts = WriteOptions {
        extra,
        ..WriteOptions::default().with_mode(mode)
    };
    fs.stats
        .measure(OpKind::Write, b.pipe_file(&path, data, &opts))
        .await?;
    fs.stats.add_bytes_written(n);
    Ok(PyOut::None)
}

/// `pipe_file` for many files.
pub(crate) async fn pipe_many(
    fs: Arc<FsInner>,
    paths: Vec<String>,
    datas: Vec<Bytes>,
    mode: WriteMode,
    on_error: OnError,
    batch_size: Option<i64>,
) -> Result<PyOut> {
    check_same_len(paths.len(), datas.len(), "pipe_many")?;
    let b = fs.fs()?;
    let conc = concurrency(&b, batch_size, paths.len());
    let opts = WriteOptions::default().with_mode(mode);
    run_batch(paths.len(), conc, on_error, Effects::Mutating, |i| {
        let (b, fs, p, opts) = (&b, &fs, &paths[i], &opts);
        let data = datas[i].clone();
        async move {
            let n = data.len() as u64;
            fs.stats
                .measure(OpKind::Write, b.pipe_file(p, data, opts))
                .await?;
            fs.stats.add_bytes_written(n);
            Ok(PyOut::None)
        }
    })
    .await
}

/// `rm_file(path)`.
pub(crate) async fn rm_file(fs: Arc<FsInner>, path: String) -> Result<PyOut> {
    let b = fs.fs()?;
    fs.stats.measure(OpKind::Delete, b.rm_file(&path)).await?;
    Ok(PyOut::None)
}

/// Delete many files with the backend's native batch delete.
pub(crate) async fn rm_files(
    fs: Arc<FsInner>,
    paths: Vec<String>,
    on_error: OnError,
) -> Result<PyOut> {
    let b = fs.fs()?;
    let start = std::time::Instant::now();
    let results = b.rm_files(&paths).await;
    let ok = results.iter().all(|r| r.is_ok());
    fs.stats.record_request(OpKind::Delete, start.elapsed(), ok);
    finish_results(results, on_error)
}

/// `mkdir(path, create_parents)`.
pub(crate) async fn mkdir(fs: Arc<FsInner>, path: String, create_parents: bool) -> Result<PyOut> {
    let b = fs.fs()?;
    fs.stats
        .measure(OpKind::Other, b.mkdir(&path, create_parents))
        .await?;
    Ok(PyOut::None)
}

/// `makedirs(path, exist_ok)`.
pub(crate) async fn makedirs(fs: Arc<FsInner>, path: String, exist_ok: bool) -> Result<PyOut> {
    let b = fs.fs()?;
    fs.stats
        .measure(OpKind::Other, b.makedirs(&path, exist_ok))
        .await?;
    Ok(PyOut::None)
}

/// `makedirs` for many paths (concurrently; creating parents makes the
/// order irrelevant).
pub(crate) async fn makedirs_many(
    fs: Arc<FsInner>,
    paths: Vec<String>,
    exist_ok: bool,
    on_error: OnError,
    batch_size: Option<i64>,
) -> Result<PyOut> {
    let b = fs.fs()?;
    let conc = concurrency(&b, batch_size, paths.len());
    run_batch(paths.len(), conc, on_error, Effects::Mutating, |i| {
        let (b, fs, p) = (&b, &fs, &paths[i]);
        async move {
            fs.stats
                .measure(OpKind::Other, b.makedirs(p, exist_ok))
                .await?;
            Ok(PyOut::None)
        }
    })
    .await
}

/// `rmdir(path)`.
pub(crate) async fn rmdir(fs: Arc<FsInner>, path: String) -> Result<PyOut> {
    let b = fs.fs()?;
    fs.stats.measure(OpKind::Delete, b.rmdir(&path)).await?;
    Ok(PyOut::None)
}

/// `rmdir` of many directories, one after the other in the given order (so
/// callers pass children before parents). With `ignore_missing`, a
/// directory that no longer exists counts as removed.
pub(crate) async fn rmdir_many(
    fs: Arc<FsInner>,
    paths: Vec<String>,
    on_error: OnError,
    ignore_missing: bool,
) -> Result<PyOut> {
    let b = fs.fs()?;
    run_batch(paths.len(), 1, on_error, Effects::Mutating, |i| {
        let (b, fs, p) = (&b, &fs, &paths[i]);
        async move {
            match fs.stats.measure(OpKind::Delete, b.rmdir(p)).await {
                Ok(()) => Ok(PyOut::None),
                Err(e) if ignore_missing && e.kind() == fsfast_core::ErrorKind::NotFound => {
                    Ok(PyOut::None)
                }
                Err(e) => Err(e),
            }
        }
    })
    .await
}

/// `cp_file(src, dst)`.
pub(crate) async fn cp_file(fs: Arc<FsInner>, src: String, dst: String) -> Result<PyOut> {
    let b = fs.fs()?;
    fs.stats
        .measure(OpKind::Copy, b.cp_file(&src, &dst))
        .await?;
    Ok(PyOut::None)
}

/// `cp_file` for many pairs.
pub(crate) async fn cp_files(
    fs: Arc<FsInner>,
    srcs: Vec<String>,
    dsts: Vec<String>,
    on_error: OnError,
    batch_size: Option<i64>,
) -> Result<PyOut> {
    check_same_len(srcs.len(), dsts.len(), "cp_files")?;
    let b = fs.fs()?;
    let conc = concurrency(&b, batch_size, srcs.len());
    run_batch(srcs.len(), conc, on_error, Effects::Mutating, |i| {
        let (b, fs, s, d) = (&b, &fs, &srcs[i], &dsts[i]);
        async move {
            fs.stats.measure(OpKind::Copy, b.cp_file(s, d)).await?;
            Ok(PyOut::None)
        }
    })
    .await
}

/// `mv_file(src, dst)`: move to the exact destination.
pub(crate) async fn mv_file(fs: Arc<FsInner>, src: String, dst: String) -> Result<PyOut> {
    let b = fs.fs()?;
    fs.stats
        .measure(OpKind::Copy, b.mv_file(&src, &dst))
        .await?;
    Ok(PyOut::None)
}

/// `mv_file` for many pairs.
pub(crate) async fn mv_files(
    fs: Arc<FsInner>,
    srcs: Vec<String>,
    dsts: Vec<String>,
    on_error: OnError,
    batch_size: Option<i64>,
) -> Result<PyOut> {
    check_same_len(srcs.len(), dsts.len(), "mv_files")?;
    let b = fs.fs()?;
    let conc = concurrency(&b, batch_size, srcs.len());
    run_batch(srcs.len(), conc, on_error, Effects::Mutating, |i| {
        let (b, fs, s, d) = (&b, &fs, &srcs[i], &dsts[i]);
        async move {
            fs.stats.measure(OpKind::Copy, b.mv_file(s, d)).await?;
            Ok(PyOut::None)
        }
    })
    .await
}

/// `put_file(lpath, rpath, mode)`.
pub(crate) async fn put_file(
    fs: Arc<FsInner>,
    lpath: PathBuf,
    rpath: String,
    mode: WriteMode,
) -> Result<PyOut> {
    let b = fs.fs()?;
    let opts = WriteOptions::default().with_mode(mode);
    fs.stats
        .measure(OpKind::Write, b.put_file(&lpath, &rpath, &opts))
        .await?;
    Ok(PyOut::None)
}

/// `put_file` for many pairs.
pub(crate) async fn put_files(
    fs: Arc<FsInner>,
    lpaths: Vec<PathBuf>,
    rpaths: Vec<String>,
    mode: WriteMode,
    on_error: OnError,
    batch_size: Option<i64>,
) -> Result<PyOut> {
    check_same_len(lpaths.len(), rpaths.len(), "put_files")?;
    let b = fs.fs()?;
    let conc = concurrency(&b, batch_size, lpaths.len());
    let opts = WriteOptions::default().with_mode(mode);
    run_batch(lpaths.len(), conc, on_error, Effects::Mutating, |i| {
        let (b, fs, l, r, opts) = (&b, &fs, &lpaths[i], &rpaths[i], &opts);
        async move {
            fs.stats
                .measure(OpKind::Write, b.put_file(l, r, opts))
                .await?;
            Ok(PyOut::None)
        }
    })
    .await
}

/// `get_file(rpath, lpath)`.
pub(crate) async fn get_file(fs: Arc<FsInner>, rpath: String, lpath: PathBuf) -> Result<PyOut> {
    let b = fs.fs()?;
    fs.stats
        .measure(OpKind::Read, b.get_file(&rpath, &lpath))
        .await?;
    Ok(PyOut::None)
}

/// `get_file` for many pairs.
pub(crate) async fn get_files(
    fs: Arc<FsInner>,
    rpaths: Vec<String>,
    lpaths: Vec<PathBuf>,
    on_error: OnError,
    batch_size: Option<i64>,
) -> Result<PyOut> {
    check_same_len(rpaths.len(), lpaths.len(), "get_files")?;
    let b = fs.fs()?;
    let conc = concurrency(&b, batch_size, rpaths.len());
    run_batch(rpaths.len(), conc, on_error, Effects::Mutating, |i| {
        let (b, fs, r, l) = (&b, &fs, &rpaths[i], &lpaths[i]);
        async move {
            fs.stats.measure(OpKind::Read, b.get_file(r, l)).await?;
            Ok(PyOut::None)
        }
    })
    .await
}

/// `touch(path, truncate)`.
pub(crate) async fn touch(fs: Arc<FsInner>, path: String, truncate: bool) -> Result<PyOut> {
    let b = fs.fs()?;
    fs.stats
        .measure(OpKind::Write, b.touch(&path, truncate))
        .await?;
    Ok(PyOut::None)
}

/// `sign(path, expiration)`.
pub(crate) async fn sign(fs: Arc<FsInner>, path: String, expiration: f64) -> Result<PyOut> {
    if !(expiration.is_finite() && expiration >= 0.0) {
        return Err(invalid(format!("invalid expiration {expiration}")));
    }
    let b = fs.fs()?;
    let url = fs
        .stats
        .measure(
            OpKind::Other,
            b.sign(&path, Duration::from_secs_f64(expiration)),
        )
        .await?;
    Ok(PyOut::Str(url))
}

/// Options of [`open_read`].
#[derive(Debug, Clone, Default)]
pub(crate) struct OpenReadOptions {
    pub cache_type: String,
    pub block_size: Option<usize>,
    pub max_blocks: Option<usize>,
    pub request_size: Option<usize>,
    pub concurrency: Option<usize>,
    pub version: Option<String>,
    /// Backend-specific read options (`ReadOptions::extra`).
    pub extra: Options,
}

/// Open a file for reading behind a [`FileReader`].
pub(crate) async fn open_read(fs: Arc<FsInner>, path: String, o: OpenReadOptions) -> Result<PyOut> {
    let cache = CacheMode::from_fsspec(&o.cache_type, o.block_size, o.max_blocks)?;
    let b = fs.fs()?;
    let ropts = ReadOptions {
        block_size: o.request_size,
        version: o.version,
        extra: o.extra,
        ..ReadOptions::default()
    };
    let handle = fs
        .stats
        .measure(OpKind::Open, b.open_read(&path, &ropts))
        .await?;
    let cfg = ReaderConfig {
        cache,
        request_size: o.request_size,
        concurrency: o.concurrency,
        ..ReaderConfig::default()
    };
    let info = handle.info().clone();
    let reader = FileReader::new(handle, cfg.clone());
    Ok(PyOut::Reader(Box::new(RustReader::new(
        reader,
        cfg,
        info,
        path,
        fs.backend,
        fs.stats.clone(),
    ))))
}

/// Default write-buffer size: the backend's request size, within
/// [64 KiB, 16 MiB]. Writes are handed to the backend in chunks of this size
/// (larger writes go straight through without copying).
pub(crate) fn default_write_buffer(b: &DynFileSystem, block_size: Option<usize>) -> usize {
    block_size
        .unwrap_or(b.io_hints().request_size)
        .clamp(64 << 10, 16 << 20)
}

/// Open a file for writing.
pub(crate) async fn open_write(
    fs: Arc<FsInner>,
    path: String,
    mode: WriteMode,
    block_size: Option<usize>,
    buffer_size: Option<usize>,
    extra: Options,
) -> Result<PyOut> {
    let b = fs.fs()?;
    let opts = WriteOptions {
        mode,
        block_size,
        extra,
        ..WriteOptions::default()
    };
    let handle = fs
        .stats
        .measure(OpKind::Open, b.open_write(&path, &opts))
        .await?;
    let buffer = buffer_size
        .map(|n| n.max(1))
        .unwrap_or_else(|| default_write_buffer(&b, block_size));
    Ok(PyOut::Writer(Box::new(RustWriter::new(
        handle,
        path,
        buffer,
        fs.stats.clone(),
    ))))
}

/// A backend-specific method (see [`crate::ext`]).
pub(crate) async fn call(fs: Arc<FsInner>, method: String, args: Options) -> Result<PyOut> {
    let ext = fs.backend.ext.ok_or_else(|| {
        Error::unsupported(format!(
            "the {} backend has no method {method:?}",
            fs.backend.name()
        ))
    })?;
    let any = fs.any()?;
    ext(any, method, args).await
}

/// Release pooled connections.
pub(crate) async fn close(fs: Arc<FsInner>) -> Result<PyOut> {
    let b = fs.fs()?;
    b.close().await?;
    Ok(PyOut::None)
}

/// Translate Python `seek(offset, whence)` for a reader at `pos` in a file
/// of `size` bytes (fsspec's messages and errors).
pub(crate) fn seek_target(offset: i64, whence: i32, pos: u64, size: u64) -> Result<SeekFrom> {
    let base: i128 = match whence {
        0 => 0,
        1 => i128::from(pos),
        2 => i128::from(size),
        w => {
            return Err(invalid(format!(
                "invalid whence ({w}, should be 0, 1 or 2)"
            )));
        }
    };
    let new = base + i128::from(offset);
    if new < 0 {
        return Err(invalid("Seek before start of file"));
    }
    let new = u64::try_from(new).map_err(|_| invalid("seek position out of range"))?;
    Ok(SeekFrom::Start(new))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: Option<i64>, e: Option<i64>, size: Option<u64>, inv: bool) -> ByteRange {
        resolve_range(s, e, size, inv).unwrap()
    }

    #[test]
    fn fsspec_slices() {
        assert_eq!(r(None, None, None, false), ByteRange::Full);
        assert_eq!(r(Some(3), None, None, false), ByteRange::From(3));
        assert_eq!(r(Some(-3), None, None, false), ByteRange::Suffix(3));
        assert_eq!(
            r(Some(2), Some(5), None, false),
            ByteRange::Bounded { start: 2, end: 5 }
        );
        assert!(r(Some(5), Some(2), None, false).is_empty());
        assert_eq!(
            r(None, Some(-2), Some(10), false),
            ByteRange::Bounded { start: 0, end: 8 }
        );
        assert!(resolve_range(None, Some(-2), None, false).is_err());
    }

    #[test]
    fn seek_read_ranges_follow_fsspec_local() {
        // count -1 reads to EOF, below -1 is Python's ValueError.
        assert_eq!(r(Some(3), Some(2), None, true), ByteRange::From(3));
        assert!(resolve_range(Some(5), Some(2), None, true).is_err());
        assert_eq!(
            r(Some(2), Some(5), None, true),
            ByteRange::Bounded { start: 2, end: 5 }
        );
        assert_eq!(
            r(Some(5), Some(5), None, true),
            ByteRange::Bounded { start: 5, end: 5 }
        );
        // size 10: start -3 -> 7, end -4 -> 6 => count -1 -> from 7.
        assert_eq!(r(Some(-3), Some(-4), Some(10), true), ByteRange::From(7));
        assert!(resolve_range(Some(-3), Some(-5), Some(10), true).is_err());
        // start -30 clamps to 0 (seek(max(0, size + start))).
        assert_eq!(
            r(Some(-30), Some(4), Some(10), true),
            ByteRange::Bounded { start: 0, end: 4 }
        );
        // A start of None is position 0; an empty file with end -1 reads
        // read(-1) (everything, i.e. nothing), end -3 raises.
        assert_eq!(r(None, Some(-1), Some(0), true), ByteRange::From(0));
        assert!(resolve_range(None, Some(-3), Some(0), true).is_err());
        assert_eq!(
            r(None, Some(-3), Some(10), true),
            ByteRange::Bounded { start: 0, end: 7 }
        );
        assert!(resolve_range(Some(0), Some(-30), Some(10), true).is_err());
        assert!(range_needs_size(Some(-1), Some(3), true));
        assert!(range_needs_size(None, Some(-3), true));
        assert!(!range_needs_size(Some(1), Some(3), true));
        assert!(!range_needs_size(Some(-1), None, true));
    }

    #[test]
    fn ranges_for_cat_ranges() {
        assert_eq!(to_range(ByteRange::Full, None), 0..u64::MAX);
        assert_eq!(to_range(ByteRange::Full, Some(9)), 0..9);
        assert_eq!(to_range(ByteRange::From(4), None), 4..u64::MAX);
        assert_eq!(to_range(ByteRange::Suffix(3), Some(10)), 7..10);
        assert_eq!(
            to_range(ByteRange::Bounded { start: 5, end: 2 }, None),
            5..5
        );
    }

    #[test]
    fn modes_and_on_error() {
        assert_eq!(write_mode("overwrite").unwrap(), WriteMode::Overwrite);
        assert_eq!(write_mode("xb").unwrap(), WriteMode::CreateNew);
        assert_eq!(write_mode("create").unwrap(), WriteMode::CreateNew);
        assert_eq!(write_mode("ab").unwrap(), WriteMode::Append);
        assert!(write_mode("rb").is_err());
        assert_eq!(OnError::parse("raise").unwrap(), OnError::Raise);
        assert_eq!(OnError::parse("omit").unwrap(), OnError::Return);
        assert!(OnError::parse("ignore").is_err());
    }

    #[test]
    fn a_failing_batch_item_never_abandons_writes_in_flight() {
        // Item 0 fails at once; items 1 and 2 are in flight (concurrency 3)
        // and must run to completion - dropping a write half-way leaves a
        // truncated file - while no further item starts. Read-only batches
        // may cancel.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for effects in [Effects::Mutating, Effects::ReadOnly] {
            let started = AtomicUsize::new(0);
            let completed = AtomicUsize::new(0);
            let e = rt
                .block_on(run_batch(10, 3, OnError::Raise, effects, |i| {
                    let (started, completed) = (&started, &completed);
                    async move {
                        started.fetch_add(1, Ordering::SeqCst);
                        if i == 0 {
                            tokio::task::yield_now().await;
                            return Err(Error::not_found("item0"));
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        completed.fetch_add(1, Ordering::SeqCst);
                        Ok(PyOut::None)
                    }
                }))
                .err()
                .unwrap();
            assert_eq!(e.path(), Some("item0"));
            assert_eq!(started.load(Ordering::SeqCst), 3, "{effects:?}");
            let done = completed.load(Ordering::SeqCst);
            match effects {
                Effects::Mutating => assert_eq!(done, 2, "in-flight writes were dropped"),
                Effects::ReadOnly => assert_eq!(done, 0),
            }
        }
        // "return" runs everything and reports each item.
        let out = rt
            .block_on(run_batch(
                5,
                2,
                OnError::Return,
                Effects::Mutating,
                |i| async move {
                    if i % 2 == 1 {
                        Err(Error::not_found(format!("i{i}")))
                    } else {
                        Ok(PyOut::Bool(true))
                    }
                },
            ))
            .unwrap();
        match out {
            PyOut::Items(v) => {
                let errs: Vec<bool> = v.iter().map(|x| x.is_err()).collect();
                assert_eq!(errs, [false, true, false, true, false]);
            }
            _ => panic!("not items"),
        }
    }

    #[test]
    fn seek_targets() {
        assert_eq!(seek_target(5, 0, 0, 10).unwrap(), SeekFrom::Start(5));
        assert_eq!(seek_target(-2, 1, 5, 10).unwrap(), SeekFrom::Start(3));
        assert_eq!(seek_target(-4, 2, 0, 10).unwrap(), SeekFrom::Start(6));
        assert_eq!(seek_target(5, 2, 0, 10).unwrap(), SeekFrom::Start(15));
        assert!(seek_target(-1, 0, 0, 10).is_err());
        assert!(seek_target(-11, 2, 0, 10).is_err());
        assert!(seek_target(0, 3, 0, 10).is_err());
    }

    #[cfg(feature = "memory")]
    mod with_memory {
        use super::*;
        use fsfast_core::Value;

        fn fs() -> Arc<FsInner> {
            let mut o = Options::new();
            o.insert("global_store".into(), Value::Bool(false));
            Arc::new(FsInner::new("memory", o).unwrap())
        }

        fn rt() -> tokio::runtime::Runtime {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        }

        fn bytes_items(out: PyOut) -> Vec<std::result::Result<Bytes, fsfast_core::ErrorKind>> {
            match out {
                PyOut::Items(v) => v
                    .into_iter()
                    .map(|i| match i {
                        Ok(PyOut::Bytes(b)) => Ok(b),
                        Ok(_) => panic!("not bytes"),
                        Err(e) => Err(e.kind()),
                    })
                    .collect(),
                _ => panic!("not items"),
            }
        }

        #[test]
        fn cat_ranges_groups_and_scatters() {
            rt().block_on(async {
                let f = fs();
                pipe_file(
                    f.clone(),
                    "/a".into(),
                    Bytes::from_static(b"0123456789"),
                    WriteMode::Overwrite,
                    Options::new(),
                )
                .await
                .unwrap();
                pipe_file(
                    f.clone(),
                    "/b".into(),
                    Bytes::from_static(b"abcdef"),
                    WriteMode::Overwrite,
                    Options::new(),
                )
                .await
                .unwrap();
                let paths: Vec<String> = ["/a", "/b", "/a", "/missing", "/a", "/b"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                let starts = vec![Some(0), Some(-2), Some(8), Some(0), Some(5), None];
                let ends = vec![Some(3), None, None, Some(1), Some(2), Some(-4)];
                let out = cat_ranges(
                    f.clone(),
                    paths.clone(),
                    starts.clone(),
                    ends.clone(),
                    OnError::Return,
                    None,
                    false,
                )
                .await
                .unwrap();
                let got = bytes_items(out);
                assert_eq!(got[0].as_deref().unwrap(), b"012");
                assert_eq!(got[1].as_deref().unwrap(), b"ef");
                assert_eq!(got[2].as_deref().unwrap(), b"89");
                assert_eq!(got[3], Err(fsfast_core::ErrorKind::NotFound));
                assert_eq!(got[4].as_deref().unwrap(), b"");
                assert_eq!(got[5].as_deref().unwrap(), b"ab");
                let e = cat_ranges(f.clone(), paths, starts, ends, OnError::Raise, None, false)
                    .await
                    .err()
                    .unwrap();
                assert_eq!(e.kind(), fsfast_core::ErrorKind::NotFound);
                // seek+read semantics: count -1 reads to EOF, below -1 fails
                // for that range only.
                let out = cat_ranges(
                    f.clone(),
                    vec!["/a".into(), "/a".into(), "/a".into()],
                    vec![Some(7), Some(1), Some(9)],
                    vec![Some(6), Some(2), Some(2)],
                    OnError::Return,
                    Some(-1),
                    true,
                )
                .await
                .unwrap();
                let got = bytes_items(out);
                assert_eq!(got[0].as_deref().unwrap(), b"789");
                assert_eq!(got[1].as_deref().unwrap(), b"1");
                assert_eq!(got[2], Err(fsfast_core::ErrorKind::InvalidInput));
                // A missing file beats the argument error, as in fsspec.
                let e = cat_file(f.clone(), "/nope".into(), Some(9), Some(2), true)
                    .await
                    .err()
                    .unwrap();
                assert_eq!(e.kind(), fsfast_core::ErrorKind::NotFound);
                let e = cat_file(f.clone(), "/a".into(), Some(9), Some(2), true)
                    .await
                    .err()
                    .unwrap();
                assert_eq!(e.kind(), fsfast_core::ErrorKind::InvalidInput);
            });
        }

        #[test]
        fn batches_raise_first_error_in_order_or_return_all() {
            rt().block_on(async {
                let f = fs();
                let paths: Vec<String> = (0..20).map(|i| format!("/d/f{i}")).collect();
                let datas: Vec<Bytes> = (0..20).map(|i| Bytes::from(vec![i as u8; i])).collect();
                pipe_many(
                    f.clone(),
                    paths.clone(),
                    datas,
                    WriteMode::Overwrite,
                    OnError::Raise,
                    Some(3),
                )
                .await
                .unwrap();
                let mut with_missing = paths.clone();
                with_missing.insert(5, "/d/nope".into());
                let got = bytes_items(
                    cat_many(f.clone(), with_missing.clone(), OnError::Return, None)
                        .await
                        .unwrap(),
                );
                assert_eq!(got.len(), 21);
                assert_eq!(got[5], Err(fsfast_core::ErrorKind::NotFound));
                assert_eq!(got[6].as_ref().unwrap().len(), 5);
                let e = cat_many(f.clone(), with_missing, OnError::Raise, Some(2))
                    .await
                    .err()
                    .unwrap();
                assert_eq!(e.path(), Some("/d/nope"));
                // rm_files uses the backend batch and reports per item.
                let out = rm_files(
                    f.clone(),
                    vec!["/d/f1".into(), "/d/zz".into()],
                    OnError::Return,
                )
                .await
                .unwrap();
                match out {
                    PyOut::Items(v) => {
                        assert!(v[0].is_ok());
                        assert!(v[1].is_err());
                    }
                    _ => panic!(),
                }
                assert!(
                    rm_files(f.clone(), vec!["/d/zz".into()], OnError::Raise)
                        .await
                        .is_err()
                );
                let snap = f.stats.snapshot();
                assert!(snap.requests > 0);
                assert!(snap.bytes_written > 0);
            });
        }

        #[test]
        fn cat_file_of_missing_path_with_empty_range_is_not_found() {
            rt().block_on(async {
                let f = fs();
                let e = cat_file(f.clone(), "/nope".into(), Some(5), Some(2), false)
                    .await
                    .err()
                    .unwrap();
                assert_eq!(e.kind(), fsfast_core::ErrorKind::NotFound);
            });
        }

        #[test]
        fn empty_ranges_on_directories_fail_like_reads() {
            rt().block_on(async {
                let f = fs();
                pipe_file(
                    f.clone(),
                    "/d/x".into(),
                    Bytes::from_static(b"1"),
                    WriteMode::Overwrite,
                    Options::new(),
                )
                .await
                .unwrap();
                // info("/d") succeeds (a directory of size 0) and the range
                // resolves to nothing: the read must still fail.
                for (s, e) in [(Some(-1), Some(-1)), (Some(-1), None), (Some(0), Some(0))] {
                    let err = cat_file(f.clone(), "/d".into(), s, e, false)
                        .await
                        .err()
                        .unwrap();
                    assert_eq!(err.kind(), fsfast_core::ErrorKind::NotFound, "{s:?} {e:?}");
                }
                let out = cat_ranges(
                    f.clone(),
                    vec!["/d".into(), "/d".into()],
                    vec![Some(-1), Some(0)],
                    vec![Some(-1), Some(0)],
                    OnError::Return,
                    None,
                    false,
                )
                .await
                .unwrap();
                assert!(bytes_items(out).iter().all(|r| r.is_err()));
                // A real file with an empty range is fine.
                let out = cat_file(f.clone(), "/d/x".into(), Some(-1), Some(-1), false)
                    .await
                    .unwrap();
                assert!(matches!(out, PyOut::Bytes(b) if b.is_empty()));
            });
        }

        #[test]
        fn negative_ranges_of_a_file_that_is_also_an_implied_directory() {
            // fsspec's memory store can hold a file at a path that is also
            // an implied directory; info() reports the directory (size 0),
            // but reads see the file, so negative ends count from the end
            // of the file's data.
            rt().block_on(async {
                let f = fs();
                mkdir(f.clone(), "/x/a".into(), false).await.unwrap();
                pipe_file(
                    f.clone(),
                    "/x".into(),
                    Bytes::from_static(b"0123456789"),
                    WriteMode::Overwrite,
                    Options::new(),
                )
                .await
                .unwrap();
                let got = |out: PyOut| match out {
                    PyOut::Bytes(b) => b,
                    _ => panic!("not bytes"),
                };
                for (s, e, want) in [
                    (None, Some(-2), &b"01234567"[..]),
                    (Some(2), Some(-2), b"234567"),
                    (Some(-3), Some(-1), b"78"),
                    (Some(-3), None, b"789"),
                ] {
                    let out = cat_file(f.clone(), "/x".into(), s, e, false).await.unwrap();
                    assert_eq!(got(out), want, "{s:?} {e:?}");
                }
                let out = cat_ranges(
                    f.clone(),
                    vec!["/x".into(), "/x".into()],
                    vec![None, Some(1)],
                    vec![Some(-2), Some(3)],
                    OnError::Raise,
                    None,
                    false,
                )
                .await
                .unwrap();
                let v = bytes_items(out);
                assert_eq!(v[0].as_deref().unwrap(), b"01234567");
                assert_eq!(v[1].as_deref().unwrap(), b"12");
            });
        }

        #[test]
        fn find_rejects_zero_maxdepth() {
            rt().block_on(async {
                let e = find(fs(), "/".into(), Some(0), false, false, false)
                    .await
                    .err()
                    .unwrap();
                assert_eq!(e.kind(), fsfast_core::ErrorKind::InvalidInput);
            });
        }
    }
}
