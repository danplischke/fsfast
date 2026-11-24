//! File objects: [`RustReader`] (a [`FileReader`] with fsspec caching modes)
//! and [`RustWriter`] (a buffered [`WriteHandle`]).
//!
//! Both are `frozen` pyclasses whose state lives behind a mutex, so they are
//! safe to share between threads (including free-threaded Python). The
//! mutex is only ever locked with the interpreter released: a thread holding
//! it may need to re-attach (signal checks, conversions), and a thread that
//! blocked on it while attached would deadlock with it.
//!
//! **Fork safety.** An open file's background work (prefetches, writes in
//! flight) runs on the parent's runtime, which has no threads in a forked
//! child: awaiting it would hang, and cancelling it could block on a lock
//! some parent thread held at the fork. In the child, a reader therefore
//! abandons (leaks) that state and continues on a fresh reader over the same
//! handle at the same position; a writer belongs to the parent, so writing
//! to it raises and closing it abandons it without committing.

use std::io::SeekFrom;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use bytes::{Bytes, BytesMut};
use fsfast_core::{Error, ErrorKind, FileInfo, Result, WriteHandle};
use fsfast_engine::{CacheMode, FileReader, OpKind, ReaderConfig, Stats};
use parking_lot::Mutex;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use crate::buffer::{ReadSource, WriteTarget};
use crate::convert::{bytes_from_py, bytes_to_py, info_to_py, zeroed_bytes};
use crate::errors::to_pyerr;
use crate::ops::seek_target;
use crate::registry::Backend;
use crate::runtime::{drive, fork_generation, runtime};

/// Initial read size when scanning for a delimiter (`readline`).
const SCAN_CHUNK_MIN: usize = 8 << 10;
/// Largest read size when scanning for a delimiter.
const SCAN_CHUNK_MAX: usize = 1 << 20;
/// Writes up to this size may be buffered without releasing the interpreter
/// (a short copy; larger writes always run detached).
const INLINE_WRITE_MAX: usize = 64 << 10;
/// `read(n)` of at least this many bytes reads straight into the result
/// `bytes` object instead of assembling a buffer and copying it.
const DIRECT_READ_MIN: usize = 2 << 20;

fn closed_error() -> Error {
    Error::invalid_input("I/O operation on closed file.")
}

/// A writer used in a forked child of the process that opened it.
fn forked_writer_error(path: &str) -> Error {
    Error::new(
        ErrorKind::Io,
        "file opened for writing before fork() cannot be written in the child process",
    )
    .with_path(path)
}

/// Raise a Rust error as its Python exception.
fn raise<T>(py: Python<'_>, r: Result<T>) -> PyResult<T> {
    r.map_err(|e| to_pyerr(py, &e))
}

/// The reader plus bytes already fetched past the logical position (left
/// over by delimiter scans), so `readline` never fetches anything twice.
struct ReaderState {
    reader: FileReader,
    /// Data at `[tell(), tell() + pending.len())`.
    pending: Bytes,
    /// Chunks a delimiter scan fetched after `pending` (they follow it in the
    /// file). Kept as a list so that a long line costs one copy at the end
    /// instead of one copy of everything so far per chunk; stored here, not
    /// in the scan's locals, so that a cancelled scan loses nothing. Empty
    /// outside [`ReaderState::read_until`] unless a scan was cancelled;
    /// [`ReaderState::settle`] folds it into `pending`.
    scan: Vec<Bytes>,
    /// Total length of `scan`.
    scan_len: usize,
    /// The reader's configuration, to rebuild it in a forked child.
    cfg: ReaderConfig,
    /// [`fork_generation`] the reader's background work belongs to.
    generation: u64,
}

impl ReaderState {
    fn new(reader: FileReader, cfg: ReaderConfig) -> Self {
        ReaderState {
            reader,
            pending: Bytes::new(),
            scan: Vec::new(),
            scan_len: 0,
            cfg,
            generation: fork_generation(),
        }
    }

    /// In a forked child, abandon the parent's reader and continue on a
    /// fresh one over the same handle at the same position (see the module
    /// docs). Its prefetch tasks and their data are leaked on purpose:
    /// dropping them would cancel tasks of the parent's runtime. Pending
    /// scan data is plain memory and kept.
    ///
    /// The handle is reused, which is right for backends whose handles hold
    /// no connection to the parent's runtime (`Backend::rebuild_after_fork`
    /// false: local files are positional reads on an inherited descriptor,
    /// memory files are buffers); for the others the file cannot be used in
    /// the child and must be reopened.
    fn refresh_after_fork(&mut self, backend: &Backend) -> Result<()> {
        let current = fork_generation();
        if self.generation == current {
            return Ok(());
        }
        if backend.rebuild_after_fork {
            return Err(Error::new(
                ErrorKind::Io,
                "file opened before fork() cannot be used in the child process; reopen it",
            )
            .with_path(self.reader.handle().info().name.clone()));
        }
        let at = self.reader.tell();
        let fresh = FileReader::new(self.reader.handle().clone(), self.cfg.clone());
        std::mem::forget(std::mem::replace(&mut self.reader, fresh));
        self.reader.seek(SeekFrom::Start(at))?;
        self.generation = current;
        Ok(())
    }

    fn tell(&self) -> u64 {
        self.reader.tell() - (self.pending.len() + self.scan_len) as u64
    }

    /// Fold the chunks of a cancelled delimiter scan into `pending` (a no-op
    /// unless a scan was cancelled), so that every other operation only has
    /// to look at `pending`.
    fn settle(&mut self) {
        if self.scan.is_empty() {
            return;
        }
        let mut all = BytesMut::with_capacity(self.pending.len() + self.scan_len);
        all.extend_from_slice(&self.pending);
        for c in self.scan.drain(..) {
            all.extend_from_slice(&c);
        }
        self.scan_len = 0;
        self.pending = all.freeze();
    }

    /// Remove and return the first `n` bytes of `pending` followed by
    /// `scan` (at most all of them); the rest stays in `pending`. Copies
    /// only when the bytes span several chunks.
    fn take_buffered(&mut self, n: usize) -> Bytes {
        if self.scan.is_empty() {
            let n = n.min(self.pending.len());
            return self.pending.split_to(n);
        }
        if self.pending.is_empty() && self.scan.len() == 1 {
            let mut only = self.scan.pop().expect("one chunk");
            self.scan_len = 0;
            let out = only.split_to(n.min(only.len()));
            self.pending = only;
            return out;
        }
        let total = self.pending.len() + self.scan_len;
        let n = n.min(total);
        let mut out = BytesMut::with_capacity(n);
        let mut rest: Vec<Bytes> = Vec::new();
        let chunks = std::iter::once(std::mem::take(&mut self.pending)).chain(self.scan.drain(..));
        for mut c in chunks {
            let k = (n - out.len()).min(c.len());
            if k > 0 {
                out.extend_from_slice(&c.split_to(k));
            }
            if !c.is_empty() {
                rest.push(c);
            }
        }
        self.scan_len = 0;
        // The cut lies in the last chunk for every caller, so `rest` is one
        // slice of it (no copy); fold anything else.
        self.pending = match rest.len() {
            0 => Bytes::new(),
            1 => rest.pop().expect("one chunk"),
            _ => {
                let mut all = BytesMut::with_capacity(total - n);
                for c in &rest {
                    all.extend_from_slice(c);
                }
                all.freeze()
            }
        };
        out.freeze()
    }

    /// The last `k` buffered bytes (`pending` then `scan`), for finding a
    /// delimiter that straddles a chunk boundary.
    fn buffered_tail(&self, k: usize) -> Vec<u8> {
        let mut parts: Vec<&[u8]> = Vec::new();
        let mut need = k;
        for c in self.scan.iter().rev().chain(std::iter::once(&self.pending)) {
            if need == 0 {
                break;
            }
            let t = need.min(c.len());
            parts.push(&c[c.len() - t..]);
            need -= t;
        }
        parts.iter().rev().flat_map(|p| p.iter().copied()).collect()
    }

    fn seek(&mut self, to: SeekFrom) -> Result<u64> {
        self.settle();
        let target = match to {
            SeekFrom::Start(n) => n,
            _ => unreachable!("seek targets are resolved to absolute positions"),
        };
        let pos = self.tell();
        let ahead = self.pending.len() as u64;
        if target >= pos && target - pos <= ahead {
            // Within the pending bytes: just drop the skipped prefix.
            let _ = self.pending.split_to((target - pos) as usize);
            return Ok(target);
        }
        self.pending = Bytes::new();
        self.reader.seek(SeekFrom::Start(target))
    }

    /// `read(n)` (`None`: to EOF). Cancel-safe: pending bytes are only
    /// consumed once the read from the reader has completed.
    async fn read(&mut self, n: Option<usize>) -> Result<Bytes> {
        self.settle();
        if self.pending.is_empty() {
            return self.reader.read(n).await;
        }
        if let Some(n) = n
            && n <= self.pending.len()
        {
            return Ok(self.pending.split_to(n));
        }
        let rest = self.reader.read(n.map(|n| n - self.pending.len())).await?;
        let head = std::mem::take(&mut self.pending);
        if rest.is_empty() {
            return Ok(head);
        }
        let mut out = BytesMut::with_capacity(head.len() + rest.len());
        out.extend_from_slice(&head);
        out.extend_from_slice(&rest);
        Ok(out.freeze())
    }

    /// `readinto(buf)`: pending bytes first, then straight from the reader
    /// into `buf`.
    async fn read_into(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.settle();
        let k = self.pending.len().min(buf.len());
        if k == buf.len() {
            buf.copy_from_slice(&self.pending[..k]);
            let _ = self.pending.split_to(k);
            return Ok(k);
        }
        let n = self.reader.read_into(&mut buf[k..]).await?;
        buf[..k].copy_from_slice(&self.pending[..k]);
        self.pending = Bytes::new();
        Ok(k + n)
    }

    /// The next line if it is already in `pending` (no I/O): up to and
    /// including the first `delim`, or `limit` bytes.
    fn take_line(&mut self, delim: &[u8], limit: Option<usize>) -> Option<Bytes> {
        self.settle();
        let limit = limit.unwrap_or(usize::MAX);
        let window = &self.pending[..self.pending.len().min(limit.saturating_add(delim.len()))];
        let found = find(window, delim);
        match found {
            Some(i) => Some(self.pending.split_to((i + delim.len()).min(limit))),
            None if self.pending.len() >= limit => Some(self.pending.split_to(limit)),
            None => None,
        }
    }

    /// Read up to and including the first `delim` (or EOF, or `limit`
    /// bytes).
    ///
    /// Each fetched chunk is searched once (plus the few bytes before it a
    /// straddling delimiter can start in) and appended to `scan`; the line
    /// is assembled once at the end, so a line of `L` bytes costs `O(L)`
    /// work however many chunks it spans. Cancel-safe: chunks are stored in
    /// `self` as soon as they arrive.
    async fn read_until(&mut self, delim: &[u8], limit: Option<usize>) -> Result<Bytes> {
        self.settle();
        let dlen = delim.len();
        let limit = limit.unwrap_or(usize::MAX);
        if let Some(line) = self.take_line(delim, Some(limit)) {
            return Ok(line);
        }
        let mut chunk = SCAN_CHUNK_MIN;
        loop {
            let before = self.pending.len() + self.scan_len;
            let want = chunk.min(limit - before);
            let more = self.reader.read(Some(want)).await?;
            if more.is_empty() {
                // EOF: the rest of the file is the line.
                return Ok(self.take_buffered(before));
            }
            // A delimiter starting in the buffered bytes and ending in `more`
            // comes first; then one entirely inside `more`.
            let straddling = if dlen > 1 {
                let mut window = self.buffered_tail(dlen - 1);
                let carried = window.len();
                window.extend_from_slice(&more[..more.len().min(dlen - 1)]);
                find(&window, delim)
                    .filter(|&i| i < carried)
                    .map(|i| i + dlen - carried)
            } else {
                None
            };
            let found = straddling.or_else(|| find(&more, delim).map(|i| i + dlen));
            let fetched = more.len();
            self.scan_len += fetched;
            self.scan.push(more);
            if let Some(end) = found {
                return Ok(self.take_buffered((before + end).min(limit)));
            }
            if before + fetched >= limit {
                return Ok(self.take_buffered(limit));
            }
            chunk = (chunk * 2).min(SCAN_CHUNK_MAX);
        }
    }
}

/// Index of the first occurrence of `delim` in `hay`.
fn find(hay: &[u8], delim: &[u8]) -> Option<usize> {
    if delim.len() == 1 {
        memchr::memchr(delim[0], hay)
    } else {
        memchr::memmem::find(hay, delim)
    }
}

/// A file opened for reading (`fs.open_read(...)`).
///
/// Reads go through the engine's [`FileReader`] with the cache mode chosen
/// at open (fsspec `cache_type`): adaptive readahead by default, block LRU,
/// whole-file, or none. Large reads are fetched as parallel ranged requests.
#[pyclass(frozen, module = "fsfast._core")]
pub struct RustReader {
    state: Mutex<Option<ReaderState>>,
    info: FileInfo,
    path: String,
    size: u64,
    cache_mode: CacheMode,
    backend: &'static Backend,
    stats: Arc<Stats>,
}

impl RustReader {
    pub(crate) fn new(
        reader: FileReader,
        cfg: ReaderConfig,
        info: FileInfo,
        path: String,
        backend: &'static Backend,
        stats: Arc<Stats>,
    ) -> Self {
        RustReader {
            size: reader.size(),
            cache_mode: reader.cache_mode(),
            state: Mutex::new(Some(ReaderState::new(reader, cfg))),
            info,
            path,
            backend,
            stats,
        }
    }

    /// The open reader state, made usable in this process (see
    /// [`ReaderState::refresh_after_fork`]); `closed_error` once closed.
    fn open_state<'a>(&self, g: &'a mut Option<ReaderState>) -> Result<&'a mut ReaderState> {
        let st = g.as_mut().ok_or_else(closed_error)?;
        st.refresh_after_fork(self.backend)?;
        Ok(st)
    }

    /// Run the cheap synchronous `f` on the open reader state: inline when
    /// the state is free (no detach), otherwise after waiting for it with
    /// the interpreter released.
    fn with_state<T, F>(&self, py: Python<'_>, f: F) -> PyResult<T>
    where
        T: Send,
        F: FnOnce(&mut ReaderState) -> Result<T> + Send,
    {
        // `try_lock` never blocks while attached (see the module docs).
        if let Some(mut g) = self.state.try_lock() {
            return raise(py, self.open_state(&mut g).and_then(f));
        }
        let r = py.detach(|| {
            let mut g = self.state.lock();
            self.open_state(&mut g).and_then(f)
        });
        raise(py, r)
    }

    /// Drive an async operation on the reader state. When the state is free
    /// the future is polled once inline, so operations served from buffered
    /// data (most small reads and lines) cost no detach and no executor;
    /// otherwise it is driven with the interpreter released (Ctrl-C cancels
    /// it and leaves the reader usable).
    fn run<T, F>(&self, py: Python<'_>, f: F) -> PyResult<T>
    where
        T: Send,
        F: for<'a> FnOnce(&'a mut ReaderState) -> futures::future::BoxFuture<'a, Result<T>> + Send,
    {
        let slot = runtime();
        if let Some(mut g) = self.state.try_lock() {
            let st = raise(py, self.open_state(&mut g))?;
            let mut fut = f(st);
            if let Poll::Ready(r) = poll_inline(&slot, fut.as_mut()) {
                return raise(py, r);
            }
            // Pending: finish detached, still holding the state (other
            // threads only ever wait for it detached). The next poll
            // registers the real waker.
            let r = py.detach(move || drive(&slot, fut));
            return raise(py, r?);
        }
        let r: PyResult<Result<T>> = py.detach(|| {
            let mut g = self.state.lock();
            match self.open_state(&mut g) {
                Ok(st) => drive(&slot, f(st)),
                Err(e) => Ok(Err(e)),
            }
        });
        raise(py, r?)
    }

    /// One line (up to `limit` bytes), from buffered data when possible.
    fn line<'py>(&self, py: Python<'py>, limit: Option<usize>) -> PyResult<Bound<'py, PyBytes>> {
        if let Some(mut g) = self.state.try_lock()
            && let Ok(st) = self.open_state(&mut g)
            && let Some(line) = st.take_line(b"\n", limit)
        {
            drop(g);
            return self.bytes_out(py, line);
        }
        let data = self.run(py, move |st| Box::pin(st.read_until(b"\n", limit)))?;
        self.bytes_out(py, data)
    }

    /// Large read straight into a new `bytes` object (the engine fills it
    /// with parallel ranged reads): no intermediate buffer, one copy.
    fn read_direct<'py>(&self, py: Python<'py>, len: usize) -> PyResult<Bound<'py, PyBytes>> {
        let (obj, mut buf) = zeroed_bytes(py, len)?;
        let slot = runtime();
        let dst = buf.as_mut_slice();
        let r: PyResult<Result<usize>> = py.detach(|| {
            let mut g = self.state.lock();
            match self.open_state(&mut g) {
                Ok(st) => drive(&slot, st.read_into(dst)),
                Err(e) => Ok(Err(e)),
            }
        });
        let got = raise(py, r?)?;
        self.stats.add_bytes_read(got as u64);
        if got == len {
            return Ok(obj);
        }
        // The file shrank since it was opened (or another thread moved the
        // position): return what was read.
        Ok(PyBytes::new(py, &buf.as_mut_slice()[..got]))
    }

    fn bytes_out<'py>(&self, py: Python<'py>, data: Bytes) -> PyResult<Bound<'py, PyBytes>> {
        self.stats.add_bytes_read(data.len() as u64);
        bytes_to_py(py, &data)
    }
}

/// First poll of a file operation on the calling thread, which is attached
/// to the interpreter: inside the fork gate when it is open, skipped
/// (`Pending`, so the caller finishes detached) while a fork is pending,
/// because an attached thread must never wait for the gate.
fn poll_inline<T>(
    slot: &crate::runtime::RuntimeSlot,
    fut: std::pin::Pin<&mut (dyn std::future::Future<Output = Result<T>> + Send + '_)>,
) -> Poll<Result<T>> {
    let Some(_gate) = crate::gate::try_enter() else {
        return Poll::Pending;
    };
    let _ctx = slot.handle().enter();
    fut.poll(&mut Context::from_waker(Waker::noop()))
}

fn opt_len(n: Option<i64>) -> Option<usize> {
    match n {
        Some(n) if n >= 0 => Some(n as usize),
        _ => None,
    }
}

#[pymethods]
impl RustReader {
    /// Read `n` bytes (`None` or negative: to the end of the file). Returns
    /// fewer only at EOF.
    #[pyo3(signature = (n=None))]
    fn read<'py>(&self, py: Python<'py>, n: Option<i64>) -> PyResult<Bound<'py, PyBytes>> {
        let n = opt_len(n);
        let pos = self.with_state(py, |st| Ok(st.tell()))?;
        let avail = self.size.saturating_sub(pos);
        let len = n.map_or(avail, |n| (n as u64).min(avail));
        if len >= DIRECT_READ_MIN as u64
            && let Ok(len) = usize::try_from(len)
        {
            return self.read_direct(py, len);
        }
        let data = self.run(py, move |st| Box::pin(st.read(n)))?;
        self.bytes_out(py, data)
    }

    /// Fill a writable buffer-protocol object; returns the number of bytes
    /// read (0 at EOF). Data is written straight into `buf` with the
    /// interpreter released.
    fn readinto(&self, py: Python<'_>, buf: &Bound<'_, PyAny>) -> PyResult<usize> {
        let mut target = WriteTarget::new(buf).map_err(|e| {
            // Python's file objects (and fsspec's) raise TypeError for a
            // read-only or non-buffer argument, not BufferError.
            if e.is_instance_of::<pyo3::exceptions::PyBufferError>(py)
                || e.is_instance_of::<pyo3::exceptions::PyTypeError>(py)
            {
                let ty = buf
                    .get_type()
                    .name()
                    .map(|n| n.to_string())
                    .unwrap_or_else(|_| "object".to_owned());
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "readinto() argument must be read-write bytes-like object, not {ty}"
                ))
            } else {
                e
            }
        })?;
        let slot = runtime();
        let dst = target.as_mut_slice();
        let r: PyResult<Result<usize>> = py.detach(|| {
            let mut g = self.state.lock();
            match self.open_state(&mut g) {
                Ok(st) => drive(&slot, st.read_into(dst)),
                Err(e) => Ok(Err(e)),
            }
        });
        let n = raise(py, r?)?;
        target.finish(py, n)?;
        self.stats.add_bytes_read(n as u64);
        Ok(n)
    }

    /// Read one line (up to and including `b"\n"`), at most `limit` bytes.
    #[pyo3(signature = (limit=None))]
    fn readline<'py>(&self, py: Python<'py>, limit: Option<i64>) -> PyResult<Bound<'py, PyBytes>> {
        self.line(py, opt_len(limit))
    }

    /// An iterator over the remaining lines (each including its `b"\n"`).
    /// It shares this reader's position; iterating costs no Python frame
    /// per line.
    fn lines(slf: Bound<'_, Self>) -> LineIter {
        LineIter {
            reader: slf.unbind(),
        }
    }

    /// Read up to and including the first occurrence of `delim` (fsspec
    /// `readuntil`), at most `limit` bytes.
    #[pyo3(signature = (delim=b"\n".as_slice(), limit=None))]
    fn readuntil<'py>(
        &self,
        py: Python<'py>,
        delim: &[u8],
        limit: Option<i64>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        if delim.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err("empty delimiter"));
        }
        let delim = delim.to_vec();
        let limit = opt_len(limit);
        let data = self.run(py, move |st| {
            Box::pin(async move { st.read_until(&delim, limit).await })
        })?;
        self.bytes_out(py, data)
    }

    /// Move the position; returns the new absolute position. Seeking past
    /// the end is allowed; before the start is a `ValueError`.
    #[pyo3(signature = (offset, whence=0))]
    fn seek(&self, py: Python<'_>, offset: i64, whence: i32) -> PyResult<u64> {
        let size = self.size;
        self.with_state(py, move |st| {
            let to = seek_target(offset, whence, st.tell(), size)?;
            st.seek(to)
        })
    }

    /// Current position.
    fn tell(&self, py: Python<'_>) -> PyResult<u64> {
        self.with_state(py, |st| Ok(st.tell()))
    }

    /// Read several `(start, end)` byte ranges (end exclusive) without
    /// moving the position; nearby ranges are coalesced and fetched
    /// concurrently.
    fn read_ranges<'py>(
        &self,
        py: Python<'py>,
        ranges: Vec<(u64, u64)>,
    ) -> PyResult<Bound<'py, PyList>> {
        let handle = self.with_state(py, |st| Ok(st.reader.handle().clone()))?;
        let ranges: Vec<std::ops::Range<u64>> =
            ranges.into_iter().map(|(s, e)| s..e.max(s)).collect();
        let stats = self.stats.clone();
        let out = crate::runtime::block_on(py, async move {
            stats
                .measure(OpKind::Read, handle.read_ranges(&ranges))
                .await
        })?;
        let out = raise(py, out)?;
        let items = out
            .iter()
            .map(|d| self.bytes_out(py, d.clone()))
            .collect::<PyResult<Vec<_>>>()?;
        PyList::new(py, items)
    }

    /// Drop cached and prefetched data (the reader stays usable).
    fn clear_cache(&self, py: Python<'_>) -> PyResult<()> {
        self.with_state(py, |st| {
            st.reader.clear_cache();
            Ok(())
        })
    }

    /// Close the file (idempotent). Cancels background prefetches and
    /// releases the backend handle.
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        let slot = runtime();
        let r: PyResult<Result<()>> = py.detach(|| {
            let mut g = self.state.lock();
            match g.take() {
                Some(st) if st.generation != fork_generation() => {
                    // Opened before a fork: never touch the parent's tasks
                    // (or a handle bound to its runtime) here.
                    std::mem::forget(st);
                    Ok(Ok(()))
                }
                Some(mut st) => drive(&slot, async move { st.reader.close().await }),
                None => Ok(Ok(())),
            }
        });
        raise(py, r?)
    }

    /// Whether `close()` was called.
    #[getter]
    fn closed(&self, py: Python<'_>) -> bool {
        py.detach(|| self.state.lock().is_none())
    }

    /// File size at open time.
    #[getter]
    fn size(&self) -> u64 {
        self.size
    }

    /// Path the file was opened with.
    #[getter]
    fn path(&self) -> &str {
        &self.path
    }

    /// Cache mode name (`none`, `readahead`, `blockcache`, `background`,
    /// `all`).
    #[getter]
    fn cache_mode(&self) -> &'static str {
        match self.cache_mode {
            CacheMode::None => "none",
            CacheMode::Readahead => "readahead",
            CacheMode::Blocks(c) if c.prefetch => "background",
            CacheMode::Blocks(_) => "blockcache",
            CacheMode::Whole => "all",
        }
    }

    /// The info dict observed when the file was opened.
    fn info<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        info_to_py(py, &self.info, self.backend)
    }

    fn __repr__(&self) -> String {
        format!("<fsfast RustReader {:?} size={}>", self.path, self.size)
    }
}

impl Drop for RustReader {
    fn drop(&mut self) {
        if let Some(st) = self.state.get_mut().take()
            && st.generation != fork_generation()
        {
            // Dropping would cancel the parent's prefetch tasks (see the
            // module docs).
            std::mem::forget(st);
        }
    }
}

/// Iterator over the lines of a [`RustReader`] (`RustReader.lines()`).
#[pyclass(frozen, module = "fsfast._core")]
pub struct LineIter {
    reader: Py<RustReader>,
}

#[pymethods]
impl LineIter {
    fn __iter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }

    fn __next__<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let line = self.reader.get().line(py, None)?;
        Ok(if line.as_bytes().is_empty() {
            None
        } else {
            Some(line)
        })
    }
}

struct WriterState {
    handle: Option<Box<dyn WriteHandle>>,
    buf: BytesMut,
    buffer_size: usize,
    accepted: u64,
    closed: bool,
    /// [`fork_generation`] that opened the handle (a forked child must not
    /// touch it).
    generation: u64,
    /// The handle was given up in a forked child (see `check_fork`).
    abandoned: bool,
    /// For error messages.
    path: String,
}

impl WriterState {
    fn handle(&mut self) -> Result<&mut Box<dyn WriteHandle>> {
        if self.closed {
            return Err(closed_error());
        }
        if self.abandoned {
            return Err(forked_writer_error(&self.path));
        }
        self.handle.as_mut().ok_or_else(closed_error)
    }

    /// In a forked child of the process that opened the handle, give it up
    /// without touching it: its writes in flight belong to the parent's
    /// runtime, and the parent commits the file. Afterwards writes raise and
    /// `close`/`abort` only mark the file closed. Idempotent.
    fn check_fork(&mut self) {
        if self.abandoned || self.generation == fork_generation() {
            return;
        }
        self.abandoned = true;
        self.buf = BytesMut::new();
        if let Some(h) = self.handle.take() {
            std::mem::forget(h);
        }
    }

    /// Hand the buffered bytes to the backend.
    async fn push(&mut self) -> Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let data = self.buf.split().freeze();
        self.handle()?.write(data).await
    }
}

/// Data passed to `write`: an owned buffer (zero-copy for large `bytes`) or
/// a borrowed buffer-protocol view, copied only where needed.
enum InData {
    Owned(Bytes),
    View(ReadSource),
}

impl InData {
    fn as_slice(&self) -> &[u8] {
        match self {
            InData::Owned(b) => b,
            InData::View(v) => v.as_slice(),
        }
    }

    fn into_bytes(self) -> Bytes {
        match self {
            InData::Owned(b) => b,
            InData::View(v) => Bytes::copy_from_slice(v.as_slice()),
        }
    }
}

/// A file opened for writing (`fs.open_write(...)`).
///
/// Small writes are collected into one buffer and handed to the backend in
/// `buffer_size` chunks (one copy, no per-write runtime round trip); writes
/// of at least `buffer_size` go straight to the backend (without copying
/// when they are `bytes`). Data is committed by `close()`; `abort()`
/// discards it. A writer dropped without either is closed in the background
/// (like a Python file flushed on garbage collection).
#[pyclass(frozen, module = "fsfast._core")]
pub struct RustWriter {
    state: Mutex<WriterState>,
    path: String,
    stats: Arc<Stats>,
}

impl RustWriter {
    pub(crate) fn new(
        handle: Box<dyn WriteHandle>,
        path: String,
        buffer_size: usize,
        stats: Arc<Stats>,
    ) -> Self {
        RustWriter {
            state: Mutex::new(WriterState {
                handle: Some(handle),
                buf: BytesMut::new(),
                buffer_size,
                accepted: 0,
                closed: false,
                generation: fork_generation(),
                abandoned: false,
                path: path.clone(),
            }),
            path,
            stats,
        }
    }

    /// Run `f` on the writer state with the interpreter released. With
    /// `inline_first`, and the state free, the future is first polled once
    /// without detaching (small writes that only fill the buffer finish
    /// there; callers only ask for this when that work is small).
    fn run<T, F>(&self, py: Python<'_>, inline_first: bool, f: F) -> PyResult<T>
    where
        T: Send,
        F: for<'a> FnOnce(&'a mut WriterState) -> futures::future::BoxFuture<'a, Result<T>> + Send,
    {
        let slot = runtime();
        if inline_first && let Some(mut g) = self.state.try_lock() {
            g.check_fork();
            let mut fut = f(&mut g);
            if let Poll::Ready(r) = poll_inline(&slot, fut.as_mut()) {
                return raise(py, r);
            }
            let r = py.detach(move || drive(&slot, fut));
            return raise(py, r?);
        }
        let r: PyResult<Result<T>> = py.detach(|| {
            let mut g = self.state.lock();
            g.check_fork();
            drive(&slot, f(&mut g))
        });
        raise(py, r?)
    }
}

#[pymethods]
impl RustWriter {
    /// Write a bytes-like object; returns the number of bytes accepted.
    fn write(&self, py: Python<'_>, data: &Bound<'_, PyAny>) -> PyResult<usize> {
        let data = if data.is_instance_of::<PyBytes>() {
            InData::Owned(bytes_from_py(data)?)
        } else {
            if data.is_instance_of::<pyo3::types::PyString>() {
                return Err(pyo3::exceptions::PyTypeError::new_err(
                    "a bytes-like object is required, not 'str'",
                ));
            }
            InData::View(ReadSource::new(data)?)
        };
        let n = data.as_slice().len();
        let stats = self.stats.clone();
        self.run(py, n <= INLINE_WRITE_MAX, move |st| {
            Box::pin(async move {
                st.handle()?;
                if n == 0 {
                    return Ok(0);
                }
                if n >= st.buffer_size {
                    // Large write: flush what is buffered, then pass the data
                    // through as one chunk.
                    st.push().await?;
                    st.handle()?.write(data.into_bytes()).await?;
                } else {
                    st.buf.extend_from_slice(data.as_slice());
                    if st.buf.len() >= st.buffer_size {
                        st.push().await?;
                    }
                }
                st.accepted += n as u64;
                stats.add_bytes_written(n as u64);
                Ok(n)
            })
        })
    }

    /// Push buffered data to the backend and flush it where the protocol
    /// allows.
    fn flush(&self, py: Python<'_>) -> PyResult<()> {
        self.run(py, false, |st| {
            Box::pin(async move {
                st.push().await?;
                st.handle()?.flush().await
            })
        })
    }

    /// Commit the file (idempotent). On failure the partial upload is
    /// aborted and the error raised.
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        let stats = self.stats.clone();
        self.run(py, false, move |st| {
            Box::pin(async move {
                if st.closed {
                    return Ok(());
                }
                if st.abandoned {
                    // A forked child closing the parent's file.
                    st.closed = true;
                    return Ok(());
                }
                let res = async {
                    st.push().await?;
                    let h = st.handle()?;
                    stats.measure(OpKind::Close, h.close()).await
                }
                .await;
                st.closed = true;
                if let Some(mut h) = st.handle.take()
                    && res.is_err()
                {
                    let _ = h.abort().await;
                }
                res
            })
        })
    }

    /// Discard the file: nothing written becomes visible (or, for appends,
    /// the original content is kept). Idempotent.
    fn abort(&self, py: Python<'_>) -> PyResult<()> {
        self.run(py, false, |st| {
            Box::pin(async move {
                st.buf.clear();
                let was_closed = st.closed;
                st.closed = true;
                match st.handle.take() {
                    Some(mut h) if !was_closed => h.abort().await,
                    _ => Ok(()),
                }
            })
        })
    }

    /// Bytes accepted by `write` so far (including buffered bytes).
    #[getter]
    fn bytes_written(&self, py: Python<'_>) -> u64 {
        py.detach(|| self.state.lock().accepted)
    }

    /// Whether `close()` or `abort()` was called.
    #[getter]
    fn closed(&self, py: Python<'_>) -> bool {
        py.detach(|| self.state.lock().closed)
    }

    /// Path the file was opened with.
    #[getter]
    fn path(&self) -> &str {
        &self.path
    }

    fn __repr__(&self) -> String {
        format!("<fsfast RustWriter {:?}>", self.path)
    }
}

impl Drop for RustWriter {
    fn drop(&mut self) {
        let st = self.state.get_mut();
        // In a forked child the handle is the parent's: forget it (dropping
        // it could commit it, or touch the parent's runtime).
        st.check_fork();
        if st.closed {
            return;
        }
        let Some(mut h) = st.handle.take() else {
            return;
        };
        let buf = std::mem::take(&mut st.buf).freeze();
        let path = std::mem::take(&mut self.path);
        // Finish like a garbage-collected Python file: write what is left and
        // commit, in the background (drop may run on any thread).
        runtime().handle().spawn(crate::gate::Gated(Box::pin(async move {
            if !buf.is_empty()
                && let Err(e) = h.write(buf).await
            {
                tracing::warn!(%path, error = %e, "fsfast: writer dropped unclosed; final write failed");
                let _ = h.abort().await;
                return;
            }
            if let Err(e) = h.close().await {
                tracing::warn!(%path, error = %e, "fsfast: writer dropped unclosed; close failed");
                if e.kind() != ErrorKind::Cancelled {
                    let _ = h.abort().await;
                }
            }
        })));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsfast_core::{ReadHandle, async_trait};
    use std::pin::pin;

    /// An in-memory read handle whose every read first yields once, so a
    /// test can cancel an operation between fetches.
    #[derive(Debug)]
    struct YieldingHandle {
        info: FileInfo,
        data: Bytes,
    }

    #[async_trait]
    impl ReadHandle for YieldingHandle {
        fn info(&self) -> &FileInfo {
            &self.info
        }

        async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
            tokio::task::yield_now().await;
            let s = (offset as usize).min(self.data.len());
            let e = s.saturating_add(len).min(self.data.len());
            Ok(self.data.slice(s..e))
        }
    }

    fn state(data: &[u8]) -> ReaderState {
        let handle = Arc::new(YieldingHandle {
            info: FileInfo::file("/t", data.len() as u64),
            data: Bytes::copy_from_slice(data),
        });
        let cfg = ReaderConfig::with_cache(CacheMode::None);
        ReaderState::new(FileReader::new(handle, cfg.clone()), cfg)
    }

    /// `readuntil` on a byte vector: the reference semantics.
    fn model_until(data: &[u8], pos: &mut usize, delim: &[u8], limit: Option<usize>) -> Vec<u8> {
        let rest = &data[*pos..];
        let mut end = find(rest, delim).map_or(rest.len(), |i| i + delim.len());
        if let Some(l) = limit {
            end = end.min(l);
        }
        *pos += end;
        rest[..end].to_vec()
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n.max(1)
        }
    }

    #[test]
    fn delimiter_scans_match_a_model_across_chunk_boundaries() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for round in 0..40 {
            // Sparse delimiters (long lines spanning many scan chunks) in
            // some rounds, dense ones in others; multi-byte delimiters are
            // placed right at scan-chunk boundaries (8 KiB, 24 KiB, ...).
            let len = 1 + rng.below(300_000) as usize;
            let mut data: Vec<u8> = (0..len).map(|_| b'a' + rng.below(3) as u8).collect();
            let delims: [&[u8]; 3] = [b"\n", b"\r\n", b"<END>"];
            let delim = delims[round % 3];
            let density = if round % 2 == 0 { 50_000 } else { 300 };
            let mut at = rng.below(density) as usize;
            while at + delim.len() <= data.len() {
                data[at..at + delim.len()].copy_from_slice(delim);
                at += 1 + rng.below(density) as usize;
            }
            for b in [SCAN_CHUNK_MIN, 3 * SCAN_CHUNK_MIN, 7 * SCAN_CHUNK_MIN] {
                // Starts 2 bytes before the boundary: straddles it.
                let n = delim.len().min(data.len().saturating_sub(b - 2));
                if b + 2 <= data.len() {
                    data[b - 2..b - 2 + n].copy_from_slice(&delim[..n]);
                }
            }
            let mut st = state(&data);
            let mut pos = 0usize;
            rt.block_on(async {
                while pos < data.len() {
                    match rng.below(10) {
                        0 => {
                            let n = rng.below(20_000) as usize;
                            let got = st.read(Some(n)).await.unwrap();
                            let want = &data[pos..(pos + n).min(data.len())];
                            assert_eq!(&got[..], want, "read at {pos}");
                            pos += want.len();
                        }
                        1 => {
                            let to = rng.below(data.len() as u64 + 1) as usize;
                            assert_eq!(st.seek(SeekFrom::Start(to as u64)).unwrap(), to as u64);
                            pos = to;
                        }
                        k => {
                            let limit = (k == 2).then(|| rng.below(40_000) as usize);
                            let got = st.read_until(delim, limit).await.unwrap();
                            let want = model_until(&data, &mut pos, delim, limit);
                            assert_eq!(got.len(), want.len(), "round {round} at {pos}");
                            assert!(got[..] == want[..], "round {round}: content");
                        }
                    }
                    assert_eq!(st.tell(), pos as u64);
                }
                assert!(st.read_until(delim, None).await.unwrap().is_empty());
            });
        }
    }

    #[test]
    fn a_cancelled_scan_loses_no_data() {
        // A 2 MB line: the scan needs many fetches (each takes two polls of
        // the yielding handle). Cancel it after a few of them; every byte
        // must still come back, in order.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut data: Vec<u8> = (0..2_000_000u32).map(|i| b'a' + (i % 26) as u8).collect();
        data.extend_from_slice(b"\nnext line\n");
        let mut st = state(&data);
        let head = rt.block_on(st.read(Some(5))).unwrap();
        assert_eq!(&head[..], &data[..5]);
        {
            let mut fut = pin!(st.read_until(b"\n", None));
            let mut cx = Context::from_waker(Waker::noop());
            let _guard = rt.enter();
            for _ in 0..7 {
                assert!(fut.as_mut().poll(&mut cx).is_pending());
            }
        } // dropped half-way
        assert!(st.scan_len > 0, "the test did not cancel mid-scan");
        assert_eq!(st.tell(), 5);
        let line = rt.block_on(st.read_until(b"\n", None)).unwrap();
        assert_eq!(&line[..], &data[5..2_000_001]);
        // The same after a cancelled scan followed by a plain read.
        let mut st = state(&data);
        {
            let mut fut = pin!(st.read_until(b"\n", None));
            let mut cx = Context::from_waker(Waker::noop());
            let _guard = rt.enter();
            for _ in 0..5 {
                assert!(fut.as_mut().poll(&mut cx).is_pending());
            }
        }
        assert!(st.scan_len > 0, "the test did not cancel mid-scan");
        assert_eq!(&rt.block_on(st.read(None)).unwrap()[..], &data[..]);
    }
}
