//! `RustFileSystem`: the Python-facing wrapper around a backend.
//!
//! Every operation exists twice: a sync method that releases the
//! interpreter and blocks on the Rust future (no event loop, no thread hop),
//! and an `*_async` method returning an asyncio awaitable. Both run the same
//! future from [`crate::ops`].

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use fsfast_core::{Error, Result};
use fsfast_engine::OpKind;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple};

use crate::convert::{bytes_from_py, options_from_py, options_to_py};
use crate::errors::to_pyerr;
use crate::ops::{self, FsInner, OnError, OpenReadOptions, write_mode};
use crate::out::{Converted, PyOut, convert};
use crate::runtime::{block_on, future_into_py};

/// A Rust filesystem backend (local, memory, ...) created by
/// `make_filesystem(protocol, options)`.
///
/// Paths are protocol-stripped fsspec paths. Batch methods take
/// `on_error="raise"` (raise the first failure in input order) or
/// `"return"` (an exception instance in place of each failed item) and run
/// at most `batch_size` items at a time (default: the backend's preferred
/// concurrency; `-1` for no limit).
#[pyclass(frozen, module = "fsfast._core")]
pub struct RustFileSystem {
    inner: Arc<FsInner>,
}

/// `__reduce__` result: `(make_filesystem, (protocol, options))`.
type Reduced<'py> = (Bound<'py, PyAny>, (String, Bound<'py, PyDict>));

fn raise<T>(py: Python<'_>, r: Result<T>) -> PyResult<T> {
    r.map_err(|e| to_pyerr(py, &e))
}

fn on_error(py: Python<'_>, s: &str) -> PyResult<OnError> {
    raise(py, OnError::parse(s))
}

fn mode(py: Python<'_>, s: &str) -> PyResult<fsfast_core::WriteMode> {
    raise(py, write_mode(s))
}

fn datas_from_py(items: &[Bound<'_, PyAny>]) -> PyResult<Vec<bytes::Bytes>> {
    items.iter().map(bytes_from_py).collect()
}

impl RustFileSystem {
    pub(crate) fn create(protocol: &str, options: fsfast_core::Options) -> Result<Self> {
        Ok(RustFileSystem {
            inner: Arc::new(FsInner::new(protocol, options)?),
        })
    }

    fn fs(&self) -> Arc<FsInner> {
        self.inner.clone()
    }

    /// Run `fut` synchronously and convert its result.
    fn sync<'py, F>(&self, py: Python<'py>, fut: F) -> PyResult<Bound<'py, PyAny>>
    where
        F: Future<Output = Result<PyOut>> + Send,
    {
        let out = block_on(py, fut)?;
        convert(py, out, self.inner.backend)
    }

    /// Return an asyncio awaitable for `fut`.
    ///
    /// The future is first polled once on the calling thread (with the
    /// interpreter released). If that completes it — operations served from
    /// memory or caches — the result is returned as an already-resolved
    /// asyncio future, skipping every thread hop of the general path
    /// (tokio worker, blocking pool, event-loop wake-up). Otherwise the
    /// partially polled future continues on the runtime through
    /// `pyo3-async-runtimes` (its next poll registers the real waker).
    ///
    /// Without a running event loop this raises `RuntimeError` *before*
    /// polling, so a call that fails has no side effects.
    fn spawn<'py, F>(&self, py: Python<'py>, fut: F) -> PyResult<Bound<'py, PyAny>>
    where
        F: Future<Output = Result<PyOut>> + Send + 'static,
    {
        let event_loop = pyo3_async_runtimes::get_running_loop(py)?;
        let backend = self.inner.backend;
        let slot = crate::runtime::runtime();
        let mut fut = Box::pin(fut);
        let first = py.detach(|| {
            let _ctx = slot.handle().enter();
            fut.as_mut()
                .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
        });
        match first {
            std::task::Poll::Ready(out) => {
                resolved_future(py, &event_loop, convert(py, out, backend))
            }
            std::task::Poll::Pending => future_into_py(py, event_loop, async move {
                Ok(Converted {
                    out: fut.await,
                    backend,
                })
            }),
        }
    }
}

/// An asyncio future of `event_loop` (the running loop) already holding
/// `result` (or its exception), so awaiting it returns or raises
/// immediately.
fn resolved_future<'py>(
    py: Python<'py>,
    event_loop: &Bound<'py, PyAny>,
    result: PyResult<Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    let fut = event_loop.call_method0(pyo3::intern!(py, "create_future"))?;
    match result {
        Ok(v) => fut.call_method1(pyo3::intern!(py, "set_result"), (v,))?,
        Err(e) => fut.call_method1(pyo3::intern!(py, "set_exception"), (e.into_value(py),))?,
    };
    Ok(fut)
}

#[pymethods]
impl RustFileSystem {
    /// Canonical protocol name of the backend.
    #[getter]
    fn protocol(&self) -> &'static str {
        self.inner.backend.name()
    }

    /// Every protocol name the backend serves.
    #[getter]
    fn protocols<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        PyTuple::new(py, self.inner.backend.protocols)
    }

    /// The options the backend was built from.
    #[getter]
    fn options<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        options_to_py(py, &self.inner.options)
    }

    /// Backend capabilities as a dict of booleans.
    fn capabilities<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let c = raise(py, self.inner.fs())?.capabilities();
        let d = PyDict::new(py);
        d.set_item("hierarchical", c.hierarchical)?;
        d.set_item("atomic_rename", c.atomic_rename)?;
        d.set_item("server_side_copy", c.server_side_copy)?;
        d.set_item("append", c.append)?;
        d.set_item("conditional_create", c.conditional_create)?;
        d.set_item("random_write", c.random_write)?;
        d.set_item("versioning", c.versioning)?;
        d.set_item("signed_urls", c.signed_urls)?;
        d.set_item("pinned_reads", c.pinned_reads)?;
        Ok(d)
    }

    /// Backend I/O hints (`request_size`, `max_concurrency`,
    /// `coalesce_gap`, `max_coalesced`).
    fn io_hints<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let h = raise(py, self.inner.fs())?.io_hints();
        let d = PyDict::new(py);
        d.set_item("request_size", h.request_size)?;
        d.set_item("max_concurrency", h.max_concurrency)?;
        d.set_item("coalesce_gap", h.coalesce_gap)?;
        d.set_item("max_coalesced", h.max_coalesced)?;
        Ok(d)
    }

    // ---- metadata ---------------------------------------------------------

    /// fsspec `info(path)` dict.
    fn info<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        self.sync(py, ops::info(self.fs(), path))
    }

    /// Awaitable `info(path)`.
    fn info_async<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        self.spawn(py, ops::info(self.fs(), path))
    }

    /// `(modified, created)` timestamps of `path` as timezone-aware UTC
    /// datetimes (`None` where the backend does not know them).
    fn times<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        self.sync(py, ops::times(self.fs(), path))
    }

    /// Awaitable `times`.
    fn times_async<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        self.spawn(py, ops::times(self.fs(), path))
    }

    /// `info` for many paths, concurrently.
    #[pyo3(signature = (paths, on_error="raise", batch_size=None))]
    fn info_many<'py>(
        &self,
        py: Python<'py>,
        paths: Vec<String>,
        on_error: &str,
        batch_size: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let oe = self::on_error(py, on_error)?;
        self.sync(py, ops::info_many(self.fs(), paths, oe, batch_size))
    }

    /// Awaitable `info_many`.
    #[pyo3(signature = (paths, on_error="raise", batch_size=None))]
    fn info_many_async<'py>(
        &self,
        py: Python<'py>,
        paths: Vec<String>,
        on_error: &str,
        batch_size: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let oe = self::on_error(py, on_error)?;
        self.spawn(py, ops::info_many(self.fs(), paths, oe, batch_size))
    }

    /// Directory listing: info dicts, or names when `detail=False`.
    #[pyo3(signature = (path, detail=true))]
    fn ls<'py>(&self, py: Python<'py>, path: String, detail: bool) -> PyResult<Bound<'py, PyAny>> {
        self.sync(py, ops::ls(self.fs(), path, detail))
    }

    /// Awaitable `ls`.
    #[pyo3(signature = (path, detail=true))]
    fn ls_async<'py>(
        &self,
        py: Python<'py>,
        path: String,
        detail: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.spawn(py, ops::ls(self.fs(), path, detail))
    }

    /// Recursive listing sorted by name: `{name: info}` when `detail`, else
    /// a list of names.
    #[pyo3(signature = (path, maxdepth=None, withdirs=false, detail=false))]
    fn find<'py>(
        &self,
        py: Python<'py>,
        path: String,
        maxdepth: Option<i64>,
        withdirs: bool,
        detail: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.sync(py, ops::find(self.fs(), path, maxdepth, withdirs, detail))
    }

    /// Awaitable `find`.
    #[pyo3(signature = (path, maxdepth=None, withdirs=false, detail=false))]
    fn find_async<'py>(
        &self,
        py: Python<'py>,
        path: String,
        maxdepth: Option<i64>,
        withdirs: bool,
        detail: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.spawn(py, ops::find(self.fs(), path, maxdepth, withdirs, detail))
    }

    /// Whether `path` exists.
    fn exists<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        self.sync(py, ops::exists(self.fs(), path))
    }

    /// Awaitable `exists`.
    fn exists_async<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        self.spawn(py, ops::exists(self.fs(), path))
    }

    // ---- reading ----------------------------------------------------------

    /// fsspec `cat_file(path, start, end)` (Python slice semantics; the size
    /// is looked up only for negative ranges). `seek_read` selects the
    /// semantics of fsspec's generic `cat_file` instead (seek, then
    /// `read(end - pos)`: a count of -1 reads to EOF, below -1 is a
    /// `ValueError`), as used by fsspec's `LocalFileSystem`.
    #[pyo3(signature = (path, start=None, end=None, seek_read=false))]
    fn cat_file<'py>(
        &self,
        py: Python<'py>,
        path: String,
        start: Option<i64>,
        end: Option<i64>,
        seek_read: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.sync(py, ops::cat_file(self.fs(), path, start, end, seek_read))
    }

    /// Awaitable `cat_file`.
    #[pyo3(signature = (path, start=None, end=None, seek_read=false))]
    fn cat_file_async<'py>(
        &self,
        py: Python<'py>,
        path: String,
        start: Option<i64>,
        end: Option<i64>,
        seek_read: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.spawn(py, ops::cat_file(self.fs(), path, start, end, seek_read))
    }

    /// Whole contents of many files, concurrently (list in input order).
    #[pyo3(signature = (paths, on_error="raise", batch_size=None))]
    fn cat_many<'py>(
        &self,
        py: Python<'py>,
        paths: Vec<String>,
        on_error: &str,
        batch_size: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let oe = self::on_error(py, on_error)?;
        self.sync(py, ops::cat_many(self.fs(), paths, oe, batch_size))
    }

    /// Awaitable `cat_many`.
    #[pyo3(signature = (paths, on_error="raise", batch_size=None))]
    fn cat_many_async<'py>(
        &self,
        py: Python<'py>,
        paths: Vec<String>,
        on_error: &str,
        batch_size: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let oe = self::on_error(py, on_error)?;
        self.spawn(py, ops::cat_many(self.fs(), paths, oe, batch_size))
    }

    /// fsspec `cat_ranges(paths, starts, ends)`: grouped by path, each
    /// file's ranges coalesced by the backend, files read concurrently.
    #[pyo3(signature = (paths, starts, ends, on_error="return", batch_size=None, seek_read=false))]
    #[allow(clippy::too_many_arguments)]
    fn cat_ranges<'py>(
        &self,
        py: Python<'py>,
        paths: Vec<String>,
        starts: Vec<Option<i64>>,
        ends: Vec<Option<i64>>,
        on_error: &str,
        batch_size: Option<i64>,
        seek_read: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let oe = self::on_error(py, on_error)?;
        self.sync(
            py,
            ops::cat_ranges(self.fs(), paths, starts, ends, oe, batch_size, seek_read),
        )
    }

    /// Awaitable `cat_ranges`.
    #[pyo3(signature = (paths, starts, ends, on_error="return", batch_size=None, seek_read=false))]
    #[allow(clippy::too_many_arguments)]
    fn cat_ranges_async<'py>(
        &self,
        py: Python<'py>,
        paths: Vec<String>,
        starts: Vec<Option<i64>>,
        ends: Vec<Option<i64>>,
        on_error: &str,
        batch_size: Option<i64>,
        seek_read: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let oe = self::on_error(py, on_error)?;
        self.spawn(
            py,
            ops::cat_ranges(self.fs(), paths, starts, ends, oe, batch_size, seek_read),
        )
    }

    /// Open a file for reading. `cache_type` takes fsspec's names
    /// (`readahead` default, `none`, `blockcache`, `background`, `mmap`,
    /// `bytes`, `first`, `all`); `block_size`/`max_blocks` size block caches;
    /// `request_size`/`concurrency` override the backend's I/O hints.
    #[pyo3(signature = (path, cache_type="readahead", block_size=None, max_blocks=None, request_size=None, concurrency=None, version=None))]
    #[allow(clippy::too_many_arguments)]
    fn open_read<'py>(
        &self,
        py: Python<'py>,
        path: String,
        cache_type: &str,
        block_size: Option<usize>,
        max_blocks: Option<usize>,
        request_size: Option<usize>,
        concurrency: Option<usize>,
        version: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let o = OpenReadOptions {
            cache_type: cache_type.to_owned(),
            block_size,
            max_blocks,
            request_size,
            concurrency,
            version,
        };
        self.sync(py, ops::open_read(self.fs(), path, o))
    }

    /// Awaitable `open_read`.
    #[pyo3(signature = (path, cache_type="readahead", block_size=None, max_blocks=None, request_size=None, concurrency=None, version=None))]
    #[allow(clippy::too_many_arguments)]
    fn open_read_async<'py>(
        &self,
        py: Python<'py>,
        path: String,
        cache_type: &str,
        block_size: Option<usize>,
        max_blocks: Option<usize>,
        request_size: Option<usize>,
        concurrency: Option<usize>,
        version: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let o = OpenReadOptions {
            cache_type: cache_type.to_owned(),
            block_size,
            max_blocks,
            request_size,
            concurrency,
            version,
        };
        self.spawn(py, ops::open_read(self.fs(), path, o))
    }

    // ---- writing ----------------------------------------------------------

    /// Write a whole file from a bytes-like object. `mode` is `overwrite`
    /// or `create` (fsspec) — or `wb`/`xb`/`ab`.
    #[pyo3(signature = (path, data, mode="overwrite"))]
    fn pipe_file<'py>(
        &self,
        py: Python<'py>,
        path: String,
        data: &Bound<'py, PyAny>,
        mode: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let m = self::mode(py, mode)?;
        let data = bytes_from_py(data)?;
        self.sync(py, ops::pipe_file(self.fs(), path, data, m))
    }

    /// Awaitable `pipe_file`.
    #[pyo3(signature = (path, data, mode="overwrite"))]
    fn pipe_file_async<'py>(
        &self,
        py: Python<'py>,
        path: String,
        data: &Bound<'py, PyAny>,
        mode: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let m = self::mode(py, mode)?;
        let data = bytes_from_py(data)?;
        self.spawn(py, ops::pipe_file(self.fs(), path, data, m))
    }

    /// `pipe_file` for many files (`paths[i]` gets `datas[i]`).
    #[pyo3(signature = (paths, datas, mode="overwrite", on_error="raise", batch_size=None))]
    fn pipe_many<'py>(
        &self,
        py: Python<'py>,
        paths: Vec<String>,
        datas: Vec<Bound<'py, PyAny>>,
        mode: &str,
        on_error: &str,
        batch_size: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let m = self::mode(py, mode)?;
        let oe = self::on_error(py, on_error)?;
        let datas = datas_from_py(&datas)?;
        self.sync(
            py,
            ops::pipe_many(self.fs(), paths, datas, m, oe, batch_size),
        )
    }

    /// Awaitable `pipe_many`.
    #[pyo3(signature = (paths, datas, mode="overwrite", on_error="raise", batch_size=None))]
    fn pipe_many_async<'py>(
        &self,
        py: Python<'py>,
        paths: Vec<String>,
        datas: Vec<Bound<'py, PyAny>>,
        mode: &str,
        on_error: &str,
        batch_size: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let m = self::mode(py, mode)?;
        let oe = self::on_error(py, on_error)?;
        let datas = datas_from_py(&datas)?;
        self.spawn(
            py,
            ops::pipe_many(self.fs(), paths, datas, m, oe, batch_size),
        )
    }

    /// Open a file for writing (`mode` `wb`, `xb` or `ab`). `block_size` is
    /// the backend's part size hint; `buffer_size` the write-buffer size
    /// (default: the backend's request size within 64 KiB..16 MiB).
    #[pyo3(signature = (path, mode="wb", block_size=None, buffer_size=None))]
    fn open_write<'py>(
        &self,
        py: Python<'py>,
        path: String,
        mode: &str,
        block_size: Option<usize>,
        buffer_size: Option<usize>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let m = self::mode(py, mode)?;
        self.sync(
            py,
            ops::open_write(self.fs(), path, m, block_size, buffer_size),
        )
    }

    /// Awaitable `open_write`.
    #[pyo3(signature = (path, mode="wb", block_size=None, buffer_size=None))]
    fn open_write_async<'py>(
        &self,
        py: Python<'py>,
        path: String,
        mode: &str,
        block_size: Option<usize>,
        buffer_size: Option<usize>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let m = self::mode(py, mode)?;
        self.spawn(
            py,
            ops::open_write(self.fs(), path, m, block_size, buffer_size),
        )
    }

    /// Create an empty file, or truncate (`truncate=True`) / update the
    /// timestamp of an existing one.
    #[pyo3(signature = (path, truncate=true))]
    fn touch<'py>(
        &self,
        py: Python<'py>,
        path: String,
        truncate: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.sync(py, ops::touch(self.fs(), path, truncate))
    }

    /// Awaitable `touch`.
    #[pyo3(signature = (path, truncate=true))]
    fn touch_async<'py>(
        &self,
        py: Python<'py>,
        path: String,
        truncate: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.spawn(py, ops::touch(self.fs(), path, truncate))
    }

    // ---- deleting ---------------------------------------------------------

    /// Delete one file.
    fn rm_file<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        self.sync(py, ops::rm_file(self.fs(), path))
    }

    /// Awaitable `rm_file`.
    fn rm_file_async<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        self.spawn(py, ops::rm_file(self.fs(), path))
    }

    /// Delete many files with the backend's native batch delete.
    #[pyo3(signature = (paths, on_error="raise"))]
    fn rm_files<'py>(
        &self,
        py: Python<'py>,
        paths: Vec<String>,
        on_error: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let oe = self::on_error(py, on_error)?;
        self.sync(py, ops::rm_files(self.fs(), paths, oe))
    }

    /// Awaitable `rm_files`.
    #[pyo3(signature = (paths, on_error="raise"))]
    fn rm_files_async<'py>(
        &self,
        py: Python<'py>,
        paths: Vec<String>,
        on_error: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let oe = self::on_error(py, on_error)?;
        self.spawn(py, ops::rm_files(self.fs(), paths, oe))
    }

    /// Remove an empty directory.
    fn rmdir<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        self.sync(py, ops::rmdir(self.fs(), path))
    }

    /// Awaitable `rmdir`.
    fn rmdir_async<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        self.spawn(py, ops::rmdir(self.fs(), path))
    }

    /// Remove directories one after the other in the given order (children
    /// first). `ignore_missing` treats vanished directories as removed.
    #[pyo3(signature = (paths, on_error="raise", ignore_missing=false))]
    fn rmdir_many<'py>(
        &self,
        py: Python<'py>,
        paths: Vec<String>,
        on_error: &str,
        ignore_missing: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let oe = self::on_error(py, on_error)?;
        self.sync(py, ops::rmdir_many(self.fs(), paths, oe, ignore_missing))
    }

    /// Awaitable `rmdir_many`.
    #[pyo3(signature = (paths, on_error="raise", ignore_missing=false))]
    fn rmdir_many_async<'py>(
        &self,
        py: Python<'py>,
        paths: Vec<String>,
        on_error: &str,
        ignore_missing: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let oe = self::on_error(py, on_error)?;
        self.spawn(py, ops::rmdir_many(self.fs(), paths, oe, ignore_missing))
    }

    // ---- directories ------------------------------------------------------

    /// fsspec `mkdir(path, create_parents)`.
    #[pyo3(signature = (path, create_parents=true))]
    fn mkdir<'py>(
        &self,
        py: Python<'py>,
        path: String,
        create_parents: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.sync(py, ops::mkdir(self.fs(), path, create_parents))
    }

    /// Awaitable `mkdir`.
    #[pyo3(signature = (path, create_parents=true))]
    fn mkdir_async<'py>(
        &self,
        py: Python<'py>,
        path: String,
        create_parents: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.spawn(py, ops::mkdir(self.fs(), path, create_parents))
    }

    /// fsspec `makedirs(path, exist_ok)`.
    #[pyo3(signature = (path, exist_ok=false))]
    fn makedirs<'py>(
        &self,
        py: Python<'py>,
        path: String,
        exist_ok: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.sync(py, ops::makedirs(self.fs(), path, exist_ok))
    }

    /// Awaitable `makedirs`.
    #[pyo3(signature = (path, exist_ok=false))]
    fn makedirs_async<'py>(
        &self,
        py: Python<'py>,
        path: String,
        exist_ok: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.spawn(py, ops::makedirs(self.fs(), path, exist_ok))
    }

    /// `makedirs` for many paths, concurrently.
    #[pyo3(signature = (paths, exist_ok=true, on_error="raise", batch_size=None))]
    fn makedirs_many<'py>(
        &self,
        py: Python<'py>,
        paths: Vec<String>,
        exist_ok: bool,
        on_error: &str,
        batch_size: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let oe = self::on_error(py, on_error)?;
        self.sync(
            py,
            ops::makedirs_many(self.fs(), paths, exist_ok, oe, batch_size),
        )
    }

    /// Awaitable `makedirs_many`.
    #[pyo3(signature = (paths, exist_ok=true, on_error="raise", batch_size=None))]
    fn makedirs_many_async<'py>(
        &self,
        py: Python<'py>,
        paths: Vec<String>,
        exist_ok: bool,
        on_error: &str,
        batch_size: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let oe = self::on_error(py, on_error)?;
        self.spawn(
            py,
            ops::makedirs_many(self.fs(), paths, exist_ok, oe, batch_size),
        )
    }

    // ---- copy / move ------------------------------------------------------

    /// Copy one file within the filesystem (server-side where possible).
    fn cp_file<'py>(
        &self,
        py: Python<'py>,
        src: String,
        dst: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.sync(py, ops::cp_file(self.fs(), src, dst))
    }

    /// Awaitable `cp_file`.
    fn cp_file_async<'py>(
        &self,
        py: Python<'py>,
        src: String,
        dst: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.spawn(py, ops::cp_file(self.fs(), src, dst))
    }

    /// `cp_file` for many pairs, concurrently.
    #[pyo3(signature = (srcs, dsts, on_error="raise", batch_size=None))]
    fn cp_files<'py>(
        &self,
        py: Python<'py>,
        srcs: Vec<String>,
        dsts: Vec<String>,
        on_error: &str,
        batch_size: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let oe = self::on_error(py, on_error)?;
        self.sync(py, ops::cp_files(self.fs(), srcs, dsts, oe, batch_size))
    }

    /// Awaitable `cp_files`.
    #[pyo3(signature = (srcs, dsts, on_error="raise", batch_size=None))]
    fn cp_files_async<'py>(
        &self,
        py: Python<'py>,
        srcs: Vec<String>,
        dsts: Vec<String>,
        on_error: &str,
        batch_size: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let oe = self::on_error(py, on_error)?;
        self.spawn(py, ops::cp_files(self.fs(), srcs, dsts, oe, batch_size))
    }

    /// Move one path to the exact destination (atomic rename where the
    /// backend supports it).
    fn mv_file<'py>(
        &self,
        py: Python<'py>,
        src: String,
        dst: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.sync(py, ops::mv_file(self.fs(), src, dst))
    }

    /// Awaitable `mv_file`.
    fn mv_file_async<'py>(
        &self,
        py: Python<'py>,
        src: String,
        dst: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.spawn(py, ops::mv_file(self.fs(), src, dst))
    }

    /// `mv_file` for many pairs, concurrently.
    #[pyo3(signature = (srcs, dsts, on_error="raise", batch_size=None))]
    fn mv_files<'py>(
        &self,
        py: Python<'py>,
        srcs: Vec<String>,
        dsts: Vec<String>,
        on_error: &str,
        batch_size: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let oe = self::on_error(py, on_error)?;
        self.sync(py, ops::mv_files(self.fs(), srcs, dsts, oe, batch_size))
    }

    /// Awaitable `mv_files`.
    #[pyo3(signature = (srcs, dsts, on_error="raise", batch_size=None))]
    fn mv_files_async<'py>(
        &self,
        py: Python<'py>,
        srcs: Vec<String>,
        dsts: Vec<String>,
        on_error: &str,
        batch_size: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let oe = self::on_error(py, on_error)?;
        self.spawn(py, ops::mv_files(self.fs(), srcs, dsts, oe, batch_size))
    }

    // ---- local transfers --------------------------------------------------

    /// Upload a local file (a local directory becomes a directory).
    #[pyo3(signature = (lpath, rpath, mode="overwrite"))]
    fn put_file<'py>(
        &self,
        py: Python<'py>,
        lpath: PathBuf,
        rpath: String,
        mode: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let m = self::mode(py, mode)?;
        self.sync(py, ops::put_file(self.fs(), lpath, rpath, m))
    }

    /// Awaitable `put_file`.
    #[pyo3(signature = (lpath, rpath, mode="overwrite"))]
    fn put_file_async<'py>(
        &self,
        py: Python<'py>,
        lpath: PathBuf,
        rpath: String,
        mode: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let m = self::mode(py, mode)?;
        self.spawn(py, ops::put_file(self.fs(), lpath, rpath, m))
    }

    /// `put_file` for many pairs, concurrently.
    #[pyo3(signature = (lpaths, rpaths, mode="overwrite", on_error="raise", batch_size=None))]
    fn put_files<'py>(
        &self,
        py: Python<'py>,
        lpaths: Vec<PathBuf>,
        rpaths: Vec<String>,
        mode: &str,
        on_error: &str,
        batch_size: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let m = self::mode(py, mode)?;
        let oe = self::on_error(py, on_error)?;
        self.sync(
            py,
            ops::put_files(self.fs(), lpaths, rpaths, m, oe, batch_size),
        )
    }

    /// Awaitable `put_files`.
    #[pyo3(signature = (lpaths, rpaths, mode="overwrite", on_error="raise", batch_size=None))]
    fn put_files_async<'py>(
        &self,
        py: Python<'py>,
        lpaths: Vec<PathBuf>,
        rpaths: Vec<String>,
        mode: &str,
        on_error: &str,
        batch_size: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let m = self::mode(py, mode)?;
        let oe = self::on_error(py, on_error)?;
        self.spawn(
            py,
            ops::put_files(self.fs(), lpaths, rpaths, m, oe, batch_size),
        )
    }

    /// Download to a local file (a remote directory becomes a directory).
    fn get_file<'py>(
        &self,
        py: Python<'py>,
        rpath: String,
        lpath: PathBuf,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.sync(py, ops::get_file(self.fs(), rpath, lpath))
    }

    /// Awaitable `get_file`.
    fn get_file_async<'py>(
        &self,
        py: Python<'py>,
        rpath: String,
        lpath: PathBuf,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.spawn(py, ops::get_file(self.fs(), rpath, lpath))
    }

    /// `get_file` for many pairs, concurrently.
    #[pyo3(signature = (rpaths, lpaths, on_error="raise", batch_size=None))]
    fn get_files<'py>(
        &self,
        py: Python<'py>,
        rpaths: Vec<String>,
        lpaths: Vec<PathBuf>,
        on_error: &str,
        batch_size: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let oe = self::on_error(py, on_error)?;
        self.sync(
            py,
            ops::get_files(self.fs(), rpaths, lpaths, oe, batch_size),
        )
    }

    /// Awaitable `get_files`.
    #[pyo3(signature = (rpaths, lpaths, on_error="raise", batch_size=None))]
    fn get_files_async<'py>(
        &self,
        py: Python<'py>,
        rpaths: Vec<String>,
        lpaths: Vec<PathBuf>,
        on_error: &str,
        batch_size: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let oe = self::on_error(py, on_error)?;
        self.spawn(
            py,
            ops::get_files(self.fs(), rpaths, lpaths, oe, batch_size),
        )
    }

    // ---- misc -------------------------------------------------------------

    /// Pre-signed URL valid for `expiration` seconds.
    #[pyo3(signature = (path, expiration=100.0))]
    fn sign<'py>(
        &self,
        py: Python<'py>,
        path: String,
        expiration: f64,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.sync(py, ops::sign(self.fs(), path, expiration))
    }

    /// Awaitable `sign`.
    #[pyo3(signature = (path, expiration=100.0))]
    fn sign_async<'py>(
        &self,
        py: Python<'py>,
        path: String,
        expiration: f64,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.spawn(py, ops::sign(self.fs(), path, expiration))
    }

    /// Drop cached listings/metadata for `path` (and parents), or all.
    #[pyo3(signature = (path=None))]
    fn invalidate_cache(&self, py: Python<'_>, path: Option<&str>) -> PyResult<()> {
        raise(py, self.inner.fs())?.invalidate_cache(path);
        Ok(())
    }

    /// Release pooled connections (the filesystem stays usable).
    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.sync(py, ops::close(self.fs()))
    }

    /// Awaitable `close`.
    fn close_async<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.spawn(py, ops::close(self.fs()))
    }

    /// Request counters and latency quantiles of this instance:
    /// `{"requests", "errors", "bytes_read", "bytes_written", "retries",
    /// "throttles", "ops": {kind: {"count", "mean_us", "p50_us", "p90_us",
    /// "p99_us", "max_us"}}}`.
    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let s = self.inner.stats.snapshot();
        let d = PyDict::new(py);
        d.set_item("requests", s.requests)?;
        d.set_item("errors", s.errors)?;
        d.set_item("bytes_read", s.bytes_read)?;
        d.set_item("bytes_written", s.bytes_written)?;
        d.set_item("retries", s.retries)?;
        d.set_item("throttles", s.throttles)?;
        let ops = PyDict::new(py);
        let us = |x: Option<std::time::Duration>| x.map(|d| d.as_secs_f64() * 1e6);
        for op in OpKind::ALL {
            let h = s.latency(op);
            if h.count == 0 {
                continue;
            }
            let e = PyDict::new(py);
            e.set_item("count", h.count)?;
            e.set_item("mean_us", us(h.mean()))?;
            e.set_item("p50_us", us(h.quantile(0.5)))?;
            e.set_item("p90_us", us(h.quantile(0.9)))?;
            e.set_item("p99_us", us(h.quantile(0.99)))?;
            e.set_item("max_us", us(h.max()))?;
            ops.set_item(op.as_str(), e)?;
        }
        d.set_item("ops", ops)?;
        Ok(d)
    }

    /// Zero the counters returned by `stats()`.
    fn reset_stats(&self) {
        self.inner.stats.reset();
    }

    fn __repr__(&self) -> String {
        format!("<fsfast RustFileSystem {:?}>", self.inner.protocol)
    }

    /// Pickle as `make_filesystem(protocol, options)` (a fresh backend;
    /// state of an isolated memory store is not carried over).
    fn __reduce__<'py>(&self, py: Python<'py>) -> PyResult<Reduced<'py>> {
        let f = py.import("fsfast._core")?.getattr("make_filesystem")?;
        Ok((
            f,
            (
                self.inner.protocol.clone(),
                options_to_py(py, &self.inner.options)?,
            ),
        ))
    }
}

/// Build the Rust filesystem for `protocol` from `options` (the backend's
/// fsspec-compatible `storage_options`; unknown options are a `ValueError`).
#[pyfunction]
#[pyo3(signature = (protocol, options=None))]
pub(crate) fn make_filesystem(
    py: Python<'_>,
    protocol: &str,
    options: Option<&Bound<'_, PyDict>>,
) -> PyResult<RustFileSystem> {
    let opts = options_from_py(options)?;
    let protocol = protocol.to_owned();
    let slot = crate::runtime::runtime();
    // Building may do I/O (credential discovery, ...): release the
    // interpreter, and enter the runtime in case the backend spawns tasks.
    let r: std::result::Result<RustFileSystem, Error> = py.detach(move || {
        let _ctx = slot.handle().enter();
        RustFileSystem::create(&protocol, opts)
    });
    raise(py, r)
}
