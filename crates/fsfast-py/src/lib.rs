//! `fsfast._core`: the PyO3 extension module behind fsfast's
//! fsspec-compatible Python classes (docs/PLAN.md §4.4).
//!
//! The data path is Rust end to end. Python's fsspec classes
//! (`python/fsfast/`) are thin shells: every public sync method calls a
//! [`RustFileSystem`] method that releases the interpreter and drives the
//! Rust future directly on the calling thread (no `fsspec.asyn.sync()`, no
//! event-loop hop), and every async `_method` awaits an asyncio future
//! produced through `pyo3-async-runtimes`. File objects ([`RustReader`],
//! [`RustWriter`]) wrap the engine's readahead reader and a buffered write
//! handle, so `read`/`readinto`/`write` never go through Python caches.
//!
//! Module layout:
//! * `runtime` — the process-wide tokio runtime, fork safety, the sync
//!   (`block_on` with signal checks) and async bridges.
//! * `registry` — compiled-in backends and `make_filesystem`.
//! * `filesystem` / `ops` — `RustFileSystem` and its operations.
//! * `file` — `RustReader` / `RustWriter`.
//! * `convert`, `buffer`, `errors`, `out` — conversions, the buffer
//!   protocol, exception mapping and result conversion.
//!
//! The module is declared free-threading safe (`gil_used = false`): all
//! state is `Send + Sync`, pyclasses are `frozen` with interior mutexes that
//! are only locked while detached from the interpreter.

#![warn(missing_docs)]

mod buffer;
mod convert;
mod errors;
mod file;
mod filesystem;
mod ops;
mod out;
mod registry;
mod runtime;

use pyo3::prelude::*;
use pyo3::types::PyDict;

pub use errors::PreconditionFailed;
pub use file::{LineIter, RustReader, RustWriter};
pub use filesystem::RustFileSystem;

/// Protocol names served by the backends compiled into this build.
#[pyfunction]
fn available_protocols() -> Vec<&'static str> {
    registry::available()
}

/// Diagnostics about the shared runtime: `{"pid", "workers",
/// "alive_tasks"}` (builds the runtime if needed).
#[pyfunction]
fn runtime_info(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let slot = runtime::runtime();
    let m = slot.handle().metrics();
    let d = PyDict::new(py);
    d.set_item("pid", slot.pid())?;
    d.set_item("workers", m.num_workers())?;
    d.set_item("alive_tasks", m.num_alive_tasks())?;
    Ok(d)
}

/// Fork hook (`os.register_at_fork(after_in_child=...)`): abandon the
/// parent's runtime so the child builds its own on next use.
#[pyfunction]
fn _after_fork_child() {
    runtime::after_fork_child();
}

/// Register [`_after_fork_child`] with `os.register_at_fork` where the
/// platform supports forking.
fn register_fork_hook(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    let os = py.import("os")?;
    if let Ok(register) = os.getattr("register_at_fork") {
        let hook = m.getattr("_after_fork_child")?;
        let kwargs = PyDict::new(py);
        kwargs.set_item("after_in_child", hook)?;
        register.call((), Some(&kwargs))?;
    }
    Ok(())
}

/// The `fsfast._core` module.
#[pymodule(gil_used = false)]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    errors::init(py)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<RustFileSystem>()?;
    m.add_class::<RustReader>()?;
    m.add_class::<RustWriter>()?;
    m.add_class::<LineIter>()?;
    m.add("PreconditionFailed", py.get_type::<PreconditionFailed>())?;
    m.add_function(wrap_pyfunction!(filesystem::make_filesystem, m)?)?;
    m.add_function(wrap_pyfunction!(available_protocols, m)?)?;
    m.add_function(wrap_pyfunction!(runtime_info, m)?)?;
    m.add_function(wrap_pyfunction!(_after_fork_child, m)?)?;
    register_fork_hook(m)?;
    Ok(())
}
