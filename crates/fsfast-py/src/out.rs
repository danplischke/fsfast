//! [`PyOut`]: results of filesystem operations, produced without the
//! interpreter and converted to Python objects once it is attached.
//!
//! Every operation is written once as a future returning
//! `Result<PyOut, fsfast_core::Error>`. The sync API drives it with
//! [`crate::runtime::block_on`] and converts the result; the async API hands
//! it to `pyo3-async-runtimes` wrapped in [`Converted`], whose
//! `IntoPyObject` impl runs on completion (with the interpreter attached)
//! and turns an `Err` into the matching Python exception.

use std::sync::Arc;

use bytes::Bytes;
use fsfast_core::{Error, FileInfo};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};

use crate::convert::{bytes_to_py, info_to_py, time_to_py, value_to_py};
use crate::errors::{to_exception, to_pyerr};
use crate::file::{RustReader, RustWriter};
use crate::registry::Backend;

/// One item of a batch result: a value, or the error of that item (shared,
/// because one failure can affect several items, e.g. all ranges of a file).
pub(crate) type Item = std::result::Result<PyOut, Arc<Error>>;

/// A result waiting to be converted to Python.
pub(crate) enum PyOut {
    /// `None`.
    None,
    /// `bool`.
    Bool(bool),
    /// `str`.
    Str(String),
    /// `bytes`.
    Bytes(Bytes),
    /// One info dict.
    Info(Box<FileInfo>),
    /// A list of info dicts.
    InfoList(Vec<FileInfo>),
    /// A dict `{name: info}` (fsspec `find(detail=True)`).
    InfoMap(Vec<FileInfo>),
    /// A list of names.
    Names(Vec<String>),
    /// A list of per-item results; failed items become exception instances.
    Items(Vec<Item>),
    /// `(modified, created)` as timezone-aware datetimes (or `None`).
    Times(Option<std::time::SystemTime>, Option<std::time::SystemTime>),
    /// A file opened for reading.
    Reader(Box<RustReader>),
    /// A file opened for writing.
    Writer(Box<RustWriter>),
    /// Any other value (backend-specific methods).
    Value(fsfast_core::Value),
}

impl PyOut {
    /// Convert to a Python object.
    pub(crate) fn into_py<'py>(
        self,
        py: Python<'py>,
        backend: &Backend,
    ) -> PyResult<Bound<'py, PyAny>> {
        Ok(match self {
            PyOut::None => py.None().into_bound(py),
            PyOut::Bool(b) => pyo3::types::PyBool::new(py, b).to_owned().into_any(),
            PyOut::Str(s) => PyString::new(py, &s).into_any(),
            PyOut::Bytes(b) => bytes_to_py(py, &b)?.into_any(),
            PyOut::Info(i) => info_to_py(py, &i, backend)?.into_any(),
            PyOut::InfoList(v) => {
                let items = v
                    .iter()
                    .map(|i| info_to_py(py, i, backend))
                    .collect::<PyResult<Vec<_>>>()?;
                PyList::new(py, items)?.into_any()
            }
            PyOut::InfoMap(v) => {
                let d = PyDict::new(py);
                for i in &v {
                    d.set_item(PyString::new(py, &i.name), info_to_py(py, i, backend)?)?;
                }
                d.into_any()
            }
            PyOut::Names(v) => PyList::new(py, v.iter().map(|s| PyString::new(py, s)))?.into_any(),
            PyOut::Items(v) => {
                let list = PyList::empty(py);
                for item in v {
                    match item {
                        Ok(x) => list.append(x.into_py(py, backend)?)?,
                        Err(e) => list.append(to_exception(py, &e))?,
                    }
                }
                list.into_any()
            }
            PyOut::Times(m, c) => {
                let conv = |t: Option<std::time::SystemTime>| -> PyResult<Bound<'py, PyAny>> {
                    match t {
                        Some(t) => time_to_py(py, t),
                        None => Ok(py.None().into_bound(py)),
                    }
                };
                pyo3::types::PyTuple::new(py, [conv(m)?, conv(c)?])?.into_any()
            }
            PyOut::Reader(r) => Bound::new(py, *r)?.into_any(),
            PyOut::Writer(w) => Bound::new(py, *w)?.into_any(),
            PyOut::Value(v) => value_to_py(py, &v)?,
        })
    }
}

/// Convert an operation's outcome, raising its error.
pub(crate) fn convert<'py>(
    py: Python<'py>,
    out: Result<PyOut, Error>,
    backend: &Backend,
) -> PyResult<Bound<'py, PyAny>> {
    match out {
        Ok(v) => v.into_py(py, backend),
        Err(e) => Err(to_pyerr(py, &e)),
    }
}

/// An operation's outcome travelling back to asyncio; converted (or raised)
/// when `pyo3-async-runtimes` resolves the Python future.
pub(crate) struct Converted {
    pub out: Result<PyOut, Error>,
    pub backend: &'static Backend,
}

impl<'py> IntoPyObject<'py> for Converted {
    type Target = PyAny;
    type Output = Bound<'py, PyAny>;
    type Error = PyErr;

    fn into_pyobject(self, py: Python<'py>) -> PyResult<Self::Output> {
        convert(py, self.out, self.backend)
    }
}
