//! Conversions between fsfast's Rust types and Python objects.
//!
//! * [`Value`] ⇄ Python (`Time` ⇄ timezone-aware UTC `datetime`, nested
//!   lists and dicts).
//! * [`FileInfo`] → the fsspec `info()` dict `{"name", "size", "type",
//!   **extra}`, with the extra keys in the reference implementation's order
//!   (see [`crate::registry::Backend::layouts`]).
//! * `storage_options` dicts → [`Options`].
//! * Byte buffers: results are built straight into a Python `bytes` object
//!   (one copy from the backend's buffer, with the interpreter released for
//!   large copies); `bytes` arguments are wrapped without copying.

use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use fsfast_core::{FileInfo, FileType, Options, Value};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::types::{
    PyBool, PyByteArray, PyBytes, PyDateTime, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple,
    PyTzInfo,
};

use crate::buffer::ReadSource;
use crate::registry::Backend;

/// Copies at least this large are done with the interpreter released.
const DETACHED_COPY_MIN: usize = 1 << 20;

/// `bytes` arguments at least this large are wrapped instead of copied.
const ZERO_COPY_MIN: usize = 16 << 10;

/// Days since 1970-01-01 → (year, month, day) in the proleptic Gregorian
/// calendar (Howard Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u8, u8) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Nanoseconds since the Unix epoch (negative before it).
fn epoch_nanos(t: SystemTime) -> i128 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    }
}

/// A timezone-aware UTC `datetime` for `t`, exact to the microsecond
/// (truncated towards the past, like `datetime.fromtimestamp`'s floor of
/// integer nanoseconds), without going through a float timestamp.
pub(crate) fn time_to_py(py: Python<'_>, t: SystemTime) -> PyResult<Bound<'_, PyAny>> {
    let ns = epoch_nanos(t);
    let micros_total = ns.div_euclid(1_000);
    let secs = micros_total.div_euclid(1_000_000);
    let micros = micros_total.rem_euclid(1_000_000) as u32;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400) as u32;
    let days = i64::try_from(days).map_err(|_| PyValueError::new_err("time out of range"))?;
    let (y, m, d) = civil_from_days(days);
    let y = i32::try_from(y).map_err(|_| PyValueError::new_err("year out of range"))?;
    let utc = PyTzInfo::utc(py)?;
    Ok(PyDateTime::new(
        py,
        y,
        m,
        d,
        (sod / 3600) as u8,
        ((sod / 60) % 60) as u8,
        (sod % 60) as u8,
        micros,
        Some(&utc),
    )?
    .into_any())
}

/// A `datetime` → `SystemTime` (naive datetimes are local time, as
/// `datetime.timestamp()` assumes).
fn time_from_py(obj: &Bound<'_, PyAny>) -> PyResult<SystemTime> {
    let ts: f64 = obj
        .call_method0(pyo3::intern!(obj.py(), "timestamp"))?
        .extract()?;
    if !ts.is_finite() {
        return Err(PyValueError::new_err("invalid datetime"));
    }
    let d = std::time::Duration::from_secs_f64(ts.abs());
    Ok(if ts >= 0.0 {
        UNIX_EPOCH + d
    } else {
        UNIX_EPOCH - d
    })
}

/// [`Value`] → Python.
pub(crate) fn value_to_py<'py>(py: Python<'py>, v: &Value) -> PyResult<Bound<'py, PyAny>> {
    Ok(match v {
        Value::Null => py.None().into_bound(py),
        Value::Bool(b) => PyBool::new(py, *b).to_owned().into_any(),
        Value::Int(i) => i.into_pyobject(py)?.into_any(),
        Value::Float(f) => PyFloat::new(py, *f).into_any(),
        Value::Str(s) => PyString::new(py, s).into_any(),
        Value::Bytes(b) => PyBytes::new(py, b).into_any(),
        Value::Time(t) => time_to_py(py, *t)?,
        Value::List(l) => {
            let items = l
                .iter()
                .map(|x| value_to_py(py, x))
                .collect::<PyResult<Vec<_>>>()?;
            PyList::new(py, items)?.into_any()
        }
        Value::Map(m) => {
            let d = PyDict::new(py);
            for (k, x) in m {
                d.set_item(k, value_to_py(py, x)?)?;
            }
            d.into_any()
        }
        // `Value` may grow variants; render unknown ones as their debug form.
        #[allow(unreachable_patterns)]
        other => PyString::new(py, &format!("{other:?}")).into_any(),
    })
}

/// Python → [`Value`] (for `storage_options`).
pub(crate) fn py_to_value(obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    let py = obj.py();
    if obj.is_none() {
        return Ok(Value::Null);
    }
    // bool before int: `True` is an `int` in Python.
    if let Ok(b) = obj.cast::<PyBool>() {
        return Ok(Value::Bool(b.is_true()));
    }
    if obj.is_instance_of::<PyInt>() {
        return obj
            .extract::<i64>()
            .map(Value::Int)
            .map_err(|_| PyValueError::new_err(format!("integer option out of range: {obj}")));
    }
    if let Ok(f) = obj.cast::<PyFloat>() {
        return Ok(Value::Float(f.value()));
    }
    if let Ok(s) = obj.cast::<PyString>() {
        return Ok(Value::Str(s.to_str()?.to_owned()));
    }
    if let Ok(b) = obj.cast::<PyBytes>() {
        return Ok(Value::Bytes(b.as_bytes().to_vec()));
    }
    if let Ok(b) = obj.cast::<PyByteArray>() {
        return Ok(Value::Bytes(b.to_vec()));
    }
    if let Ok(d) = obj.cast::<PyDict>() {
        let mut m = Options::new();
        for (k, v) in d.iter() {
            let key: String = k.extract().map_err(|_| {
                PyTypeError::new_err(format!(
                    "option dict keys must be str, got {}",
                    k.get_type()
                ))
            })?;
            m.insert(key, py_to_value(&v)?);
        }
        return Ok(Value::Map(m));
    }
    if obj.is_instance_of::<PyList>() || obj.is_instance_of::<PyTuple>() {
        let items = obj
            .try_iter()?
            .map(|x| py_to_value(&x?))
            .collect::<PyResult<Vec<_>>>()?;
        return Ok(Value::List(items));
    }
    if obj.is_instance_of::<PyDateTime>() {
        return Ok(Value::Time(time_from_py(obj)?));
    }
    if obj.hasattr(pyo3::intern!(py, "__fspath__"))? {
        let p = py.import("os")?.getattr("fspath")?.call1((obj,))?;
        return py_to_value(&p);
    }
    Err(PyTypeError::new_err(format!(
        "unsupported option value of type {}",
        obj.get_type()
    )))
}

/// A `storage_options` dict → [`Options`].
pub(crate) fn options_from_py(obj: Option<&Bound<'_, PyDict>>) -> PyResult<Options> {
    let mut out = Options::new();
    if let Some(d) = obj {
        for (k, v) in d.iter() {
            let key: String = k.extract().map_err(|_| {
                PyTypeError::new_err(format!("option names must be str, got {}", k.get_type()))
            })?;
            out.insert(key, py_to_value(&v)?);
        }
    }
    Ok(out)
}

/// [`Options`] → a Python dict (for `RustFileSystem.options` and pickling).
pub(crate) fn options_to_py<'py>(py: Python<'py>, opts: &Options) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    for (k, v) in opts {
        d.set_item(k, value_to_py(py, v)?)?;
    }
    Ok(d)
}

fn type_str(py: Python<'_>, t: FileType) -> &Bound<'_, PyString> {
    match t {
        FileType::File => pyo3::intern!(py, "file"),
        FileType::Directory => pyo3::intern!(py, "directory"),
        FileType::Symlink => pyo3::intern!(py, "link"),
        FileType::Other => pyo3::intern!(py, "other"),
    }
}

/// [`FileInfo`] → the fsspec info dict, keys in the reference
/// implementation's order (see [`Backend::layouts`]): `name`, `size` and
/// `type` first unless the layout places them, then the layout's keys, then
/// any other extra keys (sorted). An extra key named `name`, `size` or
/// `type` overrides the core field (SMB directory names with a trailing
/// slash, Azure's `size: None` for directories).
pub(crate) fn info_to_py<'py>(
    py: Python<'py>,
    info: &FileInfo,
    backend: &Backend,
) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    let (layout, keys) = backend.layout(py, info);
    let core = |d: &Bound<'py, PyDict>, name: &str| -> PyResult<()> {
        let key = match name {
            "name" => pyo3::intern!(py, "name"),
            "size" => pyo3::intern!(py, "size"),
            _ => pyo3::intern!(py, "type"),
        };
        if let Some(v) = info.extra.get(name) {
            return d.set_item(key, value_to_py(py, v)?);
        }
        match name {
            "name" => d.set_item(key, PyString::new(py, &info.name)),
            "size" => d.set_item(key, info.size),
            _ => d.set_item(key, type_str(py, info.file_type)),
        }
    };
    for name in ["name", "size", "type"] {
        if !layout.contains(&name) {
            core(&d, name)?;
        }
    }
    let mut done = 0;
    for (name, key) in layout.iter().zip(keys) {
        match *name {
            "name" | "size" | "type" => core(&d, name)?,
            _ => {
                if let Some(v) = info.extra.get(*name) {
                    d.set_item(key.bind(py), value_to_py(py, v)?)?;
                    done += 1;
                }
            }
        }
    }
    let is_core = |k: &str| matches!(k, "name" | "size" | "type");
    let overrides = info.extra.keys().filter(|k| is_core(k)).count();
    if done + overrides < info.extra.len() {
        for (k, v) in &info.extra {
            if !is_core(k) && !layout.contains(&k.as_str()) {
                d.set_item(k, value_to_py(py, v)?)?;
            }
        }
    }
    Ok(d)
}

/// Copies of at least this many bytes are split across threads: a fresh
/// buffer of that size costs as much in page faults as in copying, and one
/// thread cannot saturate memory bandwidth.
const PARALLEL_COPY_MIN: usize = 32 << 20;

/// Work per thread for parallel copies and fills.
const PARALLEL_CHUNK: usize = 16 << 20;

/// Run `f(offset, len)` over `[0, total)` in chunks, on several threads when
/// `total` is large (scoped threads, so `f` may borrow).
fn par_chunks(total: usize, f: impl Fn(usize, usize) + Sync) {
    if total < PARALLEL_COPY_MIN {
        f(0, total);
        return;
    }
    let threads = std::thread::available_parallelism()
        .map_or(4, |n| n.get())
        .clamp(2, 8)
        .min(total.div_ceil(PARALLEL_CHUNK));
    let per = total.div_ceil(threads);
    std::thread::scope(|scope| {
        for t in 1..threads {
            let (off, f) = (t * per, &f);
            if off < total {
                scope.spawn(move || f(off, per.min(total - off)));
            }
        }
        f(0, per.min(total));
    });
}

/// A new, uninitialised Python `bytes` object of `len` bytes and a raw
/// pointer to its buffer. The caller must initialise every byte before the
/// object is used (or dropped back into Python code).
fn alloc_bytes(py: Python<'_>, len: usize) -> PyResult<(Bound<'_, PyBytes>, usize)> {
    // SAFETY: PyBytes_FromStringAndSize(NULL, n) returns a new, uninitialised
    // bytes object of length n (or NULL with an exception set); filling its
    // buffer before anyone else sees the object is the documented C-API
    // pattern. We hold the only reference.
    unsafe {
        let ptr = ffi::PyBytes_FromStringAndSize(std::ptr::null(), len as ffi::Py_ssize_t);
        let obj = Bound::from_owned_ptr_or_err(py, ptr)?.cast_into_unchecked::<PyBytes>();
        let buf = ffi::PyBytes_AsString(obj.as_ptr()) as usize;
        Ok((obj, buf))
    }
}

/// A new Python `bytes` holding a copy of `data`.
///
/// Large copies skip `PyBytes::new_with`'s zero-fill, run with the
/// interpreter released (the new object is not yet visible to anyone) and,
/// above [`PARALLEL_COPY_MIN`], on several threads.
pub(crate) fn bytes_to_py<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    if data.len() < DETACHED_COPY_MIN {
        return Ok(PyBytes::new(py, data));
    }
    let (obj, dst) = alloc_bytes(py, data.len())?;
    let src = data.as_ptr() as usize;
    py.detach(|| {
        par_chunks(data.len(), |off, n| {
            // SAFETY: `src` and `dst` point to `data.len()` bytes each, the
            // chunks are disjoint, and `dst` is the new object's buffer that
            // only this call writes. Raw pointers avoid references to the
            // not-yet-initialised destination.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    (src as *const u8).add(off),
                    (dst as *mut u8).add(off),
                    n,
                )
            }
        });
    });
    Ok(obj)
}

/// A new, zero-filled Python `bytes` of `len` bytes to be filled in place
/// (e.g. by a read straight into it). Returns the object and its buffer;
/// the buffer must only be written before the object is handed to Python.
/// Large fills run detached and on several threads (that is also where the
/// page faults of the fresh buffer are taken).
pub(crate) fn zeroed_bytes(py: Python<'_>, len: usize) -> PyResult<(Bound<'_, PyBytes>, BytesBuf)> {
    let (obj, dst) = alloc_bytes(py, len)?;
    py.detach(|| {
        par_chunks(len, |off, n| {
            // SAFETY: disjoint chunks of the new object's `len`-byte buffer.
            unsafe { std::ptr::write_bytes((dst as *mut u8).add(off), 0, n) }
        });
    });
    Ok((obj, BytesBuf { ptr: dst, len }))
}

/// The (initialised) buffer of a `bytes` object created by
/// [`zeroed_bytes`], writable until the object is handed to Python.
pub(crate) struct BytesBuf {
    ptr: usize,
    len: usize,
}

impl BytesBuf {
    /// The buffer.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: the buffer belongs to a live bytes object owned by the
        // caller (see `zeroed_bytes`), is fully initialised (zero-filled),
        // and `&mut self` makes this the only access.
        unsafe { std::slice::from_raw_parts_mut(self.ptr as *mut u8, self.len) }
    }
}

/// Keeps a Python `bytes` object alive as the owner of a [`Bytes`] view.
struct PyBytesOwner {
    _obj: Py<PyBytes>,
    ptr: *const u8,
    len: usize,
}

// SAFETY: `bytes` objects are immutable and their buffer stays valid while
// `_obj` holds a reference; `Py<T>` may be moved and dropped on any thread
// (PyO3 defers the decref until the interpreter is attached).
unsafe impl Send for PyBytesOwner {}
// SAFETY: shared access only reads immutable memory.
unsafe impl Sync for PyBytesOwner {}

impl AsRef<[u8]> for PyBytesOwner {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: see the `Send` impl; `ptr`/`len` describe the object's data.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

/// The bytes of a Python object as [`Bytes`]: large `bytes` objects are
/// wrapped without copying (they are immutable); anything else supporting
/// the buffer protocol is copied once, with the interpreter released for
/// large buffers (the export keeps the memory alive and unresizable; a
/// concurrent mutation by another thread is the caller's race, as with
/// `hashlib`, which does the same).
pub(crate) fn bytes_from_py(obj: &Bound<'_, PyAny>) -> PyResult<Bytes> {
    if let Ok(b) = obj.cast::<PyBytes>() {
        let data = b.as_bytes();
        if data.len() < ZERO_COPY_MIN {
            return Ok(Bytes::copy_from_slice(data));
        }
        return Ok(Bytes::from_owner(PyBytesOwner {
            ptr: data.as_ptr(),
            len: data.len(),
            _obj: b.clone().unbind(),
        }));
    }
    if obj.is_instance_of::<PyString>() {
        return Err(PyTypeError::new_err(
            "a bytes-like object is required, not 'str'",
        ));
    }
    let src = ReadSource::new(obj)?;
    let data = src.as_slice();
    if data.len() >= DETACHED_COPY_MIN {
        return Ok(obj.py().detach(|| Bytes::copy_from_slice(data)));
    }
    Ok(Bytes::copy_from_slice(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(-719_162), (1, 1, 1));
    }

    #[test]
    fn times_round_trip_exactly() {
        Python::attach(|py| {
            let datetime = py.import("datetime").unwrap();
            let utc = datetime
                .getattr("timezone")
                .unwrap()
                .getattr("utc")
                .unwrap();
            for ns in [
                0i128,
                1,
                999,
                1_000,
                1_700_000_000_123_456_789,
                -1,
                -1_000_001,
                -86_400_000_000_000,
            ] {
                let t = if ns >= 0 {
                    UNIX_EPOCH + Duration::from_nanos(ns as u64)
                } else {
                    UNIX_EPOCH - Duration::from_nanos((-ns) as u64)
                };
                let dt = time_to_py(py, t).unwrap();
                // Reference: epoch + timedelta(microseconds=floor(ns / 1000)).
                let us = ns.div_euclid(1000) as i64;
                let td = datetime
                    .getattr("timedelta")
                    .unwrap()
                    .call1((0, 0, us))
                    .unwrap();
                let epoch = datetime
                    .getattr("datetime")
                    .unwrap()
                    .call1((1970, 1, 1, 0, 0, 0, 0, &utc))
                    .unwrap();
                let expected = epoch.add(td).unwrap();
                assert!(dt.eq(&expected).unwrap(), "{ns}: {dt} != {expected}");
                assert!(!dt.getattr("tzinfo").unwrap().is_none());
            }
        });
    }

    #[test]
    fn values_round_trip() {
        Python::attach(|py| {
            let mut m = Options::new();
            m.insert("a".into(), Value::Int(-5));
            m.insert(
                "b".into(),
                Value::List(vec![Value::Bool(true), Value::Null]),
            );
            m.insert("c".into(), Value::Str("x".into()));
            m.insert("d".into(), Value::Float(1.5));
            m.insert("e".into(), Value::Bytes(b"raw".to_vec()));
            let v = Value::Map(m);
            let obj = value_to_py(py, &v).unwrap();
            assert_eq!(py_to_value(&obj).unwrap(), v);
            // Tuples become lists; bools stay bools.
            let t = PyTuple::new(py, [true, false]).unwrap();
            assert_eq!(
                py_to_value(t.as_any()).unwrap(),
                Value::List(vec![Value::Bool(true), Value::Bool(false)])
            );
            // Unsupported types and non-str keys are errors.
            assert!(py_to_value(&py.eval(c"object()", None, None).unwrap()).is_err());
            assert!(py_to_value(&py.eval(c"{1: 2}", None, None).unwrap()).is_err());
            assert!(py_to_value(&py.eval(c"2**80", None, None).unwrap()).is_err());
            // Path-likes become strings.
            let p = py
                .eval(c"__import__('pathlib').PurePosixPath('/a/b')", None, None)
                .unwrap();
            assert_eq!(py_to_value(&p).unwrap(), Value::Str("/a/b".into()));
        });
    }

    #[test]
    fn bytes_conversions() {
        Python::attach(|py| {
            let big = vec![7u8; DETACHED_COPY_MIN + 3];
            let b = bytes_to_py(py, &big).unwrap();
            assert_eq!(b.as_bytes(), &big[..]);
            // Parallel copy: distinct content per chunk, odd length.
            let huge: Vec<u8> = (0..PARALLEL_COPY_MIN + 12_345)
                .map(|i| (i % 251) as u8)
                .collect();
            let b = bytes_to_py(py, &huge).unwrap();
            assert_eq!(b.as_bytes(), &huge[..]);
            let (z, mut buf) = zeroed_bytes(py, PARALLEL_COPY_MIN + 7).unwrap();
            assert!(z.as_bytes().iter().all(|&x| x == 0));
            buf.as_mut_slice()[3] = 9;
            assert_eq!(z.as_bytes()[3], 9);
            let small = bytes_to_py(py, b"abc").unwrap();
            assert_eq!(small.as_bytes(), b"abc");

            // Large bytes are wrapped without copying.
            let src = PyBytes::new(py, &vec![1u8; ZERO_COPY_MIN]);
            let wrapped = bytes_from_py(src.as_any()).unwrap();
            assert_eq!(wrapped.as_ptr(), src.as_bytes().as_ptr());
            drop(wrapped);
            let ba = PyByteArray::new(py, b"xyz");
            assert_eq!(bytes_from_py(ba.as_any()).unwrap(), &b"xyz"[..]);
            // Large mutable buffers are copied (detached), not borrowed.
            let big: Vec<u8> = (0..DETACHED_COPY_MIN + 5)
                .map(|i| (i % 253) as u8)
                .collect();
            let ba = PyByteArray::new(py, &big);
            let copied = bytes_from_py(ba.as_any()).unwrap();
            assert_eq!(&copied[..], &big[..]);
            // SAFETY: no other reference to `ba` exists in this test.
            unsafe { ba.as_bytes_mut()[0] ^= 0xff };
            assert_eq!(copied[0], big[0]);
            let mv = py.eval(c"memoryview(b'hello')[1:3]", None, None).unwrap();
            assert_eq!(bytes_from_py(&mv).unwrap(), &b"el"[..]);
            assert!(bytes_from_py(PyString::new(py, "s").as_any()).is_err());
        });
    }
}
