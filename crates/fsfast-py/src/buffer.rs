//! Access to Python buffer-protocol objects (`bytearray`, `memoryview`,
//! `array.array`, NumPy arrays, ...) without intermediate copies.
//!
//! The wheel targets the stable ABI for CPython 3.10+ (`abi3-py310`), whose
//! limited API only gained the buffer protocol in 3.11, so PyO3's `PyBuffer`
//! is unavailable. `PyObject_GetBuffer`/`PyBuffer_Release` and the
//! `Py_buffer` layout have nevertheless been exported and unchanged since
//! CPython 3.3 (the layout is frozen in the 3.11 stable ABI), and on Unix an
//! extension resolves them from the running interpreter at load time, so this
//! module declares them itself. On Windows an abi3 module links against
//! `python3.dll`, which only exports them from 3.11, so there a slower path
//! through Python (`memoryview`) with one extra copy is used instead.
//!
//! Buffers are requested with `PyBUF_SIMPLE` (plus `PyBUF_WRITABLE` for
//! targets): contiguous raw bytes regardless of the item format, which is
//! what `io.RawIOBase.readinto` and `write` mean. Non-contiguous exporters
//! raise `BufferError`.

use pyo3::prelude::*;

#[cfg(not(windows))]
mod imp {
    use std::ffi::{c_char, c_int, c_void};

    use pyo3::ffi;
    use pyo3::prelude::*;

    /// `Py_buffer` (Include/pybuffer.h; unchanged since CPython 3.3).
    #[repr(C)]
    struct RawBuffer {
        buf: *mut c_void,
        obj: *mut ffi::PyObject,
        len: ffi::Py_ssize_t,
        itemsize: ffi::Py_ssize_t,
        readonly: c_int,
        ndim: c_int,
        format: *mut c_char,
        shape: *mut ffi::Py_ssize_t,
        strides: *mut ffi::Py_ssize_t,
        suboffsets: *mut ffi::Py_ssize_t,
        internal: *mut c_void,
    }

    unsafe extern "C" {
        fn PyObject_GetBuffer(obj: *mut ffi::PyObject, view: *mut RawBuffer, flags: c_int)
        -> c_int;
        fn PyBuffer_Release(view: *mut RawBuffer);
    }

    const PYBUF_SIMPLE: c_int = 0;
    const PYBUF_WRITABLE: c_int = 0x0001;

    /// An exported buffer, released on drop.
    pub(crate) struct BufferView {
        // Boxed: the exporter may keep a pointer to the struct until release.
        raw: Box<RawBuffer>,
    }

    // SAFETY: the view only holds raw pointers into memory whose lifetime is
    // pinned by the export (the exporter cannot free or resize it until
    // `PyBuffer_Release`). It is used by one call at a time; `Drop` re-attaches
    // to the interpreter before releasing, so it may run on any thread.
    unsafe impl Send for BufferView {}

    impl BufferView {
        fn get(obj: &Bound<'_, PyAny>, flags: c_int) -> PyResult<Self> {
            let mut raw = Box::new(RawBuffer {
                buf: std::ptr::null_mut(),
                obj: std::ptr::null_mut(),
                len: 0,
                itemsize: 0,
                readonly: 0,
                ndim: 0,
                format: std::ptr::null_mut(),
                shape: std::ptr::null_mut(),
                strides: std::ptr::null_mut(),
                suboffsets: std::ptr::null_mut(),
                internal: std::ptr::null_mut(),
            });
            // SAFETY: `obj` is a valid object (we hold a reference and are
            // attached); `raw` points to writable storage for a Py_buffer.
            let rc = unsafe { PyObject_GetBuffer(obj.as_ptr(), &mut *raw, flags) };
            if rc != 0 {
                return Err(PyErr::fetch(obj.py()));
            }
            Ok(BufferView { raw })
        }

        /// Export `obj` for reading.
        pub(crate) fn readable(obj: &Bound<'_, PyAny>) -> PyResult<Self> {
            Self::get(obj, PYBUF_SIMPLE)
        }

        /// Export `obj` for writing (fails with `BufferError` if read-only).
        pub(crate) fn writable(obj: &Bound<'_, PyAny>) -> PyResult<Self> {
            Self::get(obj, PYBUF_WRITABLE)
        }

        /// Length in bytes.
        pub(crate) fn len(&self) -> usize {
            self.raw.len.max(0) as usize
        }

        /// The exported bytes.
        ///
        /// Another thread may mutate a mutable exporter (e.g. a `bytearray`)
        /// concurrently, exactly as with any C extension reading a buffer;
        /// that is a race in the caller's program, not memory unsafety of
        /// ours beyond reading torn bytes.
        pub(crate) fn as_slice(&self) -> &[u8] {
            if self.len() == 0 {
                return &[];
            }
            // SAFETY: `buf` points to `len` contiguous bytes kept alive by the
            // export (PyBUF_SIMPLE guarantees contiguity).
            unsafe { std::slice::from_raw_parts(self.raw.buf as *const u8, self.len()) }
        }

        /// The exported bytes, writable. Only valid for views obtained with
        /// [`BufferView::writable`].
        pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
            debug_assert_eq!(self.raw.readonly, 0);
            if self.len() == 0 {
                return &mut [];
            }
            // SAFETY: as in `as_slice`; the exporter granted PyBUF_WRITABLE
            // and `&mut self` makes this the only Rust reference.
            unsafe { std::slice::from_raw_parts_mut(self.raw.buf as *mut u8, self.len()) }
        }
    }

    impl Drop for BufferView {
        fn drop(&mut self) {
            // SAFETY: the view was filled by a successful PyObject_GetBuffer
            // and is released exactly once, with the interpreter attached.
            Python::attach(|_| unsafe { PyBuffer_Release(&mut *self.raw) });
        }
    }
}

#[cfg(not(windows))]
pub(crate) use imp::BufferView;

/// A readable byte source borrowed from a Python object.
pub(crate) struct ReadSource {
    #[cfg(not(windows))]
    view: BufferView,
    #[cfg(windows)]
    copy: Vec<u8>,
}

impl ReadSource {
    /// Borrow the bytes of any buffer-protocol object.
    pub(crate) fn new(obj: &Bound<'_, PyAny>) -> PyResult<Self> {
        #[cfg(not(windows))]
        {
            Ok(ReadSource {
                view: BufferView::readable(obj)?,
            })
        }
        #[cfg(windows)]
        {
            let py = obj.py();
            let mv = py
                .import("builtins")?
                .getattr("memoryview")?
                .call1((obj,))?
                .call_method1("cast", ("B",))?;
            let b = mv.call_method0("tobytes")?;
            let bytes: &[u8] = b.cast::<pyo3::types::PyBytes>()?.as_bytes();
            Ok(ReadSource {
                copy: bytes.to_vec(),
            })
        }
    }

    /// The borrowed bytes.
    pub(crate) fn as_slice(&self) -> &[u8] {
        #[cfg(not(windows))]
        {
            self.view.as_slice()
        }
        #[cfg(windows)]
        {
            &self.copy
        }
    }
}

/// A writable byte target borrowed from a Python object (`readinto`).
pub(crate) struct WriteTarget {
    #[cfg(not(windows))]
    view: BufferView,
    #[cfg(windows)]
    obj: Py<PyAny>,
    #[cfg(windows)]
    scratch: Vec<u8>,
}

impl WriteTarget {
    /// Borrow the memory of a writable buffer-protocol object.
    pub(crate) fn new(obj: &Bound<'_, PyAny>) -> PyResult<Self> {
        #[cfg(not(windows))]
        {
            Ok(WriteTarget {
                view: BufferView::writable(obj)?,
            })
        }
        #[cfg(windows)]
        {
            let py = obj.py();
            let mv = py
                .import("builtins")?
                .getattr("memoryview")?
                .call1((obj,))?;
            if mv.getattr("readonly")?.is_truthy()? {
                return Err(pyo3::exceptions::PyBufferError::new_err(
                    "the buffer is read-only",
                ));
            }
            let n: usize = mv.getattr("nbytes")?.extract()?;
            Ok(WriteTarget {
                obj: mv.unbind(),
                scratch: vec![0; n],
            })
        }
    }

    /// The memory to fill.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        #[cfg(not(windows))]
        {
            self.view.as_mut_slice()
        }
        #[cfg(windows)]
        {
            &mut self.scratch
        }
    }

    /// Publish the first `n` bytes written (a no-op where the memory was
    /// written in place).
    pub(crate) fn finish(self, py: Python<'_>, n: usize) -> PyResult<()> {
        #[cfg(not(windows))]
        {
            let _ = (py, n);
            drop(self.view);
            Ok(())
        }
        #[cfg(windows)]
        {
            if n > 0 {
                let mv = self.obj.bind(py).call_method1("cast", ("B",))?;
                let data = pyo3::types::PyBytes::new(py, &self.scratch[..n]);
                let slice = pyo3::types::PySlice::new(py, 0, n as isize, 1);
                mv.set_item(slice, data)?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::{PyByteArray, PyBytes};

    #[test]
    fn reads_and_writes_buffers() {
        Python::attach(|py| {
            let b = PyBytes::new(py, b"hello");
            let src = ReadSource::new(b.as_any()).unwrap();
            assert_eq!(src.as_slice(), b"hello");
            drop(src);

            let ba = PyByteArray::new(py, &[0u8; 4]);
            let mut t = WriteTarget::new(ba.as_any()).unwrap();
            t.as_mut_slice()[..3].copy_from_slice(b"abc");
            t.finish(py, 3).unwrap();
            assert_eq!(ba.to_vec(), b"abc\0");

            // Read-only targets are refused.
            assert!(WriteTarget::new(b.as_any()).is_err());
            // Non-buffer objects are refused.
            assert!(ReadSource::new(py.None().bind(py)).is_err());

            // Typed arrays are raw bytes.
            let arr = py
                .import("array")
                .unwrap()
                .getattr("array")
                .unwrap()
                .call1(("i", vec![0i32; 2]))
                .unwrap();
            let mut t = WriteTarget::new(&arr).unwrap();
            assert_eq!(t.as_mut_slice().len(), 8);
            t.as_mut_slice().copy_from_slice(&[1, 0, 0, 0, 2, 0, 0, 0]);
            t.finish(py, 8).unwrap();
            let v: Vec<i32> = arr.call_method0("tolist").unwrap().extract().unwrap();
            if cfg!(target_endian = "little") {
                assert_eq!(v, vec![1, 2]);
            }
        });
    }
}
