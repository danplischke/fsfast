//! Mapping of [`fsfast_core::Error`] onto Python exceptions (PLAN §4.7).
//!
//! | `ErrorKind` | Python exception | errno |
//! |---|---|---|
//! | `NotFound` | `FileNotFoundError` | `ENOENT` |
//! | `PermissionDenied` | `PermissionError` | `EACCES` |
//! | `AlreadyExists` | `FileExistsError` | `EEXIST` |
//! | `IsADirectory` | `IsADirectoryError` | `EISDIR` |
//! | `NotADirectory` | `NotADirectoryError` | `ENOTDIR` |
//! | `DirectoryNotEmpty` | `OSError` | `ENOTEMPTY` |
//! | `InvalidInput` | `ValueError` | — |
//! | `Unsupported` | `NotImplementedError` | — |
//! | `Timeout` | `TimeoutError` | `ETIMEDOUT` |
//! | `PreconditionFailed` | `fsfast.PreconditionFailed` (an `OSError`) | `EINVAL` (as s3fs) |
//! | `Throttled` | `OSError` | `EBUSY` (as s3fs's `SlowDown`) |
//! | `ConnectionFailed` | `ConnectionError` | `ECONNRESET` |
//! | `Protocol` | `OSError` | `EPROTO` |
//! | `Cancelled` | `OSError` | `ECANCELED` |
//! | `Io`, `Other` | `OSError` (subclass chosen by errno) | native or `EIO` |
//!
//! errno values come from Python's `errno` module (they differ between
//! platforms); an OS errno attached to the error ([`Detail::Errno`]) takes
//! precedence. `strerror` is the error message (without Rust's
//! `" (os error N)"` suffix) and `filename` the path, so `str(e)` reads
//! exactly like an OS error raised by Python (`[Errno 2] No such file or
//! directory: '/x'`). Backend details are attached as the attributes
//! `http_status`, `ntstatus`, `sftp_status` and `code` (`None` when absent).

use std::sync::OnceLock;

use fsfast_core::{Detail, Error, ErrorKind};
use pyo3::exceptions::{
    PyConnectionError, PyFileExistsError, PyFileNotFoundError, PyIsADirectoryError,
    PyNotADirectoryError, PyNotImplementedError, PyOSError, PyPermissionError, PyTimeoutError,
    PyValueError,
};
use pyo3::prelude::*;
use pyo3::types::PyType;

pyo3::create_exception!(
    fsfast,
    PreconditionFailed,
    PyOSError,
    "A conditional request failed: the object changed under a pinned read, or an \
     If-Match / generation precondition was not met."
);

/// errno values of the running Python (looked up by name).
#[derive(Debug, Clone, Copy)]
struct Errnos {
    enoent: i32,
    eacces: i32,
    eexist: i32,
    eisdir: i32,
    enotdir: i32,
    enotempty: i32,
    etimedout: i32,
    einval: i32,
    ebusy: i32,
    econnreset: i32,
    eproto: i32,
    ecanceled: i32,
    eio: i32,
}

impl Errnos {
    /// Linux values, used until [`init`] has run (and for names a platform's
    /// `errno` module lacks).
    const LINUX: Errnos = Errnos {
        enoent: 2,
        eacces: 13,
        eexist: 17,
        eisdir: 21,
        enotdir: 20,
        enotempty: 39,
        etimedout: 110,
        einval: 22,
        ebusy: 16,
        econnreset: 104,
        eproto: 71,
        ecanceled: 125,
        eio: 5,
    };
}

static ERRNOS: OnceLock<Errnos> = OnceLock::new();

fn errnos() -> &'static Errnos {
    ERRNOS.get().unwrap_or(&Errnos::LINUX)
}

/// Read the platform's errno values from Python's `errno` module.
pub(crate) fn init(py: Python<'_>) -> PyResult<()> {
    let m = py.import("errno")?;
    let get = |name: &str, default: i32| -> i32 {
        m.getattr(name)
            .and_then(|v| v.extract::<i32>())
            .unwrap_or(default)
    };
    let l = Errnos::LINUX;
    let table = Errnos {
        enoent: get("ENOENT", l.enoent),
        eacces: get("EACCES", l.eacces),
        eexist: get("EEXIST", l.eexist),
        eisdir: get("EISDIR", l.eisdir),
        enotdir: get("ENOTDIR", l.enotdir),
        enotempty: get("ENOTEMPTY", l.enotempty),
        etimedout: get("ETIMEDOUT", l.etimedout),
        einval: get("EINVAL", l.einval),
        ebusy: get("EBUSY", l.ebusy),
        econnreset: get("ECONNRESET", l.econnreset),
        eproto: get("EPROTO", l.eproto),
        ecanceled: get("ECANCELED", l.ecanceled),
        eio: get("EIO", l.eio),
    };
    let _ = ERRNOS.set(table);
    Ok(())
}

/// The Python exception class and default errno for an `OSError`-family kind.
fn os_class<'py>(py: Python<'py>, kind: ErrorKind) -> (Bound<'py, PyType>, i32) {
    let e = errnos();
    match kind {
        ErrorKind::NotFound => (py.get_type::<PyFileNotFoundError>(), e.enoent),
        ErrorKind::PermissionDenied => (py.get_type::<PyPermissionError>(), e.eacces),
        ErrorKind::AlreadyExists => (py.get_type::<PyFileExistsError>(), e.eexist),
        ErrorKind::IsADirectory => (py.get_type::<PyIsADirectoryError>(), e.eisdir),
        ErrorKind::NotADirectory => (py.get_type::<PyNotADirectoryError>(), e.enotdir),
        ErrorKind::DirectoryNotEmpty => (py.get_type::<PyOSError>(), e.enotempty),
        ErrorKind::Timeout => (py.get_type::<PyTimeoutError>(), e.etimedout),
        ErrorKind::PreconditionFailed => (py.get_type::<PreconditionFailed>(), e.einval),
        ErrorKind::Throttled => (py.get_type::<PyOSError>(), e.ebusy),
        ErrorKind::ConnectionFailed => (py.get_type::<PyConnectionError>(), e.econnreset),
        ErrorKind::Protocol => (py.get_type::<PyOSError>(), e.eproto),
        ErrorKind::Cancelled => (py.get_type::<PyOSError>(), e.ecanceled),
        _ => (py.get_type::<PyOSError>(), e.eio),
    }
}

/// Remove every `" (os error N)"` that Rust's `io::Error` display appends.
fn strip_os_error(s: &str) -> String {
    const MARK: &str = " (os error ";
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find(MARK) {
        let after = &rest[i + MARK.len()..];
        match after.find(')') {
            Some(j) if after[..j].bytes().all(|b| b.is_ascii_digit() || b == b'-') => {
                out.push_str(&rest[..i]);
                rest = &after[j + 1..];
            }
            _ => {
                out.push_str(&rest[..i + MARK.len()]);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// `strerror` for the Python exception: the message, backend details and
/// the source error when it adds information.
pub(crate) fn strerror(err: &Error) -> String {
    let mut s = strip_os_error(err.message());
    for d in err.details() {
        match d {
            Detail::Http(c) => s.push_str(&format!(" (HTTP {c})")),
            Detail::NtStatus(c) => s.push_str(&format!(" (NTSTATUS 0x{c:08X})")),
            Detail::Sftp(c) => s.push_str(&format!(" (SFTP status {c})")),
            Detail::Code(c) => s.push_str(&format!(" ({c})")),
            // Already the exception's errno.
            Detail::Errno(_) => {}
            _ => {}
        }
    }
    if let Some(src) = std::error::Error::source(err) {
        let t = strip_os_error(&src.to_string());
        if !t.is_empty() && !s.contains(&t) && !t.contains(&s) {
            s.push_str(": ");
            s.push_str(&t);
        }
    }
    s
}

fn native_errno(err: &Error) -> Option<i32> {
    err.details().iter().find_map(|d| match d {
        Detail::Errno(c) => Some(*c),
        _ => None,
    })
}

/// Build the exception instance for `err`.
fn build<'py>(py: Python<'py>, err: &Error) -> PyResult<Bound<'py, PyAny>> {
    let exc = match err.kind() {
        ErrorKind::InvalidInput => PyValueError::new_err(err.to_string())
            .into_value(py)
            .into_bound(py)
            .into_any(),
        ErrorKind::Unsupported => PyNotImplementedError::new_err(err.to_string())
            .into_value(py)
            .into_bound(py)
            .into_any(),
        kind => {
            let (ty, kind_errno) = os_class(py, kind);
            let errno = native_errno(err).unwrap_or(kind_errno);
            let msg = strerror(err);
            match err.path() {
                Some(p) => ty.call1((errno, msg, p))?,
                None => ty.call1((errno, msg))?,
            }
        }
    };
    let mut http = None;
    let mut ntstatus = None;
    let mut sftp = None;
    let mut code = None;
    for d in err.details() {
        match d {
            Detail::Http(c) => http = http.or(Some(*c)),
            Detail::NtStatus(c) => ntstatus = ntstatus.or(Some(*c)),
            Detail::Sftp(c) => sftp = sftp.or(Some(*c)),
            Detail::Code(c) => code = code.or(Some(c.as_str())),
            _ => {}
        }
    }
    exc.setattr(pyo3::intern!(py, "http_status"), http)?;
    exc.setattr(pyo3::intern!(py, "ntstatus"), ntstatus)?;
    exc.setattr(pyo3::intern!(py, "sftp_status"), sftp)?;
    exc.setattr(pyo3::intern!(py, "code"), code)?;
    Ok(exc)
}

/// Convert `err` into the matching Python exception.
pub(crate) fn to_pyerr(py: Python<'_>, err: &Error) -> PyErr {
    match build(py, err) {
        Ok(exc) => PyErr::from_value(exc),
        Err(e) => e,
    }
}

/// The exception instance for `err` (used for per-item results of batch
/// operations called with `on_error="return"`).
pub(crate) fn to_exception<'py>(py: Python<'py>, err: &Error) -> Bound<'py, PyAny> {
    match build(py, err) {
        Ok(exc) => exc,
        Err(e) => e.into_value(py).into_bound(py).into_any(),
    }
}

/// An `fsfast_core::Error` from a Python-side argument problem.
pub(crate) fn invalid(msg: impl Into<String>) -> Error {
    Error::invalid_input(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_rust_os_error_suffixes() {
        assert_eq!(
            strip_os_error("No such file or directory (os error 2)"),
            "No such file or directory"
        );
        assert_eq!(
            strip_os_error("Is a directory (os error 21) (-> '/x')"),
            "Is a directory (-> '/x')"
        );
        assert_eq!(strip_os_error("odd (os error x)"), "odd (os error x)");
        assert_eq!(strip_os_error("plain"), "plain");
    }

    #[test]
    fn strerror_adds_details_and_new_source_text() {
        let e = Error::not_found("b/k")
            .with_detail(Detail::Http(404))
            .with_detail(Detail::Code("NoSuchKey".into()));
        assert_eq!(
            strerror(&e),
            "no such file or directory (HTTP 404) (NoSuchKey)"
        );
        let io = std::io::Error::from_raw_os_error(2);
        let e: Error = io.into();
        assert_eq!(strerror(&e), "No such file or directory");
        let e = Error::protocol("bad frame").with_source(std::io::Error::other("short read"));
        assert_eq!(strerror(&e), "bad frame: short read");
    }

    #[test]
    fn exceptions_carry_class_errno_filename_and_details() {
        Python::attach(|py| {
            init(py).unwrap();
            let check = |err: Error, class: &str, errno: Option<i32>| {
                let exc = to_exception(py, &err);
                let name: String = exc.get_type().name().unwrap().extract().unwrap();
                assert_eq!(name, class, "{err:?}");
                if let Some(n) = errno {
                    let got: i32 = exc.getattr("errno").unwrap().extract().unwrap();
                    assert_eq!(got, n);
                }
                exc
            };
            let exc = check(Error::not_found("/a/b"), "FileNotFoundError", Some(2));
            let f: String = exc.getattr("filename").unwrap().extract().unwrap();
            assert_eq!(f, "/a/b");
            assert_eq!(
                exc.str().unwrap().to_string(),
                "[Errno 2] no such file or directory: '/a/b'"
            );
            check(Error::permission_denied("no"), "PermissionError", Some(13));
            check(Error::already_exists("x"), "FileExistsError", Some(17));
            check(Error::is_a_directory("x"), "IsADirectoryError", Some(21));
            check(Error::not_a_directory("x"), "NotADirectoryError", Some(20));
            check(
                Error::new(ErrorKind::DirectoryNotEmpty, "not empty"),
                "OSError",
                Some(39),
            );
            check(Error::invalid_input("bad"), "ValueError", None);
            check(Error::unsupported("sign"), "NotImplementedError", None);
            check(Error::timeout("slow"), "TimeoutError", Some(110));
            check(Error::connection("down"), "ConnectionError", Some(104));
            check(
                Error::new(ErrorKind::Throttled, "slow down"),
                "OSError",
                Some(16),
            );
            let exc = check(
                Error::new(ErrorKind::PreconditionFailed, "changed").with_detail(Detail::Http(412)),
                "PreconditionFailed",
                Some(22),
            );
            assert!(exc.is_instance_of::<PyOSError>());
            let http: u16 = exc.getattr("http_status").unwrap().extract().unwrap();
            assert_eq!(http, 412);
            assert!(exc.getattr("ntstatus").unwrap().is_none());
            // A native errno picks the OSError subclass and the errno.
            let io = std::io::Error::from_raw_os_error(36); // ENAMETOOLONG
            let e = Error::from(io).with_kind(ErrorKind::Io).with_path("/long");
            let exc = check(e, "OSError", Some(36));
            assert_eq!(
                exc.str().unwrap().to_string(),
                "[Errno 36] File name too long: '/long'"
            );
            let e =
                Error::new(ErrorKind::NotFound, "gone").with_detail(Detail::NtStatus(0xC000_0034));
            let exc = check(e, "FileNotFoundError", Some(2));
            let nt: u32 = exc.getattr("ntstatus").unwrap().extract().unwrap();
            assert_eq!(nt, 0xC000_0034);
        });
    }
}
