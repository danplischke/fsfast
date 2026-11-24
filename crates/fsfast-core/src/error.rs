//! Error model shared by every backend.
//!
//! Every backend maps its native failures (HTTP status, NTSTATUS, SFTP status,
//! errno, ...) onto an [`ErrorKind`]. The Python layer maps kinds onto the
//! builtin exception types fsspec users expect (`FileNotFoundError`,
//! `PermissionError`, ...). The native code is preserved in [`Detail`] so it can
//! be surfaced as an attribute on the Python exception.

use std::fmt;

/// Result alias used throughout fsfast.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Broad error category. Maps 1:1 onto Python exception types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Path does not exist. Python: `FileNotFoundError` (ENOENT).
    NotFound,
    /// Authentication succeeded but access was refused, or credentials are
    /// invalid. Python: `PermissionError` (EACCES).
    PermissionDenied,
    /// Target already exists (e.g. mode `xb`, `mkdir` of existing dir).
    /// Python: `FileExistsError` (EEXIST).
    AlreadyExists,
    /// A file operation was attempted on a directory. Python: `IsADirectoryError`.
    IsADirectory,
    /// A directory operation was attempted on a file. Python: `NotADirectoryError`.
    NotADirectory,
    /// `rmdir` on a non-empty directory. Python: `OSError(ENOTEMPTY)`.
    DirectoryNotEmpty,
    /// Bad argument or option. Python: `ValueError`.
    InvalidInput,
    /// The backend or server does not support the operation.
    /// Python: `NotImplementedError`.
    Unsupported,
    /// Operation timed out. Python: `TimeoutError`.
    Timeout,
    /// A conditional request failed: the object changed under a pinned read,
    /// or an `If-Match`/generation precondition was not met.
    /// Python: `OSError` subclass `fsfast.PreconditionFailed`.
    PreconditionFailed,
    /// Server asked us to slow down (HTTP 429/503 SlowDown, SMB credits exhausted).
    Throttled,
    /// Could not establish or lost the connection. Python: `ConnectionError`.
    ConnectionFailed,
    /// The peer violated the protocol or sent something we cannot parse.
    Protocol,
    /// Generic I/O failure. Python: `OSError`.
    Io,
    /// Operation was cancelled.
    Cancelled,
    /// Anything else.
    Other,
}

impl ErrorKind {
    /// The POSIX errno that best describes this kind, used for `OSError(errno, ...)`.
    pub fn errno(self) -> Option<i32> {
        // Values are Linux errno numbers; Python's errno module agrees on all
        // platforms we ship for these symbols except Windows, where the Python
        // layer remaps via the `errno` module by name.
        Some(match self {
            ErrorKind::NotFound => 2,           // ENOENT
            ErrorKind::PermissionDenied => 13,  // EACCES
            ErrorKind::AlreadyExists => 17,     // EEXIST
            ErrorKind::NotADirectory => 20,     // ENOTDIR
            ErrorKind::IsADirectory => 21,      // EISDIR
            ErrorKind::InvalidInput => 22,      // EINVAL
            ErrorKind::DirectoryNotEmpty => 39, // ENOTEMPTY
            ErrorKind::Unsupported => 95,       // EOPNOTSUPP
            ErrorKind::Timeout => 110,          // ETIMEDOUT
            ErrorKind::ConnectionFailed => 104, // ECONNRESET
            ErrorKind::Io => 5,                 // EIO
            ErrorKind::Cancelled => 125,        // ECANCELED
            ErrorKind::Throttled => 11,         // EAGAIN
            ErrorKind::PreconditionFailed | ErrorKind::Protocol | ErrorKind::Other => return None,
        })
    }

    /// Whether errors of this kind are worth retrying by default.
    pub fn is_transient(self) -> bool {
        matches!(
            self,
            ErrorKind::Timeout | ErrorKind::Throttled | ErrorKind::ConnectionFailed
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::NotFound => "not found",
            ErrorKind::PermissionDenied => "permission denied",
            ErrorKind::AlreadyExists => "already exists",
            ErrorKind::IsADirectory => "is a directory",
            ErrorKind::NotADirectory => "not a directory",
            ErrorKind::DirectoryNotEmpty => "directory not empty",
            ErrorKind::InvalidInput => "invalid input",
            ErrorKind::Unsupported => "unsupported",
            ErrorKind::Timeout => "timed out",
            ErrorKind::PreconditionFailed => "precondition failed",
            ErrorKind::Throttled => "throttled",
            ErrorKind::ConnectionFailed => "connection failed",
            ErrorKind::Protocol => "protocol error",
            ErrorKind::Io => "i/o error",
            ErrorKind::Cancelled => "cancelled",
            ErrorKind::Other => "error",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Backend-native detail attached to an error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Detail {
    /// HTTP status code.
    Http(u16),
    /// Windows NTSTATUS (SMB).
    NtStatus(u32),
    /// SFTP status code (SSH_FX_*).
    Sftp(u32),
    /// OS errno.
    Errno(i32),
    /// Service-specific error code string (e.g. S3 `NoSuchKey`, `SlowDown`).
    Code(String),
}

/// The error type used by every fsfast API.
pub struct Error {
    kind: ErrorKind,
    message: String,
    path: Option<String>,
    details: Vec<Detail>,
    retryable: Option<bool>,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Error {
            kind,
            message: message.into(),
            path: None,
            details: Vec::new(),
            retryable: None,
            source: None,
        }
    }

    /// `NotFound` for `path`.
    pub fn not_found(path: impl Into<String>) -> Self {
        let path = path.into();
        Error::new(ErrorKind::NotFound, "no such file or directory").with_path(path)
    }

    pub fn already_exists(path: impl Into<String>) -> Self {
        Error::new(ErrorKind::AlreadyExists, "file exists").with_path(path)
    }

    pub fn is_a_directory(path: impl Into<String>) -> Self {
        Error::new(ErrorKind::IsADirectory, "is a directory").with_path(path)
    }

    pub fn not_a_directory(path: impl Into<String>) -> Self {
        Error::new(ErrorKind::NotADirectory, "not a directory").with_path(path)
    }

    pub fn permission_denied(message: impl Into<String>) -> Self {
        Error::new(ErrorKind::PermissionDenied, message)
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Error::new(ErrorKind::InvalidInput, message)
    }

    /// The operation `op` is not supported by this backend.
    pub fn unsupported(op: impl fmt::Display) -> Self {
        Error::new(ErrorKind::Unsupported, format!("{op} is not supported"))
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Error::new(ErrorKind::Protocol, message)
    }

    pub fn timeout(message: impl Into<String>) -> Self {
        Error::new(ErrorKind::Timeout, message)
    }

    pub fn connection(message: impl Into<String>) -> Self {
        Error::new(ErrorKind::ConnectionFailed, message)
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn with_detail(mut self, detail: Detail) -> Self {
        self.details.push(detail);
        self
    }

    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// Override the default retry classification.
    pub fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = Some(retryable);
        self
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn details(&self) -> &[Detail] {
        &self.details
    }

    /// HTTP status, if one is attached.
    pub fn http_status(&self) -> Option<u16> {
        self.details.iter().find_map(|d| match d {
            Detail::Http(s) => Some(*s),
            _ => None,
        })
    }

    /// Whether retrying the same request may succeed.
    ///
    /// Explicit overrides win; otherwise transient kinds and HTTP 500/502/503/504
    /// are retryable.
    pub fn is_retryable(&self) -> bool {
        if let Some(r) = self.retryable {
            return r;
        }
        if self.kind.is_transient() {
            return true;
        }
        matches!(self.http_status(), Some(500 | 502 | 503 | 504))
    }

    /// Re-tag the error kind, keeping message, details and source.
    pub fn with_kind(mut self, kind: ErrorKind) -> Self {
        self.kind = kind;
        self
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Error");
        d.field("kind", &self.kind).field("message", &self.message);
        if let Some(p) = &self.path {
            d.field("path", p);
        }
        if !self.details.is_empty() {
            d.field("details", &self.details);
        }
        if let Some(s) = &self.source {
            d.field("source", s);
        }
        d.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)?;
        if let Some(p) = &self.path {
            write!(f, ": '{p}'")?;
        }
        for d in &self.details {
            match d {
                Detail::Http(s) => write!(f, " (HTTP {s})")?,
                Detail::NtStatus(s) => write!(f, " (NTSTATUS 0x{s:08X})")?,
                Detail::Sftp(s) => write!(f, " (SFTP status {s})")?,
                Detail::Errno(e) => write!(f, " (errno {e})")?,
                Detail::Code(c) => write!(f, " ({c})")?,
            }
        }
        if let Some(s) = &self.source {
            write!(f, ": {s}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        use std::io::ErrorKind as Io;
        let kind = match err.kind() {
            Io::NotFound => ErrorKind::NotFound,
            Io::PermissionDenied => ErrorKind::PermissionDenied,
            Io::AlreadyExists => ErrorKind::AlreadyExists,
            Io::IsADirectory => ErrorKind::IsADirectory,
            Io::NotADirectory => ErrorKind::NotADirectory,
            Io::DirectoryNotEmpty => ErrorKind::DirectoryNotEmpty,
            Io::InvalidInput | Io::InvalidData | Io::InvalidFilename => ErrorKind::InvalidInput,
            Io::Unsupported => ErrorKind::Unsupported,
            Io::TimedOut => ErrorKind::Timeout,
            Io::ConnectionRefused
            | Io::ConnectionReset
            | Io::ConnectionAborted
            | Io::NotConnected
            | Io::BrokenPipe
            | Io::HostUnreachable
            | Io::NetworkUnreachable
            | Io::NetworkDown
            | Io::AddrNotAvailable => ErrorKind::ConnectionFailed,
            Io::UnexpectedEof => ErrorKind::Protocol,
            Io::Interrupted | Io::WouldBlock => ErrorKind::Throttled,
            _ => ErrorKind::Io,
        };
        let mut e = Error::new(kind, err.to_string());
        if let Some(code) = err.raw_os_error() {
            e.details.push(Detail::Errno(code));
        }
        e.source = Some(Box::new(err));
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_includes_path_and_details() {
        let e = Error::not_found("bucket/key").with_detail(Detail::Http(404));
        assert_eq!(
            e.to_string(),
            "no such file or directory: 'bucket/key' (HTTP 404)"
        );
        assert_eq!(e.kind(), ErrorKind::NotFound);
        assert!(!e.is_retryable());
    }

    #[test]
    fn retry_classification() {
        assert!(
            Error::new(ErrorKind::Io, "x")
                .with_detail(Detail::Http(503))
                .is_retryable()
        );
        assert!(Error::timeout("t").is_retryable());
        assert!(!Error::timeout("t").with_retryable(false).is_retryable());
        assert!(
            !Error::new(ErrorKind::Io, "x")
                .with_detail(Detail::Http(400))
                .is_retryable()
        );
    }

    #[test]
    fn from_io_error() {
        let io = std::io::Error::from_raw_os_error(2);
        let e: Error = io.into();
        assert_eq!(e.kind(), ErrorKind::NotFound);
        assert!(e.details().contains(&Detail::Errno(2)));
    }
}
