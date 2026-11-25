//! Mapping SFTP status codes to fsfast errors.
//!
//! OpenSSH's `sftp-server` reports `errno` values through only four codes:
//! `ENOENT`, `ENOTDIR`, `EBADF` and `ELOOP` become `NO_SUCH_FILE`; `EPERM`,
//! `EACCES` and `EFAULT` become `PERMISSION_DENIED`; `EINVAL` and
//! `ENAMETOOLONG` become `BAD_MESSAGE`; everything else (`EEXIST`,
//! `ENOTEMPTY`, `EISDIR`, `ENOSPC`, ...) becomes `FAILURE`. The operations
//! refine `FAILURE`/`NO_SUCH_FILE` where a follow-up `LSTAT` can tell what
//! happened (see the filesystem methods); this module gives the base
//! mapping, which also covers the more precise codes of later drafts that
//! some v3 servers send.

use fsfast_core::{Detail, Error, ErrorKind};

use crate::proto::{Status, status};

/// The error kind for an SFTP status code.
pub fn kind_for(code: u32) -> ErrorKind {
    match code {
        status::NO_SUCH_FILE | status::NO_SUCH_PATH => ErrorKind::NotFound,
        status::PERMISSION_DENIED | status::WRITE_PROTECT => ErrorKind::PermissionDenied,
        status::BAD_MESSAGE | status::INVALID_FILENAME | status::INVALID_HANDLE => {
            ErrorKind::InvalidInput
        }
        status::NO_CONNECTION | status::CONNECTION_LOST => ErrorKind::ConnectionFailed,
        status::OP_UNSUPPORTED => ErrorKind::Unsupported,
        status::FILE_ALREADY_EXISTS => ErrorKind::AlreadyExists,
        status::DIR_NOT_EMPTY => ErrorKind::DirectoryNotEmpty,
        status::NOT_A_DIRECTORY => ErrorKind::NotADirectory,
        status::FILE_IS_A_DIRECTORY => ErrorKind::IsADirectory,
        _ => ErrorKind::Io,
    }
}

/// An error for a non-OK status of operation `op` on `path`.
pub fn status_error(s: &Status, op: &str, path: Option<&str>) -> Error {
    let msg = if s.message.is_empty() {
        format!("{op}: {}", status::name(s.code))
    } else {
        format!("{op}: {}", s.message)
    };
    let mut e = Error::new(kind_for(s.code), msg).with_detail(Detail::Sftp(s.code));
    if let Some(p) = path {
        e = e.with_path(p);
    }
    e
}

/// Re-tag `e` with a more precise kind, keeping message and details.
pub fn refine(e: Error, kind: ErrorKind) -> Error {
    e.with_kind(kind)
}

/// The SFTP status code attached to `e`, if any.
pub fn sftp_code(e: &Error) -> Option<u32> {
    e.details().iter().find_map(|d| match d {
        Detail::Sftp(c) => Some(*c),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_and_details() {
        let e = status_error(&Status::new(status::NO_SUCH_FILE), "stat", Some("/x"));
        assert_eq!(e.kind(), ErrorKind::NotFound);
        assert_eq!(e.path(), Some("/x"));
        assert_eq!(sftp_code(&e), Some(2));
        assert_eq!(e.to_string(), "stat: No such file: '/x' (SFTP status 2)");
        assert_eq!(
            kind_for(status::PERMISSION_DENIED),
            ErrorKind::PermissionDenied
        );
        assert_eq!(kind_for(status::FAILURE), ErrorKind::Io);
        assert_eq!(kind_for(status::OP_UNSUPPORTED), ErrorKind::Unsupported);
        assert_eq!(
            kind_for(status::CONNECTION_LOST),
            ErrorKind::ConnectionFailed
        );
        assert_eq!(
            kind_for(status::DIR_NOT_EMPTY),
            ErrorKind::DirectoryNotEmpty
        );
        assert_eq!(kind_for(999), ErrorKind::Io);
        let empty = Status {
            code: status::FAILURE,
            message: String::new(),
            lang: String::new(),
        };
        assert_eq!(
            status_error(&empty, "rmdir", None).message(),
            "rmdir: Failure"
        );
        assert_eq!(
            refine(e, ErrorKind::NotADirectory).kind(),
            ErrorKind::NotADirectory
        );
    }
}
