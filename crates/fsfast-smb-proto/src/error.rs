//! Codec error type.
//!
//! The codec is I/O free, so its errors are about bytes: truncated or
//! malformed input, failed integrity checks and authentication failures.
//! [`ProtoError`] is cheap to construct (no allocation on the hot decode paths)
//! and converts into [`fsfast_core::Error`] with the most precise
//! [`ErrorKind`](fsfast_core::ErrorKind).

use fsfast_core::{Detail, Error, ErrorKind};

use crate::header::Command;
use crate::status::NtStatus;

/// Result alias for codec operations.
pub type Result<T, E = ProtoError> = std::result::Result<T, E>;

/// An error produced while encoding, decoding, authenticating or applying
/// SMB cryptography.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProtoError {
    /// The input ended before a complete structure could be read.
    #[error("truncated {what}: need {need} bytes, have {have}")]
    Truncated {
        /// The structure being decoded.
        what: &'static str,
        /// Bytes required.
        need: usize,
        /// Bytes available.
        have: usize,
    },
    /// A structure is internally inconsistent (bad offsets, wrong structure
    /// size, wrong signature bytes, ...).
    #[error("malformed {what}: {reason}")]
    Malformed {
        /// The structure being decoded.
        what: &'static str,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A message body was decoded as the wrong command.
    #[error("unexpected command: expected {expected:?}, got {actual:?}")]
    UnexpectedCommand {
        /// Command of the requested body type.
        expected: Command,
        /// Command in the message header.
        actual: Command,
    },
    /// A UTF-16LE string contained unpaired surrogates or had odd length.
    #[error("invalid UTF-16LE string in {what}")]
    InvalidUtf16 {
        /// The field being decoded.
        what: &'static str,
    },
    /// A message signature did not verify.
    #[error("SMB2 message signature verification failed")]
    BadSignature,
    /// An encrypted message failed authentication (wrong key, corrupted or
    /// forged message).
    #[error("SMB3 decryption failed: authentication tag mismatch")]
    DecryptFailed,
    /// A frame announced a length above the configured limit.
    #[error("frame of {len} bytes exceeds the limit of {max} bytes")]
    FrameTooLarge {
        /// Announced length.
        len: usize,
        /// Configured maximum.
        max: usize,
    },
    /// A caller-provided output buffer is too small.
    #[error("output buffer too small: need {need} bytes, have {have}")]
    BufferTooSmall {
        /// Bytes required.
        need: usize,
        /// Bytes available.
        have: usize,
    },
    /// The caller passed a value the protocol cannot express (e.g. a name
    /// longer than 65535 bytes).
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    /// Authentication failed or the peer sent an unusable token.
    #[error("authentication failed: {0}")]
    Auth(String),
    /// A feature the codec does not implement (e.g. a compression algorithm).
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    /// The server answered with an error status.
    #[error("server returned {0}")]
    Status(NtStatus),
}

impl ProtoError {
    pub(crate) fn malformed(what: &'static str, reason: &'static str) -> Self {
        ProtoError::Malformed { what, reason }
    }

    /// The [`ErrorKind`] this error maps to.
    pub fn kind(&self) -> ErrorKind {
        match self {
            ProtoError::Truncated { .. }
            | ProtoError::Malformed { .. }
            | ProtoError::UnexpectedCommand { .. }
            | ProtoError::InvalidUtf16 { .. }
            | ProtoError::BadSignature
            | ProtoError::DecryptFailed
            | ProtoError::FrameTooLarge { .. } => ErrorKind::Protocol,
            ProtoError::BufferTooSmall { .. } | ProtoError::InvalidInput(_) => {
                ErrorKind::InvalidInput
            }
            ProtoError::Auth(_) => ErrorKind::PermissionDenied,
            ProtoError::Unsupported(_) => ErrorKind::Unsupported,
            ProtoError::Status(s) => s.kind(),
        }
    }
}

impl From<ProtoError> for Error {
    fn from(err: ProtoError) -> Self {
        match err {
            ProtoError::Status(status) => status.to_error(None),
            other => {
                let kind = other.kind();
                // Integrity failures must never be retried blindly: they
                // indicate tampering or a key mismatch, not a transient fault.
                let retryable = !matches!(
                    other,
                    ProtoError::BadSignature | ProtoError::DecryptFailed
                );
                let e = Error::new(kind, other.to_string());
                if retryable {
                    e
                } else {
                    e.with_retryable(false)
                }
            }
        }
    }
}

impl From<ProtoError> for std::io::Error {
    fn from(err: ProtoError) -> Self {
        let kind = match err.kind() {
            ErrorKind::InvalidInput => std::io::ErrorKind::InvalidInput,
            ErrorKind::PermissionDenied => std::io::ErrorKind::PermissionDenied,
            ErrorKind::Unsupported => std::io::ErrorKind::Unsupported,
            _ => std::io::ErrorKind::InvalidData,
        };
        std::io::Error::new(kind, err)
    }
}

/// Attach the NTSTATUS detail to an existing fsfast error.
pub(crate) fn with_status(e: Error, status: NtStatus) -> Error {
    e.with_detail(Detail::NtStatus(status.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds() {
        assert_eq!(ProtoError::BadSignature.kind(), ErrorKind::Protocol);
        assert_eq!(
            ProtoError::Auth("x".into()).kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            ProtoError::Status(NtStatus::OBJECT_NAME_NOT_FOUND).kind(),
            ErrorKind::NotFound
        );
        let e: Error = ProtoError::DecryptFailed.into();
        assert!(!e.is_retryable());
        let e: Error = ProtoError::Status(NtStatus::ACCESS_DENIED).into();
        assert_eq!(e.kind(), ErrorKind::PermissionDenied);
        assert!(e.details().contains(&Detail::NtStatus(0xC000_0022)));
    }
}
