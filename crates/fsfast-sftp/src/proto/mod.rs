//! SFTP version 3 codec, as OpenSSH implements it
//! (draft-ietf-secsh-filexfer-02 plus OpenSSH's `PROTOCOL` extensions).
//!
//! The codec does no I/O. Decoders are total: any input, however hostile,
//! yields a value or a [`ProtoError`], never a panic, and no allocation is
//! sized from an unchecked length or count (see the property tests).

pub mod attrs;
pub mod frame;
pub mod packet;
pub mod wire;

#[cfg(test)]
mod proptests;

use std::fmt;

pub use attrs::{FileAttributes, Kind};
pub use frame::{Frame, FrameAssembler};
pub use packet::{
    Encoded, ExtRequest, Limits, NameEntry, Payload, Reply, Request, Statvfs, Status, Version,
    encode_init, open_flags,
};

/// The protocol version this client speaks.
pub const SFTP_VERSION: u32 = 3;

/// Packet type numbers (`SSH_FXP_*`).
pub mod fxp {
    /// Client hello.
    pub const INIT: u8 = 1;
    /// Server hello.
    pub const VERSION: u8 = 2;
    /// Open a file.
    pub const OPEN: u8 = 3;
    /// Close a handle.
    pub const CLOSE: u8 = 4;
    /// Read from a file handle.
    pub const READ: u8 = 5;
    /// Write to a file handle.
    pub const WRITE: u8 = 6;
    /// Attributes of a path, not following symlinks.
    pub const LSTAT: u8 = 7;
    /// Attributes of an open handle.
    pub const FSTAT: u8 = 8;
    /// Set attributes of a path.
    pub const SETSTAT: u8 = 9;
    /// Set attributes of an open handle.
    pub const FSETSTAT: u8 = 10;
    /// Open a directory for listing.
    pub const OPENDIR: u8 = 11;
    /// Read directory entries.
    pub const READDIR: u8 = 12;
    /// Remove a file.
    pub const REMOVE: u8 = 13;
    /// Create a directory.
    pub const MKDIR: u8 = 14;
    /// Remove a directory.
    pub const RMDIR: u8 = 15;
    /// Canonicalize a path.
    pub const REALPATH: u8 = 16;
    /// Attributes of a path, following symlinks.
    pub const STAT: u8 = 17;
    /// Rename.
    pub const RENAME: u8 = 18;
    /// Read a symlink target.
    pub const READLINK: u8 = 19;
    /// Create a symlink.
    pub const SYMLINK: u8 = 20;
    /// Status reply.
    pub const STATUS: u8 = 101;
    /// Handle reply.
    pub const HANDLE: u8 = 102;
    /// Data reply.
    pub const DATA: u8 = 103;
    /// Name reply.
    pub const NAME: u8 = 104;
    /// Attributes reply.
    pub const ATTRS: u8 = 105;
    /// Extension request.
    pub const EXTENDED: u8 = 200;
    /// Extension reply.
    pub const EXTENDED_REPLY: u8 = 201;
}

/// Status codes (`SSH_FX_*`). Codes above 8 come from later drafts; some
/// v3 servers send them anyway, so they are mapped too.
pub mod status {
    /// Success.
    pub const OK: u32 = 0;
    /// End of file / end of directory.
    pub const EOF: u32 = 1;
    /// No such file or directory.
    pub const NO_SUCH_FILE: u32 = 2;
    /// Permission denied.
    pub const PERMISSION_DENIED: u32 = 3;
    /// Generic failure (OpenSSH: any errno without a better code).
    pub const FAILURE: u32 = 4;
    /// Badly formatted packet or invalid argument.
    pub const BAD_MESSAGE: u32 = 5;
    /// No connection.
    pub const NO_CONNECTION: u32 = 6;
    /// Connection lost.
    pub const CONNECTION_LOST: u32 = 7;
    /// Operation not supported by the server.
    pub const OP_UNSUPPORTED: u32 = 8;
    /// Invalid handle (v4+).
    pub const INVALID_HANDLE: u32 = 9;
    /// No such path (v4+).
    pub const NO_SUCH_PATH: u32 = 10;
    /// File already exists (v4+).
    pub const FILE_ALREADY_EXISTS: u32 = 11;
    /// Write protected (v4+).
    pub const WRITE_PROTECT: u32 = 12;
    /// No media (v4+).
    pub const NO_MEDIA: u32 = 13;
    /// No space left on the file system (v5+).
    pub const NO_SPACE_ON_FILESYSTEM: u32 = 14;
    /// Quota exceeded (v5+).
    pub const QUOTA_EXCEEDED: u32 = 15;
    /// Unknown principal (v5+).
    pub const UNKNOWN_PRINCIPAL: u32 = 16;
    /// Lock conflict (v5+).
    pub const LOCK_CONFLICT: u32 = 17;
    /// Directory not empty (v6).
    pub const DIR_NOT_EMPTY: u32 = 18;
    /// Not a directory (v6).
    pub const NOT_A_DIRECTORY: u32 = 19;
    /// Invalid file name (v6).
    pub const INVALID_FILENAME: u32 = 20;
    /// Too many symbolic links (v6).
    pub const LINK_LOOP: u32 = 21;
    /// File is a directory (v6).
    pub const FILE_IS_A_DIRECTORY: u32 = 24;

    /// The standard message for a code (OpenSSH's wording for v3 codes).
    pub fn name(code: u32) -> &'static str {
        match code {
            OK => "Success",
            EOF => "End of file",
            NO_SUCH_FILE => "No such file",
            PERMISSION_DENIED => "Permission denied",
            FAILURE => "Failure",
            BAD_MESSAGE => "Bad message",
            NO_CONNECTION => "No connection",
            CONNECTION_LOST => "Connection lost",
            OP_UNSUPPORTED => "Operation unsupported",
            INVALID_HANDLE => "Invalid handle",
            NO_SUCH_PATH => "No such path",
            FILE_ALREADY_EXISTS => "File already exists",
            WRITE_PROTECT => "Write protected",
            NO_MEDIA => "No media",
            NO_SPACE_ON_FILESYSTEM => "No space on file system",
            QUOTA_EXCEEDED => "Quota exceeded",
            UNKNOWN_PRINCIPAL => "Unknown principal",
            LOCK_CONFLICT => "Lock conflict",
            DIR_NOT_EMPTY => "Directory not empty",
            NOT_A_DIRECTORY => "Not a directory",
            INVALID_FILENAME => "Invalid file name",
            LINK_LOOP => "Too many symbolic links",
            FILE_IS_A_DIRECTORY => "File is a directory",
            _ => "Unknown error",
        }
    }
}

/// Extension names.
pub mod ext {
    /// Rename replacing the target (POSIX `rename(2)`).
    pub const POSIX_RENAME: &str = "posix-rename@openssh.com";
    /// File system statistics of a path.
    pub const STATVFS: &str = "statvfs@openssh.com";
    /// File system statistics of a handle.
    pub const FSTATVFS: &str = "fstatvfs@openssh.com";
    /// Hard links.
    pub const HARDLINK: &str = "hardlink@openssh.com";
    /// `fsync(2)` of a handle.
    pub const FSYNC: &str = "fsync@openssh.com";
    /// SETSTAT without following symlinks.
    pub const LSETSTAT: &str = "lsetstat@openssh.com";
    /// Server packet and I/O size limits.
    pub const LIMITS: &str = "limits@openssh.com";
    /// REALPATH with `~` expansion.
    pub const EXPAND_PATH: &str = "expand-path@openssh.com";
    /// Server-side copy between handles.
    pub const COPY_DATA: &str = "copy-data";
    /// Home directory of a user.
    pub const HOME_DIRECTORY: &str = "home-directory";
}

/// A malformed packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoError(String);

impl ProtoError {
    /// An error with `msg`.
    pub fn new(msg: impl Into<String>) -> Self {
        ProtoError(msg.into())
    }
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SFTP protocol error: {}", self.0)
    }
}

impl std::error::Error for ProtoError {}

impl From<ProtoError> for fsfast_core::Error {
    fn from(e: ProtoError) -> Self {
        fsfast_core::Error::protocol(e.to_string())
    }
}
