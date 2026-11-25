//! SFTP v3 packets: requests (encode + decode) and replies (encode +
//! decode), including OpenSSH's extensions.
//!
//! Every packet is `uint32 length, byte type, [uint32 request-id], payload`.
//! Requests encode into an [`Encoded`] whose bulk payload (the data of a
//! `WRITE`) stays a separate, zero-copy [`Bytes`].

use bytes::{BufMut, Bytes, BytesMut};

use super::attrs::FileAttributes;
use super::wire::{Cursor, put_string, string_len};
use super::{ProtoError, ext, fxp};

/// An encoded request: `head` is the packet up to the bulk payload, which
/// follows in `payload` (only `WRITE` has one). Sending `head` then
/// `payload` puts exactly one packet on the wire.
#[derive(Debug, Clone)]
pub struct Encoded {
    /// Length, type, id and every field before the bulk data.
    pub head: Bytes,
    /// The data of a `WRITE`, untouched.
    pub payload: Option<Bytes>,
}

impl Encoded {
    /// Total bytes on the wire.
    pub fn len(&self) -> usize {
        self.head.len() + self.payload.as_ref().map_or(0, Bytes::len)
    }

    /// Whether the packet is empty (never true for a valid packet).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The packet as one contiguous buffer (copies a `WRITE` payload).
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.len());
        v.extend_from_slice(&self.head);
        if let Some(p) = &self.payload {
            v.extend_from_slice(p);
        }
        v
    }
}

/// `SSH_FXF_*` open flags.
pub mod open_flags {
    /// Open for reading.
    pub const READ: u32 = 0x01;
    /// Open for writing.
    pub const WRITE: u32 = 0x02;
    /// Writes go to the end of the file.
    pub const APPEND: u32 = 0x04;
    /// Create the file if it does not exist.
    pub const CREAT: u32 = 0x08;
    /// Truncate an existing file to zero length.
    pub const TRUNC: u32 = 0x10;
    /// With `CREAT`: fail if the file exists.
    pub const EXCL: u32 = 0x20;
}

/// An OpenSSH extension request (`SSH_FXP_EXTENDED`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtRequest {
    /// `posix-rename@openssh.com`: rename that replaces the target.
    PosixRename {
        /// Old path.
        old: Bytes,
        /// New path.
        new: Bytes,
    },
    /// `statvfs@openssh.com`.
    Statvfs {
        /// Any path on the file system.
        path: Bytes,
    },
    /// `fstatvfs@openssh.com`.
    Fstatvfs {
        /// An open handle.
        handle: Bytes,
    },
    /// `hardlink@openssh.com`.
    Hardlink {
        /// Existing path.
        old: Bytes,
        /// New link.
        new: Bytes,
    },
    /// `fsync@openssh.com`.
    Fsync {
        /// An open file handle.
        handle: Bytes,
    },
    /// `lsetstat@openssh.com`: SETSTAT that does not follow symlinks.
    Lsetstat {
        /// Path.
        path: Bytes,
        /// Attributes to set.
        attrs: FileAttributes,
    },
    /// `limits@openssh.com`: the server's packet and I/O size limits.
    Limits,
    /// `expand-path@openssh.com`: REALPATH with `~` expansion.
    ExpandPath {
        /// Path, possibly starting with `~` or `~user`.
        path: Bytes,
    },
    /// `copy-data`: server-side copy between two open handles.
    CopyData {
        /// Handle opened for reading.
        read_handle: Bytes,
        /// Offset to read from.
        read_offset: u64,
        /// Bytes to copy; 0 means until end of file.
        length: u64,
        /// Handle opened for writing.
        write_handle: Bytes,
        /// Offset to write to.
        write_offset: u64,
    },
    /// `home-directory`: the home directory of a user.
    HomeDirectory {
        /// User name.
        user: Bytes,
    },
    /// Any other extension, with its raw request payload.
    Other {
        /// Extension name.
        name: Bytes,
        /// Raw request-specific data.
        data: Bytes,
    },
}

impl ExtRequest {
    /// The extension name sent on the wire.
    pub fn name(&self) -> &[u8] {
        match self {
            ExtRequest::PosixRename { .. } => ext::POSIX_RENAME.as_bytes(),
            ExtRequest::Statvfs { .. } => ext::STATVFS.as_bytes(),
            ExtRequest::Fstatvfs { .. } => ext::FSTATVFS.as_bytes(),
            ExtRequest::Hardlink { .. } => ext::HARDLINK.as_bytes(),
            ExtRequest::Fsync { .. } => ext::FSYNC.as_bytes(),
            ExtRequest::Lsetstat { .. } => ext::LSETSTAT.as_bytes(),
            ExtRequest::Limits => ext::LIMITS.as_bytes(),
            ExtRequest::ExpandPath { .. } => ext::EXPAND_PATH.as_bytes(),
            ExtRequest::CopyData { .. } => ext::COPY_DATA.as_bytes(),
            ExtRequest::HomeDirectory { .. } => ext::HOME_DIRECTORY.as_bytes(),
            ExtRequest::Other { name, .. } => name,
        }
    }

    fn body_len(&self) -> usize {
        match self {
            ExtRequest::PosixRename { old, new } | ExtRequest::Hardlink { old, new } => {
                string_len(old.len()) + string_len(new.len())
            }
            ExtRequest::Statvfs { path }
            | ExtRequest::ExpandPath { path }
            | ExtRequest::HomeDirectory { user: path } => string_len(path.len()),
            ExtRequest::Fstatvfs { handle } | ExtRequest::Fsync { handle } => {
                string_len(handle.len())
            }
            ExtRequest::Lsetstat { path, attrs } => string_len(path.len()) + attrs.encoded_len(),
            ExtRequest::Limits => 0,
            ExtRequest::CopyData {
                read_handle,
                write_handle,
                ..
            } => string_len(read_handle.len()) + string_len(write_handle.len()) + 24,
            ExtRequest::Other { data, .. } => data.len(),
        }
    }

    fn encode_body(&self, b: &mut BytesMut) {
        match self {
            ExtRequest::PosixRename { old, new } | ExtRequest::Hardlink { old, new } => {
                put_string(b, old);
                put_string(b, new);
            }
            ExtRequest::Statvfs { path }
            | ExtRequest::ExpandPath { path }
            | ExtRequest::HomeDirectory { user: path } => put_string(b, path),
            ExtRequest::Fstatvfs { handle } | ExtRequest::Fsync { handle } => put_string(b, handle),
            ExtRequest::Lsetstat { path, attrs } => {
                put_string(b, path);
                attrs.encode(b);
            }
            ExtRequest::Limits => {}
            ExtRequest::CopyData {
                read_handle,
                read_offset,
                length,
                write_handle,
                write_offset,
            } => {
                put_string(b, read_handle);
                b.put_u64(*read_offset);
                b.put_u64(*length);
                put_string(b, write_handle);
                b.put_u64(*write_offset);
            }
            ExtRequest::Other { data, .. } => b.put_slice(data),
        }
    }

    fn decode(name: Bytes, c: &mut Cursor) -> Result<Self, ProtoError> {
        let n = name.as_ref();
        let r = if n == ext::POSIX_RENAME.as_bytes() {
            ExtRequest::PosixRename {
                old: c.string()?,
                new: c.string()?,
            }
        } else if n == ext::STATVFS.as_bytes() {
            ExtRequest::Statvfs { path: c.string()? }
        } else if n == ext::FSTATVFS.as_bytes() {
            ExtRequest::Fstatvfs { handle: c.string()? }
        } else if n == ext::HARDLINK.as_bytes() {
            ExtRequest::Hardlink {
                old: c.string()?,
                new: c.string()?,
            }
        } else if n == ext::FSYNC.as_bytes() {
            ExtRequest::Fsync { handle: c.string()? }
        } else if n == ext::LSETSTAT.as_bytes() {
            ExtRequest::Lsetstat {
                path: c.string()?,
                attrs: FileAttributes::decode(c)?,
            }
        } else if n == ext::LIMITS.as_bytes() {
            ExtRequest::Limits
        } else if n == ext::EXPAND_PATH.as_bytes() {
            ExtRequest::ExpandPath { path: c.string()? }
        } else if n == ext::COPY_DATA.as_bytes() {
            ExtRequest::CopyData {
                read_handle: c.string()?,
                read_offset: c.u64()?,
                length: c.u64()?,
                write_handle: c.string()?,
                write_offset: c.u64()?,
            }
        } else if n == ext::HOME_DIRECTORY.as_bytes() {
            ExtRequest::HomeDirectory { user: c.string()? }
        } else {
            return Ok(ExtRequest::Other {
                name,
                data: c.rest(),
            });
        };
        Ok(r)
    }
}

/// A client request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `SSH_FXP_OPEN`.
    Open {
        /// Path.
        path: Bytes,
        /// [`open_flags`] bits.
        pflags: u32,
        /// Initial attributes for a created file.
        attrs: FileAttributes,
    },
    /// `SSH_FXP_CLOSE`.
    Close {
        /// Handle.
        handle: Bytes,
    },
    /// `SSH_FXP_READ`.
    Read {
        /// Handle.
        handle: Bytes,
        /// Offset.
        offset: u64,
        /// Maximum bytes to return.
        len: u32,
    },
    /// `SSH_FXP_WRITE`; `data` travels as the zero-copy payload.
    Write {
        /// Handle.
        handle: Bytes,
        /// Offset.
        offset: u64,
        /// Data.
        data: Bytes,
    },
    /// `SSH_FXP_LSTAT`.
    Lstat {
        /// Path.
        path: Bytes,
    },
    /// `SSH_FXP_FSTAT`.
    Fstat {
        /// Handle.
        handle: Bytes,
    },
    /// `SSH_FXP_SETSTAT`.
    Setstat {
        /// Path.
        path: Bytes,
        /// Attributes to set.
        attrs: FileAttributes,
    },
    /// `SSH_FXP_FSETSTAT`.
    Fsetstat {
        /// Handle.
        handle: Bytes,
        /// Attributes to set.
        attrs: FileAttributes,
    },
    /// `SSH_FXP_OPENDIR`.
    Opendir {
        /// Path.
        path: Bytes,
    },
    /// `SSH_FXP_READDIR`.
    Readdir {
        /// Directory handle.
        handle: Bytes,
    },
    /// `SSH_FXP_REMOVE`.
    Remove {
        /// Path.
        path: Bytes,
    },
    /// `SSH_FXP_MKDIR`.
    Mkdir {
        /// Path.
        path: Bytes,
        /// Attributes of the new directory.
        attrs: FileAttributes,
    },
    /// `SSH_FXP_RMDIR`.
    Rmdir {
        /// Path.
        path: Bytes,
    },
    /// `SSH_FXP_REALPATH`.
    Realpath {
        /// Path.
        path: Bytes,
    },
    /// `SSH_FXP_STAT` (follows symlinks).
    Stat {
        /// Path.
        path: Bytes,
    },
    /// `SSH_FXP_RENAME` (v3: fails if the target exists on OpenSSH).
    Rename {
        /// Old path.
        old: Bytes,
        /// New path.
        new: Bytes,
    },
    /// `SSH_FXP_READLINK`.
    Readlink {
        /// Path of the link.
        path: Bytes,
    },
    /// `SSH_FXP_SYMLINK`. Encoded in OpenSSH's argument order (target
    /// first, then the link path), which every common server follows; the
    /// draft specifies the opposite order.
    Symlink {
        /// Path of the new link.
        link: Bytes,
        /// What the link points to.
        target: Bytes,
    },
    /// `SSH_FXP_EXTENDED`.
    Extended(ExtRequest),
}

impl Request {
    /// The packet type byte.
    pub fn packet_type(&self) -> u8 {
        match self {
            Request::Open { .. } => fxp::OPEN,
            Request::Close { .. } => fxp::CLOSE,
            Request::Read { .. } => fxp::READ,
            Request::Write { .. } => fxp::WRITE,
            Request::Lstat { .. } => fxp::LSTAT,
            Request::Fstat { .. } => fxp::FSTAT,
            Request::Setstat { .. } => fxp::SETSTAT,
            Request::Fsetstat { .. } => fxp::FSETSTAT,
            Request::Opendir { .. } => fxp::OPENDIR,
            Request::Readdir { .. } => fxp::READDIR,
            Request::Remove { .. } => fxp::REMOVE,
            Request::Mkdir { .. } => fxp::MKDIR,
            Request::Rmdir { .. } => fxp::RMDIR,
            Request::Realpath { .. } => fxp::REALPATH,
            Request::Stat { .. } => fxp::STAT,
            Request::Rename { .. } => fxp::RENAME,
            Request::Readlink { .. } => fxp::READLINK,
            Request::Symlink { .. } => fxp::SYMLINK,
            Request::Extended(_) => fxp::EXTENDED,
        }
    }

    /// Body length after the type byte and id, excluding a WRITE payload.
    fn head_body_len(&self) -> usize {
        match self {
            Request::Open { path, attrs, .. } => string_len(path.len()) + 4 + attrs.encoded_len(),
            Request::Close { handle }
            | Request::Fstat { handle }
            | Request::Readdir { handle } => string_len(handle.len()),
            Request::Read { handle, .. } => string_len(handle.len()) + 12,
            Request::Write { handle, .. } => string_len(handle.len()) + 8 + 4,
            Request::Lstat { path }
            | Request::Opendir { path }
            | Request::Remove { path }
            | Request::Rmdir { path }
            | Request::Realpath { path }
            | Request::Stat { path }
            | Request::Readlink { path } => string_len(path.len()),
            Request::Setstat { path, attrs } | Request::Mkdir { path, attrs } => {
                string_len(path.len()) + attrs.encoded_len()
            }
            Request::Fsetstat { handle, attrs } => string_len(handle.len()) + attrs.encoded_len(),
            Request::Rename { old, new } => string_len(old.len()) + string_len(new.len()),
            Request::Symlink { link, target } => string_len(link.len()) + string_len(target.len()),
            Request::Extended(e) => string_len(e.name().len()) + e.body_len(),
        }
    }

    /// Encode with request id `id`.
    pub fn encode(&self, id: u32) -> Encoded {
        let body = self.head_body_len();
        let payload_len = match self {
            Request::Write { data, .. } => data.len(),
            _ => 0,
        };
        let mut b = BytesMut::with_capacity(4 + 5 + body);
        // Packet length: type + id + body + bulk payload.
        b.put_u32((5 + body + payload_len) as u32);
        b.put_u8(self.packet_type());
        b.put_u32(id);
        let mut payload = None;
        match self {
            Request::Open {
                path,
                pflags,
                attrs,
            } => {
                put_string(&mut b, path);
                b.put_u32(*pflags);
                attrs.encode(&mut b);
            }
            Request::Close { handle }
            | Request::Fstat { handle }
            | Request::Readdir { handle } => put_string(&mut b, handle),
            Request::Read {
                handle,
                offset,
                len,
            } => {
                put_string(&mut b, handle);
                b.put_u64(*offset);
                b.put_u32(*len);
            }
            Request::Write {
                handle,
                offset,
                data,
            } => {
                put_string(&mut b, handle);
                b.put_u64(*offset);
                b.put_u32(data.len() as u32);
                payload = (!data.is_empty()).then(|| data.clone());
            }
            Request::Lstat { path }
            | Request::Opendir { path }
            | Request::Remove { path }
            | Request::Rmdir { path }
            | Request::Realpath { path }
            | Request::Stat { path }
            | Request::Readlink { path } => put_string(&mut b, path),
            Request::Setstat { path, attrs } | Request::Mkdir { path, attrs } => {
                put_string(&mut b, path);
                attrs.encode(&mut b);
            }
            Request::Fsetstat { handle, attrs } => {
                put_string(&mut b, handle);
                attrs.encode(&mut b);
            }
            Request::Rename { old, new } => {
                put_string(&mut b, old);
                put_string(&mut b, new);
            }
            Request::Symlink { link, target } => {
                // OpenSSH order: target, then link (see the variant docs).
                put_string(&mut b, target);
                put_string(&mut b, link);
            }
            Request::Extended(e) => {
                put_string(&mut b, e.name());
                e.encode_body(&mut b);
            }
        }
        debug_assert_eq!(b.len(), 4 + 5 + body);
        Encoded {
            head: b.freeze(),
            payload,
        }
    }

    /// Decode a request packet body (everything after the length field).
    /// Returns the request id and the request. Used by test servers and
    /// property tests; the client itself never decodes requests.
    pub fn decode(packet: Bytes) -> Result<(u32, Request), ProtoError> {
        let mut c = Cursor::new(packet);
        let ty = c.u8()?;
        let id = c.u32()?;
        let r = match ty {
            fxp::OPEN => Request::Open {
                path: c.string()?,
                pflags: c.u32()?,
                attrs: FileAttributes::decode(&mut c)?,
            },
            fxp::CLOSE => Request::Close { handle: c.string()? },
            fxp::READ => Request::Read {
                handle: c.string()?,
                offset: c.u64()?,
                len: c.u32()?,
            },
            fxp::WRITE => Request::Write {
                handle: c.string()?,
                offset: c.u64()?,
                data: c.string()?,
            },
            fxp::LSTAT => Request::Lstat { path: c.string()? },
            fxp::FSTAT => Request::Fstat { handle: c.string()? },
            fxp::SETSTAT => Request::Setstat {
                path: c.string()?,
                attrs: FileAttributes::decode(&mut c)?,
            },
            fxp::FSETSTAT => Request::Fsetstat {
                handle: c.string()?,
                attrs: FileAttributes::decode(&mut c)?,
            },
            fxp::OPENDIR => Request::Opendir { path: c.string()? },
            fxp::READDIR => Request::Readdir { handle: c.string()? },
            fxp::REMOVE => Request::Remove { path: c.string()? },
            fxp::MKDIR => Request::Mkdir {
                path: c.string()?,
                attrs: FileAttributes::decode(&mut c)?,
            },
            fxp::RMDIR => Request::Rmdir { path: c.string()? },
            fxp::REALPATH => Request::Realpath { path: c.string()? },
            fxp::STAT => Request::Stat { path: c.string()? },
            fxp::RENAME => Request::Rename {
                old: c.string()?,
                new: c.string()?,
            },
            fxp::READLINK => Request::Readlink { path: c.string()? },
            fxp::SYMLINK => {
                let target = c.string()?;
                let link = c.string()?;
                Request::Symlink { link, target }
            }
            fxp::EXTENDED => {
                let name = c.string()?;
                Request::Extended(ExtRequest::decode(name, &mut c)?)
            }
            other => return Err(ProtoError::new(format!("unknown request type {other}"))),
        };
        c.finish("request")?;
        Ok((id, r))
    }
}

/// An `SSH_FXP_STATUS` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// `SSH_FX_*` code (see [`super::status`]).
    pub code: u32,
    /// Human-readable message (may be empty; some old servers omit it).
    pub message: String,
    /// Language tag.
    pub lang: String,
}

impl Status {
    /// A status with `code` and the standard message for it.
    pub fn new(code: u32) -> Self {
        Status {
            code,
            message: super::status::name(code).to_owned(),
            lang: String::new(),
        }
    }

    /// Whether this is `SSH_FX_OK`.
    pub fn is_ok(&self) -> bool {
        self.code == super::status::OK
    }
}

/// One entry of an `SSH_FXP_NAME` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameEntry {
    /// File name (a bare name for READDIR, a full path for REALPATH).
    pub filename: String,
    /// `ls -l`-style line (informational).
    pub longname: String,
    /// Attributes (READDIR replies carry `lstat` attributes).
    pub attrs: FileAttributes,
}

/// The data of an `SSH_FXP_DATA` reply, kept as the received chunks so the
/// receive path never copies it: the consumer copies once into its final
/// buffer (or takes the single chunk as is).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Payload {
    chunks: Vec<Bytes>,
    len: usize,
}

impl Payload {
    /// A payload from one buffer.
    pub fn from_bytes(b: Bytes) -> Self {
        let len = b.len();
        Payload {
            chunks: if len == 0 { Vec::new() } else { vec![b] },
            len,
        }
    }

    /// A payload from several buffers (empty ones are dropped).
    pub fn from_chunks(chunks: Vec<Bytes>) -> Self {
        let chunks: Vec<Bytes> = chunks.into_iter().filter(|c| !c.is_empty()).collect();
        let len = chunks.iter().map(Bytes::len).sum();
        Payload { chunks, len }
    }

    /// Total length.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The chunks, in order.
    pub fn chunks(&self) -> &[Bytes] {
        &self.chunks
    }

    /// Keep only the first `n` bytes.
    pub fn truncate(&mut self, n: usize) {
        if n >= self.len {
            return;
        }
        let mut left = n;
        let mut keep = 0;
        for c in self.chunks.iter_mut() {
            if left == 0 {
                break;
            }
            if c.len() > left {
                c.truncate(left);
            }
            left -= c.len();
            keep += 1;
        }
        self.chunks.truncate(keep);
        self.len = n;
    }

    /// One contiguous buffer: free for a single chunk, one copy otherwise.
    pub fn into_bytes(self) -> Bytes {
        match self.chunks.len() {
            0 => Bytes::new(),
            1 => self.chunks.into_iter().next().unwrap_or_default(),
            _ => {
                let mut b = BytesMut::with_capacity(self.len);
                for c in &self.chunks {
                    b.extend_from_slice(c);
                }
                b.freeze()
            }
        }
    }

    /// Append every byte to `dst`.
    pub fn copy_to(&self, dst: &mut BytesMut) {
        for c in &self.chunks {
            dst.extend_from_slice(c);
        }
    }
}

/// `limits@openssh.com` reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest packet the server accepts (0: unknown).
    pub max_packet_len: u64,
    /// Largest READ length the server honours in full (0: unknown).
    pub max_read_len: u64,
    /// Largest WRITE length the server accepts (0: unknown).
    pub max_write_len: u64,
    /// Maximum number of open handles (0: unknown).
    pub max_open_handles: u64,
}

impl Limits {
    /// Decode an `SSH_FXP_EXTENDED_REPLY` body.
    pub fn decode(data: Bytes) -> Result<Self, ProtoError> {
        let mut c = Cursor::new(data);
        let l = Limits {
            max_packet_len: c.u64()?,
            max_read_len: c.u64()?,
            max_write_len: c.u64()?,
            max_open_handles: c.u64()?,
        };
        c.finish("limits@openssh.com reply")?;
        Ok(l)
    }

    /// Encode as an `SSH_FXP_EXTENDED_REPLY` body.
    pub fn encode(&self) -> Bytes {
        let mut b = BytesMut::with_capacity(32);
        b.put_u64(self.max_packet_len);
        b.put_u64(self.max_read_len);
        b.put_u64(self.max_write_len);
        b.put_u64(self.max_open_handles);
        b.freeze()
    }
}

/// `statvfs@openssh.com` / `fstatvfs@openssh.com` reply (`struct statvfs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Statvfs {
    /// File system block size.
    pub bsize: u64,
    /// Fundamental block size.
    pub frsize: u64,
    /// Blocks (in `frsize` units).
    pub blocks: u64,
    /// Free blocks.
    pub bfree: u64,
    /// Free blocks for unprivileged users.
    pub bavail: u64,
    /// Inodes.
    pub files: u64,
    /// Free inodes.
    pub ffree: u64,
    /// Free inodes for unprivileged users.
    pub favail: u64,
    /// File system id.
    pub fsid: u64,
    /// Mount flags (bit 0: read-only, bit 1: nosuid).
    pub flag: u64,
    /// Maximum file name length.
    pub namemax: u64,
}

impl Statvfs {
    /// Decode an `SSH_FXP_EXTENDED_REPLY` body.
    pub fn decode(data: Bytes) -> Result<Self, ProtoError> {
        let mut c = Cursor::new(data);
        let s = Statvfs {
            bsize: c.u64()?,
            frsize: c.u64()?,
            blocks: c.u64()?,
            bfree: c.u64()?,
            bavail: c.u64()?,
            files: c.u64()?,
            ffree: c.u64()?,
            favail: c.u64()?,
            fsid: c.u64()?,
            flag: c.u64()?,
            namemax: c.u64()?,
        };
        c.finish("statvfs@openssh.com reply")?;
        Ok(s)
    }

    /// Encode as an `SSH_FXP_EXTENDED_REPLY` body.
    pub fn encode(&self) -> Bytes {
        let mut b = BytesMut::with_capacity(88);
        for v in [
            self.bsize,
            self.frsize,
            self.blocks,
            self.bfree,
            self.bavail,
            self.files,
            self.ffree,
            self.favail,
            self.fsid,
            self.flag,
            self.namemax,
        ] {
            b.put_u64(v);
        }
        b.freeze()
    }
}

/// A decoded server reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// `SSH_FXP_STATUS`.
    Status(Status),
    /// `SSH_FXP_HANDLE`.
    Handle(Bytes),
    /// `SSH_FXP_DATA`.
    Data(Payload),
    /// `SSH_FXP_NAME`.
    Name(Vec<NameEntry>),
    /// `SSH_FXP_ATTRS`.
    Attrs(FileAttributes),
    /// `SSH_FXP_EXTENDED_REPLY` (request-specific body).
    ExtendedReply(Bytes),
}

impl Reply {
    /// A short name of the reply type, for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Reply::Status(_) => "STATUS",
            Reply::Handle(_) => "HANDLE",
            Reply::Data(_) => "DATA",
            Reply::Name(_) => "NAME",
            Reply::Attrs(_) => "ATTRS",
            Reply::ExtendedReply(_) => "EXTENDED_REPLY",
        }
    }

    /// Decode the body that follows the type byte and request id.
    pub fn decode(ty: u8, body: Bytes) -> Result<Reply, ProtoError> {
        let mut c = Cursor::new(body);
        let r = match ty {
            fxp::STATUS => {
                let code = c.u32()?;
                // OpenSSH always sends message and language; a few old
                // servers end the packet after the code.
                let (message, lang) = if c.remaining() == 0 {
                    (super::status::name(code).to_owned(), String::new())
                } else {
                    let m = c.string_lossy()?;
                    let l = if c.remaining() == 0 {
                        String::new()
                    } else {
                        c.string_lossy()?
                    };
                    (m, l)
                };
                Reply::Status(Status {
                    code,
                    message,
                    lang,
                })
            }
            fxp::HANDLE => Reply::Handle(c.string()?),
            fxp::DATA => Reply::Data(Payload::from_bytes(c.string()?)),
            fxp::NAME => {
                let n = c.u32()? as usize;
                // An entry is at least 12 bytes (two empty strings and an
                // empty ATTRS); never trust the count for the allocation.
                if n > c.remaining() / 12 {
                    return Err(ProtoError::new(format!(
                        "NAME claims {n} entries in {} bytes",
                        c.remaining()
                    )));
                }
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(NameEntry {
                        filename: c.string_lossy()?,
                        longname: c.string_lossy()?,
                        attrs: FileAttributes::decode(&mut c)?,
                    });
                }
                Reply::Name(v)
            }
            fxp::ATTRS => Reply::Attrs(FileAttributes::decode(&mut c)?),
            fxp::EXTENDED_REPLY => Reply::ExtendedReply(c.rest()),
            other => return Err(ProtoError::new(format!("unknown reply type {other}"))),
        };
        c.finish(r.type_name())?;
        Ok(r)
    }

    /// Encode as a complete packet (length included) with id `id`.
    pub fn encode(&self, id: u32) -> Bytes {
        let mut b = BytesMut::new();
        b.put_u32(0); // patched below
        let ty = match self {
            Reply::Status(_) => fxp::STATUS,
            Reply::Handle(_) => fxp::HANDLE,
            Reply::Data(_) => fxp::DATA,
            Reply::Name(_) => fxp::NAME,
            Reply::Attrs(_) => fxp::ATTRS,
            Reply::ExtendedReply(_) => fxp::EXTENDED_REPLY,
        };
        b.put_u8(ty);
        b.put_u32(id);
        match self {
            Reply::Status(s) => {
                b.put_u32(s.code);
                put_string(&mut b, s.message.as_bytes());
                put_string(&mut b, s.lang.as_bytes());
            }
            Reply::Handle(h) => put_string(&mut b, h),
            Reply::Data(p) => {
                b.put_u32(p.len() as u32);
                p.copy_to(&mut b);
            }
            Reply::Name(v) => {
                b.put_u32(v.len() as u32);
                for e in v {
                    put_string(&mut b, e.filename.as_bytes());
                    put_string(&mut b, e.longname.as_bytes());
                    e.attrs.encode(&mut b);
                }
            }
            Reply::Attrs(a) => a.encode(&mut b),
            Reply::ExtendedReply(d) => b.put_slice(d),
        }
        let len = (b.len() - 4) as u32;
        b[..4].copy_from_slice(&len.to_be_bytes());
        b.freeze()
    }
}

/// `SSH_FXP_INIT` packet (length included) asking for `version`.
pub fn encode_init(version: u32) -> Bytes {
    let mut b = BytesMut::with_capacity(9);
    b.put_u32(5);
    b.put_u8(fxp::INIT);
    b.put_u32(version);
    b.freeze()
}

/// The server's `SSH_FXP_VERSION`: protocol version and extensions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Version {
    /// Protocol version the server speaks.
    pub version: u32,
    /// `(name, data)` extension pairs, in the server's order.
    pub extensions: Vec<(String, Bytes)>,
}

impl Version {
    /// Decode a VERSION packet body (after the length field, type byte
    /// included).
    pub fn decode(packet: Bytes) -> Result<Self, ProtoError> {
        let mut c = Cursor::new(packet);
        let ty = c.u8()?;
        if ty != fxp::VERSION {
            return Err(ProtoError::new(format!(
                "expected SSH_FXP_VERSION, got packet type {ty}"
            )));
        }
        let version = c.u32()?;
        let mut extensions = Vec::new();
        while c.remaining() > 0 {
            let name = c.string_lossy()?;
            let data = c.string()?;
            extensions.push((name, data));
        }
        Ok(Version {
            version,
            extensions,
        })
    }

    /// Encode as a complete packet (length included).
    pub fn encode(&self) -> Bytes {
        let mut b = BytesMut::new();
        b.put_u32(0);
        b.put_u8(fxp::VERSION);
        b.put_u32(self.version);
        for (n, d) in &self.extensions {
            put_string(&mut b, n.as_bytes());
            put_string(&mut b, d);
        }
        let len = (b.len() - 4) as u32;
        b[..4].copy_from_slice(&len.to_be_bytes());
        b.freeze()
    }

    /// Whether extension `name` is offered (any version string).
    pub fn has(&self, name: &str) -> bool {
        self.extensions.iter().any(|(n, _)| n == name)
    }
}

#[cfg(test)]
mod tests {
    use super::super::status;
    use super::*;

    fn b(s: &str) -> Bytes {
        Bytes::copy_from_slice(s.as_bytes())
    }

    fn roundtrip(r: Request) {
        let e = r.encode(42);
        let wire = Bytes::from(e.to_vec());
        let len = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
        assert_eq!(len, wire.len() - 4, "length field of {r:?}");
        let (id, d) = Request::decode(wire.slice(4..)).unwrap();
        assert_eq!(id, 42);
        assert_eq!(d, r);
    }

    #[test]
    fn every_request_roundtrips() {
        let h = Bytes::from_static(b"\0\0\0\x07");
        let a = FileAttributes::with_size(9);
        for r in [
            Request::Open {
                path: b("/a b"),
                pflags: open_flags::WRITE | open_flags::CREAT,
                attrs: a.clone(),
            },
            Request::Close { handle: h.clone() },
            Request::Read {
                handle: h.clone(),
                offset: 1 << 33,
                len: 261_120,
            },
            Request::Write {
                handle: h.clone(),
                offset: 7,
                data: b("payload"),
            },
            Request::Write {
                handle: h.clone(),
                offset: 7,
                data: Bytes::new(),
            },
            Request::Lstat { path: b("l") },
            Request::Fstat { handle: h.clone() },
            Request::Setstat {
                path: b("s"),
                attrs: FileAttributes::with_times(1, 2),
            },
            Request::Fsetstat {
                handle: h.clone(),
                attrs: a.clone(),
            },
            Request::Opendir { path: b("/") },
            Request::Readdir { handle: h.clone() },
            Request::Remove { path: b("r") },
            Request::Mkdir {
                path: b("m"),
                attrs: FileAttributes::default(),
            },
            Request::Rmdir { path: b("d") },
            Request::Realpath { path: b(".") },
            Request::Stat { path: b("ü") },
            Request::Rename {
                old: b("o"),
                new: b("n"),
            },
            Request::Readlink { path: b("k") },
            Request::Symlink {
                link: b("link"),
                target: b("target"),
            },
            Request::Extended(ExtRequest::PosixRename {
                old: b("o"),
                new: b("n"),
            }),
            Request::Extended(ExtRequest::Statvfs { path: b("/") }),
            Request::Extended(ExtRequest::Fstatvfs { handle: h.clone() }),
            Request::Extended(ExtRequest::Hardlink {
                old: b("o"),
                new: b("n"),
            }),
            Request::Extended(ExtRequest::Fsync { handle: h.clone() }),
            Request::Extended(ExtRequest::Lsetstat {
                path: b("p"),
                attrs: a,
            }),
            Request::Extended(ExtRequest::Limits),
            Request::Extended(ExtRequest::ExpandPath { path: b("~/x") }),
            Request::Extended(ExtRequest::CopyData {
                read_handle: h.clone(),
                read_offset: 1,
                length: 0,
                write_handle: b("w"),
                write_offset: 3,
            }),
            Request::Extended(ExtRequest::HomeDirectory { user: b("") }),
            Request::Extended(ExtRequest::Other {
                name: b("x@example.com"),
                data: b("raw"),
            }),
        ] {
            roundtrip(r);
        }
    }

    #[test]
    fn symlink_uses_openssh_argument_order() {
        let e = Request::Symlink {
            link: b("L"),
            target: b("T"),
        }
        .encode(1);
        // len(4) type(1) id(4) then the first string is the target.
        assert_eq!(&e.head[9..14], b"\0\0\0\x01T");
    }

    #[test]
    fn write_payload_is_not_copied() {
        let data = Bytes::from(vec![7u8; 1000]);
        let e = Request::Write {
            handle: b("h"),
            offset: 0,
            data: data.clone(),
        }
        .encode(3);
        let p = e.payload.unwrap();
        assert_eq!(p.as_ptr(), data.as_ptr());
        assert_eq!(e.head.len(), 4 + 1 + 4 + 5 + 8 + 4);
    }

    #[test]
    fn replies_roundtrip() {
        for r in [
            Reply::Status(Status::new(status::NO_SUCH_FILE)),
            Reply::Handle(b("hh")),
            Reply::Data(Payload::from_bytes(b("data"))),
            Reply::Data(Payload::default()),
            Reply::Name(vec![NameEntry {
                filename: "f".into(),
                longname: "-rw-r--r-- f".into(),
                attrs: FileAttributes::with_size(3),
            }]),
            Reply::Attrs(FileAttributes::default()),
            Reply::ExtendedReply(
                Limits {
                    max_packet_len: 1,
                    max_read_len: 2,
                    max_write_len: 3,
                    max_open_handles: 4,
                }
                .encode(),
            ),
        ] {
            let wire = r.encode(9);
            assert_eq!(&wire[5..9], &9u32.to_be_bytes());
            let d = Reply::decode(wire[4], wire.slice(9..)).unwrap();
            assert_eq!(d, r);
        }
    }

    #[test]
    fn status_without_message_is_accepted() {
        let d = Reply::decode(fxp::STATUS, Bytes::from_static(&[0, 0, 0, 1])).unwrap();
        assert_eq!(
            d,
            Reply::Status(Status {
                code: 1,
                message: "End of file".into(),
                lang: String::new()
            })
        );
    }

    #[test]
    fn version_roundtrip_and_ext_structs() {
        let v = Version {
            version: 3,
            extensions: vec![
                ("posix-rename@openssh.com".into(), b("1")),
                ("limits@openssh.com".into(), b("1")),
            ],
        };
        let wire = v.encode();
        let d = Version::decode(wire.slice(4..)).unwrap();
        assert_eq!(d, v);
        assert!(d.has("limits@openssh.com"));
        assert!(!d.has("copy-data"));
        let s = Statvfs {
            bsize: 4096,
            namemax: 255,
            ..Default::default()
        };
        assert_eq!(Statvfs::decode(s.encode()).unwrap(), s);
        assert!(Statvfs::decode(b("short")).is_err());
        assert!(Limits::decode(b("short")).is_err());
        assert_eq!(&encode_init(3)[..], &[0, 0, 0, 5, 1, 0, 0, 0, 3]);
    }

    #[test]
    fn payload_truncate_and_concat() {
        let mut p = Payload::from_chunks(vec![b("abc"), Bytes::new(), b("defg"), b("h")]);
        assert_eq!(p.len(), 8);
        assert_eq!(p.chunks().len(), 3);
        p.truncate(5);
        assert_eq!(p.len(), 5);
        assert_eq!(&p.clone().into_bytes()[..], b"abcde");
        p.truncate(3);
        assert_eq!(p.chunks().len(), 1);
        assert_eq!(&p.into_bytes()[..], b"abc");
    }

    #[test]
    fn hostile_name_count_is_rejected() {
        let mut body = BytesMut::new();
        body.put_u32(u32::MAX);
        assert!(Reply::decode(fxp::NAME, body.freeze()).is_err());
    }
}
