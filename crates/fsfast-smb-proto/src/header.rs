//! The 64-byte SMB2 packet header ([MS-SMB2] §2.2.1), sync and async forms.

use std::fmt;

use bitflags::bitflags;
use bytes::{BufMut, BytesMut};

use crate::error::{ProtoError, Result};
use crate::status::NtStatus;
use crate::wire::Reader;

/// Size of the SMB2 header in bytes.
pub const HEADER_LEN: usize = 64;
/// `ProtocolId` of a plain SMB2 message: `0xFE 'S' 'M' 'B'`.
pub const PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];
/// `ProtocolId` of an SMB2 TRANSFORM_HEADER (encrypted message).
pub const TRANSFORM_PROTOCOL_ID: [u8; 4] = [0xFD, b'S', b'M', b'B'];
/// `ProtocolId` of an SMB2 COMPRESSION_TRANSFORM_HEADER.
pub const COMPRESSION_PROTOCOL_ID: [u8; 4] = [0xFC, b'S', b'M', b'B'];
/// `ProtocolId` of an SMB1 message (only seen in multi-protocol negotiate).
pub const SMB1_PROTOCOL_ID: [u8; 4] = [0xFF, b'S', b'M', b'B'];

/// Offset of the `Flags` field within the header.
pub const FLAGS_OFFSET: usize = 16;
/// Offset of the `NextCommand` field within the header.
pub const NEXT_COMMAND_OFFSET: usize = 20;
/// Offset of the `MessageId` field within the header.
pub const MESSAGE_ID_OFFSET: usize = 24;
/// Offset of the `SessionId` field within the header.
pub const SESSION_ID_OFFSET: usize = 40;
/// Offset of the 16-byte `Signature` field within the header.
pub const SIGNATURE_OFFSET: usize = 48;

/// MessageId used by the server for unsolicited oplock/lease break
/// notifications.
pub const UNSOLICITED_MESSAGE_ID: u64 = u64::MAX;

/// SMB2 command code.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct Command(pub u16);

macro_rules! commands {
    ($( $name:ident = $val:literal, )*) => {
        impl Command {
            $(
                #[doc = concat!("`SMB2_", stringify!($name), "`.")]
                pub const $name: Command = Command($val);
            )*

            /// Symbolic name, if known.
            pub fn name(self) -> Option<&'static str> {
                match self.0 {
                    $( $val => Some(stringify!($name)), )*
                    _ => None,
                }
            }
        }
    };
}

commands! {
    NEGOTIATE = 0x0000,
    SESSION_SETUP = 0x0001,
    LOGOFF = 0x0002,
    TREE_CONNECT = 0x0003,
    TREE_DISCONNECT = 0x0004,
    CREATE = 0x0005,
    CLOSE = 0x0006,
    FLUSH = 0x0007,
    READ = 0x0008,
    WRITE = 0x0009,
    LOCK = 0x000A,
    IOCTL = 0x000B,
    CANCEL = 0x000C,
    ECHO = 0x000D,
    QUERY_DIRECTORY = 0x000E,
    CHANGE_NOTIFY = 0x000F,
    QUERY_INFO = 0x0010,
    SET_INFO = 0x0011,
    OPLOCK_BREAK = 0x0012,
    SERVER_TO_CLIENT_NOTIFICATION = 0x0013,
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(n) => f.write_str(n),
            None => write!(f, "Command(0x{:04X})", self.0),
        }
    }
}

bitflags! {
    /// Header `Flags` ([MS-SMB2] §2.2.1.2).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct HeaderFlags: u32 {
        /// The message is a response.
        const SERVER_TO_REDIR = 0x0000_0001;
        /// The header is the async form (`AsyncId` instead of `TreeId`).
        const ASYNC_COMMAND = 0x0000_0002;
        /// The request is part of a related compound chain.
        const RELATED_OPERATIONS = 0x0000_0004;
        /// The message is signed.
        const SIGNED = 0x0000_0008;
        /// Priority value mask (3.1.1).
        const PRIORITY_MASK = 0x0000_0070;
        /// The request is a DFS operation.
        const DFS_OPERATIONS = 0x1000_0000;
        /// The request is a replay of an earlier request (3.x).
        const REPLAY_OPERATION = 0x2000_0000;
        const _ = !0;
    }
}

impl HeaderFlags {
    /// The 3-bit I/O priority value (3.1.1).
    pub fn priority(self) -> u8 {
        ((self.bits() & Self::PRIORITY_MASK.bits()) >> 4) as u8
    }

    /// Replace the priority value (only the low 3 bits of `p` are used).
    pub fn with_priority(self, p: u8) -> Self {
        Self::from_bits_retain((self.bits() & !Self::PRIORITY_MASK.bits()) | ((u32::from(p) & 7) << 4))
    }
}

/// The part of the header that differs between the sync and async forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeaderId {
    /// Sync header: `Reserved` (historically the process id) and `TreeId`.
    Sync {
        /// The `Reserved` field (clients send 0 or 0xFEFF).
        process_id: u32,
        /// The tree connect id.
        tree_id: u32,
    },
    /// Async header (interim/final responses to async operations and
    /// CANCEL of an async request).
    Async {
        /// The `AsyncId` assigned by the server.
        async_id: u64,
    },
}

impl Default for HeaderId {
    fn default() -> Self {
        HeaderId::Sync { process_id: 0, tree_id: 0 }
    }
}

/// A decoded SMB2 header.
///
/// For requests in SMB 3.x the `status` field carries `ChannelSequence`
/// (low 16 bits) and a reserved word; see [`Header::channel_sequence`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Header {
    /// Number of credits this request consumes (`CreditCharge`).
    pub credit_charge: u16,
    /// Response status (or `ChannelSequence`/`Reserved` in 3.x requests).
    pub status: NtStatus,
    /// Command code.
    pub command: Command,
    /// `CreditRequest` (requests) or `CreditResponse` (responses).
    pub credits: u16,
    /// Header flags. `ASYNC_COMMAND` is kept consistent with [`Header::id`]
    /// on encode.
    pub flags: HeaderFlags,
    /// Offset of the next message in a compound chain (0 for the last).
    pub next_command: u32,
    /// Message id.
    pub message_id: u64,
    /// Sync (tree id) or async (async id) form.
    pub id: HeaderId,
    /// Session id.
    pub session_id: u64,
    /// Message signature (zero when unsigned).
    pub signature: [u8; 16],
}

impl Header {
    /// A request header for `command` with everything else zero.
    pub fn request(command: Command) -> Self {
        Header { command, ..Default::default() }
    }

    /// A response header for `command`, mirroring a request's ids.
    pub fn response_to(req: &Header, status: NtStatus) -> Self {
        Header {
            credit_charge: req.credit_charge,
            status,
            command: req.command,
            credits: req.credits.max(1),
            flags: HeaderFlags::SERVER_TO_REDIR,
            next_command: 0,
            message_id: req.message_id,
            id: req.id,
            session_id: req.session_id,
            signature: [0; 16],
        }
    }

    /// `true` if this is a response (`SERVER_TO_REDIR`).
    pub fn is_response(&self) -> bool {
        self.flags.contains(HeaderFlags::SERVER_TO_REDIR)
    }

    /// `true` for the async header form.
    pub fn is_async(&self) -> bool {
        matches!(self.id, HeaderId::Async { .. })
    }

    /// `true` if the `SIGNED` flag is set.
    pub fn is_signed(&self) -> bool {
        self.flags.contains(HeaderFlags::SIGNED)
    }

    /// The tree id (sync form only).
    pub fn tree_id(&self) -> Option<u32> {
        match self.id {
            HeaderId::Sync { tree_id, .. } => Some(tree_id),
            HeaderId::Async { .. } => None,
        }
    }

    /// The async id (async form only).
    pub fn async_id(&self) -> Option<u64> {
        match self.id {
            HeaderId::Async { async_id } => Some(async_id),
            HeaderId::Sync { .. } => None,
        }
    }

    /// Set the sync form with `tree_id` (keeps the process id).
    pub fn set_tree_id(&mut self, tree_id: u32) {
        let process_id = match self.id {
            HeaderId::Sync { process_id, .. } => process_id,
            HeaderId::Async { .. } => 0,
        };
        self.id = HeaderId::Sync { process_id, tree_id };
    }

    /// `ChannelSequence` of a 3.x request (low 16 bits of the status field).
    pub fn channel_sequence(&self) -> u16 {
        self.status.0 as u16
    }

    /// Set `ChannelSequence` (3.x requests), clearing the reserved word.
    pub fn set_channel_sequence(&mut self, seq: u16) {
        self.status = NtStatus(u32::from(seq));
    }

    /// `true` for an interim `STATUS_PENDING` async response.
    pub fn is_interim(&self) -> bool {
        self.is_response() && self.is_async() && self.status == NtStatus::PENDING
    }

    /// Flags as written on the wire (ASYNC bit forced to match [`Header::id`]).
    pub fn wire_flags(&self) -> HeaderFlags {
        let mut f = self.flags;
        f.set(HeaderFlags::ASYNC_COMMAND, self.is_async());
        f
    }

    /// Append the 64-byte header to `dst`.
    pub fn encode(&self, dst: &mut BytesMut) {
        dst.reserve(HEADER_LEN);
        dst.put_slice(&PROTOCOL_ID);
        dst.put_u16_le(64);
        dst.put_u16_le(self.credit_charge);
        dst.put_u32_le(self.status.0);
        dst.put_u16_le(self.command.0);
        dst.put_u16_le(self.credits);
        dst.put_u32_le(self.wire_flags().bits());
        dst.put_u32_le(self.next_command);
        dst.put_u64_le(self.message_id);
        match self.id {
            HeaderId::Sync { process_id, tree_id } => {
                dst.put_u32_le(process_id);
                dst.put_u32_le(tree_id);
            }
            HeaderId::Async { async_id } => dst.put_u64_le(async_id),
        }
        dst.put_u64_le(self.session_id);
        dst.put_slice(&self.signature);
    }

    /// The 64 header bytes.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut b = BytesMut::with_capacity(HEADER_LEN);
        self.encode(&mut b);
        let mut out = [0u8; HEADER_LEN];
        out.copy_from_slice(&b);
        out
    }

    /// Decode a header from the start of `buf` (which may contain more).
    pub fn decode(buf: &[u8]) -> Result<Header> {
        let mut r = Reader::new(buf, "SMB2 header");
        let proto: [u8; 4] = r.array()?;
        if proto != PROTOCOL_ID {
            return Err(ProtoError::malformed("SMB2 header", "bad protocol id"));
        }
        if r.u16()? != 64 {
            return Err(ProtoError::malformed("SMB2 header", "structure size is not 64"));
        }
        let credit_charge = r.u16()?;
        let status = NtStatus(r.u32()?);
        let command = Command(r.u16()?);
        let credits = r.u16()?;
        let flags = HeaderFlags::from_bits_retain(r.u32()?);
        let next_command = r.u32()?;
        let message_id = r.u64()?;
        let id = if flags.contains(HeaderFlags::ASYNC_COMMAND) {
            HeaderId::Async { async_id: r.u64()? }
        } else {
            HeaderId::Sync { process_id: r.u32()?, tree_id: r.u32()? }
        };
        let session_id = r.u64()?;
        let signature = r.array()?;
        Ok(Header {
            credit_charge,
            status,
            command,
            credits,
            flags,
            next_command,
            message_id,
            id,
            session_id,
            signature,
        })
    }
}

/// Number of credits a request needs for a payload of `bytes` bytes
/// (`CreditCharge`, [MS-SMB2] §3.1.5.2): one credit per started 64 KiB.
#[inline]
pub fn credit_charge_for(bytes: usize) -> u16 {
    if bytes == 0 {
        1
    } else {
        u16::try_from((bytes - 1) / 65536 + 1).unwrap_or(u16::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_round_trip() {
        let h = Header {
            credit_charge: 3,
            status: NtStatus::ACCESS_DENIED,
            command: Command::READ,
            credits: 256,
            flags: HeaderFlags::SERVER_TO_REDIR | HeaderFlags::SIGNED,
            next_command: 0x68,
            message_id: 0x0102_0304_0506_0708,
            id: HeaderId::Sync { process_id: 0xFEFF, tree_id: 7 },
            session_id: 0x1122_3344_5566_7788,
            signature: [9; 16],
        };
        let b = h.to_bytes();
        assert_eq!(&b[..4], &PROTOCOL_ID);
        assert_eq!(Header::decode(&b).unwrap(), h);
        assert_eq!(h.tree_id(), Some(7));
    }

    #[test]
    fn async_form_sets_flag() {
        let h = Header {
            command: Command::CHANGE_NOTIFY,
            id: HeaderId::Async { async_id: 42 },
            status: NtStatus::PENDING,
            flags: HeaderFlags::SERVER_TO_REDIR,
            ..Default::default()
        };
        let b = h.to_bytes();
        let d = Header::decode(&b).unwrap();
        assert!(d.flags.contains(HeaderFlags::ASYNC_COMMAND));
        assert_eq!(d.async_id(), Some(42));
        assert!(d.is_interim());
    }

    #[test]
    fn rejects_garbage() {
        assert!(Header::decode(&[0u8; 10]).is_err());
        let mut b = Header::default().to_bytes();
        b[4] = 65;
        assert!(Header::decode(&b).is_err());
        b[4] = 64;
        b[0] = 0xFD;
        assert!(Header::decode(&b).is_err());
    }

    #[test]
    fn credits() {
        assert_eq!(credit_charge_for(0), 1);
        assert_eq!(credit_charge_for(1), 1);
        assert_eq!(credit_charge_for(65536), 1);
        assert_eq!(credit_charge_for(65537), 2);
        assert_eq!(credit_charge_for(8 << 20), 128);
    }

    #[test]
    fn priority() {
        let f = HeaderFlags::SIGNED.with_priority(5);
        assert_eq!(f.priority(), 5);
        assert!(f.contains(HeaderFlags::SIGNED));
        assert_eq!(format!("{:?}", Command::QUERY_INFO), "QUERY_INFO");
        assert_eq!(format!("{:?}", Command(0x99)), "Command(0x0099)");
    }
}
