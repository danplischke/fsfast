//! CLOSE, FLUSH, LOCK, ECHO, CANCEL and the oplock/lease break messages
//! ([MS-SMB2] §2.2.15–§2.2.18, §2.2.23–§2.2.30).

use bitflags::bitflags;
use bytes::{BufMut, Bytes, BytesMut};

use super::session::empty_message;
use super::{Message, RawMessage, body_reader};
use crate::error::{ProtoError, Result};
use crate::fscc::{FileAttributes, FileTime, OplockLevel};
use crate::header::Command;
use crate::types::FileId;
use crate::wire::len_u16;

bitflags! {
    /// CLOSE `Flags`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct CloseFlags: u16 {
        /// Return the file's attributes in the response.
        const POSTQUERY_ATTRIB = 0x0001;
        const _ = !0;
    }
}

/// SMB2 CLOSE request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CloseRequest {
    /// Flags.
    pub flags: CloseFlags,
    /// Handle to close.
    pub file_id: FileId,
}

impl Message for CloseRequest {
    const COMMAND: Command = Command::CLOSE;
    const RESPONSE: bool = false;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u16_le(24);
        dst.put_u16_le(self.flags.bits());
        dst.put_u32_le(0);
        self.file_id.put(dst);
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "CLOSE request", 24)?;
        let flags = CloseFlags::from_bits_retain(r.u16()?);
        r.skip(4)?;
        Ok(CloseRequest { flags, file_id: FileId::read(&mut r)? })
    }
}

/// SMB2 CLOSE response. The attribute fields are only valid when the
/// request had `POSTQUERY_ATTRIB` (and the response echoes it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CloseResponse {
    /// Flags (echo of `POSTQUERY_ATTRIB`).
    pub flags: CloseFlags,
    /// Creation time.
    pub creation_time: FileTime,
    /// Last access time.
    pub last_access_time: FileTime,
    /// Last write time.
    pub last_write_time: FileTime,
    /// Change time.
    pub change_time: FileTime,
    /// Allocation size.
    pub allocation_size: u64,
    /// File size.
    pub end_of_file: u64,
    /// Attributes.
    pub file_attributes: FileAttributes,
}

impl Message for CloseResponse {
    const COMMAND: Command = Command::CLOSE;
    const RESPONSE: bool = true;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u16_le(60);
        dst.put_u16_le(self.flags.bits());
        dst.put_u32_le(0);
        for t in [self.creation_time, self.last_access_time, self.last_write_time, self.change_time] {
            dst.put_u64_le(t.0);
        }
        dst.put_u64_le(self.allocation_size);
        dst.put_u64_le(self.end_of_file);
        dst.put_u32_le(self.file_attributes.bits());
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "CLOSE response", 60)?;
        let flags = CloseFlags::from_bits_retain(r.u16()?);
        r.skip(4)?;
        Ok(CloseResponse {
            flags,
            creation_time: FileTime(r.u64()?),
            last_access_time: FileTime(r.u64()?),
            last_write_time: FileTime(r.u64()?),
            change_time: FileTime(r.u64()?),
            allocation_size: r.u64()?,
            end_of_file: r.u64()?,
            file_attributes: FileAttributes::from_bits_retain(r.u32()?),
        })
    }
}

/// SMB2 FLUSH request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlushRequest {
    /// Handle to flush.
    pub file_id: FileId,
}

impl Message for FlushRequest {
    const COMMAND: Command = Command::FLUSH;
    const RESPONSE: bool = false;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u16_le(24);
        dst.put_u16_le(0);
        dst.put_u32_le(0);
        self.file_id.put(dst);
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "FLUSH request", 24)?;
        r.skip(6)?;
        Ok(FlushRequest { file_id: FileId::read(&mut r)? })
    }
}

empty_message!(
    /// SMB2 FLUSH response.
    FlushResponse, Command::FLUSH, true, "FLUSH response"
);
empty_message!(
    /// SMB2 ECHO request.
    EchoRequest, Command::ECHO, false, "ECHO request"
);
empty_message!(
    /// SMB2 ECHO response.
    EchoResponse, Command::ECHO, true, "ECHO response"
);
empty_message!(
    /// SMB2 CANCEL request (no response). Send it with the MessageId (sync)
    /// or AsyncId (async) of the request to cancel and no credit charge.
    CancelRequest, Command::CANCEL, false, "CANCEL request"
);
empty_message!(
    /// SMB2 LOCK response.
    LockResponse, Command::LOCK, true, "LOCK response"
);

bitflags! {
    /// SMB2_LOCK_ELEMENT `Flags`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct LockFlags: u32 {
        /// Shared lock.
        const SHARED = 0x0000_0001;
        /// Exclusive lock.
        const EXCLUSIVE = 0x0000_0002;
        /// Unlock.
        const UNLOCK = 0x0000_0004;
        /// Fail immediately instead of waiting.
        const FAIL_IMMEDIATELY = 0x0000_0010;
        const _ = !0;
    }
}

/// One byte-range lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LockElement {
    /// Start of the range.
    pub offset: u64,
    /// Length of the range.
    pub length: u64,
    /// Lock flags.
    pub flags: LockFlags,
}

/// SMB2 LOCK request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LockRequest {
    /// `LockSequenceNumber` (low 4 bits) and `LockSequenceIndex` (high 28
    /// bits), used for resilient/durable handles.
    pub lock_sequence: u32,
    /// Target handle.
    pub file_id: FileId,
    /// Locks (at least one).
    pub locks: Vec<LockElement>,
}

impl Message for LockRequest {
    const COMMAND: Command = Command::LOCK;
    const RESPONSE: bool = false;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        if self.locks.is_empty() {
            return Err(ProtoError::InvalidInput("LOCK request needs at least one lock"));
        }
        dst.put_u16_le(48);
        dst.put_u16_le(len_u16(self.locks.len(), "too many locks")?);
        dst.put_u32_le(self.lock_sequence);
        self.file_id.put(dst);
        for l in &self.locks {
            dst.put_u64_le(l.offset);
            dst.put_u64_le(l.length);
            dst.put_u32_le(l.flags.bits());
            dst.put_u32_le(0);
        }
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "LOCK request", 48)?;
        let n = usize::from(r.u16()?);
        let lock_sequence = r.u32()?;
        let file_id = FileId::read(&mut r)?;
        let mut locks = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            let offset = r.u64()?;
            let length = r.u64()?;
            let flags = LockFlags::from_bits_retain(r.u32()?);
            r.skip(4)?;
            locks.push(LockElement { offset, length, flags });
        }
        Ok(LockRequest { lock_sequence, file_id, locks })
    }
}

macro_rules! oplock_break {
    ($(#[$m:meta])* $name:ident, $resp:expr, $what:literal) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub struct $name {
            /// Oplock level (new level in notifications, acknowledged level otherwise).
            pub oplock_level: OplockLevel,
            /// Handle the oplock belongs to.
            pub file_id: FileId,
        }

        impl Message for $name {
            const COMMAND: Command = Command::OPLOCK_BREAK;
            const RESPONSE: bool = $resp;

            fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
                dst.put_u16_le(24);
                dst.put_u8(self.oplock_level.0);
                dst.put_u8(0);
                dst.put_u32_le(0);
                self.file_id.put(dst);
                Ok(())
            }

            fn decode_body(msg: &Bytes) -> Result<Self> {
                let mut r = body_reader(msg, $what, 24)?;
                let oplock_level = OplockLevel(r.u8()?);
                r.skip(5)?;
                Ok($name { oplock_level, file_id: FileId::read(&mut r)? })
            }
        }
    };
}

oplock_break!(
    /// Oplock break notification (server to client, MessageId `u64::MAX`).
    OplockBreakNotification, true, "oplock break notification"
);
oplock_break!(
    /// Oplock break acknowledgment (client to server).
    OplockBreakAck, false, "oplock break acknowledgment"
);
oplock_break!(
    /// Oplock break response (server's answer to the acknowledgment).
    OplockBreakResponse, true, "oplock break response"
);

bitflags! {
    /// Lease state (`SMB2_LEASE_*_CACHING`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct LeaseState: u32 {
        /// Read caching.
        const READ_CACHING = 0x0000_0001;
        /// Handle caching.
        const HANDLE_CACHING = 0x0000_0002;
        /// Write caching.
        const WRITE_CACHING = 0x0000_0004;
        const _ = !0;
    }
}

/// `SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED`.
pub const LEASE_BREAK_FLAG_ACK_REQUIRED: u32 = 0x0000_0001;

/// Lease break notification (server to client, [MS-SMB2] §2.2.23.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LeaseBreakNotification {
    /// New epoch (lease v2).
    pub new_epoch: u16,
    /// Flags (`LEASE_BREAK_FLAG_ACK_REQUIRED`).
    pub flags: u32,
    /// Lease key.
    pub lease_key: [u8; 16],
    /// Current lease state.
    pub current_lease_state: LeaseState,
    /// New lease state.
    pub new_lease_state: LeaseState,
    /// Break reason (reserved, 0).
    pub break_reason: u32,
    /// Access mask hint (reserved, 0).
    pub access_mask_hint: u32,
    /// Share mask hint (reserved, 0).
    pub share_mask_hint: u32,
}

impl LeaseBreakNotification {
    /// Whether the client must acknowledge the break.
    pub fn ack_required(&self) -> bool {
        self.flags & LEASE_BREAK_FLAG_ACK_REQUIRED != 0
    }
}

impl Message for LeaseBreakNotification {
    const COMMAND: Command = Command::OPLOCK_BREAK;
    const RESPONSE: bool = true;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u16_le(44);
        dst.put_u16_le(self.new_epoch);
        dst.put_u32_le(self.flags);
        dst.put_slice(&self.lease_key);
        dst.put_u32_le(self.current_lease_state.bits());
        dst.put_u32_le(self.new_lease_state.bits());
        dst.put_u32_le(self.break_reason);
        dst.put_u32_le(self.access_mask_hint);
        dst.put_u32_le(self.share_mask_hint);
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "lease break notification", 44)?;
        Ok(LeaseBreakNotification {
            new_epoch: r.u16()?,
            flags: r.u32()?,
            lease_key: r.array()?,
            current_lease_state: LeaseState::from_bits_retain(r.u32()?),
            new_lease_state: LeaseState::from_bits_retain(r.u32()?),
            break_reason: r.u32()?,
            access_mask_hint: r.u32()?,
            share_mask_hint: r.u32()?,
        })
    }
}

macro_rules! lease_break_ack {
    ($(#[$m:meta])* $name:ident, $resp:expr, $what:literal) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub struct $name {
            /// Flags (reserved, 0).
            pub flags: u32,
            /// Lease key.
            pub lease_key: [u8; 16],
            /// Acknowledged / granted lease state.
            pub lease_state: LeaseState,
            /// Lease duration (reserved, 0).
            pub lease_duration: u64,
        }

        impl Message for $name {
            const COMMAND: Command = Command::OPLOCK_BREAK;
            const RESPONSE: bool = $resp;

            fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
                dst.put_u16_le(36);
                dst.put_u16_le(0);
                dst.put_u32_le(self.flags);
                dst.put_slice(&self.lease_key);
                dst.put_u32_le(self.lease_state.bits());
                dst.put_u64_le(self.lease_duration);
                Ok(())
            }

            fn decode_body(msg: &Bytes) -> Result<Self> {
                let mut r = body_reader(msg, $what, 36)?;
                r.skip(2)?;
                Ok($name {
                    flags: r.u32()?,
                    lease_key: r.array()?,
                    lease_state: LeaseState::from_bits_retain(r.u32()?),
                    lease_duration: r.u64()?,
                })
            }
        }
    };
}

lease_break_ack!(
    /// Lease break acknowledgment (client to server, [MS-SMB2] §2.2.24.2).
    LeaseBreakAck, false, "lease break acknowledgment"
);
lease_break_ack!(
    /// Lease break response (server to client, [MS-SMB2] §2.2.25.2).
    LeaseBreakResponse, true, "lease break response"
);

/// A server-to-client OPLOCK_BREAK message, classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakMessage {
    /// Unsolicited oplock break notification.
    OplockNotification(OplockBreakNotification),
    /// Response to an oplock break acknowledgment.
    OplockResponse(OplockBreakResponse),
    /// Unsolicited lease break notification.
    LeaseNotification(LeaseBreakNotification),
    /// Response to a lease break acknowledgment.
    LeaseResponse(LeaseBreakResponse),
}

impl BreakMessage {
    /// Classify a server OPLOCK_BREAK message by `StructureSize` and
    /// MessageId (`u64::MAX` marks unsolicited notifications).
    pub fn decode(raw: &RawMessage) -> Result<Self> {
        if raw.command() != Command::OPLOCK_BREAK {
            return Err(ProtoError::UnexpectedCommand { expected: Command::OPLOCK_BREAK, actual: raw.command() });
        }
        let ss = match raw.body() {
            [a, b, ..] => u16::from_le_bytes([*a, *b]),
            _ => return Err(ProtoError::Truncated { what: "OPLOCK_BREAK", need: 66, have: raw.bytes().len() }),
        };
        let unsolicited = raw.header().message_id == crate::header::UNSOLICITED_MESSAGE_ID;
        Ok(match (ss, unsolicited) {
            (24, true) => BreakMessage::OplockNotification(raw.decode()?),
            (24, false) => BreakMessage::OplockResponse(raw.decode()?),
            (44, _) => BreakMessage::LeaseNotification(raw.decode()?),
            (36, _) => BreakMessage::LeaseResponse(raw.decode()?),
            _ => return Err(ProtoError::malformed("OPLOCK_BREAK", "unknown StructureSize")),
        })
    }
}
