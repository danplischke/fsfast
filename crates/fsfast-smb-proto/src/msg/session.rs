//! SESSION_SETUP and LOGOFF ([MS-SMB2] §2.2.5–§2.2.8).

use bitflags::bitflags;
use bytes::{BufMut, Bytes, BytesMut};

use super::{Message, body_reader};
use crate::error::Result;
use crate::header::{Command, HEADER_LEN};
use crate::types::{Capabilities, SecurityMode};
use crate::wire::{len_u16, slice_bytes};

bitflags! {
    /// SESSION_SETUP request `Flags`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct SessionSetupRequestFlags: u8 {
        /// Bind an existing session to a new channel (multichannel).
        const BINDING = 0x01;
    }
}

bitflags! {
    /// SESSION_SETUP response `SessionFlags`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct SessionFlags: u16 {
        /// Authenticated as guest.
        const IS_GUEST = 0x0001;
        /// Anonymous session.
        const IS_NULL = 0x0002;
        /// The server requires encryption for this session (3.x).
        const ENCRYPT_DATA = 0x0004;
    }
}

/// SMB2 SESSION_SETUP request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionSetupRequest {
    /// Flags (`BINDING` for multichannel).
    pub flags: SessionSetupRequestFlags,
    /// Client security mode (8-bit on the wire).
    pub security_mode: SecurityMode,
    /// Client capabilities (only `DFS` is meaningful).
    pub capabilities: Capabilities,
    /// Channel (must be 0).
    pub channel: u32,
    /// Previous session id for reconnect cleanup (0 if none).
    pub previous_session_id: u64,
    /// GSS token (SPNEGO).
    pub security_buffer: Bytes,
}

impl Message for SessionSetupRequest {
    const COMMAND: Command = Command::SESSION_SETUP;
    const RESPONSE: bool = false;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u16_le(25);
        dst.put_u8(self.flags.bits());
        dst.put_u8(self.security_mode.bits() as u8);
        dst.put_u32_le(self.capabilities.bits());
        dst.put_u32_le(self.channel);
        dst.put_u16_le(if self.security_buffer.is_empty() {
            0
        } else {
            (HEADER_LEN + 24) as u16
        });
        dst.put_u16_le(len_u16(
            self.security_buffer.len(),
            "security buffer too long",
        )?);
        dst.put_u64_le(self.previous_session_id);
        dst.put_slice(&self.security_buffer);
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "SESSION_SETUP request", 25)?;
        let flags = SessionSetupRequestFlags::from_bits_retain(r.u8()?);
        let security_mode = SecurityMode::from_bits_retain(u16::from(r.u8()?));
        let capabilities = Capabilities::from_bits_retain(r.u32()?);
        let channel = r.u32()?;
        let off = usize::from(r.u16()?);
        let len = usize::from(r.u16()?);
        let previous_session_id = r.u64()?;
        Ok(SessionSetupRequest {
            flags,
            security_mode,
            capabilities,
            channel,
            previous_session_id,
            security_buffer: slice_bytes(msg, off, len, "SESSION_SETUP security buffer")?,
        })
    }
}

/// SMB2 SESSION_SETUP response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionSetupResponse {
    /// Session flags.
    pub session_flags: SessionFlags,
    /// GSS token (SPNEGO).
    pub security_buffer: Bytes,
}

impl Message for SessionSetupResponse {
    const COMMAND: Command = Command::SESSION_SETUP;
    const RESPONSE: bool = true;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u16_le(9);
        dst.put_u16_le(self.session_flags.bits());
        dst.put_u16_le(if self.security_buffer.is_empty() {
            0
        } else {
            (HEADER_LEN + 8) as u16
        });
        dst.put_u16_le(len_u16(
            self.security_buffer.len(),
            "security buffer too long",
        )?);
        dst.put_slice(&self.security_buffer);
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "SESSION_SETUP response", 9)?;
        let session_flags = SessionFlags::from_bits_retain(r.u16()?);
        let off = usize::from(r.u16()?);
        let len = usize::from(r.u16()?);
        Ok(SessionSetupResponse {
            session_flags,
            security_buffer: slice_bytes(msg, off, len, "SESSION_SETUP security buffer")?,
        })
    }
}

macro_rules! empty_message {
    ($(#[$m:meta])* $name:ident, $cmd:expr, $resp:expr, $what:literal) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub struct $name;

        impl Message for $name {
            const COMMAND: Command = $cmd;
            const RESPONSE: bool = $resp;

            fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
                dst.put_u16_le(4);
                dst.put_u16_le(0);
                Ok(())
            }

            fn decode_body(msg: &Bytes) -> Result<Self> {
                let mut r = body_reader(msg, $what, 4)?;
                r.skip(2)?;
                Ok($name)
            }
        }
    };
}

pub(crate) use empty_message;

empty_message!(
    /// SMB2 LOGOFF request.
    LogoffRequest, Command::LOGOFF, false, "LOGOFF request"
);
empty_message!(
    /// SMB2 LOGOFF response.
    LogoffResponse, Command::LOGOFF, true, "LOGOFF response"
);
