//! READ and WRITE ([MS-SMB2] §2.2.19–§2.2.22).
//!
//! Both directions keep bulk data out of the inline body: a decoded
//! [`ReadResponse`] exposes its data as a `Bytes` slice of the received frame,
//! and an encoded [`WriteRequest`] carries its data as a separate payload
//! segment (see [`super::EncodedMessage`]).

use bitflags::bitflags;
use bytes::{BufMut, Bytes, BytesMut};

use super::{Message, body_reader};
use crate::error::{ProtoError, Result};
use crate::header::{Command, HEADER_LEN, credit_charge_for};
use crate::types::FileId;
use crate::wire::{len_u16, len_u32, slice_bytes};

bitflags! {
    /// READ request `Flags`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct ReadFlags: u8 {
        /// Bypass the server cache (3.0.2+).
        const UNBUFFERED = 0x01;
        /// Request a compressed response (3.1.1).
        const REQUEST_COMPRESSED = 0x02;
        const _ = !0;
    }
}

bitflags! {
    /// WRITE request `Flags`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct WriteFlags: u32 {
        /// Write through to stable storage.
        const WRITE_THROUGH = 0x0000_0001;
        /// Bypass the server cache (3.0.2+).
        const UNBUFFERED = 0x0000_0002;
        const _ = !0;
    }
}

/// `Channel` values of READ/WRITE.
pub mod channel {
    /// No RDMA channel.
    pub const NONE: u32 = 0;
    /// SMB Direct v1.
    pub const RDMA_V1: u32 = 1;
    /// SMB Direct v1 with invalidate.
    pub const RDMA_V1_INVALIDATE: u32 = 2;
    /// RDMA transform.
    pub const RDMA_TRANSFORM: u32 = 3;
}

/// Offset (from the header) at which servers place READ data: header plus
/// the 16-byte fixed response body.
pub const READ_RESPONSE_DATA_OFFSET: u8 = (HEADER_LEN + 16) as u8;
/// Offset (from the header) of WRITE data: header plus the 48-byte fixed body.
pub const WRITE_REQUEST_DATA_OFFSET: u16 = (HEADER_LEN + 48) as u16;

/// SMB2 READ request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRequest {
    /// Requested placement of the data in the response, relative to the
    /// header (`0x50` asks for data right after the fixed response body).
    pub padding: u8,
    /// Flags.
    pub flags: ReadFlags,
    /// Bytes to read.
    pub length: u32,
    /// File offset.
    pub offset: u64,
    /// Handle.
    pub file_id: FileId,
    /// Minimum bytes for a successful read.
    pub minimum_count: u32,
    /// RDMA channel (see [`channel`]).
    pub channel: u32,
    /// Bytes the client intends to read next (hint).
    pub remaining_bytes: u32,
    /// RDMA channel descriptors.
    pub read_channel_info: Bytes,
}

impl Default for ReadRequest {
    fn default() -> Self {
        ReadRequest {
            padding: READ_RESPONSE_DATA_OFFSET,
            flags: ReadFlags::empty(),
            length: 0,
            offset: 0,
            file_id: FileId::default(),
            minimum_count: 0,
            channel: channel::NONE,
            remaining_bytes: 0,
            read_channel_info: Bytes::new(),
        }
    }
}

impl Message for ReadRequest {
    const COMMAND: Command = Command::READ;
    const RESPONSE: bool = false;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u16_le(49);
        dst.put_u8(self.padding);
        dst.put_u8(self.flags.bits());
        dst.put_u32_le(self.length);
        dst.put_u64_le(self.offset);
        self.file_id.put(dst);
        dst.put_u32_le(self.minimum_count);
        dst.put_u32_le(self.channel);
        dst.put_u32_le(self.remaining_bytes);
        if self.read_channel_info.is_empty() {
            dst.put_u16_le(0);
            dst.put_u16_le(0);
            // The variable buffer must contain at least one byte.
            dst.put_u8(0);
        } else {
            dst.put_u16_le((HEADER_LEN + 48) as u16);
            dst.put_u16_le(len_u16(self.read_channel_info.len(), "read channel info too long")?);
            dst.put_slice(&self.read_channel_info);
        }
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "READ request", 49)?;
        let padding = r.u8()?;
        let flags = ReadFlags::from_bits_retain(r.u8()?);
        let length = r.u32()?;
        let offset = r.u64()?;
        let file_id = FileId::read(&mut r)?;
        let minimum_count = r.u32()?;
        let channel = r.u32()?;
        let remaining_bytes = r.u32()?;
        let ci_off = usize::from(r.u16()?);
        let ci_len = usize::from(r.u16()?);
        Ok(ReadRequest {
            padding,
            flags,
            length,
            offset,
            file_id,
            minimum_count,
            channel,
            remaining_bytes,
            read_channel_info: slice_bytes(msg, ci_off, ci_len, "READ channel info")?,
        })
    }

    fn credit_charge(&self) -> u16 {
        credit_charge_for(self.length as usize)
    }
}

/// `SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM`.
pub const READ_RESPONSE_RDMA_TRANSFORM: u32 = 0x0000_0001;

/// SMB2 READ response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReadResponse {
    /// Bytes still to be sent over RDMA (0 for TCP).
    pub data_remaining: u32,
    /// Flags (`READ_RESPONSE_RDMA_TRANSFORM`).
    pub flags: u32,
    /// The data: a zero-copy slice of the received frame.
    pub data: Bytes,
}

impl Message for ReadResponse {
    const COMMAND: Command = Command::READ;
    const RESPONSE: bool = true;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u16_le(17);
        dst.put_u8(READ_RESPONSE_DATA_OFFSET);
        dst.put_u8(0);
        dst.put_u32_le(len_u32(self.data.len(), "read data too long")?);
        dst.put_u32_le(self.data_remaining);
        dst.put_u32_le(self.flags);
        if self.data.is_empty() {
            dst.put_u8(0);
        }
        Ok(())
    }

    fn payload(&self) -> Option<&Bytes> {
        Some(&self.data)
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "READ response", 17)?;
        let off = usize::from(r.u8()?);
        r.skip(1)?;
        let len = r.u32()? as usize;
        let data_remaining = r.u32()?;
        let flags = r.u32()?;
        if len > 0 && off < HEADER_LEN + 16 {
            return Err(ProtoError::malformed("READ response", "data overlaps the header"));
        }
        Ok(ReadResponse { data_remaining, flags, data: slice_bytes(msg, off, len, "READ data")? })
    }
}

/// SMB2 WRITE request. `data` is sent as a separate zero-copy segment.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WriteRequest {
    /// File offset. `u64::MAX` (with an append-only handle) appends.
    pub offset: u64,
    /// Handle.
    pub file_id: FileId,
    /// RDMA channel (see [`channel`]).
    pub channel: u32,
    /// Bytes the client intends to write next (hint).
    pub remaining_bytes: u32,
    /// Flags.
    pub flags: WriteFlags,
    /// RDMA channel descriptors (only with empty `data`).
    pub write_channel_info: Bytes,
    /// Data to write.
    pub data: Bytes,
}

impl Message for WriteRequest {
    const COMMAND: Command = Command::WRITE;
    const RESPONSE: bool = false;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        if !self.data.is_empty() && !self.write_channel_info.is_empty() {
            return Err(ProtoError::InvalidInput("WRITE with both data and channel info"));
        }
        dst.put_u16_le(49);
        dst.put_u16_le(WRITE_REQUEST_DATA_OFFSET);
        dst.put_u32_le(len_u32(self.data.len(), "write data too long")?);
        dst.put_u64_le(self.offset);
        self.file_id.put(dst);
        dst.put_u32_le(self.channel);
        dst.put_u32_le(self.remaining_bytes);
        if self.write_channel_info.is_empty() {
            dst.put_u16_le(0);
            dst.put_u16_le(0);
        } else {
            dst.put_u16_le(WRITE_REQUEST_DATA_OFFSET);
            dst.put_u16_le(len_u16(self.write_channel_info.len(), "write channel info too long")?);
        }
        dst.put_u32_le(self.flags.bits());
        if !self.write_channel_info.is_empty() {
            dst.put_slice(&self.write_channel_info);
        } else if self.data.is_empty() {
            dst.put_u8(0);
        }
        Ok(())
    }

    fn payload(&self) -> Option<&Bytes> {
        Some(&self.data)
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "WRITE request", 49)?;
        let off = usize::from(r.u16()?);
        let len = r.u32()? as usize;
        let offset = r.u64()?;
        let file_id = FileId::read(&mut r)?;
        let channel = r.u32()?;
        let remaining_bytes = r.u32()?;
        let ci_off = usize::from(r.u16()?);
        let ci_len = usize::from(r.u16()?);
        let flags = WriteFlags::from_bits_retain(r.u32()?);
        Ok(WriteRequest {
            offset,
            file_id,
            channel,
            remaining_bytes,
            flags,
            write_channel_info: slice_bytes(msg, ci_off, ci_len, "WRITE channel info")?,
            data: slice_bytes(msg, off, len, "WRITE data")?,
        })
    }

    fn credit_charge(&self) -> u16 {
        credit_charge_for(self.data.len())
    }
}

/// SMB2 WRITE response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WriteResponse {
    /// Bytes written.
    pub count: u32,
    /// Reserved (0).
    pub remaining: u32,
}

impl Message for WriteResponse {
    const COMMAND: Command = Command::WRITE;
    const RESPONSE: bool = true;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u16_le(17);
        dst.put_u16_le(0);
        dst.put_u32_le(self.count);
        dst.put_u32_le(self.remaining);
        dst.put_u16_le(0);
        dst.put_u16_le(0);
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "WRITE response", 17)?;
        r.skip(2)?;
        let count = r.u32()?;
        let remaining = r.u32()?;
        Ok(WriteResponse { count, remaining })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{Header, HeaderFlags};
    use crate::msg::{RawMessage, encode_message};

    #[test]
    fn read_response_is_zero_copy() {
        let mut h = Header::request(Command::READ);
        h.flags = HeaderFlags::SERVER_TO_REDIR;
        let data = Bytes::from(vec![0xAB; 100_000]);
        let m = encode_message(&h, &ReadResponse { data: data.clone(), ..Default::default() }).unwrap();
        let frame = m.into_contiguous().freeze();
        let raw = RawMessage::parse(frame.clone()).unwrap();
        let r: ReadResponse = raw.decode().unwrap();
        assert_eq!(r.data, data);
        // Same allocation as the frame.
        let base = frame.as_ptr() as usize;
        assert_eq!(r.data.as_ptr() as usize, base + usize::from(READ_RESPONSE_DATA_OFFSET));
    }

    #[test]
    fn write_request_keeps_payload_separate() {
        let data = Bytes::from(vec![1u8; 70_000]);
        let w = WriteRequest { offset: 5, file_id: FileId::new(1, 2), data: data.clone(), ..Default::default() };
        assert_eq!(w.credit_charge(), 2);
        let m = encode_message(&Header::request(Command::WRITE), &w).unwrap();
        assert_eq!(m.head.len(), HEADER_LEN + 48);
        assert_eq!(m.payload.as_ref().unwrap().as_ptr(), data.as_ptr());
        let raw = RawMessage::parse(m.into_contiguous().freeze()).unwrap();
        assert_eq!(raw.decode::<WriteRequest>().unwrap(), w);
    }

    #[test]
    fn empty_read_and_write() {
        for w in [WriteRequest::default(), WriteRequest { write_channel_info: Bytes::from_static(b"ci"), ..Default::default() }] {
            let m = encode_message(&Header::request(Command::WRITE), &w).unwrap();
            let raw = RawMessage::parse(m.into_contiguous().freeze()).unwrap();
            assert_eq!(raw.decode::<WriteRequest>().unwrap(), w);
        }
        let r = ReadRequest { length: 1 << 20, ..Default::default() };
        assert_eq!(r.credit_charge(), 16);
        let m = encode_message(&Header::request(Command::READ), &r).unwrap();
        assert_eq!(m.head.len(), HEADER_LEN + 49);
        let raw = RawMessage::parse(m.into_contiguous().freeze()).unwrap();
        assert_eq!(raw.decode::<ReadRequest>().unwrap(), r);
    }
}
