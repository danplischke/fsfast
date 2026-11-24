//! QUERY_DIRECTORY, QUERY_INFO and SET_INFO ([MS-SMB2] §2.2.33–§2.2.40).

use bitflags::bitflags;
use bytes::{BufMut, Bytes, BytesMut};

use super::{Message, body_reader};
use crate::error::Result;
use crate::fscc::{DirectoryEntries, FileInfoClass, InfoClass, InfoType};
use crate::header::{Command, HEADER_LEN, credit_charge_for};
use crate::types::FileId;
use crate::wire::{decode_utf16le, len_u16, len_u32, put_utf16le, slice_bytes, slice_ref, utf16le_len};

bitflags! {
    /// QUERY_DIRECTORY `Flags`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct QueryDirectoryFlags: u8 {
        /// Restart the enumeration from the beginning.
        const RESTART_SCANS = 0x01;
        /// Return only one entry.
        const RETURN_SINGLE_ENTRY = 0x02;
        /// Resume at `FileIndex`.
        const INDEX_SPECIFIED = 0x04;
        /// Restart with a new search pattern.
        const REOPEN = 0x10;
        const _ = !0;
    }
}

/// SMB2 QUERY_DIRECTORY request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueryDirectoryRequest {
    /// Directory information class of the entries.
    pub file_information_class: FileInfoClass,
    /// Flags.
    pub flags: QueryDirectoryFlags,
    /// Resume index (with `INDEX_SPECIFIED`).
    pub file_index: u32,
    /// Directory handle.
    pub file_id: FileId,
    /// Search pattern, e.g. `*`.
    pub file_name: String,
    /// Maximum bytes of entries to return.
    pub output_buffer_length: u32,
}

impl Message for QueryDirectoryRequest {
    const COMMAND: Command = Command::QUERY_DIRECTORY;
    const RESPONSE: bool = false;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        let name_len = len_u16(utf16le_len(&self.file_name), "search pattern too long")?;
        dst.put_u16_le(33);
        dst.put_u8(self.file_information_class.0);
        dst.put_u8(self.flags.bits());
        dst.put_u32_le(self.file_index);
        self.file_id.put(dst);
        dst.put_u16_le(if name_len == 0 { 0 } else { (HEADER_LEN + 32) as u16 });
        dst.put_u16_le(name_len);
        dst.put_u32_le(self.output_buffer_length);
        if name_len == 0 {
            dst.put_u8(0);
        } else {
            put_utf16le(dst, &self.file_name);
        }
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "QUERY_DIRECTORY request", 33)?;
        let file_information_class = FileInfoClass(r.u8()?);
        let flags = QueryDirectoryFlags::from_bits_retain(r.u8()?);
        let file_index = r.u32()?;
        let file_id = FileId::read(&mut r)?;
        let off = usize::from(r.u16()?);
        let len = usize::from(r.u16()?);
        let output_buffer_length = r.u32()?;
        let file_name = decode_utf16le(slice_ref(msg, off, len, "search pattern")?, "search pattern")?;
        Ok(QueryDirectoryRequest {
            file_information_class,
            flags,
            file_index,
            file_id,
            file_name,
            output_buffer_length,
        })
    }

    fn credit_charge(&self) -> u16 {
        credit_charge_for(self.output_buffer_length as usize)
    }
}

/// Encode the common "StructureSize 9 + offset/length + buffer" response
/// body shared by QUERY_DIRECTORY, QUERY_INFO and CHANGE_NOTIFY.
pub(crate) fn encode_buffer_response(dst: &mut BytesMut, buf: &Bytes) -> Result<()> {
    dst.put_u16_le(9);
    dst.put_u16_le(if buf.is_empty() { 0 } else { (HEADER_LEN + 8) as u16 });
    dst.put_u32_le(len_u32(buf.len(), "output buffer too long")?);
    if buf.is_empty() {
        dst.put_u8(0);
    } else {
        dst.put_slice(buf);
    }
    Ok(())
}

pub(crate) fn decode_buffer_response(msg: &Bytes, what: &'static str) -> Result<Bytes> {
    let mut r = body_reader(msg, what, 9)?;
    let off = usize::from(r.u16()?);
    let len = r.u32()? as usize;
    slice_bytes(msg, off, len, what)
}

/// SMB2 QUERY_DIRECTORY response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueryDirectoryResponse {
    /// Entries of the requested class (zero-copy slice of the frame).
    pub output_buffer: Bytes,
}

impl QueryDirectoryResponse {
    /// Iterate the entries, decoded as `class` (the class of the request).
    pub fn entries(&self, class: FileInfoClass) -> Result<DirectoryEntries> {
        DirectoryEntries::new(class, self.output_buffer.clone())
    }
}

impl Message for QueryDirectoryResponse {
    const COMMAND: Command = Command::QUERY_DIRECTORY;
    const RESPONSE: bool = true;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        encode_buffer_response(dst, &self.output_buffer)
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        Ok(QueryDirectoryResponse { output_buffer: decode_buffer_response(msg, "QUERY_DIRECTORY response")? })
    }
}

/// QUERY_INFO `Flags` (for FileFullEaInformation).
pub mod query_info_flags {
    /// Restart the EA scan.
    pub const RESTART_SCAN: u32 = 0x0000_0001;
    /// Return a single entry.
    pub const RETURN_SINGLE_ENTRY: u32 = 0x0000_0002;
    /// Start at an index.
    pub const INDEX_SPECIFIED: u32 = 0x0000_0004;
}

/// SMB2 QUERY_INFO request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueryInfoRequest {
    /// Information type.
    pub info_type: InfoType,
    /// Information class within the type.
    pub file_info_class: u8,
    /// Maximum bytes to return.
    pub output_buffer_length: u32,
    /// `AdditionalInformation` (security information bits for SECURITY).
    pub additional_information: u32,
    /// Flags (see [`query_info_flags`]).
    pub flags: u32,
    /// Handle (or [`FileId::RELATED`] in a compound).
    pub file_id: FileId,
    /// Input buffer (EA list / quota SIDs; usually empty).
    pub input_buffer: Bytes,
}

impl QueryInfoRequest {
    /// A request for information class `T` on `file_id`.
    pub fn for_class<T: InfoClass>(file_id: FileId, output_buffer_length: u32) -> Self {
        QueryInfoRequest {
            info_type: T::INFO_TYPE,
            file_info_class: T::CLASS,
            output_buffer_length,
            file_id,
            ..Default::default()
        }
    }
}

impl Message for QueryInfoRequest {
    const COMMAND: Command = Command::QUERY_INFO;
    const RESPONSE: bool = false;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u16_le(41);
        dst.put_u8(self.info_type.0);
        dst.put_u8(self.file_info_class);
        dst.put_u32_le(self.output_buffer_length);
        dst.put_u16_le(if self.input_buffer.is_empty() { 0 } else { (HEADER_LEN + 40) as u16 });
        dst.put_u16_le(0);
        dst.put_u32_le(len_u32(self.input_buffer.len(), "input buffer too long")?);
        dst.put_u32_le(self.additional_information);
        dst.put_u32_le(self.flags);
        self.file_id.put(dst);
        dst.put_slice(&self.input_buffer);
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "QUERY_INFO request", 41)?;
        let info_type = InfoType(r.u8()?);
        let file_info_class = r.u8()?;
        let output_buffer_length = r.u32()?;
        let off = usize::from(r.u16()?);
        r.skip(2)?;
        let len = r.u32()? as usize;
        let additional_information = r.u32()?;
        let flags = r.u32()?;
        let file_id = FileId::read(&mut r)?;
        Ok(QueryInfoRequest {
            info_type,
            file_info_class,
            output_buffer_length,
            additional_information,
            flags,
            file_id,
            input_buffer: slice_bytes(msg, off, len, "QUERY_INFO input buffer")?,
        })
    }

    fn credit_charge(&self) -> u16 {
        credit_charge_for((self.output_buffer_length as usize).max(self.input_buffer.len()))
    }
}

/// SMB2 QUERY_INFO response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueryInfoResponse {
    /// The information (zero-copy slice of the frame).
    pub output_buffer: Bytes,
}

impl QueryInfoResponse {
    /// Decode the output buffer as information class `T`.
    pub fn decode_as<T: InfoClass>(&self) -> Result<T> {
        T::decode(&self.output_buffer)
    }
}

impl Message for QueryInfoResponse {
    const COMMAND: Command = Command::QUERY_INFO;
    const RESPONSE: bool = true;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        encode_buffer_response(dst, &self.output_buffer)
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        Ok(QueryInfoResponse { output_buffer: decode_buffer_response(msg, "QUERY_INFO response")? })
    }
}

/// SMB2 SET_INFO request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SetInfoRequest {
    /// Information type.
    pub info_type: InfoType,
    /// Information class.
    pub file_info_class: u8,
    /// `AdditionalInformation` (security information bits for SECURITY).
    pub additional_information: u32,
    /// Handle (or [`FileId::RELATED`]).
    pub file_id: FileId,
    /// Encoded information.
    pub buffer: Bytes,
}

impl SetInfoRequest {
    /// Build a SET_INFO for information class `T`.
    pub fn new<T: InfoClass>(file_id: FileId, info: &T) -> Result<Self> {
        Ok(SetInfoRequest {
            info_type: T::INFO_TYPE,
            file_info_class: T::CLASS,
            additional_information: 0,
            file_id,
            buffer: info.to_bytes()?,
        })
    }
}

impl Message for SetInfoRequest {
    const COMMAND: Command = Command::SET_INFO;
    const RESPONSE: bool = false;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u16_le(33);
        dst.put_u8(self.info_type.0);
        dst.put_u8(self.file_info_class);
        dst.put_u32_le(len_u32(self.buffer.len(), "set info buffer too long")?);
        dst.put_u16_le((HEADER_LEN + 32) as u16);
        dst.put_u16_le(0);
        dst.put_u32_le(self.additional_information);
        self.file_id.put(dst);
        if self.buffer.is_empty() {
            dst.put_u8(0);
        } else {
            dst.put_slice(&self.buffer);
        }
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "SET_INFO request", 33)?;
        let info_type = InfoType(r.u8()?);
        let file_info_class = r.u8()?;
        let len = r.u32()? as usize;
        let off = usize::from(r.u16()?);
        r.skip(2)?;
        let additional_information = r.u32()?;
        let file_id = FileId::read(&mut r)?;
        Ok(SetInfoRequest {
            info_type,
            file_info_class,
            additional_information,
            file_id,
            buffer: slice_bytes(msg, off, len, "SET_INFO buffer")?,
        })
    }

    fn credit_charge(&self) -> u16 {
        credit_charge_for(self.buffer.len())
    }
}

/// SMB2 SET_INFO response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SetInfoResponse;

impl Message for SetInfoResponse {
    const COMMAND: Command = Command::SET_INFO;
    const RESPONSE: bool = true;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u16_le(2);
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        body_reader(msg, "SET_INFO response", 2)?;
        Ok(SetInfoResponse)
    }
}
