//! CHANGE_NOTIFY ([MS-SMB2] §2.2.35, §2.2.36) and FILE_NOTIFY_INFORMATION
//! ([MS-FSCC] §2.7.1).

use bitflags::bitflags;
use bytes::{BufMut, Bytes, BytesMut};

use super::query::{decode_buffer_response, encode_buffer_response};
use super::{Message, body_reader};
use crate::error::{ProtoError, Result};
use crate::header::{Command, credit_charge_for};
use crate::types::FileId;
use crate::wire::{Reader, decode_utf16le, len_u32, padding, patch_u32, put_utf16le, utf16le_len};

/// `SMB2_WATCH_TREE`: watch the whole subtree.
pub const WATCH_TREE: u16 = 0x0001;

bitflags! {
    /// CHANGE_NOTIFY `CompletionFilter`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct CompletionFilter: u32 {
        /// File name changes.
        const FILE_NAME = 0x0000_0001;
        /// Directory name changes.
        const DIR_NAME = 0x0000_0002;
        /// Attribute changes.
        const ATTRIBUTES = 0x0000_0004;
        /// Size changes.
        const SIZE = 0x0000_0008;
        /// Last write time changes.
        const LAST_WRITE = 0x0000_0010;
        /// Last access time changes.
        const LAST_ACCESS = 0x0000_0020;
        /// Creation time changes.
        const CREATION = 0x0000_0040;
        /// EA changes.
        const EA = 0x0000_0080;
        /// Security descriptor changes.
        const SECURITY = 0x0000_0100;
        /// Stream name changes.
        const STREAM_NAME = 0x0000_0200;
        /// Stream size changes.
        const STREAM_SIZE = 0x0000_0400;
        /// Stream write changes.
        const STREAM_WRITE = 0x0000_0800;
        const _ = !0;
    }
}

/// SMB2 CHANGE_NOTIFY request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChangeNotifyRequest {
    /// Flags ([`WATCH_TREE`]).
    pub flags: u16,
    /// Maximum bytes of notifications to return.
    pub output_buffer_length: u32,
    /// Directory handle.
    pub file_id: FileId,
    /// Changes to watch for.
    pub completion_filter: CompletionFilter,
}

impl Message for ChangeNotifyRequest {
    const COMMAND: Command = Command::CHANGE_NOTIFY;
    const RESPONSE: bool = false;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u16_le(32);
        dst.put_u16_le(self.flags);
        dst.put_u32_le(self.output_buffer_length);
        self.file_id.put(dst);
        dst.put_u32_le(self.completion_filter.bits());
        dst.put_u32_le(0);
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "CHANGE_NOTIFY request", 32)?;
        let flags = r.u16()?;
        let output_buffer_length = r.u32()?;
        let file_id = FileId::read(&mut r)?;
        let completion_filter = CompletionFilter::from_bits_retain(r.u32()?);
        Ok(ChangeNotifyRequest { flags, output_buffer_length, file_id, completion_filter })
    }

    fn credit_charge(&self) -> u16 {
        credit_charge_for(self.output_buffer_length as usize)
    }
}

/// Notification action (`FILE_ACTION_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct FileAction(pub u32);

impl FileAction {
    /// Added.
    pub const ADDED: Self = Self(1);
    /// Removed.
    pub const REMOVED: Self = Self(2);
    /// Modified.
    pub const MODIFIED: Self = Self(3);
    /// Renamed (old name).
    pub const RENAMED_OLD_NAME: Self = Self(4);
    /// Renamed (new name).
    pub const RENAMED_NEW_NAME: Self = Self(5);
    /// Stream added.
    pub const ADDED_STREAM: Self = Self(6);
    /// Stream removed.
    pub const REMOVED_STREAM: Self = Self(7);
    /// Stream modified.
    pub const MODIFIED_STREAM: Self = Self(8);
    /// Removed by delete.
    pub const REMOVED_BY_DELETE: Self = Self(9);
}

/// One FILE_NOTIFY_INFORMATION entry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileNotifyInformation {
    /// What happened.
    pub action: FileAction,
    /// Path relative to the watched directory.
    pub file_name: String,
}

/// Decode a FILE_NOTIFY_INFORMATION chain.
pub fn decode_notify_information(buf: &[u8]) -> Result<Vec<FileNotifyInformation>> {
    const W: &str = "FILE_NOTIFY_INFORMATION";
    let mut out = Vec::new();
    let mut pos = 0usize;
    if buf.is_empty() {
        return Ok(out);
    }
    loop {
        let rest = buf.get(pos..).ok_or(ProtoError::malformed(W, "entry offset out of range"))?;
        let mut r = Reader::new(rest, W);
        let next = r.u32()? as usize;
        let action = FileAction(r.u32()?);
        let len = r.u32()? as usize;
        let file_name = decode_utf16le(r.bytes(len)?, W)?;
        out.push(FileNotifyInformation { action, file_name });
        if next == 0 {
            return Ok(out);
        }
        if next < 12 {
            return Err(ProtoError::malformed(W, "NextEntryOffset too small"));
        }
        pos += next;
    }
}

/// Encode a FILE_NOTIFY_INFORMATION chain (entries 4-byte aligned).
pub fn encode_notify_information(entries: &[FileNotifyInformation], dst: &mut BytesMut) -> Result<()> {
    let base = dst.len();
    for (i, e) in entries.iter().enumerate() {
        let start = dst.len();
        dst.put_u32_le(0);
        dst.put_u32_le(e.action.0);
        dst.put_u32_le(len_u32(utf16le_len(&e.file_name), "file name too long")?);
        put_utf16le(dst, &e.file_name);
        if i + 1 < entries.len() {
            dst.put_bytes(0, padding(dst.len() - base, 4));
            let next = (dst.len() - start) as u32;
            patch_u32(dst, start, next);
        }
    }
    Ok(())
}

/// SMB2 CHANGE_NOTIFY response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChangeNotifyResponse {
    /// FILE_NOTIFY_INFORMATION chain (zero-copy slice).
    pub output_buffer: Bytes,
}

impl ChangeNotifyResponse {
    /// Decode the notifications.
    pub fn notifications(&self) -> Result<Vec<FileNotifyInformation>> {
        decode_notify_information(&self.output_buffer)
    }
}

impl Message for ChangeNotifyResponse {
    const COMMAND: Command = Command::CHANGE_NOTIFY;
    const RESPONSE: bool = true;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        encode_buffer_response(dst, &self.output_buffer)
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        Ok(ChangeNotifyResponse { output_buffer: decode_buffer_response(msg, "CHANGE_NOTIFY response")? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_chain_round_trip() {
        let entries = vec![
            FileNotifyInformation { action: FileAction::ADDED, file_name: "a.txt".into() },
            FileNotifyInformation { action: FileAction::RENAMED_NEW_NAME, file_name: "dir\\b".into() },
        ];
        let mut b = BytesMut::new();
        encode_notify_information(&entries, &mut b).unwrap();
        assert_eq!(decode_notify_information(&b).unwrap(), entries);
        for i in 0..b.len() {
            let _ = decode_notify_information(&b[..i]);
        }
    }
}
