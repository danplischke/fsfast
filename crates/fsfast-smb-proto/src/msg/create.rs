//! CREATE request/response and create contexts ([MS-SMB2] §2.2.13,
//! §2.2.14).

use bytes::{BufMut, Bytes, BytesMut};

use super::misc::LeaseState;
use super::{Message, body_reader, wire_offset};
use crate::error::{ProtoError, Result};
use crate::fscc::{
    AccessMask, CreateAction, CreateDisposition, CreateOptions, FileAttributes, FileTime,
    ImpersonationLevel, OplockLevel, ShareAccess,
};
use crate::header::{Command, HEADER_LEN};
use crate::status::NtStatus;
use crate::types::FileId;
use crate::wire::{
    Guid, Reader, decode_utf16le, len_u16, len_u32, patch_u16, patch_u32, put_utf16le, slice_bytes,
    slice_ref, utf16le_len,
};

/// Well-known create context names.
pub mod context_name {
    /// Durable handle request (v1) / response.
    pub const DURABLE_HANDLE_REQUEST: &[u8; 4] = b"DHnQ";
    /// Durable handle reconnect (v1).
    pub const DURABLE_HANDLE_RECONNECT: &[u8; 4] = b"DHnC";
    /// Durable handle request (v2) / response.
    pub const DURABLE_HANDLE_REQUEST_V2: &[u8; 4] = b"DH2Q";
    /// Durable handle reconnect (v2).
    pub const DURABLE_HANDLE_RECONNECT_V2: &[u8; 4] = b"DH2C";
    /// Query maximal access.
    pub const QUERY_MAXIMAL_ACCESS: &[u8; 4] = b"MxAc";
    /// Query on-disk file id.
    pub const QUERY_ON_DISK_ID: &[u8; 4] = b"QFid";
    /// Request lease (v1 or v2, told apart by data length).
    pub const REQUEST_LEASE: &[u8; 4] = b"RqLs";
    /// Allocation size.
    pub const ALLOCATION_SIZE: &[u8; 4] = b"AlSi";
    /// Timewarp token (open a snapshot).
    pub const TIMEWARP_TOKEN: &[u8; 4] = b"TWrp";
    /// Extended attributes.
    pub const EA_BUFFER: &[u8; 4] = b"ExtA";
    /// Security descriptor.
    pub const SD_BUFFER: &[u8; 4] = b"SecD";
}

/// `SMB2_DHANDLE_FLAG_PERSISTENT` (durable v2).
pub const DHANDLE_FLAG_PERSISTENT: u32 = 0x0000_0002;
/// `SMB2_LEASE_FLAG_BREAK_IN_PROGRESS` (lease response).
pub const LEASE_FLAG_BREAK_IN_PROGRESS: u32 = 0x0000_0002;
/// `SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET` (lease v2).
pub const LEASE_FLAG_PARENT_LEASE_KEY_SET: u32 = 0x0000_0004;

/// A lease create context (`SMB2_CREATE_REQUEST_LEASE` /
/// `SMB2_CREATE_REQUEST_LEASE_V2` and their responses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lease {
    /// Lease v1 (SMB 2.1+), 32 bytes.
    V1 {
        /// Lease key.
        key: [u8; 16],
        /// Requested / granted state.
        state: LeaseState,
        /// Flags.
        flags: u32,
        /// Duration (reserved, 0).
        duration: u64,
    },
    /// Lease v2 (SMB 3.x), 52 bytes.
    V2 {
        /// Lease key.
        key: [u8; 16],
        /// Requested / granted state.
        state: LeaseState,
        /// Flags (`LEASE_FLAG_PARENT_LEASE_KEY_SET`, ...).
        flags: u32,
        /// Duration (reserved, 0).
        duration: u64,
        /// Parent directory's lease key.
        parent_key: [u8; 16],
        /// Epoch.
        epoch: u16,
    },
}

impl Lease {
    /// The lease key.
    pub fn key(&self) -> &[u8; 16] {
        match self {
            Lease::V1 { key, .. } | Lease::V2 { key, .. } => key,
        }
    }

    /// The lease state.
    pub fn state(&self) -> LeaseState {
        match self {
            Lease::V1 { state, .. } | Lease::V2 { state, .. } => *state,
        }
    }

    fn encode(&self, dst: &mut BytesMut) {
        match self {
            Lease::V1 {
                key,
                state,
                flags,
                duration,
            } => {
                dst.put_slice(key);
                dst.put_u32_le(state.bits());
                dst.put_u32_le(*flags);
                dst.put_u64_le(*duration);
            }
            Lease::V2 {
                key,
                state,
                flags,
                duration,
                parent_key,
                epoch,
            } => {
                dst.put_slice(key);
                dst.put_u32_le(state.bits());
                dst.put_u32_le(*flags);
                dst.put_u64_le(*duration);
                dst.put_slice(parent_key);
                dst.put_u16_le(*epoch);
                dst.put_u16_le(0);
            }
        }
    }

    fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data, "lease context");
        let key = r.array()?;
        let state = LeaseState::from_bits_retain(r.u32()?);
        let flags = r.u32()?;
        let duration = r.u64()?;
        if data.len() >= 52 {
            let parent_key = r.array()?;
            let epoch = r.u16()?;
            Ok(Lease::V2 {
                key,
                state,
                flags,
                duration,
                parent_key,
                epoch,
            })
        } else {
            Ok(Lease::V1 {
                key,
                state,
                flags,
                duration,
            })
        }
    }
}

/// A create context sent with a CREATE request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateRequestContext {
    /// `DHnQ`: request a durable handle (v1).
    DurableHandleRequest,
    /// `DHnC`: reconnect a durable handle (v1).
    DurableHandleReconnect {
        /// The handle to reclaim.
        file_id: FileId,
    },
    /// `DH2Q`: request a durable/persistent handle (v2).
    DurableHandleRequestV2 {
        /// Requested timeout in milliseconds (0 = server default).
        timeout: u32,
        /// Flags (`DHANDLE_FLAG_PERSISTENT`).
        flags: u32,
        /// Client-generated id of this create, for replay detection.
        create_guid: Guid,
    },
    /// `DH2C`: reconnect a durable handle (v2).
    DurableHandleReconnectV2 {
        /// The handle to reclaim.
        file_id: FileId,
        /// The create GUID of the original open.
        create_guid: Guid,
        /// Flags (`DHANDLE_FLAG_PERSISTENT`).
        flags: u32,
    },
    /// `MxAc`: return the maximal access of the caller.
    QueryMaximalAccess {
        /// Optional timestamp for which to evaluate the access.
        timestamp: Option<FileTime>,
    },
    /// `QFid`: return the on-disk file id.
    QueryOnDiskId,
    /// `RqLs`: request a lease.
    RequestLease(Lease),
    /// `AlSi`: initial allocation size.
    AllocationSize(u64),
    /// `TWrp`: open the version of the file at this snapshot time.
    TimewarpToken(FileTime),
    /// Any other context, verbatim.
    Raw {
        /// Context name (usually 4 ASCII bytes or a 16-byte GUID).
        name: Bytes,
        /// Context data.
        data: Bytes,
    },
}

impl CreateRequestContext {
    fn name(&self) -> &[u8] {
        use context_name::*;
        match self {
            CreateRequestContext::DurableHandleRequest => DURABLE_HANDLE_REQUEST,
            CreateRequestContext::DurableHandleReconnect { .. } => DURABLE_HANDLE_RECONNECT,
            CreateRequestContext::DurableHandleRequestV2 { .. } => DURABLE_HANDLE_REQUEST_V2,
            CreateRequestContext::DurableHandleReconnectV2 { .. } => DURABLE_HANDLE_RECONNECT_V2,
            CreateRequestContext::QueryMaximalAccess { .. } => QUERY_MAXIMAL_ACCESS,
            CreateRequestContext::QueryOnDiskId => QUERY_ON_DISK_ID,
            CreateRequestContext::RequestLease(_) => REQUEST_LEASE,
            CreateRequestContext::AllocationSize(_) => ALLOCATION_SIZE,
            CreateRequestContext::TimewarpToken(_) => TIMEWARP_TOKEN,
            CreateRequestContext::Raw { name, .. } => name,
        }
    }

    fn encode_data(&self, dst: &mut BytesMut) {
        match self {
            CreateRequestContext::DurableHandleRequest => dst.put_bytes(0, 16),
            CreateRequestContext::DurableHandleReconnect { file_id } => file_id.put(dst),
            CreateRequestContext::DurableHandleRequestV2 {
                timeout,
                flags,
                create_guid,
            } => {
                dst.put_u32_le(*timeout);
                dst.put_u32_le(*flags);
                dst.put_u64_le(0);
                dst.put_slice(&create_guid.0);
            }
            CreateRequestContext::DurableHandleReconnectV2 {
                file_id,
                create_guid,
                flags,
            } => {
                file_id.put(dst);
                dst.put_slice(&create_guid.0);
                dst.put_u32_le(*flags);
            }
            CreateRequestContext::QueryMaximalAccess { timestamp } => {
                if let Some(t) = timestamp {
                    dst.put_u64_le(t.0);
                }
            }
            CreateRequestContext::QueryOnDiskId => {}
            CreateRequestContext::RequestLease(l) => l.encode(dst),
            CreateRequestContext::AllocationSize(n) => dst.put_u64_le(*n),
            CreateRequestContext::TimewarpToken(t) => dst.put_u64_le(t.0),
            CreateRequestContext::Raw { data, .. } => dst.put_slice(data),
        }
    }

    fn decode(name: Bytes, data: Bytes) -> Result<Self> {
        use context_name::*;
        let mut r = Reader::new(&data, "create context");
        let n: &[u8] = &name;
        Ok(if n == DURABLE_HANDLE_REQUEST && data.len() == 16 {
            CreateRequestContext::DurableHandleRequest
        } else if n == DURABLE_HANDLE_RECONNECT && data.len() == 16 {
            CreateRequestContext::DurableHandleReconnect {
                file_id: FileId::read(&mut r)?,
            }
        } else if n == DURABLE_HANDLE_REQUEST_V2 && data.len() == 32 {
            let timeout = r.u32()?;
            let flags = r.u32()?;
            r.skip(8)?;
            CreateRequestContext::DurableHandleRequestV2 {
                timeout,
                flags,
                create_guid: r.guid()?,
            }
        } else if n == DURABLE_HANDLE_RECONNECT_V2 && data.len() == 36 {
            let file_id = FileId::read(&mut r)?;
            let create_guid = r.guid()?;
            CreateRequestContext::DurableHandleReconnectV2 {
                file_id,
                create_guid,
                flags: r.u32()?,
            }
        } else if n == QUERY_MAXIMAL_ACCESS && (data.is_empty() || data.len() == 8) {
            let timestamp = if data.is_empty() {
                None
            } else {
                Some(FileTime(r.u64()?))
            };
            CreateRequestContext::QueryMaximalAccess { timestamp }
        } else if n == QUERY_ON_DISK_ID && data.is_empty() {
            CreateRequestContext::QueryOnDiskId
        } else if n == REQUEST_LEASE && (data.len() == 32 || data.len() == 52) {
            CreateRequestContext::RequestLease(Lease::decode(&data)?)
        } else if n == ALLOCATION_SIZE && data.len() == 8 {
            CreateRequestContext::AllocationSize(r.u64()?)
        } else if n == TIMEWARP_TOKEN && data.len() == 8 {
            CreateRequestContext::TimewarpToken(FileTime(r.u64()?))
        } else {
            CreateRequestContext::Raw { name, data }
        })
    }
}

/// A create context returned in a CREATE response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateResponseContext {
    /// `DHnQ`: the durable handle (v1) was granted.
    DurableHandleResponse,
    /// `DH2Q`: the durable handle (v2) was granted.
    DurableHandleResponseV2 {
        /// Granted timeout in milliseconds.
        timeout: u32,
        /// Flags (`DHANDLE_FLAG_PERSISTENT`).
        flags: u32,
    },
    /// `MxAc`: maximal access.
    MaximalAccess {
        /// Status of the access query.
        query_status: NtStatus,
        /// The caller's maximal access.
        maximal_access: AccessMask,
    },
    /// `QFid`: on-disk ids.
    OnDiskId {
        /// On-disk file id.
        disk_file_id: u64,
        /// Volume id.
        volume_id: u64,
    },
    /// `RqLs`: the granted lease.
    Lease(Lease),
    /// Any other context, verbatim.
    Raw {
        /// Context name.
        name: Bytes,
        /// Context data.
        data: Bytes,
    },
}

impl CreateResponseContext {
    fn name(&self) -> &[u8] {
        use context_name::*;
        match self {
            CreateResponseContext::DurableHandleResponse => DURABLE_HANDLE_REQUEST,
            CreateResponseContext::DurableHandleResponseV2 { .. } => DURABLE_HANDLE_REQUEST_V2,
            CreateResponseContext::MaximalAccess { .. } => QUERY_MAXIMAL_ACCESS,
            CreateResponseContext::OnDiskId { .. } => QUERY_ON_DISK_ID,
            CreateResponseContext::Lease(_) => REQUEST_LEASE,
            CreateResponseContext::Raw { name, .. } => name,
        }
    }

    fn encode_data(&self, dst: &mut BytesMut) {
        match self {
            CreateResponseContext::DurableHandleResponse => dst.put_bytes(0, 8),
            CreateResponseContext::DurableHandleResponseV2 { timeout, flags } => {
                dst.put_u32_le(*timeout);
                dst.put_u32_le(*flags);
            }
            CreateResponseContext::MaximalAccess {
                query_status,
                maximal_access,
            } => {
                dst.put_u32_le(query_status.0);
                dst.put_u32_le(maximal_access.bits());
            }
            CreateResponseContext::OnDiskId {
                disk_file_id,
                volume_id,
            } => {
                dst.put_u64_le(*disk_file_id);
                dst.put_u64_le(*volume_id);
                dst.put_bytes(0, 16);
            }
            CreateResponseContext::Lease(l) => l.encode(dst),
            CreateResponseContext::Raw { data, .. } => dst.put_slice(data),
        }
    }

    fn decode(name: Bytes, data: Bytes) -> Result<Self> {
        use context_name::*;
        let mut r = Reader::new(&data, "create response context");
        let n: &[u8] = &name;
        Ok(if n == DURABLE_HANDLE_REQUEST && data.len() == 8 {
            CreateResponseContext::DurableHandleResponse
        } else if n == DURABLE_HANDLE_REQUEST_V2 && data.len() == 8 {
            CreateResponseContext::DurableHandleResponseV2 {
                timeout: r.u32()?,
                flags: r.u32()?,
            }
        } else if n == QUERY_MAXIMAL_ACCESS && data.len() == 8 {
            CreateResponseContext::MaximalAccess {
                query_status: NtStatus(r.u32()?),
                maximal_access: AccessMask::from_bits_retain(r.u32()?),
            }
        } else if n == QUERY_ON_DISK_ID && data.len() == 32 {
            CreateResponseContext::OnDiskId {
                disk_file_id: r.u64()?,
                volume_id: r.u64()?,
            }
        } else if n == REQUEST_LEASE && (data.len() == 32 || data.len() == 52) {
            CreateResponseContext::Lease(Lease::decode(&data)?)
        } else {
            CreateResponseContext::Raw { name, data }
        })
    }
}

/// Something that can be encoded as one create context.
trait ContextItem {
    fn name(&self) -> &[u8];
    fn encode_data(&self, dst: &mut BytesMut);
}

impl ContextItem for CreateRequestContext {
    fn name(&self) -> &[u8] {
        CreateRequestContext::name(self)
    }
    fn encode_data(&self, dst: &mut BytesMut) {
        CreateRequestContext::encode_data(self, dst)
    }
}

impl ContextItem for CreateResponseContext {
    fn name(&self) -> &[u8] {
        CreateResponseContext::name(self)
    }
    fn encode_data(&self, dst: &mut BytesMut) {
        CreateResponseContext::encode_data(self, dst)
    }
}

/// Encode a create context chain. Contexts are 8-byte aligned relative to
/// the start of the chain (which itself is 8-byte aligned in the message);
/// the last context is not padded.
fn encode_context_chain<C: ContextItem>(dst: &mut BytesMut, contexts: &[C]) -> Result<()> {
    let n = contexts.len();
    for (i, c) in contexts.iter().enumerate() {
        let name = c.name();
        let start = dst.len();
        dst.put_u32_le(0); // Next
        dst.put_u16_le(16); // NameOffset
        dst.put_u16_le(len_u16(name.len(), "create context name too long")?);
        dst.put_u16_le(0); // Reserved
        let data_off_pos = dst.len();
        dst.put_u16_le(0); // DataOffset
        dst.put_u32_le(0); // DataLength
        dst.put_slice(name);
        let before_pad = dst.len();
        pad_to_rel(dst, start, 8);
        let data_start = dst.len();
        c.encode_data(dst);
        let data_len = dst.len() - data_start;
        if data_len == 0 {
            // No data: drop the alignment padding after the name.
            dst.truncate(before_pad);
        } else {
            patch_u16(
                dst,
                data_off_pos,
                len_u16(data_start - start, "create context too long")?,
            );
            patch_u32(
                dst,
                data_off_pos + 2,
                len_u32(data_len, "create context too long")?,
            );
        }
        if i + 1 < n {
            pad_to_rel(dst, start, 8);
            let v = len_u32(dst.len() - start, "create context too long")?;
            patch_u32(dst, start, v);
        }
    }
    Ok(())
}

fn pad_to_rel(dst: &mut BytesMut, start: usize, align: usize) {
    let pad = crate::wire::padding(dst.len() - start, align);
    dst.put_bytes(0, pad);
}

/// Decode a create context chain located at `msg[offset..offset + len]`,
/// yielding `(name, data)` pairs.
fn decode_context_chain(msg: &Bytes, offset: usize, len: usize) -> Result<Vec<(Bytes, Bytes)>> {
    const W: &str = "create context";
    let mut out = Vec::new();
    if len == 0 {
        return Ok(out);
    }
    let region = slice_bytes(msg, offset, len, W)?;
    let mut pos = 0usize;
    loop {
        let rest = region
            .get(pos..)
            .ok_or(ProtoError::malformed(W, "Next out of range"))?;
        let mut r = Reader::new(rest, W);
        let next = r.u32()? as usize;
        let name_off = usize::from(r.u16()?);
        let name_len = usize::from(r.u16()?);
        r.skip(2)?;
        let data_off = usize::from(r.u16()?);
        let data_len = r.u32()? as usize;
        let name = slice_bytes(&region, pos + name_off, name_len, W)?;
        let data = slice_bytes(&region, pos + data_off, data_len, W)?;
        out.push((name, data));
        if next == 0 {
            return Ok(out);
        }
        if next < 16 {
            return Err(ProtoError::malformed(W, "Next too small"));
        }
        pos += next;
    }
}

/// SMB2 CREATE request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CreateRequest {
    /// Security flags (reserved, 0).
    pub security_flags: u8,
    /// Requested oplock level ([`OplockLevel::LEASE`] with a lease context).
    pub requested_oplock_level: OplockLevel,
    /// Impersonation level (normally `IMPERSONATION`).
    pub impersonation_level: ImpersonationLevel,
    /// `SmbCreateFlags` (reserved, 0).
    pub smb_create_flags: u64,
    /// Desired access.
    pub desired_access: AccessMask,
    /// Attributes for a newly created file.
    pub file_attributes: FileAttributes,
    /// Share access.
    pub share_access: ShareAccess,
    /// Create disposition.
    pub create_disposition: CreateDisposition,
    /// Create options.
    pub create_options: CreateOptions,
    /// Path relative to the share root, without a leading `\` (empty for
    /// the root).
    pub name: String,
    /// Create contexts.
    pub contexts: Vec<CreateRequestContext>,
}

impl Message for CreateRequest {
    const COMMAND: Command = Command::CREATE;
    const RESPONSE: bool = false;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        let start = dst.len();
        let name_len = len_u16(utf16le_len(&self.name), "file name too long")?;
        dst.put_u16_le(57);
        dst.put_u8(self.security_flags);
        dst.put_u8(self.requested_oplock_level.0);
        dst.put_u32_le(self.impersonation_level.0);
        dst.put_u64_le(self.smb_create_flags);
        dst.put_u64_le(0);
        dst.put_u32_le(self.desired_access.bits());
        dst.put_u32_le(self.file_attributes.bits());
        dst.put_u32_le(self.share_access.bits());
        dst.put_u32_le(self.create_disposition.0);
        dst.put_u32_le(self.create_options.bits());
        dst.put_u16_le((HEADER_LEN + 56) as u16);
        dst.put_u16_le(name_len);
        let ctx_pos = dst.len();
        dst.put_u32_le(0);
        dst.put_u32_le(0);
        if name_len == 0 {
            // The buffer must not be empty; send a (zero-length) NUL name.
            dst.put_u16_le(0);
        } else {
            put_utf16le(dst, &self.name);
        }
        if !self.contexts.is_empty() {
            // Header (64) and fixed body (56) keep 8-byte alignment.
            pad_to_rel(dst, start, 8);
            let off = wire_offset(start, dst);
            let chain_start = dst.len();
            encode_context_chain(dst, &self.contexts)?;
            patch_u32(dst, ctx_pos, off as u32);
            let v = len_u32(dst.len() - chain_start, "create contexts too long")?;
            patch_u32(dst, ctx_pos + 4, v);
        }
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "CREATE request", 57)?;
        let security_flags = r.u8()?;
        let requested_oplock_level = OplockLevel(r.u8()?);
        let impersonation_level = ImpersonationLevel(r.u32()?);
        let smb_create_flags = r.u64()?;
        r.skip(8)?;
        let desired_access = AccessMask::from_bits_retain(r.u32()?);
        let file_attributes = FileAttributes::from_bits_retain(r.u32()?);
        let share_access = ShareAccess::from_bits_retain(r.u32()?);
        let create_disposition = CreateDisposition(r.u32()?);
        let create_options = CreateOptions::from_bits_retain(r.u32()?);
        let name_off = usize::from(r.u16()?);
        let name_len = usize::from(r.u16()?);
        let ctx_off = r.u32()? as usize;
        let ctx_len = r.u32()? as usize;
        let name = decode_utf16le(
            slice_ref(msg, name_off, name_len, "CREATE name")?,
            "CREATE name",
        )?;
        let contexts = decode_context_chain(msg, ctx_off, ctx_len)?
            .into_iter()
            .map(|(n, d)| CreateRequestContext::decode(n, d))
            .collect::<Result<_>>()?;
        Ok(CreateRequest {
            security_flags,
            requested_oplock_level,
            impersonation_level,
            smb_create_flags,
            desired_access,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            name,
            contexts,
        })
    }
}

/// `SMB2_CREATE_FLAG_REPARSEPOINT` in the CREATE response `Flags` (3.1.1).
pub const CREATE_FLAG_REPARSEPOINT: u8 = 0x01;

/// SMB2 CREATE response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CreateResponse {
    /// Granted oplock level.
    pub oplock_level: OplockLevel,
    /// Flags (`CREATE_FLAG_REPARSEPOINT`).
    pub flags: u8,
    /// What the server did.
    pub create_action: CreateAction,
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
    /// The new handle.
    pub file_id: FileId,
    /// Response contexts.
    pub contexts: Vec<CreateResponseContext>,
}

impl CreateResponse {
    /// The granted lease, if any.
    pub fn lease(&self) -> Option<&Lease> {
        self.contexts.iter().find_map(|c| match c {
            CreateResponseContext::Lease(l) => Some(l),
            _ => None,
        })
    }

    /// The maximal access, if requested and returned successfully.
    pub fn maximal_access(&self) -> Option<AccessMask> {
        self.contexts.iter().find_map(|c| match c {
            CreateResponseContext::MaximalAccess {
                query_status,
                maximal_access,
            } if query_status.is_success() => Some(*maximal_access),
            _ => None,
        })
    }

    /// `true` if the open is a directory.
    pub fn is_directory(&self) -> bool {
        self.file_attributes.contains(FileAttributes::DIRECTORY)
    }
}

impl Message for CreateResponse {
    const COMMAND: Command = Command::CREATE;
    const RESPONSE: bool = true;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        let start = dst.len();
        dst.put_u16_le(89);
        dst.put_u8(self.oplock_level.0);
        dst.put_u8(self.flags);
        dst.put_u32_le(self.create_action.0);
        for t in [
            self.creation_time,
            self.last_access_time,
            self.last_write_time,
            self.change_time,
        ] {
            dst.put_u64_le(t.0);
        }
        dst.put_u64_le(self.allocation_size);
        dst.put_u64_le(self.end_of_file);
        dst.put_u32_le(self.file_attributes.bits());
        dst.put_u32_le(0);
        self.file_id.put(dst);
        let ctx_pos = dst.len();
        dst.put_u32_le(0);
        dst.put_u32_le(0);
        if self.contexts.is_empty() {
            dst.put_u8(0);
        } else {
            let off = wire_offset(start, dst);
            let chain_start = dst.len();
            encode_context_chain(dst, &self.contexts)?;
            patch_u32(dst, ctx_pos, off as u32);
            let v = len_u32(dst.len() - chain_start, "create contexts too long")?;
            patch_u32(dst, ctx_pos + 4, v);
        }
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "CREATE response", 89)?;
        let oplock_level = OplockLevel(r.u8()?);
        let flags = r.u8()?;
        let create_action = CreateAction(r.u32()?);
        let creation_time = FileTime(r.u64()?);
        let last_access_time = FileTime(r.u64()?);
        let last_write_time = FileTime(r.u64()?);
        let change_time = FileTime(r.u64()?);
        let allocation_size = r.u64()?;
        let end_of_file = r.u64()?;
        let file_attributes = FileAttributes::from_bits_retain(r.u32()?);
        r.skip(4)?;
        let file_id = FileId::read(&mut r)?;
        let ctx_off = r.u32()? as usize;
        let ctx_len = r.u32()? as usize;
        let contexts = decode_context_chain(msg, ctx_off, ctx_len)?
            .into_iter()
            .map(|(n, d)| CreateResponseContext::decode(n, d))
            .collect::<Result<_>>()?;
        Ok(CreateResponse {
            oplock_level,
            flags,
            create_action,
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
            allocation_size,
            end_of_file,
            file_attributes,
            file_id,
            contexts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{Header, HeaderFlags};
    use crate::msg::{RawMessage, encode_message};

    fn rt<M: Message + PartialEq + std::fmt::Debug>(m: &M) -> M {
        let mut h = Header::request(M::COMMAND);
        if M::RESPONSE {
            h.flags = HeaderFlags::SERVER_TO_REDIR;
        }
        let enc = encode_message(&h, m).unwrap().into_contiguous().freeze();
        RawMessage::parse(enc).unwrap().decode::<M>().unwrap()
    }

    #[test]
    fn create_request_all_contexts() {
        let req = CreateRequest {
            requested_oplock_level: OplockLevel::LEASE,
            impersonation_level: ImpersonationLevel::IMPERSONATION,
            desired_access: AccessMask::GENERIC_READ | AccessMask::FILE_READ_ATTRIBUTES,
            file_attributes: FileAttributes::NORMAL,
            share_access: ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE,
            create_disposition: CreateDisposition::OPEN_IF,
            create_options: CreateOptions::NON_DIRECTORY_FILE,
            name: "dir\\file.txt".into(),
            contexts: vec![
                CreateRequestContext::DurableHandleRequest,
                CreateRequestContext::DurableHandleReconnect {
                    file_id: FileId::new(1, 2),
                },
                CreateRequestContext::DurableHandleRequestV2 {
                    timeout: 60_000,
                    flags: DHANDLE_FLAG_PERSISTENT,
                    create_guid: Guid([5; 16]),
                },
                CreateRequestContext::DurableHandleReconnectV2 {
                    file_id: FileId::new(3, 4),
                    create_guid: Guid([6; 16]),
                    flags: 0,
                },
                CreateRequestContext::QueryMaximalAccess { timestamp: None },
                CreateRequestContext::QueryMaximalAccess {
                    timestamp: Some(FileTime(77)),
                },
                CreateRequestContext::QueryOnDiskId,
                CreateRequestContext::RequestLease(Lease::V1 {
                    key: [1; 16],
                    state: LeaseState::READ_CACHING | LeaseState::HANDLE_CACHING,
                    flags: 0,
                    duration: 0,
                }),
                CreateRequestContext::RequestLease(Lease::V2 {
                    key: [2; 16],
                    state: LeaseState::all(),
                    flags: LEASE_FLAG_PARENT_LEASE_KEY_SET,
                    duration: 0,
                    parent_key: [3; 16],
                    epoch: 9,
                }),
                CreateRequestContext::AllocationSize(1 << 20),
                CreateRequestContext::TimewarpToken(FileTime(1234)),
                CreateRequestContext::Raw {
                    name: Bytes::from_static(&[0xAB; 16]),
                    data: Bytes::from_static(b"xyz"),
                },
                CreateRequestContext::Raw {
                    name: Bytes::from_static(b"ExtA"),
                    data: Bytes::new(),
                },
            ],
            ..Default::default()
        };
        assert_eq!(rt(&req), req);
        let empty = CreateRequest::default();
        assert_eq!(rt(&empty), empty);
        let only_ctx = CreateRequest {
            contexts: vec![CreateRequestContext::QueryOnDiskId],
            ..Default::default()
        };
        assert_eq!(rt(&only_ctx), only_ctx);
    }

    #[test]
    fn create_response_contexts() {
        let resp = CreateResponse {
            oplock_level: OplockLevel::LEASE,
            create_action: CreateAction::CREATED,
            end_of_file: 10,
            file_attributes: FileAttributes::ARCHIVE,
            file_id: FileId::new(10, 20),
            contexts: vec![
                CreateResponseContext::DurableHandleResponse,
                CreateResponseContext::DurableHandleResponseV2 {
                    timeout: 1,
                    flags: 0,
                },
                CreateResponseContext::MaximalAccess {
                    query_status: NtStatus::SUCCESS,
                    maximal_access: AccessMask::from_bits_retain(0x001F_01FF),
                },
                CreateResponseContext::OnDiskId {
                    disk_file_id: 5,
                    volume_id: 6,
                },
                CreateResponseContext::Lease(Lease::V1 {
                    key: [1; 16],
                    state: LeaseState::READ_CACHING,
                    flags: LEASE_FLAG_BREAK_IN_PROGRESS,
                    duration: 0,
                }),
            ],
            ..Default::default()
        };
        let d = rt(&resp);
        assert_eq!(d, resp);
        assert_eq!(
            d.maximal_access(),
            Some(AccessMask::from_bits_retain(0x001F_01FF))
        );
        assert_eq!(d.lease().unwrap().state(), LeaseState::READ_CACHING);
        assert_eq!(rt(&CreateResponse::default()), CreateResponse::default());
    }
}
