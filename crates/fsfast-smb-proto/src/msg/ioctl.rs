//! IOCTL request/response ([MS-SMB2] §2.2.31, §2.2.32) and the FSCTL
//! payloads a client needs: VALIDATE_NEGOTIATE_INFO, SRV_REQUEST_RESUME_KEY,
//! SRV_COPYCHUNK(_WRITE), DFS_GET_REFERRALS(_EX) ([MS-DFSC]) and
//! QUERY_NETWORK_INTERFACE_INFO.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::{BufMut, Bytes, BytesMut};

use super::{Message, body_reader};
use crate::error::{ProtoError, Result};
use crate::header::{Command, HEADER_LEN, credit_charge_for};
use crate::types::{Capabilities, Dialect, FileId, SecurityMode};
use crate::wire::{
    Guid, Reader, decode_utf16z, len_u16, len_u32, padding, patch_u16, patch_u32, put_utf16le,
    slice_bytes,
};

/// IOCTL/FSCTL control codes.
pub mod fsctl {
    /// FSCTL_DFS_GET_REFERRALS.
    pub const DFS_GET_REFERRALS: u32 = 0x0006_0194;
    /// FSCTL_DFS_GET_REFERRALS_EX.
    pub const DFS_GET_REFERRALS_EX: u32 = 0x0006_01B0;
    /// FSCTL_PIPE_PEEK.
    pub const PIPE_PEEK: u32 = 0x0011_400C;
    /// FSCTL_PIPE_WAIT.
    pub const PIPE_WAIT: u32 = 0x0011_0018;
    /// FSCTL_PIPE_TRANSCEIVE.
    pub const PIPE_TRANSCEIVE: u32 = 0x0011_C017;
    /// FSCTL_SRV_COPYCHUNK.
    pub const SRV_COPYCHUNK: u32 = 0x0014_40F2;
    /// FSCTL_SRV_COPYCHUNK_WRITE.
    pub const SRV_COPYCHUNK_WRITE: u32 = 0x0014_80F2;
    /// FSCTL_SRV_ENUMERATE_SNAPSHOTS.
    pub const SRV_ENUMERATE_SNAPSHOTS: u32 = 0x0014_4064;
    /// FSCTL_SRV_REQUEST_RESUME_KEY.
    pub const SRV_REQUEST_RESUME_KEY: u32 = 0x0014_0078;
    /// FSCTL_SRV_READ_HASH.
    pub const SRV_READ_HASH: u32 = 0x0014_41BB;
    /// FSCTL_LMR_REQUEST_RESILIENCY.
    pub const LMR_REQUEST_RESILIENCY: u32 = 0x0014_01D4;
    /// FSCTL_QUERY_NETWORK_INTERFACE_INFO.
    pub const QUERY_NETWORK_INTERFACE_INFO: u32 = 0x0014_01FC;
    /// FSCTL_VALIDATE_NEGOTIATE_INFO.
    pub const VALIDATE_NEGOTIATE_INFO: u32 = 0x0014_0204;
    /// FSCTL_SET_REPARSE_POINT.
    pub const SET_REPARSE_POINT: u32 = 0x0009_00A4;
    /// FSCTL_GET_REPARSE_POINT.
    pub const GET_REPARSE_POINT: u32 = 0x0009_00A8;
    /// FSCTL_SET_SPARSE.
    pub const SET_SPARSE: u32 = 0x0009_00C4;
    /// FSCTL_SET_ZERO_DATA.
    pub const SET_ZERO_DATA: u32 = 0x0009_80C8;
    /// FSCTL_QUERY_ALLOCATED_RANGES.
    pub const QUERY_ALLOCATED_RANGES: u32 = 0x0009_40CF;
    /// FSCTL_DUPLICATE_EXTENTS_TO_FILE.
    pub const DUPLICATE_EXTENTS_TO_FILE: u32 = 0x0009_8344;
    /// FSCTL_FILE_LEVEL_TRIM.
    pub const FILE_LEVEL_TRIM: u32 = 0x0009_8208;
}

/// `SMB2_0_IOCTL_IS_FSCTL`.
pub const IOCTL_IS_FSCTL: u32 = 0x0000_0001;

/// SMB2 IOCTL request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IoctlRequest {
    /// Control code (see [`fsctl`]).
    pub ctl_code: u32,
    /// Target handle; [`FileId::RELATED`] in compounds, all-ones for
    /// connection-level FSCTLs (VALIDATE_NEGOTIATE_INFO, DFS referrals,
    /// interface queries).
    pub file_id: FileId,
    /// Input buffer.
    pub input: Bytes,
    /// Output buffer (normally empty in requests).
    pub output: Bytes,
    /// Maximum input buffer size in the response.
    pub max_input_response: u32,
    /// Maximum output buffer size in the response.
    pub max_output_response: u32,
    /// Flags ([`IOCTL_IS_FSCTL`]).
    pub flags: u32,
}

impl IoctlRequest {
    /// An FSCTL request with `input`.
    pub fn fsctl(ctl_code: u32, file_id: FileId, input: Bytes, max_output_response: u32) -> Self {
        IoctlRequest {
            ctl_code,
            file_id,
            input,
            output: Bytes::new(),
            max_input_response: 0,
            max_output_response,
            flags: IOCTL_IS_FSCTL,
        }
    }
}

impl Message for IoctlRequest {
    const COMMAND: Command = Command::IOCTL;
    const RESPONSE: bool = false;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        let buf_off = (HEADER_LEN + 56) as u32;
        let out_off = buf_off + self.input.len() as u32;
        dst.put_u16_le(57);
        dst.put_u16_le(0);
        dst.put_u32_le(self.ctl_code);
        self.file_id.put(dst);
        dst.put_u32_le(if self.input.is_empty() { 0 } else { buf_off });
        dst.put_u32_le(len_u32(self.input.len(), "ioctl input too long")?);
        dst.put_u32_le(self.max_input_response);
        dst.put_u32_le(if self.output.is_empty() { 0 } else { out_off });
        dst.put_u32_le(len_u32(self.output.len(), "ioctl output too long")?);
        dst.put_u32_le(self.max_output_response);
        dst.put_u32_le(self.flags);
        dst.put_u32_le(0);
        dst.put_slice(&self.input);
        dst.put_slice(&self.output);
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "IOCTL request", 57)?;
        r.skip(2)?;
        let ctl_code = r.u32()?;
        let file_id = FileId::read(&mut r)?;
        let in_off = r.u32()? as usize;
        let in_len = r.u32()? as usize;
        let max_input_response = r.u32()?;
        let out_off = r.u32()? as usize;
        let out_len = r.u32()? as usize;
        let max_output_response = r.u32()?;
        let flags = r.u32()?;
        Ok(IoctlRequest {
            ctl_code,
            file_id,
            input: slice_bytes(msg, in_off, in_len, "IOCTL input")?,
            output: slice_bytes(msg, out_off, out_len, "IOCTL output")?,
            max_input_response,
            max_output_response,
            flags,
        })
    }

    fn credit_charge(&self) -> u16 {
        credit_charge_for(
            (self.input.len() + self.output.len())
                .max(self.max_output_response as usize + self.max_input_response as usize),
        )
    }
}

/// SMB2 IOCTL response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IoctlResponse {
    /// Control code.
    pub ctl_code: u32,
    /// Handle.
    pub file_id: FileId,
    /// Input buffer (usually empty).
    pub input: Bytes,
    /// Output buffer (zero-copy slice).
    pub output: Bytes,
    /// Flags.
    pub flags: u32,
}

impl Message for IoctlResponse {
    const COMMAND: Command = Command::IOCTL;
    const RESPONSE: bool = true;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        let start = dst.len();
        let buf_off = HEADER_LEN + 48;
        dst.put_u16_le(49);
        dst.put_u16_le(0);
        dst.put_u32_le(self.ctl_code);
        self.file_id.put(dst);
        let offs_pos = dst.len();
        dst.put_u32_le(0);
        dst.put_u32_le(len_u32(self.input.len(), "ioctl input too long")?);
        dst.put_u32_le(0);
        dst.put_u32_le(len_u32(self.output.len(), "ioctl output too long")?);
        dst.put_u32_le(self.flags);
        dst.put_u32_le(0);
        if !self.input.is_empty() {
            patch_u32(dst, offs_pos, buf_off as u32);
            dst.put_slice(&self.input);
        }
        if !self.output.is_empty() {
            dst.put_bytes(0, padding(dst.len() - start, 8));
            let v = (HEADER_LEN + dst.len() - start) as u32;
            patch_u32(dst, offs_pos + 8, v);
            dst.put_slice(&self.output);
        }
        if self.input.is_empty() && self.output.is_empty() {
            dst.put_u8(0);
        }
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "IOCTL response", 49)?;
        r.skip(2)?;
        let ctl_code = r.u32()?;
        let file_id = FileId::read(&mut r)?;
        let in_off = r.u32()? as usize;
        let in_len = r.u32()? as usize;
        let out_off = r.u32()? as usize;
        let out_len = r.u32()? as usize;
        let flags = r.u32()?;
        Ok(IoctlResponse {
            ctl_code,
            file_id,
            input: slice_bytes(msg, in_off, in_len, "IOCTL input")?,
            output: slice_bytes(msg, out_off, out_len, "IOCTL output")?,
            flags,
        })
    }
}

/// An FSCTL input/output structure.
pub trait FsctlData: Sized {
    /// Encode to bytes.
    fn encode(&self, dst: &mut BytesMut) -> Result<()>;
    /// Decode from bytes.
    fn decode(buf: &[u8]) -> Result<Self>;
    /// Encode into a fresh buffer.
    fn to_bytes(&self) -> Result<Bytes> {
        let mut b = BytesMut::new();
        self.encode(&mut b)?;
        Ok(b.freeze())
    }
}

/// VALIDATE_NEGOTIATE_INFO request (3.0/3.0.2 downgrade protection).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidateNegotiateInfoRequest {
    /// Client capabilities as sent in NEGOTIATE.
    pub capabilities: Capabilities,
    /// Client GUID.
    pub guid: Guid,
    /// Client security mode.
    pub security_mode: SecurityMode,
    /// Dialects offered in NEGOTIATE.
    pub dialects: Vec<Dialect>,
}

impl FsctlData for ValidateNegotiateInfoRequest {
    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u32_le(self.capabilities.bits());
        dst.put_slice(&self.guid.0);
        dst.put_u16_le(self.security_mode.bits());
        dst.put_u16_le(len_u16(self.dialects.len(), "too many dialects")?);
        for d in &self.dialects {
            dst.put_u16_le(d.0);
        }
        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "VALIDATE_NEGOTIATE_INFO request");
        let capabilities = Capabilities::from_bits_retain(r.u32()?);
        let guid = r.guid()?;
        let security_mode = SecurityMode::from_bits_retain(r.u16()?);
        let n = usize::from(r.u16()?);
        let dialects = (0..n)
            .map(|_| r.u16().map(Dialect))
            .collect::<Result<_>>()?;
        Ok(ValidateNegotiateInfoRequest {
            capabilities,
            guid,
            security_mode,
            dialects,
        })
    }
}

/// VALIDATE_NEGOTIATE_INFO response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ValidateNegotiateInfoResponse {
    /// Server capabilities.
    pub capabilities: Capabilities,
    /// Server GUID.
    pub guid: Guid,
    /// Server security mode.
    pub security_mode: SecurityMode,
    /// Negotiated dialect.
    pub dialect: Dialect,
}

impl FsctlData for ValidateNegotiateInfoResponse {
    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u32_le(self.capabilities.bits());
        dst.put_slice(&self.guid.0);
        dst.put_u16_le(self.security_mode.bits());
        dst.put_u16_le(self.dialect.0);
        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "VALIDATE_NEGOTIATE_INFO response");
        Ok(ValidateNegotiateInfoResponse {
            capabilities: Capabilities::from_bits_retain(r.u32()?),
            guid: r.guid()?,
            security_mode: SecurityMode::from_bits_retain(r.u16()?),
            dialect: Dialect(r.u16()?),
        })
    }
}

/// SRV_REQUEST_RESUME_KEY response: the key identifying a source file for
/// server-side copy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvRequestResumeKeyResponse {
    /// Opaque 24-byte resume key.
    pub resume_key: [u8; 24],
    /// Context (usually empty).
    pub context: Bytes,
}

impl FsctlData for SrvRequestResumeKeyResponse {
    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_slice(&self.resume_key);
        dst.put_u32_le(len_u32(self.context.len(), "context too long")?);
        dst.put_slice(&self.context);
        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "SRV_REQUEST_RESUME_KEY response");
        let resume_key = r.array()?;
        let len = r.u32()? as usize;
        // Windows reports ContextLength 0 but appends 4 reserved bytes; take
        // what the length says.
        let context = Bytes::copy_from_slice(r.bytes(len)?);
        Ok(SrvRequestResumeKeyResponse {
            resume_key,
            context,
        })
    }
}

/// One chunk of a server-side copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SrvCopyChunk {
    /// Offset in the source file.
    pub source_offset: u64,
    /// Offset in the target file.
    pub target_offset: u64,
    /// Bytes to copy.
    pub length: u32,
}

/// SRV_COPYCHUNK_COPY: input of FSCTL_SRV_COPYCHUNK(_WRITE).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SrvCopyChunkCopy {
    /// Resume key of the source file.
    pub source_key: [u8; 24],
    /// Chunks to copy (servers limit the count, typically to 256).
    pub chunks: Vec<SrvCopyChunk>,
}

impl FsctlData for SrvCopyChunkCopy {
    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_slice(&self.source_key);
        dst.put_u32_le(len_u32(self.chunks.len(), "too many chunks")?);
        dst.put_u32_le(0);
        for c in &self.chunks {
            dst.put_u64_le(c.source_offset);
            dst.put_u64_le(c.target_offset);
            dst.put_u32_le(c.length);
            dst.put_u32_le(0);
        }
        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "SRV_COPYCHUNK_COPY");
        let source_key = r.array()?;
        let n = r.u32()? as usize;
        r.skip(4)?;
        if n > r.remaining() / 24 {
            return Err(r.malformed("chunk count exceeds buffer"));
        }
        let mut chunks = Vec::with_capacity(n);
        for _ in 0..n {
            let source_offset = r.u64()?;
            let target_offset = r.u64()?;
            let length = r.u32()?;
            r.skip(4)?;
            chunks.push(SrvCopyChunk {
                source_offset,
                target_offset,
                length,
            });
        }
        Ok(SrvCopyChunkCopy { source_key, chunks })
    }
}

/// SRV_COPYCHUNK_RESPONSE. With `STATUS_INVALID_PARAMETER` the fields carry
/// the server's limits (max chunks, max chunk size, max total bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SrvCopyChunkResponse {
    /// Chunks written (or the server's maximum chunk count).
    pub chunks_written: u32,
    /// Bytes written in a partial last chunk (or the maximum chunk size).
    pub chunk_bytes_written: u32,
    /// Total bytes written (or the maximum total size).
    pub total_bytes_written: u32,
}

impl FsctlData for SrvCopyChunkResponse {
    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u32_le(self.chunks_written);
        dst.put_u32_le(self.chunk_bytes_written);
        dst.put_u32_le(self.total_bytes_written);
        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "SRV_COPYCHUNK_RESPONSE");
        Ok(SrvCopyChunkResponse {
            chunks_written: r.u32()?,
            chunk_bytes_written: r.u32()?,
            total_bytes_written: r.u32()?,
        })
    }
}

fn put_utf16z(dst: &mut BytesMut, s: &str) {
    put_utf16le(dst, s);
    dst.put_u16_le(0);
}

/// REQ_GET_DFS_REFERRAL ([MS-DFSC] §2.2.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DfsReferralRequest {
    /// Highest referral version understood (4).
    pub max_referral_level: u16,
    /// Path to resolve, e.g. `\\domain\dfs\folder`.
    pub request_file_name: String,
}

impl FsctlData for DfsReferralRequest {
    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u16_le(self.max_referral_level);
        put_utf16z(dst, &self.request_file_name);
        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "REQ_GET_DFS_REFERRAL");
        let max_referral_level = r.u16()?;
        let request_file_name = decode_utf16z(buf, 2, "REQ_GET_DFS_REFERRAL")?;
        Ok(DfsReferralRequest {
            max_referral_level,
            request_file_name,
        })
    }
}

/// REQ_GET_DFS_REFERRAL_EX ([MS-DFSC] §2.2.3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DfsReferralRequestEx {
    /// Highest referral version understood.
    pub max_referral_level: u16,
    /// Path to resolve.
    pub request_file_name: String,
    /// Optional site name (sets `SITE_NAME` in RequestFlags).
    pub site_name: Option<String>,
}

impl FsctlData for DfsReferralRequestEx {
    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        let name = crate::wire::utf16le_vec(&self.request_file_name);
        let site = self.site_name.as_deref().map(crate::wire::utf16le_vec);
        dst.put_u16_le(self.max_referral_level);
        dst.put_u16_le(u16::from(site.is_some()));
        let data_len = 2 + name.len() + site.as_ref().map_or(0, |s| 2 + s.len());
        dst.put_u32_le(len_u32(data_len, "referral request too long")?);
        dst.put_u16_le(len_u16(name.len(), "file name too long")?);
        dst.put_slice(&name);
        if let Some(s) = site {
            dst.put_u16_le(len_u16(s.len(), "site name too long")?);
            dst.put_slice(&s);
        }
        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        const W: &str = "REQ_GET_DFS_REFERRAL_EX";
        let mut r = Reader::new(buf, W);
        let max_referral_level = r.u16()?;
        let flags = r.u16()?;
        let _data_len = r.u32()?;
        let n = usize::from(r.u16()?);
        let request_file_name = crate::wire::decode_utf16le(r.bytes(n)?, W)?;
        let site_name = if flags & 1 != 0 {
            let n = usize::from(r.u16()?);
            Some(crate::wire::decode_utf16le(r.bytes(n)?, W)?)
        } else {
            None
        };
        Ok(DfsReferralRequestEx {
            max_referral_level,
            request_file_name,
            site_name,
        })
    }
}

/// DFS referral header flags ([MS-DFSC] §2.2.4).
pub mod dfs_header_flags {
    /// The targets are DFS root/link servers (ReferralServers).
    pub const REFERRAL_SERVERS: u32 = 0x0000_0001;
    /// The targets hold the storage (StorageServers).
    pub const STORAGE_SERVERS: u32 = 0x0000_0002;
    /// Clients should fail back to preferred targets (TargetFailback).
    pub const TARGET_FAILBACK: u32 = 0x0000_0004;
}

/// DFS referral entry flags.
pub mod dfs_entry_flags {
    /// Domain/DC name list referral.
    pub const NAME_LIST_REFERRAL: u16 = 0x0002;
    /// First target of a target set (v4).
    pub const TARGET_SET_BOUNDARY: u16 = 0x0004;
}

/// The variable part of a DFS referral entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DfsReferralTarget {
    /// v1 entry: just a share name.
    V1 {
        /// Target share path.
        share_name: String,
    },
    /// A regular target (v2/v3/v4).
    Target {
        /// The DFS path this referral resolves.
        dfs_path: String,
        /// 8.3 form of `dfs_path`.
        dfs_alternate_path: String,
        /// The target, e.g. `\\server\share\path`.
        network_address: String,
    },
    /// A name list referral (v3/v4 with `NAME_LIST_REFERRAL`): domain or DC
    /// names.
    NameList {
        /// Domain name being resolved.
        special_name: String,
        /// Expanded names (DCs or domains).
        expanded_names: Vec<String>,
    },
}

/// One DFS referral entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DfsReferral {
    /// Version number (1–4).
    pub version: u16,
    /// Server type (1 = root targets, 0 = link targets).
    pub server_type: u16,
    /// Entry flags (see [`dfs_entry_flags`]).
    pub referral_entry_flags: u16,
    /// Proximity (v2 only).
    pub proximity: u32,
    /// Cache time-to-live in seconds (v2+).
    pub time_to_live: u32,
    /// Target description.
    pub target: DfsReferralTarget,
}

/// RESP_GET_DFS_REFERRAL ([MS-DFSC] §2.2.4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DfsReferralResponse {
    /// Bytes of the request path consumed by the referral (UTF-16 bytes).
    pub path_consumed: u16,
    /// Header flags (see [`dfs_header_flags`]).
    pub header_flags: u32,
    /// Referral entries.
    pub referrals: Vec<DfsReferral>,
}

impl FsctlData for DfsReferralResponse {
    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        let base = dst.len();
        dst.put_u16_le(self.path_consumed);
        dst.put_u16_le(len_u16(self.referrals.len(), "too many referrals")?);
        dst.put_u32_le(self.header_flags);
        // Fixed entries first, strings in a trailing buffer; offsets are
        // relative to each entry's start.
        let mut fixups: Vec<(usize, usize, Vec<String>)> = Vec::new(); // (entry start, field pos, strings)
        for r in &self.referrals {
            let start = dst.len();
            dst.put_u16_le(r.version);
            let size_pos = dst.len();
            dst.put_u16_le(0);
            dst.put_u16_le(r.server_type);
            dst.put_u16_le(r.referral_entry_flags);
            match (&r.target, r.version) {
                (DfsReferralTarget::V1 { share_name }, 1) => {
                    put_utf16z(dst, share_name);
                }
                (
                    DfsReferralTarget::Target {
                        dfs_path,
                        dfs_alternate_path,
                        network_address,
                    },
                    v @ 2..=4,
                ) => {
                    if v == 2 {
                        dst.put_u32_le(r.proximity);
                    }
                    dst.put_u32_le(r.time_to_live);
                    for s in [dfs_path, dfs_alternate_path, network_address] {
                        fixups.push((start, dst.len(), vec![s.clone()]));
                        dst.put_u16_le(0);
                    }
                    if v >= 3 {
                        dst.put_bytes(0, 16); // ServiceSiteGuid
                    }
                }
                (
                    DfsReferralTarget::NameList {
                        special_name,
                        expanded_names,
                    },
                    3 | 4,
                ) => {
                    dst.put_u32_le(r.time_to_live);
                    fixups.push((start, dst.len(), vec![special_name.clone()]));
                    dst.put_u16_le(0);
                    dst.put_u16_le(len_u16(expanded_names.len(), "too many expanded names")?);
                    fixups.push((start, dst.len(), expanded_names.clone()));
                    dst.put_u16_le(0);
                    dst.put_bytes(0, 16);
                }
                _ => {
                    return Err(ProtoError::InvalidInput(
                        "DFS referral target does not match its version",
                    ));
                }
            }
            let v = len_u16(dst.len() - start, "referral too long")?;
            patch_u16(dst, size_pos, v);
        }
        for (start, pos, strings) in fixups {
            let v = len_u16(dst.len() - start, "referral strings too long")?;
            patch_u16(dst, pos, v);
            for s in strings {
                put_utf16z(dst, &s);
            }
        }
        let _ = base;
        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        const W: &str = "RESP_GET_DFS_REFERRAL";
        let mut r = Reader::new(buf, W);
        let path_consumed = r.u16()?;
        let n = usize::from(r.u16()?);
        let header_flags = r.u32()?;
        let mut referrals = Vec::with_capacity(n.min(64));
        let mut pos = 8usize;
        for _ in 0..n {
            let entry = buf.get(pos..).ok_or(ProtoError::Truncated {
                what: W,
                need: pos,
                have: buf.len(),
            })?;
            let mut e = Reader::new(entry, W);
            let version = e.u16()?;
            let size = usize::from(e.u16()?);
            let server_type = e.u16()?;
            let referral_entry_flags = e.u16()?;
            if size < 8 {
                return Err(ProtoError::malformed(W, "referral entry size too small"));
            }
            let s = |off: u16| decode_utf16z(entry, usize::from(off), W);
            let (proximity, time_to_live, target) = match version {
                1 => (
                    0,
                    0,
                    DfsReferralTarget::V1 {
                        share_name: decode_utf16z(entry, 8, W)?,
                    },
                ),
                2 => {
                    let proximity = e.u32()?;
                    let ttl = e.u32()?;
                    let (p, a, n) = (e.u16()?, e.u16()?, e.u16()?);
                    (
                        proximity,
                        ttl,
                        DfsReferralTarget::Target {
                            dfs_path: s(p)?,
                            dfs_alternate_path: s(a)?,
                            network_address: s(n)?,
                        },
                    )
                }
                3 | 4 => {
                    let ttl = e.u32()?;
                    if referral_entry_flags & dfs_entry_flags::NAME_LIST_REFERRAL != 0 {
                        let special = e.u16()?;
                        let count = usize::from(e.u16()?);
                        let mut off = usize::from(e.u16()?);
                        let mut expanded_names = Vec::with_capacity(count.min(64));
                        for _ in 0..count {
                            let name = decode_utf16z(entry, off, W)?;
                            off += name.encode_utf16().count() * 2 + 2;
                            expanded_names.push(name);
                        }
                        (
                            0,
                            ttl,
                            DfsReferralTarget::NameList {
                                special_name: s(special)?,
                                expanded_names,
                            },
                        )
                    } else {
                        let (p, a, n) = (e.u16()?, e.u16()?, e.u16()?);
                        (
                            0,
                            ttl,
                            DfsReferralTarget::Target {
                                dfs_path: s(p)?,
                                dfs_alternate_path: s(a)?,
                                network_address: s(n)?,
                            },
                        )
                    }
                }
                _ => return Err(ProtoError::Unsupported("DFS referral version")),
            };
            referrals.push(DfsReferral {
                version,
                server_type,
                referral_entry_flags,
                proximity,
                time_to_live,
                target,
            });
            pos += size;
        }
        Ok(DfsReferralResponse {
            path_consumed,
            header_flags,
            referrals,
        })
    }
}

/// Interface capability bits of [`NetworkInterfaceInfo`].
pub mod interface_capability {
    /// Receive-side scaling.
    pub const RSS_CAPABLE: u32 = 0x0000_0001;
    /// RDMA.
    pub const RDMA_CAPABLE: u32 = 0x0000_0002;
}

/// One NETWORK_INTERFACE_INFO entry (multichannel discovery).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkInterfaceInfo {
    /// Interface index.
    pub if_index: u32,
    /// Capabilities (see [`interface_capability`]).
    pub capability: u32,
    /// Link speed in bits per second.
    pub link_speed: u64,
    /// Interface address; `None` for address families other than IPv4/IPv6.
    pub address: Option<SocketAddr>,
}

const AF_INET: u16 = 0x0002;
const AF_INET6: u16 = 0x0017;
const NETWORK_INTERFACE_INFO_LEN: usize = 152;

/// Decode the output of FSCTL_QUERY_NETWORK_INTERFACE_INFO.
pub fn decode_network_interfaces(buf: &[u8]) -> Result<Vec<NetworkInterfaceInfo>> {
    const W: &str = "NETWORK_INTERFACE_INFO";
    let mut out = Vec::new();
    let mut pos = 0usize;
    if buf.is_empty() {
        return Ok(out);
    }
    loop {
        let entry = buf
            .get(pos..)
            .ok_or(ProtoError::malformed(W, "Next out of range"))?;
        let mut r = Reader::new(entry, W);
        let next = r.u32()? as usize;
        let if_index = r.u32()?;
        let capability = r.u32()?;
        r.skip(4)?;
        let link_speed = r.u64()?;
        let sa = r.bytes(128)?;
        let mut s = Reader::new(sa, W);
        let family = s.u16()?;
        let port = u16::from_be_bytes(s.array()?);
        let address = match family {
            AF_INET => Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(s.array::<4>()?),
                port,
            ))),
            AF_INET6 => {
                let flow = s.u32()?;
                let ip = Ipv6Addr::from(s.array::<16>()?);
                let scope = s.u32()?;
                Some(SocketAddr::V6(SocketAddrV6::new(ip, port, flow, scope)))
            }
            _ => None,
        };
        out.push(NetworkInterfaceInfo {
            if_index,
            capability,
            link_speed,
            address,
        });
        if next == 0 {
            return Ok(out);
        }
        if next < NETWORK_INTERFACE_INFO_LEN {
            return Err(ProtoError::malformed(W, "Next too small"));
        }
        pos += next;
    }
}

/// Encode NETWORK_INTERFACE_INFO entries (mock servers, tests).
pub fn encode_network_interfaces(entries: &[NetworkInterfaceInfo], dst: &mut BytesMut) {
    for (i, e) in entries.iter().enumerate() {
        let next = if i + 1 < entries.len() {
            NETWORK_INTERFACE_INFO_LEN as u32
        } else {
            0
        };
        dst.put_u32_le(next);
        dst.put_u32_le(e.if_index);
        dst.put_u32_le(e.capability);
        dst.put_u32_le(0);
        dst.put_u64_le(e.link_speed);
        let start = dst.len();
        match e.address {
            Some(SocketAddr::V4(a)) => {
                dst.put_u16_le(AF_INET);
                dst.put_u16(a.port());
                dst.put_slice(&a.ip().octets());
            }
            Some(SocketAddr::V6(a)) => {
                dst.put_u16_le(AF_INET6);
                dst.put_u16(a.port());
                dst.put_u32_le(a.flowinfo());
                dst.put_slice(&a.ip().octets());
                dst.put_u32_le(a.scope_id());
            }
            None => dst.put_u16_le(0),
        }
        dst.put_bytes(0, 128 - (dst.len() - start));
    }
}

impl NetworkInterfaceInfo {
    /// The IP address, if known.
    pub fn ip(&self) -> Option<IpAddr> {
        self.address.map(|a| a.ip())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt<T: FsctlData + PartialEq + std::fmt::Debug>(v: T) {
        let b = v.to_bytes().unwrap();
        assert_eq!(T::decode(&b).unwrap(), v);
        for i in 0..b.len() {
            let _ = T::decode(&b[..i]);
        }
    }

    #[test]
    fn fsctl_round_trips() {
        rt(ValidateNegotiateInfoRequest {
            capabilities: Capabilities::DFS,
            guid: Guid([1; 16]),
            security_mode: SecurityMode::SIGNING_ENABLED,
            dialects: vec![Dialect::SMB_3_0, Dialect::SMB_3_0_2],
        });
        rt(ValidateNegotiateInfoResponse {
            dialect: Dialect::SMB_3_0_2,
            ..Default::default()
        });
        rt(SrvRequestResumeKeyResponse {
            resume_key: [7; 24],
            context: Bytes::new(),
        });
        rt(SrvCopyChunkCopy {
            source_key: [1; 24],
            chunks: vec![SrvCopyChunk {
                source_offset: 0,
                target_offset: 10,
                length: 1 << 20,
            }],
        });
        rt(SrvCopyChunkResponse {
            chunks_written: 1,
            chunk_bytes_written: 0,
            total_bytes_written: 5,
        });
        rt(DfsReferralRequest {
            max_referral_level: 4,
            request_file_name: "\\\\dom\\dfs".into(),
        });
        rt(DfsReferralRequestEx {
            max_referral_level: 4,
            request_file_name: "\\\\dom\\dfs".into(),
            site_name: None,
        });
        rt(DfsReferralRequestEx {
            max_referral_level: 4,
            request_file_name: "\\\\dom\\dfs".into(),
            site_name: Some("site".into()),
        });
        rt(DfsReferralResponse {
            path_consumed: 20,
            header_flags: dfs_header_flags::STORAGE_SERVERS,
            referrals: vec![
                DfsReferral {
                    version: 4,
                    server_type: 1,
                    referral_entry_flags: dfs_entry_flags::TARGET_SET_BOUNDARY,
                    proximity: 0,
                    time_to_live: 300,
                    target: DfsReferralTarget::Target {
                        dfs_path: "\\dom\\dfs".into(),
                        dfs_alternate_path: "\\dom\\dfs".into(),
                        network_address: "\\srv1\\share".into(),
                    },
                },
                DfsReferral {
                    version: 3,
                    server_type: 0,
                    referral_entry_flags: dfs_entry_flags::NAME_LIST_REFERRAL,
                    proximity: 0,
                    time_to_live: 600,
                    target: DfsReferralTarget::NameList {
                        special_name: "\\dom".into(),
                        expanded_names: vec!["\\dc1".into(), "\\dc2".into()],
                    },
                },
                DfsReferral {
                    version: 2,
                    server_type: 0,
                    referral_entry_flags: 0,
                    proximity: 7,
                    time_to_live: 60,
                    target: DfsReferralTarget::Target {
                        dfs_path: "a".into(),
                        dfs_alternate_path: "b".into(),
                        network_address: "c".into(),
                    },
                },
                DfsReferral {
                    version: 1,
                    server_type: 0,
                    referral_entry_flags: 0,
                    proximity: 0,
                    time_to_live: 0,
                    target: DfsReferralTarget::V1 {
                        share_name: "\\srv\\s".into(),
                    },
                },
            ],
        });
    }

    #[test]
    fn network_interfaces() {
        let v = vec![
            NetworkInterfaceInfo {
                if_index: 1,
                capability: interface_capability::RSS_CAPABLE,
                link_speed: 10_000_000_000,
                address: Some("192.168.1.2:0".parse().unwrap()),
            },
            NetworkInterfaceInfo {
                if_index: 2,
                capability: 0,
                link_speed: 1_000_000_000,
                address: Some(SocketAddr::V6(SocketAddrV6::new(
                    "fe80::1".parse().unwrap(),
                    0,
                    0,
                    3,
                ))),
            },
        ];
        let mut b = BytesMut::new();
        encode_network_interfaces(&v, &mut b);
        assert_eq!(b.len(), 2 * NETWORK_INTERFACE_INFO_LEN);
        assert_eq!(decode_network_interfaces(&b).unwrap(), v);
    }
}
