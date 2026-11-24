//! TREE_CONNECT and TREE_DISCONNECT ([MS-SMB2] §2.2.9–§2.2.12).

use bitflags::bitflags;
use bytes::{BufMut, Bytes, BytesMut};

use super::session::empty_message;
use super::{Message, body_reader};
use crate::error::Result;
use crate::fscc::AccessMask;
use crate::header::{Command, HEADER_LEN};
use crate::wire::{decode_utf16le, len_u16, put_utf16le, slice_ref, utf16le_len};

bitflags! {
    /// TREE_CONNECT request `Flags` (3.1.1).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct TreeConnectFlags: u16 {
        /// Cluster reconnect.
        const CLUSTER_RECONNECT = 0x0001;
        /// Redirect to owner.
        const REDIRECT_TO_OWNER = 0x0002;
        /// A TREE_CONNECT_Request_Extension follows (not produced by this
        /// codec).
        const EXTENSION_PRESENT = 0x0004;
        const _ = !0;
    }
}

/// Share type of a TREE_CONNECT response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct ShareType(pub u8);

impl ShareType {
    /// Disk share.
    pub const DISK: Self = Self(0x01);
    /// Named pipe share (IPC$).
    pub const PIPE: Self = Self(0x02);
    /// Printer share.
    pub const PRINT: Self = Self(0x03);
}

bitflags! {
    /// TREE_CONNECT response `ShareFlags`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct ShareFlags: u32 {
        /// The share is in DFS.
        const DFS = 0x0000_0001;
        /// The share is a DFS root.
        const DFS_ROOT = 0x0000_0002;
        /// Caching mode mask (manual = 0).
        const CACHING_MASK = 0x0000_0030;
        /// Automatic caching of documents.
        const AUTO_CACHING = 0x0000_0010;
        /// Automatic caching of programs and documents.
        const VDO_CACHING = 0x0000_0020;
        /// Offline caching disabled.
        const NO_CACHING = 0x0000_0030;
        /// Restrict exclusive opens.
        const RESTRICT_EXCLUSIVE_OPENS = 0x0000_0100;
        /// Force shared delete.
        const FORCE_SHARED_DELETE = 0x0000_0200;
        /// Namespace caching allowed.
        const ALLOW_NAMESPACE_CACHING = 0x0000_0400;
        /// Access-based directory enumeration.
        const ACCESS_BASED_DIRECTORY_ENUM = 0x0000_0800;
        /// Force level II oplocks.
        const FORCE_LEVELII_OPLOCK = 0x0000_1000;
        /// Hash v1 enabled.
        const ENABLE_HASH_V1 = 0x0000_2000;
        /// Hash v2 enabled.
        const ENABLE_HASH_V2 = 0x0000_4000;
        /// The share requires encryption.
        const ENCRYPT_DATA = 0x0000_8000;
        /// Identity remoting.
        const IDENTITY_REMOTING = 0x0004_0000;
        /// Compression requested.
        const COMPRESS_DATA = 0x0010_0000;
        /// Isolated transport preferred.
        const ISOLATED_TRANSPORT = 0x0020_0000;
        const _ = !0;
    }
}

bitflags! {
    /// TREE_CONNECT response `Capabilities`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct ShareCapabilities: u32 {
        /// DFS.
        const DFS = 0x0000_0008;
        /// Continuous availability.
        const CONTINUOUS_AVAILABILITY = 0x0000_0010;
        /// Scale-out.
        const SCALEOUT = 0x0000_0020;
        /// Cluster.
        const CLUSTER = 0x0000_0040;
        /// Asymmetric.
        const ASYMMETRIC = 0x0000_0080;
        /// Redirect to owner.
        const REDIRECT_TO_OWNER = 0x0000_0100;
        const _ = !0;
    }
}

/// SMB2 TREE_CONNECT request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TreeConnectRequest {
    /// Flags (3.1.1).
    pub flags: TreeConnectFlags,
    /// UNC path, e.g. `\\server\share`.
    pub path: String,
}

impl Message for TreeConnectRequest {
    const COMMAND: Command = Command::TREE_CONNECT;
    const RESPONSE: bool = false;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u16_le(9);
        dst.put_u16_le(self.flags.bits());
        dst.put_u16_le((HEADER_LEN + 8) as u16);
        dst.put_u16_le(len_u16(utf16le_len(&self.path), "share path too long")?);
        put_utf16le(dst, &self.path);
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "TREE_CONNECT request", 9)?;
        let flags = TreeConnectFlags::from_bits_retain(r.u16()?);
        let off = usize::from(r.u16()?);
        let len = usize::from(r.u16()?);
        let path = decode_utf16le(slice_ref(msg, off, len, "TREE_CONNECT path")?, "TREE_CONNECT path")?;
        Ok(TreeConnectRequest { flags, path })
    }
}

/// SMB2 TREE_CONNECT response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TreeConnectResponse {
    /// Share type.
    pub share_type: ShareType,
    /// Share flags.
    pub share_flags: ShareFlags,
    /// Share capabilities.
    pub capabilities: ShareCapabilities,
    /// Maximal access the user has on the share.
    pub maximal_access: AccessMask,
}

impl Message for TreeConnectResponse {
    const COMMAND: Command = Command::TREE_CONNECT;
    const RESPONSE: bool = true;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u16_le(16);
        dst.put_u8(self.share_type.0);
        dst.put_u8(0);
        dst.put_u32_le(self.share_flags.bits());
        dst.put_u32_le(self.capabilities.bits());
        dst.put_u32_le(self.maximal_access.bits());
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "TREE_CONNECT response", 16)?;
        let share_type = ShareType(r.u8()?);
        r.skip(1)?;
        Ok(TreeConnectResponse {
            share_type,
            share_flags: ShareFlags::from_bits_retain(r.u32()?),
            capabilities: ShareCapabilities::from_bits_retain(r.u32()?),
            maximal_access: AccessMask::from_bits_retain(r.u32()?),
        })
    }
}

empty_message!(
    /// SMB2 TREE_DISCONNECT request.
    TreeDisconnectRequest, Command::TREE_DISCONNECT, false, "TREE_DISCONNECT request"
);
empty_message!(
    /// SMB2 TREE_DISCONNECT response.
    TreeDisconnectResponse, Command::TREE_DISCONNECT, true, "TREE_DISCONNECT response"
);
