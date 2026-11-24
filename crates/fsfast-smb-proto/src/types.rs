//! Small protocol types shared across messages: dialects, file ids,
//! security mode and global capabilities.

use std::fmt;

use bitflags::bitflags;
use bytes::{BufMut, BytesMut};

use crate::error::Result;
use crate::wire::Reader;

/// SMB2 dialect revision.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct Dialect(pub u16);

impl Dialect {
    /// SMB 2.0.2.
    pub const SMB_2_0_2: Dialect = Dialect(0x0202);
    /// SMB 2.1.
    pub const SMB_2_1: Dialect = Dialect(0x0210);
    /// The SMB 2.x wildcard revision used in multi-protocol negotiation.
    pub const SMB_2_WILDCARD: Dialect = Dialect(0x02FF);
    /// SMB 3.0.
    pub const SMB_3_0: Dialect = Dialect(0x0300);
    /// SMB 3.0.2.
    pub const SMB_3_0_2: Dialect = Dialect(0x0302);
    /// SMB 3.1.1.
    pub const SMB_3_1_1: Dialect = Dialect(0x0311);

    /// All dialects this crate speaks, oldest first.
    pub const ALL: [Dialect; 5] =
        [Self::SMB_2_0_2, Self::SMB_2_1, Self::SMB_3_0, Self::SMB_3_0_2, Self::SMB_3_1_1];

    /// `true` for the SMB 3.x family (AES signing, encryption, KDF).
    pub fn is_smb3(self) -> bool {
        self.0 >= 0x0300 && self != Self::SMB_2_WILDCARD
    }

    /// `true` for 3.1.1 (preauth integrity, negotiate contexts).
    pub fn is_3_1_1(self) -> bool {
        self == Self::SMB_3_1_1
    }

    /// `true` if multi-credit (large MTU) requests are possible.
    pub fn supports_multi_credit(self) -> bool {
        self.0 >= 0x0210 && self != Self::SMB_2_WILDCARD
    }
}

impl fmt::Debug for Dialect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::SMB_2_0_2 => f.write_str("SMB 2.0.2"),
            Self::SMB_2_1 => f.write_str("SMB 2.1"),
            Self::SMB_2_WILDCARD => f.write_str("SMB 2.???"),
            Self::SMB_3_0 => f.write_str("SMB 3.0"),
            Self::SMB_3_0_2 => f.write_str("SMB 3.0.2"),
            Self::SMB_3_1_1 => f.write_str("SMB 3.1.1"),
            Dialect(d) => write!(f, "Dialect(0x{d:04X})"),
        }
    }
}

impl fmt::Display for Dialect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// An SMB2 file id (`SMB2_FILEID`): persistent and volatile halves.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct FileId {
    /// Persistent handle part (survives reconnect for durable handles).
    pub persistent: u64,
    /// Volatile handle part.
    pub volatile: u64,
}

impl FileId {
    /// The file id that refers to the handle created by a previous request
    /// in a related compound chain ([MS-SMB2] §3.2.4.1.4).
    pub const RELATED: FileId = FileId { persistent: u64::MAX, volatile: u64::MAX };

    /// Build from the two halves.
    pub const fn new(persistent: u64, volatile: u64) -> Self {
        FileId { persistent, volatile }
    }

    /// `true` for [`FileId::RELATED`].
    pub fn is_related(&self) -> bool {
        *self == Self::RELATED
    }

    /// The 16 wire bytes.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&self.persistent.to_le_bytes());
        b[8..].copy_from_slice(&self.volatile.to_le_bytes());
        b
    }

    /// Parse 16 wire bytes.
    pub fn from_bytes(b: [u8; 16]) -> Self {
        let mut p = [0u8; 8];
        let mut v = [0u8; 8];
        p.copy_from_slice(&b[..8]);
        v.copy_from_slice(&b[8..]);
        FileId { persistent: u64::from_le_bytes(p), volatile: u64::from_le_bytes(v) }
    }

    pub(crate) fn put(&self, dst: &mut BytesMut) {
        dst.put_u64_le(self.persistent);
        dst.put_u64_le(self.volatile);
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(FileId { persistent: r.u64()?, volatile: r.u64()? })
    }
}

impl fmt::Debug for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_related() {
            f.write_str("FileId(RELATED)")
        } else {
            write!(f, "FileId({:#x}:{:#x})", self.persistent, self.volatile)
        }
    }
}

bitflags! {
    /// `SecurityMode` of NEGOTIATE (16-bit) and SESSION_SETUP (8-bit).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct SecurityMode: u16 {
        /// Signing is enabled.
        const SIGNING_ENABLED = 0x0001;
        /// Signing is required.
        const SIGNING_REQUIRED = 0x0002;
        const _ = !0;
    }
}

bitflags! {
    /// Global `Capabilities` of NEGOTIATE / SESSION_SETUP ([MS-SMB2] §2.2.3).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct Capabilities: u32 {
        /// DFS.
        const DFS = 0x0000_0001;
        /// File leasing.
        const LEASING = 0x0000_0002;
        /// Multi-credit operations (large MTU).
        const LARGE_MTU = 0x0000_0004;
        /// Multichannel.
        const MULTI_CHANNEL = 0x0000_0008;
        /// Persistent handles.
        const PERSISTENT_HANDLES = 0x0000_0010;
        /// Directory leasing.
        const DIRECTORY_LEASING = 0x0000_0020;
        /// Encryption (3.0/3.0.2; implied by contexts in 3.1.1).
        const ENCRYPTION = 0x0000_0040;
        /// Server-to-client notifications (3.1.1).
        const NOTIFICATIONS = 0x0000_0080;
        const _ = !0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_id_bytes() {
        let id = FileId::new(0x0102030405060708, 0x1112131415161718);
        assert_eq!(FileId::from_bytes(id.to_bytes()), id);
        assert!(FileId::RELATED.is_related());
        assert_eq!(FileId::RELATED.to_bytes(), [0xFF; 16]);
    }

    #[test]
    fn dialect_props() {
        assert!(Dialect::SMB_3_0.is_smb3());
        assert!(!Dialect::SMB_2_WILDCARD.is_smb3());
        assert!(!Dialect::SMB_2_0_2.supports_multi_credit());
        assert!(Dialect::SMB_2_1.supports_multi_credit());
        assert!(Dialect::SMB_3_1_1 > Dialect::SMB_3_0_2);
        assert_eq!(format!("{}", Dialect::SMB_3_1_1), "SMB 3.1.1");
    }
}
