//! The SFTP v3 `ATTRS` structure (draft-ietf-secsh-filexfer-02 §5).

use bytes::{BufMut, Bytes, BytesMut};

use super::ProtoError;
use super::wire::{Cursor, put_string};

/// `SSH_FILEXFER_ATTR_*` flag bits.
pub mod flags {
    /// `size` is present.
    pub const SIZE: u32 = 0x0000_0001;
    /// `uid` and `gid` are present.
    pub const UIDGID: u32 = 0x0000_0002;
    /// `permissions` is present.
    pub const PERMISSIONS: u32 = 0x0000_0004;
    /// `atime` and `mtime` are present.
    pub const ACMODTIME: u32 = 0x0000_0008;
    /// Extended attribute pairs follow.
    pub const EXTENDED: u32 = 0x8000_0000;
}

/// POSIX file type bits of `permissions` (`st_mode`).
pub mod mode {
    /// Mask of the file type bits.
    pub const S_IFMT: u32 = 0o170_000;
    /// Directory.
    pub const S_IFDIR: u32 = 0o040_000;
    /// Regular file.
    pub const S_IFREG: u32 = 0o100_000;
    /// Symbolic link.
    pub const S_IFLNK: u32 = 0o120_000;
}

/// File attributes. Every field is optional on the wire; `uid`/`gid` and
/// `atime`/`mtime` travel in pairs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileAttributes {
    /// File size in bytes.
    pub size: Option<u64>,
    /// `(uid, gid)`.
    pub uid_gid: Option<(u32, u32)>,
    /// POSIX `st_mode`: file type and permission bits.
    pub permissions: Option<u32>,
    /// `(atime, mtime)` in seconds since the Unix epoch.
    pub times: Option<(u32, u32)>,
    /// Extended attributes as `(type, data)` pairs.
    pub extended: Vec<(Bytes, Bytes)>,
}

/// File type derived from [`FileAttributes::permissions`], using the same
/// rules as fsspec's `SFTPFileSystem._decode_stat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `S_ISDIR`.
    Directory,
    /// `S_ISLNK`.
    Symlink,
    /// Anything else, including attributes without permission bits.
    File,
}

impl FileAttributes {
    /// Attributes carrying only a size (used to truncate a file).
    pub fn with_size(size: u64) -> Self {
        FileAttributes {
            size: Some(size),
            ..Default::default()
        }
    }

    /// Attributes carrying only access and modification times.
    pub fn with_times(atime: u32, mtime: u32) -> Self {
        FileAttributes {
            times: Some((atime, mtime)),
            ..Default::default()
        }
    }

    /// The flag word for the fields present.
    pub fn flags(&self) -> u32 {
        let mut f = 0;
        if self.size.is_some() {
            f |= flags::SIZE;
        }
        if self.uid_gid.is_some() {
            f |= flags::UIDGID;
        }
        if self.permissions.is_some() {
            f |= flags::PERMISSIONS;
        }
        if self.times.is_some() {
            f |= flags::ACMODTIME;
        }
        if !self.extended.is_empty() {
            f |= flags::EXTENDED;
        }
        f
    }

    /// Number of bytes [`FileAttributes::encode`] appends.
    pub fn encoded_len(&self) -> usize {
        let mut n = 4;
        if self.size.is_some() {
            n += 8;
        }
        if self.uid_gid.is_some() {
            n += 8;
        }
        if self.permissions.is_some() {
            n += 4;
        }
        if self.times.is_some() {
            n += 8;
        }
        if !self.extended.is_empty() {
            n += 4;
            for (t, d) in &self.extended {
                n += 8 + t.len() + d.len();
            }
        }
        n
    }

    /// Append the wire form.
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.flags());
        if let Some(s) = self.size {
            buf.put_u64(s);
        }
        if let Some((u, g)) = self.uid_gid {
            buf.put_u32(u);
            buf.put_u32(g);
        }
        if let Some(p) = self.permissions {
            buf.put_u32(p);
        }
        if let Some((a, m)) = self.times {
            buf.put_u32(a);
            buf.put_u32(m);
        }
        if !self.extended.is_empty() {
            buf.put_u32(self.extended.len() as u32);
            for (t, d) in &self.extended {
                put_string(buf, t);
                put_string(buf, d);
            }
        }
    }

    /// Decode from `c`. Unknown flag bits are an error: their fields would
    /// be of unknown size, so the rest of the packet could not be parsed.
    pub fn decode(c: &mut Cursor) -> Result<Self, ProtoError> {
        let f = c.u32()?;
        let known = flags::SIZE | flags::UIDGID | flags::PERMISSIONS | flags::ACMODTIME;
        if f & !(known | flags::EXTENDED) != 0 {
            return Err(ProtoError::new(format!(
                "ATTRS with unknown flag bits 0x{:08x}",
                f & !(known | flags::EXTENDED)
            )));
        }
        let mut a = FileAttributes::default();
        if f & flags::SIZE != 0 {
            a.size = Some(c.u64()?);
        }
        if f & flags::UIDGID != 0 {
            a.uid_gid = Some((c.u32()?, c.u32()?));
        }
        if f & flags::PERMISSIONS != 0 {
            a.permissions = Some(c.u32()?);
        }
        if f & flags::ACMODTIME != 0 {
            a.times = Some((c.u32()?, c.u32()?));
        }
        if f & flags::EXTENDED != 0 {
            let n = c.u32()? as usize;
            // Each pair needs at least 8 bytes: never trust the count for
            // the allocation.
            if n > c.remaining() / 8 {
                return Err(ProtoError::new(format!(
                    "ATTRS claims {n} extended pairs in {} bytes",
                    c.remaining()
                )));
            }
            a.extended.reserve_exact(n);
            for _ in 0..n {
                let t = c.string()?;
                let d = c.string()?;
                a.extended.push((t, d));
            }
        }
        Ok(a)
    }

    /// The file type, as fsspec's `_decode_stat` derives it.
    pub fn kind(&self) -> Kind {
        match self.permissions.map(|p| p & mode::S_IFMT) {
            Some(mode::S_IFDIR) => Kind::Directory,
            Some(mode::S_IFLNK) => Kind::Symlink,
            _ => Kind::File,
        }
    }

    /// Whether the attributes describe a directory.
    pub fn is_dir(&self) -> bool {
        self.kind() == Kind::Directory
    }

    /// `uid`, if present.
    pub fn uid(&self) -> Option<u32> {
        self.uid_gid.map(|(u, _)| u)
    }

    /// `gid`, if present.
    pub fn gid(&self) -> Option<u32> {
        self.uid_gid.map(|(_, g)| g)
    }

    /// `atime`, if present.
    pub fn atime(&self) -> Option<u32> {
        self.times.map(|(a, _)| a)
    }

    /// `mtime`, if present.
    pub fn mtime(&self) -> Option<u32> {
        self.times.map(|(_, m)| m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(a: &FileAttributes) -> FileAttributes {
        let mut b = BytesMut::new();
        a.encode(&mut b);
        assert_eq!(b.len(), a.encoded_len());
        let mut c = Cursor::new(b.freeze());
        let d = FileAttributes::decode(&mut c).unwrap();
        c.finish("attrs").unwrap();
        d
    }

    #[test]
    fn empty_and_full_roundtrip() {
        let empty = FileAttributes::default();
        assert_eq!(roundtrip(&empty), empty);
        let full = FileAttributes {
            size: Some(1 << 40),
            uid_gid: Some((1000, 100)),
            permissions: Some(0o100_644),
            times: Some((1, u32::MAX)),
            extended: vec![(Bytes::from_static(b"x@y"), Bytes::from_static(b"\0\x01"))],
        };
        assert_eq!(roundtrip(&full), full);
        assert_eq!(full.flags(), 0x8000_000f);
    }

    #[test]
    fn kinds_follow_fsspec() {
        let k = |p| FileAttributes {
            permissions: p,
            ..Default::default()
        }
        .kind();
        assert_eq!(k(Some(0o040_755)), Kind::Directory);
        assert_eq!(k(Some(0o120_777)), Kind::Symlink);
        assert_eq!(k(Some(0o100_644)), Kind::File);
        assert_eq!(k(Some(0o020_644)), Kind::File); // character device
        assert_eq!(k(None), Kind::File);
    }

    #[test]
    fn unknown_flags_and_hostile_counts_are_errors() {
        let mut c = Cursor::new(Bytes::from_static(&[0, 0, 0, 0x10]));
        assert!(FileAttributes::decode(&mut c).is_err());
        let mut b = BytesMut::new();
        b.put_u32(flags::EXTENDED);
        b.put_u32(u32::MAX);
        let mut c = Cursor::new(b.freeze());
        assert!(FileAttributes::decode(&mut c).is_err());
    }
}
