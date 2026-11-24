//! File and file system information classes ([MS-FSCC] §2.4, §2.5) used
//! with QUERY_INFO and SET_INFO.

use bitflags::bitflags;
use bytes::{BufMut, Bytes, BytesMut};

use super::{AccessMask, FileAttributes, FileInfoClass, FileTime, FsInfoClass, InfoType};
use crate::error::{ProtoError, Result};
use crate::wire::{Reader, decode_utf16le, len_u32, put_utf16le, utf16le_len};

/// An information class that can be queried or set.
pub trait InfoClass: Sized {
    /// `InfoType` of the QUERY_INFO/SET_INFO request.
    const INFO_TYPE: InfoType;
    /// `FileInfoClass` byte of the request.
    const CLASS: u8;

    /// Decode from an output buffer.
    fn decode(buf: &[u8]) -> Result<Self>;

    /// Encode into a SET_INFO buffer (or a mock server's output buffer).
    fn encode(&self, dst: &mut BytesMut) -> Result<()>;

    /// Encode into a fresh buffer.
    fn to_bytes(&self) -> Result<Bytes> {
        let mut b = BytesMut::new();
        self.encode(&mut b)?;
        Ok(b.freeze())
    }
}

macro_rules! file_class {
    ($t:ty, $class:expr) => {
        const INFO_TYPE: InfoType = InfoType::FILE;
        const CLASS: u8 = $class.0;
    };
}

macro_rules! fs_class {
    ($class:expr) => {
        const INFO_TYPE: InfoType = InfoType::FILESYSTEM;
        const CLASS: u8 = $class.0;
    };
}

fn times(r: &mut Reader<'_>) -> Result<[FileTime; 4]> {
    Ok([FileTime(r.u64()?), FileTime(r.u64()?), FileTime(r.u64()?), FileTime(r.u64()?)])
}

/// FileBasicInformation (40 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileBasicInformation {
    /// Creation time.
    pub creation_time: FileTime,
    /// Last access time.
    pub last_access_time: FileTime,
    /// Last write time.
    pub last_write_time: FileTime,
    /// Change time.
    pub change_time: FileTime,
    /// Attributes (0 in SET_INFO means "do not change").
    pub file_attributes: FileAttributes,
}

impl FileBasicInformation {
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let [c, a, w, ch] = times(r)?;
        let file_attributes = FileAttributes::from_bits_retain(r.u32()?);
        r.skip(4)?;
        Ok(FileBasicInformation {
            creation_time: c,
            last_access_time: a,
            last_write_time: w,
            change_time: ch,
            file_attributes,
        })
    }
}

impl InfoClass for FileBasicInformation {
    file_class!(Self, FileInfoClass::BASIC);

    fn decode(buf: &[u8]) -> Result<Self> {
        Self::read(&mut Reader::new(buf, "FileBasicInformation"))
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u64_le(self.creation_time.0);
        dst.put_u64_le(self.last_access_time.0);
        dst.put_u64_le(self.last_write_time.0);
        dst.put_u64_le(self.change_time.0);
        dst.put_u32_le(self.file_attributes.bits());
        dst.put_u32_le(0);
        Ok(())
    }
}

/// FileStandardInformation (24 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileStandardInformation {
    /// Allocated size.
    pub allocation_size: u64,
    /// File size.
    pub end_of_file: u64,
    /// Hard link count.
    pub number_of_links: u32,
    /// Delete pending.
    pub delete_pending: bool,
    /// Is a directory.
    pub directory: bool,
}

impl FileStandardInformation {
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let s = FileStandardInformation {
            allocation_size: r.u64()?,
            end_of_file: r.u64()?,
            number_of_links: r.u32()?,
            delete_pending: r.u8()? != 0,
            directory: r.u8()? != 0,
        };
        r.skip(2)?;
        Ok(s)
    }
}

impl InfoClass for FileStandardInformation {
    file_class!(Self, FileInfoClass::STANDARD);

    fn decode(buf: &[u8]) -> Result<Self> {
        Self::read(&mut Reader::new(buf, "FileStandardInformation"))
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u64_le(self.allocation_size);
        dst.put_u64_le(self.end_of_file);
        dst.put_u32_le(self.number_of_links);
        dst.put_u8(self.delete_pending.into());
        dst.put_u8(self.directory.into());
        dst.put_u16_le(0);
        Ok(())
    }
}

macro_rules! scalar_class {
    ($(#[$m:meta])* $name:ident, $field:ident : $ty:ty, $class:expr, $get:ident, $put:ident, $info:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub struct $name {
            #[allow(missing_docs)]
            pub $field: $ty,
        }

        impl InfoClass for $name {
            const INFO_TYPE: InfoType = InfoType::$info;
            const CLASS: u8 = $class.0;

            fn decode(buf: &[u8]) -> Result<Self> {
                let mut r = Reader::new(buf, stringify!($name));
                Ok($name { $field: r.$get()?.into() })
            }

            fn encode(&self, dst: &mut BytesMut) -> Result<()> {
                dst.$put(self.$field.into());
                Ok(())
            }
        }
    };
}

scalar_class!(
    /// FileInternalInformation: the file's index number (inode).
    FileInternalInformation, index_number: u64, FileInfoClass::INTERNAL, u64, put_u64_le, FILE
);
scalar_class!(
    /// FileEaInformation: size of the extended attributes.
    FileEaInformation, ea_size: u32, FileInfoClass::EA, u32, put_u32_le, FILE
);
scalar_class!(
    /// FilePositionInformation: current byte offset of the handle.
    FilePositionInformation, current_byte_offset: u64, FileInfoClass::POSITION, u64, put_u64_le, FILE
);
scalar_class!(
    /// FileModeInformation.
    FileModeInformation, mode: u32, FileInfoClass::MODE, u32, put_u32_le, FILE
);
scalar_class!(
    /// FileAlignmentInformation.
    FileAlignmentInformation, alignment_requirement: u32, FileInfoClass::ALIGNMENT, u32, put_u32_le, FILE
);
scalar_class!(
    /// FileEndOfFileInformation: set the file size (truncate/extend).
    FileEndOfFileInformation, end_of_file: u64, FileInfoClass::END_OF_FILE, u64, put_u64_le, FILE
);
scalar_class!(
    /// FileAllocationInformation: set the allocation size.
    FileAllocationInformation, allocation_size: u64, FileInfoClass::ALLOCATION, u64, put_u64_le, FILE
);

/// FileAccessInformation: the access granted to the handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileAccessInformation {
    /// Granted access.
    pub access_flags: AccessMask,
}

impl InfoClass for FileAccessInformation {
    file_class!(Self, FileInfoClass::ACCESS);

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "FileAccessInformation");
        Ok(FileAccessInformation { access_flags: AccessMask::from_bits_retain(r.u32()?) })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u32_le(self.access_flags.bits());
        Ok(())
    }
}

fn read_name(r: &mut Reader<'_>, what: &'static str) -> Result<String> {
    let len = r.u32()? as usize;
    decode_utf16le(r.bytes(len)?, what)
}

fn put_name(dst: &mut BytesMut, name: &str) -> Result<()> {
    dst.put_u32_le(len_u32(utf16le_len(name), "name too long")?);
    put_utf16le(dst, name);
    Ok(())
}

/// FileNameInformation (also FileAlternateNameInformation's layout).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileNameInformation {
    /// The file name (path relative to the share root, with a leading `\`).
    pub file_name: String,
}

impl InfoClass for FileNameInformation {
    file_class!(Self, FileInfoClass::NAME);

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "FileNameInformation");
        Ok(FileNameInformation { file_name: read_name(&mut r, "FileNameInformation")? })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        put_name(dst, &self.file_name)
    }
}

/// FileAllInformation: basic, standard, internal, EA, access, position,
/// mode, alignment and name information in one query.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileAllInformation {
    /// Basic information.
    pub basic: FileBasicInformation,
    /// Standard information.
    pub standard: FileStandardInformation,
    /// Index number.
    pub internal: FileInternalInformation,
    /// EA size.
    pub ea: FileEaInformation,
    /// Granted access.
    pub access: FileAccessInformation,
    /// Position.
    pub position: FilePositionInformation,
    /// Mode.
    pub mode: FileModeInformation,
    /// Alignment.
    pub alignment: FileAlignmentInformation,
    /// Name.
    pub name: FileNameInformation,
}

impl InfoClass for FileAllInformation {
    file_class!(Self, FileInfoClass::ALL);

    fn decode(buf: &[u8]) -> Result<Self> {
        const W: &str = "FileAllInformation";
        let mut r = Reader::new(buf, W);
        let basic = FileBasicInformation::read(&mut r)?;
        let standard = FileStandardInformation::read(&mut r)?;
        let internal = FileInternalInformation { index_number: r.u64()? };
        let ea = FileEaInformation { ea_size: r.u32()? };
        let access = FileAccessInformation { access_flags: AccessMask::from_bits_retain(r.u32()?) };
        let position = FilePositionInformation { current_byte_offset: r.u64()? };
        let mode = FileModeInformation { mode: r.u32()? };
        let alignment = FileAlignmentInformation { alignment_requirement: r.u32()? };
        let name = FileNameInformation { file_name: read_name(&mut r, W)? };
        Ok(FileAllInformation { basic, standard, internal, ea, access, position, mode, alignment, name })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        self.basic.encode(dst)?;
        self.standard.encode(dst)?;
        self.internal.encode(dst)?;
        self.ea.encode(dst)?;
        self.access.encode(dst)?;
        self.position.encode(dst)?;
        self.mode.encode(dst)?;
        self.alignment.encode(dst)?;
        self.name.encode(dst)
    }
}

/// FileNetworkOpenInformation (56 bytes): what `info()` needs in one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileNetworkOpenInformation {
    /// Creation time.
    pub creation_time: FileTime,
    /// Last access time.
    pub last_access_time: FileTime,
    /// Last write time.
    pub last_write_time: FileTime,
    /// Change time.
    pub change_time: FileTime,
    /// Allocated size.
    pub allocation_size: u64,
    /// File size.
    pub end_of_file: u64,
    /// Attributes.
    pub file_attributes: FileAttributes,
}

impl InfoClass for FileNetworkOpenInformation {
    file_class!(Self, FileInfoClass::NETWORK_OPEN);

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "FileNetworkOpenInformation");
        let [c, a, w, ch] = times(&mut r)?;
        let v = FileNetworkOpenInformation {
            creation_time: c,
            last_access_time: a,
            last_write_time: w,
            change_time: ch,
            allocation_size: r.u64()?,
            end_of_file: r.u64()?,
            file_attributes: FileAttributes::from_bits_retain(r.u32()?),
        };
        r.skip(4)?;
        Ok(v)
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        for t in [self.creation_time, self.last_access_time, self.last_write_time, self.change_time] {
            dst.put_u64_le(t.0);
        }
        dst.put_u64_le(self.allocation_size);
        dst.put_u64_le(self.end_of_file);
        dst.put_u32_le(self.file_attributes.bits());
        dst.put_u32_le(0);
        Ok(())
    }
}

/// FileAttributeTagInformation (8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileAttributeTagInformation {
    /// Attributes.
    pub file_attributes: FileAttributes,
    /// Reparse tag (when `REPARSE_POINT` is set).
    pub reparse_tag: u32,
}

impl InfoClass for FileAttributeTagInformation {
    file_class!(Self, FileInfoClass::ATTRIBUTE_TAG);

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "FileAttributeTagInformation");
        Ok(FileAttributeTagInformation {
            file_attributes: FileAttributes::from_bits_retain(r.u32()?),
            reparse_tag: r.u32()?,
        })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u32_le(self.file_attributes.bits());
        dst.put_u32_le(self.reparse_tag);
        Ok(())
    }
}

/// FileRenameInformation, SMB2 form (`FILE_RENAME_INFORMATION_TYPE_2`,
/// [MS-FSCC] §2.4.37.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileRenameInformation {
    /// Replace an existing target.
    pub replace_if_exists: bool,
    /// Must be 0 over SMB2.
    pub root_directory: u64,
    /// Target path relative to the share root (no leading `\`).
    pub file_name: String,
}

fn decode_rename(buf: &[u8], what: &'static str) -> Result<(u32, u64, String)> {
    let mut r = Reader::new(buf, what);
    let flags = r.u32()?;
    r.skip(4)?;
    let root = r.u64()?;
    let name = read_name(&mut r, what)?;
    Ok((flags, root, name))
}

fn encode_rename(dst: &mut BytesMut, flags: u32, root: u64, name: &str) -> Result<()> {
    dst.put_u32_le(flags);
    dst.put_u32_le(0);
    dst.put_u64_le(root);
    put_name(dst, name)
}

impl InfoClass for FileRenameInformation {
    file_class!(Self, FileInfoClass::RENAME);

    fn decode(buf: &[u8]) -> Result<Self> {
        let (flags, root_directory, file_name) = decode_rename(buf, "FileRenameInformation")?;
        Ok(FileRenameInformation { replace_if_exists: flags & 0xFF != 0, root_directory, file_name })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        encode_rename(dst, u32::from(self.replace_if_exists), self.root_directory, &self.file_name)
    }
}

/// FileLinkInformation (create a hard link); same layout as
/// [`FileRenameInformation`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileLinkInformation {
    /// Replace an existing target.
    pub replace_if_exists: bool,
    /// Must be 0 over SMB2.
    pub root_directory: u64,
    /// Link path relative to the share root.
    pub file_name: String,
}

impl InfoClass for FileLinkInformation {
    file_class!(Self, FileInfoClass::LINK);

    fn decode(buf: &[u8]) -> Result<Self> {
        let (flags, root_directory, file_name) = decode_rename(buf, "FileLinkInformation")?;
        Ok(FileLinkInformation { replace_if_exists: flags & 0xFF != 0, root_directory, file_name })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        encode_rename(dst, u32::from(self.replace_if_exists), self.root_directory, &self.file_name)
    }
}

bitflags! {
    /// Flags of [`FileRenameInformationEx`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct RenameFlags: u32 {
        /// Replace an existing target.
        const REPLACE_IF_EXISTS = 0x0000_0001;
        /// POSIX semantics: replace even if the target is open.
        const POSIX_SEMANTICS = 0x0000_0002;
        /// Suppress PIDL update.
        const SUPPRESS_PIDL_UPDATE = 0x0000_0004;
        /// Suppress storage reserve inheritance.
        const SUPPRESS_STORAGE_RESERVE_INHERITANCE = 0x0000_0008;
        /// No increase of available space.
        const NO_INCREASE_AVAILABLE_SPACE = 0x0000_0010;
        /// No decrease of available space.
        const NO_DECREASE_AVAILABLE_SPACE = 0x0000_0020;
        /// Replace a read-only target.
        const IGNORE_READONLY_ATTRIBUTE = 0x0000_0040;
        /// Force resize of the target stream.
        const FORCE_RESIZE_TARGET_SR = 0x0000_0080;
        /// Force resize of the source stream.
        const FORCE_RESIZE_SOURCE_SR = 0x0000_0100;
        const _ = !0;
    }
}

/// FileRenameInformationEx ([MS-FSCC] §2.4.38).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileRenameInformationEx {
    /// Rename flags.
    pub flags: RenameFlags,
    /// Must be 0 over SMB2.
    pub root_directory: u64,
    /// Target path relative to the share root.
    pub file_name: String,
}

impl InfoClass for FileRenameInformationEx {
    file_class!(Self, FileInfoClass::RENAME_EX);

    fn decode(buf: &[u8]) -> Result<Self> {
        let (flags, root_directory, file_name) = decode_rename(buf, "FileRenameInformationEx")?;
        Ok(FileRenameInformationEx { flags: RenameFlags::from_bits_retain(flags), root_directory, file_name })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        encode_rename(dst, self.flags.bits(), self.root_directory, &self.file_name)
    }
}

/// FileDispositionInformation (1 byte): mark for deletion on close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileDispositionInformation {
    /// Delete when the last handle closes.
    pub delete_pending: bool,
}

impl InfoClass for FileDispositionInformation {
    file_class!(Self, FileInfoClass::DISPOSITION);

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "FileDispositionInformation");
        Ok(FileDispositionInformation { delete_pending: r.u8()? != 0 })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u8(self.delete_pending.into());
        Ok(())
    }
}

bitflags! {
    /// Flags of [`FileDispositionInformationEx`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct DispositionFlags: u32 {
        /// Delete.
        const DELETE = 0x0000_0001;
        /// POSIX semantics: unlink immediately even if other handles are open.
        const POSIX_SEMANTICS = 0x0000_0002;
        /// Force image section check.
        const FORCE_IMAGE_SECTION_CHECK = 0x0000_0004;
        /// Set or clear delete-on-close.
        const ON_CLOSE = 0x0000_0008;
        /// Delete even if read-only.
        const IGNORE_READONLY_ATTRIBUTE = 0x0000_0010;
        const _ = !0;
    }
}

/// FileDispositionInformationEx ([MS-FSCC] §2.4.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileDispositionInformationEx {
    /// Disposition flags (0 = do not delete).
    pub flags: DispositionFlags,
}

impl InfoClass for FileDispositionInformationEx {
    file_class!(Self, FileInfoClass::DISPOSITION_EX);

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "FileDispositionInformationEx");
        Ok(FileDispositionInformationEx { flags: DispositionFlags::from_bits_retain(r.u32()?) })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u32_le(self.flags.bits());
        Ok(())
    }
}

/// One entry of [`FileStreamInformation`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StreamEntry {
    /// Stream name, e.g. `::$DATA` or `:name:$DATA`.
    pub name: String,
    /// Stream size.
    pub size: u64,
    /// Stream allocation size.
    pub allocation_size: u64,
}

/// FileStreamInformation: the alternate data streams of a file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileStreamInformation {
    /// Streams in server order.
    pub entries: Vec<StreamEntry>,
}

impl InfoClass for FileStreamInformation {
    file_class!(Self, FileInfoClass::STREAM);

    fn decode(buf: &[u8]) -> Result<Self> {
        const W: &str = "FileStreamInformation";
        let mut entries = Vec::new();
        let mut pos = 0usize;
        if buf.is_empty() {
            return Ok(FileStreamInformation { entries });
        }
        loop {
            let rest = buf.get(pos..).ok_or(ProtoError::malformed(W, "entry offset out of range"))?;
            let mut r = Reader::new(rest, W);
            let next = r.u32()? as usize;
            let name_len = r.u32()? as usize;
            let size = r.u64()?;
            let allocation_size = r.u64()?;
            let name = decode_utf16le(r.bytes(name_len)?, W)?;
            entries.push(StreamEntry { name, size, allocation_size });
            if next == 0 {
                break;
            }
            if next < 24 {
                return Err(ProtoError::malformed(W, "NextEntryOffset too small"));
            }
            pos += next;
        }
        Ok(FileStreamInformation { entries })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        let base = dst.len();
        for (i, e) in self.entries.iter().enumerate() {
            let start = dst.len();
            dst.put_u32_le(0);
            dst.put_u32_le(len_u32(utf16le_len(&e.name), "stream name too long")?);
            dst.put_u64_le(e.size);
            dst.put_u64_le(e.allocation_size);
            put_utf16le(dst, &e.name);
            if i + 1 < self.entries.len() {
                // Entries are 8-byte aligned relative to the buffer start.
                let rel = dst.len() - base;
                dst.put_bytes(0, crate::wire::padding(rel, 8));
                let next = (dst.len() - start) as u32;
                crate::wire::patch_u32(dst, start, next);
            }
        }
        Ok(())
    }
}

/// FileIdInformation: volume serial number and 128-bit file id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileIdInformation {
    /// Volume serial number.
    pub volume_serial_number: u64,
    /// 128-bit file id.
    pub file_id: [u8; 16],
}

impl InfoClass for FileIdInformation {
    file_class!(Self, FileInfoClass::ID);

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "FileIdInformation");
        Ok(FileIdInformation { volume_serial_number: r.u64()?, file_id: r.array()? })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u64_le(self.volume_serial_number);
        dst.put_slice(&self.file_id);
        Ok(())
    }
}

/// FileFsSizeInformation (24 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileFsSizeInformation {
    /// Total allocation units for the caller.
    pub total_allocation_units: u64,
    /// Free allocation units for the caller.
    pub available_allocation_units: u64,
    /// Sectors per allocation unit.
    pub sectors_per_allocation_unit: u32,
    /// Bytes per sector.
    pub bytes_per_sector: u32,
}

impl FileFsSizeInformation {
    /// Bytes per allocation unit.
    pub fn unit_size(&self) -> u64 {
        u64::from(self.sectors_per_allocation_unit) * u64::from(self.bytes_per_sector)
    }
}

impl InfoClass for FileFsSizeInformation {
    fs_class!(FsInfoClass::SIZE);

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "FileFsSizeInformation");
        Ok(FileFsSizeInformation {
            total_allocation_units: r.u64()?,
            available_allocation_units: r.u64()?,
            sectors_per_allocation_unit: r.u32()?,
            bytes_per_sector: r.u32()?,
        })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u64_le(self.total_allocation_units);
        dst.put_u64_le(self.available_allocation_units);
        dst.put_u32_le(self.sectors_per_allocation_unit);
        dst.put_u32_le(self.bytes_per_sector);
        Ok(())
    }
}

/// FileFsFullSizeInformation (32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileFsFullSizeInformation {
    /// Total allocation units.
    pub total_allocation_units: u64,
    /// Free units available to the caller (quota aware).
    pub caller_available_allocation_units: u64,
    /// Free units on the volume.
    pub actual_available_allocation_units: u64,
    /// Sectors per allocation unit.
    pub sectors_per_allocation_unit: u32,
    /// Bytes per sector.
    pub bytes_per_sector: u32,
}

impl FileFsFullSizeInformation {
    /// Bytes per allocation unit.
    pub fn unit_size(&self) -> u64 {
        u64::from(self.sectors_per_allocation_unit) * u64::from(self.bytes_per_sector)
    }
}

impl InfoClass for FileFsFullSizeInformation {
    fs_class!(FsInfoClass::FULL_SIZE);

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "FileFsFullSizeInformation");
        Ok(FileFsFullSizeInformation {
            total_allocation_units: r.u64()?,
            caller_available_allocation_units: r.u64()?,
            actual_available_allocation_units: r.u64()?,
            sectors_per_allocation_unit: r.u32()?,
            bytes_per_sector: r.u32()?,
        })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u64_le(self.total_allocation_units);
        dst.put_u64_le(self.caller_available_allocation_units);
        dst.put_u64_le(self.actual_available_allocation_units);
        dst.put_u32_le(self.sectors_per_allocation_unit);
        dst.put_u32_le(self.bytes_per_sector);
        Ok(())
    }
}

bitflags! {
    /// `FileSystemAttributes` of [`FileFsAttributeInformation`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct FsAttributes: u32 {
        /// Case-sensitive search.
        const CASE_SENSITIVE_SEARCH = 0x0000_0001;
        /// Case-preserved names.
        const CASE_PRESERVED_NAMES = 0x0000_0002;
        /// Unicode on disk.
        const UNICODE_ON_DISK = 0x0000_0004;
        /// Persistent ACLs.
        const PERSISTENT_ACLS = 0x0000_0008;
        /// File compression.
        const FILE_COMPRESSION = 0x0000_0010;
        /// Volume quotas.
        const VOLUME_QUOTAS = 0x0000_0020;
        /// Sparse files.
        const SUPPORTS_SPARSE_FILES = 0x0000_0040;
        /// Reparse points.
        const SUPPORTS_REPARSE_POINTS = 0x0000_0080;
        /// Remote storage.
        const SUPPORTS_REMOTE_STORAGE = 0x0000_0100;
        /// Compressed volume.
        const VOLUME_IS_COMPRESSED = 0x0000_8000;
        /// Object ids.
        const SUPPORTS_OBJECT_IDS = 0x0001_0000;
        /// Encryption.
        const SUPPORTS_ENCRYPTION = 0x0002_0000;
        /// Named streams.
        const NAMED_STREAMS = 0x0004_0000;
        /// Read-only volume.
        const READ_ONLY_VOLUME = 0x0008_0000;
        /// Hard links.
        const SUPPORTS_HARD_LINKS = 0x0040_0000;
        /// Extended attributes.
        const SUPPORTS_EXTENDED_ATTRIBUTES = 0x0080_0000;
        /// Block refcounting (server-side copy via duplicate extents).
        const SUPPORTS_BLOCK_REFCOUNTING = 0x0800_0000;
        /// POSIX unlink/rename semantics.
        const SUPPORTS_POSIX_UNLINK_RENAME = 0x0000_0400;
        const _ = !0;
    }
}

/// FileFsAttributeInformation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileFsAttributeInformation {
    /// File system attributes.
    pub file_system_attributes: FsAttributes,
    /// Maximum length of a path component, in characters.
    pub maximum_component_name_length: u32,
    /// File system name, e.g. `NTFS`.
    pub file_system_name: String,
}

impl InfoClass for FileFsAttributeInformation {
    fs_class!(FsInfoClass::ATTRIBUTE);

    fn decode(buf: &[u8]) -> Result<Self> {
        const W: &str = "FileFsAttributeInformation";
        let mut r = Reader::new(buf, W);
        Ok(FileFsAttributeInformation {
            file_system_attributes: FsAttributes::from_bits_retain(r.u32()?),
            maximum_component_name_length: r.u32()?,
            file_system_name: read_name(&mut r, W)?,
        })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u32_le(self.file_system_attributes.bits());
        dst.put_u32_le(self.maximum_component_name_length);
        put_name(dst, &self.file_system_name)
    }
}

/// FileFsVolumeInformation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileFsVolumeInformation {
    /// Volume creation time.
    pub volume_creation_time: FileTime,
    /// Volume serial number.
    pub volume_serial_number: u32,
    /// Object ids supported.
    pub supports_objects: bool,
    /// Volume label.
    pub volume_label: String,
}

impl InfoClass for FileFsVolumeInformation {
    fs_class!(FsInfoClass::VOLUME);

    fn decode(buf: &[u8]) -> Result<Self> {
        const W: &str = "FileFsVolumeInformation";
        let mut r = Reader::new(buf, W);
        let volume_creation_time = FileTime(r.u64()?);
        let volume_serial_number = r.u32()?;
        let label_len = r.u32()? as usize;
        let supports_objects = r.u8()? != 0;
        r.skip(1)?;
        let volume_label = decode_utf16le(r.bytes(label_len)?, W)?;
        Ok(FileFsVolumeInformation { volume_creation_time, volume_serial_number, supports_objects, volume_label })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u64_le(self.volume_creation_time.0);
        dst.put_u32_le(self.volume_serial_number);
        dst.put_u32_le(len_u32(utf16le_len(&self.volume_label), "label too long")?);
        dst.put_u8(self.supports_objects.into());
        dst.put_u8(0);
        put_utf16le(dst, &self.volume_label);
        Ok(())
    }
}

/// FileFsDeviceInformation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileFsDeviceInformation {
    /// Device type (`FILE_DEVICE_DISK` = 7, ...).
    pub device_type: u32,
    /// Device characteristics.
    pub characteristics: u32,
}

impl InfoClass for FileFsDeviceInformation {
    fs_class!(FsInfoClass::DEVICE);

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "FileFsDeviceInformation");
        Ok(FileFsDeviceInformation { device_type: r.u32()?, characteristics: r.u32()? })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u32_le(self.device_type);
        dst.put_u32_le(self.characteristics);
        Ok(())
    }
}

/// FileFsSectorSizeInformation (28 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileFsSectorSizeInformation {
    /// Logical bytes per sector.
    pub logical_bytes_per_sector: u32,
    /// Physical bytes per sector for atomicity.
    pub physical_bytes_per_sector_for_atomicity: u32,
    /// Physical bytes per sector for performance.
    pub physical_bytes_per_sector_for_performance: u32,
    /// Effective physical bytes per sector for atomicity.
    pub fs_effective_physical_bytes_per_sector_for_atomicity: u32,
    /// Flags.
    pub flags: u32,
    /// Byte offset for sector alignment.
    pub byte_offset_for_sector_alignment: u32,
    /// Byte offset for partition alignment.
    pub byte_offset_for_partition_alignment: u32,
}

impl InfoClass for FileFsSectorSizeInformation {
    fs_class!(FsInfoClass::SECTOR_SIZE);

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "FileFsSectorSizeInformation");
        Ok(FileFsSectorSizeInformation {
            logical_bytes_per_sector: r.u32()?,
            physical_bytes_per_sector_for_atomicity: r.u32()?,
            physical_bytes_per_sector_for_performance: r.u32()?,
            fs_effective_physical_bytes_per_sector_for_atomicity: r.u32()?,
            flags: r.u32()?,
            byte_offset_for_sector_alignment: r.u32()?,
            byte_offset_for_partition_alignment: r.u32()?,
        })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        for v in [
            self.logical_bytes_per_sector,
            self.physical_bytes_per_sector_for_atomicity,
            self.physical_bytes_per_sector_for_performance,
            self.fs_effective_physical_bytes_per_sector_for_atomicity,
            self.flags,
            self.byte_offset_for_sector_alignment,
            self.byte_offset_for_partition_alignment,
        ] {
            dst.put_u32_le(v);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt<T: InfoClass + PartialEq + std::fmt::Debug>(v: T) {
        let b = v.to_bytes().unwrap();
        assert_eq!(T::decode(&b).unwrap(), v);
        // Truncation never panics.
        for i in 0..b.len() {
            let _ = T::decode(&b[..i]);
        }
    }

    #[test]
    fn round_trips() {
        rt(FileBasicInformation {
            creation_time: FileTime(1),
            last_access_time: FileTime(2),
            last_write_time: FileTime(3),
            change_time: FileTime(4),
            file_attributes: FileAttributes::ARCHIVE,
        });
        rt(FileStandardInformation {
            allocation_size: 4096,
            end_of_file: 10,
            number_of_links: 1,
            delete_pending: false,
            directory: true,
        });
        rt(FileAllInformation {
            name: FileNameInformation { file_name: "\\dir\\file.txt".into() },
            ..Default::default()
        });
        rt(FileNetworkOpenInformation { end_of_file: 5, ..Default::default() });
        rt(FileAttributeTagInformation { file_attributes: FileAttributes::REPARSE_POINT, reparse_tag: 0xA000_000C });
        rt(FileEndOfFileInformation { end_of_file: 1 << 40 });
        rt(FileRenameInformation { replace_if_exists: true, root_directory: 0, file_name: "a\\b".into() });
        rt(FileRenameInformationEx {
            flags: RenameFlags::REPLACE_IF_EXISTS | RenameFlags::POSIX_SEMANTICS,
            root_directory: 0,
            file_name: "x".into(),
        });
        rt(FileDispositionInformation { delete_pending: true });
        rt(FileDispositionInformationEx { flags: DispositionFlags::DELETE | DispositionFlags::POSIX_SEMANTICS });
        rt(FileStreamInformation {
            entries: vec![
                StreamEntry { name: "::$DATA".into(), size: 10, allocation_size: 4096 },
                StreamEntry { name: ":ads:$DATA".into(), size: 3, allocation_size: 8 },
            ],
        });
        rt(FileFsSizeInformation {
            total_allocation_units: 100,
            available_allocation_units: 50,
            sectors_per_allocation_unit: 8,
            bytes_per_sector: 512,
        });
        rt(FileFsFullSizeInformation { total_allocation_units: 7, ..Default::default() });
        rt(FileFsAttributeInformation {
            file_system_attributes: FsAttributes::CASE_PRESERVED_NAMES,
            maximum_component_name_length: 255,
            file_system_name: "NTFS".into(),
        });
        rt(FileFsVolumeInformation { volume_label: "vol".into(), ..Default::default() });
        rt(FileIdInformation { volume_serial_number: 1, file_id: [2; 16] });
        rt(FileLinkInformation { replace_if_exists: false, root_directory: 0, file_name: "l".into() });
        rt(FileFsSectorSizeInformation { logical_bytes_per_sector: 512, ..Default::default() });
    }

    #[test]
    fn rename_layout() {
        let b = FileRenameInformation { replace_if_exists: true, root_directory: 0, file_name: "ab".into() }
            .to_bytes()
            .unwrap();
        assert_eq!(&b[..], &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, b'a', 0, b'b', 0]);
    }

    #[test]
    fn stream_info_rejects_loops() {
        let mut b = BytesMut::new();
        b.put_u32_le(4); // NextEntryOffset smaller than the entry: malformed
        b.put_u32_le(0);
        b.put_u64_le(0);
        b.put_u64_le(0);
        assert!(FileStreamInformation::decode(&b).is_err());
    }
}
