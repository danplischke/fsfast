//! [MS-FSCC] file system structures used by SMB2: FILETIME, attribute and
//! access-mask constants, information classes and directory entries.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitflags::bitflags;

pub mod dir;
pub mod info;

pub use dir::*;
pub use info::*;

/// 100-ns intervals between 1601-01-01 and 1970-01-01.
const UNIX_EPOCH_FILETIME: u64 = 116_444_736_000_000_000;
const TICKS_PER_SEC: u64 = 10_000_000;

/// A Windows FILETIME: 100-nanosecond intervals since 1601-01-01 UTC.
///
/// SET_INFO gives a few values special meaning: `0` leaves a timestamp
/// unchanged, `-1` suspends automatic updates for the handle and `-2`
/// resumes them.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct FileTime(pub u64);

impl FileTime {
    /// Zero ("not set" / "do not change" in SET_INFO).
    pub const ZERO: FileTime = FileTime(0);
    /// `-1`: stop updating this timestamp for the handle (SET_INFO).
    pub const SUSPEND_UPDATES: FileTime = FileTime(u64::MAX);
    /// `-2`: resume updating this timestamp (SET_INFO).
    pub const RESUME_UPDATES: FileTime = FileTime(u64::MAX - 1);

    /// Convert to [`SystemTime`]. Returns `None` for zero and for the
    /// negative (special) values.
    pub fn to_system_time(self) -> Option<SystemTime> {
        if self.0 == 0 || self.0 >= 1 << 63 {
            return None;
        }
        if self.0 >= UNIX_EPOCH_FILETIME {
            let d = self.0 - UNIX_EPOCH_FILETIME;
            UNIX_EPOCH.checked_add(ticks_to_duration(d))
        } else {
            let d = UNIX_EPOCH_FILETIME - self.0;
            UNIX_EPOCH.checked_sub(ticks_to_duration(d))
        }
    }

    /// Convert from [`SystemTime`], truncating to 100 ns and saturating at
    /// the representable range (times before 1601 become 1601-01-01).
    pub fn from_system_time(t: SystemTime) -> FileTime {
        match t.duration_since(UNIX_EPOCH) {
            Ok(d) => FileTime(UNIX_EPOCH_FILETIME.saturating_add(duration_to_ticks(d)).min(i64::MAX as u64)),
            Err(e) => FileTime(UNIX_EPOCH_FILETIME.saturating_sub(duration_to_ticks(e.duration())).max(1)),
        }
    }

    /// The current time.
    pub fn now() -> FileTime {
        FileTime::from_system_time(SystemTime::now())
    }

    /// Seconds since the Unix epoch as a float (what `smbclient`'s
    /// `stat_result` exposes as `st_mtime`).
    pub fn to_unix_f64(self) -> Option<f64> {
        if self.0 == 0 || self.0 >= 1 << 63 {
            return None;
        }
        Some((self.0 as f64 - UNIX_EPOCH_FILETIME as f64) / TICKS_PER_SEC as f64)
    }
}

fn ticks_to_duration(ticks: u64) -> Duration {
    Duration::new(ticks / TICKS_PER_SEC, ((ticks % TICKS_PER_SEC) * 100) as u32)
}

fn duration_to_ticks(d: Duration) -> u64 {
    d.as_secs()
        .saturating_mul(TICKS_PER_SEC)
        .saturating_add(u64::from(d.subsec_nanos() / 100))
}

impl fmt::Debug for FileTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_unix_f64() {
            Some(s) => write!(f, "FileTime({} = unix {s:.7})", self.0),
            None => write!(f, "FileTime({})", self.0),
        }
    }
}

impl From<SystemTime> for FileTime {
    fn from(t: SystemTime) -> Self {
        FileTime::from_system_time(t)
    }
}

bitflags! {
    /// `FILE_ATTRIBUTE_*` ([MS-FSCC] §2.6).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct FileAttributes: u32 {
        /// Read-only.
        const READONLY = 0x0000_0001;
        /// Hidden.
        const HIDDEN = 0x0000_0002;
        /// System.
        const SYSTEM = 0x0000_0004;
        /// Directory.
        const DIRECTORY = 0x0000_0010;
        /// Archive.
        const ARCHIVE = 0x0000_0020;
        /// Normal (only valid alone).
        const NORMAL = 0x0000_0080;
        /// Temporary.
        const TEMPORARY = 0x0000_0100;
        /// Sparse file.
        const SPARSE_FILE = 0x0000_0200;
        /// Reparse point (symlink, junction, ...).
        const REPARSE_POINT = 0x0000_0400;
        /// Compressed.
        const COMPRESSED = 0x0000_0800;
        /// Offline.
        const OFFLINE = 0x0000_1000;
        /// Not content indexed.
        const NOT_CONTENT_INDEXED = 0x0000_2000;
        /// Encrypted.
        const ENCRYPTED = 0x0000_4000;
        /// Integrity stream.
        const INTEGRITY_STREAM = 0x0000_8000;
        /// No scrub data.
        const NO_SCRUB_DATA = 0x0002_0000;
        /// Recall on open.
        const RECALL_ON_OPEN = 0x0004_0000;
        /// Pinned.
        const PINNED = 0x0008_0000;
        /// Unpinned.
        const UNPINNED = 0x0010_0000;
        /// Recall on data access.
        const RECALL_ON_DATA_ACCESS = 0x0040_0000;
        const _ = !0;
    }
}

bitflags! {
    /// File/directory access mask ([MS-SMB2] §2.2.13.1).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct AccessMask: u32 {
        /// Read data (files) / list directory (directories).
        const FILE_READ_DATA = 0x0000_0001;
        /// Write data / add file.
        const FILE_WRITE_DATA = 0x0000_0002;
        /// Append data / add subdirectory.
        const FILE_APPEND_DATA = 0x0000_0004;
        /// Read extended attributes.
        const FILE_READ_EA = 0x0000_0008;
        /// Write extended attributes.
        const FILE_WRITE_EA = 0x0000_0010;
        /// Execute / traverse.
        const FILE_EXECUTE = 0x0000_0020;
        /// Delete children (directories).
        const FILE_DELETE_CHILD = 0x0000_0040;
        /// Read attributes.
        const FILE_READ_ATTRIBUTES = 0x0000_0080;
        /// Write attributes.
        const FILE_WRITE_ATTRIBUTES = 0x0000_0100;
        /// Delete.
        const DELETE = 0x0001_0000;
        /// Read the security descriptor.
        const READ_CONTROL = 0x0002_0000;
        /// Change the DACL.
        const WRITE_DAC = 0x0004_0000;
        /// Change the owner.
        const WRITE_OWNER = 0x0008_0000;
        /// Synchronize.
        const SYNCHRONIZE = 0x0010_0000;
        /// Access the SACL.
        const ACCESS_SYSTEM_SECURITY = 0x0100_0000;
        /// Grant the maximum allowed access.
        const MAXIMUM_ALLOWED = 0x0200_0000;
        /// Generic all.
        const GENERIC_ALL = 0x1000_0000;
        /// Generic execute.
        const GENERIC_EXECUTE = 0x2000_0000;
        /// Generic write.
        const GENERIC_WRITE = 0x4000_0000;
        /// Generic read.
        const GENERIC_READ = 0x8000_0000;
        /// Directory alias of `FILE_READ_DATA`.
        const FILE_LIST_DIRECTORY = 0x0000_0001;
        /// Directory alias of `FILE_WRITE_DATA`.
        const FILE_ADD_FILE = 0x0000_0002;
        /// Directory alias of `FILE_APPEND_DATA`.
        const FILE_ADD_SUBDIRECTORY = 0x0000_0004;
        /// Directory alias of `FILE_EXECUTE`.
        const FILE_TRAVERSE = 0x0000_0020;
        const _ = !0;
    }
}

bitflags! {
    /// `ShareAccess` of CREATE.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct ShareAccess: u32 {
        /// Allow concurrent readers.
        const READ = 0x0000_0001;
        /// Allow concurrent writers.
        const WRITE = 0x0000_0002;
        /// Allow concurrent delete/rename.
        const DELETE = 0x0000_0004;
        const _ = !0;
    }
}

bitflags! {
    /// `CreateOptions` of CREATE.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct CreateOptions: u32 {
        /// The target must be a directory.
        const DIRECTORY_FILE = 0x0000_0001;
        /// Write-through.
        const WRITE_THROUGH = 0x0000_0002;
        /// Sequential access only.
        const SEQUENTIAL_ONLY = 0x0000_0004;
        /// No intermediate buffering.
        const NO_INTERMEDIATE_BUFFERING = 0x0000_0008;
        /// Synchronous I/O, alertable.
        const SYNCHRONOUS_IO_ALERT = 0x0000_0010;
        /// Synchronous I/O, non-alertable.
        const SYNCHRONOUS_IO_NONALERT = 0x0000_0020;
        /// The target must not be a directory.
        const NON_DIRECTORY_FILE = 0x0000_0040;
        /// Complete if oplocked.
        const COMPLETE_IF_OPLOCKED = 0x0000_0100;
        /// No EA knowledge.
        const NO_EA_KNOWLEDGE = 0x0000_0200;
        /// Open a remote instance.
        const OPEN_REMOTE_INSTANCE = 0x0000_0400;
        /// Random access.
        const RANDOM_ACCESS = 0x0000_0800;
        /// Delete the file when the last handle closes.
        const DELETE_ON_CLOSE = 0x0000_1000;
        /// Open by file id.
        const OPEN_BY_FILE_ID = 0x0000_2000;
        /// Open for backup intent.
        const OPEN_FOR_BACKUP_INTENT = 0x0000_4000;
        /// No compression.
        const NO_COMPRESSION = 0x0000_8000;
        /// Open requiring an oplock.
        const OPEN_REQUIRING_OPLOCK = 0x0001_0000;
        /// Disallow exclusive.
        const DISALLOW_EXCLUSIVE = 0x0002_0000;
        /// Reserve oplock filter.
        const RESERVE_OPFILTER = 0x0010_0000;
        /// Open the reparse point itself instead of following it.
        const OPEN_REPARSE_POINT = 0x0020_0000;
        /// Do not recall offline data.
        const OPEN_NO_RECALL = 0x0040_0000;
        /// Open for free-space query.
        const OPEN_FOR_FREE_SPACE_QUERY = 0x0080_0000;
        const _ = !0;
    }
}

/// `CreateDisposition` of CREATE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct CreateDisposition(pub u32);

impl CreateDisposition {
    /// Replace if it exists, create otherwise.
    pub const SUPERSEDE: Self = Self(0);
    /// Open; fail if it does not exist.
    pub const OPEN: Self = Self(1);
    /// Create; fail if it exists.
    pub const CREATE: Self = Self(2);
    /// Open if it exists, create otherwise.
    pub const OPEN_IF: Self = Self(3);
    /// Open and truncate; fail if it does not exist.
    pub const OVERWRITE: Self = Self(4);
    /// Open and truncate if it exists, create otherwise.
    pub const OVERWRITE_IF: Self = Self(5);
}

/// `CreateAction` returned by CREATE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct CreateAction(pub u32);

impl CreateAction {
    /// An existing file was superseded.
    pub const SUPERSEDED: Self = Self(0);
    /// An existing file was opened.
    pub const OPENED: Self = Self(1);
    /// A new file was created.
    pub const CREATED: Self = Self(2);
    /// An existing file was overwritten.
    pub const OVERWRITTEN: Self = Self(3);
}

/// `ImpersonationLevel` of CREATE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct ImpersonationLevel(pub u32);

impl ImpersonationLevel {
    /// Anonymous.
    pub const ANONYMOUS: Self = Self(0);
    /// Identification.
    pub const IDENTIFICATION: Self = Self(1);
    /// Impersonation (what clients normally send).
    pub const IMPERSONATION: Self = Self(2);
    /// Delegate.
    pub const DELEGATE: Self = Self(3);
}

/// Oplock level of CREATE / OPLOCK_BREAK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct OplockLevel(pub u8);

impl OplockLevel {
    /// No oplock.
    pub const NONE: Self = Self(0x00);
    /// Level II (shared read caching).
    pub const LEVEL_II: Self = Self(0x01);
    /// Exclusive.
    pub const EXCLUSIVE: Self = Self(0x08);
    /// Batch.
    pub const BATCH: Self = Self(0x09);
    /// Lease (the lease create context carries the state).
    pub const LEASE: Self = Self(0xFF);
}

/// `InfoType` of QUERY_INFO / SET_INFO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct InfoType(pub u8);

impl InfoType {
    /// File information.
    pub const FILE: Self = Self(0x01);
    /// File system information.
    pub const FILESYSTEM: Self = Self(0x02);
    /// Security descriptor.
    pub const SECURITY: Self = Self(0x03);
    /// Quota information.
    pub const QUOTA: Self = Self(0x04);
}

/// File information class numbers ([MS-FSCC] §2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct FileInfoClass(pub u8);

impl FileInfoClass {
    /// FileDirectoryInformation.
    pub const DIRECTORY: Self = Self(1);
    /// FileFullDirectoryInformation.
    pub const FULL_DIRECTORY: Self = Self(2);
    /// FileBothDirectoryInformation.
    pub const BOTH_DIRECTORY: Self = Self(3);
    /// FileBasicInformation.
    pub const BASIC: Self = Self(4);
    /// FileStandardInformation.
    pub const STANDARD: Self = Self(5);
    /// FileInternalInformation.
    pub const INTERNAL: Self = Self(6);
    /// FileEaInformation.
    pub const EA: Self = Self(7);
    /// FileAccessInformation.
    pub const ACCESS: Self = Self(8);
    /// FileNameInformation.
    pub const NAME: Self = Self(9);
    /// FileRenameInformation.
    pub const RENAME: Self = Self(10);
    /// FileLinkInformation.
    pub const LINK: Self = Self(11);
    /// FileNamesInformation.
    pub const NAMES: Self = Self(12);
    /// FileDispositionInformation.
    pub const DISPOSITION: Self = Self(13);
    /// FilePositionInformation.
    pub const POSITION: Self = Self(14);
    /// FileFullEaInformation.
    pub const FULL_EA: Self = Self(15);
    /// FileModeInformation.
    pub const MODE: Self = Self(16);
    /// FileAlignmentInformation.
    pub const ALIGNMENT: Self = Self(17);
    /// FileAllInformation.
    pub const ALL: Self = Self(18);
    /// FileAllocationInformation.
    pub const ALLOCATION: Self = Self(19);
    /// FileEndOfFileInformation.
    pub const END_OF_FILE: Self = Self(20);
    /// FileAlternateNameInformation.
    pub const ALTERNATE_NAME: Self = Self(21);
    /// FileStreamInformation.
    pub const STREAM: Self = Self(22);
    /// FilePipeInformation.
    pub const PIPE: Self = Self(23);
    /// FileCompressionInformation.
    pub const COMPRESSION: Self = Self(28);
    /// FileNetworkOpenInformation.
    pub const NETWORK_OPEN: Self = Self(34);
    /// FileAttributeTagInformation.
    pub const ATTRIBUTE_TAG: Self = Self(35);
    /// FileIdBothDirectoryInformation.
    pub const ID_BOTH_DIRECTORY: Self = Self(37);
    /// FileIdFullDirectoryInformation.
    pub const ID_FULL_DIRECTORY: Self = Self(38);
    /// FileValidDataLengthInformation.
    pub const VALID_DATA_LENGTH: Self = Self(39);
    /// FileShortNameInformation.
    pub const SHORT_NAME: Self = Self(40);
    /// FileNormalizedNameInformation.
    pub const NORMALIZED_NAME: Self = Self(48);
    /// FileIdInformation.
    pub const ID: Self = Self(59);
    /// FileIdExtdDirectoryInformation.
    pub const ID_EXTD_DIRECTORY: Self = Self(60);
    /// FileDispositionInformationEx.
    pub const DISPOSITION_EX: Self = Self(64);
    /// FileRenameInformationEx.
    pub const RENAME_EX: Self = Self(65);
}

/// File system information class numbers ([MS-FSCC] §2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct FsInfoClass(pub u8);

impl FsInfoClass {
    /// FileFsVolumeInformation.
    pub const VOLUME: Self = Self(1);
    /// FileFsLabelInformation.
    pub const LABEL: Self = Self(2);
    /// FileFsSizeInformation.
    pub const SIZE: Self = Self(3);
    /// FileFsDeviceInformation.
    pub const DEVICE: Self = Self(4);
    /// FileFsAttributeInformation.
    pub const ATTRIBUTE: Self = Self(5);
    /// FileFsControlInformation.
    pub const CONTROL: Self = Self(6);
    /// FileFsFullSizeInformation.
    pub const FULL_SIZE: Self = Self(7);
    /// FileFsObjectIdInformation.
    pub const OBJECT_ID: Self = Self(8);
    /// FileFsSectorSizeInformation.
    pub const SECTOR_SIZE: Self = Self(11);
}

/// Reparse tags ([MS-FSCC] §2.1.2.1) clients commonly meet.
pub mod reparse_tag {
    /// Mount point / junction.
    pub const MOUNT_POINT: u32 = 0xA000_0003;
    /// Symbolic link.
    pub const SYMLINK: u32 = 0xA000_000C;
    /// DFS.
    pub const DFS: u32 = 0x8000_000A;
    /// NFS-style special files (Samba POSIX extensions).
    pub const NFS: u32 = 0x8000_0014;
    /// Linux/WSL symlink.
    pub const LX_SYMLINK: u32 = 0xA000_001D;
}

/// `AdditionalInformation` bits for security descriptor queries.
pub mod security_information {
    /// Owner SID.
    pub const OWNER: u32 = 0x0000_0001;
    /// Group SID.
    pub const GROUP: u32 = 0x0000_0002;
    /// DACL.
    pub const DACL: u32 = 0x0000_0004;
    /// SACL.
    pub const SACL: u32 = 0x0000_0008;
    /// Label.
    pub const LABEL: u32 = 0x0000_0010;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_epoch() {
        let ft = FileTime(UNIX_EPOCH_FILETIME);
        assert_eq!(ft.to_system_time(), Some(UNIX_EPOCH));
        assert_eq!(FileTime::from_system_time(UNIX_EPOCH), ft);
        assert_eq!(FileTime::ZERO.to_system_time(), None);
        assert_eq!(FileTime::SUSPEND_UPDATES.to_system_time(), None);
    }

    #[test]
    fn filetime_round_trip_precision() {
        let t = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_700);
        let ft = FileTime::from_system_time(t);
        assert_eq!(ft.to_system_time(), Some(t));
        // Sub-100ns precision is truncated.
        let t2 = t + Duration::from_nanos(99);
        assert_eq!(FileTime::from_system_time(t2), ft);
        // Before 1970.
        let old = UNIX_EPOCH - Duration::new(86_400 * 365, 500);
        let ft = FileTime::from_system_time(old);
        assert_eq!(ft.to_system_time(), Some(old));
        assert!((FileTime(UNIX_EPOCH_FILETIME + 15_000_000).to_unix_f64().unwrap() - 1.5).abs() < 1e-9);
    }
}
