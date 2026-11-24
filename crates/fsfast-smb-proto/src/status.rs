//! NTSTATUS codes ([MS-ERREF] §2.3) and their mapping onto fsfast errors.
//!
//! [`NtStatus`] is a transparent newtype so unknown codes round-trip
//! unchanged. Every constant carries a short description and the
//! [`ErrorKind`] used when the status surfaces as an error. The mapping
//! follows what the reference stacks do (smbprotocol's errno table, the Linux
//! cifs client's `smb2maperror.c`) so Python users see the same exception
//! types they get from `smbclient`.

use std::fmt;

use fsfast_core::{Error, ErrorKind};

/// A Windows NTSTATUS value.
///
/// The two high bits are the severity: success (0), informational (1),
/// warning (2) and error (3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct NtStatus(pub u32);

macro_rules! statuses {
    ($( $name:ident = $val:literal, $kind:ident, $desc:literal; )*) => {
        impl NtStatus {
            $(
                #[doc = concat!("`STATUS_", stringify!($name), "`: ", $desc)]
                pub const $name: NtStatus = NtStatus($val);
            )*
        }

        /// (name, description, kind) for a known status.
        fn lookup(code: u32) -> Option<(&'static str, &'static str, ErrorKind)> {
            match code {
                $( $val => Some((concat!("STATUS_", stringify!($name)), $desc, ErrorKind::$kind)), )*
                _ => None,
            }
        }

        /// Every status constant known to this crate (for tests and tooling).
        pub const ALL_KNOWN: &[NtStatus] = &[$( NtStatus($val), )*];
    };
}

statuses! {
    // --- success / informational -------------------------------------------
    SUCCESS = 0x0000_0000, Other, "the operation completed successfully";
    PENDING = 0x0000_0103, Other, "the operation is in progress (interim response)";
    NOTIFY_CLEANUP = 0x0000_010B, Other, "the handle with a change notify request was closed";
    REPARSE = 0x0000_0104, Other, "the create must be reissued with the reparsed name";
    NOTIFY_ENUM_DIR = 0x0000_010C, Other, "too many changes to report; enumerate the directory";
    OBJECT_NAME_EXISTS = 0x4000_0000, Other, "the object name already existed (informational)";
    // --- warnings ------------------------------------------------------------
    BUFFER_OVERFLOW = 0x8000_0005, Other, "the data was too large to fit into the buffer";
    NO_MORE_FILES = 0x8000_0006, Other, "no more files were found";
    INVALID_EA_NAME = 0x8000_0013, InvalidInput, "the extended attribute name is invalid";
    EA_LIST_INCONSISTENT = 0x8000_0014, InvalidInput, "the extended attribute list is inconsistent";
    STOPPED_ON_SYMLINK = 0x8000_002D, Other, "the create operation stopped after reaching a symbolic link";
    // --- errors --------------------------------------------------------------
    UNSUCCESSFUL = 0xC000_0001, Io, "the requested operation was unsuccessful";
    NOT_IMPLEMENTED = 0xC000_0002, Unsupported, "the requested operation is not implemented";
    INVALID_INFO_CLASS = 0xC000_0003, Unsupported, "the information class is not supported";
    INFO_LENGTH_MISMATCH = 0xC000_0004, InvalidInput, "the buffer length does not match the information class";
    INVALID_HANDLE = 0xC000_0008, Io, "the file handle is invalid";
    INVALID_PARAMETER = 0xC000_000D, InvalidInput, "an invalid parameter was passed";
    INVALID_LOCK_SEQUENCE = 0xC000_001E, InvalidInput, "the lock sequence is invalid";
    NO_SUCH_DEVICE = 0xC000_000E, NotFound, "the device does not exist";
    NO_SUCH_FILE = 0xC000_000F, NotFound, "the file does not exist";
    INVALID_DEVICE_REQUEST = 0xC000_0010, Unsupported, "the request is not valid for this device";
    END_OF_FILE = 0xC000_0011, Io, "the end of the file was reached";
    MORE_PROCESSING_REQUIRED = 0xC000_0016, Other, "more processing is required (authentication continues)";
    NO_MEMORY = 0xC000_0017, Throttled, "the server is out of memory";
    ACCESS_DENIED = 0xC000_0022, PermissionDenied, "access is denied";
    BUFFER_TOO_SMALL = 0xC000_0023, InvalidInput, "the buffer is too small for the result";
    OBJECT_TYPE_MISMATCH = 0xC000_0024, InvalidInput, "the object type does not match";
    DISK_CORRUPT_ERROR = 0xC000_0032, Io, "the disk structure is corrupt";
    OBJECT_NAME_INVALID = 0xC000_0033, InvalidInput, "the object name is invalid";
    OBJECT_NAME_NOT_FOUND = 0xC000_0034, NotFound, "the object name is not found";
    OBJECT_NAME_COLLISION = 0xC000_0035, AlreadyExists, "the object name already exists";
    PORT_DISCONNECTED = 0xC000_0037, ConnectionFailed, "the port is disconnected";
    OBJECT_PATH_INVALID = 0xC000_0039, NotADirectory, "a path component is not a directory";
    OBJECT_PATH_NOT_FOUND = 0xC000_003A, NotFound, "the path does not exist";
    OBJECT_PATH_SYNTAX_BAD = 0xC000_003B, InvalidInput, "the path syntax is invalid";
    DATA_ERROR = 0xC000_003E, Io, "a data error occurred";
    SHARING_VIOLATION = 0xC000_0043, PermissionDenied, "the file is in use by another open (sharing violation)";
    QUOTA_EXCEEDED = 0xC000_0044, Io, "the quota was exceeded";
    EAS_NOT_SUPPORTED = 0xC000_004F, Unsupported, "extended attributes are not supported";
    EA_TOO_LARGE = 0xC000_0050, InvalidInput, "the extended attributes are too large";
    NONEXISTENT_EA_ENTRY = 0xC000_0051, NotFound, "the extended attribute does not exist";
    NO_EAS_ON_FILE = 0xC000_0052, NotFound, "the file has no extended attributes";
    EA_CORRUPT_ERROR = 0xC000_0053, Io, "the extended attributes are corrupt";
    FILE_LOCK_CONFLICT = 0xC000_0054, PermissionDenied, "a byte-range lock conflicts with the request";
    LOCK_NOT_GRANTED = 0xC000_0055, PermissionDenied, "the byte-range lock was not granted";
    DELETE_PENDING = 0xC000_0056, NotFound, "the file is pending deletion";
    INVALID_OWNER = 0xC000_005A, InvalidInput, "the owner SID is invalid";
    NO_LOGON_SERVERS = 0xC000_005E, PermissionDenied, "no logon servers are available";
    NO_SUCH_LOGON_SESSION = 0xC000_005F, PermissionDenied, "the logon session does not exist";
    PRIVILEGE_NOT_HELD = 0xC000_0061, PermissionDenied, "a required privilege is not held";
    NO_SUCH_USER = 0xC000_0064, PermissionDenied, "the user does not exist";
    WRONG_PASSWORD = 0xC000_006A, PermissionDenied, "the password is wrong";
    PASSWORD_RESTRICTION = 0xC000_006C, PermissionDenied, "the password does not meet the policy";
    LOGON_FAILURE = 0xC000_006D, PermissionDenied, "unknown user name or bad password";
    ACCOUNT_RESTRICTION = 0xC000_006E, PermissionDenied, "account restrictions prevent logon";
    INVALID_LOGON_HOURS = 0xC000_006F, PermissionDenied, "logon is not allowed at this time";
    INVALID_WORKSTATION = 0xC000_0070, PermissionDenied, "logon is not allowed from this workstation";
    PASSWORD_EXPIRED = 0xC000_0071, PermissionDenied, "the password has expired";
    ACCOUNT_DISABLED = 0xC000_0072, PermissionDenied, "the account is disabled";
    NONE_MAPPED = 0xC000_0073, InvalidInput, "no mapping between account names and SIDs";
    INVALID_SECURITY_DESCR = 0xC000_0079, InvalidInput, "the security descriptor is invalid";
    RANGE_NOT_LOCKED = 0xC000_007E, InvalidInput, "the range is not locked";
    DISK_FULL = 0xC000_007F, Io, "the disk is full";
    FILE_INVALID = 0xC000_0098, Io, "the file is no longer valid";
    INSUFFICIENT_RESOURCES = 0xC000_009A, Throttled, "insufficient server resources";
    MEDIA_WRITE_PROTECTED = 0xC000_00A2, PermissionDenied, "the media is write protected";
    DEVICE_NOT_READY = 0xC000_00A3, Io, "the device is not ready";
    BAD_IMPERSONATION_LEVEL = 0xC000_00A5, PermissionDenied, "the impersonation level is not sufficient";
    PIPE_NOT_AVAILABLE = 0xC000_00AC, Throttled, "no pipe instance is available";
    INVALID_PIPE_STATE = 0xC000_00AD, Io, "the pipe is in an invalid state";
    PIPE_BUSY = 0xC000_00AE, Throttled, "all pipe instances are busy";
    PIPE_DISCONNECTED = 0xC000_00B0, ConnectionFailed, "the pipe is disconnected";
    PIPE_CLOSING = 0xC000_00B1, ConnectionFailed, "the pipe is closing";
    IO_TIMEOUT = 0xC000_00B5, Timeout, "the operation timed out";
    FILE_FORCED_CLOSED = 0xC000_00B6, Io, "the file was forcibly closed";
    FILE_IS_A_DIRECTORY = 0xC000_00BA, IsADirectory, "the file is a directory";
    NOT_SUPPORTED = 0xC000_00BB, Unsupported, "the request is not supported";
    DUPLICATE_NAME = 0xC000_00BD, AlreadyExists, "a duplicate name exists on the network";
    BAD_NETWORK_PATH = 0xC000_00BE, NotFound, "the network path was not found";
    NETWORK_BUSY = 0xC000_00BF, Throttled, "the network is busy";
    INVALID_NETWORK_RESPONSE = 0xC000_00C3, Protocol, "the network response was invalid";
    UNEXPECTED_NETWORK_ERROR = 0xC000_00C4, ConnectionFailed, "an unexpected network error occurred";
    NETWORK_NAME_DELETED = 0xC000_00C9, ConnectionFailed, "the tree connect was deleted";
    NETWORK_ACCESS_DENIED = 0xC000_00CA, PermissionDenied, "network access is denied";
    BAD_DEVICE_TYPE = 0xC000_00CB, InvalidInput, "the device type is wrong";
    BAD_NETWORK_NAME = 0xC000_00CC, NotFound, "the share name does not exist";
    TOO_MANY_SESSIONS = 0xC000_00CE, Throttled, "too many sessions";
    REQUEST_NOT_ACCEPTED = 0xC000_00D0, Throttled, "the server cannot accept more requests";
    NOT_SAME_DEVICE = 0xC000_00D4, Unsupported, "the target is on a different device";
    FILE_RENAMED = 0xC000_00D5, NotFound, "the file was renamed";
    INVALID_SERVER_STATE = 0xC000_00DC, Io, "the server is in an invalid state";
    NO_SUCH_DOMAIN = 0xC000_00DF, PermissionDenied, "the domain does not exist";
    INTERNAL_ERROR = 0xC000_00E5, Io, "an internal server error occurred";
    UNEXPECTED_IO_ERROR = 0xC000_00E9, Io, "an unexpected I/O error occurred";
    OPLOCK_NOT_GRANTED = 0xC000_00E2, Other, "the oplock was not granted";
    INVALID_OPLOCK_PROTOCOL = 0xC000_00E3, Protocol, "invalid oplock acknowledgment";
    PIPE_EMPTY = 0xC000_00D9, Io, "the pipe is empty";
    INVALID_USER_BUFFER = 0xC000_00E8, InvalidInput, "the user buffer is invalid";
    DIRECTORY_NOT_EMPTY = 0xC000_0101, DirectoryNotEmpty, "the directory is not empty";
    FILE_CORRUPT_ERROR = 0xC000_0102, Io, "the file is corrupt";
    NOT_A_DIRECTORY = 0xC000_0103, NotADirectory, "the file is not a directory";
    NAME_TOO_LONG = 0xC000_0106, InvalidInput, "the name is too long";
    TOO_MANY_OPENED_FILES = 0xC000_011F, Throttled, "too many open files";
    CANCELLED = 0xC000_0120, Cancelled, "the request was cancelled";
    CANNOT_DELETE = 0xC000_0121, PermissionDenied, "the file cannot be deleted";
    INVALID_COMPUTER_NAME = 0xC000_0122, InvalidInput, "the computer name is invalid";
    FILE_DELETED = 0xC000_0123, NotFound, "the file was deleted";
    FILE_CLOSED = 0xC000_0128, Io, "the file handle is closed";
    TIME_DIFFERENCE_AT_DC = 0xC000_0133, PermissionDenied, "the clock differs too much from the domain controller";
    REMOTE_DISCONNECT = 0xC000_013C, ConnectionFailed, "the remote side disconnected";
    INVALID_LEVEL = 0xC000_0148, Unsupported, "the information level is not supported";
    PIPE_BROKEN = 0xC000_014B, ConnectionFailed, "the pipe is broken";
    LOGON_TYPE_NOT_GRANTED = 0xC000_015B, PermissionDenied, "the logon type is not granted";
    INVALID_DEVICE_STATE = 0xC000_0184, Io, "the device is in an invalid state";
    IO_DEVICE_ERROR = 0xC000_0185, Io, "an I/O device error occurred";
    TRUSTED_RELATIONSHIP_FAILURE = 0xC000_018D, PermissionDenied, "the trust relationship failed";
    NETLOGON_NOT_STARTED = 0xC000_0192, PermissionDenied, "the netlogon service is not started";
    ACCOUNT_EXPIRED = 0xC000_0193, PermissionDenied, "the account has expired";
    FS_DRIVER_REQUIRED = 0xC000_019C, Unsupported, "a file system driver is required";
    USER_SESSION_DELETED = 0xC000_0203, ConnectionFailed, "the session was deleted";
    INSUFF_SERVER_RESOURCES = 0xC000_0205, Throttled, "insufficient server resources";
    CONNECTION_DISCONNECTED = 0xC000_020C, ConnectionFailed, "the connection was disconnected";
    CONNECTION_RESET = 0xC000_020D, ConnectionFailed, "the connection was reset";
    PASSWORD_MUST_CHANGE = 0xC000_0224, PermissionDenied, "the password must be changed";
    NOT_FOUND = 0xC000_0225, NotFound, "the object was not found";
    DUPLICATE_OBJECTID = 0xC000_022A, AlreadyExists, "the object id already exists";
    OBJECTID_EXISTS = 0xC000_022B, AlreadyExists, "an object id is already set";
    RETRY = 0xC000_022D, Throttled, "retry the operation";
    ACCOUNT_LOCKED_OUT = 0xC000_0234, PermissionDenied, "the account is locked out";
    CONNECTION_REFUSED = 0xC000_0236, ConnectionFailed, "the connection was refused";
    GRACEFUL_DISCONNECT = 0xC000_0237, ConnectionFailed, "the connection was gracefully closed";
    NETWORK_UNREACHABLE = 0xC000_023C, ConnectionFailed, "the network is unreachable";
    HOST_UNREACHABLE = 0xC000_023D, ConnectionFailed, "the host is unreachable";
    REQUEST_ABORTED = 0xC000_0240, Cancelled, "the request was aborted";
    CONNECTION_ABORTED = 0xC000_0241, ConnectionFailed, "the connection was aborted";
    PATH_NOT_COVERED = 0xC000_0257, Other, "the path is not covered by this server (DFS referral needed)";
    DFS_UNAVAILABLE = 0xC000_026D, Unsupported, "DFS is unavailable on this server";
    TOO_MANY_LINKS = 0xC000_0265, Io, "too many links to the file";
    VOLUME_DISMOUNTED = 0xC000_026E, Io, "the volume was dismounted";
    NOT_A_REPARSE_POINT = 0xC000_0275, InvalidInput, "the file is not a reparse point";
    IO_REPARSE_TAG_NOT_HANDLED = 0xC000_0279, Unsupported, "the reparse tag is not handled";
    DIRECTORY_IS_A_REPARSE_POINT = 0xC000_0281, InvalidInput, "the directory is a reparse point";
    ENCRYPTION_FAILED = 0xC000_028A, Protocol, "encryption failed";
    DECRYPTION_FAILED = 0xC000_028B, Protocol, "decryption failed";
    NETWORK_SESSION_EXPIRED = 0xC000_035C, ConnectionFailed, "the session expired; re-authenticate";
    FILE_SYSTEM_LIMITATION = 0xC000_0427, Io, "a file system limitation was hit";
    REQUEST_OUT_OF_SEQUENCE = 0xC000_042A, Protocol, "the request is out of sequence";
    SERVER_UNAVAILABLE = 0xC000_0466, ConnectionFailed, "the server is unavailable";
    FILE_NOT_AVAILABLE = 0xC000_0467, Throttled, "the file is temporarily unavailable";
    FILE_TOO_LARGE = 0xC000_0904, Io, "the file is too large";
    VIRUS_INFECTED = 0xC000_0906, PermissionDenied, "the file contains a virus";
    INVALID_SIGNATURE = 0xC000_A000, Protocol, "the message signature is invalid";
    HASH_NOT_SUPPORTED = 0xC000_A100, Unsupported, "hash generation is not supported";
    HASH_NOT_PRESENT = 0xC000_A101, NotFound, "the hash is not present";
    SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP = 0xC05D_0000, Protocol, "no common preauth integrity hash algorithm";
    SMB_BAD_CLUSTER_DIALECT = 0xC05D_0001, Protocol, "the dialect is not supported by the cluster";
    SMB_GUEST_LOGON_BLOCKED = 0xC05D_0002, PermissionDenied, "guest logons are blocked";
    SMB_NO_SIGNING_ALGORITHM_OVERLAP = 0xC05D_0003, Protocol, "no common signing algorithm";
}

impl NtStatus {
    /// Severity bits (0 = success, 1 = informational, 2 = warning, 3 = error).
    #[inline]
    pub const fn severity(self) -> u8 {
        (self.0 >> 30) as u8
    }

    /// `true` for success and informational codes.
    #[inline]
    pub const fn is_success(self) -> bool {
        self.severity() <= 1
    }

    /// `true` for warning codes (e.g. `STATUS_BUFFER_OVERFLOW`).
    #[inline]
    pub const fn is_warning(self) -> bool {
        self.severity() == 2
    }

    /// `true` for error codes.
    #[inline]
    pub const fn is_error(self) -> bool {
        self.severity() == 3
    }

    /// The symbolic name (`STATUS_...`), if known.
    pub fn name(self) -> Option<&'static str> {
        lookup(self.0).map(|(n, _, _)| n)
    }

    /// A short human description, if known.
    pub fn description(self) -> Option<&'static str> {
        lookup(self.0).map(|(_, d, _)| d)
    }

    /// The fsfast [`ErrorKind`] for this status. Unknown error codes map to
    /// [`ErrorKind::Io`], unknown non-error codes to [`ErrorKind::Other`].
    pub fn kind(self) -> ErrorKind {
        match lookup(self.0) {
            Some((_, _, k)) => k,
            None if self.is_error() => ErrorKind::Io,
            None => ErrorKind::Other,
        }
    }

    /// Build an fsfast error for this status, with the NTSTATUS attached as
    /// [`Detail::NtStatus`](fsfast_core::Detail::NtStatus) and the path set
    /// when known.
    pub fn to_error(self, path: Option<&str>) -> Error {
        let message = match lookup(self.0) {
            Some((name, desc, _)) => format!("{name}: {desc}"),
            None => format!("NTSTATUS 0x{:08X}", self.0),
        };
        let mut e = crate::error::with_status(Error::new(self.kind(), message), self);
        if let Some(p) = path {
            e = e.with_path(p);
        }
        e
    }

    /// Shorthand for `to_error(Some(path))`.
    pub fn to_error_with_path(self, path: &str) -> Error {
        self.to_error(Some(path))
    }
}

impl From<u32> for NtStatus {
    fn from(v: u32) -> Self {
        NtStatus(v)
    }
}

impl From<NtStatus> for u32 {
    fn from(s: NtStatus) -> Self {
        s.0
    }
}

impl fmt::Debug for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(n) => write!(f, "{n}(0x{:08X})", self.0),
            None => write!(f, "NtStatus(0x{:08X})", self.0),
        }
    }
}

impl fmt::Display for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(n) => write!(f, "{n} (0x{:08X})", self.0),
            None => write!(f, "NTSTATUS 0x{:08X}", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsfast_core::Detail;

    #[test]
    fn severity() {
        assert!(NtStatus::SUCCESS.is_success());
        assert!(NtStatus::PENDING.is_success());
        assert!(NtStatus::BUFFER_OVERFLOW.is_warning());
        assert!(NtStatus::ACCESS_DENIED.is_error());
        assert!(!NtStatus::NO_MORE_FILES.is_error());
    }

    #[test]
    fn mapping() {
        use ErrorKind::*;
        let cases = [
            (NtStatus::OBJECT_NAME_NOT_FOUND, NotFound),
            (NtStatus::OBJECT_PATH_NOT_FOUND, NotFound),
            (NtStatus::NO_SUCH_FILE, NotFound),
            (NtStatus::ACCESS_DENIED, PermissionDenied),
            (NtStatus::LOGON_FAILURE, PermissionDenied),
            (NtStatus::OBJECT_NAME_COLLISION, AlreadyExists),
            (NtStatus::FILE_IS_A_DIRECTORY, IsADirectory),
            (NtStatus::NOT_A_DIRECTORY, NotADirectory),
            (NtStatus::DIRECTORY_NOT_EMPTY, DirectoryNotEmpty),
            (NtStatus::NOT_SUPPORTED, Unsupported),
            (NtStatus::INVALID_DEVICE_REQUEST, Unsupported),
            (NtStatus::IO_TIMEOUT, Timeout),
            (NtStatus::NETWORK_NAME_DELETED, ConnectionFailed),
            (NtStatus::USER_SESSION_DELETED, ConnectionFailed),
            (NtStatus::CONNECTION_RESET, ConnectionFailed),
            (NtStatus::CONNECTION_DISCONNECTED, ConnectionFailed),
            (NtStatus::CONNECTION_ABORTED, ConnectionFailed),
            (NtStatus::CONNECTION_REFUSED, ConnectionFailed),
            (NtStatus::INSUFFICIENT_RESOURCES, Throttled),
            (NtStatus::REQUEST_NOT_ACCEPTED, Throttled),
            (NtStatus::CANCELLED, Cancelled),
            (NtStatus(0xC0FF_FFFF), Io),
            (NtStatus(0x4000_1234), Other),
        ];
        for (s, k) in cases {
            assert_eq!(s.kind(), k, "{s}");
        }
    }

    #[test]
    fn to_error_attaches_detail_and_path() {
        let e = NtStatus::OBJECT_NAME_NOT_FOUND.to_error(Some("/share/a.txt"));
        assert_eq!(e.kind(), ErrorKind::NotFound);
        assert_eq!(e.path(), Some("/share/a.txt"));
        assert_eq!(e.details(), &[Detail::NtStatus(0xC000_0034)]);
        assert!(e.to_string().contains("STATUS_OBJECT_NAME_NOT_FOUND"));
        assert!(e.to_string().contains("0xC0000034"));
        let e = NtStatus(0xC0AB_CDEF).to_error(None);
        assert!(e.to_string().contains("0xC0ABCDEF"));
    }

    #[test]
    fn names_unique_and_formatting() {
        let mut seen = std::collections::HashSet::new();
        for s in ALL_KNOWN {
            assert!(seen.insert(s.0), "duplicate {s}");
            assert!(s.name().unwrap().starts_with("STATUS_"));
        }
        assert_eq!(
            format!("{:?}", NtStatus::ACCESS_DENIED),
            "STATUS_ACCESS_DENIED(0xC0000022)"
        );
        assert_eq!(
            NtStatus::ACCESS_DENIED.to_string(),
            "STATUS_ACCESS_DENIED (0xC0000022)"
        );
    }
}
