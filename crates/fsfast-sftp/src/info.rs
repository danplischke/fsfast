//! `FileInfo` records with fsspec's `SFTPFileSystem._decode_stat` keys.
//!
//! fsspec builds `{"name", "size", "type", "uid", "gid", "time", "mtime"}`:
//! `type` is `"directory"` for `S_ISDIR`, `"link"` for `S_ISLNK` (only
//! visible in `ls`, whose READDIR attributes are `lstat` results) and
//! `"file"` otherwise; `time` is the access time and `mtime` the
//! modification time as timezone-aware UTC datetimes. `name`, `size` and
//! `type` are [`FileInfo`]'s own fields; `uid`, `gid`, `time` and `mtime`
//! go to [`FileInfo::extra`] (Python `None` when the server omitted them).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fsfast_core::{FileInfo, FileType, Value};

use crate::proto::{FileAttributes, Kind};

/// Order of the keys in fsspec's `info()` dict.
pub const INFO_KEYS: &[&str] = &["name", "size", "type", "uid", "gid", "time", "mtime"];

fn time(secs: Option<u32>) -> Option<SystemTime> {
    secs.map(|s| UNIX_EPOCH + Duration::from_secs(u64::from(s)))
}

/// The fsfast file type for SFTP attributes.
pub fn file_type(a: &FileAttributes) -> FileType {
    match a.kind() {
        Kind::Directory => FileType::Directory,
        Kind::Symlink => FileType::Symlink,
        Kind::File => FileType::File,
    }
}

/// Build the record for `name` (already in canonical form).
pub fn file_info(name: String, a: &FileAttributes) -> FileInfo {
    let mtime = time(a.mtime());
    let atime = time(a.atime());
    let opt_int = |v: Option<u32>| v.map_or(Value::Null, |v| Value::Int(i64::from(v)));
    let opt_time = |v: Option<SystemTime>| v.map_or(Value::Null, Value::Time);
    let mut info = FileInfo {
        name,
        size: a.size.unwrap_or(0),
        file_type: file_type(a),
        modified: mtime,
        // fsspec's SFTPFileSystem.created() returns the modification time
        // (SFTP v3 has no creation time).
        created: mtime,
        version: None,
        extra: Default::default(),
    };
    info.set("uid", opt_int(a.uid()));
    info.set("gid", opt_int(a.gid()));
    info.set("time", opt_time(atime));
    info.set("mtime", opt_time(mtime));
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_stat_keys() {
        let a = FileAttributes {
            size: Some(5),
            uid_gid: Some((1, 2)),
            permissions: Some(0o120_777),
            times: Some((10, 20)),
            extended: vec![],
        };
        let i = file_info("/x/l".into(), &a);
        assert_eq!(i.file_type, FileType::Symlink);
        assert_eq!(i.file_type.as_fsspec_str(), "link");
        assert_eq!(i.size, 5);
        assert_eq!(i.extra["uid"], Value::Int(1));
        assert_eq!(i.extra["gid"], Value::Int(2));
        assert_eq!(i.extra["time"], Value::Time(UNIX_EPOCH + Duration::from_secs(10)));
        assert_eq!(i.extra["mtime"], Value::Time(UNIX_EPOCH + Duration::from_secs(20)));
        assert_eq!(i.modified, Some(UNIX_EPOCH + Duration::from_secs(20)));
        assert_eq!(i.created, i.modified);
        let bare = file_info("f".into(), &FileAttributes::default());
        assert_eq!(bare.file_type, FileType::File);
        assert_eq!(bare.extra["uid"], Value::Null);
        assert_eq!(bare.extra["mtime"], Value::Null);
        assert_eq!(bare.extra.len(), INFO_KEYS.len() - 3);
    }
}
