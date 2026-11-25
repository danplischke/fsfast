//! Turning JSON API resources into `FileInfo` entries with exactly the keys
//! gcsfs puts in its `info()` / `ls()` / `find()` dicts.
//!
//! * Objects (gcsfs `_process_object`): every field of the object resource
//!   as returned by the server (`kind`, `id`, `selfLink`, `mediaLink`,
//!   `bucket`, `generation`, `metageneration`, `contentType`,
//!   `storageClass`, `md5Hash`, `crc32c`, `etag`, `timeCreated`, `updated`,
//!   `metadata`, ...), with `name` = `bucket/name`, `size` as an integer,
//!   `type` = `"file"`, plus `mtime` (from `updated`) and `ctime` (from
//!   `timeCreated`) as datetimes. `generation` and `metageneration` stay
//!   strings, as in the resource.
//! * Implied directories from `ls`/`info`: `{bucket, name, size: 0,
//!   storageClass: "DIRECTORY", type: "directory"}`.
//! * Directories derived by `find(withdirs=True)`: `{Key, Size: 0, name,
//!   StorageClass: "DIRECTORY", type: "directory", size: 0}` (gcsfs uses
//!   these s3fs-style keys there).
//! * Buckets: the bucket resource with `size: 0`, `type: "directory"`;
//!   `ls("")` names them `bucket/` (trailing slash), `info(bucket)` names
//!   them `bucket`.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fsfast_core::{Error, FileInfo, FileType, Result, Value};
use serde_json::{Map, Value as Json};

/// A JSON value as an fsfast [`Value`] (objects become maps, arrays lists).
pub fn json_to_value(v: Json) -> Value {
    match v {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(b),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else if let Some(u) = n.as_u64() {
                Value::from(u)
            } else {
                Value::Float(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        Json::String(s) => Value::Str(s),
        Json::Array(a) => Value::List(a.into_iter().map(json_to_value).collect()),
        Json::Object(m) => Value::Map(m.into_iter().map(|(k, v)| (k, json_to_value(v))).collect()),
    }
}

/// Parse an RFC 3339 UTC timestamp as GCS writes them
/// (`2026-11-24T19:16:54.877746Z`), truncated to microseconds like gcsfs's
/// `_parse_timestamp` (Python datetimes). Offsets other than `Z` are
/// accepted too.
pub fn parse_timestamp(s: &str) -> Option<SystemTime> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        if t.bytes().all(|c| c.is_ascii_digit()) {
            t.parse().ok()
        } else {
            None
        }
    };
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    if second > 60 {
        return None;
    }
    let mut i = 19;
    let mut micros: i64 = 0;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let frac = &s[start..i];
        if frac.is_empty() {
            return None;
        }
        // Keep microseconds (pad or truncate to 6 digits).
        let mut digits: String = frac.chars().take(6).collect();
        while digits.len() < 6 {
            digits.push('0');
        }
        micros = digits.parse().ok()?;
    }
    let offset_secs: i64 = match &s[i..] {
        "Z" | "z" => 0,
        tz if tz.len() == 6
            && matches!(tz.as_bytes()[0], b'+' | b'-')
            && tz.as_bytes()[3] == b':' =>
        {
            let h: i64 = tz[1..3].parse().ok()?;
            let m: i64 = tz[4..6].parse().ok()?;
            let v = h * 3600 + m * 60;
            if tz.starts_with('-') { -v } else { v }
        }
        _ => return None,
    };
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset_secs;
    let total_micros = secs.checked_mul(1_000_000)?.checked_add(micros)?;
    if total_micros >= 0 {
        Some(UNIX_EPOCH + Duration::from_micros(total_micros as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_micros(total_micros.unsigned_abs()))
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// algorithm).
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The `size` of a resource: a decimal string in the JSON API (a number is
/// accepted too). Missing means 0, as in gcsfs.
fn resource_size(m: &Map<String, Json>) -> Result<u64> {
    match m.get("size") {
        None | Some(Json::Null) => Ok(0),
        Some(Json::String(s)) => s
            .trim()
            .parse()
            .map_err(|_| Error::protocol(format!("invalid object size {s:?}"))),
        Some(Json::Number(n)) => n
            .as_u64()
            .ok_or_else(|| Error::protocol(format!("invalid object size {n}"))),
        Some(other) => Err(Error::protocol(format!("invalid object size {other}"))),
    }
}

/// gcsfs `_process_object`: the object resource `obj` of `bucket` as a file
/// entry (see the module docs for the keys).
pub fn object_info(bucket: &str, obj: Map<String, Json>) -> Result<FileInfo> {
    let mut obj = obj;
    let key = match obj.remove("name") {
        Some(Json::String(s)) => s,
        _ => return Err(Error::protocol("object resource without a name")),
    };
    let size = resource_size(&obj)?;
    obj.remove("size");
    // gcsfs overwrites any `type` field with "file".
    obj.remove("type");
    let updated = obj
        .get("updated")
        .and_then(Json::as_str)
        .and_then(parse_timestamp);
    let created = obj
        .get("timeCreated")
        .and_then(Json::as_str)
        .and_then(parse_timestamp);
    let version = obj.get("generation").and_then(|g| match g {
        Json::String(s) => Some(s.clone()),
        Json::Number(n) => Some(n.to_string()),
        _ => None,
    });
    let has_gen = obj.contains_key("generation") || obj.contains_key("metageneration");
    let mut extra: BTreeMap<String, Value> = obj
        .into_iter()
        .map(|(k, v)| (k, json_to_value(v)))
        .collect();
    if updated.is_some() {
        extra.insert("mtime".into(), Value::from(updated));
    } else if extra.contains_key("updated") {
        // gcsfs would fail to parse it; report it as missing instead.
        extra.insert("mtime".into(), Value::Null);
    }
    if created.is_some() {
        extra.insert("ctime".into(), Value::from(created));
    } else if extra.contains_key("timeCreated") {
        extra.insert("ctime".into(), Value::Null);
    }
    if has_gen {
        extra.entry("generation".into()).or_insert(Value::Null);
        extra.entry("metageneration".into()).or_insert(Value::Null);
    }
    Ok(FileInfo {
        // Joined with one '/' even for names starting with '/', so the name
        // splits back into the same bucket and key (gcsfs's posixpath.join
        // would drop the bucket for those).
        name: format!("{bucket}/{key}"),
        size,
        file_type: FileType::File,
        modified: updated,
        created,
        version,
        extra,
    })
}

/// Whether an entry is a directory marker: a zero-size object whose name
/// ends with `/` (gcsfs `_is_directory_marker`).
pub fn is_directory_marker(info: &FileInfo) -> bool {
    info.is_file() && info.size == 0 && info.name.ends_with('/')
}

/// An implied directory as gcsfs's `ls`/`info` report it.
pub fn pseudo_dir(bucket: &str, name: String) -> FileInfo {
    let mut i = FileInfo::directory(name);
    i.set("bucket", bucket);
    i.set("storageClass", "DIRECTORY");
    i
}

/// A directory as gcsfs's `find(withdirs=True)` reports it.
pub fn find_dir(name: String, key: &str) -> FileInfo {
    let mut i = FileInfo::directory(name);
    i.set("Key", key);
    i.set("Size", 0u64);
    i.set("StorageClass", "DIRECTORY");
    i
}

/// A bucket resource as a directory entry named `name`.
pub fn bucket_info(name: String, res: Map<String, Json>) -> FileInfo {
    let mut res = res;
    res.remove("name");
    res.remove("size");
    res.remove("type");
    let updated = res
        .get("updated")
        .and_then(Json::as_str)
        .and_then(parse_timestamp);
    let created = res
        .get("timeCreated")
        .and_then(Json::as_str)
        .and_then(parse_timestamp);
    let version = res
        .get("metageneration")
        .and_then(Json::as_str)
        .map(str::to_owned);
    FileInfo {
        name,
        size: 0,
        file_type: FileType::Directory,
        modified: updated,
        created,
        version,
        extra: res
            .into_iter()
            .map(|(k, v)| (k, json_to_value(v)))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn timestamps() {
        let t = parse_timestamp("2026-11-24T19:16:54.877746Z").unwrap();
        let d = t.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(d.as_secs(), 1_795_547_814);
        assert_eq!(d.subsec_micros(), 877_746);
        let t = parse_timestamp("1970-01-01T00:00:00Z").unwrap();
        assert_eq!(t, UNIX_EPOCH);
        let t = parse_timestamp("2026-11-24T19:16:54.8Z").unwrap();
        assert_eq!(
            t.duration_since(UNIX_EPOCH).unwrap().subsec_micros(),
            800_000
        );
        // Nanoseconds are truncated to microseconds.
        let t = parse_timestamp("2026-11-24T19:16:54.123456789Z").unwrap();
        assert_eq!(
            t.duration_since(UNIX_EPOCH).unwrap().subsec_nanos(),
            123_456_000
        );
        let t = parse_timestamp("2000-03-01T01:00:00+01:00").unwrap();
        assert_eq!(t, parse_timestamp("2000-03-01T00:00:00Z").unwrap());
        assert_eq!(
            parse_timestamp("1969-12-31T23:59:59Z").unwrap(),
            UNIX_EPOCH - Duration::from_secs(1)
        );
        for bad in [
            "",
            "2026-11-24",
            "2026-13-01T00:00:00Z",
            "2026-11-24T19:16:54",
            "x026-11-24T19:16:54Z",
            "2026-11-24T19:16:54.Z",
        ] {
            assert!(parse_timestamp(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn days() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
    }

    #[test]
    fn object_entry() {
        let res = json!({
            "kind": "storage#object",
            "name": "a/b.txt",
            "bucket": "bkt",
            "size": "11",
            "generation": "1795547814877753",
            "metageneration": "1",
            "timeCreated": "2026-11-24T19:16:54.877746Z",
            "updated": "2026-11-24T19:16:54.877752Z",
            "metadata": {"k": "v"},
        });
        let Json::Object(m) = res else { unreachable!() };
        let i = object_info("bkt", m).unwrap();
        assert_eq!(i.name, "bkt/a/b.txt");
        assert_eq!(i.size, 11);
        assert!(i.is_file());
        assert_eq!(i.version.as_deref(), Some("1795547814877753"));
        assert_eq!(i.extra["generation"], Value::from("1795547814877753"));
        assert_eq!(i.extra["metageneration"], Value::from("1"));
        assert!(matches!(i.extra["mtime"], Value::Time(_)));
        assert!(matches!(i.extra["ctime"], Value::Time(_)));
        assert_eq!(i.extra["kind"], Value::from("storage#object"));
        assert!(matches!(&i.extra["metadata"], Value::Map(m) if m["k"] == Value::from("v")));
        assert!(!i.extra.contains_key("name") && !i.extra.contains_key("size"));
        assert!(!is_directory_marker(&i));
        let Json::Object(m) = json!({"name": "d/", "size": "0"}) else {
            unreachable!()
        };
        let marker = object_info("bkt", m).unwrap();
        assert!(is_directory_marker(&marker));
        let Json::Object(m) = json!({"size": "1"}) else {
            unreachable!()
        };
        assert!(object_info("b", m).is_err());
        let Json::Object(m) = json!({"name": "x", "size": "nan"}) else {
            unreachable!()
        };
        assert!(object_info("b", m).is_err());
    }

    #[test]
    fn json_values() {
        assert_eq!(json_to_value(json!(1)), Value::Int(1));
        assert_eq!(json_to_value(json!(u64::MAX)), Value::Int(i64::MAX));
        assert_eq!(json_to_value(json!(1.5)), Value::Float(1.5));
        assert_eq!(
            json_to_value(json!([true, null])),
            Value::List(vec![Value::Bool(true), Value::Null])
        );
    }

    #[test]
    fn directories() {
        let d = pseudo_dir("b", "b/x".into());
        assert!(d.is_dir());
        assert_eq!(d.extra["storageClass"], Value::from("DIRECTORY"));
        let f = find_dir("b/x/y".into(), "x/y");
        assert_eq!(f.extra["Key"], Value::from("x/y"));
        assert_eq!(f.extra["Size"], Value::Int(0));
        let Json::Object(m) = json!({"name": "b", "kind": "storage#bucket", "metageneration": "1"})
        else {
            unreachable!()
        };
        let b = bucket_info("b/".into(), m);
        assert_eq!(b.name, "b/");
        assert!(b.is_dir());
        assert_eq!(b.extra["kind"], Value::from("storage#bucket"));
    }
}
