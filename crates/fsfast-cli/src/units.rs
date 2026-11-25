//! Sizes, durations, timestamps and JSON conversions for output.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fsfast_core::{Error, FileInfo, Result, Value};

/// Parse a byte size: a number with an optional unit. `KiB`/`MiB`/`GiB`/
/// `TiB` and the bare `K`/`M`/`G`/`T` (as in `dd`/`fio`) are binary;
/// `KB`/`MB`/`GB`/`TB` are decimal; `B` or no unit means bytes. Fractions
/// are allowed (`1.5GiB`). Case-insensitive.
pub fn parse_size(s: &str) -> Result<u64> {
    let t = s.trim();
    let split = t
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '_'))
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    let num: String = num.chars().filter(|&c| c != '_').collect();
    let n: f64 = num
        .parse()
        .map_err(|_| Error::invalid_input(format!("invalid size {s:?}")))?;
    let mult: f64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kib" => 1024.0,
        "m" | "mib" => 1024.0 * 1024.0,
        "g" | "gib" => 1024.0 * 1024.0 * 1024.0,
        "t" | "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        "kb" => 1e3,
        "mb" => 1e6,
        "gb" => 1e9,
        "tb" => 1e12,
        _ => {
            return Err(Error::invalid_input(format!(
                "invalid size unit in {s:?} (use B, K/KiB, M/MiB, G/GiB, T/TiB, KB, MB, GB, TB)"
            )));
        }
    };
    let v = n * mult;
    if !v.is_finite() || v < 0.0 || v > u64::MAX as f64 {
        return Err(Error::invalid_input(format!("size out of range: {s:?}")));
    }
    if v.fract() != 0.0 {
        return Err(Error::invalid_input(format!(
            "size {s:?} is not a whole number of bytes"
        )));
    }
    Ok(v as u64)
}

/// `1.5 MiB`-style binary formatting.
pub fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", UNITS[i])
}

/// Human duration: `0.4 µs`, `850 µs`, `12.3 ms`, `4.56 s`.
pub fn format_duration(d: Duration) -> String {
    let us = d.as_secs_f64() * 1e6;
    if us < 10.0 {
        format!("{us:.1} µs")
    } else if us < 1000.0 {
        format!("{us:.0} µs")
    } else if us < 1e6 {
        format!("{:.2} ms", us / 1e3)
    } else {
        format!("{:.3} s", us / 1e6)
    }
}

/// RFC 3339 UTC timestamp with microseconds (`2026-11-25T10:00:00.000000Z`).
pub fn rfc3339(t: SystemTime) -> String {
    let (neg, d) = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (false, d),
        Err(e) => (true, e.duration()),
    };
    let mut secs = d.as_secs() as i64;
    let mut micros = d.subsec_micros() as i64;
    if neg {
        secs = -secs;
        if micros > 0 {
            secs -= 1;
            micros = 1_000_000 - micros;
        }
    }
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, dd) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{dd:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to (y, m, d).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A core [`Value`] as JSON (timestamps become RFC 3339 strings, bytes a
/// lower-case hex string).
pub fn value_to_json(v: &Value) -> serde_json::Value {
    use serde_json::Value as J;
    match v {
        Value::Null => J::Null,
        Value::Bool(b) => J::Bool(*b),
        Value::Int(i) => J::from(*i),
        Value::Float(f) => serde_json::Number::from_f64(*f).map_or(J::Null, J::Number),
        Value::Str(s) => J::String(s.clone()),
        Value::Bytes(b) => J::String(b.iter().map(|x| format!("{x:02x}")).collect()),
        Value::Time(t) => J::String(rfc3339(*t)),
        Value::List(l) => J::Array(l.iter().map(value_to_json).collect()),
        Value::Map(m) => J::Object(
            m.iter()
                .map(|(k, v)| (k.clone(), value_to_json(v)))
                .collect(),
        ),
    }
}

/// The fsspec `info()` dict of `info` as JSON: `name`, `size`, `type`, then
/// the backend-native `extra` keys (which may override `name`, as SMB
/// directories do), plus fsfast's `modified`/`created`/`version` under
/// distinct keys when not already present.
pub fn info_to_json(info: &FileInfo) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert("name".into(), info.name.clone().into());
    m.insert("size".into(), info.size.into());
    m.insert("type".into(), info.file_type.as_fsspec_str().into());
    for (k, v) in &info.extra {
        m.insert(k.clone(), value_to_json(v));
    }
    let mut put = |k: &str, v: Option<serde_json::Value>| {
        if let Some(v) = v
            && !m.contains_key(k)
        {
            m.insert(k.to_owned(), v);
        }
    };
    put("fsf_modified", info.modified.map(|t| rfc3339(t).into()));
    put("fsf_created", info.created.map(|t| rfc3339(t).into()));
    put("fsf_version", info.version.clone().map(Into::into));
    serde_json::Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("0").unwrap(), 0);
        assert_eq!(parse_size("512").unwrap(), 512);
        assert_eq!(parse_size("512B").unwrap(), 512);
        assert_eq!(parse_size("4k").unwrap(), 4096);
        assert_eq!(parse_size("4KiB").unwrap(), 4096);
        assert_eq!(parse_size("4KB").unwrap(), 4000);
        assert_eq!(parse_size("64M").unwrap(), 64 << 20);
        assert_eq!(parse_size("1.5GiB").unwrap(), 3 << 29);
        assert_eq!(parse_size("2 GB").unwrap(), 2_000_000_000);
        assert_eq!(parse_size("1T").unwrap(), 1 << 40);
        assert_eq!(parse_size("1_000").unwrap(), 1000);
        assert!(parse_size("").is_err());
        assert!(parse_size("abc").is_err());
        assert!(parse_size("4X").is_err());
        assert!(parse_size("1.5").is_err());
        assert!(parse_size("-1").is_err());
        assert!(parse_size("99999999999T").is_err());
    }

    #[test]
    fn formatting() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(64 << 20), "64.0 MiB");
        assert_eq!(format_duration(Duration::from_micros(850)), "850 µs");
        assert_eq!(format_duration(Duration::from_nanos(400)), "0.4 µs");
        assert_eq!(format_duration(Duration::from_micros(12_300)), "12.30 ms");
        assert_eq!(format_duration(Duration::from_millis(4560)), "4.560 s");
    }

    #[test]
    fn timestamps() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000000Z");
        let t = UNIX_EPOCH + Duration::from_micros(1_764_064_800_123_456);
        assert_eq!(rfc3339(t), "2025-11-25T10:00:00.123456Z");
        // Leap day and pre-epoch.
        let t = UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(rfc3339(t), "2000-02-29T00:00:00.000000Z");
        let t = UNIX_EPOCH - Duration::from_micros(1_500_000);
        assert_eq!(rfc3339(t), "1969-12-31T23:59:58.500000Z");
    }

    #[test]
    fn info_json() {
        let mut i = FileInfo::file("b/k", 3);
        i.extra.insert("ETag".into(), Value::Str("\"x\"".into()));
        i.extra
            .insert("LastModified".into(), Value::Time(UNIX_EPOCH));
        i.version = Some("v1".into());
        let j = info_to_json(&i);
        assert_eq!(j["name"], "b/k");
        assert_eq!(j["size"], 3);
        assert_eq!(j["type"], "file");
        assert_eq!(j["ETag"], "\"x\"");
        assert_eq!(j["LastModified"], "1970-01-01T00:00:00.000000Z");
        assert_eq!(j["fsf_version"], "v1");
        assert!(j.get("fsf_modified").is_none());
        let mut d = FileInfo::directory("/share/d");
        d.extra
            .insert("name".into(), Value::Str("/share/d/".into()));
        assert_eq!(info_to_json(&d)["name"], "/share/d/");
        assert_eq!(
            value_to_json(&Value::Bytes(vec![0, 255])),
            serde_json::json!("00ff")
        );
    }
}
