//! Timestamps: RFC 1123 (`x-ms-date`, listing and header dates) and the
//! ISO 8601 `YYYY-MM-DDThh:mm:ssZ` form of SAS start/expiry times.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// `Wed, 25 Nov 2026 06:28:54 GMT`.
pub fn rfc1123(t: SystemTime) -> String {
    httpdate::fmt_http_date(t)
}

/// Parse an RFC 1123 date (the service's `Last-Modified`, `Creation-Time`,
/// ...). `None` for anything else.
pub fn parse_rfc1123(s: &str) -> Option<SystemTime> {
    httpdate::parse_http_date(s.trim()).ok()
}

/// Days since 1970-01-01 → (year, month, day) (proleptic Gregorian; Howard
/// Hinnant's `civil_from_days`).
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

/// (year, month, day) → days since 1970-01-01.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `2026-11-25T06:30:34Z` (whole seconds, UTC), as azure-storage-blob's
/// `_to_utc_datetime` formats SAS times.
pub fn iso8601(t: SystemTime) -> String {
    let secs = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs_f64().ceil() as i64),
    };
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

/// Parse `YYYY-MM-DD[T ]hh:mm:ss[.frac][Z|±hh:mm]` (no offset means UTC).
pub fn parse_iso8601(s: &str) -> Option<SystemTime> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        if !t.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        t.parse().ok()
    };
    if b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut rest = &s[19..];
    let mut nanos = 0u32;
    if let Some(f) = rest.strip_prefix('.') {
        let n = f.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return None;
        }
        let digits = &f[..n.min(9)];
        nanos = digits.parse::<u32>().ok()? * 10u32.pow(9 - digits.len() as u32);
        rest = &f[n..];
    }
    let offset: i64 = match rest {
        "" | "Z" | "z" => 0,
        o if (o.starts_with('+') || o.starts_with('-')) && o.len() == 6 && &o[3..4] == ":" => {
            let hh: i64 = o[1..3].parse().ok()?;
            let mm: i64 = o[4..6].parse().ok()?;
            let v = hh * 3600 + mm * 60;
            if o.starts_with('-') { -v } else { v }
        }
        _ => return None,
    };
    let days = days_from_civil(y, mo as u32, d as u32);
    let secs = days * 86_400 + h * 3600 + mi * 60 + sec - offset;
    if secs < 0 {
        return None;
    }
    Some(UNIX_EPOCH + Duration::new(secs as u64, nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        let t = UNIX_EPOCH + Duration::from_secs(1_795_588_234);
        assert_eq!(iso8601(t), "2026-11-25T06:30:34Z");
        assert_eq!(rfc1123(t), "Wed, 25 Nov 2026 06:30:34 GMT");
        assert_eq!(parse_rfc1123("Wed, 25 Nov 2026 06:30:34 GMT"), Some(t));
        assert_eq!(iso8601(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(
            iso8601(UNIX_EPOCH + Duration::from_secs(951_782_400)),
            "2000-02-29T00:00:00Z"
        );
    }

    #[test]
    fn parses_iso() {
        let t = UNIX_EPOCH + Duration::from_secs(1_795_588_234);
        assert_eq!(parse_iso8601("2026-11-25T06:30:34Z"), Some(t));
        assert_eq!(parse_iso8601("2026-11-25 06:30:34"), Some(t));
        assert_eq!(parse_iso8601("2026-11-25T08:30:34+02:00"), Some(t));
        assert_eq!(
            parse_iso8601("2026-11-25T06:30:34.5000000Z"),
            Some(t + Duration::from_millis(500))
        );
        assert_eq!(parse_iso8601("2026-13-25T06:30:34Z"), None);
        assert_eq!(parse_iso8601("garbage"), None);
    }

    proptest::proptest! {
        #[test]
        fn iso_roundtrip(secs in 0u64..10_000_000_000) {
            let t = UNIX_EPOCH + Duration::from_secs(secs);
            proptest::prop_assert_eq!(parse_iso8601(&iso8601(t)), Some(t));
        }
    }
}
