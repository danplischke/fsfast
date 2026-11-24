//! Percent-encoding, base64 and date helpers shared by the signer, the URL
//! builder and the response parsers.

use std::borrow::Cow;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;

const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Whether `b` is an RFC 3986 unreserved character (`A-Za-z0-9-_.~`), the
/// only bytes SigV4 leaves unencoded.
#[inline]
fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

/// Percent-encode `s` the way botocore does (`quote(s, safe=...)` with the
/// unreserved set plus optionally `/`): every other byte of the UTF-8
/// encoding becomes `%XX` with upper-case hex digits.
///
/// With `keep_slash` this is botocore's encoding of object keys in URL paths
/// (`percent_encode(key, safe="/~")`); without it, the encoding of query
/// parameter names and values (`safe="-_.~"`).
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    let bytes = s.as_bytes();
    // Fast path: nothing to encode (the common case for keys).
    if bytes
        .iter()
        .all(|&b| unreserved(b) || (keep_slash && b == b'/'))
    {
        return s.to_owned();
    }
    let mut out = String::with_capacity(bytes.len() + bytes.len() / 2);
    for &b in bytes {
        if unreserved(b) || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 15) as usize] as char);
        }
    }
    out
}

/// Decode `application/x-www-form-urlencoded` text (`+` is a space, `%XX`
/// an escaped byte), as S3 uses for keys in listings requested with
/// `encoding-type=url` (botocore decodes them with `unquote_plus`).
/// Invalid escapes are kept literally; invalid UTF-8 is replaced.
pub fn url_decode_plus(s: &str) -> Cow<'_, str> {
    if !s.bytes().any(|b| b == b'%' || b == b'+') {
        return Cow::Borrowed(s);
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                match (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push(h << 4 | l);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    match String::from_utf8(out) {
        Ok(s) => Cow::Owned(s),
        Err(e) => Cow::Owned(String::from_utf8_lossy(e.as_bytes()).into_owned()),
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Standard base64 with padding.
pub fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Lower-case hex.
pub fn hex_lower(data: &[u8]) -> String {
    hex::encode(data)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The civil date of a day count since 1970-01-01 (`civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// UTC calendar fields of `t`: (year, month, day, hour, minute, second).
pub fn utc_fields(t: SystemTime) -> (i64, u32, u32, u32, u32, u32) {
    let secs = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs_f64().ceil() as i64),
    };
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400) as u32;
    let (y, m, d) = civil_from_days(days);
    (y, m, d, rem / 3600, rem / 60 % 60, rem % 60)
}

/// SigV4 timestamp `YYYYMMDDTHHMMSSZ`.
pub fn amz_date(t: SystemTime) -> String {
    let (y, mo, d, h, mi, s) = utc_fields(t);
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

/// ISO 8601 `YYYY-MM-DDTHH:MM:SSZ` (S3 timestamps sent in query strings or
/// headers with the `iso8601` format).
pub fn iso8601(t: SystemTime) -> String {
    let (y, mo, d, h, mi, s) = utc_fields(t);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Parse an ISO 8601 / RFC 3339 timestamp as S3, STS, ECS and IMDS write
/// them: `2026-11-24T12:34:56Z`, with optional fractional seconds and an
/// optional `±HH:MM` offset instead of `Z`.
pub fn parse_iso8601(s: &str) -> Option<SystemTime> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let part = s.get(r)?;
        if part.bytes().all(|c| c.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut i = 19;
    let mut nanos = 0u32;
    if i < b.len() && b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return None;
        }
        let frac = &s[start..i.min(start + 9)];
        let mut n: u32 = frac.parse().ok()?;
        for _ in frac.len()..9 {
            n *= 10;
        }
        nanos = n;
    }
    let offset_secs: i64 = match b.get(i) {
        None => 0,
        Some(b'Z' | b'z') if i + 1 == b.len() => 0,
        Some(&sign @ (b'+' | b'-')) => {
            let rest = &s[i + 1..];
            let (oh, om) = match rest.len() {
                5 if rest.as_bytes()[2] == b':' => (&rest[..2], &rest[3..]),
                4 => (&rest[..2], &rest[2..]),
                2 => (rest, "00"),
                _ => return None,
            };
            let v = i64::from(oh.parse::<u32>().ok()?) * 3600 + i64::from(om.parse::<u32>().ok()?) * 60;
            if sign == b'+' { v } else { -v }
        }
        _ => return None,
    };
    let days = days_from_civil(i64::from(y), mo, d);
    let secs = days * 86_400 + i64::from(h) * 3600 + i64::from(mi) * 60 + i64::from(sec) - offset_secs;
    if secs >= 0 {
        Some(UNIX_EPOCH + Duration::new(secs as u64, nanos))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))?
            .checked_add(Duration::from_nanos(u64::from(nanos)))
    }
}

/// Parse an HTTP date (`Last-Modified`, `Expires`); RFC 1123 and the
/// obsolete formats via `httpdate`.
pub fn parse_http_date(s: &str) -> Option<SystemTime> {
    httpdate::parse_http_date(s.trim()).ok()
}

/// Format an HTTP date (RFC 1123, GMT).
pub fn http_date(t: SystemTime) -> String {
    httpdate::fmt_http_date(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_matches_botocore() {
        assert_eq!(uri_encode("a b/c~d", true), "a%20b/c~d");
        assert_eq!(uri_encode("a b/c~d", false), "a%20b%2Fc~d");
        assert_eq!(uri_encode("ü+=&", false), "%C3%BC%2B%3D%26");
        assert_eq!(uri_encode("plain-key_1.txt", true), "plain-key_1.txt");
        assert_eq!(uri_encode("", true), "");
    }

    #[test]
    fn decoding_plus_and_escapes() {
        assert_eq!(url_decode_plus("a+b%2Fc%2Bd"), "a b/c+d");
        assert_eq!(url_decode_plus("%C3%BC"), "ü");
        assert_eq!(url_decode_plus("100%"), "100%");
        assert_eq!(url_decode_plus("bad%zz"), "bad%zz");
        assert_eq!(url_decode_plus("%4"), "%4");
        assert_eq!(url_decode_plus("x%41"), "xA");
        assert!(matches!(url_decode_plus("plain"), Cow::Borrowed(_)));
    }

    #[test]
    fn dates_roundtrip() {
        let t = parse_iso8601("2026-11-24T12:34:56.789Z").unwrap();
        assert_eq!(amz_date(t), "20261124T123456Z");
        assert_eq!(iso8601(t), "2026-11-24T12:34:56Z");
        assert_eq!(
            t.duration_since(UNIX_EPOCH).unwrap().subsec_millis(),
            789
        );
        let t2 = parse_iso8601("2026-11-24T14:34:56+02:00").unwrap();
        assert_eq!(amz_date(t2), "20261124T123456Z");
        assert_eq!(parse_iso8601("1970-01-01T00:00:00Z"), Some(UNIX_EPOCH));
        assert_eq!(amz_date(parse_iso8601("2000-02-29T23:59:59Z").unwrap()), "20000229T235959Z");
        assert!(parse_iso8601("2026-13-01T00:00:00Z").is_none());
        assert!(parse_iso8601("garbage").is_none());
        assert!(parse_iso8601("2026-11-24T12:34:56.Z").is_none());
        let h = parse_http_date("Tue, 24 Nov 2026 17:27:28 GMT").unwrap();
        assert_eq!(iso8601(h), "2026-11-24T17:27:28Z");
        assert_eq!(http_date(h), "Tue, 24 Nov 2026 17:27:28 GMT");
    }

    #[test]
    fn civil_conversions_agree() {
        for days in [-1_000_000i64, -1, 0, 1, 10_957, 20_000, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }
}
