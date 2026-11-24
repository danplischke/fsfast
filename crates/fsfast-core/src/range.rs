//! Byte ranges and range coalescing.

use std::ops::Range;

use crate::{Error, Result};

/// A byte range request in the shapes remote protocols can express directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ByteRange {
    /// The whole object.
    Full,
    /// `[start, end)`.
    Bounded { start: u64, end: u64 },
    /// From `start` to the end of the object.
    From(u64),
    /// The last `n` bytes (HTTP `bytes=-n`).
    Suffix(u64),
}

impl ByteRange {
    /// Translate fsspec's `cat_file(path, start, end)` arguments.
    ///
    /// fsspec semantics: `start`/`end` follow Python slice rules — negative
    /// values count from the end of the file, `end` is exclusive, `None` means
    /// "from the beginning" / "to the end".
    ///
    /// `size` is only consulted when the request cannot be expressed without
    /// knowing the object size (a negative `end`, or a negative `start`
    /// combined with an explicit `end`). Use [`ByteRange::fsspec_needs_size`]
    /// to decide whether to look the size up first.
    pub fn from_fsspec(start: Option<i64>, end: Option<i64>, size: Option<u64>) -> Result<Self> {
        match (start, end) {
            (None | Some(0), None) => Ok(ByteRange::Full),
            (Some(s), None) if s > 0 => Ok(ByteRange::From(s as u64)),
            (Some(s), None) => Ok(ByteRange::Suffix(s.unsigned_abs())),
            (s, Some(e)) => {
                let s = s.unwrap_or(0);
                if s >= 0 && e >= 0 {
                    let (s, e) = (s as u64, e as u64);
                    return Ok(ByteRange::Bounded {
                        start: s,
                        end: e.max(s),
                    });
                }
                let size = size.ok_or_else(|| {
                    Error::invalid_input("object size is required to resolve a negative range")
                })?;
                let abs = |v: i64| -> u64 {
                    if v < 0 {
                        size.saturating_sub(v.unsigned_abs())
                    } else {
                        (v as u64).min(size)
                    }
                };
                let (s, e) = (abs(s), abs(e));
                Ok(ByteRange::Bounded {
                    start: s,
                    end: e.max(s),
                })
            }
        }
    }

    /// Whether [`ByteRange::from_fsspec`] needs the object size for these arguments.
    pub fn fsspec_needs_size(start: Option<i64>, end: Option<i64>) -> bool {
        match (start, end) {
            (_, Some(e)) if e < 0 => true,
            (Some(s), Some(_)) if s < 0 => true,
            _ => false,
        }
    }

    /// Resolve against a known object size, clamping to `[0, size]`.
    pub fn resolve(self, size: u64) -> Range<u64> {
        match self {
            ByteRange::Full => 0..size,
            ByteRange::Bounded { start, end } => {
                let s = start.min(size);
                s..end.min(size).max(s)
            }
            ByteRange::From(s) => s.min(size)..size,
            ByteRange::Suffix(n) => size.saturating_sub(n)..size,
        }
    }

    /// True when the range is known to select zero bytes without a request.
    pub fn is_empty(self) -> bool {
        matches!(self, ByteRange::Bounded { start, end } if end <= start)
            || matches!(self, ByteRange::Suffix(0))
    }

    /// Render as an HTTP `Range` header value, or `None` for the full object.
    pub fn to_http_header(self) -> Option<String> {
        match self {
            ByteRange::Full => None,
            ByteRange::Bounded { start, end } => Some(format!(
                "bytes={}-{}",
                start,
                end.saturating_sub(1).max(start)
            )),
            ByteRange::From(s) => Some(format!("bytes={s}-")),
            ByteRange::Suffix(n) => Some(format!("bytes=-{n}")),
        }
    }
}

impl From<Range<u64>> for ByteRange {
    fn from(r: Range<u64>) -> Self {
        ByteRange::Bounded {
            start: r.start,
            end: r.end,
        }
    }
}

/// A merged read that satisfies one or more requested ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoalescedRange {
    /// The range actually fetched.
    pub range: Range<u64>,
    /// Indices into the original request slice served by this fetch.
    pub members: Vec<usize>,
}

/// Merge `ranges` whose gaps are at most `max_gap` bytes, without letting a
/// merged range exceed `max_len` bytes (a single requested range larger than
/// `max_len` is kept as-is; splitting large ranges is the caller's job).
///
/// Input order is arbitrary and may contain overlaps/duplicates; every input
/// index appears in exactly one output member list. Empty ranges are attached
/// to the first output (or produce an empty fetch if all are empty) so callers
/// can return empty buffers for them without special casing.
pub fn coalesce_ranges(ranges: &[Range<u64>], max_gap: u64, max_len: u64) -> Vec<CoalescedRange> {
    let mut order: Vec<usize> = (0..ranges.len())
        .filter(|&i| ranges[i].end > ranges[i].start)
        .collect();
    order.sort_by_key(|&i| (ranges[i].start, ranges[i].end));

    let mut out: Vec<CoalescedRange> = Vec::new();
    for i in order {
        let r = &ranges[i];
        if let Some(last) = out.last_mut() {
            let gap_ok = r.start <= last.range.end.saturating_add(max_gap);
            let new_end = last.range.end.max(r.end);
            let len_ok = new_end - last.range.start <= max_len;
            if gap_ok && len_ok {
                last.range.end = new_end;
                last.members.push(i);
                continue;
            }
        }
        out.push(CoalescedRange {
            range: r.clone(),
            members: vec![i],
        });
    }

    let empties: Vec<usize> = (0..ranges.len())
        .filter(|&i| ranges[i].end <= ranges[i].start)
        .collect();
    if !empties.is_empty() {
        match out.first_mut() {
            Some(first) => first.members.extend(empties),
            None => out.push(CoalescedRange {
                range: 0..0,
                members: empties,
            }),
        }
    }
    out
}

/// Split `range` into consecutive chunks of at most `chunk` bytes.
pub fn split_range(range: Range<u64>, chunk: u64) -> Vec<Range<u64>> {
    let chunk = chunk.max(1);
    let mut out = Vec::new();
    let mut s = range.start;
    while s < range.end {
        let e = (s + chunk).min(range.end);
        out.push(s..e);
        s = e;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fsspec_translation() {
        assert_eq!(
            ByteRange::from_fsspec(None, None, None).unwrap(),
            ByteRange::Full
        );
        assert_eq!(
            ByteRange::from_fsspec(Some(10), None, None).unwrap(),
            ByteRange::From(10)
        );
        assert_eq!(
            ByteRange::from_fsspec(Some(-10), None, None).unwrap(),
            ByteRange::Suffix(10)
        );
        assert_eq!(
            ByteRange::from_fsspec(Some(5), Some(9), None).unwrap(),
            ByteRange::Bounded { start: 5, end: 9 }
        );
        assert_eq!(
            ByteRange::from_fsspec(None, Some(-2), Some(10)).unwrap(),
            ByteRange::Bounded { start: 0, end: 8 }
        );
        assert_eq!(
            ByteRange::from_fsspec(Some(-4), Some(-1), Some(10)).unwrap(),
            ByteRange::Bounded { start: 6, end: 9 }
        );
        assert!(ByteRange::from_fsspec(None, Some(-2), None).is_err());
        assert!(ByteRange::fsspec_needs_size(None, Some(-1)));
        assert!(!ByteRange::fsspec_needs_size(Some(-1), None));
        // start beyond end selects nothing
        assert!(
            ByteRange::from_fsspec(Some(9), Some(5), None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn resolve_and_header() {
        assert_eq!(ByteRange::Suffix(4).resolve(10), 6..10);
        assert_eq!(ByteRange::Suffix(40).resolve(10), 0..10);
        assert_eq!(ByteRange::Bounded { start: 8, end: 20 }.resolve(10), 8..10);
        assert_eq!(
            ByteRange::Bounded { start: 0, end: 10 }
                .to_http_header()
                .unwrap(),
            "bytes=0-9"
        );
        assert_eq!(ByteRange::Suffix(5).to_http_header().unwrap(), "bytes=-5");
        assert_eq!(ByteRange::Full.to_http_header(), None);
    }

    #[test]
    fn coalesce_basic() {
        let r = vec![0..10, 100..110, 12..20, 15..18, 5..5];
        let c = coalesce_ranges(&r, 4, 1 << 20);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].range, 0..20);
        assert_eq!(c[0].members, vec![0, 2, 3, 4]);
        assert_eq!(c[1].range, 100..110);
    }

    #[test]
    fn coalesce_respects_max_len() {
        let r = vec![0..10, 10..20, 20..30];
        let c = coalesce_ranges(&r, 0, 20);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].range, 0..20);
        assert_eq!(c[1].range, 20..30);
    }

    #[test]
    fn split() {
        assert_eq!(split_range(0..10, 4), vec![0..4, 4..8, 8..10]);
        assert!(split_range(5..5, 4).is_empty());
    }
}
