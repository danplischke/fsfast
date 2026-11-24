//! Deterministic, random-access test data.
//!
//! The byte at absolute offset `o` of a pattern is a pure function of
//! `(seed, o)`: bytes are taken from a SplitMix64 stream indexed by `o / 8`.
//! That lets the suite generate, and above all *verify*, any sub-range of a
//! multi-megabyte file without materialising the whole expected content, and
//! report the exact file offset of the first wrong byte.
//!
//! Seeds are usually derived from the file path with [`seed_for`], so two
//! files written by the suite never share content by accident (which would
//! hide a backend that serves the wrong object).

use bytes::Bytes;

const GOLDEN_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

/// 64-bit FNV-1a hash of `key`, used to derive a pattern seed from a path.
pub fn seed_for(key: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// SplitMix64 output for stream position `index`.
#[inline]
fn word(seed: u64, index: u64) -> u64 {
    let mut z = seed.wrapping_add(index.wrapping_add(1).wrapping_mul(GOLDEN_GAMMA));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The pattern byte at absolute offset `pos`.
#[inline]
pub fn byte_at(seed: u64, pos: u64) -> u8 {
    word(seed, pos / 8).to_le_bytes()[(pos % 8) as usize]
}

/// Fill `buf` with the pattern bytes for `[offset, offset + buf.len())`.
pub fn fill(seed: u64, offset: u64, buf: &mut [u8]) {
    let mut pos = offset;
    let mut i = 0;
    // Unaligned head, one byte at a time.
    while i < buf.len() && pos % 8 != 0 {
        buf[i] = byte_at(seed, pos);
        i += 1;
        pos += 1;
    }
    // Aligned body, one 64-bit word at a time.
    let mut chunks = buf[i..].chunks_exact_mut(8);
    for c in &mut chunks {
        c.copy_from_slice(&word(seed, pos / 8).to_le_bytes());
        pos += 8;
    }
    // Tail.
    for b in chunks.into_remainder() {
        *b = byte_at(seed, pos);
        pos += 1;
    }
}

/// The pattern bytes for `[offset, offset + len)`.
pub fn generate(seed: u64, offset: u64, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    fill(seed, offset, &mut v);
    v
}

/// Like [`generate`], as [`Bytes`] so the suite can hand out zero-copy slices.
pub fn generate_bytes(seed: u64, offset: u64, len: usize) -> Bytes {
    Bytes::from(generate(seed, offset, len))
}

/// Absolute offset of the first byte of `actual` that differs from the
/// pattern starting at `offset`, or `None` if all of `actual` matches.
///
/// Length is not checked here; callers compare lengths separately.
pub fn first_mismatch(seed: u64, offset: u64, actual: &[u8]) -> Option<u64> {
    const CHUNK: usize = 64 << 10;
    let mut expected = vec![0u8; CHUNK.min(actual.len())];
    let mut done = 0usize;
    for chunk in actual.chunks(CHUNK) {
        let exp = &mut expected[..chunk.len()];
        fill(seed, offset + done as u64, exp);
        if exp != chunk {
            let i = first_difference(exp, chunk).unwrap_or(0);
            return Some(offset + (done + i) as u64);
        }
        done += chunk.len();
    }
    None
}

/// Index of the first differing byte within the common prefix of `a` and `b`.
pub fn first_difference(a: &[u8], b: &[u8]) -> Option<usize> {
    const BLOCK: usize = 4096;
    let n = a.len().min(b.len());
    let (a, b) = (&a[..n], &b[..n]);
    let mut base = 0;
    for (ca, cb) in a.chunks(BLOCK).zip(b.chunks(BLOCK)) {
        if ca != cb {
            return ca
                .iter()
                .zip(cb)
                .position(|(x, y)| x != y)
                .map(|i| base + i);
        }
        base += ca.len();
    }
    None
}

/// Deterministic xorshift64* generator for offsets, lengths and write sizes.
#[derive(Debug, Clone)]
pub struct XorShift(u64);

impl XorShift {
    /// A generator seeded with `seed` (zero is remapped, xorshift needs a
    /// non-zero state).
    pub fn new(seed: u64) -> Self {
        XorShift(if seed == 0 { GOLDEN_GAMMA } else { seed })
    }

    /// Next 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform-ish value in `[lo, hi]` (inclusive). `lo` must be `<= hi`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        debug_assert!(lo <= hi);
        let span = hi - lo;
        if span == u64::MAX {
            return self.next_u64();
        }
        lo + self.next_u64() % (span + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn seed_is_stable_and_path_sensitive() {
        assert_eq!(seed_for("a/b"), seed_for("a/b"));
        assert_ne!(seed_for("a/b"), seed_for("a/c"));
        // FNV-1a reference value for the empty string.
        assert_eq!(seed_for(""), 0xcbf2_9ce4_8422_2325);
    }

    #[test]
    fn mismatch_reports_absolute_offset() {
        let seed = 42;
        let mut data = generate(seed, 1000, 200_000);
        assert_eq!(first_mismatch(seed, 1000, &data), None);
        data[150_001] ^= 0xff;
        assert_eq!(first_mismatch(seed, 1000, &data), Some(151_001));
    }

    #[test]
    fn first_difference_basics() {
        assert_eq!(first_difference(b"abc", b"abc"), None);
        assert_eq!(first_difference(b"abc", b"abd"), Some(2));
        assert_eq!(first_difference(b"abc", b"ab"), None);
        let a = vec![7u8; 10_000];
        let mut b = a.clone();
        b[9_999] = 0;
        assert_eq!(first_difference(&a, &b), Some(9_999));
    }

    #[test]
    fn xorshift_range_bounds() {
        let mut r = XorShift::new(0);
        for _ in 0..10_000 {
            let v = r.range(3, 9);
            assert!((3..=9).contains(&v));
        }
        assert_eq!(r.range(5, 5), 5);
    }

    proptest! {
        /// Any window of the pattern equals the corresponding slice of a
        /// larger generated buffer (random access is consistent).
        #[test]
        fn windows_are_consistent(seed in any::<u64>(), start in 0u64..10_000, len in 0usize..3_000, sub in 0usize..3_000) {
            let whole = generate(seed, start, len + sub);
            let window = generate(seed, start + sub as u64, len);
            prop_assert_eq!(&whole[sub..], &window[..]);
            for (i, b) in window.iter().enumerate() {
                prop_assert_eq!(*b, byte_at(seed, start + (sub + i) as u64));
            }
        }

        /// A single flipped byte is always located exactly.
        #[test]
        fn flipped_byte_is_located(seed in any::<u64>(), start in 0u64..1_000_000, len in 1usize..200_000, pos in any::<prop::sample::Index>()) {
            let mut data = generate(seed, start, len);
            let i = pos.index(len);
            data[i] = data[i].wrapping_add(1);
            prop_assert_eq!(first_mismatch(seed, start, &data), Some(start + i as u64));
        }
    }
}
