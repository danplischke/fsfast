//! Little-endian wire helpers shared by every structure in the crate.
//!
//! Decoding goes through [`Reader`], a bounds-checked cursor that never
//! panics: every read returns [`ProtoError::Truncated`] when the input is too
//! short. Variable-length fields that SMB2 locates by `(offset, length)` pairs
//! relative to the start of the SMB2 header are sliced out of the received
//! frame with [`slice_bytes`], which is zero-copy (`Bytes::slice`).
//!
//! Encoding writes straight into a [`BytesMut`] with [`BufMut`]; offsets that
//! are only known later are back-patched with the `patch_*` helpers.

use std::fmt;

use bytes::{BufMut, Bytes, BytesMut};

use crate::error::{ProtoError, Result};

/// Bounds-checked little-endian cursor over a byte slice.
#[derive(Clone)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    what: &'static str,
}

impl<'a> Reader<'a> {
    /// A reader over `buf`; `what` names the structure for error messages.
    pub(crate) fn new(buf: &'a [u8], what: &'static str) -> Self {
        Reader { buf, pos: 0, what }
    }

    #[inline]
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    #[inline]
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    #[inline]
    fn need(&self, n: usize) -> Result<()> {
        if self.remaining() < n {
            Err(ProtoError::Truncated {
                what: self.what,
                need: self.pos.saturating_add(n),
                have: self.buf.len(),
            })
        } else {
            Ok(())
        }
    }

    #[inline]
    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.need(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    #[inline]
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let s = self.bytes(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    #[inline]
    pub(crate) fn skip(&mut self, n: usize) -> Result<()> {
        self.need(n)?;
        self.pos += n;
        Ok(())
    }

    #[inline]
    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    #[inline]
    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    #[inline]
    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    #[inline]
    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    #[inline]
    pub(crate) fn guid(&mut self) -> Result<Guid> {
        Ok(Guid(self.array()?))
    }

    /// The rest of the input.
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }

    /// Error helper for this structure.
    pub(crate) fn malformed(&self, reason: &'static str) -> ProtoError {
        ProtoError::malformed(self.what, reason)
    }
}

/// Zero-copy slice of `buf[offset..offset + len]` with bounds checking.
///
/// SMB2 commonly sends `offset = 0` together with `len = 0`; a zero length
/// always yields an empty buffer regardless of the offset.
#[inline]
pub(crate) fn slice_bytes(buf: &Bytes, offset: usize, len: usize, what: &'static str) -> Result<Bytes> {
    if len == 0 {
        return Ok(Bytes::new());
    }
    let end = offset.checked_add(len).ok_or(ProtoError::malformed(what, "offset overflow"))?;
    if end > buf.len() {
        return Err(ProtoError::Truncated { what, need: end, have: buf.len() });
    }
    Ok(buf.slice(offset..end))
}

/// Borrowed variant of [`slice_bytes`].
#[inline]
pub(crate) fn slice_ref<'a>(buf: &'a [u8], offset: usize, len: usize, what: &'static str) -> Result<&'a [u8]> {
    if len == 0 {
        return Ok(&[]);
    }
    let end = offset.checked_add(len).ok_or(ProtoError::malformed(what, "offset overflow"))?;
    if end > buf.len() {
        return Err(ProtoError::Truncated { what, need: end, have: buf.len() });
    }
    Ok(&buf[offset..end])
}

#[inline]
pub(crate) fn patch_u16(buf: &mut [u8], at: usize, v: u16) {
    buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

#[inline]
pub(crate) fn patch_u32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// Zero-fill `buf` up to the next multiple of `align` (relative to the start
/// of `buf`). Returns the number of bytes written.
#[inline]
pub(crate) fn pad_to(buf: &mut BytesMut, align: usize) -> usize {
    let pad = padding(buf.len(), align);
    buf.put_bytes(0, pad);
    pad
}

/// Padding needed to bring `len` up to a multiple of `align`.
#[inline]
pub(crate) const fn padding(len: usize, align: usize) -> usize {
    (align - (len % align)) % align
}

/// Convert a length to `u16`, failing with `InvalidInput` when it does not fit.
#[inline]
pub(crate) fn len_u16(len: usize, what: &'static str) -> Result<u16> {
    u16::try_from(len).map_err(|_| ProtoError::InvalidInput(what))
}

/// Convert a length to `u32`, failing with `InvalidInput` when it does not fit.
#[inline]
pub(crate) fn len_u32(len: usize, what: &'static str) -> Result<u32> {
    u32::try_from(len).map_err(|_| ProtoError::InvalidInput(what))
}

/// Number of bytes `s` occupies when encoded as UTF-16LE.
#[inline]
pub fn utf16le_len(s: &str) -> usize {
    s.encode_utf16().count() * 2
}

/// Append `s` as UTF-16LE (no terminator).
#[inline]
pub fn put_utf16le(dst: &mut BytesMut, s: &str) {
    dst.reserve(s.len() * 2);
    for u in s.encode_utf16() {
        dst.put_u16_le(u);
    }
}

/// Encode `s` as UTF-16LE into a new vector (no terminator).
pub fn utf16le_vec(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

/// Decode UTF-16LE strictly (odd lengths and unpaired surrogates are errors).
pub fn decode_utf16le(b: &[u8], what: &'static str) -> Result<String> {
    if b.len() % 2 != 0 {
        return Err(ProtoError::InvalidUtf16 { what });
    }
    char::decode_utf16(b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])))
        .collect::<std::result::Result<String, _>>()
        .map_err(|_| ProtoError::InvalidUtf16 { what })
}

/// Decode UTF-16LE, replacing invalid sequences with U+FFFD. A trailing odd
/// byte is ignored.
pub fn decode_utf16le_lossy(b: &[u8]) -> String {
    char::decode_utf16(b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])))
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Decode a NUL-terminated UTF-16LE string starting at `offset` in `buf`.
pub(crate) fn decode_utf16z(buf: &[u8], offset: usize, what: &'static str) -> Result<String> {
    let s = buf.get(offset..).ok_or(ProtoError::Truncated { what, need: offset, have: buf.len() })?;
    let mut end = None;
    let mut i = 0;
    while i + 1 < s.len() {
        if s[i] == 0 && s[i + 1] == 0 {
            end = Some(i);
            break;
        }
        i += 2;
    }
    let end = end.ok_or(ProtoError::malformed(what, "missing NUL terminator"))?;
    decode_utf16le(&s[..end], what)
}

/// A UTF-16LE name kept in its wire form.
///
/// Directory listings can contain names that are not valid Unicode (Windows
/// allows unpaired surrogates). Keeping the raw bytes lets a client list,
/// compare and re-open such entries; conversion to `String` happens on demand.
/// The bytes are a zero-copy slice of the received frame.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Utf16Name(Bytes);

impl Utf16Name {
    /// Wrap raw UTF-16LE bytes.
    pub fn from_wire(b: Bytes) -> Self {
        Utf16Name(b)
    }

    /// Encode a Rust string.
    pub fn from_str_lossless(s: &str) -> Self {
        Utf16Name(Bytes::from(utf16le_vec(s)))
    }

    /// The raw UTF-16LE bytes.
    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the name is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Strict conversion to `String`.
    pub fn to_string_strict(&self) -> Result<String> {
        decode_utf16le(&self.0, "UTF-16 name")
    }

    /// Lossy conversion to `String` (invalid sequences become U+FFFD).
    pub fn to_string_lossy(&self) -> String {
        decode_utf16le_lossy(&self.0)
    }

    /// `true` for the `.` entry.
    pub fn is_dot(&self) -> bool {
        self.0.as_ref() == b".\0"
    }

    /// `true` for the `..` entry.
    pub fn is_dot_dot(&self) -> bool {
        self.0.as_ref() == b".\0.\0"
    }
}

impl fmt::Debug for Utf16Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.to_string_lossy(), f)
    }
}

impl fmt::Display for Utf16Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_lossy())
    }
}

impl From<&str> for Utf16Name {
    fn from(s: &str) -> Self {
        Utf16Name::from_str_lossless(s)
    }
}

/// A 16-byte GUID in its wire (mixed-endian) byte order.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// The all-zero GUID.
    pub const ZERO: Guid = Guid([0; 16]);

    /// A random (version 4) GUID from the OS RNG.
    pub fn random() -> Self {
        let mut b = [0u8; 16];
        crate::crypto::random_bytes(&mut b);
        // RFC 4122 version 4 / variant bits, in wire order (data3 is LE).
        b[7] = (b[7] & 0x0F) | 0x40;
        b[8] = (b[8] & 0x3F) | 0x80;
        Guid(b)
    }

    /// The raw wire bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
            u16::from_le_bytes([b[6], b[7]]),
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_bounds() {
        let mut r = Reader::new(&[1, 2, 3], "t");
        assert_eq!(r.u16().unwrap(), 0x0201);
        assert!(matches!(r.u16(), Err(ProtoError::Truncated { need: 4, have: 3, .. })));
        assert_eq!(r.u8().unwrap(), 3);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn utf16_round_trip() {
        let s = "dir\\f\u{1F600}e.txt";
        let mut b = BytesMut::new();
        put_utf16le(&mut b, s);
        assert_eq!(b.len(), utf16le_len(s));
        assert_eq!(decode_utf16le(&b, "x").unwrap(), s);
        assert!(decode_utf16le(&b[..3], "x").is_err());
        // Unpaired surrogate.
        assert!(decode_utf16le(&[0x00, 0xD8], "x").is_err());
        assert_eq!(decode_utf16le_lossy(&[0x00, 0xD8, b'a', 0]), "\u{FFFD}a");
    }

    #[test]
    fn slices() {
        let b = Bytes::from_static(b"0123456789");
        assert_eq!(slice_bytes(&b, 2, 3, "x").unwrap(), Bytes::from_static(b"234"));
        assert!(slice_bytes(&b, 8, 3, "x").is_err());
        assert!(slice_bytes(&b, usize::MAX, 3, "x").is_err());
        assert!(slice_bytes(&b, 999, 0, "x").unwrap().is_empty());
    }

    #[test]
    fn utf16z() {
        let b = [b'a', 0, b'b', 0, 0, 0, b'c', 0];
        assert_eq!(decode_utf16z(&b, 0, "x").unwrap(), "ab");
        assert!(decode_utf16z(&b, 6, "x").is_err());
        assert!(decode_utf16z(&b, 100, "x").is_err());
    }

    #[test]
    fn guid_display() {
        let g = Guid([
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        assert_eq!(g.to_string(), "00112233-4455-6677-8899-aabbccddeeff");
        let r = Guid::random();
        assert_eq!(r.0[7] >> 4, 4);
    }
}
