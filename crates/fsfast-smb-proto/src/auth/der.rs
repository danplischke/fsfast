//! A minimal ASN.1 DER encoder/decoder, just enough for SPNEGO
//! ([RFC 4178]) and the GSS-API initial context token framing ([RFC 2743]
//! §3.1).
//!
//! Only single-byte tags are supported (every tag SPNEGO uses fits), lengths
//! use the definite short or long form, and the decoder rejects indefinite
//! lengths and lengths that overrun their container. Decoding borrows from
//! the input; nothing is copied until the caller asks for owned data.
//!
//! [RFC 4178]: https://www.rfc-editor.org/rfc/rfc4178
//! [RFC 2743]: https://www.rfc-editor.org/rfc/rfc2743

use std::fmt;

use crate::error::{ProtoError, Result};

/// Universal `INTEGER`.
pub const TAG_INTEGER: u8 = 0x02;
/// Universal `BIT STRING`.
pub const TAG_BIT_STRING: u8 = 0x03;
/// Universal `OCTET STRING`.
pub const TAG_OCTET_STRING: u8 = 0x04;
/// Universal `OBJECT IDENTIFIER`.
pub const TAG_OID: u8 = 0x06;
/// Universal `ENUMERATED`.
pub const TAG_ENUMERATED: u8 = 0x0A;
/// Universal `GeneralString`.
pub const TAG_GENERAL_STRING: u8 = 0x1B;
/// Universal constructed `SEQUENCE`.
pub const TAG_SEQUENCE: u8 = 0x30;
/// `[APPLICATION 0]` constructed (the GSS-API InitialContextToken).
pub const TAG_APPLICATION_0: u8 = 0x60;

/// The tag of a context-specific constructed field `[n]` (n < 31).
#[inline]
pub const fn context(n: u8) -> u8 {
    0xA0 | n
}

/// Append the DER length octets for `len`.
pub fn put_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    out.push(0x80 | (bytes.len() - skip) as u8);
    out.extend_from_slice(&bytes[skip..]);
}

/// Append a complete TLV.
pub fn put_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    put_length(out, content.len());
    out.extend_from_slice(content);
}

/// Append a TLV whose content is produced by `f`. The content is built in
/// place and the length is inserted afterwards (one `memmove` of the
/// content, which for SPNEGO tokens is a few hundred bytes).
pub fn put_constructed(out: &mut Vec<u8>, tag: u8, f: impl FnOnce(&mut Vec<u8>)) {
    out.push(tag);
    let len_pos = out.len();
    f(out);
    let content_len = out.len() - len_pos;
    let mut len = Vec::with_capacity(4);
    put_length(&mut len, content_len);
    out.splice(len_pos..len_pos, len);
}

/// An object identifier kept in its DER content encoding (without tag and
/// length), so comparisons are byte comparisons.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Oid<'a>(pub &'a [u8]);

impl Oid<'_> {
    /// Append the OID as a complete TLV.
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_tlv(out, TAG_OID, self.0);
    }

    /// The dotted-decimal arcs, or `None` if the encoding is invalid.
    pub fn arcs(&self) -> Option<Vec<u64>> {
        let mut arcs = Vec::with_capacity(8);
        let mut v: u64 = 0;
        let mut first = true;
        if self.0.is_empty() || self.0.last().is_some_and(|b| b & 0x80 != 0) {
            return None;
        }
        for &b in self.0 {
            v = v.checked_mul(128)?.checked_add(u64::from(b & 0x7F))?;
            if b & 0x80 == 0 {
                if first {
                    let (a, b) = match v {
                        0..=39 => (0, v),
                        40..=79 => (1, v - 40),
                        _ => (2, v - 80),
                    };
                    arcs.push(a);
                    arcs.push(b);
                    first = false;
                } else {
                    arcs.push(v);
                }
                v = 0;
            }
        }
        Some(arcs)
    }
}

impl fmt::Debug for Oid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({self})")
    }
}

impl fmt::Display for Oid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.arcs() {
            Some(arcs) => {
                for (i, a) in arcs.iter().enumerate() {
                    if i > 0 {
                        f.write_str(".")?;
                    }
                    write!(f, "{a}")?;
                }
                Ok(())
            }
            None => write!(f, "<invalid OID {:02x?}>", self.0),
        }
    }
}

/// Encode dotted-decimal arcs as OID content octets.
pub fn encode_oid_arcs(arcs: &[u64]) -> Result<Vec<u8>> {
    if arcs.len() < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39) {
        return Err(ProtoError::InvalidInput("invalid OID arcs"));
    }
    let mut out = Vec::with_capacity(arcs.len() + 4);
    let first = arcs[0]
        .checked_mul(40)
        .and_then(|v| v.checked_add(arcs[1]))
        .ok_or(ProtoError::InvalidInput("invalid OID arcs"))?;
    for &arc in std::iter::once(&first).chain(&arcs[2..]) {
        let mut tmp = [0u8; 10];
        let mut n = 0;
        let mut v = arc;
        loop {
            tmp[n] = (v & 0x7F) as u8;
            n += 1;
            v >>= 7;
            if v == 0 {
                break;
            }
        }
        for i in (0..n).rev() {
            out.push(tmp[i] | if i > 0 { 0x80 } else { 0 });
        }
    }
    Ok(out)
}

/// One decoded TLV, borrowing its content from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The identifier octet.
    pub tag: u8,
    /// The content octets.
    pub content: &'a [u8],
    /// The complete encoding (tag, length and content).
    pub raw: &'a [u8],
}

/// A cursor over a sequence of DER TLVs.
#[derive(Debug, Clone)]
pub struct DerReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

const W: &str = "DER";

impl<'a> DerReader<'a> {
    /// A reader over `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        DerReader { buf, pos: 0 }
    }

    /// `true` when all input was consumed.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// The bytes not yet consumed.
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos.min(self.buf.len())..]
    }

    /// The tag of the next TLV, if any.
    pub fn peek_tag(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// Read the next TLV.
    pub fn read(&mut self) -> Result<Tlv<'a>> {
        let start = self.pos;
        let tag = *self.buf.get(self.pos).ok_or(ProtoError::Truncated {
            what: W,
            need: self.pos + 1,
            have: self.buf.len(),
        })?;
        if tag & 0x1F == 0x1F {
            return Err(ProtoError::malformed(
                W,
                "multi-byte tags are not supported",
            ));
        }
        let mut p = self.pos + 1;
        let first = *self.buf.get(p).ok_or(ProtoError::Truncated {
            what: W,
            need: p + 1,
            have: self.buf.len(),
        })?;
        p += 1;
        let len = if first < 0x80 {
            usize::from(first)
        } else if first == 0x80 {
            return Err(ProtoError::malformed(W, "indefinite length"));
        } else {
            let n = usize::from(first & 0x7F);
            if n > std::mem::size_of::<usize>() || n > 4 {
                return Err(ProtoError::malformed(W, "length too large"));
            }
            let bytes = self.buf.get(p..p + n).ok_or(ProtoError::Truncated {
                what: W,
                need: p + n,
                have: self.buf.len(),
            })?;
            p += n;
            bytes
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | usize::from(b))
        };
        let end =
            p.checked_add(len)
                .filter(|&e| e <= self.buf.len())
                .ok_or(ProtoError::Truncated {
                    what: W,
                    need: p.saturating_add(len),
                    have: self.buf.len(),
                })?;
        self.pos = end;
        Ok(Tlv {
            tag,
            content: &self.buf[p..end],
            raw: &self.buf[start..end],
        })
    }

    /// Read the next TLV and check its tag.
    pub fn expect(&mut self, tag: u8, what: &'static str) -> Result<Tlv<'a>> {
        let t = self.read()?;
        if t.tag != tag {
            return Err(ProtoError::malformed(what, "unexpected DER tag"));
        }
        Ok(t)
    }

    /// Read the next TLV if it has `tag`.
    pub fn optional(&mut self, tag: u8) -> Result<Option<Tlv<'a>>> {
        if self.peek_tag() == Some(tag) {
            self.read().map(Some)
        } else {
            Ok(None)
        }
    }
}

/// Decode an `ENUMERATED`/`INTEGER` content as a small non-negative value.
pub fn decode_small_uint(content: &[u8], what: &'static str) -> Result<u32> {
    if content.is_empty() || content.len() > 5 || content[0] & 0x80 != 0 {
        return Err(ProtoError::malformed(what, "invalid integer"));
    }
    let v = content
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    u32::try_from(v).map_err(|_| ProtoError::malformed(what, "integer too large"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths() {
        for (len, enc) in [
            (0usize, &[0x00][..]),
            (0x7F, &[0x7F]),
            (0x80, &[0x81, 0x80]),
            (0xFF, &[0x81, 0xFF]),
            (0x100, &[0x82, 0x01, 0x00]),
            (0x1_0000, &[0x83, 0x01, 0x00, 0x00]),
        ] {
            let mut out = Vec::new();
            put_length(&mut out, len);
            assert_eq!(out, enc, "{len}");
            let mut tlv = vec![0x04];
            tlv.extend_from_slice(enc);
            tlv.resize(tlv.len() + len, 0xAB);
            let t = DerReader::new(&tlv).read().unwrap();
            assert_eq!(t.content.len(), len);
            assert_eq!(t.raw.len(), tlv.len());
        }
    }

    #[test]
    fn constructed_and_nested() {
        let mut out = Vec::new();
        put_constructed(&mut out, TAG_SEQUENCE, |o| {
            put_tlv(o, TAG_OCTET_STRING, &[1; 200]);
            put_tlv(o, TAG_INTEGER, &[5]);
        });
        assert_eq!(&out[..3], &[0x30, 0x81, 0xCE]);
        let mut r = DerReader::new(&out);
        let seq = r.expect(TAG_SEQUENCE, "t").unwrap();
        assert!(r.is_empty());
        let mut inner = DerReader::new(seq.content);
        assert_eq!(inner.read().unwrap().content.len(), 200);
        assert!(inner.optional(TAG_OID).unwrap().is_none());
        assert_eq!(
            decode_small_uint(inner.expect(TAG_INTEGER, "t").unwrap().content, "t").unwrap(),
            5
        );
    }

    #[test]
    fn rejects_bad_input() {
        assert!(DerReader::new(&[]).read().is_err());
        assert!(DerReader::new(&[0x30]).read().is_err());
        assert!(DerReader::new(&[0x30, 0x80, 0, 0]).read().is_err());
        assert!(DerReader::new(&[0x30, 0x05, 1]).read().is_err());
        assert!(DerReader::new(&[0x1F, 0x01, 0]).read().is_err());
        assert!(
            DerReader::new(&[0x04, 0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9])
                .read()
                .is_err()
        );
        assert!(decode_small_uint(&[0x80], "t").is_err());
        assert!(decode_small_uint(&[], "t").is_err());
    }

    #[test]
    fn oids() {
        // NTLMSSP 1.3.6.1.4.1.311.2.2.10
        let enc = encode_oid_arcs(&[1, 3, 6, 1, 4, 1, 311, 2, 2, 10]).unwrap();
        assert_eq!(
            enc,
            [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A]
        );
        assert_eq!(Oid(&enc).to_string(), "1.3.6.1.4.1.311.2.2.10");
        // MS Kerberos 1.2.840.48018.1.2.2
        let enc = encode_oid_arcs(&[1, 2, 840, 48018, 1, 2, 2]).unwrap();
        assert_eq!(enc, [0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02]);
        assert_eq!(Oid(&enc).arcs().unwrap(), [1, 2, 840, 48018, 1, 2, 2]);
        assert_eq!(Oid(&[0x88, 0x37]).arcs().unwrap(), [2, 999]);
        assert!(Oid(&[0x82]).arcs().is_none());
        assert!(encode_oid_arcs(&[3, 1]).is_err());
        assert!(encode_oid_arcs(&[1]).is_err());
    }
}
