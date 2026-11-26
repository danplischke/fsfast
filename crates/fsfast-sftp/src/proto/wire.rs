//! Bounds-checked primitives of the SSH wire encoding (RFC 4251 §5) as SFTP
//! uses them: `byte`, `uint32`, `uint64` and `string`.
//!
//! Decoding never panics: every length is checked against the bytes that
//! are actually present before anything is sliced or allocated.

use bytes::{BufMut, Bytes, BytesMut};

use super::ProtoError;

/// A read cursor over one received packet. Strings are returned as
/// zero-copy slices of the packet.
#[derive(Debug, Clone)]
pub struct Cursor {
    buf: Bytes,
    pos: usize,
}

impl Cursor {
    /// A cursor at the start of `buf`.
    pub fn new(buf: Bytes) -> Self {
        Cursor { buf, pos: 0 }
    }

    /// Bytes not consumed yet.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn need(&self, n: usize, what: &str) -> Result<(), ProtoError> {
        if self.remaining() < n {
            Err(ProtoError::new(format!(
                "truncated packet: {what} needs {n} bytes, {} left",
                self.remaining()
            )))
        } else {
            Ok(())
        }
    }

    /// One byte.
    pub fn u8(&mut self) -> Result<u8, ProtoError> {
        self.need(1, "byte")?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    /// A big-endian `uint32`.
    pub fn u32(&mut self) -> Result<u32, ProtoError> {
        self.need(4, "uint32")?;
        let b = &self.buf[self.pos..self.pos + 4];
        self.pos += 4;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A big-endian `uint64`.
    pub fn u64(&mut self) -> Result<u64, ProtoError> {
        self.need(8, "uint64")?;
        let mut a = [0u8; 8];
        a.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_be_bytes(a))
    }

    /// A `string`: a `uint32` length followed by that many bytes, returned
    /// as a slice of the packet (no copy).
    pub fn string(&mut self) -> Result<Bytes, ProtoError> {
        let n = self.u32()? as usize;
        self.need(n, "string body")?;
        let s = self.buf.slice(self.pos..self.pos + n);
        self.pos += n;
        Ok(s)
    }

    /// A `string` decoded as UTF-8; invalid sequences are replaced with
    /// U+FFFD (SFTP v3 does not define a file name encoding; OpenSSH sends
    /// the raw bytes of the server's file system, normally UTF-8).
    pub fn string_lossy(&mut self) -> Result<String, ProtoError> {
        let b = self.string()?;
        Ok(match String::from_utf8(b.to_vec()) {
            Ok(s) => s,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        })
    }

    /// A `string` that must be valid UTF-8 (file names: they are sent back
    /// to the server as paths, so a lossy decoding would make different
    /// files share one name and later operations hit the wrong file).
    /// Invalid UTF-8 is an error, as in paramiko (`get_text`, strict).
    pub fn string_utf8(&mut self, what: &str) -> Result<String, ProtoError> {
        let b = self.string()?;
        String::from_utf8(b.to_vec()).map_err(|_| {
            ProtoError::new(format!(
                "{what} is not valid UTF-8: b\"{}\"",
                b.escape_ascii()
            ))
        })
    }

    /// Everything not consumed yet, as a slice.
    pub fn rest(&mut self) -> Bytes {
        let s = self.buf.slice(self.pos..);
        self.pos = self.buf.len();
        s
    }

    /// Fail unless every byte was consumed (`what` names the packet).
    pub fn finish(&self, what: &str) -> Result<(), ProtoError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(ProtoError::new(format!(
                "{what}: {} unexpected trailing bytes",
                self.remaining()
            )))
        }
    }
}

/// Append an SSH `string` (length-prefixed bytes).
pub fn put_string(buf: &mut BytesMut, s: &[u8]) {
    // Callers never pass more than u32::MAX bytes: every string we send is a
    // path, a handle or a bounded chunk of file data.
    buf.put_u32(s.len() as u32);
    buf.put_slice(s);
}

/// Encoded size of an SSH `string` holding `n` bytes.
pub const fn string_len(n: usize) -> usize {
    4 + n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_roundtrip_and_bounds() {
        let mut b = BytesMut::new();
        b.put_u8(7);
        b.put_u32(0xdead_beef);
        b.put_u64(u64::MAX - 1);
        put_string(&mut b, b"hello");
        put_string(&mut b, &[0xff, b'a']);
        let mut c = Cursor::new(b.freeze());
        assert_eq!(c.u8().unwrap(), 7);
        assert_eq!(c.u32().unwrap(), 0xdead_beef);
        assert_eq!(c.u64().unwrap(), u64::MAX - 1);
        assert_eq!(&c.string().unwrap()[..], b"hello");
        assert_eq!(c.string_lossy().unwrap(), "\u{fffd}a");
        c.finish("test").unwrap();
        let mut b = BytesMut::new();
        put_string(&mut b, "é".as_bytes());
        put_string(&mut b, b"bad\xff");
        let mut c = Cursor::new(b.freeze());
        assert_eq!(c.string_utf8("name").unwrap(), "é");
        let e = c.string_utf8("name").unwrap_err().to_string();
        assert!(
            e.contains("not valid UTF-8") && e.contains("bad\\xff"),
            "{e}"
        );
        assert!(c.u8().is_err());
        assert!(c.u32().is_err());
        assert!(c.u64().is_err());
    }

    #[test]
    fn hostile_string_length_is_an_error() {
        let mut b = BytesMut::new();
        b.put_u32(u32::MAX);
        b.put_slice(b"abc");
        let mut c = Cursor::new(b.freeze());
        assert!(c.string().is_err());
        let mut c = Cursor::new(Bytes::from_static(&[0, 0, 0]));
        assert!(c.string().is_err());
    }

    #[test]
    fn finish_reports_trailing_bytes() {
        let c = Cursor::new(Bytes::from_static(b"x"));
        assert!(
            c.finish("pkt")
                .unwrap_err()
                .to_string()
                .contains("trailing")
        );
    }
}
