//! Direct TCP transport framing ([MS-SMB2] §2.1).
//!
//! Every SMB2 message (or compound chain, or transform) on TCP port 445 is
//! prefixed with a 4-byte header: a zero byte followed by a 24-bit big-endian
//! length. [`FrameDecoder`] turns a stream of bytes accumulated in a
//! [`BytesMut`] into complete frames without copying: a frame is split off the
//! front of the read buffer, so the client can decrypt it in place and then
//! `freeze()` it into `Bytes` that responses slice into.

use bytes::{Buf, BytesMut};

use crate::error::{ProtoError, Result};

/// Size of the Direct TCP transport header.
pub const TRANSPORT_HEADER_LEN: usize = 4;
/// Largest length the 24-bit length field can express.
pub const MAX_TRANSPORT_FRAME_LEN: usize = 0x00FF_FFFF;

/// NetBIOS session message type (port 139); identical to the Direct TCP zero byte.
const NBSS_SESSION_MESSAGE: u8 = 0x00;
/// NetBIOS session keep-alive (port 139); carries no payload.
const NBSS_KEEPALIVE: u8 = 0x85;

/// Build the 4-byte transport header for a frame of `len` bytes.
pub fn transport_header(len: usize) -> Result<[u8; 4]> {
    if len > MAX_TRANSPORT_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge { len, max: MAX_TRANSPORT_FRAME_LEN });
    }
    let l = (len as u32).to_be_bytes();
    Ok([0, l[1], l[2], l[3]])
}

/// Streaming decoder for Direct TCP frames.
///
/// ```
/// use bytes::BytesMut;
/// use fsfast_smb_proto::framing::{transport_header, FrameDecoder};
///
/// let mut dec = FrameDecoder::new();
/// let mut buf = BytesMut::new();
/// buf.extend_from_slice(&transport_header(3).unwrap());
/// buf.extend_from_slice(b"ab");
/// assert!(dec.decode(&mut buf).unwrap().is_none());
/// assert_eq!(dec.bytes_needed(&buf), 1);
/// buf.extend_from_slice(b"c");
/// assert_eq!(&dec.decode(&mut buf).unwrap().unwrap()[..], b"abc");
/// ```
#[derive(Debug, Clone)]
pub struct FrameDecoder {
    max_frame_len: usize,
    /// Length of the frame whose header was already consumed.
    pending: Option<usize>,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameDecoder {
    /// A decoder accepting frames up to the protocol maximum (16 MiB - 1).
    pub fn new() -> Self {
        FrameDecoder { max_frame_len: MAX_TRANSPORT_FRAME_LEN, pending: None }
    }

    /// A decoder rejecting frames larger than `max` bytes, e.g.
    /// `MaxReadSize + 64 KiB` once negotiated, to bound memory use.
    pub fn with_max_frame_len(max: usize) -> Self {
        FrameDecoder { max_frame_len: max.min(MAX_TRANSPORT_FRAME_LEN), pending: None }
    }

    /// Change the frame size limit.
    pub fn set_max_frame_len(&mut self, max: usize) {
        self.max_frame_len = max.min(MAX_TRANSPORT_FRAME_LEN);
    }

    /// Try to extract one complete frame (without the transport header) from
    /// the front of `buf`. Returns `Ok(None)` when more bytes are needed.
    ///
    /// When a frame header has been parsed but its body is incomplete, the
    /// decoder reserves capacity for the whole frame so the next socket reads
    /// land in one allocation.
    pub fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<BytesMut>> {
        loop {
            let len = match self.pending {
                Some(len) => len,
                None => {
                    if buf.len() < TRANSPORT_HEADER_LEN {
                        return Ok(None);
                    }
                    let kind = buf[0];
                    let len = (usize::from(buf[1]) << 16) | (usize::from(buf[2]) << 8) | usize::from(buf[3]);
                    match kind {
                        NBSS_SESSION_MESSAGE => {}
                        NBSS_KEEPALIVE if len == 0 => {
                            buf.advance(TRANSPORT_HEADER_LEN);
                            continue;
                        }
                        _ => {
                            return Err(ProtoError::malformed(
                                "transport header",
                                "first byte must be zero",
                            ));
                        }
                    }
                    if len > self.max_frame_len {
                        return Err(ProtoError::FrameTooLarge { len, max: self.max_frame_len });
                    }
                    buf.advance(TRANSPORT_HEADER_LEN);
                    self.pending = Some(len);
                    len
                }
            };
            if buf.len() < len {
                buf.reserve(len - buf.len());
                return Ok(None);
            }
            self.pending = None;
            return Ok(Some(buf.split_to(len)));
        }
    }

    /// How many more bytes must arrive before [`decode`](Self::decode) can
    /// yield the next frame (at least 1 when nothing is buffered).
    pub fn bytes_needed(&self, buf: &BytesMut) -> usize {
        match self.pending {
            Some(len) => len.saturating_sub(buf.len()),
            None if buf.len() < TRANSPORT_HEADER_LEN => TRANSPORT_HEADER_LEN - buf.len(),
            None => {
                let len = (usize::from(buf[1]) << 16) | (usize::from(buf[2]) << 8) | usize::from(buf[3]);
                (TRANSPORT_HEADER_LEN + len).saturating_sub(buf.len())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_encoding() {
        assert_eq!(transport_header(0x0102_03).unwrap(), [0, 1, 2, 3]);
        assert!(transport_header(MAX_TRANSPORT_FRAME_LEN + 1).is_err());
    }

    #[test]
    fn multiple_frames_and_partial_reads() {
        let mut stream = Vec::new();
        for payload in [&b"hello"[..], b"", b"world!"] {
            stream.extend_from_slice(&transport_header(payload.len()).unwrap());
            stream.extend_from_slice(payload);
        }
        // Feed one byte at a time.
        let mut dec = FrameDecoder::new();
        let mut buf = BytesMut::new();
        let mut frames = Vec::new();
        for b in stream {
            buf.extend_from_slice(&[b]);
            while let Some(f) = dec.decode(&mut buf).unwrap() {
                frames.push(f.freeze());
            }
        }
        assert_eq!(frames, vec![&b"hello"[..], b"", b"world!"]);
        assert!(buf.is_empty());
    }

    #[test]
    fn keepalive_skipped_and_garbage_rejected() {
        let mut dec = FrameDecoder::new();
        let mut buf = BytesMut::from(&[0x85, 0, 0, 0, 0, 0, 0, 1, b'x'][..]);
        assert_eq!(&dec.decode(&mut buf).unwrap().unwrap()[..], b"x");
        let mut buf = BytesMut::from(&[0x81, 0, 0, 0][..]);
        assert!(dec.decode(&mut buf).is_err());
    }

    #[test]
    fn limit_enforced() {
        let mut dec = FrameDecoder::with_max_frame_len(10);
        let mut buf = BytesMut::from(&transport_header(11).unwrap()[..]);
        assert!(matches!(dec.decode(&mut buf), Err(ProtoError::FrameTooLarge { len: 11, max: 10 })));
    }

    #[test]
    fn bytes_needed() {
        let dec = FrameDecoder::new();
        let mut buf = BytesMut::new();
        assert_eq!(dec.bytes_needed(&buf), 4);
        buf.extend_from_slice(&transport_header(100).unwrap());
        assert_eq!(dec.bytes_needed(&buf), 100);
    }
}
