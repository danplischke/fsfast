//! Splits the SFTP byte stream (as received in SSH channel data chunks)
//! into packets.
//!
//! The data of a `SSH_FXP_DATA` reply is never copied: it is handed out as
//! slices of the received chunks ([`Payload`]). Every other packet is
//! returned as one contiguous buffer (a slice when it fits in one chunk).

use std::collections::VecDeque;

use bytes::{Buf, Bytes, BytesMut};

use super::packet::Payload;
use super::{ProtoError, fxp};

/// Default upper bound on the length of one received packet. OpenSSH never
/// sends more than 256 KiB; a larger bound leaves room for servers with big
/// NAME replies while still refusing absurd lengths before buffering them.
pub const DEFAULT_MAX_FRAME: u32 = 16 << 20;

/// One received packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// `SSH_FXP_VERSION` (no request id): the packet after the length
    /// field, type byte included.
    Version(Bytes),
    /// A reply carrying a request id.
    Reply {
        /// Packet type.
        ty: u8,
        /// Request id.
        id: u32,
        /// Body after the id (for DATA: see `data`).
        body: Bytes,
        /// For `SSH_FXP_DATA`: the data, as zero-copy chunks; `body` is then
        /// empty.
        data: Option<Payload>,
    },
}

/// Incremental packet splitter.
#[derive(Debug)]
pub struct FrameAssembler {
    chunks: VecDeque<Bytes>,
    len: usize,
    max_frame: u32,
}

impl Default for FrameAssembler {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FRAME)
    }
}

impl FrameAssembler {
    /// A splitter refusing packets longer than `max_frame` bytes.
    pub fn new(max_frame: u32) -> Self {
        FrameAssembler {
            chunks: VecDeque::new(),
            len: 0,
            max_frame: max_frame.max(16),
        }
    }

    /// Bytes buffered but not yet returned as packets.
    pub fn buffered(&self) -> usize {
        self.len
    }

    /// Feed received bytes.
    pub fn push(&mut self, b: Bytes) {
        if !b.is_empty() {
            self.len += b.len();
            self.chunks.push_back(b);
        }
    }

    /// Copy `dst.len()` bytes starting `off` bytes into the buffer. The
    /// caller guarantees they are buffered.
    fn peek(&self, mut off: usize, dst: &mut [u8]) {
        let mut filled = 0;
        for c in &self.chunks {
            if off >= c.len() {
                off -= c.len();
                continue;
            }
            let n = (c.len() - off).min(dst.len() - filled);
            dst[filled..filled + n].copy_from_slice(&c[off..off + n]);
            filled += n;
            off = 0;
            if filled == dst.len() {
                return;
            }
        }
    }

    fn peek_u32(&self, off: usize) -> u32 {
        let mut b = [0u8; 4];
        self.peek(off, &mut b);
        u32::from_be_bytes(b)
    }

    fn peek_u8(&self, off: usize) -> u8 {
        let mut b = [0u8; 1];
        self.peek(off, &mut b);
        b[0]
    }

    /// Drop `n` buffered bytes from the front.
    fn advance(&mut self, mut n: usize) {
        self.len -= n;
        while n > 0 {
            let Some(front) = self.chunks.front_mut() else {
                return;
            };
            if front.len() <= n {
                n -= front.len();
                self.chunks.pop_front();
            } else {
                front.advance(n);
                n = 0;
            }
        }
    }

    /// Remove `n` bytes from the front as zero-copy slices.
    fn take_chunks(&mut self, mut n: usize) -> Vec<Bytes> {
        self.len -= n;
        let mut out = Vec::new();
        while n > 0 {
            let Some(front) = self.chunks.front_mut() else {
                break;
            };
            if front.len() <= n {
                n -= front.len();
                if let Some(c) = self.chunks.pop_front() {
                    out.push(c);
                }
            } else {
                out.push(front.split_to(n));
                n = 0;
            }
        }
        out
    }

    /// Remove `n` bytes from the front as one buffer (a slice if they are
    /// in one chunk, else one copy).
    fn take_contiguous(&mut self, n: usize) -> Bytes {
        if let Some(front) = self.chunks.front_mut()
            && front.len() >= n
        {
            let b = front.split_to(n);
            if front.is_empty() {
                self.chunks.pop_front();
            }
            self.len -= n;
            return b;
        }
        let mut out = BytesMut::with_capacity(n);
        for c in self.take_chunks(n) {
            out.extend_from_slice(&c);
        }
        out.freeze()
    }

    /// The next complete packet, `Ok(None)` if more bytes are needed.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, ProtoError> {
        if self.len < 4 {
            return Ok(None);
        }
        let plen = self.peek_u32(0);
        if plen == 0 || plen > self.max_frame {
            return Err(ProtoError::new(format!(
                "invalid packet length {plen} (limit {})",
                self.max_frame
            )));
        }
        let plen = plen as usize;
        if self.len < 4 + plen {
            return Ok(None);
        }
        let ty = self.peek_u8(4);
        if ty == fxp::VERSION {
            self.advance(4);
            return Ok(Some(Frame::Version(self.take_contiguous(plen))));
        }
        if plen < 5 {
            return Err(ProtoError::new(format!(
                "packet of type {ty} is too short ({plen} bytes) for a request id"
            )));
        }
        let id = self.peek_u32(5);
        if ty == fxp::DATA {
            if plen < 9 {
                return Err(ProtoError::new("truncated SSH_FXP_DATA packet"));
            }
            let dlen = self.peek_u32(9) as usize;
            if dlen != plen - 9 {
                return Err(ProtoError::new(format!(
                    "SSH_FXP_DATA string of {dlen} bytes in a packet of {plen}"
                )));
            }
            self.advance(13);
            let data = Payload::from_chunks(self.take_chunks(dlen));
            return Ok(Some(Frame::Reply {
                ty,
                id,
                body: Bytes::new(),
                data: Some(data),
            }));
        }
        self.advance(9);
        let body = self.take_contiguous(plen - 5);
        Ok(Some(Frame::Reply {
            ty,
            id,
            body,
            data: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::super::packet::{Reply, Status, Version};
    use super::*;

    fn all_frames(a: &mut FrameAssembler) -> Vec<Frame> {
        let mut v = Vec::new();
        while let Some(f) = a.next_frame().unwrap() {
            v.push(f);
        }
        v
    }

    #[test]
    fn splits_across_chunk_boundaries() {
        let mut wire = Vec::new();
        wire.extend_from_slice(
            &Version {
                version: 3,
                extensions: vec![],
            }
            .encode(),
        );
        wire.extend_from_slice(&Reply::Status(Status::new(0)).encode(1));
        let content: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
        wire.extend_from_slice(
            &Reply::Data(Payload::from_bytes(Bytes::from(content.clone()))).encode(2),
        );
        wire.extend_from_slice(&Reply::Handle(Bytes::from_static(b"h")).encode(3));

        for step in [1usize, 3, 7, 4096, 32768, wire.len()] {
            let mut a = FrameAssembler::default();
            let mut frames = Vec::new();
            for c in wire.chunks(step) {
                a.push(Bytes::copy_from_slice(c));
                frames.extend(all_frames(&mut a));
            }
            assert_eq!(a.buffered(), 0, "step {step}");
            assert_eq!(frames.len(), 4, "step {step}");
            assert!(matches!(&frames[0], Frame::Version(v) if v[0] == fxp::VERSION));
            match &frames[2] {
                Frame::Reply { ty, id, data, .. } => {
                    assert_eq!((*ty, *id), (fxp::DATA, 2));
                    let p = data.clone().unwrap();
                    assert_eq!(p.len(), content.len());
                    assert_eq!(&p.into_bytes()[..], &content[..]);
                }
                f => panic!("unexpected {f:?}"),
            }
            match &frames[3] {
                Frame::Reply { ty, id, body, .. } => {
                    assert_eq!((*ty, *id), (fxp::HANDLE, 3));
                    let r = Reply::decode(*ty, body.clone()).unwrap();
                    assert_eq!(r, Reply::Handle(Bytes::from_static(b"h")));
                }
                f => panic!("unexpected {f:?}"),
            }
        }
    }

    #[test]
    fn data_payload_is_zero_copy() {
        let data = Bytes::from(vec![5u8; 50_000]);
        let wire = Reply::Data(Payload::from_bytes(data)).encode(7);
        let wire = Bytes::from(wire.to_vec());
        let mut a = FrameAssembler::default();
        a.push(wire.clone());
        let Some(Frame::Reply { data: Some(p), .. }) = a.next_frame().unwrap() else {
            panic!("no data frame");
        };
        assert_eq!(p.chunks().len(), 1);
        assert_eq!(p.chunks()[0].as_ptr(), wire[13..].as_ptr());
    }

    #[test]
    fn hostile_lengths_are_errors() {
        for bad in [
            &[0u8, 0, 0, 0][..],                                  // zero length
            &[0xff, 0xff, 0xff, 0xff][..],                        // above the limit
            &[0, 0, 0, 2, fxp::STATUS, 0][..],                    // no room for an id
            &[0, 0, 0, 6, fxp::DATA, 0, 0, 0, 1, 0][..],          // DATA without length
            &[0, 0, 0, 9, fxp::DATA, 0, 0, 0, 1, 0, 0, 0, 9][..], // DATA length mismatch
        ] {
            let mut a = FrameAssembler::default();
            a.push(Bytes::copy_from_slice(bad));
            assert!(a.next_frame().is_err(), "{bad:?}");
        }
        // Incomplete but valid so far: wait for more.
        let mut a = FrameAssembler::default();
        a.push(Bytes::from_static(&[0, 0, 1, 0, fxp::NAME]));
        assert_eq!(a.next_frame().unwrap(), None);
    }
}
