//! Compound requests and responses ([MS-SMB2] §3.2.4.1.4, §3.3.5.2.7).
//!
//! A compound chain packs several messages into one transport frame. Every
//! member except the last is padded to an 8-byte boundary and its header's
//! `NextCommand` holds the distance to the next member. In a *related* chain
//! the second and later requests carry `SMB2_FLAGS_RELATED_OPERATIONS` and
//! use [`FileId::RELATED`](crate::types::FileId::RELATED) to refer to the
//! handle produced by the previous request (e.g. CREATE + QUERY_INFO +
//! CLOSE in one round trip).
//!
//! Signing happens per member *after* the chain is built, because the
//! signature covers `NextCommand` and the padding.

use bytes::Bytes;

use crate::error::{ProtoError, Result};
use crate::header::{FLAGS_OFFSET, HEADER_LEN, Header, HeaderFlags};
use crate::msg::{EncodedMessage, Message, RawMessage, encode_message};

/// Builds a compound request chain.
///
/// ```
/// use fsfast_smb_proto::compound::CompoundBuilder;
/// use fsfast_smb_proto::header::{Command, Header};
/// use fsfast_smb_proto::msg::{CloseRequest, CreateRequest, QueryInfoRequest};
/// use fsfast_smb_proto::fscc::FileNetworkOpenInformation;
/// use fsfast_smb_proto::types::FileId;
///
/// let mut h = Header::request(Command::CREATE);
/// h.message_id = 10;
/// let mut chain = CompoundBuilder::new();
/// chain.push(h, &CreateRequest { name: "a.txt".into(), ..Default::default() }).unwrap();
/// h.message_id = 11;
/// chain
///     .push_related(h, &QueryInfoRequest::for_class::<FileNetworkOpenInformation>(FileId::RELATED, 56))
///     .unwrap();
/// h.message_id = 12;
/// chain.push_related(h, &CloseRequest { file_id: FileId::RELATED, ..Default::default() }).unwrap();
/// let msgs = chain.finish();
/// assert_eq!(msgs.len(), 3);
/// assert!(msgs.iter().take(2).all(|m| m.len() % 8 == 0));
/// ```
#[derive(Debug, Default)]
pub struct CompoundBuilder {
    msgs: Vec<EncodedMessage>,
}

impl CompoundBuilder {
    /// An empty chain.
    pub fn new() -> Self {
        CompoundBuilder { msgs: Vec::with_capacity(4) }
    }

    /// Number of messages so far.
    pub fn len(&self) -> usize {
        self.msgs.len()
    }

    /// `true` if no message was added.
    pub fn is_empty(&self) -> bool {
        self.msgs.is_empty()
    }

    /// Append an unrelated request (its own session/tree/file ids).
    pub fn push<M: Message>(&mut self, mut header: Header, body: &M) -> Result<&mut Self> {
        header.flags.remove(HeaderFlags::RELATED_OPERATIONS);
        let m = encode_message(&header, body)?;
        self.msgs.push(m);
        Ok(self)
    }

    /// Append a request related to the previous one: sets
    /// `SMB2_FLAGS_RELATED_OPERATIONS`. Fails for the first message of the
    /// chain, which can never be related.
    pub fn push_related<M: Message>(&mut self, mut header: Header, body: &M) -> Result<&mut Self> {
        if self.msgs.is_empty() {
            return Err(ProtoError::InvalidInput("the first request of a compound cannot be related"));
        }
        header.flags.insert(HeaderFlags::RELATED_OPERATIONS);
        let m = encode_message(&header, body)?;
        self.msgs.push(m);
        Ok(self)
    }

    /// Append an already encoded message as is (its flags are not changed).
    pub fn push_encoded(&mut self, msg: EncodedMessage) -> &mut Self {
        self.msgs.push(msg);
        self
    }

    /// Finish the chain: pad every member but the last to 8 bytes and set
    /// `NextCommand`. The result is ready for signing (per member) and for
    /// [`OutgoingFrame::from_messages`](crate::msg::OutgoingFrame::from_messages)
    /// or encryption.
    pub fn finish(mut self) -> Vec<EncodedMessage> {
        let n = self.msgs.len();
        for (i, m) in self.msgs.iter_mut().enumerate() {
            if i + 1 < n {
                m.pad8();
                let len = m.len() as u32;
                m.set_next_command(len);
            } else {
                m.set_next_command(0);
            }
        }
        self.msgs
    }
}

/// Iterator over the members of a received (decrypted) frame; see
/// [`split_compound`].
#[derive(Debug, Clone)]
pub struct CompoundIter {
    frame: Bytes,
    pos: Option<usize>,
}

impl Iterator for CompoundIter {
    type Item = Result<RawMessage>;

    fn next(&mut self) -> Option<Self::Item> {
        let pos = self.pos.take()?;
        let rest = &self.frame[pos..];
        let header = match Header::decode(rest) {
            Ok(h) => h,
            Err(e) => return Some(Err(e)),
        };
        let next = header.next_command as usize;
        if next == 0 {
            return Some(Ok(RawMessage::from_parts(header, self.frame.slice(pos..))));
        }
        if next < HEADER_LEN || next > rest.len() {
            return Some(Err(ProtoError::malformed("compound response", "NextCommand out of range")));
        }
        if next < rest.len() {
            self.pos = Some(pos + next);
        }
        Some(Ok(RawMessage::from_parts(header, self.frame.slice(pos..pos + next))))
    }
}

/// Split a received frame (plain SMB2, after decryption/decompression) into
/// its messages. Each [`RawMessage`] keeps its exact bytes including any
/// padding, which is what its signature covers.
pub fn split_compound(frame: Bytes) -> CompoundIter {
    let pos = (!frame.is_empty()).then_some(0);
    CompoundIter { frame, pos }
}

/// `true` if the header bytes at the start of `msg` have the related flag
/// set (cheap check without a full header decode).
pub fn is_related(msg: &[u8]) -> bool {
    msg.get(FLAGS_OFFSET..FLAGS_OFFSET + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) & HeaderFlags::RELATED_OPERATIONS.bits() != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fscc::FileNetworkOpenInformation;
    use crate::header::Command;
    use crate::msg::*;
    use crate::types::FileId;
    use bytes::BytesMut;

    #[test]
    fn build_and_split() {
        let mut h = Header::request(Command::CREATE);
        h.session_id = 5;
        h.set_tree_id(9);
        let mut b = CompoundBuilder::new();
        assert!(b.push_related(h, &EchoRequest).is_err());
        h.message_id = 1;
        b.push(h, &CreateRequest { name: "x".into(), ..Default::default() }).unwrap();
        h.message_id = 2;
        b.push_related(h, &QueryInfoRequest::for_class::<FileNetworkOpenInformation>(FileId::RELATED, 56))
            .unwrap();
        h.message_id = 3;
        b.push_related(
            h,
            &WriteRequest { file_id: FileId::RELATED, data: Bytes::from_static(b"abc"), ..Default::default() },
        )
        .unwrap();
        h.message_id = 4;
        b.push_related(h, &CloseRequest { file_id: FileId::RELATED, ..Default::default() }).unwrap();
        let msgs = b.finish();
        assert_eq!(msgs.len(), 4);
        // The WRITE keeps its payload separate and pads after it.
        assert!(msgs[2].payload.is_some());
        assert_eq!(msgs[2].len() % 8, 0);
        let mut frame = BytesMut::new();
        for m in &msgs {
            m.write_to(&mut frame);
        }
        let parts: Vec<RawMessage> = split_compound(frame.freeze()).collect::<Result<_>>().unwrap();
        assert_eq!(parts.len(), 4);
        assert!(!parts[0].header().flags.contains(HeaderFlags::RELATED_OPERATIONS));
        for (i, p) in parts.iter().enumerate() {
            assert_eq!(p.header().message_id, i as u64 + 1);
            assert_eq!(p.bytes().len(), msgs[i].len());
            if i > 0 {
                assert!(is_related(p.bytes()));
            }
        }
        let w: WriteRequest = parts[2].decode().unwrap();
        assert_eq!(&w.data[..], b"abc");
        assert_eq!(w.file_id, FileId::RELATED);
        let c: CloseRequest = parts[3].decode().unwrap();
        assert!(c.file_id.is_related());
    }

    #[test]
    fn split_rejects_bad_next_command() {
        let mut m = encode_message(&Header::request(Command::ECHO), &EchoRequest).unwrap();
        m.set_next_command(8);
        let frame = m.into_contiguous().freeze();
        let r: Vec<_> = split_compound(frame).collect();
        assert!(r[0].is_err());
        assert_eq!(split_compound(Bytes::new()).count(), 0);
    }
}
