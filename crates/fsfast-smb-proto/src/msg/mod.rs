//! SMB2 message bodies ([MS-SMB2] §2.2) and the plumbing to turn them into
//! bytes on the wire and back.
//!
//! # Encoding
//!
//! Every body implements [`Message`]. [`encode_message`] writes the 64-byte
//! header plus the *inline* part of the body into one [`BytesMut`]; bulk data
//! (WRITE request data, READ response data) is returned by
//! [`Message::payload`] and stays a separate [`Bytes`] in the resulting
//! [`EncodedMessage`]. Signing hashes the parts in sequence and
//! [`OutgoingFrame`] hands them to the socket as an `IoSlice` vector, so an
//! 8 MiB WRITE is never copied by the codec.
//!
//! # Decoding
//!
//! A received frame (after decryption, if any) is split with
//! [`crate::compound::split_compound`] into [`RawMessage`]s. Each keeps its
//! exact bytes (header included) for signature verification, and bodies are
//! decoded with [`RawMessage::decode`]. Variable-length fields are zero-copy
//! slices of the frame.

use std::collections::VecDeque;
use std::io::IoSlice;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::{ProtoError, Result};
use crate::framing::transport_header;
use crate::header::{Command, HEADER_LEN, Header, NEXT_COMMAND_OFFSET};
use crate::status::NtStatus;
use crate::wire::Reader;

pub mod create;
pub mod error_response;
pub mod ioctl;
pub mod misc;
pub mod negotiate;
pub mod notify;
pub mod query;
pub mod rw;
pub mod session;
pub mod tree;

pub use create::*;
pub use error_response::*;
pub use ioctl::*;
pub use misc::*;
pub use negotiate::*;
pub use notify::*;
pub use query::*;
pub use rw::*;
pub use session::*;
pub use tree::*;

/// An SMB2 message body.
///
/// Implemented by every request and response structure. The same type is
/// used for both directions of the codec (client encode / server decode and
/// vice versa) so the crate can also drive mock servers in tests.
pub trait Message: Sized {
    /// Command code carried in the header.
    const COMMAND: Command;
    /// `true` for server-to-client structures (responses, notifications).
    const RESPONSE: bool;

    /// Append the inline body (everything after the header except
    /// [`payload`](Self::payload)). Offsets inside the body are computed
    /// relative to the start of the SMB2 header, which precedes the body by
    /// [`HEADER_LEN`] bytes.
    fn encode_body(&self, dst: &mut BytesMut) -> Result<()>;

    /// Bulk data that follows the inline body on the wire, kept separate so
    /// it can be transmitted without copying.
    fn payload(&self) -> Option<&Bytes> {
        None
    }

    /// Decode the body. `msg` is the complete message starting at the SMB2
    /// header (SMB2 offsets are relative to it); the header itself is not
    /// validated here.
    fn decode_body(msg: &Bytes) -> Result<Self>;

    /// The `CreditCharge` this request needs (1 unless the request moves
    /// more than 64 KiB in either direction).
    fn credit_charge(&self) -> u16 {
        1
    }
}

/// Start reading a body: checks the length and the `StructureSize` field.
pub(crate) fn body_reader<'a>(
    msg: &'a [u8],
    what: &'static str,
    structure_size: u16,
) -> Result<Reader<'a>> {
    let body = msg.get(HEADER_LEN..).ok_or(ProtoError::Truncated {
        what,
        need: HEADER_LEN,
        have: msg.len(),
    })?;
    let mut r = Reader::new(body, what);
    let ss = r.u16()?;
    if ss != structure_size {
        return Err(ProtoError::malformed(what, "unexpected StructureSize"));
    }
    Ok(r)
}

/// Body offset helper: the wire offset (from the header start) of a body
/// position, as a `u16`/`u32`.
#[inline]
pub(crate) fn wire_offset(body_start: usize, dst: &BytesMut) -> usize {
    HEADER_LEN + dst.len() - body_start
}

/// One encoded message, ready to be signed and sent.
#[derive(Debug, Clone)]
pub struct EncodedMessage {
    /// Header plus inline body (and compound padding when there is no
    /// payload). The signature lives at `head[48..64]`.
    pub head: BytesMut,
    /// Zero-copy bulk data following `head`.
    pub payload: Option<Bytes>,
    /// Zero bytes after `payload` (compound alignment). Always 0 when
    /// `payload` is `None` (padding is then part of `head`).
    pub padding: usize,
}

static ZEROS: [u8; 8] = [0; 8];

impl EncodedMessage {
    /// Total length on the wire.
    pub fn len(&self) -> usize {
        self.head.len() + self.payload.as_ref().map_or(0, Bytes::len) + self.padding
    }

    /// Always `false`: a message has at least a header.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Decode this message's header.
    pub fn header(&self) -> Header {
        Header::decode(&self.head).expect("EncodedMessage always starts with a valid header")
    }

    /// The parts of the message in wire order (empty parts omitted).
    pub fn segments(&self) -> impl Iterator<Item = &[u8]> {
        let payload = self.payload.as_deref();
        std::iter::once(&self.head[..])
            .chain(payload)
            .chain((self.padding > 0).then(|| &ZEROS[..self.padding]))
            .filter(|s| !s.is_empty())
    }

    /// Append the whole message to `dst` (copies the payload).
    pub fn write_to(&self, dst: &mut BytesMut) {
        dst.reserve(self.len());
        for s in self.segments() {
            dst.put_slice(s);
        }
    }

    /// The message as one contiguous buffer. Free when there is no payload;
    /// otherwise the payload is copied once.
    pub fn into_contiguous(self) -> BytesMut {
        if self.payload.is_none() {
            return self.head;
        }
        let mut b = BytesMut::with_capacity(self.len());
        self.write_to(&mut b);
        b
    }

    /// Pad the message to a multiple of 8 bytes (compound members).
    pub(crate) fn pad8(&mut self) {
        let pad = crate::wire::padding(self.len(), 8);
        if self.payload.is_some() {
            self.padding += pad;
        } else {
            self.head.put_bytes(0, pad);
        }
    }

    /// Patch `NextCommand` in the header.
    pub(crate) fn set_next_command(&mut self, next: u32) {
        crate::wire::patch_u32(&mut self.head, NEXT_COMMAND_OFFSET, next);
    }
}

/// Encode `header` followed by `body`.
///
/// The header's `command` is overwritten with `M::COMMAND`;
/// `credit_charge` is kept as given (see [`Message::credit_charge`]).
pub fn encode_message<M: Message>(header: &Header, body: &M) -> Result<EncodedMessage> {
    let mut h = *header;
    h.command = M::COMMAND;
    let mut head = BytesMut::with_capacity(HEADER_LEN + 128);
    h.encode(&mut head);
    body.encode_body(&mut head)?;
    let payload = body.payload().filter(|p| !p.is_empty()).cloned();
    Ok(EncodedMessage { head, payload, padding: 0 })
}

/// A complete outgoing transport frame: the 4-byte Direct TCP header followed
/// by the message parts. Implements [`Buf`] with vectored chunks, so
/// `tokio::io::AsyncWriteExt::write_all_buf` sends it with `writev` and no
/// copying.
#[derive(Debug, Clone, Default)]
pub struct OutgoingFrame {
    chunks: VecDeque<Bytes>,
    remaining: usize,
}

impl OutgoingFrame {
    /// Frame one or more (already signed) messages. Several messages form a
    /// compound chain and must have been built with
    /// [`crate::compound::CompoundBuilder`].
    pub fn from_messages(msgs: impl IntoIterator<Item = EncodedMessage>) -> Result<Self> {
        let mut chunks = VecDeque::with_capacity(4);
        chunks.push_back(Bytes::new()); // placeholder for the transport header
        let mut total = 0usize;
        for m in msgs {
            total += m.len();
            chunks.push_back(m.head.freeze());
            if let Some(p) = m.payload {
                chunks.push_back(p);
            }
            if m.padding > 0 {
                chunks.push_back(Bytes::from_static(&ZEROS[..m.padding]));
            }
        }
        chunks[0] = Bytes::copy_from_slice(&transport_header(total)?);
        Ok(OutgoingFrame { chunks, remaining: total + 4 })
    }

    /// Frame an already contiguous payload (e.g. a TRANSFORM_HEADER message).
    pub fn from_bytes(b: Bytes) -> Result<Self> {
        let hdr = Bytes::copy_from_slice(&transport_header(b.len())?);
        let remaining = b.len() + 4;
        Ok(OutgoingFrame { chunks: VecDeque::from([hdr, b]), remaining })
    }

    /// Copy the frame into one vector (tests, debugging).
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.remaining);
        for c in &self.chunks {
            v.extend_from_slice(c);
        }
        v
    }
}

impl Buf for OutgoingFrame {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn chunk(&self) -> &[u8] {
        self.chunks.iter().find(|c| !c.is_empty()).map_or(&[], |c| &c[..])
    }

    fn advance(&mut self, mut cnt: usize) {
        assert!(cnt <= self.remaining, "advance past end of OutgoingFrame");
        self.remaining -= cnt;
        while cnt > 0 {
            let front = self.chunks.front_mut().expect("remaining > 0 implies a chunk");
            if cnt >= front.len() {
                cnt -= front.len();
                self.chunks.pop_front();
            } else {
                front.advance(cnt);
                cnt = 0;
            }
        }
        while self.chunks.front().is_some_and(Bytes::is_empty) {
            self.chunks.pop_front();
        }
    }

    fn chunks_vectored<'a>(&'a self, dst: &mut [IoSlice<'a>]) -> usize {
        let mut n = 0;
        for c in self.chunks.iter().filter(|c| !c.is_empty()) {
            if n == dst.len() {
                break;
            }
            dst[n] = IoSlice::new(c);
            n += 1;
        }
        n
    }
}

/// The normal response `StructureSize` of a command, used to tell error
/// bodies apart from regular ones.
fn response_structure_size(cmd: Command) -> Option<u16> {
    Some(match cmd {
        Command::NEGOTIATE => 65,
        Command::SESSION_SETUP => 9,
        Command::LOGOFF => 4,
        Command::TREE_CONNECT => 16,
        Command::TREE_DISCONNECT => 4,
        Command::CREATE => 89,
        Command::CLOSE => 60,
        Command::FLUSH => 4,
        Command::READ => 17,
        Command::WRITE => 17,
        Command::LOCK => 4,
        Command::IOCTL => 49,
        Command::ECHO => 4,
        Command::QUERY_DIRECTORY => 9,
        Command::CHANGE_NOTIFY => 9,
        Command::QUERY_INFO => 9,
        Command::SET_INFO => 2,
        _ => return None,
    })
}

/// One received SMB2 message (a member of a possibly compound frame).
#[derive(Debug, Clone)]
pub struct RawMessage {
    header: Header,
    bytes: Bytes,
}

impl RawMessage {
    /// Parse a single, non-compound message. For frames that may be
    /// compounds use [`crate::compound::split_compound`].
    pub fn parse(bytes: Bytes) -> Result<Self> {
        let header = Header::decode(&bytes)?;
        Ok(RawMessage { header, bytes })
    }

    pub(crate) fn from_parts(header: Header, bytes: Bytes) -> Self {
        RawMessage { header, bytes }
    }

    /// The decoded header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The exact message bytes, header first, including any compound
    /// padding. This is the input to signature verification.
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// The body bytes (after the 64-byte header).
    pub fn body(&self) -> &[u8] {
        &self.bytes[HEADER_LEN.min(self.bytes.len())..]
    }

    /// Shorthand for `header().status`.
    pub fn status(&self) -> NtStatus {
        self.header.status
    }

    /// Shorthand for `header().command`.
    pub fn command(&self) -> Command {
        self.header.command
    }

    /// Whether the body is an SMB2 ERROR response ([MS-SMB2] §2.2.2) rather
    /// than the command's regular response.
    ///
    /// Interim `STATUS_PENDING` responses carry an error body. Non-success
    /// statuses carry one too, except `STATUS_MORE_PROCESSING_REQUIRED` on
    /// SESSION_SETUP, `STATUS_BUFFER_OVERFLOW` on READ/QUERY_INFO/
    /// QUERY_DIRECTORY/IOCTL/CHANGE_NOTIFY and IOCTL responses that carry a
    /// regular body (e.g. copy-chunk limits with `STATUS_INVALID_PARAMETER`).
    pub fn is_error_response(&self) -> bool {
        let status = self.header.status;
        if status == NtStatus::PENDING {
            return true;
        }
        if status.is_success() {
            return false;
        }
        let ss = match self.body() {
            [a, b, ..] => u16::from_le_bytes([*a, *b]),
            _ => return true,
        };
        let cmd = self.header.command;
        match response_structure_size(cmd) {
            Some(9) => {
                let regular = (cmd == Command::SESSION_SETUP
                    && status == NtStatus::MORE_PROCESSING_REQUIRED)
                    || (status == NtStatus::BUFFER_OVERFLOW
                        && matches!(
                            cmd,
                            Command::QUERY_INFO | Command::QUERY_DIRECTORY | Command::CHANGE_NOTIFY
                        ));
                !regular
            }
            Some(_) | None => ss == 9,
        }
    }

    /// Decode the body as `M`. Checks the command and direction; does not
    /// look at the status (see [`RawMessage::into_result`]).
    pub fn decode<M: Message>(&self) -> Result<M> {
        if self.header.command != M::COMMAND {
            return Err(ProtoError::UnexpectedCommand {
                expected: M::COMMAND,
                actual: self.header.command,
            });
        }
        if self.header.is_response() != M::RESPONSE {
            return Err(ProtoError::malformed("SMB2 message", "unexpected message direction"));
        }
        M::decode_body(&self.bytes)
    }

    /// Decode the body as an ERROR response.
    pub fn decode_error(&self) -> Result<ErrorResponse> {
        ErrorResponse::decode_body(&self.bytes)
    }

    /// Decode as `M`, or fail with [`ProtoError::Status`] when the server
    /// sent an error response.
    pub fn into_result<M: Message>(&self) -> Result<M> {
        if self.is_error_response() {
            return Err(ProtoError::Status(self.header.status));
        }
        self.decode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::HeaderFlags;

    #[test]
    fn outgoing_frame_buf() {
        let h = Header::request(Command::WRITE);
        let w = WriteRequest {
            file_id: crate::types::FileId::new(1, 2),
            offset: 0,
            data: Bytes::from_static(b"payload"),
            ..Default::default()
        };
        let m = encode_message(&h, &w).unwrap();
        assert_eq!(m.segments().count(), 2);
        let mut f = OutgoingFrame::from_messages([m.clone()]).unwrap();
        let contiguous = f.to_vec();
        assert_eq!(&contiguous[4..], &m.clone().into_contiguous()[..]);
        let mut slices = [IoSlice::new(&[]); 8];
        assert_eq!(f.chunks_vectored(&mut slices), 3);
        // Drain through Buf in odd steps.
        let mut out = Vec::new();
        while f.has_remaining() {
            let n = f.chunk().len().min(5);
            out.extend_from_slice(&f.chunk()[..n]);
            f.advance(n);
        }
        assert_eq!(out, contiguous);
    }

    #[test]
    fn error_detection() {
        let mut h = Header::request(Command::CREATE);
        h.flags = HeaderFlags::SERVER_TO_REDIR;
        h.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let m = encode_error_message(&h, &ErrorResponse::default()).unwrap();
        let raw = RawMessage::parse(m.into_contiguous().freeze()).unwrap();
        assert!(raw.is_error_response());
        assert!(matches!(
            raw.into_result::<CreateResponse>(),
            Err(ProtoError::Status(NtStatus::OBJECT_NAME_NOT_FOUND))
        ));
        // MORE_PROCESSING_REQUIRED on SESSION_SETUP carries a regular body.
        let mut h = Header::request(Command::SESSION_SETUP);
        h.flags = HeaderFlags::SERVER_TO_REDIR;
        h.status = NtStatus::MORE_PROCESSING_REQUIRED;
        let m = encode_message(&h, &SessionSetupResponse::default()).unwrap();
        let raw = RawMessage::parse(m.into_contiguous().freeze()).unwrap();
        assert!(!raw.is_error_response());
        assert!(raw.into_result::<SessionSetupResponse>().is_ok());
    }
}
