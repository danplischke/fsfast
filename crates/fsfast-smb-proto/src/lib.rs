//! I/O-free SMB 2/3 protocol codec, authentication and cryptography.
//!
//! This crate is the foundation of fsfast's SMB client (`fsfast-smb`). It
//! never touches a socket: it turns structures into bytes and bytes into
//! structures, computes signatures and keys, and drives authentication
//! state machines. The client owns connections, credits and sessions.
//!
//! # Layout
//!
//! * [`framing`]: Direct TCP transport framing and a streaming frame decoder.
//! * [`header`]: the 64-byte SMB2 header (sync and async forms).
//! * [`msg`]: every SMB2 message body ([MS-SMB2] §2.2), encode and decode,
//!   with zero-copy payloads; [`msg::RawMessage`] for received messages.
//! * [`compound`]: building compound chains and splitting compound responses.
//! * [`fscc`]: [MS-FSCC] information classes, directory entries, FILETIME
//!   and attribute/access constants.
//! * [`status`]: NTSTATUS codes and their mapping onto
//!   [`fsfast_core::ErrorKind`].
//! * [`crypto`]: SP800-108 KDF, session key derivation, preauth integrity,
//!   signing (HMAC-SHA256, AES-CMAC, AES-GMAC), encryption (AES-CCM/GCM
//!   128/256) and compression transform parsing.
//! * [`auth`]: NTLMv2 and SPNEGO behind the [`auth::Authenticator`] trait.
//!
//! # A request/response round trip
//!
//! ```
//! use bytes::BytesMut;
//! use fsfast_smb_proto::compound::split_compound;
//! use fsfast_smb_proto::framing::FrameDecoder;
//! use fsfast_smb_proto::header::{Command, Header};
//! use fsfast_smb_proto::msg::{encode_message, EchoRequest, EchoResponse, OutgoingFrame};
//!
//! // Client side: encode and frame.
//! let mut h = Header::request(Command::ECHO);
//! h.message_id = 1;
//! let msg = encode_message(&h, &EchoRequest).unwrap();
//! let wire = OutgoingFrame::from_messages([msg]).unwrap().to_vec();
//!
//! // Receiving side: deframe and decode.
//! let mut buf = BytesMut::from(&wire[..]);
//! let frame = FrameDecoder::new().decode(&mut buf).unwrap().unwrap().freeze();
//! let raw = split_compound(frame).next().unwrap().unwrap();
//! assert_eq!(raw.header().message_id, 1);
//! let _: EchoRequest = raw.decode().unwrap();
//! # let _ = EchoResponse;
//! ```
//!
//! [MS-SMB2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/
//! [MS-FSCC]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/

#![warn(missing_docs)]

pub mod auth;
pub mod compound;
pub mod crypto;
pub mod error;
pub mod framing;
pub mod fscc;
pub mod header;
pub mod msg;
pub mod status;
pub mod types;
pub mod wire;

#[cfg(test)]
mod reference_tests;
#[cfg(test)]
#[rustfmt::skip]
mod reference_vectors;

pub use error::{ProtoError, Result};
pub use header::{Command, Header, HeaderFlags, HeaderId};
pub use status::NtStatus;
pub use types::{Capabilities, Dialect, FileId, SecurityMode};
pub use wire::{Guid, Utf16Name};
