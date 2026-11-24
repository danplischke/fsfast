//! NEGOTIATE request/response and negotiate contexts ([MS-SMB2] §2.2.3,
//! §2.2.4).

use bytes::{BufMut, Bytes, BytesMut};

use super::{Message, body_reader, wire_offset};
use crate::error::Result;
use crate::fscc::FileTime;
use crate::header::{Command, HEADER_LEN};
use crate::types::{Capabilities, Dialect, SecurityMode};
use crate::wire::{
    Guid, Reader, decode_utf16le, len_u16, pad_to, padding, patch_u16, patch_u32, put_utf16le,
    slice_bytes,
};

macro_rules! id_newtype {
    ($(#[$m:meta])* $name:ident { $( $(#[$cm:meta])* $c:ident = $v:literal, )* }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
        #[repr(transparent)]
        pub struct $name(pub u16);
        impl $name {
            $( $(#[$cm])* pub const $c: $name = $name($v); )*
        }
    };
}

id_newtype!(
    /// Preauth integrity hash algorithm id.
    HashAlgorithm {
        /// SHA-512 (the only one defined).
        SHA512 = 0x0001,
    }
);

id_newtype!(
    /// Encryption cipher id (ENCRYPTION_CAPABILITIES).
    CipherId {
        /// AES-128-CCM.
        AES_128_CCM = 0x0001,
        /// AES-128-GCM.
        AES_128_GCM = 0x0002,
        /// AES-256-CCM.
        AES_256_CCM = 0x0003,
        /// AES-256-GCM.
        AES_256_GCM = 0x0004,
    }
);

id_newtype!(
    /// Compression algorithm id (COMPRESSION_CAPABILITIES and compression
    /// transform headers).
    CompressionAlgorithm {
        /// No compression.
        NONE = 0x0000,
        /// LZNT1.
        LZNT1 = 0x0001,
        /// Plain LZ77.
        LZ77 = 0x0002,
        /// LZ77 + Huffman.
        LZ77_HUFFMAN = 0x0003,
        /// Pattern scanning (chained only).
        PATTERN_V1 = 0x0004,
        /// LZ4.
        LZ4 = 0x0005,
    }
);

id_newtype!(
    /// Signing algorithm id (SIGNING_CAPABILITIES).
    SigningAlgorithmId {
        /// HMAC-SHA256.
        HMAC_SHA256 = 0x0000,
        /// AES-128-CMAC.
        AES_CMAC = 0x0001,
        /// AES-128-GMAC.
        AES_GMAC = 0x0002,
    }
);

id_newtype!(
    /// RDMA transform id (RDMA_TRANSFORM_CAPABILITIES).
    RdmaTransformId {
        /// No transform.
        NONE = 0x0000,
        /// Encryption.
        ENCRYPTION = 0x0001,
        /// Signing.
        SIGNING = 0x0002,
    }
);

/// Negotiate context type ids.
pub mod context_type {
    /// SMB2_PREAUTH_INTEGRITY_CAPABILITIES.
    pub const PREAUTH_INTEGRITY_CAPABILITIES: u16 = 0x0001;
    /// SMB2_ENCRYPTION_CAPABILITIES.
    pub const ENCRYPTION_CAPABILITIES: u16 = 0x0002;
    /// SMB2_COMPRESSION_CAPABILITIES.
    pub const COMPRESSION_CAPABILITIES: u16 = 0x0003;
    /// SMB2_NETNAME_NEGOTIATE_CONTEXT_ID.
    pub const NETNAME_NEGOTIATE_CONTEXT_ID: u16 = 0x0005;
    /// SMB2_TRANSPORT_CAPABILITIES.
    pub const TRANSPORT_CAPABILITIES: u16 = 0x0006;
    /// SMB2_RDMA_TRANSFORM_CAPABILITIES.
    pub const RDMA_TRANSFORM_CAPABILITIES: u16 = 0x0007;
    /// SMB2_SIGNING_CAPABILITIES.
    pub const SIGNING_CAPABILITIES: u16 = 0x0008;
    /// SMB2_POSIX_EXTENSIONS_AVAILABLE (Samba, kept raw).
    pub const POSIX_EXTENSIONS_AVAILABLE: u16 = 0x0100;
}

/// `SMB2_COMPRESSION_CAPABILITIES_FLAG_CHAINED`.
pub const COMPRESSION_CAPABILITIES_FLAG_CHAINED: u32 = 0x0000_0001;
/// `SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY`.
pub const ACCEPT_TRANSPORT_LEVEL_SECURITY: u32 = 0x0000_0001;

/// A negotiate context ([MS-SMB2] §2.2.3.1). Unknown types are preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiateContext {
    /// SMB2_PREAUTH_INTEGRITY_CAPABILITIES.
    PreauthIntegrity {
        /// Offered (request) or selected (response) hash algorithms.
        hash_algorithms: Vec<HashAlgorithm>,
        /// Random salt.
        salt: Bytes,
    },
    /// SMB2_ENCRYPTION_CAPABILITIES.
    Encryption {
        /// Offered ciphers in preference order, or the selected one.
        ciphers: Vec<CipherId>,
    },
    /// SMB2_COMPRESSION_CAPABILITIES.
    Compression {
        /// Flags (`COMPRESSION_CAPABILITIES_FLAG_CHAINED`).
        flags: u32,
        /// Offered or selected algorithms.
        algorithms: Vec<CompressionAlgorithm>,
    },
    /// SMB2_NETNAME_NEGOTIATE_CONTEXT_ID: the server name the client
    /// connected to.
    NetName(String),
    /// SMB2_TRANSPORT_CAPABILITIES.
    Transport {
        /// Flags (`ACCEPT_TRANSPORT_LEVEL_SECURITY`).
        flags: u32,
    },
    /// SMB2_RDMA_TRANSFORM_CAPABILITIES.
    RdmaTransform {
        /// Offered or selected transforms.
        transform_ids: Vec<RdmaTransformId>,
    },
    /// SMB2_SIGNING_CAPABILITIES.
    Signing {
        /// Offered signing algorithms in preference order, or the selected one.
        algorithms: Vec<SigningAlgorithmId>,
    },
    /// Any other context, kept verbatim.
    Unknown {
        /// Context type.
        context_type: u16,
        /// Raw context data.
        data: Bytes,
    },
}

impl NegotiateContext {
    /// The wire context type.
    pub fn context_type(&self) -> u16 {
        use context_type::*;
        match self {
            NegotiateContext::PreauthIntegrity { .. } => PREAUTH_INTEGRITY_CAPABILITIES,
            NegotiateContext::Encryption { .. } => ENCRYPTION_CAPABILITIES,
            NegotiateContext::Compression { .. } => COMPRESSION_CAPABILITIES,
            NegotiateContext::NetName(_) => NETNAME_NEGOTIATE_CONTEXT_ID,
            NegotiateContext::Transport { .. } => TRANSPORT_CAPABILITIES,
            NegotiateContext::RdmaTransform { .. } => RDMA_TRANSFORM_CAPABILITIES,
            NegotiateContext::Signing { .. } => SIGNING_CAPABILITIES,
            NegotiateContext::Unknown { context_type, .. } => *context_type,
        }
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u16_le(self.context_type());
        let len_pos = dst.len();
        dst.put_u16_le(0);
        dst.put_u32_le(0);
        let data_start = dst.len();
        match self {
            NegotiateContext::PreauthIntegrity { hash_algorithms, salt } => {
                dst.put_u16_le(len_u16(hash_algorithms.len(), "too many hash algorithms")?);
                dst.put_u16_le(len_u16(salt.len(), "salt too long")?);
                for h in hash_algorithms {
                    dst.put_u16_le(h.0);
                }
                dst.put_slice(salt);
            }
            NegotiateContext::Encryption { ciphers } => {
                dst.put_u16_le(len_u16(ciphers.len(), "too many ciphers")?);
                for c in ciphers {
                    dst.put_u16_le(c.0);
                }
            }
            NegotiateContext::Compression { flags, algorithms } => {
                dst.put_u16_le(len_u16(algorithms.len(), "too many compression algorithms")?);
                dst.put_u16_le(0);
                dst.put_u32_le(*flags);
                for a in algorithms {
                    dst.put_u16_le(a.0);
                }
            }
            NegotiateContext::NetName(name) => put_utf16le(dst, name),
            NegotiateContext::Transport { flags } => dst.put_u32_le(*flags),
            NegotiateContext::RdmaTransform { transform_ids } => {
                dst.put_u16_le(len_u16(transform_ids.len(), "too many RDMA transforms")?);
                dst.put_u16_le(0);
                dst.put_u32_le(0);
                for t in transform_ids {
                    dst.put_u16_le(t.0);
                }
            }
            NegotiateContext::Signing { algorithms } => {
                dst.put_u16_le(len_u16(algorithms.len(), "too many signing algorithms")?);
                for a in algorithms {
                    dst.put_u16_le(a.0);
                }
            }
            NegotiateContext::Unknown { data, .. } => dst.put_slice(data),
        }
        let len = len_u16(dst.len() - data_start, "negotiate context too long")?;
        patch_u16(dst, len_pos, len);
        Ok(())
    }

    fn decode(context_type: u16, data: Bytes) -> Result<Self> {
        use context_type::*;
        const W: &str = "negotiate context";
        let mut r = Reader::new(&data, W);
        let ids = |r: &mut Reader<'_>, n: usize| -> Result<Vec<u16>> {
            (0..n).map(|_| r.u16()).collect()
        };
        Ok(match context_type {
            PREAUTH_INTEGRITY_CAPABILITIES => {
                let n = usize::from(r.u16()?);
                let salt_len = usize::from(r.u16()?);
                let hash_algorithms = ids(&mut r, n)?.into_iter().map(HashAlgorithm).collect();
                let pos = r.pos();
                r.skip(salt_len)?;
                NegotiateContext::PreauthIntegrity {
                    hash_algorithms,
                    salt: data.slice(pos..pos + salt_len),
                }
            }
            ENCRYPTION_CAPABILITIES => {
                let n = usize::from(r.u16()?);
                NegotiateContext::Encryption {
                    ciphers: ids(&mut r, n)?.into_iter().map(CipherId).collect(),
                }
            }
            COMPRESSION_CAPABILITIES => {
                let n = usize::from(r.u16()?);
                r.skip(2)?;
                let flags = r.u32()?;
                NegotiateContext::Compression {
                    flags,
                    algorithms: ids(&mut r, n)?.into_iter().map(CompressionAlgorithm).collect(),
                }
            }
            NETNAME_NEGOTIATE_CONTEXT_ID => {
                // Some servers NUL-terminate the name; strip trailing NULs.
                let mut b = &data[..data.len() & !1];
                while b.ends_with(&[0, 0]) {
                    b = &b[..b.len() - 2];
                }
                NegotiateContext::NetName(decode_utf16le(b, "netname context")?)
            }
            TRANSPORT_CAPABILITIES => NegotiateContext::Transport { flags: r.u32()? },
            RDMA_TRANSFORM_CAPABILITIES => {
                let n = usize::from(r.u16()?);
                r.skip(6)?;
                NegotiateContext::RdmaTransform {
                    transform_ids: ids(&mut r, n)?.into_iter().map(RdmaTransformId).collect(),
                }
            }
            SIGNING_CAPABILITIES => {
                let n = usize::from(r.u16()?);
                NegotiateContext::Signing {
                    algorithms: ids(&mut r, n)?.into_iter().map(SigningAlgorithmId).collect(),
                }
            }
            _ => NegotiateContext::Unknown { context_type, data },
        })
    }
}

/// Encode a context list (8-byte aligned, relative to the header start).
/// `body_start` is the position of the body's first byte in `dst`.
fn encode_contexts(dst: &mut BytesMut, contexts: &[NegotiateContext]) -> Result<()> {
    for (i, c) in contexts.iter().enumerate() {
        if i > 0 {
            pad_to(dst, 8);
        }
        c.encode(dst)?;
    }
    Ok(())
}

/// Decode `count` contexts starting at `offset` (relative to the header).
fn decode_contexts(msg: &Bytes, offset: usize, count: usize) -> Result<Vec<NegotiateContext>> {
    const W: &str = "negotiate context list";
    let mut out = Vec::with_capacity(count.min(16));
    let mut pos = offset;
    for i in 0..count {
        if i > 0 {
            pos += padding(pos, 8);
        }
        let hdr = slice_bytes(msg, pos, 8, W)?;
        let ctype = u16::from_le_bytes([hdr[0], hdr[1]]);
        let len = usize::from(u16::from_le_bytes([hdr[2], hdr[3]]));
        let data = slice_bytes(msg, pos + 8, len, W)?;
        out.push(NegotiateContext::decode(ctype, data)?);
        pos += 8 + len;
    }
    Ok(out)
}

/// The position in `dst` where a buffer must start so that it is 8-byte
/// aligned relative to the header (the body starts 64 bytes after the header,
/// which keeps alignment).
fn align_body(dst: &mut BytesMut, body_start: usize) {
    let pad = padding(dst.len() - body_start, 8);
    dst.put_bytes(0, pad);
}

/// SMB2 NEGOTIATE request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NegotiateRequest {
    /// Client security mode.
    pub security_mode: SecurityMode,
    /// Client capabilities.
    pub capabilities: Capabilities,
    /// Client GUID (must be stable per client for 2.1+).
    pub client_guid: Guid,
    /// Offered dialects.
    pub dialects: Vec<Dialect>,
    /// Negotiate contexts (3.1.1 only; must be empty unless 3.1.1 is offered).
    pub negotiate_contexts: Vec<NegotiateContext>,
}

impl Message for NegotiateRequest {
    const COMMAND: Command = Command::NEGOTIATE;
    const RESPONSE: bool = false;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        let start = dst.len();
        dst.put_u16_le(36);
        dst.put_u16_le(len_u16(self.dialects.len(), "too many dialects")?);
        dst.put_u16_le(self.security_mode.bits());
        dst.put_u16_le(0);
        dst.put_u32_le(self.capabilities.bits());
        dst.put_slice(&self.client_guid.0);
        let ctx_off_pos = dst.len();
        // NegotiateContextOffset/Count/Reserved2, or ClientStartTime (0).
        dst.put_u64_le(0);
        for d in &self.dialects {
            dst.put_u16_le(d.0);
        }
        if !self.negotiate_contexts.is_empty() {
            align_body(dst, start);
            let off = wire_offset(start, dst) as u32;
            patch_u32(dst, ctx_off_pos, off);
            patch_u16(
                dst,
                ctx_off_pos + 4,
                len_u16(self.negotiate_contexts.len(), "too many negotiate contexts")?,
            );
            encode_contexts(dst, &self.negotiate_contexts)?;
        }
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "NEGOTIATE request", 36)?;
        let n = usize::from(r.u16()?);
        let security_mode = SecurityMode::from_bits_retain(r.u16()?);
        r.skip(2)?;
        let capabilities = Capabilities::from_bits_retain(r.u32()?);
        let client_guid = r.guid()?;
        let ctx_off = r.u32()? as usize;
        let ctx_count = usize::from(r.u16()?);
        r.skip(2)?;
        let dialects: Vec<Dialect> = (0..n).map(|_| r.u16().map(Dialect)).collect::<Result<_>>()?;
        let negotiate_contexts = if dialects.contains(&Dialect::SMB_3_1_1) && ctx_count > 0 {
            decode_contexts(msg, ctx_off, ctx_count)?
        } else {
            Vec::new()
        };
        Ok(NegotiateRequest { security_mode, capabilities, client_guid, dialects, negotiate_contexts })
    }
}

/// SMB2 NEGOTIATE response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NegotiateResponse {
    /// Server security mode.
    pub security_mode: SecurityMode,
    /// Selected dialect (`0x02FF` in a multi-protocol wildcard response).
    pub dialect_revision: Dialect,
    /// Server GUID.
    pub server_guid: Guid,
    /// Server capabilities.
    pub capabilities: Capabilities,
    /// Maximum size of a QUERY_INFO/SET_INFO/IOCTL/QUERY_DIRECTORY buffer.
    pub max_transact_size: u32,
    /// Maximum READ length.
    pub max_read_size: u32,
    /// Maximum WRITE length.
    pub max_write_size: u32,
    /// Server system time.
    pub system_time: FileTime,
    /// Server start time (0 for most servers).
    pub server_start_time: FileTime,
    /// GSS token hinting the supported mechanisms (SPNEGO NegTokenInit2).
    pub security_buffer: Bytes,
    /// Negotiate contexts (3.1.1).
    pub negotiate_contexts: Vec<NegotiateContext>,
}

impl NegotiateResponse {
    /// The selected preauth hash algorithm and salt (3.1.1).
    pub fn preauth_integrity(&self) -> Option<(HashAlgorithm, &Bytes)> {
        self.negotiate_contexts.iter().find_map(|c| match c {
            NegotiateContext::PreauthIntegrity { hash_algorithms, salt } => {
                hash_algorithms.first().map(|h| (*h, salt))
            }
            _ => None,
        })
    }

    /// The selected cipher (3.1.1). `CipherId(0)` means no common cipher.
    pub fn cipher(&self) -> Option<CipherId> {
        self.negotiate_contexts.iter().find_map(|c| match c {
            NegotiateContext::Encryption { ciphers } => ciphers.first().copied(),
            _ => None,
        })
    }

    /// The selected signing algorithm (3.1.1 with SIGNING_CAPABILITIES).
    pub fn signing_algorithm(&self) -> Option<SigningAlgorithmId> {
        self.negotiate_contexts.iter().find_map(|c| match c {
            NegotiateContext::Signing { algorithms } => algorithms.first().copied(),
            _ => None,
        })
    }

    /// The selected compression algorithms and flags (3.1.1).
    pub fn compression(&self) -> Option<(u32, &[CompressionAlgorithm])> {
        self.negotiate_contexts.iter().find_map(|c| match c {
            NegotiateContext::Compression { flags, algorithms } => Some((*flags, &algorithms[..])),
            _ => None,
        })
    }
}

impl Message for NegotiateResponse {
    const COMMAND: Command = Command::NEGOTIATE;
    const RESPONSE: bool = true;

    fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        let start = dst.len();
        let has_ctx = !self.negotiate_contexts.is_empty();
        dst.put_u16_le(65);
        dst.put_u16_le(self.security_mode.bits());
        dst.put_u16_le(self.dialect_revision.0);
        dst.put_u16_le(if has_ctx {
            len_u16(self.negotiate_contexts.len(), "too many negotiate contexts")?
        } else {
            0
        });
        dst.put_slice(&self.server_guid.0);
        dst.put_u32_le(self.capabilities.bits());
        dst.put_u32_le(self.max_transact_size);
        dst.put_u32_le(self.max_read_size);
        dst.put_u32_le(self.max_write_size);
        dst.put_u64_le(self.system_time.0);
        dst.put_u64_le(self.server_start_time.0);
        let sec_off = HEADER_LEN + 64;
        dst.put_u16_le(if self.security_buffer.is_empty() { 0 } else { sec_off as u16 });
        dst.put_u16_le(len_u16(self.security_buffer.len(), "security buffer too long")?);
        let ctx_off_pos = dst.len();
        dst.put_u32_le(0);
        dst.put_slice(&self.security_buffer);
        if has_ctx {
            align_body(dst, start);
            let off = wire_offset(start, dst) as u32;
            patch_u32(dst, ctx_off_pos, off);
            encode_contexts(dst, &self.negotiate_contexts)?;
        }
        Ok(())
    }

    fn decode_body(msg: &Bytes) -> Result<Self> {
        let mut r = body_reader(msg, "NEGOTIATE response", 65)?;
        let security_mode = SecurityMode::from_bits_retain(r.u16()?);
        let dialect_revision = Dialect(r.u16()?);
        let ctx_count = usize::from(r.u16()?);
        let server_guid = r.guid()?;
        let capabilities = Capabilities::from_bits_retain(r.u32()?);
        let max_transact_size = r.u32()?;
        let max_read_size = r.u32()?;
        let max_write_size = r.u32()?;
        let system_time = FileTime(r.u64()?);
        let server_start_time = FileTime(r.u64()?);
        let sec_off = usize::from(r.u16()?);
        let sec_len = usize::from(r.u16()?);
        let ctx_off = r.u32()? as usize;
        let security_buffer = slice_bytes(msg, sec_off, sec_len, "NEGOTIATE security buffer")?;
        let negotiate_contexts = if dialect_revision == Dialect::SMB_3_1_1 && ctx_count > 0 {
            decode_contexts(msg, ctx_off, ctx_count)?
        } else {
            Vec::new()
        };
        Ok(NegotiateResponse {
            security_mode,
            dialect_revision,
            server_guid,
            capabilities,
            max_transact_size,
            max_read_size,
            max_write_size,
            system_time,
            server_start_time,
            security_buffer,
            negotiate_contexts,
        })
    }
}

/// A legacy SMB1 `SMB_COM_NEGOTIATE` offering "SMB 2.002" and "SMB 2.???",
/// used to probe servers that only answer multi-protocol negotiation
/// ([MS-SMB2] §3.2.4.2.1). Returns the complete message (no transport header).
pub fn smb1_multi_protocol_negotiate() -> Bytes {
    let dialects: &[u8] = b"\x02NT LM 0.12\0\x02SMB 2.002\0\x02SMB 2.???\0";
    let mut b = BytesMut::with_capacity(35 + dialects.len());
    b.put_slice(&crate::header::SMB1_PROTOCOL_ID);
    b.put_u8(0x72); // SMB_COM_NEGOTIATE
    b.put_u32_le(0); // status
    b.put_u8(0x18); // flags: case-insensitive, canonicalized paths
    b.put_u16_le(0xC853); // flags2: unicode, NT status, extended security, long names
    b.put_bytes(0, 12); // PIDHigh, SecurityFeatures, Reserved
    b.put_u16_le(0xFFFF); // TID
    b.put_u16_le(0xFEFF); // PIDLow
    b.put_u16_le(0); // UID
    b.put_u16_le(0); // MID
    b.put_u8(0); // WordCount
    b.put_u16_le(dialects.len() as u16);
    b.put_slice(dialects);
    b.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::Header;
    use crate::msg::{RawMessage, encode_message};

    fn round_trip<M: Message + PartialEq + std::fmt::Debug>(m: &M, response: bool) -> M {
        let mut h = Header::request(M::COMMAND);
        if response {
            h.flags = crate::header::HeaderFlags::SERVER_TO_REDIR;
        }
        let enc = encode_message(&h, m).unwrap().into_contiguous().freeze();
        RawMessage::parse(enc).unwrap().decode::<M>().unwrap()
    }

    #[test]
    fn request_round_trip_with_contexts() {
        let req = NegotiateRequest {
            security_mode: SecurityMode::SIGNING_ENABLED,
            capabilities: Capabilities::DFS | Capabilities::LARGE_MTU | Capabilities::ENCRYPTION,
            client_guid: Guid([7; 16]),
            dialects: Dialect::ALL.to_vec(),
            negotiate_contexts: vec![
                NegotiateContext::PreauthIntegrity {
                    hash_algorithms: vec![HashAlgorithm::SHA512],
                    salt: Bytes::from_static(&[1; 32]),
                },
                NegotiateContext::Encryption {
                    ciphers: vec![CipherId::AES_128_GCM, CipherId::AES_128_CCM],
                },
                NegotiateContext::NetName("server".into()),
                NegotiateContext::Signing {
                    algorithms: vec![SigningAlgorithmId::AES_GMAC, SigningAlgorithmId::AES_CMAC],
                },
                NegotiateContext::Compression {
                    flags: COMPRESSION_CAPABILITIES_FLAG_CHAINED,
                    algorithms: vec![CompressionAlgorithm::LZ77, CompressionAlgorithm::PATTERN_V1],
                },
                NegotiateContext::Transport { flags: ACCEPT_TRANSPORT_LEVEL_SECURITY },
                NegotiateContext::RdmaTransform { transform_ids: vec![RdmaTransformId::ENCRYPTION] },
                NegotiateContext::Unknown { context_type: 0x100, data: Bytes::from_static(b"abc") },
            ],
        };
        assert_eq!(round_trip(&req, false), req);
    }

    #[test]
    fn request_without_contexts() {
        let req = NegotiateRequest {
            dialects: vec![Dialect::SMB_2_0_2, Dialect::SMB_2_1],
            ..Default::default()
        };
        assert_eq!(round_trip(&req, false), req);
    }

    #[test]
    fn response_round_trip() {
        let resp = NegotiateResponse {
            security_mode: SecurityMode::SIGNING_ENABLED | SecurityMode::SIGNING_REQUIRED,
            dialect_revision: Dialect::SMB_3_1_1,
            server_guid: Guid([3; 16]),
            capabilities: Capabilities::LARGE_MTU,
            max_transact_size: 8 << 20,
            max_read_size: 8 << 20,
            max_write_size: 8 << 20,
            system_time: FileTime(133_000_000_000_000_000),
            server_start_time: FileTime(0),
            security_buffer: Bytes::from_static(b"\x60\x03\x06\x01\x00"),
            negotiate_contexts: vec![
                NegotiateContext::PreauthIntegrity {
                    hash_algorithms: vec![HashAlgorithm::SHA512],
                    salt: Bytes::from_static(&[9; 32]),
                },
                NegotiateContext::Encryption { ciphers: vec![CipherId::AES_128_GCM] },
                NegotiateContext::Signing { algorithms: vec![SigningAlgorithmId::AES_GMAC] },
            ],
        };
        let d = round_trip(&resp, true);
        assert_eq!(d, resp);
        assert_eq!(d.cipher(), Some(CipherId::AES_128_GCM));
        assert_eq!(d.signing_algorithm(), Some(SigningAlgorithmId::AES_GMAC));
        assert_eq!(d.preauth_integrity().unwrap().0, HashAlgorithm::SHA512);
    }

    #[test]
    fn smb1_probe_shape() {
        let p = smb1_multi_protocol_negotiate();
        assert_eq!(&p[..4], b"\xFFSMB");
        assert!(p.ends_with(b"SMB 2.???\0"));
    }
}
