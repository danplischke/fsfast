//! SMB2 message signing and verification ([MS-SMB2] §3.1.4.1).
//!
//! | dialect | algorithm |
//! |---|---|
//! | 2.0.2, 2.1 | HMAC-SHA256, truncated to 16 bytes |
//! | 3.0, 3.0.2, 3.1.1 without SIGNING_CAPABILITIES | AES-128-CMAC |
//! | 3.1.1 with SIGNING_CAPABILITIES | the negotiated one (AES-128-GMAC preferred) |
//!
//! The signature covers the whole message (header with a zeroed signature
//! field, body, payload and — inside compound chains — the padding). The
//! GMAC nonce is the MessageId followed by a 32-bit word whose bit 0 marks a
//! server-to-client message and bit 1 a CANCEL request.

use aes::Aes128;
use cmac::Cmac;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::gmac::GmacKey;
use crate::error::{ProtoError, Result};
use crate::header::{
    Command, FLAGS_OFFSET, HEADER_LEN, HeaderFlags, MESSAGE_ID_OFFSET, SIGNATURE_OFFSET,
};
use crate::msg::{EncodedMessage, SigningAlgorithmId};
use crate::types::Dialect;

/// A signing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningAlgorithm {
    /// HMAC-SHA256 (SMB 2.x).
    HmacSha256,
    /// AES-128-CMAC (SMB 3.x).
    AesCmac,
    /// AES-128-GMAC (SMB 3.1.1 with signing capabilities).
    AesGmac,
}

impl SigningAlgorithm {
    /// The wire id used in SIGNING_CAPABILITIES.
    pub fn id(self) -> SigningAlgorithmId {
        match self {
            SigningAlgorithm::HmacSha256 => SigningAlgorithmId::HMAC_SHA256,
            SigningAlgorithm::AesCmac => SigningAlgorithmId::AES_CMAC,
            SigningAlgorithm::AesGmac => SigningAlgorithmId::AES_GMAC,
        }
    }

    /// Map a wire id.
    pub fn from_id(id: SigningAlgorithmId) -> Option<Self> {
        Some(match id {
            SigningAlgorithmId::HMAC_SHA256 => SigningAlgorithm::HmacSha256,
            SigningAlgorithmId::AES_CMAC => SigningAlgorithm::AesCmac,
            SigningAlgorithmId::AES_GMAC => SigningAlgorithm::AesGmac,
            _ => return None,
        })
    }

    /// The algorithm a connection uses: the negotiated one for 3.1.1 with
    /// SIGNING_CAPABILITIES, AES-CMAC for other 3.x, HMAC-SHA256 for 2.x.
    pub fn for_dialect(dialect: Dialect, negotiated: Option<SigningAlgorithmId>) -> Result<Self> {
        if dialect.is_3_1_1()
            && let Some(id) = negotiated
        {
            return Self::from_id(id)
                .ok_or(ProtoError::Unsupported("negotiated signing algorithm"));
        }
        Ok(if dialect.is_smb3() {
            SigningAlgorithm::AesCmac
        } else {
            SigningAlgorithm::HmacSha256
        })
    }
}

#[derive(Clone)]
enum Keyed {
    Hmac(Hmac<Sha256>),
    Cmac(Cmac<Aes128>),
    Gmac(GmacKey),
}

// One per signature, on the stack for a single MAC pass: boxing the CMAC
// state would add a heap allocation to every signed message.
#[allow(clippy::large_enum_variant)]
enum Running {
    Hmac(Hmac<Sha256>),
    Cmac(Cmac<Aes128>),
    Gmac(super::gmac::Gmac),
}

impl Running {
    fn update(&mut self, d: &[u8]) {
        match self {
            Running::Hmac(m) => m.update(d),
            Running::Cmac(m) => m.update(d),
            Running::Gmac(m) => m.update(d),
        }
    }

    fn finalize(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        match self {
            Running::Hmac(m) => out.copy_from_slice(&m.finalize().into_bytes()[..16]),
            Running::Cmac(m) => out.copy_from_slice(&m.finalize().into_bytes()),
            Running::Gmac(m) => out = m.finalize(),
        }
        out
    }
}

/// A keyed signer for one session (or channel).
///
/// Key schedules are computed once; per message the signer clones the
/// keyed state (a memcpy) and runs one MAC pass over the message parts.
#[derive(Clone)]
pub struct Signer {
    alg: SigningAlgorithm,
    keyed: Keyed,
    _key: Zeroizing<[u8; 16]>,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("algorithm", &self.alg)
            .finish_non_exhaustive()
    }
}

impl Signer {
    /// A signer for `alg` with a 16-byte signing key.
    pub fn new(alg: SigningAlgorithm, key: &[u8]) -> Result<Self> {
        let key: [u8; 16] = key
            .try_into()
            .map_err(|_| ProtoError::InvalidInput("signing key must be 16 bytes"))?;
        let keyed = match alg {
            SigningAlgorithm::HmacSha256 => Keyed::Hmac(
                <Hmac<Sha256> as KeyInit>::new_from_slice(&key)
                    .expect("HMAC accepts any key length"),
            ),
            SigningAlgorithm::AesCmac => Keyed::Cmac(
                <Cmac<Aes128> as KeyInit>::new_from_slice(&key).expect("16-byte AES key"),
            ),
            SigningAlgorithm::AesGmac => Keyed::Gmac(GmacKey::new(&key)),
        };
        Ok(Signer {
            alg,
            keyed,
            _key: Zeroizing::new(key),
        })
    }

    /// The algorithm.
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.alg
    }

    /// Compute the signature of a message given as consecutive parts. The
    /// first part must contain at least the 64-byte header; its signature
    /// field is treated as zero.
    pub fn compute(&self, parts: &[&[u8]]) -> Result<[u8; 16]> {
        let first = parts.first().copied().unwrap_or_default();
        if first.len() < HEADER_LEN {
            return Err(ProtoError::Truncated {
                what: "signed message",
                need: HEADER_LEN,
                have: first.len(),
            });
        }
        let mut hdr = [0u8; HEADER_LEN];
        hdr.copy_from_slice(&first[..HEADER_LEN]);
        hdr[SIGNATURE_OFFSET..].fill(0);
        let mut m = match &self.keyed {
            Keyed::Hmac(k) => Running::Hmac(k.clone()),
            Keyed::Cmac(k) => Running::Cmac(k.clone()),
            Keyed::Gmac(k) => Running::Gmac(k.start(&gmac_nonce(&hdr))),
        };
        m.update(&hdr);
        m.update(&first[HEADER_LEN..]);
        for p in &parts[1..] {
            m.update(p);
        }
        Ok(m.finalize())
    }

    /// Sign an encoded message in place: sets `SMB2_FLAGS_SIGNED` and writes
    /// the signature. Call after the compound chain is final.
    pub fn sign(&self, msg: &mut EncodedMessage) -> Result<()> {
        set_signed_flag(&mut msg.head);
        let sig = {
            let parts: Vec<&[u8]> = msg.segments().collect();
            self.compute(&parts)?
        };
        msg.head[SIGNATURE_OFFSET..HEADER_LEN].copy_from_slice(&sig);
        Ok(())
    }

    /// Sign a contiguous message buffer in place.
    pub fn sign_in_place(&self, msg: &mut [u8]) -> Result<()> {
        if msg.len() < HEADER_LEN {
            return Err(ProtoError::Truncated {
                what: "signed message",
                need: HEADER_LEN,
                have: msg.len(),
            });
        }
        set_signed_flag(msg);
        let sig = self.compute(&[msg])?;
        msg[SIGNATURE_OFFSET..HEADER_LEN].copy_from_slice(&sig);
        Ok(())
    }

    /// Verify the signature of a received message (the exact bytes of one
    /// compound member, see [`RawMessage::bytes`](crate::msg::RawMessage::bytes)).
    /// The comparison is constant time.
    ///
    /// Do not call this for messages that arrived inside a TRANSFORM_HEADER:
    /// they are authenticated by the AEAD tag and their signature is not
    /// verified ([MS-SMB2] §3.2.5.1.3). Servers may still set
    /// `SMB2_FLAGS_SIGNED` on them without a valid signature (Samba does
    /// on the encrypted `STATUS_ACCESS_DENIED` it returns for an
    /// unencrypted request on an encryption-required share).
    pub fn verify(&self, msg: &[u8]) -> Result<()> {
        if msg.len() < HEADER_LEN {
            return Err(ProtoError::Truncated {
                what: "signed message",
                need: HEADER_LEN,
                have: msg.len(),
            });
        }
        let expected = self.compute(&[msg])?;
        if bool::from(expected.ct_eq(&msg[SIGNATURE_OFFSET..HEADER_LEN])) {
            Ok(())
        } else {
            Err(ProtoError::BadSignature)
        }
    }
}

fn set_signed_flag(head: &mut [u8]) {
    let mut f = [0u8; 4];
    f.copy_from_slice(&head[FLAGS_OFFSET..FLAGS_OFFSET + 4]);
    let flags = u32::from_le_bytes(f) | HeaderFlags::SIGNED.bits();
    head[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&flags.to_le_bytes());
}

/// AES-GMAC nonce ([MS-SMB2] §3.1.4.1): MessageId, then a 32-bit word with
/// bit 0 = server-to-client, bit 1 = CANCEL request.
fn gmac_nonce(hdr: &[u8; HEADER_LEN]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&hdr[MESSAGE_ID_OFFSET..MESSAGE_ID_OFFSET + 8]);
    let flags = u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]);
    let command = u16::from_le_bytes([hdr[12], hdr[13]]);
    let mut info = 0u32;
    if flags & HeaderFlags::SERVER_TO_REDIR.bits() != 0 {
        info |= 1;
    }
    if command == Command::CANCEL.0 && flags & HeaderFlags::SERVER_TO_REDIR.bits() == 0 {
        info |= 2;
    }
    nonce[8..].copy_from_slice(&info.to_le_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::Header;
    use crate::msg::{WriteRequest, encode_message};
    use bytes::Bytes;

    #[test]
    fn sign_verify_all_algorithms() {
        for alg in [
            SigningAlgorithm::HmacSha256,
            SigningAlgorithm::AesCmac,
            SigningAlgorithm::AesGmac,
        ] {
            let s = Signer::new(alg, &[3u8; 16]).unwrap();
            let w = WriteRequest {
                data: Bytes::from(vec![9u8; 1000]),
                ..Default::default()
            };
            let mut h = Header::request(Command::WRITE);
            h.message_id = 77;
            let mut m = encode_message(&h, &w).unwrap();
            s.sign(&mut m).unwrap();
            let mut contiguous = m.clone().into_contiguous();
            assert!(Header::decode(&contiguous).unwrap().is_signed());
            s.verify(&contiguous).unwrap();
            // Contiguous signing yields the same signature.
            let mut again = contiguous.clone();
            again[SIGNATURE_OFFSET..HEADER_LEN].fill(0);
            s.sign_in_place(&mut again).unwrap();
            assert_eq!(again, contiguous);
            // Any bit flip is detected.
            let last = contiguous.len() - 1;
            contiguous[last] ^= 1;
            assert_eq!(s.verify(&contiguous), Err(ProtoError::BadSignature));
        }
    }

    #[test]
    fn gmac_nonce_bits() {
        let mut h = Header::request(Command::CANCEL);
        h.message_id = 0x0102030405060708;
        let n = gmac_nonce(&h.to_bytes());
        assert_eq!(&n[..8], &0x0102030405060708u64.to_le_bytes());
        assert_eq!(&n[8..], &[2, 0, 0, 0]);
        h.command = Command::READ;
        h.flags = HeaderFlags::SERVER_TO_REDIR;
        assert_eq!(&gmac_nonce(&h.to_bytes())[8..], &[1, 0, 0, 0]);
    }

    #[test]
    fn algorithm_selection() {
        use SigningAlgorithm::*;
        assert_eq!(
            SigningAlgorithm::for_dialect(Dialect::SMB_2_1, None).unwrap(),
            HmacSha256
        );
        assert_eq!(
            SigningAlgorithm::for_dialect(Dialect::SMB_3_0_2, None).unwrap(),
            AesCmac
        );
        assert_eq!(
            SigningAlgorithm::for_dialect(Dialect::SMB_3_1_1, None).unwrap(),
            AesCmac
        );
        assert_eq!(
            SigningAlgorithm::for_dialect(Dialect::SMB_3_1_1, Some(SigningAlgorithmId::AES_GMAC))
                .unwrap(),
            AesGmac
        );
        assert!(Signer::new(AesCmac, &[0; 15]).is_err());
    }
}
