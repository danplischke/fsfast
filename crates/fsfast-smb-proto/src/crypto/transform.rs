//! SMB 3.x encryption: the TRANSFORM_HEADER ([MS-SMB2] §2.2.41) with
//! AES-128/256-CCM and AES-128/256-GCM ([MS-SMB2] §3.1.4.3).
//!
//! The AAD is the transform header from `Nonce` onward (32 bytes); CCM uses
//! an 11-byte nonce and GCM a 12-byte nonce, both zero-padded to 16 bytes in
//! the header. Encryption copies the plaintext once into the output frame
//! and encrypts it in place; decryption works in place on the received
//! frame ([`SmbCipher::decrypt_in_place`]) or straight into caller memory
//! ([`SmbCipher::decrypt_into`]) without an intermediate buffer.

use std::sync::atomic::{AtomicU64, Ordering};

use aes::cipher::{BlockCipherEncrypt, InnerIvInit, StreamCipher};
use aes::{Aes128, Aes256};
use aes_gcm::aead::consts::{U11, U16};
use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use bytes::{BufMut, BytesMut};
use ccm::Ccm;
use ghash::GHash;
use ghash::universal_hash::UniversalHash;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{ProtoError, Result};
use crate::header::TRANSFORM_PROTOCOL_ID;
use crate::msg::{CipherId, EncodedMessage};
use crate::wire::Reader;

/// Size of the TRANSFORM_HEADER.
pub const TRANSFORM_HEADER_LEN: usize = 52;
/// Offset of the AAD (the `Nonce` field) in the transform header.
const AAD_OFFSET: usize = 20;
/// `Flags` value "encrypted" (3.1.1) / `EncryptionAlgorithm` AES-128-CCM (3.0).
pub const TRANSFORM_FLAG_ENCRYPTED: u16 = 0x0001;

type Aes128Ccm = Ccm<Aes128, U16, U11>;
type Aes256Ccm = Ccm<Aes256, U16, U11>;

/// An SMB encryption cipher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cipher {
    /// AES-128-CCM (the only cipher of 3.0/3.0.2).
    Aes128Ccm,
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-CCM.
    Aes256Ccm,
    /// AES-256-GCM.
    Aes256Gcm,
}

impl Cipher {
    /// Wire id.
    pub fn id(self) -> CipherId {
        match self {
            Cipher::Aes128Ccm => CipherId::AES_128_CCM,
            Cipher::Aes128Gcm => CipherId::AES_128_GCM,
            Cipher::Aes256Ccm => CipherId::AES_256_CCM,
            Cipher::Aes256Gcm => CipherId::AES_256_GCM,
        }
    }

    /// Map a wire id (`None` for 0 = no common cipher, or unknown ids).
    pub fn from_id(id: CipherId) -> Option<Self> {
        Some(match id {
            CipherId::AES_128_CCM => Cipher::Aes128Ccm,
            CipherId::AES_128_GCM => Cipher::Aes128Gcm,
            CipherId::AES_256_CCM => Cipher::Aes256Ccm,
            CipherId::AES_256_GCM => Cipher::Aes256Gcm,
            _ => return None,
        })
    }

    /// Key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Cipher::Aes128Ccm | Cipher::Aes128Gcm => 16,
            Cipher::Aes256Ccm | Cipher::Aes256Gcm => 32,
        }
    }

    /// Nonce length in bytes (11 for CCM, 12 for GCM).
    pub fn nonce_len(self) -> usize {
        match self {
            Cipher::Aes128Ccm | Cipher::Aes256Ccm => 11,
            Cipher::Aes128Gcm | Cipher::Aes256Gcm => 12,
        }
    }
}

/// A decoded TRANSFORM_HEADER.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransformHeader {
    /// AEAD tag.
    pub signature: [u8; 16],
    /// Nonce, zero-padded to 16 bytes.
    pub nonce: [u8; 16],
    /// Size of the plaintext.
    pub original_message_size: u32,
    /// `Flags` / `EncryptionAlgorithm` (must be 1).
    pub flags: u16,
    /// Session whose keys protect the message.
    pub session_id: u64,
}

impl TransformHeader {
    /// Encode into 52 bytes.
    pub fn to_bytes(&self) -> [u8; TRANSFORM_HEADER_LEN] {
        let mut b = [0u8; TRANSFORM_HEADER_LEN];
        b[..4].copy_from_slice(&TRANSFORM_PROTOCOL_ID);
        b[4..20].copy_from_slice(&self.signature);
        b[20..36].copy_from_slice(&self.nonce);
        b[36..40].copy_from_slice(&self.original_message_size.to_le_bytes());
        b[42..44].copy_from_slice(&self.flags.to_le_bytes());
        b[44..52].copy_from_slice(&self.session_id.to_le_bytes());
        b
    }

    /// Decode from the start of `buf`.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "TRANSFORM_HEADER");
        if r.array::<4>()? != TRANSFORM_PROTOCOL_ID {
            return Err(r.malformed("bad protocol id"));
        }
        let signature = r.array()?;
        let nonce = r.array()?;
        let original_message_size = r.u32()?;
        r.skip(2)?;
        let flags = r.u16()?;
        let session_id = r.u64()?;
        Ok(TransformHeader {
            signature,
            nonce,
            original_message_size,
            flags,
            session_id,
        })
    }
}

enum Aead {
    Ccm128(Box<Aes128Ccm>),
    Gcm128(Box<Aes128Gcm>),
    Ccm256(Box<Aes256Ccm>),
    Gcm256(Box<Aes256Gcm>),
}

/// A keyed SMB cipher for one direction of one session.
///
/// Nonces are a random per-instance prefix (32 bits for GCM, 24 bits for
/// CCM) followed by a 64-bit counter that starts at a random value below
/// 2^63 and only ever increments, so one instance never repeats a nonce
/// (it fails instead of wrapping). The random counter start also keeps
/// nonces apart when several instances exist for the same key, even if
/// their prefixes collide. Still, create exactly one encrypting
/// `SmbCipher` per session and share it: the counter is atomic, so
/// concurrent senders and all channels of a multichannel session (which
/// share `Session.EncryptionKey`) can use the same instance.
pub struct SmbCipher {
    cipher: Cipher,
    aead: Aead,
    /// Expanded AES key and GHASH key for [`SmbCipher::decrypt_into_parts`]
    /// (GCM only; the `aes-gcm` crate does not expose its internals).
    gcm: Option<Box<GcmParts>>,
    nonce_prefix: [u8; 4],
    counter: AtomicU64,
    _key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for SmbCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmbCipher")
            .field("cipher", &self.cipher)
            .finish_non_exhaustive()
    }
}

impl SmbCipher {
    /// Key a cipher. `key` must be [`Cipher::key_len`] bytes.
    pub fn new(cipher: Cipher, key: &[u8]) -> Result<Self> {
        if key.len() != cipher.key_len() {
            return Err(ProtoError::InvalidInput(
                "encryption key length does not match the cipher",
            ));
        }
        let bad = |_| ProtoError::InvalidInput("bad encryption key");
        let aead = match cipher {
            Cipher::Aes128Ccm => {
                Aead::Ccm128(Box::new(Aes128Ccm::new_from_slice(key).map_err(bad)?))
            }
            Cipher::Aes128Gcm => {
                Aead::Gcm128(Box::new(Aes128Gcm::new_from_slice(key).map_err(bad)?))
            }
            Cipher::Aes256Ccm => {
                Aead::Ccm256(Box::new(Aes256Ccm::new_from_slice(key).map_err(bad)?))
            }
            Cipher::Aes256Gcm => {
                Aead::Gcm256(Box::new(Aes256Gcm::new_from_slice(key).map_err(bad)?))
            }
        };
        let gcm = match cipher {
            Cipher::Aes128Gcm => Some(Box::new(GcmParts::A128(GcmKey::new(
                <Aes128 as aes::cipher::KeyInit>::new_from_slice(key).map_err(bad)?,
            )))),
            Cipher::Aes256Gcm => Some(Box::new(GcmParts::A256(GcmKey::new(
                <Aes256 as aes::cipher::KeyInit>::new_from_slice(key).map_err(bad)?,
            )))),
            Cipher::Aes128Ccm | Cipher::Aes256Ccm => None,
        };
        let mut seed = [0u8; 12];
        super::random_bytes(&mut seed);
        let mut nonce_prefix = [0u8; 4];
        nonce_prefix.copy_from_slice(&seed[..4]);
        let mut start = [0u8; 8];
        start.copy_from_slice(&seed[4..]);
        // Below 2^63, so exhausting the counter takes at least 2^63
        // messages; never 0.
        let start = (u64::from_le_bytes(start) >> 1).max(1);
        Ok(SmbCipher {
            cipher,
            aead,
            gcm,
            nonce_prefix,
            counter: AtomicU64::new(start),
            _key: Zeroizing::new(key.to_vec()),
        })
    }

    /// The cipher.
    pub fn cipher(&self) -> Cipher {
        self.cipher
    }

    /// The next unique nonce (zero-padded to 16 bytes).
    pub fn next_nonce(&self) -> Result<[u8; 16]> {
        // `fetch_update` with `checked_add` never wraps: once the counter
        // reaches u64::MAX every later call fails, instead of `fetch_add`
        // silently restarting at 0 and reusing nonces.
        let c = self
            .counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| c.checked_add(1))
            .map_err(|_| ProtoError::InvalidInput("nonce space exhausted; re-key the session"))?;
        let mut n = [0u8; 16];
        match self.cipher.nonce_len() {
            11 => {
                n[..3].copy_from_slice(&self.nonce_prefix[..3]);
                n[3..11].copy_from_slice(&c.to_le_bytes());
            }
            _ => {
                n[..4].copy_from_slice(&self.nonce_prefix);
                n[4..12].copy_from_slice(&c.to_le_bytes());
            }
        }
        Ok(n)
    }

    /// Encrypt a plaintext given as parts into a complete transform message
    /// (header + ciphertext), using a fresh nonce.
    pub fn encrypt(&self, session_id: u64, parts: &[&[u8]]) -> Result<BytesMut> {
        let nonce = self.next_nonce()?;
        self.encrypt_with_nonce(session_id, &nonce, parts)
    }

    /// Encrypt encoded (unsigned) messages — one message or a compound chain.
    pub fn encrypt_messages(&self, session_id: u64, msgs: &[EncodedMessage]) -> Result<BytesMut> {
        let parts: Vec<&[u8]> = msgs.iter().flat_map(|m| m.segments()).collect();
        self.encrypt(session_id, &parts)
    }

    /// Encrypt with an explicit nonce (only the first 11/12 bytes are used;
    /// the rest must be zero). Deterministic; for tests and interop vectors.
    pub fn encrypt_with_nonce(
        &self,
        session_id: u64,
        nonce: &[u8; 16],
        parts: &[&[u8]],
    ) -> Result<BytesMut> {
        if nonce[self.cipher.nonce_len()..].iter().any(|&b| b != 0) {
            return Err(ProtoError::InvalidInput("nonce padding must be zero"));
        }
        let len: usize = parts.iter().map(|p| p.len()).sum();
        let original_message_size = u32::try_from(len)
            .map_err(|_| ProtoError::InvalidInput("message too large to encrypt"))?;
        let hdr = TransformHeader {
            signature: [0; 16],
            nonce: *nonce,
            original_message_size,
            flags: TRANSFORM_FLAG_ENCRYPTED,
            session_id,
        };
        let mut out = BytesMut::with_capacity(TRANSFORM_HEADER_LEN + len);
        out.put_slice(&hdr.to_bytes());
        for p in parts {
            out.put_slice(p);
        }
        let (head, body) = out.split_at_mut(TRANSFORM_HEADER_LEN);
        let aad = &head[AAD_OFFSET..];
        let tag = self.seal(nonce, aad, body.into())?;
        head[4..20].copy_from_slice(&tag);
        Ok(out)
    }

    /// Verify and decrypt a transform message in place. Returns the header
    /// and the plaintext, which shares the frame's allocation (no copy).
    pub fn decrypt_in_place(&self, mut frame: BytesMut) -> Result<(TransformHeader, BytesMut)> {
        let hdr = self.check_header(&frame)?;
        let (head, body) = frame.split_at_mut(TRANSFORM_HEADER_LEN);
        let aad = &head[AAD_OFFSET..];
        self.open(&hdr.nonce, aad, body.into(), &hdr.signature)?;
        let plain = frame.split_off(TRANSFORM_HEADER_LEN);
        Ok((hdr, plain))
    }

    /// Verify and decrypt a transform message into `out` (which must hold
    /// at least `OriginalMessageSize` bytes), reading the ciphertext from
    /// `frame` without modifying it. Returns the header and the plaintext
    /// length. On failure the contents of `out` are unspecified and must
    /// not be used.
    pub fn decrypt_into(&self, frame: &[u8], out: &mut [u8]) -> Result<(TransformHeader, usize)> {
        let hdr = self.check_header(frame)?;
        let ct = &frame[TRANSFORM_HEADER_LEN..];
        if out.len() < ct.len() {
            return Err(ProtoError::BufferTooSmall {
                need: ct.len(),
                have: out.len(),
            });
        }
        let dst = &mut out[..ct.len()];
        let buf = InOutBuf::new(ct, dst).expect("equal lengths");
        let aad = &frame[AAD_OFFSET..TRANSFORM_HEADER_LEN];
        let res = self.open(&hdr.nonce, aad, buf, &hdr.signature);
        if res.is_err() {
            // Do not leave unauthenticated plaintext in caller memory.
            out[..ct.len()].fill(0);
        }
        res?;
        Ok((hdr, ct.len()))
    }

    /// Verify and decrypt a transform message into several caller buffers,
    /// filled in order, without modifying `frame`. Returns the header and
    /// the plaintext length; buffer space beyond it is left untouched.
    ///
    /// This is how a READ response lands directly in the caller's memory:
    /// pass a small scratch buffer for the SMB2 header and READ response
    /// body (`OriginalMessageSize - DataLength`, normally 80 bytes) and the
    /// destination slice for the data.
    ///
    /// With AES-GCM the tag is verified over the ciphertext *before* any
    /// plaintext is written, and the plaintext is produced in one pass
    /// straight into the outputs. AES-CCM authenticates the plaintext, so it
    /// decrypts into a scratch buffer and copies (one extra copy). Either
    /// way the outputs are untouched when authentication fails.
    pub fn decrypt_into_parts(
        &self,
        frame: &[u8],
        outputs: &mut [&mut [u8]],
    ) -> Result<(TransformHeader, usize)> {
        let hdr = self.check_header(frame)?;
        let ct = &frame[TRANSFORM_HEADER_LEN..];
        let have: usize = outputs.iter().map(|o| o.len()).sum();
        if have < ct.len() {
            return Err(ProtoError::BufferTooSmall {
                need: ct.len(),
                have,
            });
        }
        let aad = &frame[AAD_OFFSET..TRANSFORM_HEADER_LEN];
        match self.gcm.as_deref() {
            Some(GcmParts::A128(k)) => k.open_into(&hdr, aad, ct, outputs)?,
            Some(GcmParts::A256(k)) => k.open_into(&hdr, aad, ct, outputs)?,
            None => {
                let mut scratch = Zeroizing::new(vec![0u8; ct.len()]);
                self.decrypt_into(frame, &mut scratch)?;
                scatter(&scratch, outputs);
            }
        }
        Ok((hdr, ct.len()))
    }

    fn seal(&self, nonce: &[u8; 16], aad: &[u8], buf: InOutBuf<'_, '_, u8>) -> Result<[u8; 16]> {
        let n = &nonce[..self.cipher.nonce_len()];
        match &self.aead {
            Aead::Ccm128(a) => seal_with(&**a, n, aad, buf),
            Aead::Gcm128(a) => seal_with(&**a, n, aad, buf),
            Aead::Ccm256(a) => seal_with(&**a, n, aad, buf),
            Aead::Gcm256(a) => seal_with(&**a, n, aad, buf),
        }
    }

    fn open(
        &self,
        nonce: &[u8; 16],
        aad: &[u8],
        buf: InOutBuf<'_, '_, u8>,
        tag: &[u8; 16],
    ) -> Result<()> {
        let n = &nonce[..self.cipher.nonce_len()];
        match &self.aead {
            Aead::Ccm128(a) => open_with(&**a, n, aad, buf, tag),
            Aead::Gcm128(a) => open_with(&**a, n, aad, buf, tag),
            Aead::Ccm256(a) => open_with(&**a, n, aad, buf, tag),
            Aead::Gcm256(a) => open_with(&**a, n, aad, buf, tag),
        }
    }

    fn check_header(&self, frame: &[u8]) -> Result<TransformHeader> {
        let hdr = TransformHeader::decode(frame)?;
        if hdr.flags != TRANSFORM_FLAG_ENCRYPTED {
            return Err(ProtoError::malformed(
                "TRANSFORM_HEADER",
                "flags must be 0x0001",
            ));
        }
        if hdr.original_message_size as usize != frame.len() - TRANSFORM_HEADER_LEN {
            return Err(ProtoError::malformed(
                "TRANSFORM_HEADER",
                "OriginalMessageSize does not match the frame",
            ));
        }
        Ok(hdr)
    }
}

/// Copy `src` into consecutive output buffers.
fn scatter(mut src: &[u8], outputs: &mut [&mut [u8]]) {
    for out in outputs.iter_mut() {
        if src.is_empty() {
            break;
        }
        let n = out.len().min(src.len());
        out[..n].copy_from_slice(&src[..n]);
        src = &src[n..];
    }
}

enum GcmParts {
    A128(GcmKey<Aes128>),
    A256(GcmKey<Aes256>),
}

/// AES-GCM with a 96-bit nonce, decomposed into GHASH and CTR so that
/// authentication and decryption can run against non-contiguous outputs
/// (NIST SP 800-38D §7.2).
struct GcmKey<C> {
    aes: C,
    ghash: GHash,
}

impl<C: BlockCipherEncrypt<BlockSize = aes::cipher::consts::U16> + Clone> GcmKey<C> {
    fn new(aes: C) -> Self {
        let mut h = ghash::Block::default();
        aes.encrypt_block(&mut h);
        GcmKey {
            ghash: GHash::new(&h),
            aes,
        }
    }

    fn open_into(
        &self,
        hdr: &TransformHeader,
        aad: &[u8],
        ct: &[u8],
        outputs: &mut [&mut [u8]],
    ) -> Result<()> {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&hdr.nonce[..12]);
        // Tag = E(K, J0) xor GHASH(H, A || C || len(A) || len(C)).
        let mut g = self.ghash.clone();
        g.update_padded(aad);
        g.update_padded(ct);
        let mut lens = ghash::Block::default();
        lens[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
        lens[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
        g.update(std::slice::from_ref(&lens));
        let s = g.finalize();
        let mut j0 = ghash::Block::default();
        j0[..12].copy_from_slice(&nonce);
        j0[15] = 1;
        self.aes.encrypt_block(&mut j0);
        let mut tag = [0u8; 16];
        for (t, (a, b)) in tag.iter_mut().zip(s.iter().zip(j0.iter())) {
            *t = a ^ b;
        }
        if !bool::from(tag.ct_eq(&hdr.signature)) {
            return Err(ProtoError::DecryptFailed);
        }
        // Authentic: decrypt with the counter starting at inc32(J0).
        let mut iv = ghash::Block::default();
        iv[..12].copy_from_slice(&nonce);
        iv[15] = 2;
        let core = ctr::CtrCore::<C, ctr::flavors::Ctr32BE>::inner_iv_init(self.aes.clone(), &iv);
        let mut ctr = ctr::Ctr32BE::<C>::from_core(core);
        let mut src = ct;
        for out in outputs.iter_mut() {
            if src.is_empty() {
                break;
            }
            let n = out.len().min(src.len());
            // Equal lengths by construction; a 32-bit block counter covers
            // 64 GiB, far beyond the 16 MiB frame limit.
            ctr.apply_keystream_b2b(&src[..n], &mut out[..n]);
            src = &src[n..];
        }
        Ok(())
    }
}

fn seal_with<A: AeadInOut<TagSize = U16>>(
    a: &A,
    nonce: &[u8],
    aad: &[u8],
    buf: InOutBuf<'_, '_, u8>,
) -> Result<[u8; 16]> {
    let nonce =
        aes_gcm::aead::Nonce::<A>::try_from(nonce).expect("nonce length matches the cipher");
    let tag = a
        .encrypt_inout_detached(&nonce, aad, buf)
        .map_err(|_| ProtoError::InvalidInput("message too large to encrypt"))?;
    let mut t = [0u8; 16];
    t.copy_from_slice(&tag);
    Ok(t)
}

fn open_with<A: AeadInOut<TagSize = U16>>(
    a: &A,
    nonce: &[u8],
    aad: &[u8],
    buf: InOutBuf<'_, '_, u8>,
    tag: &[u8; 16],
) -> Result<()> {
    let nonce =
        aes_gcm::aead::Nonce::<A>::try_from(nonce).expect("nonce length matches the cipher");
    let tag = aes_gcm::aead::Tag::<A>::from(*tag);
    a.decrypt_inout_detached(&nonce, aad, buf, &tag)
        .map_err(|_| ProtoError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> [Cipher; 4] {
        [
            Cipher::Aes128Ccm,
            Cipher::Aes128Gcm,
            Cipher::Aes256Ccm,
            Cipher::Aes256Gcm,
        ]
    }

    #[test]
    fn round_trip_all_ciphers() {
        for c in all() {
            let key = vec![0x5Au8; c.key_len()];
            let enc = SmbCipher::new(c, &key).unwrap();
            let dec = SmbCipher::new(c, &key).unwrap();
            let msg = b"\xFESMB plaintext message of some length .....".repeat(20);
            let frame = enc.encrypt(0x1122, &[&msg[..10], &msg[10..]]).unwrap();
            assert_eq!(frame.len(), TRANSFORM_HEADER_LEN + msg.len());
            assert_ne!(&frame[TRANSFORM_HEADER_LEN..], &msg[..]);
            // decrypt_into
            let mut out = vec![0u8; msg.len() + 5];
            let (h, n) = dec.decrypt_into(&frame, &mut out).unwrap();
            assert_eq!(h.session_id, 0x1122);
            assert_eq!(&out[..n], &msg[..]);
            // in place
            let (_, plain) = dec.decrypt_in_place(frame.clone()).unwrap();
            assert_eq!(&plain[..], &msg[..]);
            // tamper with ciphertext, tag and AAD
            for idx in [TRANSFORM_HEADER_LEN + 3, 5, 44] {
                let mut bad = frame.clone();
                bad[idx] ^= 0x80;
                assert!(
                    dec.decrypt_in_place(bad.clone()).is_err(),
                    "{c:?} idx {idx}"
                );
                let mut out = vec![0xEEu8; msg.len()];
                assert!(dec.decrypt_into(&bad, &mut out).is_err());
                assert!(
                    out.iter().all(|&b| b == 0),
                    "plaintext must be wiped on failure"
                );
            }
        }
    }

    #[test]
    fn decrypt_into_parts_all_ciphers_and_splits() {
        for c in all() {
            let key: Vec<u8> = (0..c.key_len() as u8).collect();
            let k = SmbCipher::new(c, &key).unwrap();
            for len in [0usize, 1, 15, 16, 17, 80, 81, 1000, 4096 + 80] {
                let msg: Vec<u8> = (0..len).map(|i| (i * 7 % 256) as u8).collect();
                let frame = k.encrypt(9, &[&msg]).unwrap();
                for split in [0usize, 1, 16, 33, 80, len / 2, len] {
                    let split = split.min(len);
                    let mut head = vec![0xEEu8; split];
                    let mut data = vec![0xEEu8; len - split + 3];
                    let (h, n) = k
                        .decrypt_into_parts(&frame, &mut [&mut head, &mut data])
                        .unwrap();
                    assert_eq!((h.session_id, n), (9, len));
                    assert_eq!(head, &msg[..split], "{c:?} len {len} split {split}");
                    assert_eq!(&data[..len - split], &msg[split..]);
                    assert_eq!(&data[len - split..], &[0xEE; 3], "spare space untouched");
                }
                // Too small.
                let mut small = vec![0u8; len.saturating_sub(1)];
                if len > 0 {
                    assert!(matches!(
                        k.decrypt_into_parts(&frame, &mut [&mut small]),
                        Err(ProtoError::BufferTooSmall { .. })
                    ));
                }
                // Tampering is detected before anything reaches the outputs.
                let mut bad = frame.to_vec();
                let i = bad.len() - 1;
                bad[i] ^= 1;
                let mut out = vec![0xEEu8; len];
                if len > 0 {
                    assert_eq!(
                        k.decrypt_into_parts(&bad, &mut [&mut out]),
                        Err(ProtoError::DecryptFailed)
                    );
                    assert!(out.iter().all(|&b| b == 0xEE), "{c:?}");
                }
            }
        }
    }

    #[test]
    fn nonces_are_unique_and_sized() {
        let c = SmbCipher::new(Cipher::Aes128Ccm, &[0; 16]).unwrap();
        let a = c.next_nonce().unwrap();
        let b = c.next_nonce().unwrap();
        assert_ne!(a, b);
        assert_eq!(&a[11..], &[0; 5]);
        let g = SmbCipher::new(Cipher::Aes128Gcm, &[0; 16]).unwrap();
        assert_eq!(&g.next_nonce().unwrap()[12..], &[0; 4]);
        assert!(g.encrypt_with_nonce(1, &[1; 16], &[b"x"]).is_err());
    }

    #[test]
    fn nonces_unique_across_instances_even_if_prefixes_collide() {
        // Two SmbCiphers for one key (e.g. one per channel of a
        // multichannel session, or rebuilt after re-authentication) pick
        // random prefixes; CCM's 24-bit prefix collides with probability
        // 2^-24 per pair. Even then the nonce sequences must not overlap.
        for c in all() {
            let key = vec![7u8; c.key_len()];
            let mut a = SmbCipher::new(c, &key).unwrap();
            let mut b = SmbCipher::new(c, &key).unwrap();
            a.nonce_prefix = [1, 2, 3, 4];
            b.nonce_prefix = [1, 2, 3, 4];
            let seen: std::collections::HashSet<[u8; 16]> =
                (0..1000).map(|_| a.next_nonce().unwrap()).collect();
            assert_eq!(seen.len(), 1000);
            for _ in 0..1000 {
                assert!(
                    !seen.contains(&b.next_nonce().unwrap()),
                    "{c:?} nonce reuse"
                );
            }
        }
    }

    #[test]
    fn nonce_exhaustion_is_permanent() {
        let c = SmbCipher::new(Cipher::Aes128Gcm, &[0; 16]).unwrap();
        c.counter.store(u64::MAX - 1, Ordering::Relaxed);
        let last = c.next_nonce().unwrap();
        assert_eq!(&last[4..12], &(u64::MAX - 1).to_le_bytes());
        // Once exhausted the counter must not wrap around and hand out
        // nonces that were already used.
        for _ in 0..3 {
            assert!(c.next_nonce().is_err());
            assert!(c.encrypt(1, &[b"x"]).is_err());
        }
    }

    #[test]
    fn header_checks() {
        let c = SmbCipher::new(Cipher::Aes128Gcm, &[0; 16]).unwrap();
        let mut f = c.encrypt(1, &[b"hello"]).unwrap();
        f.truncate(f.len() - 1);
        assert!(c.decrypt_in_place(f).is_err());
        assert!(SmbCipher::new(Cipher::Aes256Gcm, &[0; 16]).is_err());
        assert_eq!(
            Cipher::from_id(Cipher::Aes256Ccm.id()),
            Some(Cipher::Aes256Ccm)
        );
        assert_eq!(Cipher::from_id(CipherId(0)), None);
    }
}
