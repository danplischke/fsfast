//! Peeking at the plaintext header of an AES-GCM encrypted frame.
//!
//! GCM encrypts with AES in counter mode: plaintext block `i` is the
//! ciphertext block XOR `AES(K, nonce || BE32(i + 2))`. Decrypting the first
//! 80 bytes this way (without authenticating) reveals the SMB2 header and
//! the fixed READ response body, which tells the reader task whose request
//! the frame answers and where its data goes. The frame is then handed,
//! still encrypted, to that caller, which authenticates and decrypts it
//! straight into its destination buffer ([`SmbCipher::decrypt_into_parts`]
//! checks the tag before writing any plaintext). Decryption therefore runs
//! in parallel on the callers' tasks instead of serially in the reader, and
//! writes each byte once.
//!
//! Nothing peeked is trusted: the caller re-checks every peeked field
//! against the authenticated plaintext and kills the connection on any
//! mismatch or tag failure.
//!
//! [`SmbCipher::decrypt_into_parts`]: fsfast_smb_proto::crypto::SmbCipher::decrypt_into_parts

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use fsfast_smb_proto::crypto::Cipher;

/// Length of the TRANSFORM_HEADER.
pub(crate) const TRANSFORM_LEN: usize = 52;
/// Offset of the nonce in the TRANSFORM_HEADER.
const NONCE_OFFSET: usize = 20;

/// The server-to-client AES key schedule of a GCM session.
pub(crate) enum Peek {
    A128(Box<aes::Aes128>),
    A256(Box<aes::Aes256>),
}

impl std::fmt::Debug for Peek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Peek")
    }
}

impl Peek {
    /// A peeker for `cipher` (GCM only; CCM uses another counter layout).
    pub fn new(cipher: Cipher, key: &[u8]) -> Option<Peek> {
        match cipher {
            Cipher::Aes128Gcm => aes::Aes128::new_from_slice(key)
                .ok()
                .map(|c| Peek::A128(Box::new(c))),
            Cipher::Aes256Gcm => aes::Aes256::new_from_slice(key)
                .ok()
                .map(|c| Peek::A256(Box::new(c))),
            Cipher::Aes128Ccm | Cipher::Aes256Ccm => None,
        }
    }

    fn block(&self, b: &mut [u8; 16]) {
        let mut blk = aes::Block::from(*b);
        match self {
            Peek::A128(c) => c.encrypt_block(&mut blk),
            Peek::A256(c) => c.encrypt_block(&mut blk),
        }
        b.copy_from_slice(&blk);
    }

    /// The first `N` plaintext bytes (N a multiple of 16) of the encrypted
    /// frame `frame` (which starts with the TRANSFORM_HEADER), unauthenticated.
    pub fn peek<const N: usize>(&self, frame: &[u8]) -> Option<[u8; N]> {
        if frame.len() < TRANSFORM_LEN + N || !N.is_multiple_of(16) {
            return None;
        }
        let nonce = &frame[NONCE_OFFSET..NONCE_OFFSET + 12];
        let ct = &frame[TRANSFORM_LEN..TRANSFORM_LEN + N];
        let mut out = [0u8; N];
        for (i, chunk) in out.chunks_exact_mut(16).enumerate() {
            let mut ctr = [0u8; 16];
            ctr[..12].copy_from_slice(nonce);
            ctr[12..].copy_from_slice(&(i as u32 + 2).to_be_bytes());
            self.block(&mut ctr);
            for (j, o) in chunk.iter_mut().enumerate() {
                *o = ct[i * 16 + j] ^ ctr[j];
            }
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsfast_smb_proto::crypto::SmbCipher;

    #[test]
    fn peek_matches_authenticated_decryption() {
        for (cipher, key) in [
            (Cipher::Aes128Gcm, vec![7u8; 16]),
            (Cipher::Aes256Gcm, vec![9u8; 32]),
        ] {
            let c = SmbCipher::new(cipher, &key).unwrap();
            let plain: Vec<u8> = (0..300u32).map(|i| (i * 7) as u8).collect();
            let frame = c.encrypt(0x1234, &[&plain[..100], &plain[100..]]).unwrap();
            let p = Peek::new(cipher, &key).unwrap();
            let head: [u8; 80] = p.peek(&frame).unwrap();
            assert_eq!(&head[..], &plain[..80]);
            assert!(p.peek::<80>(&frame[..100]).is_none());
        }
        assert!(Peek::new(Cipher::Aes128Ccm, &[0; 16]).is_none());
    }
}
