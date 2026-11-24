//! Streaming AES-128-GMAC (GCM with an empty plaintext), so a message made
//! of several segments (header, inline body, zero-copy payload, padding) can
//! be authenticated without first concatenating it.

use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use ghash::GHash;
use ghash::universal_hash::UniversalHash;

/// A keyed GMAC instance: the expanded AES key and the GHASH key `H`.
#[derive(Clone)]
pub(crate) struct GmacKey {
    aes: Aes128,
    ghash: GHash,
}

impl GmacKey {
    pub(crate) fn new(key: &[u8; 16]) -> Self {
        let aes = Aes128::new(key.into());
        let mut h = ghash::Block::default();
        aes.encrypt_block(&mut h);
        GmacKey { aes, ghash: GHash::new(&h) }
    }

    /// Start a MAC computation with a 96-bit nonce.
    pub(crate) fn start(&self, nonce: &[u8; 12]) -> Gmac {
        let mut j0 = ghash::Block::default();
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        self.aes.encrypt_block(&mut j0);
        Gmac { ghash: self.ghash.clone(), ek_j0: j0.into(), buf: [0; 16], buf_len: 0, aad_len: 0 }
    }
}

/// An in-progress GMAC computation over associated data.
pub(crate) struct Gmac {
    ghash: GHash,
    ek_j0: [u8; 16],
    buf: [u8; 16],
    buf_len: usize,
    aad_len: u64,
}

impl Gmac {
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.aad_len += data.len() as u64;
        if self.buf_len > 0 {
            let take = (16 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 16 {
                return;
            }
            let block = ghash::Block::from(self.buf);
            self.ghash.update(std::slice::from_ref(&block));
            self.buf_len = 0;
        }
        let (blocks, rest) = ghash::Block::slice_as_chunks(data);
        self.ghash.update(blocks);
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    pub(crate) fn finalize(mut self) -> [u8; 16] {
        if self.buf_len > 0 {
            self.ghash.update_padded(&self.buf[..self.buf_len]);
        }
        let mut len_block = ghash::Block::default();
        len_block[..8].copy_from_slice(&(self.aad_len * 8).to_be_bytes());
        self.ghash.update(std::slice::from_ref(&len_block));
        let s = self.ghash.finalize();
        let mut tag = [0u8; 16];
        for (t, (a, b)) in tag.iter_mut().zip(s.iter().zip(self.ek_j0.iter())) {
            *t = a ^ b;
        }
        tag
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::AeadInOut;
    use aes_gcm::{Aes128Gcm, KeyInit as _};

    #[test]
    fn matches_aes_gcm_with_empty_plaintext() {
        let key = [0x42u8; 16];
        let nonce = [7u8; 12];
        let gk = GmacKey::new(&key);
        let gcm = Aes128Gcm::new((&key).into());
        for len in [0usize, 1, 15, 16, 17, 31, 64, 100, 1000] {
            let aad: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let expected = gcm.encrypt_inout_detached((&nonce).into(), &aad, (&mut [][..]).into()).unwrap();
            // Feed in awkward split points.
            for split in [0, 1, 7, 16, 33] {
                let split = split.min(len);
                let mut g = gk.start(&nonce);
                g.update(&aad[..split]);
                g.update(&[]);
                g.update(&aad[split..]);
                assert_eq!(g.finalize().as_slice(), expected.as_slice(), "len {len} split {split}");
            }
        }
    }
}
