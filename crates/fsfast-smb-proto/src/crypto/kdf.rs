//! SP800-108 key derivation in counter mode with HMAC-SHA256, as used by
//! SMB 3.x ([MS-SMB2] §3.1.4.2).

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// Derive `out.len()` bytes from `key` with the SP800-108 counter-mode KDF
/// (PRF = HMAC-SHA256, r = 32): `K(i) = PRF(key, [i]_32 || label || 0x00 ||
/// context || [L]_32)` where `L` is the output length in bits.
///
/// SMB passes labels *including* their NUL terminator (e.g.
/// `b"SMBSigningKey\0"`), so the input contains two zero bytes in a row.
pub fn sp800_108_hmac_sha256(key: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) {
    let l_bits = (out.len() as u32).wrapping_mul(8).to_be_bytes();
    let base = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let mut mac = base.clone();
        mac.update(&(i as u32 + 1).to_be_bytes());
        mac.update(label);
        mac.update(&[0]);
        mac.update(context);
        mac.update(&l_bits);
        let block = mac.finalize().into_bytes();
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer_smb30_signing_key() {
        // SMB 3.0 signing key from Microsoft's "SMB 2 and SMB 3 security in
        // Windows 10" example session key; the expected value was confirmed
        // with Python `cryptography`'s KBKDFHMAC (the KDF smbprotocol uses).
        let key = hex(b"7CD451825D0450D235424E44BA6E78CC");
        let mut out = [0u8; 16];
        sp800_108_hmac_sha256(&key, b"SMB2AESCMAC\0", b"SmbSign\0", &mut out);
        assert_eq!(out.to_vec(), hex(b"0B7E9C5CAC36C0F6EA9AB275298CEDCE"));
    }

    #[test]
    fn multi_block_output() {
        let mut a = [0u8; 64];
        sp800_108_hmac_sha256(b"k", b"l", b"c", &mut a);
        let mut b = [0u8; 32];
        sp800_108_hmac_sha256(b"k", b"l", b"c", &mut b);
        // L differs, so even the first block differs.
        assert_ne!(&a[..32], &b[..]);
    }

    fn hex(s: &[u8]) -> Vec<u8> {
        s.chunks(2).map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap()).collect()
    }
}
