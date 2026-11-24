//! SMB 2/3 cryptography: key derivation, preauth integrity, signing,
//! encryption and compression transform parsing.
//!
//! Everything here is a pure function or a small keyed object; nothing does
//! I/O. AES runs on the RustCrypto implementations, which detect AES-NI /
//! PCLMULQDQ (x86) and the ARMv8 crypto extensions at runtime. Keyed objects
//! precompute their key schedules once so per-message work is just the MAC
//! or cipher pass.

pub mod compression;
mod gmac;
pub mod kdf;
pub mod keys;
pub mod preauth;
pub mod signing;
pub mod transform;

pub use compression::{CompressedPayload, CompressionTransform};
pub use kdf::sp800_108_hmac_sha256;
pub use keys::{SessionKeys, derive_session_keys};
pub use preauth::PreauthHasher;
pub use signing::{Signer, SigningAlgorithm};
pub use transform::{Cipher, SmbCipher, TRANSFORM_HEADER_LEN, TransformHeader};

/// Fill `buf` from the operating system's CSPRNG.
///
/// # Panics
///
/// Panics if the OS random number generator is unavailable, which on
/// supported platforms only happens in a badly broken environment (the same
/// policy as `rand::rngs::OsRng`).
pub fn random_bytes(buf: &mut [u8]) {
    getrandom::fill(buf).expect("the OS random number generator is unavailable");
}
