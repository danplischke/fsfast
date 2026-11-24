//! SMB session key derivation ([MS-SMB2] §3.2.5.3.1, §3.1.4.2).

use zeroize::Zeroizing;

use super::kdf::sp800_108_hmac_sha256;
use super::transform::Cipher;
use crate::error::{ProtoError, Result};
use crate::types::Dialect;

/// The keys of an authenticated session.
///
/// `encryption_key` protects client-to-server traffic and `decryption_key`
/// server-to-client traffic (from the client's point of view; see
/// [`SessionKeys::server_view`]).
#[derive(Clone)]
pub struct SessionKeys {
    /// `Session.SessionKey`: the first 16 bytes of the GSS session key,
    /// zero-padded.
    pub session_key: Zeroizing<[u8; 16]>,
    /// Signing key (16 bytes).
    pub signing_key: Zeroizing<[u8; 16]>,
    /// Application key (16 bytes), exposed to upper layers (e.g. DCE/RPC).
    pub application_key: Zeroizing<[u8; 16]>,
    /// Client-to-server encryption key (16 or 32 bytes); `None` for 2.x.
    pub encryption_key: Option<Zeroizing<Vec<u8>>>,
    /// Server-to-client decryption key (16 or 32 bytes); `None` for 2.x.
    pub decryption_key: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys").finish_non_exhaustive()
    }
}

impl SessionKeys {
    /// The same keys from the server's point of view (encryption and
    /// decryption swapped), for mock servers and tests.
    pub fn server_view(&self) -> SessionKeys {
        let mut k = self.clone();
        std::mem::swap(&mut k.encryption_key, &mut k.decryption_key);
        k
    }
}

fn kdf16(key: &[u8], label: &[u8], context: &[u8]) -> Zeroizing<[u8; 16]> {
    let mut out = Zeroizing::new([0u8; 16]);
    sp800_108_hmac_sha256(key, label, context, out.as_mut());
    out
}

fn kdf_vec(key: &[u8], label: &[u8], context: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; len]);
    sp800_108_hmac_sha256(key, label, context, &mut out);
    out
}

/// Derive the session keys.
///
/// * `full_session_key`: the session key exported by authentication
///   (16 bytes for NTLM, up to 32 for Kerberos).
/// * `preauth_hash`: the session's final preauth integrity hash; required
///   for 3.1.1, ignored otherwise.
/// * `cipher`: the negotiated cipher; decides 128- vs 256-bit encryption
///   keys for 3.1.1. 3.0/3.0.2 always use AES-128-CCM.
pub fn derive_session_keys(
    dialect: Dialect,
    full_session_key: &[u8],
    preauth_hash: Option<&[u8; 64]>,
    cipher: Option<Cipher>,
) -> Result<SessionKeys> {
    if full_session_key.is_empty() {
        return Err(ProtoError::InvalidInput("empty session key"));
    }
    let mut session_key = Zeroizing::new([0u8; 16]);
    let n = full_session_key.len().min(16);
    session_key[..n].copy_from_slice(&full_session_key[..n]);

    if dialect.is_3_1_1() {
        let h = preauth_hash.ok_or(ProtoError::InvalidInput(
            "SMB 3.1.1 key derivation needs the preauth hash",
        ))?;
        let signing_key = kdf16(session_key.as_ref(), b"SMBSigningKey\0", h);
        let application_key = kdf16(session_key.as_ref(), b"SMBAppKey\0", h);
        let (kdk, len): (&[u8], usize) = match cipher {
            Some(c) if c.key_len() == 32 => (full_session_key, 32),
            _ => (session_key.as_ref(), 16),
        };
        Ok(SessionKeys {
            encryption_key: Some(kdf_vec(kdk, b"SMBC2SCipherKey\0", h, len)),
            decryption_key: Some(kdf_vec(kdk, b"SMBS2CCipherKey\0", h, len)),
            session_key,
            signing_key,
            application_key,
        })
    } else if dialect.is_smb3() {
        let signing_key = kdf16(session_key.as_ref(), b"SMB2AESCMAC\0", b"SmbSign\0");
        let application_key = kdf16(session_key.as_ref(), b"SMB2APP\0", b"SmbRpc\0");
        Ok(SessionKeys {
            encryption_key: Some(kdf_vec(
                session_key.as_ref(),
                b"SMB2AESCCM\0",
                b"ServerIn \0",
                16,
            )),
            decryption_key: Some(kdf_vec(
                session_key.as_ref(),
                b"SMB2AESCCM\0",
                b"ServerOut\0",
                16,
            )),
            signing_key,
            application_key,
            session_key,
        })
    } else {
        Ok(SessionKeys {
            signing_key: session_key.clone(),
            application_key: session_key.clone(),
            encryption_key: None,
            decryption_key: None,
            session_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smb2_uses_session_key() {
        let k = derive_session_keys(Dialect::SMB_2_1, &[1u8; 16], None, None).unwrap();
        assert_eq!(*k.signing_key, [1u8; 16]);
        assert!(k.encryption_key.is_none());
    }

    #[test]
    fn short_keys_are_padded_and_311_needs_hash() {
        let k = derive_session_keys(Dialect::SMB_2_0_2, &[1u8; 8], None, None).unwrap();
        assert_eq!(&k.session_key[8..], &[0u8; 8]);
        assert!(derive_session_keys(Dialect::SMB_3_1_1, &[1u8; 16], None, None).is_err());
        let k = derive_session_keys(
            Dialect::SMB_3_1_1,
            &[1u8; 16],
            Some(&[0; 64]),
            Some(Cipher::Aes256Gcm),
        )
        .unwrap();
        assert_eq!(k.encryption_key.as_ref().unwrap().len(), 32);
        let sv = k.server_view();
        assert_eq!(
            sv.encryption_key.as_ref().unwrap().as_slice(),
            k.decryption_key.as_ref().unwrap().as_slice()
        );
    }
}
