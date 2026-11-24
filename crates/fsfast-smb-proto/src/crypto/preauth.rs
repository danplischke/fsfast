//! SMB 3.1.1 preauthentication integrity hash ([MS-SMB2] §3.2.5.2,
//! §3.2.5.3.1).

use sha2::{Digest, Sha512};

/// Running SHA-512 preauth integrity hash: `H = SHA512(H || message)`.
///
/// The connection hash starts at zero and absorbs the NEGOTIATE request and
/// response. Each session starts from (a clone of) the connection hash and
/// absorbs every SESSION_SETUP request and every SESSION_SETUP response
/// except the final successful one. Messages are whole SMB2 messages
/// (header included, transport header excluded).
#[derive(Clone, PartialEq, Eq)]
pub struct PreauthHasher {
    value: [u8; 64],
}

impl Default for PreauthHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for PreauthHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PreauthHasher(")?;
        for b in &self.value[..8] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "..)")
    }
}

impl PreauthHasher {
    /// The initial (all-zero) hash value.
    pub fn new() -> Self {
        PreauthHasher { value: [0; 64] }
    }

    /// Absorb one message.
    pub fn update(&mut self, message: &[u8]) {
        self.update_parts(&[message]);
    }

    /// Absorb one message given as consecutive parts (e.g. the segments of
    /// an [`EncodedMessage`](crate::msg::EncodedMessage)).
    pub fn update_parts(&mut self, parts: &[&[u8]]) {
        let mut h = Sha512::new();
        h.update(self.value);
        for p in parts {
            h.update(p);
        }
        self.value.copy_from_slice(&h.finalize());
    }

    /// The current hash value.
    pub fn value(&self) -> &[u8; 64] {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chaining_matches_definition() {
        let mut p = PreauthHasher::new();
        p.update(b"neg-req");
        p.update_parts(&[b"neg-", b"resp"]);
        let h1 = Sha512::digest([[0u8; 64].as_slice(), b"neg-req"].concat());
        let h2 = Sha512::digest([h1.as_slice(), b"neg-resp"].concat());
        assert_eq!(p.value().as_slice(), h2.as_slice());
    }
}
