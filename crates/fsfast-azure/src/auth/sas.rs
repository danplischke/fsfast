//! Service SAS tokens for blobs, as azure-storage-blob's
//! `generate_blob_sas` builds them (used by `sign()`), and handling of SAS
//! tokens the user supplies.
//!
//! String-to-sign (service SAS, account key):
//!
//! ```text
//! sp \n st \n se \n /blob/<account>/<container>/<blob> \n si \n sip \n spr \n
//! sv \n sr \n snapshot \n ses \n rscc \n rscd \n rsce \n rscl \n rsct
//! ```
//!
//! The token lists `st, se, sp, sip, spr, sv, si, sr, rscc, rscd, rsce,
//! rscl, rsct, ses, sig` (present ones only, values quoted like Python's
//! `quote`); the version/snapshot timestamp is signed but not included.

use std::time::SystemTime;

use crate::auth::SharedKey;
use crate::path::quote;
use crate::time::iso8601;

/// Parameters of a blob service SAS.
#[derive(Debug, Clone, Default)]
pub struct BlobSas<'a> {
    /// Container name.
    pub container: &'a str,
    /// Blob name (unencoded); empty for a container SAS (`sr=c`).
    pub blob: &'a str,
    /// Permissions in canonical order (`racwdxytmei` subset), e.g. `"r"`.
    pub permission: &'a str,
    /// Expiry time.
    pub expiry: Option<SystemTime>,
    /// Start time.
    pub start: Option<SystemTime>,
    /// Signed service version (`sv`).
    pub version: &'a str,
    /// Blob version id (`sr=bv`).
    pub version_id: Option<&'a str>,
    /// Snapshot timestamp (`sr=bs`).
    pub snapshot: Option<&'a str>,
    /// Stored access policy id (`si`).
    pub policy_id: Option<&'a str>,
    /// Allowed IP or range (`sip`).
    pub ip: Option<&'a str>,
    /// Allowed protocols (`spr`), e.g. `https`.
    pub protocol: Option<&'a str>,
    /// Response `Cache-Control` override.
    pub cache_control: Option<&'a str>,
    /// Response `Content-Disposition` override.
    pub content_disposition: Option<&'a str>,
    /// Response `Content-Encoding` override.
    pub content_encoding: Option<&'a str>,
    /// Response `Content-Language` override.
    pub content_language: Option<&'a str>,
    /// Response `Content-Type` override.
    pub content_type: Option<&'a str>,
    /// Encryption scope (`ses`).
    pub encryption_scope: Option<&'a str>,
}

impl BlobSas<'_> {
    /// `(string_to_sign, token)` signed with `key`.
    pub fn sign(&self, key: &SharedKey) -> (String, String) {
        let st = self.start.map(iso8601);
        let se = self.expiry.map(iso8601);
        let resource = if self.blob.is_empty() {
            // A container SAS (`generate_container_sas`).
            "c"
        } else if self.version_id.is_some() {
            "bv"
        } else if self.snapshot.is_some() {
            "bs"
        } else {
            "b"
        };
        let timestamp = self.version_id.or(self.snapshot);
        let nz = |v: Option<&str>| v.filter(|s| !s.is_empty()).map(str::to_owned);
        let perm = nz(Some(self.permission));
        let sv = nz(Some(self.version));
        // Query parameters in the SDK's insertion order.
        let mut q: Vec<(&str, Option<String>)> = vec![
            ("st", st),
            ("se", se),
            ("sp", perm),
            ("sip", nz(self.ip)),
            ("spr", nz(self.protocol)),
            ("sv", sv),
            ("si", nz(self.policy_id)),
            ("sr", Some(resource.to_owned())),
            ("rscc", nz(self.cache_control)),
            ("rscd", nz(self.content_disposition)),
            ("rsce", nz(self.content_encoding)),
            ("rscl", nz(self.content_language)),
            ("rsct", nz(self.content_type)),
            ("ses", nz(self.encryption_scope)),
        ];
        let get = |q: &[(&str, Option<String>)], n: &str| -> String {
            q.iter()
                .find(|(k, _)| *k == n)
                .and_then(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let mut sts = String::with_capacity(256);
        for n in ["sp", "st", "se"] {
            sts.push_str(&get(&q, n));
            sts.push('\n');
        }
        sts.push_str("/blob/");
        sts.push_str(key.account());
        sts.push('/');
        sts.push_str(self.container);
        if !self.blob.is_empty() {
            sts.push('/');
            sts.push_str(self.blob);
        }
        sts.push('\n');
        for n in ["si", "sip", "spr", "sv", "sr"] {
            sts.push_str(&get(&q, n));
            sts.push('\n');
        }
        sts.push_str(timestamp.unwrap_or(""));
        sts.push('\n');
        for n in ["ses", "rscc", "rscd", "rsce", "rscl", "rsct"] {
            sts.push_str(&get(&q, n));
            sts.push('\n');
        }
        sts.pop();
        let sig = key.sign(&sts);
        q.push(("sig", Some(sig)));
        let token = q
            .iter()
            .filter_map(|(k, v)| v.as_ref().map(|v| format!("{k}={}", quote(v, true))))
            .collect::<Vec<_>>()
            .join("&");
        (sts, token)
    }
}

/// A user-supplied SAS token without its leading `?`.
pub fn normalize_sas(token: &str) -> String {
    token.trim().trim_start_matches('?').to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn token_shape() {
        let key = SharedKey::new("acct", "a2V5").unwrap();
        let sas = BlobSas {
            container: "c",
            blob: "a b/ü",
            permission: "r",
            expiry: Some(UNIX_EPOCH + Duration::from_secs(1_795_588_234)),
            version: "2024-11-04",
            ..BlobSas::default()
        };
        let (sts, token) = sas.sign(&key);
        assert!(
            sts.starts_with("r\n\n2026-11-25T06:30:34Z\n/blob/acct/c/a b/ü\n\n\n\n2024-11-04\nb\n")
        );
        assert_eq!(sts.matches('\n').count(), 15);
        assert!(token.starts_with("se=2026-11-25T06%3A30%3A34Z&sp=r&sv=2024-11-04&sr=b&sig="));
    }
}
