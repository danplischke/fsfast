//! Shared Key authorization of Blob service requests (the "Authorize with
//! Shared Key" scheme of the Storage REST API), as azure-storage-blob's
//! `SharedKeyCredentialPolicy` computes it.
//!
//! ```text
//! StringToSign = VERB \n
//!                Content-Encoding \n Content-Language \n Content-Length \n
//!                Content-MD5 \n Content-Type \n Date \n If-Modified-Since \n
//!                If-Match \n If-None-Match \n If-Unmodified-Since \n Range \n
//!                CanonicalizedHeaders   (x-ms-*: "name:value\n", service order)
//!                CanonicalizedResource  ("/" account url-path, then
//!                                        "\nname:value" per query parameter)
//! Authorization: SharedKey <account>:<base64(HMAC-SHA256(key, StringToSign))>
//! ```
//!
//! `Content-Length` is empty when zero (API versions since 2015-02-21).
//! `x-ms-*` headers are ordered with the service's culture-sensitive
//! comparison (hyphens are ignored at the first level), ported from the
//! SDK's `_storage_header_sort`.

use std::cmp::Ordering;
use std::fmt;

use base64::Engine as _;
use fsfast_core::{Error, Result};
use fsfast_http_transport::Url;
use fsfast_http_transport::header::HeaderMap;
use hmac::{KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::path::unquote;

/// An account name and its (decoded) access key.
#[derive(Clone)]
pub struct SharedKey {
    account: String,
    key: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for SharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedKey")
            .field("account", &self.account)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Lenient base64 (the SDK uses Python's `b64decode`, which ignores
/// missing padding errors only when the length allows; we accept both
/// padded and unpadded keys).
pub(crate) fn decode_b64(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    let e = base64::engine::general_purpose::STANDARD;
    e.decode(s).ok().or_else(|| {
        base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(s.trim_end_matches('='))
            .ok()
    })
}

impl SharedKey {
    /// A key from the base64 account key the portal shows.
    pub fn new(account: impl Into<String>, key_b64: &str) -> Result<Self> {
        let account = account.into();
        if account.is_empty() {
            return Err(Error::invalid_input(
                "Unable to determine account name for shared key credential.",
            ));
        }
        let key = decode_b64(key_b64)
            .ok_or_else(|| Error::invalid_input("account key is not valid base64"))?;
        Ok(SharedKey {
            account,
            key: Zeroizing::new(key),
        })
    }

    /// The storage account name.
    pub fn account(&self) -> &str {
        &self.account
    }

    /// base64(HMAC-SHA256(key, data)).
    pub fn sign(&self, data: &str) -> String {
        let mut mac = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(&self.key)
            .expect("HMAC accepts keys of any length");
        mac.update(data.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
    }

    /// The Shared Key string-to-sign for a request.
    ///
    /// `content_length` is the body length the transport will send (the
    /// transport sets the header itself).
    pub fn string_to_sign(
        &self,
        method: &str,
        url: &Url,
        headers: &HeaderMap,
        content_length: u64,
    ) -> String {
        // Values are trimmed: HTTP parsers (the service's included) strip
        // the blanks around a header value, so the service signs the
        // trimmed value (a metadata value like " v " would otherwise fail
        // authentication).
        let h = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .unwrap_or("")
        };
        let len = if content_length == 0 {
            String::new()
        } else {
            content_length.to_string()
        };
        let mut s = String::with_capacity(256);
        s.push_str(method);
        s.push('\n');
        for name in ["content-encoding", "content-language"] {
            s.push_str(h(name));
            s.push('\n');
        }
        s.push_str(&len);
        s.push('\n');
        for name in [
            "content-md5",
            "content-type",
            "date",
            "if-modified-since",
            "if-match",
            "if-none-match",
            "if-unmodified-since",
            "range",
        ] {
            s.push_str(h(name));
            s.push('\n');
        }
        // Canonicalized headers.
        let mut xms: Vec<(&str, &str)> = headers
            .iter()
            .filter(|(n, _)| n.as_str().starts_with("x-ms-"))
            .filter_map(|(n, v)| v.to_str().ok().map(|v| (n.as_str(), v.trim())))
            .collect();
        xms.sort_by(|a, b| storage_compare(a.0, b.0));
        for (n, v) in xms {
            s.push_str(n);
            s.push(':');
            s.push_str(v);
            s.push('\n');
        }
        // Canonicalized resource.
        s.push('/');
        s.push_str(&self.account);
        s.push_str(url.path());
        let mut params: Vec<(String, String)> = url
            .query()
            .unwrap_or("")
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (k, v) = p.split_once('=').unwrap_or((p, ""));
                (unquote(k).to_lowercase(), unquote(v).into_owned())
            })
            .collect();
        params.sort();
        // Repeated names are joined with commas (the service's rule; the SDK
        // never sends them).
        let mut i = 0;
        while i < params.len() {
            let mut j = i + 1;
            let mut value = params[i].1.clone();
            while j < params.len() && params[j].0 == params[i].0 {
                value.push(',');
                value.push_str(&params[j].1);
                j += 1;
            }
            s.push('\n');
            s.push_str(&params[i].0);
            s.push(':');
            s.push_str(&value);
            i = j;
        }
        s
    }

    /// The `Authorization` header value for a string-to-sign.
    pub fn authorization(&self, string_to_sign: &str) -> String {
        format!("SharedKey {}:{}", self.account, self.sign(string_to_sign))
    }
}

/// Collation weights of the service's header comparison (level 0), indexed
/// by ASCII code. 0 means "ignored at this level".
#[rustfmt::skip]
const TABLE_LV0: [u16; 128] = [
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x71c, 0x0, 0x71f, 0x721, 0x723, 0x725,
    0x0, 0x0, 0x0, 0x72d, 0x803, 0x0, 0x0, 0x733, 0x0, 0xd03, 0xd1a, 0xd1c, 0xd1e,
    0xd20, 0xd22, 0xd24, 0xd26, 0xd28, 0xd2a, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0xe02, 0xe09, 0xe0a, 0xe1a, 0xe21, 0xe23, 0xe25, 0xe2c, 0xe32, 0xe35, 0xe36, 0xe48, 0xe51,
    0xe70, 0xe7c, 0xe7e, 0xe89, 0xe8a, 0xe91, 0xe99, 0xe9f, 0xea2, 0xea4, 0xea6, 0xea7, 0xea9,
    0x0, 0x0, 0x0, 0x743, 0x744, 0x748, 0xe02, 0xe09, 0xe0a, 0xe1a, 0xe21, 0xe23, 0xe25,
    0xe2c, 0xe32, 0xe35, 0xe36, 0xe48, 0xe51, 0xe70, 0xe7c, 0xe7e, 0xe89, 0xe8a, 0xe91, 0xe99,
    0xe9f, 0xea2, 0xea4, 0xea6, 0xea7, 0xea9, 0x0, 0x74c, 0x0, 0x750, 0x0,
];

/// Level 4 weights: only `'` and `-` count.
fn lv4(c: u8) -> u16 {
    match c {
        b'\'' => 0x8012,
        b'-' => 0x8212,
        _ => 0,
    }
}

/// The SDK's `compare` (a port of the service's header ordering).
pub fn storage_compare(lhs: &str, rhs: &str) -> Ordering {
    let (l, r) = (lhs.as_bytes(), rhs.as_bytes());
    if !lhs.is_ascii() || !rhs.is_ascii() {
        return l.cmp(r);
    }
    let weight = |level: usize, c: u8| -> u16 {
        if level == 0 {
            TABLE_LV0[c as usize & 0x7f]
        } else {
            lv4(c)
        }
    };
    let n = 2;
    let (mut level, mut i, mut j) = (0usize, 0usize, 0usize);
    while level < n {
        if level == n - 1 && i != j {
            return if i > j {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }
        let w1 = if i < l.len() {
            weight(level, l[i])
        } else {
            0x1
        };
        let w2 = if j < r.len() {
            weight(level, r[j])
        } else {
            0x1
        };
        if w1 == 0x1 && w2 == 0x1 {
            i = 0;
            j = 0;
            level += 1;
        } else if w1 == w2 {
            i += 1;
            j += 1;
        } else if w1 == 0 {
            i += 1;
        } else if w2 == 0 {
            j += 1;
        } else {
            return w1.cmp(&w2);
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_order() {
        let mut v = vec![
            "x-ms-version",
            "x-ms-date",
            "x-ms-blob-type",
            "x-ms-meta-a",
            "x-ms-meta-B",
            "x-ms-blob-content-type",
            "x-ms-client-request-id",
            "x-ms-copy-source",
            "x-ms-range",
            "x-ms-meta-a-b",
            "x-ms-meta-ab",
        ];
        v.sort_by(|a, b| storage_compare(a, b));
        assert_eq!(
            v,
            [
                "x-ms-blob-content-type",
                "x-ms-blob-type",
                "x-ms-client-request-id",
                "x-ms-copy-source",
                "x-ms-date",
                "x-ms-meta-a",
                "x-ms-meta-ab",
                "x-ms-meta-a-b",
                "x-ms-meta-B",
                "x-ms-range",
                "x-ms-version",
            ]
        );
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(SharedKey::new("acct", "not base64!").is_err());
        assert!(SharedKey::new("", "a2V5").is_err());
        let k = SharedKey::new("acct", "a2V5").unwrap();
        assert!(!format!("{k:?}").contains("a2V5"));
    }
}
