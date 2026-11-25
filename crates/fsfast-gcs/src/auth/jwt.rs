//! Service-account keys: RS256 signing (RSASSA-PKCS1-v1_5 / SHA-256 with
//! aws-lc-rs) and the OAuth 2.0 JWT-bearer assertion google-auth builds.
//!
//! The assertion is byte-for-byte what `google.oauth2.service_account`
//! produces for the same key and clock (Python `json.dumps` formatting,
//! claim order, `aud` = `https://oauth2.googleapis.com/token`), which the
//! tests check against a vector generated with google-auth. PKCS#1 v1.5
//! signatures are deterministic, so the whole JWT is reproducible.

use std::fmt;

use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use base64::Engine as _;
use fsfast_core::{Error, Result};
use serde_json::{Map, Value as Json};
use zeroize::Zeroizing;

/// google-auth's default token endpoint (also the JWT audience).
pub const GOOGLE_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// Lifetime of an assertion (google-auth `_DEFAULT_TOKEN_LIFETIME_SECS`).
pub const ASSERTION_LIFETIME_SECS: u64 = 3600;

/// The JWT-bearer grant type.
pub const JWT_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// A service-account key (the `"type": "service_account"` JSON file).
pub struct ServiceAccountKey {
    /// `client_email`: the JWT issuer and signed-URL credential.
    pub client_email: String,
    /// `private_key_id`: the JWT `kid` header.
    pub private_key_id: Option<String>,
    /// `token_uri`: where assertions are exchanged for access tokens.
    pub token_uri: String,
    /// `project_id`.
    pub project_id: Option<String>,
    /// `quota_project_id` (sent as `x-goog-user-project`).
    pub quota_project_id: Option<String>,
    key: RsaKeyPair,
}

impl fmt::Debug for ServiceAccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccountKey")
            .field("client_email", &self.client_email)
            .field("private_key_id", &self.private_key_id)
            .field("token_uri", &self.token_uri)
            .finish_non_exhaustive()
    }
}

fn str_field<'a>(info: &'a Map<String, Json>, k: &str) -> Option<&'a str> {
    info.get(k).and_then(Json::as_str)
}

impl ServiceAccountKey {
    /// Load from the parsed JSON key file (google-auth
    /// `service_account.Credentials.from_service_account_info`: requires
    /// `client_email`, `token_uri` and a valid `private_key`).
    pub fn from_info(info: &Map<String, Json>) -> Result<Self> {
        let missing = |k: &str| {
            Error::invalid_input(format!(
                "Service account info was not in the expected format, missing fields {k}."
            ))
        };
        let client_email = str_field(info, "client_email").ok_or_else(|| missing("client_email"))?;
        let token_uri = str_field(info, "token_uri").ok_or_else(|| missing("token_uri"))?;
        let pem = str_field(info, "private_key").ok_or_else(|| missing("private_key"))?;
        let key = parse_private_key(pem)?;
        Ok(ServiceAccountKey {
            client_email: client_email.to_owned(),
            private_key_id: str_field(info, "private_key_id").map(str::to_owned),
            token_uri: token_uri.to_owned(),
            project_id: str_field(info, "project_id").map(str::to_owned),
            quota_project_id: str_field(info, "quota_project_id").map(str::to_owned),
            key,
        })
    }

    /// RS256 signature of `msg`.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let mut sig = vec![0u8; self.key.public_modulus_len()];
        let rng = aws_lc_rs::rand::SystemRandom::new();
        self.key
            .sign(&RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .map_err(|_| Error::new(fsfast_core::ErrorKind::Other, "RSA signing failed"))?;
        Ok(sig)
    }

    /// The signed JWT assertion for `scope`, issued at `iat` (seconds since
    /// the epoch), exactly as google-auth encodes it.
    pub fn assertion(&self, scope: &str, iat: u64) -> Result<Zeroizing<String>> {
        let mut header = String::from("{\"typ\": \"JWT\", \"alg\": \"RS256\"");
        if let Some(kid) = &self.private_key_id {
            header.push_str(", \"kid\": ");
            push_py_json_str(&mut header, kid);
        }
        header.push('}');
        let mut payload = format!(
            "{{\"iat\": {iat}, \"exp\": {}, \"iss\": ",
            iat + ASSERTION_LIFETIME_SECS
        );
        push_py_json_str(&mut payload, &self.client_email);
        payload.push_str(", \"aud\": ");
        push_py_json_str(&mut payload, GOOGLE_TOKEN_URI);
        payload.push_str(", \"scope\": ");
        push_py_json_str(&mut payload, scope);
        payload.push('}');
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut out = Zeroizing::new(String::with_capacity(1024));
        out.push_str(&b64.encode(header.as_bytes()));
        out.push('.');
        out.push_str(&b64.encode(payload.as_bytes()));
        let sig = self.sign(out.as_bytes())?;
        out.push('.');
        out.push_str(&b64.encode(&sig));
        Ok(out)
    }
}

/// Parse a PEM private key: PKCS#8 (`BEGIN PRIVATE KEY`, what Google issues)
/// or PKCS#1 (`BEGIN RSA PRIVATE KEY`).
pub fn parse_private_key(pem: &str) -> Result<RsaKeyPair> {
    let bad = |why: &str| Error::invalid_input(format!("invalid service account private key: {why}"));
    let (label, body) = pem_body(pem).ok_or_else(|| bad("no PEM block found"))?;
    let der: Zeroizing<Vec<u8>> = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .map_err(|_| bad("invalid base64"))?,
    );
    match label.as_str() {
        "PRIVATE KEY" => RsaKeyPair::from_pkcs8(&der).map_err(|e| bad(&format!("PKCS#8: {e}"))),
        "RSA PRIVATE KEY" => RsaKeyPair::from_der(&der).map_err(|e| bad(&format!("PKCS#1: {e}"))),
        other => Err(bad(&format!("unsupported PEM block {other:?}"))),
    }
}

/// The label and base64 body (whitespace removed) of the first PEM block.
fn pem_body(pem: &str) -> Option<(String, Zeroizing<String>)> {
    let begin = pem.find("-----BEGIN ")?;
    let rest = &pem[begin + "-----BEGIN ".len()..];
    let label_end = rest.find("-----")?;
    let label = rest[..label_end].to_owned();
    let body_start = &rest[label_end + 5..];
    let end_marker = format!("-----END {label}-----");
    let body_end = body_start.find(&end_marker)?;
    let body: String = body_start[..body_end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    Some((label, Zeroizing::new(body)))
}

/// Append `s` as a JSON string the way Python's `json.dumps` writes it
/// (`ensure_ascii=True`: non-ASCII as lowercase `\uXXXX` escapes, UTF-16
/// surrogate pairs above the BMP).
pub fn push_py_json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if !(' '..='~').contains(&c) => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `application/x-www-form-urlencoded` body from pairs, like Python's
/// `urllib.parse.urlencode` (`quote_plus`).
pub fn form_urlencode(pairs: &[(&str, &str)]) -> String {
    const FORM: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~')
        .remove(b' ');
    let enc = |s: &str| percent_encoding::utf8_percent_encode(s, FORM).to_string().replace(' ', "+");
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_json_strings() {
        let mut s = String::new();
        push_py_json_str(&mut s, "a\"b\\c\n\u{1}é😀\u{7f}~");
        assert_eq!(s, r#""a\"b\\c\n\u0001\u00e9\ud83d\ude00\u007f~""#);
    }

    #[test]
    fn form_encoding() {
        assert_eq!(
            form_urlencode(&[("grant_type", JWT_GRANT_TYPE), ("x", "a b+c")]),
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&x=a+b%2Bc"
        );
    }

    #[test]
    fn pem_parsing() {
        assert!(pem_body("nothing").is_none());
        let (label, body) =
            pem_body("x\n-----BEGIN PRIVATE KEY-----\nAAAA\nBBBB\n-----END PRIVATE KEY-----\n").unwrap();
        assert_eq!(label, "PRIVATE KEY");
        assert_eq!(body.as_str(), "AAAABBBB");
        assert!(parse_private_key("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----").is_err());
        assert!(parse_private_key("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----").is_err());
    }
}
