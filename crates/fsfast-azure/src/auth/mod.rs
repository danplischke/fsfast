//! Request authorization: Shared Key, SAS, Entra ID bearer tokens, or
//! anonymous access.
//!
//! [`Credential::authorize`] is applied to every Blob service request after
//! all headers are set: it adds `x-ms-version` / `x-ms-date` (always, like
//! the SDK) and then
//!
//! * Shared Key: `Authorization: SharedKey account:signature` over the final
//!   URL, headers and body length ([`shared_key`]);
//! * SAS: the token's query parameters appended to the URL ([`sas`]);
//! * bearer: `Authorization: Bearer <token>` from a [`token::TokenCache`];
//!   bearer tokens are only sent over HTTPS (azure-core refuses plain HTTP)
//!   or to a loopback address (test servers).

pub mod sas;
pub mod shared_key;
pub mod token;

use std::sync::Arc;
use std::time::SystemTime;

use fsfast_core::{Error, Result};
use fsfast_http_transport::Request;
use fsfast_http_transport::header::{AUTHORIZATION, HeaderName, HeaderValue};
use zeroize::Zeroizing;

pub use shared_key::SharedKey;
pub use token::{AccessToken, TokenCache, TokenSource};

use crate::time::rfc1123;

/// The REST API version fsfast speaks (`x-ms-version`). Recent enough for
/// 4000 MiB blocks, 100 MiB append blocks, versioning and Put Block From
/// URL; accepted by Azurite.
pub const API_VERSION: &str = "2024-11-04";

/// How requests are authorized. `Debug` never shows the SAS token.
#[derive(Clone)]
pub enum Credential {
    /// No authorization (public containers).
    Anonymous,
    /// Shared Key with the account key.
    SharedKey(Arc<SharedKey>),
    /// A SAS token (query string without `?`).
    Sas(Arc<str>),
    /// Entra ID bearer tokens.
    Bearer(Arc<TokenCache>),
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credential::Anonymous => f.write_str("Anonymous"),
            Credential::SharedKey(k) => f.debug_tuple("SharedKey").field(k).finish(),
            Credential::Sas(_) => f.write_str("Sas(<redacted>)"),
            Credential::Bearer(c) => f.debug_tuple("Bearer").field(c).finish(),
        }
    }
}

/// What [`Credential::authorize`] used, so a 401 can invalidate a token.
pub enum Used {
    /// Nothing to refresh.
    Static,
    /// This bearer token.
    Token(Zeroizing<String>),
}

impl std::fmt::Debug for Used {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Used::Static => f.write_str("Static"),
            Used::Token(_) => f.write_str("Token(<redacted>)"),
        }
    }
}

fn is_loopback(url: &fsfast_http_transport::Url) -> bool {
    let Some(h) = url.host_str() else {
        return false;
    };
    let h = h.trim_start_matches('[').trim_end_matches(']');
    h.eq_ignore_ascii_case("localhost")
        || h.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_loopback())
}

/// Append `extra` (already encoded `k=v&...`) to the URL's query.
pub fn append_query(req: &mut Request, extra: &str) {
    if extra.is_empty() {
        return;
    }
    let u = req.url_mut();
    let q = match u.query() {
        Some(q) if !q.is_empty() => format!("{q}&{extra}"),
        _ => extra.to_owned(),
    };
    u.set_query(Some(&q));
}

impl Credential {
    /// Whether requests carry no credentials at all.
    pub fn is_anonymous(&self) -> bool {
        matches!(self, Credential::Anonymous)
    }

    /// The SAS token, if this is SAS authorization.
    pub fn sas(&self) -> Option<&str> {
        match self {
            Credential::Sas(s) => Some(s),
            _ => None,
        }
    }

    /// Authorize `req`, whose body is `content_length` bytes.
    pub async fn authorize(&self, req: &mut Request, content_length: u64) -> Result<Used> {
        let h = req.headers_mut();
        h.insert(
            HeaderName::from_static("x-ms-version"),
            HeaderValue::from_static(API_VERSION),
        );
        let date = HeaderValue::from_str(&rfc1123(SystemTime::now()))
            .expect("an HTTP date is a valid header value");
        h.insert(HeaderName::from_static("x-ms-date"), date);
        match self {
            Credential::Anonymous => Ok(Used::Static),
            Credential::Sas(token) => {
                append_query(req, token);
                Ok(Used::Static)
            }
            Credential::SharedKey(key) => {
                let sts = key.string_to_sign(
                    req.method().as_str(),
                    req.url(),
                    req.headers(),
                    content_length,
                );
                let auth = HeaderValue::from_str(&key.authorization(&sts))
                    .map_err(|_| Error::invalid_input("invalid Shared Key authorization header"))?;
                req.headers_mut().insert(AUTHORIZATION, auth);
                Ok(Used::Static)
            }
            Credential::Bearer(cache) => {
                if req.url().scheme() != "https" && !is_loopback(req.url()) {
                    return Err(Error::invalid_input(
                        "Bearer token authentication is not permitted for non-TLS protected (non-https) URLs.",
                    ));
                }
                let token = cache.token().await?;
                let mut v = HeaderValue::from_str(&format!("Bearer {}", token.as_str()))
                    .map_err(|_| Error::protocol("access token is not a valid header value"))?;
                v.set_sensitive(true);
                req.headers_mut().insert(AUTHORIZATION, v);
                Ok(Used::Token(token))
            }
        }
    }

    /// After a 401 for a request authorized with `used`: whether retrying
    /// with a fresh token may help (the rejected token is dropped).
    pub async fn on_unauthorized(&self, used: &Used) -> bool {
        match (self, used) {
            (Credential::Bearer(cache), Used::Token(t)) => cache.invalidate(t).await,
            _ => false,
        }
    }
}
