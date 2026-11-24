//! ECS / EKS Pod Identity container credentials
//! (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`,
//! `AWS_CONTAINER_CREDENTIALS_FULL_URI`, with
//! `AWS_CONTAINER_AUTHORIZATION_TOKEN[_FILE]`).

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use fsfast_core::{Error, ErrorKind, Result};
use fsfast_http_transport::{Request, Url};

use super::imds::metadata_client;
use super::{Credentials, ProvideCredentials, credentials_from_json};
use crate::profile::Env;

/// The ECS agent's credential endpoint, for relative URIs.
pub const DEFAULT_BASE: &str = "http://169.254.170.2";
const TIMEOUT: Duration = Duration::from_secs(2);
const ATTEMPTS: u32 = 3;
const RETRY_SLEEP: Duration = Duration::from_secs(1);
/// Hosts a non-HTTPS full URI may name (botocore's `_ALLOWED_HOSTS`), in
/// addition to loopback addresses.
const ALLOWED_HOSTS: &[&str] = &["169.254.170.2", "169.254.170.23", "fd00:ec2::23", "localhost"];

/// Container credentials provider.
#[derive(Debug, Clone)]
pub struct ContainerProvider {
    env: Env,
    base: String,
    retry_sleep: Duration,
}

impl ContainerProvider {
    /// A provider reading `env`; relative URIs are resolved against `base`.
    pub fn new(env: Env, base: impl Into<String>) -> Self {
        ContainerProvider {
            env,
            base: base.into(),
            retry_sleep: RETRY_SLEEP,
        }
    }

    /// Shorten the pause between attempts (tests).
    #[doc(hidden)]
    pub fn with_retry_sleep(mut self, d: Duration) -> Self {
        self.retry_sleep = d;
        self
    }

    fn url(&self) -> Result<Option<Url>> {
        if let Some(rel) = self.env.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
            let s = format!("{}{}", self.base.trim_end_matches('/'), rel);
            return Url::parse(&s)
                .map(Some)
                .map_err(|e| Error::invalid_input(format!("invalid container credentials URI {s:?}: {e}")));
        }
        let Some(full) = self.env.get("AWS_CONTAINER_CREDENTIALS_FULL_URI") else {
            return Ok(None);
        };
        let url = Url::parse(&full).map_err(|e| {
            Error::invalid_input(format!("invalid AWS_CONTAINER_CREDENTIALS_FULL_URI {full:?}: {e}"))
        })?;
        validate_full_uri(&url)?;
        Ok(Some(url))
    }

    fn auth_token(&self) -> Result<Option<String>> {
        let token = if let Some(path) = self.env.get("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") {
            // Re-read on every fetch: EKS rotates the token file.
            Some(std::fs::read_to_string(&path).map_err(|e| {
                Error::new(
                    ErrorKind::PermissionDenied,
                    format!("cannot read AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE {path:?}: {e}"),
                )
            })?)
        } else {
            self.env.get("AWS_CONTAINER_AUTHORIZATION_TOKEN")
        };
        if let Some(t) = &token
            && (t.contains('\r') || t.contains('\n'))
        {
            return Err(Error::invalid_input("Auth token value is not a legal header value"));
        }
        Ok(token)
    }
}

/// botocore's rule: HTTPS, a loopback address, or an allowed host.
fn validate_full_uri(url: &Url) -> Result<()> {
    if url.scheme() == "https" {
        return Ok(());
    }
    let host = url.host_str().unwrap_or("");
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()) || ALLOWED_HOSTS.contains(&bare) {
        return Ok(());
    }
    Err(Error::invalid_input(format!(
        "Unsupported host '{bare}'.  Can only retrieve metadata from a loopback address or one of \
         these hosts: {}",
        ALLOWED_HOSTS.join(", ")
    )))
}

#[async_trait]
impl ProvideCredentials for ContainerProvider {
    async fn provide(&self) -> Result<Option<Credentials>> {
        let Some(url) = self.url()? else {
            return Ok(None);
        };
        let client = metadata_client(TIMEOUT)?;
        let mut last = None;
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(self.retry_sleep).await;
            }
            // The token file is re-read on every attempt.
            let mut req = Request::from_url(fsfast_http_transport::Method::GET, url.clone())?
                .try_header("accept", "application/json")?
                .retry_safe(false);
            if let Some(t) = self.auth_token()? {
                let mut v = fsfast_http_transport::header::HeaderValue::from_str(&t)
                    .map_err(|_| Error::invalid_input("Auth token value is not a legal header value"))?;
                v.set_sensitive(true);
                req = req.header(fsfast_http_transport::header::AUTHORIZATION, v);
            }
            let res = async {
                let resp = client.send(req).await?;
                let body = resp.bytes_truncated(1 << 20).await?;
                let v: serde_json::Value = serde_json::from_slice(&body).map_err(|_| {
                    Error::protocol("Unable to parse JSON returned from container metadata services")
                })?;
                credentials_from_json(&v, "container metadata")
            }
            .await;
            match res {
                Ok(c) => return Ok(Some(c)),
                Err(e) => {
                    tracing::debug!(error = %e, attempt, "container credentials fetch failed");
                    last = Some(e);
                }
            }
        }
        let e = last.unwrap_or_else(|| Error::new(ErrorKind::Other, "no attempt made"));
        Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("Error when retrieving credentials from container-role: {e}"),
        ))
    }

    fn name(&self) -> &'static str {
        "container-role"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_uri_rules() {
        for ok in [
            "https://example.com/creds",
            "http://127.0.0.1:8080/x",
            "http://[::1]/x",
            "http://localhost/x",
            "http://169.254.170.23/v1/credentials",
        ] {
            assert!(validate_full_uri(&Url::parse(ok).unwrap()).is_ok(), "{ok}");
        }
        assert!(validate_full_uri(&Url::parse("http://evil.example.com/").unwrap()).is_err());
    }

    #[tokio::test]
    async fn not_configured_is_none() {
        let p = ContainerProvider::new(Env::from_map::<[(&str, &str); 0], _, _>([]), DEFAULT_BASE);
        assert!(p.provide().await.unwrap().is_none());
    }
}
