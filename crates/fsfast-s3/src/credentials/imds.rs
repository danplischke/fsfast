//! EC2 instance metadata (IMDSv2 with IMDSv1 fallback) role credentials.
//!
//! Short timeouts (default 1 s, one attempt, like botocore) keep machines
//! outside EC2 from hanging: an unreachable metadata service yields "no
//! credentials" from this provider, never an error.

use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use fsfast_core::{Error, Result};
use fsfast_http_transport::{HttpClient, HttpConfig, Method, ProxyConfig, Request};

use super::{Credentials, ProvideCredentials, credentials_from_json};
use crate::profile::{Env, ProfileFiles};

const IPV4_ENDPOINT: &str = "http://169.254.169.254/";
const IPV6_ENDPOINT: &str = "http://[fd00:ec2::254]/";
const TOKEN_TTL: &str = "21600";
const ROLE_PATH: &str = "latest/meta-data/iam/security-credentials/";

/// An HTTP client for link-local metadata services: short timeouts, no
/// retries of its own, no proxy (a proxy cannot reach link-local
/// addresses), no redirects.
pub(crate) fn metadata_client(timeout: Duration) -> Result<HttpClient> {
    HttpClient::new(HttpConfig {
        connect_timeout: Some(timeout),
        read_timeout: Some(timeout),
        total_timeout: Some(timeout * 3),
        max_retries: 0,
        proxy: ProxyConfig::Disabled,
        max_redirects: None,
        http2: false,
        ..HttpConfig::default()
    })
}

/// The IMDS role-credentials provider.
#[derive(Debug, Clone)]
pub struct ImdsProvider {
    disabled: bool,
    base: String,
    timeout: Duration,
    attempts: u32,
    v1_disabled: bool,
}

impl ImdsProvider {
    /// Configure from the environment and profile like botocore
    /// (`AWS_EC2_METADATA_DISABLED`, `AWS_EC2_METADATA_SERVICE_ENDPOINT[_MODE]`,
    /// `AWS_METADATA_SERVICE_TIMEOUT`, `AWS_METADATA_SERVICE_NUM_ATTEMPTS`,
    /// `AWS_EC2_METADATA_V1_DISABLED` and their profile keys).
    pub fn new(env: &Env, profiles: &ProfileFiles, profile: &str) -> Self {
        let cfg = |envk: &str, key: &str| {
            env.get(envk)
                .or_else(|| profiles.get(profile, key).map(str::to_owned))
        };
        let base = cfg("AWS_EC2_METADATA_SERVICE_ENDPOINT", "ec2_metadata_service_endpoint")
            .unwrap_or_else(|| {
                match cfg(
                    "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
                    "ec2_metadata_service_endpoint_mode",
                ) {
                    Some(m) if m.eq_ignore_ascii_case("ipv6") => IPV6_ENDPOINT.to_owned(),
                    _ => IPV4_ENDPOINT.to_owned(),
                }
            });
        let timeout = cfg("AWS_METADATA_SERVICE_TIMEOUT", "metadata_service_timeout")
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v > 0.0)
            .map_or(Duration::from_secs(1), Duration::from_secs_f64);
        let attempts = cfg("AWS_METADATA_SERVICE_NUM_ATTEMPTS", "metadata_service_num_attempts")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(1)
            .max(1);
        let v1_disabled = cfg("AWS_EC2_METADATA_V1_DISABLED", "ec2_metadata_v1_disabled")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        ImdsProvider {
            disabled: env.flag("AWS_EC2_METADATA_DISABLED"),
            base,
            timeout,
            attempts,
            v1_disabled,
        }
    }

    fn url(&self, path: &str) -> String {
        if self.base.ends_with('/') {
            format!("{}{path}", self.base)
        } else {
            format!("{}/{path}", self.base)
        }
    }

    /// `PUT latest/api/token`: `Some(token)`, or `None` when the service
    /// does not support IMDSv2 (403/404/405) or does not answer in time.
    async fn token(&self, client: &HttpClient) -> Result<Option<String>> {
        for _ in 0..self.attempts {
            let req = Request::new(Method::PUT, &self.url("latest/api/token"))?
                .try_header("x-aws-ec2-metadata-token-ttl-seconds", TOKEN_TTL)?
                .allow_status(403)
                .allow_status(404)
                .allow_status(405)
                .allow_status(400);
            match client.send(req).await {
                Ok(resp) => match resp.status().as_u16() {
                    200 => {
                        let body = resp.bytes_truncated(64 << 10).await?;
                        return Ok(Some(String::from_utf8_lossy(&body).trim().to_owned()));
                    }
                    403..=405 => return Ok(None),
                    400 => return Err(Error::invalid_input("bad IMDS token request (HTTP 400)")),
                    _ => {}
                },
                Err(e) if e.kind() == fsfast_core::ErrorKind::Timeout => return Ok(None),
                Err(e) => tracing::debug!(error = %e, "IMDS token request failed"),
            }
        }
        Ok(None)
    }

    async fn get(&self, client: &HttpClient, path: &str, token: Option<&str>) -> Option<String> {
        for _ in 0..self.attempts {
            let mut req = Request::new(Method::GET, &self.url(path)).ok()?.retry_safe(false);
            if let Some(t) = token {
                req = req.try_header("x-aws-ec2-metadata-token", t).ok()?;
            }
            match client.send(req).await {
                Ok(resp) if resp.status().as_u16() == 200 => {
                    if let Ok(b) = resp.bytes_truncated(1 << 20).await
                        && !b.is_empty()
                    {
                        return Some(String::from_utf8_lossy(&b).into_owned());
                    }
                }
                Ok(_) => {}
                Err(e) => tracing::debug!(error = %e, path, "IMDS request failed"),
            }
        }
        None
    }
}

#[async_trait]
impl ProvideCredentials for ImdsProvider {
    async fn provide(&self) -> Result<Option<Credentials>> {
        if self.disabled {
            return Ok(None);
        }
        let client = metadata_client(self.timeout)?;
        let token = match self.token(&client).await {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!(error = %e, "IMDS token fetch failed");
                return Ok(None);
            }
        };
        if token.is_none() && self.v1_disabled {
            tracing::debug!("IMDSv2 token unavailable and IMDSv1 is disabled");
            return Ok(None);
        }
        let Some(role) = self.get(&client, ROLE_PATH, token.as_deref()).await else {
            return Ok(None);
        };
        let Some(role) = role.lines().next().map(str::trim).filter(|r| !r.is_empty()) else {
            return Ok(None);
        };
        let Some(doc) = self
            .get(&client, &format!("{ROLE_PATH}{role}"), token.as_deref())
            .await
        else {
            return Ok(None);
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&doc) else {
            tracing::debug!("IMDS returned invalid JSON credentials");
            return Ok(None);
        };
        if let Some(code) = v.get("Code").and_then(|c| c.as_str())
            && code != "Success"
        {
            tracing::debug!(code, "IMDS credentials error");
            return Ok(None);
        }
        let Ok(mut creds) = credentials_from_json(&v, "instance metadata") else {
            return Ok(None);
        };
        // Static stability (botocore): credentials the service still hands
        // out after their expiry stay usable for a while instead of failing
        // every request while IMDS refreshes them.
        let now = SystemTime::now();
        if creds.expiry.is_some_and(|e| e <= now) {
            tracing::warn!("IMDS returned expired credentials; extending them by 15 minutes");
            creds.expiry = Some(now + Duration::from_secs(15 * 60));
        }
        Ok(Some(creds))
    }

    fn name(&self) -> &'static str {
        "iam-role"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration() {
        let env = Env::from_map([
            ("AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE", "IPv6"),
            ("AWS_METADATA_SERVICE_TIMEOUT", "0.25"),
            ("AWS_METADATA_SERVICE_NUM_ATTEMPTS", "3"),
        ]);
        let p = ImdsProvider::new(&env, &ProfileFiles::default(), "default");
        assert_eq!(p.base, IPV6_ENDPOINT);
        assert_eq!(p.timeout, Duration::from_millis(250));
        assert_eq!(p.attempts, 3);
        assert!(!p.disabled);
        let env = Env::from_map([
            ("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://127.0.0.1:1"),
            ("AWS_EC2_METADATA_DISABLED", "TRUE"),
        ]);
        let p = ImdsProvider::new(&env, &ProfileFiles::default(), "default");
        assert_eq!(p.url("latest/api/token"), "http://127.0.0.1:1/latest/api/token");
        assert!(p.disabled);
    }
}
