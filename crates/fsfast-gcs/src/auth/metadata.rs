//! The GCE metadata server (Compute Engine, GKE, Cloud Run, ...): residency
//! detection and access tokens, as google-auth's
//! `compute_engine._metadata` does it.
//!
//! * Detection pings `http://$GCE_METADATA_IP` (default `169.254.169.254`)
//!   with `Metadata-Flavor: Google` and requires the same header back; it
//!   falls back to the DMI product name (`Google...`) on Linux.
//!   `NO_GCE_CHECK=true` disables it. The result is cached per process and
//!   metadata address, so only the first filesystem pays for it.
//! * Requests never go through an HTTP proxy (the server is link-local)
//!   and use a short timeout: `GCE_METADATA_TIMEOUT` seconds per attempt
//!   (default 1, google-auth uses 3) with `GCE_METADATA_DETECT_RETRIES`
//!   attempts (default 3), so a machine outside Google Cloud waits at most
//!   ~3 s once per process instead of ~9 s.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use fsfast_core::{Error, ErrorKind, Result};
use fsfast_http_transport::{HttpClient, HttpConfig, ProxyConfig, Request};
use parking_lot::Mutex;
use tokio::sync::OnceCell;

use super::AccessToken;
use crate::env::GcsEnv;
use crate::error::GcsErrorParser;

const DEFAULT_IP: &str = "169.254.169.254";
const DEFAULT_HOST: &str = "metadata.google.internal";
const FLAVOR: &str = "Google";

/// Where and how to reach the metadata server.
#[derive(Debug, Clone)]
pub struct MetadataServer {
    /// `host[:port]` for metadata requests (`GCE_METADATA_HOST`).
    pub host: String,
    /// `host[:port]` for the residency ping (`GCE_METADATA_IP`).
    pub ip: String,
    /// Timeout of one attempt.
    pub timeout: Duration,
    /// Ping attempts.
    pub attempts: u32,
    /// `NO_GCE_CHECK=true`.
    pub no_check: bool,
    product_name_file: std::path::PathBuf,
    client: HttpClient,
}

impl MetadataServer {
    /// Configure from the environment.
    pub fn from_env(env: &GcsEnv) -> Result<Self> {
        let host = env
            .non_empty("GCE_METADATA_HOST")
            .or_else(|| env.non_empty("GCE_METADATA_ROOT"))
            .unwrap_or(DEFAULT_HOST)
            .to_owned();
        let ip = env.non_empty("GCE_METADATA_IP").unwrap_or(DEFAULT_IP).to_owned();
        let timeout = env
            .non_empty("GCE_METADATA_TIMEOUT")
            .and_then(|v| v.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v > 0.0)
            .map_or(Duration::from_secs(1), Duration::from_secs_f64);
        let attempts = env
            .non_empty("GCE_METADATA_DETECT_RETRIES")
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(3)
            .max(1);
        let cfg = HttpConfig {
            connect_timeout: Some(timeout),
            read_timeout: Some(timeout.max(Duration::from_secs(5))),
            proxy: ProxyConfig::Disabled,
            http2: false,
            max_retries: 3,
            retry_base_delay: Duration::from_millis(50),
            retry_max_delay: Duration::from_secs(1),
            max_redirects: None,
            ..HttpConfig::default()
        };
        let client = HttpClient::builder(cfg)
            .error_parser(Arc::new(GcsErrorParser))
            .build()?;
        Ok(MetadataServer {
            host,
            ip,
            timeout,
            attempts,
            no_check: env.get("NO_GCE_CHECK") == Some("true"),
            product_name_file: env
                .product_name_file
                .clone()
                .unwrap_or_else(|| "/sys/class/dmi/id/product_name".into()),
            client,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}/computeMetadata/v1/{path}", self.host)
    }

    /// Whether this process runs on Google Cloud with a metadata server
    /// (cached per process and address).
    pub async fn is_on_gce(&self) -> bool {
        if self.no_check {
            return false;
        }
        static CACHE: Mutex<Option<HashMap<String, Arc<OnceCell<bool>>>>> = Mutex::new(None);
        let cell = {
            let mut g = CACHE.lock();
            g.get_or_insert_with(HashMap::new)
                .entry(format!("{}|{}", self.ip, self.product_name_file.display()))
                .or_default()
                .clone()
        };
        *cell.get_or_init(|| self.detect()).await
    }

    async fn detect(&self) -> bool {
        if self.ping().await {
            return true;
        }
        if cfg!(windows) {
            return false;
        }
        match tokio::fs::read_to_string(&self.product_name_file).await {
            Ok(s) => s.trim().starts_with(FLAVOR),
            Err(_) => false,
        }
    }

    async fn ping(&self) -> bool {
        let url = format!("http://{}", self.ip);
        for attempt in 1..=self.attempts {
            let req = match Request::get(&url) {
                Ok(r) => r
                    .header(
                        fsfast_http_transport::header::HeaderName::from_static("metadata-flavor"),
                        fsfast_http_transport::header::HeaderValue::from_static(FLAVOR),
                    )
                    .timeout(self.timeout)
                    .allow_status(404)
                    .allow_status(403)
                    .retry_safe(false),
                Err(_) => return false,
            };
            match self.client.send_once(&req).await {
                Ok(resp) => {
                    let ok = resp.status().as_u16() == 200 && resp.header_str("metadata-flavor") == Some(FLAVOR);
                    return ok;
                }
                Err(e) => {
                    tracing::debug!(
                        attempt,
                        attempts = self.attempts,
                        error = %e.message(),
                        "GCE metadata server unavailable"
                    );
                    if attempt < self.attempts {
                        tokio::time::sleep(Duration::from_millis(50 << attempt.min(6))).await;
                    }
                }
            }
        }
        false
    }

    async fn get_text(&self, path: &str, query: Option<&str>) -> Result<String> {
        let mut url = self.url(path);
        if let Some(q) = query {
            url.push('?');
            url.push_str(q);
        }
        let req = Request::get(&url)?
            .header(
                fsfast_http_transport::header::HeaderName::from_static("metadata-flavor"),
                fsfast_http_transport::header::HeaderValue::from_static(FLAVOR),
            )
            .path(format!("metadata server {path}"));
        let resp = self.client.send(req).await.map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                e.with_kind(ErrorKind::PermissionDenied)
            } else {
                e
            }
        })?;
        if resp.header_str("metadata-flavor") != Some(FLAVOR) {
            return Err(Error::protocol(
                "metadata server response lacks the 'Metadata-Flavor: Google' header",
            ));
        }
        let body = resp.bytes().await?;
        String::from_utf8(body.to_vec())
            .map_err(|_| Error::protocol("metadata server returned non-UTF-8 text"))
    }

    /// An access token for the default service account, optionally for
    /// `scopes` (comma separated).
    pub async fn token(&self, scopes: Option<&str>) -> Result<AccessToken> {
        let q = scopes.map(|s| format!("scopes={}", crate::path::quote(s)));
        let text = zeroize::Zeroizing::new(
            self.get_text("instance/service-accounts/default/token", q.as_deref())
                .await?,
        );
        AccessToken::from_token_response(text.as_bytes(), None)
    }

    /// The project id of the instance.
    pub async fn project_id(&self) -> Result<String> {
        Ok(self.get_text("project/project-id", None).await?.trim().to_owned())
    }
}
