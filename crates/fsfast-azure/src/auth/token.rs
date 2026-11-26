//! Microsoft Entra ID (Azure AD) OAuth2 bearer tokens for the Blob service.
//!
//! Token sources (azure-identity's credentials, reimplemented):
//!
//! * [`ClientSecret`]: `client_credentials` grant against
//!   `{authority}/{tenant}/oauth2/v2.0/token` (adlfs `client_id` /
//!   `client_secret` / `tenant_id`; `AZURE_CLIENT_*` in the default chain).
//! * [`WorkloadIdentity`]: the same endpoint with a federated
//!   `client_assertion` read from `AZURE_FEDERATED_TOKEN_FILE` on every
//!   fetch (the file is rotated by the kubelet).
//! * [`ManagedIdentity`]: App Service / Functions (`IDENTITY_ENDPOINT` +
//!   `IDENTITY_HEADER`), or the instance metadata service (IMDS,
//!   `169.254.169.254`, short timeouts, no proxy).
//! * [`AzureCli`]: `az account get-access-token --output json --resource
//!   https://storage.azure.com` run without blocking the runtime.
//! * [`StaticToken`]: a token the caller already has.
//! * [`Chain`]: adlfs's `DefaultAzureCredential` order (environment,
//!   workload identity, managed identity, Azure CLI); the first source that
//!   yields a token is used from then on.
//!
//! [`TokenCache`] keeps the current token, refreshes it 5 minutes before it
//! expires (azure-core's `BearerTokenCredentialPolicy` margin) with a single
//! fetch in flight, keeps using a still-valid token when a refresh fails, and
//! drops a token the service rejected (401) so the request is retried once
//! with a fresh one.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use fsfast_core::{Error, ErrorKind, Result};
use fsfast_http_transport::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use fsfast_http_transport::{HttpClient, Method, Request};
use zeroize::Zeroizing;

use crate::path::quote;

/// OAuth2 scope of the Storage data plane.
pub const STORAGE_SCOPE: &str = "https://storage.azure.com/.default";
/// v1 "resource" form of the same audience (IMDS, App Service, Azure CLI).
pub const STORAGE_RESOURCE: &str = "https://storage.azure.com";
/// Public-cloud authority host.
pub const DEFAULT_AUTHORITY: &str = "https://login.microsoftonline.com";
/// IMDS token endpoint.
pub const IMDS_ENDPOINT: &str = "http://169.254.169.254/metadata/identity/oauth2/token";
/// Refresh this long before expiry.
pub const REFRESH_MARGIN: Duration = Duration::from_secs(300);

/// An access token and its expiry.
#[derive(Clone)]
pub struct AccessToken {
    /// The bearer token.
    pub token: Zeroizing<String>,
    /// When it expires.
    pub expires_on: SystemTime,
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessToken")
            .field("token", &"<redacted>")
            .field("expires_on", &self.expires_on)
            .finish()
    }
}

/// HTTP clients used to fetch tokens.
#[derive(Debug, Clone)]
pub struct TokenHttp {
    /// For Entra ID endpoints (honours proxies).
    pub aad: HttpClient,
    /// For IMDS / App Service identity endpoints (no proxy, short timeouts).
    pub local: HttpClient,
}

/// Something that can produce access tokens.
#[async_trait]
pub trait TokenSource: Send + Sync + fmt::Debug {
    /// Fetch a new token.
    async fn fetch(&self, http: &TokenHttp) -> Result<AccessToken>;
    /// Credential name for messages (azure-identity's class name).
    fn name(&self) -> &'static str;
}

fn auth_error(source: &str, msg: impl fmt::Display) -> Error {
    Error::new(ErrorKind::PermissionDenied, format!("{source}: {msg}"))
}

/// Seconds since the epoch from a JSON number or numeric string.
fn json_secs(v: &serde_json::Value) -> Option<u64> {
    match v {
        serde_json::Value::Number(n) => n.as_u64().or_else(|| n.as_f64().map(|f| f as u64)),
        serde_json::Value::String(s) => s.trim().parse::<f64>().ok().map(|f| f as u64),
        _ => None,
    }
}

/// Parse a token endpoint response (`access_token` with `expires_on`
/// (epoch seconds) or `expires_in` (seconds from now)).
pub fn parse_token_response(body: &[u8], now: SystemTime) -> Result<AccessToken> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| Error::protocol(format!("invalid token response: {e}")))?;
    let token = v
        .get("access_token")
        .and_then(|t| t.as_str())
        .ok_or_else(|| Error::protocol("token response has no access_token"))?;
    let expires_on = if let Some(s) = v.get("expires_on").and_then(json_secs) {
        UNIX_EPOCH + Duration::from_secs(s)
    } else if let Some(s) = v.get("expires_in").and_then(json_secs) {
        now + Duration::from_secs(s)
    } else {
        return Err(Error::protocol("token response has no expiry"));
    };
    Ok(AccessToken {
        token: Zeroizing::new(token.to_owned()),
        expires_on,
    })
}

/// `application/x-www-form-urlencoded` body.
fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", quote(k, false), quote(v, false)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Normalise an authority host (`login.microsoftonline.com` →
/// `https://login.microsoftonline.com`).
pub fn normalize_authority(a: &str) -> String {
    let a = a.trim().trim_end_matches('/');
    if a.contains("://") {
        a.to_owned()
    } else {
        format!("https://{a}")
    }
}

/// POST a form to a token endpoint and parse the answer. Errors from the
/// endpoint (`{"error": ..., "error_description": ...}`) become
/// `PermissionDenied`.
async fn post_token(
    http: &HttpClient,
    url: &str,
    body: String,
    source: &str,
) -> Result<AccessToken> {
    let req = Request::new(Method::POST, url)?
        .header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        )
        .body(bytes::Bytes::from(body))
        // Token requests have no side effects.
        .retry_safe(true)
        .allow_status(400)
        .allow_status(401)
        .path(url.to_owned());
    let (status, body) = http
        .send_with(req, |r| async move {
            let s = r.status().as_u16();
            Ok((s, r.bytes().await?))
        })
        .await
        .map_err(|e| {
            auth_error(source, format_args!("token request failed: {e}")).with_kind(e.kind())
        })?;
    if status >= 400 {
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let err = v.get("error").and_then(|e| e.as_str()).unwrap_or("error");
        let desc = v
            .get("error_description")
            .and_then(|e| e.as_str())
            .and_then(|d| d.lines().next())
            .unwrap_or("");
        return Err(auth_error(source, format_args!("{err}: {desc}"))
            .with_detail(fsfast_core::Detail::Http(status))
            .with_detail(fsfast_core::Detail::Code(err.to_owned())));
    }
    parse_token_response(&body, SystemTime::now())
}

/// A fixed token supplied by the caller.
#[derive(Debug)]
pub struct StaticToken(pub AccessToken);

#[async_trait]
impl TokenSource for StaticToken {
    async fn fetch(&self, _: &TokenHttp) -> Result<AccessToken> {
        Ok(self.0.clone())
    }
    fn name(&self) -> &'static str {
        "StaticToken"
    }
}

/// Service principal with a client secret.
pub struct ClientSecret {
    /// Directory (tenant) id.
    pub tenant_id: String,
    /// Application (client) id.
    pub client_id: String,
    /// The secret.
    pub client_secret: Zeroizing<String>,
    /// Authority host URL.
    pub authority: String,
}

impl fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientSecret")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}

impl ClientSecret {
    /// The token endpoint.
    pub fn token_url(&self) -> String {
        format!(
            "{}/{}/oauth2/v2.0/token",
            self.authority,
            quote(&self.tenant_id, false)
        )
    }

    /// The form body of the token request.
    pub fn request_body(&self) -> String {
        form(&[
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("grant_type", "client_credentials"),
            ("scope", STORAGE_SCOPE),
        ])
    }
}

#[async_trait]
impl TokenSource for ClientSecret {
    async fn fetch(&self, http: &TokenHttp) -> Result<AccessToken> {
        post_token(
            &http.aad,
            &self.token_url(),
            self.request_body(),
            self.name(),
        )
        .await
    }
    fn name(&self) -> &'static str {
        "ClientSecretCredential"
    }
}

/// Federated workload identity (AKS, GitHub OIDC, ...).
#[derive(Debug)]
pub struct WorkloadIdentity {
    /// Directory (tenant) id.
    pub tenant_id: String,
    /// Application (client) id.
    pub client_id: String,
    /// File holding the federated token (`AZURE_FEDERATED_TOKEN_FILE`).
    pub token_file: std::path::PathBuf,
    /// Authority host URL.
    pub authority: String,
}

impl WorkloadIdentity {
    /// The token endpoint.
    pub fn token_url(&self) -> String {
        format!(
            "{}/{}/oauth2/v2.0/token",
            self.authority,
            quote(&self.tenant_id, false)
        )
    }

    /// The form body for a federated `assertion`.
    pub fn request_body(&self, assertion: &str) -> String {
        form(&[
            ("client_assertion", assertion),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_id", &self.client_id),
            ("grant_type", "client_credentials"),
            ("scope", STORAGE_SCOPE),
        ])
    }
}

#[async_trait]
impl TokenSource for WorkloadIdentity {
    async fn fetch(&self, http: &TokenHttp) -> Result<AccessToken> {
        let assertion = Zeroizing::new(tokio::fs::read_to_string(&self.token_file).await.map_err(
            |e| {
                auth_error(
                    self.name(),
                    format_args!("cannot read {}: {e}", self.token_file.display()),
                )
            },
        )?);
        let body = self.request_body(assertion.trim());
        post_token(&http.aad, &self.token_url(), body, self.name()).await
    }
    fn name(&self) -> &'static str {
        "WorkloadIdentityCredential"
    }
}

/// Where a managed identity token comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedIdentityEndpoint {
    /// The instance metadata service at this URL.
    Imds(String),
    /// App Service / Functions: `IDENTITY_ENDPOINT` and `IDENTITY_HEADER`.
    AppService {
        /// Endpoint URL.
        endpoint: String,
        /// Value of the `X-IDENTITY-HEADER` request header.
        header: String,
    },
}

/// Managed identity (system- or user-assigned).
#[derive(Debug)]
pub struct ManagedIdentity {
    /// Where to ask.
    pub endpoint: ManagedIdentityEndpoint,
    /// Client id of a user-assigned identity.
    pub client_id: Option<String>,
}

impl ManagedIdentity {
    /// The token request.
    pub fn request(&self) -> Result<Request> {
        let mut q = vec![];
        let (url, api, header) = match &self.endpoint {
            ManagedIdentityEndpoint::Imds(u) => (u.as_str(), "2018-02-01", None),
            ManagedIdentityEndpoint::AppService { endpoint, header } => {
                (endpoint.as_str(), "2019-08-01", Some(header.as_str()))
            }
        };
        q.push(format!("api-version={api}"));
        q.push(format!("resource={}", quote(STORAGE_RESOURCE, false)));
        if let Some(c) = &self.client_id {
            q.push(format!("client_id={}", quote(c, false)));
        }
        let sep = if url.contains('?') { '&' } else { '?' };
        let full = format!("{url}{sep}{}", q.join("&"));
        let mut req = Request::new(Method::GET, &full)?
            .allow_status(400)
            .path(url.to_owned());
        match header {
            None => {
                req = req.header(
                    HeaderName::from_static("metadata"),
                    HeaderValue::from_static("true"),
                );
            }
            Some(h) => {
                let v = HeaderValue::from_str(h).map_err(|_| {
                    Error::invalid_input("IDENTITY_HEADER is not a valid header value")
                })?;
                req = req.header(HeaderName::from_static("x-identity-header"), v);
            }
        }
        Ok(req)
    }
}

#[async_trait]
impl TokenSource for ManagedIdentity {
    async fn fetch(&self, http: &TokenHttp) -> Result<AccessToken> {
        let req = self.request()?;
        let (status, body) = http
            .local
            .send_with(req, |r| async move {
                let s = r.status().as_u16();
                Ok((s, r.bytes().await?))
            })
            .await
            .map_err(|e| {
                auth_error(
                    self.name(),
                    format_args!("no managed identity endpoint available: {e}"),
                )
                .with_kind(e.kind())
            })?;
        if status >= 400 {
            return Err(auth_error(
                self.name(),
                format_args!("{}", String::from_utf8_lossy(&body[..body.len().min(300)])),
            )
            .with_detail(fsfast_core::Detail::Http(status)));
        }
        parse_token_response(&body, SystemTime::now())
    }
    fn name(&self) -> &'static str {
        "ManagedIdentityCredential"
    }
}

/// The Azure CLI's cached login.
#[derive(Debug)]
pub struct AzureCli {
    /// `--tenant`.
    pub tenant_id: Option<String>,
    /// Kill `az` after this long (azure-identity `process_timeout`, 10 s).
    pub timeout: Duration,
    /// The executable (`az`).
    pub program: String,
}

impl AzureCli {
    /// The command-line arguments.
    pub fn args(&self) -> Vec<String> {
        let mut a = vec![
            "account".to_owned(),
            "get-access-token".to_owned(),
            "--output".to_owned(),
            "json".to_owned(),
            "--resource".to_owned(),
            STORAGE_RESOURCE.to_owned(),
        ];
        if let Some(t) = &self.tenant_id {
            a.push("--tenant".to_owned());
            a.push(t.clone());
        }
        a
    }

    /// Parse `az account get-access-token` output (`accessToken` with
    /// `expires_on` (epoch, CLI ≥ 2.54) or `expiresOn` (local time; read as
    /// UTC and capped at 30 minutes from now, since the local offset is
    /// unknown here; a rejected token is refreshed on the 401)).
    pub fn parse_output(out: &[u8], now: SystemTime) -> Result<AccessToken> {
        let v: serde_json::Value = serde_json::from_slice(out)
            .map_err(|e| Error::protocol(format!("unexpected Azure CLI output: {e}")))?;
        let token = v
            .get("accessToken")
            .and_then(|t| t.as_str())
            .ok_or_else(|| Error::protocol("Azure CLI output has no accessToken"))?;
        let expires_on = if let Some(s) = v.get("expires_on").and_then(json_secs) {
            UNIX_EPOCH + Duration::from_secs(s)
        } else if let Some(t) = v
            .get("expiresOn")
            .and_then(|t| t.as_str())
            .and_then(crate::time::parse_iso8601)
        {
            t.min(now + Duration::from_secs(1800))
        } else {
            return Err(Error::protocol("Azure CLI output has no expiry"));
        };
        Ok(AccessToken {
            token: Zeroizing::new(token.to_owned()),
            expires_on,
        })
    }
}

#[async_trait]
impl TokenSource for AzureCli {
    async fn fetch(&self, _: &TokenHttp) -> Result<AccessToken> {
        let mut cmd = tokio::process::Command::new(&self.program);
        cmd.args(self.args())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let child = cmd.spawn().map_err(|e| {
            let msg = if e.kind() == std::io::ErrorKind::NotFound {
                "Azure CLI not found on path".to_owned()
            } else {
                format!("cannot run Azure CLI: {e}")
            };
            auth_error(self.name(), msg)
        })?;
        let out = tokio::time::timeout(self.timeout, child.wait_with_output())
            .await
            .map_err(|_| {
                auth_error(self.name(), "Azure CLI timed out").with_kind(ErrorKind::Timeout)
            })?
            .map_err(|e| auth_error(self.name(), format_args!("Azure CLI failed: {e}")))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let line = err.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
            return Err(auth_error(
                self.name(),
                format_args!("Azure CLI failed ({}): {line}", out.status),
            ));
        }
        Self::parse_output(&out.stdout, SystemTime::now())
            .map_err(|e| auth_error(self.name(), e.message()))
    }
    fn name(&self) -> &'static str {
        "AzureCliCredential"
    }
}

/// adlfs's `DefaultAzureCredential`: try sources in order; stick with the
/// first one that works.
#[derive(Debug)]
pub struct Chain {
    sources: Vec<Box<dyn TokenSource>>,
    chosen: AtomicUsize,
}

impl Chain {
    /// A chain of `sources` (tried in order).
    pub fn new(sources: Vec<Box<dyn TokenSource>>) -> Self {
        Chain {
            sources,
            chosen: AtomicUsize::new(usize::MAX),
        }
    }

    /// Names of the sources, in order.
    pub fn names(&self) -> Vec<&'static str> {
        self.sources.iter().map(|s| s.name()).collect()
    }
}

#[async_trait]
impl TokenSource for Chain {
    async fn fetch(&self, http: &TokenHttp) -> Result<AccessToken> {
        let chosen = self.chosen.load(Ordering::Acquire);
        if let Some(s) = self.sources.get(chosen) {
            return s.fetch(http).await;
        }
        let mut errors = Vec::new();
        for (i, s) in self.sources.iter().enumerate() {
            match s.fetch(http).await {
                Ok(t) => {
                    tracing::debug!(
                        credential = s.name(),
                        "DefaultAzureCredential acquired a token"
                    );
                    self.chosen.store(i, Ordering::Release);
                    return Ok(t);
                }
                Err(e) => {
                    tracing::debug!(credential = s.name(), error = %e, "credential unavailable");
                    errors.push(e.to_string());
                }
            }
        }
        if errors.is_empty() {
            errors.push("no credential sources are enabled".to_owned());
        }
        Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "DefaultAzureCredential failed to retrieve a token from the included credentials: {}",
                errors.join("; ")
            ),
        ))
    }
    fn name(&self) -> &'static str {
        "DefaultAzureCredential"
    }
}

/// A cached, auto-refreshing token from a [`TokenSource`].
pub struct TokenCache {
    source: Box<dyn TokenSource>,
    http: TokenHttp,
    /// The current token (held only briefly, never across an `.await`).
    current: parking_lot::Mutex<Option<AccessToken>>,
    /// Held by the one caller that is fetching a token.
    refresh: tokio::sync::Mutex<()>,
    fetches: AtomicUsize,
    /// How many fetches have completed, and a copy of the latest one's error
    /// if it failed.
    /// Callers that were already waiting for that fetch share its failure
    /// instead of each repeating it in turn (azure-identity likewise fails
    /// fast once a credential turned out to be unavailable).
    last: parking_lot::Mutex<(usize, Option<Error>)>,
}

/// A copy of `e` for another caller (`Error` is not `Clone`).
fn copy_error(e: &Error) -> Error {
    let mut c = Error::new(e.kind(), e.message()).with_retryable(e.is_retryable());
    if let Some(p) = e.path() {
        c = c.with_path(p);
    }
    for d in e.details() {
        c = c.with_detail(d.clone());
    }
    c
}

impl fmt::Debug for TokenCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenCache")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl TokenCache {
    /// A cache over `source`.
    pub fn new(source: Box<dyn TokenSource>, http: TokenHttp) -> Arc<Self> {
        Arc::new(TokenCache {
            source,
            http,
            current: parking_lot::Mutex::new(None),
            refresh: tokio::sync::Mutex::new(()),
            fetches: AtomicUsize::new(0),
            last: parking_lot::Mutex::new((0, None)),
        })
    }

    /// The source.
    pub fn source(&self) -> &dyn TokenSource {
        &*self.source
    }

    /// How many tokens were fetched so far (diagnostics, tests).
    pub fn fetch_count(&self) -> usize {
        self.fetches.load(Ordering::Relaxed)
    }

    /// The current token if it has not expired, and whether it is still
    /// outside the refresh margin.
    fn current(&self, now: SystemTime) -> Option<(Zeroizing<String>, bool)> {
        self.current
            .lock()
            .as_ref()
            .filter(|t| t.expires_on > now)
            .map(|t| (t.token.clone(), t.expires_on > now + REFRESH_MARGIN))
    }

    /// A valid token, fetching or refreshing it if needed. Only one fetch is
    /// in flight. While a token that is about to expire (but has not) is
    /// being refreshed, other callers keep using it instead of waiting for
    /// the token endpoint (which can take seconds, e.g. the Azure CLI);
    /// without a valid token, they wait for the fetch, and when it fails
    /// they all get its error (rather than each running the whole, possibly
    /// slow, credential chain again in turn).
    pub async fn token(&self) -> Result<Zeroizing<String>> {
        // Fetches completed before this call; one completing later (even if
        // it started earlier) is a fetch this caller waited for.
        let seen = self.last.lock().0;
        let _guard = match self.current(SystemTime::now()) {
            Some((t, true)) => return Ok(t),
            Some((t, false)) => match self.refresh.try_lock() {
                Ok(g) => g,
                // Someone else is refreshing.
                Err(_) => return Ok(t),
            },
            None => self.refresh.lock().await,
        };
        // Another caller may have refreshed while we waited.
        let now = SystemTime::now();
        if let Some((t, true)) = self.current(now) {
            return Ok(t);
        }
        // ... or failed to: share that failure (keeping a token that has
        // not expired yet, as below).
        let shared = match &*self.last.lock() {
            (n, Some(e)) if *n > seen => Some(copy_error(e)),
            _ => None,
        };
        if let Some(e) = shared {
            return match self.current(now) {
                Some((t, _)) => Ok(t),
                None => Err(e),
            };
        }
        self.fetches.fetch_add(1, Ordering::Relaxed);
        let r = self.source.fetch(&self.http).await;
        {
            let mut last = self.last.lock();
            last.0 += 1;
            last.1 = r.as_ref().err().map(copy_error);
        }
        match r {
            Ok(t) => {
                let out = t.token.clone();
                *self.current.lock() = Some(t);
                Ok(out)
            }
            Err(e) => match self.current(now) {
                // Keep using a token that has not expired yet.
                Some((t, _)) => {
                    tracing::warn!(error = %e, "token refresh failed; using the current token");
                    Ok(t)
                }
                None => Err(e),
            },
        }
    }

    /// Forget `token` if it is the current one (the service rejected it).
    /// Returns whether a different token may be obtained.
    pub async fn invalidate(&self, token: &str) -> bool {
        let mut cur = self.current.lock();
        if cur.as_ref().is_some_and(|t| t.token.as_str() == token) {
            *cur = None;
        }
        // Either it was dropped, or someone already replaced it.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hands out a token close to expiry first, then fresh tokens slowly.
    #[derive(Debug)]
    struct SlowSource(AtomicUsize);

    #[async_trait]
    impl TokenSource for SlowSource {
        async fn fetch(&self, _: &TokenHttp) -> Result<AccessToken> {
            let n = self.0.fetch_add(1, Ordering::SeqCst);
            let expires_on = if n == 0 {
                SystemTime::now() + Duration::from_secs(60)
            } else {
                tokio::time::sleep(Duration::from_millis(500)).await;
                SystemTime::now() + Duration::from_secs(3600)
            };
            Ok(AccessToken {
                token: Zeroizing::new(format!("t{n}")),
                expires_on,
            })
        }
        fn name(&self) -> &'static str {
            "Slow"
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refresh_does_not_block_while_the_token_is_valid() {
        let http = HttpClient::new(fsfast_http_transport::HttpConfig::default()).unwrap();
        let cache = TokenCache::new(
            Box::new(SlowSource(AtomicUsize::new(0))),
            TokenHttp {
                aad: http.clone(),
                local: http,
            },
        );
        // A token inside the refresh margin.
        assert_eq!(cache.token().await.unwrap().as_str(), "t0");
        let c2 = cache.clone();
        let refresher = tokio::spawn(async move { c2.token().await.unwrap() });
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Meanwhile, other callers get the still-valid token at once.
        let t = tokio::time::timeout(Duration::from_millis(100), cache.token())
            .await
            .expect("callers must not wait for a refresh while the token is valid")
            .unwrap();
        assert_eq!(t.as_str(), "t0");
        assert_eq!(refresher.await.unwrap().as_str(), "t1");
        assert_eq!(cache.token().await.unwrap().as_str(), "t1");
        assert_eq!(cache.fetch_count(), 2);
    }

    /// Fails slowly, counting its calls.
    #[derive(Debug)]
    struct FailingSource(AtomicUsize);

    #[async_trait]
    impl TokenSource for FailingSource {
        async fn fetch(&self, _: &TokenHttp) -> Result<AccessToken> {
            self.0.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(300)).await;
            Err(Error::new(ErrorKind::PermissionDenied, "no credentials")
                .with_detail(fsfast_core::Detail::Code("Nope".into())))
        }
        fn name(&self) -> &'static str {
            "Failing"
        }
    }

    /// Concurrent callers waiting for a fetch that fails share its error
    /// instead of each repeating the (slow) fetch in turn; a later call
    /// tries again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_callers_share_a_failed_fetch() {
        let http = HttpClient::new(fsfast_http_transport::HttpConfig::default()).unwrap();
        let cache = TokenCache::new(
            Box::new(FailingSource(AtomicUsize::new(0))),
            TokenHttp {
                aad: http.clone(),
                local: http,
            },
        );
        let start = std::time::Instant::now();
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let c = cache.clone();
                tokio::spawn(async move { c.token().await })
            })
            .collect();
        for t in tasks {
            let e = t.await.unwrap().unwrap_err();
            assert_eq!(e.kind(), ErrorKind::PermissionDenied);
            assert_eq!(e.message(), "no credentials");
            assert_eq!(e.details(), &[fsfast_core::Detail::Code("Nope".into())]);
        }
        let elapsed = start.elapsed();
        assert_eq!(cache.fetch_count(), 1, "took {elapsed:?}");
        assert!(elapsed < Duration::from_millis(1200), "{elapsed:?}");
        // Not cached beyond the callers that waited for it.
        assert!(cache.token().await.is_err());
        assert_eq!(cache.fetch_count(), 2);
    }

    #[test]
    fn token_responses() {
        let now = UNIX_EPOCH + Duration::from_secs(1000);
        let t = parse_token_response(br#"{"access_token":"x","expires_in":3599}"#, now).unwrap();
        assert_eq!(t.expires_on, now + Duration::from_secs(3599));
        let t = parse_token_response(br#"{"access_token":"x","expires_on":"5000"}"#, now).unwrap();
        assert_eq!(t.expires_on, UNIX_EPOCH + Duration::from_secs(5000));
        assert!(parse_token_response(br#"{"access_token":"x"}"#, now).is_err());
        assert!(parse_token_response(b"nope", now).is_err());
        assert!(format!("{t:?}").contains("<redacted>"));
    }

    #[test]
    fn cli_output() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let t = AzureCli::parse_output(
            br#"{"accessToken":"tok","expiresOn":"2023-10-31 21:59:10.000000","expires_on":1698789550,"tenant":"t","tokenType":"Bearer"}"#,
            now,
        )
        .unwrap();
        assert_eq!(
            t.expires_on,
            UNIX_EPOCH + Duration::from_secs(1_698_789_550)
        );
        let t = AzureCli::parse_output(
            br#"{"accessToken":"tok","expiresOn":"2100-01-01 00:00:00.000000"}"#,
            now,
        )
        .unwrap();
        assert_eq!(t.expires_on, now + Duration::from_secs(1800));
    }

    #[test]
    fn request_construction() {
        let cs = ClientSecret {
            tenant_id: "tid".into(),
            client_id: "cid".into(),
            client_secret: Zeroizing::new("s&cret".into()),
            authority: normalize_authority("login.microsoftonline.com/"),
        };
        assert_eq!(
            cs.token_url(),
            "https://login.microsoftonline.com/tid/oauth2/v2.0/token"
        );
        assert_eq!(
            cs.request_body(),
            "client_id=cid&client_secret=s%26cret&grant_type=client_credentials&scope=https%3A%2F%2Fstorage.azure.com%2F.default"
        );
        let mi = ManagedIdentity {
            endpoint: ManagedIdentityEndpoint::Imds(IMDS_ENDPOINT.into()),
            client_id: Some("uid".into()),
        };
        let req = mi.request().unwrap();
        assert_eq!(
            req.url().as_str(),
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fstorage.azure.com&client_id=uid"
        );
        assert_eq!(req.headers()["metadata"], "true");
        let cli = AzureCli {
            tenant_id: Some("t".into()),
            timeout: Duration::from_secs(10),
            program: "az".into(),
        };
        assert_eq!(
            cli.args().join(" "),
            "account get-access-token --output json --resource https://storage.azure.com --tenant t"
        );
    }
}
