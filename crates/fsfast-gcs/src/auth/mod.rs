//! Authentication with gcsfs's `token=` semantics.
//!
//! | `token` | credentials |
//! |---|---|
//! | `None` (default) | gcsfs tries `google_default`, then `cloud` (only against Google's endpoint), then anonymous access, falling through on any failure |
//! | `"google_default"` | application default credentials: the `GOOGLE_APPLICATION_CREDENTIALS` file, gcloud's ADC file, then the GCE metadata server; the project comes from them (`GOOGLE_CLOUD_PROJECT` overrides) and must match an explicit `project` |
//! | `"cloud"` | the GCE metadata server (not against emulators) |
//! | `"anon"` | no authentication |
//! | a path to a JSON file | a service-account key, else user credentials (`refresh_token`, `client_id`, `client_secret`) |
//! | a dict | the same, from the dict |
//! | any other string | a raw access token (used as is, never refreshed) |
//!
//! `"cache"` and `"browser"` (gcsfs's pickled token cache and interactive
//! OAuth flow) are `Unsupported`.
//!
//! Files are read when the filesystem is built; everything that needs the
//! network (the metadata server, token exchanges) happens on first use.
//! Access tokens are cached and refreshed shortly before they expire
//! (gcsfs's 300 s margin, at most half the token's lifetime), with one
//! refresh shared by all concurrent requests; a 401 response drops the
//! cached token and the request is retried once with a fresh one.

pub mod adc;
pub mod jwt;
pub mod metadata;

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fsfast_core::{Error, ErrorKind, Result, Value};
use fsfast_http_transport::header::{HeaderName, HeaderValue};
use fsfast_http_transport::{HttpClient, Method, Request};
use serde_json::Value as Json;
use tokio::sync::OnceCell;
use zeroize::Zeroizing;

use self::adc::{AuthorizedUser, FileCredentials};
use self::jwt::{JWT_GRANT_TYPE, ServiceAccountKey, form_urlencode};
use self::metadata::MetadataServer;
use crate::env::GcsEnv;
use crate::error::GcsErrorParser;

/// gcsfs's `LOCAL_REFRESH_BUFFER`: refresh tokens expiring within 300 s.
pub const REFRESH_MARGIN: Duration = Duration::from_secs(300);

/// gcsfs `access` levels and their OAuth scopes.
pub fn scope_for_access(access: &str) -> Result<String> {
    match access {
        "read_only" | "read_write" | "full_control" => Ok(format!(
            "https://www.googleapis.com/auth/devstorage.{access}"
        )),
        other => Err(Error::invalid_input(format!(
            "access must be one of {{'read_only', 'read_write', 'full_control'}}, got {other:?}"
        ))),
    }
}

/// An OAuth access token.
#[derive(Clone)]
pub struct AccessToken {
    /// `Authorization: Bearer ...` (marked sensitive).
    pub header: HeaderValue,
    /// When it expires (unknown for raw tokens).
    pub expires_at: Option<Instant>,
    /// When to refresh it.
    pub refresh_at: Option<Instant>,
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessToken")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl AccessToken {
    /// A token without known expiry.
    pub fn bearer(token: &str) -> Result<Self> {
        let mut header = HeaderValue::try_from(format!("Bearer {token}"))
            .map_err(|_| Error::invalid_input("access token contains invalid characters"))?;
        header.set_sensitive(true);
        Ok(AccessToken {
            header,
            expires_at: None,
            refresh_at: None,
        })
    }

    /// Parse an OAuth token response `{"access_token", "expires_in", ...}`.
    pub fn from_token_response(body: &[u8], now: Option<Instant>) -> Result<Self> {
        let v: Json = serde_json::from_slice(body)
            .map_err(|e| Error::protocol(format!("invalid token response: {e}")))?;
        let token = v
            .get("access_token")
            .and_then(Json::as_str)
            .ok_or_else(|| Error::protocol("No access token in response."))?;
        let token = Zeroizing::new(token.to_owned());
        let expires_in = match v.get("expires_in") {
            Some(Json::Number(n)) => n.as_f64(),
            Some(Json::String(s)) => s.trim().parse::<f64>().ok(),
            _ => None,
        }
        .filter(|s| s.is_finite() && *s >= 0.0);
        let mut t = AccessToken::bearer(&token)?;
        if let Some(secs) = expires_in {
            let now = now.unwrap_or_else(Instant::now);
            let lifetime = Duration::from_secs_f64(secs.min(1e9));
            t.expires_at = Some(now + lifetime);
            // Refresh 300 s before expiry, but never later than half-way
            // through a short-lived token (so a token issued with less
            // than 300 s left is not refetched for every request).
            let margin = REFRESH_MARGIN.min(lifetime / 2);
            t.refresh_at = Some(now + lifetime - margin);
        }
        Ok(t)
    }

    fn is_fresh(&self, now: Instant) -> bool {
        self.refresh_at.is_none_or(|r| now < r)
    }
}

/// Where access tokens come from.
#[derive(Clone)]
pub enum Source {
    /// A raw token (never refreshed).
    Static(AccessToken),
    /// A service-account key: signed JWT exchanged at its `token_uri`.
    ServiceAccount(Arc<ServiceAccountKey>),
    /// A refresh token exchanged at its `token_uri`.
    AuthorizedUser(AuthorizedUser),
    /// The GCE metadata server, optionally asking for scopes.
    Metadata(Arc<MetadataServer>, Option<String>),
}

impl fmt::Debug for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::Static(_) => f.write_str("Static"),
            Source::ServiceAccount(k) => f.debug_tuple("ServiceAccount").field(&k.client_email).finish(),
            Source::AuthorizedUser(u) => f.debug_tuple("AuthorizedUser").field(&u.client_id).finish(),
            Source::Metadata(m, s) => f.debug_tuple("Metadata").field(&m.host).field(s).finish(),
        }
    }
}

impl Source {
    fn from_file(c: &FileCredentials) -> Self {
        match c {
            FileCredentials::ServiceAccount(k) => Source::ServiceAccount(k.clone()),
            FileCredentials::AuthorizedUser(u) => Source::AuthorizedUser(u.clone()),
        }
    }

    fn quota_project(&self) -> Option<&str> {
        match self {
            Source::ServiceAccount(k) => k.quota_project_id.as_deref(),
            Source::AuthorizedUser(u) => u.quota_project_id.as_deref(),
            _ => None,
        }
    }

    async fn fetch(&self, http: &HttpClient, scope: &str) -> Result<AccessToken> {
        match self {
            Source::Static(t) => Ok(t.clone()),
            Source::ServiceAccount(key) => {
                let iat = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let assertion = key.assertion(scope, iat)?;
                let body = form_urlencode(&[("assertion", &assertion), ("grant_type", JWT_GRANT_TYPE)]);
                token_request(http, &key.token_uri, body).await
            }
            Source::AuthorizedUser(u) => {
                let body = form_urlencode(&[
                    ("grant_type", "refresh_token"),
                    ("client_id", &u.client_id),
                    ("client_secret", &u.client_secret),
                    ("refresh_token", &u.refresh_token),
                ]);
                token_request(http, &u.token_uri, body).await
            }
            Source::Metadata(m, scopes) => m.token(scopes.as_deref()).await.map_err(|e| {
                Error::new(
                    ErrorKind::PermissionDenied,
                    format!("cannot get an access token from the GCE metadata server: {e}"),
                )
                .with_retryable(e.is_retryable())
            }),
        }
    }
}

/// POST a token request (form body) and parse the response. Errors from
/// the endpoint become `PermissionDenied` with the OAuth error code.
async fn token_request(http: &HttpClient, uri: &str, body: String) -> Result<AccessToken> {
    let body = Zeroizing::new(body);
    let req = Request::new(Method::POST, uri)?
        .header(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        )
        .body(bytes::Bytes::copy_from_slice(body.as_bytes()))
        .error_parser(Arc::new(GcsErrorParser))
        .status_kind(400, ErrorKind::PermissionDenied)
        .status_kind(404, ErrorKind::PermissionDenied)
        // Exchanging the same grant twice is harmless.
        .retry_safe(true)
        .path(format!("token endpoint {}", fsfast_http_transport::redact_url(&fsfast_http_transport::Url::parse(uri).map_err(|e| Error::invalid_input(format!("invalid token_uri {uri:?}: {e}")))?)));
    let resp = http.send(req).await?;
    let started = Instant::now();
    let data = Zeroizing::new(resp.bytes().await?.to_vec());
    AccessToken::from_token_response(&data, Some(started))
}

/// A token source plus the cached token, refreshed by one request at a
/// time.
#[derive(Debug)]
pub struct TokenCache {
    source: Source,
    current: parking_lot::Mutex<Option<AccessToken>>,
    refresh: tokio::sync::Mutex<()>,
}

impl TokenCache {
    /// A cache over `source`.
    pub fn new(source: Source) -> Self {
        let current = match &source {
            Source::Static(t) => Some(t.clone()),
            _ => None,
        };
        TokenCache {
            source,
            current: parking_lot::Mutex::new(current),
            refresh: tokio::sync::Mutex::new(()),
        }
    }

    /// The source.
    pub fn source(&self) -> &Source {
        &self.source
    }

    fn fresh(&self) -> Option<HeaderValue> {
        let now = Instant::now();
        self.current
            .lock()
            .as_ref()
            .filter(|t| t.is_fresh(now))
            .map(|t| t.header.clone())
    }

    /// The `Authorization` header to send, refreshing the token if needed.
    pub async fn header(&self, http: &HttpClient, scope: &str) -> Result<HeaderValue> {
        if let Some(h) = self.fresh() {
            return Ok(h);
        }
        let _g = self.refresh.lock().await;
        if let Some(h) = self.fresh() {
            return Ok(h);
        }
        tracing::debug!(source = ?self.source, "refreshing GCS access token");
        let t = self.source.fetch(http, scope).await?;
        let h = t.header.clone();
        *self.current.lock() = Some(t);
        Ok(h)
    }

    /// Forget the token `used` (after a 401), unless it was already
    /// replaced. Returns whether a refresh can help (static tokens cannot
    /// be refreshed).
    pub fn invalidate(&self, used: &HeaderValue) -> bool {
        if matches!(self.source, Source::Static(_)) {
            return false;
        }
        let mut g = self.current.lock();
        if g.as_ref().is_some_and(|t| t.header == *used) {
            *g = None;
        }
        true
    }

    /// `x-goog-user-project` from the credentials' quota project.
    pub fn quota_project(&self) -> Option<&str> {
        self.source.quota_project()
    }
}

/// The parsed `token` option.
#[derive(Clone)]
pub enum TokenSpec {
    /// `None`: try google_default, cloud, anon.
    Auto,
    /// `"google_default"`.
    GoogleDefault,
    /// `"cloud"`.
    Cloud,
    /// `"anon"`.
    Anon,
    /// A token file or a raw token (decided by whether the file exists).
    Str(Zeroizing<String>),
    /// A token dict.
    Dict(std::collections::BTreeMap<String, Value>),
}

impl fmt::Debug for TokenSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenSpec::Auto => f.write_str("Auto"),
            TokenSpec::GoogleDefault => f.write_str("GoogleDefault"),
            TokenSpec::Cloud => f.write_str("Cloud"),
            TokenSpec::Anon => f.write_str("Anon"),
            TokenSpec::Str(_) => f.write_str("Str(<redacted>)"),
            TokenSpec::Dict(_) => f.write_str("Dict(<redacted>)"),
        }
    }
}

impl TokenSpec {
    /// From the option value.
    pub fn from_value(v: Option<Value>) -> Result<Self> {
        match v {
            None | Some(Value::Null) => Ok(TokenSpec::Auto),
            Some(Value::Str(s)) => match s.as_str() {
                "google_default" => Ok(TokenSpec::GoogleDefault),
                "cloud" => Ok(TokenSpec::Cloud),
                "anon" => Ok(TokenSpec::Anon),
                "cache" => Err(Error::unsupported(
                    "token='cache' (gcsfs's pickled token cache); pass a credentials file instead",
                )),
                "browser" => Err(Error::unsupported(
                    "token='browser' (interactive OAuth flow); run `gcloud auth application-default login` and use token='google_default'",
                )),
                "token" => Err(Error::invalid_input("token='token' requires a token value")),
                _ => Ok(TokenSpec::Str(Zeroizing::new(s))),
            },
            Some(Value::Map(m)) => Ok(TokenSpec::Dict(m)),
            Some(other) => Err(Error::invalid_input(format!(
                "gcs: option 'token' must be None, a string or a dict, got {} (credentials objects \
                 cannot be passed to fsfast; pass their JSON file or dict)",
                other.type_name()
            ))),
        }
    }
}

/// How credentials are obtained, decided when the filesystem is built.
#[derive(Debug, Clone)]
enum Plan {
    /// Known now (anonymous when `None`).
    Fixed(Option<Source>),
    /// The metadata server, decided on first use.
    Lazy {
        /// google_default reached its GCE step (detect first, ask for scopes,
        /// project from the metadata server).
        gce_default: bool,
        /// Then gcsfs's `cloud` method (fetch a token without detection).
        cloud: bool,
        /// Fall back to anonymous access if nothing worked (token=None).
        anon_fallback: bool,
        /// A project the user passed (google_default must match it).
        user_project: Option<String>,
    },
}

/// Resolved credentials.
#[derive(Debug)]
pub struct Resolved {
    /// Token cache; `None` for anonymous access.
    pub tokens: Option<TokenCache>,
    /// The effective project (gcsfs `fs.project`).
    pub project: Option<String>,
}

/// gcsfs `GoogleCredentials`.
pub struct Credentials {
    scope: String,
    plan: Plan,
    /// Project for `Fixed` plans.
    fixed_project: Option<String>,
    /// A service-account key usable for signing, when known up front.
    signer: Option<Arc<ServiceAccountKey>>,
    metadata: Arc<MetadataServer>,
    /// `GOOGLE_CLOUD_PROJECT` / `GCLOUD_PROJECT` (google-auth's explicit
    /// project, overriding detected ones).
    env_project: Option<String>,
    resolved: OnceCell<Arc<Resolved>>,
    method: &'static str,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("method", &self.method)
            .field("scope", &self.scope)
            .field("plan", &self.plan)
            .finish_non_exhaustive()
    }
}

/// Map a credential-loading failure for `token=None` (logged and skipped)
/// or explicit methods (returned).
fn adc_project_check(user: Option<&str>, found: Option<&str>) -> Result<()> {
    match (user.filter(|p| !p.is_empty()), found) {
        (Some(u), f) if Some(u) != f => Err(Error::invalid_input(format!(
            "User-provided project '{u}' does not match the google default project '{}'. Either \
             accept the google-default project by not passing a `project`, configure the default \
             project to match (gcloud config set project), or use another authorization method \
             (token=...)",
            f.unwrap_or("None")
        ))),
        _ => Ok(()),
    }
}

impl Credentials {
    /// Build from the `token`, `project` and `access` options.
    /// `on_google` is gcsfs's check that the endpoint is Google's (the
    /// `cloud` method is skipped for emulators).
    pub fn new(spec: TokenSpec, project: Option<String>, access: &str, env: &GcsEnv, on_google: bool) -> Result<Self> {
        let scope = scope_for_access(access)?;
        let metadata = Arc::new(MetadataServer::from_env(env)?);
        let explicit_env_project = env
            .non_empty("GOOGLE_CLOUD_PROJECT")
            .or_else(|| env.non_empty("GCLOUD_PROJECT"))
            .map(str::to_owned);
        let mut creds = Credentials {
            scope,
            plan: Plan::Fixed(None),
            fixed_project: project.clone(),
            signer: None,
            metadata,
            env_project: explicit_env_project.clone(),
            resolved: OnceCell::new(),
            method: "anon",
        };
        match spec {
            TokenSpec::Anon => {}
            TokenSpec::Str(s) => {
                let path = std::path::Path::new(s.as_str());
                if path.exists() {
                    let c = adc::credentials_from_token_file(path)?;
                    creds.set_file(&c, "token");
                } else {
                    creds.plan = Plan::Fixed(Some(Source::Static(AccessToken::bearer(&s)?)));
                    creds.method = "token";
                }
            }
            TokenSpec::Dict(m) => {
                let c = adc::credentials_from_token_info(&adc::value_map_to_json(&m))?;
                creds.set_file(&c, "token");
            }
            TokenSpec::Cloud => {
                if !on_google {
                    return Err(Error::invalid_input(
                        "token='cloud' needs Google's endpoint (the metadata server cannot \
                         authenticate against an emulator or custom endpoint)",
                    ));
                }
                creds.plan = Plan::Lazy {
                    gce_default: false,
                    cloud: true,
                    anon_fallback: false,
                    user_project: project,
                };
                creds.method = "cloud";
            }
            TokenSpec::GoogleDefault => {
                match adc::find_adc_file(env)? {
                    Some(found) => {
                        let p = explicit_env_project.or(found.project.clone());
                        adc_project_check(project.as_deref(), p.as_deref())?;
                        creds.set_file(&found.credentials, "google_default");
                        creds.fixed_project = p;
                    }
                    None => {
                        creds.plan = Plan::Lazy {
                            gce_default: true,
                            cloud: false,
                            anon_fallback: false,
                            user_project: project,
                        };
                        creds.method = "google_default";
                    }
                }
            }
            TokenSpec::Auto => {
                let found = adc::find_adc_file(env).and_then(|f| {
                    if let Some(found) = &f {
                        let p = explicit_env_project.clone().or(found.project.clone());
                        adc_project_check(project.as_deref(), p.as_deref())?;
                    }
                    Ok(f)
                });
                match found {
                    Ok(Some(found)) => {
                        creds.set_file(&found.credentials, "google_default");
                        creds.fixed_project = explicit_env_project.or(found.project);
                    }
                    Ok(None) => {
                        creds.plan = Plan::Lazy {
                            gce_default: true,
                            cloud: on_google,
                            anon_fallback: true,
                            user_project: project,
                        };
                        creds.method = "auto";
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "google_default credentials failed; trying the next method");
                        creds.plan = Plan::Lazy {
                            gce_default: false,
                            cloud: on_google,
                            anon_fallback: true,
                            user_project: project,
                        };
                        creds.method = "auto";
                    }
                }
            }
        }
        Ok(creds)
    }

    fn set_file(&mut self, c: &FileCredentials, method: &'static str) {
        if let FileCredentials::ServiceAccount(k) = c {
            self.signer = Some(k.clone());
        }
        self.plan = Plan::Fixed(Some(Source::from_file(c)));
        self.method = method;
    }

    /// The OAuth scope requested.
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The authentication method in use (`anon`, `token`, `google_default`,
    /// `cloud`, or `auto` while the default chain is still undecided).
    pub fn method(&self) -> &'static str {
        self.method
    }

    /// Whether requests are known to be anonymous without resolving.
    pub fn is_anonymous(&self) -> bool {
        matches!(self.plan, Plan::Fixed(None))
    }

    /// The service-account key, when the credentials are one (needed for
    /// signed URLs).
    pub fn signer(&self) -> Option<&Arc<ServiceAccountKey>> {
        self.signer.as_ref()
    }

    /// Whether signed URLs may work (a key is known, or the default chain
    /// is still undecided).
    pub fn may_sign(&self) -> bool {
        self.signer.is_some()
    }

    /// Resolve (on first use) and return the credentials. `http` is used
    /// for token endpoints (the metadata server has its own client).
    pub async fn resolve(&self, http: &HttpClient) -> Result<Arc<Resolved>> {
        self.resolved
            .get_or_try_init(|| async { self.do_resolve(http).await.map(Arc::new) })
            .await
            .cloned()
    }

    async fn do_resolve(&self, http: &HttpClient) -> Result<Resolved> {
        match &self.plan {
            Plan::Fixed(src) => Ok(Resolved {
                tokens: src.clone().map(TokenCache::new),
                project: self.fixed_project.clone(),
            }),
            Plan::Lazy {
                gce_default,
                cloud,
                anon_fallback,
                user_project,
            } => {
                let mut last_err = None;
                if *gce_default {
                    match self.resolve_gce_default(user_project.as_deref()).await {
                        Ok(r) => return Ok(r),
                        Err(e) => {
                            tracing::debug!(error = %e, "google_default credentials unavailable");
                            last_err = Some(e);
                        }
                    }
                }
                if *cloud {
                    let src = Source::Metadata(self.metadata.clone(), None);
                    let cache = TokenCache::new(src);
                    // gcsfs `_connect_cloud` refreshes once to validate.
                    match cache.source.fetch(http, &self.scope).await {
                        Ok(t) => {
                            *cache.current.lock() = Some(t);
                            return Ok(Resolved {
                                tokens: Some(cache),
                                project: user_project.clone(),
                            });
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "GCE metadata credentials unavailable");
                            last_err = Some(Error::invalid_input(format!("Invalid gcloud credentials: {e}")));
                        }
                    }
                }
                if *anon_fallback {
                    tracing::debug!("no Google credentials found; using anonymous access");
                    return Ok(Resolved {
                        tokens: None,
                        project: user_project.clone(),
                    });
                }
                Err(last_err.unwrap_or_else(|| {
                    Error::permission_denied("no Google credentials could be found")
                }))
            }
        }
    }

    async fn resolve_gce_default(&self, user_project: Option<&str>) -> Result<Resolved> {
        if !self.metadata.is_on_gce().await {
            return Err(Error::permission_denied(
                "Your default credentials were not found. To set up Application Default \
                 Credentials, see https://cloud.google.com/docs/authentication/external/set-up-adc \
                 for more information.",
            ));
        }
        let project = match &self.env_project {
            Some(p) => Some(p.clone()),
            None => self.metadata.project_id().await.ok(),
        };
        adc_project_check(user_project, project.as_deref())?;
        Ok(Resolved {
            tokens: Some(TokenCache::new(Source::Metadata(
                self.metadata.clone(),
                Some(self.scope.clone()),
            ))),
            project,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes() {
        assert_eq!(
            scope_for_access("read_only").unwrap(),
            "https://www.googleapis.com/auth/devstorage.read_only"
        );
        assert!(scope_for_access("admin").is_err());
    }

    #[test]
    fn token_responses() {
        let now = Instant::now();
        let t = AccessToken::from_token_response(br#"{"access_token":"ya29.x","expires_in":3599,"token_type":"Bearer"}"#, Some(now)).unwrap();
        assert_eq!(t.header.to_str().unwrap(), "Bearer ya29.x");
        assert!(t.header.is_sensitive());
        assert_eq!(t.expires_at, Some(now + Duration::from_secs(3599)));
        assert_eq!(t.refresh_at, Some(now + Duration::from_secs(3299)));
        // Short-lived: refresh half-way.
        let t = AccessToken::from_token_response(br#"{"access_token":"a","expires_in":"200"}"#, Some(now)).unwrap();
        assert_eq!(t.refresh_at, Some(now + Duration::from_secs(100)));
        assert!(t.is_fresh(now));
        assert!(!t.is_fresh(now + Duration::from_secs(101)));
        let t = AccessToken::from_token_response(br#"{"access_token":"a"}"#, Some(now)).unwrap();
        assert!(t.refresh_at.is_none() && t.is_fresh(now + Duration::from_secs(1 << 30)));
        assert!(AccessToken::from_token_response(br#"{"token":"a"}"#, None).is_err());
        assert!(AccessToken::from_token_response(b"nope", None).is_err());
        assert!(AccessToken::bearer("bad\ntoken").is_err());
    }

    #[test]
    fn token_specs() {
        assert!(matches!(TokenSpec::from_value(None).unwrap(), TokenSpec::Auto));
        assert!(matches!(TokenSpec::from_value(Some(Value::from("anon"))).unwrap(), TokenSpec::Anon));
        assert!(matches!(TokenSpec::from_value(Some(Value::from("cloud"))).unwrap(), TokenSpec::Cloud));
        assert!(matches!(
            TokenSpec::from_value(Some(Value::from("google_default"))).unwrap(),
            TokenSpec::GoogleDefault
        ));
        assert_eq!(
            TokenSpec::from_value(Some(Value::from("cache"))).unwrap_err().kind(),
            ErrorKind::Unsupported
        );
        assert_eq!(
            TokenSpec::from_value(Some(Value::from("browser"))).unwrap_err().kind(),
            ErrorKind::Unsupported
        );
        assert!(TokenSpec::from_value(Some(Value::Int(1))).is_err());
        assert!(format!("{:?}", TokenSpec::from_value(Some(Value::from("ya29.secret"))).unwrap()).contains("redacted"));
    }

    #[test]
    fn project_mismatch() {
        assert!(adc_project_check(None, Some("a")).is_ok());
        assert!(adc_project_check(Some(""), Some("a")).is_ok());
        assert!(adc_project_check(Some("a"), Some("a")).is_ok());
        assert!(adc_project_check(Some("a"), Some("b")).is_err());
        assert!(adc_project_check(Some("a"), None).is_err());
    }
}
