//! AWS credentials: the botocore default provider chain, with a cache that
//! refreshes temporary credentials before they expire.
//!
//! The chain (first source that yields credentials wins, and later refreshes
//! go to the same source, as in botocore):
//!
//! 1. environment (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
//!    `AWS_SESSION_TOKEN`/`AWS_SECURITY_TOKEN`, `AWS_CREDENTIAL_EXPIRATION`),
//!    skipped when a profile is selected explicitly;
//! 2. assume-role profiles (`role_arn` with `source_profile` or
//!    `credential_source`), through STS `AssumeRole`;
//! 3. web identity (`AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN`, or the
//!    profile's `web_identity_token_file` + `role_arn`), through STS
//!    `AssumeRoleWithWebIdentity`;
//! 4. the shared credentials file's profile;
//! 5. the profile's `credential_process`;
//! 6. the config file's profile keys;
//! 7. ECS/EKS container credentials
//!    (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` / `_FULL_URI`);
//! 8. EC2 instance metadata (IMDSv2, falling back to IMDSv1).
//!
//! [`CredentialsCache`] is shared by every request of a filesystem: callers
//! get the current credentials without waiting; when they enter the advisory
//! refresh window (15 minutes before expiry) one caller refreshes while the
//! others keep using the old ones, and inside the mandatory window (10
//! minutes) everyone waits for the refresh (botocore's
//! `RefreshableCredentials` policy).

mod container;
mod imds;
mod process;
mod sts;

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use fsfast_core::{Error, ErrorKind, Result};
use fsfast_http_transport::HttpConfig;
use parking_lot::{Mutex, RwLock};
use zeroize::Zeroizing;

pub use container::ContainerProvider;
pub use imds::ImdsProvider;
pub use process::{ProcessProvider, shell_split};
pub use sts::{AssumeRoleProvider, StsClient, WebIdentityProvider};

use crate::encode::parse_iso8601;
use crate::profile::{Env, ProfileFiles, ProfileValue};

/// Refresh when credentials expire within this window, without blocking
/// other users (botocore `_DEFAULT_ADVISORY_REFRESH_TIMEOUT`).
pub const ADVISORY_REFRESH: Duration = Duration::from_secs(15 * 60);
/// Refresh, blocking every user, when credentials expire within this window
/// (botocore `_DEFAULT_MANDATORY_REFRESH_TIMEOUT`).
pub const MANDATORY_REFRESH: Duration = Duration::from_secs(10 * 60);
/// After a refresh failed, or produced credentials that are themselves
/// inside the refresh window (a provider handing out short-lived
/// credentials, or a local clock running ahead), credentials that are still
/// valid are used for this long before the next refresh attempt. Without
/// it every request would call the provider (STS, IMDS, ...) again.
pub const REFRESH_RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// An access key, its secret and an optional session token. Secrets are
/// wiped from memory on drop and never printed by `Debug`.
#[derive(Clone)]
pub struct Credentials {
    access_key_id: String,
    secret_access_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
    expiry: Option<SystemTime>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expiry", &self.expiry)
            .finish()
    }
}

impl Credentials {
    /// Build credentials; `expiry` `None` means they never expire.
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        session_token: Option<String>,
        expiry: Option<SystemTime>,
    ) -> Self {
        Credentials {
            access_key_id: access_key_id.into(),
            secret_access_key: Zeroizing::new(secret_access_key.into()),
            session_token: session_token.filter(|t| !t.is_empty()).map(Zeroizing::new),
            expiry,
        }
    }

    /// The access key id.
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    /// The secret access key.
    pub fn secret_access_key(&self) -> &str {
        &self.secret_access_key
    }

    /// The session token of temporary credentials.
    pub fn session_token(&self) -> Option<&str> {
        self.session_token.as_ref().map(|t| t.as_str())
    }

    /// When the credentials expire (`None`: never).
    pub fn expiry(&self) -> Option<SystemTime> {
        self.expiry
    }

    /// Whether the credentials expire within `window` of `now`.
    pub fn expires_within(&self, now: SystemTime, window: Duration) -> bool {
        self.expiry.is_some_and(|e| e <= now + window)
    }
}

/// A source of credentials.
#[async_trait]
pub trait ProvideCredentials: Send + Sync + fmt::Debug {
    /// Load credentials. `Ok(None)` means this source is not configured, so
    /// the chain moves on; errors stop the chain (as in botocore).
    async fn provide(&self) -> Result<Option<Credentials>>;

    /// Short name for logs (`env`, `assume-role`, `iam-role`, ...).
    fn name(&self) -> &'static str;
}

/// The error for "no source yielded credentials".
pub fn no_credentials() -> Error {
    Error::new(
        ErrorKind::PermissionDenied,
        "Unable to locate credentials: pass key/secret, set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, \
         configure a profile, or use anon=True for public buckets",
    )
}

/// A refresh produced credentials that had already expired.
fn still_expired() -> Error {
    Error::new(
        ErrorKind::PermissionDenied,
        "Credentials were refreshed, but the refreshed credentials are still expired \
         (check the credential source and the system clock)",
    )
}

/// Fixed credentials (the `key`/`secret`/`token` options).
#[derive(Debug, Clone)]
pub struct StaticProvider(pub Credentials);

#[async_trait]
impl ProvideCredentials for StaticProvider {
    async fn provide(&self) -> Result<Option<Credentials>> {
        Ok(Some(self.0.clone()))
    }

    fn name(&self) -> &'static str {
        "explicit"
    }
}

/// Credentials from environment variables.
#[derive(Debug, Clone)]
pub struct EnvProvider {
    env: Env,
}

impl EnvProvider {
    /// Read from `env`.
    pub fn new(env: Env) -> Self {
        EnvProvider { env }
    }

    fn load(&self) -> Result<Option<Credentials>> {
        let Some(ak) = self.env.get("AWS_ACCESS_KEY_ID") else {
            return Ok(None);
        };
        let sk = self.env.get("AWS_SECRET_ACCESS_KEY").ok_or_else(|| {
            Error::new(
                ErrorKind::PermissionDenied,
                "Partial credentials found in env, missing: AWS_SECRET_ACCESS_KEY",
            )
        })?;
        let token = self
            .env
            .get("AWS_SECURITY_TOKEN")
            .or_else(|| self.env.get("AWS_SESSION_TOKEN"));
        let expiry = match self.env.get("AWS_CREDENTIAL_EXPIRATION") {
            Some(e) => Some(parse_iso8601(&e).ok_or_else(|| {
                Error::invalid_input(format!("invalid AWS_CREDENTIAL_EXPIRATION {e:?}"))
            })?),
            None => None,
        };
        Ok(Some(Credentials::new(ak, sk, token, expiry)))
    }
}

#[async_trait]
impl ProvideCredentials for EnvProvider {
    async fn provide(&self) -> Result<Option<Credentials>> {
        self.load()
    }

    fn name(&self) -> &'static str {
        "env"
    }
}

/// Which file's profile a [`ProfileKeysProvider`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileFile {
    /// `~/.aws/credentials`.
    Credentials,
    /// `~/.aws/config`.
    Config,
}

/// Static keys (`aws_access_key_id`, `aws_secret_access_key`,
/// `aws_session_token`) of a profile in one of the shared files.
#[derive(Debug, Clone)]
pub struct ProfileKeysProvider {
    profiles: Arc<ProfileFiles>,
    profile: String,
    file: ProfileFile,
}

impl ProfileKeysProvider {
    /// Read profile `profile` of `file`.
    pub fn new(profiles: Arc<ProfileFiles>, profile: impl Into<String>, file: ProfileFile) -> Self {
        ProfileKeysProvider {
            profiles,
            profile: profile.into(),
            file,
        }
    }
}

/// Static keys of a profile section, if complete.
pub(crate) fn section_keys(
    section: Option<&crate::profile::Section>,
    what: &str,
) -> Result<Option<Credentials>> {
    let Some(section) = section else {
        return Ok(None);
    };
    let get = |k: &str| match section.get(k) {
        Some(ProfileValue::Str(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    let Some(ak) = get("aws_access_key_id") else {
        return Ok(None);
    };
    let sk = get("aws_secret_access_key").ok_or_else(|| {
        Error::new(
            ErrorKind::PermissionDenied,
            format!("Partial credentials found in {what}, missing: aws_secret_access_key"),
        )
    })?;
    let token = get("aws_session_token").or_else(|| get("aws_security_token"));
    Ok(Some(Credentials::new(ak, sk, token, None)))
}

#[async_trait]
impl ProvideCredentials for ProfileKeysProvider {
    async fn provide(&self) -> Result<Option<Credentials>> {
        let (map, what) = match self.file {
            ProfileFile::Credentials => {
                (&self.profiles.credentials_file, "shared-credentials-file")
            }
            ProfileFile::Config => (&self.profiles.config_file, "config-file"),
        };
        section_keys(map.get(&self.profile), what)
    }

    fn name(&self) -> &'static str {
        match self.file {
            ProfileFile::Credentials => "shared-credentials-file",
            ProfileFile::Config => "config-file",
        }
    }
}

/// Tries providers in order; the first to yield credentials is remembered
/// and asked alone on later refreshes.
#[derive(Debug)]
pub struct ChainProvider {
    providers: Vec<Arc<dyn ProvideCredentials>>,
    winner: Mutex<Option<usize>>,
}

impl ChainProvider {
    /// A chain over `providers`.
    pub fn new(providers: Vec<Arc<dyn ProvideCredentials>>) -> Self {
        ChainProvider {
            providers,
            winner: Mutex::new(None),
        }
    }

    /// Names of the providers, in order.
    pub fn names(&self) -> Vec<&'static str> {
        self.providers.iter().map(|p| p.name()).collect()
    }
}

#[async_trait]
impl ProvideCredentials for ChainProvider {
    async fn provide(&self) -> Result<Option<Credentials>> {
        let winner = *self.winner.lock();
        if let Some(i) = winner {
            return self.providers[i].provide().await;
        }
        for (i, p) in self.providers.iter().enumerate() {
            if let Some(c) = p.provide().await? {
                tracing::debug!(source = p.name(), "found AWS credentials");
                *self.winner.lock() = Some(i);
                return Ok(Some(c));
            }
        }
        Ok(None)
    }

    fn name(&self) -> &'static str {
        "chain"
    }
}

/// Caches credentials and refreshes them before they expire; see the module
/// docs. Cheap to share (`Arc`).
#[derive(Debug)]
pub struct CredentialsCache {
    provider: Arc<dyn ProvideCredentials>,
    current: RwLock<Option<Arc<Credentials>>>,
    refresh: tokio::sync::Mutex<()>,
    /// No refresh attempt before this instant while the current
    /// credentials are still valid (see [`REFRESH_RETRY_INTERVAL`]).
    retry_after: Mutex<Option<std::time::Instant>>,
    /// The last mandatory refresh returned credentials that had already
    /// expired: until the cool-down ends, `get` fails without asking the
    /// provider again.
    refreshed_expired: Mutex<bool>,
}

impl CredentialsCache {
    /// A cache over `provider` (nothing is loaded until the first `get`).
    pub fn new(provider: Arc<dyn ProvideCredentials>) -> Self {
        CredentialsCache {
            provider,
            current: RwLock::new(None),
            refresh: tokio::sync::Mutex::new(()),
            retry_after: Mutex::new(None),
            refreshed_expired: Mutex::new(false),
        }
    }

    /// The current credentials, refreshing them if needed.
    pub async fn get(&self) -> Result<Arc<Credentials>> {
        let now = SystemTime::now();
        let current = self.current.read().clone();
        if let Some(c) = &current {
            if !c.expires_within(now, ADVISORY_REFRESH) {
                return Ok(c.clone());
            }
            if self.cooling_down() && !c.expires_within(now, Duration::ZERO) {
                return Ok(c.clone());
            }
            if !c.expires_within(now, MANDATORY_REFRESH) {
                // Advisory window: refresh if nobody else is, never wait.
                if let Ok(_guard) = self.refresh.try_lock() {
                    if let Some(fresh) = self.current.read().clone()
                        && !Arc::ptr_eq(&fresh, c)
                    {
                        return Ok(fresh);
                    }
                    match self.provider.provide().await {
                        Ok(Some(n)) if n.expires_within(SystemTime::now(), Duration::ZERO) => {
                            tracing::warn!(
                                "refreshed credentials are already expired; keeping the current ones"
                            );
                        }
                        Ok(Some(n)) => {
                            self.note_refresh(&n, ADVISORY_REFRESH);
                            return Ok(self.store(n));
                        }
                        Ok(None) => tracing::warn!("credential refresh found no credentials"),
                        Err(e) => tracing::warn!(error = %e, "advisory credential refresh failed"),
                    }
                    self.start_cooldown();
                }
                return Ok(c.clone());
            }
        }
        let _guard = self.refresh.lock().await;
        let now = SystemTime::now();
        let current = self.current.read().clone();
        if let Some(c) = &current
            && (!c.expires_within(now, MANDATORY_REFRESH)
                || (self.cooling_down() && !c.expires_within(now, Duration::ZERO)))
        {
            return Ok(c.clone());
        }
        if self.cooling_down() && *self.refreshed_expired.lock() {
            // The provider just handed out expired credentials; asking it
            // again on every request would not help (and would hammer
            // STS / IMDS / a credential_process helper).
            return Err(still_expired());
        }
        let res = self.provider.provide().await;
        if !matches!(res, Ok(Some(_))) {
            self.start_cooldown();
        }
        match res {
            Ok(Some(n)) if n.expires_within(now, Duration::ZERO) => {
                // botocore raises here too. Never sign with them: keep still
                // valid credentials if there are any, else fail; either way
                // cool down instead of refreshing again on every request.
                tracing::warn!("refreshed credentials are already expired");
                self.start_cooldown();
                *self.refreshed_expired.lock() = true;
                match current {
                    Some(c) if !c.expires_within(now, Duration::ZERO) => Ok(c),
                    _ => Err(still_expired()),
                }
            }
            Ok(Some(n)) => {
                *self.refreshed_expired.lock() = false;
                if n.expires_within(now, MANDATORY_REFRESH) {
                    tracing::warn!(
                        "refreshed credentials expire within the mandatory refresh window"
                    );
                }
                self.note_refresh(&n, MANDATORY_REFRESH);
                Ok(self.store(n))
            }
            Ok(None) => match current {
                Some(c) if !c.expires_within(now, Duration::ZERO) => Ok(c),
                _ => Err(no_credentials()),
            },
            Err(e) => match current {
                // Still valid: keep working and retry the refresh next time.
                Some(c) if !c.expires_within(now, Duration::ZERO) => {
                    tracing::warn!(error = %e, "mandatory credential refresh failed; using credentials until they expire");
                    Ok(c)
                }
                _ => Err(e),
            },
        }
    }

    fn cooling_down(&self) -> bool {
        self.retry_after
            .lock()
            .is_some_and(|t| std::time::Instant::now() < t)
    }

    fn start_cooldown(&self) {
        *self.retry_after.lock() = Some(std::time::Instant::now() + REFRESH_RETRY_INTERVAL);
    }

    /// After a successful refresh: cool down if the new credentials are
    /// still inside `window` (refreshing again at once would not help).
    fn note_refresh(&self, fresh: &Credentials, window: Duration) {
        if fresh.expires_within(SystemTime::now(), window) {
            self.start_cooldown();
        } else {
            *self.retry_after.lock() = None;
        }
    }

    fn store(&self, c: Credentials) -> Arc<Credentials> {
        let c = Arc::new(c);
        *self.current.write() = Some(c.clone());
        c
    }

    /// Forget the cached credentials (e.g. after the service rejected them
    /// as expired); the next `get` loads fresh ones.
    pub fn invalidate(&self) {
        *self.current.write() = None;
    }

    /// Forget the cached credentials only if they are still `rejected` (the
    /// ones a request was signed with and the service refused as expired).
    ///
    /// Concurrent requests signed with the same credentials are all
    /// rejected; the first one's refresh must not be thrown away by the
    /// others, so a stale rejection after the refresh is a no-op.
    pub fn invalidate_if_current(&self, rejected: &Arc<Credentials>) {
        let mut cur = self.current.write();
        if cur.as_ref().is_some_and(|c| Arc::ptr_eq(c, rejected)) {
            *cur = None;
        }
    }

    /// Whether the cached credentials are temporary (have an expiry), i.e.
    /// whether a reload may produce different ones.
    pub fn is_refreshable(&self) -> bool {
        self.current
            .read()
            .as_ref()
            .is_some_and(|c| c.expiry.is_some())
    }
}

/// What the default chain needs to know.
#[derive(Debug, Clone)]
pub struct ChainContext {
    /// The environment.
    pub env: Env,
    /// The shared config/credentials files.
    pub profiles: Arc<ProfileFiles>,
    /// The selected profile.
    pub profile: String,
    /// Whether the profile was given explicitly (the `profile` option): the
    /// environment provider is then skipped.
    pub explicit_profile: bool,
    /// Region for STS (regional endpoint); `None` uses the global endpoint.
    pub region: Option<String>,
    /// HTTP settings (proxy, TLS) for STS requests.
    pub http: HttpConfig,
    /// Base URL for `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` (normally
    /// `http://169.254.170.2`).
    pub container_base: String,
}

impl ChainContext {
    /// A context for `env` and `profiles` with defaults for the rest.
    pub fn new(
        env: Env,
        profiles: Arc<ProfileFiles>,
        profile: String,
        explicit_profile: bool,
    ) -> Self {
        ChainContext {
            env,
            profiles,
            profile,
            explicit_profile,
            region: None,
            http: HttpConfig::default(),
            container_base: container::DEFAULT_BASE.to_owned(),
        }
    }
}

/// botocore's default credential chain for `ctx`.
pub fn default_chain(ctx: &ChainContext) -> ChainProvider {
    let ctx = Arc::new(ctx.clone());
    let mut providers: Vec<Arc<dyn ProvideCredentials>> = Vec::new();
    if !ctx.explicit_profile {
        providers.push(Arc::new(EnvProvider::new(ctx.env.clone())));
    }
    providers.push(Arc::new(AssumeRoleProvider::new(
        ctx.clone(),
        ctx.profile.clone(),
    )));
    providers.push(Arc::new(WebIdentityProvider::new(
        ctx.clone(),
        ctx.profile.clone(),
        ctx.explicit_profile,
    )));
    providers.push(Arc::new(ProfileKeysProvider::new(
        ctx.profiles.clone(),
        ctx.profile.clone(),
        ProfileFile::Credentials,
    )));
    providers.push(Arc::new(ProcessProvider::new(
        ctx.profiles.clone(),
        ctx.profile.clone(),
    )));
    providers.push(Arc::new(ProfileKeysProvider::new(
        ctx.profiles.clone(),
        ctx.profile.clone(),
        ProfileFile::Config,
    )));
    providers.push(Arc::new(ContainerProvider::new(
        ctx.env.clone(),
        ctx.container_base.clone(),
    )));
    providers.push(Arc::new(ImdsProvider::new(
        &ctx.env,
        &ctx.profiles,
        &ctx.profile,
    )));
    ChainProvider::new(providers)
}

/// Credentials from a JSON document in the ECS/IMDS/credential_process
/// shape (`AccessKeyId`, `SecretAccessKey`, `Token`/`SessionToken`,
/// `Expiration`).
pub(crate) fn credentials_from_json(v: &serde_json::Value, what: &str) -> Result<Credentials> {
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).filter(|x| !x.is_empty());
    let bad = |m: &str| {
        Error::new(
            ErrorKind::PermissionDenied,
            format!("invalid credentials from {what}: {m}"),
        )
    };
    let ak = s("AccessKeyId").ok_or_else(|| bad("missing AccessKeyId"))?;
    let sk = s("SecretAccessKey").ok_or_else(|| bad("missing SecretAccessKey"))?;
    let token = s("Token").or_else(|| s("SessionToken")).map(str::to_owned);
    let expiry = match s("Expiration") {
        Some(e) => Some(parse_iso8601(e).ok_or_else(|| bad("unparseable Expiration"))?),
        None => None,
    };
    Ok(Credentials::new(ak, sk, token, expiry))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Debug)]
    struct Counting {
        calls: AtomicUsize,
        lifetime: Duration,
        fail_after: Option<usize>,
    }

    #[async_trait]
    impl ProvideCredentials for Counting {
        async fn provide(&self) -> Result<Option<Credentials>> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_after.is_some_and(|f| n >= f) {
                return Err(Error::new(ErrorKind::ConnectionFailed, "metadata down"));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(Some(Credentials::new(
                format!("AK{n}"),
                "s",
                Some("t".into()),
                Some(SystemTime::now() + self.lifetime),
            )))
        }

        fn name(&self) -> &'static str {
            "counting"
        }
    }

    #[tokio::test]
    async fn cache_loads_once_for_concurrent_callers() {
        let p = Arc::new(Counting {
            calls: AtomicUsize::new(0),
            lifetime: Duration::from_secs(3600),
            fail_after: None,
        });
        let cache = Arc::new(CredentialsCache::new(p.clone()));
        let tasks: Vec<_> = (0..32)
            .map(|_| {
                let c = cache.clone();
                tokio::spawn(async move { c.get().await.unwrap().access_key_id().to_owned() })
            })
            .collect();
        for t in tasks {
            assert_eq!(t.await.unwrap(), "AK0");
        }
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);
        assert!(cache.is_refreshable());
    }

    #[tokio::test]
    async fn advisory_window_refreshes_without_blocking() {
        // Expires in 12 minutes: inside the advisory window, outside the
        // mandatory one.
        let p = Arc::new(Counting {
            calls: AtomicUsize::new(0),
            lifetime: Duration::from_secs(12 * 60),
            fail_after: None,
        });
        let cache = CredentialsCache::new(p.clone());
        assert_eq!(cache.get().await.unwrap().access_key_id(), "AK0");
        // Next get refreshes (still in the advisory window afterwards, but
        // each refresh yields new credentials).
        assert_eq!(cache.get().await.unwrap().access_key_id(), "AK1");
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn mandatory_refresh_failure_keeps_valid_credentials() {
        let p = Arc::new(Counting {
            calls: AtomicUsize::new(0),
            lifetime: Duration::from_secs(5 * 60),
            fail_after: Some(1),
        });
        let cache = CredentialsCache::new(p.clone());
        assert_eq!(cache.get().await.unwrap().access_key_id(), "AK0");
        // Refresh fails, the old credentials are still valid for 5 minutes.
        assert_eq!(cache.get().await.unwrap().access_key_id(), "AK0");
        cache.invalidate();
        assert_eq!(
            cache.get().await.unwrap_err().kind(),
            ErrorKind::ConnectionFailed
        );
    }

    #[derive(Debug, Default)]
    struct AlreadyExpired {
        calls: AtomicUsize,
        /// The first call yields credentials valid for this long.
        first: Option<Duration>,
    }

    #[async_trait]
    impl ProvideCredentials for AlreadyExpired {
        async fn provide(&self) -> Result<Option<Credentials>> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n == 0
                && let Some(d) = self.first
            {
                return Ok(Some(Credentials::new(
                    "AKGOOD",
                    "s",
                    Some("t".into()),
                    Some(SystemTime::now() + d),
                )));
            }
            Ok(Some(Credentials::new(
                "AKOLD",
                "s",
                Some("t".into()),
                Some(SystemTime::now() - Duration::from_secs(3600)),
            )))
        }

        fn name(&self) -> &'static str {
            "already-expired"
        }
    }

    #[tokio::test]
    async fn already_expired_refresh_is_an_error_and_cools_down() {
        // A provider handing out credentials that have already expired (a
        // stale credential_process cache, a clock running far ahead): they
        // must not be used to sign, and the provider must not be asked again
        // on every request (botocore: "Credentials were refreshed, but the
        // refreshed credentials are still expired").
        let p = Arc::new(AlreadyExpired::default());
        let cache = CredentialsCache::new(p.clone());
        for _ in 0..20 {
            let e = cache.get().await.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
            assert!(e.message().contains("still expired"), "{e}");
        }
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);
        assert!(cache.current.read().is_none());
        // Still valid credentials are kept when a refresh (advisory or
        // mandatory) yields expired ones.
        for lifetime in [12 * 60, 5 * 60] {
            let p = Arc::new(AlreadyExpired {
                first: Some(Duration::from_secs(lifetime)),
                ..AlreadyExpired::default()
            });
            let cache = CredentialsCache::new(p.clone());
            assert_eq!(cache.get().await.unwrap().access_key_id(), "AKGOOD");
            // (Short-lived credentials start a cool-down; skip it so the
            // next get refreshes.)
            *cache.retry_after.lock() = None;
            for _ in 0..20 {
                assert_eq!(cache.get().await.unwrap().access_key_id(), "AKGOOD");
            }
            assert_eq!(p.calls.load(Ordering::SeqCst), 2, "{lifetime}");
        }
    }

    #[tokio::test]
    async fn short_lived_credentials_do_not_cause_a_refresh_storm() {
        // Every refresh yields credentials inside the mandatory window (a
        // provider with short-lived credentials, or a clock running ahead):
        // they are still valid, so they are used and the provider is not
        // called again on every request.
        let p = Arc::new(Counting {
            calls: AtomicUsize::new(0),
            lifetime: Duration::from_secs(5 * 60),
            fail_after: None,
        });
        let cache = CredentialsCache::new(p.clone());
        for _ in 0..50 {
            cache.get().await.unwrap();
        }
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);
        // Same in the advisory window, when the refresh keeps failing.
        let p = Arc::new(Counting {
            calls: AtomicUsize::new(0),
            lifetime: Duration::from_secs(12 * 60),
            fail_after: Some(1),
        });
        let cache = CredentialsCache::new(p.clone());
        for _ in 0..50 {
            assert_eq!(cache.get().await.unwrap().access_key_id(), "AK0");
        }
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
        // Expired credentials are never served from the cool-down.
        cache.invalidate();
        assert!(cache.get().await.is_err());
    }

    #[tokio::test]
    async fn env_provider_reads_variables() {
        let env = Env::from_map([
            ("AWS_ACCESS_KEY_ID", "AKENV"),
            ("AWS_SECRET_ACCESS_KEY", "SKENV"),
            ("AWS_SESSION_TOKEN", "TOKENV"),
            ("AWS_CREDENTIAL_EXPIRATION", "2030-01-01T00:00:00Z"),
        ]);
        let c = EnvProvider::new(env).provide().await.unwrap().unwrap();
        assert_eq!(c.access_key_id(), "AKENV");
        assert_eq!(c.session_token(), Some("TOKENV"));
        assert!(c.expiry().is_some());
        let partial = EnvProvider::new(Env::from_map([("AWS_ACCESS_KEY_ID", "x")]));
        assert_eq!(
            partial.provide().await.unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
        let none = EnvProvider::new(Env::from_map([("AWS_SECRET_ACCESS_KEY", "x")]));
        assert!(none.provide().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn chain_order_and_winner() {
        let profiles = Arc::new(ProfileFiles::from_texts(
            Some("[profile p]\naws_access_key_id = AKCFG\naws_secret_access_key = S\n"),
            Some("[p]\naws_access_key_id = AKCRED\naws_secret_access_key = S\n"),
        ));
        let env = Env::from_map([
            ("AWS_ACCESS_KEY_ID", "AKENV"),
            ("AWS_SECRET_ACCESS_KEY", "S"),
            ("AWS_EC2_METADATA_DISABLED", "true"),
        ]);
        // Profile from the environment: env wins.
        let ctx = ChainContext::new(env.clone(), profiles.clone(), "p".into(), false);
        let c = default_chain(&ctx).provide().await.unwrap().unwrap();
        assert_eq!(c.access_key_id(), "AKENV");
        // Explicit profile: env is skipped, the credentials file wins over
        // the config file.
        let ctx = ChainContext::new(env, profiles, "p".into(), true);
        let chain = default_chain(&ctx);
        assert!(!chain.names().contains(&"env"));
        let c = chain.provide().await.unwrap().unwrap();
        assert_eq!(c.access_key_id(), "AKCRED");
        assert_eq!(*chain.winner.lock(), Some(2));
    }

    #[test]
    fn debug_hides_secrets() {
        let c = Credentials::new("AK", "supersecret", Some("sessiontokenvalue".into()), None);
        let s = format!("{c:?}");
        assert!(
            !s.contains("supersecret") && !s.contains("sessiontokenvalue"),
            "{s}"
        );
    }
}
