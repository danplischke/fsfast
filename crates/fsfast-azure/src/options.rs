//! adlfs `storage_options`, parsed strictly.
//!
//! | option | effect |
//! |---|---|
//! | `account_name` | storage account (`$AZURE_STORAGE_ACCOUNT_NAME`); endpoint `https://{account_name}.blob.core.windows.net` |
//! | `account_host` | endpoint host instead (`https://{account_host}`); fsfast extension: a value with a scheme (`http://127.0.0.1:10000/devstoreaccount1`) is used as the endpoint URL as is |
//! | `account_key` | Shared Key (`$AZURE_STORAGE_ACCOUNT_KEY`) |
//! | `connection_string` | overrides the options above (`$AZURE_STORAGE_CONNECTION_STRING`; see [`crate::connstr`]) |
//! | `sas_token` | SAS token (`$AZURE_STORAGE_SAS_TOKEN`) |
//! | `credential` | a string (account key, or a SAS token), `{"account_name", "account_key"}`, `{"sas_token"}` or `{"token", "expires_on"}` (a bearer token); Python credential objects must be converted by the bindings |
//! | `client_id`, `client_secret`, `tenant_id` | service principal (`$AZURE_STORAGE_CLIENT_ID`, `..._SECRET`, `$AZURE_STORAGE_TENANT_ID`) |
//! | `anon` | anonymous access when no credential is given (`$AZURE_STORAGE_ANON`); otherwise the `DefaultAzureCredential` chain |
//! | `location_mode` | `primary` (default) or `secondary` (read-only secondary endpoint) |
//! | `blocksize` | default block size of file objects (50 MiB) and, when set, the upload block size |
//! | `default_fill_cache`, `default_cache_type` | file-object defaults (Python layer; exposed via getters) |
//! | `version_aware` | `?versionid=` in paths, `version_id`/`is_current_version` in info |
//! | `assume_container_exists` | skip (`True`) or enforce (`False`) container checks in `mkdir`/`rmdir` |
//! | `max_concurrency` | requests in flight per transfer (default 16) |
//! | `timeout` | server-side operation timeout in seconds (`timeout=` query parameter) |
//! | `connection_timeout`, `read_timeout` | client connect / idle timeouts in seconds |
//! | `socket_timeout`, `request_session`, `loop`, `asynchronous` | accepted without effect (as in adlfs) |
//! | `use_listings_cache`, `listings_expiry_time`, `max_paths`, `skip_instance_cache` | listings cache: Python layer, accepted |
//! | `exclude_*_credential`, `managed_identity_client_id`, `workload_identity_client_id`, `workload_identity_tenant_id`, `authority`, `process_timeout`, ... | `DefaultAzureCredential` keywords (adlfs forwards unknown keywords to it); the ones for credentials fsfast does not implement are accepted without effect |
//!
//! fsfast's own options: `request_size` (bytes per ranged GET, default
//! 8 MiB), `upload_concurrency` (blocks staged in parallel per upload,
//! default 8), `list_page_size` (List Blobs `maxresults`, default: the
//! service's 5000), `hns` (the account has a hierarchical namespace (ADLS
//! Gen2): `mv_file` becomes one atomic DFS Path Rename; default false) and
//! `dfs_endpoint` (DFS endpoint URL; default: the blob endpoint with
//! `.blob.` replaced by `.dfs.`), plus the HTTP client options of
//! `HttpConfig::apply_fsfast_options` (`connect_timeout`, `total_timeout`,
//! `max_retries`, `limit_per_host`, `http2`, `ca_bundle`, `user_agent`,
//! `rotate_dns`).

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fsfast_core::{Error, OptionReader, Options, Result, Value};
use fsfast_http_transport::HttpConfig;
use zeroize::Zeroizing;

use crate::auth::token::{
    DEFAULT_AUTHORITY, IMDS_ENDPOINT, ManagedIdentityEndpoint, normalize_authority,
};
use crate::connstr::{ConnectionString, is_sas_token};

/// adlfs `_DEFAULT_BLOCK_SIZE` (50 MiB).
pub const DEFAULT_BLOCK_SIZE: usize = 50 << 20;
/// Default size of one ranged GET.
pub const DEFAULT_REQUEST_SIZE: usize = 8 << 20;
/// Default upload block size when `blocksize` is not given.
pub const DEFAULT_UPLOAD_BLOCK: usize = 8 << 20;
/// Largest block Put Block accepts (API versions since 2019-12-12).
pub const MAX_BLOCK_SIZE: usize = 4000 << 20;
/// Most blocks in one block blob.
pub const MAX_BLOCKS: u32 = 50_000;

const IGNORED: &[&str] = &[
    "socket_timeout",
    "request_session",
    "loop",
    "asynchronous",
    "use_listings_cache",
    "listings_expiry_time",
    "max_paths",
    "skip_instance_cache",
    // DefaultAzureCredential keywords for credentials fsfast does not
    // implement.
    "exclude_shared_token_cache_credential",
    "exclude_visual_studio_code_credential",
    "exclude_powershell_credential",
    "exclude_developer_cli_credential",
    "exclude_interactive_browser_credential",
    "exclude_broker_credential",
    "interactive_browser_tenant_id",
    "interactive_browser_client_id",
    "shared_cache_username",
    "shared_cache_tenant_id",
    "visual_studio_code_tenant_id",
    "additionally_allowed_tenants",
];

/// Primary or secondary endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LocationMode {
    /// The primary (read-write) endpoint.
    #[default]
    Primary,
    /// The read-access secondary endpoint.
    Secondary,
}

/// How `DefaultAzureCredential` is assembled.
#[derive(Debug, Clone, Default)]
pub struct DefaultChainSpec {
    /// `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET`.
    pub environment: Option<ServicePrincipal>,
    /// Why the environment credential is unavailable (shown in errors).
    pub environment_unavailable: Option<String>,
    /// Workload identity.
    pub workload: Option<WorkloadSpec>,
    /// Managed identity (`None` when excluded).
    pub managed_identity: Option<ManagedIdentitySpec>,
    /// Azure CLI (`None` when excluded).
    pub cli: Option<CliSpec>,
}

/// A service principal with a secret.
#[derive(Clone)]
pub struct ServicePrincipal {
    /// Tenant id.
    pub tenant_id: String,
    /// Client id.
    pub client_id: String,
    /// Client secret.
    pub client_secret: Zeroizing<String>,
    /// Authority host URL.
    pub authority: String,
}

impl std::fmt::Debug for ServicePrincipal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServicePrincipal")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}

/// Workload identity settings.
#[derive(Debug, Clone)]
pub struct WorkloadSpec {
    /// Tenant id.
    pub tenant_id: String,
    /// Client id.
    pub client_id: String,
    /// Federated token file.
    pub token_file: PathBuf,
    /// Authority host URL.
    pub authority: String,
}

/// Managed identity settings.
#[derive(Debug, Clone)]
pub struct ManagedIdentitySpec {
    /// Endpoint.
    pub endpoint: ManagedIdentityEndpoint,
    /// User-assigned identity client id.
    pub client_id: Option<String>,
}

/// Azure CLI settings.
#[derive(Debug, Clone)]
pub struct CliSpec {
    /// Process timeout.
    pub timeout: Duration,
    /// Tenant.
    pub tenant_id: Option<String>,
}

/// The credential adlfs would use.
#[derive(Clone)]
pub enum AuthSpec {
    /// No credentials.
    Anonymous,
    /// Shared Key.
    SharedKey {
        /// Account name.
        account: String,
        /// base64 account key.
        key: Zeroizing<String>,
    },
    /// SAS token (without `?`).
    Sas(Zeroizing<String>),
    /// A fixed bearer token.
    StaticToken {
        /// The token.
        token: Zeroizing<String>,
        /// Its expiry.
        expires_on: SystemTime,
    },
    /// Service principal with a secret (adlfs `client_id`/`client_secret`/`tenant_id`).
    ClientSecret(ServicePrincipal),
    /// `DefaultAzureCredential`.
    Default(Box<DefaultChainSpec>),
}

impl std::fmt::Debug for AuthSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthSpec::Anonymous => f.write_str("Anonymous"),
            AuthSpec::SharedKey { account, .. } => write!(f, "SharedKey({account})"),
            AuthSpec::Sas(_) => f.write_str("Sas(<redacted>)"),
            AuthSpec::StaticToken { expires_on, .. } => {
                write!(f, "StaticToken(expires {expires_on:?})")
            }
            AuthSpec::ClientSecret(sp) => write!(f, "ClientSecret({sp:?})"),
            AuthSpec::Default(d) => write!(f, "Default({d:?})"),
        }
    }
}

/// Everything the filesystem needs, from the options.
#[derive(Debug, Clone)]
pub struct AzureConfig {
    /// Account name, when known.
    pub account_name: Option<String>,
    /// Primary blob endpoint, without trailing slash.
    pub endpoint: String,
    /// Secondary endpoint, if known.
    pub secondary_endpoint: Option<String>,
    /// Which endpoint to use.
    pub location_mode: LocationMode,
    /// Credential.
    pub auth: AuthSpec,
    /// Account name and key for `sign()` (adlfs uses the account key, or
    /// the connection string's).
    pub signing_key: Option<(String, Zeroizing<String>)>,
    /// `blocksize` (file-object block size).
    pub blocksize: usize,
    /// Whether `blocksize` was given (then it is also the upload block size).
    pub blocksize_set: bool,
    /// `default_fill_cache`.
    pub default_fill_cache: bool,
    /// `default_cache_type`.
    pub default_cache_type: String,
    /// `version_aware`.
    pub version_aware: bool,
    /// `assume_container_exists`.
    pub assume_container_exists: Option<bool>,
    /// Requests in flight per transfer.
    pub max_concurrency: usize,
    /// Blocks staged in parallel per upload.
    pub upload_concurrency: usize,
    /// List Blobs page size (`None`: the service default, 5000).
    pub list_page_size: Option<u32>,
    /// Hierarchical namespace (ADLS Gen2): use DFS Path Rename for moves.
    pub hns: bool,
    /// DFS endpoint (explicit `dfs_endpoint`, or derived from the blob
    /// endpoint when it has a `.blob.` host).
    pub dfs_endpoint: Option<String>,
    /// Bytes per ranged GET.
    pub request_size: usize,
    /// Server-side `timeout` in seconds.
    pub server_timeout: Option<u64>,
    /// HTTP client configuration.
    pub http: HttpConfig,
}

/// Environment lookup (injectable for tests).
pub type EnvFn<'a> = &'a dyn Fn(&str) -> Option<String>;

/// `std::env::var` as an [`EnvFn`].
pub fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn nonempty(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.is_empty())
}

/// `opt or env` with Python truthiness (an empty option falls back too).
fn opt_or_env(
    r: &mut OptionReader,
    key: &str,
    env: EnvFn<'_>,
    var: &str,
) -> Result<Option<String>> {
    Ok(nonempty(r.string(key)?).or_else(|| nonempty(env(var))))
}

/// A parsed `credential` option.
enum CredOpt {
    Key(String),
    Sas(String),
    Named {
        account: String,
        key: String,
    },
    Token {
        token: String,
        expires_on: SystemTime,
    },
}

fn parse_credential(v: Value, account: Option<&str>) -> Result<CredOpt> {
    match v {
        Value::Str(s) if s.is_empty() => Err(Error::invalid_input("abfs: empty credential")),
        Value::Str(s) => {
            if is_sas_token(&s) {
                Ok(CredOpt::Sas(s.trim_start_matches('?').to_owned()))
            } else if account.is_some() {
                Ok(CredOpt::Key(s))
            } else {
                Err(Error::invalid_input(
                    "abfs: Unable to determine account name for shared key credential.",
                ))
            }
        }
        Value::Map(m) => {
            let s = |k: &str| m.get(k).and_then(Value::as_str).map(str::to_owned);
            if let Some(k) = s("account_key") {
                let account = s("account_name").ok_or_else(|| {
                    Error::invalid_input("abfs: Shared key credential missing 'account_name")
                })?;
                return Ok(CredOpt::Named { account, key: k });
            }
            if let Some(t) = s("sas_token").or_else(|| s("signature")) {
                return Ok(CredOpt::Sas(t.trim_start_matches('?').to_owned()));
            }
            if let Some(t) = s("token") {
                let expires_on = match m.get("expires_on") {
                    Some(Value::Int(i)) if *i > 0 => UNIX_EPOCH + Duration::from_secs(*i as u64),
                    Some(Value::Float(f)) if *f > 0.0 => UNIX_EPOCH + Duration::from_secs_f64(*f),
                    Some(Value::Time(t)) => *t,
                    None | Some(Value::Null) => SystemTime::now() + Duration::from_secs(3600),
                    Some(other) => {
                        return Err(Error::invalid_input(format!(
                            "abfs: credential 'expires_on' must be epoch seconds, got {}",
                            other.type_name()
                        )));
                    }
                };
                return Ok(CredOpt::Token {
                    token: t,
                    expires_on,
                });
            }
            Err(Error::invalid_input(
                "abfs: unsupported credential dict (expected account_name/account_key, sas_token or token)",
            ))
        }
        other => Err(Error::invalid_input(format!(
            "abfs: unsupported credential type {}",
            other.type_name()
        ))),
    }
}

impl AzureConfig {
    /// Parse adlfs options, reading `AZURE_*` variables through `env`.
    pub fn from_options(opts: Options, env: EnvFn<'_>) -> Result<Self> {
        let mut r = OptionReader::new("abfs", opts);
        let account_name = opt_or_env(&mut r, "account_name", env, "AZURE_STORAGE_ACCOUNT_NAME")?;
        let account_key = opt_or_env(&mut r, "account_key", env, "AZURE_STORAGE_ACCOUNT_KEY")?;
        let connection_string = opt_or_env(
            &mut r,
            "connection_string",
            env,
            "AZURE_STORAGE_CONNECTION_STRING",
        )?;
        let sas_token = opt_or_env(&mut r, "sas_token", env, "AZURE_STORAGE_SAS_TOKEN")?;
        let client_id = opt_or_env(&mut r, "client_id", env, "AZURE_STORAGE_CLIENT_ID")?;
        let client_secret =
            opt_or_env(&mut r, "client_secret", env, "AZURE_STORAGE_CLIENT_SECRET")?;
        let tenant_id = opt_or_env(&mut r, "tenant_id", env, "AZURE_STORAGE_TENANT_ID")?;
        let anon = match r.bool("anon")? {
            Some(b) => b,
            None => {
                let v = env("AZURE_STORAGE_ANON").unwrap_or_else(|| "false".into());
                !matches!(v.to_ascii_lowercase().as_str(), "false" | "0" | "f" | "")
            }
        };
        let credential = r
            .value("credential")
            .map(|v| parse_credential(v, account_name.as_deref()))
            .transpose()?;
        let account_host = nonempty(r.string("account_host")?);
        let location_mode = match r.string("location_mode")?.as_deref() {
            None | Some("primary") => LocationMode::Primary,
            Some("secondary") => LocationMode::Secondary,
            Some(other) => {
                return Err(Error::invalid_input(format!(
                    "abfs: location_mode must be 'primary' or 'secondary', got {other:?}"
                )));
            }
        };
        let blocksize_opt = r.usize("blocksize")?;
        if blocksize_opt == Some(0) {
            return Err(Error::invalid_input("abfs: blocksize must be > 0"));
        }
        let default_fill_cache = r.bool("default_fill_cache")?.unwrap_or(true);
        let default_cache_type = r
            .string("default_cache_type")?
            .unwrap_or_else(|| "bytes".into());
        let version_aware = r.bool("version_aware")?.unwrap_or(false);
        let assume_container_exists = r.bool("assume_container_exists")?;
        let max_concurrency = r.usize("max_concurrency")?.unwrap_or(16).max(1);
        let server_timeout = r.u64("timeout")?;
        let connection_timeout = r.duration_secs("connection_timeout")?;
        r.accept_ignored(IGNORED);

        // DefaultAzureCredential keywords.
        let excl =
            |r: &mut OptionReader, k: &str| -> Result<bool> { Ok(r.bool(k)?.unwrap_or(false)) };
        let exclude_env = excl(&mut r, "exclude_environment_credential")?;
        let exclude_workload = excl(&mut r, "exclude_workload_identity_credential")?;
        let exclude_mi = excl(&mut r, "exclude_managed_identity_credential")?;
        let exclude_cli = excl(&mut r, "exclude_cli_credential")?;
        let mi_client_id = r.string("managed_identity_client_id")?;
        let wi_client_id = r.string("workload_identity_client_id")?;
        let wi_tenant_id = r.string("workload_identity_tenant_id")?;
        let authority_kw = r.string("authority")?;
        let process_timeout = r.duration_secs("process_timeout")?;

        let hns = r.bool("hns")?.unwrap_or(false);
        let dfs_endpoint_opt = nonempty(r.string("dfs_endpoint")?);
        let request_size = r
            .usize("request_size")?
            .unwrap_or(DEFAULT_REQUEST_SIZE)
            .max(1);
        let upload_concurrency = r.usize("upload_concurrency")?.unwrap_or(8).max(1);
        let list_page_size = match r.u64("list_page_size")? {
            None => None,
            Some(n @ 1..=5000) => Some(n as u32),
            Some(n) => {
                return Err(Error::invalid_input(format!(
                    "abfs: list_page_size must be between 1 and 5000, got {n}"
                )));
            }
        };
        let mut http = HttpConfig::default();
        if let Some(t) = connection_timeout {
            http.connect_timeout = Some(t);
        }
        http.apply_fsfast_options(&mut r)?;
        if http.user_agent.is_none() {
            http.user_agent = Some(format!(
                "fsfast-azure/{} (adlfs-compatible)",
                env!("CARGO_PKG_VERSION")
            ));
        }
        r.finish()?;

        let authority = normalize_authority(
            authority_kw
                .as_deref()
                .or(env("AZURE_AUTHORITY_HOST").as_deref())
                .unwrap_or(DEFAULT_AUTHORITY),
        );

        // adlfs: the service principal when only client_id is given (no
        // credential, key, SAS or connection string).
        let explicit_sp = credential.is_none()
            && account_key.is_none()
            && sas_token.is_none()
            && client_id.is_some()
            && connection_string.is_none();
        let default_chain = !explicit_sp
            && credential.is_none()
            && !anon
            && sas_token.is_none()
            && account_key.is_none()
            && connection_string.is_none();

        let mut signing_key = None;
        let (endpoint, secondary_endpoint, auth, account) = if let Some(cs) = &connection_string {
            let c = ConnectionString::parse(cs)?;
            let account = c
                .account_name
                .clone()
                .or_else(|| account_from_url(&c.blob_endpoint));
            let auth = match (&c.account_key, &c.sas_token) {
                (Some(k), _) => {
                    let a = account.clone().ok_or_else(|| {
                        Error::invalid_input(
                            "abfs: Unable to determine account name for shared key credential.",
                        )
                    })?;
                    signing_key = Some((a.clone(), Zeroizing::new(k.clone())));
                    AuthSpec::SharedKey {
                        account: a,
                        key: Zeroizing::new(k.clone()),
                    }
                }
                (None, Some(sas)) if is_sas_token(sas) => {
                    AuthSpec::Sas(Zeroizing::new(sas.trim_start_matches('?').to_owned()))
                }
                (None, Some(other)) => {
                    // The SDK treats a non-SAS string credential as a key.
                    let a = account.clone().ok_or_else(|| {
                        Error::invalid_input(
                            "abfs: Unable to determine account name for shared key credential.",
                        )
                    })?;
                    AuthSpec::SharedKey {
                        account: a,
                        key: Zeroizing::new(other.clone()),
                    }
                }
                (None, None) => AuthSpec::Anonymous,
            };
            (
                c.blob_endpoint.trim_end_matches('/').to_owned(),
                c.secondary_endpoint.clone(),
                auth,
                account,
            )
        } else if let Some(account) = &account_name {
            let endpoint = match &account_host {
                Some(h) if h.contains("://") => h.trim_end_matches('/').to_owned(),
                Some(h) => format!("https://{}", h.trim_end_matches('/')),
                None => format!("https://{account}.blob.core.windows.net"),
            };
            let secondary = match &account_host {
                None => Some(format!("https://{account}-secondary.blob.core.windows.net")),
                Some(_) => None,
            };
            if let Some(k) = &account_key {
                signing_key = Some((account.clone(), Zeroizing::new(k.clone())));
            }
            let auth = if let Some(c) = credential {
                // adlfs: `[credential, account_key]`, first that is set.
                match c {
                    CredOpt::Key(k) => AuthSpec::SharedKey {
                        account: account.clone(),
                        key: Zeroizing::new(k),
                    },
                    CredOpt::Named { account, key } => AuthSpec::SharedKey {
                        account,
                        key: Zeroizing::new(key),
                    },
                    CredOpt::Sas(s) => AuthSpec::Sas(Zeroizing::new(s)),
                    CredOpt::Token { token, expires_on } => AuthSpec::StaticToken {
                        token: Zeroizing::new(token),
                        expires_on,
                    },
                }
            } else if explicit_sp {
                AuthSpec::ClientSecret(ServicePrincipal {
                    tenant_id: tenant_id.clone().ok_or_else(|| {
                        Error::invalid_input("abfs: tenant_id should be the id of a Microsoft Entra tenant")
                    })?,
                    client_id: client_id.clone().unwrap_or_default(),
                    client_secret: Zeroizing::new(client_secret.clone().ok_or_else(|| {
                        Error::invalid_input("abfs: secret should be an Azure Active Directory application's client secret")
                    })?),
                    authority: authority.clone(),
                })
            } else if let Some(k) = &account_key {
                AuthSpec::SharedKey {
                    account: account.clone(),
                    key: Zeroizing::new(k.clone()),
                }
            } else if default_chain {
                AuthSpec::Default(Box::new(default_chain_spec(
                    env,
                    &authority,
                    ChainKw {
                        exclude_env,
                        exclude_workload,
                        exclude_mi,
                        exclude_cli,
                        mi_client_id,
                        wi_client_id,
                        wi_tenant_id,
                        process_timeout,
                    },
                )))
            } else if let Some(s) = &sas_token {
                AuthSpec::Sas(Zeroizing::new(s.trim_start_matches('?').to_owned()))
            } else {
                AuthSpec::Anonymous
            };
            (endpoint, secondary, auth, Some(account.clone()))
        } else {
            return Err(Error::invalid_input(
                "abfs: Must provide either a connection_string or account_name with credentials!!",
            ));
        };

        let (blocksize, blocksize_set) = match blocksize_opt {
            Some(b) => (b, true),
            None => (DEFAULT_BLOCK_SIZE, false),
        };
        let dfs_endpoint = dfs_endpoint_opt
            .map(|e| e.trim_end_matches('/').to_owned())
            .or_else(|| dfs_from_blob(&endpoint));
        Ok(AzureConfig {
            account_name: account,
            endpoint,
            secondary_endpoint,
            location_mode,
            auth,
            signing_key,
            blocksize,
            blocksize_set,
            default_fill_cache,
            default_cache_type,
            version_aware,
            assume_container_exists,
            max_concurrency,
            upload_concurrency,
            list_page_size,
            hns,
            dfs_endpoint,
            request_size,
            server_timeout,
            http,
        })
    }

    /// The endpoint requests go to (per `location_mode`).
    pub fn active_endpoint(&self) -> Result<String> {
        match self.location_mode {
            LocationMode::Primary => Ok(self.endpoint.clone()),
            LocationMode::Secondary => match &self.secondary_endpoint {
                Some(s) if s.contains("://") => Ok(s.trim_end_matches('/').to_owned()),
                Some(s) => {
                    let scheme = self.endpoint.split("://").next().unwrap_or("https");
                    Ok(format!("{scheme}://{}", s.trim_end_matches('/')))
                }
                None => Err(Error::invalid_input(
                    "abfs: location_mode='secondary' but no secondary endpoint is known",
                )),
            },
        }
    }

    /// Upload block size: `blocksize` when given, else 8 MiB.
    pub fn upload_block_size(&self) -> usize {
        if self.blocksize_set {
            self.blocksize.min(MAX_BLOCK_SIZE)
        } else {
            DEFAULT_UPLOAD_BLOCK
        }
    }
}

struct ChainKw {
    exclude_env: bool,
    exclude_workload: bool,
    exclude_mi: bool,
    exclude_cli: bool,
    mi_client_id: Option<String>,
    wi_client_id: Option<String>,
    wi_tenant_id: Option<String>,
    process_timeout: Option<Duration>,
}

fn default_chain_spec(env: EnvFn<'_>, authority: &str, kw: ChainKw) -> DefaultChainSpec {
    let e = |k: &str| nonempty(env(k));
    let mut spec = DefaultChainSpec::default();
    if !kw.exclude_env {
        match (
            e("AZURE_TENANT_ID"),
            e("AZURE_CLIENT_ID"),
            e("AZURE_CLIENT_SECRET"),
        ) {
            (Some(t), Some(c), Some(s)) => {
                spec.environment = Some(ServicePrincipal {
                    tenant_id: t,
                    client_id: c,
                    client_secret: Zeroizing::new(s),
                    authority: authority.to_owned(),
                });
            }
            _ if e("AZURE_CLIENT_CERTIFICATE_PATH").is_some() => {
                spec.environment_unavailable = Some(
                    "EnvironmentCredential: certificate credentials are not supported by fsfast"
                        .into(),
                );
            }
            _ => {
                spec.environment_unavailable = Some(
                    "EnvironmentCredential: environment variables are not fully configured".into(),
                );
            }
        }
    }
    if !kw.exclude_workload {
        let tenant = kw.wi_tenant_id.clone().or_else(|| e("AZURE_TENANT_ID"));
        let client = kw.wi_client_id.clone().or_else(|| e("AZURE_CLIENT_ID"));
        if let (Some(t), Some(c), Some(f)) = (tenant, client, e("AZURE_FEDERATED_TOKEN_FILE")) {
            spec.workload = Some(WorkloadSpec {
                tenant_id: t,
                client_id: c,
                token_file: PathBuf::from(f),
                authority: authority.to_owned(),
            });
        }
    }
    if !kw.exclude_mi {
        let endpoint = match (e("IDENTITY_ENDPOINT"), e("IDENTITY_HEADER")) {
            (Some(endpoint), Some(header)) => {
                ManagedIdentityEndpoint::AppService { endpoint, header }
            }
            _ => {
                let host = e("AZURE_POD_IDENTITY_AUTHORITY_HOST");
                ManagedIdentityEndpoint::Imds(match host {
                    Some(h) => {
                        format!("{}/metadata/identity/oauth2/token", h.trim_end_matches('/'))
                    }
                    None => IMDS_ENDPOINT.to_owned(),
                })
            }
        };
        spec.managed_identity = Some(ManagedIdentitySpec {
            endpoint,
            client_id: kw.mi_client_id.clone().or_else(|| e("AZURE_CLIENT_ID")),
        });
    }
    if !kw.exclude_cli {
        spec.cli = Some(CliSpec {
            timeout: kw.process_timeout.unwrap_or(Duration::from_secs(10)),
            tenant_id: None,
        });
    }
    spec
}

/// `https://acct.blob.core.windows.net` → `https://acct.dfs.core.windows.net`.
pub fn dfs_from_blob(endpoint: &str) -> Option<String> {
    let (scheme, rest) = endpoint.split_once("://")?;
    let (host, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    host.contains(".blob.")
        .then(|| format!("{scheme}://{}{path}", host.replacen(".blob.", ".dfs.", 1)))
}

/// Account name from an endpoint URL: `{account}.blob.core.*` hosts, or the
/// first path segment for loopback (emulator) endpoints, as the SDK does.
pub fn account_from_url(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let hostname = host.rsplit_once('@').map_or(host, |(_, h)| h);
    if let Some(i) = hostname.find(".blob.core.") {
        return Some(hostname[..i].to_owned()).filter(|a| !a.is_empty());
    }
    if hostname.starts_with("localhost") || hostname.starts_with("127.0.0.1") {
        let a = path.trim_matches('/');
        let a = a.split('/').next().unwrap_or("");
        return (!a.is_empty()).then(|| a.to_owned());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(pairs: &[(&str, Value)], env: &[(&str, &str)]) -> Result<AzureConfig> {
        let opts: Options = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect();
        let env: HashMap<String, String> = env
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect();
        AzureConfig::from_options(opts, &|k| env.get(k).cloned())
    }

    #[test]
    fn connection_string_wins() {
        let c = cfg(
            &[
                (
                    "connection_string",
                    "AccountName=a;AccountKey=a2V5;BlobEndpoint=http://127.0.0.1:10000/a".into(),
                ),
                ("account_name", "ignored".into()),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(c.endpoint, "http://127.0.0.1:10000/a");
        assert!(matches!(c.auth, AuthSpec::SharedKey { ref account, .. } if account == "a"));
        assert_eq!(c.signing_key.as_ref().map(|k| k.0.as_str()), Some("a"));
    }

    #[test]
    fn account_key_and_host() {
        let c = cfg(
            &[
                ("account_name", "acct".into()),
                ("account_key", "a2V5".into()),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(c.endpoint, "https://acct.blob.core.windows.net");
        assert!(matches!(c.auth, AuthSpec::SharedKey { .. }));
        let c = cfg(
            &[
                ("account_name", "acct".into()),
                ("account_host", "acct.blob.core.chinacloudapi.cn".into()),
                ("anon", true.into()),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(c.endpoint, "https://acct.blob.core.chinacloudapi.cn");
        assert!(matches!(c.auth, AuthSpec::Anonymous));
    }

    #[test]
    fn env_fallbacks_and_default_chain() {
        let c = cfg(
            &[],
            &[
                ("AZURE_STORAGE_ACCOUNT_NAME", "acct"),
                ("AZURE_STORAGE_SAS_TOKEN", "?sv=1&sig=x"),
            ],
        )
        .unwrap();
        assert!(matches!(c.auth, AuthSpec::Sas(ref s) if s.as_str() == "sv=1&sig=x"));
        let c = cfg(
            &[("account_name", "acct".into())],
            &[
                ("AZURE_TENANT_ID", "t"),
                ("AZURE_CLIENT_ID", "c"),
                ("AZURE_CLIENT_SECRET", "s"),
            ],
        )
        .unwrap();
        let AuthSpec::Default(d) = &c.auth else {
            panic!("{:?}", c.auth)
        };
        assert!(d.environment.is_some() && d.managed_identity.is_some() && d.cli.is_some());
        let c = cfg(
            &[("account_name", "acct".into())],
            &[("AZURE_STORAGE_ANON", "1")],
        )
        .unwrap();
        assert!(matches!(c.auth, AuthSpec::Anonymous));
        let c = cfg(
            &[
                ("account_name", "acct".into()),
                ("exclude_cli_credential", true.into()),
                ("exclude_managed_identity_credential", true.into()),
            ],
            &[],
        )
        .unwrap();
        let AuthSpec::Default(d) = &c.auth else {
            panic!()
        };
        assert!(d.cli.is_none() && d.managed_identity.is_none());
    }

    #[test]
    fn service_principal() {
        let c = cfg(
            &[
                ("account_name", "acct".into()),
                ("client_id", "cid".into()),
                ("client_secret", "sec".into()),
                ("tenant_id", "tid".into()),
            ],
            &[],
        )
        .unwrap();
        assert!(matches!(c.auth, AuthSpec::ClientSecret(ref sp) if sp.client_id == "cid"));
        assert!(
            cfg(
                &[("account_name", "acct".into()), ("client_id", "cid".into())],
                &[]
            )
            .is_err()
        );
    }

    #[test]
    fn credential_forms() {
        let c = cfg(
            &[
                ("account_name", "acct".into()),
                ("credential", "a2V5".into()),
            ],
            &[],
        )
        .unwrap();
        assert!(matches!(c.auth, AuthSpec::SharedKey { .. }));
        let c = cfg(
            &[
                ("account_name", "acct".into()),
                ("credential", "sv=1&sig=a".into()),
            ],
            &[],
        )
        .unwrap();
        assert!(matches!(c.auth, AuthSpec::Sas(_)));
        let mut m = std::collections::BTreeMap::new();
        m.insert("token".to_owned(), Value::Str("tok".into()));
        m.insert("expires_on".to_owned(), Value::Int(2_000_000_000));
        let c = cfg(
            &[
                ("account_name", "acct".into()),
                ("credential", Value::Map(m)),
            ],
            &[],
        )
        .unwrap();
        assert!(matches!(c.auth, AuthSpec::StaticToken { .. }));
        assert!(
            cfg(
                &[
                    ("account_name", "acct".into()),
                    ("credential", Value::Int(1))
                ],
                &[]
            )
            .is_err()
        );
    }

    #[test]
    fn strictness_and_errors() {
        assert!(cfg(&[], &[]).is_err());
        let e = cfg(
            &[
                ("account_name", "a".into()),
                ("anon", true.into()),
                ("bogus", 1.into()),
            ],
            &[],
        )
        .unwrap_err();
        assert!(e.to_string().contains("bogus"));
        assert!(
            cfg(
                &[
                    ("account_name", "a".into()),
                    ("location_mode", "tertiary".into())
                ],
                &[]
            )
            .is_err()
        );
        let c = cfg(
            &[
                ("account_name", "a".into()),
                ("anon", true.into()),
                ("socket_timeout", 5.into()),
                ("loop", Value::Null),
                ("use_listings_cache", false.into()),
                ("timeout", 30.into()),
                ("connection_timeout", 2.into()),
                ("read_timeout", 9.into()),
                ("location_mode", "secondary".into()),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(c.server_timeout, Some(30));
        assert_eq!(c.http.connect_timeout, Some(Duration::from_secs(2)));
        assert_eq!(c.http.read_timeout, Some(Duration::from_secs(9)));
        assert_eq!(
            c.active_endpoint().unwrap(),
            "https://a-secondary.blob.core.windows.net"
        );
    }

    #[test]
    fn dfs_endpoints() {
        assert_eq!(
            dfs_from_blob("https://acct.blob.core.windows.net").as_deref(),
            Some("https://acct.dfs.core.windows.net")
        );
        assert_eq!(
            dfs_from_blob("http://127.0.0.1:10000/devstoreaccount1"),
            None
        );
        let c = cfg(
            &[
                ("account_name", "acct".into()),
                ("anon", true.into()),
                ("hns", true.into()),
            ],
            &[],
        )
        .unwrap();
        assert!(c.hns);
        assert_eq!(
            c.dfs_endpoint.as_deref(),
            Some("https://acct.dfs.core.windows.net")
        );
    }

    #[test]
    fn accounts_from_urls() {
        assert_eq!(
            account_from_url("https://acct.blob.core.windows.net/"),
            Some("acct".into())
        );
        assert_eq!(
            account_from_url("http://127.0.0.1:10000/devstoreaccount1"),
            Some("devstoreaccount1".into())
        );
        assert_eq!(account_from_url("https://custom.example"), None);
    }
}
