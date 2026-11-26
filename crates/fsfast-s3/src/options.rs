//! s3fs `storage_options` → typed configuration.
//!
//! Every name s3fs's `S3FileSystem.__init__` accepts is understood, plus the
//! botocore keyword arguments s3fs forwards (`client_kwargs` to
//! `create_client`, `config_kwargs` to `botocore.config.Config`,
//! `s3_additional_kwargs` to every API call) and the session keyword
//! `profile`. Options that only matter to Python (`asynchronous`, `loop`,
//! `session`, the listings-cache knobs) are accepted and ignored on purpose;
//! anything else is an error (see [`fsfast_core::OptionReader`]).
//!
//! fsfast-specific tuning options (no s3fs equivalent):
//!
//! | option | default | meaning |
//! |---|---|---|
//! | `connect_timeout`, `read_timeout`, `total_timeout` | 5 s, 15 s, none | as in `config_kwargs` (fsfast's read timeout is an idle timeout) |
//! | `max_retries` | 4 | retries after the first attempt |
//! | `limit_per_host` | 256 | upper bound of the adaptive per-host concurrency |
//! | `http2`, `ca_bundle`, `user_agent`, `rotate_dns` | off, none, fsfast, on | transport settings |
//! | `request_size` | 8 MiB | size of ranged GETs for large reads |
//! | `part_size` | 16 MiB | multipart upload part size (when `default_block_size` is not given) |
//! | `speculative_info` | false | race `HEAD` and `LIST` in `info()` (one round trip, one extra request) |
//! | `strict_delete` | true | `rm_file`/`rm_files` report missing keys as `NotFound` (S3 itself deletes them silently; costs a check) |
//! | `probe_conditional_writes` | true | verify once that the server enforces `If-None-Match: *` before relying on it for `xb` writes |
//! | `copy_threshold` | 150 MiB | objects up to this size are copied with one `CopyObject` (s3fs's `MANAGED_COPY_THRESHOLD`), larger ones with parallel `UploadPartCopy` |
//! | `copy_part_size` | 64 MiB | part size of multipart copies (at least 5 MiB) |

use std::collections::BTreeMap;
use std::time::Duration;

use fsfast_core::{Error, OptionReader, Options, Result, Value};
use fsfast_engine::reader::CacheMode;
use fsfast_http_transport::{HttpConfig, ProxyConfig};

use crate::credentials::Credentials;
use crate::endpoint::Addressing;
use crate::params::Params;
use crate::profile::Env;

/// s3fs's `S3FileSystem.default_block_size` (50 MiB).
pub const S3FS_DEFAULT_BLOCK_SIZE: usize = 50 << 20;
/// Default ranged-GET size for large reads.
pub const DEFAULT_REQUEST_SIZE: usize = 8 << 20;
/// Default multipart part size.
pub const DEFAULT_PART_SIZE: usize = 16 << 20;
/// Default per-file transfer concurrency (s3fs: 10).
pub const DEFAULT_MAX_CONCURRENCY: usize = 16;
/// s3fs `MANAGED_COPY_THRESHOLD`: larger objects are copied in parts.
pub const COPY_THRESHOLD: u64 = 150 << 20;
/// Default part size of multipart copies.
pub const DEFAULT_COPY_PART: u64 = 64 << 20;

/// Options s3fs accepts that have no effect in fsfast (Python-side
/// concerns: event loops, sessions, listings caches, instance caching).
const IGNORED: &[&str] = &[
    "asynchronous",
    "loop",
    "session",
    "skip_instance_cache",
    "use_listings_cache",
    "listings_expiry_time",
    "max_paths",
];

/// botocore's `request_checksum_calculation`: whether object uploads carry
/// a checksum (`"when_supported"`) or only operations that require one do
/// (`"when_required"`).
pub fn parse_checksum_calculation(v: &str, what: &str) -> Result<bool> {
    match v.to_ascii_lowercase().as_str() {
        "when_supported" => Ok(true),
        "when_required" => Ok(false),
        _ => Err(Error::invalid_input(format!(
            "{what}: request_checksum_calculation must be \"when_supported\" or \"when_required\", got {v:?}"
        ))),
    }
}

/// Parsed and validated s3fs options.
#[derive(Debug, Clone)]
pub struct S3Options {
    /// `anon`: unsigned requests.
    pub anon: bool,
    /// Explicit credentials (`key`/`secret`/`token`, `username`/`password`,
    /// or the `aws_*` keys of `client_kwargs`).
    pub credentials: Option<Credentials>,
    /// `endpoint_url` (top level, else `client_kwargs`).
    pub endpoint_url: Option<String>,
    /// `client_kwargs` / `config_kwargs` `region_name`.
    pub region: Option<String>,
    /// `client_kwargs["region_name"]`, which s3fs uses as the location
    /// constraint of buckets created by `mkdir`.
    pub bucket_region: Option<String>,
    /// Session `profile`.
    pub profile: Option<String>,
    /// `use_ssl` (`client_kwargs` wins over the top-level option).
    pub use_ssl: bool,
    /// Whether `verify`/`ca_bundle` were given (otherwise `AWS_CA_BUNDLE`
    /// and the profile's `ca_bundle` apply).
    pub tls_configured: bool,
    /// `config_kwargs["s3"]["addressing_style"]`.
    pub addressing: Option<Addressing>,
    /// Dual-stack endpoints.
    pub dualstack: Option<bool>,
    /// FIPS endpoints.
    pub fips: Option<bool>,
    /// Transfer Acceleration.
    pub accelerate: Option<bool>,
    /// `us_east_1_regional_endpoint == "regional"`.
    pub us_east_1_regional: Option<bool>,
    /// `config_kwargs["s3"]["payload_signing_enabled"]`.
    pub payload_signing: Option<bool>,
    /// `config_kwargs["request_checksum_calculation"]`: `Some(true)` for
    /// `"when_supported"` (object data carries a `Content-MD5`), `Some(false)`
    /// for `"when_required"`; `None`: from the environment or profile, else
    /// `"when_supported"` (botocore's default).
    pub request_checksum: Option<bool>,
    /// `requester_pays`.
    pub requester_pays: bool,
    /// `version_aware`.
    pub version_aware: bool,
    /// `cache_regions` (disabled when a region or endpoint is configured,
    /// as in s3fs).
    pub cache_regions: bool,
    /// `default_block_size` (s3fs: 50 MiB).
    pub default_block_size: usize,
    /// Whether `default_block_size` was given explicitly.
    pub block_size_explicit: bool,
    /// `default_fill_cache`.
    pub default_fill_cache: bool,
    /// `default_cache_type`.
    pub default_cache_type: String,
    /// `fixed_upload_size`.
    pub fixed_upload_size: bool,
    /// `local_expiry_check`.
    pub local_expiry_check: bool,
    /// `max_concurrency`.
    pub max_concurrency: usize,
    /// `s3_additional_kwargs` (validated).
    pub params: Params,
    /// Transport settings.
    pub http: HttpConfig,
    /// fsfast: race HEAD and LIST in `info`.
    pub speculative_info: bool,
    /// fsfast: report missing keys on delete.
    pub strict_delete: bool,
    /// fsfast: verify conditional-write support per bucket.
    pub probe_conditional_writes: bool,
    /// fsfast: multipart part size.
    pub part_size: usize,
    /// fsfast: ranged-GET size.
    pub request_size: usize,
    /// fsfast: largest object copied with a single `CopyObject`.
    pub copy_threshold: u64,
    /// fsfast: part size of multipart copies.
    pub copy_part_size: u64,
    /// The environment credentials, regions and endpoints are read from.
    pub env: Env,
}

/// HTTP defaults for S3 (s3fs's connect/read timeouts, no automatic
/// redirects so region redirects can be handled, HTTP/1.1 with many
/// connections spread over the endpoint's addresses).
pub fn s3_http_defaults() -> HttpConfig {
    HttpConfig {
        connect_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(15)),
        max_redirects: None,
        // S3 serves HTTP/1.1; many connections beat one multiplexed HTTP/2
        // connection for bulk transfers where a server offers both.
        http2: false,
        rotate_dns: true,
        pool_max_idle_per_host: 256,
        max_connections_per_host: 256,
        initial_connections_per_host: 64,
        ..HttpConfig::default()
    }
}

fn nested_finish(r: OptionReader, what: &str) -> Result<()> {
    r.finish()
        .map_err(|e| Error::invalid_input(format!("{what}: {}", e.message())))
}

impl S3Options {
    /// Parse `opts` (s3fs keyword arguments) against the process environment.
    pub fn parse(opts: Options) -> Result<Self> {
        Self::parse_with_env(opts, Env::process())
    }

    /// Parse `opts` with a given environment (tests).
    pub fn parse_with_env(opts: Options, env: Env) -> Result<Self> {
        let mut r = OptionReader::new("s3", opts);
        let anon = r.bool("anon")?.unwrap_or(false);
        let key = r.string("key")?;
        let username = r.string("username")?;
        let secret = r.string("secret")?;
        let password = r.string("password")?;
        if key.is_some() && username.is_some() {
            return Err(Error::invalid_input(
                "Supply either key or username, not both",
            ));
        }
        if secret.is_some() && password.is_some() {
            return Err(Error::invalid_input("Supply secret or password, not both"));
        }
        let mut key = key.or(username);
        let mut secret = secret.or(password);
        let mut token = r.string("token")?;
        let mut endpoint_url = r.string("endpoint_url")?;
        let mut use_ssl = r.bool("use_ssl")?.unwrap_or(true);
        let requester_pays = r.bool("requester_pays")?.unwrap_or(false);
        let version_aware = r.bool("version_aware")?.unwrap_or(false);
        let cache_regions_opt = r.bool("cache_regions")?.unwrap_or(false);
        let block_size = r.usize("default_block_size")?.filter(|b| *b > 0);
        let default_fill_cache = r.bool("default_fill_cache")?.unwrap_or(true);
        let default_cache_type = r
            .string("default_cache_type")?
            .unwrap_or_else(|| "readahead".to_owned());
        CacheMode::from_fsspec(&default_cache_type, block_size, None)?;
        let fixed_upload_size = r.bool("fixed_upload_size")?.unwrap_or(false);
        let local_expiry_check = r.bool("local_expiry_check")?.unwrap_or(false);
        let max_concurrency = match r.i64("max_concurrency")? {
            Some(n) if n < 1 => return Err(Error::invalid_input("max_concurrency must be >= 1")),
            Some(n) => n as usize,
            None => DEFAULT_MAX_CONCURRENCY,
        };
        let profile = r.string("profile")?;
        r.accept_ignored(IGNORED);

        let mut params = match r.map("s3_additional_kwargs")? {
            Some(m) => Params::from_map(&m, "s3_additional_kwargs")?,
            None => Params::default(),
        };
        if requester_pays {
            params.set("RequestPayer", &Value::Str("requester".into()))?;
        }

        let mut http = s3_http_defaults();
        // fsfast tuning options at the top level (no s3fs equivalent).
        http.apply_fsfast_options(&mut r)?;
        let mut tls_configured = http.ca_bundle.is_some();

        let mut region = None;
        let mut bucket_region = None;
        let mut config_from_client: Option<BTreeMap<String, Value>> = None;
        if let Some(mut ck) = r.nested("client_kwargs")? {
            if let Some(rn) = ck.string("region_name")? {
                bucket_region = Some(rn.clone());
                region = Some(rn);
            }
            if let Some(e) = ck.string("endpoint_url")?
                && endpoint_url.is_none()
            {
                endpoint_url = Some(e);
            }
            if let Some(s) = ck.bool("use_ssl")? {
                use_ssl = s;
            }
            match ck.value("verify") {
                None => {}
                Some(Value::Bool(b)) => {
                    http.tls_verify = b;
                    tls_configured = true;
                }
                Some(Value::Str(path)) => {
                    http.ca_bundle = Some(path.into());
                    tls_configured = true;
                }
                Some(v) => {
                    return Err(Error::invalid_input(format!(
                        "client_kwargs: 'verify' must be a boolean or a CA bundle path, got {}",
                        v.type_name()
                    )));
                }
            }
            let ck_key = ck.string("aws_access_key_id")?;
            let ck_secret = ck.string("aws_secret_access_key")?;
            let ck_token = ck.string("aws_session_token")?;
            key = key.or(ck_key);
            secret = secret.or(ck_secret);
            token = token.or(ck_token);
            config_from_client = ck.map("config")?;
            ck.accept_ignored(&["api_version", "aws_account_id"]);
            nested_finish(ck, "client_kwargs")?;
        }

        let mut addressing = None;
        let mut dualstack = None;
        let mut fips = None;
        let mut accelerate = None;
        let mut us_east_1_regional = None;
        let mut payload_signing = None;
        let mut request_checksum = None;
        let mut anon = anon;
        // `client_kwargs["config"]` (a botocore Config converted to a dict)
        // first, then `config_kwargs`, which s3fs merges on top.
        let mut configs = Vec::new();
        if let Some(c) = config_from_client {
            configs.push((OptionReader::new("s3", c), "client_kwargs['config']"));
        }
        if let Some(c) = r.nested("config_kwargs")? {
            configs.push((c, "config_kwargs"));
        }
        for (mut c, what) in configs {
            if let Some(rn) = c.string("region_name")? {
                region = Some(rn);
            }
            match c.string("signature_version")?.as_deref() {
                None | Some("s3v4" | "v4") => {}
                Some("unsigned" | "UNSIGNED") => anon = true,
                Some(v) => {
                    return Err(Error::unsupported(format!(
                        "{what}: signature_version {v:?} (only SigV4 is implemented)"
                    )));
                }
            }
            if let Some(v) = c.string("request_checksum_calculation")? {
                request_checksum = Some(parse_checksum_calculation(&v, what)?);
            }
            if let Some(d) = c.duration_secs("connect_timeout")? {
                http.connect_timeout = Some(d);
            }
            if let Some(d) = c.duration_secs("read_timeout")? {
                http.read_timeout = Some(d);
            }
            if let Some(n) = c.usize("max_pool_connections")? {
                let n = n.max(1);
                http.max_connections_per_host = n;
                http.pool_max_idle_per_host = n;
                http.initial_connections_per_host = http.initial_connections_per_host.min(n);
            }
            if let Some(ua) = c.string("user_agent")? {
                http.user_agent = Some(ua);
            }
            let extra = c.string("user_agent_extra")?;
            let appid = c.string("user_agent_appid")?;
            if extra.is_some() || appid.is_some() {
                let base = http
                    .user_agent
                    .clone()
                    .unwrap_or_else(|| format!("fsfast/{}", env!("CARGO_PKG_VERSION")));
                let mut ua = base;
                if let Some(a) = appid {
                    ua.push_str(&format!(" app/{a}"));
                }
                if let Some(e) = extra {
                    ua.push(' ');
                    ua.push_str(&e);
                }
                http.user_agent = Some(ua);
            }
            if let Some(proxies) = c.string_map("proxies")? {
                let scheme = if endpoint_url
                    .as_deref()
                    .is_some_and(|e| e.starts_with("http://"))
                    || (endpoint_url.is_none() && !use_ssl)
                {
                    "http"
                } else {
                    "https"
                };
                if let Some(url) = proxies.get(scheme).or_else(|| proxies.get("all")) {
                    http.proxy = ProxyConfig::Url {
                        url: url.clone(),
                        auth: None,
                    };
                }
            }
            if let Some(b) = c.bool("use_dualstack_endpoint")? {
                dualstack = Some(b);
            }
            if let Some(b) = c.bool("use_fips_endpoint")? {
                fips = Some(b);
            }
            if let Some(mut s3) = c.nested("s3")? {
                if let Some(a) = s3.string("addressing_style")? {
                    addressing = Some(Addressing::parse(&a)?);
                }
                if let Some(b) = s3.bool("use_accelerate_endpoint")? {
                    accelerate = Some(b);
                }
                if let Some(b) = s3.bool("use_dualstack_endpoint")? {
                    dualstack = Some(b);
                }
                if let Some(b) = s3.bool("payload_signing_enabled")? {
                    payload_signing = Some(b);
                }
                match s3.string("us_east_1_regional_endpoint")?.as_deref() {
                    None => {}
                    Some("regional") => us_east_1_regional = Some(true),
                    Some("legacy") => us_east_1_regional = Some(false),
                    Some(v) => {
                        return Err(Error::invalid_input(format!(
                            "{what}: us_east_1_regional_endpoint must be 'regional' or 'legacy', got {v:?}"
                        )));
                    }
                }
                s3.accept_ignored(&["use_arn_region", "s3_disable_multiregion_access_points"]);
                nested_finish(s3, &format!("{what}['s3']"))?;
            }
            if let Some(mut retries) = c.nested("retries")? {
                if let Some(n) = retries.u64("total_max_attempts")? {
                    http.max_retries = u32::try_from(n.saturating_sub(1)).unwrap_or(u32::MAX);
                } else if let Some(n) = retries.u64("max_attempts")? {
                    // botocore: retries after the first attempt.
                    http.max_retries = u32::try_from(n).unwrap_or(u32::MAX);
                }
                match retries.string("mode")?.as_deref() {
                    None | Some("legacy" | "standard" | "adaptive") => {}
                    Some(m) => {
                        return Err(Error::invalid_input(format!(
                            "{what}: retries mode must be legacy, standard or adaptive, got {m:?}"
                        )));
                    }
                }
                nested_finish(retries, &format!("{what}['retries']"))?;
            }
            if c.value("client_cert").is_some() {
                return Err(Error::unsupported(format!(
                    "{what}: client_cert (mutual TLS)"
                )));
            }
            if c.value("sigv4a_signing_region_set").is_some() {
                return Err(Error::unsupported(format!("{what}: SigV4a")));
            }
            // Accepted without effect: they tune botocore internals
            // (validation, compression, checksums fsfast does not compute,
            // host prefixes, endpoint discovery, keep-alive) or name
            // defaults fsfast already uses.
            c.accept_ignored(&[
                "parameter_validation",
                "inject_host_prefix",
                "tcp_keepalive",
                "endpoint_discovery_enabled",
                "proxies_config",
                "request_min_compression_size_bytes",
                "disable_request_compression",
                "response_checksum_validation",
                "account_id_endpoint_mode",
                "auth_scheme_preference",
                "client_context_params",
                "defaults_mode",
                "ignore_configured_endpoint_urls",
            ]);
            nested_finish(c, what)?;
        }

        // fsfast-specific behaviour options.
        let speculative_info = r.bool("speculative_info")?.unwrap_or(false);
        let strict_delete = r.bool("strict_delete")?.unwrap_or(true);
        let probe_conditional_writes = r.bool("probe_conditional_writes")?.unwrap_or(true);
        let part_size = r.usize("part_size")?.filter(|p| *p > 0);
        let request_size = r
            .usize("request_size")?
            .filter(|p| *p > 0)
            .unwrap_or(DEFAULT_REQUEST_SIZE);
        let copy_threshold = r
            .u64("copy_threshold")?
            .unwrap_or(COPY_THRESHOLD)
            .min(5 << 30);
        let copy_part_size = r
            .u64("copy_part_size")?
            .unwrap_or(DEFAULT_COPY_PART)
            .clamp(5 << 20, 5 << 30);
        r.finish()?;

        let credentials = if anon {
            None
        } else {
            match (key, secret) {
                (Some(k), Some(s)) => Some(Credentials::new(k, s, token, None)),
                (None, None) => None,
                (Some(_), None) => {
                    return Err(Error::invalid_input(
                        "Partial credentials found in explicit, missing: aws_secret_access_key",
                    ));
                }
                (None, Some(_)) => {
                    return Err(Error::invalid_input(
                        "Partial credentials found in explicit, missing: aws_access_key_id",
                    ));
                }
            }
        };
        // s3fs turns region caching off when a region or endpoint is set.
        let cache_regions = cache_regions_opt && region.is_none() && endpoint_url.is_none();
        let part_size = part_size
            .or(block_size)
            .unwrap_or(DEFAULT_PART_SIZE)
            .clamp(5 << 20, 5 << 30);
        if block_size.is_some_and(|b| b < 5 << 20) {
            // s3fs refuses write blocks under 5 MiB (S3's minimum part size)
            // when opening for writing; reads are fine.
            tracing::debug!("default_block_size below 5 MiB: writes use 5 MiB parts");
        }
        Ok(S3Options {
            anon,
            credentials,
            endpoint_url,
            region,
            bucket_region,
            profile,
            use_ssl,
            tls_configured,
            addressing,
            dualstack,
            fips,
            accelerate,
            us_east_1_regional,
            payload_signing,
            request_checksum,
            requester_pays,
            version_aware,
            cache_regions,
            default_block_size: block_size.unwrap_or(S3FS_DEFAULT_BLOCK_SIZE),
            block_size_explicit: block_size.is_some(),
            default_fill_cache,
            default_cache_type,
            fixed_upload_size,
            local_expiry_check,
            max_concurrency,
            params,
            http,
            speculative_info,
            strict_delete,
            probe_conditional_writes,
            part_size,
            request_size,
            copy_threshold,
            copy_part_size,
            env,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(pairs: &[(&str, Value)]) -> Options {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    fn map(pairs: &[(&str, Value)]) -> Value {
        Value::Map(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        )
    }

    fn parse(pairs: &[(&str, Value)]) -> Result<S3Options> {
        S3Options::parse_with_env(opts(pairs), Env::from_map::<[(&str, &str); 0], _, _>([]))
    }

    #[test]
    fn s3fs_names() {
        let o = parse(&[
            ("key", "AK".into()),
            ("secret", "SK".into()),
            ("token", "T".into()),
            ("endpoint_url", "http://127.0.0.1:9000".into()),
            ("requester_pays", true.into()),
            ("version_aware", true.into()),
            ("default_block_size", Value::Int(8 << 20)),
            ("default_cache_type", "bytes".into()),
            ("max_concurrency", Value::Int(4)),
            ("use_listings_cache", false.into()),
            ("skip_instance_cache", true.into()),
            ("asynchronous", false.into()),
            (
                "client_kwargs",
                map(&[
                    ("region_name", "eu-west-1".into()),
                    ("verify", false.into()),
                ]),
            ),
            (
                "config_kwargs",
                map(&[
                    ("connect_timeout", Value::Int(3)),
                    ("read_timeout", Value::Int(60)),
                    ("max_pool_connections", Value::Int(50)),
                    ("s3", map(&[("addressing_style", "virtual".into())])),
                    (
                        "retries",
                        map(&[
                            ("max_attempts", Value::Int(10)),
                            ("mode", "standard".into()),
                        ]),
                    ),
                ]),
            ),
            (
                "s3_additional_kwargs",
                map(&[("ServerSideEncryption", "AES256".into())]),
            ),
        ])
        .unwrap();
        let c = o.credentials.as_ref().unwrap();
        assert_eq!(c.access_key_id(), "AK");
        assert_eq!(c.session_token(), Some("T"));
        assert_eq!(o.region.as_deref(), Some("eu-west-1"));
        assert_eq!(o.bucket_region.as_deref(), Some("eu-west-1"));
        assert!(!o.http.tls_verify);
        assert_eq!(o.http.connect_timeout, Some(Duration::from_secs(3)));
        assert_eq!(o.http.read_timeout, Some(Duration::from_secs(60)));
        assert_eq!(o.http.max_connections_per_host, 50);
        assert_eq!(o.http.max_retries, 10);
        assert_eq!(o.addressing, Some(Addressing::Virtual));
        assert_eq!(o.params.get("RequestPayer"), Some("requester"));
        assert_eq!(o.params.get("ServerSideEncryption"), Some("AES256"));
        assert_eq!(o.max_concurrency, 4);
        assert_eq!(o.part_size, 8 << 20);
        assert!(!o.cache_regions);
    }

    #[test]
    fn aliases_and_conflicts() {
        let o = parse(&[("username", "U".into()), ("password", "P".into())]).unwrap();
        assert_eq!(o.credentials.unwrap().access_key_id(), "U");
        assert!(parse(&[("key", "a".into()), ("username", "b".into())]).is_err());
        assert!(parse(&[("secret", "a".into()), ("password", "b".into())]).is_err());
        assert!(parse(&[("key", "a".into())]).is_err());
        let o = parse(&[
            ("anon", true.into()),
            ("key", "a".into()),
            ("secret", "b".into()),
        ])
        .unwrap();
        assert!(o.anon && o.credentials.is_none());
        let o = parse(&[(
            "client_kwargs",
            map(&[
                ("aws_access_key_id", "CK".into()),
                ("aws_secret_access_key", "CS".into()),
                ("endpoint_url", "http://x:1".into()),
            ]),
        )])
        .unwrap();
        assert_eq!(o.credentials.unwrap().access_key_id(), "CK");
        assert_eq!(o.endpoint_url.as_deref(), Some("http://x:1"));
    }

    #[test]
    fn strictness() {
        assert!(parse(&[("bogus", true.into())]).is_err());
        assert!(parse(&[("client_kwargs", map(&[("bogus", true.into())]))]).is_err());
        assert!(
            parse(&[(
                "config_kwargs",
                map(&[("s3", map(&[("bogus", true.into())]))])
            )])
            .is_err()
        );
        assert!(parse(&[("s3_additional_kwargs", map(&[("NotAParam", "x".into())]))]).is_err());
        assert!(parse(&[("max_concurrency", Value::Int(0))]).is_err());
        assert!(parse(&[("default_cache_type", "nonsense".into())]).is_err());
        assert_eq!(
            parse(&[("config_kwargs", map(&[("signature_version", "s3".into())]))])
                .unwrap_err()
                .kind(),
            fsfast_core::ErrorKind::Unsupported
        );
        let o = parse(&[(
            "config_kwargs",
            map(&[("signature_version", "UNSIGNED".into())]),
        )])
        .unwrap();
        assert!(o.anon);
        let o = parse(&[("cache_regions", true.into())]).unwrap();
        assert!(o.cache_regions);
        let o = parse(&[
            ("cache_regions", true.into()),
            ("client_kwargs", map(&[("region_name", "us-west-2".into())])),
        ])
        .unwrap();
        assert!(!o.cache_regions);
    }
}
