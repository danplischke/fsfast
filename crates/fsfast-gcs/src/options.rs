//! gcsfs `storage_options`, parsed strictly.
//!
//! | option | effect |
//! |---|---|
//! | `project` | project for listing (`ls("")`) and creating buckets, and the requester-pays `userProject`; default `$GCSFS_DEFAULT_PROJECT` or `""`. With `token="google_default"` it must match the default project |
//! | `access` | `read_only`, `read_write` or `full_control` (default): the OAuth scope |
//! | `token` | see [`crate::auth`] |
//! | `block_size` | gcsfs `default_block_size` for file objects (default 5 MiB); also the upload chunk size of `open_write` when set |
//! | `consistency` | `none` (default), `size`, `md5` or `crc32c`: check uploads against the size/hash GCS reports (any other value means none, as in gcsfs) |
//! | `requests_timeout` | total timeout of each request, seconds |
//! | `requester_pays` | `True` (bill `project`) or a project id: sent as `userProject` |
//! | `session_kwargs` | `aiohttp.ClientSession` keywords (headers, proxy, timeouts, ...; see `HttpConfig::apply_client_kwargs`) |
//! | `endpoint_url` | `http(s)://host:port` instead of `$STORAGE_EMULATOR_HOST` / `https://storage.googleapis.com` |
//! | `default_location` | location of buckets created by `mkdir` |
//! | `version_aware` | parse `#generation` / `?generation=` in paths |
//! | `cache_timeout`, `use_listings_cache`, `listings_expiry_time`, `max_paths`, `skip_instance_cache` | listings cache: Python layer, accepted |
//! | `timeout` | gcsfs's timeout of sync calls: Python layer, accepted |
//! | `secure_serialize`, `check_connection`, `asynchronous`, `loop`, `batch_size` | accepted without effect |
//!
//! fsfast's own tuning options: `request_size` (bytes per ranged GET,
//! default 8 MiB), `max_concurrency` (parallel requests of one transfer,
//! default 16), `upload_chunk_size` (resumable-upload chunk, default
//! 16 MiB, rounded down to a multiple of 256 KiB), `simple_upload_threshold`
//! (`pipe_file`/`put_file` sizes up to which one request uploads the
//! object, default 16 MiB), `verify_crc32c` (check whole-object downloads
//! against GCS's CRC32C, default true), plus the HTTP client options of
//! `HttpConfig::apply_fsfast_options` (`connect_timeout`, `read_timeout`,
//! `total_timeout`, `max_retries`, `limit_per_host`, `http2`, `ca_bundle`,
//! `user_agent`, `rotate_dns`).

use std::time::Duration;

use fsfast_core::{Error, OptionReader, Options, Result};
use fsfast_http_transport::HttpConfig;

use crate::auth::TokenSpec;
use crate::env::GcsEnv;

/// gcsfs `DEFAULT_BLOCK_SIZE`.
pub const DEFAULT_BLOCK_SIZE: usize = 5 << 20;
/// GCS's resumable-upload granularity (gcsfs `GCS_MIN_BLOCK_SIZE`).
pub const CHUNK_GRANULARITY: usize = 256 << 10;
/// gcsfs `GCS_MAX_BLOCK_SIZE`.
pub const MAX_CHUNK: usize = 256 << 20;
/// Default resumable-upload chunk: large enough that the round trip per
/// chunk costs little throughput, small enough to keep two per open file
/// in memory.
pub const DEFAULT_UPLOAD_CHUNK: usize = 16 << 20;

const IGNORED: &[&str] = &[
    "cache_timeout",
    "secure_serialize",
    "check_connection",
    "timeout",
    "asynchronous",
    "loop",
    "batch_size",
    "skip_instance_cache",
    "use_listings_cache",
    "listings_expiry_time",
    "max_paths",
];

/// What `consistency` checks after an upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Consistency {
    /// No check (gcsfs default).
    #[default]
    None,
    /// Compare the object size.
    Size,
    /// Compare the MD5 hash.
    Md5,
    /// Compare the CRC32C checksum.
    Crc32c,
}

impl Consistency {
    /// gcsfs `get_consistency_checker`: unknown values mean no check.
    pub fn parse(s: &str) -> Self {
        match s {
            "size" => Consistency::Size,
            "md5" => Consistency::Md5,
            "crc32c" => Consistency::Crc32c,
            _ => Consistency::None,
        }
    }
}

/// `requester_pays`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RequesterPays {
    /// Off.
    #[default]
    Off,
    /// Bill the filesystem's project.
    Project,
    /// Bill this project.
    Explicit(String),
}

/// Parsed gcsfs options.
#[derive(Debug, Clone)]
pub struct GcsOptions {
    /// `project` as given (or `$GCSFS_DEFAULT_PROJECT`).
    pub project: Option<String>,
    /// `access`.
    pub access: String,
    /// `token`.
    pub token: TokenSpec,
    /// `block_size` (file objects), if given.
    pub block_size: Option<usize>,
    /// `consistency`.
    pub consistency: Consistency,
    /// `requester_pays`.
    pub requester_pays: RequesterPays,
    /// `endpoint_url` (scheme://host[:port], no trailing slash).
    pub endpoint_url: Option<String>,
    /// `default_location`.
    pub default_location: Option<String>,
    /// `version_aware`.
    pub version_aware: bool,
    /// fsfast `request_size`.
    pub request_size: usize,
    /// fsfast `max_concurrency`.
    pub max_concurrency: usize,
    /// fsfast `upload_chunk_size` (a multiple of 256 KiB).
    pub upload_chunk_size: usize,
    /// fsfast `simple_upload_threshold`.
    pub simple_upload_threshold: usize,
    /// fsfast `verify_crc32c`.
    pub verify_crc32c: bool,
    /// HTTP client configuration.
    pub http: HttpConfig,
    /// The environment captured at construction.
    pub env: GcsEnv,
}

/// Round `n` down to a multiple of 256 KiB within GCS's chunk limits.
pub fn round_chunk(n: usize) -> usize {
    (n / CHUNK_GRANULARITY * CHUNK_GRANULARITY).clamp(CHUNK_GRANULARITY, MAX_CHUNK)
}

/// The HTTP defaults for GCS: gcsfs makes 6 attempts with exponential
/// backoff capped at 32 s.
pub fn gcs_http_defaults() -> HttpConfig {
    HttpConfig {
        max_retries: 5,
        retry_base_delay: Duration::from_millis(500),
        retry_max_delay: Duration::from_secs(32),
        ..HttpConfig::default()
    }
}

impl GcsOptions {
    /// Parse `opts`, reading the process environment.
    pub fn parse(opts: Options) -> Result<Self> {
        Self::parse_with_env(opts, GcsEnv::from_process())
    }

    /// Parse `opts` with an explicit environment snapshot.
    pub fn parse_with_env(opts: Options, env: GcsEnv) -> Result<Self> {
        let mut r = OptionReader::new("gcs", opts);
        let project = match r.value("project") {
            None => match env.get("GCSFS_DEFAULT_PROJECT") {
                Some(p) => Some(p.to_owned()),
                None => Some(String::new()),
            },
            Some(fsfast_core::Value::Str(s)) => Some(s),
            Some(v) => {
                return Err(Error::invalid_input(format!(
                    "gcs: option 'project' must be a string, got {}",
                    v.type_name()
                )));
            }
        };
        // `project=None` passed explicitly also arrives as absent; gcsfs
        // warns that buckets cannot be listed or created then.
        let access = r.string("access")?.unwrap_or_else(|| "full_control".to_owned());
        crate::auth::scope_for_access(&access)?;
        let token = TokenSpec::from_value(r.value("token"))?;
        let block_size = r.usize("block_size")?;
        if block_size == Some(0) {
            return Err(Error::invalid_input("gcs: block_size must be positive"));
        }
        let consistency = Consistency::parse(r.string("consistency")?.as_deref().unwrap_or("none"));
        let requester_pays = match r.value("requester_pays") {
            None | Some(fsfast_core::Value::Bool(false)) => RequesterPays::Off,
            Some(fsfast_core::Value::Bool(true)) => RequesterPays::Project,
            Some(fsfast_core::Value::Str(s)) if s.is_empty() => RequesterPays::Off,
            Some(fsfast_core::Value::Str(s)) => RequesterPays::Explicit(s),
            Some(fsfast_core::Value::Int(0)) => RequesterPays::Off,
            Some(fsfast_core::Value::Int(_)) => RequesterPays::Project,
            Some(v) => {
                return Err(Error::invalid_input(format!(
                    "gcs: option 'requester_pays' must be a bool or a project id, got {}",
                    v.type_name()
                )));
            }
        };
        let endpoint_url = match r.string("endpoint_url")? {
            Some(u) => Some(normalize_endpoint(&u)?),
            None => None,
        };
        let default_location = r.string("default_location")?;
        let version_aware = r.bool("version_aware")?.unwrap_or(false);
        let requests_timeout = r.duration_secs("requests_timeout")?;
        r.accept_ignored(IGNORED);

        let request_size = r.usize("request_size")?.unwrap_or(8 << 20);
        if request_size == 0 {
            return Err(Error::invalid_input("gcs: request_size must be positive"));
        }
        let max_concurrency = r.usize("max_concurrency")?.unwrap_or(16).max(1);
        let upload_chunk_size = round_chunk(
            r.usize("upload_chunk_size")?
                .or(block_size)
                .unwrap_or(DEFAULT_UPLOAD_CHUNK),
        );
        let simple_upload_threshold = r.usize("simple_upload_threshold")?.unwrap_or(16 << 20);
        let verify_crc32c = r.bool("verify_crc32c")?.unwrap_or(true);

        let mut http = gcs_http_defaults();
        if let Some(mut sk) = r.nested("session_kwargs")? {
            http.apply_client_kwargs(&mut sk)?;
            sk.finish()
                .map_err(|e| Error::invalid_input(format!("session_kwargs: {}", e.message())))?;
        }
        http.apply_fsfast_options(&mut r)?;
        if let Some(t) = requests_timeout {
            http.total_timeout = Some(t);
        }
        r.finish()?;
        Ok(GcsOptions {
            project,
            access,
            token,
            block_size,
            consistency,
            requester_pays,
            endpoint_url,
            default_location,
            version_aware,
            request_size,
            max_concurrency,
            upload_chunk_size,
            simple_upload_threshold,
            verify_crc32c,
            http,
            env,
        })
    }

    /// gcsfs `_location`: `endpoint_url`, else `$STORAGE_EMULATOR_HOST`
    /// (unless empty or `default`; `http://` added when it has no scheme),
    /// else `https://storage.$GOOGLE_CLOUD_UNIVERSE_DOMAIN`.
    pub fn location(&self) -> Result<String> {
        if let Some(u) = &self.endpoint_url {
            return Ok(u.clone());
        }
        match self.env.get("STORAGE_EMULATOR_HOST") {
            Some(h) if !h.is_empty() && h != "default" => {
                let u = if h.starts_with("http://") || h.starts_with("https://") {
                    h.to_owned()
                } else {
                    format!("http://{h}")
                };
                normalize_endpoint(&u)
            }
            _ => Ok(format!("https://storage.{}", self.universe_domain())),
        }
    }

    /// `$GOOGLE_CLOUD_UNIVERSE_DOMAIN`, default `googleapis.com`.
    pub fn universe_domain(&self) -> &str {
        self.env
            .non_empty("GOOGLE_CLOUD_UNIVERSE_DOMAIN")
            .unwrap_or("googleapis.com")
    }
}

/// Validate an endpoint URL (`http(s)://host[:port]`); a trailing slash is
/// dropped.
pub fn normalize_endpoint(u: &str) -> Result<String> {
    let trimmed = u.trim_end_matches('/');
    let parsed = fsfast_http_transport::Url::parse(trimmed)
        .map_err(|e| Error::invalid_input(format!("gcs: invalid endpoint_url {u:?}: {e}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(Error::invalid_input(format!(
            "gcs: endpoint_url must be http(s)://host[:port], got {u:?}"
        )));
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsfast_core::Value;

    fn parse(pairs: &[(&str, Value)], env: &[(&str, &str)]) -> Result<GcsOptions> {
        let opts = pairs.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect();
        GcsOptions::parse_with_env(opts, GcsEnv::from_pairs(env.iter().copied()))
    }

    #[test]
    fn defaults() {
        let o = parse(&[("token", Value::from("anon"))], &[]).unwrap();
        assert_eq!(o.project.as_deref(), Some(""));
        assert_eq!(o.access, "full_control");
        assert_eq!(o.consistency, Consistency::None);
        assert_eq!(o.requester_pays, RequesterPays::Off);
        assert!(!o.version_aware);
        assert_eq!(o.location().unwrap(), "https://storage.googleapis.com");
        assert_eq!(o.upload_chunk_size, 16 << 20);
        assert_eq!(o.http.max_retries, 5);
    }

    #[test]
    fn all_gcsfs_options() {
        let mut sk = std::collections::BTreeMap::new();
        sk.insert("trust_env".to_owned(), Value::Bool(false));
        let o = parse(
            &[
                ("project", Value::from("p")),
                ("access", Value::from("read_only")),
                ("token", Value::from("anon")),
                ("block_size", Value::Int(1 << 20)),
                ("consistency", Value::from("md5")),
                ("cache_timeout", Value::Float(1.0)),
                ("secure_serialize", Value::Bool(true)),
                ("check_connection", Value::Null),
                ("requests_timeout", Value::Int(30)),
                ("requester_pays", Value::from("billing-proj")),
                ("asynchronous", Value::Bool(false)),
                ("session_kwargs", Value::Map(sk)),
                ("loop", Value::Null),
                ("timeout", Value::Int(10)),
                ("endpoint_url", Value::from("http://127.0.0.1:4443/")),
                ("default_location", Value::from("EU")),
                ("version_aware", Value::Bool(true)),
                ("use_listings_cache", Value::Bool(false)),
                ("skip_instance_cache", Value::Bool(true)),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(o.project.as_deref(), Some("p"));
        assert_eq!(o.consistency, Consistency::Md5);
        assert_eq!(o.requester_pays, RequesterPays::Explicit("billing-proj".into()));
        assert_eq!(o.location().unwrap(), "http://127.0.0.1:4443");
        assert_eq!(o.http.total_timeout, Some(Duration::from_secs(30)));
        assert_eq!(o.http.proxy, fsfast_http_transport::ProxyConfig::Disabled);
        assert_eq!(o.upload_chunk_size, 1 << 20);
        assert!(o.version_aware);
    }

    #[test]
    fn strictness() {
        assert!(parse(&[("bogus", Value::Int(1))], &[]).is_err());
        assert!(parse(&[("access", Value::from("admin"))], &[]).is_err());
        assert!(parse(&[("endpoint_url", Value::from("ftp://x"))], &[]).is_err());
        assert!(parse(&[("endpoint_url", Value::from("not a url"))], &[]).is_err());
        let mut sk = std::collections::BTreeMap::new();
        sk.insert("connector".to_owned(), Value::Null);
        sk.insert("bogus".to_owned(), Value::Int(1));
        assert!(parse(&[("session_kwargs", Value::Map(sk))], &[]).is_err());
        assert!(parse(&[("requester_pays", Value::Float(1.5))], &[]).is_err());
    }

    #[test]
    fn endpoints_from_env() {
        let o = parse(&[], &[("STORAGE_EMULATOR_HOST", "localhost:9023")]).unwrap();
        assert_eq!(o.location().unwrap(), "http://localhost:9023");
        let o = parse(&[], &[("STORAGE_EMULATOR_HOST", "default")]).unwrap();
        assert_eq!(o.location().unwrap(), "https://storage.googleapis.com");
        let o = parse(&[], &[("GOOGLE_CLOUD_UNIVERSE_DOMAIN", "example.goog")]).unwrap();
        assert_eq!(o.location().unwrap(), "https://storage.example.goog");
        let o = parse(&[], &[("GCSFS_DEFAULT_PROJECT", "dp")]).unwrap();
        assert_eq!(o.project.as_deref(), Some("dp"));
        // endpoint_url wins over the environment.
        let o = parse(
            &[("endpoint_url", Value::from("https://gcs.example"))],
            &[("STORAGE_EMULATOR_HOST", "localhost:1")],
        )
        .unwrap();
        assert_eq!(o.location().unwrap(), "https://gcs.example");
    }

    #[test]
    fn chunks_and_consistency() {
        assert_eq!(round_chunk(1), CHUNK_GRANULARITY);
        assert_eq!(round_chunk(5 << 20), 5 << 20);
        assert_eq!(round_chunk((5 << 20) + 1000), 5 << 20);
        assert_eq!(round_chunk(1 << 40), MAX_CHUNK);
        assert_eq!(Consistency::parse("weird"), Consistency::None);
        assert_eq!(Consistency::parse("crc32c"), Consistency::Crc32c);
        assert_eq!(Consistency::parse("size"), Consistency::Size);
    }
}
