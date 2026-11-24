//! Client configuration and the `storage_options` parsing shared by every
//! HTTP-based backend.
//!
//! [`HttpConfig`] is plain data. Backends fill it from their reference
//! implementation's option names with the `apply_*` helpers:
//!
//! * [`HttpConfig::apply_client_kwargs`]: keyword arguments of
//!   `aiohttp.ClientSession` (fsspec http `client_kwargs`, gcsfs
//!   `session_kwargs`).
//! * [`HttpConfig::apply_request_kwargs`]: per-request keyword arguments of
//!   `aiohttp.ClientSession.request` (fsspec http passes any extra
//!   `storage_options` to every request: `headers`, `auth`, `ssl`, ...).
//! * [`HttpConfig::apply_fsfast_options`]: fsfast tuning knobs that have no
//!   aiohttp equivalent (`max_retries`, `http2`, `ca_bundle`, ...).
//!
//! Python objects that cannot cross the boundary as plain data are expected
//! in a plain form: `aiohttp.BasicAuth` as a `[login, password(, encoding)]`
//! list (that is what the namedtuple converts to) or a `{"login",
//! "password", "encoding"}` dict, `aiohttp.ClientTimeout` as a number
//! (total seconds) or a `{"total", "connect", "sock_read", "sock_connect"}`
//! dict.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use fsfast_core::{Error, OptionReader, Result, Value};
use reqwest::header::{AUTHORIZATION, COOKIE, HeaderMap, HeaderName, HeaderValue};

/// Default TCP connect timeout (aiohttp's default `sock_connect`).
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default idle timeout ([`HttpConfig::read_timeout`]). aiohttp has no
/// idle timeout but a 300 s *total* timeout, which kills large transfers;
/// fsfast bounds stalls instead of transfer time.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(120);

/// Default number of retries after the first attempt.
pub const DEFAULT_MAX_RETRIES: u32 = 4;

/// Default redirect limit (aiohttp's `max_redirects`).
pub const DEFAULT_MAX_REDIRECTS: usize = 10;

/// Default upper bound of concurrent requests per host.
pub const DEFAULT_MAX_CONNECTIONS_PER_HOST: usize = 64;

/// Default starting point of the per-host adaptive concurrency limit.
pub const DEFAULT_INITIAL_CONNECTIONS_PER_HOST: usize = 16;

/// Text encoding of the `login:password` pair of HTTP Basic credentials
/// (aiohttp `BasicAuth(encoding=...)`, default `latin1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthEncoding {
    /// ISO-8859-1 (aiohttp's default). Characters above U+00FF are an error.
    #[default]
    Latin1,
    /// UTF-8.
    Utf8,
}

/// HTTP Basic credentials (aiohttp `BasicAuth`). `Debug` hides the password.
#[derive(Clone, PartialEq, Eq)]
pub struct BasicAuth {
    /// User name; may not contain `:`.
    pub login: String,
    /// Password.
    pub password: String,
    /// How the pair is encoded before base64.
    pub encoding: AuthEncoding,
}

impl fmt::Debug for BasicAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicAuth")
            .field("login", &self.login)
            .field("password", &"<redacted>")
            .field("encoding", &self.encoding)
            .finish()
    }
}

impl BasicAuth {
    /// Credentials with aiohttp's default (latin-1) encoding.
    pub fn new(login: impl Into<String>, password: impl Into<String>) -> Self {
        BasicAuth {
            login: login.into(),
            password: password.into(),
            encoding: AuthEncoding::Latin1,
        }
    }

    /// The `Basic ...` header value, marked sensitive so it is never logged.
    pub fn header_value(&self) -> Result<HeaderValue> {
        if self.login.contains(':') {
            return Err(Error::invalid_input(
                "basic auth: a ':' is not allowed in the login",
            ));
        }
        let pair = format!("{}:{}", self.login, self.password);
        let raw: Vec<u8> = match self.encoding {
            AuthEncoding::Utf8 => pair.into_bytes(),
            AuthEncoding::Latin1 => pair
                .chars()
                .map(|c| {
                    u8::try_from(u32::from(c)).map_err(|_| {
                        Error::invalid_input(format!(
                            "basic auth: {c:?} cannot be encoded as latin1 (use encoding='utf-8')"
                        ))
                    })
                })
                .collect::<Result<_>>()?,
        };
        let mut v = HeaderValue::try_from(format!("Basic {}", base64_encode(&raw)))
            .map_err(|e| Error::invalid_input(format!("basic auth: {e}")))?;
        v.set_sensitive(true);
        Ok(v)
    }
}

/// Which proxy requests go through.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ProxyConfig {
    /// `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` with `NO_PROXY` exclusions
    /// (aiohttp `trust_env=True`). The default: in many environments direct
    /// outbound connections are blocked and local services must bypass the
    /// proxy through `NO_PROXY`.
    #[default]
    Environment,
    /// Connect directly, ignoring the environment (aiohttp
    /// `trust_env=False` without a `proxy`).
    Disabled,
    /// Send every request through this proxy (aiohttp `proxy=`), ignoring
    /// the environment.
    Url {
        /// Proxy URL, e.g. `http://proxy:3128`.
        url: String,
        /// aiohttp `proxy_auth`.
        auth: Option<BasicAuth>,
    },
}

/// Everything needed to build an [`HttpClient`](crate::HttpClient).
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// TCP (and TLS) connect timeout. `None`: no limit.
    pub connect_timeout: Option<Duration>,
    /// Idle timeout: the longest a request may go without progress (request
    /// body handed to the connection, response head, response body data).
    /// It never limits how long a steadily progressing transfer takes.
    /// `None`: no limit.
    pub read_timeout: Option<Duration>,
    /// Limit on a whole request including its body. `None`: no limit.
    pub total_timeout: Option<Duration>,
    /// How long idle pooled connections are kept.
    pub pool_idle_timeout: Option<Duration>,
    /// Idle connections kept per host.
    pub pool_max_idle_per_host: usize,
    /// Upper bound of the per-host adaptive concurrency limit.
    pub max_connections_per_host: usize,
    /// Starting point of the per-host adaptive concurrency limit.
    pub initial_connections_per_host: usize,
    /// Offer HTTP/2 through TLS ALPN. `false` forces HTTP/1.1.
    pub http2: bool,
    /// Speak HTTP/2 without negotiation (h2c), for servers known to support it.
    pub http2_prior_knowledge: bool,
    /// Verify server certificates (aiohttp `ssl=False` turns this off).
    pub tls_verify: bool,
    /// Extra trusted root certificates (PEM bundle), added to the OS store.
    pub ca_bundle: Option<PathBuf>,
    /// Headers sent with every request.
    pub headers: HeaderMap,
    /// HTTP Basic credentials sent with every request (aiohttp `auth`).
    /// Dropped on redirects to another origin.
    pub auth: Option<BasicAuth>,
    /// Cookies sent with every request (aiohttp `cookies`), as name/value pairs.
    pub cookies: Vec<(String, String)>,
    /// Query parameters appended to every request URL (aiohttp `params`).
    pub query: Vec<(String, String)>,
    /// `User-Agent` header. `None` sends `fsfast/<version>`.
    pub user_agent: Option<String>,
    /// Proxy selection.
    pub proxy: ProxyConfig,
    /// Retries after the first attempt for retry-safe requests.
    pub max_retries: u32,
    /// Backoff cap before the first retry (full jitter).
    pub retry_base_delay: Duration,
    /// Upper bound of any single backoff (also caps `Retry-After`).
    pub retry_max_delay: Duration,
    /// Follow at most this many redirects. `None`: do not follow (3xx
    /// responses are returned to the caller).
    pub max_redirects: Option<usize>,
    /// Resolve host names to all their addresses and rotate the list on every
    /// lookup, so new connections spread over the server's IPs (the AWS CRT
    /// technique for S3-style endpoints with many addresses).
    pub rotate_dns: bool,
    /// Let latency inflation (not only throttling) shrink the per-host
    /// concurrency limit. Off by default: request sizes vary too much
    /// (HEAD vs multi-MiB GET) for latency to be a reliable congestion signal.
    pub latency_aimd: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        HttpConfig {
            connect_timeout: Some(DEFAULT_CONNECT_TIMEOUT),
            read_timeout: Some(DEFAULT_READ_TIMEOUT),
            total_timeout: None,
            pool_idle_timeout: Some(Duration::from_secs(90)),
            pool_max_idle_per_host: DEFAULT_MAX_CONNECTIONS_PER_HOST,
            max_connections_per_host: DEFAULT_MAX_CONNECTIONS_PER_HOST,
            initial_connections_per_host: DEFAULT_INITIAL_CONNECTIONS_PER_HOST,
            http2: true,
            http2_prior_knowledge: false,
            tls_verify: true,
            ca_bundle: None,
            headers: HeaderMap::new(),
            auth: None,
            cookies: Vec::new(),
            query: Vec::new(),
            user_agent: None,
            proxy: ProxyConfig::Environment,
            max_retries: DEFAULT_MAX_RETRIES,
            retry_base_delay: Duration::from_millis(100),
            retry_max_delay: Duration::from_secs(20),
            max_redirects: Some(DEFAULT_MAX_REDIRECTS),
            rotate_dns: false,
            latency_aimd: false,
        }
    }
}

impl HttpConfig {
    /// Read fsspec http's option set from `r`: `client_kwargs` (a nested
    /// dict of `aiohttp.ClientSession` keywords, which must all be known),
    /// then the per-request aiohttp keywords and fsfast's tuning options at
    /// the top level. Other keys of `r` are left for the caller (who calls
    /// `finish()`).
    pub fn from_options(r: &mut OptionReader) -> Result<Self> {
        let mut cfg = HttpConfig::default();
        if let Some(mut ck) = r.nested("client_kwargs")? {
            cfg.apply_client_kwargs(&mut ck)?;
            ck.finish()
                .map_err(|e| Error::invalid_input(format!("client_kwargs: {}", e.message())))?;
        }
        cfg.apply_request_kwargs(r)?;
        cfg.apply_fsfast_options(r)?;
        Ok(cfg)
    }

    /// Set (or replace) a default header.
    pub fn set_header(&mut self, name: &str, value: &str) -> Result<()> {
        let (n, v) = parse_header(name, value)?;
        self.headers.insert(n, v);
        Ok(())
    }

    /// Set a default header only if none with that name is configured.
    pub fn set_header_if_absent(&mut self, name: &str, value: &str) -> Result<()> {
        let (n, v) = parse_header(name, value)?;
        self.headers.entry(n).or_insert(v);
        Ok(())
    }

    /// Read `aiohttp.ClientSession` keyword arguments (fsspec http
    /// `client_kwargs`).
    ///
    /// Supported: `headers`, `auth`, `timeout`, `read_timeout`,
    /// `conn_timeout`, `trust_env`, `cookies`, `proxy`, `proxy_auth`.
    /// Accepted without effect (they do not change what fsfast sends or
    /// returns): `auto_decompress` (fsfast never decompresses, so sizes and
    /// ranges refer to the bytes on the wire), `raise_for_status` (fsfast
    /// always checks statuses), `requote_redirect_url`, `read_bufsize`,
    /// `max_line_size`, `max_field_size`, `max_headers`, `connector_owner`,
    /// `skip_auto_headers`, `ssl_shutdown_timeout`. Anything else (e.g.
    /// `connector`, `cookie_jar`, `base_url`) is left unconsumed, so the
    /// caller's `finish()` reports it.
    pub fn apply_client_kwargs(&mut self, r: &mut OptionReader) -> Result<()> {
        self.read_headers(r)?;
        self.read_auth(r, "auth")?;
        self.read_timeout_option(r)?;
        if let Some(d) = r.duration_secs("read_timeout")? {
            self.read_timeout = Some(d);
        }
        if let Some(d) = r.duration_secs("conn_timeout")? {
            self.connect_timeout = Some(d);
        }
        if let Some(trust) = r.bool("trust_env")?
            && self.proxy == ProxyConfig::Environment
            && !trust
        {
            self.proxy = ProxyConfig::Disabled;
        }
        self.read_cookies(r)?;
        self.read_proxy(r)?;
        r.accept_ignored(&[
            "auto_decompress",
            "raise_for_status",
            "requote_redirect_url",
            "read_bufsize",
            "max_line_size",
            "max_field_size",
            "max_headers",
            "connector_owner",
            "skip_auto_headers",
            "ssl_shutdown_timeout",
        ]);
        Ok(())
    }

    /// Read `aiohttp.ClientSession.request` keyword arguments that fsspec
    /// http forwards from its `storage_options` to every request.
    ///
    /// Supported: `headers`, `auth`, `timeout`, `ssl` / `verify_ssl`
    /// (booleans only), `proxy`, `proxy_auth`, `allow_redirects`,
    /// `max_redirects`, `cookies`, `params`. Accepted without effect:
    /// `raise_for_status`, `read_until_eof`, `read_bufsize`,
    /// `auto_decompress`, `max_line_size`, `max_field_size`, `max_headers`,
    /// `skip_auto_headers`.
    pub fn apply_request_kwargs(&mut self, r: &mut OptionReader) -> Result<()> {
        self.read_headers(r)?;
        self.read_auth(r, "auth")?;
        self.read_timeout_option(r)?;
        for key in ["ssl", "verify_ssl"] {
            match r.value(key) {
                None => {}
                Some(Value::Bool(b)) => self.tls_verify = b,
                Some(v) => {
                    return Err(Error::invalid_input(format!(
                        "option '{key}' must be a boolean, got {}; custom SSL contexts are not \
                         supported, use 'ca_bundle' for extra trusted certificates",
                        v.type_name()
                    )));
                }
            }
        }
        self.read_proxy(r)?;
        let allow = r.bool("allow_redirects")?;
        let max = r.usize("max_redirects")?;
        match (allow, max) {
            (Some(false), _) => self.max_redirects = None,
            (_, Some(n)) => self.max_redirects = Some(n),
            _ => {}
        }
        self.read_cookies(r)?;
        if let Some(v) = r.value("params") {
            for (k, v) in pairs("params", v)? {
                for item in scalar_strings("params", v)? {
                    self.query.push((k.clone(), item));
                }
            }
        }
        r.accept_ignored(&[
            "raise_for_status",
            "read_until_eof",
            "read_bufsize",
            "auto_decompress",
            "max_line_size",
            "max_field_size",
            "max_headers",
            "skip_auto_headers",
        ]);
        Ok(())
    }

    /// Read fsfast's own tuning options (no aiohttp equivalent):
    ///
    /// | option | meaning |
    /// |---|---|
    /// | `connect_timeout`, `read_timeout`, `total_timeout` | seconds |
    /// | `max_retries` | retries after the first attempt (default 4) |
    /// | `limit_per_host` | max concurrent requests per host (0 = 1024) |
    /// | `http2` | offer HTTP/2 via ALPN (default true) |
    /// | `ca_bundle` | PEM file with extra trusted roots |
    /// | `user_agent` | `User-Agent` header |
    /// | `rotate_dns` | spread connections over all resolved IPs |
    pub fn apply_fsfast_options(&mut self, r: &mut OptionReader) -> Result<()> {
        if let Some(d) = r.duration_secs("connect_timeout")? {
            self.connect_timeout = Some(d);
        }
        if let Some(d) = r.duration_secs("read_timeout")? {
            self.read_timeout = Some(d);
        }
        if let Some(d) = r.duration_secs("total_timeout")? {
            self.total_timeout = Some(d);
        }
        if let Some(n) = r.u64("max_retries")? {
            self.max_retries = u32::try_from(n).unwrap_or(u32::MAX);
        }
        if let Some(n) = r.usize("limit_per_host")? {
            let n = if n == 0 { 1024 } else { n };
            self.max_connections_per_host = n;
            self.pool_max_idle_per_host = n;
            self.initial_connections_per_host = self.initial_connections_per_host.min(n);
        }
        if let Some(b) = r.bool("http2")? {
            self.http2 = b;
        }
        if let Some(p) = r.string("ca_bundle")? {
            self.ca_bundle = Some(PathBuf::from(p));
        }
        if let Some(ua) = r.string("user_agent")? {
            self.user_agent = Some(ua);
        }
        if let Some(b) = r.bool("rotate_dns")? {
            self.rotate_dns = b;
        }
        Ok(())
    }

    /// Check for contradictory settings (aiohttp refuses an `Authorization`
    /// header combined with `auth`).
    pub fn validate(&self) -> Result<()> {
        if self.auth.is_some() && self.headers.contains_key(AUTHORIZATION) {
            return Err(Error::invalid_input(
                "cannot combine an Authorization header with the 'auth' option",
            ));
        }
        if self.max_connections_per_host == 0 {
            return Err(Error::invalid_input("max_connections_per_host must be > 0"));
        }
        Ok(())
    }

    /// The default headers to install on the client: `headers`, plus
    /// `Authorization` from `auth` and `Cookie` from `cookies`.
    pub fn effective_headers(&self) -> Result<HeaderMap> {
        let mut h = self.headers.clone();
        if let Some(auth) = &self.auth {
            h.insert(AUTHORIZATION, auth.header_value()?);
        }
        if !self.cookies.is_empty() {
            let mut s = String::new();
            for (k, v) in &self.cookies {
                if !s.is_empty() {
                    s.push_str("; ");
                }
                s.push_str(k);
                s.push('=');
                s.push_str(v);
            }
            let mut v = HeaderValue::try_from(s)
                .map_err(|e| Error::invalid_input(format!("cookies: {e}")))?;
            v.set_sensitive(true);
            h.insert(COOKIE, v);
        }
        Ok(h)
    }

    fn read_headers(&mut self, r: &mut OptionReader) -> Result<()> {
        if let Some(v) = r.value("headers") {
            for (k, v) in pairs("headers", v)? {
                let Value::Str(s) = v else {
                    return Err(Error::invalid_input(format!(
                        "option 'headers': value of {k:?} must be a string, got {}",
                        v.type_name()
                    )));
                };
                self.set_header(&k, &s)?;
            }
        }
        Ok(())
    }

    fn read_auth(&mut self, r: &mut OptionReader, key: &str) -> Result<()> {
        if let Some(v) = r.value(key) {
            self.auth = Some(parse_basic_auth(key, v)?);
        }
        Ok(())
    }

    fn read_cookies(&mut self, r: &mut OptionReader) -> Result<()> {
        if let Some(v) = r.value("cookies") {
            for (k, v) in pairs("cookies", v)? {
                let Value::Str(s) = v else {
                    return Err(Error::invalid_input(format!(
                        "option 'cookies': value of {k:?} must be a string, got {}",
                        v.type_name()
                    )));
                };
                self.cookies.retain(|(n, _)| *n != k);
                self.cookies.push((k, s));
            }
        }
        Ok(())
    }

    fn read_proxy(&mut self, r: &mut OptionReader) -> Result<()> {
        let url = r.string("proxy")?;
        let auth = match r.value("proxy_auth") {
            Some(v) => Some(parse_basic_auth("proxy_auth", v)?),
            None => None,
        };
        match (url, auth) {
            (Some(url), auth) => self.proxy = ProxyConfig::Url { url, auth },
            (None, Some(a)) => match &mut self.proxy {
                ProxyConfig::Url { auth, .. } => *auth = Some(a),
                _ => {
                    return Err(Error::invalid_input("option 'proxy_auth' requires 'proxy'"));
                }
            },
            (None, None) => {}
        }
        Ok(())
    }

    fn read_timeout_option(&mut self, r: &mut OptionReader) -> Result<()> {
        match r.value("timeout") {
            None => Ok(()),
            Some(Value::Map(m)) => self.apply_client_timeout(&m),
            Some(v) => match v.as_f64() {
                Some(s) if s.is_finite() && s >= 0.0 => {
                    self.total_timeout = Some(Duration::from_secs_f64(s));
                    Ok(())
                }
                _ => Err(Error::invalid_input(format!(
                    "option 'timeout' must be a number of seconds or a dict of \
                     aiohttp.ClientTimeout fields, got {}",
                    v.type_name()
                ))),
            },
        }
    }

    /// `aiohttp.ClientTimeout` as a dict: a field set to `None` disables that
    /// timeout (as in aiohttp), an absent field keeps the current value.
    fn apply_client_timeout(&mut self, m: &BTreeMap<String, Value>) -> Result<()> {
        let field = |k: &str| -> Result<Option<Option<Duration>>> {
            match m.get(k) {
                None => Ok(None),
                Some(Value::Null) => Ok(Some(None)),
                Some(v) => match v.as_f64() {
                    Some(s) if s.is_finite() && s >= 0.0 => {
                        Ok(Some(Some(Duration::from_secs_f64(s))))
                    }
                    _ => Err(Error::invalid_input(format!(
                        "option 'timeout': field '{k}' must be a number of seconds or None"
                    ))),
                },
            }
        };
        for k in m.keys() {
            if !matches!(
                k.as_str(),
                "total" | "connect" | "sock_read" | "sock_connect" | "ceil_threshold"
            ) {
                return Err(Error::invalid_input(format!(
                    "option 'timeout': unknown ClientTimeout field '{k}'"
                )));
            }
        }
        if let Some(t) = field("total")? {
            self.total_timeout = t;
        }
        // aiohttp's `connect` also covers waiting for a pooled connection;
        // `sock_connect` is the TCP connect itself, the closer match.
        if let Some(t) = field("connect")? {
            self.connect_timeout = t;
        }
        if let Some(t) = field("sock_connect")? {
            self.connect_timeout = t;
        }
        if let Some(t) = field("sock_read")? {
            self.read_timeout = t;
        }
        Ok(())
    }
}

fn parse_header(name: &str, value: &str) -> Result<(HeaderName, HeaderValue)> {
    let n = HeaderName::try_from(name)
        .map_err(|e| Error::invalid_input(format!("invalid header name {name:?}: {e}")))?;
    let v = HeaderValue::try_from(value)
        .map_err(|e| Error::invalid_input(format!("invalid value for header {name:?}: {e}")))?;
    Ok((n, v))
}

/// A mapping given as a dict or as a list of `[key, value]` pairs.
fn pairs(key: &str, v: Value) -> Result<Vec<(String, Value)>> {
    match v {
        Value::Map(m) => Ok(m.into_iter().collect()),
        Value::List(items) => items
            .into_iter()
            .map(|item| match item {
                Value::List(mut kv) if kv.len() == 2 => {
                    let v = kv.pop().unwrap_or(Value::Null);
                    match kv.pop() {
                        Some(Value::Str(k)) => Ok((k, v)),
                        _ => Err(Error::invalid_input(format!(
                            "option '{key}': keys must be strings"
                        ))),
                    }
                }
                other => Err(Error::invalid_input(format!(
                    "option '{key}': expected [key, value] pairs, got a {}",
                    other.type_name()
                ))),
            })
            .collect(),
        other => Err(Error::invalid_input(format!(
            "option '{key}' must be a dict, got {}",
            other.type_name()
        ))),
    }
}

/// aiohttp `params` values: strings, numbers, or sequences of those.
fn scalar_strings(key: &str, v: Value) -> Result<Vec<String>> {
    match v {
        Value::Str(s) => Ok(vec![s]),
        Value::Int(i) => Ok(vec![i.to_string()]),
        Value::Float(f) => Ok(vec![python_float_repr(f)]),
        Value::List(items) => items
            .into_iter()
            .map(|i| scalar_strings(key, i).map(|mut v| v.remove(0)))
            .collect(),
        other => Err(Error::invalid_input(format!(
            "option '{key}': values must be str, int or float, got {}",
            other.type_name()
        ))),
    }
}

/// `str(float)` for the common cases (`1.0`, `0.5`, `1e+20`).
fn python_float_repr(f: f64) -> String {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e16 {
        format!("{f:.1}")
    } else {
        format!("{f}")
    }
}

fn parse_basic_auth(key: &str, v: Value) -> Result<BasicAuth> {
    let bad = || {
        Error::invalid_input(format!(
            "option '{key}' must be [login, password(, encoding)] or a dict with \
             'login', 'password' and optional 'encoding'"
        ))
    };
    let (login, password, encoding) = match v {
        Value::List(items) if (2..=3).contains(&items.len()) => {
            let mut it = items.into_iter();
            let login = it.next().and_then(|v| v.as_str().map(str::to_owned));
            let password = it.next().and_then(|v| v.as_str().map(str::to_owned));
            let encoding = it.next().and_then(|v| v.as_str().map(str::to_owned));
            (login.ok_or_else(bad)?, password.ok_or_else(bad)?, encoding)
        }
        Value::Map(m) => {
            let get = |k: &str| m.get(k).and_then(|v| v.as_str().map(str::to_owned));
            for k in m.keys() {
                if !matches!(k.as_str(), "login" | "password" | "encoding") {
                    return Err(bad());
                }
            }
            (
                get("login").ok_or_else(bad)?,
                get("password").unwrap_or_default(),
                get("encoding"),
            )
        }
        _ => return Err(bad()),
    };
    let encoding = match encoding.as_deref().map(str::to_ascii_lowercase).as_deref() {
        None | Some("latin1" | "latin-1" | "latin_1" | "iso-8859-1" | "iso8859-1") => {
            AuthEncoding::Latin1
        }
        Some("utf-8" | "utf8" | "utf_8") => AuthEncoding::Utf8,
        Some(other) => {
            return Err(Error::invalid_input(format!(
                "option '{key}': unsupported encoding {other:?} (use 'latin1' or 'utf-8')"
            )));
        }
    };
    Ok(BasicAuth {
        login,
        password,
        encoding,
    })
}

/// Standard base64 with padding (RFC 4648 §4).
pub(crate) fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsfast_core::Options;

    fn reader(pairs: &[(&str, Value)]) -> OptionReader {
        let opts: Options = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect();
        OptionReader::new("http", opts)
    }

    fn map(pairs: &[(&str, Value)]) -> Value {
        Value::Map(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        )
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        for (i, o) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(i.as_bytes()), o);
        }
    }

    #[test]
    fn basic_auth_header_like_aiohttp() {
        // aiohttp.BasicAuth("user", "päss").encode() (latin1 by default)
        let a = BasicAuth::new("user", "päss");
        assert_eq!(a.header_value().unwrap(), "Basic dXNlcjpw5HNz");
        let a = BasicAuth {
            encoding: AuthEncoding::Utf8,
            ..a
        };
        assert_eq!(a.header_value().unwrap(), "Basic dXNlcjpww6Rzcw==");
        assert!(a.header_value().unwrap().is_sensitive());
        assert!(BasicAuth::new("a:b", "c").header_value().is_err());
        assert!(BasicAuth::new("a", "\u{20ac}").header_value().is_err());
        assert!(!format!("{a:?}").contains("päss"));
    }

    #[test]
    fn client_kwargs_and_request_kwargs() {
        let mut cfg = HttpConfig::default();
        let mut r = reader(&[
            ("headers", map(&[("X-A", "1".into()), ("X-B", "2".into())])),
            (
                "auth",
                Value::List(vec!["u".into(), "p".into(), "latin1".into()]),
            ),
            (
                "timeout",
                map(&[
                    ("total", Value::Null),
                    ("sock_connect", Value::Float(2.5)),
                    ("sock_read", Value::Int(7)),
                    ("connect", Value::Null),
                    ("ceil_threshold", Value::Int(5)),
                ]),
            ),
            ("trust_env", Value::Bool(false)),
            ("auto_decompress", Value::Bool(true)),
        ]);
        cfg.apply_client_kwargs(&mut r).unwrap();
        r.finish().unwrap();
        assert_eq!(cfg.headers["x-a"], "1");
        assert_eq!(cfg.auth.as_ref().unwrap().login, "u");
        assert_eq!(cfg.total_timeout, None);
        assert_eq!(cfg.connect_timeout, Some(Duration::from_millis(2500)));
        assert_eq!(cfg.read_timeout, Some(Duration::from_secs(7)));
        assert_eq!(cfg.proxy, ProxyConfig::Disabled);

        let mut r = reader(&[
            ("headers", map(&[("x-b", "3".into())])),
            ("ssl", Value::Bool(false)),
            ("allow_redirects", Value::Bool(true)),
            ("max_redirects", Value::Int(3)),
            (
                "params",
                map(&[
                    ("q", "a b".into()),
                    ("n", Value::List(vec![Value::Int(1), Value::Float(2.0)])),
                ]),
            ),
            ("cookies", map(&[("sid", "abc".into())])),
            ("timeout", Value::Int(9)),
            ("proxy", "http://proxy:3128".into()),
            ("proxy_auth", Value::List(vec!["pu".into(), "pp".into()])),
        ]);
        cfg.apply_request_kwargs(&mut r).unwrap();
        r.finish().unwrap();
        assert_eq!(cfg.headers["x-b"], "3");
        assert!(!cfg.tls_verify);
        assert_eq!(cfg.max_redirects, Some(3));
        assert_eq!(
            cfg.query,
            vec![
                ("n".to_owned(), "1".to_owned()),
                ("n".to_owned(), "2.0".to_owned()),
                ("q".to_owned(), "a b".to_owned())
            ]
        );
        assert_eq!(cfg.total_timeout, Some(Duration::from_secs(9)));
        match &cfg.proxy {
            ProxyConfig::Url { url, auth } => {
                assert_eq!(url, "http://proxy:3128");
                assert_eq!(auth.as_ref().unwrap().login, "pu");
            }
            other => panic!("{other:?}"),
        }
        let h = cfg.effective_headers().unwrap();
        assert_eq!(h[COOKIE], "sid=abc");
        assert!(h[AUTHORIZATION].to_str().unwrap().starts_with("Basic "));
    }

    #[test]
    fn from_options_reads_all_three_sets() {
        let mut r = reader(&[
            (
                "client_kwargs",
                map(&[("headers", map(&[("x-s", "1".into())]))]),
            ),
            ("headers", map(&[("x-r", "2".into())])),
            ("max_retries", Value::Int(2)),
            ("simple_links", Value::Bool(true)),
        ]);
        let cfg = HttpConfig::from_options(&mut r).unwrap();
        assert_eq!(cfg.headers["x-s"], "1");
        assert_eq!(cfg.headers["x-r"], "2");
        assert_eq!(cfg.max_retries, 2);
        assert_eq!(r.remaining(), vec!["simple_links".to_owned()]);
        let mut r = reader(&[(
            "client_kwargs",
            map(&[("connector", Value::Null), ("bogus", Value::Int(1))]),
        )]);
        let e = HttpConfig::from_options(&mut r).unwrap_err();
        assert!(e.message().contains("client_kwargs"), "{e}");
    }

    #[test]
    fn redirects_can_be_disabled() {
        let mut cfg = HttpConfig::default();
        let mut r = reader(&[("allow_redirects", Value::Bool(false))]);
        cfg.apply_request_kwargs(&mut r).unwrap();
        assert_eq!(cfg.max_redirects, None);
    }

    #[test]
    fn invalid_options_are_errors() {
        let bad: Vec<(&str, Value)> = vec![
            ("headers", Value::Int(1)),
            ("headers", map(&[("bad name", "x".into())])),
            ("headers", map(&[("x", "bad\nvalue".into())])),
            ("auth", "user:pass".into()),
            ("timeout", "soon".into()),
            ("timeout", map(&[("whenever", Value::Int(1))])),
            ("ssl", "context".into()),
            ("proxy_auth", Value::List(vec!["a".into(), "b".into()])),
            ("params", map(&[("x", map(&[]))])),
        ];
        for (k, v) in bad {
            let mut cfg = HttpConfig::default();
            let mut r = reader(&[(k, v.clone())]);
            assert!(
                cfg.apply_request_kwargs(&mut r).is_err(),
                "{k} = {v:?} should be rejected"
            );
        }
        let mut cfg = HttpConfig::default();
        cfg.set_header("Authorization", "Bearer x").unwrap();
        cfg.auth = Some(BasicAuth::new("a", "b"));
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn fsfast_options() {
        let mut cfg = HttpConfig::default();
        let mut r = reader(&[
            ("max_retries", Value::Int(0)),
            ("limit_per_host", Value::Int(4)),
            ("http2", Value::Bool(false)),
            ("ca_bundle", "/tmp/ca.pem".into()),
            ("user_agent", "me/1".into()),
            ("rotate_dns", Value::Bool(true)),
            ("connect_timeout", Value::Int(1)),
            ("read_timeout", Value::Int(2)),
            ("total_timeout", Value::Int(3)),
        ]);
        cfg.apply_fsfast_options(&mut r).unwrap();
        r.finish().unwrap();
        assert_eq!(cfg.max_retries, 0);
        assert_eq!(cfg.max_connections_per_host, 4);
        assert_eq!(cfg.initial_connections_per_host, 4);
        assert!(!cfg.http2);
        assert!(cfg.rotate_dns);
        assert_eq!(cfg.total_timeout, Some(Duration::from_secs(3)));
    }

    #[test]
    fn unknown_client_kwargs_stay_unconsumed() {
        let mut cfg = HttpConfig::default();
        let mut r = reader(&[("connector", "x".into()), ("base_url", "y".into())]);
        cfg.apply_client_kwargs(&mut r).unwrap();
        let err = r.finish().unwrap_err();
        assert!(err.to_string().contains("connector"), "{err}");
    }
}
