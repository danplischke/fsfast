//! Configuration (`storage_options`) and fsspec path handling.
//!
//! Option names follow fsspec's `SMBFileSystem.__init__`
//! (`fsspec/implementations/smb.py`) so `storage_options` dicts carry over
//! unchanged; fsfast-only tuning knobs have descriptive names of their own
//! (see [`SmbConfig`]).

use std::fmt;
use std::time::Duration;

use fsfast_core::{Error, OptionReader, Options, Result, Value};
use fsfast_smb_proto::Dialect;
use fsfast_smb_proto::fscc::ShareAccess;

/// Options accepted by `AbstractFileSystem.__init__` (and keys that
/// `SMBFileSystem._get_kwargs_from_urls` leaves in the kwargs) that have no
/// effect here: instance and listing caches live in the Python layer.
const IGNORED_BASE_OPTIONS: &[&str] = &[
    "skip_instance_cache",
    "use_listings_cache",
    "listings_expiry_time",
    "max_paths",
    "asynchronous",
    "loop",
    "url_query",
    "url_fragment",
];

/// Default SMB port.
pub const DEFAULT_PORT: u16 = 445;

/// Typed configuration of an [`SmbFileSystem`](crate::SmbFileSystem).
#[derive(Clone)]
pub struct SmbConfig {
    /// `host`: server name or IP address (IPv6 literals may be bracketed).
    pub host: String,
    /// `port`: TCP port; `None` means 445 (fsspec's `_port`).
    pub port: Option<u16>,
    /// `username`: `user`, `DOMAIN\user`, `user@REALM` or fsspec's URL form
    /// `workgroup;user`. `None` authenticates anonymously.
    pub username: Option<String>,
    /// `password`.
    pub password: Option<String>,
    /// `timeout`: connection timeout (TCP connect, negotiate and session
    /// setup), seconds. Default 60.
    pub timeout: Duration,
    /// `encrypt`: `Some(true)` encrypts every request (fails when the server
    /// cannot encrypt); `None`/`Some(false)` encrypt only where the server
    /// requires it (session or share flag).
    pub encrypt: Option<bool>,
    /// `share_access`: share mode for file handles opened by `open_read`,
    /// `open_write`, `cat_file` and `pipe_file` (`None` = exclusive, like
    /// smbclient's default; letters `r`, `w`, `d`).
    pub share_access: Option<String>,
    /// `register_session_retries`: connection attempts after the first one
    /// (authentication failures are never retried). Negative values disable
    /// the eager connection of [`SmbFileSystem::connect`](crate::SmbFileSystem::connect).
    pub register_session_retries: i64,
    /// `register_session_retry_wait`: seconds, see fsspec's docstring.
    pub register_session_retry_wait: f64,
    /// `register_session_retry_factor`: base of the exponential wait.
    pub register_session_retry_factor: f64,
    /// `auto_mkdir`: create the parent directory of every write target.
    pub auto_mkdir: bool,
    /// `temppath`: directory (below the share) for fsspec's non-autocommit
    /// writes; stored for the Python layer.
    pub temppath: String,

    // ---- fsfast extensions ---------------------------------------------
    /// `require_signing` (default `true`, like smbprotocol): sign every
    /// request and reject unsigned responses even when the server does not
    /// require signing. Encrypted traffic is authenticated by AES-GCM/CCM
    /// instead. Guest and anonymous sessions cannot sign and are refused
    /// while this is set.
    pub require_signing: bool,
    /// `min_dialect` / `max_dialect`: dialect range offered in NEGOTIATE
    /// (`"2.0.2"`, `"2.1"`, `"3.0"`, `"3.0.2"`, `"3.1.1"`). Default: all.
    pub min_dialect: Dialect,
    /// See [`SmbConfig::min_dialect`].
    pub max_dialect: Dialect,
    /// `max_credits`: credit window the client asks the server for
    /// (default 2048, i.e. up to 128 MiB of I/O in flight per connection).
    pub max_credits: u16,
    /// `read_chunk_size`: bytes per READ request (default 1 MiB; clamped to
    /// the server's `MaxReadSize`).
    pub read_chunk_size: usize,
    /// `write_chunk_size`: bytes per WRITE request (default 1 MiB; clamped to
    /// the server's `MaxWriteSize`).
    pub write_chunk_size: usize,
    /// `max_inflight`: READ/WRITE requests in flight per handle operation
    /// (default 16).
    pub max_inflight: usize,
    /// `connections`: TCP connections (each with its own session) the
    /// filesystem spreads operations over (default 1). Samba serves each
    /// connection with its own process, so several connections let a busy
    /// workload use several server cores.
    pub connections: usize,
    /// `request_timeout`: per-request timeout in seconds until the first
    /// (interim or final) response; `None` (default) relies on the
    /// keepalive to detect dead peers.
    pub request_timeout: Option<Duration>,
    /// `keepalive_interval`: seconds of silence after which an ECHO probes
    /// the connection (default 60; 0 disables). An unanswered probe marks the
    /// connection dead, failing its requests, and the next operation
    /// reconnects.
    pub keepalive_interval: Option<Duration>,
}

impl fmt::Debug for SmbConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmbConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("timeout", &self.timeout)
            .field("encrypt", &self.encrypt)
            .field("share_access", &self.share_access)
            .field("auto_mkdir", &self.auto_mkdir)
            .field("require_signing", &self.require_signing)
            .field("dialects", &(self.min_dialect, self.max_dialect))
            .field("max_credits", &self.max_credits)
            .field("read_chunk_size", &self.read_chunk_size)
            .field("write_chunk_size", &self.write_chunk_size)
            .field("max_inflight", &self.max_inflight)
            .field("connections", &self.connections)
            .finish_non_exhaustive()
    }
}

impl SmbConfig {
    /// A configuration for `host` with fsspec's defaults.
    pub fn new(host: impl Into<String>) -> Self {
        SmbConfig {
            host: host.into(),
            port: None,
            username: None,
            password: None,
            timeout: Duration::from_secs(60),
            encrypt: None,
            share_access: None,
            register_session_retries: 4,
            register_session_retry_wait: 1.0,
            register_session_retry_factor: 10.0,
            auto_mkdir: false,
            temppath: String::new(),
            require_signing: true,
            min_dialect: Dialect::SMB_2_0_2,
            max_dialect: Dialect::SMB_3_1_1,
            max_credits: 2048,
            read_chunk_size: 1 << 20,
            write_chunk_size: 1 << 20,
            max_inflight: 16,
            connections: 1,
            request_timeout: None,
            keepalive_interval: Some(Duration::from_secs(60)),
        }
    }

    /// Builder: credentials.
    pub fn with_credentials(mut self, username: &str, password: &str) -> Self {
        self.username = Some(username.to_owned());
        self.password = Some(password.to_owned());
        self
    }

    /// Builder: port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Parse fsspec `storage_options` (strict: unknown keys are errors).
    pub fn from_options(opts: Options) -> Result<Self> {
        let mut r = OptionReader::new("smb", opts);
        let host = r
            .string("host")?
            .ok_or_else(|| Error::invalid_input("smb: option 'host' is required"))?;
        let mut c = SmbConfig::new(host);
        if let Some(p) = r.u64("port")? {
            c.port = Some(
                u16::try_from(p)
                    .ok()
                    .filter(|p| *p > 0)
                    .ok_or_else(|| Error::invalid_input(format!("smb: invalid port {p}")))?,
            );
        }
        c.username = r.string("username")?;
        c.password = r.string("password")?;
        if let Some(t) = r.duration_secs("timeout")? {
            c.timeout = t;
        }
        c.encrypt = r.bool("encrypt")?;
        c.share_access = r.string("share_access")?;
        if let Some(sa) = &c.share_access {
            parse_share_access(Some(sa), false)?;
        }
        if let Some(n) = r.i64("register_session_retries")? {
            c.register_session_retries = n;
        }
        if let Some(w) = r.f64("register_session_retry_wait")? {
            if !(w >= 0.0 && w.is_finite()) {
                return Err(Error::invalid_input(
                    "register_session_retry_wait must be a non-negative integer",
                ));
            }
            c.register_session_retry_wait = w;
        }
        if let Some(f) = r.f64("register_session_retry_factor")? {
            if !(f >= 1.0 && f.is_finite()) {
                return Err(Error::invalid_input(
                    "register_session_retry_factor must be a positive integer equal to or greater than 1",
                ));
            }
            c.register_session_retry_factor = f;
        }
        if let Some(b) = r.bool("auto_mkdir")? {
            c.auto_mkdir = b;
        }
        if let Some(t) = r.string("temppath")? {
            c.temppath = t;
        }

        // fsfast extensions.
        if let Some(b) = r.bool("require_signing")? {
            c.require_signing = b;
        }
        if let Some(d) = r.string("min_dialect")? {
            c.min_dialect = parse_dialect(&d)?;
        }
        if let Some(d) = r.string("max_dialect")? {
            c.max_dialect = parse_dialect(&d)?;
        }
        if c.min_dialect > c.max_dialect {
            return Err(Error::invalid_input(format!(
                "smb: min_dialect {} is above max_dialect {}",
                c.min_dialect, c.max_dialect
            )));
        }
        if let Some(n) = r.u64("max_credits")? {
            c.max_credits = n.clamp(16, 8192) as u16;
        }
        if let Some(n) = r.usize("read_chunk_size")? {
            c.read_chunk_size = check_chunk("read_chunk_size", n)?;
        }
        if let Some(n) = r.usize("write_chunk_size")? {
            c.write_chunk_size = check_chunk("write_chunk_size", n)?;
        }
        if let Some(n) = r.usize("max_inflight")? {
            c.max_inflight = n.clamp(1, 256);
        }
        if let Some(n) = r.usize("connections")? {
            c.connections = n.clamp(1, 64);
        }
        c.request_timeout = r.duration_secs("request_timeout")?.filter(|d| !d.is_zero());
        if let Some(d) = r.duration_secs("keepalive_interval")? {
            c.keepalive_interval = (!d.is_zero()).then_some(d);
        }
        r.accept_ignored(IGNORED_BASE_OPTIONS);
        r.finish()?;
        Ok(c)
    }

    /// The TCP port (fsspec `_port`).
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_PORT)
    }

    /// Host name as used for the socket (IPv6 brackets removed).
    pub(crate) fn connect_host(&self) -> &str {
        let h = self.host.as_str();
        h.strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(h)
    }

    /// The dialects to offer, lowest first.
    pub(crate) fn dialects(&self) -> Vec<Dialect> {
        Dialect::ALL
            .iter()
            .copied()
            .filter(|d| *d >= self.min_dialect && *d <= self.max_dialect)
            .collect()
    }

    /// Wait before retry `n` (0-based) of the session registration, as
    /// fsspec computes it: `factor ** (n / n_waits - 1) * wait` with
    /// `n_waits = retries - 1` (the last wait equals `wait`).
    pub(crate) fn retry_wait(&self, n: u32) -> Duration {
        let n_waits = self.register_session_retries - 1;
        let w = self.register_session_retry_wait;
        let secs = if n_waits <= 0 {
            // fsspec divides by zero here (retries == 1); use the plain wait.
            w
        } else {
            self.register_session_retry_factor
                .powf(f64::from(n) / n_waits as f64 - 1.0)
                * w
        };
        Duration::from_secs_f64(secs.max(0.0))
    }
}

fn check_chunk(name: &str, n: usize) -> Result<usize> {
    if (4096..=(8 << 20)).contains(&n) {
        Ok(n)
    } else {
        Err(Error::invalid_input(format!(
            "smb: option '{name}' must be between 4096 and 8388608 bytes, got {n}"
        )))
    }
}

/// Parse a dialect name such as `"3.1.1"` (also `"SMB3_11"`-style names and
/// hexadecimal codes like `"0x0311"`).
pub fn parse_dialect(s: &str) -> Result<Dialect> {
    let t = s.trim().to_ascii_lowercase();
    let t = t
        .strip_prefix("smb")
        .map(|r| r.trim_start_matches(['_', ' ']))
        .unwrap_or(&t);
    let d = match t {
        "2.0.2" | "2_02" | "2.02" | "202" | "0x0202" => Dialect::SMB_2_0_2,
        "2.1" | "2_10" | "2.10" | "210" | "0x0210" => Dialect::SMB_2_1,
        "3.0" | "3" | "3_00" | "3.00" | "300" | "0x0300" => Dialect::SMB_3_0,
        "3.0.2" | "3_02" | "3.02" | "302" | "0x0302" => Dialect::SMB_3_0_2,
        "3.1.1" | "3_11" | "3.11" | "311" | "0x0311" => Dialect::SMB_3_1_1,
        _ => {
            return Err(Error::invalid_input(format!(
                "smb: unknown dialect {s:?} (expected 2.0.2, 2.1, 3.0, 3.0.2 or 3.1.1)"
            )));
        }
    };
    Ok(d)
}

/// smbclient's `_parse_share_access`: letters `r`, `w`, `d`; reading always
/// shares read access once any share access is given.
pub(crate) fn parse_share_access(raw: Option<&str>, reading: bool) -> Result<ShareAccess> {
    let mut sa = ShareAccess::empty();
    let Some(raw) = raw.filter(|r| !r.is_empty()) else {
        return Ok(sa);
    };
    for c in raw.chars() {
        sa |= match c {
            'r' => ShareAccess::READ,
            'w' => ShareAccess::WRITE,
            'd' => ShareAccess::DELETE,
            _ => {
                return Err(Error::invalid_input(format!(
                    "Invalid share_access char {c}, can only be d, r, w"
                )));
            }
        };
    }
    if reading {
        sa |= ShareAccess::READ;
    }
    Ok(sa)
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// A parsed fsspec SMB path: `/share/dir/file`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SmbPath {
    /// Canonical fsspec name: `/share/a/b` (no trailing slash).
    pub name: String,
    /// Share name (first component).
    pub share: String,
    /// Path below the share with `\` separators, no leading separator
    /// (empty for the share root).
    pub rel: String,
}

impl SmbPath {
    /// Parse a protocol-stripped path. `\` is a separator too (smbclient
    /// turns `/` into `\`, so both separate components on the server).
    /// Paths without a share are rejected like smbclient does.
    pub fn parse(path: &str) -> Result<SmbPath> {
        let path = strip_protocol(path);
        let comps: Vec<&str> = path
            .split(['/', '\\'])
            .filter(|c| !c.is_empty())
            .collect();
        let Some((share, rest)) = comps.split_first() else {
            return Err(Error::invalid_input(
                "The SMB path specified must contain the server and share to connect to",
            )
            .with_path(path.as_str()));
        };
        if comps.iter().any(|c| *c == "." || *c == "..") {
            return Err(Error::invalid_input(
                "SMB paths must not contain '.' or '..' components",
            )
            .with_path(path.as_str()));
        }
        let mut name = String::with_capacity(path.len() + 1);
        for c in &comps {
            name.push('/');
            name.push_str(c);
        }
        Ok(SmbPath {
            name,
            share: (*share).to_owned(),
            rel: rest.join("\\"),
        })
    }

    /// Whether this is the share root (fsspec `not _share_has_path`).
    pub fn is_share_root(&self) -> bool {
        self.rel.is_empty()
    }

    /// The parent directory (`None` for a share root).
    pub fn parent(&self) -> Option<SmbPath> {
        if self.is_share_root() {
            return None;
        }
        let name = match self.name.rfind('/') {
            Some(i) => self.name[..i].to_owned(),
            None => return None,
        };
        let rel = match self.rel.rfind('\\') {
            Some(i) => self.rel[..i].to_owned(),
            None => String::new(),
        };
        Some(SmbPath {
            name,
            share: self.share.clone(),
            rel,
        })
    }

    /// Whether both paths are on the same share (share names compare
    /// case-insensitively, as servers do).
    pub fn same_share(&self, other: &SmbPath) -> bool {
        self.share.eq_ignore_ascii_case(&other.share)
    }
}

/// fsspec `SMBFileSystem._strip_protocol`: the path part of
/// `infer_storage_options(path)`. `smb://[user[:password]@]host[:port]/share/x`
/// becomes `/share/x`; anything that is not a URL is returned unchanged.
pub fn strip_protocol(path: &str) -> String {
    match split_url(path) {
        Some(u) => u.path,
        None => path.to_owned(),
    }
}

/// fsspec `SMBFileSystem._get_kwargs_from_urls`: `host`, `port`,
/// `username`, `password` (and `url_query`/`url_fragment`) from an
/// `smb://` URL, exactly as `infer_storage_options` reports them (no
/// percent-decoding).
pub fn get_kwargs_from_urls(url: &str) -> Options {
    let mut out = Options::new();
    let Some(u) = split_url(url) else {
        return out;
    };
    if let Some(h) = u.host {
        out.insert("host".into(), Value::Str(h));
    }
    if let Some(p) = u.port {
        out.insert("port".into(), Value::Int(i64::from(p)));
    }
    if let Some(user) = u.username {
        out.insert("username".into(), Value::Str(user));
    }
    if let Some(pw) = u.password {
        out.insert("password".into(), Value::Str(pw));
    }
    if let Some(q) = u.query {
        out.insert("url_query".into(), Value::Str(q));
    }
    if let Some(f) = u.fragment {
        out.insert("url_fragment".into(), Value::Str(f));
    }
    out
}

/// fsspec `AbstractFileSystem._parent` for SMB paths.
pub fn parent(path: &str) -> String {
    let p = strip_protocol(path);
    let p = p.trim_end_matches('/');
    match p.rfind('/') {
        Some(i) => p[..i].to_owned(),
        None => String::new(),
    }
}

struct UrlParts {
    path: String,
    host: Option<String>,
    port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
    query: Option<String>,
    fragment: Option<String>,
}

/// `urlsplit`-style parsing as `infer_storage_options` does it.
fn split_url(s: &str) -> Option<UrlParts> {
    // Windows drive paths are not URLs.
    let b = s.as_bytes();
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
    {
        return None;
    }
    let idx = s.find("://")?;
    let scheme = &s[..idx];
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'.' | b'-'))
    {
        return None;
    }
    let rest = &s[idx + 3..];
    let (rest, fragment) = match rest.split_once('#') {
        Some((a, f)) => (a, Some(f.to_owned())),
        None => (rest, None),
    };
    let (rest, query) = match rest.split_once('?') {
        Some((a, q)) => (a, Some(q.to_owned())),
        None => (rest, None),
    };
    let (netloc, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let mut path = path.to_owned();
    if let Some(f) = &fragment
        && !f.is_empty()
    {
        path = format!("{path}#{f}");
    }
    let mut out = UrlParts {
        path,
        host: None,
        port: None,
        username: None,
        password: None,
        query: query.filter(|q| !q.is_empty()),
        fragment: fragment.filter(|f| !f.is_empty()),
    };
    if !netloc.is_empty() {
        let (userinfo, hostport) = match netloc.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, netloc),
        };
        // `rsplit(":", 1)[0]` as fsspec does for the host...
        let host = match hostport.rsplit_once(':') {
            Some((h, _)) => h,
            None => hostport,
        };
        out.host = Some(host.to_owned());
        // ...while the port comes from urlsplit (brackets respected).
        let port_str = if let Some(end) = hostport.rfind(']') {
            hostport[end + 1..].strip_prefix(':')
        } else {
            hostport.rsplit_once(':').map(|(_, p)| p)
        };
        out.port = port_str.and_then(|p| p.parse().ok());
        if let Some(ui) = userinfo {
            let (u, p) = match ui.split_once(':') {
                Some((u, p)) => (u, Some(p)),
                None => (ui, None),
            };
            out.username = (!u.is_empty()).then(|| u.to_owned());
            out.password = p.filter(|p| !p.is_empty()).map(str::to_owned);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_and_kwargs_match_infer_storage_options() {
        assert_eq!(strip_protocol("smb://h/share/a/b"), "/share/a/b");
        assert_eq!(strip_protocol("/share/a/"), "/share/a/");
        assert_eq!(strip_protocol("share/a"), "share/a");
        assert_eq!(strip_protocol("smb://u:p@h:1445/share/a"), "/share/a");
        assert_eq!(strip_protocol("smb://h"), "");
        assert_eq!(strip_protocol("smb://h/s/a?x=1#frag"), "/s/a#frag");
        assert_eq!(strip_protocol("C:\\x"), "C:\\x");
        let k = get_kwargs_from_urls("smb://wg;u:p@h:1445/share/a");
        assert_eq!(k.get("host"), Some(&Value::Str("h".into())));
        assert_eq!(k.get("port"), Some(&Value::Int(1445)));
        assert_eq!(k.get("username"), Some(&Value::Str("wg;u".into())));
        assert_eq!(k.get("password"), Some(&Value::Str("p".into())));
        let k = get_kwargs_from_urls("smb://[::1]:445/s/x");
        assert_eq!(k.get("host"), Some(&Value::Str("[::1]".into())));
        assert_eq!(k.get("port"), Some(&Value::Int(445)));
        let k = get_kwargs_from_urls("smb://u@h/s/a");
        assert_eq!(k.get("username"), Some(&Value::Str("u".into())));
        assert!(!k.contains_key("password"));
        assert!(get_kwargs_from_urls("/share/x").is_empty());
    }

    #[test]
    fn parent_matches_fsspec() {
        assert_eq!(parent("/data/a/b"), "/data/a");
        assert_eq!(parent("/data"), "");
        assert_eq!(parent("/data/a/"), "/data");
    }

    #[test]
    fn smb_path_parsing() {
        let p = SmbPath::parse("/data/a//b/").unwrap();
        assert_eq!(p.name, "/data/a/b");
        assert_eq!(p.share, "data");
        assert_eq!(p.rel, "a\\b");
        assert!(!p.is_share_root());
        let root = SmbPath::parse("data").unwrap();
        assert_eq!(root.name, "/data");
        assert!(root.is_share_root());
        assert_eq!(p.parent().unwrap().name, "/data/a");
        assert_eq!(p.parent().unwrap().parent().unwrap().name, "/data");
        assert!(root.parent().is_none());
        assert_eq!(SmbPath::parse("smb://h/s/x").unwrap().name, "/s/x");
        assert_eq!(SmbPath::parse("/s\\x\\y").unwrap().rel, "x\\y");
        for bad in ["", "/", "//", "/s/../x", "/s/./x"] {
            assert_eq!(
                SmbPath::parse(bad).unwrap_err().kind(),
                fsfast_core::ErrorKind::InvalidInput,
                "{bad:?}"
            );
        }
        assert!(p.same_share(&SmbPath::parse("/DATA/x").unwrap()));
    }

    #[test]
    fn options_are_strict_and_typed() {
        let mut o = Options::new();
        o.insert("host".into(), "srv".into());
        o.insert("port".into(), Value::Int(1445));
        o.insert("username".into(), "u".into());
        o.insert("password".into(), "p".into());
        o.insert("timeout".into(), Value::Int(5));
        o.insert("encrypt".into(), Value::Bool(true));
        o.insert("share_access".into(), "rw".into());
        o.insert("auto_mkdir".into(), Value::Bool(true));
        o.insert("max_dialect".into(), "3.0.2".into());
        o.insert("read_chunk_size".into(), Value::Int(1 << 20));
        o.insert("skip_instance_cache".into(), Value::Bool(true));
        let c = SmbConfig::from_options(o.clone()).unwrap();
        assert_eq!(c.port(), 1445);
        assert_eq!(c.timeout, Duration::from_secs(5));
        assert_eq!(c.encrypt, Some(true));
        assert!(c.auto_mkdir);
        assert_eq!(c.max_dialect, Dialect::SMB_3_0_2);
        assert_eq!(c.dialects().last(), Some(&Dialect::SMB_3_0_2));
        assert!(format!("{c:?}").contains("redacted"));
        assert!(!format!("{c:?}").contains("\"p\""));

        o.insert("bogus".into(), Value::Int(1));
        assert!(SmbConfig::from_options(o).is_err());
        let mut o = Options::new();
        o.insert("port".into(), Value::Int(1));
        assert!(SmbConfig::from_options(o).is_err(), "host is required");
        for (k, v) in [
            ("register_session_retry_wait", Value::Int(-1)),
            ("register_session_retry_factor", Value::Float(0.5)),
            ("share_access", Value::Str("x".into())),
            ("port", Value::Int(70000)),
            ("read_chunk_size", Value::Int(1)),
            ("min_dialect", Value::Str("4.0".into())),
        ] {
            let mut o = Options::new();
            o.insert("host".into(), "h".into());
            o.insert(k.into(), v);
            assert!(SmbConfig::from_options(o).is_err(), "{k}");
        }
    }

    #[test]
    fn retry_waits_follow_fsspec() {
        let mut c = SmbConfig::new("h");
        // retries=4, wait=1, factor=10: 10**(n/3 - 1)
        let w: Vec<f64> = (0..4).map(|n| c.retry_wait(n).as_secs_f64()).collect();
        assert!((w[0] - 0.1).abs() < 1e-9 && (w[3] - 1.0).abs() < 1e-9, "{w:?}");
        c.register_session_retries = 1;
        assert_eq!(c.retry_wait(0), Duration::from_secs(1));
    }

    #[test]
    fn share_access_letters() {
        assert_eq!(parse_share_access(None, true).unwrap(), ShareAccess::empty());
        assert_eq!(
            parse_share_access(Some("w"), true).unwrap(),
            ShareAccess::READ | ShareAccess::WRITE
        );
        assert_eq!(
            parse_share_access(Some("rwd"), false).unwrap(),
            ShareAccess::all()
        );
        assert!(parse_share_access(Some("q"), false).is_err());
    }

    #[test]
    fn dialect_names() {
        assert_eq!(parse_dialect("3.1.1").unwrap(), Dialect::SMB_3_1_1);
        assert_eq!(parse_dialect("SMB3_11").unwrap(), Dialect::SMB_3_1_1);
        assert_eq!(parse_dialect("smb2_02").unwrap(), Dialect::SMB_2_0_2);
        assert_eq!(parse_dialect("0x0210").unwrap(), Dialect::SMB_2_1);
        assert!(parse_dialect("1.0").is_err());
    }
}
