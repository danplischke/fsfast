//! `storage_options` of [`SftpFileSystem`](crate::SftpFileSystem) and the
//! fsspec path helpers (`_strip_protocol`, `_get_kwargs_from_urls`,
//! `_parent`).

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use fsfast_core::{Error, OptionReader, Options, Result, Value};

use crate::ssh::known_hosts::HostKeyPolicy;

/// Default SSH port.
pub const DEFAULT_PORT: u16 = 22;

/// `AbstractFileSystem` options fsspec accepts for every filesystem; they
/// have no effect here (caching lives in the Python layer).
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

/// paramiko's `disabled_algorithms` categories.
const ALGORITHM_CATEGORIES: &[&str] = &[
    "ciphers",
    "macs",
    "keys",
    "pubkeys",
    "kex",
    "compression",
    "gsskex",
];

/// A secret string: zeroized on drop, redacted in `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(zeroize::Zeroizing<String>);

impl Secret {
    /// Wrap `s`.
    pub fn new(s: impl Into<String>) -> Self {
        Secret(zeroize::Zeroizing::new(s.into()))
    }

    /// The secret value.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// Where SSH client configuration comes from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SshConfigSource {
    /// `~/.ssh/config`, then `/etc/ssh/ssh_config` (OpenSSH's order).
    #[default]
    Default,
    /// Only these files.
    Files(Vec<PathBuf>),
    /// No configuration files (paramiko's behaviour).
    Disabled,
}

/// Typed configuration of an [`SftpFileSystem`](crate::SftpFileSystem).
///
/// Field names follow `paramiko.SSHClient.connect` (which fsspec forwards
/// its keyword arguments to) and fsspec's own `temppath` and
/// `host_key_policy`; the rest are fsfast extensions.
#[derive(Debug, Clone)]
pub struct SftpConfig {
    /// `host`: host name, IP address or ssh_config alias.
    pub host: String,
    /// `port` (default: ssh_config `Port`, else 22).
    pub port: Option<u16>,
    /// `username` (default: ssh_config `User`, else the local user).
    pub username: Option<String>,
    /// `password`: password authentication, keyboard-interactive answers,
    /// and the passphrase of encrypted keys when `passphrase` is unset.
    pub password: Option<Secret>,
    /// `pkey`: a private key in OpenSSH or PEM text form (the Python layer
    /// serializes a `paramiko.PKey`).
    pub pkey: Option<Secret>,
    /// `key_filename`: private key file(s) to try.
    pub key_filenames: Vec<String>,
    /// `passphrase` for encrypted private keys.
    pub passphrase: Option<Secret>,
    /// `timeout`: TCP connect (and handshake) timeout.
    pub timeout: Option<Duration>,
    /// `allow_agent` (default true): try keys of the ssh-agent at
    /// `SSH_AUTH_SOCK`.
    pub allow_agent: bool,
    /// `look_for_keys` (default true): try `~/.ssh/id_{rsa,ecdsa,ed25519}`.
    pub look_for_keys: bool,
    /// `compress`: negotiate zlib compression.
    pub compress: bool,
    /// `banner_timeout` (paramiko default 15 s): server banner and key
    /// exchange.
    pub banner_timeout: Duration,
    /// `auth_timeout` (paramiko default 30 s): the whole authentication.
    pub auth_timeout: Duration,
    /// `channel_timeout` (paramiko default 1 h): opening the SFTP channel.
    pub channel_timeout: Duration,
    /// `disabled_algorithms`: `{category: [names]}` with paramiko's
    /// categories (`ciphers`, `macs`, `keys`, `pubkeys`, `kex`,
    /// `compression`).
    pub disabled_algorithms: Vec<(String, Vec<String>)>,
    /// `host_key_policy` (default `auto_add`, or ssh_config's
    /// `StrictHostKeyChecking`); see [`crate::ssh::known_hosts`].
    pub host_key_policy: Option<HostKeyPolicy>,
    /// `temppath` (default `/tmp`): where fsspec transactions stage files.
    pub temppath: String,
    /// fsfast: `known_hosts` file(s) replacing the defaults; an empty list
    /// (Python `False`) loads none.
    pub known_hosts: Option<Vec<PathBuf>>,
    /// fsfast: `ssh_config` file(s), or `False` to ignore ssh_config.
    pub ssh_config: SshConfigSource,
    /// fsfast: maximum SSH connections in the pool (default 4). Extra
    /// connections open in the background while operations run
    /// concurrently.
    pub connections: usize,
    /// fsfast: maximum READ/WRITE requests in flight per transfer
    /// (default 64).
    pub max_inflight: usize,
    /// fsfast: READ request size (default: the server's
    /// `limits@openssh.com` maximum, else 32 KiB).
    pub read_chunk_size: Option<usize>,
    /// fsfast: WRITE request size (default: as for reads).
    pub write_chunk_size: Option<usize>,
    /// fsfast: per-request timeout (default none).
    pub request_timeout: Option<Duration>,
    /// fsfast: SSH keepalive interval (default: ssh_config
    /// `ServerAliveInterval`, else none).
    pub keepalive_interval: Option<Duration>,
    /// fsfast: `fsync@openssh.com` before closing written files.
    pub fsync_on_close: bool,
}

impl SftpConfig {
    /// Defaults for `host`.
    pub fn new(host: impl Into<String>) -> Self {
        SftpConfig {
            host: host.into(),
            port: None,
            username: None,
            password: None,
            pkey: None,
            key_filenames: Vec::new(),
            passphrase: None,
            timeout: None,
            allow_agent: true,
            look_for_keys: true,
            compress: false,
            banner_timeout: Duration::from_secs(15),
            auth_timeout: Duration::from_secs(30),
            channel_timeout: Duration::from_secs(3600),
            disabled_algorithms: Vec::new(),
            host_key_policy: None,
            temppath: "/tmp".into(),
            known_hosts: None,
            ssh_config: SshConfigSource::Default,
            connections: 4,
            max_inflight: 64,
            read_chunk_size: None,
            write_chunk_size: None,
            request_timeout: None,
            keepalive_interval: None,
            fsync_on_close: false,
        }
    }

    /// Set `username` and `password`.
    pub fn with_credentials(mut self, username: &str, password: &str) -> Self {
        self.username = Some(username.to_owned());
        self.password = Some(Secret::new(password));
        self
    }

    /// Set `port`.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// The names disabled in `category`.
    pub fn disabled(&self, category: &str) -> &[String] {
        self.disabled_algorithms
            .iter()
            .find(|(c, _)| c == category)
            .map_or(&[], |(_, v)| v.as_slice())
    }

    /// Parse fsspec `storage_options`.
    pub fn from_options(opts: Options) -> Result<Self> {
        let mut r = OptionReader::new("sftp", opts);
        let host = r
            .string("host")?
            .filter(|h| !h.is_empty())
            .ok_or_else(|| Error::invalid_input("sftp: option 'host' is required"))?;
        let mut c = SftpConfig::new(host);
        if let Some(p) = r.u64("port")? {
            c.port = Some(
                u16::try_from(p)
                    .ok()
                    .filter(|p| *p > 0)
                    .ok_or_else(|| Error::invalid_input(format!("sftp: invalid port {p}")))?,
            );
        }
        c.username = r.string("username")?;
        c.password = r.string("password")?.map(Secret::new);
        c.pkey = match r.value("pkey") {
            None => None,
            Some(Value::Str(s)) => Some(Secret::new(s)),
            Some(Value::Bytes(b)) => Some(Secret::new(String::from_utf8(b).map_err(|_| {
                Error::invalid_input("sftp: option 'pkey' must be a private key in text form")
            })?)),
            Some(v) => {
                return Err(Error::invalid_input(format!(
                    "sftp: option 'pkey' must be a private key string (OpenSSH or PEM), got {}",
                    v.type_name()
                )));
            }
        };
        c.key_filenames = r.string_list("key_filename")?.unwrap_or_default();
        c.passphrase = r.string("passphrase")?.map(Secret::new);
        c.timeout = r.duration_secs("timeout")?;
        if let Some(b) = r.bool("allow_agent")? {
            c.allow_agent = b;
        }
        if let Some(b) = r.bool("look_for_keys")? {
            c.look_for_keys = b;
        }
        if let Some(b) = r.bool("compress")? {
            c.compress = b;
        }
        if let Some(d) = r.duration_secs("banner_timeout")? {
            c.banner_timeout = d;
        }
        if let Some(d) = r.duration_secs("auth_timeout")? {
            c.auth_timeout = d;
        }
        if let Some(d) = r.duration_secs("channel_timeout")? {
            c.channel_timeout = d;
        }
        if let Some(mut sub) = r.nested("disabled_algorithms")? {
            for cat in ALGORITHM_CATEGORIES {
                if let Some(names) = sub.string_list(cat)? {
                    c.disabled_algorithms.push(((*cat).to_owned(), names));
                }
            }
            sub.finish()?;
        }
        for unsupported in ["sock", "transport_factory", "auth_strategy"] {
            if r.value(unsupported).is_some() {
                return Err(Error::unsupported(format!(
                    "sftp: option '{unsupported}' (a Python object)"
                )));
            }
        }
        if let Some(p) = r.string("host_key_policy")? {
            c.host_key_policy = Some(HostKeyPolicy::parse(&p).ok_or_else(|| {
                Error::invalid_input(format!(
                    "Unknown host_key_policy {p:?}; expected one of ['auto_add', 'reject', 'warning']"
                ))
            })?);
        }
        if let Some(t) = r.string("temppath")? {
            c.temppath = t;
        }

        // fsfast extensions.
        c.known_hosts = match r.value("known_hosts") {
            None | Some(Value::Bool(true)) => None,
            Some(Value::Bool(false)) => Some(Vec::new()),
            Some(Value::Str(s)) => Some(vec![PathBuf::from(s)]),
            Some(Value::List(l)) => Some(path_list("known_hosts", l)?),
            Some(v) => {
                return Err(Error::invalid_input(format!(
                    "sftp: option 'known_hosts' must be a path, a list of paths or False, got {}",
                    v.type_name()
                )));
            }
        };
        c.ssh_config = match r.value("ssh_config") {
            None | Some(Value::Bool(true)) => SshConfigSource::Default,
            Some(Value::Bool(false)) => SshConfigSource::Disabled,
            Some(Value::Str(s)) => SshConfigSource::Files(vec![PathBuf::from(s)]),
            Some(Value::List(l)) => SshConfigSource::Files(path_list("ssh_config", l)?),
            Some(v) => {
                return Err(Error::invalid_input(format!(
                    "sftp: option 'ssh_config' must be a path, a list of paths or a boolean, got {}",
                    v.type_name()
                )));
            }
        };
        if let Some(n) = r.usize("connections")? {
            c.connections = n.clamp(1, 64);
        }
        if let Some(n) = r.usize("max_inflight")? {
            c.max_inflight = n.clamp(1, 1024);
        }
        if let Some(n) = r.usize("read_chunk_size")? {
            c.read_chunk_size = Some(check_chunk("read_chunk_size", n)?);
        }
        if let Some(n) = r.usize("write_chunk_size")? {
            c.write_chunk_size = Some(check_chunk("write_chunk_size", n)?);
        }
        c.request_timeout = r.duration_secs("request_timeout")?.filter(|d| !d.is_zero());
        c.keepalive_interval = r
            .duration_secs("keepalive_interval")?
            .filter(|d| !d.is_zero());
        if let Some(b) = r.bool("fsync_on_close")? {
            c.fsync_on_close = b;
        }
        r.accept_ignored(IGNORED_BASE_OPTIONS);
        r.finish()?;
        Ok(c)
    }
}

fn path_list(name: &str, l: Vec<Value>) -> Result<Vec<PathBuf>> {
    l.into_iter()
        .map(|v| match v {
            Value::Str(s) => Ok(PathBuf::from(s)),
            other => Err(Error::invalid_input(format!(
                "sftp: option '{name}' must contain paths, got {}",
                other.type_name()
            ))),
        })
        .collect()
}

fn check_chunk(name: &str, n: usize) -> Result<usize> {
    if (1024..=(4 << 20)).contains(&n) {
        Ok(n)
    } else {
        Err(Error::invalid_input(format!(
            "sftp: option '{name}' must be between 1024 and 4194304 bytes, got {n}"
        )))
    }
}

/// fsspec `SFTPFileSystem._strip_protocol`: the path part of
/// `infer_storage_options(path)`. `sftp://[user[:pw]@]host[:port]/a/b`
/// becomes `/a/b`; anything that is not a URL is returned unchanged
/// (fsspec keeps trailing slashes and relative paths as they are).
pub fn strip_protocol(path: &str) -> String {
    match split_url(path) {
        Some(u) => u.path,
        None => path.to_owned(),
    }
}

/// fsspec `SFTPFileSystem._get_kwargs_from_urls`: `host`, `port`,
/// `username`, `password` (and `url_query`/`url_fragment`) of an
/// `sftp://`/`ssh://` URL, as `infer_storage_options` reports them.
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

/// fsspec `AbstractFileSystem._parent` with SFTP's `_strip_protocol`
/// (root marker `""`): `"/a/b" -> "/a"`, `"/a" -> ""`, `"a" -> ""`,
/// `"/a/b/" -> "/a/b"`.
pub fn parent(path: &str) -> String {
    let p = strip_protocol(path);
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
    let b = s.as_bytes();
    // Windows drive paths are not URLs.
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

    fn opts(pairs: &[(&str, Value)]) -> Options {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    #[test]
    fn strip_parent_kwargs_match_fsspec() {
        // Values observed from fsspec's SFTPFileSystem (see the probe in
        // the crate docs' test notes).
        let cases = [
            ("sftp://h:22/a/b/", "/a/b/"),
            ("/a/b/", "/a/b/"),
            ("a/b", "a/b"),
            ("sftp://u:p@h/x", "/x"),
            ("sftp://h", ""),
            ("ssh://h/z?q=1#f", "/z#f"),
        ];
        for (i, o) in cases {
            assert_eq!(strip_protocol(i), o, "{i}");
        }
        let parents = [
            ("/a/b/", "/a/b"),
            ("/a", ""),
            ("a", ""),
            ("sftp://h/a/b", "/a"),
            ("/", ""),
        ];
        for (i, o) in parents {
            assert_eq!(parent(i), o, "{i}");
        }
        let k = get_kwargs_from_urls("sftp://u:p@h:2200/a");
        assert_eq!(k.get("host"), Some(&Value::Str("h".into())));
        assert_eq!(k.get("port"), Some(&Value::Int(2200)));
        assert_eq!(k.get("username"), Some(&Value::Str("u".into())));
        assert_eq!(k.get("password"), Some(&Value::Str("p".into())));
        assert!(get_kwargs_from_urls("/x").is_empty());
        let k = get_kwargs_from_urls("sftp://[::1]:2222/x");
        assert_eq!(k.get("host"), Some(&Value::Str("[::1]".into())));
        assert_eq!(k.get("port"), Some(&Value::Int(2222)));
    }

    #[test]
    fn options_parse() {
        let c = SftpConfig::from_options(opts(&[
            ("host", "h".into()),
            ("port", Value::Int(2222)),
            ("username", "u".into()),
            ("password", "pw".into()),
            ("key_filename", Value::List(vec!["a".into(), "b".into()])),
            ("timeout", Value::Float(2.5)),
            ("allow_agent", Value::Bool(false)),
            ("look_for_keys", Value::Bool(false)),
            ("compress", Value::Bool(true)),
            ("banner_timeout", Value::Int(3)),
            (
                "disabled_algorithms",
                Value::Map(opts(&[("ciphers", Value::List(vec!["aes128-ctr".into()]))])),
            ),
            ("host_key_policy", "reject".into()),
            ("temppath", "/var/tmp".into()),
            ("known_hosts", Value::Bool(false)),
            ("ssh_config", Value::Bool(false)),
            ("connections", Value::Int(2)),
            ("sock", Value::Null),
            ("use_listings_cache", Value::Bool(false)),
        ]))
        .unwrap();
        assert_eq!(c.port, Some(2222));
        assert_eq!(c.password.as_ref().map(Secret::expose), Some("pw"));
        assert_eq!(c.key_filenames, ["a", "b"]);
        assert_eq!(c.timeout, Some(Duration::from_millis(2500)));
        assert!(!c.allow_agent && !c.look_for_keys && c.compress);
        assert_eq!(c.banner_timeout, Duration::from_secs(3));
        assert_eq!(c.disabled("ciphers"), ["aes128-ctr"]);
        assert!(c.disabled("macs").is_empty());
        assert_eq!(c.host_key_policy, Some(HostKeyPolicy::Reject));
        assert_eq!(c.temppath, "/var/tmp");
        assert_eq!(c.known_hosts, Some(vec![]));
        assert_eq!(c.ssh_config, SshConfigSource::Disabled);
        assert_eq!(c.connections, 2);
        assert!(
            !format!("{c:?}").contains("pw\""),
            "password leaked in Debug"
        );
    }

    #[test]
    fn option_errors() {
        let bad = |pairs: &[(&str, Value)]| {
            let mut v = vec![("host", Value::Str("h".into()))];
            v.extend_from_slice(pairs);
            SftpConfig::from_options(opts(&v)).unwrap_err()
        };
        assert!(SftpConfig::from_options(Options::new()).is_err());
        assert!(bad(&[("port", Value::Int(0))]).to_string().contains("port"));
        assert!(bad(&[("typo", Value::Int(1))]).to_string().contains("typo"));
        assert!(
            bad(&[("host_key_policy", "maybe".into())])
                .to_string()
                .contains("Unknown host_key_policy")
        );
        assert_eq!(
            bad(&[("sock", Value::Int(3))]).kind(),
            fsfast_core::ErrorKind::Unsupported
        );
        assert!(
            bad(&[(
                "disabled_algorithms",
                Value::Map(opts(&[("cyphers", Value::List(vec![]))]))
            )])
            .to_string()
            .contains("cyphers")
        );
        assert!(
            bad(&[("read_chunk_size", Value::Int(10))])
                .to_string()
                .contains("1024")
        );
        assert!(bad(&[("pkey", Value::Int(1))]).to_string().contains("pkey"));
    }
}
