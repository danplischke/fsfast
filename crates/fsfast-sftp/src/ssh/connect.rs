//! Establishing an authenticated SSH connection with russh and opening the
//! `sftp` subsystem channel on it.

use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use russh::client::{self, Handle, Msg};
use russh::keys::{Algorithm, PublicKeyOrCertificate};
use russh::{ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Preferred, SshId, cipher, compression};

use fsfast_core::{Detail, Error, ErrorKind, Result};

use super::auth::{self, AuthParams};
use super::config::{self as sshconf, Context, Tokens};
use super::known_hosts::{self, HostKeyPolicy, HostKeyVerifier, KnownHosts};
use crate::options::{SftpConfig, SshConfigSource};

/// Initial SSH channel window we grant the server. Large enough that the
/// window never limits a pipelined transfer (`max_inflight` x chunk is 16
/// MiB by default), so the server can stream continuously.
pub const CHANNEL_WINDOW: u32 = 64 << 20;

/// Largest SSH packet we accept on the channel. russh warns above 64 KiB;
/// OpenSSH sends at most 32 KiB of channel data per packet anyway.
pub const MAX_PACKET: u32 = 65_535;

/// Cipher preference: AEAD first (one pass for encryption and integrity),
/// AES-GCM before ChaCha20-Poly1305 because aws-lc uses AES-NI/PMULL.
const CIPHERS: &[cipher::Name] = &[
    cipher::AES_128_GCM,
    cipher::AES_256_GCM,
    cipher::CHACHA20_POLY1305,
    cipher::AES_128_CTR,
    cipher::AES_192_CTR,
    cipher::AES_256_CTR,
];

/// Everything needed to open connections to one destination, resolved once
/// from the options, ssh_config and the environment.
#[derive(Debug, Clone)]
pub struct Target {
    /// fsspec's `host` (possibly an ssh_config alias).
    pub alias: String,
    /// Host to connect to (ssh_config `HostName`, brackets removed).
    pub connect_host: String,
    /// Port.
    pub port: u16,
    /// Remote user.
    pub user: String,
    /// Name looked up in known_hosts (`HostKeyAlias` or the host).
    pub key_host: String,
    /// Port used for the known_hosts lookup: the connection port, or 22
    /// (meaning "no `[name]:port` form") when `key_host` comes from
    /// `HostKeyAlias`, which OpenSSH looks up exactly as written.
    pub key_port: u16,
    /// Known-hosts files to load.
    pub known_hosts_files: Vec<PathBuf>,
    /// Policy for unknown keys.
    pub policy: HostKeyPolicy,
    /// Authentication material.
    pub auth: AuthParams,
    /// TCP connect timeout.
    pub connect_timeout: Option<Duration>,
    /// Banner + key exchange timeout.
    pub banner_timeout: Duration,
    /// Authentication timeout.
    pub auth_timeout: Duration,
    /// Channel open timeout.
    pub channel_timeout: Duration,
    /// Negotiate zlib compression.
    pub compress: bool,
    /// SSH keepalive interval.
    pub keepalive: Option<Duration>,
    /// paramiko `disabled_algorithms`.
    pub disabled: Vec<(String, Vec<String>)>,
}

impl Target {
    /// Resolve `cfg` against ssh_config and the environment.
    pub fn resolve(cfg: &SftpConfig) -> Result<Target> {
        let home = super::home_dir();
        let home_s = home.as_ref().map(|h| h.to_string_lossy().into_owned());
        let local_user = super::local_user().unwrap_or_default();
        let files = match &cfg.ssh_config {
            SshConfigSource::Disabled => Vec::new(),
            SshConfigSource::Files(f) => f.clone(),
            SshConfigSource::Default => {
                let mut v = Vec::new();
                if let Some(h) = &home {
                    v.push(h.join(".ssh/config"));
                }
                v.push(PathBuf::from("/etc/ssh/ssh_config"));
                v
            }
        };
        let ctx = Context {
            home: home_s.clone(),
            local_user: local_user.clone(),
            remote_user: cfg.username.clone(),
        };
        let hc = sshconf::resolve(&cfg.host, &files, &ctx)?;
        for (kw, v) in [
            ("ProxyJump", &hc.proxy_jump),
            ("ProxyCommand", &hc.proxy_command),
        ] {
            if let Some(v) = v
                && !v.eq_ignore_ascii_case("none")
            {
                return Err(Error::unsupported(format!(
                    "sftp: ssh_config {kw} ({v}) for host {:?}; connect to the target directly or \
                     pass ssh_config=False to ignore the configuration",
                    cfg.host
                )));
            }
        }

        let raw_host = hc.hostname.clone().unwrap_or_else(|| cfg.host.clone());
        let connect_host = raw_host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(&raw_host)
            .to_owned();
        let port = cfg.port.or(hc.port).unwrap_or(crate::options::DEFAULT_PORT);
        let user = cfg
            .username
            .clone()
            .or_else(|| hc.user.clone())
            .filter(|u| !u.is_empty())
            .or_else(|| (!local_user.is_empty()).then(|| local_user.clone()))
            .ok_or_else(|| {
                Error::invalid_input("sftp: no username given and the local user is unknown")
            })?;
        let tokens = Tokens {
            home: home_s.as_deref(),
            host: &connect_host,
            alias: &cfg.host,
            port,
            remote_user: &user,
            local_user: &local_user,
        };
        let expand = |v: &str| PathBuf::from(sshconf::expand_tokens(v, &tokens));

        let known_hosts_files = match &cfg.known_hosts {
            Some(v) => v.clone(),
            None => {
                let user_files = hc.user_known_hosts_files.clone();
                let global_files = hc.global_known_hosts_files.clone();
                if user_files.is_none() && global_files.is_none() {
                    known_hosts::default_files(home.as_deref())
                } else {
                    let mut v = Vec::new();
                    let defaults = known_hosts::default_files(home.as_deref());
                    match user_files {
                        Some(f) => v.extend(
                            f.iter()
                                .filter(|f| !f.eq_ignore_ascii_case("none"))
                                .map(|f| expand(f)),
                        ),
                        None => v.extend(defaults.iter().take(2).cloned()),
                    }
                    match global_files {
                        Some(f) => v.extend(
                            f.iter()
                                .filter(|f| !f.eq_ignore_ascii_case("none"))
                                .map(|f| expand(f)),
                        ),
                        None => v.extend(defaults.iter().skip(2).cloned()),
                    }
                    v
                }
            }
        };
        let policy = cfg
            .host_key_policy
            .unwrap_or(match hc.strict_host_key_checking.as_deref() {
                Some("yes" | "ask") => HostKeyPolicy::Reject,
                _ => HostKeyPolicy::AutoAdd,
            });

        let mut identity_files: Vec<PathBuf> =
            cfg.key_filenames.iter().map(|k| expand(k)).collect();
        for f in &hc.identity_files {
            let p = expand(f);
            if !identity_files.contains(&p) {
                identity_files.push(p);
            }
        }
        let mut default_identity_files = Vec::new();
        if cfg.look_for_keys
            && let Some(h) = &home
        {
            for dir in [".ssh", "ssh"] {
                for name in ["id_rsa", "id_ecdsa", "id_ed25519"] {
                    let p = h.join(dir).join(name);
                    if !identity_files.contains(&p) {
                        default_identity_files.push(p);
                    }
                }
            }
        }
        let agent_socket = if !cfg.allow_agent {
            None
        } else {
            identity_agent_socket(hc.identity_agent.as_deref(), &expand, &|k| {
                std::env::var_os(k)
            })
        };

        Ok(Target {
            alias: cfg.host.clone(),
            // OpenSSH looks a HostKeyAlias up verbatim (no `[alias]:port`);
            // only the real host name gets the port (put_host_port).
            key_port: if hc.host_key_alias.is_some() {
                22
            } else {
                port
            },
            key_host: hc
                .host_key_alias
                .clone()
                .unwrap_or_else(|| connect_host.clone()),
            connect_host,
            port,
            known_hosts_files,
            policy,
            auth: AuthParams {
                user: user.clone(),
                password: cfg.password.clone(),
                passphrase: cfg.passphrase.clone(),
                pkey: cfg.pkey.clone(),
                identity_files,
                default_identity_files,
                identities_only: hc.identities_only.unwrap_or(false),
                agent_socket,
                disabled_pubkeys: cfg.disabled("pubkeys").to_vec(),
            },
            user,
            connect_timeout: cfg.timeout.or(hc.connect_timeout),
            banner_timeout: cfg.banner_timeout,
            auth_timeout: cfg.auth_timeout,
            channel_timeout: cfg.channel_timeout,
            compress: cfg.compress || hc.compression.unwrap_or(false),
            keepalive: cfg.keepalive_interval.or(hc.server_alive_interval),
            disabled: cfg.disabled_algorithms.clone(),
        })
    }

    fn disabled(&self, category: &str) -> &[String] {
        self.disabled
            .iter()
            .find(|(c, _)| c == category)
            .map_or(&[], |(_, v)| v.as_slice())
    }

    /// `user@host:port` for messages.
    pub fn describe(&self) -> String {
        format!("{}@{}:{}", self.user, self.connect_host, self.port)
    }

    fn preferred(&self, known_algorithms: &[Algorithm]) -> Preferred {
        let d = Preferred::DEFAULT;
        let off = |cat: &str, name: &str| self.disabled(cat).iter().any(|n| n == name);
        let kex: Vec<_> = d
            .kex
            .iter()
            .filter(|k| !off("kex", k.as_ref()))
            .cloned()
            .collect();
        // Host key algorithms already recorded for this host come first,
        // so we negotiate a key that known_hosts can vouch for (as OpenSSH
        // does); RSA entries cover every rsa-sha2 signature variant.
        let mut key: Vec<Algorithm> = Vec::new();
        for a in d.key.iter() {
            let known = known_algorithms.iter().any(|k| match (k, a) {
                (Algorithm::Rsa { .. }, Algorithm::Rsa { .. }) => true,
                (k, a) => k == a,
            });
            if known {
                key.push(a.clone());
            }
        }
        for a in d.key.iter() {
            if !key.contains(a) {
                key.push(a.clone());
            }
        }
        key.retain(|a| !off("keys", a.as_str()));
        let cipher: Vec<_> = CIPHERS
            .iter()
            .filter(|c| !off("ciphers", c.as_ref()))
            .cloned()
            .collect();
        let mac: Vec<_> = d
            .mac
            .iter()
            .filter(|m| !off("macs", m.as_ref()))
            .cloned()
            .collect();
        let comp_order: &[compression::Name] = if self.compress {
            &[
                compression::ZLIB_LEGACY,
                compression::ZLIB,
                compression::NONE,
            ]
        } else {
            &[compression::NONE]
        };
        let comp: Vec<_> = comp_order
            .iter()
            .filter(|c| !off("compression", c.as_ref()))
            .cloned()
            .collect();
        Preferred {
            kex: Cow::Owned(kex),
            key: Cow::Owned(key),
            host_key_certificates: Cow::Borrowed(&[]),
            cipher: Cow::Owned(cipher),
            mac: Cow::Owned(mac),
            compression: Cow::Owned(comp),
        }
    }
}

/// Algorithms negotiated by the key exchange (diagnostics).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Negotiated {
    /// Key exchange method.
    pub kex: String,
    /// Host key algorithm.
    pub host_key: String,
    /// Cipher (client to server).
    pub cipher: String,
    /// MAC (`none` for AEAD ciphers).
    pub mac: String,
    /// Compression (client to server).
    pub compression: String,
}

/// russh event handler: verifies the host key and records the negotiated
/// algorithms.
struct ClientHandler {
    verifier: HostKeyVerifier,
    verdict: Arc<Mutex<Option<Error>>>,
    negotiated: Arc<Mutex<Negotiated>>,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let res = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => self.verifier.verify(key),
            PublicKeyOrCertificate::Certificate(_) => Err(Error::new(
                ErrorKind::ConnectionFailed,
                "the server presented a host certificate, which is not supported",
            )
            .with_retryable(false)),
        };
        match res {
            Ok(()) => Ok(true),
            Err(e) => {
                *self.verdict.lock() = Some(e);
                Ok(false)
            }
        }
    }

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &russh::Names,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        let comp = match names.client_compression {
            russh::compression::Compression::None => "none",
            russh::compression::Compression::Zlib => "zlib",
            russh::compression::Compression::ZlibOpenSSH => "zlib@openssh.com",
        };
        *self.negotiated.lock() = Negotiated {
            kex: names.kex.as_ref().to_owned(),
            host_key: names.key.as_str().to_owned(),
            cipher: names.cipher.as_ref().to_owned(),
            mac: names.client_mac.as_ref().to_owned(),
            compression: comp.to_owned(),
        };
        Ok(())
    }

    async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        tracing::debug!("SSH banner: {}", banner.trim_end());
        Ok(())
    }
}

/// Map a russh error to an fsfast error.
pub fn map_ssh_error(e: russh::Error, what: &str) -> Error {
    use russh::Error as E;
    let msg = format!("{what}: {e}");
    match e {
        E::IO(io) => {
            let kind = Error::from(io).kind();
            Error::new(kind, msg)
        }
        E::ConnectionTimeout | E::KeepaliveTimeout | E::InactivityTimeout | E::Elapsed(_) => {
            Error::new(ErrorKind::Timeout, msg)
        }
        E::NoCommonAlgo { .. } | E::Version | E::UnknownAlgo => {
            Error::new(ErrorKind::ConnectionFailed, msg).with_retryable(false)
        }
        E::NotAuthenticated | E::NoAuthMethod | E::UnsupportedAuthMethod => {
            Error::new(ErrorKind::PermissionDenied, msg)
        }
        E::WrongServerSig
        | E::PacketAuth
        | E::DecryptionError
        | E::Inconsistent
        | E::PacketSize(_)
        | E::StrictKeyExchangeViolation { .. }
        | E::Kex
        | E::KexInit => Error::new(ErrorKind::Protocol, msg),
        E::ChannelOpenFailure(_) | E::RequestDenied => Error::new(ErrorKind::ConnectionFailed, msg),
        _ => Error::new(ErrorKind::ConnectionFailed, msg),
    }
}

async fn within<T>(
    d: Option<Duration>,
    what: &str,
    fut: impl Future<Output = Result<T>>,
) -> Result<T> {
    match d {
        Some(d) => tokio::time::timeout(d, fut)
            .await
            .map_err(|_| Error::timeout(format!("{what} timed out after {d:?}")))?,
        None => fut.await,
    }
}

/// The agent socket for ssh_config `IdentityAgent` (`None` when the
/// keyword is absent), as OpenSSH resolves it: `none` disables the agent;
/// `SSH_AUTH_SOCK` (or no keyword) uses that environment variable; `$NAME`
/// reads the environment variable `NAME` (unset or empty disables the
/// agent, an invalid name is ignored); anything else is a path with `~` and
/// `%` tokens expanded.
fn identity_agent_socket(
    value: Option<&str>,
    expand: &dyn Fn(&str) -> PathBuf,
    getenv: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    let from_env = |name: &str| getenv(name).filter(|s| !s.is_empty()).map(PathBuf::from);
    match value {
        None | Some("SSH_AUTH_SOCK") => from_env("SSH_AUTH_SOCK"),
        Some(a) if a.eq_ignore_ascii_case("none") => None,
        Some(a) => match a.strip_prefix('$') {
            Some(name) => {
                let valid = !name.is_empty()
                    && !name.starts_with(|c: char| c.is_ascii_digit())
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                if !valid {
                    tracing::debug!(
                        "ssh_config IdentityAgent {a:?}: invalid environment variable name"
                    );
                    return None;
                }
                from_env(name)
            }
            None => Some(expand(a)),
        },
    }
}

/// An authenticated SSH connection.
pub struct SshConnection {
    handle: Handle<ClientHandler>,
    desc: String,
    negotiated: Arc<Mutex<Negotiated>>,
}

impl std::fmt::Debug for SshConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConnection")
            .field("target", &self.desc)
            .finish()
    }
}

impl SshConnection {
    /// Connect and authenticate.
    pub async fn connect(t: &Target) -> Result<SshConnection> {
        let desc = t.describe();
        // Known hosts are re-read for every connection, so edits apply
        // without recreating the filesystem.
        let known = KnownHosts::load(&t.known_hosts_files);
        let verifier = HostKeyVerifier::new(t.policy, known, &t.key_host, t.key_port);
        let config = client::Config {
            client_id: SshId::Standard(Cow::Owned(format!(
                "SSH-2.0-fsfast_{}",
                env!("CARGO_PKG_VERSION")
            ))),
            window_size: CHANNEL_WINDOW,
            maximum_packet_size: MAX_PACKET,
            // Inbound channel messages buffered before russh applies TCP
            // backpressure; our reader drains them immediately.
            channel_buffer_size: 512,
            preferred: t.preferred(&verifier.preferred_algorithms()),
            keepalive_interval: t.keepalive,
            // Requests are batched by our writer task; Nagle would only
            // delay the small READ requests.
            nodelay: true,
            ..Default::default()
        };

        let addr = (t.connect_host.as_str(), t.port);
        let tcp = within(t.connect_timeout, &format!("connecting to {desc}"), async {
            tokio::net::TcpStream::connect(addr).await.map_err(|e| {
                let msg = format!("connecting to {desc}: {e}");
                Error::new(Error::from(e).kind(), msg)
            })
        })
        .await?;
        if let Err(e) = tcp.set_nodelay(true) {
            tracing::debug!("set_nodelay failed: {e}");
        }

        let verdict = Arc::new(Mutex::new(None));
        let negotiated = Arc::new(Mutex::new(Negotiated::default()));
        let handler = ClientHandler {
            verifier,
            verdict: verdict.clone(),
            negotiated: negotiated.clone(),
        };
        let handshake = Some(match t.connect_timeout {
            Some(c) => c.min(t.banner_timeout),
            None => t.banner_timeout,
        });
        let res = within(handshake, &format!("SSH handshake with {desc}"), async {
            client::connect_stream(Arc::new(config), tcp, handler)
                .await
                .map_err(|e| map_ssh_error(e, &format!("SSH handshake with {desc}")))
        })
        .await;
        let mut handle = match res {
            Ok(h) => h,
            Err(e) => {
                // A rejected host key surfaces as a generic russh error;
                // report the verifier's reason instead.
                if let Some(v) = verdict.lock().take() {
                    return Err(v);
                }
                return Err(e);
            }
        };
        within(
            Some(t.auth_timeout),
            &format!("authentication to {desc}"),
            auth::authenticate(&mut handle, &t.auth, &desc),
        )
        .await?;
        tracing::debug!(
            "SSH connection to {desc} established: {:?}",
            negotiated.lock()
        );
        Ok(SshConnection {
            handle,
            desc,
            negotiated,
        })
    }

    /// Open a session channel and start the `sftp` subsystem on it.
    pub async fn open_sftp_channel(
        &self,
        timeout: Duration,
    ) -> Result<(ChannelReadHalf, ChannelWriteHalf<Msg>)> {
        let desc = self.desc.clone();
        within(
            Some(timeout),
            &format!("opening the SFTP channel to {desc}"),
            async {
                let mut ch = self.handle.channel_open_session().await.map_err(|e| {
                    map_ssh_error(e, &format!("opening a session channel to {desc}"))
                })?;
                ch.request_subsystem(true, "sftp")
                    .await
                    .map_err(|e| map_ssh_error(e, "requesting the sftp subsystem"))?;
                loop {
                    match ch.wait().await {
                        Some(ChannelMsg::Success) => break,
                        Some(ChannelMsg::Failure) => {
                            return Err(Error::new(
                                ErrorKind::Unsupported,
                                format!("{desc} refused the sftp subsystem"),
                            )
                            .with_detail(Detail::Code("SubsystemRefused".into())));
                        }
                        Some(ChannelMsg::Eof | ChannelMsg::Close) | None => {
                            return Err(Error::connection(format!(
                                "{desc} closed the channel while starting the sftp subsystem"
                            )));
                        }
                        Some(_) => {}
                    }
                }
                Ok(ch.split())
            },
        )
        .await
    }

    /// The algorithms in use (as of the latest key exchange).
    pub fn negotiated(&self) -> Negotiated {
        self.negotiated.lock().clone()
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    /// `user@host:port`.
    pub fn describe(&self) -> &str {
        &self.desc
    }

    /// Send a disconnect message (best effort).
    pub async fn disconnect(&self) {
        let _ = self
            .handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_agent_env_vars() {
        let expand = |v: &str| PathBuf::from(v.replace('~', "/home/u"));
        let getenv = |k: &str| match k {
            "SSH_AUTH_SOCK" => Some("/run/agent.sock".into()),
            "MY_AGENT" => Some("/run/my.sock".into()),
            "EMPTY" => Some("".into()),
            _ => None,
        };
        let r = |v| identity_agent_socket(v, &expand, &getenv);
        assert_eq!(r(None), Some(PathBuf::from("/run/agent.sock")));
        assert_eq!(
            r(Some("SSH_AUTH_SOCK")),
            Some(PathBuf::from("/run/agent.sock"))
        );
        assert_eq!(
            r(Some("$SSH_AUTH_SOCK")),
            Some(PathBuf::from("/run/agent.sock"))
        );
        assert_eq!(r(Some("$MY_AGENT")), Some(PathBuf::from("/run/my.sock")));
        assert_eq!(r(Some("$UNSET_VAR")), None);
        assert_eq!(r(Some("$EMPTY")), None);
        assert_eq!(r(Some("$1BAD")), None);
        assert_eq!(r(Some("none")), None);
        assert_eq!(r(Some("~/agent")), Some(PathBuf::from("/home/u/agent")));
    }

    fn resolve_with_config(text: &str, port: u16) -> Target {
        let dir = tempfile::tempdir().unwrap();
        let cfgf = dir.path().join("config");
        std::fs::write(&cfgf, text).unwrap();
        let mut cfg = SftpConfig::new("example.test").with_port(port);
        cfg.username = Some("u".into());
        cfg.ssh_config = SshConfigSource::Files(vec![cfgf]);
        Target::resolve(&cfg).unwrap()
    }

    #[test]
    fn host_key_alias_is_looked_up_without_port() {
        // OpenSSH looks a HostKeyAlias up verbatim, whatever the port.
        let t = resolve_with_config("Host *\n  HostKeyAlias myalias\n", 2222);
        assert_eq!(t.key_host, "myalias");
        assert_eq!(known_hosts::lookup_name(&t.key_host, t.key_port), "myalias");
        // Without an alias, non-default ports use `[host]:port`.
        let t = resolve_with_config("Host other\n  User x\n", 2222);
        assert_eq!(
            known_hosts::lookup_name(&t.key_host, t.key_port),
            "[example.test]:2222"
        );
    }
}
