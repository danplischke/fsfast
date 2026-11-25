//! Client authentication, in paramiko's order:
//!
//! 1. `pkey` (a private key given in memory);
//! 2. `key_filename` files, then ssh_config `IdentityFile`s;
//! 3. the ssh-agent's keys (`allow_agent`, `SSH_AUTH_SOCK` or ssh_config
//!    `IdentityAgent`; with `IdentitiesOnly yes` only keys matching an
//!    identity file);
//! 4. `~/.ssh/id_rsa`, `id_ecdsa`, `id_ed25519` (`look_for_keys`);
//! 5. the password: `password` authentication, or `keyboard-interactive`
//!    answering every prompt with the password when the server only offers
//!    that (paramiko's `auth_password` fallback).
//!
//! A `none` request first learns which methods the server accepts, so keys
//! are only tried when `publickey` is offered. Encrypted keys are unlocked
//! with `passphrase`, else with `password` (as paramiko does); key
//! decryption (bcrypt KDF) runs on the blocking pool. Partial success
//! (multi-factor) continues with the remaining methods.

use std::path::PathBuf;
use std::sync::Arc;

use russh::MethodKind;
use russh::client::{AuthResult, Handle, Handler, KeyboardInteractiveAuthResponse};
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::AgentClient;
use russh::keys::{Algorithm, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey};

use fsfast_core::{Error, ErrorKind, Result};

use super::connect::map_ssh_error;
use crate::options::Secret;

/// Authentication material for one destination.
#[derive(Debug, Clone)]
pub struct AuthParams {
    /// Remote user.
    pub user: String,
    /// Password (also the fallback passphrase).
    pub password: Option<Secret>,
    /// Passphrase for encrypted keys.
    pub passphrase: Option<Secret>,
    /// In-memory private key (OpenSSH or PEM text).
    pub pkey: Option<Secret>,
    /// `key_filename` plus ssh_config `IdentityFile`, expanded.
    pub identity_files: Vec<PathBuf>,
    /// `~/.ssh/id_*` candidates (`look_for_keys`).
    pub default_identity_files: Vec<PathBuf>,
    /// ssh_config `IdentitiesOnly`.
    pub identities_only: bool,
    /// ssh-agent socket, if the agent may be used.
    pub agent_socket: Option<PathBuf>,
    /// paramiko `disabled_algorithms["pubkeys"]`.
    pub disabled_pubkeys: Vec<String>,
}

/// Why each attempt failed, for the final error message.
#[derive(Default)]
struct Attempts {
    notes: Vec<String>,
}

impl Attempts {
    fn note(&mut self, s: impl Into<String>) {
        self.notes.push(s.into());
    }
}

enum Step {
    Done,
    Continue,
}

fn methods_list(m: &[MethodKind]) -> String {
    let v: Vec<&str> = m.iter().map(<&str>::from).collect();
    v.join(",")
}

struct Session<'a, H: Handler> {
    handle: &'a mut Handle<H>,
    p: &'a AuthParams,
    desc: &'a str,
    methods: Vec<MethodKind>,
    rsa_hash: Option<Option<Option<HashAlg>>>,
    attempts: Attempts,
}

impl<H: Handler> Session<'_, H> {
    fn allows(&self, k: MethodKind) -> bool {
        self.methods.contains(&k)
    }

    fn outcome(&mut self, r: AuthResult, what: &str) -> Step {
        match r {
            AuthResult::Success => Step::Done,
            AuthResult::Failure {
                remaining_methods,
                partial_success,
            } => {
                self.methods = remaining_methods.to_vec();
                if partial_success {
                    self.attempts
                        .note(format!("{what}: accepted, more authentication required"));
                } else {
                    self.attempts.note(format!("{what}: rejected"));
                }
                Step::Continue
            }
        }
    }

    /// The RSA signature hash to use, honouring server-sig-algs and
    /// `disabled_algorithms["pubkeys"]`. `None` inside means `ssh-rsa`
    /// (SHA-1); `Err` means every variant is disabled.
    async fn rsa_hash(&mut self) -> std::result::Result<Option<HashAlg>, ()> {
        let server = match self.rsa_hash {
            Some(h) => h,
            None => {
                let h = self.handle.best_supported_rsa_hash().await.ok().flatten();
                self.rsa_hash = Some(h);
                h
            }
        };
        let disabled = |name: &str| self.p.disabled_pubkeys.iter().any(|d| d == name);
        // Server preference (or SHA-512 when the server did not say), then
        // the other variants as fallbacks.
        let first = server.unwrap_or(Some(HashAlg::Sha512));
        let mut order = vec![first, Some(HashAlg::Sha512), Some(HashAlg::Sha256), None];
        if server.is_some() {
            // The server told us what it accepts; do not offer SHA-1
            // unless it asked for exactly that.
            order.retain(|h| h.is_some() || first.is_none());
        }
        for h in order {
            let name = Algorithm::Rsa { hash: h }.to_string();
            if !disabled(&name) {
                return Ok(h);
            }
        }
        Err(())
    }

    async fn try_private_key(&mut self, key: PrivateKey, label: &str) -> Result<Step> {
        let hash = if key.algorithm().is_rsa() {
            match self.rsa_hash().await {
                Ok(h) => h,
                Err(()) => {
                    self.attempts
                        .note(format!("{label}: RSA disabled by disabled_algorithms"));
                    return Ok(Step::Continue);
                }
            }
        } else {
            if self
                .p
                .disabled_pubkeys
                .iter()
                .any(|d| d == key.algorithm().as_str())
            {
                self.attempts.note(format!(
                    "{label}: {} disabled by disabled_algorithms",
                    key.algorithm().as_str()
                ));
                return Ok(Step::Continue);
            }
            None
        };
        let k = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
        let r = self
            .handle
            .authenticate_publickey(self.p.user.clone(), k)
            .await
            .map_err(|e| map_ssh_error(e, &format!("public key authentication to {}", self.desc)))?;
        Ok(self.outcome(r, label))
    }

    async fn try_agent(&mut self, socket: &PathBuf, only: &[PublicKey]) -> Result<Step> {
        let mut agent = match AgentClient::connect_uds(socket).await {
            Ok(a) => a,
            Err(e) => {
                self.attempts.note(format!(
                    "ssh-agent at {}: cannot connect: {e}",
                    socket.display()
                ));
                return Ok(Step::Continue);
            }
        };
        let ids = match agent.request_identities().await {
            Ok(ids) => ids,
            Err(e) => {
                self.attempts.note(format!("ssh-agent: listing keys failed: {e}"));
                return Ok(Step::Continue);
            }
        };
        for id in ids {
            let AgentIdentity::PublicKey { key, comment } = id else {
                continue; // certificates are not supported
            };
            if self.p.identities_only && !only.iter().any(|k| k.key_data() == key.key_data()) {
                continue;
            }
            if !self.allows(MethodKind::PublicKey) {
                break;
            }
            let label = format!("ssh-agent key {comment:?}");
            let hash = if key.algorithm().is_rsa() {
                match self.rsa_hash().await {
                    Ok(h) => h,
                    Err(()) => continue,
                }
            } else {
                if self
                    .p
                    .disabled_pubkeys
                    .iter()
                    .any(|d| d == key.algorithm().as_str())
                {
                    continue;
                }
                None
            };
            match self
                .handle
                .authenticate_publickey_with(self.p.user.clone(), key, hash, &mut agent)
                .await
            {
                Ok(r) => {
                    if let Step::Done = self.outcome(r, &label) {
                        return Ok(Step::Done);
                    }
                }
                Err(e) => self.attempts.note(format!("{label}: agent failed to sign: {e}")),
            }
        }
        Ok(Step::Continue)
    }

    async fn try_password(&mut self, pw: &Secret) -> Result<Step> {
        if self.allows(MethodKind::Password) {
            let r = self
                .handle
                .authenticate_password(self.p.user.clone(), pw.expose().to_owned())
                .await
                .map_err(|e| map_ssh_error(e, &format!("password authentication to {}", self.desc)))?;
            return Ok(self.outcome(r, "password"));
        }
        if !self.allows(MethodKind::KeyboardInteractive) {
            return Ok(Step::Continue);
        }
        let map = |e| map_ssh_error(e, "keyboard-interactive authentication");
        let mut resp = self
            .handle
            .authenticate_keyboard_interactive_start(self.p.user.clone(), None)
            .await
            .map_err(map)?;
        // Each round answers every prompt with the password (paramiko's
        // `auth_interactive_dumb` behaviour); bound the rounds so a server
        // cannot keep us here forever.
        for _ in 0..16 {
            match resp {
                KeyboardInteractiveAuthResponse::Success => return Ok(Step::Done),
                KeyboardInteractiveAuthResponse::Failure {
                    remaining_methods,
                    partial_success,
                } => {
                    return Ok(self.outcome(
                        AuthResult::Failure {
                            remaining_methods,
                            partial_success,
                        },
                        "keyboard-interactive",
                    ));
                }
                KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                    let answers = prompts.iter().map(|_| pw.expose().to_owned()).collect();
                    resp = self
                        .handle
                        .authenticate_keyboard_interactive_respond(answers)
                        .await
                        .map_err(map)?;
                }
            }
        }
        self.attempts
            .note("keyboard-interactive: too many prompt rounds");
        Ok(Step::Continue)
    }
}

/// Decode a private key on the blocking pool. `Ok(None)` when the file does
/// not exist.
async fn load_key(
    source: KeySource,
    passphrase: Option<Secret>,
) -> std::result::Result<Option<PrivateKey>, String> {
    tokio::task::spawn_blocking(move || {
        let text = match &source {
            KeySource::Text(t) => t.expose().to_owned(),
            KeySource::File(p) => match std::fs::read_to_string(p) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(format!("cannot read: {e}")),
            },
        };
        let text = zeroize::Zeroizing::new(text);
        // russh reports a missing passphrase as KeyIsEncrypted only for
        // OpenSSH-format keys; recognise encrypted PEM and PKCS#8 here.
        if passphrase.is_none()
            && (text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
                || text.contains("Proc-Type: 4,ENCRYPTED"))
        {
            return Err(ENCRYPTED.into());
        }
        match russh::keys::decode_secret_key(&text, passphrase.as_ref().map(Secret::expose)) {
            Ok(k) => Ok(Some(k)),
            Err(russh::keys::Error::KeyIsEncrypted) => Err(ENCRYPTED.into()),
            Err(e) => Err(format!("cannot decode: {e}")),
        }
    })
    .await
    .unwrap_or_else(|e| Err(format!("key loading task failed: {e}")))
}

const ENCRYPTED: &str = "the key is encrypted and no passphrase or password was given";

enum KeySource {
    Text(Secret),
    File(PathBuf),
}

/// Public key next to an identity file (`<file>.pub`), for IdentitiesOnly.
async fn sidecar_public_key(path: &std::path::Path) -> Option<PublicKey> {
    let mut p = path.as_os_str().to_owned();
    p.push(".pub");
    let p = PathBuf::from(p);
    tokio::task::spawn_blocking(move || russh::keys::load_public_key(p).ok())
        .await
        .ok()
        .flatten()
}

/// Authenticate `p.user` on `handle`.
pub async fn authenticate<H: Handler>(
    handle: &mut Handle<H>,
    p: &AuthParams,
    desc: &str,
) -> Result<()> {
    let first = handle
        .authenticate_none(p.user.clone())
        .await
        .map_err(|e| map_ssh_error(e, &format!("authentication to {desc}")))?;
    let methods = match first {
        AuthResult::Success => return Ok(()),
        AuthResult::Failure {
            remaining_methods, ..
        } => remaining_methods.to_vec(),
    };
    let offered = methods_list(&methods);
    let mut s = Session {
        handle,
        p,
        desc,
        methods,
        rsa_hash: None,
        attempts: Attempts::default(),
    };
    let passphrase = p.passphrase.clone().or_else(|| p.password.clone());

    if let Some(pk) = &p.pkey {
        match load_key(KeySource::Text(pk.clone()), passphrase.clone()).await {
            Ok(Some(k)) if s.allows(MethodKind::PublicKey) => {
                if let Step::Done = s.try_private_key(k, "pkey").await? {
                    return Ok(());
                }
            }
            Ok(_) => {}
            Err(why) => {
                // An unusable explicit key is a configuration error worth
                // reporting even if another method succeeds later.
                s.attempts.note(format!("pkey: {why}"));
            }
        }
    }

    let mut identity_pubkeys = Vec::new();
    for f in &p.identity_files {
        match load_key(KeySource::File(f.clone()), passphrase.clone()).await {
            Ok(Some(k)) => {
                identity_pubkeys.push(k.public_key().clone());
                if s.allows(MethodKind::PublicKey)
                    && let Step::Done = s
                        .try_private_key(k, &format!("key {}", f.display()))
                        .await?
                {
                    return Ok(());
                }
            }
            Ok(None) => s.attempts.note(format!("key {}: not found", f.display())),
            Err(why) => {
                if let Some(pk) = sidecar_public_key(f).await {
                    identity_pubkeys.push(pk);
                }
                s.attempts.note(format!("key {}: {why}", f.display()));
            }
        }
    }

    if let Some(sock) = &p.agent_socket
        && s.allows(MethodKind::PublicKey)
        && let Step::Done = s.try_agent(sock, &identity_pubkeys).await?
    {
        return Ok(());
    }

    for f in &p.default_identity_files {
        if !s.allows(MethodKind::PublicKey) {
            break;
        }
        match load_key(KeySource::File(f.clone()), passphrase.clone()).await {
            Ok(Some(k)) => {
                if let Step::Done = s
                    .try_private_key(k, &format!("key {}", f.display()))
                    .await?
                {
                    return Ok(());
                }
            }
            Ok(None) => {}
            Err(why) => s.attempts.note(format!("key {}: {why}", f.display())),
        }
    }

    if let Some(pw) = &p.password
        && let Step::Done = s.try_password(pw).await?
    {
        return Ok(());
    }

    let tried = if s.attempts.notes.is_empty() {
        "no usable credentials (give a password, a key or an agent)".to_owned()
    } else {
        s.attempts.notes.join("; ")
    };
    Err(Error::new(
        ErrorKind::PermissionDenied,
        format!("authentication to {desc} failed (server offers: {offered}): {tried}"),
    )
    .with_retryable(false))
}
