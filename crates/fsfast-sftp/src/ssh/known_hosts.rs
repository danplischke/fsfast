//! `known_hosts` files and the host key policy.
//!
//! # Policy (fsspec's `host_key_policy`)
//!
//! The server's host key is looked up in the known-hosts files (by default
//! `~/.ssh/known_hosts`, `~/.ssh/known_hosts2`, `/etc/ssh/ssh_known_hosts`
//! and `/etc/ssh/ssh_known_hosts2`, or what `known_hosts`/ssh_config name)
//! and in the keys this process accepted earlier:
//!
//! * a key listed for the host is accepted in every mode;
//! * a key marked `@revoked`, or a key of an algorithm for which the host has
//!   a *different* key on record (a changed host key, the classic
//!   man-in-the-middle sign), is **rejected in every mode**, including
//!   `auto_add`;
//! * an unknown key (no entry for the host, or only entries of other key
//!   types) is handled by the policy: `auto_add` (fsspec's default) accepts
//!   it and remembers it for the rest of the process, so a later connection
//!   presenting another key is rejected; `warning` logs a warning and
//!   accepts it without remembering; `reject` refuses it, even when an
//!   `auto_add` filesystem of the same process accepted it before (only the
//!   known-hosts files vouch for a key under `reject`).
//!
//! Nothing is ever written to a known-hosts file (paramiko's AutoAddPolicy
//! does not save either). Host names are matched case-insensitively; hashed
//! entries (`|1|salt|hash`, HMAC-SHA1) are supported; non-default ports are
//! looked up as `[host]:port`, as OpenSSH does. `@cert-authority` lines are
//! ignored (host certificates are not negotiated).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, KeyInit, Mac};
use parking_lot::Mutex;
use russh::keys::{Algorithm, PublicKey};
use sha1::Sha1;

use fsfast_core::{Detail, Error, ErrorKind};

/// fsspec's `host_key_policy` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostKeyPolicy {
    /// Accept and remember unknown keys (paramiko `AutoAddPolicy`).
    #[default]
    AutoAdd,
    /// Log a warning and accept unknown keys (paramiko `WarningPolicy`).
    Warning,
    /// Refuse unknown keys (paramiko `RejectPolicy`).
    Reject,
}

impl HostKeyPolicy {
    /// Parse fsspec's names (`"auto_add"`, `"warning"`, `"reject"`) and the
    /// paramiko class names the Python layer may pass through.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto_add" | "AutoAddPolicy" => Some(HostKeyPolicy::AutoAdd),
            "warning" | "WarningPolicy" => Some(HostKeyPolicy::Warning),
            "reject" | "RejectPolicy" => Some(HostKeyPolicy::Reject),
            _ => None,
        }
    }

    /// The fsspec name.
    pub fn as_str(self) -> &'static str {
        match self {
            HostKeyPolicy::AutoAdd => "auto_add",
            HostKeyPolicy::Warning => "warning",
            HostKeyPolicy::Reject => "reject",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Marker {
    None,
    CertAuthority,
    Revoked,
}

#[derive(Debug, Clone)]
enum HostPattern {
    Hashed { salt: Vec<u8>, hash: Vec<u8> },
    Plain { pattern: String, negated: bool },
}

#[derive(Debug, Clone)]
struct Entry {
    marker: Marker,
    hosts: Vec<HostPattern>,
    key: PublicKey,
    source: String,
}

/// Parsed known-hosts entries from one or more files.
#[derive(Debug, Clone, Default)]
pub struct KnownHosts {
    entries: Vec<Entry>,
}

/// Outcome of looking a key up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyMatch {
    /// The key is listed for the host.
    Known,
    /// The host has a different key of the same type (`source` names the
    /// file and line of the conflicting entry).
    Mismatch {
        /// `file:line` of the entry that conflicts.
        source: String,
    },
    /// The key is marked `@revoked`.
    Revoked {
        /// `file:line` of the revocation.
        source: String,
    },
    /// No entry for this host and key type.
    Unknown,
}

/// The name OpenSSH looks up: `host`, or `[host]:port` for other ports.
pub fn lookup_name(host: &str, port: u16) -> String {
    let h = host.to_ascii_lowercase();
    if port == 22 {
        h
    } else {
        format!("[{h}]:{port}")
    }
}

fn same_key_type(a: &PublicKey, b: &PublicKey) -> bool {
    match (a.algorithm(), b.algorithm()) {
        (Algorithm::Rsa { .. }, Algorithm::Rsa { .. }) => true,
        (x, y) => x == y,
    }
}

fn same_key(a: &PublicKey, b: &PublicKey) -> bool {
    a.key_data() == b.key_data()
}

impl KnownHosts {
    /// Load `paths` in order. Missing files are skipped; unparsable lines
    /// are skipped with a debug log (as OpenSSH does).
    pub fn load(paths: &[PathBuf]) -> Self {
        let mut kh = KnownHosts::default();
        for p in paths {
            match std::fs::read_to_string(p) {
                Ok(text) => kh.add_text(&text, &p.display().to_string()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => tracing::debug!("cannot read known_hosts file {}: {e}", p.display()),
            }
        }
        kh
    }

    /// Parse known-hosts text; `source` labels entries in messages.
    pub fn parse(text: &str, source: &str) -> Self {
        let mut kh = KnownHosts::default();
        kh.add_text(text, source);
        kh
    }

    fn add_text(&mut self, text: &str, source: &str) {
        for (n, line) in text.lines().enumerate() {
            match parse_line(line, &format!("{source}:{}", n + 1)) {
                Ok(Some(e)) => self.entries.push(e),
                Ok(None) => {}
                Err(why) => tracing::debug!("{source}:{}: skipping known_hosts line: {why}", n + 1),
            }
        }
    }

    /// Number of usable entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no entries were loaded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn entries_for<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Entry> + 'a {
        self.entries
            .iter()
            .filter(move |e| host_matches(&e.hosts, name))
    }

    /// Look up `key` presented by `host`:`port`.
    pub fn check(&self, host: &str, port: u16, key: &PublicKey) -> HostKeyMatch {
        let name = lookup_name(host, port);
        let mut mismatch = None;
        let mut known = false;
        for e in self.entries_for(&name) {
            match e.marker {
                Marker::Revoked if same_key(&e.key, key) => {
                    return HostKeyMatch::Revoked {
                        source: e.source.clone(),
                    };
                }
                Marker::None if same_key(&e.key, key) => known = true,
                Marker::None if same_key_type(&e.key, key) && mismatch.is_none() => {
                    mismatch = Some(e.source.clone());
                }
                _ => {}
            }
        }
        if known {
            HostKeyMatch::Known
        } else if let Some(source) = mismatch {
            HostKeyMatch::Mismatch { source }
        } else {
            HostKeyMatch::Unknown
        }
    }

    /// Key algorithms recorded for the host, in file order (used to prefer
    /// them during key exchange, as OpenSSH does).
    pub fn algorithms_for(&self, host: &str, port: u16) -> Vec<Algorithm> {
        let name = lookup_name(host, port);
        let mut out: Vec<Algorithm> = Vec::new();
        for e in self.entries_for(&name) {
            if e.marker == Marker::None {
                let a = e.key.algorithm();
                if !out.contains(&a) {
                    out.push(a);
                }
            }
        }
        out
    }
}

fn host_matches(pats: &[HostPattern], name: &str) -> bool {
    let mut positive = false;
    for p in pats {
        match p {
            HostPattern::Hashed { salt, hash } => {
                let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(salt) else {
                    continue;
                };
                mac.update(name.as_bytes());
                // Constant time is not needed (the hash is not secret), but
                // `verify_slice` is the clean API for the comparison.
                if mac.verify_slice(hash).is_ok() {
                    positive = true;
                }
            }
            HostPattern::Plain { pattern, negated } => {
                if super::config::wildcard_match(pattern, name, true) {
                    if *negated {
                        return false;
                    }
                    positive = true;
                }
            }
        }
    }
    positive
}

fn parse_line(line: &str, source: &str) -> Result<Option<Entry>, String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let mut fields = line.split_whitespace();
    let mut first = fields.next().ok_or("empty line")?;
    let marker = match first {
        "@revoked" => Marker::Revoked,
        "@cert-authority" => Marker::CertAuthority,
        m if m.starts_with('@') => return Err(format!("unknown marker {m}")),
        _ => Marker::None,
    };
    if marker != Marker::None {
        first = fields.next().ok_or("missing host patterns")?;
    }
    let keytype = fields.next().ok_or("missing key type")?;
    let blob = fields.next().ok_or("missing key")?;
    let key = russh::keys::parse_public_key_base64(blob).map_err(|e| format!("bad key: {e}"))?;
    if key.algorithm().as_str() != keytype
        && !(keytype == "ssh-rsa" && matches!(key.algorithm(), Algorithm::Rsa { .. }))
    {
        return Err(format!(
            "key type {keytype} does not match the key ({})",
            key.algorithm().as_str()
        ));
    }
    let mut hosts = Vec::new();
    for p in first.split(',').filter(|p| !p.is_empty()) {
        if let Some(h) = p.strip_prefix("|1|") {
            let (salt, hash) = h.split_once('|').ok_or("malformed hashed host")?;
            hosts.push(HostPattern::Hashed {
                salt: B64.decode(salt).map_err(|e| format!("bad salt: {e}"))?,
                hash: B64.decode(hash).map_err(|e| format!("bad hash: {e}"))?,
            });
        } else if let Some(n) = p.strip_prefix('!') {
            hosts.push(HostPattern::Plain {
                pattern: n.to_owned(),
                negated: true,
            });
        } else {
            hosts.push(HostPattern::Plain {
                pattern: p.to_owned(),
                negated: false,
            });
        }
    }
    Ok(Some(Entry {
        marker,
        hosts,
        key,
        source: source.to_owned(),
    }))
}

/// Keys accepted by `auto_add` in this process, per `(lookup name)`.
static LEARNED: LazyLock<Mutex<HashMap<String, Vec<PublicKey>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Applies the policy to a presented key.
#[derive(Debug, Clone)]
pub struct HostKeyVerifier {
    policy: HostKeyPolicy,
    known: KnownHosts,
    host: String,
    port: u16,
}

impl HostKeyVerifier {
    /// A verifier for `host` (the name to look up: `HostKeyAlias` or the
    /// connection host) on `port`.
    pub fn new(policy: HostKeyPolicy, known: KnownHosts, host: &str, port: u16) -> Self {
        HostKeyVerifier {
            policy,
            known,
            host: host.to_owned(),
            port,
        }
    }

    /// Algorithms to prefer during key exchange.
    pub fn preferred_algorithms(&self) -> Vec<Algorithm> {
        let mut v = self.known.algorithms_for(&self.host, self.port);
        let name = lookup_name(&self.host, self.port);
        if let Some(keys) = LEARNED.lock().get(&name) {
            for k in keys {
                let a = k.algorithm();
                if !v.contains(&a) {
                    v.push(a);
                }
            }
        }
        v
    }

    /// Accept or reject `key`.
    pub fn verify(&self, key: &PublicKey) -> fsfast_core::Result<()> {
        let name = lookup_name(&self.host, self.port);
        let fp = key.fingerprint(Default::default());
        let reject = |code: &str, msg: String| {
            Err(Error::new(ErrorKind::ConnectionFailed, msg)
                .with_detail(Detail::Code(code.to_owned()))
                .with_retryable(false))
        };
        match self.known.check(&self.host, self.port, key) {
            HostKeyMatch::Known => return Ok(()),
            HostKeyMatch::Revoked { source } => {
                return reject(
                    "HostKeyRevoked",
                    format!(
                        "host key {fp} ({}) of {name} is marked @revoked in {source}",
                        key.algorithm().as_str()
                    ),
                );
            }
            HostKeyMatch::Mismatch { source } => {
                return reject(
                    "HostKeyMismatch",
                    format!(
                        "host key verification failed: {name} presented {} key {fp}, which \
                         differs from the key recorded in {source} (possible \
                         man-in-the-middle attack)",
                        key.algorithm().as_str()
                    ),
                );
            }
            HostKeyMatch::Unknown => {}
        }
        let mut learned = LEARNED.lock();
        if let Some(keys) = learned.get(&name) {
            // A key learned by `auto_add` was never verified, so it does not
            // make the key "known" for `reject` (which, like a fresh
            // paramiko client with RejectPolicy, only trusts the known-hosts
            // files); it still pins the host against a different key.
            if keys.iter().any(|k| same_key(k, key)) {
                if self.policy != HostKeyPolicy::Reject {
                    return Ok(());
                }
            } else if keys.iter().any(|k| same_key_type(k, key)) {
                return reject(
                    "HostKeyMismatch",
                    format!(
                        "host key verification failed: {name} presented {} key {fp}, which \
                         differs from the key accepted earlier in this process (possible \
                         man-in-the-middle attack)",
                        key.algorithm().as_str()
                    ),
                );
            }
        }
        match self.policy {
            HostKeyPolicy::AutoAdd => {
                tracing::info!(
                    "accepting unknown {} host key {fp} for {name} (host_key_policy=auto_add)",
                    key.algorithm().as_str()
                );
                learned.entry(name).or_default().push(key.clone());
                Ok(())
            }
            HostKeyPolicy::Warning => {
                tracing::warn!(
                    "unknown {} host key {fp} for {name} (host_key_policy=warning)",
                    key.algorithm().as_str()
                );
                Ok(())
            }
            HostKeyPolicy::Reject => reject(
                "HostKeyUnknown",
                format!(
                    "{name} is not in known_hosts and host_key_policy is 'reject' \
                     (server {} key {fp})",
                    key.algorithm().as_str()
                ),
            ),
        }
    }
}

/// Default known-hosts files: the user's, then the system's.
pub fn default_files(home: Option<&Path>) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(h) = home {
        v.push(h.join(".ssh/known_hosts"));
        v.push(h.join(".ssh/known_hosts2"));
    }
    v.push(PathBuf::from("/etc/ssh/ssh_known_hosts"));
    v.push(PathBuf::from("/etc/ssh/ssh_known_hosts2"));
    v
}

/// Forget every key accepted by `auto_add` (for tests).
#[doc(hidden)]
pub fn forget_learned_keys() {
    LEARNED.lock().clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    // Two ed25519 keys and an ecdsa key (public halves only).
    const K1: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIE3s/G1nMC66ima9H+Z6Sv0pAYq0tUewS/52TAp/oZ+n";
    const K2: &str = "AAAAC3NzaC1lZDI1NTE5AAAAILRE8DSyFxEgdZMM4miMVjqM5YgT1bwkzz5XRrp95Nyg";
    const EC: &str = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFKcB7s+J+rjvBRb2Mld/UCy1ftO9/9jAZYod3XRAoYsQfCvu0xWBC+W5jfOwpfzFDKaZJCcRQuyhoMqftIA7oY=";

    fn key(b: &str) -> PublicKey {
        russh::keys::parse_public_key_base64(b).unwrap()
    }

    fn hashed(name: &str, salt: &[u8]) -> String {
        let mut mac = Hmac::<Sha1>::new_from_slice(salt).unwrap();
        mac.update(name.as_bytes());
        format!(
            "|1|{}|{}",
            B64.encode(salt),
            B64.encode(mac.finalize().into_bytes())
        )
    }

    #[test]
    fn plain_and_hashed_entries_with_ports() {
        let text = format!(
            "# c\nexample.com,10.0.0.1 ssh-ed25519 {K1}\n{} ssh-ed25519 {K1} comment here\n\
             [Alt.Example]:2222 ssh-ed25519 {K2}\n",
            hashed("[127.0.0.1]:2222", b"0123456789abcdefghij")
        );
        let kh = KnownHosts::parse(&text, "kh");
        assert_eq!(kh.len(), 3);
        assert_eq!(kh.check("EXAMPLE.com", 22, &key(K1)), HostKeyMatch::Known);
        assert_eq!(kh.check("10.0.0.1", 22, &key(K1)), HostKeyMatch::Known);
        // Port 2222 entries do not match port 22 and vice versa.
        assert_eq!(
            kh.check("example.com", 2222, &key(K1)),
            HostKeyMatch::Unknown
        );
        assert_eq!(kh.check("127.0.0.1", 2222, &key(K1)), HostKeyMatch::Known);
        assert_eq!(kh.check("127.0.0.1", 22, &key(K1)), HostKeyMatch::Unknown);
        assert_eq!(kh.check("alt.example", 2222, &key(K2)), HostKeyMatch::Known);
        assert_eq!(
            kh.check("127.0.0.1", 2222, &key(K2)),
            HostKeyMatch::Mismatch {
                source: "kh:3".into()
            }
        );
        // A different key type is unknown, not a mismatch.
        assert_eq!(kh.check("example.com", 22, &key(EC)), HostKeyMatch::Unknown);
        assert_eq!(
            kh.algorithms_for("127.0.0.1", 2222),
            vec![Algorithm::Ed25519]
        );
    }

    #[test]
    fn wildcards_negation_markers_and_garbage() {
        let text = format!(
            "*.corp,!evil.corp ssh-ed25519 {K1}\n@revoked * ssh-ed25519 {K2}\n\
             @cert-authority *.corp ssh-ed25519 {K2}\nbroken line\n\
             host ssh-rsa {K1}\nhost ssh-ed25519 not-base64!\n@bogus h ssh-ed25519 {K1}\n"
        );
        let kh = KnownHosts::parse(&text, "kh");
        assert_eq!(kh.len(), 3);
        assert_eq!(kh.check("a.corp", 22, &key(K1)), HostKeyMatch::Known);
        assert_eq!(kh.check("evil.corp", 22, &key(K1)), HostKeyMatch::Unknown);
        assert!(matches!(
            kh.check("anything", 22, &key(K2)),
            HostKeyMatch::Revoked { .. }
        ));
    }

    #[test]
    fn policy_matrix() {
        forget_learned_keys();
        let kh = KnownHosts::parse(&format!("[known]:2200 ssh-ed25519 {K1}\n"), "kh");
        for policy in [
            HostKeyPolicy::AutoAdd,
            HostKeyPolicy::Warning,
            HostKeyPolicy::Reject,
        ] {
            let v = HostKeyVerifier::new(policy, kh.clone(), "known", 2200);
            v.verify(&key(K1)).unwrap();
            let e = v.verify(&key(K2)).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::ConnectionFailed);
            assert!(!e.is_retryable());
            assert!(e.to_string().contains("HostKeyMismatch"), "{e}");
        }
        let unknown = |p| HostKeyVerifier::new(p, kh.clone(), "fresh-host", 2200);
        let e = unknown(HostKeyPolicy::Reject).verify(&key(K2)).unwrap_err();
        assert!(e.to_string().contains("HostKeyUnknown"), "{e}");
        // warning accepts without remembering...
        unknown(HostKeyPolicy::Warning).verify(&key(K2)).unwrap();
        unknown(HostKeyPolicy::Warning).verify(&key(K1)).unwrap();
        // ...auto_add remembers: a later different key of the same type is
        // rejected even under auto_add. A key learned (unverified) by
        // auto_add must not satisfy `reject`, which trusts only the
        // known-hosts files.
        unknown(HostKeyPolicy::AutoAdd).verify(&key(K2)).unwrap();
        unknown(HostKeyPolicy::AutoAdd).verify(&key(K2)).unwrap();
        unknown(HostKeyPolicy::Warning).verify(&key(K2)).unwrap();
        let e = unknown(HostKeyPolicy::Reject).verify(&key(K2)).unwrap_err();
        assert!(e.to_string().contains("HostKeyUnknown"), "{e}");
        let e = unknown(HostKeyPolicy::Warning)
            .verify(&key(K1))
            .unwrap_err();
        assert!(e.to_string().contains("HostKeyMismatch"), "{e}");
        let e = unknown(HostKeyPolicy::AutoAdd)
            .verify(&key(K1))
            .unwrap_err();
        assert!(e.to_string().contains("earlier in this process"), "{e}");
        assert_eq!(
            unknown(HostKeyPolicy::Reject).preferred_algorithms(),
            vec![Algorithm::Ed25519]
        );
        forget_learned_keys();
    }

    #[test]
    fn policy_names() {
        assert_eq!(
            HostKeyPolicy::parse("auto_add"),
            Some(HostKeyPolicy::AutoAdd)
        );
        assert_eq!(
            HostKeyPolicy::parse("RejectPolicy"),
            Some(HostKeyPolicy::Reject)
        );
        assert_eq!(HostKeyPolicy::parse("nope"), None);
        assert_eq!(HostKeyPolicy::Warning.as_str(), "warning");
        assert_eq!(lookup_name("H", 22), "h");
        assert_eq!(lookup_name("H", 2), "[h]:2");
    }
}
