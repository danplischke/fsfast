//! A subset of OpenSSH's client configuration (`ssh_config(5)`).
//!
//! Supported: `Host` blocks (patterns with `*`/`?` wildcards and `!`
//! negation, matched case-insensitively against the alias as given),
//! `Match` with the `all`, `host`, `originalhost`, `user` and `localuser`
//! criteria (other criteria never match), `Include` (globs in the last path
//! component, relative to `~/.ssh` or `/etc/ssh`, conditional on the
//! enclosing block), and the keywords listed on [`HostConfig`]. As in
//! OpenSSH the first value obtained for a keyword wins, except for
//! `IdentityFile`, which accumulates.
//!
//! `ProxyJump` and `ProxyCommand` are parsed so a connection can refuse to
//! silently bypass them (they are not supported).

use std::path::{Path, PathBuf};
use std::time::Duration;

use fsfast_core::{Error, Result};

/// Maximum `Include` nesting (OpenSSH uses 16).
const MAX_INCLUDE_DEPTH: usize = 16;

/// Settings resolved for one destination.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostConfig {
    /// `HostName`: the real host to connect to (`%h` expanded).
    pub hostname: Option<String>,
    /// `Port`.
    pub port: Option<u16>,
    /// `User`.
    pub user: Option<String>,
    /// `IdentityFile`s, in order (tokens not yet expanded).
    pub identity_files: Vec<String>,
    /// `IdentitiesOnly`.
    pub identities_only: Option<bool>,
    /// `IdentityAgent` (`none` disables the agent; `SSH_AUTH_SOCK` means
    /// the environment variable).
    pub identity_agent: Option<String>,
    /// `UserKnownHostsFile` (several files allowed; `none` disables).
    pub user_known_hosts_files: Option<Vec<String>>,
    /// `GlobalKnownHostsFile`.
    pub global_known_hosts_files: Option<Vec<String>>,
    /// `StrictHostKeyChecking` (raw value, lower-cased).
    pub strict_host_key_checking: Option<String>,
    /// `HostKeyAlias`: the name to look up in known_hosts.
    pub host_key_alias: Option<String>,
    /// `ConnectTimeout`.
    pub connect_timeout: Option<Duration>,
    /// `Compression`.
    pub compression: Option<bool>,
    /// `ServerAliveInterval`.
    pub server_alive_interval: Option<Duration>,
    /// `ProxyJump` (unsupported; recorded to refuse the connection).
    pub proxy_jump: Option<String>,
    /// `ProxyCommand` (unsupported; recorded to refuse the connection).
    pub proxy_command: Option<String>,
}

/// Values needed while evaluating `Match` and expanding tokens.
#[derive(Debug, Clone, Default)]
pub struct Context {
    /// Home directory of the local user (`~`, `%d`).
    pub home: Option<String>,
    /// Local user name (`%l`... `%u`, `Match localuser`).
    pub local_user: String,
    /// Remote user requested explicitly (fsspec `username`), if any.
    pub remote_user: Option<String>,
}

/// Resolve the configuration for host alias `host` from `files`, read in
/// order (the user's file before the system one). Missing files are
/// skipped; unreadable or malformed ones are errors, like in OpenSSH.
pub fn resolve(host: &str, files: &[PathBuf], ctx: &Context) -> Result<HostConfig> {
    let mut r = Resolver {
        host: host.to_owned(),
        ctx,
        out: HostConfig::default(),
    };
    for f in files {
        r.process_file(f, 0, true)?;
    }
    if let Some(h) = &r.out.hostname {
        r.out.hostname = Some(expand_hostname(h, host));
    }
    Ok(r.out)
}

/// Resolve from configuration text (for tests and in-memory configs).
pub fn resolve_str(host: &str, text: &str, ctx: &Context) -> Result<HostConfig> {
    let mut r = Resolver {
        host: host.to_owned(),
        ctx,
        out: HostConfig::default(),
    };
    r.process_text(text, Path::new("<config>"), None, 0, true)?;
    if let Some(h) = &r.out.hostname {
        r.out.hostname = Some(expand_hostname(h, host));
    }
    Ok(r.out)
}

/// `HostName` allows `%h` (the alias) and `%%`.
fn expand_hostname(v: &str, alias: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut it = v.chars();
    while let Some(c) = it.next() {
        if c == '%' {
            match it.next() {
                Some('h') => out.push_str(alias),
                Some('%') => out.push('%'),
                Some(o) => {
                    out.push('%');
                    out.push(o);
                }
                None => out.push('%'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

struct Resolver<'a> {
    host: String,
    ctx: &'a Context,
    out: HostConfig,
}

impl Resolver<'_> {
    fn process_file(&mut self, path: &Path, depth: usize, active: bool) -> Result<()> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(Error::from(e).with_path(path.display().to_string()));
            }
        };
        let base = path.parent().map(Path::to_path_buf);
        self.process_text(&text, path, base, depth, active)
    }

    fn process_text(
        &mut self,
        text: &str,
        path: &Path,
        base: Option<PathBuf>,
        depth: usize,
        outer_active: bool,
    ) -> Result<()> {
        // Lines before the first Host/Match of a file inherit the activeness
        // of the place it was included from.
        let mut active = outer_active;
        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (kw, rest) = split_keyword(line);
            let kw = kw.to_ascii_lowercase();
            let args = tokenize(rest).map_err(|m| {
                Error::invalid_input(format!("ssh config {}:{}: {m}", path.display(), n + 1))
            })?;
            match kw.as_str() {
                "host" => active = outer_active && host_matches(&self.host, &args),
                "match" => active = outer_active && self.match_matches(&args),
                "include" => {
                    if active {
                        if depth >= MAX_INCLUDE_DEPTH {
                            return Err(Error::invalid_input(format!(
                                "ssh config {}:{}: Include nested too deeply",
                                path.display(),
                                n + 1
                            )));
                        }
                        for a in &args {
                            for f in self.expand_include(a, base.as_deref()) {
                                self.process_file(&f, depth + 1, active)?;
                            }
                        }
                    }
                }
                _ if active => self.apply(&kw, &args, path, n + 1)?,
                _ => {}
            }
        }
        Ok(())
    }

    fn expand_include(&self, pattern: &str, base: Option<&Path>) -> Vec<PathBuf> {
        let p = expand_tilde(pattern, self.ctx.home.as_deref());
        let p = PathBuf::from(p);
        let p = if p.is_absolute() {
            p
        } else {
            match base {
                Some(b) => b.join(p),
                None => p,
            }
        };
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !name.contains(['*', '?']) {
            return vec![p];
        }
        let Some(dir) = p.parent() else {
            return Vec::new();
        };
        let mut out: Vec<PathBuf> = match std::fs::read_dir(dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .filter(|e| wildcard_match(&name, &e.file_name().to_string_lossy(), false))
                .map(|e| e.path())
                .collect(),
            Err(_) => Vec::new(),
        };
        out.sort();
        out
    }

    fn match_matches(&self, args: &[String]) -> bool {
        let mut i = 0;
        let mut result = true;
        while i < args.len() {
            let (neg, crit) = match args[i].strip_prefix('!') {
                Some(c) => (true, c.to_ascii_lowercase()),
                None => (false, args[i].to_ascii_lowercase()),
            };
            i += 1;
            let hit = match crit.as_str() {
                "all" => true,
                "canonical" | "final" | "localnetwork" => false,
                "host" | "originalhost" | "user" | "localuser" | "exec" | "tagged" => {
                    let Some(arg) = args.get(i) else {
                        return false;
                    };
                    i += 1;
                    let pats: Vec<String> = arg.split(',').map(str::to_owned).collect();
                    match crit.as_str() {
                        "host" => {
                            let h = self.out.hostname.as_deref().unwrap_or(&self.host);
                            host_matches(h, &pats)
                        }
                        "originalhost" => host_matches(&self.host, &pats),
                        "user" => {
                            let u = self
                                .ctx
                                .remote_user
                                .as_deref()
                                .or(self.out.user.as_deref())
                                .unwrap_or(&self.ctx.local_user);
                            pattern_list_matches(u, &pats, false)
                        }
                        "localuser" => pattern_list_matches(&self.ctx.local_user, &pats, false),
                        // `exec` would run a command; `tagged` needs `Tag`.
                        _ => {
                            tracing::debug!("ssh config: Match {crit} is not supported");
                            false
                        }
                    }
                }
                other => {
                    tracing::debug!("ssh config: unknown Match criterion {other:?}");
                    false
                }
            };
            result &= hit != neg;
        }
        result
    }

    fn apply(&mut self, kw: &str, args: &[String], path: &Path, line: usize) -> Result<()> {
        let bad = |what: &str| {
            Error::invalid_input(format!(
                "ssh config {}:{line}: {what} for '{kw}'",
                path.display()
            ))
        };
        let first = || args.first().cloned().ok_or_else(|| bad("missing argument"));
        let yes_no = |v: &str| match v.to_ascii_lowercase().as_str() {
            "yes" | "true" => Ok(true),
            "no" | "false" => Ok(false),
            _ => Err(bad("expected yes or no")),
        };
        let secs = |v: &str| {
            v.parse::<u64>()
                .map(Duration::from_secs)
                .map_err(|_| bad("expected a number of seconds"))
        };
        let o = &mut self.out;
        match kw {
            "hostname" if o.hostname.is_none() => o.hostname = Some(first()?),
            "port" if o.port.is_none() => {
                let v = first()?;
                o.port = Some(
                    v.parse::<u16>()
                        .ok()
                        .filter(|p| *p > 0)
                        .ok_or_else(|| bad("invalid port"))?,
                );
            }
            "user" if o.user.is_none() => o.user = Some(first()?),
            "identityfile" => {
                let v = first()?;
                if !o.identity_files.contains(&v) {
                    o.identity_files.push(v);
                }
            }
            "identitiesonly" if o.identities_only.is_none() => {
                o.identities_only = Some(yes_no(&first()?)?);
            }
            "identityagent" if o.identity_agent.is_none() => o.identity_agent = Some(first()?),
            "userknownhostsfile" if o.user_known_hosts_files.is_none() => {
                o.user_known_hosts_files = Some(args.to_vec());
            }
            "globalknownhostsfile" if o.global_known_hosts_files.is_none() => {
                o.global_known_hosts_files = Some(args.to_vec());
            }
            "stricthostkeychecking" if o.strict_host_key_checking.is_none() => {
                o.strict_host_key_checking = Some(first()?.to_ascii_lowercase());
            }
            "hostkeyalias" if o.host_key_alias.is_none() => o.host_key_alias = Some(first()?),
            "connecttimeout" if o.connect_timeout.is_none() => {
                let v = first()?;
                if !v.eq_ignore_ascii_case("none") {
                    o.connect_timeout = Some(secs(&v)?);
                }
            }
            "compression" if o.compression.is_none() => o.compression = Some(yes_no(&first()?)?),
            "serveraliveinterval" if o.server_alive_interval.is_none() => {
                let d = secs(&first()?)?;
                o.server_alive_interval = Some(d);
            }
            "proxyjump" if o.proxy_jump.is_none() => o.proxy_jump = Some(first()?),
            "proxycommand" if o.proxy_command.is_none() => o.proxy_command = Some(args.join(" ")),
            _ => {}
        }
        Ok(())
    }
}

/// Split `Keyword args` / `Keyword=args` / `Keyword = args`.
fn split_keyword(line: &str) -> (&str, &str) {
    let end = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    let kw = &line[..end];
    let mut rest = line[end..].trim_start();
    if let Some(r) = rest.strip_prefix('=') {
        rest = r.trim_start();
    }
    (kw, rest)
}

/// Split arguments on whitespace, honouring double quotes.
fn tokenize(s: &str) -> std::result::Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut have = false;
    for c in s.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                have = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if have {
                    out.push(std::mem::take(&mut cur));
                    have = false;
                }
            }
            c => {
                cur.push(c);
                have = true;
            }
        }
    }
    if in_quotes {
        return Err("unterminated quote".into());
    }
    if have {
        out.push(cur);
    }
    Ok(out)
}

/// OpenSSH `match_hostname` for a `Host` line: no negated pattern may
/// match and at least one positive one must (case-insensitive).
pub fn host_matches(host: &str, patterns: &[String]) -> bool {
    pattern_list_matches(host, patterns, true)
}

fn pattern_list_matches(s: &str, patterns: &[String], ci: bool) -> bool {
    let mut positive = false;
    for p in patterns {
        // A Host line may also carry comma-separated lists.
        for p in p.split(',').filter(|p| !p.is_empty()) {
            match p.strip_prefix('!') {
                Some(neg) => {
                    if wildcard_match(neg, s, ci) {
                        return false;
                    }
                }
                None => positive |= wildcard_match(p, s, ci),
            }
        }
    }
    positive
}

/// Glob match with `*` and `?` (OpenSSH `match_pattern`).
pub fn wildcard_match(pattern: &str, s: &str, case_insensitive: bool) -> bool {
    let norm = |x: &str| -> Vec<char> {
        if case_insensitive {
            x.chars().flat_map(char::to_lowercase).collect()
        } else {
            x.chars().collect()
        }
    };
    let p = norm(pattern);
    let t = norm(s);
    // Iterative matcher with single-star backtracking: O(len(p) * len(t)).
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Replace a leading `~` or `~/` with `home`.
pub fn expand_tilde(p: &str, home: Option<&str>) -> String {
    match (p.strip_prefix('~'), home) {
        (Some(rest), Some(h)) if rest.is_empty() || rest.starts_with('/') => format!("{h}{rest}"),
        _ => p.to_owned(),
    }
}

/// Tokens for [`expand_tokens`].
#[derive(Debug, Clone, Default)]
pub struct Tokens<'a> {
    /// `%d`: local home directory.
    pub home: Option<&'a str>,
    /// `%h`: remote host name.
    pub host: &'a str,
    /// `%n`: the original host alias.
    pub alias: &'a str,
    /// `%p`: remote port.
    pub port: u16,
    /// `%r`: remote user.
    pub remote_user: &'a str,
    /// `%u`: local user.
    pub local_user: &'a str,
}

/// Expand `~` and the `%` tokens OpenSSH allows in `IdentityFile`,
/// `UserKnownHostsFile` and `IdentityAgent`.
pub fn expand_tokens(v: &str, t: &Tokens<'_>) -> String {
    let v = expand_tilde(v, t.home);
    let mut out = String::with_capacity(v.len());
    let mut it = v.chars();
    while let Some(c) = it.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('%') => out.push('%'),
            Some('d') => out.push_str(t.home.unwrap_or("")),
            Some('h') => out.push_str(t.host),
            Some('n') => out.push_str(t.alias),
            Some('p') => out.push_str(&t.port.to_string()),
            Some('r') => out.push_str(t.remote_user),
            Some('u') => out.push_str(t.local_user),
            Some(o) => {
                out.push('%');
                out.push(o);
            }
            None => out.push('%'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Context {
        Context {
            home: Some("/home/me".into()),
            local_user: "me".into(),
            remote_user: None,
        }
    }

    #[test]
    fn host_blocks_first_value_wins_and_identity_files_accumulate() {
        let text = r#"
# comment
Host web prod-*
    HostName %h.example.com
    Port 2200
    User deploy
    IdentityFile ~/.ssh/web_key

Host prod-db
    HostName db.internal
    Port 2201

Host *
    User nobody
    IdentityFile ~/.ssh/id_default
    Port 22
"#;
        let c = resolve_str("prod-db", text, &ctx()).unwrap();
        assert_eq!(c.hostname.as_deref(), Some("prod-db.example.com"));
        assert_eq!(c.port, Some(2200));
        assert_eq!(c.user.as_deref(), Some("deploy"));
        assert_eq!(c.identity_files, ["~/.ssh/web_key", "~/.ssh/id_default"]);

        let c = resolve_str("other", text, &ctx()).unwrap();
        assert_eq!(c.hostname, None);
        assert_eq!(c.port, Some(22));
        assert_eq!(c.user.as_deref(), Some("nobody"));
    }

    #[test]
    fn negation_equals_quotes_and_case() {
        let text =
            "host *.corp !bastion.corp\n  user=alice\nHOST bastion.corp\n  User \"bob smith\"\n";
        assert_eq!(
            resolve_str("x.CORP", text, &ctx()).unwrap().user.as_deref(),
            Some("alice")
        );
        assert_eq!(
            resolve_str("bastion.corp", text, &ctx())
                .unwrap()
                .user
                .as_deref(),
            Some("bob smith")
        );
    }

    #[test]
    fn match_criteria() {
        let text = "Match originalhost a*,!ab user root\n Port 1\nMatch all\n Port 2\n";
        let mut c = ctx();
        c.remote_user = Some("root".into());
        assert_eq!(resolve_str("ax", text, &c).unwrap().port, Some(1));
        assert_eq!(resolve_str("ab", text, &c).unwrap().port, Some(2));
        let text = "Match exec \"true\"\n Port 1\nMatch !localuser me\n Port 3\n";
        assert_eq!(resolve_str("h", text, &ctx()).unwrap().port, None);
    }

    #[test]
    fn include_is_conditional_and_relative() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::create_dir(d.join("conf.d")).unwrap();
        std::fs::write(d.join("conf.d/a.conf"), "Host inc\n Port 7\n").unwrap();
        std::fs::write(d.join("conf.d/b.conf"), "User fromb\n").unwrap();
        std::fs::write(
            d.join("config"),
            "Host nomatch\n Include conf.d/b.conf\nHost *\n Include conf.d/*.conf\n User late\n",
        )
        .unwrap();
        let c = resolve("inc", &[d.join("config"), d.join("missing")], &ctx()).unwrap();
        assert_eq!(c.port, Some(7));
        // b.conf's top-level User applies via the `Host *` include, before
        // the later `User late`.
        assert_eq!(c.user.as_deref(), Some("fromb"));
    }

    #[test]
    fn include_recursion_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("loop");
        std::fs::write(&f, format!("Include {}\n", f.display())).unwrap();
        assert!(resolve("h", &[f], &ctx()).is_err());
    }

    #[test]
    fn values_parse_and_errors() {
        let text = "Host *\n ConnectTimeout 5\n Compression yes\n ServerAliveInterval 30\n \
                    StrictHostKeyChecking Accept-New\n UserKnownHostsFile ~/a ~/b\n \
                    HostKeyAlias alias\n IdentitiesOnly yes\n ProxyJump jump\n";
        let c = resolve_str("h", text, &ctx()).unwrap();
        assert_eq!(c.connect_timeout, Some(Duration::from_secs(5)));
        assert_eq!(c.compression, Some(true));
        assert_eq!(c.server_alive_interval, Some(Duration::from_secs(30)));
        assert_eq!(c.strict_host_key_checking.as_deref(), Some("accept-new"));
        assert_eq!(
            c.user_known_hosts_files,
            Some(vec!["~/a".to_owned(), "~/b".to_owned()])
        );
        assert_eq!(c.host_key_alias.as_deref(), Some("alias"));
        assert_eq!(c.identities_only, Some(true));
        assert_eq!(c.proxy_jump.as_deref(), Some("jump"));
        assert!(resolve_str("h", "Port nope\n", &ctx()).is_err());
        assert!(resolve_str("h", "Compression maybe\n", &ctx()).is_err());
        assert!(resolve_str("h", "User \"unterminated\n", &ctx()).is_err());
    }

    #[test]
    fn wildcards() {
        assert!(wildcard_match("*", "", false));
        assert!(wildcard_match("a*b?c", "aXXbYc", false));
        assert!(!wildcard_match("a*b?c", "aXXbc", false));
        assert!(wildcard_match("*.Example.COM", "www.example.com", true));
        assert!(!wildcard_match("*.example.com", "example.com", true));
        assert!(wildcard_match("[h]:22*", "[h]:2222", false));
    }

    #[test]
    fn token_expansion() {
        let t = Tokens {
            home: Some("/home/me"),
            host: "srv",
            alias: "a",
            port: 2222,
            remote_user: "bob",
            local_user: "me",
        };
        assert_eq!(
            expand_tokens("~/.ssh/%r@%h:%p-%n-%u-%%-%d-%x", &t),
            "/home/me/.ssh/bob@srv:2222-a-me-%-/home/me-%x"
        );
        assert_eq!(expand_tilde("~user/x", Some("/h")), "~user/x");
        assert_eq!(expand_hostname("%h.%%.x%", "a"), "a.%.x%");
    }
}
