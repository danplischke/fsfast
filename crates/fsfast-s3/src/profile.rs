//! The environment and the shared AWS config/credentials files.
//!
//! [`Env`] abstracts the process environment (tests substitute a map).
//! [`ProfileFiles`] reads `~/.aws/config` (`AWS_CONFIG_FILE`) and
//! `~/.aws/credentials` (`AWS_SHARED_CREDENTIALS_FILE`) like botocore's
//! `raw_config_parse` + `load_config`:
//!
//! * INI syntax as Python's `RawConfigParser` reads it: `[section]` headers,
//!   `key = value` or `key: value`, keys lower-cased, `#`/`;` comment lines
//!   (no inline comments), indented continuation lines;
//! * a value that starts on the next line is a nested block of
//!   `key = value` lines (e.g. `s3 =` followed by `addressing_style = path`);
//! * config-file sections `[profile name]` (and `[default]`) are profiles,
//!   `[sso-session name]` and `[services name]` are kept separately;
//!   credentials-file sections are profile names, and their keys override
//!   the config file's.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

use fsfast_core::{Error, Result};

/// The process environment, or a fixed map of variables (tests).
#[derive(Clone, Debug, Default)]
pub struct Env {
    vars: Option<Arc<HashMap<String, String>>>,
}

impl Env {
    /// The real process environment.
    pub fn process() -> Self {
        Env { vars: None }
    }

    /// A fixed set of variables (nothing else is visible).
    pub fn from_map<I, K, V>(vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Env {
            vars: Some(Arc::new(
                vars.into_iter().map(|(k, v)| (k.into(), v.into())).collect(),
            )),
        }
    }

    /// The value of `key`; empty values count as unset (botocore treats
    /// them as false-y).
    pub fn get(&self, key: &str) -> Option<String> {
        let v = match &self.vars {
            Some(m) => m.get(key).cloned(),
            None => std::env::var(key).ok(),
        };
        v.filter(|v| !v.is_empty())
    }

    /// Whether `key` is set to a true value (`true`, case-insensitive).
    pub fn flag(&self, key: &str) -> bool {
        self.get(key).is_some_and(|v| v.eq_ignore_ascii_case("true"))
    }

    /// The home directory (`HOME`, else `USERPROFILE`).
    pub fn home(&self) -> Option<PathBuf> {
        self.get("HOME")
            .or_else(|| self.get("USERPROFILE"))
            .map(PathBuf::from)
    }

    /// Expand a leading `~` with the home directory.
    pub fn expand(&self, path: &str) -> PathBuf {
        if let Some(rest) = path.strip_prefix('~')
            && (rest.is_empty() || rest.starts_with('/') || rest.starts_with('\\'))
            && let Some(home) = self.home()
        {
            return home.join(rest.trim_start_matches(['/', '\\']));
        }
        PathBuf::from(path)
    }
}

/// A value in a profile: a string or a nested block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileValue {
    /// `key = value`.
    Str(String),
    /// `key =` followed by indented `sub = value` lines.
    Nested(BTreeMap<String, String>),
}

/// The keys of one section.
pub type Section = BTreeMap<String, ProfileValue>;

/// Parse INI text into `(section name, keys)` pairs, in file order.
pub fn parse_ini(text: &str) -> Vec<(String, Section)> {
    let mut sections: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let indented = line.starts_with([' ', '\t']);
        if !indented && trimmed.starts_with('[') {
            if let Some(end) = trimmed.find(']') {
                sections.push((trimmed[1..end].trim().to_owned(), Vec::new()));
            }
            continue;
        }
        let Some((_, keys)) = sections.last_mut() else {
            continue; // keys before the first section: ignored
        };
        if indented && let Some((_, value)) = keys.last_mut() {
            // Continuation line of the previous value.
            value.push('\n');
            value.push_str(trimmed);
            continue;
        }
        let split = trimmed.find(['=', ':']);
        match split {
            Some(i) => keys.push((
                trimmed[..i].trim().to_ascii_lowercase(),
                trimmed[i + 1..].trim().to_owned(),
            )),
            None => keys.push((trimmed.to_ascii_lowercase(), String::new())),
        }
    }
    sections
        .into_iter()
        .map(|(name, keys)| {
            let mut section = Section::new();
            for (k, v) in keys {
                let value = if let Some(nested) = v.strip_prefix('\n') {
                    let mut map = BTreeMap::new();
                    for l in nested.lines() {
                        if let Some((a, b)) = l.split_once(['=', ':']) {
                            map.insert(a.trim().to_ascii_lowercase(), b.trim().to_owned());
                        }
                    }
                    ProfileValue::Nested(map)
                } else if v.is_empty() {
                    ProfileValue::Str(String::new())
                } else {
                    ProfileValue::Str(v)
                };
                section.insert(k, value);
            }
            (name, section)
        })
        .collect()
}

/// The merged contents of the shared config and credentials files.
#[derive(Debug, Clone, Default)]
pub struct ProfileFiles {
    /// Profiles by name.
    pub profiles: HashMap<String, Section>,
    /// `[sso-session name]` sections.
    pub sso_sessions: HashMap<String, Section>,
    /// `[services name]` sections.
    pub services: HashMap<String, Section>,
    /// Profiles of the config file alone.
    pub config_file: HashMap<String, Section>,
    /// Profiles of the credentials file alone.
    pub credentials_file: HashMap<String, Section>,
}

impl ProfileFiles {
    /// Build from the two files' contents (either may be absent).
    pub fn from_texts(config: Option<&str>, credentials: Option<&str>) -> Self {
        let mut out = ProfileFiles::default();
        if let Some(text) = config {
            for (name, section) in parse_ini(text) {
                let (kind, rest) = match name.split_once(char::is_whitespace) {
                    Some((k, r)) => (k, r.trim()),
                    None => (name.as_str(), ""),
                };
                match (kind, rest) {
                    ("default", "") => {
                        merge(&mut out.config_file, "default", section.clone());
                        merge(&mut out.profiles, "default", section);
                    }
                    ("profile", n) if !n.is_empty() => {
                        merge(&mut out.config_file, n, section.clone());
                        merge(&mut out.profiles, n, section);
                    }
                    ("sso-session", n) if !n.is_empty() => merge(&mut out.sso_sessions, n, section),
                    ("services", n) if !n.is_empty() => merge(&mut out.services, n, section),
                    _ => {}
                }
            }
        }
        if let Some(text) = credentials {
            for (name, section) in parse_ini(text) {
                merge(&mut out.credentials_file, &name, section.clone());
                merge(&mut out.profiles, &name, section);
            }
        }
        out
    }

    /// Read the files named by `AWS_CONFIG_FILE` / `AWS_SHARED_CREDENTIALS_FILE`
    /// (defaults `~/.aws/config`, `~/.aws/credentials`). Missing files are
    /// fine; unreadable ones are errors.
    pub async fn load(env: &Env) -> Result<Self> {
        let config = env
            .get("AWS_CONFIG_FILE")
            .unwrap_or_else(|| "~/.aws/config".to_owned());
        let creds = env
            .get("AWS_SHARED_CREDENTIALS_FILE")
            .unwrap_or_else(|| "~/.aws/credentials".to_owned());
        let config = read_optional(env.expand(&config)).await?;
        let creds = read_optional(env.expand(&creds)).await?;
        Ok(Self::from_texts(config.as_deref(), creds.as_deref()))
    }

    /// The profile named `name`.
    pub fn profile(&self, name: &str) -> Option<&Section> {
        self.profiles.get(name)
    }

    /// A string value of profile `name`.
    pub fn get(&self, name: &str, key: &str) -> Option<&str> {
        match self.profiles.get(name)?.get(key)? {
            ProfileValue::Str(s) if !s.is_empty() => Some(s),
            _ => None,
        }
    }

    /// A nested value of profile `name` (`s3.addressing_style`).
    pub fn nested(&self, name: &str, key: &str, sub: &str) -> Option<&str> {
        match self.profiles.get(name)?.get(key)? {
            ProfileValue::Nested(m) => m.get(sub).map(String::as_str).filter(|s| !s.is_empty()),
            _ => None,
        }
    }

    /// The `endpoint_url` configured for `service` (e.g. `s3`, `sts`) in the
    /// profile's `services` section, else the profile's global
    /// `endpoint_url` (botocore's config lookup order).
    pub fn endpoint_url(&self, profile: &str, service: &str) -> Result<Option<String>> {
        if let Some(section_name) = self.get(profile, "services") {
            let section = self.services.get(section_name).ok_or_else(|| {
                Error::invalid_input(format!(
                    "The profile is configured to use the services section but the \
                     {section_name:?} services configuration does not exist."
                ))
            })?;
            if let Some(ProfileValue::Nested(m)) = section.get(service)
                && let Some(u) = m.get("endpoint_url").filter(|u| !u.is_empty())
            {
                return Ok(Some(u.clone()));
            }
        }
        Ok(self.get(profile, "endpoint_url").map(str::to_owned))
    }
}

fn merge(map: &mut HashMap<String, Section>, name: &str, section: Section) {
    map.entry(name.to_owned()).or_default().extend(section);
}

async fn read_optional(path: PathBuf) -> Result<Option<String>> {
    match tokio::fs::read(&path).await {
        Ok(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        // A directory or unreadable file where the config should be.
        Err(e) => Err(Error::invalid_input(format!(
            "cannot read AWS config file {}: {e}",
            path.display()
        ))),
    }
}

/// The profile to use: the `profile` option, else `AWS_DEFAULT_PROFILE`, else
/// `AWS_PROFILE`, else `default`.
pub fn profile_name(explicit: Option<&str>, env: &Env) -> String {
    explicit
        .map(str::to_owned)
        .or_else(|| env.get("AWS_DEFAULT_PROFILE"))
        .or_else(|| env.get("AWS_PROFILE"))
        .unwrap_or_else(|| "default".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_botocore_style_files() {
        let config = "\
# comment
[default]
region = us-west-2
s3 =
    addressing_style = path
    payload_signing_enabled = true

[profile dev]
region=eu-west-1 # not an inline comment
role_arn = arn:aws:iam::123456789012:role/dev
source_profile = default
services = local

[services local]
s3 =
  endpoint_url = http://localhost:9000

[sso-session corp]
sso_region = us-east-1
";
        let creds = "\
[default]
aws_access_key_id = AKID
aws_secret_access_key = SECRET
[dev]
aws_session_token = TOK
";
        let p = ProfileFiles::from_texts(Some(config), Some(creds));
        assert_eq!(p.get("default", "region"), Some("us-west-2"));
        assert_eq!(p.nested("default", "s3", "addressing_style"), Some("path"));
        assert_eq!(p.get("default", "aws_access_key_id"), Some("AKID"));
        assert_eq!(
            p.get("dev", "region"),
            Some("eu-west-1 # not an inline comment")
        );
        assert_eq!(p.get("dev", "aws_session_token"), Some("TOK"));
        assert_eq!(
            p.endpoint_url("dev", "s3").unwrap().as_deref(),
            Some("http://localhost:9000")
        );
        assert_eq!(p.endpoint_url("dev", "sts").unwrap(), None);
        assert!(p.sso_sessions.contains_key("corp"));
    }

    #[test]
    fn env_lookup_and_home_expansion() {
        let env = Env::from_map([("HOME", "/home/u"), ("EMPTY", ""), ("AWS_PROFILE", "p")]);
        assert_eq!(env.get("EMPTY"), None);
        assert_eq!(env.expand("~/.aws/config"), PathBuf::from("/home/u/.aws/config"));
        assert_eq!(env.expand("/abs"), PathBuf::from("/abs"));
        assert_eq!(profile_name(None, &env), "p");
        assert_eq!(profile_name(Some("x"), &env), "x");
        assert_eq!(profile_name(None, &Env::from_map::<[(&str, &str); 0], _, _>([])), "default");
    }

    #[tokio::test]
    async fn loads_files_from_env_paths() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("cfg");
        std::fs::write(&cfg, "[profile x]\nregion = ap-south-1\n").unwrap();
        let env = Env::from_map([
            ("AWS_CONFIG_FILE", cfg.to_str().unwrap()),
            ("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/creds"),
        ]);
        let p = ProfileFiles::load(&env).await.unwrap();
        assert_eq!(p.get("x", "region"), Some("ap-south-1"));
    }
}
