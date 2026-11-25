//! `--opt` parsing and the environment-based option defaults.
//!
//! Option sources, from lowest to highest precedence:
//! 1. `--test-services`: the settings `scripts/test-services.sh env` exports
//!    (`FSFAST_TEST_*`), mapped to each backend's option names;
//! 2. `FSF_OPTS` (a JSON object applied like unscoped `--opt`s) and
//!    `FSF_OPTS_<PROTOCOL>` (a JSON object for one protocol, e.g.
//!    `FSF_OPTS_S3`, `FSF_OPTS_GS`, `FSF_OPTS_ABFS`);
//! 3. options inferred from the URL (fsspec `_get_kwargs_from_urls`, e.g.
//!    the host and credentials of `smb://user:pw@host/share`);
//! 4. `--opt` values.
//!
//! Like fsspec's `url_to_fs`, an option given both in the URL and with
//! `--opt` must have the same value, otherwise it is an error. Sources 1–2
//! are defaults that later sources silently override.
//!
//! `--opt` syntax: `[PROTOCOL:]KEY=VALUE` or `[PROTOCOL:]KEY:=JSON`.
//! * Without a protocol scope, the option applies to every *network*
//!   backend the command uses (not to `file`/`memory`, which take almost no
//!   options; scope those explicitly, e.g. `file:auto_mkdir=true`). When a
//!   command uses two different network protocols, unscoped options are
//!   ambiguous and rejected.
//! * `KEY=VALUE`: the value is read as JSON when it is a JSON number,
//!   boolean, `null`, object or array, and as a plain string otherwise
//!   (backends accept `"true"`/`"8"` strings for boolean/integer options,
//!   so this only matters for numbers and dicts). `KEY:=JSON` requires JSON,
//!   e.g. `key:='"0123"'` for a string that looks like a number.

use std::collections::BTreeMap;

use fsfast_core::{Error, Options, Result, Value};

use crate::backends::{self, Backend};

/// One parsed `--opt`.
#[derive(Debug, Clone, PartialEq)]
pub struct OptSpec {
    /// Canonical protocol the option is scoped to, if any.
    pub scope: Option<&'static str>,
    /// Option name.
    pub key: String,
    /// Option value.
    pub value: Value,
}

/// Parse one `--opt` argument (see the module docs).
pub fn parse_opt(arg: &str) -> Result<OptSpec> {
    let (lhs, raw) = arg.split_once('=').ok_or_else(|| {
        Error::invalid_input(format!(
            "--opt {arg:?}: expected [PROTOCOL:]KEY=VALUE or [PROTOCOL:]KEY:=JSON"
        ))
    })?;
    let (lhs, force_json) = match lhs.strip_suffix(':') {
        Some(l) => (l, true),
        None => (lhs, false),
    };
    let (scope, key) = match lhs.split_once(':') {
        Some((p, k)) => (Some(backends::lookup(p)?.name()), k),
        None => (None, lhs),
    };
    if key.is_empty() || key.contains(':') {
        return Err(Error::invalid_input(format!(
            "--opt {arg:?}: invalid option name {key:?}"
        )));
    }
    let value = if force_json {
        let j: serde_json::Value = serde_json::from_str(raw).map_err(|e| {
            Error::invalid_input(format!("--opt {arg:?}: value is not valid JSON: {e}"))
        })?;
        json_to_value(j)
    } else {
        auto_value(raw)
    };
    Ok(OptSpec {
        scope,
        key: key.to_owned(),
        value,
    })
}

/// `KEY=VALUE` value rule: JSON scalars other than strings, objects and
/// arrays are JSON; everything else is a plain string.
pub fn auto_value(raw: &str) -> Value {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(serde_json::Value::String(_)) | Err(_) => Value::Str(raw.to_owned()),
        Ok(j) => json_to_value(j),
    }
}

/// JSON to the core option [`Value`].
pub fn json_to_value(j: serde_json::Value) -> Value {
    match j {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Value::Int(i),
            None => Value::Float(n.as_f64().unwrap_or(f64::NAN)),
        },
        serde_json::Value::String(s) => Value::Str(s),
        serde_json::Value::Array(a) => Value::List(a.into_iter().map(json_to_value).collect()),
        serde_json::Value::Object(m) => {
            Value::Map(m.into_iter().map(|(k, v)| (k, json_to_value(v))).collect())
        }
    }
}

/// A JSON object string (from an environment variable) as options.
fn json_object(name: &str, raw: &str) -> Result<Options> {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(serde_json::Value::Object(m)) => {
            Ok(m.into_iter().map(|(k, v)| (k, json_to_value(v))).collect())
        }
        Ok(_) => Err(Error::invalid_input(format!(
            "${name} must be a JSON object"
        ))),
        Err(e) => Err(Error::invalid_input(format!(
            "${name} is not valid JSON: {e}"
        ))),
    }
}

/// Every source of options for a command.
#[derive(Debug, Clone, Default)]
pub struct OptionSet {
    /// `--opt` values in command-line order (later wins).
    pub specs: Vec<OptSpec>,
    /// `FSF_OPTS` (unscoped defaults).
    pub env_unscoped: Options,
    /// `FSF_OPTS_<PROTOCOL>` and `--test-services` defaults per canonical
    /// protocol.
    pub env_scoped: BTreeMap<&'static str, Options>,
}

impl OptionSet {
    /// Build from parsed `--opt`s and an environment lookup.
    pub fn new(
        specs: Vec<OptSpec>,
        test_services: bool,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        let mut set = OptionSet {
            specs,
            ..Default::default()
        };
        if test_services {
            for (proto, opts) in test_service_options(env) {
                set.env_scoped.entry(proto).or_default().extend(opts);
            }
        }
        if let Some(raw) = env("FSF_OPTS").filter(|s| !s.trim().is_empty()) {
            set.env_unscoped = json_object("FSF_OPTS", &raw)?;
        }
        for b in backends::BACKENDS {
            for alias in b.protocols {
                let name = format!("FSF_OPTS_{}", alias.to_ascii_uppercase());
                if let Some(raw) = env(&name).filter(|s| !s.trim().is_empty()) {
                    let o = json_object(&name, &raw)?;
                    set.env_scoped.entry(b.name()).or_default().extend(o);
                }
            }
        }
        Ok(set)
    }

    /// Fail when unscoped options would apply to two different network
    /// protocols of one command.
    pub fn check_unscoped(&self, used: &[&'static Backend]) -> Result<()> {
        let has_unscoped =
            self.specs.iter().any(|s| s.scope.is_none()) || !self.env_unscoped.is_empty();
        if !has_unscoped {
            return Ok(());
        }
        let mut net: Vec<&str> = used
            .iter()
            .filter(|b| !b.in_process)
            .map(|b| b.name())
            .collect();
        net.sort_unstable();
        net.dedup();
        if net.len() > 1 {
            return Err(Error::invalid_input(format!(
                "unscoped options are ambiguous with several protocols ({}): \
                 prefix them with a protocol, e.g. --opt {}:key=value",
                net.join(", "),
                net[0]
            )));
        }
        Ok(())
    }

    /// The final option map for `backend`, given the options inferred from
    /// the URL.
    pub fn options_for(&self, backend: &Backend, url_opts: Options) -> Result<Options> {
        let name = backend.name();
        let applies = |scope: Option<&str>| match scope {
            Some(s) => s == name,
            None => !backend.in_process,
        };
        let mut out = Options::new();
        if let Some(o) = self.env_scoped.get(name) {
            out.extend(o.clone());
        }
        if !backend.in_process {
            out.extend(self.env_unscoped.clone());
        }
        out.extend(url_opts.clone());
        let mut explicit = Options::new();
        for s in self.specs.iter().filter(|s| applies(s.scope)) {
            explicit.insert(s.key.clone(), s.value.clone());
        }
        for (k, v) in &explicit {
            if let Some(u) = url_opts.get(k)
                && u != v
            {
                return Err(Error::invalid_input(format!(
                    "collision between the option {k:?} inferred from the URL and the one given \
                     with --opt"
                )));
            }
        }
        out.extend(explicit);
        Ok(out)
    }
}

/// The `scripts/test-services.sh env` settings mapped to backend options.
/// Only services whose variables are set are included.
pub fn test_service_options(env: &dyn Fn(&str) -> Option<String>) -> Vec<(&'static str, Options)> {
    let get = |k: &str| env(k).filter(|v| !v.is_empty());
    let s = |v: String| Value::Str(v);
    let port = |v: String| v.parse::<i64>().map(Value::Int).unwrap_or(Value::Str(v));
    let mut out = Vec::new();
    if let (Some(ep), Some(key), Some(secret)) = (
        get("FSFAST_TEST_S3_ENDPOINT"),
        get("FSFAST_TEST_S3_KEY"),
        get("FSFAST_TEST_S3_SECRET"),
    ) {
        out.push((
            "s3",
            Options::from([
                ("endpoint_url".into(), s(ep)),
                ("key".into(), s(key)),
                ("secret".into(), s(secret)),
            ]),
        ));
    }
    for (proto, prefix) in [("smb", "FSFAST_TEST_SMB"), ("sftp", "FSFAST_TEST_SFTP")] {
        if let Some(host) = get(&format!("{prefix}_HOST")) {
            let mut o = Options::from([("host".into(), s(host))]);
            if let Some(p) = get(&format!("{prefix}_PORT")) {
                o.insert("port".into(), port(p));
            }
            if let Some(u) = get(&format!("{prefix}_USER")) {
                o.insert("username".into(), s(u));
            }
            if let Some(p) = get(&format!("{prefix}_PASSWORD")) {
                o.insert("password".into(), s(p));
            }
            if proto == "sftp" {
                // A throwaway sshd: password auth only, no user ssh config.
                for k in ["ssh_config", "allow_agent", "look_for_keys"] {
                    o.insert(k.into(), Value::Bool(false));
                }
            }
            out.push((proto, o));
        }
    }
    if let Some(ep) = get("FSFAST_TEST_GCS_ENDPOINT") {
        out.push((
            "gs",
            Options::from([
                ("endpoint_url".into(), s(ep)),
                ("token".into(), s("anon".into())),
                ("project".into(), s("test-project".into())),
            ]),
        ));
    }
    if let Some(cs) = get("FSFAST_TEST_AZURE_CONNECTION_STRING") {
        out.push(("abfs", Options::from([("connection_string".into(), s(cs))])));
    }
    // Only keep protocols compiled into this build.
    out.retain(|(p, _)| backends::lookup(p).is_ok());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)] // unused in builds without some backends
    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn opt_syntax() {
        let o = parse_opt("endpoint_url=http://127.0.0.1:9000").unwrap();
        assert_eq!(o.scope, None);
        assert_eq!(o.key, "endpoint_url");
        assert_eq!(o.value, Value::Str("http://127.0.0.1:9000".into()));

        let o = parse_opt("timeout=2.5").unwrap();
        assert_eq!(o.value, Value::Float(2.5));
        let o = parse_opt("connections=8").unwrap();
        assert_eq!(o.value, Value::Int(8));
        let o = parse_opt("anon=true").unwrap();
        assert_eq!(o.value, Value::Bool(true));
        let o = parse_opt("x=null").unwrap();
        assert_eq!(o.value, Value::Null);
        let o = parse_opt("empty=").unwrap();
        assert_eq!(o.value, Value::Str(String::new()));
        // A JSON string literal stays the raw text with KEY=VALUE...
        let o = parse_opt("k=\"q\"").unwrap();
        assert_eq!(o.value, Value::Str("\"q\"".into()));
        // ...and is decoded with KEY:=JSON.
        let o = parse_opt("k:=\"0123\"").unwrap();
        assert_eq!(o.value, Value::Str("0123".into()));
        assert!(parse_opt("k:=nope").is_err());

        let o = parse_opt("client_kwargs={\"region_name\": \"eu-west-1\"}").unwrap();
        let m = o.value.as_map().unwrap();
        assert_eq!(m["region_name"], Value::Str("eu-west-1".into()));
        let o = parse_opt("disabled_algorithms:={\"kex\": [\"a\", \"b\"]}").unwrap();
        assert_eq!(o.value.as_map().unwrap()["kex"].as_list().unwrap().len(), 2);

        assert!(parse_opt("novalue").is_err());
        assert!(parse_opt("=v").is_err());
        assert!(parse_opt("a:b:c=v").is_err());
    }

    #[test]
    #[cfg(all(feature = "s3", feature = "local"))]
    fn scoped_opts_resolve_aliases() {
        let o = parse_opt("s3a:key=AK").unwrap();
        assert_eq!(o.scope, Some("s3"));
        let o = parse_opt("local:auto_mkdir=true").unwrap();
        assert_eq!(o.scope, Some("file"));
        let o = parse_opt("s3:client_kwargs:={\"verify\": false}").unwrap();
        assert_eq!(o.scope, Some("s3"));
        assert_eq!(o.key, "client_kwargs");
        assert!(parse_opt("nosuchproto:key=v").is_err());
    }

    #[test]
    #[cfg(all(feature = "s3", feature = "local", feature = "gcs"))]
    fn precedence_and_scoping() {
        let env = |k: &str| match k {
            "FSF_OPTS" => Some(r#"{"key": "envkey", "anon": false}"#.to_owned()),
            "FSF_OPTS_S3" => Some(r#"{"endpoint_url": "http://env"}"#.to_owned()),
            _ => None,
        };
        let specs = vec![
            parse_opt("key=clikey").unwrap(),
            parse_opt("file:auto_mkdir=true").unwrap(),
        ];
        let set = OptionSet::new(specs, false, &env).unwrap();
        let s3 = backends::lookup("s3").unwrap();
        let file = backends::lookup("file").unwrap();
        let o = set.options_for(s3, Options::new()).unwrap();
        assert_eq!(o["key"], Value::Str("clikey".into()));
        assert_eq!(o["anon"], Value::Bool(false));
        assert_eq!(o["endpoint_url"], Value::Str("http://env".into()));
        assert!(!o.contains_key("auto_mkdir"));
        let o = set.options_for(file, Options::new()).unwrap();
        assert_eq!(
            o.len(),
            1,
            "unscoped options skip in-process backends: {o:?}"
        );
        assert_eq!(o["auto_mkdir"], Value::Bool(true));

        let gs = backends::lookup("gs").unwrap();
        assert!(set.check_unscoped(&[s3, file]).is_ok());
        assert!(set.check_unscoped(&[s3, gs]).is_err());
        let scoped_only =
            OptionSet::new(vec![parse_opt("s3:key=x").unwrap()], false, &no_env).unwrap();
        assert!(scoped_only.check_unscoped(&[s3, gs]).is_ok());
    }

    #[test]
    #[cfg(feature = "smb")]
    fn url_options_collide_like_fsspec() {
        let smb = backends::lookup("smb").unwrap();
        let url = Options::from([("host".to_owned(), Value::Str("srv".into()))]);
        let same = OptionSet::new(vec![parse_opt("host=srv").unwrap()], false, &no_env).unwrap();
        assert_eq!(
            same.options_for(smb, url.clone()).unwrap()["host"],
            Value::Str("srv".into())
        );
        let other = OptionSet::new(vec![parse_opt("host=x").unwrap()], false, &no_env).unwrap();
        assert!(other.options_for(smb, url.clone()).is_err());
        // Environment defaults are overridden by the URL silently.
        let env = |k: &str| (k == "FSF_OPTS_SMB").then(|| r#"{"host": "envhost"}"#.to_owned());
        let set = OptionSet::new(vec![], false, &env).unwrap();
        assert_eq!(
            set.options_for(smb, url).unwrap()["host"],
            Value::Str("srv".into())
        );
    }

    #[test]
    fn bad_env_json_is_an_error() {
        let env = |k: &str| (k == "FSF_OPTS").then(|| "[1]".to_owned());
        assert!(OptionSet::new(vec![], false, &env).is_err());
        let env = |k: &str| (k == "FSF_OPTS").then(|| "{".to_owned());
        assert!(OptionSet::new(vec![], false, &env).is_err());
    }

    #[test]
    fn test_services_mapping() {
        let vars: BTreeMap<&str, &str> = [
            ("FSFAST_TEST_S3_ENDPOINT", "http://127.0.0.1:9000"),
            ("FSFAST_TEST_S3_KEY", "k"),
            ("FSFAST_TEST_S3_SECRET", "s"),
            ("FSFAST_TEST_SFTP_HOST", "127.0.0.1"),
            ("FSFAST_TEST_SFTP_PORT", "2222"),
            ("FSFAST_TEST_SFTP_USER", "u"),
            ("FSFAST_TEST_SFTP_PASSWORD", "p"),
        ]
        .into();
        let env = |k: &str| vars.get(k).map(|v| (*v).to_owned());
        let m: BTreeMap<_, _> = test_service_options(&env).into_iter().collect();
        #[cfg(feature = "s3")]
        assert_eq!(m["s3"]["key"], Value::Str("k".into()));
        #[cfg(feature = "sftp")]
        {
            assert_eq!(m["sftp"]["port"], Value::Int(2222));
            assert_eq!(m["sftp"]["look_for_keys"], Value::Bool(false));
        }
        assert!(!m.contains_key("smb"));
        assert!(!m.contains_key("gs"));
    }
}
