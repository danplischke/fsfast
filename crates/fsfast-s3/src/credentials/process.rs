//! `credential_process`: run an external helper that prints credentials as
//! JSON (`{"Version": 1, "AccessKeyId": ..., "SecretAccessKey": ...,
//! "SessionToken": ..., "Expiration": ...}`).

use std::process::Stdio;
use std::sync::Arc;

use async_trait::async_trait;
use fsfast_core::{Error, ErrorKind, Result};

use super::{Credentials, ProvideCredentials, credentials_from_json};
use crate::profile::ProfileFiles;

/// Split a command line like Python's `shlex.split` (POSIX mode, no
/// comments), as botocore does for `credential_process`.
pub fn shell_split(s: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => cur.push(c),
                        None => return Err(Error::invalid_input("credential_process: no closing quotation")),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.peek().copied() {
                            Some(n @ ('\\' | '"' | '$' | '`' | '\n')) => {
                                chars.next();
                                if n != '\n' {
                                    cur.push(n);
                                }
                            }
                            _ => cur.push('\\'),
                        },
                        Some(c) => cur.push(c),
                        None => return Err(Error::invalid_input("credential_process: no closing quotation")),
                    }
                }
            }
            '\\' => {
                in_word = true;
                match chars.next() {
                    Some('\n') => {}
                    Some(n) => cur.push(n),
                    None => return Err(Error::invalid_input("credential_process: no escaped character")),
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    Ok(out)
}

/// Runs the profile's `credential_process`.
#[derive(Debug, Clone)]
pub struct ProcessProvider {
    profiles: Arc<ProfileFiles>,
    profile: String,
}

impl ProcessProvider {
    /// The provider for `profile`.
    pub fn new(profiles: Arc<ProfileFiles>, profile: impl Into<String>) -> Self {
        ProcessProvider {
            profiles,
            profile: profile.into(),
        }
    }

    /// Run `command` and parse its output.
    pub async fn run(command: &str) -> Result<Credentials> {
        let argv = shell_split(command)?;
        let (prog, args) = argv
            .split_first()
            .ok_or_else(|| Error::invalid_input("credential_process is empty"))?;
        let out = tokio::process::Command::new(prog)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::PermissionDenied,
                    format!("credential_process {prog:?} could not be started: {e}"),
                )
            })?;
        if !out.status.success() {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "credential_process failed ({}): {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
            ));
        }
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).map_err(|e| {
            Error::new(
                ErrorKind::PermissionDenied,
                format!("credential_process returned invalid JSON: {e}"),
            )
        })?;
        match v.get("Version").and_then(|x| x.as_i64()) {
            Some(1) => {}
            other => {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    format!(
                        "Unsupported version {} for credential process provider, supported versions: 1",
                        other.map_or_else(|| "<Version key not provided>".to_owned(), |v| v.to_string())
                    ),
                ));
            }
        }
        credentials_from_json(&v, "credential_process")
    }
}

#[async_trait]
impl ProvideCredentials for ProcessProvider {
    async fn provide(&self) -> Result<Option<Credentials>> {
        match self.profiles.get(&self.profile, "credential_process") {
            Some(cmd) => Ok(Some(Self::run(cmd).await?)),
            None => Ok(None),
        }
    }

    fn name(&self) -> &'static str {
        "custom-process"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_like_shlex() {
        assert_eq!(shell_split("a b  c").unwrap(), vec!["a", "b", "c"]);
        assert_eq!(
            shell_split(r#"/bin/helper --profile 'my profile' "x \"y\" \$z" a\ b"#).unwrap(),
            vec!["/bin/helper", "--profile", "my profile", "x \"y\" $z", "a b"]
        );
        assert_eq!(shell_split(r#""a\b""#).unwrap(), vec![r"a\b"]);
        assert_eq!(shell_split("''").unwrap(), vec![""]);
        assert!(shell_split("'open").is_err());
        assert!(shell_split("").unwrap().is_empty());
    }

    #[tokio::test]
    async fn runs_a_helper() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("helper.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\necho '{\"Version\": 1, \"AccessKeyId\": \"AKP\", \"SecretAccessKey\": \"S\", \"SessionToken\": \"T\", \"Expiration\": \"2030-01-01T00:00:00Z\"}'\n",
        )
        .unwrap();
        let profiles = Arc::new(ProfileFiles::from_texts(
            Some(&format!("[default]\ncredential_process = sh {}\n", script.display())),
            None,
        ));
        let c = ProcessProvider::new(profiles, "default")
            .provide()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(c.access_key_id(), "AKP");
        assert_eq!(c.session_token(), Some("T"));
        assert!(c.expiry().is_some());

        let e = ProcessProvider::run("sh -c 'echo nope >&2; exit 3'").await.unwrap_err();
        assert!(e.to_string().contains("nope"), "{e}");
        let e = ProcessProvider::run(r#"sh -c 'echo {\"Version\": 2}'"#).await.unwrap_err();
        assert!(e.to_string().contains("Unsupported version"), "{e}");
    }
}
