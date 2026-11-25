//! Shared helpers for the live OpenSSH integration tests.
//!
//! Gated on `FSFAST_TEST_SFTP_HOST` (see `scripts/test-services.sh env`);
//! also reads `FSFAST_TEST_SFTP_PORT`, `FSFAST_TEST_SFTP_USER`,
//! `FSFAST_TEST_SFTP_PASSWORD` and `FSFAST_TEST_STATE` (the test user's home
//! is `$FSFAST_TEST_STATE/sftp/home`).

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use fsfast_core::{Options, Value};
use fsfast_sftp::SftpFileSystem;

/// Connection settings of the test server.
#[derive(Debug, Clone)]
pub struct Env {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    /// The test user's home directory (absolute path on the server, which
    /// is this machine).
    pub home: String,
    /// `$FSFAST_TEST_STATE`.
    pub state: PathBuf,
}

/// The test environment, or `None` (with a skip message) when unset.
pub fn env() -> Option<Env> {
    let host = match std::env::var("FSFAST_TEST_SFTP_HOST") {
        Ok(h) if !h.is_empty() => h,
        _ => {
            eprintln!("skipping live SFTP test: FSFAST_TEST_SFTP_HOST is not set");
            return None;
        }
    };
    let get = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_owned());
    let state = PathBuf::from(get("FSFAST_TEST_STATE", "/tmp/fsfast-test"));
    Some(Env {
        host,
        port: get("FSFAST_TEST_SFTP_PORT", "22")
            .parse()
            .expect("FSFAST_TEST_SFTP_PORT"),
        user: get("FSFAST_TEST_SFTP_USER", "fsfast"),
        password: get("FSFAST_TEST_SFTP_PASSWORD", "fsfastpw"),
        home: state.join("sftp/home").display().to_string(),
        state,
    })
}

impl Env {
    /// The fsspec storage options for this server plus `extra`. The test
    /// does not depend on the user's ssh_config or agent.
    pub fn options(&self, extra: &[(&str, Value)]) -> Options {
        let mut o = Options::new();
        o.insert("host".into(), Value::Str(self.host.clone()));
        o.insert("port".into(), Value::Int(i64::from(self.port)));
        o.insert("username".into(), Value::Str(self.user.clone()));
        o.insert("password".into(), Value::Str(self.password.clone()));
        o.insert("ssh_config".into(), Value::Bool(false));
        o.insert("allow_agent".into(), Value::Bool(false));
        o.insert("look_for_keys".into(), Value::Bool(false));
        for (k, v) in extra {
            o.insert((*k).into(), v.clone());
        }
        o
    }

    /// A filesystem with the default options plus `extra`.
    pub fn fs(&self, extra: &[(&str, Value)]) -> SftpFileSystem {
        SftpFileSystem::from_options(self.options(extra)).expect("valid options")
    }

    /// A unique absolute directory path below the test user's home.
    pub fn dir(&self, tag: &str) -> String {
        format!("{}/{}", self.home, unique(tag))
    }
}

/// A unique name for one test run.
pub fn unique(tag: &str) -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "fsfast-sftp-{tag}-{}-{:x}-{}",
        std::process::id(),
        t,
        N.fetch_add(1, Ordering::Relaxed)
    )
}

/// Remove a directory tree on the server through the filesystem.
pub async fn rm_tree(fs: &SftpFileSystem, dir: &str) {
    use fsfast_core::{FileSystem, FindOptions};
    let Ok(all) = fs
        .find(
            dir,
            &FindOptions {
                maxdepth: None,
                withdirs: true,
            },
        )
        .await
    else {
        return;
    };
    let mut entries = all;
    entries.sort_by_key(|e| std::cmp::Reverse(e.name.len()));
    for e in entries {
        if e.is_dir() {
            let _ = fs.rmdir(&e.name).await;
        } else {
            let _ = fs.rm_file(&e.name).await;
        }
    }
    let _ = fs.rmdir(dir).await;
}
