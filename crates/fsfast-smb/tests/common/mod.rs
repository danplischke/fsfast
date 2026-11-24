//! Shared helpers for the live Samba integration tests.
//!
//! Gated on `FSFAST_TEST_SMB_HOST` (see `scripts/test-services.sh env`); also
//! reads `FSFAST_TEST_SMB_PORT`, `FSFAST_TEST_SMB_USER`,
//! `FSFAST_TEST_SMB_PASSWORD`, `FSFAST_TEST_SMB_SHARE` (signing required) and
//! `FSFAST_TEST_SMB_ENC_SHARE` (encryption required).

#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use fsfast_core::{Options, Value};
use fsfast_smb::SmbFileSystem;

/// Connection settings of the test Samba.
#[derive(Debug, Clone)]
pub struct Env {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub share: String,
    pub enc_share: String,
}

/// The test environment, or `None` (with a skip message) when unset.
pub fn env() -> Option<Env> {
    let host = match std::env::var("FSFAST_TEST_SMB_HOST") {
        Ok(h) if !h.is_empty() => h,
        _ => {
            eprintln!("skipping live SMB test: FSFAST_TEST_SMB_HOST is not set");
            return None;
        }
    };
    let get = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_owned());
    Some(Env {
        host,
        port: get("FSFAST_TEST_SMB_PORT", "445").parse().expect("FSFAST_TEST_SMB_PORT"),
        user: get("FSFAST_TEST_SMB_USER", "fsfast"),
        password: get("FSFAST_TEST_SMB_PASSWORD", "fsfastpw"),
        share: get("FSFAST_TEST_SMB_SHARE", "data"),
        enc_share: get("FSFAST_TEST_SMB_ENC_SHARE", "enc"),
    })
}

impl Env {
    /// The fsspec storage options for this server plus `extra`.
    pub fn options(&self, extra: &[(&str, Value)]) -> Options {
        let mut o = Options::new();
        o.insert("host".into(), Value::Str(self.host.clone()));
        o.insert("port".into(), Value::Int(i64::from(self.port)));
        o.insert("username".into(), Value::Str(self.user.clone()));
        o.insert("password".into(), Value::Str(self.password.clone()));
        for (k, v) in extra {
            o.insert((*k).into(), v.clone());
        }
        o
    }

    /// A filesystem with the default options plus `extra`.
    pub fn fs(&self, extra: &[(&str, Value)]) -> SmbFileSystem {
        SmbFileSystem::from_options(self.options(extra)).expect("valid options")
    }
}

/// A unique directory name for one test run.
pub fn unique(tag: &str) -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "fsfast-smb-{tag}-{}-{:x}-{}",
        std::process::id(),
        t,
        N.fetch_add(1, Ordering::Relaxed)
    )
}

/// Deterministic test data.
pub fn pattern(len: usize, seed: u8) -> bytes::Bytes {
    let mut v = Vec::with_capacity(len);
    let mut x: u32 = 0x9E37_79B9 ^ u32::from(seed);
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        v.push((x >> 24) as u8);
    }
    v.into()
}

/// Remove a test tree recursively (best effort).
pub async fn cleanup(fs: &SmbFileSystem, root: &str) {
    use fsfast_core::{FileSystem, FindOptions};
    let Ok(all) = fs
        .find(root, &FindOptions { maxdepth: None, withdirs: true })
        .await
    else {
        return;
    };
    let mut entries = all;
    entries.sort_by(|a, b| b.name.len().cmp(&a.name.len()));
    for e in entries {
        if e.is_dir() {
            let _ = fs.rmdir(&e.name).await;
        } else {
            let _ = fs.rm_file(&e.name).await;
        }
    }
    let _ = fs.rmdir(root).await;
}
