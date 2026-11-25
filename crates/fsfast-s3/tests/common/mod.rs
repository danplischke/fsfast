//! Shared helpers for the integration tests (gated on environment
//! variables, see each test file).

#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use fsfast_core::{FileSystem, FindOptions, Options, Value};
use fsfast_s3::S3FileSystem;

/// RustFS settings from `scripts/test-services.sh env`.
pub struct S3Env {
    pub endpoint: String,
    pub key: String,
    pub secret: String,
}

pub fn s3_env() -> Option<S3Env> {
    let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    Some(S3Env {
        endpoint: get("FSFAST_TEST_S3_ENDPOINT")?,
        key: get("FSFAST_TEST_S3_KEY")?,
        secret: get("FSFAST_TEST_S3_SECRET")?,
    })
}

pub fn skip(what: &str) {
    eprintln!(
        "skipping {what}: set FSFAST_TEST_S3_ENDPOINT, FSFAST_TEST_S3_KEY and FSFAST_TEST_S3_SECRET \
         (eval \"$(scripts/test-services.sh env)\")"
    );
}

pub fn options(env: &S3Env, extra: &[(&str, Value)]) -> Options {
    let mut o = Options::new();
    o.insert("endpoint_url".into(), Value::from(env.endpoint.as_str()));
    o.insert("key".into(), Value::from(env.key.as_str()));
    o.insert("secret".into(), Value::from(env.secret.as_str()));
    for (k, v) in extra {
        o.insert((*k).into(), v.clone());
    }
    o
}

pub fn filesystem(env: &S3Env, extra: &[(&str, Value)]) -> S3FileSystem {
    S3FileSystem::from_options(options(env, extra)).expect("valid options")
}

/// A bucket name unique to this process and call.
pub fn unique_bucket(tag: &str) -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!(
        "fsfast-{tag}-{}-{}-{}",
        std::process::id(),
        t % 1_000_000_000,
        N.fetch_add(1, Ordering::Relaxed)
    )
}

/// Delete everything in `bucket` and the bucket itself.
pub async fn destroy_bucket(fs: &S3FileSystem, bucket: &str) {
    if let Ok(all) = fs.find(bucket, &FindOptions::default()).await {
        let names: Vec<String> = all.into_iter().map(|i| i.name).collect();
        for r in fs.rm_files(&names).await {
            if let Err(e) = r {
                eprintln!("cleanup of {bucket}: {e}");
            }
        }
    }
    if let Err(e) = fs.rmdir(bucket).await {
        eprintln!("cleanup: rmdir({bucket}): {e}");
    }
}
