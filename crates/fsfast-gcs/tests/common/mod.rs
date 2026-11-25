//! Shared helpers for the integration tests against fake-gcs-server
//! (gated on `FSFAST_TEST_GCS_ENDPOINT`, see each test file).

#![allow(dead_code)]

pub mod mock;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use fsfast_core::{FileSystem, FindOptions, Options, Value};
use fsfast_gcs::{GCSFileSystem, GcsEnv};

/// The emulator endpoint from `scripts/test-services.sh env`.
pub fn endpoint() -> Option<String> {
    std::env::var("FSFAST_TEST_GCS_ENDPOINT")
        .ok()
        .filter(|v| !v.is_empty())
}

pub fn skip(what: &str) {
    eprintln!(
        "skipping {what}: set FSFAST_TEST_GCS_ENDPOINT (eval \"$(scripts/test-services.sh env)\")"
    );
}

pub fn options(endpoint: &str, extra: &[(&str, Value)]) -> Options {
    let mut o = Options::new();
    o.insert("endpoint_url".into(), Value::from(endpoint));
    o.insert("token".into(), Value::from("anon"));
    o.insert("project".into(), Value::from("test-project"));
    for (k, v) in extra {
        o.insert((*k).into(), v.clone());
    }
    o
}

/// An anonymous filesystem on the emulator, isolated from the process
/// environment (so a developer's gcloud credentials do not interfere).
pub fn filesystem(endpoint: &str, extra: &[(&str, Value)]) -> GCSFileSystem {
    GCSFileSystem::from_options_with_env(
        options(endpoint, extra),
        GcsEnv::from_pairs([("NO_GCE_CHECK", "true")]),
    )
    .expect("valid options")
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
pub async fn destroy_bucket(fs: &GCSFileSystem, bucket: &str) {
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
