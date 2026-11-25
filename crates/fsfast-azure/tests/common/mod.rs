//! Shared helpers for the Azurite integration tests.
//!
//! Gated on `FSFAST_TEST_AZURE_CONNECTION_STRING` (plus `FSFAST_TEST_AZURE_ACCOUNT`,
//! `FSFAST_TEST_AZURE_KEY`, `FSFAST_TEST_AZURE_ENDPOINT` for the non-connection-string
//! tests): `eval "$(scripts/test-services.sh env)"`.

#![allow(dead_code)]

pub mod mock;

use std::sync::atomic::{AtomicU32, Ordering};

use fsfast_azure::AzureBlobFileSystem;
use fsfast_core::{Options, Value};

/// The Azurite connection string, or `None` (skip).
pub fn connection_string() -> Option<String> {
    std::env::var("FSFAST_TEST_AZURE_CONNECTION_STRING")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Print a skip message.
pub fn skip(name: &str) {
    eprintln!(
        "skipping {name}: FSFAST_TEST_AZURE_CONNECTION_STRING is not set (eval \"$(scripts/test-services.sh env)\")"
    );
}

/// Options for `extra` plus the connection string.
pub fn options(cs: &str, extra: &[(&str, Value)]) -> Options {
    let mut o: Options = extra
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    o.insert("connection_string".into(), Value::Str(cs.to_owned()));
    o
}

/// A filesystem on Azurite.
pub fn filesystem(cs: &str, extra: &[(&str, Value)]) -> AzureBlobFileSystem {
    AzureBlobFileSystem::from_options_with_env(options(cs, extra), &|_| None).unwrap()
}

/// A unique container name for this run.
pub fn unique_container(tag: &str) -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "fsfast-{tag}-{}-{:x}-{}",
        std::process::id(),
        nanos & 0xffff_ffff,
        N.fetch_add(1, Ordering::Relaxed)
    )
    .chars()
    .take(63)
    .collect()
}

/// Delete a container created by a test (with everything in it).
pub async fn destroy_container(fs: &AzureBlobFileSystem, container: &str) {
    if let Err(e) = fs.delete_container_raw(container).await {
        eprintln!("cleanup of {container} failed: {e}");
    }
}
