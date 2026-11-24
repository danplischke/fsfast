//! The fsfast-testkit conformance suite against the local Samba, on the
//! signing-required share and on the encryption-required share. Gated on
//! `FSFAST_TEST_SMB_HOST`.

mod common;

use std::sync::Arc;

use fsfast_core::{FileSystem, Value};
use fsfast_testkit::{SuiteConfig, assert_suite, check_names};

async fn run_on(share: &str, extra: &[(&str, Value)], cfg: SuiteConfig) {
    // Samba presents names that Windows cannot represent (here the
    // trailing dots of "comma,dot.dot..") under mangled 8.3 aliases in
    // directory listings, exactly as it does for smbclient, so the listing
    // part of `special_names` cannot pass against Samba without the SMB
    // 3.1.1 POSIX extensions. `live.rs` covers the representable names.
    let cfg = cfg.skip(["special_names"]);
    let Some(env) = common::env() else { return };
    let fs = env.fs(extra);
    let root = format!("/{share}/{}", common::unique("suite"));
    let report = assert_suite(Arc::new(fs.clone()), &root, cfg).await;
    eprintln!("{report}");
    for o in &report.outcomes {
        eprintln!("  {:<24} {:>10.2?}", o.name, o.duration);
    }
    // SMB supports every capability the suite exercises: only the check
    // skipped above is not run.
    assert_eq!(report.skipped().count(), 1, "{report}");
    assert_eq!(report.passed().count(), check_names().len() - 1);
    assert!(!fs.exists(&root).await.unwrap(), "suite left {root} behind");
    fs.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn suite_on_signing_share() {
    let Some(env) = common::env() else { return };
    run_on(&env.share, &[], SuiteConfig::default()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn suite_on_encrypted_share() {
    let Some(env) = common::env() else { return };
    run_on(&env.enc_share, &[], SuiteConfig::default()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn suite_parallel_checks_two_connections_small_chunks() {
    let Some(env) = common::env() else { return };
    run_on(
        &env.share,
        &[
            ("connections", Value::Int(2)),
            ("read_chunk_size", Value::Int(64 << 10)),
            ("write_chunk_size", Value::Int(96 << 10)),
            ("auto_mkdir", Value::Bool(true)),
        ],
        SuiteConfig::default().parallelism(6).large_file_bytes(8 << 20),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn suite_on_smb2_0_2() {
    let Some(env) = common::env() else { return };
    run_on(
        &env.share,
        &[("max_dialect", Value::Str("2.0.2".into()))],
        SuiteConfig::default().large_file_bytes(4 << 20),
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn suite_on_current_thread_runtime_encrypt_forced() {
    let Some(env) = common::env() else { return };
    run_on(
        &env.share,
        &[("encrypt", Value::Bool(true))],
        SuiteConfig::default().large_file_bytes(4 << 20),
    )
    .await;
}
