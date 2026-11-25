//! The fsfast-testkit conformance suite against the local OpenSSH server.
//! Gated on `FSFAST_TEST_SFTP_HOST`.

mod common;

use std::sync::Arc;

use fsfast_core::{FileSystem, Value};
use fsfast_testkit::{SuiteConfig, assert_suite, check_names};

async fn run(extra: &[(&str, Value)], cfg: SuiteConfig) {
    let Some(env) = common::env() else { return };
    let fs = env.fs(extra);
    let root = env.dir("suite");
    fs.mkdir(&root, false).await.unwrap();
    let report = assert_suite(Arc::new(fs.clone()), &root, cfg).await;
    eprintln!("{report}");
    for o in &report.outcomes {
        eprintln!("  {:<24} {:>10.2?}", o.name, o.duration);
    }
    // SFTP supports every capability the suite exercises.
    assert_eq!(report.skipped().count(), 0, "{report}");
    assert_eq!(report.passed().count(), check_names().len());
    let left = fs.ls(&root).await.unwrap();
    assert!(left.is_empty(), "suite left {left:?} behind");
    fs.rmdir(&root).await.unwrap();
    fs.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn suite_default_options() {
    run(&[], SuiteConfig::default()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn suite_parallel_checks_small_chunks_two_connections() {
    run(
        &[
            ("connections", Value::Int(2)),
            ("read_chunk_size", Value::Int(20_000)),
            ("write_chunk_size", Value::Int(30_001)),
            ("max_inflight", Value::Int(5)),
        ],
        SuiteConfig::default()
            .parallelism(6)
            .large_file_bytes(6 << 20),
    )
    .await;
}
