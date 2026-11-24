//! The fsfast-testkit conformance suite against the memory backend.
//!
//! Needs no external service, so it always runs.

use std::sync::Arc;

use fsfast_core::{FileSystem, FindOptions};
use fsfast_memory::MemoryFileSystem;
use fsfast_testkit::{CheckStatus, SuiteConfig, assert_suite, check_names};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn global_store_passes_the_suite() {
    let fs = MemoryFileSystem::new();
    let report = assert_suite(Arc::new(fs.clone()), "/fsfast-testkit", SuiteConfig::default()).await;
    eprintln!("{report}");
    // Memory supports every capability the suite exercises: nothing skipped.
    assert_eq!(report.skipped().count(), 0, "{report}");
    assert_eq!(report.passed().count(), check_names().len());
    // The suite cleaned up after itself, including the root it created.
    let left = fs
        .find("/fsfast-testkit", &FindOptions { maxdepth: None, withdirs: true })
        .await
        .unwrap();
    assert!(left.is_empty(), "left behind: {left:?}");
    assert!(!fs.exists("/fsfast-testkit").await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn isolated_store_passes_the_suite_with_parallel_checks() {
    let fs = MemoryFileSystem::new_isolated();
    let cfg = SuiteConfig::default().parallelism(8).large_file_bytes(8 << 20);
    let report = assert_suite(Arc::new(fs.clone()), "/scratch", cfg).await;
    assert!(report.outcomes.iter().all(|o| o.status == CheckStatus::Passed));
    // Only the root pseudo-directory survives; "/scratch" was implied.
    assert_eq!(fs.file_count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn suite_runs_on_a_current_thread_runtime() {
    let fs: Arc<dyn FileSystem> = Arc::new(MemoryFileSystem::new_isolated());
    assert_suite(fs, "/ct", SuiteConfig::default().large_file_bytes(2 << 20)).await;
}

#[tokio::test]
async fn skip_and_only_are_honoured() {
    let fs: Arc<dyn FileSystem> = Arc::new(MemoryFileSystem::new_isolated());
    let cfg = SuiteConfig::default()
        .only(["info", "ls", "touch"])
        .skip(["touch"]);
    let report = assert_suite(fs, "/sel", cfg).await;
    assert_eq!(report.outcome("info").unwrap().status, CheckStatus::Passed);
    assert_eq!(report.outcome("ls").unwrap().status, CheckStatus::Passed);
    assert!(matches!(report.outcome("touch").unwrap().status, CheckStatus::Skipped(_)));
    assert!(matches!(report.outcome("find").unwrap().status, CheckStatus::Skipped(_)));
    assert_eq!(report.outcomes.len(), check_names().len());
}
