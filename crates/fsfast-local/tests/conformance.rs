//! The fsfast-testkit conformance suite against the local backend, under a
//! fresh temporary directory. Needs no external service, so it always runs.
//!
//! Set `FSFAST_TEST_LOCAL_ROOT` to run it under another directory as well
//! (e.g. a tmpfs, a network mount or a different filesystem type).

use std::sync::Arc;

use fsfast_core::{FileSystem, FindOptions, Options};
use fsfast_local::LocalFileSystem;
use fsfast_testkit::{SuiteConfig, assert_suite, check_names};

fn root_of(dir: &tempfile::TempDir) -> String {
    let p = dir.path().to_str().expect("UTF-8 temp dir").to_owned();
    // The suite compares `info().name` with the paths it builds, so give it
    // the canonical (stripped) form.
    fsfast_local::strip_protocol(&p).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_passes_the_suite() {
    let dir = tempfile::tempdir().unwrap();
    let root = root_of(&dir);
    let fs = LocalFileSystem::new();
    let report = assert_suite(Arc::new(fs.clone()), &root, SuiteConfig::default()).await;
    eprintln!("{report}");
    // Local supports every capability the suite exercises: nothing skipped.
    assert_eq!(report.skipped().count(), 0, "{report}");
    assert_eq!(report.passed().count(), check_names().len());
    // The suite removed everything it created.
    let left = fs
        .find(
            &root,
            &FindOptions {
                maxdepth: None,
                withdirs: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(left.len(), 1, "left behind: {left:?}"); // the root itself
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_passes_the_suite_with_parallel_checks_and_auto_mkdir() {
    let dir = tempfile::tempdir().unwrap();
    // A root that does not exist yet: the suite creates it and removes it.
    let root = format!("{}/not/yet/there", root_of(&dir));
    let mut opts = Options::new();
    opts.insert("auto_mkdir".into(), true.into());
    let fs = LocalFileSystem::from_options(opts).unwrap();
    let cfg = SuiteConfig::default()
        .parallelism(6)
        .large_file_bytes(8 << 20);
    assert_suite(Arc::new(fs), &root, cfg).await;
    assert!(!dir.path().join("not").exists());
}

#[tokio::test(flavor = "current_thread")]
async fn local_passes_the_suite_on_a_current_thread_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let root = root_of(&dir);
    let fs: Arc<dyn FileSystem> = Arc::new(LocalFileSystem::new());
    assert_suite(fs, &root, SuiteConfig::default().large_file_bytes(4 << 20)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_passes_the_suite_under_configured_root() {
    let Ok(root) = std::env::var("FSFAST_TEST_LOCAL_ROOT") else {
        eprintln!("skipping: set FSFAST_TEST_LOCAL_ROOT to run the suite under another directory");
        return;
    };
    let root = fsfast_local::strip_protocol(&root).into_owned();
    let fs: Arc<dyn FileSystem> = Arc::new(LocalFileSystem::new());
    assert_suite(fs, &root, SuiteConfig::default()).await;
}
