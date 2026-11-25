//! The fsfast-testkit conformance suite against fake-gcs-server, in a fresh
//! bucket.
//!
//! Gated on `FSFAST_TEST_GCS_ENDPOINT` (`eval "$(scripts/test-services.sh env)"`).

mod common;

use std::sync::Arc;

use common::{destroy_bucket, endpoint, filesystem, skip, unique_bucket};
use fsfast_core::FileSystem;
use fsfast_testkit::{SuiteConfig, assert_suite};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conformance_suite() {
    let Some(ep) = endpoint() else {
        return skip("conformance_suite");
    };
    let fs = filesystem(&ep, &[]);
    let bucket = unique_bucket("conf");
    fs.mkdir(&bucket, true).await.unwrap();
    let dynfs: Arc<dyn FileSystem> = Arc::new(fs.clone());
    let report = assert_suite(
        dynfs,
        &format!("{bucket}/suite"),
        SuiteConfig::default().parallelism(4),
    )
    .await;
    eprintln!("{report}");
    destroy_bucket(&fs, &bucket).await;
}
