//! The fsfast-testkit conformance suite against Azurite, in a fresh
//! container.
//!
//! Gated on `FSFAST_TEST_AZURE_CONNECTION_STRING` (`eval "$(scripts/test-services.sh env)"`).

mod common;

use std::sync::Arc;

use common::{connection_string, destroy_container, filesystem, skip, unique_container};
use fsfast_core::FileSystem;
use fsfast_testkit::{SuiteConfig, assert_suite};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conformance_suite() {
    let Some(cs) = connection_string() else {
        return skip("conformance_suite");
    };
    let fs = filesystem(&cs, &[]);
    let container = unique_container("conf");
    fs.mkdir(&container, true).await.unwrap();
    let dynfs: Arc<dyn FileSystem> = Arc::new(fs.clone());
    let report = assert_suite(
        dynfs,
        &format!("{container}/suite"),
        SuiteConfig::default().parallelism(4),
    )
    .await;
    eprintln!("{report}");
    destroy_container(&fs, &container).await;
}
