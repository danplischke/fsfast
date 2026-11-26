//! Bulk downloads stay inside the global memory budget. A separate test
//! binary: it shrinks and drains the process-wide budget, which would stall
//! unrelated tests running in parallel in the same process.

use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Response;
use fsfast_core::{FileSystem, Options, Value};
use fsfast_engine::budget::MemoryBudget;
use fsfast_s3::profile::Env;
use fsfast_s3::{S3FileSystem, S3Options};

const SIZE: usize = 3 << 20;

/// Serves one object of `SIZE` bytes with ranged GETs.
async fn serve() -> String {
    let app = Router::new().fallback(|req: Request| async move {
        let data: Vec<u8> = (0..SIZE).map(|i| i as u8).collect();
        let range = req
            .headers()
            .get("range")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let r = Response::builder().header("etag", "\"e\"");
        match range {
            Some(r0) => {
                let (a, b) = r0.trim_start_matches("bytes=").split_once('-').unwrap();
                let a: usize = a.parse().unwrap();
                let b: usize = b.parse::<usize>().unwrap().min(SIZE - 1);
                r.status(StatusCode::PARTIAL_CONTENT)
                    .header("content-range", format!("bytes {a}-{b}/{SIZE}"))
                    .body(Body::from(data[a..=b].to_vec()))
                    .unwrap()
            }
            None => r.status(200).body(Body::from(data)).unwrap(),
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn get_file_parts_wait_for_the_memory_budget() {
    let base = serve().await;
    let mut o = Options::new();
    o.insert("endpoint_url".into(), Value::from(base.as_str()));
    o.insert("key".into(), Value::from("AK"));
    o.insert("secret".into(), Value::from("SK"));
    o.insert("request_size".into(), Value::Int(1 << 20));
    let fs = S3FileSystem::with_options(
        S3Options::parse_with_env(o, Env::from_map([("AWS_EC2_METADATA_DISABLED", "true")]))
            .unwrap(),
    );
    let budget = MemoryBudget::global();
    budget.resize(4 << 20);
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("out");
    // The whole budget is taken: the parallel parts after the first GET
    // must wait for it.
    let held = budget.acquire(4 << 20).await;
    let blocked =
        tokio::time::timeout(Duration::from_millis(500), fs.get_file("b/k", &local)).await;
    assert!(
        blocked.is_err(),
        "get_file read its parts without budget: {blocked:?}"
    );
    drop(held);
    tokio::time::timeout(Duration::from_secs(30), fs.get_file("b/k", &local))
        .await
        .expect("get_file finishes once the budget is free")
        .unwrap();
    let got = std::fs::read(&local).unwrap();
    assert_eq!(got.len(), SIZE);
    assert!(got.iter().enumerate().all(|(i, b)| *b == i as u8));
    assert_eq!(budget.in_use(), 0);
}
