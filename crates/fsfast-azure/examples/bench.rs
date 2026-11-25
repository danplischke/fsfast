//! Throughput benchmark against Azurite (compare with
//! `tools/bench_adlfs.py`, which runs the same workload through adlfs).
//!
//! ```text
//! eval "$(scripts/test-services.sh env)"
//! cargo run --release -p fsfast-azure --example bench -- [large_mib] [small_count] [list_count]
//! ```

use std::time::Instant;

use bytes::Bytes;
use fsfast_azure::AzureBlobFileSystem;
use fsfast_core::{ByteRange, FileSystem, FindOptions, Options, Value, WriteOptions};
use futures::{StreamExt, stream};

fn arg(i: usize, default: usize) -> usize {
    std::env::args()
        .nth(i)
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cs = std::env::var("FSFAST_TEST_AZURE_CONNECTION_STRING")
        .expect("set FSFAST_TEST_AZURE_CONNECTION_STRING");
    let large_mib = arg(1, 256);
    let small_count = arg(2, 500);
    let list_count = arg(3, 2000);
    let mut o = Options::new();
    o.insert("connection_string".into(), Value::Str(cs));
    // Optional tuning, e.g. FSFAST_BENCH_OPTS="blocksize=33554432,upload_concurrency=16".
    if let Ok(extra) = std::env::var("FSFAST_BENCH_OPTS") {
        for kv in extra.split(',').filter(|s| !s.is_empty()) {
            let (k, v) = kv.split_once('=').expect("key=value");
            o.insert(k.to_owned(), Value::Int(v.parse().expect("integer option")));
        }
    }
    let fs = AzureBlobFileSystem::from_options(o).unwrap();
    let c = format!("bench-rs-{}", std::process::id());
    fs.mkdir(&c, true).await.unwrap();
    let w = WriteOptions::default();

    // Large blob.
    let data = Bytes::from(
        (0..large_mib << 20)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<u8>>(),
    );
    let p = format!("{c}/large.bin");
    let t = Instant::now();
    fs.pipe_file(&p, data.clone(), &w).await.unwrap();
    let put = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let got = fs.cat_file(&p, ByteRange::Full).await.unwrap();
    let get = t.elapsed().as_secs_f64();
    assert_eq!(got.len(), data.len());
    println!(
        "large put  {large_mib} MiB: {:.2} s, {:.1} MB/s",
        put,
        data.len() as f64 / put / 1e6
    );
    println!(
        "large get  {large_mib} MiB: {:.2} s, {:.1} MB/s",
        get,
        data.len() as f64 / get / 1e6
    );

    // Many small blobs, 32 in flight.
    let small = Bytes::from(vec![7u8; 4096]);
    let paths: Vec<String> = (0..small_count)
        .map(|i| format!("{c}/small/{i:05}"))
        .collect();
    let t = Instant::now();
    let futs: Vec<_> = paths
        .iter()
        .map(|p| fs.pipe_file(p, small.clone(), &w))
        .collect();
    let r: Vec<_> = stream::iter(futs).buffer_unordered(32).collect().await;
    assert!(r.iter().all(Result::is_ok));
    let el = t.elapsed().as_secs_f64();
    println!(
        "small put  {small_count} x 4 KiB: {:.2} s, {:.0} ops/s",
        el,
        small_count as f64 / el
    );
    let t = Instant::now();
    let futs: Vec<_> = paths
        .iter()
        .map(|p| fs.cat_file(p, ByteRange::Full))
        .collect();
    let r: Vec<_> = stream::iter(futs).buffer_unordered(32).collect().await;
    assert!(r.iter().all(|r| r.as_ref().is_ok_and(|b| b.len() == 4096)));
    let el = t.elapsed().as_secs_f64();
    println!(
        "small get  {small_count} x 4 KiB: {:.2} s, {:.0} ops/s",
        el,
        small_count as f64 / el
    );
    let t = Instant::now();
    let futs: Vec<_> = paths.iter().map(|p| fs.info(p)).collect();
    let r: Vec<_> = stream::iter(futs).buffer_unordered(32).collect().await;
    assert!(r.iter().all(Result::is_ok));
    let el = t.elapsed().as_secs_f64();
    println!(
        "small info {small_count}: {:.2} s, {:.0} ops/s",
        el,
        small_count as f64 / el
    );

    // Listing.
    let empty = Bytes::new();
    let lpaths: Vec<String> = (0..list_count)
        .map(|i| format!("{c}/list/d{:02}/{i:05}", i % 20))
        .collect();
    let futs: Vec<_> = lpaths
        .iter()
        .map(|p| fs.pipe_file(p, empty.clone(), &w))
        .collect();
    let r: Vec<_> = stream::iter(futs).buffer_unordered(32).collect().await;
    assert!(r.iter().all(Result::is_ok));
    let t = Instant::now();
    let found = fs
        .find(&format!("{c}/list"), &FindOptions::default())
        .await
        .unwrap();
    let el = t.elapsed().as_secs_f64();
    assert_eq!(found.len(), list_count);
    println!(
        "find       {list_count} blobs: {:.3} s, {:.0} entries/s",
        el,
        list_count as f64 / el
    );
    let t = Instant::now();
    let mut n = 0;
    for d in 0..20 {
        n += fs.ls(&format!("{c}/list/d{d:02}")).await.unwrap().len();
    }
    let el = t.elapsed().as_secs_f64();
    assert_eq!(n, list_count);
    println!(
        "ls x20     {list_count} blobs: {:.3} s, {:.0} entries/s",
        el,
        list_count as f64 / el
    );

    // Cleanup (rm_files of everything, then the container).
    let t = Instant::now();
    let mut all: Vec<String> = paths;
    all.extend(lpaths);
    all.push(p);
    let r = fs.rm_files(&all).await;
    assert!(r.iter().all(Result::is_ok));
    let el = t.elapsed().as_secs_f64();
    println!(
        "rm         {} blobs: {:.2} s, {:.0} ops/s",
        all.len(),
        el,
        all.len() as f64 / el
    );
    fs.rmdir(&c).await.unwrap();
    let s = fs.stats().snapshot();
    println!(
        "requests {} retries {} errors {}",
        s.requests, s.retries, s.errors
    );
}
