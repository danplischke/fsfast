//! Workloads for comparing fsfast-s3 with s3fs on the same endpoint
//! (`tools/bench_s3fs.py` runs the same workloads through s3fs).
//!
//! ```text
//! eval "$(scripts/test-services.sh env)"
//! cargo run --release -p fsfast-s3 --example s3_bench -- [size_mib] [repeats]
//! ```
//!
//! Each workload runs `repeats` times (default 3); the best run is reported.
//! The endpoint and credentials come from `FSFAST_TEST_S3_ENDPOINT`,
//! `FSFAST_TEST_S3_KEY`, `FSFAST_TEST_S3_SECRET`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use fsfast_core::{ByteRange, FileSystem, Options, Value, WriteOptions};
use fsfast_s3::S3FileSystem;
use futures::{StreamExt, stream};

fn best<F>(repeats: usize, mut f: F) -> Duration
where
    F: FnMut() -> Duration,
{
    (0..repeats).map(|_| f()).min().unwrap()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let size_mib: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(256);
    let repeats: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} not set"));
    let mut o = Options::new();
    o.insert(
        "endpoint_url".into(),
        Value::from(env("FSFAST_TEST_S3_ENDPOINT")),
    );
    o.insert("key".into(), Value::from(env("FSFAST_TEST_S3_KEY")));
    o.insert("secret".into(), Value::from(env("FSFAST_TEST_S3_SECRET")));
    if let Ok(extra) = std::env::var("FSFAST_BENCH_OPTIONS") {
        // `name=value,...` integers or booleans, e.g. strict_delete=false
        for kv in extra.split(',').filter(|s| !s.is_empty()) {
            let (k, v) = kv.split_once('=').unwrap();
            let v = match v {
                "true" => Value::Bool(true),
                "false" => Value::Bool(false),
                n => Value::Int(n.parse().unwrap()),
            };
            o.insert(k.into(), v);
        }
    }
    let fs = Arc::new(S3FileSystem::from_options(o).unwrap());
    let bucket = format!("fsfast-bench-{}", std::process::id());
    rt.block_on(fs.mkdir(&bucket, true)).unwrap();
    let w = WriteOptions::default();

    // 1. Large object put/get from memory.
    let size = size_mib << 20;
    let data: Bytes = (0..size)
        .map(|i| (i * 7 % 251) as u8)
        .collect::<Vec<u8>>()
        .into();
    let big = format!("{bucket}/big.bin");
    let put = best(repeats, || {
        let t = Instant::now();
        rt.block_on(fs.pipe_file(&big, data.clone(), &w)).unwrap();
        t.elapsed()
    });
    let get = best(repeats, || {
        let t = Instant::now();
        let got = rt.block_on(fs.cat_file(&big, ByteRange::Full)).unwrap();
        assert_eq!(got.len(), size);
        t.elapsed()
    });
    let mib = size as f64 / (1 << 20) as f64;
    println!(
        "put {size_mib} MiB (pipe_file): {:.0} MB/s ({:.2} s)",
        mib / put.as_secs_f64() * 1.048576,
        put.as_secs_f64()
    );
    println!(
        "get {size_mib} MiB (cat_file):  {:.0} MB/s ({:.2} s)",
        mib / get.as_secs_f64() * 1.048576,
        get.as_secs_f64()
    );

    // 1b. Local file put/get.
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("big.bin");
    std::fs::write(&local, &data).unwrap();
    let out = dir.path().join("out.bin");
    let put_file = best(repeats, || {
        let t = Instant::now();
        rt.block_on(fs.put_file(&local, &big, &w)).unwrap();
        t.elapsed()
    });
    let get_file = best(repeats, || {
        let t = Instant::now();
        rt.block_on(fs.get_file(&big, &out)).unwrap();
        t.elapsed()
    });
    println!(
        "put_file {size_mib} MiB:        {:.0} MB/s",
        mib / put_file.as_secs_f64() * 1.048576
    );
    println!(
        "get_file {size_mib} MiB:        {:.0} MB/s",
        mib / get_file.as_secs_f64() * 1.048576
    );

    // `FSFAST_BENCH_ONLY=large`: stop after the large-object workloads.
    let large_only = std::env::var("FSFAST_BENCH_ONLY").is_ok_and(|v| v == "large");

    // 2. 1000 small objects: cat and info.
    let n = if large_only { 0 } else { 1000 };
    let small: Vec<String> = (0..n).map(|i| format!("{bucket}/small/{i:05}")).collect();
    let payload = Bytes::from(vec![42u8; 4096]);
    rt.block_on(async {
        stream::iter(small.iter().map(|p| {
            let fs = fs.clone();
            let payload = payload.clone();
            async move { fs.pipe_file(p, payload, &WriteOptions::default()).await }
        }))
        .buffer_unordered(64)
        .collect::<Vec<_>>()
        .await
    });
    for conc in [1usize, 64] {
        let cat = best(repeats, || {
            let t = Instant::now();
            let res: Vec<_> = rt.block_on(
                stream::iter(small.iter().map(|p| {
                    let fs = fs.clone();
                    async move { fs.cat_file(p, ByteRange::Full).await }
                }))
                .buffer_unordered(conc)
                .collect(),
            );
            assert!(
                res.iter()
                    .all(|r| r.as_ref().is_ok_and(|b| b.len() == 4096))
            );
            t.elapsed()
        });
        let info = best(repeats, || {
            let t = Instant::now();
            let res: Vec<_> = rt.block_on(
                stream::iter(small.iter().map(|p| {
                    let fs = fs.clone();
                    async move { fs.info(p).await }
                }))
                .buffer_unordered(conc)
                .collect(),
            );
            assert!(res.iter().all(Result::is_ok));
            t.elapsed()
        });
        println!(
            "cat 1000 x 4 KiB (concurrency {conc:>2}): {:.0} files/s; info 1000: {:.0} ops/s",
            n as f64 / cat.as_secs_f64(),
            n as f64 / info.as_secs_f64()
        );
    }

    // 3. rm of 5000 keys.
    let m = if large_only { 0 } else { 5000 };
    let doomed: Vec<String> = (0..m).map(|i| format!("{bucket}/rm/{i:05}")).collect();
    let mut rm_times = Vec::new();
    for _ in 0..repeats {
        rt.block_on(async {
            stream::iter(doomed.iter().map(|p| {
                let fs = fs.clone();
                async move {
                    fs.pipe_file(p, Bytes::from_static(b"x"), &WriteOptions::default())
                        .await
                }
            }))
            .buffer_unordered(64)
            .collect::<Vec<_>>()
            .await
        });
        let t = Instant::now();
        let res = rt.block_on(fs.rm_files(&doomed));
        rm_times.push(t.elapsed());
        assert!(res.iter().all(Result::is_ok));
    }
    let rm = rm_times.into_iter().min().unwrap();
    println!(
        "rm 5000 keys: {:.2} s ({:.0} keys/s)",
        rm.as_secs_f64(),
        m as f64 / rm.as_secs_f64()
    );
    let s = fs.stats().snapshot();
    println!(
        "requests: {} total, {} retries, {} throttled",
        s.requests, s.retries, s.throttles
    );

    // Cleanup.
    rt.block_on(async {
        let all = fs.find(&bucket, &Default::default()).await.unwrap();
        let names: Vec<String> = all.into_iter().map(|i| i.name).collect();
        fs.rm_files(&names).await;
        fs.rmdir(&bucket).await.unwrap();
    });
}
