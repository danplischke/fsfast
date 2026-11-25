//! Workloads for comparing fsfast-gcs with gcsfs on the same endpoint
//! (`tools/bench_gcsfs.py` runs the same workloads through gcsfs).
//!
//! ```text
//! eval "$(scripts/test-services.sh env)"
//! cargo run --release -p fsfast-gcs --example gcs_bench -- [size_mib] [repeats]
//! ```
//!
//! Each workload runs `repeats` times (default 3); the best run is reported.
//! The endpoint comes from `FSFAST_TEST_GCS_ENDPOINT` (anonymous access);
//! `FSFAST_BENCH_OPTIONS=name=value,...` adds storage options.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use fsfast_core::{ByteRange, FileSystem, FindOptions, Options, Value, WriteOptions};
use fsfast_gcs::{GCSFileSystem, GcsEnv};
use futures::{StreamExt, stream};

fn best<F>(repeats: usize, mut f: F) -> Duration
where
    F: FnMut() -> Duration,
{
    (0..repeats).map(|_| f()).min().unwrap()
}

fn mbps(bytes: usize, d: Duration) -> f64 {
    bytes as f64 / 1e6 / d.as_secs_f64()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let size_mib: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(128);
    let repeats: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let endpoint = std::env::var("FSFAST_TEST_GCS_ENDPOINT").expect("FSFAST_TEST_GCS_ENDPOINT");
    let mut o = Options::new();
    o.insert("endpoint_url".into(), Value::from(endpoint));
    o.insert("token".into(), Value::from("anon"));
    o.insert("project".into(), Value::from("test-project"));
    if let Ok(extra) = std::env::var("FSFAST_BENCH_OPTIONS") {
        // `name=value,...` integers or booleans, e.g. upload_chunk_size=52428800
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
    let fs = Arc::new(
        GCSFileSystem::from_options_with_env(o, GcsEnv::from_pairs([("NO_GCE_CHECK", "true")]))
            .unwrap(),
    );
    let bucket = format!("fsfast-bench-{}", std::process::id());
    rt.block_on(fs.mkdir(&bucket, true)).unwrap();
    let w = WriteOptions::default();

    // 1. Large object put/get from memory and from/to a local file.
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
    println!(
        "put {size_mib} MiB (pipe_file): {:.0} MB/s",
        mbps(size, put)
    );
    println!(
        "get {size_mib} MiB (cat_file):  {:.0} MB/s",
        mbps(size, get)
    );
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
        mbps(size, put_file)
    );
    println!(
        "get_file {size_mib} MiB:        {:.0} MB/s",
        mbps(size, get_file)
    );
    // Streaming write through open_write (resumable session), 1 MiB writes.
    let stream_put = best(repeats, || {
        let t = Instant::now();
        rt.block_on(async {
            let mut h = fs.open_write(&big, &w).await.unwrap();
            for c in data.chunks(1 << 20) {
                h.write(data.slice_ref(c)).await.unwrap();
            }
            h.close().await.unwrap();
        });
        t.elapsed()
    });
    println!(
        "open_write {size_mib} MiB:      {:.0} MB/s",
        mbps(size, stream_put)
    );

    // 2. 1000 small objects: pipe, cat, info.
    let n = 1000;
    let small: Vec<String> = (0..n).map(|i| format!("{bucket}/small/{i:05}")).collect();
    let payload = Bytes::from(vec![42u8; 4096]);
    for conc in [1usize, 64] {
        let pipe = best(repeats, || {
            let t = Instant::now();
            let res: Vec<_> = rt.block_on(
                stream::iter(small.iter().map(|p| {
                    let fs = fs.clone();
                    let payload = payload.clone();
                    async move { fs.pipe_file(p, payload, &WriteOptions::default()).await }
                }))
                .buffer_unordered(conc)
                .collect(),
            );
            assert!(res.iter().all(Result::is_ok));
            t.elapsed()
        });
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
            "1000 x 4 KiB (concurrency {conc:>2}): pipe {:.0} files/s; cat {:.0} files/s; info {:.0} ops/s",
            n as f64 / pipe.as_secs_f64(),
            n as f64 / cat.as_secs_f64(),
            n as f64 / info.as_secs_f64()
        );
    }

    // 3. Listing: ls and find of the 1000 objects.
    let small_dir = format!("{bucket}/small");
    let ls = best(repeats, || {
        let t = Instant::now();
        assert_eq!(rt.block_on(fs.ls(&small_dir)).unwrap().len(), n);
        t.elapsed()
    });
    let find = best(repeats, || {
        let t = Instant::now();
        let all = rt
            .block_on(fs.find(&bucket, &FindOptions::default()))
            .unwrap();
        assert_eq!(all.len(), n + 1);
        t.elapsed()
    });
    println!(
        "ls 1000 entries: {:.1} ms; find 1001 entries: {:.1} ms",
        ls.as_secs_f64() * 1e3,
        find.as_secs_f64() * 1e3
    );

    // 4. rm of the 1000 objects.
    let rm = {
        let t = Instant::now();
        let res = rt.block_on(fs.rm_files(&small));
        assert!(res.iter().all(Result::is_ok));
        t.elapsed()
    };
    println!(
        "rm 1000 objects: {:.0} objects/s",
        n as f64 / rm.as_secs_f64()
    );
    let s = fs.stats().snapshot();
    println!(
        "requests: {} total, {} retries, {} throttled",
        s.requests, s.retries, s.throttles
    );

    rt.block_on(async {
        let all = fs.find(&bucket, &FindOptions::default()).await.unwrap();
        let names: Vec<String> = all.into_iter().map(|i| i.name).collect();
        fs.rm_files(&names).await;
        fs.rmdir(&bucket).await.unwrap();
    });
}
