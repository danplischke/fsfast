//! Throughput and many-file benchmarks against the local OpenSSH server.
//!
//! Gated on `FSFAST_TEST_SFTP_HOST` *and* `FSFAST_SFTP_BENCH=1` (they take a
//! while); run in release mode:
//!
//! ```text
//! eval "$(scripts/test-services.sh env)"
//! FSFAST_SFTP_BENCH=1 cargo test --release -p fsfast-sftp --test bench -- --nocapture --test-threads=1
//! ```
//!
//! `FSFAST_SFTP_BENCH_MB` sets the large-file size (default 256 MiB) and
//! `FSFAST_SFTP_BENCH_FILES` the small-file count (default 1000 x 16 KiB).

mod common;

use std::time::Instant;

use bytes::Bytes;
use fsfast_core::{ByteRange, FileSystem, Value, WriteOptions};
use futures::StreamExt;

fn enabled() -> Option<common::Env> {
    let env = common::env()?;
    if std::env::var("FSFAST_SFTP_BENCH").ok().as_deref() != Some("1") {
        eprintln!("skipping SFTP benchmark: set FSFAST_SFTP_BENCH=1");
        return None;
    }
    Some(env)
}

fn mb() -> usize {
    std::env::var("FSFAST_SFTP_BENCH_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(256)
}

fn files() -> usize {
    std::env::var("FSFAST_SFTP_BENCH_FILES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000)
}

fn rate(bytes: usize, secs: f64) -> String {
    format!("{:8.1} MB/s", bytes as f64 / secs / 1e6)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_file_throughput() {
    let Some(env) = enabled() else { return };
    let size = mb() << 20;
    let fs = env.fs(&[]);
    let dir = env.dir("bench");
    fs.mkdir(&dir, false).await.unwrap();
    let data: Bytes = (0..size).map(|i| (i * 31 % 251) as u8).collect::<Vec<u8>>().into();
    let p = format!("{dir}/big.bin");
    // Warm up the connection.
    fs.info(&dir).await.unwrap();

    for round in 0..2 {
        let t = Instant::now();
        let mut w = fs.open_write(&p, &WriteOptions::default()).await.unwrap();
        for c in data.chunks(1 << 20) {
            w.write(data.slice_ref(c)).await.unwrap();
        }
        w.close().await.unwrap();
        let dt = t.elapsed().as_secs_f64();
        eprintln!("round {round}: write   {} MiB: {}  ({dt:.2}s)", size >> 20, rate(size, dt));

        let t = Instant::now();
        let got = fs.cat_file(&p, ByteRange::Full).await.unwrap();
        let dt = t.elapsed().as_secs_f64();
        assert_eq!(got.len(), size);
        assert!(got == data, "read back mismatch");
        drop(got);
        eprintln!("round {round}: cat     {} MiB: {}  ({dt:.2}s)", size >> 20, rate(size, dt));

        let local = std::env::temp_dir().join(format!("{}.bin", common::unique("get")));
        let t = Instant::now();
        fs.get_file(&p, &local).await.unwrap();
        let dt = t.elapsed().as_secs_f64();
        eprintln!("round {round}: get     {} MiB: {}  ({dt:.2}s)", size >> 20, rate(size, dt));

        let p2 = format!("{dir}/put.bin");
        let t = Instant::now();
        fs.put_file(&local, &p2, &WriteOptions::default()).await.unwrap();
        let dt = t.elapsed().as_secs_f64();
        eprintln!("round {round}: put     {} MiB: {}  ({dt:.2}s)", size >> 20, rate(size, dt));
        let _ = std::fs::remove_file(&local);

        let p3 = format!("{dir}/copy.bin");
        let t = Instant::now();
        fs.cp_file(&p, &p3).await.unwrap();
        let dt = t.elapsed().as_secs_f64();
        eprintln!("round {round}: cp_file {} MiB: {}  ({dt:.2}s, server-side)", size >> 20, rate(size, dt));
    }
    common::rm_tree(&fs, &dir).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_small_files() {
    let Some(env) = enabled() else { return };
    let n = files();
    let fs = env.fs(&[("connections", Value::Int(4))]);
    let dir = env.dir("benchsmall");
    fs.mkdir(&dir, false).await.unwrap();
    let payload = Bytes::from(vec![7u8; 16 << 10]);
    let paths: Vec<String> = (0..n).map(|i| format!("{dir}/f{i:05}")).collect();
    fs.info(&dir).await.unwrap();

    for conc in [1usize, 32] {
        let t = Instant::now();
        futures::stream::iter(paths.iter())
            .map(|p| {
                let fs = &fs;
                let payload = payload.clone();
                async move { fs.pipe_file(p, payload, &WriteOptions::default()).await.unwrap() }
            })
            .buffer_unordered(conc)
            .collect::<Vec<_>>()
            .await;
        let dt = t.elapsed().as_secs_f64();
        eprintln!("conc {conc:2}: pipe  {n} x 16 KiB: {:8.0} files/s", n as f64 / dt);

        let t = Instant::now();
        futures::stream::iter(paths.iter())
            .map(|p| {
                let fs = &fs;
                async move { fs.cat_file(p, ByteRange::Full).await.unwrap().len() }
            })
            .buffer_unordered(conc)
            .collect::<Vec<_>>()
            .await;
        let dt = t.elapsed().as_secs_f64();
        eprintln!("conc {conc:2}: cat   {n} x 16 KiB: {:8.0} files/s", n as f64 / dt);

        let t = Instant::now();
        futures::stream::iter(paths.iter())
            .map(|p| {
                let fs = &fs;
                async move { fs.info(p).await.unwrap().size }
            })
            .buffer_unordered(conc)
            .collect::<Vec<_>>()
            .await;
        let dt = t.elapsed().as_secs_f64();
        eprintln!("conc {conc:2}: info  {n}: {:8.0} ops/s", n as f64 / dt);
        eprintln!("          connections in pool: {}", fs.connections());
    }
    let t = Instant::now();
    let l = fs.ls(&dir).await.unwrap();
    let dt = t.elapsed().as_secs_f64();
    assert_eq!(l.len(), n);
    eprintln!("ls of {n} entries: {:.1} ms", dt * 1e3);
    let t = Instant::now();
    let r = fs.rm_files(&paths).await;
    assert!(r.iter().all(Result::is_ok));
    let dt = t.elapsed().as_secs_f64();
    eprintln!("rm_files {n}: {:8.0} files/s", n as f64 / dt);
    fs.rmdir(&dir).await.unwrap();
}
