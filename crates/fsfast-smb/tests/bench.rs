//! Throughput and metadata-rate measurements against the local Samba,
//! optionally side by side with fsspec's `SMBFileSystem` (smbprotocol).
//!
//! Gated on `FSFAST_TEST_SMB_HOST` and `FSFAST_TEST_SMB_BENCH=1` (run with
//! `--release --nocapture`). With `FSFAST_TEST_FSSPEC_PYTHON` set, the same
//! workloads run through fsspec on the same server and both results are
//! printed. `FSFAST_TEST_SMB_BENCH_MB` sets the large-file size (default
//! 256 MiB).

mod common;

use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use fsfast_core::{ByteRange, FileSystem, Value, WriteOptions};
use fsfast_smb::SmbFileSystem;
use futures::StreamExt;

const FSSPEC_SCRIPT: &str = r#"
import sys, time, uuid
from fsspec.implementations.smb import SMBFileSystem
host, port, user, pw, share, mb = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], int(sys.argv[6])
fs = SMBFileSystem(host=host, port=port, username=user, password=pw)
root = f"/{share}/fsfast-bench-py-{uuid.uuid4().hex[:8]}"
fs.mkdir(root)
def rate(label, n, unit, secs):
    print(f"{label}\t{n/secs:.1f}\t{unit}\t{secs:.3f}", flush=True)
try:
    data = bytes(range(256)) * (mb * 4096)
    t = time.perf_counter()
    with fs.open(root + "/big.bin", "wb", block_size=8 << 20) as f:
        for i in range(0, len(data), 8 << 20):
            f.write(data[i:i + (8 << 20)])
    rate("seq_write", mb, "MB/s", time.perf_counter() - t)
    t = time.perf_counter()
    got = fs.cat_file(root + "/big.bin")
    rate("seq_read", mb, "MB/s", time.perf_counter() - t)
    assert len(got) == len(data)
    del got
    fs.rm_file(root + "/big.bin")
    fs.mkdir(root + "/small")
    t = time.perf_counter()
    for i in range(1000):
        fs.pipe_file(f"{root}/small/f{i:05}", b"x" * 4096)
    rate("pipe_1000x4k", 1000, "ops/s", time.perf_counter() - t)
    t = time.perf_counter()
    for i in range(1000):
        fs.info(f"{root}/small/f{i:05}")
    rate("info_1000", 1000, "ops/s", time.perf_counter() - t)
    t = time.perf_counter()
    for i in range(1000):
        fs.cat_file(f"{root}/small/f{i:05}")
    rate("cat_1000x4k", 1000, "ops/s", time.perf_counter() - t)
finally:
    fs.rm(root, recursive=True)
"#;

const FSSPEC_LS_SCRIPT: &str = r#"
import sys, time
from fsspec.implementations.smb import SMBFileSystem
host, port, user, pw, d = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
fs = SMBFileSystem(host=host, port=port, username=user, password=pw)
t = time.perf_counter()
n = len(fs.ls(d, detail=False))
s = time.perf_counter() - t
print(f"ls_names_{n}\t{1/s:.2f}\tlistings/s\t{s:.3f}", flush=True)
t = time.perf_counter()
n = len(fs.ls(d, detail=True))
s = time.perf_counter() - t
print(f"ls_detail_{n}\t{1/s:.4f}\tlistings/s\t{s:.3f}", flush=True)
"#;

fn report(label: &str, n: f64, unit: &str, secs: f64) {
    println!("fsfast\t{label}\t{:.1}\t{unit}\t{secs:.3}", n / secs);
}

async fn run_fsfast(fs: &SmbFileSystem, share: &str, mb: usize) {
    let root = format!("/{share}/{}", common::unique("bench"));
    fs.mkdir(&root, false).await.unwrap();
    let data = common::pattern(mb << 20, 7);
    let big = format!("{root}/big.bin");

    // Sequential write through a write handle in 8 MiB writes.
    let t = Instant::now();
    let mut w = fs.open_write(&big, &WriteOptions::default()).await.unwrap();
    for off in (0..data.len()).step_by(8 << 20) {
        w.write(data.slice(off..(off + (8 << 20)).min(data.len())))
            .await
            .unwrap();
    }
    w.close().await.unwrap();
    report("seq_write", mb as f64, "MB/s", t.elapsed().as_secs_f64());

    // Sequential read of the whole file.
    let t = Instant::now();
    let got = fs.cat_file(&big, ByteRange::Full).await.unwrap();
    report("seq_read", mb as f64, "MB/s", t.elapsed().as_secs_f64());
    assert!(got == data, "read back different data");
    drop(got);

    // Server-side copy.
    let t = Instant::now();
    fs.cp_file(&big, &format!("{root}/copy.bin")).await.unwrap();
    report("server_copy", mb as f64, "MB/s", t.elapsed().as_secs_f64());
    fs.rm_file(&format!("{root}/copy.bin")).await.unwrap();
    fs.rm_file(&big).await.unwrap();

    // Small files, one at a time (fsspec's access pattern) and batched.
    let small = format!("{root}/small");
    fs.mkdir(&small, false).await.unwrap();
    let names: Vec<String> = (0..1000).map(|i| format!("{small}/f{i:05}")).collect();
    let payload = Bytes::from(vec![b'x'; 4096]);
    let t = Instant::now();
    for n in &names {
        fs.pipe_file(n, payload.clone(), &WriteOptions::default())
            .await
            .unwrap();
    }
    report("pipe_1000x4k", 1000.0, "ops/s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    for n in &names {
        fs.info(n).await.unwrap();
    }
    report("info_1000", 1000.0, "ops/s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    for n in &names {
        fs.cat_file(n, ByteRange::Full).await.unwrap();
    }
    report("cat_1000x4k", 1000.0, "ops/s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    let r: Vec<_> = futures::stream::iter(names.iter().map(|n| fs.info(n)))
        .buffer_unordered(64)
        .collect()
        .await;
    assert!(r.iter().all(|r| r.is_ok()));
    report(
        "info_1000_conc64",
        1000.0,
        "ops/s",
        t.elapsed().as_secs_f64(),
    );
    let t = Instant::now();
    let r: Vec<_> = futures::stream::iter(names.iter().map(|n| fs.cat_file(n, ByteRange::Full)))
        .buffer_unordered(64)
        .collect()
        .await;
    assert!(r.iter().all(|r| r.is_ok()));
    report(
        "cat_1000x4k_conc64",
        1000.0,
        "ops/s",
        t.elapsed().as_secs_f64(),
    );
    let r = fs.rm_files(&names).await;
    assert!(r.iter().all(|r| r.is_ok()));
    fs.rmdir(&small).await.unwrap();
    fs.rmdir(&root).await.unwrap();
}

async fn ls_tree(fs: &SmbFileSystem, share: &str, n: usize) -> String {
    let dir = format!("/{share}/{}", common::unique("bench-ls"));
    fs.mkdir(&dir, false).await.unwrap();
    let names: Vec<String> = (0..n).map(|i| format!("{dir}/entry-{i:06}.dat")).collect();
    let opts = WriteOptions::default();
    let r: Vec<_> =
        futures::stream::iter(names.iter().map(|p| fs.pipe_file(p, Bytes::new(), &opts)))
            .buffer_unordered(64)
            .collect()
            .await;
    assert!(r.iter().all(|r| r.is_ok()));
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bench_against_fsspec() {
    let Some(env) = common::env() else { return };
    if std::env::var("FSFAST_TEST_SMB_BENCH").as_deref() != Ok("1") {
        eprintln!("skipping SMB benchmark: set FSFAST_TEST_SMB_BENCH=1 (and use --release)");
        return;
    }
    let mb: usize = std::env::var("FSFAST_TEST_SMB_BENCH_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(256);
    let py = std::env::var("FSFAST_TEST_FSSPEC_PYTHON").ok();
    for share in [env.share.clone(), env.enc_share.clone()] {
        let conns: i64 = std::env::var("FSFAST_TEST_SMB_BENCH_CONNS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        println!("== share {share} ({mb} MiB large file, {conns} connection(s))");
        let fs = env.fs(&[("connections", Value::Int(conns))]);
        run_fsfast(&fs, &share, mb).await;
        if let Some(py) = &py {
            let out = Command::new(py)
                .args([
                    "-c",
                    FSSPEC_SCRIPT,
                    &env.host,
                    &env.port.to_string(),
                    &env.user,
                    &env.password,
                    &share,
                    &mb.to_string(),
                ])
                .output()
                .expect("run fsspec benchmark");
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            for l in String::from_utf8_lossy(&out.stdout).lines() {
                println!("fsspec\t{l}");
            }
        }
        // ls of a 10k-entry directory.
        let dir = ls_tree(&fs, &share, 10_000).await;
        let t = Instant::now();
        let n = fs.ls(&dir).await.unwrap().len();
        assert_eq!(n, 10_000);
        report("ls_10000", 1.0, "listings/s", t.elapsed().as_secs_f64());
        if let Some(py) = &py {
            let out = Command::new(py)
                .args([
                    "-c",
                    FSSPEC_LS_SCRIPT,
                    &env.host,
                    &env.port.to_string(),
                    &env.user,
                    &env.password,
                    &dir,
                ])
                .output()
                .expect("run fsspec ls benchmark");
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            for l in String::from_utf8_lossy(&out.stdout).lines() {
                println!("fsspec\t{l}");
            }
        }
        let fsd: Arc<dyn FileSystem> = Arc::new(fs.clone());
        let names: Vec<String> = fsd
            .ls(&dir)
            .await
            .unwrap()
            .into_iter()
            .map(|i| i.name)
            .collect();
        let r = fsd.rm_files(&names).await;
        assert!(r.iter().all(|r| r.is_ok()));
        fs.rmdir(&dir).await.unwrap();
        let s = fs.stats().snapshot();
        println!(
            "fsfast stats: requests={} retries={} errors={}",
            s.requests, s.retries, s.errors
        );
        fs.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bench_chunk_sizes() {
    let Some(env) = common::env() else { return };
    if std::env::var("FSFAST_TEST_SMB_BENCH").as_deref() != Ok("1") {
        eprintln!("skipping SMB benchmark: set FSFAST_TEST_SMB_BENCH=1");
        return;
    }
    let mb = 256usize;
    let data = common::pattern(mb << 20, 3);
    for share in [env.share.clone(), env.enc_share.clone()] {
        for (chunk, inflight, conns) in [
            (1 << 20, 16, 1),
            (2 << 20, 16, 1),
            (4 << 20, 8, 1),
            (8 << 20, 8, 1),
            (1 << 20, 32, 1),
        ] {
            let fs = env.fs(&[
                ("read_chunk_size", Value::Int(chunk)),
                ("write_chunk_size", Value::Int(chunk)),
                ("max_inflight", Value::Int(inflight)),
                ("connections", Value::Int(conns)),
            ]);
            let root = format!("/{share}/{}", common::unique("chunks"));
            fs.mkdir(&root, false).await.unwrap();
            let p = format!("{root}/big.bin");
            let t = Instant::now();
            fs.pipe_file(&p, data.clone(), &WriteOptions::default())
                .await
                .unwrap();
            let w = t.elapsed().as_secs_f64();
            let t = Instant::now();
            let got = fs.cat_file(&p, ByteRange::Full).await.unwrap();
            let r = t.elapsed().as_secs_f64();
            assert_eq!(got.len(), data.len());
            println!(
                "{share}\tchunk={}KiB\tinflight={inflight}\twrite={:.0} MB/s\tread={:.0} MB/s",
                chunk >> 10,
                mb as f64 / w,
                mb as f64 / r
            );
            fs.rm_file(&p).await.unwrap();
            fs.rmdir(&root).await.unwrap();
            fs.close().await.unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bench_read_modes() {
    let Some(env) = common::env() else { return };
    if std::env::var("FSFAST_TEST_SMB_BENCH").as_deref() != Ok("1") {
        eprintln!("skipping SMB benchmark: set FSFAST_TEST_SMB_BENCH=1");
        return;
    }
    let mb = 256usize;
    let data = common::pattern(mb << 20, 3);
    for share in [env.share.clone(), env.enc_share.clone()] {
        let fs = env.fs(&[]);
        let root = format!("/{share}/{}", common::unique("modes"));
        fs.mkdir(&root, false).await.unwrap();
        let p = format!("{root}/big.bin");
        fs.pipe_file(&p, data.clone(), &WriteOptions::default())
            .await
            .unwrap();
        for _ in 0..2 {
            // One big read_at (pipelined chunks copied into one buffer).
            let t = Instant::now();
            let got = fs.cat_file(&p, ByteRange::Full).await.unwrap();
            let one = t.elapsed().as_secs_f64();
            assert_eq!(got.len(), data.len());
            drop(got);
            // Chunk-sized read_at calls, 16 in flight, results dropped
            // (zero-copy slices of the received frames).
            let h = fs
                .open_read(&p, &fsfast_core::ReadOptions::default())
                .await
                .unwrap();
            let chunk = 1usize << 20;
            let t = Instant::now();
            let n: usize = futures::stream::iter((0..(mb << 20)).step_by(chunk).map(|off| {
                let h = h.clone();
                async move { h.read_at(off as u64, chunk).await.unwrap().len() }
            }))
            .buffer_unordered(16)
            .fold(0usize, |a, b| async move { a + b })
            .await;
            let slices = t.elapsed().as_secs_f64();
            assert_eq!(n, mb << 20);
            h.close().await.unwrap();
            println!(
                "{share}\tcat_file={:.0} MB/s\tslices={:.0} MB/s\tdirect_reads={}",
                mb as f64 / one,
                mb as f64 / slices,
                fs.connection_info(&share).await.unwrap().direct_reads
            );
        }
        fs.rm_file(&p).await.unwrap();
        fs.rmdir(&root).await.unwrap();
        fs.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bench_metadata_latency() {
    let Some(env) = common::env() else { return };
    if std::env::var("FSFAST_TEST_SMB_BENCH").as_deref() != Ok("1") {
        eprintln!("skipping SMB benchmark: set FSFAST_TEST_SMB_BENCH=1");
        return;
    }
    let fs = env.fs(&[]);
    let root = format!("/{}/{}", env.share, common::unique("meta"));
    fs.mkdir(&root, false).await.unwrap();
    let names: Vec<String> = (0..500).map(|i| format!("{root}/f{i:04}")).collect();
    let payload = Bytes::from(vec![b'x'; 4096]);
    for n in &names {
        fs.pipe_file(n, payload.clone(), &WriteOptions::default())
            .await
            .unwrap();
    }
    for round in 0..3 {
        let t = Instant::now();
        for n in &names {
            fs.info(n).await.unwrap();
        }
        let info = 500.0 / t.elapsed().as_secs_f64();
        let t = Instant::now();
        for n in &names {
            fs.cat_file(n, ByteRange::Full).await.unwrap();
        }
        let cat = 500.0 / t.elapsed().as_secs_f64();
        println!("round {round}: info {info:.0} ops/s, cat {cat:.0} ops/s");
    }
    assert!(fs.rm_files(&names).await.iter().all(|r| r.is_ok()));
    fs.rmdir(&root).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bench_ls_10k() {
    let Some(env) = common::env() else { return };
    if std::env::var("FSFAST_TEST_SMB_BENCH").as_deref() != Ok("1") {
        eprintln!("skipping SMB benchmark: set FSFAST_TEST_SMB_BENCH=1");
        return;
    }
    let fs = env.fs(&[]);
    let dir = ls_tree(&fs, &env.share, 10_000).await;
    for _ in 0..5 {
        let t = Instant::now();
        let n = fs.ls(&dir).await.unwrap().len();
        println!(
            "ls of {n} entries: {:.1} ms",
            t.elapsed().as_secs_f64() * 1e3
        );
    }
    let names: Vec<String> = fs
        .ls(&dir)
        .await
        .unwrap()
        .into_iter()
        .map(|i| i.name)
        .collect();
    assert!(fs.rm_files(&names).await.iter().all(|r| r.is_ok()));
    fs.rmdir(&dir).await.unwrap();
}
