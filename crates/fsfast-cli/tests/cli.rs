//! End-to-end tests of the `fsf` binary.
//!
//! The memory and local tests always run. The live-service tests run when
//! the `scripts/test-services.sh env` variables are set
//! (`eval "$(scripts/test-services.sh env)"`) and print a skip message
//! otherwise.

#![cfg(all(feature = "memory", feature = "local"))]

use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

fn fsf(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fsf"))
        .args(args)
        .output()
        .expect("run fsf")
}

fn ok(args: &[&str]) -> Output {
    let out = fsf(args);
    assert!(
        out.status.success(),
        "fsf {args:?} failed ({:?})\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn unique(tag: &str) -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        % 10_000_000_000;
    format!("fsf-it-{tag}-{}-{ms}", std::process::id())
}

const TINY: &[&str] = &[
    "--size",
    "256KiB",
    "--file-size",
    "1KiB",
    "--count",
    "24",
    "--ranges",
    "16",
    "--range-size",
    "4KiB",
    "--dirs",
    "3",
    "-n",
    "2",
    "--warmup",
    "1",
    "-c",
    "4",
    "--json",
    "-q",
];

/// Run a tiny bench of every workload and check the JSON report.
fn tiny_bench(url: &str, extra: &[&str]) -> Value {
    let mut args = vec!["bench", url];
    args.extend_from_slice(TINY);
    args.extend_from_slice(extra);
    let out = ok(&args);
    let v: Value = serde_json::from_slice(&out.stdout).expect("JSON report");
    assert_eq!(v["tool"], "fsf");
    assert!(v["error"].is_null(), "{}", v["error"]);
    assert_eq!(v["cleanup"]["ran"], true);
    assert_eq!(v["cleanup"]["errors"].as_array().unwrap().len(), 0);
    let results = v["results"].as_array().unwrap();
    let names: Vec<&str> = results
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "seq-read",
            "seq-write",
            "small-read",
            "small-write",
            "metadata-info",
            "metadata-ls",
            "metadata-find",
            "random-read",
            "copy",
            "delete"
        ]
    );
    for r in results {
        assert_eq!(r["iterations"], 2, "{r}");
        assert_eq!(r["warmup"], 1);
        assert_eq!(r["times_s"].as_array().unwrap().len(), 2);
        assert!(r["best_s"].as_f64().unwrap() > 0.0, "{r}");
        assert!(r["best_s"].as_f64() <= r["median_s"].as_f64());
        assert!(r["ops_per_s"]["best"].as_f64().unwrap() > 0.0);
        let lat = &r["latency_ms"];
        assert!(lat["p50"].as_f64().unwrap() <= lat["p99"].as_f64().unwrap());
    }
    let by_name = |n: &str| results.iter().find(|r| r["name"] == n).unwrap();
    assert_eq!(by_name("seq-read")["bytes_per_iter"], 256 * 1024);
    assert_eq!(by_name("small-read")["ops_per_iter"], 24);
    assert_eq!(by_name("small-read")["bytes_per_iter"], 24 * 1024);
    assert_eq!(by_name("random-read")["bytes_per_iter"], 16 * 4096);
    assert_eq!(by_name("metadata-ls")["items_per_iter"], 24);
    assert_eq!(by_name("metadata-ls")["ops_per_iter"], 3);
    assert_eq!(by_name("metadata-find")["items_per_iter"], 24);
    assert!(by_name("delete")["mb_per_s"].is_null());
    assert_eq!(by_name("delete")["latency_ms"]["kind"], "batch");
    v
}

#[test]
fn bench_memory_all_workloads() {
    let url = format!("memory://{}", unique("mem"));
    let v = tiny_bench(&url, &["--create"]);
    assert_eq!(v["protocol"], "memory");
    // In-process backends have no wire counters.
    assert!(v["results"][0]["stats"].is_null());
    // Everything, including the created root, is gone (and since memory is
    // per process, a fresh process sees nothing either way).
    let out = fsf(&["ls", &url]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn bench_local_cleans_up_and_copies_across_backends() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_str().unwrap();
    tiny_bench(root, &[]);
    assert_eq!(
        std::fs::read_dir(tmp.path()).unwrap().count(),
        0,
        "prefix left behind"
    );

    // W7 from memory to the local disk (streamed downloads).
    let dest = tmp.path().join("dest");
    std::fs::create_dir(&dest).unwrap();
    let url = format!("memory://{}", unique("w7"));
    let out = ok(&[
        "bench",
        &url,
        "--create",
        "-w",
        "W7",
        "--count",
        "10",
        "--file-size",
        "2KiB",
        "-n",
        "1",
        "--warmup",
        "0",
        "--dest",
        dest.to_str().unwrap(),
        "--json",
        "-q",
    ]);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let r = &v["results"][0];
    assert_eq!(r["name"], "copy");
    assert_eq!(r["params"]["method"], "Download");
    assert_eq!(r["bytes_per_iter"], 10 * 2048);
    assert_eq!(std::fs::read_dir(&dest).unwrap().count(), 0);
}

#[test]
fn bench_human_output_and_keep() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_str().unwrap();
    let out = ok(&[
        "bench",
        root,
        "-w",
        "W3,W8",
        "--count",
        "5",
        "--file-size",
        "100",
        "-n",
        "1",
        "--keep",
        "-q",
    ]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("W3 small-read"), "{text}");
    assert!(text.contains("latency   (op, n=5)"), "{text}");
    assert!(text.contains("W8 delete"), "{text}");
    assert!(text.contains("kept "), "{text}");
    // --keep leaves the prefix in place.
    let entries: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().collect();
    assert_eq!(entries.len(), 1);
}

#[test]
fn bench_rejects_missing_target_and_bad_flags() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("nope");
    let out = fsf(&["bench", missing.to_str().unwrap(), "-w", "W3", "-q"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("error"));
    assert!(!missing.exists());
    let out = fsf(&["bench", "memory://x", "-w", "W42"]);
    assert_eq!(out.status.code(), Some(2));
    let out = fsf(&[
        "bench",
        "memory://x",
        "--range-size",
        "2MiB",
        "--size",
        "1MiB",
    ]);
    assert_eq!(out.status.code(), Some(2));
}

fn write(p: &Path, data: &[u8]) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

#[test]
fn manual_commands_on_the_local_filesystem() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    write(&t.join("src/a.txt"), b"alpha");
    write(&t.join("src/sub/b.bin"), &[7u8; 3000]);
    let s = |p: &str| t.join(p).to_str().unwrap().to_owned();

    // ls / ls -l / --json
    let out = ok(&["ls", &s("src")]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        text.lines().collect::<Vec<_>>(),
        [s("src/a.txt"), s("src/sub")]
    );
    let out = ok(&["ls", "-l", &s("src")]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.lines()
            .next()
            .unwrap()
            .starts_with("-              5 "),
        "{text}"
    );
    let out = ok(&["--json", "ls", &format!("file://{}", s("src"))]);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v[1]["type"], "directory");
    assert!(v[0].get("mtime").is_some(), "local info keys: {}", v[0]);

    // info
    let out = ok(&["info", &s("src/sub/b.bin")]);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["size"], 3000);
    assert_eq!(v["type"], "file");

    // cat (whole, ranged)
    assert_eq!(ok(&["cat", &s("src/a.txt")]).stdout, b"alpha");
    assert_eq!(
        ok(&["cat", "--start", "1", "--end", "3", &s("src/a.txt")]).stdout,
        b"lp"
    );

    // cp -r into a new directory, then into an existing one.
    ok(&["cp", "-r", "-q", &s("src"), &s("copy")]);
    assert_eq!(
        std::fs::read(t.join("copy/sub/b.bin")).unwrap(),
        [7u8; 3000]
    );
    ok(&["mkdir", &s("into")]);
    ok(&["cp", "-r", "-q", "-j", "1", &s("src"), &s("into")]);
    assert_eq!(std::fs::read(t.join("into/src/a.txt")).unwrap(), b"alpha");
    // cp without -r on a directory fails.
    assert_eq!(fsf(&["cp", &s("src"), &s("x")]).status.code(), Some(1));

    // find
    let out = ok(&["find", &s("copy")]);
    assert_eq!(String::from_utf8(out.stdout).unwrap().lines().count(), 2);
    let out = ok(&["find", "--withdirs", "--maxdepth", "1", &s("copy")]);
    assert_eq!(String::from_utf8(out.stdout).unwrap().lines().count(), 3);

    // mkdir -p is idempotent; rm needs -r for directories.
    ok(&["mkdir", "-p", &s("deep/er/est")]);
    ok(&["mkdir", "-p", &s("deep/er/est")]);
    assert!(t.join("deep/er/est").is_dir());
    assert_eq!(fsf(&["mkdir", &s("deep")]).status.code(), Some(1));
    assert_eq!(fsf(&["rm", &s("copy")]).status.code(), Some(1));
    ok(&["rm", "-r", "-q", &s("copy"), &s("into"), &s("deep")]);
    ok(&["rm", &s("src/a.txt")]);
    assert!(!t.join("copy").exists() && !t.join("deep").exists());
    assert!(!t.join("src/a.txt").exists());

    // Errors: missing path (1), unknown protocol (1), usage (2).
    let out = fsf(&["info", &s("missing")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("fsf: error"));
    assert_eq!(fsf(&["ls", "nope://x"]).status.code(), Some(1));
    assert_eq!(fsf(&["ls"]).status.code(), Some(2));
    assert_eq!(fsf(&["--opt", "bad", "ls", "/"]).status.code(), Some(2));
    // Strict options: a typo is an error.
    assert_eq!(
        fsf(&["--opt", "file:auto_mkdirr=true", "ls", &s("src")])
            .status
            .code(),
        Some(1)
    );
    ok(&["--opt", "file:auto_mkdir=true", "ls", &s("src")]);
    assert!(ok(&["protocols"]).stdout.starts_with(b"file local\n"));
}

#[test]
fn cat_into_a_closed_pipe_is_quiet() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("big");
    std::fs::write(&p, vec![b'x'; 8 << 20]).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_fsf"))
        .args(["cat", p.to_str().unwrap()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // Read a little, then close our end.
    {
        use std::io::Read;
        let mut buf = [0u8; 16];
        child.stdout.take().unwrap().read_exact(&mut buf).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---- live services ----

#[allow(dead_code)] // unused without the network backends
fn env_set(vars: &[&str]) -> bool {
    vars.iter()
        .all(|v| std::env::var(v).is_ok_and(|s| !s.is_empty()))
}

#[allow(dead_code)]
fn live(name: &str, vars: &[&str], url: impl FnOnce() -> String) {
    if !env_set(vars) {
        eprintln!(
            "skipping live {name} bench: set {} (eval \"$(scripts/test-services.sh env)\")",
            vars.join(", ")
        );
        return;
    }
    let url = url();
    let v = tiny_bench(&url, &["--test-services", "--create"]);
    // Network backends report engine counters for every workload.
    for r in v["results"].as_array().unwrap() {
        assert!(r["stats"].is_object(), "{name}: {r}");
    }
    let seq_read = &v["results"][0]["stats"];
    assert!(
        seq_read["bytes_read"].as_u64().unwrap() >= 2 * 256 * 1024,
        "{name}: {seq_read}"
    );
}

#[test]
#[cfg(feature = "s3")]
fn live_s3() {
    live(
        "s3",
        &[
            "FSFAST_TEST_S3_ENDPOINT",
            "FSFAST_TEST_S3_KEY",
            "FSFAST_TEST_S3_SECRET",
        ],
        || format!("s3://{}", unique("s3")),
    );
}

#[test]
#[cfg(feature = "gcs")]
fn live_gcs() {
    live("gcs", &["FSFAST_TEST_GCS_ENDPOINT"], || {
        format!("gs://{}", unique("gcs"))
    });
}

#[test]
#[cfg(feature = "azure")]
fn live_azure() {
    live("azure", &["FSFAST_TEST_AZURE_CONNECTION_STRING"], || {
        format!("abfs://{}", unique("az"))
    });
}

#[test]
#[cfg(feature = "smb")]
fn live_smb() {
    live(
        "smb",
        &[
            "FSFAST_TEST_SMB_HOST",
            "FSFAST_TEST_SMB_USER",
            "FSFAST_TEST_SMB_PASSWORD",
            "FSFAST_TEST_SMB_SHARE",
        ],
        || {
            format!(
                "smb://{}/{}/{}",
                std::env::var("FSFAST_TEST_SMB_HOST").unwrap(),
                std::env::var("FSFAST_TEST_SMB_SHARE").unwrap(),
                unique("smb")
            )
        },
    );
}

#[test]
#[cfg(feature = "sftp")]
fn live_sftp() {
    live(
        "sftp",
        &[
            "FSFAST_TEST_SFTP_HOST",
            "FSFAST_TEST_SFTP_USER",
            "FSFAST_TEST_SFTP_PASSWORD",
        ],
        || {
            format!(
                "sftp://{}/tmp/{}",
                std::env::var("FSFAST_TEST_SFTP_HOST").unwrap(),
                unique("sftp")
            )
        },
    );
}

#[test]
#[cfg(feature = "s3")]
fn live_s3_cp_round_trip() {
    let vars = [
        "FSFAST_TEST_S3_ENDPOINT",
        "FSFAST_TEST_S3_KEY",
        "FSFAST_TEST_S3_SECRET",
    ];
    if !env_set(&vars) {
        eprintln!("skipping live s3 cp: set {}", vars.join(", "));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("up/a"), b"one");
    write(&tmp.path().join("up/d/b"), &[1u8; 70_000]);
    let bucket = format!("s3://{}", unique("s3cp"));
    let t = ["--test-services", "-q"];
    let run = |args: &[&str]| {
        let mut v = t.to_vec();
        v.extend_from_slice(args);
        ok(&v)
    };
    run(&["mkdir", &bucket]);
    let up = tmp.path().join("up");
    run(&["cp", "-r", up.to_str().unwrap(), &format!("{bucket}/")]);
    // Server-side copy within the bucket, then download.
    run(&[
        "cp",
        "-r",
        &format!("{bucket}/up"),
        &format!("{bucket}/copy"),
    ]);
    let down = tmp.path().join("down");
    run(&[
        "cp",
        "-r",
        &format!("{bucket}/copy"),
        down.to_str().unwrap(),
    ]);
    assert_eq!(std::fs::read(down.join("d/b")).unwrap(), [1u8; 70_000]);
    assert_eq!(run(&["cat", &format!("{bucket}/copy/a")]).stdout, b"one");
    let out = run(&["--stats", "ls", &format!("{bucket}/copy")]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("stats[s3]: requests"));
    run(&["rm", "-r", &bucket]);
    assert_eq!(
        fsf(&["--test-services", "ls", &bucket]).status.code(),
        Some(1)
    );
}

#[cfg(unix)]
#[test]
fn bench_interrupted_by_sigint_still_cleans_up() {
    let tmp = tempfile::tempdir().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_fsf"))
        .args([
            "bench",
            tmp.path().to_str().unwrap(),
            "-w",
            "W4",
            "--count",
            "100000",
            "--file-size",
            "16",
            "-n",
            "1000",
            "-q",
            "--json",
        ])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // Wait until the benchmark prefix exists, then interrupt.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::fs::read_dir(tmp.path()).unwrap().count() == 0 {
        assert!(std::time::Instant::now() < deadline, "bench never started");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    std::thread::sleep(std::time::Duration::from_millis(200));
    let killed = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(130));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["interrupted"], true);
    assert_eq!(v["cleanup"]["ran"], true);
    assert_eq!(
        std::fs::read_dir(tmp.path()).unwrap().count(),
        0,
        "prefix left behind after SIGINT"
    );
}
