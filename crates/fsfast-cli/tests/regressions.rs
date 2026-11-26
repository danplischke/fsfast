//! Regression tests for reviewed `fsf` defects (rm/cp/bench semantics,
//! location parsing, credential redaction).
//!
//! The memory/local tests always run; the live tests run when the
//! `scripts/test-services.sh env` variables are set and print a skip
//! message otherwise.

#![cfg(all(feature = "memory", feature = "local"))]

use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use fsfast_core::{ErrorKind, FileSystem, WriteOptions};

fn fsf_in(dir: Option<&Path>, args: &[&str]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_fsf"));
    c.args(args);
    if let Some(d) = dir {
        c.current_dir(d);
    }
    c.output().expect("run fsf")
}

fn fsf(args: &[&str]) -> Output {
    fsf_in(None, args)
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

fn write(p: &Path, data: &[u8]) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

fn s(p: &Path) -> String {
    p.to_str().unwrap().to_owned()
}

#[cfg(unix)]
#[test]
fn rm_r_on_a_symlink_to_a_directory_removes_only_the_link() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    write(&t.join("precious/file1"), b"1");
    write(&t.join("precious/sub/file2"), b"2");
    std::os::unix::fs::symlink("precious", t.join("link")).unwrap();
    ok(&["rm", "-r", "-q", &s(&t.join("link"))]);
    assert!(
        std::fs::symlink_metadata(t.join("link")).is_err(),
        "link kept"
    );
    assert_eq!(std::fs::read(t.join("precious/file1")).unwrap(), b"1");
    assert_eq!(std::fs::read(t.join("precious/sub/file2")).unwrap(), b"2");
    // Without -r too (fsspec: `os.remove` on the link).
    std::os::unix::fs::symlink("precious", t.join("link2")).unwrap();
    ok(&["rm", &s(&t.join("link2"))]);
    assert!(std::fs::symlink_metadata(t.join("link2")).is_err());
    assert!(t.join("precious/sub/file2").exists());
}

#[tokio::test]
async fn recursive_remove_of_the_root_is_refused() {
    let fs = fsfast_memory::MemoryFileSystem::new_isolated();
    fs.pipe_file(
        "/keep/x",
        Bytes::from_static(b"x"),
        &WriteOptions::default(),
    )
    .await
    .unwrap();
    for root in ["", "/", "//"] {
        let e = fsfast_cli::ops::remove(&fs, root, true).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{root:?}: {e}");
    }
    assert!(fs.exists("/keep/x").await.unwrap());
}

/// `fsf rm -r abfs://` (an empty container) used to delete every blob of
/// every container. The refusal happens before any request, so the
/// endpoint here (a closed port) is never contacted.
#[cfg(feature = "azure")]
#[test]
fn rm_r_of_an_azure_account_root_is_refused() {
    let cs = "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;\
              AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;\
              BlobEndpoint=http://127.0.0.1:9/devstoreaccount1;";
    for url in ["abfs://", "az://", "abfs:///"] {
        let out = fsf(&["--opt", &format!("connection_string={cs}"), "rm", "-r", url]);
        assert_eq!(out.status.code(), Some(1), "{url}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("refusing"), "{url}: {err}");
    }
}

#[test]
fn local_paths_with_multibyte_characters_parse() {
    let tmp = tempfile::tempdir().unwrap();
    for name in ["Grüße", "日本語", "fil\u{e9}x", "loca\u{e9}l"] {
        write(&tmp.path().join(name).join("f"), b"x");
        let out = fsf_in(Some(tmp.path()), &["ls", name]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("/f"));
    }
}

#[test]
fn cp_r_trailing_slash_on_the_source_copies_its_contents() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    write(&t.join("src/a"), b"A");
    write(&t.join("src/sub/b"), b"B");
    std::fs::create_dir(t.join("dst")).unwrap();
    // Existing destination: contents go straight in (fsspec).
    ok(&[
        "cp",
        "-r",
        "-q",
        &format!("{}/", s(&t.join("src"))),
        &format!("{}/", s(&t.join("dst"))),
    ]);
    assert_eq!(std::fs::read(t.join("dst/a")).unwrap(), b"A");
    assert_eq!(std::fs::read(t.join("dst/sub/b")).unwrap(), b"B");
    assert!(!t.join("dst/src").exists());
    // New destination: same.
    ok(&[
        "cp",
        "-r",
        "-q",
        &format!("{}/", s(&t.join("src"))),
        &format!("{}/", s(&t.join("new"))),
    ]);
    assert_eq!(std::fs::read(t.join("new/sub/b")).unwrap(), b"B");
    // Without the slash the directory itself is copied into `dst`.
    ok(&["cp", "-r", "-q", &s(&t.join("src")), &s(&t.join("dst"))]);
    assert_eq!(std::fs::read(t.join("dst/src/a")).unwrap(), b"A");
}

#[test]
fn single_file_cp_creates_missing_parents() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    write(&t.join("a.txt"), b"alpha");
    ok(&["cp", "-q", &s(&t.join("a.txt")), &s(&t.join("np/x/f"))]);
    assert_eq!(std::fs::read(t.join("np/x/f")).unwrap(), b"alpha");
    // memory -> local (get_file path) and local -> memory (put_file).
    let mem = format!("memory://fsf-reg-{}/k", std::process::id());
    let out = fsf(&[
        "cp",
        "-q",
        &s(&t.join("a.txt")),
        &format!("{mem}/deep/er/f"),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test]
async fn concurrent_jobs_finish_in_flight_work_after_a_failure() {
    let finished = Arc::new(AtomicBool::new(false));
    let started = Arc::new(AtomicUsize::new(0));
    let r = fsfast_cli::ops::for_each_concurrent(10, 2, |i| {
        let finished = finished.clone();
        let started = started.clone();
        async move {
            started.fetch_add(1, Ordering::SeqCst);
            if i == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
                return Err(fsfast_core::Error::not_found("job0"));
            }
            // Job 1 is mid-transfer when job 0 fails: it must complete
            // (close/abort its writer), not be dropped.
            tokio::time::sleep(Duration::from_millis(200)).await;
            finished.store(true, Ordering::SeqCst);
            Ok(())
        }
    })
    .await;
    assert_eq!(r.unwrap_err().kind(), ErrorKind::NotFound);
    assert!(finished.load(Ordering::SeqCst), "in-flight job was dropped");
    // No new job starts after the failure.
    assert_eq!(started.load(Ordering::SeqCst), 2);
}

#[test]
fn bench_create_removes_the_parents_it_created() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let target = t.join("x/y/z");
    ok(&[
        "bench",
        &s(&target),
        "--create",
        "-w",
        "W8",
        "--count",
        "3",
        "-n",
        "1",
        "--warmup",
        "0",
        "-q",
    ]);
    assert!(!t.join("x").exists(), "--create left x/ behind");
    // --dest makedirs: missing parents of the destination go too.
    std::fs::create_dir(t.join("src")).unwrap();
    ok(&[
        "bench",
        &s(&t.join("src")),
        "--dest",
        &s(&t.join("d1/d2")),
        "-w",
        "W7",
        "--count",
        "3",
        "--file-size",
        "1KiB",
        "-n",
        "1",
        "--warmup",
        "0",
        "-q",
    ]);
    assert!(!t.join("d1").exists(), "--dest left d1/ behind");
    assert!(t.join("src").is_dir());
    assert_eq!(std::fs::read_dir(t.join("src")).unwrap().count(), 0);
}

// ---- live services ----

#[allow(dead_code)]
fn env_set(vars: &[&str]) -> bool {
    vars.iter()
        .all(|v| std::env::var(v).is_ok_and(|s| !s.is_empty()))
}

#[allow(dead_code)]
fn unique(tag: &str) -> String {
    format!("fsf-reg-{tag}-{}-{}", std::process::id(), fastrand::u32(..))
}

#[allow(dead_code)]
fn session() -> fsfast_cli::target::Session {
    let opts =
        fsfast_cli::options::OptionSet::new(vec![], true, &|k| std::env::var(k).ok()).unwrap();
    fsfast_cli::target::Session::new(opts)
}

#[allow(dead_code)]
const S3_VARS: &[&str] = &[
    "FSFAST_TEST_S3_ENDPOINT",
    "FSFAST_TEST_S3_KEY",
    "FSFAST_TEST_S3_SECRET",
];

/// A scratch bucket holding `h/f`, `h/sub/` (folder marker), `h/sub/g`,
/// plus `d/` (marker), `d/f`, `d/sub/`, `d/sub/g`.
#[cfg(feature = "s3")]
async fn marker_bucket() -> (fsfast_cli::target::Session, String) {
    let sess = session();
    let bucket = unique("mk");
    let r = sess.resolve_all(&[&format!("s3://{bucket}")]).unwrap();
    let fs = r[0].built.fs.clone();
    fs.mkdir(&bucket, true).await.unwrap();
    let w = WriteOptions::default();
    for (k, v) in [
        ("h/f", &b"F"[..]),
        ("h/sub/", b""),
        ("h/sub/g", b"G"),
        ("d/", b""),
        ("d/f", b"F"),
        ("d/sub/", b""),
        ("d/sub/g", b"G"),
    ] {
        fs.pipe_file(&format!("{bucket}/{k}"), Bytes::from_static(v), &w)
            .await
            .unwrap();
    }
    (sess, bucket)
}

#[cfg(feature = "s3")]
#[tokio::test(flavor = "multi_thread")]
async fn live_s3_folder_markers() {
    if !env_set(S3_VARS) {
        eprintln!("skipping live s3 marker test: set {}", S3_VARS.join(", "));
        return;
    }
    let (sess, bucket) = marker_bucket().await;
    let b = format!("s3://{bucket}");
    let t = |args: &[&str]| {
        let mut v = vec!["--test-services", "-q"];
        v.extend_from_slice(args);
        fsf(&v)
    };
    let check = |o: Output| {
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        o
    };
    // cp -r across the marker: same bucket, to local, to memory.
    check(t(&["cp", "-r", &format!("{b}/h"), &format!("{b}/h2")]));
    let tmp = tempfile::tempdir().unwrap();
    check(t(&[
        "cp",
        "-r",
        &format!("{b}/h"),
        &s(&tmp.path().join("h")),
    ]));
    assert_eq!(std::fs::read(tmp.path().join("h/sub/g")).unwrap(), b"G");
    assert!(tmp.path().join("h/f").is_file());
    check(t(&["cp", "-r", &format!("{b}/h"), "memory://fsf-reg-mk/x"]));
    let out = check(t(&["find", &format!("{b}/h2")]));
    let listed = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        listed.contains("h2/f") && listed.contains("h2/sub/g"),
        "{listed}"
    );

    // rm -r removes the prefix's own marker too.
    check(t(&["rm", "-r", &format!("{b}/d")]));
    let fs = sess.resolve_all(&[&b]).unwrap()[0].built.fs.clone();
    fs.invalidate_cache(None);
    let left = fs
        .find(
            &bucket,
            &fsfast_core::FindOptions {
                maxdepth: None,
                withdirs: true,
            },
        )
        .await
        .unwrap();
    assert!(
        !left
            .iter()
            .any(|e| e.name.starts_with(&format!("{bucket}/d"))),
        "{:?}",
        left.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
    assert_eq!(
        t(&["info", &format!("{b}/d")]).status.code(),
        Some(1),
        "the prefix still exists"
    );
    check(t(&["rm", "-r", &b]));
}

#[cfg(feature = "s3")]
#[test]
fn live_s3_bench_same_fs_dest_counts_requests_once_and_create_removes_bucket() {
    if !env_set(S3_VARS) {
        eprintln!("skipping live s3 bench test: set {}", S3_VARS.join(", "));
        return;
    }
    let bucket = unique("bd");
    let out = ok(&[
        "--test-services",
        "--json",
        "bench",
        &format!("s3://{bucket}/sub/prefix"),
        "--create",
        "--dest",
        &format!("s3://{bucket}/other"),
        "-w",
        "W7",
        "--count",
        "4",
        "--file-size",
        "1KiB",
        "-n",
        "1",
        "--warmup",
        "0",
        "-q",
    ]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let r = &v["results"][0];
    assert_eq!(r["params"]["method"], "SameFs", "{r}");
    assert!(r["stats"].is_object(), "{r}");
    assert!(r.get("dest_stats").is_none(), "double-counted: {r}");
    // --create made the bucket: it is gone again.
    assert_eq!(
        fsf(&["--test-services", "info", &format!("s3://{bucket}")])
            .status
            .code(),
        Some(1),
        "bucket left behind"
    );
}

#[cfg(feature = "smb")]
#[test]
fn live_smb_url_passwords_are_not_echoed() {
    let vars = [
        "FSFAST_TEST_SMB_HOST",
        "FSFAST_TEST_SMB_USER",
        "FSFAST_TEST_SMB_PASSWORD",
        "FSFAST_TEST_SMB_SHARE",
    ];
    if !env_set(&vars) {
        eprintln!("skipping live smb redaction test: set {}", vars.join(", "));
        return;
    }
    let e = |k: &str| std::env::var(k).unwrap();
    let pw = e("FSFAST_TEST_SMB_PASSWORD");
    let port = std::env::var("FSFAST_TEST_SMB_PORT").unwrap_or_else(|_| "445".into());
    let base = format!(
        "smb://{}:{}@{}:{}/{}/{}",
        e("FSFAST_TEST_SMB_USER"),
        pw,
        e("FSFAST_TEST_SMB_HOST"),
        port,
        e("FSFAST_TEST_SMB_SHARE"),
        unique("red")
    );
    let leaks = |o: &Output| {
        String::from_utf8_lossy(&o.stdout).contains(&pw)
            || String::from_utf8_lossy(&o.stderr).contains(&pw)
    };
    // Bench on a missing directory: the error names the URL.
    let o = fsf(&["bench", &base, "-w", "W8", "-q"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(!leaks(&o), "{}", String::from_utf8_lossy(&o.stderr));
    // Bench JSON report and rm progress.
    let o = ok(&[
        "--json", "bench", &base, "--create", "-w", "W8", "--count", "3", "-n", "1", "--warmup",
        "0", "-q",
    ]);
    assert!(!leaks(&o), "{}", String::from_utf8_lossy(&o.stdout));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(v["url"].as_str().unwrap().contains(":***@"), "{}", v["url"]);
    ok(&["mkdir", &base]);
    let o = ok(&["rm", "-r", &base]);
    assert!(!leaks(&o), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stderr).contains("removed smb://"));
}
