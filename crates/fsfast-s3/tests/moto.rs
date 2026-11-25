//! Tests against moto's S3 server, for features RustFS lacks or implements
//! differently: bucket versioning (`version_aware`), conditional writes
//! with a `Condition` in the error body, requester-pays buckets, plus the
//! conformance suite on a second server implementation.
//!
//! Gated on `FSFAST_TEST_MOTO=1`. The server binary is
//! `FSFAST_TEST_MOTO_SERVER`, else `moto_server` next to
//! `FSFAST_TEST_FSSPEC_PYTHON`, else `.venv/bin/moto_server` of the
//! repository. Each test starts its own server on a free port.

mod common;

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use fsfast_core::{
    ByteRange, ErrorKind, FileSystem, FindOptions, Options, ReadOptions, Value, WriteMode,
    WriteOptions,
};
use fsfast_s3::S3FileSystem;
use fsfast_testkit::{SuiteConfig, assert_suite};

struct Moto {
    child: Child,
    endpoint: String,
}

impl Drop for Moto {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn moto_binary() -> PathBuf {
    if let Ok(p) = std::env::var("FSFAST_TEST_MOTO_SERVER") {
        return PathBuf::from(p);
    }
    if let Ok(py) = std::env::var("FSFAST_TEST_FSSPEC_PYTHON") {
        let p = PathBuf::from(py).with_file_name("moto_server");
        if p.exists() {
            return p;
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.venv/bin/moto_server")
}

async fn start_moto() -> Option<Moto> {
    if std::env::var("FSFAST_TEST_MOTO").ok().as_deref() != Some("1") {
        eprintln!("skipping: set FSFAST_TEST_MOTO=1 to run the moto tests");
        return None;
    }
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let child = Command::new(moto_binary())
        .args(["-H", "127.0.0.1", "-p", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start moto_server (set FSFAST_TEST_MOTO_SERVER)");
    let moto = Moto {
        child,
        endpoint: format!("http://127.0.0.1:{port}"),
    };
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Some(moto);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("moto_server did not start");
}

fn fs(m: &Moto, extra: &[(&str, Value)]) -> S3FileSystem {
    let mut o = Options::new();
    o.insert("endpoint_url".into(), Value::from(m.endpoint.as_str()));
    o.insert("key".into(), Value::from("testing"));
    o.insert("secret".into(), Value::from("testing"));
    for (k, v) in extra {
        o.insert((*k).into(), v.clone());
    }
    S3FileSystem::from_options(o).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conformance_suite_on_moto() {
    let Some(m) = start_moto().await else { return };
    let f = fs(&m, &[]);
    f.mkdir("suite-bucket", true).await.unwrap();
    let dynfs: Arc<dyn FileSystem> = Arc::new(f);
    assert_suite(
        dynfs,
        "suite-bucket/run",
        SuiteConfig::default().parallelism(4),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn version_aware_filesystem() {
    let Some(m) = start_moto().await else { return };
    let f = fs(&m, &[("version_aware", true.into())]);
    f.mkdir("versioned", true).await.unwrap();
    f.make_bucket_versioned("versioned", true).await.unwrap();
    let w = WriteOptions::default();
    f.pipe_file("versioned/k", Bytes::from_static(b"one"), &w)
        .await
        .unwrap();
    let v1 = match &f.info("versioned/k").await.unwrap().extra["VersionId"] {
        Value::Str(s) => s.clone(),
        other => panic!("no VersionId: {other:?}"),
    };
    f.pipe_file("versioned/k", Bytes::from_static(b"two"), &w)
        .await
        .unwrap();
    let latest = f.info("versioned/k").await.unwrap();
    assert_ne!(latest.extra["VersionId"], Value::Str(v1.clone()));
    // Version paths read the old content.
    let vpath = format!("versioned/k?versionId={v1}");
    assert_eq!(
        &f.cat_file(&vpath, ByteRange::Full).await.unwrap()[..],
        b"one"
    );
    assert_eq!(f.info(&vpath).await.unwrap().size, 3);
    let h = f
        .open_read(
            "versioned/k",
            &ReadOptions {
                version: Some(v1.clone()),
                ..ReadOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(&h.read_at(0, 10).await.unwrap()[..], b"one");
    // A handle on the latest version stays on it across an overwrite
    // (pinned by version id, not by ETag).
    let h = f
        .open_read("versioned/k", &ReadOptions::default())
        .await
        .unwrap();
    f.pipe_file("versioned/k", Bytes::from_static(b"three"), &w)
        .await
        .unwrap();
    assert_eq!(&h.read_at(0, 10).await.unwrap()[..], b"two");
    // Listings: latest only by default, every version on request.
    let ls = f.ls("versioned").await.unwrap();
    assert_eq!(ls.len(), 1);
    assert_eq!(ls[0].name, "versioned/k");
    assert_eq!(ls[0].extra["IsLatest"], Value::Bool(true));
    let all = f.ls_versions("versioned").await.unwrap();
    assert_eq!(all.len(), 3);
    assert!(
        all.iter()
            .all(|i| i.name.starts_with("versioned/k?versionId="))
    );
    assert_eq!(f.object_versions("versioned/k").await.unwrap().len(), 3);
    let found = f.find("versioned", &FindOptions::default()).await.unwrap();
    assert_eq!(found.len(), 1);
    // A signed URL for an old version.
    let url = f.sign(&vpath, Duration::from_secs(60)).await.unwrap();
    assert!(url.contains("versionId="), "{url}");
    // Version ids on a non-version-aware filesystem are refused.
    let plain = fs(&m, &[]);
    assert_eq!(
        plain
            .open_read(
                "versioned/k",
                &ReadOptions {
                    version: Some(v1),
                    ..ReadOptions::default()
                }
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidInput
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conditional_writes_and_requester_pays() {
    let Some(m) = start_moto().await else { return };
    let f = fs(
        &m,
        &[
            ("requester_pays", true.into()),
            ("part_size", Value::Int(5 << 20)),
        ],
    );
    f.mkdir("cond", true).await.unwrap();
    let cn = WriteOptions::default().with_mode(WriteMode::CreateNew);
    f.pipe_file("cond/a", Bytes::from_static(b"1"), &cn)
        .await
        .unwrap();
    let e = f
        .pipe_file("cond/a", Bytes::from_static(b"2"), &cn)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AlreadyExists, "{e}");
    // Multipart create-only: the condition is checked on completion.
    let big = Bytes::from(vec![7u8; 11 << 20]);
    let e = f.pipe_file("cond/a", big.clone(), &cn).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AlreadyExists, "{e}");
    assert_eq!(
        &f.cat_file("cond/a", ByteRange::Full).await.unwrap()[..],
        b"1"
    );
    f.pipe_file("cond/b", big.clone(), &cn).await.unwrap();
    assert_eq!(f.cat_file("cond/b", ByteRange::Full).await.unwrap(), big);
    // The probe object was cleaned up.
    let names: Vec<String> = f
        .find("cond", &FindOptions::default())
        .await
        .unwrap()
        .into_iter()
        .map(|i| i.name)
        .collect();
    assert_eq!(names, vec!["cond/a", "cond/b"]);
    assert!(f.exists("cond").await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3fs_extras() {
    let Some(m) = start_moto().await else { return };
    let f = fs(&m, &[]);
    f.mkdir("extras", true).await.unwrap();
    assert!(!f.is_bucket_versioned("extras").await.unwrap());
    f.make_bucket_versioned("extras", true).await.unwrap();
    assert!(f.is_bucket_versioned("extras").await.unwrap());
    let mut meta = std::collections::BTreeMap::new();
    meta.insert("first_key".to_owned(), "1".to_owned());
    let w = WriteOptions {
        content_type: Some("text/plain".into()),
        metadata: meta,
        ..WriteOptions::default()
    };
    f.pipe_file("extras/obj", Bytes::from_static(b"data"), &w)
        .await
        .unwrap();
    let md = f.metadata("extras/obj").await.unwrap();
    assert_eq!(md.get("first-key").map(String::as_str), Some("1"), "{md:?}");
    assert_eq!(
        f.getxattr("extras/obj", "first_key")
            .await
            .unwrap()
            .as_deref(),
        Some("1")
    );
    let mut attrs = std::collections::BTreeMap::new();
    attrs.insert("second".to_owned(), Some("2".to_owned()));
    attrs.insert("first_key".to_owned(), None);
    f.setxattr("extras/obj", &attrs, None).await.unwrap();
    let md = f.metadata("extras/obj").await.unwrap();
    assert_eq!(md.get("second").map(String::as_str), Some("2"));
    assert!(!md.contains_key("first-key"), "{md:?}");
    // The content type survived the metadata rewrite.
    assert_eq!(
        f.info("extras/obj").await.unwrap().extra["ContentType"],
        Value::Str("text/plain".into())
    );
    let mut tags = std::collections::BTreeMap::new();
    tags.insert("team".to_owned(), "data + ml = 1".to_owned());
    f.put_tags("extras/obj", &tags, false).await.unwrap();
    let mut more = std::collections::BTreeMap::new();
    more.insert("env".to_owned(), "test".to_owned());
    f.put_tags("extras/obj", &more, true).await.unwrap();
    let got = f.get_tags("extras/obj").await.unwrap();
    assert_eq!(got.get("team").map(String::as_str), Some("data + ml = 1"));
    assert_eq!(got.get("env").map(String::as_str), Some("test"));
    f.chmod("extras/obj", "public-read", false).await.unwrap();
    assert_eq!(
        f.chmod("extras/obj", "not-an-acl", false)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidInput
    );
    // find(prefix=...)
    for k in ["p/2024-01/a", "p/2024-02/b", "p/2025-01/c", "p/2024.txt"] {
        f.pipe_file(
            &format!("extras/{k}"),
            Bytes::from_static(b"x"),
            &WriteOptions::default(),
        )
        .await
        .unwrap();
    }
    let names = |v: Vec<fsfast_core::FileInfo>| v.into_iter().map(|i| i.name).collect::<Vec<_>>();
    assert_eq!(
        names(
            f.find_prefix("extras/p", "2024", &FindOptions::default())
                .await
                .unwrap()
        ),
        vec![
            "extras/p/2024-01/a",
            "extras/p/2024-02/b",
            "extras/p/2024.txt"
        ]
    );
    assert_eq!(
        names(
            f.find_prefix(
                "extras/p",
                "2024-",
                &FindOptions {
                    maxdepth: Some(1),
                    withdirs: true
                }
            )
            .await
            .unwrap()
        ),
        vec!["extras/p/2024-01", "extras/p/2024-02"]
    );
}

const VERSIONED_SCRIPT: &str = r#"
import datetime, json, sys
import s3fs
fs = s3fs.S3FileSystem(key="testing", secret="testing", endpoint_url=sys.argv[3],
    version_aware=True, use_listings_cache=False, skip_instance_cache=True)

def norm(v):
    if isinstance(v, datetime.datetime):
        return "TIME"
    if isinstance(v, dict):
        return {k: norm(x) for k, x in v.items() if k != "Owner"}
    if isinstance(v, (list, tuple)):
        return [norm(x) for x in v]
    return v

out = []
for op in json.load(open(sys.argv[1])):
    fs.invalidate_cache()
    p = op["path"]
    try:
        if op["op"] == "info":
            r = norm(fs.info(p))
        elif op["op"] == "ls":
            r = norm(fs.ls(p, detail=True))
        elif op["op"] == "ls_versions":
            r = norm(fs.ls(p, detail=True, versions=True))
        elif op["op"] == "find":
            r = norm(fs.find(p, detail=True, withdirs=True))
        elif op["op"] == "exists":
            r = fs.exists(p)
        elif op["op"] == "cat":
            r = fs.cat_file(p).decode()
        elif op["op"] == "object_versions":
            r = len(fs.object_version_info(p))
        out.append({"ok": r})
    except Exception as e:
        out.append({"error": type(e).__name__})
json.dump(out, open(sys.argv[2], "w"))
"#;

fn value_json(v: &Value) -> serde_json::Value {
    use serde_json::json;
    match v {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => json!(b),
        Value::Int(i) => json!(i),
        Value::Float(f) => json!(f),
        Value::Str(s) => json!(s),
        Value::Bytes(b) => json!(String::from_utf8_lossy(b)),
        Value::Time(_) => json!("TIME"),
        Value::List(l) => serde_json::Value::Array(l.iter().map(value_json).collect()),
        Value::Map(m) => serde_json::Value::Object(
            m.iter()
                .filter(|(k, _)| k.as_str() != "Owner")
                .map(|(k, v)| (k.clone(), value_json(v)))
                .collect(),
        ),
    }
}

fn info_json(i: &fsfast_core::FileInfo) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert("name".into(), i.name.clone().into());
    m.insert("size".into(), i.size.into());
    m.insert("type".into(), i.file_type.as_fsspec_str().into());
    for (k, v) in &i.extra {
        if k != "Owner" {
            m.insert(k.clone(), value_json(v));
        }
    }
    serde_json::Value::Object(m)
}

/// `version_aware=True` against s3fs on the same moto server: version
/// paths, listings of versioned buckets (latest versions only, delete
/// markers hidden), `ls(versions=True)`, and the error types.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn version_aware_matches_s3fs() {
    use serde_json::json;
    let Ok(python) = std::env::var("FSFAST_TEST_FSSPEC_PYTHON") else {
        eprintln!("skipping version_aware_matches_s3fs: set FSFAST_TEST_FSSPEC_PYTHON");
        return;
    };
    let Some(m) = start_moto().await else { return };
    let f = fs(&m, &[("version_aware", true.into())]);
    f.mkdir("vdiff", true).await.unwrap();
    f.make_bucket_versioned("vdiff", true).await.unwrap();
    let w = WriteOptions::default();
    let mut versions = Vec::new();
    for body in ["one", "two", "three"] {
        f.pipe_file("vdiff/dir/k", Bytes::from(body), &w)
            .await
            .unwrap();
        match &f.info("vdiff/dir/k").await.unwrap().extra["VersionId"] {
            Value::Str(s) => versions.push(s.clone()),
            other => panic!("no VersionId: {other:?}"),
        }
    }
    f.pipe_file("vdiff/gone", Bytes::from_static(b"x"), &w)
        .await
        .unwrap();
    let gone_v = match &f.info("vdiff/gone").await.unwrap().extra["VersionId"] {
        Value::Str(s) => s.clone(),
        other => panic!("{other:?}"),
    };
    // A delete marker hides "gone"; its old version stays readable.
    fsfast_s3::S3FileSystem::rm_file(&fs(&m, &[("strict_delete", false.into())]), "vdiff/gone")
        .await
        .unwrap();
    f.pipe_file("vdiff/other.txt", Bytes::from_static(b"o"), &w)
        .await
        .unwrap();

    let mut paths = vec![
        "vdiff".to_owned(),
        "vdiff/dir".to_owned(),
        "vdiff/dir/k".to_owned(),
        "vdiff/gone".to_owned(),
        format!("vdiff/gone?versionId={gone_v}"),
        "vdiff/other.txt".to_owned(),
        "vdiff/dir/k?versionId=nonexistent".to_owned(),
    ];
    paths.extend(
        versions
            .iter()
            .map(|v| format!("vdiff/dir/k?versionId={v}")),
    );
    let mut ops = Vec::new();
    for p in &paths {
        for op in ["info", "exists", "ls", "find", "cat"] {
            ops.push(json!({"op": op, "path": p}));
        }
    }
    for p in ["vdiff", "vdiff/dir", "vdiff/dir/k", "vdiff/missing"] {
        ops.push(json!({"op": "ls_versions", "path": p}));
    }
    ops.push(
        json!({"op": "ls_versions", "path": format!("vdiff/dir/k?versionId={}", versions[0])}),
    );
    ops.push(json!({"op": "object_versions", "path": "vdiff/dir/k"}));

    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("ops.json");
    let output = dir.path().join("out.json");
    let script = dir.path().join("vdiff.py");
    std::fs::write(&input, serde_json::to_vec(&ops).unwrap()).unwrap();
    std::fs::write(&script, VERSIONED_SCRIPT).unwrap();
    let status = Command::new(&python)
        .arg(&script)
        .arg(&input)
        .arg(&output)
        .arg(&m.endpoint)
        .status()
        .unwrap();
    assert!(status.success(), "s3fs script failed");
    let want: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();

    let class = |k: ErrorKind| match k {
        ErrorKind::NotFound => "FileNotFoundError",
        ErrorKind::PermissionDenied => "PermissionError",
        ErrorKind::InvalidInput => "ValueError",
        ErrorKind::IsADirectory => "IsADirectoryError",
        _ => "OSError",
    };
    let list =
        |v: Vec<fsfast_core::FileInfo>| serde_json::Value::Array(v.iter().map(info_json).collect());
    let mut mismatches = Vec::new();
    for (op, want) in ops.iter().zip(&want) {
        let p = op["path"].as_str().unwrap();
        let got = match op["op"].as_str().unwrap() {
            "info" => f.info(p).await.map(|i| info_json(&i)),
            "exists" => f.exists(p).await.map(|b| json!(b)),
            "ls" => f.ls(p).await.map(list),
            "ls_versions" => f.ls_versions(p).await.map(list),
            "find" => f
                .find(
                    p,
                    &FindOptions {
                        maxdepth: None,
                        withdirs: true,
                    },
                )
                .await
                .map(list),
            "cat" => f
                .cat_file(p, ByteRange::Full)
                .await
                .map(|d| json!(String::from_utf8_lossy(&d))),
            "object_versions" => f.object_versions(p).await.map(|v| json!(v.len())),
            other => panic!("{other}"),
        };
        let got = match got {
            Ok(v) => json!({ "ok": v }),
            Err(e) => json!({ "error": class(e.kind()) }),
        };
        // s3fs's find returns a dict (name -> info); compare as a list.
        let want = match (op["op"].as_str(), want.get("ok")) {
            (Some("find"), Some(serde_json::Value::Object(m))) => {
                json!({ "ok": m.values().cloned().collect::<Vec<_>>() })
            }
            _ => want.clone(),
        };
        // Deliberate: s3fs lets botocore reject the empty key
        // (ParamValidationError); fsfast says the bucket is a directory.
        if op["op"] == "cat" && p == "vdiff" && got["error"] == "IsADirectoryError" {
            continue;
        }
        if got != want {
            mismatches.push(format!("{op}\n  s3fs:   {want}\n  fsfast: {got}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} calls differ from s3fs:\n{}",
        mismatches.len(),
        ops.len(),
        mismatches.join("\n")
    );
}
