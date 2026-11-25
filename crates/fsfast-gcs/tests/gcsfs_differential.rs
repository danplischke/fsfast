//! Differential test against gcsfs on the same fake-gcs-server: the same
//! `info`, `ls`, `find`, `exists`, `cat_file` calls (and the error paths of
//! a few mutations) go through gcsfs in a Python subprocess and through
//! fsfast on a tree with awkward object names; the results must be
//! identical: the entries' dict keys and values (timestamps compared as "is
//! a datetime"), their order, and the exception types of failures.
//!
//! Gated on `FSFAST_TEST_FSSPEC_PYTHON` (a Python with gcsfs) and
//! `FSFAST_TEST_GCS_ENDPOINT` (`eval "$(scripts/test-services.sh env)"`).
//! gcsfs runs with `GCSFS_EXPERIMENTAL_ZB_HNS_SUPPORT=false`: its default
//! `ExtendedGcsFileSystem` probes every bucket's type over gRPC, which the
//! emulator does not serve (each call would wait 60 s and fall back).

mod common;

use std::collections::BTreeMap;
use std::process::Command;

use bytes::Bytes;
use common::{destroy_bucket, endpoint, filesystem, unique_bucket};
use fsfast_core::{ByteRange, ErrorKind, FileInfo, FileSystem, FindOptions, Value, WriteOptions};
use serde_json::{Value as J, json};
use sha2::Digest as _;

const SCRIPT: &str = r#"
import datetime, hashlib, json, os, sys
import gcsfs
fs = gcsfs.GCSFileSystem(
    endpoint_url=os.environ["FSFAST_TEST_GCS_ENDPOINT"], token="anon",
    project="test-project", use_listings_cache=False, skip_instance_cache=True)

def norm(v):
    if isinstance(v, datetime.datetime):
        return "TIME"
    if isinstance(v, dict):
        return {k: norm(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [norm(x) for x in v]
    return v

def run(op):
    kind = op["op"]
    p = op["path"]
    if kind == "info":
        return norm(fs.info(p))
    if kind == "ls":
        return norm(fs.ls(p, detail=True))
    if kind == "ls_names":
        return fs.ls(p, detail=False)
    if kind == "find":
        return norm(fs.find(p, maxdepth=op.get("maxdepth"), withdirs=op["withdirs"], detail=True))
    if kind == "find_names":
        return fs.find(p, maxdepth=op.get("maxdepth"), withdirs=op["withdirs"])
    if kind == "exists":
        return fs.exists(p)
    if kind == "cat":
        d = fs.cat_file(p, start=op.get("start"), end=op.get("end"))
        return [len(d), hashlib.sha256(d).hexdigest()]
    if kind == "mkdir":
        fs.mkdir(p, create_parents=op["create_parents"])
        return None
    if kind == "rmdir":
        fs.rmdir(p)
        return None
    if kind == "cp":
        fs.cp_file(p, op["dst"])
        return None
    if kind == "rm":
        fs.rm_file(p)
        return None
    raise ValueError(kind)

out = []
for op in json.load(open(sys.argv[1])):
    fs.invalidate_cache()
    try:
        out.append({"ok": run(op)})
    except Exception as e:
        out.append({"error": type(e).__name__})
json.dump(out, open(sys.argv[2], "w"))
"#;

fn value_json(v: &Value) -> J {
    match v {
        Value::Null => J::Null,
        Value::Bool(b) => json!(b),
        Value::Int(i) => json!(i),
        Value::Float(f) => json!(f),
        Value::Str(s) => json!(s),
        Value::Bytes(b) => json!(String::from_utf8_lossy(b)),
        Value::Time(_) => json!("TIME"),
        Value::List(l) => J::Array(l.iter().map(value_json).collect()),
        Value::Map(m) => J::Object(m.iter().map(|(k, v)| (k.clone(), value_json(v))).collect()),
    }
}

/// The dict fsspec users see: `{"name", "size", "type", **extra}`.
fn info_json(i: &FileInfo) -> J {
    let mut m = serde_json::Map::new();
    m.insert("name".into(), json!(i.name));
    m.insert("size".into(), json!(i.size));
    m.insert("type".into(), json!(i.file_type.as_fsspec_str()));
    for (k, v) in &i.extra {
        m.insert(k.clone(), value_json(v));
    }
    J::Object(m)
}

/// The Python exception class the bindings raise for an error kind.
fn error_class(k: ErrorKind) -> &'static str {
    match k {
        ErrorKind::NotFound => "FileNotFoundError",
        ErrorKind::PermissionDenied => "PermissionError",
        ErrorKind::AlreadyExists => "FileExistsError",
        ErrorKind::IsADirectory => "IsADirectoryError",
        ErrorKind::NotADirectory => "NotADirectoryError",
        ErrorKind::InvalidInput => "ValueError",
        ErrorKind::Unsupported => "NotImplementedError",
        ErrorKind::Timeout => "TimeoutError",
        // OSError(ENOTEMPTY), kept apart for the documented deviation.
        ErrorKind::DirectoryNotEmpty => "OSError[ENOTEMPTY]",
        _ => "OSError",
    }
}

/// Order-insensitive comparison of dict keys.
fn canonical(v: &J) -> J {
    match v {
        J::Object(m) => {
            let sorted: BTreeMap<_, _> = m.iter().map(|(k, v)| (k.clone(), canonical(v))).collect();
            J::Object(sorted.into_iter().collect())
        }
        J::Array(a) => J::Array(a.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

fn sha256_hex(d: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(d))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn matches_gcsfs() {
    let Some(ep) = endpoint() else {
        return common::skip("matches_gcsfs");
    };
    let Ok(python) = std::env::var("FSFAST_TEST_FSSPEC_PYTHON") else {
        eprintln!("skipping matches_gcsfs: set FSFAST_TEST_FSSPEC_PYTHON to a Python with gcsfs");
        return;
    };
    let fs = filesystem(&ep, &[]);
    let b = unique_bucket("diff");
    fs.mkdir(&b, true).await.unwrap();
    let keys = [
        "plain.txt",
        "dir/a.txt",
        "dir/sub/b.txt",
        "dir/sub/deeper/c.bin",
        "space dir/file name.csv",
        "unicode/ünïcödé/файл.txt",
        "plus+equals=amp&.txt",
        "pct%41/x",
        "tilde~/y",
        "hash#frag?q=1",
        "emptydir/",
        "empty",
        "x/.hidden",
    ];
    for (i, k) in keys.iter().enumerate() {
        let data = if *k == "empty" || k.ends_with('/') {
            Bytes::new()
        } else {
            Bytes::from(format!("content {i} of {k}").repeat(i + 1))
        };
        fs.pipe_file(&format!("{b}/{k}"), data, &WriteOptions::default())
            .await
            .unwrap();
    }

    let mut ops: Vec<J> = Vec::new();
    let mut paths: Vec<String> = vec![b.clone(), format!("{b}/")];
    for k in keys {
        paths.push(format!("{b}/{k}"));
        let trimmed = k.trim_end_matches('/');
        let mut acc = String::new();
        for part in trimmed.split('/') {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(part);
            paths.push(format!("{b}/{acc}"));
        }
    }
    paths.extend([
        format!("gs://{b}/dir"),
        format!("gcs://{b}/dir/a.txt"),
        format!("{b}/missing"),
        format!("{b}/missing/deeper"),
        format!("{b}/plain.txt/child"),
        format!("{b}/dir/"),
        format!("{b}/dir/sub/"),
        "fsfast-no-such-bucket-diff".into(),
        "fsfast-no-such-bucket-diff/key".into(),
    ]);
    paths.sort();
    paths.dedup();
    ops.push(json!({"op": "info", "path": ""}));
    for p in &paths {
        ops.push(json!({"op": "info", "path": p}));
        ops.push(json!({"op": "exists", "path": p}));
        ops.push(json!({"op": "ls", "path": p}));
        ops.push(json!({"op": "ls_names", "path": p}));
        for withdirs in [false, true] {
            ops.push(json!({"op": "find", "path": p, "withdirs": withdirs}));
            ops.push(json!({"op": "find_names", "path": p, "withdirs": withdirs}));
            for d in [1, 2] {
                ops.push(json!({"op": "find", "path": p, "withdirs": withdirs, "maxdepth": d}));
            }
        }
    }
    for k in [
        "plain.txt",
        "dir/sub/deeper/c.bin",
        "empty",
        "unicode/ünïcödé/файл.txt",
        "hash#frag?q=1",
    ] {
        let p = format!("{b}/{k}");
        for (s, e) in [
            (None, None),
            (Some(2), Some(9)),
            (Some(-5), None),
            (Some(3), None),
            (Some(0), Some(1)),
        ] {
            ops.push(json!({"op": "cat", "path": p, "start": s, "end": e}));
        }
    }
    ops.push(json!({"op": "cat", "path": b.clone(), "start": null, "end": null}));
    ops.push(json!({"op": "cat", "path": format!("{b}/missing"), "start": null, "end": null}));
    // Error paths of mutations (none of these changes anything).
    for (p, parents) in [
        (format!("{b}/newdir/x"), true),
        ("fsfast-no-such-bucket-diff/x".to_owned(), false),
    ] {
        ops.push(json!({"op": "mkdir", "path": p, "create_parents": parents}));
    }
    for p in [
        b.clone(),
        format!("{b}/dir"),
        format!("{b}/missing"),
        "fsfast-no-such-bucket-diff".to_owned(),
    ] {
        ops.push(json!({"op": "rmdir", "path": p}));
    }
    ops.push(json!({"op": "cp", "path": format!("{b}/missing"), "dst": format!("{b}/never")}));
    ops.push(json!({"op": "rm", "path": format!("{b}/missing")}));
    ops.push(json!({"op": "rm", "path": "fsfast-no-such-bucket-diff/key"}));

    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("ops.json");
    let output = dir.path().join("out.json");
    std::fs::write(&input, serde_json::to_vec(&ops).unwrap()).unwrap();
    let script = dir.path().join("diff.py");
    std::fs::write(&script, SCRIPT).unwrap();
    let status = Command::new(&python)
        .arg("-I")
        .arg(&script)
        .arg(&input)
        .arg(&output)
        .env("GCSFS_EXPERIMENTAL_ZB_HNS_SUPPORT", "false")
        .env("FSFAST_TEST_GCS_ENDPOINT", &ep)
        .current_dir(dir.path())
        .status()
        .expect("run python");
    assert!(status.success(), "gcsfs script failed");
    let expected: Vec<J> = serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
    assert_eq!(expected.len(), ops.len());

    let mut mismatches = Vec::new();
    for (op, want) in ops.iter().zip(&expected) {
        let p = op["path"].as_str().unwrap();
        let withdirs = op["withdirs"].as_bool().unwrap_or(false);
        let maxdepth = op["maxdepth"].as_u64().map(|d| d as usize);
        let got: Result<J, ErrorKind> = match op["op"].as_str().unwrap() {
            "info" => fs
                .info(p)
                .await
                .map(|i| info_json(&i))
                .map_err(|e| e.kind()),
            "exists" => fs.exists(p).await.map(|b| json!(b)).map_err(|e| e.kind()),
            "ls" => fs
                .ls(p)
                .await
                .map(|v| J::Array(v.iter().map(info_json).collect()))
                .map_err(|e| e.kind()),
            "ls_names" => fs
                .ls(p)
                .await
                .map(|v| json!(v.into_iter().map(|i| i.name).collect::<Vec<_>>()))
                .map_err(|e| e.kind()),
            "find" => fs
                .find(p, &FindOptions { maxdepth, withdirs })
                .await
                .map(|v| {
                    let m: serde_json::Map<String, J> =
                        v.iter().map(|i| (i.name.clone(), info_json(i))).collect();
                    J::Object(m)
                })
                .map_err(|e| e.kind()),
            "find_names" => fs
                .find(p, &FindOptions { maxdepth, withdirs })
                .await
                .map(|v| json!(v.into_iter().map(|i| i.name).collect::<Vec<_>>()))
                .map_err(|e| e.kind()),
            "cat" => {
                let start = op["start"].as_i64();
                let end = op["end"].as_i64();
                let size = if ByteRange::fsspec_needs_size(start, end) {
                    fs.info(p).await.ok().map(|i| i.size)
                } else {
                    None
                };
                match ByteRange::from_fsspec(start, end, size) {
                    Ok(r) => fs
                        .cat_file(p, r)
                        .await
                        .map(|d| json!([d.len(), sha256_hex(&d)]))
                        .map_err(|e| e.kind()),
                    Err(e) => Err(e.kind()),
                }
            }
            "mkdir" => fs
                .mkdir(p, op["create_parents"].as_bool().unwrap())
                .await
                .map(|()| J::Null)
                .map_err(|e| e.kind()),
            "rmdir" => fs.rmdir(p).await.map(|()| J::Null).map_err(|e| e.kind()),
            "rm" => fs.rm_file(p).await.map(|()| J::Null).map_err(|e| e.kind()),
            "cp" => fs
                .cp_file(p, op["dst"].as_str().unwrap())
                .await
                .map(|()| J::Null)
                .map_err(|e| e.kind()),
            other => panic!("{other}"),
        };
        let got_json = match got {
            Ok(v) => json!({"ok": v}),
            Err(k) => json!({"error": error_class(k)}),
        };
        if canonical(&got_json) != canonical(want) && !documented_deviation(op, want, &got_json) {
            mismatches.push(format!("{op}\n  gcsfs:  {want}\n  fsfast: {got_json}"));
        }
    }
    destroy_bucket(&fs, &b).await;
    assert!(
        mismatches.is_empty(),
        "{} of {} calls differ from gcsfs:\n{}",
        mismatches.len(),
        ops.len(),
        mismatches.join("\n")
    );
}

/// Deliberate differences (see the crate docs):
/// * `cat_file` of a range starting at or after the end of the object:
///   GCS answers 416, which gcsfs raises as `HttpError`; fsfast returns
///   empty bytes (fsfast core contract, like fsspec's other filesystems).
/// * `info("")`: gcsfs returns the raw bucket-list response with `size` and
///   `type` added; fsfast returns an empty-named directory entry.
/// * `rmdir` of a non-empty bucket: gcsfs raises `FileExistsError` for the
///   emulator's 412 and `HttpError` for GCS's 409; fsfast raises
///   `DirectoryNotEmpty` (`OSError(ENOTEMPTY)`) for both.
fn documented_deviation(op: &J, want: &J, got: &J) -> bool {
    match op["op"].as_str() {
        Some("cat") => want["error"] == "HttpError" && got["ok"][0] == 0,
        Some("info") => {
            op["path"] == "" && got["ok"]["name"] == "" && got["ok"]["type"] == "directory"
        }
        Some("rmdir") => {
            matches!(
                want["error"].as_str(),
                Some("FileExistsError" | "HttpError")
            ) && got["error"] == "OSError[ENOTEMPTY]"
        }
        _ => false,
    }
}
