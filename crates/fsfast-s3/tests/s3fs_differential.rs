//! Differential test against s3fs on the same RustFS endpoint: the same
//! `info`, `ls`, `find`, `exists` and `cat_file` calls go through s3fs (in a
//! Python subprocess) and through fsfast on a tree with awkward keys, and
//! the results must be identical: the entries' dict keys and values
//! (timestamps compared as "is a datetime"), their order, and the exception
//! types of failures.
//!
//! Gated on `FSFAST_TEST_FSSPEC_PYTHON` (a Python with s3fs) and the RustFS
//! variables (`eval "$(scripts/test-services.sh env)"`).

mod common;

use std::collections::BTreeMap;
use std::process::Command;

use bytes::Bytes;
use common::{destroy_bucket, filesystem, s3_env, unique_bucket};
use fsfast_core::{ByteRange, ErrorKind, FileInfo, FileSystem, FindOptions, Value, WriteOptions};
use serde_json::{Value as J, json};

const SCRIPT: &str = r#"
import datetime, hashlib, json, os, sys
import s3fs
fs = s3fs.S3FileSystem(
    key=os.environ["FSFAST_TEST_S3_KEY"], secret=os.environ["FSFAST_TEST_S3_SECRET"],
    endpoint_url=os.environ["FSFAST_TEST_S3_ENDPOINT"],
    use_listings_cache=False, skip_instance_cache=True)

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
    if kind == "find_prefix":
        return norm(fs.find(p, maxdepth=op.get("maxdepth"), withdirs=op["withdirs"], detail=True, prefix=op["prefix"]))
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
        _ => "OSError",
    }
}

/// Sort-insensitive object comparison: dict key order is irrelevant.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn matches_s3fs() {
    let Some(env) = s3_env() else {
        return common::skip("matches_s3fs");
    };
    let Ok(python) = std::env::var("FSFAST_TEST_FSSPEC_PYTHON") else {
        eprintln!("skipping matches_s3fs: set FSFAST_TEST_FSSPEC_PYTHON to a Python with s3fs");
        return;
    };
    let fs = filesystem(&env, &[]);
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
        "emptydir/",
        "both",
        "both/inner",
        "trailing/slash/",
        // (RustFS, like MinIO, rejects keys with empty path segments.)
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
    let mut paths: Vec<String> = vec![String::new(), b.clone(), format!("{b}/")];
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
        format!("{b}/missing"),
        format!("{b}/missing/deeper"),
        format!("{b}/plain.txt/child"),
        format!("{b}/dir/"),
        // Trailing slashes on files and directories, protocol prefixes.
        format!("{b}/plain.txt/"),
        format!("{b}/dir/sub/"),
        format!("{b}/both/"),
        format!("{b}/emptydir"),
        format!("s3://{b}/dir/a.txt"),
        format!("s3://{b}/dir"),
        format!("s3a://{b}/space dir/"),
        format!("s3://{b}"),
        "fsfast-no-such-bucket-diff".into(),
        "fsfast-no-such-bucket-diff/key".into(),
    ]);
    paths.sort();
    paths.dedup();
    for p in &paths {
        // s3fs lists every bucket for "": only compare info/exists there.
        ops.push(json!({"op": "info", "path": p}));
        ops.push(json!({"op": "exists", "path": p}));
        if p.is_empty() {
            continue;
        }
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
    ] {
        let p = format!("{b}/{k}");
        for (s, e) in [
            (None, None),
            (Some(2), Some(9)),
            (Some(-5), None),
            (Some(3), None),
        ] {
            ops.push(json!({"op": "cat", "path": p, "start": s, "end": e}));
        }
    }
    ops.push(json!({"op": "cat", "path": format!("{b}/dir"), "start": null, "end": null}));
    for (p, prefix) in [
        (b.clone(), "di"),
        (b.clone(), "dir"),
        (format!("{b}/dir"), "s"),
        (format!("{b}/dir"), "sub/"),
        (b.clone(), "nothing-matches"),
    ] {
        for withdirs in [false, true] {
            ops.push(
                json!({"op": "find_prefix", "path": p, "prefix": prefix, "withdirs": withdirs}),
            );
            for d in [1, 2] {
                ops.push(json!({"op": "find_prefix", "path": p, "prefix": prefix, "withdirs": withdirs, "maxdepth": d}));
            }
        }
    }
    // Error paths of mutations (none of these changes anything).
    for (p, parents) in [
        (b.clone(), true),
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
    ops.push(json!({"op": "cat", "path": format!("{b}/missing"), "start": null, "end": null}));

    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("ops.json");
    let output = dir.path().join("out.json");
    std::fs::write(&input, serde_json::to_vec(&ops).unwrap()).unwrap();
    let script = dir.path().join("diff.py");
    std::fs::write(&script, SCRIPT).unwrap();
    let status = Command::new(&python)
        .arg(&script)
        .arg(&input)
        .arg(&output)
        .status()
        .expect("run python");
    assert!(status.success(), "s3fs script failed");
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
                .map(|v| {
                    // s3fs: sorted names for detail=False.
                    let mut n: Vec<String> = v.into_iter().map(|i| i.name).collect();
                    n.sort();
                    json!(n)
                })
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
            "find_prefix" => fs
                .find_prefix(
                    p,
                    op["prefix"].as_str().unwrap(),
                    &FindOptions { maxdepth, withdirs },
                )
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
                        .map(|d| {
                            use sha2_hex::digest;
                            json!([d.len(), digest(&d)])
                        })
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
            mismatches.push(format!("{op}\n  s3fs:   {want}\n  fsfast: {got_json}"));
        }
    }
    destroy_bucket(&fs, &b).await;
    assert!(
        mismatches.is_empty(),
        "{} of {} calls differ from s3fs:\n{}",
        mismatches.len(),
        ops.len(),
        mismatches.join("\n")
    );
}

/// Deliberate differences (see the crate docs):
/// * `cat_file` of a range starting at or after the end of the object:
///   S3 answers `InvalidRange`, which s3fs raises as `OSError(EINVAL)`;
///   fsfast returns empty bytes like fsspec's other filesystems (and the
///   fsfast core contract: ranges past EOF are truncated).
fn documented_deviation(op: &J, want: &J, got: &J) -> bool {
    op["op"] == "cat" && want["error"] == "OSError" && got["ok"][0] == 0
}

/// SHA-256 hex without another dev-dependency: the crate's signer helper.
mod sha2_hex {
    pub fn digest(d: &[u8]) -> String {
        fsfast_s3::sigv4::sha256_hex(d)
    }
}
