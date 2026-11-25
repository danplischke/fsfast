//! Differential test against adlfs on the same Azurite: the same `info`,
//! `ls`, `find`, `exists`, `cat_file` calls (and the error paths of a few
//! mutations) go through adlfs in a Python subprocess and through fsfast on
//! a tree with awkward blob names; the results must match: the entries'
//! dict keys and values (timestamps compared as "is a datetime", bytes as
//! base64), their order, and the exception types of failures.
//!
//! Known, documented differences are normalised here: fsfast's
//! `find(withdirs=True)` includes the root (fsspec's contract; adlfs leaves
//! it out).
//!
//! Gated on `FSFAST_TEST_FSSPEC_PYTHON` (a Python with adlfs) and
//! `FSFAST_TEST_AZURE_CONNECTION_STRING` (`eval "$(scripts/test-services.sh env)"`).

mod common;

use std::process::Command;

use base64::Engine as _;
use bytes::Bytes;
use common::{connection_string, destroy_container, filesystem, unique_container};
use fsfast_core::{
    ByteRange, ErrorKind, FileInfo, FileSystem, FindOptions, Value, WriteMode, WriteOptions,
};
use serde_json::{Value as J, json};

const SCRIPT: &str = r#"
import base64, datetime, json, os, sys, warnings
warnings.simplefilter("ignore")
from adlfs import AzureBlobFileSystem
fs = AzureBlobFileSystem(connection_string=os.environ["FSFAST_TEST_AZURE_CONNECTION_STRING"], skip_instance_cache=True)

def norm(v):
    if isinstance(v, datetime.datetime):
        return "TIME"
    if isinstance(v, (bytes, bytearray)):
        return base64.b64encode(bytes(v)).decode()
    if isinstance(v, dict) or hasattr(v, "items"):
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
    if kind == "find":
        r = fs.find(p, withdirs=op["withdirs"], detail=True)
        if isinstance(r, list):
            # adlfs returns a plain list of names when the root is a file.
            return {"names": r}
        return norm(list(r.values()))
    if kind == "exists":
        return fs.exists(p)
    if kind == "cat":
        d = fs.cat_file(p, start=op.get("start"), end=op.get("end"))
        return base64.b64encode(d).decode()
    if kind == "mkdir":
        fs.mkdir(p, create_parents=op["create_parents"])
        return None
    if kind == "cp":
        fs.cp_file(p, op["dst"])
        return None
    if kind == "rm":
        fs.rm_file(p)
        return None
    if kind == "pipe_create":
        fs.pipe_file(p, b"x", mode="create")
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

fn val(v: &Value) -> J {
    match v {
        Value::Null => J::Null,
        Value::Bool(b) => json!(b),
        Value::Int(i) => json!(i),
        Value::Float(f) => json!(f),
        Value::Str(s) => json!(s),
        Value::Bytes(b) => json!(base64::engine::general_purpose::STANDARD.encode(b)),
        Value::Time(_) => json!("TIME"),
        Value::List(l) => J::Array(l.iter().map(val).collect()),
        Value::Map(m) => J::Object(m.iter().map(|(k, v)| (k.clone(), val(v))).collect()),
    }
}

/// The dict the Python layer builds: name, size, type, then extras (which
/// may override size with None).
fn info_json(i: &FileInfo) -> J {
    let mut m = serde_json::Map::new();
    m.insert("name".into(), json!(i.name));
    m.insert("size".into(), json!(i.size));
    m.insert("type".into(), json!(i.file_type.as_fsspec_str()));
    for (k, v) in &i.extra {
        m.insert(k.clone(), val(v));
    }
    J::Object(m)
}

fn err_name(k: ErrorKind) -> &'static str {
    match k {
        ErrorKind::NotFound => "FileNotFoundError",
        ErrorKind::AlreadyExists => "FileExistsError",
        ErrorKind::PermissionDenied => "PermissionError",
        ErrorKind::InvalidInput => "ValueError",
        _ => "OSError",
    }
}

fn outcome<T>(r: fsfast_core::Result<T>, f: impl FnOnce(T) -> J) -> J {
    match r {
        Ok(v) => json!({"ok": f(v)}),
        Err(e) => json!({"error": err_name(e.kind())}),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matches_adlfs() {
    let (Some(cs), Ok(python)) = (
        connection_string(),
        std::env::var("FSFAST_TEST_FSSPEC_PYTHON"),
    ) else {
        eprintln!(
            "skipping matches_adlfs: needs FSFAST_TEST_FSSPEC_PYTHON and FSFAST_TEST_AZURE_CONNECTION_STRING"
        );
        return;
    };
    let fs = filesystem(&cs, &[]);
    let c = unique_container("diff");
    fs.mkdir(&c, true).await.unwrap();
    let w = WriteOptions::default();
    let typed = WriteOptions {
        content_type: Some("text/csv".into()),
        ..WriteOptions::default()
    };
    for (name, data, opts) in [
        ("top.txt", &b"0123456789"[..], &w),
        ("a/b.txt", b"hello", &w),
        ("a/c/d.bin", b"deep", &w),
        ("f", b"fff", &w),
        ("f/z", b"z", &w),
        ("sp ace/ü+x%20y.csv", b"a,b\n", &typed),
        ("empty", b"", &w),
    ] {
        fs.pipe_file(&format!("{c}/{name}"), Bytes::from_static(data), opts)
            .await
            .unwrap();
    }

    let p = |rel: &str| {
        if rel.is_empty() {
            c.clone()
        } else {
            format!("{c}/{rel}")
        }
    };
    let missing_container = unique_container("nocont");
    let mut ops: Vec<J> = Vec::new();
    for rel in [
        "",
        "top.txt",
        "a/b.txt",
        "a",
        "a/",
        "a/c",
        "sp ace/ü+x%20y.csv",
        "empty",
        "missing",
        "a/missing/deeper",
    ] {
        ops.push(json!({"op": "info", "path": p(rel)}));
    }
    ops.push(json!({"op": "info", "path": missing_container}));
    for rel in ["", "a", "a/c", "top.txt", "sp ace", "missing"] {
        ops.push(json!({"op": "ls", "path": p(rel)}));
    }
    ops.push(json!({"op": "ls", "path": missing_container}));
    for rel in ["", "a", "top.txt", "missing"] {
        for withdirs in [false, true] {
            ops.push(json!({"op": "find", "path": p(rel), "withdirs": withdirs}));
        }
    }
    for rel in ["", "top.txt", "a", "a/c", "missing", "f"] {
        ops.push(json!({"op": "exists", "path": p(rel)}));
    }
    ops.push(json!({"op": "exists", "path": missing_container}));
    for (start, end) in [
        (None, None),
        (Some(2), Some(5)),
        (Some(3), None),
        (Some(0), Some(10)),
    ] {
        ops.push(json!({"op": "cat", "path": p("top.txt"), "start": start, "end": end}));
    }
    ops.push(json!({"op": "cat", "path": p("missing")}));
    ops.push(json!({"op": "rm", "path": p("missing")}));
    ops.push(json!({"op": "cp", "path": p("missing"), "dst": p("x")}));
    ops.push(
        json!({"op": "mkdir", "path": format!("{missing_container}/sub"), "create_parents": false}),
    );
    ops.push(json!({"op": "pipe_create", "path": p("top.txt")}));

    let dir = tempfile::tempdir().unwrap();
    let (inp, outp, script) = (
        dir.path().join("ops.json"),
        dir.path().join("out.json"),
        dir.path().join("diff.py"),
    );
    std::fs::write(&inp, serde_json::to_vec(&ops).unwrap()).unwrap();
    std::fs::write(&script, SCRIPT).unwrap();
    let status = tokio::task::spawn_blocking({
        let (python, script, inp, outp, cs) = (
            python.clone(),
            script.clone(),
            inp.clone(),
            outp.clone(),
            cs.clone(),
        );
        move || {
            Command::new(python)
                .arg("-I")
                .arg(script)
                .arg(inp)
                .arg(outp)
                .env("FSFAST_TEST_AZURE_CONNECTION_STRING", cs)
                .status()
        }
    })
    .await
    .unwrap()
    .unwrap();
    assert!(status.success(), "adlfs script failed");
    let theirs: Vec<J> = serde_json::from_slice(&std::fs::read(&outp).unwrap()).unwrap();

    let mut mismatches = Vec::new();
    for (op, want) in ops.iter().zip(&theirs) {
        let path = op["path"].as_str().unwrap();
        let got = match op["op"].as_str().unwrap() {
            "info" => outcome(fs.info(path).await, |i| info_json(&i)),
            "ls" => outcome(fs.ls(path).await, |v| {
                J::Array(v.iter().map(info_json).collect())
            }),
            "find" => {
                let withdirs = op["withdirs"].as_bool().unwrap();
                outcome(
                    fs.find(
                        path,
                        &FindOptions {
                            maxdepth: None,
                            withdirs,
                        },
                    )
                    .await,
                    |v| {
                        if v.len() == 1 && v[0].name == path && v[0].is_file() {
                            return json!({"names": [path]});
                        }
                        // fsfast includes the root with withdirs; adlfs does not.
                        J::Array(
                            v.iter()
                                .filter(|i| !(i.name == path && i.is_dir()))
                                .map(info_json)
                                .collect(),
                        )
                    },
                )
            }
            "exists" => outcome(fs.exists(path).await, |b| json!(b)),
            "cat" => {
                let r =
                    ByteRange::from_fsspec(op["start"].as_i64(), op["end"].as_i64(), None).unwrap();
                outcome(fs.cat_file(path, r).await, |d| {
                    json!(base64::engine::general_purpose::STANDARD.encode(d))
                })
            }
            "rm" => outcome(fs.rm_file(path).await, |_| J::Null),
            "cp" => outcome(fs.cp_file(path, op["dst"].as_str().unwrap()).await, |_| {
                J::Null
            }),
            "mkdir" => outcome(
                fs.mkdir(path, op["create_parents"].as_bool().unwrap())
                    .await,
                |_| J::Null,
            ),
            "pipe_create" => outcome(
                fs.pipe_file(
                    path,
                    Bytes::from_static(b"x"),
                    &WriteOptions::default().with_mode(WriteMode::CreateNew),
                )
                .await,
                |_| J::Null,
            ),
            other => panic!("{other}"),
        };
        let mut want: J = want.clone();
        if op["op"] == "info" && path.ends_with('/') {
            // fsfast reports directory names without the trailing slash
            // (fsfast-core contract); adlfs echoes the path.
            if let Some(n) = want.pointer_mut("/ok/name") {
                *n = json!(path.trim_end_matches('/'));
            }
        }
        if got != want {
            mismatches.push(format!("{op}\n  adlfs:  {want}\n  fsfast: {got}"));
        }
    }
    destroy_container(&fs, &c).await;
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
