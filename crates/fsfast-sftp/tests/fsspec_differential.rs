//! Differential tests against fsspec's own `SFTPFileSystem` (paramiko) on
//! the same OpenSSH server.
//!
//! * Phase 1 (exact values): both implementations inspect the same tree
//!   (files, directories, symlinks to files and directories, a dangling
//!   symlink, non-ASCII names) and must produce identical `info()` and
//!   `ls()` dicts (every key and value, datetimes to the microsecond),
//!   identical `find()` names, `exists()`, `isdir()`,
//!   `modified()`/`created()`, `cat_file` results and error classes.
//! * Phase 2 (behaviour): the same sequence of mutating operations runs on
//!   two mirrored trees, one through fsspec and one through fsfast; return
//!   values, error classes and the resulting trees must agree step by step.
//!
//! Gated on `FSFAST_TEST_SFTP_HOST` and `FSFAST_TEST_FSSPEC_PYTHON` (a
//! Python with fsspec and paramiko, e.g. `.venv/bin/python`).
//!
//! The documented, deliberate differences are not exercised here (see the
//! crate docs): trailing slashes in `info` names, `ls` of a file, the more
//! precise error kinds for `rmdir`/`rm_file`/`open` of the wrong type,
//! `xb` on an existing file, `cp_file` and `touch(truncate=False)`.

mod common;

use std::fmt::Write as _;
use std::process::Command;
use std::time::UNIX_EPOCH;

use bytes::Bytes;
use fsfast_core::{ByteRange, ErrorKind, FileInfo, FileSystem, FindOptions, Value, WriteOptions};
use fsfast_sftp::{INFO_KEYS, SftpFileSystem};

const SCRIPT: &str = r#"
import datetime, hashlib, sys
from fsspec.implementations.sftp import SFTPFileSystem

host, port, user, pw, script = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
fs = SFTPFileSystem(host, port=port, username=user, password=pw, look_for_keys=False, allow_agent=False)

def err(e):
    if isinstance(e, FileNotFoundError): return "NotFound"
    if isinstance(e, FileExistsError): return "AlreadyExists"
    if isinstance(e, IsADirectoryError): return "IsADirectory"
    if isinstance(e, NotADirectoryError): return "NotADirectory"
    if isinstance(e, PermissionError): return "PermissionDenied"
    if isinstance(e, NotImplementedError): return "Unsupported"
    if isinstance(e, OSError): return "Io"
    return "Other:" + type(e).__name__

def val(v):
    if v is None: return "n"
    if isinstance(v, bool): return f"b:{v}"
    if isinstance(v, int): return f"i:{v}"
    if isinstance(v, str): return "s:" + v
    if isinstance(v, datetime.datetime):
        return "us:%d" % ((v - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)) // datetime.timedelta(microseconds=1))
    return "?:" + type(v).__name__

def info(i, root):
    return "{" + ";".join(f"{k}={val(i[k].replace(root, '<R>', 1) if k == 'name' else i[k])}" for k in i) + "}"

def tree(root):
    out = []
    for n in sorted(fs.find(root, withdirs=True)):
        if n == root: continue
        i = fs.info(n) if fs.exists(n) else None
        t = i["type"] if i else "dangling"
        sz = i["size"] if i and i["type"] == "file" else 0
        out.append(f"{n.replace(root, '<R>', 1)}:{t}:{sz}")
    return " ".join(out) or "-"

for line in open(script, encoding="utf-8"):
    f = line.rstrip("\n").split("\t")
    op, root, a = f[0], f[1], f[2:]
    try:
        if op == "info": r = info(fs.info(a[0]), root)
        elif op == "ls": r = " ".join(sorted(info(e, root) for e in fs.ls(a[0], detail=True))) or "-"
        elif op == "lsn": r = " ".join(sorted(n.replace(root, "<R>", 1) for n in fs.ls(a[0], detail=False))) or "-"
        elif op == "find": r = " ".join(n.replace(root, "<R>", 1) for n in fs.find(a[0], withdirs=a[1] == "1", maxdepth=int(a[2]) or None)) or "-"
        elif op == "exists": r = str(fs.exists(a[0]))
        elif op == "isdir": r = str(fs.isdir(a[0]))
        elif op == "isfile": r = str(fs.isfile(a[0]))
        elif op == "modified": r = val(fs.modified(a[0]))
        elif op == "created": r = val(fs.created(a[0]))
        elif op == "cat": r = hashlib.sha256(fs.cat_file(a[0])).hexdigest()
        elif op == "catr": r = fs.cat_file(a[0], int(a[1]), int(a[2])).hex()
        elif op == "pipe": fs.pipe_file(a[0], a[1].encode()); r = "ok"
        elif op == "mkdir": fs.mkdir(a[0], create_parents=a[1] == "1"); r = "ok"
        elif op == "makedirs": fs.makedirs(a[0], exist_ok=a[1] == "1"); r = "ok"
        elif op == "rm": fs.rm_file(a[0]); r = "ok"
        elif op == "rmdir": fs.rmdir(a[0]); r = "ok"
        elif op == "mv": fs.mv(a[0], a[1]); r = "ok"
        elif op == "touch": fs.touch(a[0]); r = "ok"
        elif op == "tree": r = tree(a[0])
        else: r = "?op"
    except Exception as e:
        r = "E:" + err(e)
    print(f"{op} {r}", flush=True)
"#;

fn val(v: &Value) -> String {
    match v {
        Value::Null => "n".into(),
        Value::Bool(b) => format!("b:{}", if *b { "True" } else { "False" }),
        Value::Int(i) => format!("i:{i}"),
        Value::Str(s) => format!("s:{s}"),
        Value::Time(t) => format!("us:{}", t.duration_since(UNIX_EPOCH).unwrap().as_micros()),
        other => format!("?:{}", other.type_name()),
    }
}

/// The fsspec dict of `i`, in fsspec's key order.
fn info_str(i: &FileInfo, root: &str) -> String {
    let mut parts = Vec::new();
    for k in INFO_KEYS {
        let v = match *k {
            "name" => format!("s:{}", i.name.replacen(root, "<R>", 1)),
            "size" => format!("i:{}", i.size),
            "type" => format!("s:{}", i.file_type.as_fsspec_str()),
            k => val(&i.extra[k]),
        };
        parts.push(format!("{k}={v}"));
    }
    format!("{{{}}}", parts.join(";"))
}

fn kind_str(k: ErrorKind) -> String {
    match k {
        ErrorKind::NotFound => "NotFound".into(),
        ErrorKind::AlreadyExists => "AlreadyExists".into(),
        ErrorKind::IsADirectory => "IsADirectory".into(),
        ErrorKind::NotADirectory => "NotADirectory".into(),
        ErrorKind::PermissionDenied => "PermissionDenied".into(),
        ErrorKind::Unsupported => "Unsupported".into(),
        ErrorKind::Io | ErrorKind::DirectoryNotEmpty => "Io".into(),
        other => format!("Other:{other:?}"),
    }
}

async fn tree(fs: &SftpFileSystem, root: &str) -> String {
    let all = fs
        .find(
            root,
            &FindOptions {
                maxdepth: None,
                withdirs: true,
            },
        )
        .await
        .unwrap();
    let mut out = Vec::new();
    let mut names: Vec<String> = all
        .into_iter()
        .map(|e| e.name)
        .filter(|n| n != root)
        .collect();
    names.sort();
    for n in names {
        let (t, sz) = match fs.info(&n).await {
            Ok(i) => (
                i.file_type.as_fsspec_str().to_owned(),
                if i.is_file() { i.size } else { 0 },
            ),
            Err(_) => ("dangling".to_owned(), 0),
        };
        out.push(format!("{}:{t}:{sz}", n.replacen(root, "<R>", 1)));
    }
    if out.is_empty() {
        "-".into()
    } else {
        out.join(" ")
    }
}

async fn ours(fs: &SftpFileSystem, line: &str) -> String {
    let f: Vec<&str> = line.split('\t').collect();
    let (op, root, a) = (f[0], f[1], &f[2..]);
    let r: fsfast_core::Result<String> = async {
        Ok(match op {
            "info" => info_str(&fs.info(a[0]).await?, root),
            "ls" => {
                let mut v: Vec<String> = fs
                    .ls(a[0])
                    .await?
                    .iter()
                    .map(|e| info_str(e, root))
                    .collect();
                v.sort();
                if v.is_empty() {
                    "-".into()
                } else {
                    v.join(" ")
                }
            }
            "lsn" => {
                let mut v: Vec<String> = fs
                    .ls(a[0])
                    .await?
                    .into_iter()
                    .map(|e| e.name.replacen(root, "<R>", 1))
                    .collect();
                v.sort();
                if v.is_empty() {
                    "-".into()
                } else {
                    v.join(" ")
                }
            }
            "find" => {
                let maxdepth: usize = a[2].parse().unwrap();
                let v: Vec<String> = fs
                    .find(
                        a[0],
                        &FindOptions {
                            maxdepth: (maxdepth > 0).then_some(maxdepth),
                            withdirs: a[1] == "1",
                        },
                    )
                    .await?
                    .into_iter()
                    .map(|e| e.name.replacen(root, "<R>", 1))
                    .collect();
                if v.is_empty() {
                    "-".into()
                } else {
                    v.join(" ")
                }
            }
            "exists" => if fs.exists(a[0]).await? {
                "True"
            } else {
                "False"
            }
            .into(),
            "isdir" => match fs.info(a[0]).await {
                Ok(i) => if i.is_dir() { "True" } else { "False" }.into(),
                Err(_) => "False".into(),
            },
            "isfile" => match fs.info(a[0]).await {
                Ok(i) => if i.is_file() { "True" } else { "False" }.into(),
                Err(_) => "False".into(),
            },
            "modified" => val(&Value::Time(fs.info(a[0]).await?.modified.unwrap())),
            "created" => val(&Value::Time(fs.info(a[0]).await?.created.unwrap())),
            "cat" => {
                use sha2::Digest;
                let b = fs.cat_file(a[0], ByteRange::Full).await?;
                hex(&sha2::Sha256::digest(&b))
            }
            "catr" => {
                let (s, e) = (a[1].parse().unwrap(), a[2].parse().unwrap());
                hex(&fs
                    .cat_file(a[0], ByteRange::Bounded { start: s, end: e })
                    .await?)
            }
            "pipe" => {
                fs.pipe_file(
                    a[0],
                    Bytes::copy_from_slice(a[1].as_bytes()),
                    &WriteOptions::default(),
                )
                .await?;
                "ok".into()
            }
            "mkdir" => {
                fs.mkdir(a[0], a[1] == "1").await?;
                "ok".into()
            }
            "makedirs" => {
                fs.makedirs(a[0], a[1] == "1").await?;
                "ok".into()
            }
            "rm" => {
                fs.rm_file(a[0]).await?;
                "ok".into()
            }
            "rmdir" => {
                fs.rmdir(a[0]).await?;
                "ok".into()
            }
            "mv" => {
                fs.mv_file(a[0], a[1]).await?;
                "ok".into()
            }
            "touch" => {
                fs.touch(a[0], true).await?;
                "ok".into()
            }
            "tree" => tree(fs, a[0]).await,
            _ => "?op".into(),
        })
    }
    .await;
    match r {
        Ok(s) => format!("{op} {s}"),
        Err(e) => format!("{op} E:{}", kind_str(e.kind())),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn run_python(py: &str, env: &common::Env, lines: &[String]) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("diff.py");
    let ops = dir.path().join("ops.tsv");
    std::fs::write(&script, SCRIPT).unwrap();
    std::fs::write(&ops, lines.join("\n") + "\n").unwrap();
    let out = Command::new(py)
        .arg(&script)
        .arg(&env.host)
        .arg(env.port.to_string())
        .arg(&env.user)
        .arg(&env.password)
        .arg(&ops)
        .output()
        .expect("running the fsspec reference");
    assert!(
        out.status.success(),
        "fsspec script failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn python() -> Option<String> {
    match std::env::var("FSFAST_TEST_FSSPEC_PYTHON") {
        Ok(p) if !p.is_empty() => Some(p),
        _ => {
            eprintln!("skipping differential test: FSFAST_TEST_FSSPEC_PYTHON is not set");
            None
        }
    }
}

fn compare(lines: &[String], theirs: &[String], mine: &[String]) {
    assert_eq!(theirs.len(), lines.len(), "fsspec output: {theirs:#?}");
    let mut diffs = String::new();
    for ((l, t), m) in lines.iter().zip(theirs).zip(mine) {
        if !equivalent(l, t, m) {
            let _ = writeln!(diffs, "op:     {l}\nfsspec: {t}\nfsfast: {m}\n");
        }
    }
    assert!(diffs.is_empty(), "differences:\n{diffs}");
}

/// `t` (fsspec) and `m` (fsfast) agree, modulo:
///
/// * access times (`time`): both sides read the same files at different
///   moments, and every read or listing moves the atime, so only its
///   presence and format are compared (`mtime` is compared exactly).
///
/// Error classes must match exactly (including `mkdir`/`makedirs` below a
/// regular file and `rmdir` of a file: `FileNotFoundError` on both sides).
fn equivalent(op: &str, t: &str, m: &str) -> bool {
    fn mask_atime(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(i) = rest.find(";time=us:") {
            let (head, tail) = rest.split_at(i + ";time=us:".len());
            out.push_str(head);
            out.push('*');
            rest = tail.trim_start_matches(|c: char| c.is_ascii_digit() || c == '-');
        }
        out.push_str(rest);
        out
    }
    let _ = op;
    mask_atime(t) == mask_atime(m)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_tree_same_answers() {
    let Some(env) = common::env() else { return };
    let Some(py) = python() else { return };
    let fs = env.fs(&[]);
    let root = env.dir("diff1");
    let p = |r: &str| format!("{root}/{r}");
    fs.mkdir(&root, false).await.unwrap();
    for (name, data) in [
        ("a.txt", b"alpha".to_vec()),
        ("empty", vec![]),
        (
            "big.bin",
            (0..300_000u32).map(|i| (i % 253) as u8).collect(),
        ),
        ("dir/b.txt", b"bravo".to_vec()),
        ("dir/sub/c.txt", b"charlie".to_vec()),
        ("ünï cödé.txt", "名前".as_bytes().to_vec()),
    ] {
        fs.makedirs(&fsfast_core::path::parent(&p(name)), true)
            .await
            .unwrap();
        fs.pipe_file(&p(name), Bytes::from(data), &WriteOptions::default())
            .await
            .unwrap();
    }
    fs.mkdir(&p("emptydir"), false).await.unwrap();
    fs.symlink("a.txt", &p("link")).await.unwrap();
    fs.symlink(&p("dir"), &p("dirlink")).await.unwrap();
    fs.symlink(&p("nowhere"), &p("dangling")).await.unwrap();

    let mut lines = Vec::new();
    let mut add = |op: &str, args: &[&str]| {
        let mut l = format!("{op}\t{root}");
        for a in args {
            l.push('\t');
            l.push_str(a);
        }
        lines.push(l);
    };
    for path in [
        "a.txt",
        "empty",
        "big.bin",
        "dir",
        "dir/sub",
        "dir/b.txt",
        "emptydir",
        "link",
        "dirlink",
        "dangling",
        "missing",
        "a.txt/x",
        "ünï cödé.txt",
    ] {
        let full = p(path);
        for op in ["info", "exists", "isdir", "isfile"] {
            add(op, &[&full]);
        }
        if !["missing", "dangling", "a.txt/x"].contains(&path) {
            add("modified", &[&full]);
            add("created", &[&full]);
        }
    }
    add("info", &[&root]);
    for d in [
        root.as_str(),
        &p("dir"),
        &p("dir/sub"),
        &p("emptydir"),
        &p("dirlink"),
        &p("missing"),
    ] {
        add("ls", &[d]);
        add("lsn", &[d]);
    }
    for (w, m) in [
        ("0", "0"),
        ("1", "0"),
        ("0", "1"),
        ("1", "1"),
        ("1", "2"),
        ("0", "3"),
    ] {
        add("find", &[&root, w, m]);
    }
    add("find", &[&p("a.txt"), "0", "0"]);
    add("find", &[&p("missing"), "1", "0"]);
    for f in [
        "a.txt",
        "big.bin",
        "empty",
        "link",
        "dir/sub/c.txt",
        "ünï cödé.txt",
    ] {
        add("cat", &[&p(f)]);
    }
    add("cat", &[&p("missing")]);
    add("catr", &[&p("big.bin"), "1000", "1010"]);
    add("catr", &[&p("big.bin"), "299995", "400000"]);
    add("catr", &[&p("a.txt"), "10", "20"]);

    let theirs = run_python(&py, &env, &lines);
    let mut mine = Vec::new();
    for l in &lines {
        mine.push(ours(&fs, l).await);
    }
    compare(&lines, &theirs, &mine);
    common::rm_tree(&fs, &root).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_operations_same_results() {
    let Some(env) = common::env() else { return };
    let Some(py) = python() else { return };
    let fs = env.fs(&[]);
    let base = env.dir("diff2");
    fs.mkdir(&base, false).await.unwrap();
    let (ra, rb) = (format!("{base}/fsspec"), format!("{base}/fsfast"));
    fs.mkdir(&ra, false).await.unwrap();
    fs.mkdir(&rb, false).await.unwrap();

    // (op, args relative to the root; a leading "@" marks a path)
    let steps: &[(&str, &[&str])] = &[
        ("pipe", &["@f1", "one"]),
        ("pipe", &["@f1", "replaced and longer"]),
        ("mkdir", &["@d1", "0"]),
        ("mkdir", &["@d1", "0"]),
        ("mkdir", &["@d1", "1"]),
        ("mkdir", &["@x/y/z", "0"]),
        ("mkdir", &["@x/y/z", "1"]),
        ("makedirs", &["@x/y/z", "1"]),
        ("makedirs", &["@x/y/z", "0"]),
        ("makedirs", &["@m/n", "0"]),
        ("pipe", &["@d1/f2", "two"]),
        ("pipe", &["@nodir/f", "x"]),
        ("mv", &["@f1", "@d1/f1"]),
        ("mv", &["@missing", "@whatever"]),
        ("mv", &["@d1/f2", "@d1/f1"]),
        ("mv", &["@m", "@m2"]),
        ("rm", &["@d1/f2"]),
        ("rm", &["@missing"]),
        ("rmdir", &["@x/y/z"]),
        ("rmdir", &["@missing"]),
        ("touch", &["@t"]),
        ("pipe", &["@t", "content"]),
        ("touch", &["@t"]),
        ("mkdir", &["@t", "0"]),
        ("mkdir", &["@t/sub", "1"]),
        ("mkdir", &["@t/sub", "0"]),
        ("makedirs", &["@t/sub/deeper", "1"]),
        ("rmdir", &["@t"]),
        ("tree", &["@"]),
    ];
    let mut lines_a = Vec::new();
    let mut lines_b = Vec::new();
    for (op, args) in steps {
        for (root, lines) in [(&ra, &mut lines_a), (&rb, &mut lines_b)] {
            let mut l = format!("{op}\t{root}");
            for a in *args {
                l.push('\t');
                match a.strip_prefix('@') {
                    Some("") => l.push_str(root),
                    Some(rel) => l.push_str(&format!("{root}/{rel}")),
                    None => l.push_str(a),
                }
            }
            lines.push(l);
        }
        lines_a.push(format!("tree\t{ra}\t{ra}"));
        lines_b.push(format!("tree\t{rb}\t{rb}"));
    }
    let theirs = run_python(&py, &env, &lines_a);
    let mut mine = Vec::new();
    for l in &lines_b {
        mine.push(ours(&fs, l).await);
    }
    compare(&lines_b, &theirs, &mine);
    common::rm_tree(&fs, &base).await;
}
