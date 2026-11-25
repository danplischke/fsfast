//! Differential tests against fsspec's own `SMBFileSystem` (smbprotocol /
//! smbclient) on the same Samba server.
//!
//! * Phase 1 (exact values): both implementations inspect the same tree and
//!   must produce identical `info()` and `ls()` dicts — every key, every
//!   value, floats compared bit for bit — plus identical `find()` names,
//!   `exists()`, `created()`/`modified()`, `cat_file` results and error
//!   types.
//! * Phase 2 (behaviour): the same sequence of mutating operations runs on
//!   two mirrored trees, one through fsspec and one through fsfast; results
//!   (return values, listings, error types) must agree line by line.
//!
//! Gated on `FSFAST_TEST_SMB_HOST` and `FSFAST_TEST_FSSPEC_PYTHON` (a Python
//! with fsspec and smbprotocol, e.g. `.venv/bin/python`).
//!
//! The documented, deliberate differences are not exercised: `mv_file`
//! onto an existing file (fsfast replaces it), `ls` of a file (fsfast
//! returns the file's info), `touch(truncate=False)` of an existing file
//! (fsfast updates the time) and moves across shares (fsfast copies).

mod common;

use std::fmt::Write as _;
use std::process::Command;

use bytes::Bytes;
use fsfast_core::{
    ByteRange, ErrorKind, FileInfo, FileSystem, FindOptions, Value, WriteMode, WriteOptions,
};
use fsfast_smb::SmbFileSystem;

const SCRIPT: &str = r#"
import datetime, errno, struct, sys
from fsspec.implementations.smb import SMBFileSystem

host, port, user, pw, script = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
fs = SMBFileSystem(host=host, port=port, username=user, password=pw)

def err(e):
    # smbclient raises SMBOSError, an OSError subclass carrying the errno
    # (not FileNotFoundError & co.), so classify by errno first.
    no = getattr(e, "errno", None)
    by_errno = {errno.ENOENT: "NotFound", errno.EEXIST: "AlreadyExists", errno.EISDIR: "IsADirectory",
                errno.ENOTDIR: "NotADirectory", errno.EACCES: "PermissionDenied", errno.EPERM: "PermissionDenied",
                errno.ENOTEMPTY: "DirectoryNotEmpty"}
    if isinstance(e, OSError) and no in by_errno: return by_errno[no]
    if isinstance(e, FileNotFoundError): return "NotFound"
    if isinstance(e, FileExistsError): return "AlreadyExists"
    if isinstance(e, IsADirectoryError): return "IsADirectory"
    if isinstance(e, NotADirectoryError): return "NotADirectory"
    if isinstance(e, PermissionError): return "PermissionDenied"
    if isinstance(e, NotImplementedError): return "Unsupported"
    if isinstance(e, ValueError): return "InvalidInput"
    if isinstance(e, OSError) and e.errno == errno.ENOTEMPTY: return "DirectoryNotEmpty"
    if isinstance(e, OSError): return "Io"
    return "Other:" + type(e).__name__

def val(v):
    if isinstance(v, bool): return f"b:{v}"
    if isinstance(v, int): return f"i:{v}"
    if isinstance(v, float): return "f:%016x" % struct.unpack("<Q", struct.pack("<d", v))[0]
    if isinstance(v, str): return "s:" + v
    if isinstance(v, datetime.datetime):
        return "us:%d" % ((v - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)) // datetime.timedelta(microseconds=1))
    return "?:" + type(v).__name__

def info(i):
    return "{" + ";".join(f"{k}={val(i[k])}" for k in i) + "}"

for line in open(script, encoding="utf-8"):
    f = line.rstrip("\n").split("\t")
    op, a = f[0], f[1:]
    try:
        if op == "info": r = info(fs.info(a[0]))
        elif op == "ls": r = " ".join(sorted(info(e) for e in fs.ls(a[0], detail=True))) or "-"
        elif op == "lsn": r = " ".join(sorted(fs.ls(a[0], detail=False))) or "-"
        elif op == "find": r = " ".join(n.rstrip("/") for n in fs.find(a[0], withdirs=a[1] == "1", maxdepth=int(a[2]) or None)) or "-"
        elif op == "exists": r = str(fs.exists(a[0]))
        elif op == "isdir": r = str(fs.isdir(a[0]))
        elif op == "created": r = val(fs.created(a[0]))
        elif op == "modified": r = val(fs.modified(a[0]))
        elif op == "cat": r = fs.cat_file(a[0], int(a[1]) if a[1] else None, int(a[2]) if a[2] else None).hex() or "-"
        elif op == "pipe": fs.pipe_file(a[0], bytes.fromhex(a[1])); r = "ok"
        elif op == "pipex":
            with fs.open(a[0], "xb") as fh: fh.write(bytes.fromhex(a[1]))
            r = "ok"
        elif op == "append":
            with fs.open(a[0], "ab") as fh: fh.write(bytes.fromhex(a[1]))
            r = "ok"
        elif op == "mkdir": fs.mkdir(a[0], create_parents=a[1] == "1"); r = "ok"
        elif op == "makedirs": fs.makedirs(a[0], exist_ok=a[1] == "1"); r = "ok"
        elif op == "rm_file": fs.rm_file(a[0]); r = "ok"
        elif op == "rmdir": fs.rmdir(a[0]); r = "ok"
        elif op == "mv": fs.mv(a[0], a[1]); r = "ok"
        elif op == "cp": fs.copy(a[0], a[1]); r = "ok"
        elif op == "touch": fs.touch(a[0], truncate=True); r = "ok"
        elif op == "size": r = str(fs.size(a[0]))
        else: r = "bad op " + op
    except Exception as e:
        r = "E:" + err(e)
    print(f"{line.rstrip(chr(10))}\t=> {r}", flush=True)
"#;

fn val(v: &Value) -> String {
    match v {
        Value::Bool(b) => format!("b:{}", if *b { "True" } else { "False" }),
        Value::Int(i) => format!("i:{i}"),
        Value::Float(f) => format!("f:{:016x}", f.to_bits()),
        Value::Str(s) => format!("s:{s}"),
        other => format!("?:{}", other.type_name()),
    }
}

/// The Python dict fsfast's bindings build: `{"name", "size", "type",
/// **extra}` with the reference key order.
fn info(i: &FileInfo) -> String {
    let mut keys: Vec<(String, String)> = vec![
        ("name".into(), format!("s:{}", i.name)),
        ("size".into(), format!("i:{}", i.size)),
        ("type".into(), format!("s:{}", i.file_type.as_fsspec_str())),
    ];
    for k in fsfast_smb::INFO_KEYS {
        if let Some(v) = i.extra.get(*k) {
            keys.push(((*k).to_owned(), val(v)));
        }
    }
    if let Some(n) = i.extra.get("name") {
        keys[0].1 = val(n);
    }
    let body: Vec<String> = keys.into_iter().map(|(k, v)| format!("{k}={v}")).collect();
    format!("{{{}}}", body.join(";"))
}

fn kind(k: ErrorKind) -> &'static str {
    match k {
        ErrorKind::NotFound => "NotFound",
        ErrorKind::AlreadyExists => "AlreadyExists",
        ErrorKind::IsADirectory => "IsADirectory",
        ErrorKind::NotADirectory => "NotADirectory",
        ErrorKind::PermissionDenied => "PermissionDenied",
        ErrorKind::Unsupported => "Unsupported",
        ErrorKind::InvalidInput => "InvalidInput",
        ErrorKind::DirectoryNotEmpty => "DirectoryNotEmpty",
        _ => "Io",
    }
}

/// A timestamp as Python's `datetime.fromtimestamp(st_time)` sees it:
/// microseconds, rounded half-even from the float seconds smbclient reports.
fn ts(t: Option<std::time::SystemTime>) -> String {
    let d = t.unwrap().duration_since(std::time::UNIX_EPOCH).unwrap();
    let secs = d.as_secs() as f64 + f64::from(d.subsec_nanos()) / 1e9;
    let int = secs.trunc();
    let us = ((secs - int) * 1e6).round_ties_even();
    format!("us:{}", int as i64 * 1_000_000 + us as i64)
}

/// Directory access times change when the other implementation lists the
/// directory (or when Samba scans it for a case-insensitive lookup of a
/// missing name), so they are not compared.
fn mask_dir_atime(out: &str) -> String {
    out.lines()
        .map(|l| {
            let mut s = l.to_owned();
            let mut from = 0;
            while let Some(i) = s[from..].find("type=s:directory;uid=i:0;gid=i:0;time=f:") {
                let start = from + i + "type=s:directory;uid=i:0;gid=i:0;time=f:".len();
                s.replace_range(start..start + 16, "****************");
                from = start;
            }
            s
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_opt(s: &str) -> Option<i64> {
    (!s.is_empty()).then(|| s.parse().unwrap())
}

async fn run_fsfast(fs: &SmbFileSystem, script: &str) -> String {
    let mut out = String::new();
    for line in script.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let (op, a) = (f[0], &f[1..]);
        let r: fsfast_core::Result<String> = async {
            Ok(match op {
                "info" => info(&fs.info(a[0]).await?),
                "ls" => {
                    let mut v: Vec<String> = fs.ls(a[0]).await?.iter().map(info).collect();
                    v.sort();
                    if v.is_empty() {
                        "-".into()
                    } else {
                        v.join(" ")
                    }
                }
                "lsn" => {
                    let mut v: Vec<String> =
                        fs.ls(a[0]).await?.into_iter().map(|i| i.name).collect();
                    v.sort();
                    if v.is_empty() {
                        "-".into()
                    } else {
                        v.join(" ")
                    }
                }
                "find" => {
                    let maxdepth = a[2].parse::<usize>().unwrap();
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
                        .map(|i| i.name)
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
                "created" => ts(fs.info(a[0]).await?.created),
                "modified" => ts(fs.info(a[0]).await?.modified),
                "cat" => {
                    let (s, e) = (parse_opt(a[1]), parse_opt(a[2]));
                    let size = if ByteRange::fsspec_needs_size(s, e) {
                        Some(fs.info(a[0]).await?.size)
                    } else {
                        None
                    };
                    let b = fs
                        .cat_file(a[0], ByteRange::from_fsspec(s, e, size)?)
                        .await?;
                    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
                    if h.is_empty() { "-".into() } else { h }
                }
                "pipe" | "pipex" | "append" => {
                    let data: Vec<u8> = (0..a[1].len() / 2)
                        .map(|i| u8::from_str_radix(&a[1][2 * i..2 * i + 2], 16).unwrap())
                        .collect();
                    let mode = match op {
                        "pipe" => WriteMode::Overwrite,
                        "pipex" => WriteMode::CreateNew,
                        _ => WriteMode::Append,
                    };
                    fs.pipe_file(
                        a[0],
                        Bytes::from(data),
                        &WriteOptions::default().with_mode(mode),
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
                "rm_file" => {
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
                "cp" => {
                    fs.cp_file(a[0], a[1]).await?;
                    "ok".into()
                }
                "touch" => {
                    fs.touch(a[0], true).await?;
                    "ok".into()
                }
                "size" => fs.info(a[0]).await?.size.to_string(),
                _ => format!("bad op {op}"),
            })
        }
        .await;
        let r = match r {
            Ok(r) => r,
            Err(e) => format!("E:{}", kind(e.kind())),
        };
        writeln!(out, "{line}\t=> {r}").unwrap();
    }
    out
}

fn run_fsspec(py: &str, env: &common::Env, script: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("script.tsv");
    std::fs::write(&path, script).unwrap();
    let out = Command::new(py)
        .args([
            "-c",
            SCRIPT,
            &env.host,
            &env.port.to_string(),
            &env.user,
            &env.password,
            path.to_str().unwrap(),
        ])
        .output()
        .expect("run fsspec");
    assert!(
        out.status.success(),
        "fsspec script failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn compare(what: &str, ours: &str, theirs: &str) {
    let (a, b): (Vec<&str>, Vec<&str>) = (ours.lines().collect(), theirs.lines().collect());
    assert_eq!(a.len(), b.len(), "{what}: different number of results");
    let mut bad = Vec::new();
    for (x, y) in a.iter().zip(&b) {
        if x != y {
            bad.push(format!("  fsfast: {x}\n  fsspec: {y}"));
        }
    }
    assert!(
        bad.is_empty(),
        "{what}: {} mismatches:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

fn python() -> Option<String> {
    match std::env::var("FSFAST_TEST_FSSPEC_PYTHON") {
        Ok(p) if !p.is_empty() => Some(p),
        _ => {
            eprintln!("skipping fsspec differential test: FSFAST_TEST_FSSPEC_PYTHON is not set");
            None
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_tree_same_answers() {
    let Some(env) = common::env() else { return };
    let Some(py) = python() else { return };
    for share in [env.share.clone(), env.enc_share.clone()] {
        let fs = env.fs(&[]);
        let root = format!("/{share}/{}", common::unique("diff"));
        let opts = WriteOptions::default();
        fs.mkdir(&format!("{root}/d1/d2"), true).await.unwrap();
        for (p, n) in [
            ("f1", 5usize),
            ("empty", 0),
            ("d1/f2", 1000),
            ("sp ace.txt", 3),
            ("ünï-名.bin", 7),
            ("d1/d2/deep", 70_000),
        ] {
            fs.pipe_file(&format!("{root}/{p}"), common::pattern(n, n as u8), &opts)
                .await
                .unwrap();
        }
        // 1a: metadata only (opens for attributes do not touch access times).
        let mut meta = String::new();
        let paths = [
            root.clone(),
            format!("{root}/f1"),
            format!("{root}/empty"),
            format!("{root}/d1"),
            format!("{root}/d1/d2"),
            format!("{root}/d1/d2/deep"),
            format!("{root}/sp ace.txt"),
            format!("{root}/ünï-名.bin"),
            format!("{root}/missing"),
            format!("{root}/missing/deeper"),
            format!("{root}/f1/below-a-file"),
            "/no-such-share-fsfast/x".to_owned(),
        ];
        for p in &paths {
            for op in ["info", "exists", "isdir"] {
                writeln!(meta, "{op}\t{p}").unwrap();
            }
        }
        // The share root changes under concurrent tests, and fsspec names
        // `dir/` as `dir//`: only existence and type are compared there.
        for p in [
            format!("{root}/"),
            format!("/{share}"),
            format!("/{share}/"),
        ] {
            writeln!(meta, "exists\t{p}").unwrap();
            writeln!(meta, "isdir\t{p}").unwrap();
        }
        for p in ["f1", "d1/d2/deep", "d1"] {
            writeln!(meta, "created\t{root}/{p}").unwrap();
            writeln!(meta, "modified\t{root}/{p}").unwrap();
        }
        let theirs = mask_dir_atime(&run_fsspec(&py, &env, &meta));
        let ours = mask_dir_atime(&run_fsfast(&fs, &meta).await);
        compare(&format!("phase 1a on {share}"), &ours, &theirs);
        // 1b: listings and data.
        let mut script = String::new();
        for p in [
            &root,
            &format!("{root}/d1"),
            &format!("{root}/d1/d2"),
            &format!("{root}/missing"),
        ] {
            writeln!(script, "ls\t{p}").unwrap();
            writeln!(script, "lsn\t{p}").unwrap();
        }
        for (w, d) in [("0", "0"), ("1", "0"), ("0", "1"), ("1", "2")] {
            writeln!(script, "find\t{root}\t{w}\t{d}").unwrap();
        }
        writeln!(script, "find\t{root}/missing\t0\t0").unwrap();
        writeln!(script, "find\t{root}/f1\t1\t0").unwrap();
        let theirs = mask_dir_atime(&run_fsspec(&py, &env, &script));
        let ours = mask_dir_atime(&run_fsfast(&fs, &script).await);
        compare(&format!("phase 1b on {share}"), &ours, &theirs);
        // 1c: data (reads change access times, so after the listings).
        // Negative offsets are not compared: fsspec's generic cat_file seeks
        // with `f.size`, which smbclient's file objects lack
        // (AttributeError); start > end makes it call read(-n) (ValueError),
        // where fsfast returns b"" (core ByteRange semantics).
        let mut script = String::new();
        for (s, e) in [("", ""), ("1", "3"), ("2", ""), ("10", "20"), ("0", "0")] {
            writeln!(script, "cat\t{root}/f1\t{s}\t{e}").unwrap();
        }
        writeln!(script, "cat\t{root}/d1/d2/deep\t65530\t65540").unwrap();
        writeln!(script, "cat\t{root}/d1/d2/deep\t\t").unwrap();
        writeln!(script, "cat\t{root}/d1\t\t").unwrap();
        writeln!(script, "cat\t{root}/missing\t\t").unwrap();
        let theirs = run_fsspec(&py, &env, &script);
        let ours = run_fsfast(&fs, &script).await;
        compare(&format!("phase 1c on {share}"), &ours, &theirs);
        common::cleanup(&fs, &root).await;
        fs.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_operations_same_outcomes() {
    let Some(env) = common::env() else { return };
    let Some(py) = python() else { return };
    let fs = env.fs(&[]);
    let share = env.share.clone();
    let base_ours = format!("/{share}/{}", common::unique("diff-ours"));
    let base_theirs = format!("/{share}/{}", common::unique("diff-theirs"));
    // `R` stands for the per-implementation root.
    let template = "\
mkdir\tR\t0
mkdir\tR\t0
mkdir\tR\t1
mkdir\tR/a/b/c\t0
mkdir\tR/a/b/c\t1
mkdir\tR/a/b/c\t1
makedirs\tR/a/b/c\t1
makedirs\tR/a/b/c\t0
makedirs\tR/x/y\t0
pipe\tR/f\t68656c6c6f
pipe\tR/f\t776f726c64
cat\tR/f\t\t
pipex\tR/f\t00
pipex\tR/g\t0102
cat\tR/g\t\t
append\tR/g\t0304
append\tR/new\t05
cat\tR/g\t\t
cat\tR/new\t\t
size\tR/g
makedirs\tR/f\t1
makedirs\tR/f\t0
mkdir\tR/f\t0
mkdir\tR/f/sub\t1
pipe\tR/nodir/f\t00
pipe\tR/a\t00
cat\tR/a\t\t
mv\tR/g\tR/h
exists\tR/g
cat\tR/h\t\t
mv\tR/missing\tR/z
mv\tR/h\tR/nodir/h
mv\tR/x\tR/x2
lsn\tR/x2
cp\tR/h\tR/h2
cp\tR/h\tR/f
cat\tR/f\t\t
cp\tR/missing\tR/m2
exists\tR/m2
touch\tR/h2
size\tR/h2
rm_file\tR/missing
rm_file\tR/h2
rm_file\tR/a
rmdir\tR/a/b
rmdir\tR/f
rmdir\tR/missing
rmdir\tR/x2/y
rm_file\tR/x2
lsn\tR
find\tR\t1\t0
";
    let ours_script = template.replace("R", &base_ours);
    let theirs_script = template.replace("R", &base_theirs);
    let theirs = run_fsspec(&py, &env, &theirs_script).replace(&base_theirs, "R");
    let ours = run_fsfast(&fs, &ours_script).await.replace(&base_ours, "R");
    common::cleanup(&fs, &base_ours).await;
    common::cleanup(&fs, &base_theirs).await;
    compare("phase 2", &ours, &theirs);
    fs.close().await.unwrap();
}
