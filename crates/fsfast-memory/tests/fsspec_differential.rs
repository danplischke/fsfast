//! Differential test against fsspec's own `MemoryFileSystem`.
//!
//! Runs the same operation sequences (fixed edge cases plus seeded random
//! ones) through fsspec in a Python subprocess and through
//! `fsfast_memory::MemoryFileSystem`, and compares the normalised results
//! line by line: return values, `info()`/`ls()`/`find()` entries including the
//! extra keys and their Python types, and error kinds.
//!
//! Gated on `FSFAST_TEST_FSSPEC_PYTHON`, the path of a Python interpreter with
//! fsspec installed (e.g. `.venv/bin/python`).

use std::fmt::Write as _;
use std::process::Command;

use bytes::Bytes;
use fsfast_core::{
    ByteRange, ErrorKind, FileInfo, FileSystem, FindOptions, ReadOptions, Value, WriteMode,
    WriteOptions,
};
use fsfast_memory::MemoryFileSystem;
use fsfast_testkit::pattern::XorShift;

const SCRIPT: &str = r#"
import sys
from fsspec.implementations.memory import MemoryFileSystem

fs = MemoryFileSystem(global_store=False, skip_instance_cache=True)

def err(e):
    if isinstance(e, FileNotFoundError): return "NotFound"
    if isinstance(e, FileExistsError): return "AlreadyExists"
    if isinstance(e, IsADirectoryError): return "IsADirectory"
    if isinstance(e, NotADirectoryError): return "NotADirectory"
    if isinstance(e, NotImplementedError): return "Unsupported"
    if isinstance(e, ValueError): return "InvalidInput"
    if isinstance(e, OSError) and e.errno == 39: return "DirectoryNotEmpty"
    return "Other:" + type(e).__name__

def info(i):
    extra = ",".join(f"{k}:{type(v).__name__}" for k, v in sorted(i.items())
                     if k not in ("name", "size", "type"))
    return f"{i['type']}|{i['name']}|{i['size']}|{extra}"

def listing(entries):
    return " ".join(sorted(info(e) for e in entries)) or "-"

for line in open(sys.argv[1], encoding="utf-8"):
    f = line.rstrip("\n").split("\t")
    op, a = f[0], f[1:]
    try:
        if op == "pipe":
            fs.pipe_file(a[0], b"x" * int(a[1])); r = "ok"
        elif op == "pipex":
            fs.pipe_file(a[0], b"y", mode="create"); r = "ok"
        elif op == "cat":
            r = "ok " + fs.cat_file(a[0], int(a[1]), int(a[2])).decode()
        elif op == "info":
            r = "ok " + info(fs.info(a[0]))
        elif op == "ls":
            r = "ok " + listing(fs.ls(a[0], detail=True))
        elif op == "find":
            md = None if a[1] == "-" else int(a[1])
            r = "ok " + listing(fs.find(a[0], maxdepth=md, withdirs=a[2] == "1", detail=True).values())
        elif op == "exists":
            r = "ok " + str(fs.exists(a[0]))
        elif op == "mkdir":
            fs.mkdir(a[0], create_parents=a[1] == "1"); r = "ok"
        elif op == "makedirs":
            fs.makedirs(a[0], exist_ok=a[1] == "1"); r = "ok"
        elif op == "rmdir":
            fs.rmdir(a[0]); r = "ok"
        elif op == "rm":
            fs.rm_file(a[0]); r = "ok"
        elif op == "cp":
            fs.cp_file(a[0], a[1]); r = "ok"
        elif op == "mv":
            src, dst = fs._strip_protocol(a[0]), fs._strip_protocol(a[1])
            # fsfast's mv_file takes the final destination; fsspec's mv moves
            # *into* an existing directory. Skip the cases where they differ
            # by design (the Rust side applies the same rule).
            if src == "" or dst.startswith(src + "/") or (src != dst and fs.exists(dst)
                    and (fs.isdir(dst) or fs.isdir(src))):
                r = "skip"
            else:
                fs.mv(src, dst, recursive=True); r = "ok"
        elif op == "touch":
            fs.touch(a[0], truncate=a[1] == "1"); r = "ok"
        elif op == "open":
            mode = a[1]
            if mode == "rb":
                with fs.open(a[0], "rb") as fh:
                    r = "ok " + str(len(fh.read()))
            else:
                with fs.open(a[0], mode) as fh:
                    fh.write(b"w")
                r = "ok"
        else:
            r = "bad op"
    except Exception as e:
        r = "err " + err(e)
    print("\t".join([op] + a) + " => " + r)
"#;

fn kind_name(k: ErrorKind) -> String {
    match k {
        ErrorKind::NotFound => "NotFound".into(),
        ErrorKind::AlreadyExists => "AlreadyExists".into(),
        ErrorKind::IsADirectory => "IsADirectory".into(),
        ErrorKind::NotADirectory => "NotADirectory".into(),
        ErrorKind::Unsupported => "Unsupported".into(),
        ErrorKind::InvalidInput => "InvalidInput".into(),
        ErrorKind::DirectoryNotEmpty => "DirectoryNotEmpty".into(),
        other => format!("Other:{other:?}"),
    }
}

fn py_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Int(_) => "int",
        Value::Float(_) => "float",
        Value::Str(_) => "str",
        Value::Bytes(_) => "bytes",
        Value::Time(_) => "datetime",
        Value::List(_) => "list",
        Value::Map(_) => "dict",
    }
}

fn info(i: &FileInfo) -> String {
    let extra: Vec<String> = i
        .extra
        .iter()
        .map(|(k, v)| format!("{k}:{}", py_type(v)))
        .collect();
    format!(
        "{}|{}|{}|{}",
        i.file_type.as_fsspec_str(),
        i.name,
        i.size,
        extra.join(",")
    )
}

fn listing(entries: &[FileInfo]) -> String {
    let mut v: Vec<String> = entries.iter().map(info).collect();
    v.sort();
    if v.is_empty() { "-".into() } else { v.join(" ") }
}

async fn run_rust(fs: &MemoryFileSystem, op: &[&str]) -> String {
    let a = &op[1..];
    let res: fsfast_core::Result<String> = async {
        Ok(match op[0] {
            "pipe" => {
                let n: usize = a[1].parse().unwrap();
                fs.pipe_file(a[0], Bytes::from(vec![b'x'; n]), &WriteOptions::default())
                    .await?;
                "ok".into()
            }
            "pipex" => {
                fs.pipe_file(
                    a[0],
                    Bytes::from_static(b"y"),
                    &WriteOptions::default().with_mode(WriteMode::CreateNew),
                )
                .await?;
                "ok".into()
            }
            "cat" => {
                let r = ByteRange::from_fsspec(Some(a[1].parse().unwrap()), Some(a[2].parse().unwrap()), None)?;
                let b = fs.cat_file(a[0], r).await?;
                format!("ok {}", String::from_utf8_lossy(&b))
            }
            "info" => format!("ok {}", info(&fs.info(a[0]).await?)),
            "ls" => format!("ok {}", listing(&fs.ls(a[0]).await?)),
            "find" => {
                let opts = FindOptions {
                    maxdepth: if a[1] == "-" { None } else { Some(a[1].parse().unwrap()) },
                    withdirs: a[2] == "1",
                };
                format!("ok {}", listing(&fs.find(a[0], &opts).await?))
            }
            "exists" => format!("ok {}", if fs.exists(a[0]).await? { "True" } else { "False" }),
            "mkdir" => {
                fs.mkdir(a[0], a[1] == "1").await?;
                "ok".into()
            }
            "makedirs" => {
                fs.makedirs(a[0], a[1] == "1").await?;
                "ok".into()
            }
            "rmdir" => {
                fs.rmdir(a[0]).await?;
                "ok".into()
            }
            "rm" => {
                fs.rm_file(a[0]).await?;
                "ok".into()
            }
            "cp" => {
                fs.cp_file(a[0], a[1]).await?;
                "ok".into()
            }
            "mv" => {
                let src = fsfast_memory::strip_protocol(a[0]).into_owned();
                let dst = fsfast_memory::strip_protocol(a[1]).into_owned();
                let is_dir = |p: String| async move {
                    fs.info(&p).await.map(|i| i.is_dir()).unwrap_or(false)
                };
                if src.is_empty()
                    || dst.starts_with(&format!("{src}/"))
                    || (src != dst
                        && fs.exists(&dst).await?
                        && (is_dir(dst.clone()).await || is_dir(src.clone()).await))
                {
                    "skip".into()
                } else {
                    fs.mv_file(&src, &dst).await?;
                    "ok".into()
                }
            }
            "touch" => {
                fs.touch(a[0], a[1] == "1").await?;
                "ok".into()
            }
            "open" => match a[1] {
                "rb" => {
                    let h = fs.open_read(a[0], &ReadOptions::default()).await?;
                    let d = h.read_at(0, h.size() as usize).await?;
                    format!("ok {}", d.len())
                }
                m => {
                    let mode = match m {
                        "wb" => WriteMode::Overwrite,
                        "xb" => WriteMode::CreateNew,
                        _ => WriteMode::Append,
                    };
                    let mut w = fs
                        .open_write(a[0], &WriteOptions::default().with_mode(mode))
                        .await?;
                    w.write(Bytes::from_static(b"w")).await?;
                    w.close().await?;
                    "ok".into()
                }
            },
            other => panic!("unknown op {other}"),
        })
    }
    .await;
    let r = res.unwrap_or_else(|e| format!("err {}", kind_name(e.kind())));
    format!("{} => {r}", op.join("\t"))
}

const UNIVERSE: &[&str] = &[
    "", "/a", "/a/b", "/a/b/c", "/a/d", "/a/b-x", "/e", "/e/f", "/g/h/i", "a/b/", "/a//b", "memory://e/f",
];

fn random_ops(seed: u64, n: usize) -> Vec<String> {
    let mut rng = XorShift::new(seed);
    let pick = |rng: &mut XorShift| UNIVERSE[rng.range(0, UNIVERSE.len() as u64 - 1) as usize];
    let mut ops = Vec::with_capacity(n);
    for _ in 0..n {
        let p = pick(&mut rng);
        let q = pick(&mut rng);
        let b = rng.range(0, 1);
        let line = match rng.range(0, 18) {
            0 | 1 => format!("pipe\t{p}\t{}", rng.range(0, 5)),
            2 => format!("pipex\t{p}"),
            3 => format!("cat\t{p}\t{}\t{}", rng.range(0, 3), rng.range(0, 6)),
            4 => format!("info\t{p}"),
            5 => format!("ls\t{p}"),
            6 => {
                let md = match rng.range(0, 3) {
                    0 => "-".to_owned(),
                    d => d.to_string(),
                };
                format!("find\t{p}\t{md}\t{b}")
            }
            7 => format!("exists\t{p}"),
            8 | 9 => format!("mkdir\t{p}\t{b}"),
            10 => format!("makedirs\t{p}\t{b}"),
            11 => format!("rmdir\t{p}"),
            12 => format!("rm\t{p}"),
            13 => format!("cp\t{p}\t{q}"),
            14 => format!("mv\t{p}\t{q}"),
            15 => format!("touch\t{p}\t{b}"),
            _ => {
                let mode = ["rb", "wb", "xb", "ab"][rng.range(0, 3) as usize];
                format!("open\t{p}\t{mode}")
            }
        };
        ops.push(line);
    }
    ops
}

fn edge_cases() -> Vec<String> {
    [
        "pipe\t/a/b/c\t3",
        "info\t/a",
        "info\t/a/b/c",
        "info\t",
        "info\t/",
        "info\t/zz",
        "ls\t/a/b",
        "ls\t/a/b/c",
        "ls\t",
        "ls\t/zz",
        "mkdir\t/q/r\t0",
        "info\t/q",
        "makedirs\t/a\t0",
        "mkdir\t/a\t1",
        "rmdir\t/a",
        "rmdir\t/a/b",
        "rmdir\t/a/b/c",
        "open\t/a/b/c/d\trb",
        "cat\t/a/b/c/d\t0\t1",
        "open\t/a\twb",
        "open\t/q\trb",
        "mkdir\t/pd\t1",
        "open\t/pd\trb",
        "open\t/pd\txb",
        "open\t/pd\tab",
        "mkdir\t/i/j/k\t1",
        "pipe\t/i/j/f\t1",
        "mkdir\t/i/j/f/g\t1",
        "mkdir\t/i/j/f/g/h\t0",
        "find\t\t-\t1",
        "find\t/a\t1\t1",
        "find\t/a/b/c\t-\t1",
        "find\t/zzz\t-\t1",
        "find\t/a\t0\t0",
        "touch\t/t\t0",
        "touch\t/t\t0",
        "touch\t/t\t1",
        "open\t/ap\tab",
        "open\t/ap\tab",
        "cat\t/ap\t0\t5",
        "pipex\t/ap",
        "cp\t/pd\t/pd2",
        "cp\t/nope\t/x",
        "mv\t/ap\t/ap2",
        "mv\t/i\t/moved",
        "find\t/moved\t-\t1",
        "rmdir\t",
        "rm\t/nope",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

async fn compare(python: &str, name: &str, ops: &[String]) {
    let dir = std::env::temp_dir().join(format!("fsfast-memory-diff-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("diff.py");
    let ops_file = dir.join("ops.tsv");
    std::fs::write(&script, SCRIPT).unwrap();
    std::fs::write(&ops_file, ops.join("\n") + "\n").unwrap();
    let out = Command::new(python)
        .arg("-I")
        .arg(&script)
        .arg(&ops_file)
        .output()
        .expect("run python");
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(out.status.success(), "python failed: {}", String::from_utf8_lossy(&out.stderr));
    let expected = String::from_utf8(out.stdout).unwrap();

    let fs = MemoryFileSystem::new_isolated();
    let mut mismatches = String::new();
    let mut count = 0;
    for (line, want) in ops.iter().zip(expected.lines()) {
        let fields: Vec<&str> = line.split('\t').collect();
        let got = run_rust(&fs, &fields).await;
        if got != want {
            count += 1;
            if count <= 10 {
                let _ = writeln!(mismatches, "  op:     {line:?}\n  fsspec: {want}\n  fsfast: {got}");
            }
        }
    }
    assert_eq!(expected.lines().count(), ops.len(), "python output length");
    assert!(count == 0, "{name}: {count} of {} results differ from fsspec:\n{mismatches}", ops.len());
}

fn python() -> Option<String> {
    match std::env::var("FSFAST_TEST_FSSPEC_PYTHON") {
        Ok(p) if !p.is_empty() => Some(p),
        _ => {
            eprintln!("skipping: set FSFAST_TEST_FSSPEC_PYTHON to a python with fsspec installed");
            None
        }
    }
}

#[tokio::test]
async fn edge_cases_match_fsspec() {
    let Some(py) = python() else { return };
    compare(&py, "edge", &edge_cases()).await;
}

#[tokio::test]
async fn random_sequences_match_fsspec() {
    let Some(py) = python() else { return };
    for seed in 1..=6u64 {
        compare(&py, &format!("seed{seed}"), &random_ops(seed * 7919, 400)).await;
    }
}
