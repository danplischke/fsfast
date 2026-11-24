//! Differential test against fsspec's own `LocalFileSystem`.
//!
//! * Phase 1 (exact values): fsspec and fsfast inspect the *same* directory
//!   tree (files, directories, symlinks to files and directories, a broken
//!   symlink) and must produce identical `info()`/`ls()`/`find()` dicts,
//!   including every extra key and its exact value (floats compared bit for
//!   bit), plus identical `exists`, `cat_file` results and error kinds.
//! * Phase 2 (behaviour): seeded random sequences of mutating operations run
//!   on two identical trees, one through fsspec and one through fsfast; the
//!   results (return values, entry names/types/sizes, extra key types, error
//!   kinds) must agree line by line.
//!
//! Gated on `FSFAST_TEST_FSSPEC_PYTHON`, the path of a Python interpreter with
//! fsspec installed (e.g. `.venv/bin/python`). `FSFAST_TEST_DIFF_SEEDS` sets
//! the number of random sequences (default 8).
//!
//! Known, deliberate differences are excluded from the comparison and
//! documented on the methods: `mv_file` takes the final destination (fsspec's
//! `shutil.move` moves *into* an existing directory), and `CreateNew` is an
//! atomic `O_EXCL` create (fsspec's `pipe_file(mode="create")` is
//! `exists()` + `"wb"`, so the harness uses fsspec's `open(path, "xb")`).

use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

use bytes::Bytes;
use fsfast_core::{
    ByteRange, ErrorKind, FileInfo, FileSystem, FindOptions, ReadOptions, Value, WriteMode,
    WriteOptions,
};
use fsfast_local::LocalFileSystem;
use fsfast_testkit::pattern::XorShift;

const SCRIPT: &str = r#"
import errno, os, struct, sys
from fsspec.implementations.local import LocalFileSystem

fs = LocalFileSystem(skip_instance_cache=True)
root, exact = sys.argv[1], sys.argv[3] == "exact"

def err(e):
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
    if isinstance(v, str): return "s:" + v.replace(root, "<root>")
    return "?:" + type(v).__name__

def info(i):
    out = []
    for k in sorted(i):
        v = i[k]
        if exact or k in ("name", "type") or (k == "size" and i["type"] == "file"):
            out.append(f"{k}={val(v)}")
        else:
            out.append(f"{k}:{type(v).__name__}")
    return ";".join(out)

def listing(entries):
    return " ".join(sorted(info(e) for e in entries)) or "-"

for line in open(sys.argv[2], encoding="utf-8"):
    f = line.rstrip("\n").replace("<root>", root).split("\t")
    op, a = f[0], f[1:]
    try:
        if op == "pipe":
            fs.pipe_file(a[0], b"x" * int(a[1])); r = "ok"
        elif op == "pipex":
            # fsspec's pipe_file(mode="create") is a non-atomic exists() check
            # plus "wb" (it writes through a dangling symlink); fsfast's
            # CreateNew is atomic O_EXCL, which is fsspec's open(path, "xb").
            with fs.open(a[0], "xb") as fh:
                fh.write(b"y")
            r = "ok"
        elif op == "cat":
            r = "ok " + fs.cat_file(a[0], int(a[1]), int(a[2])).hex()
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
            # shutil.move moves *into* an existing directory (and refuses to
            # move a directory into itself with shutil.Error); fsfast's
            # mv_file takes the final destination. Skip those cases (the
            # Rust side applies the same rule).
            # (shutil.move only renames in place when src and dst are the
            # same non-symlink; a symlink to a directory moved onto itself
            # is moved *into* that directory.)
            # Moving a directory into itself is excluded on resolved paths:
            # shutil.move misses aliases through symlinks and then copies
            # the tree into itself and deletes it (rename(2) refuses).
            same = src == dst and not os.path.islink(src)
            # (rename does not follow the destination's last component.)
            rdst = os.path.join(os.path.realpath(os.path.dirname(dst)), os.path.basename(dst))
            rsrc = os.path.realpath(src) + "/"
            inside = rdst.startswith(rsrc) or os.path.realpath(dst).startswith(rsrc)
            if (fs.isdir(dst) and not same) or dst.startswith(src + "/") or inside:
                r = "skip"
            else:
                fs.mv(src, dst); r = "ok"
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
    print("\t".join([op] + a).replace(root, "<root>") + " => " + r)
"#;

fn kind_name(k: ErrorKind) -> String {
    match k {
        ErrorKind::NotFound => "NotFound".into(),
        ErrorKind::AlreadyExists => "AlreadyExists".into(),
        ErrorKind::IsADirectory => "IsADirectory".into(),
        ErrorKind::NotADirectory => "NotADirectory".into(),
        ErrorKind::PermissionDenied => "PermissionDenied".into(),
        ErrorKind::Unsupported => "Unsupported".into(),
        ErrorKind::InvalidInput => "InvalidInput".into(),
        ErrorKind::DirectoryNotEmpty => "DirectoryNotEmpty".into(),
        ErrorKind::Io => "Io".into(),
        other => format!("Other:{other:?}"),
    }
}

struct Fmt<'a> {
    root: &'a str,
    exact: bool,
}

impl Fmt<'_> {
    fn val(&self, v: &Value) -> String {
        match v {
            Value::Bool(b) => format!("b:{}", if *b { "True" } else { "False" }),
            Value::Int(i) => format!("i:{i}"),
            Value::Float(f) => format!("f:{:016x}", f.to_bits()),
            Value::Str(s) => format!("s:{}", s.replace(self.root, "<root>")),
            other => format!("?:{other:?}"),
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

    fn info(&self, i: &FileInfo) -> String {
        let mut d = i.extra.clone();
        d.insert("name".into(), Value::Str(i.name.clone()));
        d.insert("size".into(), Value::from(i.size));
        d.insert(
            "type".into(),
            Value::Str(i.file_type.as_fsspec_str().into()),
        );
        d.iter()
            .map(|(k, v)| {
                if self.exact || k == "name" || k == "type" || (k == "size" && i.is_file()) {
                    format!("{k}={}", self.val(v))
                } else {
                    format!("{k}:{}", Self::py_type(v))
                }
            })
            .collect::<Vec<_>>()
            .join(";")
    }

    fn listing(&self, entries: &[FileInfo]) -> String {
        let mut v: Vec<String> = entries.iter().map(|e| self.info(e)).collect();
        v.sort();
        if v.is_empty() {
            "-".into()
        } else {
            v.join(" ")
        }
    }
}

async fn run_rust(fs: &LocalFileSystem, root: &str, exact: bool, line: &str) -> String {
    let resolved = line.replace("<root>", root);
    let op: Vec<&str> = resolved.split('\t').collect();
    let a = &op[1..];
    let f = Fmt { root, exact };
    let res: fsfast_core::Result<String> = async {
        Ok(match op[0] {
            "pipe" => {
                let n: usize = a[1].parse().unwrap();
                fs.pipe_file(a[0], Bytes::from(vec![b'x'; n]), &WriteOptions::default())
                    .await?;
                "ok".into()
            }
            "pipex" => {
                let o = WriteOptions::default().with_mode(WriteMode::CreateNew);
                fs.pipe_file(a[0], Bytes::from_static(b"y"), &o).await?;
                "ok".into()
            }
            "cat" => {
                // The Python layer looks the size up when the range needs it.
                let (start, end) = (Some(a[1].parse().unwrap()), Some(a[2].parse().unwrap()));
                let size = if ByteRange::fsspec_needs_size(start, end) {
                    Some(fs.info(a[0]).await?.size)
                } else {
                    None
                };
                let r = ByteRange::from_fsspec(start, end, size)?;
                let b = fs.cat_file(a[0], r).await?;
                let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
                format!("ok {hex}")
            }
            "info" => format!("ok {}", f.info(&fs.info(a[0]).await?)),
            "ls" => format!("ok {}", f.listing(&fs.ls(a[0]).await?)),
            "find" => {
                let opts = FindOptions {
                    maxdepth: if a[1] == "-" {
                        None
                    } else {
                        Some(a[1].parse().unwrap())
                    },
                    withdirs: a[2] == "1",
                };
                format!("ok {}", f.listing(&fs.find(a[0], &opts).await?))
            }
            "exists" => format!(
                "ok {}",
                if fs.exists(a[0]).await? {
                    "True"
                } else {
                    "False"
                }
            ),
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
                let src = fsfast_local::strip_protocol(a[0]).into_owned();
                let dst = fsfast_local::strip_protocol(a[1]).into_owned();
                let same = src == dst && !Path::new(&src).is_symlink();
                let rsrc = format!("{}/", realpath(&src));
                let inside =
                    realpath_parent(&dst).starts_with(&rsrc) || realpath(&dst).starts_with(&rsrc);
                if (Path::new(&dst).is_dir() && !same)
                    || dst.starts_with(&format!("{src}/"))
                    || inside
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
    format!("{} => {r}", line)
}

/// `os.path.realpath(p)` (non-strict): resolve symlinks component by
/// component, following dangling ones too, without requiring existence.
fn realpath(p: &str) -> String {
    fn resolve(p: &Path, depth: usize) -> std::path::PathBuf {
        use std::path::Component;
        let mut out = std::path::PathBuf::new();
        for c in p.components() {
            match c {
                Component::RootDir => out.push("/"),
                Component::ParentDir => {
                    out.pop();
                }
                Component::Normal(n) => {
                    out.push(n);
                    if depth < 40
                        && let Ok(target) = std::fs::read_link(&out)
                    {
                        let base = out.parent().map(Path::to_path_buf).unwrap_or_default();
                        out = resolve(&base.join(target), depth + 1);
                    }
                }
                Component::CurDir | Component::Prefix(_) => {}
            }
        }
        out
    }
    resolve(Path::new(p), 0).to_string_lossy().into_owned()
}

/// `realpath(dirname(p)) + "/" + basename(p)`: the path `rename(2)` acts on
/// (the last component is not followed).
fn realpath_parent(p: &str) -> String {
    let path = Path::new(p);
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => {
            format!(
                "{}/{}",
                realpath(parent.to_str().unwrap()),
                name.to_str().unwrap()
            )
        }
        _ => p.to_owned(),
    }
}

/// Build the fixture tree under `root`.
fn build_tree(root: &Path) {
    use std::fs;
    fs::create_dir_all(root.join("a/b/c")).unwrap();
    fs::create_dir_all(root.join("empty")).unwrap();
    fs::write(root.join("f"), b"0123456789").unwrap();
    fs::write(root.join("a/f2"), b"").unwrap();
    fs::write(root.join("a/b/c/deep"), vec![7u8; 4097]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(root.join("f"), root.join("link")).unwrap();
        symlink("a/b", root.join("dlink")).unwrap();
        symlink(root.join("gone"), root.join("broken")).unwrap();
    }
}

const NAMES: &[&str] = &[
    "",
    "/a",
    "/a/b",
    "/a/b/c",
    "/a/b/c/deep",
    "/f",
    "/a/f2",
    "/empty",
    "/link",
    "/dlink",
    "/broken",
    "/nope",
    "/f/child",
    "/a/new",
    "/dlink/c",
    "/a/b/",
    // Characters that are special in URLs or shells, and non-ASCII.
    "/sp ace#q?%20x",
    "/a/ünï-名前",
];

/// [`NAMES`] plus a name of the maximum component length (255 bytes) and an
/// over-long one (`ENAMETOOLONG`: fsspec raises a plain `OSError`).
fn names() -> Vec<String> {
    let mut v: Vec<String> = NAMES.iter().map(|n| (*n).to_owned()).collect();
    v.push(format!("/a/{}", "L".repeat(255)));
    v.push(format!("/{}", "T".repeat(300)));
    v
}

fn read_only_ops() -> Vec<String> {
    let mut ops = Vec::new();
    for n in names() {
        let p = format!("<root>{n}");
        ops.push(format!("info\t{p}"));
        ops.push(format!("ls\t{p}"));
        ops.push(format!("exists\t{p}"));
        ops.push(format!("open\t{p}\trb"));
        ops.push(format!("cat\t{p}\t2\t7"));
        for md in ["-", "1", "2"] {
            for wd in ["0", "1"] {
                ops.push(format!("find\t{p}\t{md}\t{wd}"));
            }
        }
    }
    ops.push("cat\t<root>/f\t0\t100".into());
    ops.push("cat\t<root>/f\t-3\t10".into());
    ops.push("cat\t<root>/f\t20\t30".into());
    ops.push("info\tfile://<root>/f".into());
    ops.push("info\tlocal:<root>/a/".into());
    ops
}

fn random_ops(seed: u64, n: usize) -> Vec<String> {
    let mut rng = XorShift::new(seed);
    let names = names();
    let pick = |rng: &mut XorShift| {
        format!(
            "<root>{}",
            names[rng.range(0, names.len() as u64 - 1) as usize]
        )
    };
    let mut ops = Vec::with_capacity(n);
    for _ in 0..n {
        let p = pick(&mut rng);
        let q = pick(&mut rng);
        let b = rng.range(0, 1);
        let line = match rng.range(0, 19) {
            0 | 1 => format!("pipe\t{p}\t{}", rng.range(0, 5)),
            2 => format!("pipex\t{p}"),
            3 => format!("cat\t{p}\t{}\t{}", rng.range(0, 3), rng.range(3, 8)),
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

fn run_python(python: &str, root: &Path, ops: &[String], exact: bool) -> Vec<String> {
    let scratch = tempfile::tempdir().unwrap();
    let script = scratch.path().join("diff.py");
    let ops_file = scratch.path().join("ops.tsv");
    std::fs::write(&script, SCRIPT).unwrap();
    std::fs::write(&ops_file, ops.join("\n") + "\n").unwrap();
    let out = Command::new(python)
        .arg("-I")
        .arg(&script)
        .arg(root.to_str().unwrap())
        .arg(&ops_file)
        .arg(if exact { "exact" } else { "types" })
        .output()
        .expect("run python");
    assert!(
        out.status.success(),
        "python failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<String> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(lines.len(), ops.len(), "python output length");
    lines
}

fn report(name: &str, ops: &[String], expected: &[String], got: &[String]) {
    let mut msg = String::new();
    // The operations leading up to the first difference (state drifts show
    // up later than the operation that caused them).
    if let Some(first) = expected.iter().zip(got).position(|(a, b)| a != b) {
        let _ = writeln!(msg, "  context before the first difference (#{first}):");
        for line in &got[first.saturating_sub(12)..first] {
            let _ = writeln!(msg, "    {line}");
        }
    }
    let mut count = 0;
    for ((op, want), have) in ops.iter().zip(expected).zip(got) {
        if want != have {
            count += 1;
            if count <= 10 {
                let _ = writeln!(msg, "  op:     {op:?}\n  fsspec: {want}\n  fsfast: {have}");
            }
        }
    }
    assert!(
        count == 0,
        "{name}: {count} of {} results differ from fsspec:\n{msg}",
        ops.len()
    );
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

fn canonical(dir: &tempfile::TempDir) -> String {
    fsfast_local::strip_protocol(dir.path().to_str().unwrap()).into_owned()
}

#[tokio::test]
async fn read_only_results_are_identical_to_fsspec() {
    let Some(py) = python() else { return };
    let dir = tempfile::tempdir().unwrap();
    build_tree(dir.path());
    let root = canonical(&dir);
    let ops = read_only_ops();
    let expected = run_python(&py, Path::new(&root), &ops, true);
    let fs = LocalFileSystem::new();
    let mut got = Vec::new();
    for op in &ops {
        got.push(run_rust(&fs, &root, true, op).await);
    }
    report("read-only", &ops, &expected, &got);
}

#[tokio::test]
async fn random_mutations_behave_like_fsspec() {
    let Some(py) = python() else { return };
    // FSFAST_TEST_DIFF_SEEDS widens the sweep (default 8 sequences).
    let seeds: u64 = std::env::var("FSFAST_TEST_DIFF_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8);
    for seed in 1..=seeds {
        let (dpy, drs) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        build_tree(dpy.path());
        build_tree(drs.path());
        let ops = random_ops(seed * 104_729, 300);
        let expected = run_python(&py, Path::new(&canonical(&dpy)), &ops, false);
        let fs = LocalFileSystem::new();
        let root = canonical(&drs);
        let mut got = Vec::new();
        for op in &ops {
            got.push(run_rust(&fs, &root, false, op).await);
        }
        report(&format!("seed {seed}"), &ops, &expected, &got);
    }
}
