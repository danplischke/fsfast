//! Differential test against fsspec's own `HTTPFileSystem`.
//!
//! The in-process test server serves randomly generated index pages (link
//! forms, quoting, case, odd whitespace, broken tags, bare URLs, relative and
//! absolute links inside and outside the page, invalid UTF-8, latin-1 pages,
//! missing or unusual `Content-Type`s, pages whose trailing-slash variant
//! differs) plus the fixed endpoints of the other tests. The same `ls`,
//! `info`, `exists` and `cat_file` calls go through fsspec in a Python
//! subprocess and through fsfast, and the results must be identical.
//!
//! Gated on `FSFAST_TEST_FSSPEC_PYTHON` (a Python with fsspec and aiohttp,
//! e.g. `.venv/bin/python`). `FSFAST_TEST_DIFF_SEEDS` sets the number of
//! random pages (default 300).
//!
//! Not compared, by design (documented deviations): `info` of URLs failing
//! with 5xx (fsspec: `FileNotFoundError`, fsfast: the server error), and
//! `cat_file` ranges on servers that ignore `Range` (fsspec returns the whole
//! body, fsfast the requested bytes). Accepted differences are listed in
//! [`documented_deviation`].

mod common;

use std::fmt::Write as _;
use std::process::Command;

use fsfast_core::{ByteRange, ErrorKind, FileInfo, FileSystem, Value};
use fsfast_http::{HttpFileSystem, known_size};
use fsfast_testkit::pattern::XorShift;

const SCRIPT: &str = r#"
import sys, hashlib
import fsspec
fs = fsspec.filesystem("http", skip_instance_cache=True)
def hx(s): return s.encode("utf-8", "surrogatepass").hex()
def err(e):
    if isinstance(e, FileNotFoundError): return "NotFound"
    if isinstance(e, PermissionError): return "PermissionDenied"
    return "Other:" + type(e).__name__
def val(v):
    if v is None: return "None"
    if isinstance(v, bool): return "b:" + str(v)
    if isinstance(v, int): return "i:" + str(v)
    return "s:" + hx(str(v))
out = open(sys.argv[2], "w", encoding="utf-8")
for line in open(sys.argv[1], encoding="utf-8"):
    f = line.rstrip("\n").split("\t")
    op, url = f[0], bytes.fromhex(f[1]).decode("utf-8")
    try:
        if op == "ls":
            entries = fs.ls(url, detail=True)
            r = " ".join(sorted(("D" if e["type"] == "directory" else "F") + hx(e["name"])
                                + ("" if e["size"] is None else "!size") for e in entries))
            res = "ok " + r
        elif op == "info":
            i = fs.info(url)
            res = "ok " + " ".join(k + "=" + val(i[k]) for k in sorted(i))
        elif op == "exists":
            res = "ok " + str(fs.exists(url))
        elif op == "cat":
            start = None if f[2] == "-" else int(f[2])
            end = None if f[3] == "-" else int(f[3])
            data = fs.cat_file(url, start=start, end=end)
            res = "ok %d %s" % (len(data), hashlib.sha256(data).hexdigest())
        else:
            res = "bad op"
    except Exception as e:
        res = "err " + err(e)
    out.write(res + "\n")
out.close()
"#;

fn hx(s: &str) -> String {
    s.bytes().fold(String::new(), |mut o, b| {
        let _ = write!(o, "{b:02x}");
        o
    })
}

fn val(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(b) => format!("b:{}", if *b { "True" } else { "False" }),
        Value::Int(i) => format!("i:{i}"),
        Value::Str(s) => format!("s:{}", hx(s)),
        other => format!("?{other:?}"),
    }
}

fn err_name(k: ErrorKind) -> String {
    match k {
        ErrorKind::NotFound => "NotFound".into(),
        ErrorKind::PermissionDenied => "PermissionDenied".into(),
        other => format!("Other:{other:?}"),
    }
}

fn info_line(i: &FileInfo) -> String {
    let mut kv: Vec<(String, String)> = vec![
        ("name".into(), val(&Value::from(i.name.clone()))),
        (
            "type".into(),
            val(&Value::from(i.file_type.as_fsspec_str())),
        ),
        (
            "size".into(),
            known_size(i).map_or("None".into(), |s| format!("i:{s}")),
        ),
    ];
    for (k, v) in &i.extra {
        if k != "size" {
            kv.push((k.clone(), val(v)));
        }
    }
    kv.sort();
    kv.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A random index page.
fn page(rng: &mut XorShift, base: &str, port: u16) -> (Option<String>, Vec<u8>) {
    let pick = |rng: &mut XorShift, n: usize| (rng.next_u64() % n as u64) as usize;
    let targets = [
        "a.txt".to_owned(),
        "sub/".into(),
        "deep/er/x.bin".into(),
        "x y.txt".into(),
        "./".into(),
        "../".into(),
        "..".into(),
        ".".into(),
        "?C=N;O=D".into(),
        "#frag".into(),
        "mailto:x@y.z".into(),
        "httpfoo.html".into(),
        "/".into(),
        "/abs/path".into(),
        format!("{base}abs.txt"),
        format!("{base}dir/"),
        "//proto.relative/x".into(),
        format!("http://127.0.0.1:{port}{base}child"),
        format!("https://127.0.0.1:{port}{base}child2"),
        format!("http://127.0.0.1:{port}/elsewhere"),
        format!("http://localhost:{port}{base}x"),
        "http://other.example/".into(),
        "caf\u{e9}.txt".into(),
        "\u{1F600}.txt".into(),
        "q?a=1&b=2".into(),
        "https".into(),
    ];
    let ws = [" ", "  ", "\t", "\n", "\u{1c}", "\u{a0}", "\r\n"];
    let mut html = String::from("<html><body>");
    let n = pick(rng, 12);
    for _ in 0..n {
        let t = &targets[pick(rng, targets.len())];
        let q = if pick(rng, 2) == 0 { '"' } else { '\'' };
        let a = if pick(rng, 4) == 0 { "A" } else { "a" };
        let href = match pick(rng, 5) {
            0 => "HREF",
            1 => "Href",
            _ => "href",
        };
        let w = ws[pick(rng, ws.len())];
        match pick(rng, 10) {
            0 => {
                let _ = write!(html, "<{a}{w}class=\"c\"{w}{href}={q}{t}{q}>x</{a}>");
            }
            1 => {
                let _ = write!(html, "<{a}{href}={q}{t}{q}>broken</{a}>");
            }
            2 => {
                let _ = write!(html, " text {t} more ");
            }
            3 => {
                let _ = write!(html, "<link{w}href={q}{t}{q}>");
            }
            4 => {
                let _ = write!(html, "<{a}{w}{href}={q}{t}");
            }
            _ => {
                let _ = write!(html, "<{a}{w}{href}={q}{t}{q}>{t}</{a}>{w}");
            }
        }
    }
    html.push_str("</body></html>");
    let mut body = html.into_bytes();
    let ctype = match pick(rng, 9) {
        0 => None,
        1 => Some("text/html; charset=utf-8".to_owned()),
        2 => {
            // A latin-1 page with high bytes inside links.
            body = body
                .iter()
                .flat_map(|&b| if b == b'x' { vec![0xe9] } else { vec![b] })
                .collect();
            Some("text/html; charset=ISO-8859-1".to_owned())
        }
        3 => Some("Text/HTML".to_owned()),
        4 => Some("text/plain".to_owned()),
        5 => {
            // Invalid UTF-8 sprinkled in.
            body.insert(body.len() / 2, 0xff);
            body.insert(body.len() / 3, 0xc3);
            Some("text/html".to_owned())
        }
        6 => Some("text/html;charset=windows-1252".to_owned()),
        _ => Some("text/html".to_owned()),
    };
    (ctype, body)
}

/// Index pages as real servers render them, plus HTML oddities.
fn sample_pages(port: u16) -> Vec<(Option<&'static str>, String)> {
    let apache = r#"<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /pub</title>
 </head>
 <body>
<h1>Index of /pub</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td></tr>
<tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="data/">data/</a></td><td align="right">2024-01-01 10:00  </td><td align="right">  - </td></tr>
<tr><td valign="top"><img src="/icons/compressed.gif" alt="[   ]"></td><td><a href="file%20one.tar.gz">file one.tar.gz</a></td><td align="right">2024-01-01 10:00  </td><td align="right">1.2M</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="README.txt">README.txt</a></td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.58 (Unix) Server at example.org Port 80</address>
</body></html>
"#
    .to_owned();
    let nginx = r#"<html>
<head><title>Index of /files/</title></head>
<body>
<h1>Index of /files/</h1><hr><pre><a href="../">../</a>
<a href="sub%20dir/">sub dir/</a>                                           01-Jan-2024 10:00       -
<a href="caf%C3%A9.csv">caf&#233;.csv</a>                                       01-Jan-2024 10:00    1234
<a href="data.parquet">data.parquet</a>                                       01-Jan-2024 10:00   56789
</pre><hr></body>
</html>
"#
    .to_owned();
    let python = r#"<!DOCTYPE HTML>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Directory listing for /</title>
</head>
<body>
<h1>Directory listing for /</h1>
<hr>
<ul>
<li><a href=".git/">.git/</a></li>
<li><a href="a%26b.txt">a&amp;b.txt</a></li>
<li><a href="link%40/">link@/</a></li>
</ul>
<hr>
</body>
</html>
"#
    .to_owned();
    let odd = format!(
        r##"<html><head><base href="http://elsewhere.example/"></head><body>
<a href=unquoted.txt>unquoted</a>
<a href="q?x=1&amp;y=2">entities stay escaped</a>
<a
   href="multi
line.txt">newline inside</a>
<A HREF='upper.txt'>upper</A> <a hReF="mixed.txt">mixed case attr</a>
<area href="area.txt"> <abbr href="abbr.txt"> <a/href="slash.txt">
<a data-href="data.txt" href="real.txt">two hrefs</a>
<a href="">empty</a> <a href="#">hash</a> <a href="javascript:void(0)">js</a>
<a href="//cdn.example/x.js">protocol relative</a>
<a href="HTTP://127.0.0.1:{port}/samples/3/UPPER-SCHEME">upper scheme</a>
<a href="https://127.0.0.1:{port}/samples/3/sec">https</a>
<a href="/samples/3/abs">absolute</a> <a href="/samples/30/">sibling prefix</a>
plain text http://127.0.0.1:{port}/samples/3/bare.txt?a=1&b=2#frag, done
<!-- <a href="commented.txt">comment</a> -->
<script>var u = "http://127.0.0.1:{port}/samples/3/in-script.js";</script>
</body></html>"##
    );
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult><Contents><Key>a.txt</Key></Contents>
<a href="not-html.txt">x</a></ListBucketResult>"#
        .to_owned();
    vec![
        (Some("text/html;charset=ISO-8859-1"), apache),
        (Some("text/html"), nginx),
        (Some("text/html; charset=utf-8"), python),
        (Some("text/html; charset=utf-8"), odd),
        (Some("application/xml"), xml),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matches_fsspec() {
    let Ok(python) = std::env::var("FSFAST_TEST_FSSPEC_PYTHON") else {
        eprintln!("skipping: FSFAST_TEST_FSSPEC_PYTHON is not set");
        return;
    };
    let seeds: u64 = std::env::var("FSFAST_TEST_DIFF_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let s = common::start().await;
    let port = s.addr.port();

    let mut ops: Vec<(String, String, Option<ByteRange>)> = Vec::new();
    {
        let mut pages = s.state.pages.lock();
        for seed in 0..seeds {
            let mut rng = XorShift::new(seed * 7919 + 1);
            let base = format!("/diff/{seed}/");
            let slash = page(&mut rng, &base, port);
            // The variant without the trailing slash differs (fsspec retries
            // it when the slash page has no links).
            let no_slash = page(&mut rng, &base, port);
            pages.insert(base.clone(), slash);
            pages.insert(base.trim_end_matches('/').to_owned(), no_slash);
            ops.push(("ls".into(), s.url(&base), None));
            if seed % 5 == 0 {
                ops.push(("ls".into(), s.url(base.trim_end_matches('/')), None));
            }
        }
    }
    // Realistic index pages, served verbatim.
    {
        let mut pages = s.state.pages.lock();
        for (i, (ctype, body)) in sample_pages(port).into_iter().enumerate() {
            let path = format!("/samples/{i}/");
            pages.insert(path.clone(), (ctype.map(str::to_owned), body.into_bytes()));
            ops.push(("ls".into(), s.url(&path), None));
        }
    }
    for p in [
        "/site/",
        "/site",
        "/site/empty/",
        "/site/latin1/",
        "/site/simple/",
        "/site/a.txt",
        "/site/nope/",
        "/files/blob.bin",
        "/data/status/403",
    ] {
        ops.push(("ls".into(), s.url(p), None));
    }
    for p in [
        "/files/blob.bin",
        "/files/empty.bin",
        "/files/hello.txt",
        "/files/missing",
        "/site/",
        "/site/a.txt",
        "/data/plain/b",
        "/data/norange/b",
        "/data/nolength/b",
        "/data/nohead/b",
        "/data/acceptnone/b",
        "/data/gzip/b",
        "/data/gzip-ranged/b",
        "/data/plain/a b",
        "/data/plain/caf\u{e9}",
        "/data/plain/%7Ex%41%e2%82%ac",
        "/data/plain/a/./b/../c#frag",
        "/data/redirect/b",
        "/data/etag/b",
        "/data/weak/b",
        "/data/status/403",
        "/data/status/404",
        "/data/status/410",
    ] {
        ops.push(("info".into(), s.url(p), None));
        ops.push(("exists".into(), s.url(p), None));
    }
    let n = common::BLOB_LEN as u64;
    for p in [
        "/files/blob.bin",
        "/data/plain/b",
        "/data/redirect/b",
        "/files/hello.txt",
    ] {
        for r in [
            ByteRange::Full,
            ByteRange::Bounded { start: 0, end: 5 },
            ByteRange::Bounded {
                start: 3,
                end: 1_000_003,
            },
            ByteRange::From(2),
            ByteRange::Suffix(3),
            ByteRange::Bounded {
                start: n - 3,
                end: n + 10,
            },
        ] {
            ops.push(("cat".into(), s.url(p), Some(r)));
        }
    }
    ops.push(("cat".into(), s.url("/files/missing"), Some(ByteRange::Full)));
    ops.push((
        "cat".into(),
        s.url("/data/norange/b"),
        Some(ByteRange::Full),
    ));

    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("diff.py");
    let input = dir.path().join("ops.tsv");
    let output = dir.path().join("out.txt");
    std::fs::write(&script, SCRIPT).unwrap();
    let mut lines = String::new();
    for (op, url, r) in &ops {
        let (a, b) = match r {
            None | Some(ByteRange::Full) => ("-".to_owned(), "-".to_owned()),
            Some(ByteRange::Bounded { start, end }) => (start.to_string(), end.to_string()),
            Some(ByteRange::From(s)) => (s.to_string(), "-".to_owned()),
            Some(ByteRange::Suffix(k)) => (format!("-{k}"), "-".to_owned()),
        };
        let _ = writeln!(lines, "{op}\t{}\t{a}\t{b}", hx(url));
    }
    std::fs::write(&input, lines).unwrap();

    // Run fsspec while this runtime keeps serving.
    let status = tokio::task::spawn_blocking({
        let (python, script, input, output) = (
            python.clone(),
            script.clone(),
            input.clone(),
            output.clone(),
        );
        move || {
            Command::new(python)
                .arg(&script)
                .arg(&input)
                .arg(&output)
                .env("NO_PROXY", "127.0.0.1,localhost")
                .status()
                .unwrap()
        }
    })
    .await
    .unwrap();
    assert!(status.success(), "python failed");
    let expected: Vec<String> = std::fs::read_to_string(&output)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(expected.len(), ops.len());

    let fs = HttpFileSystem::new().unwrap();
    let mut mismatches = Vec::new();
    for ((op, url, r), want) in ops.iter().zip(&expected) {
        let got = match op.as_str() {
            "ls" => match fs.ls(url).await {
                Ok(v) => {
                    let mut items: Vec<String> = v
                        .iter()
                        .map(|e| {
                            format!(
                                "{}{}{}",
                                if e.is_dir() { "D" } else { "F" },
                                hx(&e.name),
                                if known_size(e).is_some() { "!size" } else { "" }
                            )
                        })
                        .collect();
                    items.sort();
                    format!("ok {}", items.join(" "))
                }
                Err(e) => format!("err {}", err_name(e.kind())),
            },
            "info" => match fs.info(url).await {
                Ok(i) => format!("ok {}", info_line(&i)),
                Err(e) => format!("err {}", err_name(e.kind())),
            },
            "exists" => match fs.exists(url).await {
                Ok(b) => format!("ok {}", if b { "True" } else { "False" }),
                Err(e) => format!("err {}", err_name(e.kind())),
            },
            "cat" => match fs.cat_file(url, r.unwrap()).await {
                Ok(d) => format!("ok {} {}", d.len(), sha256_hex(&d)),
                Err(e) => format!("err {}", err_name(e.kind())),
            },
            _ => unreachable!(),
        };
        if &got != want && !documented_deviation(op, want, &got) {
            mismatches.push(format!(
                "{op} {url} {r:?}\n  fsspec: {}\n  fsfast: {}",
                decode_line(want),
                decode_line(&got)
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} operations differ:\n{}",
        mismatches.len(),
        ops.len(),
        mismatches.join("\n")
    );
}

/// Differences that are deliberate (see the crate docs):
/// * fsspec lets `aiohttp.ClientResponseError` escape for statuses it does
///   not translate (e.g. 403 on `ls`); fsfast maps them onto precise kinds.
/// * A range starting past the end: fsspec raises on the 416, fsfast returns
///   no bytes (the core contract: ranges past EOF are truncated).
fn documented_deviation(op: &str, fsspec: &str, fsfast: &str) -> bool {
    const EMPTY: &str = "ok 0 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    fsspec == "err Other:ClientResponseError"
        && ((fsfast.starts_with("err ") && fsfast != "err NotFound")
            || (op == "cat" && fsfast == EMPTY))
}

/// Make hex-encoded names readable in failure messages.
fn decode_line(line: &str) -> String {
    line.split(' ')
        .map(|tok| {
            let (prefix, rest) = tok.split_at(tok.len().min(1));
            let body = rest.trim_end_matches("!size");
            if matches!(prefix, "D" | "F")
                && body.len() % 2 == 0
                && !body.is_empty()
                && body.bytes().all(|b| b.is_ascii_hexdigit())
            {
                let bytes: Vec<u8> = (0..body.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&body[i..i + 2], 16).unwrap())
                    .collect();
                format!("{prefix}{:?}", String::from_utf8_lossy(&bytes))
            } else {
                tok.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// SHA-256 (FIPS 180-4), to compare bodies with Python's hashlib.
fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for block in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, c) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [
                t1.wrapping_add(t2),
                v[0],
                v[1],
                v[2],
                v[3].wrapping_add(t1),
                v[4],
                v[5],
                v[6],
            ];
        }
        for (a, b) in h.iter_mut().zip(v) {
            *a = a.wrapping_add(b);
        }
    }
    h.iter().fold(String::new(), |mut o, x| {
        let _ = write!(o, "{x:08x}");
        o
    })
}

#[test]
fn sha256_known_answers() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(&[b'a'; 1000]),
        "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
    );
}
