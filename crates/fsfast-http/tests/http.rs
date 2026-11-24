//! HttpFileSystem against the in-process test server (see common/mod.rs).

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use common::{BLOB_LEN, TestServer, blob, pattern, start};
use fsfast_core::{
    ByteRange, Detail, ErrorKind, FileInfo, FileSystem, FindOptions, Options, ReadOptions, Value,
    WriteMode, WriteOptions,
};
use fsfast_http::{HttpFileSystem, known_size};
use futures::StreamExt;

fn fs_with(pairs: &[(&str, Value)]) -> HttpFileSystem {
    let opts: Options = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    HttpFileSystem::from_options(opts).unwrap()
}

/// Small blocks so the 3 MiB blob takes many parts (parallel paths).
fn small_blocks() -> HttpFileSystem {
    fs_with(&[("block_size", Value::Int(256 << 10))])
}

fn no_retries() -> HttpFileSystem {
    fs_with(&[("max_retries", Value::Int(0))])
}

fn gets(s: &TestServer, prefix: &str) -> Vec<common::Seen> {
    s.state
        .requests(prefix)
        .into_iter()
        .filter(|r| r.method == "GET")
        .collect()
}

fn range_header(r: &common::Seen) -> Option<String> {
    r.headers
        .get("range")
        .map(|v| v.to_str().unwrap().to_owned())
}

#[tokio::test]
async fn info_fields_and_fallbacks() {
    let s = start().await;
    let fs = HttpFileSystem::new().unwrap();

    let url = s.url("/files/blob.bin");
    let i = fs.info(&url).await.unwrap();
    assert_eq!(i.name, url);
    assert!(i.is_file());
    assert_eq!(known_size(&i), Some(BLOB_LEN as u64));
    assert_eq!(i.extra["url"], Value::from(url.clone()));
    assert_eq!(i.extra["mimetype"], Value::from("application/octet-stream"));
    assert!(i.extra.contains_key("Last-Modified"));
    assert!(i.modified.is_some());
    assert!(!i.extra.contains_key("partial"));

    // Directories are files to fsspec http.
    let i = fs.info(&s.url("/site/")).await.unwrap();
    assert!(i.is_file());
    assert_eq!(i.extra["mimetype"], Value::from("text/html"));

    // HEAD refused: GET bytes=0-0 gives the size from Content-Range.
    s.state.clear_log();
    let i = fs.info(&s.url("/data/nohead/b")).await.unwrap();
    assert_eq!(known_size(&i), Some(BLOB_LEN as u64));
    let log = s.state.requests("/data/nohead");
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].method, "HEAD");
    assert_eq!(range_header(&log[1]).as_deref(), Some("bytes=0-0"));
    assert_eq!(log[0].headers["accept-encoding"], "identity");

    // No length anywhere: size None.
    let i = fs.info(&s.url("/data/nolength/b")).await.unwrap();
    assert_eq!(known_size(&i), None);
    assert_eq!(i.extra["size"], Value::Null);
    assert_eq!(i.size, 0);

    // A content coding makes Content-Length meaningless (fsspec's rule).
    let i = fs.info(&s.url("/data/gzip/b")).await.unwrap();
    assert_eq!(known_size(&i), None);
    // ...also when the server honours the bytes=0-0 fallback: fsspec's GET
    // sees `Content-Length` plus `Content-Encoding` and reports None, so the
    // coded total of `Content-Range` must not leak into `size` either.
    let i = fs.info(&s.url("/data/gzip-ranged/b")).await.unwrap();
    assert_eq!(known_size(&i), None, "{i:?}");

    let i = fs.info(&s.url("/data/acceptnone/b")).await.unwrap();
    assert_eq!(i.extra["partial"], Value::Bool(false));
    assert_eq!(known_size(&i), Some(BLOB_LEN as u64));

    // Redirects: the name stays, `url` is the final location.
    let i = fs.info(&s.url("/data/redirect/b")).await.unwrap();
    assert_eq!(i.name, s.url("/data/redirect/b"));
    assert_eq!(i.extra["url"], Value::from(s.url("/data/plain/b")));

    // `url` is aiohttp's `str(r.url)`: normalized by yarl, without user
    // info or fragment, while `name` stays the URL as given. Expected values
    // recorded from fsspec 2026.x / yarl 1.25.
    let host = s.addr.to_string();
    for (given, want) in [
        ("http://@/data/plain/a b", "http://@/data/plain/a%20b"),
        (
            "http://@/data/plain/caf\u{e9}",
            "http://@/data/plain/caf%C3%A9",
        ),
        ("HTTP://@/data/plain/x", "http://@/data/plain/x"),
        ("http://@/data/plain/a/./b/../c", "http://@/data/plain/a/c"),
        ("http://@/data/plain/x#frag", "http://@/data/plain/x"),
        ("http://user:pw@@/data/plain/x", "http://@/data/plain/x"),
        ("http://@/data/plain/%7Ex%41", "http://@/data/plain/~xA"),
        (
            "http://@/data/plain/%e2%82%ac",
            "http://@/data/plain/%E2%82%AC",
        ),
    ] {
        let given = given.replace("@/", &format!("{host}/"));
        let i = fs.info(&given).await.unwrap();
        assert_eq!(i.name, given);
        assert_eq!(
            i.extra["url"],
            Value::from(want.replace("@/", &format!("{host}/"))),
            "{given}"
        );
    }

    let i = fs.info(&s.url("/files/empty.bin")).await.unwrap();
    assert_eq!(known_size(&i), Some(0));

    let i = fs.info(&s.url("/data/etag/b")).await.unwrap();
    assert_eq!(i.extra["ETag"], Value::from("\"v0\""));
    assert_eq!(i.version.as_deref(), Some("\"v0\""));

    // Errors: any 4xx is FileNotFoundError like fsspec (status attached),
    // server errors and transport failures keep their kinds.
    for (path, status) in [("/files/missing", 404), ("/data/status/403", 403)] {
        let e = fs.info(&s.url(path)).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotFound, "{path}: {e}");
        assert!(e.details().contains(&Detail::Http(status)), "{e:?}");
        assert_eq!(e.path(), Some(s.url(path).as_str()));
    }
    let e = no_retries()
        .info(&s.url("/data/status/500"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io, "{e}");
    assert_eq!(e.http_status(), Some(500));

    let free = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let e = no_retries()
        .info(&format!("http://{free}/x"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ConnectionFailed, "{e}");
    let e = fs.info("not a url").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
    let e = fs.info("ftp://h/x").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
}

fn names(v: &[FileInfo]) -> Vec<(String, bool)> {
    v.iter().map(|i| (i.name.clone(), i.is_dir())).collect()
}

#[tokio::test]
async fn ls_scrapes_links_like_fsspec() {
    let s = start().await;
    let fs = HttpFileSystem::new().unwrap();
    let port = s.addr.port();
    let base = format!("http://127.0.0.1:{port}/site");
    let expected = vec![
        (format!("{base}/?C=N;O=D"), false),
        (format!("{base}/a.txt"), false),
        (format!("{base}/abs.bin"), false),
        (format!("{base}/bare.txt"), false),
        (format!("{base}/sub/"), true),
        (format!("https://127.0.0.1:{port}/site/cross.txt"), false),
    ];
    let got = fs.ls(&s.url("/site/")).await.unwrap();
    assert_eq!(names(&got), expected);
    assert!(got.iter().all(|i| known_size(i).is_none()));
    // Without the trailing slash links resolve to the same URLs.
    assert_eq!(names(&fs.ls(&s.url("/site")).await.unwrap()), expected);

    // simple_links=False ignores the bare URL in the text.
    let strict = fs_with(&[("simple_links", Value::Bool(false))]);
    let got = strict.ls(&s.url("/site/")).await.unwrap();
    assert!(!got.iter().any(|i| i.name.ends_with("bare.txt")));
    assert_eq!(got.len(), expected.len() - 1);

    // A page without links whose URL ends with "/" is retried without it.
    let got = fs.ls(&s.url("/site/empty/")).await.unwrap();
    assert_eq!(names(&got), vec![(format!("{base}/empty/x"), false)]);

    // charset=latin-1 decoding.
    let got = fs.ls(&s.url("/site/latin1/")).await.unwrap();
    assert_eq!(
        names(&got),
        vec![(format!("{base}/latin1/café.txt"), false)]
    );

    // Not HTML: nothing to list (fsspec does not read the body).
    assert!(fs.ls(&s.url("/site/a.txt")).await.unwrap().is_empty());
    assert!(fs.ls(&s.url("/files/blob.bin")).await.unwrap().is_empty());

    let e = fs.ls(&s.url("/site/nope/")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);

    assert!(fs.isdir(&s.url("/site/")).await.unwrap());
    assert!(!fs.isdir(&s.url("/site/a.txt")).await.unwrap());
    assert!(!fs.isdir(&s.url("/site/nope/")).await.unwrap());
    assert!(!fs.isdir("not a url").await.unwrap());
}

#[tokio::test]
async fn find_walks_pages() {
    let s = start().await;
    let fs = HttpFileSystem::new().unwrap();
    let port = s.addr.port();
    let base = format!("http://127.0.0.1:{port}/site");
    let root = s.url("/site/");
    let files = vec![
        format!("{base}/?C=N;O=D"),
        format!("{base}/a.txt"),
        format!("{base}/abs.bin"),
        format!("{base}/bare.txt"),
        format!("{base}/sub/deep.txt"),
        format!("{base}/sub/deeper/z.txt"),
        format!("https://127.0.0.1:{port}/site/cross.txt"),
    ];
    let got = fs.find(&root, &FindOptions::default()).await.unwrap();
    let got_names: Vec<String> = got.iter().map(|i| i.name.clone()).collect();
    assert_eq!(got_names, files);

    let got = fs
        .find(
            &root,
            &FindOptions {
                maxdepth: None,
                withdirs: true,
            },
        )
        .await
        .unwrap();
    let mut want: Vec<String> = files.clone();
    want.push(root.clone());
    want.push(format!("{base}/sub/"));
    want.push(format!("{base}/sub/deeper/"));
    want.sort();
    let got_names: Vec<String> = got.iter().map(|i| i.name.clone()).collect();
    assert_eq!(got_names, want);
    // The root comes from info() (a "file" to fsspec http), dirs from links.
    let root_entry = got.iter().find(|i| i.name == root).unwrap();
    assert!(root_entry.is_file());
    assert!(
        got.iter()
            .find(|i| i.name.ends_with("/sub/"))
            .unwrap()
            .is_dir()
    );

    let got = fs
        .find(
            &root,
            &FindOptions {
                maxdepth: Some(1),
                withdirs: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(got.len(), 5);

    // A file finds itself; a missing URL finds nothing.
    let a = s.url("/site/a.txt");
    let got = fs.find(&a, &FindOptions::default()).await.unwrap();
    assert_eq!(names(&got), vec![(a, false)]);
    assert!(
        fs.find(&s.url("/site/nope/"), &FindOptions::default())
            .await
            .unwrap()
            .is_empty()
    );

    // "./" links do not make the walk loop forever.
    let got = tokio::time::timeout(
        Duration::from_secs(10),
        fs.find(&s.url("/site/dots/"), &FindOptions::default()),
    )
    .await
    .expect("walk terminates")
    .unwrap();
    assert_eq!(names(&got), vec![(format!("{base}/dots/f.txt"), false)]);
}

#[tokio::test]
async fn exists_semantics() {
    let s = start().await;
    let fs = HttpFileSystem::new().unwrap();
    assert!(fs.exists(&s.url("/files/blob.bin")).await.unwrap());
    assert!(fs.exists(&s.url("/files/empty.bin")).await.unwrap());
    assert!(fs.exists(&s.url("/site/")).await.unwrap());
    assert!(!fs.exists(&s.url("/files/missing")).await.unwrap());
    assert!(!fs.exists(&s.url("/data/status/403")).await.unwrap());
    assert!(!fs.exists("not a url").await.unwrap());
    let e = no_retries()
        .exists(&s.url("/data/status/500"))
        .await
        .unwrap_err();
    assert_eq!(e.http_status(), Some(500));
    // A probe, not a download: one byte requested.
    s.state.clear_log();
    assert!(fs.exists(&s.url("/data/plain/b")).await.unwrap());
    let log = gets(&s, "/data/plain");
    assert_eq!(range_header(&log[0]).as_deref(), Some("bytes=0-0"));
}

const ENDPOINTS: [&str; 8] = [
    "/files/blob.bin",
    "/data/plain/b",
    "/data/norange/b",
    "/data/nolength/b",
    "/data/capped/b",
    "/data/unknowntotal/b",
    "/data/redirect/b",
    "/data/nohead/b",
];

fn ranges() -> Vec<ByteRange> {
    let n = BLOB_LEN as u64;
    vec![
        ByteRange::Full,
        ByteRange::Bounded { start: 0, end: 10 },
        ByteRange::Bounded {
            start: 1_000,
            end: 301_000,
        },
        ByteRange::Bounded {
            start: 7,
            end: n - 7,
        },
        ByteRange::Bounded {
            start: n - 10,
            end: n + 100,
        },
        ByteRange::From(n - 5),
        ByteRange::From(100),
        ByteRange::Suffix(1_000),
        ByteRange::Suffix(2 * n),
        ByteRange::Bounded {
            start: n + 1,
            end: n + 2,
        },
        ByteRange::From(n),
        ByteRange::Bounded { start: 5, end: 5 },
    ]
}

#[tokio::test]
async fn cat_file_returns_exact_bytes_from_every_kind_of_server() {
    let s = start().await;
    let fs = small_blocks();
    let data = blob();
    for ep in ENDPOINTS {
        let url = s.url(ep);
        for r in ranges() {
            let got = fs
                .cat_file(&url, r)
                .await
                .unwrap_or_else(|e| panic!("{ep} {r:?}: {e}"));
            let w = r.resolve(data.len() as u64);
            assert!(
                got[..] == data[w.start as usize..w.end as usize],
                "{ep} {r:?}: got {} bytes, want {}",
                got.len(),
                w.end - w.start
            );
        }
    }
    let e = fs
        .cat_file(&s.url("/files/missing"), ByteRange::Full)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    let e = fs
        .cat_file(&s.url("/data/status/403"), ByteRange::Full)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    assert!(
        fs.cat_file(&s.url("/files/empty.bin"), ByteRange::Full)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn large_reads_use_parallel_pinned_parts() {
    let s = start().await;
    let fs = small_blocks();
    s.state.clear_log();
    let got = fs
        .cat_file(&s.url("/data/etag/b"), ByteRange::Full)
        .await
        .unwrap();
    assert_eq!(got, pattern(100, BLOB_LEN));
    let log = gets(&s, "/data/etag");
    let parts = BLOB_LEN.div_ceil(256 << 10);
    assert_eq!(log.len(), parts, "one GET per part");
    assert_eq!(range_header(&log[0]).as_deref(), Some("bytes=0-262143"));
    assert!(log[0].headers.get("if-match").is_none());
    // Parts after the first are pinned to its ETag.
    assert!(
        log[1..]
            .iter()
            .all(|r| r.headers.get("if-match").is_some_and(|v| v == "\"v0\""))
    );

    // A server that ignores Range costs exactly one request.
    s.state.clear_log();
    let got = fs
        .cat_file(&s.url("/data/norange/b"), ByteRange::Full)
        .await
        .unwrap();
    assert_eq!(got.len(), BLOB_LEN);
    assert_eq!(gets(&s, "/data/norange").len(), 1);

    // Small reads are one request.
    s.state.clear_log();
    fs.cat_file(
        &s.url("/data/plain/b"),
        ByteRange::Bounded { start: 5, end: 50 },
    )
    .await
    .unwrap();
    assert_eq!(gets(&s, "/data/plain").len(), 1);
}

#[tokio::test]
async fn open_read_ranged_pinned_and_fallbacks() {
    let s = start().await;
    let fs = small_blocks();
    let data = blob();

    // Plain static server: concurrent ranged reads.
    let h = fs
        .open_read(&s.url("/files/blob.bin"), &ReadOptions::default())
        .await
        .unwrap();
    assert_eq!(h.size(), BLOB_LEN as u64);
    let futs = (0..32u64).map(|i| {
        let h = h.clone();
        async move {
            let off = (i * 97_531) % BLOB_LEN as u64;
            (off, h.read_at(off, 70_000).await.unwrap())
        }
    });
    for (off, got) in futures::future::join_all(futs).await {
        let end = (off as usize + 70_000).min(BLOB_LEN);
        assert_eq!(&got[..], &data[off as usize..end]);
    }
    assert!(h.read_at(BLOB_LEN as u64, 10).await.unwrap().is_empty());
    let rs = h
        .read_ranges(&[0..10, 5..20, 1_000_000..1_000_100, 3_000_000..4_000_000])
        .await
        .unwrap();
    assert_eq!(&rs[2][..], &data[1_000_000..1_000_100]);
    assert_eq!(&rs[3][..], &data[3_000_000..]);
    h.close().await.unwrap();

    // A server ignoring Range: the first answer becomes the one download.
    s.state.clear_log();
    let h = fs
        .open_read(&s.url("/data/norange/b"), &ReadOptions::default())
        .await
        .unwrap();
    for off in [0u64, 1_000, 2_000_000, 50] {
        assert_eq!(
            &h.read_at(off, 1000).await.unwrap()[..],
            &data[off as usize..off as usize + 1000]
        );
    }
    assert_eq!(gets(&s, "/data/norange").len(), 1);

    // Accept-Ranges: none: a single full download on first use.
    s.state.clear_log();
    let h = fs
        .open_read(&s.url("/data/acceptnone/b"), &ReadOptions::default())
        .await
        .unwrap();
    let futs = (0..8u64).map(|i| {
        let h = h.clone();
        async move { h.read_at(i * 1000, 10).await.unwrap() }
    });
    futures::future::join_all(futs).await;
    let log = gets(&s, "/data/acceptnone");
    assert_eq!(log.len(), 1, "one shared download");
    assert!(range_header(&log[0]).is_none());

    // Unknown size: downloaded at open.
    let h = fs
        .open_read(&s.url("/data/nolength/b"), &ReadOptions::default())
        .await
        .unwrap();
    assert_eq!(h.size(), BLOB_LEN as u64);
    assert_eq!(known_size(h.info()), Some(BLOB_LEN as u64));
    s.state.clear_log();
    assert_eq!(&h.read_at(10, 10).await.unwrap()[..], &data[10..20]);
    assert!(gets(&s, "/data/nolength").is_empty());

    // Servers capping part sizes: reads loop until complete.
    let h = fs
        .open_read(&s.url("/data/capped/b"), &ReadOptions::default())
        .await
        .unwrap();
    assert_eq!(&h.read_at(5, 350_000).await.unwrap()[..], &data[5..350_005]);

    let e = fs
        .open_read(&s.url("/files/missing"), &ReadOptions::default())
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    let e = fs
        .open_read(
            &s.url("/files/blob.bin"),
            &ReadOptions {
                version: Some("v1".into()),
                ..ReadOptions::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unsupported);
}

#[tokio::test]
async fn pinned_reads_detect_changes() {
    let s = start().await;
    let fs = small_blocks();
    let url = s.url("/data/etag/b");
    let h = fs.open_read(&url, &ReadOptions::default()).await.unwrap();
    s.state.clear_log();
    assert_eq!(
        &h.read_at(0, 100).await.unwrap()[..],
        &pattern(100, BLOB_LEN)[..100]
    );
    assert_eq!(gets(&s, "/data/etag")[0].headers["if-match"], "\"v0\"");
    s.state.version.store(1, Ordering::SeqCst);
    let e = h.read_at(100, 100).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e}");
    assert_eq!(e.http_status(), Some(412));

    // Without pinning the new content is read.
    let h = fs
        .open_read(
            &url,
            &ReadOptions {
                pin_version: false,
                ..ReadOptions::default()
            },
        )
        .await
        .unwrap();
    s.state.version.store(2, Ordering::SeqCst);
    s.state.clear_log();
    assert_eq!(
        &h.read_at(0, 10).await.unwrap()[..],
        &pattern(102, BLOB_LEN)[..10]
    );
    assert!(gets(&s, "/data/etag")[0].headers.get("if-match").is_none());

    // Weak ETags never go into If-Match.
    let h = fs
        .open_read(&s.url("/data/weak/b"), &ReadOptions::default())
        .await
        .unwrap();
    s.state.clear_log();
    h.read_at(0, 10).await.unwrap();
    assert!(gets(&s, "/data/weak")[0].headers.get("if-match").is_none());
}

#[tokio::test]
async fn uploads() {
    let s = start().await;
    let fs = HttpFileSystem::new().unwrap();
    let stored = |p: &str| s.state.uploads.lock().get(p).cloned();

    fs.pipe_file(
        &s.url("/upload/a"),
        Bytes::from_static(b"hello"),
        &WriteOptions::default(),
    )
    .await
    .unwrap();
    let (m, b) = stored("/upload/a").unwrap();
    assert_eq!((m.as_str(), &b[..]), ("PUT", &b"hello"[..]));
    let seen = s.state.requests("/upload/a").pop().unwrap();
    assert_eq!(seen.headers["content-length"], "5");
    assert!(seen.headers.get("transfer-encoding").is_none());

    let mut extra = Options::new();
    extra.insert("method".into(), "POST".into());
    extra.insert(
        "headers".into(),
        Value::Map([("X-Meta".to_owned(), "m".into())].into_iter().collect()),
    );
    let opts = WriteOptions {
        content_type: Some("text/plain".into()),
        extra,
        ..WriteOptions::default()
    };
    fs.pipe_file(&s.url("/upload/b"), Bytes::from_static(b"x"), &opts)
        .await
        .unwrap();
    assert_eq!(stored("/upload/b").unwrap().0, "POST");
    let seen = s.state.requests("/upload/b").pop().unwrap();
    assert_eq!(seen.headers["x-meta"], "m");
    assert_eq!(seen.headers["content-type"], "text/plain");

    // Create-only: If-None-Match: *, 412 -> AlreadyExists.
    let xb = WriteOptions::default().with_mode(WriteMode::CreateNew);
    fs.pipe_file(&s.url("/upload/c"), Bytes::from_static(b"1"), &xb)
        .await
        .unwrap();
    let e = fs
        .pipe_file(&s.url("/upload/c"), Bytes::from_static(b"2"), &xb)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AlreadyExists, "{e}");
    assert_eq!(&stored("/upload/c").unwrap().1[..], b"1");

    for bad in [
        WriteOptions::default().with_mode(WriteMode::Append),
        WriteOptions {
            metadata: [("k".to_owned(), "v".to_owned())].into_iter().collect(),
            ..WriteOptions::default()
        },
    ] {
        let e = fs
            .pipe_file(&s.url("/upload/d"), Bytes::new(), &bad)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported);
    }
    let mut extra = Options::new();
    extra.insert("method".into(), "patch".into());
    let e = fs
        .pipe_file(
            &s.url("/upload/d"),
            Bytes::new(),
            &WriteOptions {
                extra,
                ..WriteOptions::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);

    // A PUT to a server that refuses it.
    let e = fs
        .pipe_file(
            &s.url("/files/x"),
            Bytes::from_static(b"x"),
            &WriteOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
}

#[tokio::test]
async fn slow_streaming_writes_outlast_the_read_timeout() {
    // `read_timeout` bounds idleness, not the duration of an upload: a
    // streaming write fed for several timeouts must still succeed.
    let s = start().await;
    let fs = fs_with(&[("read_timeout", Value::Float(0.3))]);
    let opts = WriteOptions {
        block_size: Some(1000),
        ..WriteOptions::default()
    };
    let data = pattern(11, 20_000);
    let mut w = fs.open_write(&s.url("/upload/slow"), &opts).await.unwrap();
    for c in data.chunks(2000) {
        tokio::time::sleep(Duration::from_millis(100)).await;
        w.write(Bytes::copy_from_slice(c)).await.unwrap();
    }
    w.close().await.expect("an active upload is not timed out");
    assert_eq!(&s.state.uploads.lock()["/upload/slow"].1[..], &data[..]);

    // Empty uploads carry `Content-Length: 0` (fsspec sends it explicitly).
    fs.pipe_file(
        &s.url("/upload/zero-a"),
        Bytes::new(),
        &WriteOptions::default(),
    )
    .await
    .unwrap();
    let mut w = fs
        .open_write(&s.url("/upload/zero-b"), &WriteOptions::default())
        .await
        .unwrap();
    w.close().await.unwrap();
    for p in ["/upload/zero-a", "/upload/zero-b"] {
        let seen = s.state.requests(p);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].headers["content-length"], "0", "{p}");
    }
}

#[tokio::test]
async fn open_write_buffers_or_streams() {
    let s = start().await;
    let fs = HttpFileSystem::new().unwrap();

    // Small: one request with Content-Length, sent on close.
    let mut w = fs
        .open_write(&s.url("/upload/small"), &WriteOptions::default())
        .await
        .unwrap();
    for c in [&b"ab"[..], b"", b"cde"] {
        w.write(Bytes::copy_from_slice(c)).await.unwrap();
    }
    assert!(
        s.state.requests("/upload/small").is_empty(),
        "nothing sent before close"
    );
    assert_eq!(w.bytes_written(), 5);
    w.close().await.unwrap();
    w.close().await.unwrap();
    assert!(w.write(Bytes::from_static(b"x")).await.is_err());
    let seen = s.state.requests("/upload/small");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].headers["content-length"], "5");
    assert_eq!(&s.state.uploads.lock()["/upload/small"].1[..], b"abcde");

    // Larger than the block size: a streaming (chunked) request.
    let opts = WriteOptions {
        block_size: Some(1024),
        ..WriteOptions::default()
    };
    let data = pattern(7, 100_000);
    let mut w = fs.open_write(&s.url("/upload/big"), &opts).await.unwrap();
    for c in data.chunks(999) {
        w.write(Bytes::copy_from_slice(c)).await.unwrap();
    }
    w.close().await.unwrap();
    let seen = s.state.requests("/upload/big");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].headers["transfer-encoding"], "chunked");
    assert_eq!(&s.state.uploads.lock()["/upload/big"].1[..], &data[..]);

    // Abort mid-stream: the server never gets a complete body.
    let mut w = fs
        .open_write(&s.url("/upload/aborted"), &opts)
        .await
        .unwrap();
    for c in data.chunks(999).take(20) {
        w.write(Bytes::copy_from_slice(c)).await.unwrap();
    }
    w.abort().await.unwrap();
    assert!(w.close().await.is_err());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!s.state.uploads.lock().contains_key("/upload/aborted"));

    // Dropping without close sends nothing.
    let mut w = fs
        .open_write(&s.url("/upload/dropped"), &WriteOptions::default())
        .await
        .unwrap();
    w.write(Bytes::from_static(b"zzz")).await.unwrap();
    drop(w);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(s.state.requests("/upload/dropped").is_empty());

    // An upload rejected by the server surfaces on write or close.
    let mut w = fs.open_write(&s.url("/files/nope"), &opts).await.unwrap();
    let mut res = Ok(());
    for c in data.chunks(999) {
        res = w.write(Bytes::copy_from_slice(c)).await;
        if res.is_err() {
            break;
        }
    }
    if res.is_ok() {
        res = w.close().await;
    }
    assert!(res.is_err());
}

#[tokio::test]
async fn cancelled_writes_poison_the_handle() {
    let s = start().await;
    let fs = HttpFileSystem::new().unwrap();
    let opts = WriteOptions {
        block_size: Some(1024),
        ..WriteOptions::default()
    };
    let url = s.url("/upload-slow/cancelled");
    let mut w = fs.open_write(&url, &opts).await.unwrap();
    let chunk = Bytes::from(vec![7u8; 64 << 10]);
    // The server does not read for a while: once the socket buffers are
    // full, some write blocks on the body queue and is cancelled by the
    // timeout.
    let mut cancelled = false;
    for _ in 0..2048 {
        match tokio::time::timeout(Duration::from_millis(20), w.write(chunk.clone())).await {
            Ok(r) => r.unwrap(),
            Err(_) => {
                cancelled = true;
                break;
            }
        }
    }
    assert!(cancelled, "a write should have blocked on backpressure");
    let e = w.write(chunk.clone()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Cancelled);
    assert!(w.close().await.is_err());
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        !s.state
            .uploads
            .lock()
            .contains_key("/upload-slow/cancelled"),
        "an upload with a hole must not complete"
    );
}

/// A 307 for an upload: followed when the body can be sent again (bytes in
/// memory, also large ones), otherwise an error. An upload must never report
/// success for a redirect response that stored nothing.
#[tokio::test]
async fn redirected_uploads_are_resent_or_fail() {
    let s = start().await;
    let fs = HttpFileSystem::new().unwrap();
    for (name, len) in [("small", 1000), ("large", 6 << 20)] {
        let data = Bytes::from(pattern(5, len));
        fs.pipe_file(
            &s.url(&format!("/upload-moved/{name}")),
            data.clone(),
            &WriteOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            s.state.uploads.lock()[&format!("/upload/{name}")].1,
            data,
            "{name}"
        );
    }

    // A file streamed from disk cannot be resent.
    let local = s.dir.path().join("hello.txt");
    let e = fs
        .put_file(
            &local,
            &s.url("/upload-moved/streamed"),
            &WriteOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(e.http_status(), Some(307), "{e:?}");
    assert!(!s.state.uploads.lock().contains_key("/upload/streamed"));

    // Several buffered writes are sent as chunks: same.
    let mut w = fs
        .open_write(&s.url("/upload-moved/chunks"), &WriteOptions::default())
        .await
        .unwrap();
    w.write(Bytes::from_static(b"ab")).await.unwrap();
    w.write(Bytes::from_static(b"cd")).await.unwrap();
    let e = w.close().await.unwrap_err();
    assert_eq!(e.http_status(), Some(307), "{e:?}");

    // With redirects disabled, a 3xx is not a successful upload either.
    let fs = fs_with(&[("allow_redirects", Value::Bool(false))]);
    let e = fs
        .pipe_file(
            &s.url("/upload-moved/off"),
            Bytes::from_static(b"x"),
            &WriteOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(e.http_status(), Some(307), "{e:?}");
    assert!(!s.state.uploads.lock().contains_key("/upload/off"));
}

#[tokio::test]
async fn put_and_get_files() {
    let s = start().await;
    let fs = small_blocks();
    let dir = tempfile::tempdir().unwrap();
    let data = blob();

    let local = dir.path().join("up.bin");
    std::fs::write(&local, &data).unwrap();
    fs.put_file(&local, &s.url("/upload/file"), &WriteOptions::default())
        .await
        .unwrap();
    let (m, b) = s.state.uploads.lock()["/upload/file"].clone();
    assert_eq!(m, "POST", "fsspec's put_file default method");
    assert_eq!(&b[..], &data[..]);
    let seen = s.state.requests("/upload/file").pop().unwrap();
    assert_eq!(
        seen.headers["content-length"],
        BLOB_LEN.to_string().as_str()
    );
    let mut extra = Options::new();
    extra.insert("method".into(), "put".into());
    fs.put_file(
        &local,
        &s.url("/upload/file2"),
        &WriteOptions {
            extra,
            ..WriteOptions::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(s.state.uploads.lock()["/upload/file2"].0, "PUT");
    let e = fs
        .put_file(dir.path(), &s.url("/upload/x"), &WriteOptions::default())
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::IsADirectory);
    let e = fs
        .put_file(
            &dir.path().join("missing"),
            &s.url("/upload/x"),
            &WriteOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);

    for ep in [
        "/files/blob.bin",
        "/data/norange/b",
        "/data/nolength/b",
        "/data/unknowntotal/b",
        "/data/capped/b",
        "/data/redirect/b",
    ] {
        let out = dir.path().join("down.bin");
        fs.get_file(&s.url(ep), &out).await.unwrap();
        assert!(std::fs::read(&out).unwrap() == data, "{ep}");
        std::fs::remove_file(&out).unwrap();
    }
    let out = dir.path().join("empty.bin");
    fs.get_file(&s.url("/files/empty.bin"), &out).await.unwrap();
    assert_eq!(std::fs::read(&out).unwrap().len(), 0);

    let out = dir.path().join("never.bin");
    let e = fs
        .get_file(&s.url("/files/missing"), &out)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    assert!(!out.exists(), "no local file for a failed download");
}

#[tokio::test]
async fn unsupported_and_noop_operations() {
    let s = start().await;
    let fs = HttpFileSystem::new().unwrap();
    let url = s.url("/files/hello.txt");
    for e in [
        fs.rm_file(&url).await.unwrap_err(),
        fs.cp_file(&url, &s.url("/files/x")).await.unwrap_err(),
        fs.mv_file(&url, &s.url("/files/x")).await.unwrap_err(),
        fs.touch(&url, true).await.unwrap_err(),
    ] {
        assert_eq!(e.kind(), ErrorKind::Unsupported);
    }
    assert!(fs.rm_files(std::slice::from_ref(&url)).await[0].is_err());
    fs.mkdir(&s.url("/files/newdir"), true).await.unwrap();
    fs.makedirs(&s.url("/files/newdir"), false).await.unwrap();
    fs.rmdir(&s.url("/files/dir")).await.unwrap();
    assert!(fs.exists(&url).await.unwrap());
    assert!(
        fs.sign(&url, Duration::from_secs(1)).await.is_err(),
        "no presigning"
    );
}

#[tokio::test]
async fn storage_options_reach_the_server() {
    let s = start().await;
    let fs = fs_with(&[
        (
            "headers",
            Value::Map(
                [("X-Token".to_owned(), "secret".into())]
                    .into_iter()
                    .collect(),
            ),
        ),
        ("auth", Value::List(vec!["user".into(), "pw".into()])),
        (
            "params",
            Value::Map([("q".to_owned(), "1".into())].into_iter().collect()),
        ),
        (
            "client_kwargs",
            Value::Map(
                [(
                    "headers".to_owned(),
                    Value::Map([("X-Session".to_owned(), "s".into())].into_iter().collect()),
                )]
                .into_iter()
                .collect(),
            ),
        ),
    ]);
    fs.cat_file(
        &s.url("/data/plain/b"),
        ByteRange::Bounded { start: 0, end: 4 },
    )
    .await
    .unwrap();
    let seen = s.state.requests("/data/plain").pop().unwrap();
    assert_eq!(seen.headers["x-token"], "secret");
    assert_eq!(seen.headers["x-session"], "s");
    assert_eq!(seen.headers["authorization"], "Basic dXNlcjpwdw==");
    assert_eq!(seen.headers["accept-encoding"], "identity");

    // allow_redirects=False: the redirect itself is what info sees.
    let fs = fs_with(&[("allow_redirects", Value::Bool(false))]);
    let i = fs.info(&s.url("/data/redirect/b")).await.unwrap();
    assert_eq!(i.extra["url"], Value::from(s.url("/data/redirect/b")));
}

#[tokio::test]
async fn streaming_and_retries() {
    let s = start().await;
    let fs = HttpFileSystem::new().unwrap();
    let mut st = fs.stream_file(&s.url("/data/nolength/b")).await.unwrap();
    let mut all = Vec::new();
    while let Some(c) = st.next().await {
        all.extend_from_slice(&c.unwrap());
    }
    assert!(all == blob());
    let e = fs.stream_file(&s.url("/files/missing")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);

    // Every other request to /data/flaky fails with 503: retried.
    for _ in 0..4 {
        let got = fs
            .cat_file(
                &s.url("/data/flaky/b"),
                ByteRange::Bounded { start: 0, end: 100 },
            )
            .await
            .unwrap();
        assert_eq!(&got[..], &blob()[..100]);
    }
    assert!(fs.client().stats().snapshot().retries >= 2);
}

#[tokio::test]
async fn handles_are_shareable_across_tasks() {
    let s = start().await;
    let fs = Arc::new(small_blocks());
    let url = s.url("/files/blob.bin");
    let tasks: Vec<_> = (0..8)
        .map(|i| {
            let fs = fs.clone();
            let url = url.clone();
            tokio::spawn(async move {
                fs.cat_file(
                    &url,
                    ByteRange::Bounded {
                        start: i * 1000,
                        end: i * 1000 + 500_000,
                    },
                )
                .await
                .unwrap()
            })
        })
        .collect();
    let data = blob();
    for (i, t) in tasks.into_iter().enumerate() {
        let got = t.await.unwrap();
        assert_eq!(&got[..], &data[i * 1000..i * 1000 + 500_000]);
    }
}

/// Seeded random ranges against every kind of server, through `cat_file` and
/// through read handles, compared byte for byte with the source.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn random_ranges_match_the_source() {
    use fsfast_testkit::pattern::XorShift;
    let s = start().await;
    let fs = small_blocks();
    let data = blob();
    let n = data.len() as u64;
    let mut rng = XorShift::new(42);
    for ep in ENDPOINTS {
        let url = s.url(ep);
        let h = fs.open_read(&url, &ReadOptions::default()).await.unwrap();
        for _ in 0..25 {
            let a = rng.next_u64() % (n + 1000);
            let len = match rng.next_u64() % 4 {
                0 => rng.next_u64() % 16,
                1 => rng.next_u64() % (1 << 20),
                2 => rng.next_u64() % (3 << 20),
                _ => n,
            };
            let r = match rng.next_u64() % 4 {
                0 => ByteRange::Bounded {
                    start: a,
                    end: a + len,
                },
                1 => ByteRange::From(a),
                2 => ByteRange::Suffix(len),
                _ => ByteRange::Full,
            };
            let w = r.resolve(n);
            let want = &data[w.start as usize..w.end as usize];
            let got = fs.cat_file(&url, r).await.unwrap();
            assert!(got[..] == *want, "cat_file {ep} {r:?}");
            let got = h.read_at(a, len as usize).await.unwrap();
            let w = ByteRange::Bounded {
                start: a,
                end: a + len,
            }
            .resolve(n);
            assert!(
                got[..] == data[w.start as usize..w.end as usize],
                "read_at {ep} {a}+{len}"
            );
        }
    }
}
