//! adlfs semantics against Azurite: info keys, listings, directory markers,
//! errors, containers, copies, pinned reads, multi-block uploads, appends,
//! create-only writes, SAS / anonymous / shared-key-without-connection-string
//! access and signed URLs.
//!
//! Gated on `FSFAST_TEST_AZURE_CONNECTION_STRING` (`eval "$(scripts/test-services.sh env)"`).

mod common;

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use common::{connection_string, destroy_container, filesystem, skip, unique_container};
use fsfast_azure::AzureBlobFileSystem;
use fsfast_azure::auth::SharedKey;
use fsfast_azure::auth::sas::BlobSas;
use fsfast_core::{
    ByteRange, Detail, ErrorKind, FileSystem, FindOptions, ReadOptions, Value, WriteMode,
    WriteOptions,
};
use fsfast_http_transport::{HttpClient, HttpConfig, Request};

fn pattern(n: usize, seed: u8) -> Bytes {
    Bytes::from(
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect::<Vec<u8>>(),
    )
}

fn code(e: &fsfast_core::Error) -> Option<&str> {
    e.details().iter().find_map(|d| match d {
        Detail::Code(c) => Some(c.as_str()),
        _ => None,
    })
}

macro_rules! setup {
    ($name:literal) => {{
        let Some(cs) = connection_string() else {
            skip($name);
            return;
        };
        let fs = filesystem(&cs, &[]);
        let c = unique_container($name);
        fs.mkdir(&c, true).await.unwrap();
        (cs, fs, c)
    }};
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn info_ls_find_semantics() {
    let (_cs, fs, c) = setup!("meta");
    let w = WriteOptions::default();
    fs.pipe_file(&format!("{c}/a/b.txt"), Bytes::from_static(b"hello"), &w)
        .await
        .unwrap();
    fs.pipe_file(
        &format!("{c}/top.txt"),
        Bytes::from_static(b"0123456789"),
        &w,
    )
    .await
    .unwrap();

    // Container info (adlfs `_details` of ContainerProperties).
    let ci = fs.info(&c).await.unwrap();
    assert!(ci.is_dir());
    assert_eq!(ci.name, c);
    assert_eq!(ci.extra["size"], Value::Null);
    assert_eq!(ci.extra["metadata"], Value::Null);
    assert!(matches!(&ci.extra["etag"], Value::Str(e) if e.starts_with('"') && e.ends_with('"')));
    assert!(matches!(ci.extra["last_modified"], Value::Time(_)));

    // Root listing contains the container.
    let root = fs.ls("").await.unwrap();
    assert!(root.iter().any(|i| i.name == c && i.is_dir()));

    // Blob info.
    let fi = fs.info(&format!("{c}/a/b.txt")).await.unwrap();
    assert!(fi.is_file());
    assert_eq!(fi.size, 5);
    for k in [
        "metadata",
        "creation_time",
        "deleted",
        "deleted_time",
        "last_modified",
        "content_settings",
        "remaining_retention_days",
        "archive_status",
        "last_accessed_on",
        "etag",
        "tags",
        "tag_count",
    ] {
        assert!(fi.extra.contains_key(k), "missing {k}");
    }
    assert!(!fi.extra.contains_key("version_id"));
    assert_eq!(fi.extra["deleted"], Value::Bool(false));
    let Value::Map(meta) = &fi.extra["metadata"] else {
        panic!()
    };
    assert_eq!(meta["is_directory"], Value::Str("false".into()));
    let Value::Map(cs) = &fi.extra["content_settings"] else {
        panic!()
    };
    assert_eq!(
        cs["content_type"],
        Value::Str("application/octet-stream".into())
    );
    assert!(matches!(cs["content_md5"], Value::Bytes(ref b) if b.len() == 16));

    // Implied directory.
    let di = fs.info(&format!("{c}/a")).await.unwrap();
    assert!(di.is_dir());
    assert_eq!(di.extra["size"], Value::Null);
    assert_eq!(
        fs.info(&format!("{c}/a/")).await.unwrap().name,
        format!("{c}/a")
    );

    // ls of the container: one prefix dir, one file; listing entries have
    // `deleted: None` (adlfs/azure listing quirk).
    let mut ls = fs.ls(&c).await.unwrap();
    ls.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(
        ls.iter()
            .map(|i| (i.name.as_str(), i.is_dir()))
            .collect::<Vec<_>>(),
        vec![
            (format!("{c}/a").as_str(), true),
            (format!("{c}/top.txt").as_str(), false)
        ]
    );
    assert_eq!(ls[1].extra["deleted"], Value::Null);
    assert_eq!(
        ls[0].extra.len(),
        1,
        "prefix dirs only carry size=None: {:?}",
        ls[0].extra
    );

    // ls of a file is the file.
    let lf = fs.ls(&format!("{c}/top.txt")).await.unwrap();
    assert_eq!(lf.len(), 1);
    assert_eq!(lf[0].size, 10);

    // find, with and without dirs.
    let found = fs.find(&c, &FindOptions::default()).await.unwrap();
    assert_eq!(
        found.iter().map(|i| i.name.clone()).collect::<Vec<_>>(),
        vec![format!("{c}/a/b.txt"), format!("{c}/top.txt")]
    );
    let found = fs
        .find(
            &c,
            &FindOptions {
                maxdepth: None,
                withdirs: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        found.iter().map(|i| i.name.clone()).collect::<Vec<_>>(),
        vec![
            c.clone(),
            format!("{c}/a"),
            format!("{c}/a/b.txt"),
            format!("{c}/top.txt")
        ]
    );

    // Missing things.
    let e = fs.info(&format!("{c}/nope")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    assert_eq!(e.path(), Some(format!("{c}/nope").as_str()));
    let e = fs.ls(&format!("{c}/nope")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    let e = fs
        .cat_file(&format!("{c}/nope"), ByteRange::Full)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    assert_eq!(code(&e), Some("BlobNotFound"));
    let missing = unique_container("missing");
    let e = fs.info(&missing).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    let e = fs.ls(&missing).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    assert_eq!(code(&e), Some("ContainerNotFound"));
    assert!(
        fs.find(&missing, &FindOptions::default())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(!fs.exists(&format!("{missing}/x")).await.unwrap());

    destroy_container(&fs, &c).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_markers() {
    let (_cs, fs, c) = setup!("markers");
    let w = WriteOptions::default();
    let mut hdi = WriteOptions::default();
    hdi.metadata.insert("hdi_isfolder".into(), "true".into());
    // ADLS-style markers: an empty directory, and one with a child.
    fs.pipe_file(&format!("{c}/e"), Bytes::new(), &hdi)
        .await
        .unwrap();
    fs.pipe_file(&format!("{c}/h"), Bytes::new(), &hdi)
        .await
        .unwrap();
    fs.pipe_file(&format!("{c}/h/y"), Bytes::from_static(b"22"), &w)
        .await
        .unwrap();
    // S3-style `name/` marker.
    fs.pipe_file(&format!("{c}/m/"), Bytes::new(), &w)
        .await
        .unwrap();
    fs.pipe_file(&format!("{c}/m/x"), Bytes::from_static(b"1"), &w)
        .await
        .unwrap();

    let e = fs.info(&format!("{c}/e")).await.unwrap();
    assert!(e.is_dir(), "{e:?}");
    assert_eq!(e.extra["size"], Value::Null);
    assert!(
        e.extra.contains_key("etag"),
        "marker infos carry the blob's properties"
    );
    assert!(fs.ls(&format!("{c}/e")).await.unwrap().is_empty());

    let ls = fs.ls(&c).await.unwrap();
    let mut names: Vec<_> = ls.iter().map(|i| (i.name.clone(), i.is_dir())).collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            (format!("{c}/e"), true),
            (format!("{c}/h"), true),
            (format!("{c}/m"), true)
        ],
        "markers and prefixes of the same directory appear once"
    );
    let h = ls.iter().find(|i| i.name == format!("{c}/h")).unwrap();
    assert!(
        h.extra.contains_key("metadata"),
        "the marker's properties win"
    );

    let lm = fs.ls(&format!("{c}/m")).await.unwrap();
    assert_eq!(
        lm.iter().map(|i| i.name.clone()).collect::<Vec<_>>(),
        vec![format!("{c}/m/x")]
    );

    let found = fs
        .find(
            &c,
            &FindOptions {
                maxdepth: None,
                withdirs: true,
            },
        )
        .await
        .unwrap();
    let names: Vec<_> = found.iter().map(|i| (i.name.clone(), i.is_dir())).collect();
    assert_eq!(
        names,
        vec![
            (c.clone(), true),
            (format!("{c}/e"), true),
            (format!("{c}/h"), true),
            (format!("{c}/h/y"), false),
            (format!("{c}/m"), true),
            (format!("{c}/m/x"), false),
        ]
    );
    let files = fs.find(&c, &FindOptions::default()).await.unwrap();
    assert_eq!(files.len(), 2, "markers are not files: {files:?}");

    // rmdir: empty marker directory goes; a non-empty one stays.
    fs.rmdir(&format!("{c}/e")).await.unwrap();
    assert!(!fs.exists(&format!("{c}/e")).await.unwrap());
    let err = fs.rmdir(&format!("{c}/h")).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::DirectoryNotEmpty);
    assert_eq!(
        fs.cat_file(&format!("{c}/h/y"), ByteRange::Full)
            .await
            .unwrap(),
        "22"
    );

    // rm of a marker and its children: children first.
    let res = fs
        .rm_files(&[format!("{c}/h"), format!("{c}/h/y"), format!("{c}/m/x")])
        .await;
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    assert!(!fs.exists(&format!("{c}/h")).await.unwrap());

    destroy_container(&fs, &c).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn containers_mkdir_rmdir() {
    let Some(cs) = connection_string() else {
        return skip("containers_mkdir_rmdir");
    };
    let fs = filesystem(&cs, &[]);
    let c = unique_container("mk");
    // adlfs: create_parents=False and a missing container is PermissionError.
    let e = fs.mkdir(&format!("{c}/sub"), false).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    fs.mkdir(&format!("{c}/sub/deeper"), true).await.unwrap();
    assert!(fs.info(&c).await.unwrap().is_dir());
    // Existing container: no error (adlfs exist_ok default), makedirs too.
    fs.mkdir(&c, true).await.unwrap();
    fs.makedirs(&format!("{c}/x/y"), true).await.unwrap();
    let e = fs.makedirs(&c, false).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AlreadyExists);

    fs.pipe_file(
        &format!("{c}/f"),
        Bytes::from_static(b"x"),
        &WriteOptions::default(),
    )
    .await
    .unwrap();
    let e = fs.rmdir(&c).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::DirectoryNotEmpty);
    fs.rm_file(&format!("{c}/f")).await.unwrap();
    fs.rmdir(&c).await.unwrap();
    assert!(!fs.exists(&c).await.unwrap());
    let e = fs.rm_file(&format!("{c}/f")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn copy_move_and_pinned_reads() {
    let (cs, fs, c) = setup!("copy");
    let c2 = unique_container("copy2");
    fs.mkdir(&c2, true).await.unwrap();
    let data = pattern(3 << 20, 7);
    let src = format!("{c}/src.bin");
    fs.pipe_file(&src, data.clone(), &WriteOptions::default())
        .await
        .unwrap();

    fs.cp_file(&src, &format!("{c2}/dst.bin")).await.unwrap();
    assert_eq!(
        fs.cat_file(&format!("{c2}/dst.bin"), ByteRange::Full)
            .await
            .unwrap(),
        data
    );
    fs.mv_file(&format!("{c2}/dst.bin"), &format!("{c2}/moved.bin"))
        .await
        .unwrap();
    assert!(!fs.exists(&format!("{c2}/dst.bin")).await.unwrap());
    assert_eq!(
        fs.info(&format!("{c2}/moved.bin")).await.unwrap().size,
        data.len() as u64
    );

    let e = fs
        .cp_file(&format!("{c}/missing"), &format!("{c}/x"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    assert_eq!(e.path(), Some(format!("{c}/missing").as_str()));

    // A handle pinned to the ETag fails after an overwrite.
    let small = fs
        .open_read(
            &src,
            &ReadOptions {
                block_size: Some(1 << 20),
                ..ReadOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(small.read_at(10, 5).await.unwrap(), data.slice(10..15));
    fs.pipe_file(&src, pattern(100, 1), &WriteOptions::default())
        .await
        .unwrap();
    let e = small.read_at(0, 5).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e}");
    assert_eq!(code(&e), Some("ConditionNotMet"));
    // Unpinned handles follow the new content.
    let unpinned = fs
        .open_read(
            &src,
            &ReadOptions {
                pin_version: false,
                ..ReadOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(unpinned.size(), 100);

    // Sign: a read-only URL anyone can fetch.
    let url = fs
        .sign(&format!("{c2}/moved.bin"), Duration::from_secs(600))
        .await
        .unwrap();
    assert!(url.contains("sp=r") && url.contains("sig="), "{url}");
    let http = HttpClient::new(HttpConfig::default()).unwrap();
    let body = http
        .send_with(
            Request::get(&url).unwrap(),
            |r| async move { r.bytes().await },
        )
        .await
        .unwrap();
    assert_eq!(body, data);

    let _ = cs;
    destroy_container(&fs, &c).await;
    destroy_container(&fs, &c2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_transfers_and_ranges() {
    let (cs, _fs, c) = setup!("large");
    // Small blocks and requests so multi-block paths are exercised.
    let fs = filesystem(
        &cs,
        &[
            ("blocksize", Value::Int(1 << 20)),
            ("request_size", Value::Int(1 << 20)),
        ],
    );
    let data = pattern((5 << 20) + 12345, 3);
    let p1 = format!("{c}/piped.bin");
    fs.pipe_file(&p1, data.clone(), &WriteOptions::default())
        .await
        .unwrap();
    assert_eq!(fs.cat_file(&p1, ByteRange::Full).await.unwrap(), data);

    let p2 = format!("{c}/streamed.bin");
    let mut w = fs.open_write(&p2, &WriteOptions::default()).await.unwrap();
    for chunk in data.chunks(300_001) {
        w.write(Bytes::copy_from_slice(chunk)).await.unwrap();
    }
    w.close().await.unwrap();
    assert_eq!(w.bytes_written(), data.len() as u64);
    let h = fs.open_read(&p2, &ReadOptions::default()).await.unwrap();
    assert_eq!(h.size(), data.len() as u64);
    assert_eq!(h.read_at(0, data.len()).await.unwrap(), data);
    let rs = h
        .read_ranges(&[
            0..10,
            1_000_000..3_100_000,
            5_000_000..(data.len() as u64 + 99),
        ])
        .await
        .unwrap();
    assert_eq!(rs[0], data.slice(0..10));
    assert_eq!(rs[1], data.slice(1_000_000..3_100_000));
    assert_eq!(rs[2], data.slice(5_000_000..));

    // cat_file ranges, including past the end and suffixes.
    let n = data.len() as u64;
    for (r, want) in [
        (ByteRange::Bounded { start: 5, end: 9 }, data.slice(5..9)),
        (ByteRange::From(n - 3), data.slice((n - 3) as usize..)),
        (ByteRange::Suffix(4), data.slice((n - 4) as usize..)),
        (
            ByteRange::Bounded {
                start: n,
                end: n + 10,
            },
            Bytes::new(),
        ),
        (ByteRange::From(1_500_000), data.slice(1_500_000..)),
    ] {
        assert_eq!(fs.cat_file(&p2, r).await.unwrap(), want, "{r:?}");
    }

    // get_file / put_file round trip through the local filesystem.
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("x.bin");
    fs.get_file(&p2, &local).await.unwrap();
    assert_eq!(std::fs::read(&local).unwrap(), data.as_ref());
    let p3 = format!("{c}/put.bin");
    fs.put_file(&local, &p3, &WriteOptions::default())
        .await
        .unwrap();
    assert_eq!(fs.info(&p3).await.unwrap().size, n);

    // Empty blobs.
    let p4 = format!("{c}/empty");
    fs.pipe_file(&p4, Bytes::new(), &WriteOptions::default())
        .await
        .unwrap();
    assert_eq!(
        fs.cat_file(&p4, ByteRange::Full).await.unwrap(),
        Bytes::new()
    );
    assert_eq!(fs.info(&p4).await.unwrap().size, 0);

    destroy_container(&fs, &c).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn appends_and_create_new() {
    let (cs, fs, c) = setup!("append");
    let ap = WriteOptions::default().with_mode(WriteMode::Append);

    // Missing blob: created as an append blob, then appended to.
    let p = format!("{c}/log");
    fs.pipe_file(&p, Bytes::from_static(b"one "), &ap)
        .await
        .unwrap();
    fs.pipe_file(&p, Bytes::from_static(b"two"), &ap)
        .await
        .unwrap();
    assert_eq!(fs.cat_file(&p, ByteRange::Full).await.unwrap(), "one two");
    // Larger than one Append Block.
    let big = pattern((4 << 20) + 17, 9);
    let mut w = fs.open_write(&p, &ap).await.unwrap();
    w.write(big.clone()).await.unwrap();
    w.close().await.unwrap();
    let got = fs.cat_file(&p, ByteRange::Full).await.unwrap();
    assert_eq!(&got[..7], b"one two");
    assert_eq!(got.slice(7..), big);

    // Block blob uploaded with one Put Blob (no block list): re-staged.
    let b = format!("{c}/block");
    fs.pipe_file(&b, Bytes::from_static(b"head"), &WriteOptions::default())
        .await
        .unwrap();
    let mut meta = BTreeMap::new();
    meta.insert("keep".to_owned(), "me".to_owned());
    fs.set_metadata(&b, &meta).await.unwrap();
    fs.pipe_file(&b, Bytes::from_static(b"-tail"), &ap)
        .await
        .unwrap();
    assert_eq!(fs.cat_file(&b, ByteRange::Full).await.unwrap(), "head-tail");
    let i = fs.info(&b).await.unwrap();
    let Value::Map(m) = &i.extra["metadata"] else {
        panic!()
    };
    assert_eq!(
        m.get("keep"),
        Some(&Value::Str("me".into())),
        "metadata survives a block-list append"
    );
    // Now it has a block list: appended by reusing it.
    let small = filesystem(&cs, &[("blocksize", Value::Int(1 << 20))]);
    let tail = pattern((2 << 20) + 5, 4);
    small.pipe_file(&b, tail.clone(), &ap).await.unwrap();
    let got = fs.cat_file(&b, ByteRange::Full).await.unwrap();
    assert_eq!(&got[..9], b"head-tail");
    assert_eq!(got.slice(9..), tail);

    // Abort of a block-blob append leaves it untouched; of an append-blob
    // append discards unpushed data.
    for path in [&b, &p] {
        let before = fs.cat_file(path, ByteRange::Full).await.unwrap();
        let mut w = fs.open_write(path, &ap).await.unwrap();
        w.write(Bytes::from_static(b"zzz")).await.unwrap();
        w.abort().await.unwrap();
        assert_eq!(fs.cat_file(path, ByteRange::Full).await.unwrap(), before);
    }

    // Create-only.
    let x = WriteOptions::default().with_mode(WriteMode::CreateNew);
    let e = fs
        .pipe_file(&b, Bytes::from_static(b"no"), &x)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AlreadyExists);
    assert_eq!(code(&e), Some("BlobAlreadyExists"));
    let e = fs.open_write(&b, &x).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AlreadyExists);
    let n = format!("{c}/new");
    let mut w = fs.open_write(&n, &x).await.unwrap();
    // Someone else creates it meanwhile: the conditional commit catches it.
    fs.pipe_file(&n, Bytes::from_static(b"racer"), &WriteOptions::default())
        .await
        .unwrap();
    w.write(Bytes::from_static(b"mine")).await.unwrap();
    let e = w.close().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AlreadyExists);
    assert_eq!(fs.cat_file(&n, ByteRange::Full).await.unwrap(), "racer");

    destroy_container(&fs, &c).await;
}

fn env_var(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|s| !s.is_empty())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sas_anonymous_and_account_key_access() {
    let (_cs, fs, c) = setup!("access");
    let (Some(account), Some(key), Some(endpoint)) = (
        env_var("FSFAST_TEST_AZURE_ACCOUNT"),
        env_var("FSFAST_TEST_AZURE_KEY"),
        env_var("FSFAST_TEST_AZURE_ENDPOINT"),
    ) else {
        return skip(
            "sas_anonymous_and_account_key_access (FSFAST_TEST_AZURE_ACCOUNT/KEY/ENDPOINT)",
        );
    };
    fs.pipe_file(
        &format!("{c}/f"),
        Bytes::from_static(b"data"),
        &WriteOptions::default(),
    )
    .await
    .unwrap();
    let opts = |extra: &[(&str, Value)]| {
        let mut o: fsfast_core::Options = extra
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect();
        o.insert("account_name".into(), Value::Str(account.clone()));
        o.insert("account_host".into(), Value::Str(endpoint.clone()));
        o
    };

    // account_name + account_key (+ account_host with a scheme).
    let kfs = AzureBlobFileSystem::from_options_with_env(
        opts(&[("account_key", Value::Str(key.clone()))]),
        &|_| None,
    )
    .unwrap();
    assert_eq!(
        kfs.cat_file(&format!("{c}/f"), ByteRange::Full)
            .await
            .unwrap(),
        "data"
    );

    // A container SAS (racwdl) as sas_token.
    let sk = SharedKey::new(account.clone(), &key).unwrap();
    let (_, token) = BlobSas {
        container: &c,
        permission: "racwdl",
        expiry: Some(SystemTime::now() + Duration::from_secs(3600)),
        version: fsfast_azure::auth::API_VERSION,
        ..BlobSas::default()
    }
    .sign(&sk);
    let sfs = AzureBlobFileSystem::from_options_with_env(
        opts(&[("sas_token", Value::Str(format!("?{token}")))]),
        &|_| None,
    )
    .unwrap();
    assert_eq!(
        sfs.cat_file(&format!("{c}/f"), ByteRange::Full)
            .await
            .unwrap(),
        "data"
    );
    sfs.pipe_file(&format!("{c}/g"), pattern(100, 1), &WriteOptions::default())
        .await
        .unwrap();
    assert_eq!(sfs.ls(&c).await.unwrap().len(), 2);
    sfs.cp_file(&format!("{c}/g"), &format!("{c}/h"))
        .await
        .unwrap();
    sfs.rm_file(&format!("{c}/h")).await.unwrap();
    // The SAS does not reach other containers.
    let e = sfs.info(&format!("{c}x/f")).await.unwrap_err();
    assert!(
        matches!(e.kind(), ErrorKind::PermissionDenied | ErrorKind::NotFound),
        "{e}"
    );

    // A wrong key is PermissionDenied with AuthorizationFailure-family code.
    let bad = AzureBlobFileSystem::from_options_with_env(
        opts(&[("account_key", Value::Str("YmFka2V5".into()))]),
        &|_| None,
    )
    .unwrap();
    let e = bad.info(&format!("{c}/f")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");

    // Anonymous access to a public container.
    let pubc = unique_container("public");
    fs.create_container_with_access(&pubc, Some("container"))
        .await
        .unwrap();
    fs.pipe_file(
        &format!("{pubc}/p"),
        Bytes::from_static(b"open"),
        &WriteOptions::default(),
    )
    .await
    .unwrap();
    let afs =
        AzureBlobFileSystem::from_options_with_env(opts(&[("anon", Value::Bool(true))]), &|_| None)
            .unwrap();
    assert!(afs.credential().is_anonymous());
    assert_eq!(
        afs.cat_file(&format!("{pubc}/p"), ByteRange::Full)
            .await
            .unwrap(),
        "open"
    );
    assert_eq!(afs.ls(&pubc).await.unwrap().len(), 1);
    let e = afs
        .cat_file(&format!("{c}/f"), ByteRange::Full)
        .await
        .unwrap_err();
    assert!(
        matches!(e.kind(), ErrorKind::PermissionDenied | ErrorKind::NotFound),
        "{e}"
    );

    destroy_container(&fs, &pubc).await;
    destroy_container(&fs, &c).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn special_blob_names() {
    let (_cs, fs, c) = setup!("names");
    for name in [
        "a b+c%20d",
        "ü/名前",
        "q?x=1",
        "hash#x",
        "semi;colon",
        "dots..",
        "x~y",
    ] {
        let p = format!("{c}/{name}");
        fs.pipe_file(
            &p,
            Bytes::copy_from_slice(name.as_bytes()),
            &WriteOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            fs.cat_file(&p, ByteRange::Full).await.unwrap(),
            name.as_bytes(),
            "{name}"
        );
        assert_eq!(fs.info(&p).await.unwrap().name, p);
    }
    let all = fs.find(&c, &FindOptions::default()).await.unwrap();
    assert_eq!(all.len(), 7, "{all:?}");
    destroy_container(&fs, &c).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paginated_listings_and_version_keys() {
    let (cs, fs, c) = setup!("pages");
    // Tiny pages: every listing follows NextMarker.
    let paged = filesystem(
        &cs,
        &[
            ("list_page_size", Value::Int(3)),
            ("version_aware", Value::Bool(true)),
        ],
    );
    let w = WriteOptions::default();
    for i in 0..10 {
        fs.pipe_file(&format!("{c}/d/f{i:02}"), Bytes::from_static(b"x"), &w)
            .await
            .unwrap();
        fs.pipe_file(&format!("{c}/s{i:02}/x"), Bytes::from_static(b"y"), &w)
            .await
            .unwrap();
    }
    assert_eq!(paged.ls(&format!("{c}/d")).await.unwrap().len(), 10);
    assert_eq!(paged.ls(&c).await.unwrap().len(), 11);
    assert_eq!(
        paged.find(&c, &FindOptions::default()).await.unwrap().len(),
        20
    );
    let found = paged
        .find(
            &c,
            &FindOptions {
                maxdepth: Some(1),
                withdirs: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(found.len(), 12, "root + 11 first-level directories");
    // Version-aware filesystems report the version keys.
    let i = paged.info(&format!("{c}/d/f00")).await.unwrap();
    assert!(i.extra.contains_key("version_id") && i.extra.contains_key("is_current_version"));
    assert!(paged.capabilities().versioning);
    assert!(!fs.capabilities().versioning);
    let e = fs
        .open_read(
            &format!("{c}/d/f00"),
            &ReadOptions {
                version: Some("v".into()),
                ..ReadOptions::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
    destroy_container(&fs, &c).await;
}
