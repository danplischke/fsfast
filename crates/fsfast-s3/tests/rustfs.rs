//! Integration tests against the local RustFS S3 server, including the
//! fsfast-testkit conformance suite in a fresh bucket.
//!
//! Gated on `FSFAST_TEST_S3_ENDPOINT`, `FSFAST_TEST_S3_KEY` and
//! `FSFAST_TEST_S3_SECRET` (`eval "$(scripts/test-services.sh env)"`).

mod common;

use std::sync::Arc;

use bytes::Bytes;
use common::{destroy_bucket, filesystem, s3_env, skip, unique_bucket};
use fsfast_core::{
    ByteRange, ErrorKind, FileSystem, FindOptions, ReadOptions, Value, WriteMode, WriteOptions,
};
use fsfast_testkit::{SuiteConfig, assert_suite};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conformance_suite() {
    let Some(env) = s3_env() else {
        return skip("conformance_suite");
    };
    let fs = filesystem(&env, &[]);
    let bucket = unique_bucket("conf");
    fs.mkdir(&bucket, true).await.unwrap();
    let dynfs: Arc<dyn FileSystem> = Arc::new(fs.clone());
    let report = assert_suite(
        dynfs,
        &format!("{bucket}/suite"),
        SuiteConfig::default().parallelism(4),
    )
    .await;
    eprintln!("{report}");
    destroy_bucket(&fs, &bucket).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3fs_directory_semantics() {
    let Some(env) = s3_env() else {
        return skip("s3fs_directory_semantics");
    };
    let fs = filesystem(&env, &[]);
    let b = unique_bucket("dirs");
    fs.mkdir(&b, true).await.unwrap();
    // mkdir of an existing bucket fails; below a bucket it is a no-op.
    assert_eq!(
        fs.mkdir(&b, true).await.unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );
    fs.mkdir(&format!("{b}/x/y"), true).await.unwrap();
    fs.makedirs(&b, true).await.unwrap();
    assert_eq!(
        fs.makedirs(&b, false).await.unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );

    let w = WriteOptions::default();
    for (k, v) in [
        ("a/b/c.txt", &b"hello"[..]),
        ("a/x.txt", b"hey"),
        ("top.txt", b"t"),
        ("emptydir/", b""),
    ] {
        fs.pipe_file(&format!("{b}/{k}"), Bytes::from_static(v), &w)
            .await
            .unwrap();
    }
    let info = fs.info(&format!("{b}/a/x.txt")).await.unwrap();
    assert!(info.is_file());
    assert_eq!(info.size, 3);
    for k in [
        "ETag",
        "LastModified",
        "StorageClass",
        "VersionId",
        "ContentType",
    ] {
        assert!(info.extra.contains_key(k), "{k} missing: {info:?}");
    }
    let d = fs.info(&format!("{b}/a")).await.unwrap();
    assert!(d.is_dir());
    assert_eq!(d.name, format!("{b}/a"));
    assert_eq!(d.extra["StorageClass"], Value::Str("DIRECTORY".into()));
    let e = fs.info(&format!("{b}/emptydir/")).await.unwrap();
    assert!(e.is_dir());
    let bi = fs.info(&b).await.unwrap();
    assert!(bi.is_dir());
    assert_eq!(bi.extra["VersionId"], Value::Null);
    assert_eq!(
        fs.info(&format!("{b}/nope")).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        fs.info("fsfast-no-such-bucket-zz")
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );

    let names = |v: Vec<fsfast_core::FileInfo>| v.into_iter().map(|i| i.name).collect::<Vec<_>>();
    assert_eq!(
        names(fs.ls(&b).await.unwrap()),
        vec![
            format!("{b}/a"),
            format!("{b}/emptydir"),
            format!("{b}/top.txt")
        ]
    );
    // An "empty directory" lists its placeholder (s3fs).
    assert_eq!(
        names(fs.ls(&format!("{b}/emptydir")).await.unwrap()),
        vec![format!("{b}/emptydir/")]
    );
    assert_eq!(
        names(fs.ls(&format!("{b}/a/x.txt")).await.unwrap()),
        vec![format!("{b}/a/x.txt")]
    );
    assert_eq!(
        fs.ls(&format!("{b}/nope")).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    let buckets = names(fs.ls("").await.unwrap());
    assert!(buckets.contains(&b));

    let all = names(fs.find(&b, &FindOptions::default()).await.unwrap());
    assert_eq!(
        all,
        vec![
            format!("{b}/a/b/c.txt"),
            format!("{b}/a/x.txt"),
            format!("{b}/emptydir/"),
            format!("{b}/top.txt")
        ]
    );
    let withdirs = names(
        fs.find(
            &b,
            &FindOptions {
                maxdepth: None,
                withdirs: true,
            },
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        withdirs,
        vec![
            format!("{b}/a"),
            format!("{b}/a/b"),
            format!("{b}/a/b/c.txt"),
            format!("{b}/a/x.txt"),
            format!("{b}/emptydir"),
            format!("{b}/emptydir/"),
            format!("{b}/top.txt")
        ]
    );
    let depth1 = names(
        fs.find(
            &b,
            &FindOptions {
                maxdepth: Some(1),
                withdirs: true,
            },
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        depth1,
        vec![
            b.clone(),
            format!("{b}/a"),
            format!("{b}/emptydir"),
            format!("{b}/top.txt")
        ]
    );
    assert!(fs.exists(&b).await.unwrap());
    assert!(fs.exists(&format!("{b}/a")).await.unwrap());
    assert!(!fs.exists(&format!("{b}/nope")).await.unwrap());
    assert!(!fs.exists("fsfast-no-such-bucket-zz").await.unwrap());

    // rmdir: non-empty bucket, then emulated directory, then empty bucket.
    assert_eq!(
        fs.rmdir(&b).await.unwrap_err().kind(),
        ErrorKind::DirectoryNotEmpty
    );
    assert_eq!(
        fs.rmdir(&format!("{b}/a")).await.unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );
    destroy_bucket(&fs, &b).await;
    assert!(!fs.exists(&b).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reads_writes_and_copies() {
    let Some(env) = s3_env() else {
        return skip("reads_writes_and_copies");
    };
    let fs = filesystem(
        &env,
        &[
            ("request_size", Value::Int(1 << 20)),
            ("part_size", Value::Int(5 << 20)),
            ("copy_threshold", Value::Int(8 << 20)),
            ("copy_part_size", Value::Int(5 << 20)),
        ],
    );
    let b = unique_bucket("rw");
    fs.mkdir(&b, true).await.unwrap();
    let big: Bytes = (0..(13u32 << 20))
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>()
        .into();
    let p = format!("{b}/big.bin");
    fs.pipe_file(&p, big.clone(), &WriteOptions::default())
        .await
        .unwrap();
    assert_eq!(fs.info(&p).await.unwrap().size, big.len() as u64);
    // Multipart ETag ("-N" suffix): the object was uploaded in parts.
    let etag = fs.info(&p).await.unwrap().version.unwrap();
    assert!(etag.contains('-'), "{etag}");
    assert_eq!(fs.cat_file(&p, ByteRange::Full).await.unwrap(), big);
    assert_eq!(
        fs.cat_file(
            &p,
            ByteRange::Bounded {
                start: 100,
                end: 3 << 20
            }
        )
        .await
        .unwrap(),
        big.slice(100..3 << 20)
    );
    assert_eq!(
        fs.cat_file(&p, ByteRange::Suffix(10)).await.unwrap(),
        big.slice(big.len() - 10..)
    );
    assert_eq!(
        fs.cat_file(&p, ByteRange::From(big.len() as u64 + 5))
            .await
            .unwrap(),
        Bytes::new()
    );
    let h = fs.open_read(&p, &ReadOptions::default()).await.unwrap();
    assert_eq!(
        h.read_at(5 << 20, 4 << 20).await.unwrap(),
        big.slice(5 << 20..9 << 20)
    );
    let r = h
        .read_ranges(&[0..10, (12 << 20)..(13 << 20) + 99])
        .await
        .unwrap();
    assert_eq!(r[0], big.slice(0..10));
    assert_eq!(r[1], big.slice(12 << 20..));
    // Replacing the object breaks the pinned handle cleanly.
    fs.pipe_file(
        &p,
        Bytes::from_static(b"replaced"),
        &WriteOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        h.read_at(0, 10).await.unwrap_err().kind(),
        ErrorKind::PreconditionFailed
    );

    // Copy (multipart above copy_threshold, single request below) and
    // append.
    let mut meta = std::collections::BTreeMap::new();
    meta.insert("origin".to_owned(), "test".to_owned());
    let opts = WriteOptions {
        content_type: Some("application/x-test".into()),
        metadata: meta,
        ..WriteOptions::default()
    };
    fs.pipe_file(&p, big.clone(), &opts).await.unwrap();
    let c = format!("{b}/copy.bin");
    fs.cp_file(&p, &c).await.unwrap();
    assert_eq!(fs.cat_file(&c, ByteRange::Full).await.unwrap(), big);
    let ci = fs.info(&c).await.unwrap();
    assert_eq!(
        ci.extra["ContentType"],
        Value::Str("application/x-test".into())
    );
    assert!(ci.version.unwrap().contains('-'), "multipart copy");
    let small = format!("{b}/small.bin");
    fs.pipe_file(&small, Bytes::from_static(b"small"), &opts)
        .await
        .unwrap();
    fs.cp_file(&small, &format!("{b}/small2.bin"))
        .await
        .unwrap();
    let si = fs.info(&format!("{b}/small2.bin")).await.unwrap();
    assert_eq!(
        si.extra["ContentType"],
        Value::Str("application/x-test".into())
    );
    fs.mv_file(&format!("{b}/small2.bin"), &format!("{b}/moved.bin"))
        .await
        .unwrap();
    assert!(!fs.exists(&format!("{b}/small2.bin")).await.unwrap());
    assert_eq!(
        fs.cat_file(&format!("{b}/moved.bin"), ByteRange::Full)
            .await
            .unwrap(),
        Bytes::from_static(b"small")
    );
    let mut w = fs
        .open_write(&c, &WriteOptions::default().with_mode(WriteMode::Append))
        .await
        .unwrap();
    w.write(Bytes::from_static(b"tail")).await.unwrap();
    w.close().await.unwrap();
    let got = fs.cat_file(&c, ByteRange::Full).await.unwrap();
    assert_eq!(got.len(), big.len() + 4);
    assert_eq!(&got[big.len()..], b"tail");

    // Create-only writes.
    let x = format!("{b}/x");
    let cn = WriteOptions::default().with_mode(WriteMode::CreateNew);
    fs.pipe_file(&x, Bytes::from_static(b"1"), &cn)
        .await
        .unwrap();
    assert_eq!(
        fs.pipe_file(&x, Bytes::from_static(b"2"), &cn)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::AlreadyExists
    );
    assert_eq!(
        fs.cat_file(&x, ByteRange::Full).await.unwrap(),
        Bytes::from_static(b"1")
    );

    // Presigned URL works with a plain HTTP client.
    let url = fs
        .sign(&c, std::time::Duration::from_secs(300))
        .await
        .unwrap();
    let http = fs.http_client().await.unwrap();
    let resp = http
        .send(fsfast_http_transport::Request::get(&url).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.bytes().await.unwrap().len(), big.len() + 4);
    destroy_bucket(&fs, &b).await;
}
