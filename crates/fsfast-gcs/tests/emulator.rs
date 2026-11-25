//! gcsfs semantics against fake-gcs-server: entry shapes, directory and
//! bucket semantics, uploads on every path (one request, resumable with
//! several chunks, create-only, from disk), downloads (parallel parts,
//! CRC32C), copies, moves, compose, odd object names.
//!
//! Gated on `FSFAST_TEST_GCS_ENDPOINT` (`eval "$(scripts/test-services.sh env)"`).
//! fake-gcs-server quirks this suite works around rather than bending the
//! semantics: no object versioning (fs backend), `ifGenerationMatch` is
//! ignored on downloads and rewrites, `objects.move` is missing (moves fall
//! back to copy + delete), deleting a non-empty bucket answers 412 (GCS:
//! 409), list responses carry `acl` (GCS: only with `projection=full`).

mod common;

use bytes::Bytes;
use common::{destroy_bucket, endpoint, filesystem, skip, unique_bucket};
use fsfast_core::{
    ByteRange, ErrorKind, FileSystem, FindOptions, ReadOptions, Value, WriteMode, WriteOptions,
};
use fsfast_gcs::GCSFileSystem;

async fn setup(tag: &str, extra: &[(&str, Value)]) -> Option<(GCSFileSystem, String)> {
    let ep = endpoint()?;
    let fs = filesystem(&ep, extra);
    let b = unique_bucket(tag);
    fs.mkdir(&b, false).await.unwrap();
    Some((fs, b))
}

fn pattern(len: usize, seed: u8) -> Bytes {
    Bytes::from(
        (0..len)
            .map(|i| ((i as u64).wrapping_mul(2_654_435_761) >> 13) as u8 ^ seed)
            .collect::<Vec<u8>>(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn entries_have_gcsfs_keys() {
    let Some((fs, b)) = setup("keys", &[]).await else {
        return skip("entries_have_gcsfs_keys");
    };
    let w = WriteOptions::default();
    fs.pipe_file(
        &format!("{b}/a/b/c.txt"),
        Bytes::from_static(b"hello world"),
        &w,
    )
    .await
    .unwrap();
    fs.pipe_file(
        &format!("{b}/top.bin"),
        Bytes::from_static(b"0123456789"),
        &w,
    )
    .await
    .unwrap();
    fs.pipe_file(&format!("{b}/marker/"), Bytes::new(), &w)
        .await
        .unwrap();
    fs.pipe_file(&format!("{b}/marker/inside"), Bytes::from_static(b"i"), &w)
        .await
        .unwrap();

    let i = fs.info(&format!("gs://{b}/a/b/c.txt")).await.unwrap();
    assert_eq!(i.name, format!("{b}/a/b/c.txt"));
    assert_eq!(i.size, 11);
    assert!(i.is_file());
    for k in [
        "bucket",
        "contentType",
        "crc32c",
        "etag",
        "generation",
        "metageneration",
        "md5Hash",
        "kind",
        "id",
        "selfLink",
        "mediaLink",
        "storageClass",
        "timeCreated",
        "updated",
        "mtime",
        "ctime",
    ] {
        assert!(
            i.extra.contains_key(k),
            "{k} missing from {:?}",
            i.extra.keys()
        );
    }
    assert_eq!(i.extra["crc32c"], Value::from("yZRlqg=="));
    assert_eq!(i.extra["md5Hash"], Value::from("XrY7u+Ae7tCTyyK7j1rNww=="));
    assert!(matches!(i.extra["mtime"], Value::Time(_)));
    assert!(matches!(i.extra["generation"], Value::Str(_)));
    assert_eq!(
        i.version.as_ref(),
        i.extra["generation"].as_str().map(str::to_owned).as_ref()
    );
    assert!(i.modified.is_some() && i.created.is_some());

    let d = fs.info(&format!("{b}/a/")).await.unwrap();
    assert!(d.is_dir());
    assert_eq!(d.name, format!("{b}/a"));
    assert_eq!(d.extra["storageClass"], Value::from("DIRECTORY"));
    assert_eq!(d.extra["bucket"], Value::from(b.as_str()));
    // A directory marker counts as a directory.
    let m = fs.info(&format!("{b}/marker")).await.unwrap();
    assert!(m.is_dir());

    let bi = fs.info(&b).await.unwrap();
    assert!(bi.is_dir());
    assert_eq!(bi.name, b);
    assert_eq!(bi.extra["kind"], Value::from("storage#bucket"));

    // ls: directories from prefixes, files with full resources, sorted.
    let ls = fs.ls(&b).await.unwrap();
    let names: Vec<_> = ls.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        [
            format!("{b}/a"),
            format!("{b}/marker"),
            format!("{b}/top.bin")
        ]
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
    );
    assert!(ls[0].is_dir() && ls[1].is_dir() && ls[2].is_file());
    // Listing a directory with a marker reports the directory itself too
    // (gcsfs turns the marker into an entry for the listed path).
    let lm = fs.ls(&format!("{b}/marker/")).await.unwrap();
    let names: Vec<_> = lm.iter().map(|e| (e.name.clone(), e.is_dir())).collect();
    // fake-gcs-server quirk: a delimited listing leaves out the object
    // equal to the prefix (GCS includes it), so the marker entry is
    // missing there; gcsfs shows the same against the emulator.
    let inside = (format!("{b}/marker/inside"), false);
    assert!(
        names == vec![(format!("{b}/marker"), true), inside.clone()] || names == vec![inside],
        "{names:?}"
    );
    // Listing a file is the file.
    let lf = fs.ls(&format!("{b}/top.bin")).await.unwrap();
    assert_eq!(lf.len(), 1);
    assert_eq!(lf[0].size, 10);

    // find: flat, with s3fs-style keys for the derived directories; the
    // marker object itself is listed as a file (rm recursive deletes it).
    let all = fs
        .find(
            &b,
            &FindOptions {
                maxdepth: None,
                withdirs: true,
            },
        )
        .await
        .unwrap();
    let names: Vec<_> = all.iter().map(|e| e.name.clone()).collect();
    let mut want = vec![
        format!("{b}/a"),
        format!("{b}/a/b"),
        format!("{b}/a/b/c.txt"),
        format!("{b}/marker"),
        format!("{b}/marker/"),
        format!("{b}/marker/inside"),
        format!("{b}/top.bin"),
    ];
    // fake-gcs-server quirk: its storage drops the object `marker/` once
    // `marker/inside` exists (GCS keeps both); gcsfs sees the same.
    if !names.contains(&format!("{b}/marker/")) {
        want.retain(|n| *n != format!("{b}/marker/"));
    }
    assert_eq!(names, want);
    let ab = &all[1];
    assert_eq!(ab.extra["Key"], Value::from("a/b"));
    assert_eq!(ab.extra["StorageClass"], Value::from("DIRECTORY"));
    assert_eq!(ab.extra["Size"], Value::Int(0));
    let depth1 = fs
        .find(
            &b,
            &FindOptions {
                maxdepth: Some(1),
                withdirs: true,
            },
        )
        .await
        .unwrap();
    let names: Vec<_> = depth1.iter().map(|e| e.name.clone()).collect();
    assert_eq!(
        names,
        vec![
            format!("{b}/a"),
            format!("{b}/marker"),
            format!("{b}/top.bin")
        ]
    );
    assert_eq!(
        fs.find(
            &b,
            &FindOptions {
                maxdepth: Some(0),
                withdirs: false
            }
        )
        .await
        .unwrap_err()
        .kind(),
        ErrorKind::InvalidInput
    );

    // ls("") lists buckets as "bucket/".
    let roots = fs.ls("").await.unwrap();
    assert!(
        roots
            .iter()
            .any(|e| e.name == format!("{b}/") && e.is_dir()),
        "{roots:?}"
    );
    assert!(fs.buckets().await.unwrap().contains(&b));

    for missing in [
        format!("{b}/nope"),
        format!("{b}/a/nope/deeper"),
        "fsfast-no-such-bucket-xyz".to_owned(),
    ] {
        let e = fs.info(&missing).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotFound, "{missing}: {e}");
    }
    assert_eq!(
        fs.ls(&format!("{b}/nope")).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert!(
        fs.find(&format!("{b}/nope"), &FindOptions::default())
            .await
            .unwrap()
            .is_empty()
    );
    destroy_bucket(&fs, &b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn buckets_and_directories_behave_like_gcsfs() {
    let Some((fs, b)) = setup("dirs", &[]).await else {
        return skip("buckets_and_directories_behave_like_gcsfs");
    };
    assert_eq!(
        fs.mkdir(&b, false).await.unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );
    fs.mkdir(&format!("{b}/x/y"), false).await.unwrap();
    assert!(
        fs.info(&format!("{b}/x")).await.is_err(),
        "mkdir below a bucket creates nothing"
    );
    let other = unique_bucket("dirs2");
    assert_eq!(
        fs.mkdir(&format!("{other}/sub"), false)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    fs.mkdir(&format!("{other}/sub"), true).await.unwrap();
    assert!(fs.info(&other).await.unwrap().is_dir());
    // makedirs is a no-op, as in gcsfs.
    fs.makedirs(&format!("{b}/q/r"), false).await.unwrap();
    // rmdir: no-op below a bucket, refuses a non-empty bucket.
    fs.pipe_file(
        &format!("{b}/q/f"),
        Bytes::from_static(b"d"),
        &WriteOptions::default(),
    )
    .await
    .unwrap();
    fs.rmdir(&format!("{b}/q")).await.unwrap();
    // A leading slash names the same bucket (gcsfs `lstrip("/")`): its
    // root is a directory, not an object with an empty name.
    let slashed = fs.info(&format!("/{b}")).await.unwrap();
    assert!(slashed.is_dir(), "{slashed:?}");
    assert!(fs.info(&format!("/{b}/q")).await.unwrap().is_dir());
    assert_eq!(
        fs.cat_file(&format!("{b}/q/f"), ByteRange::Full)
            .await
            .unwrap(),
        Bytes::from_static(b"d")
    );
    assert_eq!(
        fs.rmdir(&b).await.unwrap_err().kind(),
        ErrorKind::DirectoryNotEmpty
    );
    // rm_file of a bare bucket deletes an empty bucket (gcsfs).
    fs.rm_file(&other).await.unwrap();
    assert_eq!(
        fs.info(&other).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        fs.rmdir(&other).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    // rm_file of a directory fails without deleting anything.
    assert_eq!(
        fs.rm_file(&format!("{b}/q")).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    destroy_bucket(&fs, &b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uploads_on_every_path() {
    let Some((fs, b)) = setup(
        "up",
        &[
            ("upload_chunk_size", Value::Int(256 << 10)),
            ("simple_upload_threshold", Value::Int(300 << 10)),
            ("consistency", Value::from("md5")),
        ],
    )
    .await
    else {
        return skip("uploads_on_every_path");
    };
    // Streamed through a resumable session: many chunks plus a tail.
    let data = pattern((5 << 20) / 2 + 12_345, 1);
    let p = format!("{b}/stream.bin");
    let mut w = fs.open_write(&p, &WriteOptions::default()).await.unwrap();
    for piece in data.chunks(77_777) {
        w.write(Bytes::copy_from_slice(piece)).await.unwrap();
    }
    assert_eq!(w.bytes_written(), data.len() as u64);
    w.close().await.unwrap();
    assert_eq!(fs.cat_file(&p, ByteRange::Full).await.unwrap(), data);
    // Exactly one chunk long: the last request only finalizes.
    let exact = pattern(256 << 10, 2);
    let pe = format!("{b}/exact.bin");
    let mut w = fs.open_write(&pe, &WriteOptions::default()).await.unwrap();
    w.write(exact.clone()).await.unwrap();
    w.close().await.unwrap();
    assert_eq!(fs.cat_file(&pe, ByteRange::Full).await.unwrap(), exact);
    // pipe_file above the one-request threshold uses a session too.
    let big = pattern(700 << 10, 3);
    let pb = format!("{b}/piped.bin");
    fs.pipe_file(&pb, big.clone(), &WriteOptions::default())
        .await
        .unwrap();
    assert_eq!(fs.cat_file(&pb, ByteRange::Full).await.unwrap(), big);
    // Create-only on both paths.
    let cn = WriteOptions::default().with_mode(WriteMode::CreateNew);
    assert_eq!(
        fs.pipe_file(&pb, Bytes::from_static(b"x"), &cn)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::AlreadyExists
    );
    assert_eq!(
        fs.pipe_file(&pb, big.clone(), &cn)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::AlreadyExists
    );
    // A create-only open of an existing object fails at open, like a local
    // file opened with O_EXCL.
    assert_eq!(
        fs.open_write(&pb, &cn).await.err().map(|e| e.kind()),
        Some(ErrorKind::AlreadyExists)
    );
    assert_eq!(fs.cat_file(&pb, ByteRange::Full).await.unwrap(), big);
    // Content type, metadata and fixed-key metadata.
    let mut o = WriteOptions {
        content_type: Some("text/plain".into()),
        ..WriteOptions::default()
    };
    o.metadata.insert("color".into(), "blue".into());
    let mut fixed = std::collections::BTreeMap::new();
    fixed.insert("cache_control".to_owned(), Value::from("no-cache"));
    o.extra
        .insert("fixed_key_metadata".into(), Value::Map(fixed));
    fs.pipe_file(&format!("{b}/meta.txt"), Bytes::from_static(b"m"), &o)
        .await
        .unwrap();
    let i = fs.info(&format!("{b}/meta.txt")).await.unwrap();
    assert_eq!(i.extra["contentType"], Value::from("text/plain"));
    match &i.extra["metadata"] {
        Value::Map(m) => assert_eq!(m["color"], Value::from("blue")),
        other => panic!("metadata: {other:?}"),
    }
    // The file name decides the default content type of open().
    let mut w = fs
        .open_write(&format!("{b}/t.json"), &WriteOptions::default())
        .await
        .unwrap();
    w.write(Bytes::from_static(b"{}")).await.unwrap();
    w.close().await.unwrap();
    assert_eq!(
        fs.info(&format!("{b}/t.json")).await.unwrap().extra["contentType"],
        Value::from("application/json")
    );
    // An aborted stream leaves nothing.
    let mut w = fs
        .open_write(&format!("{b}/aborted.bin"), &WriteOptions::default())
        .await
        .unwrap();
    w.write(pattern(600 << 10, 4)).await.unwrap();
    w.abort().await.unwrap();
    assert_eq!(
        fs.info(&format!("{b}/aborted.bin"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    // touch.
    let t = format!("{b}/touched");
    fs.touch(&t, false).await.unwrap();
    assert_eq!(fs.info(&t).await.unwrap().size, 0);
    fs.pipe_file(&t, Bytes::from_static(b"data"), &WriteOptions::default())
        .await
        .unwrap();
    assert_eq!(
        fs.touch(&t, false).await.unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    fs.touch(&t, true).await.unwrap();
    assert_eq!(fs.info(&t).await.unwrap().size, 0);
    destroy_bucket(&fs, &b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_files_round_trip() {
    let Some((fs, b)) = setup(
        "files",
        &[
            ("request_size", Value::Int(1 << 20)),
            ("upload_chunk_size", Value::Int(1 << 20)),
        ],
    )
    .await
    else {
        return skip("local_files_round_trip");
    };
    let dir = tempfile::tempdir().unwrap();
    for (name, len) in [("small.csv", 1000usize), ("large.bin", (9 << 20) + 4321)] {
        let data = pattern(len, len as u8);
        let src = dir.path().join(name);
        std::fs::write(&src, &data).unwrap();
        let remote = format!("{b}/up/{name}");
        fs.put_file(&src, &remote, &WriteOptions::default())
            .await
            .unwrap();
        let i = fs.info(&remote).await.unwrap();
        assert_eq!(i.size, len as u64);
        if name.ends_with(".csv") {
            assert_eq!(i.extra["contentType"], Value::from("text/csv"));
        }
        let dst = dir.path().join("down").join(name);
        fs.get_file(&remote, &dst).await.unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), data.to_vec());
        assert_eq!(fs.cat_file(&remote, ByteRange::Full).await.unwrap(), data);
        // Parallel reads through a handle.
        let h = fs
            .open_read(&remote, &ReadOptions::default())
            .await
            .unwrap();
        let mid = len / 3;
        let got = h.read_at(mid as u64, len - mid).await.unwrap();
        assert_eq!(got, data.slice(mid..));
        let ranges = vec![0..10u64, (len as u64 - 5)..(len as u64 + 100), 7..7];
        let rr = fs.cat_ranges(&remote, &ranges).await.unwrap();
        assert_eq!(rr[0], data.slice(0..10));
        assert_eq!(rr[1], data.slice(len - 5..));
        assert!(rr[2].is_empty());
    }
    // Ranges.
    let remote = format!("{b}/up/small.csv");
    let data = pattern(1000, (1000usize) as u8);
    assert_eq!(
        fs.cat_file(&remote, ByteRange::Suffix(10)).await.unwrap(),
        data.slice(990..)
    );
    assert_eq!(
        fs.cat_file(&remote, ByteRange::From(995)).await.unwrap(),
        data.slice(995..)
    );
    assert!(
        fs.cat_file(&remote, ByteRange::From(5000))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fs.cat_file(&remote, ByteRange::Bounded { start: 10, end: 20 })
            .await
            .unwrap(),
        data.slice(10..20)
    );
    destroy_bucket(&fs, &b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn copies_moves_and_compose() {
    let Some((fs, b)) = setup("cp", &[]).await else {
        return skip("copies_moves_and_compose");
    };
    let w = WriteOptions::default();
    fs.pipe_file(&format!("{b}/a"), Bytes::from_static(b"AAA"), &w)
        .await
        .unwrap();
    fs.pipe_file(&format!("{b}/b"), Bytes::from_static(b"BB"), &w)
        .await
        .unwrap();
    fs.cp_file(&format!("{b}/a"), &format!("{b}/dir/copy"))
        .await
        .unwrap();
    assert_eq!(
        fs.cat_file(&format!("{b}/dir/copy"), ByteRange::Full)
            .await
            .unwrap(),
        Bytes::from_static(b"AAA")
    );
    // Across buckets.
    let b2 = unique_bucket("cp2");
    fs.mkdir(&b2, false).await.unwrap();
    fs.cp_file(&format!("{b}/a"), &format!("{b2}/x"))
        .await
        .unwrap();
    assert_eq!(
        fs.cat_file(&format!("{b2}/x"), ByteRange::Full)
            .await
            .unwrap(),
        Bytes::from_static(b"AAA")
    );
    // Moves fall back to copy + delete on the emulator.
    fs.mv_file(&format!("{b}/b"), &format!("{b}/moved"))
        .await
        .unwrap();
    assert_eq!(
        fs.info(&format!("{b}/b")).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        fs.cat_file(&format!("{b}/moved"), ByteRange::Full)
            .await
            .unwrap(),
        Bytes::from_static(b"BB")
    );
    fs.mv_file(&format!("{b2}/x"), &format!("{b}/from-b2"))
        .await
        .unwrap();
    assert_eq!(
        fs.cat_file(&format!("{b}/from-b2"), ByteRange::Full)
            .await
            .unwrap(),
        Bytes::from_static(b"AAA")
    );
    assert_eq!(
        fs.mv_file(&format!("{b}/nope"), &format!("{b}/x"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        fs.cp_file(&format!("{b}/nope"), &format!("{b}/x"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    // Compose.
    fs.merge(
        &format!("{b}/merged"),
        &[format!("{b}/a"), format!("{b}/moved"), format!("{b}/a")],
    )
    .await
    .unwrap();
    assert_eq!(
        fs.cat_file(&format!("{b}/merged"), ByteRange::Full)
            .await
            .unwrap(),
        Bytes::from_static(b"AAABBAAA")
    );
    destroy_bucket(&fs, &b).await;
    destroy_bucket(&fs, &b2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn odd_object_names_round_trip() {
    let Some((fs, b)) = setup("names", &[]).await else {
        return skip("odd_object_names_round_trip");
    };
    let names = [
        "with space.txt",
        "plus+sign",
        "percent%20encoded",
        "hash#frag",
        "question?mark=1",
        "amp&semi;",
        "ünïcödé/名前.bin",
        "tilde~",
        "quote'\"",
        "/leading-slash",
        "dir//double",
        "colon:name",
    ];
    for n in names {
        let p = format!("{b}/{n}");
        fs.pipe_file(
            &p,
            Bytes::copy_from_slice(n.as_bytes()),
            &WriteOptions::default(),
        )
        .await
        .unwrap();
        let i = fs.info(&p).await.unwrap();
        assert_eq!(i.name, p, "{n}");
        assert_eq!(i.size, n.len() as u64, "{n}");
        assert_eq!(
            fs.cat_file(&p, ByteRange::Full).await.unwrap(),
            n.as_bytes(),
            "{n}"
        );
        let h = fs.open_read(&p, &ReadOptions::default()).await.unwrap();
        assert_eq!(h.read_at(0, 100).await.unwrap(), n.as_bytes());
    }
    let found = fs.find(&b, &FindOptions::default()).await.unwrap();
    assert_eq!(found.len(), names.len());
    for n in names {
        fs.rm_file(&format!("{b}/{n}")).await.unwrap();
    }
    assert_eq!(
        fs.info(&format!("{b}/.")).await.unwrap_err().kind(),
        ErrorKind::InvalidInput,
        "'.' cannot be addressed"
    );
    destroy_bucket(&fs, &b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_small_objects_concurrently() {
    let Some((fs, b)) = setup("many", &[]).await else {
        return skip("many_small_objects_concurrently");
    };
    let paths: Vec<String> = (0..300).map(|i| format!("{b}/many/{i:04}")).collect();
    let wopts = WriteOptions::default();
    let futs: Vec<_> = paths
        .iter()
        .map(|p| fs.pipe_file(p, Bytes::copy_from_slice(p.as_bytes()), &wopts))
        .collect();
    for r in futures::future::join_all(futs).await {
        r.unwrap();
    }
    let listed = fs.ls(&format!("{b}/many")).await.unwrap();
    assert_eq!(listed.len(), 300);
    let found = fs
        .find(&format!("{b}/many"), &FindOptions::default())
        .await
        .unwrap();
    assert_eq!(found.len(), 300);
    let futs: Vec<_> = paths
        .iter()
        .map(|p| fs.cat_file(p, ByteRange::Full))
        .collect();
    for (p, r) in paths.iter().zip(futures::future::join_all(futs).await) {
        assert_eq!(r.unwrap(), p.as_bytes());
    }
    let mut with_missing = paths.clone();
    with_missing.push(format!("{b}/many/missing"));
    let res = fs.rm_files(&with_missing).await;
    assert!(res[..300].iter().all(|r| r.is_ok()));
    assert_eq!(res[300].as_ref().unwrap_err().kind(), ErrorKind::NotFound);
    destroy_bucket(&fs, &b).await;
}
