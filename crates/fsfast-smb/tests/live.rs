//! Live tests against the local Samba (signing-required share `data` and
//! encryption-required share `enc`). Gated on `FSFAST_TEST_SMB_HOST`.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use fsfast_core::{
    ByteRange, Detail, ErrorKind, FileSystem, FindOptions, ReadOptions, Value, WriteMode,
    WriteOptions,
};
use fsfast_smb::SmbFileSystem;
use futures::StreamExt;

fn nt(e: &fsfast_core::Error) -> Option<u32> {
    e.details().iter().find_map(|d| match d {
        Detail::NtStatus(s) => Some(*s),
        _ => None,
    })
}

async fn frames(fs: &SmbFileSystem, share: &str) -> u64 {
    fs.connection_info(share).await.unwrap().frames_sent
}

/// A scratch directory on `share`, removed by the guard's `finish`.
async fn scratch(fs: &SmbFileSystem, share: &str, tag: &str) -> String {
    let root = format!("/{share}/{}", common::unique(tag));
    fs.mkdir(&root, false).await.unwrap();
    root
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn smoke_both_shares() {
    let Some(env) = common::env() else { return };
    for share in [env.share.clone(), env.enc_share.clone()] {
        let fs = env.fs(&[]);
        let i = fs
            .info(&format!("/{share}"))
            .await
            .expect("info share root");
        assert!(i.is_dir(), "{i:?}");
        assert_eq!(i.name, format!("/{share}"));
        let root = scratch(&fs, &share, "smoke").await;
        let f = format!("{root}/hello.txt");
        fs.pipe_file(
            &f,
            Bytes::from_static(b"hello world"),
            &WriteOptions::default(),
        )
        .await
        .expect("pipe");
        let got = fs.cat_file(&f, ByteRange::Full).await.expect("cat");
        assert_eq!(&got[..], b"hello world");
        let ls = fs.ls(&root).await.expect("ls");
        assert_eq!(ls.len(), 1);
        assert_eq!(ls[0].name, f);
        assert_eq!(ls[0].size, 11);
        fs.rm_file(&f).await.expect("rm");
        fs.rmdir(&root).await.expect("rmdir");
        assert!(!fs.exists(&root).await.unwrap());
        fs.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negotiates_3_1_1_with_gmac_and_gcm() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[]);
    let i = fs.connection_info(&env.share).await.unwrap();
    eprintln!("{i:?}");
    assert_eq!(i.dialect, "3.1.1");
    assert!(
        i.signing,
        "signing is required by the server and by default"
    );
    assert_eq!(i.signing_algorithm.as_deref(), Some("AES-GMAC"));
    assert_eq!(i.cipher.as_deref(), Some("AES-128-GCM"));
    assert!(!i.share_encrypted);
    let e = fs.connection_info(&env.enc_share).await.unwrap();
    assert!(e.share_encrypted && !e.encrypt_all, "{e:?}");
    assert!(
        i.credit_window >= 64,
        "credit window did not grow: {}",
        i.credit_window
    );
    fs.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_dialect_works_on_both_shares() {
    let Some(env) = common::env() else { return };
    for d in ["2.0.2", "2.1", "3.0", "3.0.2", "3.1.1"] {
        let fs = env.fs(&[
            ("min_dialect", Value::Str(d.into())),
            ("max_dialect", Value::Str(d.into())),
        ]);
        let mut shares = vec![env.share.clone()];
        if d.starts_with('3') {
            shares.push(env.enc_share.clone());
        }
        for share in shares {
            let info = fs.connection_info(&share).await.unwrap();
            assert_eq!(info.dialect, d);
            let root = scratch(&fs, &share, "dialect").await;
            let f = format!("{root}/f.bin");
            // Larger than 64 KiB: multi-credit on 2.1+, split on 2.0.2.
            let data = common::pattern(300_000, 1);
            fs.pipe_file(&f, data.clone(), &WriteOptions::default())
                .await
                .unwrap_or_else(|e| panic!("{d} {share}: pipe: {e}"));
            assert_eq!(fs.cat_file(&f, ByteRange::Full).await.unwrap(), data);
            assert_eq!(fs.ls(&root).await.unwrap().len(), 1);
            fs.rm_file(&f).await.unwrap();
            fs.rmdir(&root).await.unwrap();
        }
        fs.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metadata_operations_are_single_round_trips() {
    let Some(env) = common::env() else { return };
    for share in [env.share.clone(), env.enc_share.clone()] {
        // One connection: frame counts would otherwise include the setup
        // of connections opened lazily for other paths.
        let fs = env.fs(&[("connections", Value::Int(1))]);
        let root = scratch(&fs, &share, "compound").await;
        let f = format!("{root}/f.txt");
        let d = format!("{root}/d");
        let base = frames(&fs, &share).await;
        let expect = |n: u64| base + n;
        fs.pipe_file(
            &f,
            Bytes::from_static(b"compound"),
            &WriteOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            frames(&fs, &share).await,
            expect(1),
            "pipe = CREATE+WRITE+CLOSE"
        );
        let i = fs.info(&f).await.unwrap();
        assert_eq!(i.size, 8);
        assert_eq!(frames(&fs, &share).await, expect(2), "info = CREATE+CLOSE");
        assert_eq!(
            &fs.cat_file(&f, ByteRange::Full).await.unwrap()[..],
            b"compound"
        );
        assert_eq!(
            frames(&fs, &share).await,
            expect(3),
            "cat = CREATE+READ+CLOSE"
        );
        fs.mkdir(&d, false).await.unwrap();
        assert_eq!(frames(&fs, &share).await, expect(4), "mkdir = CREATE+CLOSE");
        fs.touch(&f, false).await.unwrap();
        assert_eq!(
            frames(&fs, &share).await,
            expect(5),
            "touch = CREATE+SET_INFO+CLOSE"
        );
        let g = format!("{root}/g.txt");
        fs.mv_file(&f, &g).await.unwrap();
        assert_eq!(
            frames(&fs, &share).await,
            expect(6),
            "mv = CREATE+SET_INFO+CLOSE"
        );
        let ls = fs.ls(&root).await.unwrap();
        assert_eq!(ls.len(), 2);
        assert_eq!(
            frames(&fs, &share).await,
            expect(7),
            "ls = CREATE+QUERY_DIRECTORY×2+CLOSE"
        );
        fs.rm_file(&g).await.unwrap();
        assert_eq!(
            frames(&fs, &share).await,
            expect(8),
            "rm = CREATE+SET_INFO+CLOSE"
        );
        fs.rmdir(&d).await.unwrap();
        assert_eq!(
            frames(&fs, &share).await,
            expect(9),
            "rmdir = CREATE+SET_INFO+CLOSE"
        );
        assert!(!fs.exists(&g).await.unwrap());
        fs.rmdir(&root).await.unwrap();
        fs.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn info_records_match_fsspec_shape() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[]);
    let root = scratch(&fs, &env.share, "info").await;
    let f = format!("{root}/f.bin");
    fs.pipe_file(&f, Bytes::from_static(b"12345"), &WriteOptions::default())
        .await
        .unwrap();
    let i = fs.info(&f).await.unwrap();
    assert!(i.is_file() && i.size == 5 && i.name == f);
    assert_eq!(i.extra.get("uid"), Some(&Value::Int(0)));
    assert_eq!(i.extra.get("gid"), Some(&Value::Int(0)));
    let mtime = match i.extra.get("mtime") {
        Some(Value::Float(t)) => *t,
        other => panic!("mtime {other:?}"),
    };
    assert!(matches!(i.extra.get("time"), Some(Value::Float(_))));
    assert!(!i.extra.contains_key("name"), "files keep their name");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    assert!((now - mtime).abs() < 600.0, "mtime {mtime} vs now {now}");
    let modified = i.modified.unwrap();
    let m2 = modified
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    assert!((m2 - mtime).abs() < 1e-5);
    assert!(i.created.is_some() && i.version.is_some());
    // Directories: canonical name, fsspec's slashed name in extra.
    for p in [root.clone(), format!("{root}/")] {
        let d = fs.info(&p).await.unwrap();
        assert!(d.is_dir());
        assert_eq!(d.name, root);
        assert_eq!(d.extra.get("name"), Some(&Value::Str(format!("{root}/"))));
    }
    // ls entries carry the same keys and values as info().
    let ls = fs.ls(&root).await.unwrap();
    assert_eq!(ls[0].extra, i.extra);
    assert_eq!(ls[0].size, i.size);
    // touch without truncation moves mtime and keeps the content.
    tokio::time::sleep(Duration::from_millis(20)).await;
    fs.touch(&f, false).await.unwrap();
    let j = fs.info(&f).await.unwrap();
    assert!(j.modified.unwrap() > i.modified.unwrap());
    assert_eq!(
        &fs.cat_file(&f, ByteRange::Full).await.unwrap()[..],
        b"12345"
    );
    common::cleanup(&fs, &root).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn errors_map_like_fsspec() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[]);
    let root = scratch(&fs, &env.share, "errors").await;
    let f = format!("{root}/f");
    let d = format!("{root}/d");
    fs.pipe_file(&f, Bytes::from_static(b"x"), &WriteOptions::default())
        .await
        .unwrap();
    fs.mkdir(&d, false).await.unwrap();
    fs.pipe_file(
        &format!("{d}/child"),
        Bytes::new(),
        &WriteOptions::default(),
    )
    .await
    .unwrap();
    let check = |what: &str, r: fsfast_core::Result<()>, kind: ErrorKind, status: u32| {
        let e = r.expect_err(what);
        assert_eq!(e.kind(), kind, "{what}: {e}");
        assert_eq!(nt(&e), Some(status), "{what}: {e}");
        assert!(e.path().is_some(), "{what}: no path in {e}");
    };
    let missing = format!("{root}/missing");
    check(
        "info missing",
        fs.info(&missing).await.map(drop),
        ErrorKind::NotFound,
        0xC000_0034,
    );
    check(
        "info missing parent",
        fs.info(&format!("{root}/nodir/x")).await.map(drop),
        ErrorKind::NotFound,
        0xC000_003A,
    );
    check(
        "mkdir existing",
        fs.mkdir(&d, false).await,
        ErrorKind::AlreadyExists,
        0xC000_0035,
    );
    check(
        "mkdir no parent",
        fs.mkdir(&format!("{root}/a/b"), false).await,
        ErrorKind::NotFound,
        0xC000_003A,
    );
    check(
        "cat dir",
        fs.cat_file(&d, ByteRange::Full).await.map(drop),
        ErrorKind::IsADirectory,
        0xC000_00BA,
    );
    check(
        "pipe over dir",
        fs.pipe_file(&d, Bytes::from_static(b"x"), &WriteOptions::default())
            .await,
        ErrorKind::IsADirectory,
        0xC000_00BA,
    );
    check(
        "rmdir non-empty",
        fs.rmdir(&d).await,
        ErrorKind::DirectoryNotEmpty,
        0xC000_0101,
    );
    check(
        "rm_file non-empty dir",
        fs.rm_file(&d).await,
        ErrorKind::DirectoryNotEmpty,
        0xC000_0101,
    );
    check(
        "rmdir file",
        fs.rmdir(&f).await,
        ErrorKind::NotADirectory,
        0xC000_0103,
    );
    check(
        "rmdir missing",
        fs.rmdir(&missing).await,
        ErrorKind::NotFound,
        0xC000_0034,
    );
    check(
        "rm missing",
        fs.rm_file(&missing).await,
        ErrorKind::NotFound,
        0xC000_0034,
    );
    check(
        "xb existing",
        fs.pipe_file(
            &f,
            Bytes::from_static(b"y"),
            &WriteOptions::default().with_mode(WriteMode::CreateNew),
        )
        .await,
        ErrorKind::AlreadyExists,
        0xC000_0035,
    );
    check(
        "open_read missing",
        fs.open_read(&missing, &ReadOptions::default())
            .await
            .map(drop),
        ErrorKind::NotFound,
        0xC000_0034,
    );
    check(
        "mv missing",
        fs.mv_file(&missing, &format!("{root}/m2")).await,
        ErrorKind::NotFound,
        0xC000_0034,
    );
    check(
        "mv to missing dir",
        fs.mv_file(&f, &format!("{root}/nodir/f")).await,
        ErrorKind::NotFound,
        0xC000_003A,
    );
    check(
        "unknown share",
        fs.info("/no-such-share-fsfast/x").await.map(drop),
        ErrorKind::NotFound,
        0xC000_00CC,
    );
    // Paths without a share: ValueError in fsspec.
    for p in ["/", "", "smb://host/"] {
        let e = fs.info(p).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{p:?}: {e}");
        assert!(!fs.exists(p).await.unwrap());
    }
    assert!(!fs.exists("/no-such-share-fsfast/x").await.unwrap());
    assert!(!fs.exists(&format!("{f}/below-a-file")).await.unwrap());
    common::cleanup(&fs, &root).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn share_root_semantics_follow_fsspec() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[]);
    let share = format!("/{}", env.share);
    // fsspec ignores rm/rmdir/makedirs of a bare share; mkdir raises EEXIST.
    fs.rm_file(&share).await.unwrap();
    fs.rmdir(&share).await.unwrap();
    fs.makedirs(&share, false).await.unwrap();
    assert_eq!(
        fs.mkdir(&share, true).await.unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );
    assert!(fs.info(&share).await.unwrap().is_dir());
    assert!(fs.exists(&format!("{share}/")).await.unwrap());
    fs.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixty_four_concurrent_read_at_calls_on_one_handle() {
    let Some(env) = common::env() else { return };
    for share in [env.share.clone(), env.enc_share.clone()] {
        let fs = env.fs(&[("read_chunk_size", Value::Int(256 << 10))]);
        let root = scratch(&fs, &share, "conc").await;
        let f = format!("{root}/big.bin");
        let size = 40 << 20;
        let data = common::pattern(size, 9);
        fs.pipe_file(&f, data.clone(), &WriteOptions::default())
            .await
            .unwrap();
        let h = fs.open_read(&f, &ReadOptions::default()).await.unwrap();
        assert_eq!(h.size(), size as u64);
        let reads: Vec<(u64, usize)> = (0..64u64)
            .map(|i| {
                let off = (i * 7_919_993) % size as u64;
                let len = [1usize, 4096, 300_000, 3 << 20, 9 << 20][(i % 5) as usize];
                (off, len)
            })
            .collect();
        let results = futures::future::join_all(reads.iter().map(|&(off, len)| {
            let h = h.clone();
            async move { (off, len, h.read_at(off, len).await) }
        }))
        .await;
        for (off, len, r) in results {
            let got = r.unwrap();
            let end = (off as usize + len).min(size);
            assert_eq!(got.len(), end - off as usize, "read_at({off}, {len})");
            assert!(
                got == data.slice(off as usize..end),
                "data of read_at({off}, {len})"
            );
        }
        h.close().await.unwrap();
        h.close().await.unwrap();
        let e = h.read_at(0, 1).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput);
        common::cleanup(&fs, &root).await;
        fs.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixteen_files_in_parallel() {
    let Some(env) = common::env() else { return };
    for (share, conns) in [(env.share.clone(), 1), (env.enc_share.clone(), 3)] {
        let fs = env.fs(&[("connections", Value::Int(conns))]);
        let root = scratch(&fs, &share, "par").await;
        let files: Vec<(String, Bytes)> = (0..16)
            .map(|i| {
                (
                    format!("{root}/f{i:02}"),
                    common::pattern((i + 1) * 700_001, i as u8),
                )
            })
            .collect();
        let opts = WriteOptions::default();
        let w: Vec<_> =
            futures::stream::iter(files.iter().map(|(p, d)| fs.pipe_file(p, d.clone(), &opts)))
                .buffer_unordered(16)
                .collect()
                .await;
        assert!(w.iter().all(|r| r.is_ok()), "{w:?}");
        let fsr = &fs;
        let r: Vec<_> = futures::stream::iter(files.iter().map(|(p, d)| async move {
            (fsr.cat_file(p, ByteRange::Full).await.unwrap() == *d, p)
        }))
        .buffer_unordered(16)
        .collect()
        .await;
        assert!(r.iter().all(|(ok, _)| *ok), "{r:?}");
        let listed = fs.find(&root, &FindOptions::default()).await.unwrap();
        assert_eq!(listed.len(), 16);
        let names: Vec<String> = files.iter().map(|(p, _)| p.clone()).collect();
        assert!(fs.rm_files(&names).await.iter().all(|r| r.is_ok()));
        fs.rmdir(&root).await.unwrap();
        fs.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn round_trip_256_mib_both_shares() {
    let Some(env) = common::env() else { return };
    let size: usize = 256 << 20;
    let data = common::pattern(size, 42);
    let tmp = tempfile::tempdir().unwrap();
    for share in [env.share.clone(), env.enc_share.clone()] {
        let fs = env.fs(&[]);
        let root = scratch(&fs, &share, "256").await;
        let f = format!("{root}/big.bin");
        // Stream through a write handle in odd-sized writes.
        let mut w = fs.open_write(&f, &WriteOptions::default()).await.unwrap();
        let mut off = 0;
        let mut step = 1;
        while off < size {
            let n = (step * 777_777 % (5 << 20) + 1).min(size - off);
            w.write(data.slice(off..off + n)).await.unwrap();
            off += n;
            step += 1;
        }
        assert_eq!(w.bytes_written(), size as u64);
        w.close().await.unwrap();
        assert_eq!(fs.info(&f).await.unwrap().size, size as u64);
        let got = fs.cat_file(&f, ByteRange::Full).await.unwrap();
        assert!(got == data, "256 MiB read back differs");
        drop(got);
        // get_file / put_file through local files.
        let local = tmp.path().join(format!("{share}.bin"));
        fs.get_file(&f, &local).await.unwrap();
        let back = std::fs::read(&local).unwrap();
        assert!(back[..] == data[..], "get_file content");
        drop(back);
        let f2 = format!("{root}/put.bin");
        fs.put_file(&local, &f2, &WriteOptions::default())
            .await
            .unwrap();
        let h = fs.open_read(&f2, &ReadOptions::default()).await.unwrap();
        assert_eq!(h.size(), size as u64);
        let tail = h.read_at(size as u64 - 1_000_000, 2_000_000).await.unwrap();
        assert!(tail == data.slice(size - 1_000_000..));
        h.close().await.unwrap();
        common::cleanup(&fs, &root).await;
        fs.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_side_copy_within_and_across_shares() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[("connections", Value::Int(1))]);
    let a = scratch(&fs, &env.share, "copy").await;
    let b = scratch(&fs, &env.enc_share, "copy").await;
    let src = format!("{a}/src.bin");
    // More than one 16 MiB copy-chunk request.
    let data = common::pattern((40 << 20) + 123, 5);
    fs.pipe_file(&src, data.clone(), &WriteOptions::default())
        .await
        .unwrap();
    for dst in [format!("{a}/copy.bin"), format!("{b}/copy.bin")] {
        let before = frames(&fs, &env.share).await;
        fs.cp_file(&src, &dst).await.unwrap();
        // Server-side: open+resume key, open+first batch, two more 16 MiB
        // batches, two CLOSEs; a streamed copy would need 80+ frames.
        let used = frames(&fs, &env.share).await - before;
        assert!(used <= 6, "{used} frames for a server-side copy of 40 MiB");
        assert!(
            fs.cat_file(&dst, ByteRange::Full).await.unwrap() == data,
            "{dst}"
        );
    }
    // Overwrite a larger destination, copy an empty file.
    let small = format!("{a}/small");
    fs.pipe_file(
        &small,
        Bytes::from_static(b"tiny"),
        &WriteOptions::default(),
    )
    .await
    .unwrap();
    fs.cp_file(&small, &format!("{a}/copy.bin")).await.unwrap();
    assert_eq!(
        &fs.cat_file(&format!("{a}/copy.bin"), ByteRange::Full)
            .await
            .unwrap()[..],
        b"tiny"
    );
    let empty = format!("{a}/empty");
    fs.pipe_file(&empty, Bytes::new(), &WriteOptions::default())
        .await
        .unwrap();
    fs.cp_file(&empty, &format!("{b}/empty")).await.unwrap();
    assert_eq!(fs.info(&format!("{b}/empty")).await.unwrap().size, 0);
    // Onto itself: refused (sharing violation), never truncated.
    let e = fs.cp_file(&src, &src).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
    assert_eq!(fs.info(&src).await.unwrap().size, data.len() as u64);
    // Missing source: NotFound, nothing created.
    let e = fs
        .cp_file(&format!("{a}/missing"), &format!("{a}/never"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    assert!(!fs.exists(&format!("{a}/never")).await.unwrap());
    common::cleanup(&fs, &a).await;
    common::cleanup(&fs, &b).await;
    fs.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rename_semantics() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[]);
    let a = scratch(&fs, &env.share, "mv").await;
    let b = scratch(&fs, &env.enc_share, "mv").await;
    let f = format!("{a}/f");
    fs.pipe_file(&f, Bytes::from_static(b"one"), &WriteOptions::default())
        .await
        .unwrap();
    // Replace an existing file atomically.
    let g = format!("{a}/g");
    fs.pipe_file(&g, Bytes::from_static(b"two"), &WriteOptions::default())
        .await
        .unwrap();
    fs.mv_file(&f, &g).await.unwrap();
    assert!(!fs.exists(&f).await.unwrap());
    assert_eq!(&fs.cat_file(&g, ByteRange::Full).await.unwrap()[..], b"one");
    // A directory with content moves as a whole.
    let d = format!("{a}/dir");
    fs.mkdir(&format!("{d}/sub"), true).await.unwrap();
    fs.pipe_file(
        &format!("{d}/sub/x"),
        Bytes::from_static(b"x"),
        &WriteOptions::default(),
    )
    .await
    .unwrap();
    fs.mv_file(&d, &format!("{a}/moved")).await.unwrap();
    assert_eq!(
        &fs.cat_file(&format!("{a}/moved/sub/x"), ByteRange::Full)
            .await
            .unwrap()[..],
        b"x"
    );
    // Across shares: copy + delete.
    fs.mv_file(&g, &format!("{b}/g")).await.unwrap();
    assert!(!fs.exists(&g).await.unwrap());
    assert_eq!(
        &fs.cat_file(&format!("{b}/g"), ByteRange::Full)
            .await
            .unwrap()[..],
        b"one"
    );
    // Onto itself: a no-op.
    fs.mv_file(&format!("{b}/g"), &format!("{b}/g"))
        .await
        .unwrap();
    assert!(fs.exists(&format!("{b}/g")).await.unwrap());
    common::cleanup(&fs, &a).await;
    common::cleanup(&fs, &b).await;
    fs.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn share_access_is_exclusive_by_default_like_smbclient() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[]);
    let root = scratch(&fs, &env.share, "share").await;
    let f = format!("{root}/f");
    fs.pipe_file(&f, Bytes::from_static(b"data"), &WriteOptions::default())
        .await
        .unwrap();
    let h = fs.open_read(&f, &ReadOptions::default()).await.unwrap();
    let e = fs.open_read(&f, &ReadOptions::default()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
    assert_eq!(nt(&e), Some(0xC000_0043), "sharing violation");
    // Attribute-only opens (info) never conflict.
    assert_eq!(fs.info(&f).await.unwrap().size, 4);
    h.close().await.unwrap();
    let shared = env.fs(&[("share_access", Value::Str("r".into()))]);
    let h1 = shared.open_read(&f, &ReadOptions::default()).await.unwrap();
    let h2 = shared.open_read(&f, &ReadOptions::default()).await.unwrap();
    assert_eq!(&h2.read_at(0, 10).await.unwrap()[..], b"data");
    h1.close().await.unwrap();
    h2.close().await.unwrap();
    common::cleanup(&fs, &root).await;
    fs.close().await.unwrap();
    shared.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_handles_abort_and_drop() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[("write_chunk_size", Value::Int(64 << 10))]);
    let root = scratch(&fs, &env.share, "wh").await;
    // Abort of an overwrite removes the file.
    let f = format!("{root}/f");
    fs.pipe_file(&f, Bytes::from_static(b"old"), &WriteOptions::default())
        .await
        .unwrap();
    let mut w = fs.open_write(&f, &WriteOptions::default()).await.unwrap();
    w.write(common::pattern(500_000, 1)).await.unwrap();
    w.abort().await.unwrap();
    assert!(!fs.exists(&f).await.unwrap());
    // A handle dropped without close publishes its data in the background.
    let g = format!("{root}/g");
    let data = common::pattern(300_001, 2);
    {
        let mut w = fs.open_write(&g, &WriteOptions::default()).await.unwrap();
        w.write(data.clone()).await.unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let size = fs.info(&g).await.map(|i| i.size).unwrap_or(0);
        if size == data.len() as u64 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "dropped handle did not publish ({size} bytes)"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // ...and closed its handle: an exclusive open succeeds again.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match fs.open_read(&g, &ReadOptions::default()).await {
            Ok(h) => {
                assert!(h.read_at(0, data.len()).await.unwrap() == data);
                h.close().await.unwrap();
                break;
            }
            Err(e) if e.kind() == ErrorKind::PermissionDenied && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => panic!("{e}"),
        }
    }
    // auto_mkdir creates missing parents for writes and copies.
    let auto = env.fs(&[("auto_mkdir", Value::Bool(true))]);
    let deep = format!("{root}/a/b/c/file");
    auto.pipe_file(&deep, Bytes::from_static(b"deep"), &WriteOptions::default())
        .await
        .unwrap();
    auto.cp_file(&deep, &format!("{root}/x/y/copy"))
        .await
        .unwrap();
    assert_eq!(
        &fs.cat_file(&format!("{root}/x/y/copy"), ByteRange::Full)
            .await
            .unwrap()[..],
        b"deep"
    );
    let e = fs
        .pipe_file(
            &format!("{root}/no/parent"),
            Bytes::new(),
            &WriteOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound, "no auto_mkdir by default");
    common::cleanup(&fs, &root).await;
    fs.close().await.unwrap();
    auto.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn listing_large_directories_page_by_page() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[("connections", Value::Int(1))]);
    let root = scratch(&fs, &env.share, "bigdir").await;
    // Long names (~600 bytes per entry): 11,000 entries overflow the 1 MiB +
    // 4 MiB pages of the one-round-trip compound, so the listing continues
    // page by page on an open handle.
    let long = "n".repeat(240);
    let names: Vec<String> = (0..11_000)
        .map(|i| format!("{root}/{long}-{i:05}"))
        .collect();
    let opts = WriteOptions::default();
    let r: Vec<_> =
        futures::stream::iter(names.iter().map(|p| fs.pipe_file(p, Bytes::new(), &opts)))
            .buffer_unordered(64)
            .collect()
            .await;
    assert!(r.iter().all(|r| r.is_ok()));
    let before = frames(&fs, &env.share).await;
    let mut listed: Vec<String> = fs
        .ls(&root)
        .await
        .unwrap()
        .into_iter()
        .map(|i| i.name)
        .collect();
    let used = frames(&fs, &env.share).await - before;
    assert!(
        used >= 3,
        "the large-directory path was not taken ({used} frames)"
    );
    listed.sort();
    assert_eq!(listed, names);
    assert!(fs.rm_files(&names).await.iter().all(|r| r.is_ok()));
    fs.rmdir(&root).await.unwrap();
    fs.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unusual_names_round_trip() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[]);
    let root = scratch(&fs, &env.enc_share, "names").await;
    let long = format!("long-{}", "x".repeat(195));
    // The testkit's names minus those Windows cannot represent (trailing
    // dots), which Samba lists under mangled 8.3 aliases.
    let names = [
        "with space.txt",
        ".hidden",
        long.as_str(),
        "ünïcödé-名前.bin",
        "plus+sign",
        "percent%20encoded",
        "equals=amp&semi;",
        "tilde~hash#",
        "quote'single",
        "parens (1) [2] {3}",
        "dollar$and@at",
        "emoji-😀",
    ];
    for n in names {
        let p = format!("{root}/{n}");
        fs.pipe_file(
            &p,
            Bytes::copy_from_slice(n.as_bytes()),
            &WriteOptions::default(),
        )
        .await
        .unwrap_or_else(|e| panic!("{n}: {e}"));
        assert_eq!(
            &fs.cat_file(&p, ByteRange::Full).await.unwrap()[..],
            n.as_bytes()
        );
        assert_eq!(fs.info(&p).await.unwrap().name, p);
    }
    let mut listed: Vec<String> = fs
        .ls(&root)
        .await
        .unwrap()
        .into_iter()
        .map(|i| i.name)
        .collect();
    listed.sort();
    let mut want: Vec<String> = names.iter().map(|n| format!("{root}/{n}")).collect();
    want.sort();
    assert_eq!(listed, want);
    // A trailing-dot name works by path but lists mangled (as for smbclient).
    let dots = format!("{root}/comma,dot.dot..");
    fs.pipe_file(&dots, Bytes::from_static(b"d"), &WriteOptions::default())
        .await
        .unwrap();
    assert_eq!(fs.info(&dots).await.unwrap().size, 1);
    common::cleanup(&fs, &root).await;
    fs.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authentication_and_connection_failures() {
    let Some(env) = common::env() else { return };
    // Bad password: PermissionDenied at once, no retries.
    let fs = SmbFileSystem::from_options(env.options(&[("password", Value::Str("wrong".into()))]))
        .unwrap();
    let t = Instant::now();
    let e = fs.connect().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
    assert_eq!(nt(&e), Some(0xC000_006D));
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "auth failures must not be retried"
    );
    assert_eq!(fs.stats().snapshot().retries, 0);
    // Anonymous sessions cannot sign: refused while signing is required.
    let mut o = env.options(&[]);
    o.remove("username");
    o.remove("password");
    let e = SmbFileSystem::from_options(o)
        .unwrap()
        .connect()
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
    // Nothing listens: retried register_session_retries times, then fails.
    let fs = SmbFileSystem::from_options(env.options(&[
        ("port", Value::Int(1)),
        ("register_session_retries", Value::Int(2)),
        ("register_session_retry_wait", Value::Float(0.05)),
    ]))
    .unwrap();
    let e = fs.connect().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ConnectionFailed, "{e}");
    assert_eq!(fs.stats().snapshot().retries, 2);
    // Negative retries: connect() does not register (fsspec), the first
    // operation connects lazily.
    let lazy = env.fs(&[("register_session_retries", Value::Int(-1))]);
    lazy.connect().await.unwrap();
    assert!(
        lazy.info(&format!("/{}", env.share))
            .await
            .unwrap()
            .is_dir()
    );
    lazy.close().await.unwrap();
}

/// Kill the smbd process serving `fs`'s connection (Samba forks one per
/// connection), leaving other users' connections alone.
fn kill_server_side(local_addr: &str) -> bool {
    let conf = std::env::var("FSFAST_TEST_STATE").unwrap_or_else(|_| "/tmp/fsfast-test".into())
        + "/smb/smb.conf";
    let Ok(out) = std::process::Command::new("smbstatus")
        .args(["-s", &conf, "-b"])
        .output()
    else {
        return false;
    };
    let port = local_addr.rsplit(':').next().unwrap();
    let needle = format!(":{port})");
    let text = String::from_utf8_lossy(&out.stdout);
    let Some(pid) = text
        .lines()
        .find(|l| l.contains(&needle))
        .and_then(|l| l.split_whitespace().next())
        .and_then(|p| p.parse::<u32>().ok())
    else {
        return false;
    };
    std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnects_after_the_server_drops_the_connection() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[("connections", Value::Int(1))]);
    let root = scratch(&fs, &env.share, "reconnect").await;
    let f = format!("{root}/f");
    let data = common::pattern(3 << 20, 4);
    fs.pipe_file(&f, data.clone(), &WriteOptions::default())
        .await
        .unwrap();
    let h = fs.open_read(&f, &ReadOptions::default()).await.unwrap();
    let info = fs.connection_info(&env.share).await.unwrap();
    let addr = info.local_addr.clone().unwrap();
    if !kill_server_side(&addr) {
        eprintln!("skipping: could not find this connection's smbd process (smbstatus)");
        drop(h);
        common::cleanup(&fs, &root).await;
        return;
    }
    // The handle belonged to the dead connection: ConnectionFailed.
    let deadline = Instant::now() + Duration::from_secs(10);
    let e = loop {
        match h.read_at(0, 10).await {
            Err(e) => break e,
            Ok(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await
            }
            Ok(_) => panic!("reads kept working after the server process was killed"),
        }
    };
    assert_eq!(e.kind(), ErrorKind::ConnectionFailed, "{e}");
    drop(h);
    // Idempotent operations reconnect transparently.
    assert_eq!(fs.info(&f).await.unwrap().size, data.len() as u64);
    assert!(fs.cat_file(&f, ByteRange::Full).await.unwrap() == data);
    let again = fs.connection_info(&env.share).await.unwrap();
    assert_ne!(
        again.local_addr, info.local_addr,
        "a new connection is used"
    );
    // Many concurrent operations racing the reconnect all succeed.
    assert!(kill_server_side(again.local_addr.as_deref().unwrap()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let r = futures::future::join_all((0..32).map(|_| fs.info(&f))).await;
    assert!(r.iter().all(|r| r.is_ok()), "{r:?}");
    common::cleanup(&fs, &root).await;
    fs.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_disconnects_and_the_filesystem_stays_usable() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[("connections", Value::Int(1))]);
    let share = format!("/{}", env.share);
    assert!(fs.info(&share).await.unwrap().is_dir());
    let a = fs.connection_info(&env.share).await.unwrap().local_addr;
    fs.close().await.unwrap();
    assert!(fs.info(&share).await.unwrap().is_dir());
    let b = fs.connection_info(&env.share).await.unwrap().local_addr;
    assert_ne!(a, b);
    let dynfs: Arc<dyn FileSystem> = Arc::new(fs.clone());
    assert_eq!(dynfs.protocols(), &["smb"]);
    let caps = dynfs.capabilities();
    assert!(caps.hierarchical && caps.atomic_rename && caps.server_side_copy);
    assert!(caps.append && caps.conditional_create && caps.random_write);
    fs.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paths_spread_over_lazily_opened_connections() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[("connections", Value::Int(4))]);
    let root = scratch(&fs, &env.share, "conns").await;
    let names: Vec<String> = (0..64).map(|i| format!("{root}/f{i:02}")).collect();
    let opts = WriteOptions::default();
    let r = futures::future::join_all(
        names
            .iter()
            .map(|n| fs.pipe_file(n, Bytes::from(n.clone()), &opts)),
    )
    .await;
    assert!(r.iter().all(|r| r.is_ok()));
    let info = fs.connection_info(&env.share).await.unwrap();
    assert!(info.connections > 1, "{info:?}");
    assert!(info.connections <= 4);
    // Program order per path holds across connections: a dropped handle's
    // background CLOSE reaches the server before the next exclusive open.
    for n in &names[..8] {
        let h = fs.open_read(n, &ReadOptions::default()).await.unwrap();
        assert_eq!(h.read_at(0, 100).await.unwrap(), Bytes::from(n.clone()));
        drop(h);
        let h = fs.open_read(n, &ReadOptions::default()).await.unwrap();
        h.close().await.unwrap();
        // ls then rmdir/mkdir of the same directory never trip over a CLOSE.
        let d = format!("{n}.d");
        fs.mkdir(&d, false).await.unwrap();
        assert!(fs.ls(&d).await.unwrap().is_empty());
        fs.rmdir(&d).await.unwrap();
        fs.mkdir(&d, false).await.unwrap();
        fs.rmdir(&d).await.unwrap();
    }
    common::cleanup(&fs, &root).await;
    fs.close().await.unwrap();
}
