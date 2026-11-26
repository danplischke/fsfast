//! Live tests against the local OpenSSH server: semantics, error mapping,
//! extensions, pipelining under concurrency, large files and many-file
//! parallelism. Gated on `FSFAST_TEST_SFTP_HOST`.

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use fsfast_core::{
    ByteRange, Detail, ErrorKind, FileSystem, FileType, ReadHandle, ReadOptions, Value, WriteMode,
    WriteOptions,
};
use fsfast_sftp::SftpFileSystem;
use futures::StreamExt;

fn pattern(seed: u64, len: usize) -> Bytes {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect::<Vec<u8>>()
        .into()
}

async fn put(fs: &SftpFileSystem, p: &str, data: impl Into<Bytes>) {
    fs.pipe_file(p, data.into(), &WriteOptions::default())
        .await
        .unwrap_or_else(|e| panic!("pipe_file({p}): {e}"));
}

fn sftp_code(e: &fsfast_core::Error) -> Option<u32> {
    e.details().iter().find_map(|d| match d {
        Detail::Sftp(c) => Some(*c),
        _ => None,
    })
}

/// A test directory that is removed afterwards.
struct Scratch {
    fs: SftpFileSystem,
    dir: String,
}

impl Scratch {
    async fn new(env: &common::Env, fs: &SftpFileSystem, tag: &str) -> Self {
        let dir = env.dir(tag);
        fs.mkdir(&dir, false).await.unwrap();
        Scratch {
            fs: fs.clone(),
            dir,
        }
    }

    fn p(&self, rel: &str) -> String {
        format!("{}/{rel}", self.dir)
    }

    async fn cleanup(self) {
        common::rm_tree(&self.fs, &self.dir).await;
        assert!(!self.fs.exists(&self.dir).await.unwrap());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_and_extensions() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[]);
    let info = fs.connection_info().await.unwrap();
    assert_eq!(info.version, 3);
    for e in [
        "posix-rename@openssh.com",
        "limits@openssh.com",
        "statvfs@openssh.com",
        "fsync@openssh.com",
        "hardlink@openssh.com",
        "copy-data",
    ] {
        assert!(info.extensions.iter().any(|x| x == e), "missing {e}");
    }
    let l = info.limits.unwrap();
    assert_eq!(info.read_chunk as u64, l.max_read_len);
    let n = info.negotiated.unwrap();
    assert_eq!(n.cipher, "aes128-gcm@openssh.com");
    // After connecting, capabilities reflect the server.
    let caps = fs.capabilities();
    assert!(caps.hierarchical && caps.atomic_rename && caps.server_side_copy);
    assert!(caps.append && caps.conditional_create && caps.random_write);
    assert!(!caps.pinned_reads && !caps.signed_urls);
    assert_eq!(fs.protocols(), ["sftp", "ssh"]);

    // Path helpers of the server.
    assert_eq!(fs.realpath(".").await.unwrap(), env.home);
    assert_eq!(fs.home_directory("").await.unwrap(), env.home);
    assert_eq!(fs.home_directory(&env.user).await.unwrap(), env.home);
    assert_eq!(fs.expand_path("~").await.unwrap(), env.home);
    let st = fs.statvfs(&env.home).await.unwrap();
    assert!(st.bsize > 0 && st.namemax > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn algorithm_options() {
    let Some(env) = common::env() else { return };
    // disabled_algorithms (paramiko names) steer the negotiation.
    let fs = env.fs(&[(
        "disabled_algorithms",
        Value::Map(
            [(
                "ciphers".to_owned(),
                Value::List(vec![
                    "aes128-gcm@openssh.com".into(),
                    "aes256-gcm@openssh.com".into(),
                ]),
            )]
            .into_iter()
            .collect(),
        ),
    )]);
    let n = fs.connection_info().await.unwrap().negotiated.unwrap();
    assert_eq!(n.cipher, "chacha20-poly1305@openssh.com");
    // compress=True negotiates zlib@openssh.com (delayed compression) and
    // data still round-trips.
    let fs = env.fs(&[("compress", Value::Bool(true))]);
    let n = fs.connection_info().await.unwrap().negotiated.unwrap();
    assert_eq!(n.compression, "zlib@openssh.com");
    let s = Scratch::new(&env, &fs, "zlib").await;
    let data = pattern(3, 300_000);
    put(&fs, &s.p("z"), data.clone()).await;
    assert_eq!(fs.cat_file(&s.p("z"), ByteRange::Full).await.unwrap(), data);
    s.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn info_and_ls_records() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[]);
    let s = Scratch::new(&env, &fs, "records").await;
    put(&fs, &s.p("f.txt"), &b"hello"[..]).await;
    fs.mkdir(&s.p("d"), false).await.unwrap();
    fs.symlink("f.txt", &s.p("link")).await.unwrap();
    fs.symlink(&s.p("d"), &s.p("dlink")).await.unwrap();
    fs.symlink(&s.p("nowhere"), &s.p("dangle")).await.unwrap();
    assert_eq!(fs.readlink(&s.p("link")).await.unwrap(), "f.txt");

    let i = fs.info(&s.p("f.txt")).await.unwrap();
    assert_eq!(i.name, s.p("f.txt"));
    assert_eq!(i.size, 5);
    assert_eq!(i.file_type, FileType::File);
    let keys: Vec<&str> = i.extra.keys().map(String::as_str).collect();
    assert_eq!(keys, ["gid", "mtime", "time", "uid"]);
    assert!(matches!(i.extra["uid"], Value::Int(u) if u > 0));
    let Value::Time(m) = i.extra["mtime"] else {
        panic!("mtime is not a time")
    };
    let age = SystemTime::now().duration_since(m).unwrap_or_default();
    assert!(age < Duration::from_secs(120), "mtime {m:?}");
    assert_eq!(i.modified, Some(m));
    assert_eq!(i.created, Some(m));

    // info follows symlinks (STAT), like fsspec; a trailing slash is
    // accepted and the name is canonical.
    let li = fs.info(&s.p("link")).await.unwrap();
    assert_eq!((li.file_type, li.size), (FileType::File, 5));
    let di = fs.info(&format!("{}/", s.p("dlink"))).await.unwrap();
    assert_eq!(di.file_type, FileType::Directory);
    assert_eq!(di.name, s.p("dlink"));
    assert_eq!(
        fs.info(&s.p("dangle")).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert!(!fs.exists(&s.p("dangle")).await.unwrap());
    // lstat_info does not follow.
    assert_eq!(
        fs.lstat_info(&s.p("dangle")).await.unwrap().file_type,
        FileType::Symlink
    );

    // ls shows lstat attributes: links are "link".
    let mut l = fs.ls(&s.dir).await.unwrap();
    l.sort_by(|a, b| a.name.cmp(&b.name));
    let got: Vec<(String, &str)> = l
        .iter()
        .map(|e| {
            (
                e.name.rsplit('/').next().unwrap().to_owned(),
                e.file_type.as_fsspec_str(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            ("d".to_owned(), "directory"),
            ("dangle".to_owned(), "link"),
            ("dlink".to_owned(), "link"),
            ("f.txt".to_owned(), "file"),
            ("link".to_owned(), "link"),
        ]
    );
    // ls of a file returns the file (fsfast contract).
    let lf = fs.ls(&s.p("f.txt")).await.unwrap();
    assert_eq!(lf.len(), 1);
    assert_eq!(lf[0].name, s.p("f.txt"));
    // find does not descend into directory symlinks (fsspec walk).
    let found = fs
        .find(
            &s.dir,
            &fsfast_core::FindOptions {
                maxdepth: None,
                withdirs: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(found.len(), 6);
    s.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn error_mapping() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[]);
    let s = Scratch::new(&env, &fs, "errors").await;
    put(&fs, &s.p("file"), &b"x"[..]).await;
    fs.mkdir(&s.p("dir"), false).await.unwrap();
    put(&fs, &s.p("dir/child"), &b"c"[..]).await;

    let kind = |r: fsfast_core::Result<()>| r.unwrap_err().kind();
    let e = fs.info(&s.p("missing")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    assert_eq!(sftp_code(&e), Some(2));
    assert_eq!(e.path(), Some(s.p("missing").as_str()));
    assert_eq!(
        fs.info(&s.p("file/child")).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(kind(fs.rmdir(&s.dir).await), ErrorKind::DirectoryNotEmpty);
    // fsspec: FileNotFoundError (OpenSSH reports ENOTDIR as NO_SUCH_FILE).
    let e = fs.rmdir(&s.p("file")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    assert!(e.to_string().contains("is not a directory"), "{e}");
    assert_eq!(kind(fs.rmdir(&s.p("nope")).await), ErrorKind::NotFound);
    assert_eq!(kind(fs.rm_file(&s.p("dir")).await), ErrorKind::IsADirectory);
    assert_eq!(kind(fs.rm_file(&s.p("nope")).await), ErrorKind::NotFound);
    assert_eq!(
        fs.open_read(&s.p("dir"), &ReadOptions::default())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::IsADirectory
    );
    assert_eq!(
        fs.cat_file(&s.p("dir"), ByteRange::Full)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::IsADirectory
    );
    for parents in [false, true] {
        assert_eq!(
            kind(fs.mkdir(&s.p("dir"), parents).await),
            ErrorKind::AlreadyExists
        );
        assert_eq!(
            kind(fs.mkdir(&s.p("file"), parents).await),
            ErrorKind::AlreadyExists
        );
    }
    assert_eq!(
        kind(fs.mkdir(&s.p("a/b"), false).await),
        ErrorKind::NotFound
    );
    // fsspec: FileNotFoundError; the message names the file in the way.
    let e = fs.mkdir(&s.p("file/sub/deeper"), true).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    assert!(
        e.to_string()
            .contains(&format!("{} is not a directory", s.p("file"))),
        "{e}"
    );
    assert_eq!(
        kind(fs.makedirs(&s.p("file"), true).await),
        ErrorKind::AlreadyExists
    );
    assert_eq!(
        kind(fs.makedirs(&s.p("dir"), false).await),
        ErrorKind::AlreadyExists
    );
    fs.makedirs(&s.p("dir"), true).await.unwrap();
    let ow = |m| WriteOptions::default().with_mode(m);
    assert_eq!(
        fs.open_write(&s.p("file"), &ow(WriteMode::CreateNew))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::AlreadyExists
    );
    for m in [
        WriteMode::Overwrite,
        WriteMode::CreateNew,
        WriteMode::Append,
    ] {
        let e = fs.open_write(&s.p("dir"), &ow(m)).await.unwrap_err();
        assert!(
            matches!(e.kind(), ErrorKind::IsADirectory | ErrorKind::AlreadyExists),
            "{m:?}: {e}"
        );
    }
    assert_eq!(
        fs.open_write(&s.p("nodir/x"), &WriteOptions::default())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    // mv: missing source, directory onto a file (ENOTDIR -> NO_SUCH_FILE,
    // FileNotFoundError like fsspec), file onto a non-empty directory.
    assert_eq!(
        kind(fs.mv_file(&s.p("nope"), &s.p("x")).await),
        ErrorKind::NotFound
    );
    assert_eq!(
        kind(fs.mv_file(&s.p("dir"), &s.p("file")).await),
        ErrorKind::NotFound
    );
    assert_eq!(
        kind(fs.mv_file(&s.p("file"), &s.p("dir")).await),
        ErrorKind::IsADirectory
    );
    assert_eq!(
        kind(fs.touch(&s.p("dir"), true).await),
        ErrorKind::IsADirectory
    );
    assert_eq!(
        kind(fs.cp_file(&s.p("dir"), &s.p("copy")).await),
        ErrorKind::IsADirectory
    );
    assert!(!fs.exists(&s.p("copy")).await.unwrap());
    // ENAMETOOLONG comes back as BAD_MESSAGE: an OS error (OSError in
    // Python, like paramiko's IOError), not InvalidInput (ValueError).
    let long = s.p(&"a".repeat(300));
    let e = fs.info(&long).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io, "{e}");
    assert_eq!(sftp_code(&e), Some(5), "{e}");
    assert_eq!(kind(fs.rm_file(&long).await), ErrorKind::Io);
    s.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writes_appends_aborts_and_touch() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[("fsync_on_close", Value::Bool(true))]);
    let s = Scratch::new(&env, &fs, "writes").await;
    let p = s.p("w.bin");
    let data = pattern(1, 1_000_003);
    // Odd-sized writes spanning chunk boundaries.
    let mut w = fs.open_write(&p, &WriteOptions::default()).await.unwrap();
    let mut off = 0;
    for (i, n) in [1usize, 7, 300_000, 3, 261_119, 1, 261_121, 177_751]
        .iter()
        .enumerate()
    {
        let n = (*n).min(data.len() - off);
        w.write(data.slice(off..off + n)).await.unwrap();
        off += n;
        if i == 3 {
            w.flush().await.unwrap();
        }
    }
    w.write(data.slice(off..)).await.unwrap();
    assert_eq!(w.bytes_written(), data.len() as u64);
    w.close().await.unwrap();
    w.close().await.unwrap();
    assert!(w.write(Bytes::from_static(b"late")).await.is_err());
    assert_eq!(fs.cat_file(&p, ByteRange::Full).await.unwrap(), data);

    // Append, then abort an append: truncated back.
    let ap = WriteOptions::default().with_mode(WriteMode::Append);
    let mut w = fs.open_write(&p, &ap).await.unwrap();
    w.write(Bytes::from_static(b"TAIL")).await.unwrap();
    w.close().await.unwrap();
    assert_eq!(fs.info(&p).await.unwrap().size, data.len() as u64 + 4);
    let mut w = fs.open_write(&p, &ap).await.unwrap();
    w.write(pattern(2, 600_000)).await.unwrap();
    w.abort().await.unwrap();
    w.abort().await.unwrap();
    let got = fs.cat_file(&p, ByteRange::Full).await.unwrap();
    assert_eq!(got.len(), data.len() + 4);
    assert_eq!(&got[data.len()..], b"TAIL");
    // Append to a missing file creates it; aborting that removes it.
    let fresh = s.p("fresh");
    let mut w = fs.open_write(&fresh, &ap).await.unwrap();
    w.write(Bytes::from_static(b"abc")).await.unwrap();
    w.abort().await.unwrap();
    assert!(!fs.exists(&fresh).await.unwrap());
    // Overwrite abort removes.
    let mut w = fs.open_write(&p, &WriteOptions::default()).await.unwrap();
    w.write(pattern(3, 10)).await.unwrap();
    w.abort().await.unwrap();
    assert!(!fs.exists(&p).await.unwrap());
    // A dropped handle releases its server handle (the file stays).
    let mut w = fs.open_write(&p, &WriteOptions::default()).await.unwrap();
    w.write(pattern(4, 1000)).await.unwrap();
    drop(w);

    // CreateNew is exclusive.
    let x = s.p("x");
    fs.pipe_file(
        &x,
        Bytes::from_static(b"one"),
        &WriteOptions::default().with_mode(WriteMode::CreateNew),
    )
    .await
    .unwrap();
    assert_eq!(
        fs.pipe_file(
            &x,
            Bytes::from_static(b"two"),
            &WriteOptions::default().with_mode(WriteMode::CreateNew)
        )
        .await
        .unwrap_err()
        .kind(),
        ErrorKind::AlreadyExists
    );

    // touch(truncate=False) keeps content and refreshes the times.
    fs.set_times(&x, 1_000_000, 1_000_000).await.unwrap();
    let old = fs.info(&x).await.unwrap().modified.unwrap();
    assert_eq!(old, UNIX_EPOCH + Duration::from_secs(1_000_000));
    fs.touch(&x, false).await.unwrap();
    let i = fs.info(&x).await.unwrap();
    assert!(i.modified.unwrap() > old);
    assert_eq!(fs.cat_file(&x, ByteRange::Full).await.unwrap(), &b"one"[..]);
    fs.touch(&x, true).await.unwrap();
    assert_eq!(fs.info(&x).await.unwrap().size, 0);
    fs.chmod(&x, 0o600).await.unwrap();
    s.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn copy_move_links_and_paths() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[]);
    let s = Scratch::new(&env, &fs, "copymove").await;
    let src = s.p("src.bin");
    let data = pattern(5, 3_000_017);
    put(&fs, &src, data.clone()).await;
    // copy-data: the bytes never cross the connection.
    let before = fs.stats().snapshot().bytes_read;
    fs.cp_file(&src, &s.p("dst.bin")).await.unwrap();
    assert!(fs.stats().snapshot().bytes_read - before < 1000);
    assert_eq!(
        fs.cat_file(&s.p("dst.bin"), ByteRange::Full).await.unwrap(),
        data
    );
    // Copy over a longer file truncates; copy onto itself is harmless, also
    // under another name for the same file.
    put(&fs, &s.p("long"), pattern(6, 5_000_000)).await;
    fs.cp_file(&src, &s.p("long")).await.unwrap();
    assert_eq!(fs.info(&s.p("long")).await.unwrap().size, data.len() as u64);
    fs.cp_file(&src, &src).await.unwrap();
    fs.cp_file(&src, &format!("{}/./src.bin", s.dir))
        .await
        .unwrap();
    assert_eq!(fs.cat_file(&src, ByteRange::Full).await.unwrap(), data);
    fs.symlink(&src, &s.p("alias")).await.unwrap();
    fs.cp_file(&s.p("alias"), &src).await.unwrap();
    assert_eq!(fs.cat_file(&src, ByteRange::Full).await.unwrap(), data);

    // mv replaces atomically; onto itself is a no-op.
    put(&fs, &s.p("b"), &b"bbb"[..]).await;
    fs.mv_file(&s.p("dst.bin"), &s.p("b")).await.unwrap();
    assert!(!fs.exists(&s.p("dst.bin")).await.unwrap());
    assert_eq!(fs.info(&s.p("b")).await.unwrap().size, data.len() as u64);
    fs.mv_file(&s.p("b"), &s.p("b")).await.unwrap();
    // Directories move too.
    fs.makedirs(&s.p("t/u"), false).await.unwrap();
    fs.mv_file(&s.p("t"), &s.p("t2")).await.unwrap();
    assert!(fs.info(&s.p("t2/u")).await.unwrap().is_dir());

    // Hard links.
    fs.hardlink(&src, &s.p("hard")).await.unwrap();
    assert_eq!(fs.info(&s.p("hard")).await.unwrap().size, data.len() as u64);

    // Relative paths resolve against the login directory.
    let rel = common::unique("rel");
    fs.mkdir(&rel, false).await.unwrap();
    put(&fs, &format!("{rel}/r.txt"), &b"rel"[..]).await;
    let abs = format!("{}/{rel}/r.txt", env.home);
    assert_eq!(
        fs.cat_file(&abs, ByteRange::Full).await.unwrap(),
        &b"rel"[..]
    );
    let l = fs.ls(&rel).await.unwrap();
    assert_eq!(l[0].name, format!("{rel}/r.txt"));
    fs.rm_file(&format!("{rel}/r.txt")).await.unwrap();
    fs.rmdir(&rel).await.unwrap();
    s.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn put_get_files_and_directories() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[]);
    let s = Scratch::new(&env, &fs, "putget").await;
    let local = tempfile::tempdir().unwrap();
    let src = local.path().join("src.bin");
    let data = pattern(7, 5_000_011);
    std::fs::write(&src, &data).unwrap();
    // put_file creates missing parents (fsspec does too).
    let remote = s.p("a/b/c/up.bin");
    fs.put_file(&src, &remote, &WriteOptions::default())
        .await
        .unwrap();
    assert_eq!(fs.cat_file(&remote, ByteRange::Full).await.unwrap(), data);
    let dst = local.path().join("dst.bin");
    fs.get_file(&remote, &dst).await.unwrap();
    assert_eq!(std::fs::read(&dst).unwrap(), data);
    // A missing local source creates nothing remotely.
    let e = fs
        .put_file(
            &local.path().join("nope"),
            &s.p("x/never"),
            &WriteOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    assert!(!fs.exists(&s.p("x")).await.unwrap());
    // get_file of a directory creates the local directory (fsspec).
    let ldir = local.path().join("gotdir");
    fs.get_file(&s.p("a"), &ldir).await.unwrap();
    assert!(ldir.is_dir());
    // A missing remote leaves no local file.
    let never = local.path().join("never");
    assert_eq!(
        fs.get_file(&s.p("missing"), &never)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert!(!never.exists());
    s.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reads_on_one_handle() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[("max_inflight", Value::Int(24))]);
    let s = Scratch::new(&env, &fs, "concread").await;
    let p = s.p("big.bin");
    let size = 40 << 20;
    let data = pattern(9, size);
    put(&fs, &p, data.clone()).await;
    let h: Arc<dyn ReadHandle> = fs.open_read(&p, &ReadOptions::default()).await.unwrap();
    assert_eq!(h.size(), size as u64);
    // 200 random ranges, 64 at a time, on one handle (one session).
    let mut x = 12345u64;
    let ranges: Vec<(u64, usize)> = (0..200)
        .map(|_| {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let off = (x >> 20) % size as u64;
            let len = ((x >> 8) % (3 << 20)) as usize + 1;
            (off, len)
        })
        .collect();
    let results = futures::stream::iter(ranges.iter().copied())
        .map(|(off, len)| {
            let h = h.clone();
            async move { (off, len, h.read_at(off, len).await.unwrap()) }
        })
        .buffer_unordered(64)
        .collect::<Vec<_>>()
        .await;
    for (off, len, got) in results {
        let end = (off as usize + len).min(size);
        assert_eq!(got.len(), end - off as usize, "read_at({off}, {len})");
        assert!(got == data.slice(off as usize..end), "data at {off}");
    }
    // read_ranges and the engine's parallel reader on the same handle.
    let rr = h
        .read_ranges(&[0..10, 5..100_000, (size as u64 - 3)..(size as u64 + 9)])
        .await
        .unwrap();
    assert_eq!(rr[1], data.slice(5..100_000));
    assert_eq!(rr[2].len(), 3);
    let all = fsfast_engine::read_parallel(&h, 0..size as u64, 4 << 20, 8, None)
        .await
        .unwrap();
    assert!(all == data);
    h.close().await.unwrap();
    assert!(h.read_at(0, 1).await.is_err());
    s.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_file_roundtrip() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[]);
    let s = Scratch::new(&env, &fs, "large").await;
    let p = s.p("large.bin");
    let size = 96 << 20;
    let data = pattern(11, size);
    let mut w = fs.open_write(&p, &WriteOptions::default()).await.unwrap();
    for c in data.chunks(3 << 20) {
        w.write(data.slice_ref(c)).await.unwrap();
    }
    w.close().await.unwrap();
    assert_eq!(fs.info(&p).await.unwrap().size, size as u64);
    let got = fs.cat_file(&p, ByteRange::Full).await.unwrap();
    assert!(got == data);
    let mid = fs
        .cat_file(
            &p,
            ByteRange::Bounded {
                start: 50_000_001,
                end: 61_000_007,
            },
        )
        .await
        .unwrap();
    assert!(mid == data.slice(50_000_001..61_000_007));
    assert_eq!(
        fs.cat_file(&p, ByteRange::Suffix(5)).await.unwrap(),
        data.slice(size - 5..)
    );
    s.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_files_in_parallel_grow_the_pool() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[("connections", Value::Int(3))]);
    let s = Scratch::new(&env, &fs, "many").await;
    let n = 400;
    let paths: Vec<String> = (0..n)
        .map(|i| s.p(&format!("d{}/f{i:04}", i % 7)))
        .collect();
    for d in 0..7 {
        fs.mkdir(&s.p(&format!("d{d}")), false).await.unwrap();
    }
    futures::stream::iter(paths.iter().enumerate())
        .map(|(i, p)| {
            let fs = &fs;
            async move { put(fs, p, pattern(i as u64, 1000 + i)).await }
        })
        .buffer_unordered(32)
        .collect::<Vec<_>>()
        .await;
    let sizes = futures::stream::iter(paths.iter())
        .map(|p| {
            let fs = &fs;
            async move { fs.cat_file(p, ByteRange::Full).await.unwrap().len() }
        })
        .buffered(32)
        .collect::<Vec<_>>()
        .await;
    for (i, sz) in sizes.into_iter().enumerate() {
        assert_eq!(sz, 1000 + i);
    }
    // Background growth happened under concurrency.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        fs.connections() >= 2,
        "pool did not grow: {}",
        fs.connections()
    );
    assert!(fs.connections() <= 3);
    let found = fs
        .find(&s.dir, &fsfast_core::FindOptions::default())
        .await
        .unwrap();
    assert_eq!(found.len(), n);
    let r = fs.rm_files(&paths).await;
    assert_eq!(r.len(), n);
    assert!(r.iter().all(Result::is_ok));
    // close() drops the connections; the filesystem reconnects lazily.
    fs.close().await.unwrap();
    assert_eq!(fs.connections(), 0);
    assert!(fs.info(&s.dir).await.unwrap().is_dir());
    s.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authentication_and_connection_errors() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[("password", "wrong-password".into())]);
    let e = fs.info(&env.home).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
    assert!(!e.is_retryable());
    assert!(e.to_string().contains("password: rejected"), "{e}");

    // Nothing listens on port 1.
    let fs = env.fs(&[("port", Value::Int(1)), ("timeout", Value::Float(5.0))]);
    let e = fs.info("/").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ConnectionFailed, "{e}");

    // No credentials at all.
    let mut o = env.options(&[]);
    o.remove("password");
    let fs = SftpFileSystem::from_options(o).unwrap();
    let e = fs.info("/").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");

    // Unknown options are rejected at construction.
    let e = SftpFileSystem::from_options(env.options(&[("bogus", Value::Int(1))])).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssh_config_alias() {
    let Some(env) = common::env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config");
    std::fs::write(
        &cfg,
        format!(
            "Host fsfast-test-alias\n  HostName {}\n  Port {}\n  User {}\n",
            env.host, env.port, env.user
        ),
    )
    .unwrap();
    let mut o = fsfast_core::Options::new();
    o.insert("host".into(), "fsfast-test-alias".into());
    o.insert("password".into(), env.password.clone().into());
    o.insert("ssh_config".into(), cfg.display().to_string().into());
    o.insert("allow_agent".into(), Value::Bool(false));
    o.insert("look_for_keys".into(), Value::Bool(false));
    let fs = SftpFileSystem::from_options(o.clone()).unwrap();
    assert!(fs.info(&env.home).await.unwrap().is_dir());
    let label = fs.connection_info().await.unwrap().label;
    assert!(
        label.starts_with(&format!("{}@{}:{}", env.user, env.host, env.port)),
        "{label}"
    );

    // ProxyJump is refused instead of silently bypassed.
    std::fs::write(
        &cfg,
        format!(
            "Host fsfast-test-alias\n  HostName {}\n  Port {}\n  ProxyJump jumphost\n",
            env.host, env.port
        ),
    )
    .unwrap();
    let fs = SftpFileSystem::from_options(o).unwrap();
    assert_eq!(
        fs.info("/").await.unwrap_err().kind(),
        ErrorKind::Unsupported
    );
}

/// Reads go to the server's EOF, not to the size STAT reported at open
/// (paramiko reads to EOF): `/proc` files report size 0. The SFTP server
/// runs on this machine, so its `/proc/version` matches ours.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reads_go_to_eof_not_to_the_stat_size() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[]);
    let local = std::fs::read("/proc/version").unwrap_or_default();
    match fs.info("/proc/version").await {
        Ok(i) if i.size == 0 && !local.is_empty() => {
            let got = fs.cat_file("/proc/version", ByteRange::Full).await.unwrap();
            assert_eq!(got, local, "cat_file of a size-0 /proc file");
            let part = fs
                .cat_file("/proc/version", ByteRange::Bounded { start: 2, end: 9 })
                .await
                .unwrap();
            assert_eq!(&part[..], &local[2..9]);
            let dir = tempfile::tempdir().unwrap();
            let lp = dir.path().join("version");
            fs.get_file("/proc/version", &lp).await.unwrap();
            assert_eq!(std::fs::read(&lp).unwrap(), local, "get_file");
        }
        other => eprintln!("skipping /proc check: {other:?}"),
    }
    // Ordinary files: whole, ranged, past the end, empty.
    let s = Scratch::new(&env, &fs, "eof").await;
    let data = pattern(7, 300_000);
    put(&fs, &s.p("f"), data.clone()).await;
    put(&fs, &s.p("empty"), Bytes::new()).await;
    assert_eq!(fs.cat_file(&s.p("f"), ByteRange::Full).await.unwrap(), data);
    assert_eq!(
        fs.cat_file(&s.p("f"), ByteRange::From(299_990))
            .await
            .unwrap(),
        data.slice(299_990..)
    );
    assert_eq!(
        fs.cat_file(&s.p("f"), ByteRange::Suffix(10)).await.unwrap(),
        data.slice(299_990..)
    );
    assert_eq!(
        fs.cat_file(
            &s.p("f"),
            ByteRange::Bounded {
                start: 299_000,
                end: 400_000
            }
        )
        .await
        .unwrap(),
        data.slice(299_000..)
    );
    assert!(
        fs.cat_file(&s.p("f"), ByteRange::From(400_000))
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        fs.cat_file(&s.p("empty"), ByteRange::Full)
            .await
            .unwrap()
            .is_empty()
    );
    s.cleanup().await;
}

/// A non-UTF-8 file name must not be listed under a lossy name that
/// belongs to (or aliases) another file: listing fails, as with paramiko.
/// Needs the server's home directory to be visible locally.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_utf8_names_are_not_aliased() {
    use std::os::unix::ffi::OsStrExt;
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[]);
    let s = Scratch::new(&env, &fs, "names").await;
    let local = std::path::Path::new(&s.dir);
    if !local.is_dir() {
        eprintln!("skipping non-UTF-8 name test: {} is not local", s.dir);
        s.cleanup().await;
        return;
    }
    put(&fs, &s.p("bad\u{fffd}"), &b"replacement"[..]).await;
    let bad = local.join(std::ffi::OsStr::from_bytes(b"bad\xff"));
    std::fs::write(&bad, b"ff").unwrap();
    let e = fs.ls(&s.dir).await.unwrap_err();
    assert!(e.to_string().contains("not valid UTF-8"), "{e}");
    std::fs::remove_file(&bad).unwrap();
    assert_eq!(fs.ls(&s.dir).await.unwrap().len(), 1);
    s.cleanup().await;
}
