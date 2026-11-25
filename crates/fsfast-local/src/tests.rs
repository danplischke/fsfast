//! Unit tests for [`LocalFileSystem`].

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

use fsfast_core::{Detail, ErrorKind, FileType, Value};

use super::*;

fn tmp() -> (tempfile::TempDir, String) {
    let d = tempfile::tempdir().unwrap();
    let root = strip_protocol(d.path().to_str().unwrap()).into_owned();
    (d, root)
}

fn opts(pairs: &[(&str, Value)]) -> Options {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

fn names(v: &[FileInfo]) -> Vec<String> {
    v.iter().map(|i| i.name.clone()).collect()
}

fn small_hints() -> IoHints {
    // Force the parallel read paths with tiny files.
    IoHints {
        request_size: 64 << 10,
        max_concurrency: 4,
        coalesce_gap: 4096,
        max_coalesced: 1 << 20,
    }
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 + i / 251) as u8).collect()
}

#[test]
fn from_options_is_strict() {
    let fs = LocalFileSystem::from_options(Options::new()).unwrap();
    assert!(!fs.auto_mkdir());
    let fs = LocalFileSystem::from_options(opts(&[("auto_mkdir", Value::Bool(true))])).unwrap();
    assert!(fs.auto_mkdir());
    LocalFileSystem::from_options(opts(&[
        ("skip_instance_cache", Value::Bool(true)),
        ("use_listings_cache", Value::Bool(false)),
        ("auto_mkdir", Value::Null),
    ]))
    .unwrap();
    let e = LocalFileSystem::from_options(opts(&[("auto_mkdirs", Value::Bool(true))])).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
    assert!(e.to_string().contains("auto_mkdirs"), "{e}");
    let e = LocalFileSystem::from_options(opts(&[("auto_mkdir", Value::Str("perhaps".into()))]))
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
}

#[test]
fn protocols_capabilities_hints() {
    let fs = LocalFileSystem::new();
    assert_eq!(fs.protocols(), &["file", "local"]);
    let c = fs.capabilities();
    assert!(
        c.hierarchical && c.atomic_rename && c.append && c.conditional_create && c.random_write
    );
    assert!(!c.versioning && !c.signed_urls);
    let h = fs.io_hints();
    assert_eq!(
        (h.request_size, h.max_concurrency, h.coalesce_gap),
        (4 << 20, 8, 64 << 10)
    );
}

/// The exact key set fsspec's `LocalFileSystem.info` produces.
fn extra_keys(i: &FileInfo) -> Vec<&str> {
    i.extra.keys().map(String::as_str).collect()
}

#[tokio::test]
async fn info_has_fsspec_keys_and_values() {
    let (_d, root) = tmp();
    let fs = LocalFileSystem::new();
    let f = format!("{root}/f.bin");
    fs::write(&f, b"12345").unwrap();
    let i = fs.info(&f).await.unwrap();
    assert_eq!(i.name, f);
    assert_eq!((i.size, i.file_type), (5, FileType::File));
    assert_eq!(
        extra_keys(&i),
        [
            "created", "gid", "ino", "islink", "mode", "mtime", "nlink", "uid"
        ]
    );
    assert_eq!(i.extra["islink"], Value::Bool(false));
    assert!(matches!(i.extra["mtime"], Value::Float(_)));
    assert!(matches!(i.extra["created"], Value::Float(_)));
    let meta = fs::metadata(&f).unwrap();
    assert_eq!(i.modified, Some(meta.modified().unwrap()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(i.extra["mode"], Value::from(meta.mode()));
        assert_eq!(i.extra["ino"], Value::from(meta.ino()));
        assert_eq!(i.extra["uid"], Value::from(meta.uid()));
        assert_eq!(i.extra["nlink"], Value::from(meta.nlink()));
        let Value::Float(mtime) = i.extra["mtime"] else {
            unreachable!()
        };
        let expected = meta.mtime() as f64 + meta.mtime_nsec() as f64 * 1e-9;
        assert_eq!(mtime, expected);
    }
    assert!(i.version.is_some());

    // Directories, with and without trailing slash or a protocol prefix.
    for p in [
        root.clone(),
        format!("{root}/"),
        format!("file://{root}"),
        format!("local:{root}"),
    ] {
        let i = fs.info(&p).await.unwrap();
        assert_eq!(i.name, root, "{p}");
        assert!(i.is_dir());
        assert_eq!(i.extra.len(), 8);
    }

    // Missing paths: NotFound with the path and errno attached.
    let missing = format!("{root}/nope");
    let e = fs.info(&missing).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    assert_eq!(e.path(), Some(missing.as_str()));
    assert!(e.details().contains(&Detail::Errno(2)), "{e:?}");
    // Through a file.
    let e = fs.info(&format!("{f}/child")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotADirectory);
}

#[cfg(unix)]
#[tokio::test]
async fn symlinks_like_fsspec() {
    use std::os::unix::fs::{MetadataExt, symlink};
    let (_d, root) = tmp();
    let fs = LocalFileSystem::new();
    let target = format!("{root}/target");
    fs::write(&target, b"0123456789").unwrap();
    fs::create_dir(format!("{root}/realdir")).unwrap();
    fs::write(format!("{root}/realdir/inner"), b"in").unwrap();
    let link = format!("{root}/link");
    symlink(&target, &link).unwrap();
    symlink("realdir", format!("{root}/dirlink")).unwrap();
    symlink(format!("{root}/gone"), format!("{root}/broken")).unwrap();

    // info(str) follows the link: target's type, size and stat fields.
    let i = fs.info(&link).await.unwrap();
    assert_eq!(i.name, link);
    assert_eq!((i.file_type, i.size), (FileType::File, 10));
    assert_eq!(i.extra["islink"], Value::Bool(true));
    assert_eq!(i.extra["destination"], Value::Str(target.clone()));
    assert_eq!(
        i.extra["ino"],
        Value::from(fs::metadata(&target).unwrap().ino())
    );
    let d = fs.info(&format!("{root}/dirlink")).await.unwrap();
    assert!(d.is_dir());
    assert_eq!(d.extra["destination"], Value::Str("realdir".into()));
    // A broken link does not exist for info/exists.
    let broken = format!("{root}/broken");
    assert_eq!(
        fs.info(&broken).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert!(!fs.exists(&broken).await.unwrap());
    assert!(fs.exists(&link).await.unwrap());

    // ls entries describe the link itself (lstat): type "other", the
    // target's size (0 when broken), and the link's own inode.
    let entries: std::collections::BTreeMap<String, FileInfo> = fs
        .ls(&root)
        .await
        .unwrap()
        .into_iter()
        .map(|i| (i.name.clone(), i))
        .collect();
    let l = &entries[&link];
    assert_eq!((l.file_type, l.size), (FileType::Other, 10));
    assert_eq!(l.extra["islink"], Value::Bool(true));
    assert_eq!(
        l.extra["ino"],
        Value::from(fs::symlink_metadata(&link).unwrap().ino())
    );
    assert_eq!(l.extra["destination"], Value::Str(target.clone()));
    let b = &entries[&broken];
    assert_eq!((b.file_type, b.size), (FileType::Other, 0));
    let dl = &entries[&format!("{root}/dirlink")];
    assert_eq!(dl.file_type, FileType::Other);
    assert_eq!(
        entries[&format!("{root}/realdir")].file_type,
        FileType::Directory
    );
    assert_eq!(entries[&target].extra.get("destination"), None);

    // find reports symlinked directories but does not descend into them.
    let all = fs
        .find(
            &root,
            &FindOptions {
                maxdepth: None,
                withdirs: true,
            },
        )
        .await
        .unwrap();
    let n = names(&all);
    assert!(n.contains(&format!("{root}/dirlink")));
    assert!(n.contains(&format!("{root}/realdir/inner")));
    assert!(!n.contains(&format!("{root}/dirlink/inner")), "{n:?}");
    // ... but a symlinked root is followed.
    let via = fs
        .find(&format!("{root}/dirlink"), &FindOptions::default())
        .await
        .unwrap();
    assert_eq!(names(&via), [format!("{root}/dirlink/inner")]);
    // Reading and removing through links.
    assert_eq!(
        fs.cat_file(&link, ByteRange::Full).await.unwrap(),
        "0123456789"
    );
    fs.rm_file(&link).await.unwrap();
    assert!(
        Path::new(&target).exists(),
        "rm_file removes the link, not the target"
    );
    fs.rm_file(&broken).await.unwrap();
}

/// A serial, obviously-correct reference for `find`.
fn reference_find(root: &str, maxdepth: Option<usize>, withdirs: bool) -> Vec<String> {
    fn walk(
        dir: &str,
        depth: usize,
        maxdepth: Option<usize>,
        withdirs: bool,
        out: &mut Vec<String>,
    ) {
        for e in fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let name = format!("{dir}/{}", e.file_name().to_str().unwrap());
            if e.file_type().unwrap().is_dir() {
                if withdirs {
                    out.push(name.clone());
                }
                if maxdepth.is_none_or(|m| depth < m) {
                    walk(&name, depth + 1, maxdepth, withdirs, out);
                }
            } else {
                out.push(name);
            }
        }
    }
    let mut out = Vec::new();
    if withdirs {
        out.push(root.to_owned());
    }
    walk(root, 1, maxdepth, withdirs, &mut out);
    out.sort();
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_find_matches_serial_walk() {
    let (_d, root) = tmp();
    // A tree that is both wide and deep, with empty directories.
    for a in 0..6 {
        for b in 0..5 {
            let dir = format!("{root}/a{a}/b{b}");
            fs::create_dir_all(&dir).unwrap();
            for f in 0..(a + b) % 4 {
                fs::write(format!("{dir}/f{f}"), vec![b'x'; f]).unwrap();
            }
            if (a + b) % 3 == 0 {
                fs::create_dir_all(format!("{dir}/deep/er/still")).unwrap();
                fs::write(format!("{dir}/deep/er/still/leaf"), b"leaf").unwrap();
            }
        }
        fs::write(format!("{root}/top{a}"), b"t").unwrap();
    }
    for fs_ in [
        LocalFileSystem::new(),
        LocalFileSystem::new().with_io_hints(IoHints {
            max_concurrency: 1,
            ..LocalFileSystem::DEFAULT_IO_HINTS
        }),
    ] {
        for maxdepth in [None, Some(1), Some(2), Some(3), Some(5)] {
            for withdirs in [false, true] {
                let got = fs_
                    .find(&root, &FindOptions { maxdepth, withdirs })
                    .await
                    .unwrap();
                assert_eq!(
                    names(&got),
                    reference_find(&root, maxdepth, withdirs),
                    "maxdepth={maxdepth:?} withdirs={withdirs}"
                );
                for e in &got {
                    if e.is_file() {
                        assert_eq!(e.size, fs::metadata(&e.name).unwrap().len());
                    }
                }
            }
        }
    }
    let fs_ = LocalFileSystem::new();
    // File root, missing root, maxdepth 0.
    let f = format!("{root}/top0");
    assert_eq!(
        names(&fs_.find(&f, &FindOptions::default()).await.unwrap()),
        std::slice::from_ref(&f)
    );
    assert!(
        fs_.find(&format!("{root}/nope"), &FindOptions::default())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        fs_.find(&format!("{f}/below_a_file"), &FindOptions::default())
            .await
            .unwrap()
            .is_empty()
    );
    let e = fs_
        .find(
            &root,
            &FindOptions {
                maxdepth: Some(0),
                withdirs: false,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
}

#[cfg(unix)]
#[tokio::test]
async fn find_omits_unreadable_subdirectories_like_fsspec_walk() {
    use std::os::unix::fs::PermissionsExt;
    let (_d, root) = tmp();
    let locked = format!("{root}/locked");
    fs::create_dir(&locked).unwrap();
    fs::write(format!("{locked}/secret"), b"s").unwrap();
    fs::write(format!("{root}/visible"), b"v").unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    let readable = fs::read_dir(&locked).is_ok(); // true when running as root
    let got = LocalFileSystem::new()
        .find(
            &root,
            &FindOptions {
                maxdepth: None,
                withdirs: true,
            },
        )
        .await;
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    let got = names(&got.unwrap());
    if readable {
        eprintln!("running with CAP_DAC_OVERRIDE: permission check not exercised");
        assert!(got.contains(&format!("{locked}/secret")));
    } else {
        assert_eq!(
            got,
            [root.clone(), locked.clone(), format!("{root}/visible")]
        );
    }
}

#[tokio::test]
async fn ls_semantics() {
    let (_d, root) = tmp();
    let fs_ = LocalFileSystem::new();
    fs::create_dir(format!("{root}/d")).unwrap();
    fs::write(format!("{root}/b"), b"bb").unwrap();
    fs::write(format!("{root}/a"), b"a").unwrap();
    let l = fs_.ls(&root).await.unwrap();
    assert_eq!(
        names(&l),
        [
            format!("{root}/a"),
            format!("{root}/b"),
            format!("{root}/d")
        ]
    );
    assert!(l[2].is_dir() && l[0].size == 1 && l[1].size == 2);
    let f = fs_.ls(&format!("{root}/b")).await.unwrap();
    assert_eq!(names(&f), [format!("{root}/b")]);
    assert!(fs_.ls(&format!("{root}/d")).await.unwrap().is_empty());
    let e = fs_.ls(&format!("{root}/zz")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    // The filesystem root lists with single-slash names.
    let top = fs_.ls("/").await.unwrap();
    assert!(
        top.iter()
            .all(|i| i.name.starts_with('/') && !i.name.starts_with("//"))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cat_file_and_parallel_reads() {
    let (_d, root) = tmp();
    let data = pattern((1 << 20) + 12_345);
    let p = format!("{root}/big.bin");
    fs::write(&p, &data).unwrap();
    for fs_ in [
        LocalFileSystem::new(),
        LocalFileSystem::new().with_io_hints(small_hints()),
    ] {
        let n = data.len() as u64;
        for r in [
            ByteRange::Full,
            ByteRange::From(70_001),
            ByteRange::Suffix(300_000),
            ByteRange::Bounded {
                start: 3,
                end: n - 3,
            },
            ByteRange::Bounded {
                start: n + 1,
                end: n + 9,
            },
            ByteRange::Bounded { start: 9, end: 4 },
        ] {
            let got = fs_.cat_file(&p, r).await.unwrap();
            let rr = r.resolve(n);
            assert_eq!(&got[..], &data[rr.start as usize..rr.end as usize], "{r:?}");
        }
        // read_at through a handle, large and small, past EOF.
        let h = fs_.open_read(&p, &ReadOptions::default()).await.unwrap();
        assert_eq!(h.size(), data.len() as u64);
        assert_eq!(&h.read_at(5, 900_000).await.unwrap()[..], &data[5..900_005]);
        assert_eq!(
            &h.read_at(n - 10, 100).await.unwrap()[..],
            &data[n as usize - 10..]
        );
        assert!(h.read_at(n, 10).await.unwrap().is_empty());
        let rs = h
            .read_ranges(&[0..10, 5..300_000, 600_000..600_001, n - 1..n + 5])
            .await
            .unwrap();
        assert_eq!(&rs[1][..], &data[5..300_000]);
        assert_eq!(&rs[3][..], &data[n as usize - 1..]);
    }
    // block_size shapes the handle's request size.
    let fs_ = LocalFileSystem::new();
    let ro = ReadOptions {
        block_size: Some(1 << 16),
        ..ReadOptions::default()
    };
    let h = fs_.open_read(&p, &ro).await.unwrap();
    assert_eq!(h.io_hints().request_size, 1 << 16);
    assert_eq!(&h.read_at(0, data.len()).await.unwrap()[..], &data[..]);

    // Errors.
    let e = fs_.cat_file(&root, ByteRange::Full).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::IsADirectory);
    assert_eq!(e.path(), Some(root.as_str()));
    let e = fs_
        .open_read(&root, &ReadOptions::default())
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::IsADirectory);
    let missing = format!("{root}/missing");
    let e = fs_.cat_file(&missing, ByteRange::Full).await.unwrap_err();
    assert_eq!(
        (e.kind(), e.path()),
        (ErrorKind::NotFound, Some(missing.as_str()))
    );
    let ro = ReadOptions {
        version: Some("1".into()),
        ..ReadOptions::default()
    };
    assert_eq!(
        fs_.open_read(&p, &ro).await.unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    let mut ro = ReadOptions::default();
    ro.extra.insert("bogus".into(), Value::Int(1));
    assert_eq!(
        fs_.open_read(&p, &ro).await.unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_read_handles_a_file_that_shrank() {
    let (_d, root) = tmp();
    let p = format!("{root}/shrinks");
    let data = pattern(1 << 20);
    fs::write(&p, &data).unwrap();
    let fs_ = LocalFileSystem::new().with_io_hints(small_hints());
    let h = fs_.open_read(&p, &ReadOptions::default()).await.unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&p)
        .unwrap()
        .set_len(300_000)
        .unwrap();
    let got = h.read_at(0, data.len()).await.unwrap();
    assert_eq!(&got[..], &data[..300_000]);
}

#[tokio::test]
async fn write_modes_and_abort() {
    let (_d, root) = tmp();
    let fs_ = LocalFileSystem::new();
    let p = format!("{root}/w");
    let wo = |m| WriteOptions::default().with_mode(m);

    // Many writes, small and large, in order.
    let data = pattern(3 << 20);
    let mut w = fs_.open_write(&p, &WriteOptions::default()).await.unwrap();
    let mut off = 0;
    for n in [1usize, 7, 300_000, 5, 1 << 20, 13, 1_500_000] {
        let end = (off + n).min(data.len());
        w.write(Bytes::copy_from_slice(&data[off..end]))
            .await
            .unwrap();
        off = end;
    }
    w.write(Bytes::copy_from_slice(&data[off..])).await.unwrap();
    w.flush().await.unwrap();
    assert_eq!(fs::metadata(&p).unwrap().len(), data.len() as u64);
    w.close().await.unwrap();
    w.close().await.unwrap();
    assert_eq!(w.bytes_written(), data.len() as u64);
    assert_eq!(fs::read(&p).unwrap(), data);
    assert_eq!(
        w.write(Bytes::from_static(b"x")).await.unwrap_err().kind(),
        ErrorKind::InvalidInput
    );

    // xb on an existing file / directory.
    let e = fs_
        .open_write(&p, &wo(WriteMode::CreateNew))
        .await
        .unwrap_err();
    assert_eq!(
        (e.kind(), e.path()),
        (ErrorKind::AlreadyExists, Some(p.as_str()))
    );
    assert_eq!(
        fs_.open_write(&root, &wo(WriteMode::CreateNew))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::AlreadyExists
    );
    assert_eq!(
        fs_.open_write(&root, &WriteOptions::default())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::IsADirectory
    );
    // Missing parent without auto_mkdir.
    let deep = format!("{root}/no/such/dir/f");
    assert_eq!(
        fs_.open_write(&deep, &WriteOptions::default())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    let mut w = LocalFileSystem::new()
        .with_auto_mkdir(true)
        .open_write(&deep, &WriteOptions::default())
        .await
        .unwrap();
    w.close().await.unwrap();
    assert!(Path::new(&deep).is_file());

    // Append, then abort an append: cut back to the original length.
    fs::write(&p, b"hello").unwrap();
    let mut w = fs_.open_write(&p, &wo(WriteMode::Append)).await.unwrap();
    w.write(Bytes::from_static(b" world")).await.unwrap();
    w.close().await.unwrap();
    assert_eq!(fs::read(&p).unwrap(), b"hello world");
    let mut w = fs_.open_write(&p, &wo(WriteMode::Append)).await.unwrap();
    w.write(Bytes::from(vec![b'!'; 2 << 20])).await.unwrap();
    w.flush().await.unwrap();
    w.abort().await.unwrap();
    assert_eq!(fs::read(&p).unwrap(), b"hello world");
    assert_eq!(w.close().await.unwrap_err().kind(), ErrorKind::InvalidInput);

    // Abort of a new file removes it.
    let n = format!("{root}/new");
    let mut w = fs_.open_write(&n, &wo(WriteMode::CreateNew)).await.unwrap();
    w.write(Bytes::from_static(b"partial")).await.unwrap();
    w.abort().await.unwrap();
    w.abort().await.unwrap();
    assert!(!Path::new(&n).exists());

    // Abort does not delete a file that replaced the handle's file.
    let r = format!("{root}/replaced");
    let mut w = fs_.open_write(&r, &WriteOptions::default()).await.unwrap();
    w.write(Bytes::from_static(b"mine")).await.unwrap();
    fs::write(format!("{root}/other"), b"theirs").unwrap();
    fs::rename(format!("{root}/other"), &r).unwrap();
    w.abort().await.unwrap();
    assert_eq!(fs::read(&r).unwrap(), b"theirs");

    // Dropping without close still writes the data (in the background).
    let dropped = format!("{root}/dropped");
    {
        let mut w = fs_
            .open_write(&dropped, &WriteOptions::default())
            .await
            .unwrap();
        w.write(Bytes::from_static(b"kept")).await.unwrap();
    }
    let deadline = SystemTime::now() + Duration::from_secs(10);
    while fs::read(&dropped).unwrap() != b"kept" {
        assert!(SystemTime::now() < deadline, "dropped handle never flushed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Unknown backend extras are rejected.
    let mut bad = WriteOptions::default();
    bad.extra.insert("ACL".into(), Value::Str("private".into()));
    assert_eq!(
        fs_.open_write(&p, &bad).await.unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        fs_.pipe_file(&p, Bytes::new(), &bad)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidInput
    );
}

#[tokio::test]
async fn pipe_file_modes() {
    let (_d, root) = tmp();
    let fs_ = LocalFileSystem::new();
    let p = format!("{root}/p");
    fs_.pipe_file(&p, Bytes::from_static(b"one"), &WriteOptions::default())
        .await
        .unwrap();
    fs_.pipe_file(&p, Bytes::from_static(b"2"), &WriteOptions::default())
        .await
        .unwrap();
    assert_eq!(fs::read(&p).unwrap(), b"2");
    let x = WriteOptions::default().with_mode(WriteMode::CreateNew);
    assert_eq!(
        fs_.pipe_file(&p, Bytes::from_static(b"x"), &x)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::AlreadyExists
    );
    let a = WriteOptions::default().with_mode(WriteMode::Append);
    fs_.pipe_file(&p, Bytes::from_static(b"3"), &a)
        .await
        .unwrap();
    assert_eq!(fs::read(&p).unwrap(), b"23");
    let deep = format!("{root}/x/y/z");
    assert_eq!(
        fs_.pipe_file(&deep, Bytes::new(), &WriteOptions::default())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    LocalFileSystem::new()
        .with_auto_mkdir(true)
        .pipe_file(&deep, Bytes::from_static(b"z"), &WriteOptions::default())
        .await
        .unwrap();
    assert_eq!(fs::read(&deep).unwrap(), b"z");
}

#[tokio::test]
async fn directories() {
    let (_d, root) = tmp();
    let fs_ = LocalFileSystem::new();
    let d = format!("{root}/d");
    fs_.mkdir(&d, false).await.unwrap();
    assert!(Path::new(&d).is_dir());
    for parents in [false, true] {
        let e = fs_.mkdir(&d, parents).await.unwrap_err();
        assert_eq!(
            (e.kind(), e.path()),
            (ErrorKind::AlreadyExists, Some(d.as_str()))
        );
    }
    let nested = format!("{root}/x/y/z");
    let e = fs_.mkdir(&nested, false).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    fs_.mkdir(&nested, true).await.unwrap();
    assert!(Path::new(&nested).is_dir());

    fs_.makedirs(&nested, true).await.unwrap();
    assert_eq!(
        fs_.makedirs(&nested, false).await.unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );
    let f = format!("{root}/file");
    fs::write(&f, b"f").unwrap();
    assert_eq!(
        fs_.makedirs(&f, true).await.unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );
    assert_eq!(
        fs_.mkdir(&f, true).await.unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );
    assert_eq!(
        fs_.makedirs(&format!("{f}/sub"), true)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotADirectory
    );

    let e = fs_.rmdir(&format!("{root}/x")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::DirectoryNotEmpty);
    assert_eq!(e.path(), Some(format!("{root}/x").as_str()));
    assert_eq!(
        fs_.rmdir(&f).await.unwrap_err().kind(),
        ErrorKind::NotADirectory
    );
    assert_eq!(
        fs_.rmdir(&format!("{root}/nope")).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    fs_.rmdir(&nested).await.unwrap();
    assert!(!Path::new(&nested).exists());
    // rm_file of a directory fails and keeps it.
    assert!(fs_.rm_file(&d).await.is_err());
    assert!(Path::new(&d).is_dir());
}

#[tokio::test]
async fn rm_files_batches_report_per_path() {
    let (_d, root) = tmp();
    let fs_ = LocalFileSystem::new();
    let mut paths = Vec::new();
    for i in 0..(RM_BATCH * 3 + 5) {
        let p = format!("{root}/f{i:04}");
        if i % 37 != 5 {
            fs::write(&p, b"x").unwrap();
        }
        paths.push(p);
    }
    let results = fs_.rm_files(&paths).await;
    assert_eq!(results.len(), paths.len());
    for (i, (p, r)) in paths.iter().zip(results).enumerate() {
        if i % 37 == 5 {
            let e = r.unwrap_err();
            assert_eq!(
                (e.kind(), e.path()),
                (ErrorKind::NotFound, Some(p.as_str()))
            );
        } else {
            r.unwrap();
        }
        assert!(!Path::new(p).exists());
    }
    assert!(fs_.rm_files(&[]).await.is_empty());
}

#[tokio::test]
async fn copy_move_put_get() {
    let (_d, root) = tmp();
    let fs_ = LocalFileSystem::new();
    let src = format!("{root}/src");
    let data = pattern(200_000);
    fs::write(&src, &data).unwrap();

    let dst = format!("{root}/dst");
    fs::write(&dst, vec![1u8; 500_000]).unwrap();
    fs_.cp_file(&src, &dst).await.unwrap();
    assert_eq!(fs::read(&dst).unwrap(), data);
    // Onto itself: refused, data intact.
    assert!(fs_.cp_file(&src, &src).await.is_err());
    assert_eq!(fs::read(&src).unwrap(), data);
    // Missing source: NotFound naming the source.
    let missing = format!("{root}/missing");
    let e = fs_
        .cp_file(&missing, &format!("{root}/never"))
        .await
        .unwrap_err();
    assert_eq!(
        (e.kind(), e.path()),
        (ErrorKind::NotFound, Some(missing.as_str()))
    );
    assert!(!Path::new(&format!("{root}/never")).exists());
    // A directory source becomes a directory (fsspec mkdirs).
    fs::create_dir(format!("{root}/sd")).unwrap();
    fs_.cp_file(&format!("{root}/sd"), &format!("{root}/cd"))
        .await
        .unwrap();
    assert!(Path::new(&format!("{root}/cd")).is_dir());
    fs_.cp_file(&format!("{root}/sd"), &format!("{root}/cd"))
        .await
        .unwrap();
    // Missing destination parent, with and without auto_mkdir.
    let deep = format!("{root}/p/q/copy");
    assert_eq!(
        fs_.cp_file(&src, &deep).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    LocalFileSystem::new()
        .with_auto_mkdir(true)
        .cp_file(&src, &deep)
        .await
        .unwrap();
    assert_eq!(fs::read(&deep).unwrap(), data);

    // mv: replaces a file, moves directories, refuses a file onto a directory.
    let moved = format!("{root}/moved");
    fs::write(&moved, b"old").unwrap();
    fs_.mv_file(&dst, &moved).await.unwrap();
    assert!(!Path::new(&dst).exists());
    assert_eq!(fs::read(&moved).unwrap(), data);
    let e = fs_
        .mv_file(&moved, &format!("{root}/cd"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::IsADirectory);
    assert!(e.to_string().contains(&format!("-> '{root}/cd'")), "{e}");
    fs_.mv_file(&format!("{root}/p"), &format!("{root}/p2"))
        .await
        .unwrap();
    assert_eq!(fs::read(format!("{root}/p2/q/copy")).unwrap(), data);
    fs_.mv_file(&moved, &moved).await.unwrap();
    assert!(Path::new(&moved).exists());
    let e = fs_
        .mv_file(&missing, &format!("{root}/x"))
        .await
        .unwrap_err();
    assert_eq!(
        (e.kind(), e.path()),
        (ErrorKind::NotFound, Some(missing.as_str()))
    );
    LocalFileSystem::new()
        .with_auto_mkdir(true)
        .mv_file(&moved, &format!("{root}/new/parent/m"))
        .await
        .unwrap();
    assert_eq!(fs::read(format!("{root}/new/parent/m")).unwrap(), data);

    // put/get are local copies.
    let up = format!("{root}/up");
    fs_.put_file(Path::new(&src), &up, &WriteOptions::default())
        .await
        .unwrap();
    assert_eq!(fs::read(&up).unwrap(), data);
    let x = WriteOptions::default().with_mode(WriteMode::CreateNew);
    assert_eq!(
        fs_.put_file(Path::new(&src), &up, &x)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::AlreadyExists
    );
    let a = WriteOptions::default().with_mode(WriteMode::Append);
    fs_.put_file(Path::new(&src), &up, &a).await.unwrap();
    assert_eq!(fs::metadata(&up).unwrap().len(), 2 * data.len() as u64);
    let down = Path::new(&root).join("down");
    fs_.get_file(&src, &down).await.unwrap();
    assert_eq!(fs::read(&down).unwrap(), data);
    let ddir = Path::new(&root).join("down_dir");
    fs_.get_file(&format!("{root}/sd"), &ddir).await.unwrap();
    assert!(ddir.is_dir());
    let never = Path::new(&root).join("never_downloaded");
    assert_eq!(
        fs_.get_file(&missing, &never).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert!(!never.exists());
}

#[tokio::test]
async fn touch_updates_mtime_without_truncating() {
    let (_d, root) = tmp();
    let fs_ = LocalFileSystem::new();
    let p = format!("{root}/t");
    fs_.touch(&p, false).await.unwrap();
    assert_eq!(fs::metadata(&p).unwrap().len(), 0);
    fs::write(&p, b"content").unwrap();
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    fs::File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(old).set_accessed(old))
        .unwrap();
    fs_.touch(&p, false).await.unwrap();
    let i = fs_.info(&p).await.unwrap();
    assert_eq!(i.size, 7);
    assert!(i.modified.unwrap() > old + Duration::from_secs(3600));
    fs_.touch(&p, true).await.unwrap();
    assert_eq!(fs::metadata(&p).unwrap().len(), 0);
    let deep = format!("{root}/a/b/t");
    assert_eq!(
        fs_.touch(&deep, true).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    LocalFileSystem::new()
        .with_auto_mkdir(true)
        .touch(&deep, true)
        .await
        .unwrap();
    assert!(Path::new(&deep).is_file());
}

#[tokio::test]
async fn exists_follows_os_path_exists() {
    let (_d, root) = tmp();
    let fs_ = LocalFileSystem::new();
    let f = format!("{root}/f");
    fs::write(&f, b"").unwrap();
    assert!(fs_.exists(&f).await.unwrap());
    assert!(fs_.exists(&root).await.unwrap());
    assert!(fs_.exists(&format!("file://{f}")).await.unwrap());
    assert!(!fs_.exists(&format!("{root}/nope")).await.unwrap());
    assert!(!fs_.exists(&format!("{f}/child")).await.unwrap());
}

#[tokio::test]
async fn non_utf8_names_are_listed() {
    #[cfg(unix)]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let (_d, root) = tmp();
        let raw = Path::new(&root).join(OsStr::from_bytes(b"bad\xffname"));
        if fs::write(&raw, b"x").is_err() {
            eprintln!("filesystem rejects non-UTF-8 names; skipping");
            return;
        }
        let l = LocalFileSystem::new().ls(&root).await.unwrap();
        assert_eq!(l.len(), 1);
        assert!(l[0].name.starts_with(&format!("{root}/bad")));
    }
}

/// A runtime whose blocking pool has a single thread, plus a way to occupy
/// that thread: blocking work queued behind it stays pending until
/// released, which makes write-ordering races deterministic.
fn single_blocking_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap()
}

/// Occupy the (single) blocking thread until the returned sender is used.
async fn occupy_blocking_pool() -> std::sync::mpsc::Sender<()> {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    tokio::task::spawn_blocking(move || {
        let _ = started_tx.send(());
        let _ = rx.recv();
    });
    started_rx.await.unwrap();
    tx
}

async fn wait_for_len(p: &str, len: u64) {
    for _ in 0..500 {
        if fs::metadata(p).map(|m| m.len()).unwrap_or(0) >= len {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{p} never reached {len} bytes");
}

/// Regression: a handle dropped without `close` on a thread outside the
/// runtime (as a garbage-collected Python file object is) wrote its buffered
/// tail synchronously while the previous write was still queued, so the
/// tail landed *before* earlier data.
#[test]
fn dropping_a_write_handle_off_runtime_keeps_write_order() {
    let rt = single_blocking_thread_runtime();
    let (_d, root) = tmp();
    let p = format!("{root}/dropped");
    let big = pattern(handles::DIRECT_WRITE + 1000);
    let tail = b"tail".to_vec();
    let (w, release) = rt.block_on(async {
        let fs_ = LocalFileSystem::new();
        let mut w = fs_.open_write(&p, &WriteOptions::default()).await.unwrap();
        let release = occupy_blocking_pool().await;
        // Large: handed to a blocking write, queued behind the occupier.
        w.write(Bytes::from(big.clone())).await.unwrap();
        // Small: buffered in the handle.
        w.write(Bytes::from(tail.clone())).await.unwrap();
        (w, release)
    });
    // Dropped on a thread with no runtime context.
    std::thread::spawn(move || drop(w)).join().unwrap();
    release.send(()).unwrap();
    rt.block_on(wait_for_len(&p, (big.len() + tail.len()) as u64));
    // Give a late, misordered write the chance to show up.
    std::thread::sleep(Duration::from_millis(50));
    let mut expected = big;
    expected.extend_from_slice(&tail);
    let got = fs::read(&p).unwrap();
    assert_eq!(got.len(), expected.len());
    assert!(
        got == expected,
        "dropped handle wrote its data out of order"
    );
}

/// Regression: cancelling a `write` while it waited for the previous write
/// silently lost its data; later writes and `close` then succeeded with a
/// hole in the file. A cancelled handle must refuse further writes, and
/// `abort` must still clean up.
#[test]
fn cancelled_write_poisons_the_handle() {
    let rt = single_blocking_thread_runtime();
    let (_d, root) = tmp();
    let p = format!("{root}/cancelled");
    rt.block_on(async {
        let fs_ = LocalFileSystem::new();
        let mut w = fs_.open_write(&p, &WriteOptions::default()).await.unwrap();
        let release = occupy_blocking_pool().await;
        let chunk = || Bytes::from(pattern(handles::DIRECT_WRITE));
        w.write(chunk()).await.unwrap(); // queued behind the occupier
        // The next large write waits for the first one: cancel it.
        let r = tokio::time::timeout(Duration::from_millis(50), w.write(chunk())).await;
        assert!(r.is_err(), "the write should still have been waiting");
        release.send(()).unwrap();
        let after = w.write(Bytes::from_static(b"more")).await;
        let closed = w.close().await;
        assert!(
            after.is_err() || closed.is_err(),
            "a handle whose write was cancelled must not close successfully \
             (the cancelled chunk was lost): write={after:?} close={closed:?}"
        );
        w.abort().await.unwrap();
        assert!(!Path::new(&p).exists(), "abort removes the file");
    });
}

/// Regression: errnos for which Python raises a plain `OSError` (here
/// `ENAMETOOLONG` and `EINVAL`) were reported as `InvalidInput`, which the
/// bindings turn into `ValueError`, so `except OSError` stopped catching
/// them. fsspec's `shutil.move` also reports moving a directory into itself
/// as `shutil.Error`, an `OSError`.
#[tokio::test]
async fn os_errors_without_a_python_subclass_are_io() {
    let (_d, root) = tmp();
    let fs_ = LocalFileSystem::new();
    let long = format!("{root}/{}", "n".repeat(300));
    let e = fs_.info(&long).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io, "{e}");
    assert!(e.details().contains(&Detail::Errno(36)), "{e:?}");
    assert_eq!(e.path(), Some(long.as_str()));
    let e = fs_
        .pipe_file(&long, Bytes::from_static(b"x"), &WriteOptions::default())
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io, "{e}");
    let e = fs_.cp_file(&long, &format!("{root}/x")).await.unwrap_err();
    // fsspec decides with os.path.isfile, which swallows the error.
    assert_eq!(e.kind(), ErrorKind::NotFound, "{e}");
    fs::write(format!("{root}/src"), b"s").unwrap();
    let e = fs_
        .cp_file(&format!("{root}/src"), &long)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io, "{e}");
    assert!(e.details().contains(&Detail::Errno(36)), "{e:?}");
    // rename(2) reports the destination problem (ENOTDIR: `src` is a file),
    // but shutil.move's fallback opens the source first: its error wins.
    let e = fs_
        .mv_file(&long, &format!("{root}/src/child"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io, "{e}");
    assert!(e.details().contains(&Detail::Errno(36)), "{e:?}");

    fs::create_dir_all(format!("{root}/d/sub")).unwrap();
    let e = fs_
        .mv_file(&format!("{root}/d"), &format!("{root}/d/sub/x"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io, "{e}");
    assert!(Path::new(&format!("{root}/d/sub")).is_dir());
    // The same on the cross-device fallback path.
    let e = ops::move_across_devices(
        Path::new(&format!("{root}/d")),
        Path::new(&format!("{root}/d/sub/x")),
    )
    .unwrap_err();
    assert_eq!(stat::os_kind(&e), ErrorKind::Io, "{e}");
    // Two-path errors name the destination once, not three times.
    let msg = fs_
        .cp_file(&format!("{root}/src"), &long)
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(msg.matches("(errno 36)").count(), 1, "{msg}");
}

/// Regression: `makedirs("x/new/.")` creates `x/new` in Python (os.makedirs
/// splits textually), but failed with `NotFound` because `Path::parent`
/// normalises the trailing `.` away.
#[tokio::test]
async fn makedirs_with_a_trailing_dot_component() {
    let (_d, root) = tmp();
    let fs_ = LocalFileSystem::new();
    fs_.makedirs(&format!("{root}/new/."), false).await.unwrap();
    assert!(Path::new(&format!("{root}/new")).is_dir());
    // Now it exists: like Python, exist_ok decides.
    assert_eq!(
        fs_.makedirs(&format!("{root}/new/."), false)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::AlreadyExists
    );
    fs_.makedirs(&format!("{root}/new/."), true).await.unwrap();
    fs_.mkdir(&format!("{root}/deep/er/."), true).await.unwrap();
    assert!(Path::new(&format!("{root}/deep/er")).is_dir());
    // Without create_parents fsspec calls os.mkdir, which fails.
    assert_eq!(
        fs_.mkdir(&format!("{root}/other/."), false)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
}

/// Regression: `touch(fifo, truncate=True)` opened the pipe for writing and
/// blocked a thread until a reader appeared; fsspec's `os.truncate` fails at
/// once.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn touch_truncate_of_a_named_pipe_does_not_hang() {
    use rustix::fs::{CWD, FileType as RFileType, Mode, mknodat};
    let (_d, root) = tmp();
    let fifo = format!("{root}/pipe");
    mknodat(CWD, fifo.as_str(), RFileType::Fifo, Mode::from(0o644), 0).unwrap();
    let fs_ = LocalFileSystem::new();
    let r = tokio::time::timeout(Duration::from_secs(5), fs_.touch(&fifo, true)).await;
    if r.is_err() {
        // Unblock the stuck writer so the runtime can shut down.
        let _ = fs::File::open(&fifo);
        panic!("touch(fifo, truncate=true) hung");
    }
    let e = r.unwrap().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io, "{e}");
    // Without truncation only the timestamps change.
    fs_.touch(&fifo, false).await.unwrap();
}
