//! `mv_file` across filesystems (`rename(2)` fails with `EXDEV`, fsfast falls
//! back to copy + delete with rename semantics for the destination).
//!
//! Gated on `FSFAST_TEST_LOCAL_XDEV_DIR`: a writable directory on a different
//! filesystem than the system temporary directory (e.g. `/dev/shm` when
//! `/tmp` is on disk).

use std::path::Path;

use fsfast_core::{ErrorKind, FileSystem};
use fsfast_local::LocalFileSystem;

#[cfg(unix)]
fn device(p: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).unwrap().dev()
}

#[cfg(not(unix))]
fn device(_p: &Path) -> u64 {
    0
}

#[tokio::test]
async fn moves_across_filesystems() {
    let Ok(other) = std::env::var("FSFAST_TEST_LOCAL_XDEV_DIR") else {
        eprintln!("skipping: set FSFAST_TEST_LOCAL_XDEV_DIR to a directory on another filesystem");
        return;
    };
    let here = tempfile::tempdir().unwrap();
    let there = tempfile::tempdir_in(&other).unwrap();
    if device(here.path()) == device(there.path()) {
        eprintln!("skipping: {other} is on the same filesystem as the temp dir");
        return;
    }
    let a = fsfast_local::strip_protocol(here.path().to_str().unwrap()).into_owned();
    let b = fsfast_local::strip_protocol(there.path().to_str().unwrap()).into_owned();
    let fs = LocalFileSystem::new();

    // A file, replacing an existing destination file.
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(format!("{a}/f"), &data).unwrap();
    std::fs::write(format!("{b}/f"), b"old").unwrap();
    fs.mv_file(&format!("{a}/f"), &format!("{b}/f"))
        .await
        .unwrap();
    assert!(!Path::new(&format!("{a}/f")).exists());
    assert_eq!(std::fs::read(format!("{b}/f")).unwrap(), data);

    // A directory tree with a symlink, into a missing destination.
    std::fs::create_dir_all(format!("{a}/tree/sub")).unwrap();
    std::fs::write(format!("{a}/tree/sub/leaf"), b"leaf").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("sub/leaf", format!("{a}/tree/link")).unwrap();
    fs.mv_file(&format!("{a}/tree"), &format!("{b}/tree"))
        .await
        .unwrap();
    assert!(!Path::new(&format!("{a}/tree")).exists());
    assert_eq!(
        std::fs::read(format!("{b}/tree/sub/leaf")).unwrap(),
        b"leaf"
    );
    #[cfg(unix)]
    assert_eq!(
        std::fs::read_link(format!("{b}/tree/link")).unwrap(),
        Path::new("sub/leaf")
    );

    // Refusals keep both sides intact.
    std::fs::write(format!("{a}/g"), b"g").unwrap();
    let e = fs
        .mv_file(&format!("{a}/g"), &format!("{b}/tree"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::IsADirectory);
    std::fs::create_dir(format!("{a}/d")).unwrap();
    let e = fs
        .mv_file(&format!("{a}/d"), &format!("{b}/f"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AlreadyExists);
    let e = fs
        .mv_file(&format!("{a}/d"), &format!("{b}/tree"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::DirectoryNotEmpty);
    assert!(Path::new(&format!("{a}/g")).exists() && Path::new(&format!("{a}/d")).is_dir());

    // No temporary files left on the destination filesystem.
    let leftovers: Vec<_> = std::fs::read_dir(there.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".fsfast-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    // cp_file across filesystems (copy_file_range falls back as needed).
    fs.cp_file(&format!("{b}/f"), &format!("{a}/back"))
        .await
        .unwrap();
    assert_eq!(std::fs::read(format!("{a}/back")).unwrap(), data);
}
