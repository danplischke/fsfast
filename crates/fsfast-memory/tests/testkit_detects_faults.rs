//! The conformance suite must catch broken backends. These tests wrap the
//! (correct) memory backend, inject one fault each, and check that the suite
//! reports the right check as failed with a useful message.

use std::ops::Range;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use fsfast_core::{
    ByteRange, Capabilities, ErrorKind, FileInfo, FileSystem, FindOptions, IoHints,
    ReadHandle, ReadOptions, Result, WriteHandle, WriteOptions,
};
use fsfast_memory::MemoryFileSystem;
use fsfast_testkit::{CheckStatus, SuiteConfig, run_suite};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// Flip one byte of the third range returned by `cat_ranges`.
    CorruptCatRanges,
    /// `rm_files` reports success for missing paths.
    RmFilesIgnoresMissing,
    /// `ls` of a missing path returns an empty list.
    LsMissingIsEmpty,
    /// Claim no append support.
    NoAppend,
    /// `find` returns unsorted results.
    FindUnsorted,
    /// `info` reports names with a trailing slash for directories.
    InfoTrailingSlash,
    /// `rmdir` silently removes non-empty directories' marker.
    RmdirIgnoresNotEmpty,
    /// `cat_file` hangs.
    CatHangs,
}

#[derive(Debug)]
struct Faulty {
    inner: MemoryFileSystem,
    fault: Fault,
}

#[async_trait::async_trait]
impl FileSystem for Faulty {
    fn protocols(&self) -> &'static [&'static str] {
        &["faulty"]
    }
    fn capabilities(&self) -> Capabilities {
        let mut c = self.inner.capabilities();
        if self.fault == Fault::NoAppend {
            c.append = false;
        }
        c
    }
    fn io_hints(&self) -> IoHints {
        self.inner.io_hints()
    }
    async fn info(&self, path: &str) -> Result<FileInfo> {
        let mut i = self.inner.info(path).await?;
        if self.fault == Fault::InfoTrailingSlash && i.is_dir() {
            i.name.push('/');
        }
        Ok(i)
    }
    async fn ls(&self, path: &str) -> Result<Vec<FileInfo>> {
        match self.inner.ls(path).await {
            Err(e) if self.fault == Fault::LsMissingIsEmpty && e.kind() == ErrorKind::NotFound => {
                Ok(Vec::new())
            }
            r => r,
        }
    }
    async fn find(&self, path: &str, opts: &FindOptions) -> Result<Vec<FileInfo>> {
        let mut v = self.inner.find(path, opts).await?;
        if self.fault == Fault::FindUnsorted {
            v.reverse();
        }
        Ok(v)
    }
    async fn open_read(&self, path: &str, opts: &ReadOptions) -> Result<Arc<dyn ReadHandle>> {
        self.inner.open_read(path, opts).await
    }
    async fn open_write(&self, path: &str, opts: &WriteOptions) -> Result<Box<dyn WriteHandle>> {
        self.inner.open_write(path, opts).await
    }
    async fn cat_file(&self, path: &str, range: ByteRange) -> Result<Bytes> {
        if self.fault == Fault::CatHangs {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
        self.inner.cat_file(path, range).await
    }
    async fn cat_ranges(&self, path: &str, ranges: &[Range<u64>]) -> Result<Vec<Bytes>> {
        let mut v = self.inner.cat_ranges(path, ranges).await?;
        if self.fault == Fault::CorruptCatRanges && v.len() > 2 && v[2].len() > 7 {
            let mut b = v[2].to_vec();
            b[7] ^= 0x01;
            v[2] = Bytes::from(b);
        }
        Ok(v)
    }
    async fn rm_file(&self, path: &str) -> Result<()> {
        self.inner.rm_file(path).await
    }
    async fn rm_files(&self, paths: &[String]) -> Vec<Result<()>> {
        let mut out = self.inner.rm_files(paths).await;
        if self.fault == Fault::RmFilesIgnoresMissing {
            out = out
                .into_iter()
                .map(|r| match r {
                    Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
                    r => r,
                })
                .collect();
        }
        out
    }
    async fn mkdir(&self, path: &str, create_parents: bool) -> Result<()> {
        self.inner.mkdir(path, create_parents).await
    }
    async fn makedirs(&self, path: &str, exist_ok: bool) -> Result<()> {
        self.inner.makedirs(path, exist_ok).await
    }
    async fn rmdir(&self, path: &str) -> Result<()> {
        match self.inner.rmdir(path).await {
            Err(e)
                if self.fault == Fault::RmdirIgnoresNotEmpty
                    && e.kind() == ErrorKind::DirectoryNotEmpty =>
            {
                Ok(())
            }
            r => r,
        }
    }
    async fn cp_file(&self, src: &str, dst: &str) -> Result<()> {
        self.inner.cp_file(src, dst).await
    }
    async fn mv_file(&self, src: &str, dst: &str) -> Result<()> {
        self.inner.mv_file(src, dst).await
    }
    async fn put_file(&self, local: &Path, remote: &str, opts: &WriteOptions) -> Result<()> {
        self.inner.put_file(local, remote, opts).await
    }
    async fn get_file(&self, remote: &str, local: &Path) -> Result<()> {
        self.inner.get_file(remote, local).await
    }
    async fn touch(&self, path: &str, truncate: bool) -> Result<()> {
        self.inner.touch(path, truncate).await
    }
    async fn pipe_file(&self, path: &str, data: Bytes, opts: &WriteOptions) -> Result<()> {
        self.inner.pipe_file(path, data, opts).await
    }
}

async fn failure_of(fault: Fault, check: &str, cfg: SuiteConfig) -> String {
    let fs = Arc::new(Faulty {
        inner: MemoryFileSystem::new_isolated(),
        fault,
    });
    let report = run_suite(fs, "/faulty", cfg.only([check])).await;
    assert!(!report.is_success(), "{fault:?} went unnoticed:\n{report}");
    match &report.outcome(check).unwrap().status {
        CheckStatus::Failed(m) => m.clone(),
        other => panic!("{fault:?}: expected {check} to fail, got {other:?}\n{report}"),
    }
}

#[tokio::test]
async fn corrupted_range_is_located() {
    let m = failure_of(Fault::CorruptCatRanges, "cat_ranges", SuiteConfig::default()).await;
    // Range #2 is 2000..3000: byte 7 of it is file offset 2007.
    assert!(m.contains("range #2"), "{m}");
    assert!(m.contains("first mismatch at file offset 2007"), "{m}");
}

#[tokio::test]
async fn ignored_missing_path_in_batch_delete_is_caught() {
    let m = failure_of(Fault::RmFilesIgnoresMissing, "rm_files_batch", SuiteConfig::default()).await;
    assert!(m.contains("expected an error of kind NotFound"), "{m}");
}

#[tokio::test]
async fn ls_of_missing_path_must_fail() {
    let m = failure_of(Fault::LsMissingIsEmpty, "ls", SuiteConfig::default()).await;
    assert!(m.contains("ls(") && m.contains("NotFound"), "{m}");
}

#[tokio::test]
async fn unsorted_find_is_caught() {
    let m = failure_of(Fault::FindUnsorted, "find", SuiteConfig::default()).await;
    assert!(m.contains("not sorted"), "{m}");
}

#[tokio::test]
async fn directory_names_must_be_normalised() {
    let m = failure_of(Fault::InfoTrailingSlash, "info", SuiteConfig::default()).await;
    assert!(m.contains(".name"), "{m}");
}

#[tokio::test]
async fn rmdir_of_non_empty_directory_must_fail() {
    let m = failure_of(Fault::RmdirIgnoresNotEmpty, "mkdir_rmdir", SuiteConfig::default()).await;
    assert!(m.contains("DirectoryNotEmpty"), "{m}");
}

#[tokio::test]
async fn hanging_backend_times_out() {
    let mut cfg = SuiteConfig::default();
    cfg.check_timeout = Duration::from_millis(300);
    let m = failure_of(Fault::CatHangs, "pipe_cat_roundtrip", cfg).await;
    assert!(m.contains("timed out"), "{m}");
}

#[tokio::test]
async fn missing_capability_skips_instead_of_failing() {
    let fs = Arc::new(Faulty {
        inner: MemoryFileSystem::new_isolated(),
        fault: Fault::NoAppend,
    });
    let report = run_suite(fs, "/faulty", SuiteConfig::default().only(["open_write_append"])).await;
    assert!(report.is_success(), "{report}");
    match &report.outcome("open_write_append").unwrap().status {
        CheckStatus::Skipped(m) => assert!(m.contains("append"), "{m}"),
        other => panic!("expected a skip, got {other:?}"),
    }
}

#[tokio::test]
async fn report_is_readable() {
    let fs = Arc::new(Faulty {
        inner: MemoryFileSystem::new_isolated(),
        fault: Fault::CorruptCatRanges,
    });
    let report = run_suite(fs, "/faulty", SuiteConfig::default().only(["cat_ranges", "info"])).await;
    let text = report.to_string();
    assert!(text.contains("conformance suite FAILED"), "{text}");
    assert!(text.contains("backend `faulty`"), "{text}");
    assert!(text.contains("1 passed, 1 failed"), "{text}");
    assert!(text.contains("  FAIL cat_ranges"), "{text}");
}
