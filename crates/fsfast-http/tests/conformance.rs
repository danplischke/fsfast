//! The fsfast-testkit suite's read checks, run through HTTP.
//!
//! An HTTP server cannot take the suite's writes, so the backend under test
//! is an adapter: everything that reads data (`info`, `exists`, `cat_file`,
//! `cat_ranges`, `open_read`, `get_file`) goes through `HttpFileSystem`
//! against the in-process server, while writes, listings and deletes (what
//! the suite uses to prepare and clean up) go to the local directory the
//! server serves. The suite's pattern checks thereby verify every byte the
//! HTTP backend returns, across three server behaviours: a real static file
//! server (tower-http `ServeDir`), a server that ignores `Range`, and one
//! that sends no `Content-Length` at all.
//!
//! The testkit normalizes paths (collapsing `//`), so the adapter exposes
//! plain paths (`/run/...`) and maps them onto URLs itself.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use fsfast_core::{
    ByteRange, Capabilities, FileInfo, FileSystem, FindOptions, IoHints, Options, ReadHandle,
    ReadOptions, Result, Value, WriteHandle, WriteOptions, async_trait,
};
use fsfast_http::HttpFileSystem;
use fsfast_local::LocalFileSystem;
use fsfast_testkit::{SuiteConfig, assert_suite};

#[derive(Debug)]
struct HttpOverLocal {
    http: HttpFileSystem,
    local: LocalFileSystem,
    /// URL prefix the served directory is mounted at (no trailing slash).
    prefix: String,
    /// The served directory.
    root: PathBuf,
}

impl HttpOverLocal {
    fn url(&self, p: &str) -> String {
        format!("{}{}", self.prefix, p)
    }

    fn local(&self, p: &str) -> String {
        self.root
            .join(p.trim_start_matches('/'))
            .to_string_lossy()
            .into_owned()
    }

    fn local_info(&self, mut i: FileInfo) -> FileInfo {
        let root = self.root.to_string_lossy();
        i.name = i
            .name
            .strip_prefix(root.as_ref())
            .unwrap_or(&i.name)
            .to_owned();
        i
    }

    fn url_info(&self, mut i: FileInfo) -> FileInfo {
        i.name = i
            .name
            .strip_prefix(&self.prefix)
            .unwrap_or(&i.name)
            .to_owned();
        i
    }
}

#[async_trait]
impl FileSystem for HttpOverLocal {
    fn protocols(&self) -> &'static [&'static str] {
        self.http.protocols()
    }

    fn capabilities(&self) -> Capabilities {
        // The local side does the setup and cleanup.
        self.local.capabilities()
    }

    fn io_hints(&self) -> IoHints {
        self.http.io_hints()
    }

    async fn info(&self, path: &str) -> Result<FileInfo> {
        Ok(self.url_info(self.http.info(&self.url(path)).await?))
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        self.http.exists(&self.url(path)).await
    }

    async fn ls(&self, path: &str) -> Result<Vec<FileInfo>> {
        Ok(self
            .local
            .ls(&self.local(path))
            .await?
            .into_iter()
            .map(|i| self.local_info(i))
            .collect())
    }

    async fn find(&self, path: &str, opts: &FindOptions) -> Result<Vec<FileInfo>> {
        Ok(self
            .local
            .find(&self.local(path), opts)
            .await?
            .into_iter()
            .map(|i| self.local_info(i))
            .collect())
    }

    async fn open_read(&self, path: &str, opts: &ReadOptions) -> Result<Arc<dyn ReadHandle>> {
        let inner = self.http.open_read(&self.url(path), opts).await?;
        let info = self.url_info(inner.info().clone());
        Ok(Arc::new(Renamed { inner, info }))
    }

    async fn open_write(&self, path: &str, opts: &WriteOptions) -> Result<Box<dyn WriteHandle>> {
        self.local.open_write(&self.local(path), opts).await
    }

    async fn cat_file(&self, path: &str, range: ByteRange) -> Result<Bytes> {
        self.http.cat_file(&self.url(path), range).await
    }

    async fn cat_ranges(&self, path: &str, ranges: &[std::ops::Range<u64>]) -> Result<Vec<Bytes>> {
        self.http.cat_ranges(&self.url(path), ranges).await
    }

    async fn pipe_file(&self, path: &str, data: Bytes, opts: &WriteOptions) -> Result<()> {
        self.local.pipe_file(&self.local(path), data, opts).await
    }

    async fn rm_file(&self, path: &str) -> Result<()> {
        self.local.rm_file(&self.local(path)).await
    }

    async fn mkdir(&self, path: &str, create_parents: bool) -> Result<()> {
        self.local.mkdir(&self.local(path), create_parents).await
    }

    async fn makedirs(&self, path: &str, exist_ok: bool) -> Result<()> {
        self.local.makedirs(&self.local(path), exist_ok).await
    }

    async fn rmdir(&self, path: &str) -> Result<()> {
        self.local.rmdir(&self.local(path)).await
    }

    async fn put_file(&self, local: &Path, remote: &str, opts: &WriteOptions) -> Result<()> {
        self.local.put_file(local, &self.local(remote), opts).await
    }

    async fn get_file(&self, remote: &str, local: &Path) -> Result<()> {
        self.http.get_file(&self.url(remote), local).await
    }
}

/// A read handle reporting the suite's path instead of the URL.
#[derive(Debug)]
struct Renamed {
    inner: Arc<dyn ReadHandle>,
    info: FileInfo,
}

#[async_trait]
impl ReadHandle for Renamed {
    fn info(&self) -> &FileInfo {
        &self.info
    }

    fn io_hints(&self) -> IoHints {
        self.inner.io_hints()
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        self.inner.read_at(offset, len).await
    }

    async fn read_ranges(&self, ranges: &[std::ops::Range<u64>]) -> Result<Vec<Bytes>> {
        self.inner.read_ranges(ranges).await
    }

    async fn close(&self) -> Result<()> {
        self.inner.close().await
    }
}

/// The checks that only need data written by the suite and read back.
const READ_CHECKS: [&str; 8] = [
    "pipe_cat_roundtrip",
    "cat_file_ranges",
    "cat_ranges",
    "open_read_errors",
    "read_at_eof",
    "concurrent_read_at",
    "read_ranges_large",
    "put_get_large",
];

async fn run(mount: &str, block_size: i64, skip: &[&str]) {
    let s = common::start().await;
    let mut opts = Options::new();
    opts.insert("block_size".into(), Value::Int(block_size));
    let fs = HttpOverLocal {
        http: HttpFileSystem::from_options(opts).unwrap(),
        local: LocalFileSystem::new().with_auto_mkdir(true),
        prefix: s.url(mount),
        root: s.dir.path().to_owned(),
    };
    let only: Vec<&str> = READ_CHECKS
        .iter()
        .copied()
        .filter(|c| !skip.contains(c))
        .collect();
    let expected = only.len();
    let cfg = SuiteConfig::default()
        .only(only)
        .large_file_bytes(6 << 20)
        .parallelism(4);
    let report = assert_suite(
        Arc::new(fs),
        "/run",
        SuiteConfig {
            check_timeout: Duration::from_secs(120),
            ..cfg
        },
    )
    .await;
    assert_eq!(report.passed().count(), expected, "{report}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn suite_against_a_static_file_server() {
    run("/files", 1 << 20, &[]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn suite_against_a_server_ignoring_ranges() {
    run("/static-norange", 1 << 20, &[]).await;
}

/// Without any length, `info()["size"]` is `None` (fsspec semantics), so
/// the two checks that verify sizes through `info` do not apply; reads,
/// ranges and EOF handling are still checked byte for byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn suite_against_a_server_without_lengths() {
    run(
        "/static-nolength",
        1 << 20,
        &["pipe_cat_roundtrip", "put_get_large"],
    )
    .await;
}

#[tokio::test]
async fn suite_on_a_current_thread_runtime() {
    run("/files", 256 << 10, &[]).await;
}
