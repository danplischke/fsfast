//! A gcsfs-compatible Google Cloud Storage filesystem for fsfast.
//!
//! [`GCSFileSystem`] implements [`fsfast_core::FileSystem`] with gcsfs's
//! semantics: paths are `bucket/key` (`gs://` and `gcs://` stripped, see
//! [`path`]), directories are implied by `/` in object names, `info()`,
//! `ls()` and `find()` return the same entries and dict keys as gcsfs (the
//! JSON API object resource plus `mtime`/`ctime`, see [`info`]), the
//! `storage_options` names are gcsfs's (see [`options`]), `token=` works
//! like gcsfs's (service accounts, user credentials, application default
//! credentials, the GCE metadata server, anonymous, raw tokens; see
//! [`auth`]), and failures map onto the exception types gcsfs raises (see
//! [`error`]).
//!
//! Performance:
//!
//! * Requests go through the shared [`fsfast_http_transport::HttpClient`]
//!   (HTTP/2 to GCS, pooled connections, retries with backoff for the
//!   statuses gcsfs retries, adaptive per-host concurrency, statistics).
//! * `info` sends the object GET and a one-entry listing concurrently (one
//!   round trip for files and directories); listings ask for 1000 entries
//!   per page.
//! * Reads are ranged GETs pinned to the object generation; large reads
//!   are split into concurrent parts within the global memory budget;
//!   `cat_file`, `cat_ranges` and `get_file` need no metadata request, and
//!   whole-object downloads are verified with hardware CRC32C.
//! * Small uploads are one request; streams use resumable sessions with
//!   the next chunk filling while the previous one uploads, sent without
//!   copying the caller's buffers (see [`write`] for why resumable sessions
//!   rather than XML multipart uploads).
//! * Copies are server-side (`objects.rewrite`); deletes are concurrent.
//!
//! # Differences from gcsfs
//!
//! Deliberate, each documented on the method:
//!
//! * `cat_file` of a range starting at or after the end of the object
//!   returns empty bytes (fsfast contract); gcsfs raises from GCS's 416.
//! * Object names starting with `/` are reported as `bucket//name` (gcsfs's
//!   `posixpath.join` would drop the bucket, so the name would not round
//!   trip); `info("")` is an empty directory entry.
//! * `rm_files` deletes with concurrent single requests, never with the
//!   batch endpoint (gcsfs batches against Google's endpoint only).
//! * `token` as a raw access token is used without asking Google's
//!   `tokeninfo` endpoint for its expiry (gcsfs does unless
//!   `FETCH_RAW_TOKEN_EXPIRY=false`); `token="cache"`/`"browser"` are
//!   unsupported; the gcloud project comes from gcloud's configuration
//!   files instead of running `gcloud config get project`.
//! * Multipart uploads use a random boundary (gcsfs's fixed `==0==` can
//!   occur in binary data).
//! * Pre-signed URLs are V4 (`GOOG4-RSA-SHA256`); gcsfs delegates to
//!   google-cloud-storage, whose default is V2.
//! * gcsfs's listings cache (`dircache`, `cache_timeout`) belongs to the
//!   Python layer; this crate always asks the server.
//!
//! ```no_run
//! # async fn demo() -> fsfast_core::Result<()> {
//! use fsfast_core::{ByteRange, FileSystem, Options, Value};
//! use fsfast_gcs::GCSFileSystem;
//!
//! let mut opts = Options::new();
//! opts.insert("endpoint_url".into(), Value::from("http://127.0.0.1:4443"));
//! opts.insert("token".into(), Value::from("anon"));
//! let fs = GCSFileSystem::from_options(opts)?;
//! let data = fs.cat_file("bucket/data.bin", ByteRange::Full).await?;
//! # let _ = data;
//! # Ok(()) }
//! ```

#![warn(missing_docs)]

pub mod auth;
mod client;
pub mod env;
pub mod error;
pub mod info;
mod list;
mod mime;
mod ops;
pub mod options;
pub mod path;
mod read;
pub mod sign;
pub mod write;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use bytes::Bytes;
use fsfast_core::{
    ByteRange, Capabilities, Error, FileInfo, FileSystem, FindOptions, IoHints, Options, ReadHandle,
    ReadOptions, Result, WriteHandle, WriteOptions,
};
use fsfast_engine::budget::MemoryBudget;
use fsfast_engine::stats::Stats;
use fsfast_http_transport::HttpClient;

pub use env::GcsEnv;
pub use options::GcsOptions;
pub use read::{GcsReadHandle, crc32c_b64, goog_hash_crc32c};
pub use write::GcsWriteHandle;

use crate::auth::Credentials;
use crate::client::Client;
use crate::error::GcsErrorParser;

/// The GCS filesystem. Cheap to clone (clones share connections,
/// credentials and statistics).
#[derive(Clone)]
pub struct GCSFileSystem {
    pub(crate) inner: Arc<Inner>,
}

/// Alias in Rust naming style.
pub type GcsFileSystem = GCSFileSystem;

impl std::fmt::Debug for GCSFileSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GCSFileSystem")
            .field("location", &self.inner.client.location)
            .field("auth", &self.inner.client.creds.method())
            .field("version_aware", &self.inner.opts.version_aware)
            .finish_non_exhaustive()
    }
}

pub(crate) struct Inner {
    pub opts: GcsOptions,
    pub client: Client,
    pub hints: IoHints,
    pub stats: Arc<Stats>,
    pub budget: MemoryBudget,
    /// The server rejected `objects.move` (emulators): use copy + delete.
    pub move_unsupported: AtomicBool,
}

impl GCSFileSystem {
    /// Build from gcsfs `storage_options` (see [`options`]). Credential
    /// files are read now (gcsfs reads them in its constructor too);
    /// nothing touches the network until the first operation.
    pub fn from_options(opts: Options) -> Result<Self> {
        Self::with_options(GcsOptions::parse(opts)?)
    }

    /// Like [`GCSFileSystem::from_options`] with an explicit environment
    /// instead of the process environment.
    pub fn from_options_with_env(opts: Options, env: GcsEnv) -> Result<Self> {
        Self::with_options(GcsOptions::parse_with_env(opts, env)?)
    }

    /// Build from parsed options.
    pub fn with_options(opts: GcsOptions) -> Result<Self> {
        let location = opts.location()?;
        let on_google = location.contains(&format!("torage.{}", opts.universe_domain()));
        let creds = Arc::new(Credentials::new(
            opts.token.clone(),
            opts.project.clone(),
            &opts.access,
            &opts.env,
            on_google,
        )?);
        let stats = Arc::new(Stats::new());
        let http = HttpClient::builder(opts.http.clone())
            .stats(stats.clone())
            .error_parser(Arc::new(GcsErrorParser))
            .build()?;
        let hints = IoHints {
            request_size: opts.request_size,
            max_concurrency: opts.max_concurrency,
            // A ranged GET costs a round trip (10-30 ms to GCS); reading up
            // to 1 MiB of unwanted bytes is cheaper than another request.
            coalesce_gap: 1 << 20,
            max_coalesced: (opts.request_size as u64).max(32 << 20),
        };
        tracing::debug!(location = %location, auth = creds.method(), "GCS filesystem configured");
        Ok(GCSFileSystem {
            inner: Arc::new(Inner {
                client: Client::new(http, location, creds, opts.requester_pays.clone()),
                opts,
                hints,
                stats,
                budget: MemoryBudget::global().clone(),
                move_unsupported: AtomicBool::new(false),
            }),
        })
    }

    /// The parsed options.
    pub fn options(&self) -> &GcsOptions {
        &self.inner.opts
    }

    /// Request statistics (requests, errors, bytes, retries, throttles,
    /// latency per operation kind).
    pub fn stats(&self) -> &Arc<Stats> {
        &self.inner.stats
    }

    /// The HTTP client (for diagnostics).
    pub fn http_client(&self) -> &HttpClient {
        &self.inner.client.http
    }

    /// gcsfs `_location`: the endpoint requests go to.
    pub fn location(&self) -> &str {
        &self.inner.client.location
    }

    /// gcsfs `on_google`: whether the endpoint is Google's.
    pub fn on_google(&self) -> bool {
        self.inner
            .client
            .location
            .contains(&format!("torage.{}", self.inner.opts.universe_domain()))
    }

    /// gcsfs `default_block_size` (block size of file objects).
    pub fn default_block_size(&self) -> usize {
        self.inner.opts.block_size.unwrap_or(options::DEFAULT_BLOCK_SIZE)
    }

    /// gcsfs `version_aware`.
    pub fn version_aware(&self) -> bool {
        self.inner.opts.version_aware
    }

    /// The authentication method (`anon`, `token`, `google_default`,
    /// `cloud`, or `auto` while the default chain is undecided).
    pub fn auth_method(&self) -> &'static str {
        self.inner.client.creds.method()
    }

    /// gcsfs `project` (resolves credentials, which may query the metadata
    /// server for `token=None`/`"google_default"`).
    pub async fn project(&self) -> Result<Option<String>> {
        self.inner.client.project().await
    }

    /// gcsfs `split_path`: `(bucket, key, generation)`.
    pub fn split_path(&self, path: &str) -> (String, String, Option<String>) {
        let p = path::split_path(path, self.inner.opts.version_aware);
        (p.bucket, p.key, p.generation)
    }

    /// gcsfs `url`: the media download URL of `path`.
    pub fn url(&self, path: &str, generation: Option<&str>) -> Result<String> {
        let p = path::split_path(path, self.inner.opts.version_aware);
        let g = read_generation(generation, p.generation.as_deref())?;
        let mut u = format!(
            "{}?alt=media",
            self.inner.client.download_url(&p.bucket, &p.key)
        );
        if let Some(g) = g {
            u.push_str("&generation=");
            u.push_str(&path::quote(&g));
        }
        Ok(u)
    }

    /// The buckets of the project (gcsfs `buckets`).
    pub async fn buckets(&self) -> Result<Vec<String>> {
        Ok(self
            .list_buckets()
            .await?
            .into_iter()
            .map(|b| b.name.trim_end_matches('/').to_owned())
            .collect())
    }

    /// A V4 signed URL for `method` (e.g. `GET`, `PUT`) valid for
    /// `expires` from `now`.
    pub fn sign_with(&self, path: &str, method: &str, expires: Duration, now: SystemTime) -> Result<String> {
        let key = self.inner.client.creds.signer().ok_or_else(|| {
            Error::unsupported("sign without service-account credentials (a private key is needed)")
        })?;
        let p = path::split_path(path, self.inner.opts.version_aware);
        if p.key.is_empty() {
            return Err(Error::invalid_input(format!("cannot sign a bucket: {path:?}")));
        }
        let secs = expires.as_secs_f64().ceil() as u64;
        sign::signed_url_v4(
            key,
            &self.inner.client.location,
            method,
            &p.bucket,
            &p.key,
            p.generation.as_deref(),
            secs,
            now,
        )
    }
}

fn read_generation(a: Option<&str>, b: Option<&str>) -> Result<Option<String>> {
    read::coalesce_generation(a, b)
}

#[async_trait]
impl FileSystem for GCSFileSystem {
    fn protocols(&self) -> &'static [&'static str] {
        path::PROTOCOLS
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hierarchical: false,
            atomic_rename: false,
            server_side_copy: true,
            append: false,
            conditional_create: true,
            random_write: false,
            versioning: self.inner.opts.version_aware,
            signed_urls: self.inner.client.creds.may_sign(),
            pinned_reads: true,
        }
    }

    fn io_hints(&self) -> IoHints {
        self.inner.hints
    }

    async fn info(&self, path: &str) -> Result<FileInfo> {
        self.info_impl(path).await
    }

    async fn ls(&self, path: &str) -> Result<Vec<FileInfo>> {
        self.ls_impl(path).await
    }

    async fn find(&self, path: &str, opts: &FindOptions) -> Result<Vec<FileInfo>> {
        self.find_impl(path, opts).await
    }

    async fn open_read(&self, path: &str, opts: &ReadOptions) -> Result<Arc<dyn ReadHandle>> {
        Ok(Arc::new(self.open_read_impl(path, opts).await?))
    }

    async fn open_write(&self, path: &str, opts: &WriteOptions) -> Result<Box<dyn WriteHandle>> {
        Ok(Box::new(self.open_write_impl(path, opts).await?))
    }

    async fn cat_file(&self, path: &str, range: ByteRange) -> Result<Bytes> {
        self.cat_file_impl(path, range).await
    }

    async fn cat_ranges(&self, path: &str, ranges: &[std::ops::Range<u64>]) -> Result<Vec<Bytes>> {
        self.cat_ranges_impl(path, ranges).await
    }

    async fn pipe_file(&self, path: &str, data: Bytes, opts: &WriteOptions) -> Result<()> {
        self.pipe_file_impl(path, data, opts).await
    }

    async fn rm_file(&self, path: &str) -> Result<()> {
        self.rm_file_impl(path).await
    }

    async fn rm_files(&self, paths: &[String]) -> Vec<Result<()>> {
        self.rm_files_impl(paths).await
    }

    async fn mkdir(&self, path: &str, create_parents: bool) -> Result<()> {
        self.mkdir_impl(path, create_parents).await
    }

    /// gcsfs inherits fsspec's no-op `makedirs` (directories are implied,
    /// and not even a missing bucket is created).
    async fn makedirs(&self, _path: &str, _exist_ok: bool) -> Result<()> {
        Ok(())
    }

    async fn rmdir(&self, path: &str) -> Result<()> {
        self.rmdir_impl(path).await
    }

    async fn cp_file(&self, src: &str, dst: &str) -> Result<()> {
        self.cp_file_impl(src, dst).await
    }

    async fn mv_file(&self, src: &str, dst: &str) -> Result<()> {
        self.mv_file_impl(src, dst).await
    }

    async fn put_file(&self, local: &Path, remote: &str, opts: &WriteOptions) -> Result<()> {
        self.put_file_impl(local, remote, opts).await
    }

    async fn get_file(&self, remote: &str, local: &Path) -> Result<()> {
        self.get_file_impl(remote, local).await
    }

    async fn touch(&self, path: &str, truncate: bool) -> Result<()> {
        self.touch_impl(path, truncate).await
    }

    async fn sign(&self, path: &str, expires: Duration) -> Result<String> {
        self.sign_with(path, "GET", expires, SystemTime::now())
    }
}
