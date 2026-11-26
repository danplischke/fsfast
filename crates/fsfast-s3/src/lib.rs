//! An s3fs-compatible Amazon S3 (and S3-compatible: MinIO, RustFS, Ceph,
//! R2, ...) filesystem for fsfast.
//!
//! [`S3FileSystem`] implements [`fsfast_core::FileSystem`] with s3fs's
//! semantics: paths are `bucket/key`, directories are emulated from key
//! prefixes, `info()`/`ls()`/`find()` return the same entries and keys as
//! s3fs (`ETag`, `LastModified`, `StorageClass`, `VersionId`, ...), the
//! `storage_options` names are s3fs's (see [`options`]), and failures map
//! onto the exception types s3fs raises (see [`error`]).
//!
//! Everything below the filesystem is native:
//!
//! * SigV4 signing ([`sigv4`]), pinned against botocore test vectors;
//! * botocore's credential chain ([`credentials`]: explicit keys,
//!   environment, shared config/credentials files with profiles,
//!   `credential_process`, assume-role, web identity, ECS/EKS container
//!   credentials, EC2 IMDSv2) with caching and refresh before expiry;
//! * region resolution and botocore's region redirects (per-bucket region cache);
//! * addressing ([`endpoint`]): virtual-hosted or path-style, custom
//!   endpoints, dual-stack/FIPS/accelerate;
//! * XML parsing of S3 responses ([`xml`]).
//!
//! Performance: requests go through the shared
//! [`fsfast_http_transport::HttpClient`] (connection pool spread over all of
//! the endpoint's addresses, retries with backoff, adaptive per-host
//! concurrency). Large reads become parallel ranged GETs pinned to the
//! object's ETag, uploads become concurrent multipart uploads under the
//! global memory budget ([`fsfast_engine::PartUploader`]), batch deletes use
//! `DeleteObjects` (1000 keys per request, several requests in flight), and
//! `cat_file` of a small object costs a single request (no `HEAD` first).
//!
//! # Differences from s3fs
//!
//! Deliberate, each covered by a test:
//!
//! * `rm_file`/`rm_files` report missing keys as `NotFound` and directory
//!   prefixes as `IsADirectory` (the fsfast contract); S3 itself deletes
//!   missing keys silently, as s3fs does. `strict_delete=False` restores
//!   s3fs's behaviour and saves the existence check (one `LIST` page per
//!   ~1000 keys of a dense batch, else one `HEAD` per key).
//! * `cat_file` of a range that starts at or after the end of the object
//!   returns empty bytes (fsspec's other filesystems, fsfast contract);
//!   s3fs raises `OSError(EINVAL)` from S3's `InvalidRange`.
//! * `touch(path, truncate=False)` of an existing object is `Unsupported`
//!   (s3fs: `ValueError`).
//! * `open_read` of a directory (a prefix) is `NotFound`; s3fs opens an
//!   empty file.
//! * Pre-signed URLs always use SigV4 query authentication with the
//!   bucket's regional host; botocore may produce SigV2 URLs for custom
//!   endpoints and uses the legacy global host for AWS virtual-hosted URLs.
//! * Multipart copies (objects above `copy_threshold`) keep the content type
//!   and user metadata (s3fs's managed copy loses them), parts are copied in
//!   parallel, and copies on an SSE-C filesystem present the key for the
//!   source as well.
//! * `mkdir` of a bucket in `us-east-1` sends no location constraint (AWS
//!   rejects one); other regions are sent as s3fs does.
//! * Object keys with `.` or `..` path segments are rejected
//!   (`InvalidInput`): URL normalization would address another object.
//!   Access-point and outposts ARNs are split like s3fs but requests to them
//!   are `Unsupported`.
//! * s3fs's listings cache (`use_listings_cache`, `dircache`) belongs to the
//!   Python layer; this crate always asks the server.
//!
//! # Tuning
//!
//! `max_concurrency` (default 16) bounds the parallel requests of one
//! transfer; `request_size` (8 MiB) and `part_size` (16 MiB) size ranged
//! GETs and upload parts; `config_kwargs={"max_pool_connections": n}` caps
//! the connections per host (default 256, adaptive, starting at 64). On
//! HTTPS endpoints object bodies are sent with `UNSIGNED-PAYLOAD`; on plain
//! HTTP they are SHA-256 signed like botocore does, which
//! `config_kwargs={"s3": {"payload_signing_enabled": False}}` turns off.
//! Object bodies carry a `Content-MD5` (needed by Object Lock buckets;
//! botocore sends a CRC32), which
//! `config_kwargs={"request_checksum_calculation": "when_required"}` (or
//! `AWS_REQUEST_CHECKSUM_CALCULATION`) turns off to save the hashing.
//! `speculative_info=True` makes `info()` of directories one round trip
//! instead of two.
//!
//! ```no_run
//! # async fn demo() -> fsfast_core::Result<()> {
//! use fsfast_core::{ByteRange, FileSystem, Options, Value};
//! use fsfast_s3::S3FileSystem;
//!
//! let mut opts = Options::new();
//! opts.insert("endpoint_url".into(), Value::from("http://127.0.0.1:9000"));
//! opts.insert("key".into(), Value::from("testkey"));
//! opts.insert("secret".into(), Value::from("testsecret"));
//! let fs = S3FileSystem::from_options(opts)?;
//! let data = fs.cat_file("bucket/data.bin", ByteRange::Full).await?;
//! # let _ = data;
//! # Ok(()) }
//! ```

#![warn(missing_docs)]

mod client;
pub mod credentials;
pub mod encode;
pub mod endpoint;
pub mod error;
mod extras;
pub mod info;
mod list;
mod mime;
mod ops;
pub mod options;
pub mod params;
pub mod path;
pub mod profile;
mod read;
pub mod sigv4;
mod write;
pub mod xml;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use fsfast_core::{
    ByteRange, Capabilities, Error, FileInfo, FileSystem, FindOptions, IoHints, Options,
    ReadHandle, ReadOptions, Result, WriteHandle, WriteOptions,
};
use fsfast_engine::budget::MemoryBudget;
use fsfast_engine::stats::Stats;
use fsfast_http_transport::HttpClient;
use tokio::sync::OnceCell;

pub use extras::{BUCKET_ACLS, KEY_ACLS};
pub use options::S3Options;
pub use read::S3ReadHandle;
pub use write::S3WriteHandle;

use crate::client::Client;
use crate::credentials::{
    ChainContext, CredentialsCache, ProvideCredentials, StaticProvider, default_chain,
};
use crate::endpoint::Endpoint;
use crate::error::S3ErrorParser;
use crate::profile::{ProfileFiles, profile_name};

/// The S3 filesystem. Cheap to clone (clones share connections, caches and
/// statistics).
#[derive(Clone)]
pub struct S3FileSystem {
    inner: Arc<Inner>,
}

/// s3fs's class name.
pub type S3FS = S3FileSystem;

impl std::fmt::Debug for S3FileSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3FileSystem")
            .field("endpoint_url", &self.inner.opts.endpoint_url)
            .field("anon", &self.inner.opts.anon)
            .field("version_aware", &self.inner.opts.version_aware)
            .finish_non_exhaustive()
    }
}

pub(crate) struct Inner {
    pub opts: S3Options,
    state: OnceCell<Arc<State>>,
    pub hints: IoHints,
    pub stats: Arc<Stats>,
    /// Result of the conditional-write probe (see `write.rs`).
    pub conditional_writes: OnceCell<bool>,
}

/// Resolved configuration and the client (built on first use).
#[derive(Debug)]
pub(crate) struct State {
    pub client: Client,
    /// Location constraint for buckets created by `mkdir`.
    pub bucket_region: Option<String>,
    pub budget: MemoryBudget,
}

impl S3FileSystem {
    /// Build from s3fs `storage_options` (see [`options`] for every accepted
    /// name). Nothing is read from disk or the network until the first
    /// operation (like s3fs, which connects lazily).
    pub fn from_options(opts: Options) -> Result<Self> {
        Ok(Self::with_options(S3Options::parse(opts)?))
    }

    /// Build from parsed options.
    pub fn with_options(opts: S3Options) -> Self {
        let hints = IoHints {
            request_size: opts.request_size,
            max_concurrency: opts.max_concurrency,
            // A ranged GET costs a round trip (10-30 ms on AWS); reading up
            // to 1 MiB of unwanted bytes is cheaper than a second request.
            coalesce_gap: 1 << 20,
            max_coalesced: (opts.request_size as u64).max(32 << 20),
        };
        S3FileSystem {
            inner: Arc::new(Inner {
                opts,
                state: OnceCell::new(),
                hints,
                stats: Arc::new(Stats::new()),
                conditional_writes: OnceCell::new(),
            }),
        }
    }

    /// The parsed options.
    pub fn options(&self) -> &S3Options {
        &self.inner.opts
    }

    /// Request statistics (requests, errors, bytes, retries, throttles,
    /// latency per operation kind).
    pub fn stats(&self) -> &Arc<Stats> {
        &self.inner.stats
    }

    /// s3fs `default_block_size` (block size of file objects).
    pub fn default_block_size(&self) -> usize {
        self.inner.opts.default_block_size
    }

    /// s3fs `default_cache_type`.
    pub fn default_cache_type(&self) -> &str {
        &self.inner.opts.default_cache_type
    }

    /// s3fs `default_fill_cache`.
    pub fn default_fill_cache(&self) -> bool {
        self.inner.opts.default_fill_cache
    }

    /// s3fs `version_aware`.
    pub fn version_aware(&self) -> bool {
        self.inner.opts.version_aware
    }

    /// s3fs `split_path`: `(bucket, key, version_id)`.
    pub fn split_path(&self, path: &str) -> (String, String, Option<String>) {
        let p = path::split_path(path, self.inner.opts.version_aware);
        (p.bucket, p.key, p.version_id)
    }

    /// The resolved client state, built on first use.
    pub(crate) async fn state(&self) -> Result<Arc<State>> {
        self.inner
            .state
            .get_or_try_init(|| async { build_state(&self.inner).await.map(Arc::new) })
            .await
            .cloned()
    }

    /// The region requests for `bucket` are signed for (after any
    /// discovery or redirect learned so far). Resolves the configuration.
    pub async fn bucket_region(&self, bucket: &str) -> Result<String> {
        Ok(self.state().await?.client.region_for(Some(bucket)).await)
    }

    /// The HTTP client (for diagnostics), once the filesystem is resolved.
    pub async fn http_client(&self) -> Result<HttpClient> {
        Ok(self.state().await?.client.http.clone())
    }
}

/// Resolve region, endpoint, TLS settings and credentials from the options,
/// the environment and the shared config files (botocore precedence).
async fn build_state(inner: &Inner) -> Result<State> {
    let opts = &inner.opts;
    let env = &opts.env;
    let profiles = Arc::new(ProfileFiles::load(env).await?);
    let profile = profile_name(opts.profile.as_deref(), env);
    // botocore raises ProfileNotFound for a selected profile that does not
    // exist, whether the option or AWS_DEFAULT_PROFILE / AWS_PROFILE selected
    // it; only the implicit "default" may be missing.
    let selected = opts.profile.is_some()
        || env.get("AWS_DEFAULT_PROFILE").is_some()
        || env.get("AWS_PROFILE").is_some();
    if selected && profiles.profile(&profile).is_none() {
        return Err(Error::invalid_input(format!(
            "The config profile ({profile}) could not be found"
        )));
    }
    let pget = |k: &str| profiles.get(&profile, k).map(str::to_owned);
    let pnested = |k: &str| profiles.nested(&profile, "s3", k).map(str::to_owned);
    let truthy = |v: Option<String>| v.map(|v| v.eq_ignore_ascii_case("true"));

    let region = opts
        .region
        .clone()
        .or_else(|| env.get("AWS_DEFAULT_REGION"))
        .or_else(|| pget("region"));
    let endpoint_url = match &opts.endpoint_url {
        Some(u) => Some(u.clone()),
        None => profile::configured_endpoint(env, &profiles, &profile, "s3")?,
    };
    let mut endpoint = match &endpoint_url {
        Some(u) => Endpoint::custom(u)?,
        None => Endpoint::aws(),
    };
    endpoint.use_ssl = opts.use_ssl;
    endpoint.addressing = match opts.addressing {
        Some(a) => a,
        None => match pnested("addressing_style") {
            Some(a) => endpoint::Addressing::parse(&a)?,
            None => endpoint::Addressing::Auto,
        },
    };
    endpoint.dualstack = opts
        .dualstack
        .or_else(|| truthy(env.get("AWS_USE_DUALSTACK_ENDPOINT")))
        .or_else(|| truthy(pnested("use_dualstack_endpoint")))
        .or_else(|| truthy(pget("use_dualstack_endpoint")))
        .unwrap_or(false);
    endpoint.fips = opts
        .fips
        .or_else(|| truthy(env.get("AWS_USE_FIPS_ENDPOINT")))
        .or_else(|| truthy(pget("use_fips_endpoint")))
        .unwrap_or(false);
    endpoint.accelerate = opts
        .accelerate
        .or_else(|| truthy(pnested("use_accelerate_endpoint")))
        .unwrap_or(false);
    endpoint.us_east_1_regional = opts
        .us_east_1_regional
        .or_else(|| {
            env.get("AWS_S3_US_EAST_1_REGIONAL_ENDPOINT")
                .or_else(|| pnested("us_east_1_regional_endpoint"))
                .map(|v| v == "regional")
        })
        .unwrap_or(false);
    let payload_signing = opts
        .payload_signing
        .or_else(|| truthy(pnested("payload_signing_enabled")));
    // botocore: Config, then AWS_REQUEST_CHECKSUM_CALCULATION, then the
    // profile; "when_supported" by default.
    let request_checksum = match opts.request_checksum {
        Some(v) => v,
        None => match env
            .get("AWS_REQUEST_CHECKSUM_CALCULATION")
            .map(|v| (v, "AWS_REQUEST_CHECKSUM_CALCULATION"))
            .or_else(|| pget("request_checksum_calculation").map(|v| (v, "AWS config profile")))
        {
            Some((v, what)) => options::parse_checksum_calculation(&v, what)?,
            None => true,
        },
    };

    let mut http = opts.http.clone();
    if !opts.tls_configured
        && let Some(ca) = env.get("AWS_CA_BUNDLE").or_else(|| pget("ca_bundle"))
    {
        http.ca_bundle = Some(env.expand(&ca));
    }
    let signing_region = region.clone().unwrap_or_else(|| "us-east-1".to_owned());

    let creds = if opts.anon {
        None
    } else {
        let provider: Arc<dyn ProvideCredentials> = match &opts.credentials {
            Some(c) => Arc::new(StaticProvider(c.clone())),
            None => {
                let mut ctx = ChainContext::new(
                    env.clone(),
                    profiles.clone(),
                    profile.clone(),
                    opts.profile.is_some(),
                );
                ctx.region = region.clone();
                ctx.http = http.clone();
                Arc::new(default_chain(&ctx))
            }
        };
        Some(Arc::new(CredentialsCache::new(provider)))
    };
    let client = HttpClient::builder(http)
        .stats(inner.stats.clone())
        .error_parser(Arc::new(S3ErrorParser))
        .build()?;
    tracing::debug!(
        endpoint = ?endpoint_url,
        region = %signing_region,
        anon = opts.anon,
        "S3 filesystem configured"
    );
    Ok(State {
        client: Client::new(
            client,
            endpoint,
            signing_region,
            creds,
            payload_signing,
            request_checksum,
            opts.params.clone(),
            opts.cache_regions,
        ),
        bucket_region: opts.bucket_region.clone().or(region),
        budget: MemoryBudget::global().clone(),
    })
}

#[async_trait]
impl FileSystem for S3FileSystem {
    fn protocols(&self) -> &'static [&'static str] {
        path::PROTOCOLS
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hierarchical: false,
            atomic_rename: false,
            server_side_copy: true,
            append: true,
            conditional_create: true,
            random_write: false,
            versioning: self.inner.opts.version_aware,
            signed_urls: true,
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

    async fn exists(&self, path: &str) -> Result<bool> {
        self.exists_impl(path).await
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

    async fn makedirs(&self, path: &str, exist_ok: bool) -> Result<()> {
        match self.mkdir_impl(path, true).await {
            Err(e) if exist_ok && e.kind() == fsfast_core::ErrorKind::AlreadyExists => Ok(()),
            other => other,
        }
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
        self.sign_impl(path, expires).await
    }
}
