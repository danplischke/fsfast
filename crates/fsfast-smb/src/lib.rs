//! fsspec-compatible SMB 2/3 filesystem for fsfast.
//!
//! [`SmbFileSystem`] (alias [`SMBFileSystem`]) replaces fsspec's
//! `fsspec.implementations.smb.SMBFileSystem` (smbprotocol/smbclient): the
//! same `storage_options`, the same paths (`/share/dir/file`, the share is
//! the first component), the same `info()` keys and the same errors — on
//! top of a native client built for throughput:
//!
//! * **One TCP connection, many requests in flight.** A reader and a writer
//!   task multiplex requests by MessageId; credits are tracked exactly
//!   (multi-credit large-MTU requests included) and requested generously so
//!   dozens of 1–8 MiB READs/WRITEs are in flight per connection.
//! * **Compounding.** Every metadata operation is one round trip: `info` is
//!   CREATE+CLOSE, `ls` is CREATE+QUERY_DIRECTORY×3+CLOSE, a
//!   small `cat` is CREATE+READ+CLOSE, a small `pipe` CREATE+WRITE+CLOSE,
//!   `rm`/`rmdir`/`mv`/`touch` are CREATE+SET_INFO+CLOSE. (smbclient needs
//!   three to six round trips for each.)
//! * **Pipelined handles.** [`SmbReadHandle`] keeps `max_inflight` READs
//!   in flight and reassembles out-of-order completions in one buffer;
//!   concurrent `read_at` calls share the connection. [`SmbWriteHandle`]
//!   pipelines WRITEs with zero-copy payload slices.
//! * **Server-side copy** (FSCTL_SRV_COPYCHUNK_WRITE) for `cp_file`, with a
//!   streamed fallback.
//! * **Security**: dialects 2.0.2–3.1.1 with SHA-512 preauth integrity,
//!   NTLMv2 via SPNEGO, SP800-108 keys, HMAC-SHA256/AES-CMAC/AES-GMAC
//!   signing of every request and verification of every response,
//!   AES-128/256-GCM/CCM encryption when the session or share requires it
//!   (or `encrypt=True`), FSCTL_VALIDATE_NEGOTIATE_INFO on 3.0/3.0.2.
//!
//! # Options
//!
//! fsspec's: `host` (required), `port`, `username`, `password`, `timeout`,
//! `encrypt`, `share_access`, `register_session_retries`,
//! `register_session_retry_wait`, `register_session_retry_factor`,
//! `auto_mkdir`, `temppath`, plus `AbstractFileSystem`'s cache options
//! (ignored). fsfast extensions: `require_signing`, `min_dialect`,
//! `max_dialect`, `max_credits`, `read_chunk_size`, `write_chunk_size`,
//! `max_inflight`, `connections`, `request_timeout`, `keepalive_interval`
//! (see [`SmbConfig`]).
//!
//! # `info()` records
//!
//! `{"name", "size", "type", "uid", "gid", "time", "mtime"}` exactly like
//! fsspec: `time` is the last access and `mtime` the last write time in
//! float seconds, `uid`/`gid` are 0. fsspec appends `/` to directory names;
//! [`FileInfo::name`](fsfast_core::FileInfo::name) is canonical (no trailing
//! slash, as the fsfast core contract requires) and the slashed form is
//! stored as `extra["name"]`, which overrides `name` in the Python dict
//! (`{"name": ..., **extra}`).
//!
//! # Differences from fsspec's implementation
//!
//! * `mv_file` replaces an existing destination file (POSIX `mv`, and what
//!   every fsfast backend does); smbclient's `rename` raises
//!   `FileExistsError`. Moves across shares fall back to copy + delete
//!   instead of raising `ValueError`.
//! * `ls` of a file returns `[info(file)]` (the fsfast contract and fsspec's
//!   generic behaviour) instead of raising `NotADirectoryError`.
//! * `touch(path, truncate=False)` of an existing file updates its
//!   modification time (fsspec raises `NotImplementedError`).
//! * `workgroup;user` user names (fsspec's URL form) are split into domain
//!   and user. Kerberos/integrated authentication is not available: without
//!   a user name the session is anonymous.

#![warn(missing_docs)]

mod client;
pub mod config;
mod conn;
mod copy;
pub mod credits;
mod handle;
mod ops;
mod peek;
mod session;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use bytes::Bytes;
use fsfast_core::{
    ByteRange, Capabilities, Error, ErrorKind, FileInfo, FileSystem, IoHints, ReadHandle,
    ReadOptions, Result, WriteHandle, WriteMode, WriteOptions, async_trait, copy_via_stream,
};
use fsfast_engine::stats::{OpKind, Stats};
use fsfast_smb_proto::fscc::{CreateAction, CreateDisposition, ShareAccess};

pub use config::{SmbConfig, get_kwargs_from_urls, parent, parse_dialect, strip_protocol};
pub use handle::{SmbReadHandle, SmbWriteHandle};

use crate::client::{Client, Ctx};
use crate::config::{SmbPath, parse_share_access};
use crate::copy::CopyOutcome;
use crate::handle::{IoShape, Undo};
use crate::ops::Listing;

/// What a connection negotiated (diagnostics; see
/// [`SmbFileSystem::connection_info`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionInfo {
    /// Dialect, e.g. `"3.1.1"`.
    pub dialect: String,
    /// Signing algorithm (`"AES-GMAC"`, `"AES-CMAC"`, `"HMAC-SHA256"`), or
    /// `None` for an unsigned guest/anonymous session.
    pub signing_algorithm: Option<String>,
    /// Whether requests are signed (and responses must be).
    pub signing: bool,
    /// Negotiated cipher, if encryption is possible.
    pub cipher: Option<String>,
    /// Whether the whole session is encrypted.
    pub encrypt_all: bool,
    /// Whether requests on the share are encrypted.
    pub share_encrypted: bool,
    /// Server limits.
    pub max_read_size: u32,
    /// Server limits.
    pub max_write_size: u32,
    /// Server limits.
    pub max_transact_size: u32,
    /// Credits currently available plus in flight.
    pub credit_window: usize,
    /// Request frames sent so far over all of the filesystem's connections
    /// (a compound chain is one frame): shows how many round trips
    /// operations cost.
    pub frames_sent: u64,
    /// Local address of the TCP connection.
    pub local_addr: Option<String>,
    /// READ responses received (or, encrypted, decrypted) straight into the
    /// caller's buffer so far, over all connections.
    pub direct_reads: u64,
    /// Connections currently established.
    pub connections: usize,
}

/// Largest speculative READ of the one-round-trip `cat_file`.
const INLINE_READ: usize = 1 << 20;

/// Outcome of `cat_file`'s one-round-trip CREATE+READ+CLOSE attempt.
enum Inline {
    /// The whole requested range.
    Done(Bytes),
    /// A bounded range larger than one READ: nothing was sent.
    TooLarge,
    /// An unbounded read of a file larger than the speculative READ: `data`
    /// holds its first bytes, `eof` the file's size.
    Partial { data: Bytes, eof: u64 },
}

/// The fsspec `info()` keys after `name`/`size`/`type`, in the reference
/// implementation's order (for the Python bindings).
pub const INFO_KEYS: &[&str] = &["uid", "gid", "time", "mtime"];

/// fsspec-compatible SMB filesystem (`protocol = "smb"`).
///
/// Cloning is cheap and shares the connection pool.
#[derive(Clone, Debug)]
pub struct SmbFileSystem {
    client: Arc<Client>,
}

/// fsspec's class name.
pub type SMBFileSystem = SmbFileSystem;

impl SmbFileSystem {
    /// A filesystem for `cfg`. Nothing connects until the first operation
    /// (or [`SmbFileSystem::connect`]).
    pub fn new(cfg: SmbConfig) -> Self {
        SmbFileSystem {
            client: Arc::new(Client::new(cfg)),
        }
    }

    /// Build from fsspec `storage_options` (strict: unknown keys fail).
    pub fn from_options(opts: fsfast_core::Options) -> Result<Self> {
        Ok(Self::new(SmbConfig::from_options(opts)?))
    }

    /// The configuration.
    pub fn config(&self) -> &SmbConfig {
        &self.client.cfg
    }

    /// Request/byte/retry counters and latency histograms.
    pub fn stats(&self) -> &Arc<Stats> {
        &self.client.stats
    }

    /// Connect and authenticate now, as fsspec's constructor does
    /// (`register_session`), so bad credentials or an unreachable server
    /// fail early. Does nothing when `register_session_retries` is
    /// negative (fsspec skips the registration then).
    pub async fn connect(&self) -> Result<()> {
        if self.client.cfg.register_session_retries < 0 {
            return Ok(());
        }
        self.client.connect().await
    }

    /// What the connection serving `share` negotiated (connecting if
    /// needed): dialect, signing and encryption, server limits.
    pub async fn connection_info(&self, share: &str) -> Result<ConnectionInfo> {
        use std::sync::atomic::Ordering::Relaxed;
        let ctx = self.client.ctx(&SmbPath::parse(share)?).await?;
        let conns = self.client.live_connections();
        let n = ctx.live.conn.neg();
        let c = &ctx.live.crypto;
        let dialect = match n.dialect {
            d if d == fsfast_smb_proto::Dialect::SMB_2_0_2 => "2.0.2",
            d if d == fsfast_smb_proto::Dialect::SMB_2_1 => "2.1",
            d if d == fsfast_smb_proto::Dialect::SMB_3_0 => "3.0",
            d if d == fsfast_smb_proto::Dialect::SMB_3_0_2 => "3.0.2",
            _ => "3.1.1",
        };
        let signing_algorithm = c.signer.as_ref().map(|s| {
            match s.algorithm() {
                fsfast_smb_proto::crypto::SigningAlgorithm::HmacSha256 => "HMAC-SHA256",
                fsfast_smb_proto::crypto::SigningAlgorithm::AesCmac => "AES-CMAC",
                fsfast_smb_proto::crypto::SigningAlgorithm::AesGmac => "AES-GMAC",
            }
            .to_owned()
        });
        let cipher = n.cipher.map(|c| {
            match c {
                fsfast_smb_proto::crypto::Cipher::Aes128Ccm => "AES-128-CCM",
                fsfast_smb_proto::crypto::Cipher::Aes128Gcm => "AES-128-GCM",
                fsfast_smb_proto::crypto::Cipher::Aes256Ccm => "AES-256-CCM",
                fsfast_smb_proto::crypto::Cipher::Aes256Gcm => "AES-256-GCM",
            }
            .to_owned()
        });
        Ok(ConnectionInfo {
            dialect: dialect.to_owned(),
            signing_algorithm,
            signing: c.signing,
            cipher,
            encrypt_all: c.encrypt_all,
            share_encrypted: ctx.tree.encrypt,
            max_read_size: n.max_read_size,
            max_write_size: n.max_write_size,
            max_transact_size: n.max_transact_size,
            credit_window: ctx.live.conn.shared.credits.window(),
            frames_sent: conns
                .iter()
                .map(|l| l.conn.shared.frames_sent.load(Relaxed))
                .sum(),
            local_addr: ctx.live.conn.shared.local_addr.map(|a| a.to_string()),
            direct_reads: conns
                .iter()
                .map(|l| l.conn.shared.direct_reads.load(Relaxed))
                .sum(),
            connections: conns.len(),
        })
    }

    fn share_mode(&self, reading: bool) -> ShareAccess {
        // Validated when the options were parsed.
        parse_share_access(self.client.cfg.share_access.as_deref(), reading)
            .unwrap_or(ShareAccess::empty())
    }

    fn read_shape(&self, ctx: &Ctx, block_size: Option<usize>) -> IoShape {
        let want = block_size
            .filter(|b| *b >= 4096)
            .unwrap_or(self.client.cfg.read_chunk_size);
        let max = if ctx.multi_credit() {
            ctx.max_read()
        } else {
            65536
        };
        IoShape {
            chunk: want.min(max).max(4096.min(max)),
            inflight: self.client.cfg.max_inflight,
        }
    }

    fn write_shape(&self, ctx: &Ctx, block_size: Option<usize>) -> IoShape {
        let want = block_size
            .filter(|b| *b >= 4096)
            .unwrap_or(self.client.cfg.write_chunk_size);
        let max = if ctx.multi_credit() {
            ctx.max_write()
        } else {
            65536
        };
        IoShape {
            chunk: want.min(max).max(4096.min(max)),
            inflight: self.client.cfg.max_inflight,
        }
    }

    async fn measure<T>(&self, op: OpKind, fut: impl Future<Output = Result<T>>) -> Result<T> {
        self.client.stats.measure(op, fut).await
    }

    /// Create the parent directory of `p` (fsspec's `auto_mkdir`:
    /// `makedirs(parent, exist_ok=True)`).
    async fn ensure_parent(&self, p: &SmbPath) -> Result<()> {
        match p.parent() {
            Some(parent) if !parent.is_share_root() => self.makedirs_smb(&parent, true).await,
            _ => Ok(()),
        }
    }

    /// smbclient's `makedirs`: create `p`, walking up one level per missing
    /// ancestor (one round trip each) and back down. An existing entry — a
    /// directory or a file — counts as present; `exist_ok` only applies to
    /// `p` itself; a missing parent right below a present entry (a file in
    /// the way) raises the original `NotFound`.
    async fn makedirs_smb(&self, p: &SmbPath, exist_ok: bool) -> Result<()> {
        let mut queue = vec![p.clone()];
        let mut present: Option<String> = None;
        while let Some(cur) = queue.last().cloned() {
            match self.mkdir_create(&cur).await {
                Ok(()) => {
                    queue.pop();
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    present = Some(cur.name.clone());
                    queue.pop();
                    if queue.is_empty() && !exist_ok {
                        return Err(e);
                    }
                }
                Err(e) if e.kind() == ErrorKind::NotFound => match cur.parent() {
                    Some(parent)
                        if !parent.is_share_root()
                            && present.as_deref() != Some(parent.name.as_str())
                            && queue.len() < 1024 =>
                    {
                        queue.push(parent)
                    }
                    _ => return Err(e),
                },
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Open a file for reading on a context.
    async fn open_handle(&self, p: &SmbPath, opts: &ReadOptions) -> Result<Arc<SmbReadHandle>> {
        let share = self.share_mode(true);
        let (ctx, c) = self
            .client
            .run(p, true, |ctx| {
                let req = ops::read_open_req(&p.rel, share);
                async move {
                    let c = ops::open(&ctx, req, &p.name).await?;
                    Ok((ctx, c))
                }
            })
            .await?;
        let info = ops::Meta::from_create(&c).to_info(p.name.clone());
        let shape = self.read_shape(&ctx, opts.block_size);
        Ok(Arc::new(SmbReadHandle::new(
            ctx,
            c.file_id,
            info,
            shape,
            self.client.stats.clone(),
        )))
    }

    /// Finish a whole-file (`Full`/`From`) read whose speculative inline
    /// READ returned `data` (the bytes at `start`) of a file of `eof` bytes:
    /// only the remainder is read, through a handle, instead of discarding
    /// `data` and reading everything again. If the file's size changed in
    /// between, the whole range is re-read so the result is one consistent
    /// version.
    async fn read_rest(&self, p: &SmbPath, start: u64, data: Bytes, eof: u64) -> Result<Bytes> {
        let h = self
            .measure(OpKind::Open, self.open_handle(p, &ReadOptions::default()))
            .await?;
        let size = h.size();
        let out = if size == eof {
            self.client.stats.add_bytes_read(data.len() as u64);
            let at = start + data.len() as u64;
            h.read_after(&data, at, size.saturating_sub(at) as usize)
                .await
        } else if size > start {
            h.read_at(start, (size - start) as usize).await
        } else {
            Ok(Bytes::new())
        };
        let closed = h.close().await;
        let out = out?;
        closed?;
        Ok(out)
    }

    /// Read `[start, end)` (`end = None`: to EOF) through a handle.
    async fn read_via_handle(&self, p: &SmbPath, range: ByteRange) -> Result<Bytes> {
        let h = self
            .measure(OpKind::Open, self.open_handle(p, &ReadOptions::default()))
            .await?;
        let r = range.resolve(h.size());
        let out = if r.end > r.start {
            h.read_at(r.start, (r.end - r.start) as usize).await
        } else {
            Ok(Bytes::new())
        };
        let closed = h.close().await;
        let out = out?;
        closed?;
        Ok(out)
    }

    async fn open_write_inner(&self, p: &SmbPath, opts: &WriteOptions) -> Result<SmbWriteHandle> {
        let disposition = match opts.mode {
            WriteMode::Overwrite => CreateDisposition::OVERWRITE_IF,
            WriteMode::CreateNew => CreateDisposition::CREATE,
            WriteMode::Append => CreateDisposition::OPEN_IF,
        };
        let share = self.share_mode(false);
        let attempt = || {
            self.client
                .run(p, opts.mode != WriteMode::CreateNew, |ctx| {
                    let req = ops::write_open_req(&p.rel, share, disposition);
                    async move {
                        let c = ops::open(&ctx, req, &p.name).await?;
                        Ok((ctx, c))
                    }
                })
        };
        let (ctx, c) = match attempt().await {
            Err(e) if e.kind() == ErrorKind::NotFound && self.client.cfg.auto_mkdir => {
                self.ensure_parent(p).await?;
                attempt().await?
            }
            r => r?,
        };
        let append = opts.mode == WriteMode::Append;
        let undo = if append && c.create_action == CreateAction::OPENED {
            Undo::Truncate(c.end_of_file)
        } else {
            Undo::Delete
        };
        let start = if append { c.end_of_file } else { 0 };
        let shape = self.write_shape(&ctx, opts.block_size);
        let fs = self.clone();
        let target = p.clone();
        let deleter: Box<dyn FnOnce() -> futures::future::BoxFuture<'static, Result<()>> + Send> =
            Box::new(move || {
                Box::pin(async move {
                    fs.client
                        .run(&target, false, |ctx| {
                            let t = target.clone();
                            async move { ops::delete(&ctx, &t, Some(false)).await }
                        })
                        .await
                })
            });
        Ok(SmbWriteHandle::new(
            ctx,
            c.file_id,
            p.name.clone(),
            shape,
            start,
            undo,
            self.client.stats.clone(),
            deleter,
        ))
    }

    async fn write_via_handle(&self, p: &SmbPath, data: Bytes, opts: &WriteOptions) -> Result<()> {
        let mut w = self.open_write_inner(p, opts).await?;
        let res = async {
            if !data.is_empty() {
                w.write(data).await?;
            }
            w.close().await
        }
        .await;
        if res.is_err() {
            let _ = w.abort().await;
        }
        res
    }

    async fn rm_inner(&self, p: &SmbPath, directory: Option<bool>) -> Result<()> {
        self.client
            .run(p, false, |ctx| async move {
                ops::delete(&ctx, p, directory).await
            })
            .await
    }

    async fn mkdir_create(&self, p: &SmbPath) -> Result<()> {
        self.client
            .run(p, false, |ctx| async move {
                ops::mkdir_one(&ctx, p, CreateDisposition::CREATE).await
            })
            .await
    }

    async fn copy_inner(&self, src: &SmbPath, dst: &SmbPath) -> Result<()> {
        if self.client.cfg.auto_mkdir {
            self.ensure_parent(dst).await?;
        }
        let mut attempt = 1;
        let outcome = loop {
            let (sctx, dctx) = self.client.ctx_pair(src, dst).await?;
            match copy::server_side_copy(&sctx, &dctx, src, dst).await {
                Err(e)
                    if attempt < 3
                        && (crate::conn::was_not_sent(&e)
                            || e.kind() == ErrorKind::ConnectionFailed) =>
                {
                    attempt += 1;
                    self.client.stats.add_retry();
                }
                r => break r?,
            }
        };
        match outcome {
            CopyOutcome::Done => Ok(()),
            CopyOutcome::Unsupported => {
                tracing::debug!(
                    src = src.name,
                    dst = dst.name,
                    "server-side copy unsupported; streaming"
                );
                copy_via_stream(self, &src.name, &dst.name).await
            }
        }
    }
}

use std::future::Future;

#[async_trait]
impl FileSystem for SmbFileSystem {
    fn protocols(&self) -> &'static [&'static str] {
        &["smb"]
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hierarchical: true,
            atomic_rename: true,
            server_side_copy: true,
            append: true,
            conditional_create: true,
            random_write: true,
            ..Default::default()
        }
    }

    fn io_hints(&self) -> IoHints {
        IoHints {
            request_size: self.client.cfg.read_chunk_size,
            // Fan-out of independent operations (find, rm_files, ...):
            // compounds are cheap to pipeline on one connection.
            max_concurrency: 64,
            coalesce_gap: 64 << 10,
            max_coalesced: (self.client.cfg.read_chunk_size * 4) as u64,
        }
    }

    async fn info(&self, path: &str) -> Result<FileInfo> {
        let p = SmbPath::parse(path)?;
        let meta = self
            .measure(
                OpKind::Info,
                self.client.run(&p, true, |ctx| {
                    let p = &p;
                    async move { ops::stat(&ctx, p).await }
                }),
            )
            .await?;
        Ok(meta.to_info(p.name))
    }

    async fn ls(&self, path: &str) -> Result<Vec<FileInfo>> {
        let p = SmbPath::parse(path)?;
        let listing = self
            .measure(
                OpKind::List,
                self.client.run(&p, true, |ctx| {
                    let p = &p;
                    async move { ops::list(&ctx, p).await }
                }),
            )
            .await?;
        Ok(match listing {
            Listing::Dir(v) => v,
            Listing::File(m) => vec![m.to_info(p.name)],
        })
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        match self.info(path).await {
            Ok(_) => Ok(true),
            // fsspec's exists() swallows every error; a missing share, a
            // file used as a directory or a path without a share all mean
            // "does not exist" here, while connection problems still raise.
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::NotFound | ErrorKind::NotADirectory | ErrorKind::InvalidInput
                ) =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    async fn open_read(&self, path: &str, opts: &ReadOptions) -> Result<Arc<dyn ReadHandle>> {
        if opts.version.is_some() {
            return Err(Error::unsupported("reading a specific version over SMB"));
        }
        let p = SmbPath::parse(path)?;
        let h = self
            .measure(OpKind::Open, self.open_handle(&p, opts))
            .await?;
        Ok(h)
    }

    async fn open_write(&self, path: &str, opts: &WriteOptions) -> Result<Box<dyn WriteHandle>> {
        let p = SmbPath::parse(path)?;
        let h = self
            .measure(OpKind::Open, self.open_write_inner(&p, opts))
            .await?;
        Ok(Box::new(h))
    }

    async fn cat_file(&self, path: &str, range: ByteRange) -> Result<Bytes> {
        let p = SmbPath::parse(path)?;
        let (start, want) = match range {
            ByteRange::Full => (0, None),
            ByteRange::From(s) => (s, None),
            ByteRange::Bounded { start, end } => (start, Some(end.saturating_sub(start))),
            // The offset depends on the size: open a handle first.
            ByteRange::Suffix(_) => return self.read_via_handle(&p, range).await,
        };
        let share = self.share_mode(true);
        let chunk = self.client.cfg.read_chunk_size;
        // The inline read is one compound round trip (CREATE+READ+CLOSE):
        // one wire request. `None` (too large) also cost that request.
        let fast = self
            .client
            .stats
            .measure(
                OpKind::Read,
                self.client.run(&p, true, |ctx| {
                    let p = &p;
                    async move {
                        let max = if ctx.multi_credit() {
                            ctx.max_read()
                        } else {
                            65536
                        };
                        let inline = ctx.credit_limited(chunk.min(max));
                        let len = match want {
                            Some(w) if w > inline as u64 => return Ok(Inline::TooLarge),
                            Some(w) => w as usize,
                            // A read of unknown length is speculative (the
                            // server allocates the full length): at most 1 MiB,
                            // enough for typical small files.
                            None => inline.min(INLINE_READ),
                        };
                        let (meta, data) = ops::read_small(&ctx, p, share, start, len).await?;
                        let eof = meta.end_of_file;
                        let end = match want {
                            Some(w) => start.saturating_add(w).min(eof),
                            None => eof,
                        };
                        if end <= start {
                            return Ok(Inline::Done(Bytes::new()));
                        }
                        let need = (end - start) as usize;
                        if data.len() >= need {
                            return Ok(Inline::Done(data.slice(..need)));
                        }
                        if want.is_some() {
                            // Short read of a bounded range: the file ended.
                            return Ok(Inline::Done(data));
                        }
                        Ok(Inline::Partial { data, eof })
                    }
                }),
            )
            .await;
        match fast {
            Ok(Inline::Done(b)) => {
                self.client.stats.add_bytes_read(b.len() as u64);
                Ok(b)
            }
            // Larger than one request: read through a pipelined handle
            // (which counts its own requests and bytes).
            Ok(Inline::TooLarge) => self.read_via_handle(&p, range).await,
            Ok(Inline::Partial { data, eof }) => self.read_rest(&p, start, data, eof).await,
            Err(e) => Err(e),
        }
    }

    async fn pipe_file(&self, path: &str, data: Bytes, opts: &WriteOptions) -> Result<()> {
        let p = SmbPath::parse(path)?;
        let disposition = match opts.mode {
            WriteMode::Overwrite => CreateDisposition::OVERWRITE_IF,
            WriteMode::CreateNew => CreateDisposition::CREATE,
            // Appends need the current size: use a handle.
            WriteMode::Append => {
                return self
                    .measure(OpKind::Write, self.write_via_handle(&p, data, opts))
                    .await;
            }
        };
        let share = self.share_mode(false);
        let chunk = self.client.cfg.write_chunk_size;
        let len = data.len();
        let small = || {
            self.client
                .run(&p, opts.mode == WriteMode::Overwrite, |ctx| {
                    let p = &p;
                    let data = data.clone();
                    async move {
                        let max = if ctx.multi_credit() {
                            ctx.max_write()
                        } else {
                            65536
                        };
                        if data.len() > ctx.credit_limited(chunk.min(max)) {
                            return Ok(false);
                        }
                        ops::write_small(&ctx, p, share, disposition, data).await?;
                        Ok(true)
                    }
                })
        };
        let res = async {
            let done = match small().await {
                Err(e) if e.kind() == ErrorKind::NotFound && self.client.cfg.auto_mkdir => {
                    self.ensure_parent(&p).await?;
                    small().await?
                }
                r => r?,
            };
            if !done {
                self.write_via_handle(&p, data.clone(), opts).await?;
            }
            Ok(())
        };
        self.measure(OpKind::Write, res).await?;
        self.client.stats.add_bytes_written(len as u64);
        Ok(())
    }

    async fn rm_file(&self, path: &str) -> Result<()> {
        let p = SmbPath::parse(path)?;
        if p.is_share_root() {
            // fsspec's `_rm` ignores paths without a component below the share.
            return Ok(());
        }
        self.measure(OpKind::Delete, self.rm_inner(&p, None)).await
    }

    async fn mkdir(&self, path: &str, create_parents: bool) -> Result<()> {
        let p = SmbPath::parse(path)?;
        let res = async {
            if create_parents {
                // fsspec: smbclient.makedirs(path, exist_ok=False).
                self.makedirs_smb(&p, false).await
            } else {
                self.mkdir_create(&p).await
            }
        };
        self.measure(OpKind::Other, res).await
    }

    async fn makedirs(&self, path: &str, exist_ok: bool) -> Result<()> {
        let p = SmbPath::parse(path)?;
        if p.is_share_root() {
            // fsspec only acts when the path goes below the share.
            return Ok(());
        }
        self.measure(OpKind::Other, self.makedirs_smb(&p, exist_ok))
            .await
    }

    async fn rmdir(&self, path: &str) -> Result<()> {
        let p = SmbPath::parse(path)?;
        if p.is_share_root() {
            return Ok(());
        }
        self.measure(OpKind::Delete, self.rm_inner(&p, Some(true)))
            .await
    }

    async fn cp_file(&self, src: &str, dst: &str) -> Result<()> {
        let s = SmbPath::parse(src)?;
        let d = SmbPath::parse(dst)?;
        self.measure(OpKind::Copy, self.copy_inner(&s, &d)).await
    }

    async fn mv_file(&self, src: &str, dst: &str) -> Result<()> {
        let s = SmbPath::parse(src)?;
        let d = SmbPath::parse(dst)?;
        if s.name == d.name {
            return Ok(());
        }
        if !s.same_share(&d) || d.is_share_root() || s.is_share_root() {
            // SMB cannot rename across shares: copy, then delete.
            self.copy_inner(&s, &d).await?;
            return self.rm_inner(&s, Some(false)).await;
        }
        self.measure(
            OpKind::Other,
            self.client.run(&s, false, |ctx| {
                let (s, d) = (&s, &d);
                async move { ops::rename(&ctx, s, d, true).await }
            }),
        )
        .await
    }

    async fn touch(&self, path: &str, truncate: bool) -> Result<()> {
        if truncate {
            return self
                .pipe_file(path, Bytes::new(), &WriteOptions::default())
                .await;
        }
        let p = SmbPath::parse(path)?;
        self.measure(
            OpKind::Write,
            self.client.run(&p, true, |ctx| {
                let p = &p;
                async move { ops::touch(&ctx, p).await }
            }),
        )
        .await
    }

    async fn close(&self) -> Result<()> {
        self.client.close().await;
        Ok(())
    }
}
