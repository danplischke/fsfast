//! [`SftpFileSystem`]: the `fsfast_core::FileSystem` implementation.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures::StreamExt;
use futures::stream::FuturesOrdered;

use fsfast_core::{
    ByteRange, Capabilities, Error, ErrorKind, FileInfo, FileSystem, IoHints, Options, ReadHandle,
    ReadOptions, Result, WriteHandle, WriteMode, WriteOptions, async_trait, path,
};
use fsfast_engine::stats::{OpKind, Stats};

use crate::error::{refine, sftp_code};
use crate::handle::{SftpReadHandle, SftpWriteHandle, Undo};
use crate::info::file_info;
use crate::options::SftpConfig;
use crate::pool::{Lease, Pool};
use crate::proto::{FileAttributes, Limits, NameEntry, Request, Statvfs, open_flags, status};
use crate::session::{
    HandleGuard, PendingCall, Session, attrs_reply, handle_reply, readdir_reply, status_reply,
};

/// What the server negotiated (diagnostics; see
/// [`SftpFileSystem::connection_info`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionInfo {
    /// `user@host:port#n` of the session that answered.
    pub label: String,
    /// SFTP protocol version (3).
    pub version: u32,
    /// Extension names the server offered.
    pub extensions: Vec<String>,
    /// `limits@openssh.com`, if offered.
    pub limits: Option<Limits>,
    /// READ request size in use.
    pub read_chunk: usize,
    /// WRITE request size in use.
    pub write_chunk: usize,
    /// Live connections in the pool.
    pub connections: usize,
    /// SSH algorithms of the session's connection.
    pub negotiated: Option<crate::ssh::connect::Negotiated>,
}

struct FsInner {
    cfg: Arc<SftpConfig>,
    pool: Pool,
    stats: Arc<Stats>,
}

/// fsspec-compatible SFTP filesystem (`sftp://`, `ssh://`).
#[derive(Clone)]
pub struct SftpFileSystem {
    inner: Arc<FsInner>,
}

/// fsspec's class name.
pub type SFTPFileSystem = SftpFileSystem;

impl std::fmt::Debug for SftpFileSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpFileSystem")
            .field("host", &self.inner.cfg.host)
            .field("pool", &self.inner.pool)
            .finish()
    }
}

/// Seconds since the epoch, as SFTP v3 stores times.
fn now_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().min(u64::from(u32::MAX)) as u32)
        .unwrap_or(0)
}

fn bytes_of(s: &str) -> Bytes {
    Bytes::copy_from_slice(s.as_bytes())
}

/// OpenSSH's report of ENOTDIR: `NO_SUCH_FILE`, i.e. NotFound (fsspec's
/// `FileNotFoundError`), with a message naming the component `what` that is
/// not a directory.
fn enotdir(op: &str, what: &str, path: &str) -> Error {
    Error::new(
        ErrorKind::NotFound,
        format!("{op}: {what} is not a directory"),
    )
    .with_detail(fsfast_core::Detail::Sftp(status::NO_SUCH_FILE))
    .with_path(path)
}

/// The listing name of `entry` in directory `base` (fsspec:
/// `"/".join([parent.rstrip("/"), filename])`).
fn child_name(base: &str, entry: &str) -> String {
    format!("{}/{entry}", base.trim_end_matches('/'))
}

impl SftpFileSystem {
    /// A filesystem for `cfg`. Nothing connects until the first operation.
    pub fn new(cfg: SftpConfig) -> Self {
        let cfg = Arc::new(cfg);
        SftpFileSystem {
            inner: Arc::new(FsInner {
                pool: Pool::new(cfg.clone()),
                cfg,
                stats: Arc::new(Stats::new()),
            }),
        }
    }

    /// Build from fsspec `storage_options` (see [`SftpConfig::from_options`]).
    pub fn from_options(opts: Options) -> Result<Self> {
        Ok(Self::new(SftpConfig::from_options(opts)?))
    }

    /// The configuration.
    pub fn config(&self) -> &SftpConfig {
        &self.inner.cfg
    }

    /// fsspec's `temppath` (where transactions stage files).
    pub fn temppath(&self) -> &str {
        &self.inner.cfg.temppath
    }

    /// Request, byte and latency counters.
    pub fn stats(&self) -> &Arc<Stats> {
        &self.inner.stats
    }

    /// Live connections in the pool.
    pub fn connections(&self) -> usize {
        self.inner.pool.size()
    }

    /// Connect if needed and report what the server negotiated.
    pub async fn connection_info(&self) -> Result<ConnectionInfo> {
        let s = self.inner.pool.get().await?;
        Ok(ConnectionInfo {
            label: s.label().to_owned(),
            version: s.version().version,
            extensions: s
                .version()
                .extensions
                .iter()
                .map(|(n, _)| n.clone())
                .collect(),
            limits: s.limits(),
            read_chunk: s.read_chunk(),
            write_chunk: s.write_chunk(),
            connections: self.inner.pool.size(),
            negotiated: s.negotiated().cloned(),
        })
    }

    /// Run `f` on a pooled session, recording stats. Idempotent operations
    /// are retried once on a fresh connection when their session died.
    async fn run<T, F, Fut>(&self, op: OpKind, idempotent: bool, f: F) -> Result<T>
    where
        F: Fn(Lease) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let start = Instant::now();
        let mut retried = false;
        let r = loop {
            let lease = match self.inner.pool.get().await {
                Ok(l) => l,
                Err(e) => break Err(e),
            };
            let session = (*lease).clone();
            match f(lease).await {
                Err(e)
                    if idempotent
                        && !retried
                        && e.kind() == ErrorKind::ConnectionFailed
                        && session.is_closed() =>
                {
                    tracing::debug!("sftp: retrying on a new connection after: {e}");
                    self.inner.stats.add_retry();
                    retried = true;
                }
                r => break r,
            }
        };
        self.inner
            .stats
            .record_request(op, start.elapsed(), r.is_ok());
        if r.is_err() {
            self.inner.stats.add_error();
        }
        r
    }

    /// `LSTAT`-based info: does not follow a final symlink (`type` is
    /// `"link"` for symlinks, as in `ls`).
    pub async fn lstat_info(&self, p: &str) -> Result<FileInfo> {
        let name = path::normalize(p);
        let p = p.to_owned();
        self.run(OpKind::Info, true, move |s| {
            let (p, name) = (p.clone(), name.clone());
            async move { Ok(file_info(name, &s.lstat(&p).await?)) }
        })
        .await
    }

    /// Target of the symlink at `p`.
    pub async fn readlink(&self, p: &str) -> Result<String> {
        let p = p.to_owned();
        self.run(OpKind::Info, true, move |s| {
            let p = p.clone();
            async move { s.readlink(&p).await }
        })
        .await
    }

    /// Create a symlink at `link` pointing to `target`.
    pub async fn symlink(&self, target: &str, link: &str) -> Result<()> {
        let s = self.inner.pool.get().await?;
        s.symlink(target, link).await
    }

    /// Create a hard link `new` to `old` (`hardlink@openssh.com`).
    pub async fn hardlink(&self, old: &str, new: &str) -> Result<()> {
        let s = self.inner.pool.get().await?;
        s.hardlink(old, new).await
    }

    /// File system statistics of the volume holding `p`
    /// (`statvfs@openssh.com`).
    pub async fn statvfs(&self, p: &str) -> Result<Statvfs> {
        let s = self.inner.pool.get().await?;
        s.statvfs(p).await
    }

    /// Canonical absolute form of `p` (`REALPATH`; `"."` is the login
    /// directory).
    pub async fn realpath(&self, p: &str) -> Result<String> {
        let s = self.inner.pool.get().await?;
        s.realpath(p).await
    }

    /// `p` with `~`/`~user` expanded (`expand-path@openssh.com`).
    pub async fn expand_path(&self, p: &str) -> Result<String> {
        let s = self.inner.pool.get().await?;
        s.expand_path(p).await
    }

    /// Home directory of `user`, or of the login user when `user` is
    /// empty. Uses the `home-directory` extension for named users (OpenSSH
    /// needs an explicit name there) and `expand-path@openssh.com` (`~`) or
    /// `REALPATH(".")` for the login user.
    pub async fn home_directory(&self, user: &str) -> Result<String> {
        let s = self.inner.pool.get().await?;
        let e = s.extensions();
        if !user.is_empty() {
            if e.home_directory {
                return s.home_directory(user).await;
            }
            if e.expand_path {
                return s.expand_path(&format!("~{user}")).await;
            }
            return Err(Error::unsupported(
                "home directories of other users (home-directory extension)",
            ));
        }
        if e.expand_path {
            s.expand_path("~").await
        } else {
            s.realpath(".").await
        }
    }

    /// Set the permission bits of `p` (`SETSTAT`).
    pub async fn chmod(&self, p: &str, mode: u32) -> Result<()> {
        let s = self.inner.pool.get().await?;
        s.setstat(
            p,
            FileAttributes {
                permissions: Some(mode & 0o7777),
                ..Default::default()
            },
        )
        .await
    }

    /// Set access and modification times of `p` (`SETSTAT`).
    pub async fn set_times(&self, p: &str, atime: u32, mtime: u32) -> Result<()> {
        let s = self.inner.pool.get().await?;
        s.setstat(p, FileAttributes::with_times(atime, mtime)).await
    }

    /// Refine an error from a path operation whose status was `FAILURE`
    /// (OpenSSH's catch-all) by looking at what is at `p`.
    async fn lstat_kind(s: &Session, p: &str) -> Option<bool> {
        match s.lstat(p).await {
            Ok(a) => Some(a.is_dir()),
            Err(_) => None,
        }
    }

    fn is_failure(e: &Error) -> bool {
        sftp_code(e) == Some(status::FAILURE)
    }

    /// Open `p` for writing in `mode`; maps OpenSSH's FAILURE replies
    /// (EEXIST, EISDIR) to precise kinds.
    async fn open_for_write(
        &self,
        s: &Session,
        p: &str,
        mode: WriteMode,
    ) -> Result<(Bytes, u64, Undo)> {
        use open_flags::*;
        let res = match mode {
            WriteMode::Overwrite => s
                .open(p, WRITE | CREAT | TRUNC, FileAttributes::default())
                .await
                .map(|h| (h, 0, Undo::Remove)),
            WriteMode::CreateNew => s
                .open(p, WRITE | CREAT | EXCL, FileAttributes::default())
                .await
                .map(|h| (h, 0, Undo::Remove)),
            WriteMode::Append => {
                // Create-exclusive first: success means the file is new (an
                // abort removes it); otherwise append to the existing file
                // at its current end (an abort truncates back). Writes also
                // carry explicit offsets, for servers that ignore APPEND.
                match s
                    .open(p, WRITE | CREAT | EXCL | APPEND, FileAttributes::default())
                    .await
                {
                    Ok(h) => Ok((h, 0, Undo::Remove)),
                    Err(e) if Self::is_failure(&e) || e.kind() == ErrorKind::AlreadyExists => {
                        match s.open(p, WRITE | APPEND, FileAttributes::default()).await {
                            Ok(h) => {
                                // Closed if FSTAT fails or is cancelled.
                                let h = HandleGuard::new(s, h);
                                let a = s.fstat(h.handle(), p).await?;
                                let size = a.size.unwrap_or(0);
                                Ok((h.disarm(), size, Undo::Truncate(size)))
                            }
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                }
            }
        };
        match res {
            Ok(v) => Ok(v),
            Err(e) if Self::is_failure(&e) => match Self::lstat_kind(s, p).await {
                Some(true) => Err(refine(e, ErrorKind::IsADirectory)),
                Some(false) if mode == WriteMode::CreateNew => {
                    Err(refine(e, ErrorKind::AlreadyExists))
                }
                _ => Err(e),
            },
            Err(e) => Err(e),
        }
    }

    /// Pipelined `MKDIR` of every missing component of `p` (one round
    /// trip for any depth: the server handles them in order, existing
    /// components just fail with EEXIST).
    async fn mkdir_p(&self, s: &Session, p: &str) -> Result<()> {
        let norm = path::normalize(p);
        let mut dirs = path::ancestors(&norm);
        dirs.push(norm.clone());
        let calls: Vec<(String, PendingCall)> = dirs
            .into_iter()
            .filter(|d| !d.is_empty() && d != "/")
            .map(|d| {
                let c = s.start_call(&Request::Mkdir {
                    path: bytes_of(&d),
                    attrs: FileAttributes::default(),
                })?;
                Ok((d, c))
            })
            .collect::<Result<_>>()?;
        let mut results = Vec::with_capacity(calls.len());
        for (d, c) in calls {
            let r = s.finish(c).await.and_then(|r| status_reply(r, "mkdir", &d));
            results.push((d, r));
        }
        let Some((_, last)) = results.pop() else {
            return Ok(());
        };
        match last {
            Ok(()) => Ok(()),
            Err(e) if Self::is_failure(&e) => match Self::lstat_kind(s, p).await {
                Some(_) => Err(refine(e, ErrorKind::AlreadyExists)),
                None => Err(e),
            },
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // A component exists but is not a directory (ENOTDIR maps to
                // NO_SUCH_FILE): name it in the message if we can. The kind
                // stays NotFound, the FileNotFoundError fsspec raises here.
                for (d, r) in results {
                    if r.is_err() && Self::lstat_kind(s, &d).await == Some(false) {
                        return Err(enotdir("mkdir", &d, p));
                    }
                }
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    async fn list_dir(s: &Session, p: &str) -> Result<Vec<NameEntry>> {
        // The guard closes the handle when this function returns *or* is
        // cancelled. Nothing useful can come back from closing a directory
        // handle: the CLOSE is not waited for.
        let h = HandleGuard::new(s, s.opendir(p).await?);
        Self::read_dir(s, h.handle(), p).await
    }

    async fn read_dir(s: &Session, h: &Bytes, p: &str) -> Result<Vec<NameEntry>> {
        let mut out = Vec::new();
        // READDIRs are pipelined: two at first (a small directory is one
        // batch plus EOF, i.e. one round trip), doubling for big ones.
        let mut depth = 2usize;
        loop {
            let calls: Vec<PendingCall> = (0..depth)
                .map(|_| s.start_readdir(h))
                .collect::<Result<_>>()?;
            let mut eof = false;
            for c in calls {
                match readdir_reply(s.finish(c).await?, p)? {
                    Some(v) => out.extend(v),
                    None => eof = true,
                }
            }
            if eof {
                return Ok(out);
            }
            depth = (depth * 2).min(32);
        }
    }

    async fn open_read_on(&self, s: Lease, p: &str, opts: &ReadOptions) -> Result<SftpReadHandle> {
        if opts.version.is_some() {
            return Err(Error::unsupported("reading a specific version over SFTP"));
        }
        let name = path::normalize(p);
        // STAT and OPEN both take the path: send them together, one round
        // trip instead of OPEN followed by FSTAT.
        let st = s.start_call(&Request::Stat { path: bytes_of(p) })?;
        let op = s.start_call(&Request::Open {
            path: bytes_of(p),
            pflags: open_flags::READ,
            attrs: FileAttributes::default(),
        })?;
        let st = s.finish(st).await.and_then(|r| attrs_reply(r, "stat", p));
        let op = s.finish(op).await.and_then(|r| handle_reply(r, "open", p));
        let attrs = match st {
            Ok(a) => a,
            Err(e) => {
                if let Ok(h) = op {
                    s.close_nowait(h);
                }
                return Err(e);
            }
        };
        if attrs.is_dir() {
            if let Ok(h) = op {
                s.close_nowait(h);
            }
            return Err(Error::is_a_directory(name));
        }
        let h = op?;
        Ok(SftpReadHandle::new(
            s,
            h,
            file_info(name, &attrs),
            self.inner.cfg.max_inflight,
            self.inner.stats.clone(),
        ))
    }

    async fn copy_between(
        &self,
        s: &Session,
        src: &SftpReadHandle,
        dst: &Bytes,
        dst_path: &str,
    ) -> Result<()> {
        let size = src.info().size;
        if size > 0 && s.extensions().copy_data {
            match s
                .copy_data(src.raw_handle(), 0, size, dst, 0, dst_path)
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == ErrorKind::Unsupported || Self::is_failure(&e) => {
                    tracing::debug!("copy-data failed ({e}); copying through the client");
                }
                Err(e) => return Err(e),
            }
        }
        // Stream: pipelined READs feeding pipelined WRITEs at the same
        // offsets. The destination is not truncated first, so copying a
        // file onto another name for itself cannot destroy it.
        let mut reads = src.pipeline(0, size);
        let mut writes: std::collections::VecDeque<PendingCall> = Default::default();
        let max = self.inner.cfg.max_inflight.max(1);
        let wchunk = s.write_chunk().max(1);
        let mut off = 0u64;
        while let Some(p) = reads.next_chunk().await? {
            let mut data = p.into_bytes();
            while !data.is_empty() {
                let piece = data.split_to(data.len().min(wchunk));
                while writes.len() >= max {
                    if let Some(c) = writes.pop_front() {
                        status_reply(s.finish(c).await?, "write", dst_path)?;
                    }
                }
                let n = piece.len() as u64;
                writes.push_back(s.start_call(&Request::Write {
                    handle: dst.clone(),
                    offset: off,
                    data: piece,
                })?);
                off += n;
            }
        }
        while let Some(c) = writes.pop_front() {
            status_reply(s.finish(c).await?, "write", dst_path)?;
        }
        Ok(())
    }
}

#[async_trait]
impl FileSystem for SftpFileSystem {
    fn protocols(&self) -> &'static [&'static str] {
        &["sftp", "ssh"]
    }

    fn capabilities(&self) -> Capabilities {
        // Before the first connection assume an OpenSSH server
        // (posix-rename, no copy-data); afterwards report what it offers.
        let (posix_rename, copy_data, _) = self
            .inner
            .pool
            .known_extensions()
            .unwrap_or((true, false, false));
        Capabilities {
            hierarchical: true,
            atomic_rename: posix_rename,
            server_side_copy: copy_data,
            append: true,
            conditional_create: true,
            random_write: true,
            versioning: false,
            signed_urls: false,
            pinned_reads: false,
        }
    }

    fn io_hints(&self) -> IoHints {
        IoHints {
            request_size: 4 << 20,
            max_concurrency: 32,
            coalesce_gap: 256 << 10,
            max_coalesced: 8 << 20,
        }
    }

    async fn info(&self, p: &str) -> Result<FileInfo> {
        let name = path::normalize(p);
        let p = p.to_owned();
        self.run(OpKind::Info, true, move |s| {
            let (p, name) = (p.clone(), name.clone());
            async move { Ok(file_info(name, &s.stat(&p).await?)) }
        })
        .await
    }

    async fn ls(&self, p: &str) -> Result<Vec<FileInfo>> {
        let base = path::normalize(p);
        let p = p.to_owned();
        self.run(OpKind::List, true, move |s| {
            let (p, base) = (p.clone(), base.clone());
            async move {
                let entries = match Self::list_dir(&s, &p).await {
                    Ok(v) => v,
                    Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::Io) => {
                        // OPENDIR of a file fails with NO_SUCH_FILE (ENOTDIR)
                        // on OpenSSH; listing a file returns the file.
                        match s.stat(&p).await {
                            Ok(a) if !a.is_dir() => return Ok(vec![file_info(base, &a)]),
                            _ => return Err(e),
                        }
                    }
                    Err(e) => return Err(e),
                };
                Ok(entries
                    .into_iter()
                    .filter(|e| e.filename != "." && e.filename != "..")
                    .map(|e| file_info(child_name(&base, &e.filename), &e.attrs))
                    .collect())
            }
        })
        .await
    }

    async fn open_read(&self, p: &str, opts: &ReadOptions) -> Result<Arc<dyn ReadHandle>> {
        let p = p.to_owned();
        let h = self
            .run(OpKind::Open, true, move |s| {
                let p = p.clone();
                async move { self.open_read_on(s, &p, opts).await }
            })
            .await?;
        Ok(Arc::new(h))
    }

    async fn cat_file(&self, p: &str, range: ByteRange) -> Result<Bytes> {
        let p = p.to_owned();
        self.run(OpKind::Read, true, move |s| {
            let p = p.clone();
            async move {
                let h = self.open_read_on(s, &p, &ReadOptions::default()).await?;
                // Read to the server's EOF, not to the size STAT reported
                // (paramiko does): /proc-style files report size 0, and the
                // file may grow or shrink after the STAT. Only a suffix
                // range needs the size to know where to start.
                let (start, end) = match range {
                    ByteRange::Full => (0, None),
                    ByteRange::From(s) => (s, None),
                    ByteRange::Bounded { start, end } => (start, Some(end.max(start))),
                    ByteRange::Suffix(_) => {
                        let r = range.resolve(h.size());
                        (r.start, None)
                    }
                };
                let out = if end.is_none_or(|e| e > start) {
                    h.pipeline_to_eof(start, end).collect().await?
                } else {
                    Bytes::new()
                };
                self.inner.stats.add_bytes_read(out.len() as u64);
                // Dropping the handle sends CLOSE without waiting for it.
                drop(h);
                Ok(out)
            }
        })
        .await
    }

    async fn open_write(&self, p: &str, opts: &WriteOptions) -> Result<Box<dyn WriteHandle>> {
        let start = Instant::now();
        let r = async {
            let s = self.inner.pool.get().await?;
            let (h, offset, undo) = self.open_for_write(&s, p, opts.mode).await?;
            let fsync = self.inner.cfg.fsync_on_close && s.extensions().fsync;
            Ok::<_, Error>(Box::new(SftpWriteHandle::new(
                s,
                h,
                p.to_owned(),
                offset,
                undo,
                self.inner.cfg.max_inflight,
                fsync,
                self.inner.stats.clone(),
            )) as Box<dyn WriteHandle>)
        }
        .await;
        self.inner
            .stats
            .record_request(OpKind::Open, start.elapsed(), r.is_ok());
        r
    }

    async fn rm_file(&self, p: &str) -> Result<()> {
        let p = p.to_owned();
        self.run(OpKind::Delete, false, move |s| {
            let p = p.clone();
            async move {
                match s.remove(&p).await {
                    Err(e) if Self::is_failure(&e) => match Self::lstat_kind(&s, &p).await {
                        Some(true) => Err(refine(e, ErrorKind::IsADirectory)),
                        _ => Err(e),
                    },
                    r => r,
                }
            }
        })
        .await
    }

    async fn rm_files(&self, paths: &[String]) -> Vec<Result<()>> {
        if paths.is_empty() {
            return Vec::new();
        }
        let s = match self.inner.pool.get().await {
            Ok(s) => s,
            Err(e) => {
                let (k, m) = (e.kind(), e.message().to_owned());
                return paths
                    .iter()
                    .map(|_| Err(Error::new(k, m.clone())))
                    .collect();
            }
        };
        let start = Instant::now();
        // All REMOVEs pipelined on one session, a bounded number in flight.
        let window = self.inner.cfg.max_inflight.max(16);
        let mut out: Vec<Result<()>> = Vec::with_capacity(paths.len());
        let mut inflight: FuturesOrdered<_> = FuturesOrdered::new();
        let mut it = paths.iter();
        loop {
            while inflight.len() < window {
                let Some(p) = it.next() else { break };
                let call = s.start_call(&Request::Remove { path: bytes_of(p) });
                let sess = &*s;
                inflight.push_back(async move {
                    let r = match call {
                        Ok(c) => sess
                            .finish(c)
                            .await
                            .and_then(|r| status_reply(r, "remove", p)),
                        Err(e) => Err(e),
                    };
                    (p, r)
                });
            }
            let Some((p, r)) = inflight.next().await else {
                break;
            };
            let r = match r {
                Err(e) if Self::is_failure(&e) => match Self::lstat_kind(&s, p).await {
                    Some(true) => Err(refine(e, ErrorKind::IsADirectory)),
                    _ => Err(e),
                },
                r => r,
            };
            out.push(r);
        }
        self.inner.stats.record_request(
            OpKind::Delete,
            start.elapsed(),
            out.iter().all(Result::is_ok),
        );
        out
    }

    async fn mkdir(&self, p: &str, create_parents: bool) -> Result<()> {
        let p = p.to_owned();
        self.run(OpKind::Other, false, move |s| {
            let p = p.clone();
            async move {
                match s.mkdir(&p).await {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == ErrorKind::NotFound && create_parents => {
                        self.mkdir_p(&s, &p).await
                    }
                    Err(e) if Self::is_failure(&e) => match Self::lstat_kind(&s, &p).await {
                        Some(_) => Err(refine(e, ErrorKind::AlreadyExists)),
                        None => Err(e),
                    },
                    Err(e) => Err(e),
                }
            }
        })
        .await
    }

    async fn makedirs(&self, p: &str, exist_ok: bool) -> Result<()> {
        let p = p.to_owned();
        self.run(OpKind::Other, false, move |s| {
            let p = p.clone();
            async move {
                // STAT and MKDIR in one round trip: the common cases (the
                // directory exists, or only its last component is missing)
                // need nothing else.
                let st = s.start_call(&Request::Stat { path: bytes_of(&p) })?;
                let mk = s.start_call(&Request::Mkdir {
                    path: bytes_of(&p),
                    attrs: FileAttributes::default(),
                })?;
                let st = s.finish(st).await.and_then(|r| attrs_reply(r, "stat", &p));
                let mk = s
                    .finish(mk)
                    .await
                    .and_then(|r| status_reply(r, "mkdir", &p));
                match (st, mk) {
                    (Ok(a), _) => {
                        if a.is_dir() && exist_ok {
                            Ok(())
                        } else {
                            Err(Error::already_exists(path::normalize(&p)))
                        }
                    }
                    (Err(_), Ok(())) => Ok(()),
                    (Err(_), Err(e)) if e.kind() == ErrorKind::NotFound => {
                        match self.mkdir_p(&s, &p).await {
                            // Someone else created it meanwhile.
                            Err(e) if e.kind() == ErrorKind::AlreadyExists && exist_ok => {
                                match s.stat(&p).await {
                                    Ok(a) if a.is_dir() => Ok(()),
                                    _ => Err(e),
                                }
                            }
                            r => r,
                        }
                    }
                    (Err(_), Err(e)) if Self::is_failure(&e) => {
                        // Created between our STAT and MKDIR.
                        match s.stat(&p).await {
                            Ok(a) if a.is_dir() && exist_ok => Ok(()),
                            Ok(_) => Err(refine(e, ErrorKind::AlreadyExists)),
                            Err(_) => Err(e),
                        }
                    }
                    (Err(_), Err(e)) => Err(e),
                }
            }
        })
        .await
    }

    async fn rmdir(&self, p: &str) -> Result<()> {
        let p = p.to_owned();
        self.run(OpKind::Delete, false, move |s| {
            let p = p.clone();
            async move {
                match s.rmdir(&p).await {
                    Ok(()) => Ok(()),
                    // ENOTEMPTY (and EEXIST on some file systems) become
                    // FAILURE; a directory that is still there is not empty.
                    Err(e) if Self::is_failure(&e) => match Self::lstat_kind(&s, &p).await {
                        Some(true) => Err(refine(e, ErrorKind::DirectoryNotEmpty)),
                        Some(false) => Err(refine(e, ErrorKind::NotADirectory)),
                        None => Err(e),
                    },
                    // ENOTDIR becomes NO_SUCH_FILE, which fsspec raises as
                    // FileNotFoundError: keep the kind, say why.
                    Err(e) if e.kind() == ErrorKind::NotFound => {
                        match Self::lstat_kind(&s, &p).await {
                            Some(false) => Err(enotdir("rmdir", &p, &p)),
                            _ => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                }
            }
        })
        .await
    }

    async fn mv_file(&self, src: &str, dst: &str) -> Result<()> {
        let (src, dst) = (src.to_owned(), dst.to_owned());
        self.run(OpKind::Other, false, move |s| {
            let (src, dst) = (src.clone(), dst.clone());
            async move {
                if path::normalize(&src) == path::normalize(&dst) {
                    // Moving onto itself: a no-op once the source exists.
                    return s.lstat(&src).await.map(|_| ());
                }
                match s.rename(&src, &dst).await {
                    Ok(()) => Ok(()),
                    Err(e) if Self::is_failure(&e) => {
                        let dst_kind = Self::lstat_kind(&s, &dst).await;
                        if !s.extensions().posix_rename && dst_kind == Some(false) {
                            // Plain v3 RENAME refuses to replace: emulate
                            // POSIX semantics (not atomic).
                            s.remove(&dst).await?;
                            return s.rename_plain(&src, &dst).await;
                        }
                        match dst_kind {
                            Some(true) => Err(refine(e, ErrorKind::IsADirectory).with_path(dst)),
                            _ => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                }
            }
        })
        .await
    }

    async fn cp_file(&self, src: &str, dst: &str) -> Result<()> {
        let (src, dst) = (src.to_owned(), dst.to_owned());
        self.run(OpKind::Copy, false, move |s| {
            let (src, dst) = (src.clone(), dst.clone());
            async move {
                if path::normalize(&src) == path::normalize(&dst) {
                    // Copy onto itself: leave the file untouched.
                    return s.stat(&src).await.map(|_| ());
                }
                let session: Session = (*s).clone();
                let rh = self.open_read_on(s, &src, &ReadOptions::default()).await?;
                let wh = match session
                    .open(
                        &dst,
                        open_flags::WRITE | open_flags::CREAT,
                        FileAttributes::default(),
                    )
                    .await
                {
                    Ok(h) => h,
                    Err(e) if Self::is_failure(&e) => {
                        return match Self::lstat_kind(&session, &dst).await {
                            Some(true) => Err(refine(e, ErrorKind::IsADirectory)),
                            _ => Err(e),
                        };
                    }
                    Err(e) => return Err(e),
                };
                let size = rh.info().size;
                // Closes the destination handle if the copy is cancelled.
                let wh = HandleGuard::new(&session, wh);
                let r = async {
                    self.copy_between(&session, &rh, wh.handle(), &dst).await?;
                    // Cut whatever the old destination had past the copy.
                    session
                        .fsetstat(wh.handle(), FileAttributes::with_size(size), &dst)
                        .await
                }
                .await;
                let closed = session.close(wh.disarm(), &dst).await;
                drop(rh);
                match r.and(closed) {
                    Ok(()) => {
                        self.inner.stats.add_bytes_written(size);
                        Ok(())
                    }
                    Err(e) => {
                        // A half-written copy is worse than none.
                        let _ = session.remove(&dst).await;
                        Err(e)
                    }
                }
            }
        })
        .await
    }

    async fn put_file(&self, local: &Path, remote: &str, opts: &WriteOptions) -> Result<()> {
        use std::io::Read;
        // Open the local file first: a missing source creates nothing.
        let lp = local.to_path_buf();
        let file = tokio::task::spawn_blocking(move || std::fs::File::open(&lp))
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
            .map_err(|e| Error::from(e).with_path(local.display().to_string()))?;
        let mut w = match self.open_write(remote, opts).await {
            Ok(w) => w,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // fsspec's put_file creates the parent directories.
                let parent = path::parent(remote);
                if parent.is_empty() || parent == "/" {
                    return Err(e);
                }
                self.makedirs(&parent, true).await?;
                self.open_write(remote, opts).await?
            }
            Err(e) => return Err(e),
        };
        // Read 4 chunks at a time from disk on the blocking pool; the write
        // handle slices them into WRITEs without copying and keeps them in
        // flight while the next block is read.
        let block = (opts.block_size.unwrap_or(0)).max(1 << 20);
        let mut file = Some(file);
        let res = async {
            loop {
                let mut f = file
                    .take()
                    .ok_or_else(|| Error::new(ErrorKind::Other, "file lost"))?;
                let (f, buf) = tokio::task::spawn_blocking(move || {
                    let mut buf = Vec::with_capacity(block);
                    let r = (&mut f).take(block as u64).read_to_end(&mut buf);
                    r.map(|_| (f, buf))
                })
                .await
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))??;
                file = Some(f);
                if buf.is_empty() {
                    break;
                }
                let n = buf.len();
                w.write(Bytes::from(buf)).await?;
                if n < block {
                    break;
                }
            }
            w.close().await
        }
        .await;
        if res.is_err() {
            let _ = w.abort().await;
        }
        res
    }

    async fn get_file(&self, remote: &str, local: &Path) -> Result<()> {
        use std::io::Write;
        let rp = remote.to_owned();
        let opened = self
            .run(OpKind::Open, true, move |s| {
                let rp = rp.clone();
                async move { self.open_read_on(s, &rp, &ReadOptions::default()).await }
            })
            .await;
        let h = match opened {
            Ok(h) => h,
            Err(e) if e.kind() == ErrorKind::IsADirectory => {
                // fsspec: getting a directory creates it locally.
                return tokio::fs::create_dir_all(local).await.map_err(Error::from);
            }
            Err(e) => return Err(e),
        };
        let lp = local.to_path_buf();
        // Disk writes run on a blocking thread fed through a bounded queue,
        // so network reads and disk writes overlap; the received chunks are
        // written as they are (no reassembly copy).
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<Bytes>>(16);
        let writer = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let mut f = std::fs::File::create(&lp)?;
            while let Some(chunks) = rx.blocking_recv() {
                for c in chunks {
                    f.write_all(&c)?;
                }
            }
            f.flush()
        });
        let start = Instant::now();
        let read = async {
            // To the server's EOF, not the STAT size (see cat_file).
            let mut p = h.pipeline_to_eof(0, None);
            while let Some(c) = p.next_chunk().await? {
                self.inner.stats.add_bytes_read(c.len() as u64);
                if tx.send(c.chunks().to_vec()).await.is_err() {
                    break;
                }
            }
            Ok::<_, Error>(())
        }
        .await;
        drop(tx);
        let written = writer
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
            .map_err(|e| Error::from(e).with_path(local.display().to_string()));
        let _ = h.close().await;
        let res = read.and(written);
        self.inner
            .stats
            .record_request(OpKind::Read, start.elapsed(), res.is_ok());
        if res.is_err() {
            let _ = tokio::fs::remove_file(local).await;
        }
        res
    }

    async fn touch(&self, p: &str, truncate: bool) -> Result<()> {
        let s = self.inner.pool.get().await?;
        let flags = if truncate {
            open_flags::WRITE | open_flags::CREAT | open_flags::TRUNC
        } else {
            open_flags::WRITE | open_flags::CREAT
        };
        let h = match s.open(p, flags, FileAttributes::default()).await {
            Ok(h) => h,
            Err(e) if Self::is_failure(&e) => {
                return match Self::lstat_kind(&s, p).await {
                    Some(true) => Err(refine(e, ErrorKind::IsADirectory)),
                    _ => Err(e),
                };
            }
            Err(e) => return Err(e),
        };
        // Without truncation, update the times of an existing file (fsspec
        // raises NotImplementedError here); FSETSTAT and CLOSE are
        // pipelined.
        let set = if truncate {
            None
        } else {
            let now = now_secs();
            Some(s.start_call(&Request::Fsetstat {
                handle: h.clone(),
                attrs: FileAttributes::with_times(now, now),
            })?)
        };
        let close = s.start_call(&Request::Close { handle: h })?;
        let set_r = match set {
            Some(c) => s
                .finish(c)
                .await
                .and_then(|r| status_reply(r, "fsetstat", p)),
            None => Ok(()),
        };
        let close_r = s
            .finish(close)
            .await
            .and_then(|r| status_reply(r, "close", p));
        set_r.and(close_r)
    }

    async fn close(&self) -> Result<()> {
        self.inner.pool.close().await;
        Ok(())
    }
}
