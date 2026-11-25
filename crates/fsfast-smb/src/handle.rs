//! Open file handles with pipelined I/O.
//!
//! * [`SmbReadHandle`] splits reads into READ requests of up to the read
//!   chunk size (≤ `MaxReadSize`) and keeps up to `max_inflight` of them in
//!   flight. Completions arrive in any order and are copied straight into
//!   one pre-allocated buffer (the only copy after the socket read). Many
//!   `read_at` calls may run concurrently on one handle: they share the
//!   connection's credit window.
//! * [`SmbWriteHandle`] slices large writes into WRITE requests without
//!   copying (`Bytes::slice`), coalesces small writes into chunk-sized
//!   buffers, and keeps a bounded window of WRITEs in flight, accounted
//!   against the engine's memory budget.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use fsfast_core::{
    Error, ErrorKind, FileInfo, IoHints, ReadHandle, Result, WriteHandle, async_trait,
};
use fsfast_engine::budget::{BudgetGuard, MemoryBudget};
use fsfast_engine::stats::{OpKind, Stats};
use fsfast_smb_proto::FileId;
use fsfast_smb_proto::msg::{CloseFlags, CloseRequest, ReadRequest, WriteRequest};
use futures::StreamExt;
use futures::stream::FuturesUnordered;

use crate::client::Ctx;
use crate::conn::{ReadReply, Response, recv_all};
use crate::ops;

/// Coalescing gap for ranged reads: SMB READs are cheap and pipelined, so
/// only nearly adjacent ranges are merged.
const COALESCE_GAP: u64 = 64 << 10;

/// I/O sizing of a handle.
#[derive(Debug, Clone, Copy)]
pub(crate) struct IoShape {
    pub chunk: usize,
    pub inflight: usize,
}

impl IoShape {
    pub fn hints(&self) -> IoHints {
        IoHints {
            request_size: self.chunk,
            max_concurrency: self.inflight,
            coalesce_gap: COALESCE_GAP,
            max_coalesced: (self.chunk * 4) as u64,
        }
    }
}

/// An open SMB file for reading.
pub struct SmbReadHandle {
    ctx: Ctx,
    fid: FileId,
    info: FileInfo,
    shape: IoShape,
    closed: AtomicBool,
    stats: Arc<Stats>,
}

impl fmt::Debug for SmbReadHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmbReadHandle")
            .field("path", &self.info.name)
            .field("size", &self.info.size)
            .field("file_id", &self.fid)
            .field("chunk", &self.shape.chunk)
            .finish()
    }
}

impl SmbReadHandle {
    pub(crate) fn new(
        ctx: Ctx,
        fid: FileId,
        info: FileInfo,
        shape: IoShape,
        stats: Arc<Stats>,
    ) -> Self {
        SmbReadHandle {
            ctx,
            fid,
            info,
            shape,
            closed: AtomicBool::new(false),
            stats,
        }
    }

    /// Queue one READ of up to `len` bytes at `offset` (clamped to what the
    /// credit window allows) and return its pending response.
    async fn send_read(&self, offset: u64, len: usize) -> Result<(usize, Response)> {
        let len = self.ctx.credit_limited(len);
        let mut chain = self.ctx.chain();
        chain.push(&ReadRequest {
            length: len as u32,
            offset,
            file_id: self.fid,
            ..Default::default()
        })?;
        let msgs = chain.into_messages();
        let mut r = self
            .ctx
            .live
            .conn
            .shared
            .send(msgs, &self.ctx.sec())
            .await?;
        Ok((len, r.pop().expect("one response")))
    }

    /// Read exactly `len` bytes at `offset` unless EOF comes first (servers
    /// may return less than asked; the rest is re-requested).
    async fn read_exact_or_eof(&self, offset: u64, len: usize) -> Result<Bytes> {
        let (asked, resp) = self.send_read(offset, len).await?;
        let first = read_result(resp.recv().await?, &self.info.name)?;
        if first.len() >= len {
            return Ok(first.slice(..len));
        }
        if first.len() < asked {
            // Short read: end of file.
            return Ok(first);
        }
        // The credit window limited the request: continue where it ended.
        let mut out = BytesMut::with_capacity(len);
        out.extend_from_slice(&first);
        while out.len() < len {
            let off = offset + out.len() as u64;
            let (asked, resp) = self.send_read(off, len - out.len()).await?;
            let d = read_result(resp.recv().await?, &self.info.name)?;
            out.extend_from_slice(&d[..d.len().min(len - out.len())]);
            if d.len() < asked {
                break;
            }
        }
        Ok(out.freeze())
    }
}

fn read_result(raw: fsfast_smb_proto::msg::RawMessage, path: &str) -> Result<Bytes> {
    if raw.status() == fsfast_smb_proto::NtStatus::END_OF_FILE {
        return Ok(Bytes::new());
    }
    let rd: fsfast_smb_proto::msg::ReadResponse = ops::decode(&raw, path)?;
    Ok(rd.data)
}

#[async_trait]
impl ReadHandle for SmbReadHandle {
    fn info(&self) -> &FileInfo {
        &self.info
    }

    fn io_hints(&self) -> IoHints {
        self.shape.hints()
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        if self.closed.load(Ordering::Acquire) {
            return Err(
                Error::new(ErrorKind::InvalidInput, "read on a closed SMB handle")
                    .with_path(self.info.name.as_str()),
            );
        }
        let size = self.info.size;
        if len == 0 || offset >= size {
            return Ok(Bytes::new());
        }
        let n = (len as u64).min(size - offset) as usize;
        let started = Instant::now();
        let chunk = self.shape.chunk;
        let res = if n <= chunk {
            // One request: the response data is returned as a slice of the
            // received frame, without any copy.
            self.read_exact_or_eof(offset, n).await
        } else {
            self.read_pipelined(offset, n).await
        };
        self.stats
            .record_request(OpKind::Read, started.elapsed(), res.is_ok());
        if let Ok(b) = &res {
            self.stats.add_bytes_read(b.len() as u64);
        }
        res
    }

    async fn close(&self) -> Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        ops::close(&self.ctx, self.fid, &self.info.name).await
    }
}

impl SmbReadHandle {
    /// A large read: chunks in flight concurrently, landing in one buffer.
    ///
    /// The destination is allocated once and split into one piece per READ;
    /// each piece travels with its request, so the reader task can receive
    /// the data straight into it (no copy). Pieces of responses that took
    /// the regular path are filled by copying. The pieces are re-joined in
    /// O(1) (`BytesMut::unsplit` of adjacent pieces).
    async fn read_pipelined(&self, offset: u64, n: usize) -> Result<Bytes> {
        let chunk = self.shape.chunk;
        // A zeroed allocation comes from calloc: fresh pages cost no memset.
        let mut rest = BytesMut::zeroed(n);
        let mut pieces: Vec<Option<BytesMut>> = Vec::with_capacity(n / chunk + 1);
        let mut next = 0usize;
        // End of valid data (a short read means the file shrank).
        let mut valid = n;
        let mut inflight = FuturesUnordered::new();
        loop {
            while next < n && next < valid && inflight.len() < self.shape.inflight {
                let want = self.ctx.credit_limited(chunk.min(n - next));
                let piece = rest.split_to(want);
                let mut chain = self.ctx.chain();
                chain.push(&ReadRequest {
                    length: want as u32,
                    offset: offset + next as u64,
                    file_id: self.fid,
                    ..Default::default()
                })?;
                let msg = chain.into_messages().pop().expect("one message");
                let resp = self
                    .ctx
                    .live
                    .conn
                    .shared
                    .send_read(msg, &self.ctx.sec(), piece)
                    .await?;
                let idx = pieces.len();
                pieces.push(None);
                let at = next;
                next += want;
                inflight.push(async move { (idx, at, want, resp.recv_read().await) });
            }
            let Some((idx, at, asked, reply)) = inflight.next().await else {
                break;
            };
            let (mut dest, len) = match reply? {
                ReadReply::Direct { dest, len } => (dest, len),
                ReadReply::Message { msg, mut dest } => {
                    let data = read_result(msg, &self.info.name)?;
                    let len = data.len().min(asked);
                    dest[..len].copy_from_slice(&data[..len]);
                    (dest, len)
                }
            };
            if len < asked {
                valid = valid.min(at + len);
            }
            dest.truncate(len);
            pieces[idx] = Some(dest);
        }
        // Join the pieces in order up to the first short one.
        let mut out = BytesMut::new();
        let mut total = 0usize;
        for p in pieces {
            let Some(p) = p else { break };
            let full = total + p.len() <= valid;
            total += p.len();
            out.unsplit(p);
            if !full || total >= valid {
                break;
            }
        }
        out.truncate(valid.min(n));
        Ok(out.freeze())
    }
}

impl Drop for SmbReadHandle {
    fn drop(&mut self) {
        if !self.closed.swap(true, Ordering::AcqRel) && !self.ctx.live.conn.is_dead() {
            ops::close_detached(&self.ctx, self.fid);
        }
    }
}

/// What `abort` must undo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Undo {
    /// The file was created or replaced by this handle: delete it.
    Delete,
    /// Appending to an existing file: truncate back to its old size.
    Truncate(u64),
}

/// One WRITE in flight.
struct InFlight {
    resp: Response,
    len: usize,
    _budget: BudgetGuard,
}

/// An open SMB file for writing.
pub struct SmbWriteHandle {
    ctx: Ctx,
    fid: FileId,
    path: String,
    shape: IoShape,
    undo: Undo,
    /// File offset of the next WRITE.
    offset: u64,
    buf: BytesMut,
    inflight: VecDeque<InFlight>,
    written: u64,
    closed: bool,
    /// `close` succeeded: the data is committed and `abort` is a no-op.
    committed: bool,
    error: Option<Error>,
    budget: MemoryBudget,
    stats: Arc<Stats>,
    /// Called after an abort that must delete the file (the handle is
    /// closed first, so the delete is a separate path-based operation).
    deleter: Option<Box<dyn FnOnce() -> futures::future::BoxFuture<'static, Result<()>> + Send>>,
}

impl fmt::Debug for SmbWriteHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmbWriteHandle")
            .field("path", &self.path)
            .field("file_id", &self.fid)
            .field("offset", &self.offset)
            .field("written", &self.written)
            .field("inflight", &self.inflight.len())
            .field("closed", &self.closed)
            .finish()
    }
}

impl SmbWriteHandle {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        ctx: Ctx,
        fid: FileId,
        path: String,
        shape: IoShape,
        start_offset: u64,
        undo: Undo,
        stats: Arc<Stats>,
        deleter: Box<dyn FnOnce() -> futures::future::BoxFuture<'static, Result<()>> + Send>,
    ) -> Self {
        SmbWriteHandle {
            ctx,
            fid,
            path,
            shape,
            undo,
            offset: start_offset,
            buf: BytesMut::new(),
            inflight: VecDeque::new(),
            written: 0,
            closed: false,
            committed: false,
            error: None,
            budget: MemoryBudget::global().clone(),
            stats,
            deleter: Some(deleter),
        }
    }

    fn check_open(&self) -> Result<()> {
        if self.closed {
            return Err(
                Error::new(ErrorKind::InvalidInput, "write to a closed SMB handle")
                    .with_path(self.path.as_str()),
            );
        }
        Ok(())
    }

    /// Wait for the oldest WRITE.
    async fn complete_one(&mut self) -> Result<()> {
        let Some(w) = self.inflight.pop_front() else {
            return Ok(());
        };
        let started = Instant::now();
        let res = async {
            let raw = w.resp.recv().await?;
            let wr: fsfast_smb_proto::msg::WriteResponse = ops::decode(&raw, &self.path)?;
            if wr.count as usize != w.len {
                return Err(Error::new(
                    ErrorKind::Io,
                    format!("short SMB write: {} of {} bytes", wr.count, w.len),
                )
                .with_path(self.path.as_str()));
            }
            Ok(())
        }
        .await;
        self.stats
            .record_request(OpKind::Write, started.elapsed(), res.is_ok());
        if res.is_ok() {
            self.stats.add_bytes_written(w.len as u64);
        }
        res
    }

    /// Send `data` (at most one chunk) as WRITE requests, waiting for window
    /// space first.
    async fn dispatch(&mut self, mut data: Bytes) -> Result<()> {
        while !data.is_empty() {
            while self.inflight.len() >= self.shape.inflight {
                self.complete_one().await?;
            }
            let len = self.ctx.credit_limited(data.len());
            // Memory for the queued payload: wait for budget only while
            // other writes are in flight (they release theirs), otherwise
            // overcommit by this one request so progress is guaranteed.
            let guard = match self.budget.try_acquire(len) {
                Some(g) => g,
                None if !self.inflight.is_empty() => {
                    self.complete_one().await?;
                    continue;
                }
                None => self.budget.force_acquire(len),
            };
            let part = data.split_to(len);
            let mut chain = self.ctx.chain();
            chain.push(&WriteRequest {
                offset: self.offset,
                file_id: self.fid,
                data: part,
                ..Default::default()
            })?;
            let mut r = self
                .ctx
                .live
                .conn
                .shared
                .send(chain.into_messages(), &self.ctx.sec())
                .await?;
            self.offset += len as u64;
            self.inflight.push_back(InFlight {
                resp: r.pop().expect("one response"),
                len,
                _budget: guard,
            });
        }
        Ok(())
    }

    async fn write_inner(&mut self, mut data: Bytes) -> Result<()> {
        let chunk = self.shape.chunk;
        if !self.buf.is_empty() {
            let take = (chunk - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data.split_to(take));
            if self.buf.len() < chunk {
                return Ok(());
            }
            let full = self.buf.split().freeze();
            self.dispatch(full).await?;
        }
        // Whole chunks go out as zero-copy slices of the caller's buffer.
        while data.len() >= chunk {
            let part = data.split_to(chunk);
            self.dispatch(part).await?;
        }
        if !data.is_empty() {
            self.buf.reserve(chunk);
            self.buf.extend_from_slice(&data);
        }
        Ok(())
    }

    async fn flush_inner(&mut self) -> Result<()> {
        if !self.buf.is_empty() {
            let rest = self.buf.split().freeze();
            self.dispatch(rest).await?;
        }
        while !self.inflight.is_empty() {
            self.complete_one().await?;
        }
        Ok(())
    }

    fn fail(&mut self, e: Error) -> Error {
        let copy = Error::new(e.kind(), e.message().to_owned())
            .with_path(self.path.as_str())
            .with_retryable(false);
        self.error = Some(copy);
        e
    }
}

#[async_trait]
impl WriteHandle for SmbWriteHandle {
    async fn write(&mut self, data: Bytes) -> Result<()> {
        self.check_open()?;
        if let Some(e) = &self.error {
            return Err(Error::new(e.kind(), e.message().to_owned()).with_path(self.path.as_str()));
        }
        self.written += data.len() as u64;
        if data.is_empty() {
            return Ok(());
        }
        match self.write_inner(data).await {
            Ok(()) => Ok(()),
            Err(e) => Err(self.fail(e)),
        }
    }

    async fn flush(&mut self) -> Result<()> {
        self.check_open()?;
        if let Some(e) = &self.error {
            return Err(Error::new(e.kind(), e.message().to_owned()).with_path(self.path.as_str()));
        }
        match self.flush_inner().await {
            Ok(()) => Ok(()),
            Err(e) => Err(self.fail(e)),
        }
    }

    async fn close(&mut self) -> Result<()> {
        if self.closed {
            return match &self.error {
                None => Ok(()),
                Some(e) => {
                    Err(Error::new(e.kind(), e.message().to_owned()).with_path(self.path.as_str()))
                }
            };
        }
        if let Some(e) = &self.error {
            return Err(Error::new(e.kind(), e.message().to_owned()).with_path(self.path.as_str()));
        }
        let flushed = self.flush_inner().await;
        self.closed = true;
        let closed = close_handle(&self.ctx, self.fid, &self.path).await;
        match flushed.and(closed) {
            Ok(()) => {
                self.committed = true;
                self.deleter = None;
                Ok(())
            }
            Err(e) => Err(self.fail(e)),
        }
    }

    async fn abort(&mut self) -> Result<()> {
        if self.committed || (self.closed && self.deleter.is_none()) {
            return Ok(());
        }
        // Let in-flight writes finish so nothing lands after the cleanup.
        self.buf.clear();
        while !self.inflight.is_empty() {
            let _ = self.complete_one().await;
        }
        let was_open = !self.closed;
        self.closed = true;
        let mut res = Ok(());
        if was_open {
            if let Undo::Truncate(eof) = self.undo {
                res = ops::set_end_of_file(&self.ctx, self.fid, eof, &self.path).await;
            }
            let c = ops::close(&self.ctx, self.fid, &self.path).await;
            res = res.and(c);
        }
        if self.undo == Undo::Delete
            && let Some(del) = self.deleter.take()
        {
            match del().await {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => res = res.and(Err(e)),
            }
        }
        self.deleter = None;
        res
    }

    fn bytes_written(&self) -> u64 {
        self.written
    }
}

impl Drop for SmbWriteHandle {
    fn drop(&mut self) {
        if self.closed || self.ctx.live.conn.is_dead() {
            return;
        }
        // Dropped without close/abort: push the buffered tail, wait for the
        // writes and close the handle in the background, so the data is
        // published (as on local and memory) and the handle is not leaked.
        let ctx = self.ctx.clone();
        let fid = self.fid;
        let path = std::mem::take(&mut self.path);
        let mut offset = self.offset;
        let tail = self.buf.split().freeze();
        let inflight: Vec<Response> = self.inflight.drain(..).map(|w| w.resp).collect();
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        rt.spawn(async move {
            let _ = recv_all(inflight).await;
            let mut tail = tail;
            while !tail.is_empty() {
                let len = ctx.credit_limited(tail.len());
                let part = tail.split_to(len);
                if ops::write(&ctx, fid, offset, part, &path).await.is_err() {
                    break;
                }
                offset += len as u64;
            }
            if let Err(e) = ops::close(&ctx, fid, &path).await {
                tracing::debug!(path, error = %e, "background SMB CLOSE failed");
            }
        });
    }
}

async fn close_handle(ctx: &Ctx, fid: FileId, path: &str) -> Result<()> {
    let mut chain = ctx.chain();
    chain.push(&CloseRequest {
        flags: CloseFlags::empty(),
        file_id: fid,
    })?;
    let r = ctx.exec(chain).await?;
    ops::check(&r[0], path)
}
