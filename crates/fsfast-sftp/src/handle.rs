//! Pipelined file handles.
//!
//! **Reads.** [`ReadPipeline`] keeps a window of READ requests in flight
//! (slow start: it begins with a few requests and grows by one per full
//! reply, OpenSSH-style, up to `max_inflight`), so a transfer fills the
//! bandwidth-delay product without overshooting small files. Replies may
//! arrive in any order and are emitted strictly in offset order; a short
//! reply (fewer bytes than asked, not at EOF) queues a request for the rest
//! ahead of new reads. `read_at` assembles the chunks into one buffer
//! allocated once for the whole range, or returns the reply's buffer
//! untouched when one READ covers the range. Concurrent `read_at` calls on
//! one handle simply share the session's request map. The learned window
//! is kept per handle, so consecutive reads do not restart slow start.
//!
//! **Writes.** [`SftpWriteHandle`] slices large writes into WRITE requests
//! without copying (small writes are gathered into one chunk), keeps up to
//! `max_inflight` WRITEs in flight, and checks their statuses as the window
//! advances; `flush`/`close` wait for all of them. `close` issues
//! `fsync@openssh.com` first only when `fsync_on_close` is set. `abort`
//! removes a file it created or truncated, and truncates an append back to
//! its original length.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use futures::stream::FuturesUnordered;

use fsfast_core::{Error, ErrorKind, FileInfo, IoHints, ReadHandle, Result, WriteHandle, async_trait};
use fsfast_engine::stats::Stats;

use crate::pool::Lease;
use crate::proto::{FileAttributes, Payload, Request};
use crate::session::{PendingCall, RawReply, ReadReply, Session, read_reply, status_reply};

/// Requests a transfer starts with before slow start grows the window.
pub const INITIAL_WINDOW: usize = 8;

/// One READ in flight.
struct ReadFut {
    off: u64,
    len: u32,
    call: PendingCall,
}

impl Future for ReadFut {
    type Output = (u64, u32, Result<RawReply>);

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (off, len) = (self.off, self.len);
        Pin::new(&mut self.call).poll(cx).map(|r| (off, len, r))
    }
}

/// Streams `[start, end)` of an open file in order, with READ requests
/// pipelined.
pub struct ReadPipeline<'a> {
    session: &'a Session,
    handle: &'a Bytes,
    path: &'a str,
    chunk: usize,
    window: &'a AtomicUsize,
    max_window: usize,
    next: u64,
    end: u64,
    emit: u64,
    eof: Option<u64>,
    redo: VecDeque<(u64, u32)>,
    inflight: FuturesUnordered<ReadFut>,
    done: BTreeMap<u64, Payload>,
}

impl<'a> ReadPipeline<'a> {
    /// A pipeline over `[start, end)` of `handle`. `window` holds the
    /// learned window size and is updated as the transfer runs.
    pub fn new(
        session: &'a Session,
        handle: &'a Bytes,
        path: &'a str,
        start: u64,
        end: u64,
        window: &'a AtomicUsize,
        max_window: usize,
    ) -> Self {
        ReadPipeline {
            session,
            handle,
            path,
            chunk: session.read_chunk().max(1),
            window,
            max_window: max_window.max(1),
            next: start,
            end,
            emit: start,
            eof: None,
            redo: VecDeque::new(),
            inflight: FuturesUnordered::new(),
            done: BTreeMap::new(),
        }
    }

    fn limit(&self) -> u64 {
        self.eof.map_or(self.end, |e| e.min(self.end))
    }

    fn issue(&mut self, off: u64, len: u32) -> Result<()> {
        let call = self.session.start_call(&Request::Read {
            handle: self.handle.clone(),
            offset: off,
            len,
        })?;
        self.inflight.push(ReadFut { off, len, call });
        Ok(())
    }

    fn fill(&mut self) -> Result<()> {
        let window = self.window.load(Ordering::Relaxed).clamp(1, self.max_window);
        while self.inflight.len() < window {
            if let Some((off, len)) = self.redo.pop_front() {
                if off < self.limit() {
                    self.issue(off, len)?;
                }
                continue;
            }
            let limit = self.limit();
            if self.next >= limit {
                break;
            }
            let len = (limit - self.next).min(self.chunk as u64) as u32;
            let off = self.next;
            self.next += u64::from(len);
            self.issue(off, len)?;
        }
        Ok(())
    }

    /// The next chunk in offset order, `None` at the end of the range (or
    /// of the file).
    pub async fn next_chunk(&mut self) -> Result<Option<Payload>> {
        loop {
            if self.emit >= self.limit() {
                return Ok(None);
            }
            if let Some(p) = self.done.remove(&self.emit) {
                self.emit += p.len() as u64;
                return Ok(Some(p));
            }
            self.fill()?;
            let next = match self.session.request_timeout() {
                Some(d) => tokio::time::timeout(d, self.inflight.next())
                    .await
                    .map_err(|_| Error::timeout(format!("SFTP READ timed out after {d:?}")))?,
                None => self.inflight.next().await,
            };
            let Some((off, len, reply)) = next else {
                // Nothing in flight and nothing to emit: the range ended
                // (EOF) or the bookkeeping lost track, which must not hang.
                if self.emit >= self.limit() {
                    return Ok(None);
                }
                return Err(Error::protocol(format!(
                    "read of {} stalled at offset {}",
                    self.path, self.emit
                )));
            };
            match read_reply(reply?, self.path)? {
                ReadReply::Data(mut p) => {
                    let n = p.len();
                    if n == 0 {
                        // A zero-length DATA would make no progress; treat it
                        // like EOF at this offset.
                        self.eof = Some(self.eof.map_or(off, |e| e.min(off)));
                        continue;
                    }
                    if n > len as usize {
                        // More than asked for: keep what was requested.
                        p.truncate(len as usize);
                    }
                    let n = p.len();
                    if n < len as usize {
                        // Short read: fetch the rest before anything newer.
                        self.redo
                            .push_front((off + n as u64, len - n as u32));
                    } else {
                        let w = self.window.load(Ordering::Relaxed);
                        if w < self.max_window {
                            self.window.store(w + 1, Ordering::Relaxed);
                        }
                    }
                    if off >= self.emit {
                        self.done.insert(off, p);
                    }
                }
                ReadReply::Eof => {
                    self.eof = Some(self.eof.map_or(off, |e| e.min(off)));
                }
            }
        }
    }

    /// Read the whole range into one buffer (zero-copy when a single reply
    /// covers it).
    pub async fn collect(mut self) -> Result<Bytes> {
        let want = (self.end - self.emit) as usize;
        let Some(first) = self.next_chunk().await? else {
            return Ok(Bytes::new());
        };
        if first.len() >= want {
            return Ok(first.into_bytes());
        }
        let mut buf = BytesMut::with_capacity(want);
        first.copy_to(&mut buf);
        while let Some(c) = self.next_chunk().await? {
            c.copy_to(&mut buf);
        }
        Ok(buf.freeze())
    }
}

/// A file opened for reading.
pub struct SftpReadHandle {
    lease: Lease,
    handle: Bytes,
    info: FileInfo,
    window: AtomicUsize,
    max_inflight: usize,
    closed: AtomicBool,
    stats: Arc<Stats>,
}

impl std::fmt::Debug for SftpReadHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpReadHandle")
            .field("path", &self.info.name)
            .field("size", &self.info.size)
            .field("session", &self.lease.label())
            .finish()
    }
}

impl SftpReadHandle {
    pub(crate) fn new(
        lease: Lease,
        handle: Bytes,
        info: FileInfo,
        max_inflight: usize,
        stats: Arc<Stats>,
    ) -> Self {
        SftpReadHandle {
            lease,
            handle,
            info,
            window: AtomicUsize::new(INITIAL_WINDOW.min(max_inflight)),
            max_inflight,
            closed: AtomicBool::new(false),
            stats,
        }
    }

    /// The session the handle lives on.
    pub fn session(&self) -> &Session {
        &self.lease
    }

    /// The server's handle.
    pub fn raw_handle(&self) -> &Bytes {
        &self.handle
    }

    /// A pipeline over `[start, end)` (clamped to the size at open time).
    pub fn pipeline(&self, start: u64, end: u64) -> ReadPipeline<'_> {
        let end = end.min(self.info.size);
        ReadPipeline::new(
            &self.lease,
            &self.handle,
            &self.info.name,
            start.min(end),
            end,
            &self.window,
            self.max_inflight,
        )
    }
}

#[async_trait]
impl ReadHandle for SftpReadHandle {
    fn info(&self) -> &FileInfo {
        &self.info
    }

    fn io_hints(&self) -> IoHints {
        let chunk = self.lease.read_chunk();
        IoHints {
            // Each read_at pipelines internally; a few concurrent read_at
            // calls of 16 chunks keep the window full.
            request_size: chunk * 16,
            max_concurrency: (self.max_inflight / 16).max(2),
            coalesce_gap: chunk as u64,
            max_coalesced: (chunk * 32) as u64,
        }
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::invalid_input("read on a closed SFTP handle").with_path(&self.info.name));
        }
        let size = self.info.size;
        if len == 0 || offset >= size {
            return Ok(Bytes::new());
        }
        let end = offset.saturating_add(len as u64).min(size);
        let t = std::time::Instant::now();
        let r = self.pipeline(offset, end).collect().await;
        self.stats
            .record_request(fsfast_engine::stats::OpKind::Read, t.elapsed(), r.is_ok());
        if let Ok(b) = &r {
            self.stats.add_bytes_read(b.len() as u64);
        }
        r
    }

    async fn close(&self) -> Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.lease.close(self.handle.clone(), &self.info.name).await
    }
}

impl Drop for SftpReadHandle {
    fn drop(&mut self) {
        if !self.closed.load(Ordering::Acquire) {
            self.lease.close_nowait(self.handle.clone());
        }
    }
}

/// What `abort` undoes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Undo {
    /// Remove the file (it was created or truncated by this handle).
    Remove,
    /// Truncate back to this length (an append to an existing file).
    Truncate(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WState {
    Open,
    Closed,
    /// Closed, but a WRITE, FSYNC or CLOSE failed.
    Failed,
    Aborted,
}

/// A file opened for writing.
pub struct SftpWriteHandle {
    lease: Lease,
    handle: Bytes,
    path: String,
    chunk: usize,
    max_inflight: usize,
    /// Full chunks waiting for window space (zero-copy slices).
    queue: VecDeque<Bytes>,
    /// Partial chunk being gathered from small writes.
    buf: BytesMut,
    offset: u64,
    written: u64,
    inflight: VecDeque<PendingCall>,
    error: Option<(ErrorKind, String)>,
    state: WState,
    undo: Undo,
    fsync: bool,
    stats: Arc<Stats>,
}

impl std::fmt::Debug for SftpWriteHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpWriteHandle")
            .field("path", &self.path)
            .field("written", &self.written)
            .field("state", &self.state)
            .finish()
    }
}

impl SftpWriteHandle {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        lease: Lease,
        handle: Bytes,
        path: String,
        start_offset: u64,
        undo: Undo,
        max_inflight: usize,
        fsync: bool,
        stats: Arc<Stats>,
    ) -> Self {
        let chunk = lease.write_chunk().max(1);
        SftpWriteHandle {
            lease,
            handle,
            path,
            chunk,
            max_inflight: max_inflight.max(1),
            queue: VecDeque::new(),
            buf: BytesMut::new(),
            offset: start_offset,
            written: 0,
            inflight: VecDeque::new(),
            error: None,
            state: WState::Open,
            undo,
            fsync,
            stats,
        }
    }

    fn sticky(&self) -> Result<()> {
        match &self.error {
            Some((k, m)) => Err(Error::new(*k, m.clone()).with_path(&self.path)),
            None => Ok(()),
        }
    }

    fn record(&mut self, e: Error) -> Error {
        if self.error.is_none() {
            self.error = Some((e.kind(), e.message().to_owned()));
        }
        e
    }

    /// Wait for the oldest WRITE.
    async fn reap_one(&mut self) -> Result<()> {
        let Some(call) = self.inflight.pop_front() else {
            return Ok(());
        };
        let r = match self.lease.finish(call).await {
            Ok(r) => status_reply(r, "write", &self.path),
            Err(e) => Err(e),
        };
        r.map_err(|e| self.record(e))
    }

    /// Send queued chunks, waiting for window space as needed. Cancel-safe:
    /// a chunk leaves the queue only once its request is queued.
    async fn pump(&mut self) -> Result<()> {
        while let Some(data) = self.queue.front().cloned() {
            while self.inflight.len() >= self.max_inflight {
                self.reap_one().await?;
            }
            let len = data.len() as u64;
            let call = self
                .lease
                .start_call(&Request::Write {
                    handle: self.handle.clone(),
                    offset: self.offset,
                    data,
                })
                .map_err(|e| self.record(e))?;
            self.queue.pop_front();
            self.offset += len;
            self.stats.add_bytes_written(len);
            self.inflight.push_back(call);
        }
        // Collect statuses that are already there without waiting.
        Ok(())
    }

    async fn drain(&mut self) -> Result<()> {
        if !self.buf.is_empty() {
            let b = self.buf.split().freeze();
            self.queue.push_back(b);
        }
        self.pump().await?;
        while !self.inflight.is_empty() {
            self.reap_one().await?;
        }
        Ok(())
    }

    fn check_open(&self) -> Result<()> {
        match self.state {
            WState::Open => Ok(()),
            WState::Closed | WState::Failed => {
                Err(Error::invalid_input("write to a closed file").with_path(&self.path))
            }
            WState::Aborted => {
                Err(Error::invalid_input("write to an aborted file").with_path(&self.path))
            }
        }
    }
}

#[async_trait]
impl WriteHandle for SftpWriteHandle {
    async fn write(&mut self, data: Bytes) -> Result<()> {
        self.check_open()?;
        self.sticky()?;
        if data.is_empty() {
            return Ok(());
        }
        self.written += data.len() as u64;
        let mut data = data;
        if !self.buf.is_empty() {
            let take = (self.chunk - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data.split_to(take));
            if self.buf.len() == self.chunk {
                let b = self.buf.split().freeze();
                self.queue.push_back(b);
            }
        }
        while data.len() >= self.chunk {
            self.queue.push_back(data.split_to(self.chunk));
        }
        if !data.is_empty() {
            self.buf.extend_from_slice(&data);
        }
        self.pump().await
    }

    async fn flush(&mut self) -> Result<()> {
        self.check_open()?;
        self.sticky()?;
        self.drain().await
    }

    async fn close(&mut self) -> Result<()> {
        match self.state {
            WState::Closed => return Ok(()),
            WState::Failed => return self.sticky(),
            WState::Aborted => {
                return Err(Error::invalid_input("close of an aborted file").with_path(&self.path));
            }
            WState::Open => {}
        }
        self.sticky()?;
        if !self.buf.is_empty() {
            let b = self.buf.split().freeze();
            self.queue.push_back(b);
        }
        self.pump().await?;
        // The server handles requests in order, so FSYNC and CLOSE can go
        // out right behind the last WRITEs: closing costs one round trip,
        // not two. Every WRITE status is still checked.
        let fsync = if self.fsync {
            Some(
                self.lease
                    .start_call(&Request::Extended(crate::proto::ExtRequest::Fsync {
                        handle: self.handle.clone(),
                    }))
                    .map_err(|e| self.record(e))?,
            )
        } else {
            None
        };
        let close = self
            .lease
            .start_call(&Request::Close {
                handle: self.handle.clone(),
            })
            .map_err(|e| self.record(e))?;
        // From here on the server handle is (being) released.
        self.state = WState::Closed;
        let mut first_err = None;
        while !self.inflight.is_empty() {
            if let Err(e) = self.reap_one().await {
                first_err.get_or_insert(e);
            }
        }
        if let Some(f) = fsync {
            let r = self
                .lease
                .finish(f)
                .await
                .and_then(|r| status_reply(r, "fsync", &self.path));
            if let Err(e) = r {
                first_err.get_or_insert(e);
            }
        }
        let r = self
            .lease
            .finish(close)
            .await
            .and_then(|r| status_reply(r, "close", &self.path));
        if let Err(e) = r {
            first_err.get_or_insert(e);
        }
        match first_err {
            None => Ok(()),
            Some(e) => {
                // A failed close cannot be retried (the handle is gone):
                // later close() calls report the same error.
                let e = self.record(e);
                self.state = WState::Failed;
                Err(e)
            }
        }
    }

    async fn abort(&mut self) -> Result<()> {
        match self.state {
            WState::Open => {}
            WState::Failed => {
                // The handle is closed already; still undo the partial file.
                self.state = WState::Aborted;
                return self.undo_closed().await;
            }
            WState::Closed | WState::Aborted => return Ok(()),
        }
        self.state = WState::Aborted;
        self.queue.clear();
        self.buf.clear();
        // The server handles requests in order: pending WRITEs complete
        // before the undo below, so their replies can be ignored.
        self.inflight.clear();
        let s = &self.lease;
        if let Undo::Truncate(len) = self.undo {
            let t = s.start_call(&Request::Fsetstat {
                handle: self.handle.clone(),
                attrs: FileAttributes::with_size(len),
            });
            let c = s.start_call(&Request::Close {
                handle: self.handle.clone(),
            });
            let truncated = match t {
                Ok(t) => s.finish(t).await.and_then(|r| status_reply(r, "truncate", &self.path)),
                Err(e) => Err(e),
            };
            if let Ok(c) = c {
                let _ = s.finish(c).await;
            }
            return truncated;
        }
        let c = s.start_call(&Request::Close {
            handle: self.handle.clone(),
        });
        let rm = s.start_call(&Request::Remove {
            path: Bytes::copy_from_slice(self.path.as_bytes()),
        });
        if let Ok(c) = c {
            let _ = s.finish(c).await;
        }
        match rm {
            Ok(rm) => match s.finish(rm).await.and_then(|r| status_reply(r, "remove", &self.path)) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        }
    }

    fn bytes_written(&self) -> u64 {
        self.written
    }
}

impl SftpWriteHandle {
    /// Undo after the handle was closed by a failed `close`.
    async fn undo_closed(&mut self) -> Result<()> {
        match self.undo {
            Undo::Truncate(len) => {
                self.lease
                    .setstat(&self.path, FileAttributes::with_size(len))
                    .await
            }
            Undo::Remove => match self.lease.remove(&self.path).await {
                Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            },
        }
    }
}

impl Drop for SftpWriteHandle {
    fn drop(&mut self) {
        if self.state == WState::Open {
            // Not closed or aborted: release the server handle (data still
            // buffered here is lost, as with a crashed writer).
            self.inflight.clear();
            self.lease.close_nowait(self.handle.clone());
        }
    }
}
