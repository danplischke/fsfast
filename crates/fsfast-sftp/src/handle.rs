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

use fsfast_core::{
    Error, ErrorKind, FileInfo, IoHints, ReadHandle, Result, WriteHandle, async_trait,
};
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
        let window = self
            .window
            .load(Ordering::Relaxed)
            .clamp(1, self.max_window);
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
                        self.redo.push_front((off + n as u64, len - n as u32));
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
            return Err(
                Error::invalid_input("read on a closed SFTP handle").with_path(&self.info.name)
            );
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

    /// Wait for the oldest WRITE. Cancel-safe: the call stays queued until
    /// its reply has arrived, so a cancelled `write` never loses a WRITE
    /// status (which would let `close` report success after a failed WRITE).
    async fn reap_one(&mut self) -> Result<()> {
        let timeout = self.lease.request_timeout();
        let Some(call) = self.inflight.front_mut() else {
            return Ok(());
        };
        let reply = match timeout {
            Some(d) => tokio::time::timeout(d, call).await.unwrap_or_else(|_| {
                Err(Error::timeout(format!("SFTP WRITE timed out after {d:?}")))
            }),
            None => call.await,
        };
        // No await between the completion and the removal.
        self.inflight.pop_front();
        let r = reply.and_then(|r| status_reply(r, "write", &self.path));
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
                Ok(t) => s
                    .finish(t)
                    .await
                    .and_then(|r| status_reply(r, "truncate", &self.path)),
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
            Ok(rm) => match s
                .finish(rm)
                .await
                .and_then(|r| status_reply(r, "remove", &self.path))
            {
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::BytesMut;
    use tokio::sync::{mpsc, oneshot};

    use super::*;
    use crate::proto::{Reply, Status, Version, fxp, status};
    use crate::session::SessionOptions;
    use crate::session::testing::pair;

    /// Reads whole request packets from the client byte stream.
    async fn next_req(
        rx: &mut mpsc::UnboundedReceiver<Bytes>,
        buf: &mut BytesMut,
    ) -> Option<Bytes> {
        loop {
            if buf.len() >= 4 {
                let n = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                if buf.len() >= 4 + n {
                    let mut p = buf.split_to(4 + n);
                    let _ = p.split_to(4);
                    return Some(p.freeze());
                }
            }
            buf.extend_from_slice(&rx.recv().await?);
        }
    }

    /// A write cancelled while it waits for window space must not lose the
    /// status of the WRITE it was waiting for: a failure of that WRITE has to
    /// surface on `close`.
    #[tokio::test]
    async fn cancelled_write_keeps_the_pending_write_status() {
        let (tx, rx, mut srx, stx) = pair();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let mut buf = BytesMut::new();
            let init = next_req(&mut srx, &mut buf).await.unwrap();
            assert_eq!(init[0], fxp::INIT);
            stx.send(
                Version {
                    version: 3,
                    extensions: vec![],
                }
                .encode(),
            )
            .unwrap();
            let mut release = Some(release_rx);
            while let Some(p) = next_req(&mut srx, &mut buf).await {
                let (id, r) = Request::decode(p).unwrap();
                let code = match r {
                    Request::Write { offset: 0, .. } => {
                        // Hold the first WRITE's reply until the client gave up
                        // waiting, then fail it.
                        if let Some(r) = release.take() {
                            let _ = r.await;
                        }
                        status::FAILURE
                    }
                    _ => status::OK,
                };
                stx.send(Reply::Status(Status::new(code)).encode(id))
                    .unwrap();
            }
        });
        let s = Session::start(tx, rx, SessionOptions::default(), "t".into(), None)
            .await
            .unwrap();
        let chunk = s.write_chunk();
        let mut w = SftpWriteHandle::new(
            Lease::new(s),
            Bytes::from_static(b"H"),
            "/f".into(),
            0,
            Undo::Remove,
            1,
            false,
            Arc::new(Stats::new()),
        );
        w.write(Bytes::from(vec![1u8; chunk])).await.unwrap();
        // The second write waits for the first WRITE's status (window of 1);
        // cancel it there.
        let r = tokio::time::timeout(
            Duration::from_millis(50),
            w.write(Bytes::from(vec![2u8; chunk])),
        )
        .await;
        assert!(r.is_err(), "the write should have been waiting");
        release_tx.send(()).unwrap();
        let e = w
            .close()
            .await
            .expect_err("close succeeded although a WRITE failed");
        assert_eq!(e.kind(), ErrorKind::Io);
        drop(w);
        server.abort();
    }

    /// A quirky server: answers each batch of READs in reverse order, returns
    /// short reads, over-long DATA and empty DATA mid-file and stops at a
    /// real length shorter than the size announced at open time (the file
    /// shrank). `read_at` must reassemble exactly the real bytes.
    async fn quirky_reads(real: usize, announced: u64, seed: u64, allow_empty: bool) {
        let content: Vec<u8> = (0..real as u32)
            .map(|i| (i.wrapping_mul(31) >> 3) as u8)
            .collect();
        let expect = content.clone();
        let (tx, rx, mut srx, stx) = pair();
        let server = tokio::spawn(async move {
            let mut buf = BytesMut::new();
            next_req(&mut srx, &mut buf).await.unwrap();
            stx.send(
                Version {
                    version: 3,
                    extensions: vec![],
                }
                .encode(),
            )
            .unwrap();
            let mut x = seed | 1;
            let mut rnd = move || {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x
            };
            loop {
                // Everything the client queued so far, answered backwards.
                let Some(first) = next_req(&mut srx, &mut buf).await else {
                    return;
                };
                let mut batch = vec![first];
                tokio::task::yield_now().await;
                while let Ok(c) = srx.try_recv() {
                    buf.extend_from_slice(&c);
                }
                while buf.len() >= 4 {
                    let n = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                    if buf.len() < 4 + n {
                        break;
                    }
                    batch.push(next_req(&mut srx, &mut buf).await.unwrap());
                }
                for p in batch.into_iter().rev() {
                    let (id, r) = Request::decode(p).unwrap();
                    let reply = match r {
                        Request::Read { offset, len, .. } => {
                            let off = offset as usize;
                            if off >= content.len() {
                                Reply::Status(Status::new(status::EOF))
                            } else {
                                let avail = content.len() - off;
                                let pick = if allow_empty {
                                    rnd() % 5
                                } else {
                                    1 + rnd() % 4
                                };
                                let n = match pick {
                                    0 => 0,                         // empty DATA
                                    1 => (len as usize / 3).max(1), // short read
                                    2 => len as usize + 100,        // over-long
                                    _ => len as usize,
                                }
                                .min(avail);
                                if n == 0 && rnd() % 2 == 0 {
                                    // Empty DATA is legal but useless; keep
                                    // the transfer moving half of the time.
                                    Reply::Data(crate::proto::Payload::from_bytes(
                                        Bytes::copy_from_slice(
                                            &content[off..off + avail.min(len as usize)],
                                        ),
                                    ))
                                } else {
                                    Reply::Data(crate::proto::Payload::from_bytes(
                                        Bytes::copy_from_slice(&content[off..off + n]),
                                    ))
                                }
                            }
                        }
                        _ => Reply::Status(Status::new(status::OK)),
                    };
                    stx.send(reply.encode(id)).unwrap();
                }
            }
        });
        let s = Session::start(
            tx,
            rx,
            SessionOptions {
                read_chunk: Some(1024),
                ..Default::default()
            },
            "t".into(),
            None,
        )
        .await
        .unwrap();
        let info = FileInfo::file("/f", announced);
        let h = SftpReadHandle::new(
            Lease::new(s),
            Bytes::from_static(b"H"),
            info,
            16,
            Arc::new(Stats::new()),
        );
        let got = h.read_at(0, announced as usize).await.unwrap();
        // An empty DATA reply is treated as EOF at that offset, so the result
        // is a prefix of the real content; with no empty replies it is all.
        // Never more than the size at open time (the contract) or the real
        // content.
        let lim = real.min(announced as usize);
        assert!(got.len() <= lim);
        assert_eq!(&got[..], &expect[..got.len()], "seed {seed}");
        if !allow_empty {
            assert_eq!(got.len(), lim, "seed {seed}");
        }
        // Ranged reads in the middle agree with the content too.
        let mid = h.read_at(1500, 3000).await.unwrap();
        assert_eq!(
            &mid[..],
            &expect[1500.min(lim)..(1500 + mid.len()).min(lim)]
        );
        if !allow_empty {
            assert_eq!(mid.len(), 3000.min(lim.saturating_sub(1500)), "seed {seed}");
        }
        drop(h);
        server.abort();
    }

    #[tokio::test]
    async fn out_of_order_short_and_overlong_reads_reassemble() {
        for seed in 1..40 {
            quirky_reads(10_000 + seed as usize * 37, 20_000, seed, seed % 2 == 0).await;
            // File exactly as announced, and a file read past its end.
            quirky_reads(9_000, 9_000, seed, false).await;
            quirky_reads(1_200, 1_000, seed, false).await;
        }
    }
}
