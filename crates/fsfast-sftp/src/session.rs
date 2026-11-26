//! One SFTP session (one SSH channel running the `sftp` subsystem) with
//! fully pipelined requests.
//!
//! * **Request-id completion map.** Every request gets a fresh id and a
//!   oneshot completion slot; any number of requests can be in flight, and
//!   replies may arrive in any order.
//! * **Writer task.** Encoded packets go through an unbounded queue to one
//!   task that owns the channel's write half. It coalesces consecutive small
//!   packets (READ requests, STATs, ...) into one SSH channel message, so a
//!   burst of 64 READ requests costs one SSH packet instead of 64; WRITE
//!   payloads are passed through without copying. Memory stays bounded
//!   because every producer limits its own requests in flight.
//! * **Reader task.** Splits the channel byte stream into packets (DATA
//!   payloads stay zero-copy slices of the received chunks) and completes
//!   the matching slot. It never blocks, so the SSH connection is drained
//!   at full speed.
//! * **Cancellation.** Dropping a pending request removes its slot; a reply
//!   that arrives later is discarded. An abandoned OPEN/OPENDIR is marked so
//!   that, if the server still answers with a handle, the reader closes it
//!   instead of leaking it.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};

use fsfast_core::{Error, ErrorKind, Result};
use fsfast_engine::AbortOnDrop;

use crate::error::status_error;
use crate::proto::{
    self, Encoded, ExtRequest, FileAttributes, Frame, FrameAssembler, Limits, NameEntry, Payload,
    Reply, Request, Statvfs, Version, ext, fxp, status,
};

/// Read/write size used when the server does not announce
/// `limits@openssh.com`: the draft guarantees 32 KiB of data per packet.
pub const FALLBACK_IO_SIZE: usize = 32 * 1024;

/// Coalesce small packets up to this many bytes per channel message.
const BATCH_BYTES: usize = 64 * 1024;

/// Payloads up to this size are copied into the batch instead of being sent
/// as a separate channel message.
const INLINE_PAYLOAD: usize = 4 * 1024;

/// Sends raw bytes on the SFTP channel.
#[async_trait]
pub trait PacketTx: Send + 'static {
    /// Send `data` (one or more whole packets, in order).
    async fn send(&mut self, data: Bytes) -> std::io::Result<()>;
    /// Signal EOF and close the channel.
    async fn close(&mut self);
}

/// Receives raw bytes from the SFTP channel.
#[async_trait]
pub trait PacketRx: Send + 'static {
    /// The next chunk of the server's byte stream; `None` when the channel
    /// closed.
    async fn recv(&mut self) -> Option<Bytes>;
}

#[async_trait]
impl PacketTx for russh::ChannelWriteHalf<russh::client::Msg> {
    async fn send(&mut self, data: Bytes) -> std::io::Result<()> {
        self.data_bytes(data)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string()))
    }

    async fn close(&mut self) {
        let _ = self.eof().await;
        let _ = russh::ChannelWriteHalf::close(self).await;
    }
}

#[async_trait]
impl PacketRx for russh::ChannelReadHalf {
    async fn recv(&mut self) -> Option<Bytes> {
        loop {
            match self.wait().await? {
                russh::ChannelMsg::Data { data } => return Some(data),
                russh::ChannelMsg::ExtendedData { data, .. } => {
                    tracing::debug!(
                        "sftp server stderr: {}",
                        String::from_utf8_lossy(&data).trim_end()
                    );
                }
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => return None,
                _ => {}
            }
        }
    }
}

/// A reply as the reader task delivers it: decoding happens in the task
/// that awaits it, which spreads the work and keeps the reader fast.
#[derive(Debug)]
pub struct RawReply {
    ty: u8,
    body: Bytes,
    data: Option<Payload>,
}

impl RawReply {
    /// Decode into a [`Reply`].
    pub fn decode(self) -> Result<Reply> {
        if let Some(p) = self.data {
            return Ok(Reply::Data(p));
        }
        Ok(Reply::decode(self.ty, self.body)?)
    }
}

enum Waiter {
    Active(oneshot::Sender<Result<RawReply>>),
    /// The requester went away before an OPEN/OPENDIR completed: close any
    /// handle the server returns.
    CloseHandle,
    /// Fire-and-forget request: ignore the reply.
    Ignore,
}

/// Why a session stopped, kept to build errors for later requests.
#[derive(Debug, Clone)]
struct Closed {
    kind: ErrorKind,
    message: String,
}

impl Closed {
    fn error(&self) -> Error {
        Error::new(self.kind, self.message.clone())
    }
}

struct Shared {
    pending: Mutex<HashMap<u32, Waiter>>,
    closed: Mutex<Option<Closed>>,
    is_closed: AtomicBool,
    out: mpsc::UnboundedSender<Encoded>,
    next_id: AtomicU32,
}

impl Shared {
    fn fail(&self, kind: ErrorKind, message: String) {
        {
            let mut c = self.closed.lock();
            if c.is_none() {
                *c = Some(Closed { kind, message });
            }
        }
        self.is_closed.store(true, Ordering::Release);
        let waiters: Vec<Waiter> = self.pending.lock().drain().map(|(_, w)| w).collect();
        let closed = self.closed.lock().clone();
        for w in waiters {
            if let (Waiter::Active(tx), Some(c)) = (w, &closed) {
                let _ = tx.send(Err(c.error()));
            }
        }
    }

    fn closed_error(&self) -> Error {
        match &*self.closed.lock() {
            Some(c) => c.error(),
            None => Error::connection("SFTP session closed"),
        }
    }

    fn alloc_id(&self, pending: &HashMap<u32, Waiter>) -> u32 {
        loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if !pending.contains_key(&id) {
                return id;
            }
        }
    }

    /// Register `waiter` and queue the request. Registration happens before
    /// the packet is queued, so the reply can never race the slot.
    fn submit(&self, req: &Request, waiter: Waiter) -> Result<u32> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(self.closed_error());
        }
        let id = {
            let mut p = self.pending.lock();
            // Check again under the lock: `fail` sets `is_closed` before it
            // drains `pending` under this lock, so a waiter inserted after
            // that drain (the reader has exited) would never complete.
            if self.is_closed.load(Ordering::Acquire) {
                drop(p);
                return Err(self.closed_error());
            }
            let id = self.alloc_id(&p);
            p.insert(id, waiter);
            id
        };
        if self.out.send(req.encode(id)).is_err() {
            self.pending.lock().remove(&id);
            return Err(self.closed_error());
        }
        Ok(id)
    }

    /// Close the server handle carried by a reply nobody will consume.
    fn close_orphan(&self, reply: RawReply) {
        if reply.ty == fxp::HANDLE
            && let Ok(Reply::Handle(h)) = Reply::decode(reply.ty, reply.body)
        {
            tracing::debug!("closing a handle whose OPEN was abandoned");
            let _ = self.submit(&Request::Close { handle: h }, Waiter::Ignore);
        }
    }

    fn dispatch(&self, id: u32, reply: RawReply) {
        let w = self.pending.lock().remove(&id);
        match w {
            Some(Waiter::Active(tx)) => {
                // The requester may have gone away between our removing the
                // slot and this send: an orphaned HANDLE must still be closed.
                if let Err(Ok(reply)) = tx.send(Ok(reply)) {
                    self.close_orphan(reply);
                }
            }
            Some(Waiter::CloseHandle) => self.close_orphan(reply),
            Some(Waiter::Ignore) => {}
            None => tracing::trace!("reply for abandoned request {id}"),
        }
    }
}

/// A request in flight. Await it (it is a future) or drop it to abandon
/// the reply.
pub struct PendingCall {
    shared: Arc<Shared>,
    id: u32,
    rx: oneshot::Receiver<Result<RawReply>>,
    done: bool,
    close_on_drop: bool,
}

impl Future for PendingCall {
    type Output = Result<RawReply>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.rx).poll(cx) {
            Poll::Ready(r) => {
                self.done = true;
                Poll::Ready(match r {
                    Ok(r) => r,
                    Err(_) => Err(self.shared.closed_error()),
                })
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for PendingCall {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let mut p = self.shared.pending.lock();
        if !self.close_on_drop {
            p.remove(&self.id);
            return;
        }
        if let Some(w) = p.get_mut(&self.id) {
            *w = Waiter::CloseHandle;
            return;
        }
        drop(p);
        // The reader already took the slot: the reply is either in our
        // receiver (delivered, never polled) or about to be sent, in which
        // case closing the receiver makes the send fail and the reader closes
        // the handle itself (see `Shared::dispatch`).
        self.rx.close();
        if let Ok(Ok(reply)) = self.rx.try_recv() {
            self.shared.close_orphan(reply);
        }
    }
}

/// Owns an open server handle inside an operation: if the operation's
/// future is dropped (cancelled) before it closes the handle, the guard
/// sends `SSH_FXP_CLOSE` (without waiting), so cancellation cannot leak
/// server handles.
pub(crate) struct HandleGuard<'a> {
    session: &'a Session,
    handle: Option<Bytes>,
}

impl<'a> HandleGuard<'a> {
    pub(crate) fn new(session: &'a Session, handle: Bytes) -> Self {
        HandleGuard {
            session,
            handle: Some(handle),
        }
    }

    /// The guarded handle.
    pub(crate) fn handle(&self) -> &Bytes {
        self.handle
            .as_ref()
            .expect("guard holds a handle until disarmed")
    }

    /// Take the handle back; the caller is responsible for closing it.
    pub(crate) fn disarm(mut self) -> Bytes {
        self.handle
            .take()
            .expect("guard holds a handle until disarmed")
    }
}

impl Drop for HandleGuard<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            self.session.close_nowait(h);
        }
    }
}

/// Server extensions this client uses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Extensions {
    /// `posix-rename@openssh.com`.
    pub posix_rename: bool,
    /// `statvfs@openssh.com`.
    pub statvfs: bool,
    /// `fstatvfs@openssh.com`.
    pub fstatvfs: bool,
    /// `hardlink@openssh.com`.
    pub hardlink: bool,
    /// `fsync@openssh.com`.
    pub fsync: bool,
    /// `lsetstat@openssh.com`.
    pub lsetstat: bool,
    /// `limits@openssh.com`.
    pub limits: bool,
    /// `expand-path@openssh.com`.
    pub expand_path: bool,
    /// `copy-data`.
    pub copy_data: bool,
    /// `home-directory`.
    pub home_directory: bool,
}

impl Extensions {
    /// Extensions offered in a VERSION reply.
    pub fn from_version(v: &Version) -> Self {
        Extensions {
            posix_rename: v.has(ext::POSIX_RENAME),
            statvfs: v.has(ext::STATVFS),
            fstatvfs: v.has(ext::FSTATVFS),
            hardlink: v.has(ext::HARDLINK),
            fsync: v.has(ext::FSYNC),
            lsetstat: v.has(ext::LSETSTAT),
            limits: v.has(ext::LIMITS),
            expand_path: v.has(ext::EXPAND_PATH),
            copy_data: v.has(ext::COPY_DATA),
            home_directory: v.has(ext::HOME_DIRECTORY),
        }
    }
}

/// I/O sizing options for a session.
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionOptions {
    /// READ size override (clamped to the server's limit).
    pub read_chunk: Option<usize>,
    /// WRITE size override (clamped to the server's limit).
    pub write_chunk: Option<usize>,
    /// Per-request timeout.
    pub request_timeout: Option<Duration>,
    /// Bound on the SFTP handshake (`INIT`/`VERSION` and the
    /// `limits@openssh.com` query), so a server that accepts the subsystem
    /// but never answers cannot hang the connection attempt.
    pub handshake_timeout: Option<Duration>,
}

struct Inner {
    shared: Arc<Shared>,
    version: Version,
    ext: Extensions,
    limits: Option<Limits>,
    read_chunk: usize,
    write_chunk: usize,
    request_timeout: Option<Duration>,
    active: AtomicUsize,
    label: String,
    negotiated: Option<crate::ssh::connect::Negotiated>,
    _reader: AbortOnDrop<()>,
    // Keeps the SSH connection alive as long as the session is used.
    _keepalive: Option<Arc<dyn Send + Sync>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Stop the reader and refuse new requests; the writer task drains
        // what is queued (e.g. CLOSE of dropped handles), then closes the
        // channel once the last sender is gone.
        self.shared.is_closed.store(true, Ordering::Release);
    }
}

/// A shareable handle to one SFTP session.
#[derive(Clone)]
pub struct Session {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("label", &self.inner.label)
            .field("version", &self.inner.version.version)
            .field("closed", &self.is_closed())
            .finish()
    }
}

async fn writer_task<T: PacketTx>(
    mut tx: T,
    mut rx: mpsc::UnboundedReceiver<Encoded>,
    shared: std::sync::Weak<Shared>,
) {
    let mut batch = BytesMut::with_capacity(BATCH_BYTES);
    let fail = |msg: String| {
        if let Some(s) = shared.upgrade() {
            s.fail(ErrorKind::ConnectionFailed, msg);
        }
    };
    'outer: while let Some(first) = rx.recv().await {
        let mut next = Some(first);
        while let Some(pkt) = next.take() {
            batch.extend_from_slice(&pkt.head);
            if let Some(p) = pkt.payload {
                if p.len() <= INLINE_PAYLOAD {
                    batch.extend_from_slice(&p);
                } else {
                    // Large WRITE data goes out as is (zero-copy); flush the
                    // batch first to keep the byte stream in order.
                    if let Err(e) = tx.send(batch.split().freeze()).await {
                        fail(format!("SFTP channel write failed: {e}"));
                        break 'outer;
                    }
                    if let Err(e) = tx.send(p).await {
                        fail(format!("SFTP channel write failed: {e}"));
                        break 'outer;
                    }
                }
            }
            if batch.len() >= BATCH_BYTES {
                break;
            }
            // Coalesce whatever else is already queued.
            next = rx.try_recv().ok();
        }
        if !batch.is_empty()
            && let Err(e) = tx.send(batch.split().freeze()).await
        {
            fail(format!("SFTP channel write failed: {e}"));
            break;
        }
    }
    tx.close().await;
}

async fn reader_task<R: PacketRx>(mut rx: R, mut asm: FrameAssembler, shared: Arc<Shared>) {
    let (kind, msg) = 'outer: loop {
        let Some(chunk) = rx.recv().await else {
            break (
                ErrorKind::ConnectionFailed,
                "SFTP channel closed by the server".to_owned(),
            );
        };
        asm.push(chunk);
        loop {
            match asm.next_frame() {
                Ok(Some(Frame::Reply { ty, id, body, data })) => {
                    shared.dispatch(id, RawReply { ty, body, data });
                }
                Ok(Some(Frame::Version(_))) => {
                    break 'outer (
                        ErrorKind::Protocol,
                        "unexpected SSH_FXP_VERSION from the server".to_owned(),
                    );
                }
                Ok(None) => break,
                Err(e) => break 'outer (ErrorKind::Protocol, e.to_string()),
            }
        }
    };
    if kind == ErrorKind::Protocol {
        tracing::warn!("SFTP session failed: {msg}");
    } else {
        tracing::debug!("SFTP session ended: {msg}");
    }
    shared.fail(kind, msg);
}

/// Decode helpers shared by the typed calls.
fn expect_status(r: RawReply, op: &str, path: Option<&str>) -> Result<()> {
    match r.decode()? {
        Reply::Status(s) if s.is_ok() => Ok(()),
        Reply::Status(s) => Err(status_error(&s, op, path)),
        other => Err(unexpected(op, &other)),
    }
}

fn unexpected(op: &str, r: &Reply) -> Error {
    Error::protocol(format!("{op}: unexpected {} reply", r.type_name()))
}

fn bytes_of(s: &str) -> Bytes {
    Bytes::copy_from_slice(s.as_bytes())
}

impl Session {
    /// Run the SFTP handshake on a fresh channel and start the I/O tasks.
    /// `keepalive` is stored to keep the underlying SSH connection open.
    pub async fn start<T: PacketTx, R: PacketRx>(
        tx: T,
        rx: R,
        opts: SessionOptions,
        label: String,
        keepalive: Option<Arc<dyn Send + Sync>>,
    ) -> Result<Session> {
        let fut = Self::start_inner(tx, rx, opts, label, keepalive);
        match opts.handshake_timeout {
            Some(d) => tokio::time::timeout(d, fut).await.map_err(|_| {
                Error::timeout(format!("the SFTP handshake did not complete within {d:?}"))
            })?,
            None => fut.await,
        }
    }

    async fn start_inner<T: PacketTx, R: PacketRx>(
        mut tx: T,
        mut rx: R,
        opts: SessionOptions,
        label: String,
        keepalive: Option<Arc<dyn Send + Sync>>,
    ) -> Result<Session> {
        tx.send(proto::encode_init(proto::SFTP_VERSION))
            .await
            .map_err(|e| Error::connection(format!("sending SSH_FXP_INIT: {e}")))?;
        let mut asm = FrameAssembler::default();
        let version = loop {
            if let Some(f) = asm.next_frame()? {
                match f {
                    Frame::Version(b) => break Version::decode(b)?,
                    Frame::Reply { ty, .. } => {
                        return Err(Error::protocol(format!(
                            "expected SSH_FXP_VERSION, got packet type {ty}"
                        )));
                    }
                }
            }
            let Some(chunk) = rx.recv().await else {
                return Err(Error::connection(
                    "the server closed the SFTP channel during the handshake",
                ));
            };
            asm.push(chunk);
        };
        if version.version < proto::SFTP_VERSION {
            return Err(Error::unsupported(format!(
                "SFTP protocol version {} (the server must speak version 3)",
                version.version
            )));
        }
        let ext = Extensions::from_version(&version);
        tracing::debug!(
            "SFTP v{} on {label}, extensions: {:?}",
            version.version,
            version
                .extensions
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
        );

        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            pending: Mutex::new(HashMap::new()),
            closed: Mutex::new(None),
            is_closed: AtomicBool::new(false),
            out: out_tx,
            next_id: AtomicU32::new(1),
        });
        tokio::spawn(writer_task(tx, out_rx, Arc::downgrade(&shared)));
        let reader = AbortOnDrop::spawn(reader_task(rx, asm, shared.clone()));

        let mut session = Session {
            inner: Arc::new(Inner {
                shared,
                version,
                ext,
                limits: None,
                read_chunk: FALLBACK_IO_SIZE,
                write_chunk: FALLBACK_IO_SIZE,
                request_timeout: opts.request_timeout,
                active: AtomicUsize::new(0),
                label,
                negotiated: None,
                _reader: reader,
                _keepalive: keepalive,
            }),
        };
        let limits = if ext.limits {
            match session
                .call(Request::Extended(ExtRequest::Limits))
                .await?
                .decode()?
            {
                Reply::ExtendedReply(b) => Some(Limits::decode(b)?),
                Reply::Status(s) => {
                    tracing::debug!("limits@openssh.com failed: {}", s.message);
                    None
                }
                other => return Err(unexpected("limits@openssh.com", &other)),
            }
        } else {
            None
        };
        let (read_chunk, write_chunk) = io_sizes(limits.as_ref(), &opts);
        // Nothing else holds the Arc yet, so the sizes can be filled in.
        if let Some(inner) = Arc::get_mut(&mut session.inner) {
            inner.limits = limits;
            inner.read_chunk = read_chunk;
            inner.write_chunk = write_chunk;
        }
        Ok(session)
    }

    /// Record the SSH algorithms (only before the session is shared).
    pub(crate) fn set_negotiated(&mut self, n: crate::ssh::connect::Negotiated) {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.negotiated = Some(n);
        }
    }

    /// The SSH algorithms of the underlying connection, if known.
    pub fn negotiated(&self) -> Option<&crate::ssh::connect::Negotiated> {
        self.inner.negotiated.as_ref()
    }

    /// Whether the session can no longer be used.
    pub fn is_closed(&self) -> bool {
        self.inner.shared.is_closed.load(Ordering::Acquire)
    }

    /// The error describing why the session closed.
    pub fn closed_error(&self) -> Error {
        self.inner.shared.closed_error()
    }

    /// Diagnostic label (`user@host:port#n`).
    pub fn label(&self) -> &str {
        &self.inner.label
    }

    /// Server protocol version and extensions.
    pub fn version(&self) -> &Version {
        &self.inner.version
    }

    /// Extensions this client can use.
    pub fn extensions(&self) -> Extensions {
        self.inner.ext
    }

    /// The server's `limits@openssh.com` reply, if any.
    pub fn limits(&self) -> Option<Limits> {
        self.inner.limits
    }

    /// READ request size.
    pub fn read_chunk(&self) -> usize {
        self.inner.read_chunk
    }

    /// WRITE request size.
    pub fn write_chunk(&self) -> usize {
        self.inner.write_chunk
    }

    /// Operations currently using this session (pool load metric).
    pub fn active(&self) -> usize {
        self.inner.active.load(Ordering::Relaxed)
    }

    pub(crate) fn acquire(&self) {
        self.inner.active.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn release(&self) {
        self.inner.active.fetch_sub(1, Ordering::Relaxed);
    }

    /// The per-request timeout, if any.
    pub fn request_timeout(&self) -> Option<Duration> {
        self.inner.request_timeout
    }

    /// Requests waiting for a reply.
    pub fn in_flight(&self) -> usize {
        self.inner.shared.pending.lock().len()
    }

    /// Queue `req` and return its pending reply.
    pub fn start_call(&self, req: &Request) -> Result<PendingCall> {
        let close_on_drop = matches!(req, Request::Open { .. } | Request::Opendir { .. });
        let (tx, rx) = oneshot::channel();
        let id = self.inner.shared.submit(req, Waiter::Active(tx))?;
        Ok(PendingCall {
            shared: self.inner.shared.clone(),
            id,
            rx,
            done: false,
            close_on_drop,
        })
    }

    /// Wait for `call`, honouring the per-request timeout.
    pub async fn finish(&self, call: PendingCall) -> Result<RawReply> {
        match self.inner.request_timeout {
            Some(d) => tokio::time::timeout(d, call)
                .await
                .map_err(|_| Error::timeout(format!("SFTP request timed out after {d:?}")))?,
            None => call.await,
        }
    }

    /// Send `req` and wait for its reply.
    pub async fn call(&self, req: Request) -> Result<RawReply> {
        let c = self.start_call(&req)?;
        self.finish(c).await
    }

    /// Send `req` without waiting for (or caring about) the reply.
    pub fn send_nowait(&self, req: Request) {
        let _ = self.inner.shared.submit(&req, Waiter::Ignore);
    }

    /// `SSH_FXP_STAT`.
    pub async fn stat(&self, path: &str) -> Result<FileAttributes> {
        self.attrs_call(
            Request::Stat {
                path: bytes_of(path),
            },
            "stat",
            path,
        )
        .await
    }

    /// `SSH_FXP_LSTAT`.
    pub async fn lstat(&self, path: &str) -> Result<FileAttributes> {
        self.attrs_call(
            Request::Lstat {
                path: bytes_of(path),
            },
            "lstat",
            path,
        )
        .await
    }

    /// `SSH_FXP_FSTAT`.
    pub async fn fstat(&self, handle: &Bytes, path: &str) -> Result<FileAttributes> {
        self.attrs_call(
            Request::Fstat {
                handle: handle.clone(),
            },
            "fstat",
            path,
        )
        .await
    }

    async fn attrs_call(&self, req: Request, op: &str, path: &str) -> Result<FileAttributes> {
        attrs_reply(self.call(req).await?, op, path)
    }

    /// `SSH_FXP_OPEN`.
    pub async fn open(&self, path: &str, pflags: u32, attrs: FileAttributes) -> Result<Bytes> {
        let c = self.start_call(&Request::Open {
            path: bytes_of(path),
            pflags,
            attrs,
        })?;
        handle_reply(self.finish(c).await?, "open", path)
    }

    /// `SSH_FXP_OPENDIR`.
    pub async fn opendir(&self, path: &str) -> Result<Bytes> {
        let c = self.start_call(&Request::Opendir {
            path: bytes_of(path),
        })?;
        handle_reply(self.finish(c).await?, "opendir", path)
    }

    /// `SSH_FXP_CLOSE`, waiting for the status.
    pub async fn close(&self, handle: Bytes, path: &str) -> Result<()> {
        let r = self.call(Request::Close { handle }).await?;
        expect_status(r, "close", Some(path))
    }

    /// `SSH_FXP_CLOSE` without waiting.
    pub fn close_nowait(&self, handle: Bytes) {
        self.send_nowait(Request::Close { handle });
    }

    /// `SSH_FXP_READDIR` as a pending call (decode with [`readdir_reply`]).
    pub fn start_readdir(&self, handle: &Bytes) -> Result<PendingCall> {
        self.start_call(&Request::Readdir {
            handle: handle.clone(),
        })
    }

    /// `SSH_FXP_REMOVE`.
    pub async fn remove(&self, path: &str) -> Result<()> {
        let r = self
            .call(Request::Remove {
                path: bytes_of(path),
            })
            .await?;
        expect_status(r, "remove", Some(path))
    }

    /// `SSH_FXP_MKDIR`.
    pub async fn mkdir(&self, path: &str) -> Result<()> {
        let r = self
            .call(Request::Mkdir {
                path: bytes_of(path),
                attrs: FileAttributes::default(),
            })
            .await?;
        expect_status(r, "mkdir", Some(path))
    }

    /// `SSH_FXP_RMDIR`.
    pub async fn rmdir(&self, path: &str) -> Result<()> {
        let r = self
            .call(Request::Rmdir {
                path: bytes_of(path),
            })
            .await?;
        expect_status(r, "rmdir", Some(path))
    }

    /// `SSH_FXP_SETSTAT`.
    pub async fn setstat(&self, path: &str, attrs: FileAttributes) -> Result<()> {
        let r = self
            .call(Request::Setstat {
                path: bytes_of(path),
                attrs,
            })
            .await?;
        expect_status(r, "setstat", Some(path))
    }

    /// `SSH_FXP_FSETSTAT`.
    pub async fn fsetstat(&self, handle: &Bytes, attrs: FileAttributes, path: &str) -> Result<()> {
        let r = self
            .call(Request::Fsetstat {
                handle: handle.clone(),
                attrs,
            })
            .await?;
        expect_status(r, "fsetstat", Some(path))
    }

    /// Rename `old` to `new`, replacing `new` (`posix-rename@openssh.com`).
    /// Falls back to a plain `SSH_FXP_RENAME` (which fails if `new`
    /// exists on OpenSSH) when the extension is missing.
    pub async fn rename(&self, old: &str, new: &str) -> Result<()> {
        let req = if self.inner.ext.posix_rename {
            Request::Extended(ExtRequest::PosixRename {
                old: bytes_of(old),
                new: bytes_of(new),
            })
        } else {
            Request::Rename {
                old: bytes_of(old),
                new: bytes_of(new),
            }
        };
        let r = self.call(req).await?;
        expect_status(r, "rename", Some(old))
    }

    /// Plain `SSH_FXP_RENAME`.
    pub async fn rename_plain(&self, old: &str, new: &str) -> Result<()> {
        let r = self
            .call(Request::Rename {
                old: bytes_of(old),
                new: bytes_of(new),
            })
            .await?;
        expect_status(r, "rename", Some(old))
    }

    /// `SSH_FXP_REALPATH`.
    pub async fn realpath(&self, path: &str) -> Result<String> {
        let r = self
            .call(Request::Realpath {
                path: bytes_of(path),
            })
            .await?;
        single_name(r, "realpath", path)
    }

    /// `SSH_FXP_READLINK`.
    pub async fn readlink(&self, path: &str) -> Result<String> {
        let r = self
            .call(Request::Readlink {
                path: bytes_of(path),
            })
            .await?;
        single_name(r, "readlink", path)
    }

    /// `SSH_FXP_SYMLINK`: create `link` pointing to `target`.
    pub async fn symlink(&self, target: &str, link: &str) -> Result<()> {
        let r = self
            .call(Request::Symlink {
                link: bytes_of(link),
                target: bytes_of(target),
            })
            .await?;
        expect_status(r, "symlink", Some(link))
    }

    fn require(&self, have: bool, name: &str) -> Result<()> {
        if have {
            Ok(())
        } else {
            Err(Error::unsupported(format!(
                "the SFTP extension {name} (not offered by the server)"
            )))
        }
    }

    /// `hardlink@openssh.com`.
    pub async fn hardlink(&self, old: &str, new: &str) -> Result<()> {
        self.require(self.inner.ext.hardlink, ext::HARDLINK)?;
        let r = self
            .call(Request::Extended(ExtRequest::Hardlink {
                old: bytes_of(old),
                new: bytes_of(new),
            }))
            .await?;
        expect_status(r, "hardlink", Some(new))
    }

    /// `statvfs@openssh.com`.
    pub async fn statvfs(&self, path: &str) -> Result<Statvfs> {
        self.require(self.inner.ext.statvfs, ext::STATVFS)?;
        let r = self
            .call(Request::Extended(ExtRequest::Statvfs {
                path: bytes_of(path),
            }))
            .await?;
        match r.decode()? {
            Reply::ExtendedReply(b) => Ok(Statvfs::decode(b)?),
            Reply::Status(s) => Err(status_error(&s, "statvfs", Some(path))),
            other => Err(unexpected("statvfs", &other)),
        }
    }

    /// `fsync@openssh.com`.
    pub async fn fsync(&self, handle: &Bytes, path: &str) -> Result<()> {
        self.require(self.inner.ext.fsync, ext::FSYNC)?;
        let r = self
            .call(Request::Extended(ExtRequest::Fsync {
                handle: handle.clone(),
            }))
            .await?;
        expect_status(r, "fsync", Some(path))
    }

    /// `copy-data`: copy `length` bytes (0: to EOF) between open handles on
    /// the server.
    pub async fn copy_data(
        &self,
        read_handle: &Bytes,
        read_offset: u64,
        length: u64,
        write_handle: &Bytes,
        write_offset: u64,
        path: &str,
    ) -> Result<()> {
        self.require(self.inner.ext.copy_data, ext::COPY_DATA)?;
        let r = self
            .call(Request::Extended(ExtRequest::CopyData {
                read_handle: read_handle.clone(),
                read_offset,
                length,
                write_handle: write_handle.clone(),
                write_offset,
            }))
            .await?;
        expect_status(r, "copy-data", Some(path))
    }

    /// `expand-path@openssh.com` (REALPATH with `~` expansion).
    pub async fn expand_path(&self, path: &str) -> Result<String> {
        self.require(self.inner.ext.expand_path, ext::EXPAND_PATH)?;
        let r = self
            .call(Request::Extended(ExtRequest::ExpandPath {
                path: bytes_of(path),
            }))
            .await?;
        single_name(r, "expand-path", path)
    }

    /// `home-directory`: the home directory of `user` (OpenSSH requires a
    /// user name).
    pub async fn home_directory(&self, user: &str) -> Result<String> {
        self.require(self.inner.ext.home_directory, ext::HOME_DIRECTORY)?;
        let r = self
            .call(Request::Extended(ExtRequest::HomeDirectory {
                user: bytes_of(user),
            }))
            .await?;
        single_name(r, "home-directory", user)
    }
}

/// READ/WRITE sizes from the server limits and the options.
fn io_sizes(limits: Option<&Limits>, opts: &SessionOptions) -> (usize, usize) {
    let cap = |v: u64| -> usize {
        if v == 0 {
            FALLBACK_IO_SIZE
        } else {
            // Bound by what a u32 READ length and our 4 MiB option cap allow.
            v.min(4 << 20) as usize
        }
    };
    let (mut r, mut w) = match limits {
        Some(l) => {
            let r = cap(l.max_read_len);
            let mut w = cap(l.max_write_len);
            // A WRITE packet carries ~40 bytes plus the handle besides the
            // data: stay below the server's packet limit.
            if l.max_packet_len > 0 {
                w = w.min((l.max_packet_len as usize).saturating_sub(1024).max(1024));
            }
            (r, w)
        }
        None => (FALLBACK_IO_SIZE, FALLBACK_IO_SIZE),
    };
    if let Some(o) = opts.read_chunk {
        r = r.min(o);
    }
    if let Some(o) = opts.write_chunk {
        w = w.min(o);
    }
    (r.max(1024), w.max(1024))
}

/// Decode a reply expected to be ATTRS.
pub fn attrs_reply(r: RawReply, op: &str, path: &str) -> Result<FileAttributes> {
    match r.decode()? {
        Reply::Attrs(a) => Ok(a),
        Reply::Status(s) => Err(status_error(&s, op, Some(path))),
        other => Err(unexpected(op, &other)),
    }
}

/// Decode a reply expected to be HANDLE.
pub fn handle_reply(r: RawReply, op: &str, path: &str) -> Result<Bytes> {
    match r.decode()? {
        Reply::Handle(h) => Ok(h),
        Reply::Status(s) => Err(status_error(&s, op, Some(path))),
        other => Err(unexpected(op, &other)),
    }
}

/// Decode a reply expected to be a STATUS (OK or error).
pub fn status_reply(r: RawReply, op: &str, path: &str) -> Result<()> {
    expect_status(r, op, Some(path))
}

/// Decode a READDIR reply: entries, or `None` at the end of the directory.
pub fn readdir_reply(r: RawReply, path: &str) -> Result<Option<Vec<NameEntry>>> {
    match r.decode().map_err(|e| e.with_path(path))? {
        Reply::Name(v) => Ok(Some(v)),
        Reply::Status(s) if s.code == status::EOF => Ok(None),
        Reply::Status(s) => Err(status_error(&s, "readdir", Some(path))),
        other => Err(unexpected("readdir", &other)),
    }
}

fn single_name(r: RawReply, op: &str, path: &str) -> Result<String> {
    match r.decode().map_err(|e| e.with_path(path))? {
        Reply::Name(v) if !v.is_empty() => {
            Ok(v.into_iter().next().map(|e| e.filename).unwrap_or_default())
        }
        Reply::Name(_) => Err(Error::protocol(format!("{op}: empty NAME reply"))),
        Reply::Status(s) => Err(status_error(&s, op, Some(path))),
        other => Err(unexpected(op, &other)),
    }
}

/// A READ reply: data, end of file, or an error.
pub enum ReadReply {
    /// Bytes read (possibly fewer than requested).
    Data(Payload),
    /// `SSH_FX_EOF`: the offset is at or past the end of the file.
    Eof,
}

/// Decode a READ reply.
pub fn read_reply(r: RawReply, path: &str) -> Result<ReadReply> {
    match r.decode()? {
        Reply::Data(p) => Ok(ReadReply::Data(p)),
        Reply::Status(s) if s.code == status::EOF => Ok(ReadReply::Eof),
        Reply::Status(s) => Err(status_error(&s, "read", Some(path))),
        other => Err(unexpected("read", &other)),
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! An in-process transport pair for driving a [`Session`] against a
    //! scripted test server.

    use super::*;

    /// Client-side halves backed by channels.
    pub struct MemTx(pub mpsc::UnboundedSender<Bytes>);
    /// Client-side receive half.
    pub struct MemRx(pub mpsc::UnboundedReceiver<Bytes>);

    #[async_trait]
    impl PacketTx for MemTx {
        async fn send(&mut self, data: Bytes) -> std::io::Result<()> {
            self.0
                .send(data)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        async fn close(&mut self) {}
    }

    #[async_trait]
    impl PacketRx for MemRx {
        async fn recv(&mut self) -> Option<Bytes> {
            self.0.recv().await
        }
    }

    /// `(client tx, client rx, server rx of client bytes, server tx)`.
    pub fn pair() -> (
        MemTx,
        MemRx,
        mpsc::UnboundedReceiver<Bytes>,
        mpsc::UnboundedSender<Bytes>,
    ) {
        let (c2s_tx, c2s_rx) = mpsc::unbounded_channel();
        let (s2c_tx, s2c_rx) = mpsc::unbounded_channel();
        (MemTx(c2s_tx), MemRx(s2c_rx), c2s_rx, s2c_tx)
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::proto::{Status, Version};

    /// A request submitted while the reader shuts the session down (between
    /// submit's first `is_closed` check and its insert into `pending`) must
    /// fail instead of leaving a waiter nobody will ever complete.
    #[test]
    fn submit_racing_fail_does_not_leave_a_waiter() {
        let (out, _out_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            pending: Mutex::new(HashMap::new()),
            closed: Mutex::new(None),
            is_closed: AtomicBool::new(false),
            out,
            next_id: AtomicU32::new(1),
        });
        // Hold the map lock so the submitter stops right after its first
        // check, then do what `fail` does in that window.
        let guard = shared.pending.lock();
        let s2 = shared.clone();
        let submitter = std::thread::spawn(move || {
            let (tx, _rx) = oneshot::channel();
            s2.submit(
                &Request::Stat {
                    path: Bytes::from_static(b"/"),
                },
                Waiter::Active(tx),
            )
        });
        std::thread::sleep(Duration::from_millis(200));
        *shared.closed.lock() = Some(Closed {
            kind: ErrorKind::ConnectionFailed,
            message: "gone".into(),
        });
        shared.is_closed.store(true, Ordering::Release);
        // (`fail` drains the map here; it is empty.)
        drop(guard);
        let r = submitter.join().unwrap();
        assert!(r.is_err(), "submit after the drain must fail");
        assert!(shared.pending.lock().is_empty(), "a waiter was left behind");
    }

    /// Split the client byte stream into requests.
    struct ReqReader {
        rx: mpsc::UnboundedReceiver<Bytes>,
        buf: BytesMut,
    }

    impl ReqReader {
        async fn next(&mut self) -> Option<Bytes> {
            loop {
                if self.buf.len() >= 4 {
                    let n = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]])
                        as usize;
                    if self.buf.len() >= 4 + n {
                        let mut p = self.buf.split_to(4 + n);
                        let _ = p.split_to(4);
                        return Some(p.freeze());
                    }
                }
                let c = self.rx.recv().await?;
                self.buf.extend_from_slice(&c);
            }
        }
    }

    async fn handshake(
        server_rx: mpsc::UnboundedReceiver<Bytes>,
        server_tx: &mpsc::UnboundedSender<Bytes>,
        exts: &[&str],
    ) -> ReqReader {
        let mut rr = ReqReader {
            rx: server_rx,
            buf: BytesMut::new(),
        };
        let init = rr.next().await.unwrap();
        assert_eq!(&init[..], &[fxp::INIT, 0, 0, 0, 3]);
        let v = Version {
            version: 3,
            extensions: exts
                .iter()
                .map(|e| ((*e).to_owned(), Bytes::from_static(b"1")))
                .collect(),
        };
        server_tx.send(v.encode()).unwrap();
        rr
    }

    #[tokio::test]
    async fn out_of_order_replies_and_limits() {
        let (tx, rx, srx, stx) = pair();
        let server = tokio::spawn(async move {
            let mut rr = handshake(srx, &stx, &[ext::LIMITS, ext::POSIX_RENAME]).await;
            // limits@openssh.com
            let (id, r) = Request::decode(rr.next().await.unwrap()).unwrap();
            assert_eq!(r, Request::Extended(ExtRequest::Limits));
            let l = Limits {
                max_packet_len: 256 * 1024,
                max_read_len: 261_120,
                max_write_len: 261_120,
                max_open_handles: 64,
            };
            stx.send(Reply::ExtendedReply(l.encode()).encode(id))
                .unwrap();
            // Three STATs answered in reverse order, in one chunk.
            let mut ids = Vec::new();
            for _ in 0..3 {
                let (id, r) = Request::decode(rr.next().await.unwrap()).unwrap();
                assert!(matches!(r, Request::Stat { .. }));
                ids.push(id);
            }
            let mut wire = BytesMut::new();
            for (n, id) in ids.iter().enumerate().rev() {
                wire.extend_from_slice(
                    &Reply::Attrs(FileAttributes::with_size(n as u64)).encode(*id),
                );
            }
            stx.send(wire.freeze()).unwrap();
        });
        let s = Session::start(tx, rx, SessionOptions::default(), "t".into(), None)
            .await
            .unwrap();
        assert!(s.extensions().posix_rename && s.extensions().limits);
        assert!(!s.extensions().copy_data);
        assert_eq!(s.read_chunk(), 261_120);
        assert_eq!(s.write_chunk(), 256 * 1024 - 1024);
        let (a, b, c) = tokio::join!(s.stat("a"), s.stat("b"), s.stat("c"));
        assert_eq!(a.unwrap().size, Some(0));
        assert_eq!(b.unwrap().size, Some(1));
        assert_eq!(c.unwrap().size, Some(2));
        assert_eq!(s.in_flight(), 0);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn small_requests_are_coalesced_and_errors_mapped() {
        let (tx, rx, srx, stx) = pair();
        let (chunks_tx, mut chunks_rx) = mpsc::unbounded_channel::<usize>();
        let server = tokio::spawn(async move {
            let mut rr = handshake(srx, &stx, &[]).await;
            // Count raw chunks: the 50 STATs queued at once should arrive in
            // far fewer channel messages.
            let mut n = 0;
            let mut ids = Vec::new();
            while ids.len() < 50 {
                if rr.buf.len() < 4 || {
                    let l = u32::from_be_bytes([rr.buf[0], rr.buf[1], rr.buf[2], rr.buf[3]]);
                    rr.buf.len() < 4 + l as usize
                } {
                    let c = rr.rx.recv().await.unwrap();
                    n += 1;
                    rr.buf.extend_from_slice(&c);
                    continue;
                }
                let (id, _) = Request::decode(rr.next().await.unwrap()).unwrap();
                ids.push(id);
            }
            chunks_tx.send(n).unwrap();
            for id in ids {
                stx.send(Reply::Status(Status::new(status::NO_SUCH_FILE)).encode(id))
                    .unwrap();
            }
        });
        let s = Session::start(tx, rx, SessionOptions::default(), "t".into(), None)
            .await
            .unwrap();
        assert_eq!(s.read_chunk(), FALLBACK_IO_SIZE);
        let calls: Vec<_> = (0..50)
            .map(|i| {
                s.start_call(&Request::Stat {
                    path: bytes_of(&format!("/p{i}")),
                })
                .unwrap()
            })
            .collect();
        for c in calls {
            let e = attrs_reply(c.await.unwrap(), "stat", "/p").unwrap_err();
            assert_eq!(e.kind(), ErrorKind::NotFound);
        }
        let chunks = chunks_rx.recv().await.unwrap();
        assert!(
            chunks < 50,
            "50 small requests took {chunks} channel messages"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn closed_channel_fails_pending_and_later_requests() {
        let (tx, rx, srx, stx) = pair();
        let server = tokio::spawn(async move {
            let mut rr = handshake(srx, &stx, &[]).await;
            let _ = rr.next().await.unwrap();
            drop(stx); // channel closes with the request outstanding
        });
        let s = Session::start(tx, rx, SessionOptions::default(), "t".into(), None)
            .await
            .unwrap();
        let e = s.stat("/x").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ConnectionFailed);
        assert!(s.is_closed());
        let e = s.stat("/y").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ConnectionFailed);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn abandoned_open_closes_the_late_handle() {
        let (tx, rx, srx, stx) = pair();
        let (seen_tx, mut seen_rx) = mpsc::unbounded_channel::<Request>();
        let (go_tx, go_rx) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let mut rr = handshake(srx, &stx, &[]).await;
            let (id, r) = Request::decode(rr.next().await.unwrap()).unwrap();
            assert!(matches!(r, Request::Open { .. }));
            go_rx.await.unwrap(); // wait until the client gave up
            stx.send(Reply::Handle(Bytes::from_static(b"H1")).encode(id))
                .unwrap();
            let (_, r) = Request::decode(rr.next().await.unwrap()).unwrap();
            seen_tx.send(r).unwrap();
        });
        let s = Session::start(tx, rx, SessionOptions::default(), "t".into(), None)
            .await
            .unwrap();
        let open = s.open("/f", proto::open_flags::READ, FileAttributes::default());
        let r = tokio::time::timeout(Duration::from_millis(50), open).await;
        assert!(r.is_err(), "open should still be pending");
        go_tx.send(()).unwrap();
        let close = seen_rx.recv().await.unwrap();
        assert_eq!(
            close,
            Request::Close {
                handle: Bytes::from_static(b"H1")
            }
        );
        server.await.unwrap();
    }

    /// An OPEN whose HANDLE reply was already delivered to the pending call,
    /// but which is dropped before anyone polled it (a cancelled future),
    /// must still close the server handle.
    #[tokio::test]
    async fn dropped_unpolled_open_with_delivered_handle_is_closed() {
        let (tx, rx, srx, stx) = pair();
        let (seen_tx, mut seen_rx) = mpsc::unbounded_channel::<Request>();
        let server = tokio::spawn(async move {
            let mut rr = handshake(srx, &stx, &[]).await;
            let (id, r) = Request::decode(rr.next().await.unwrap()).unwrap();
            assert!(matches!(r, Request::Open { .. }));
            stx.send(Reply::Handle(Bytes::from_static(b"H2")).encode(id))
                .unwrap();
            if let Some(p) = rr.next().await {
                let (_, r) = Request::decode(p).unwrap();
                seen_tx.send(r).unwrap();
            }
        });
        let s = Session::start(tx, rx, SessionOptions::default(), "t".into(), None)
            .await
            .unwrap();
        let call = s
            .start_call(&Request::Open {
                path: bytes_of("/f"),
                pflags: proto::open_flags::READ,
                attrs: FileAttributes::default(),
            })
            .unwrap();
        // Wait until the reader delivered the reply into the call's slot.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while s.in_flight() > 0 {
            assert!(std::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        drop(call);
        let close = tokio::time::timeout(Duration::from_secs(5), seen_rx.recv())
            .await
            .expect("the handle of the dropped OPEN was never closed")
            .unwrap();
        assert_eq!(
            close,
            Request::Close {
                handle: Bytes::from_static(b"H2")
            }
        );
        drop(s);
        server.abort();
    }

    #[tokio::test]
    async fn request_timeout_and_old_version() {
        let (tx, rx, srx, stx) = pair();
        let server = tokio::spawn(async move {
            let mut rr = handshake(srx, &stx, &[]).await;
            let _ = rr.next().await; // never answered
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let opts = SessionOptions {
            request_timeout: Some(Duration::from_millis(30)),
            ..Default::default()
        };
        let s = Session::start(tx, rx, opts, "t".into(), None)
            .await
            .unwrap();
        let e = s.stat("/slow").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Timeout);
        assert_eq!(
            s.in_flight(),
            0,
            "a timed-out request must not leak its slot"
        );
        server.abort();

        let (tx, rx, mut srx, stx) = pair();
        tokio::spawn(async move {
            let _ = srx.recv().await;
            let v = Version {
                version: 2,
                extensions: vec![],
            };
            stx.send(v.encode()).unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let e = Session::start(tx, rx, SessionOptions::default(), "t".into(), None)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported);
    }

    #[tokio::test]
    async fn silent_server_handshake_times_out() {
        // VERSION never comes.
        let (tx, rx, srx, stx) = pair();
        let opts = SessionOptions {
            handshake_timeout: Some(Duration::from_millis(50)),
            ..Default::default()
        };
        let e = Session::start(tx, rx, opts, "t".into(), None)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Timeout, "{e}");
        // VERSION offers limits@, but the LIMITS query is never answered.
        let (tx, rx, srx2, stx2) = pair();
        let server = tokio::spawn(async move {
            let mut rr = handshake(srx2, &stx2, &[ext::LIMITS]).await;
            let _ = rr.next().await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let e = Session::start(tx, rx, opts, "t".into(), None)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Timeout, "{e}");
        server.abort();
        drop((srx, stx));
    }

    #[test]
    fn io_size_rules() {
        let o = SessionOptions::default();
        assert_eq!(io_sizes(None, &o), (FALLBACK_IO_SIZE, FALLBACK_IO_SIZE));
        let l = Limits {
            max_packet_len: 0,
            max_read_len: 0,
            max_write_len: 100_000,
            max_open_handles: 0,
        };
        assert_eq!(io_sizes(Some(&l), &o), (FALLBACK_IO_SIZE, 100_000));
        let o = SessionOptions {
            read_chunk: Some(8192),
            write_chunk: Some(1 << 30),
            ..Default::default()
        };
        assert_eq!(io_sizes(Some(&l), &o), (8192, 100_000));
    }
}
