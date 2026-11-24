//! One SMB connection: a TCP stream multiplexed between many concurrent
//! requests.
//!
//! * A **writer task** owns the write half. Callers hand it complete frames
//!   through an unbounded channel; it drains whatever is queued and sends it
//!   with vectored writes, so the WRITE payloads (`Bytes`) go from the caller
//!   to the socket without being copied into a header buffer, and many small
//!   frames share one `writev`.
//! * A **reader task** owns the read half. It splits the stream into frames
//!   (no copies: each frame is one allocation that later becomes the
//!   `Bytes` READ data is sliced from), decrypts TRANSFORM_HEADER frames in
//!   place, splits compound responses, returns credits, and routes every
//!   response to the waiting caller by MessageId. Interim `STATUS_PENDING`
//!   responses only record the AsyncId; the caller keeps waiting.
//! * Callers reserve credits, take MessageIds, sign or encrypt and queue the
//!   frame in one synchronous step ([`Shared::send`]), so a dropped future can
//!   never leave a hole in the MessageId sequence. Signature verification
//!   happens in the caller's task ([`Response::recv`]) so it runs in
//!   parallel across requests instead of serializing on the reader.
//! * A dropped caller does not disturb the connection: its response is
//!   discarded when it arrives (credits are still returned), and requests the
//!   server had turned async are CANCELled.
//! * Any connection-level failure (socket error, protocol violation, bad
//!   signature, failed decryption) marks the connection dead and fails every
//!   in-flight request with `ConnectionFailed`; the pool reconnects on next
//!   use.

use std::collections::{HashMap, VecDeque};
use std::io::IoSlice;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes, BytesMut};
use fsfast_core::{Error, ErrorKind, Result};
use fsfast_engine::concurrency::AbortOnDrop;
use fsfast_smb_proto::compound::split_compound;
use fsfast_smb_proto::crypto::{Signer, SmbCipher};
use fsfast_smb_proto::framing::FrameDecoder;
use fsfast_smb_proto::header::{
    COMPRESSION_PROTOCOL_ID, Command, Header, HeaderFlags, HeaderId,
    MESSAGE_ID_OFFSET, TRANSFORM_PROTOCOL_ID, UNSOLICITED_MESSAGE_ID,
};
use fsfast_smb_proto::msg::{
    CancelRequest, EchoRequest, EchoResponse, EncodedMessage, OutgoingFrame, RawMessage,
    encode_message,
};
use fsfast_smb_proto::{Dialect, NtStatus};
use parking_lot::{Mutex, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot, watch};

use crate::credits::Credits;

/// Offset of `CreditCharge` in the SMB2 header.
const CREDIT_CHARGE_OFFSET: usize = 6;
/// Offset of `CreditRequest` in the SMB2 header.
const CREDIT_REQUEST_OFFSET: usize = 14;

/// Initial receive buffer; grown to the size of each large frame.
const READ_BUF: usize = 256 << 10;
/// Frames written per vectored write at most.
const WRITE_BATCH: usize = 64;

/// Cryptographic state of the session bound to a connection.
pub(crate) struct SessionCrypto {
    /// `SessionId`.
    pub session_id: u64,
    /// Signing key schedule (`None` for guest and anonymous sessions).
    pub signer: Option<Signer>,
    /// Sign requests and require signed responses.
    pub signing: bool,
    /// Client-to-server cipher.
    pub encryptor: Option<SmbCipher>,
    /// Server-to-client cipher.
    pub decryptor: Option<SmbCipher>,
    /// Encrypt every request of the session (session `ENCRYPT_DATA` flag or
    /// the user's `encrypt=True`).
    pub encrypt_all: bool,
}

impl std::fmt::Debug for SessionCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCrypto")
            .field("session_id", &format_args!("{:#x}", self.session_id))
            .field("signing", &self.signing)
            .field("encrypt_all", &self.encrypt_all)
            .field("cipher", &self.encryptor.as_ref().map(SmbCipher::cipher))
            .finish()
    }
}

/// How a request is protected.
#[derive(Debug, Clone, Default)]
pub(crate) struct Security {
    /// The session whose keys sign/encrypt the request (`None` before the
    /// session exists).
    pub session: Option<Arc<SessionCrypto>>,
    /// Send the frame inside a TRANSFORM_HEADER.
    pub encrypt: bool,
    /// Sign even when the session does not require signing
    /// (VALIDATE_NEGOTIATE_INFO must always be signed).
    pub force_sign: bool,
}

impl Security {
    /// Unprotected (NEGOTIATE, SESSION_SETUP before keys exist).
    pub fn none() -> Self {
        Security::default()
    }
}

/// Parameters fixed by NEGOTIATE.
#[derive(Debug, Clone)]
pub(crate) struct Negotiated {
    pub dialect: Dialect,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub max_transact_size: u32,
    pub server_guid: fsfast_smb_proto::Guid,
    pub server_security_mode: fsfast_smb_proto::SecurityMode,
    pub server_capabilities: fsfast_smb_proto::Capabilities,
    /// What the client sent in NEGOTIATE (for VALIDATE_NEGOTIATE_INFO).
    pub client_guid: fsfast_smb_proto::Guid,
    pub client_security_mode: fsfast_smb_proto::SecurityMode,
    pub client_capabilities: fsfast_smb_proto::Capabilities,
    pub offered_dialects: Vec<Dialect>,
    /// The cipher both sides support (`None`: no encryption possible).
    pub cipher: Option<fsfast_smb_proto::crypto::Cipher>,
    /// SMB 3.1.1 negotiated signing algorithm.
    pub signing_algorithm: Option<fsfast_smb_proto::msg::SigningAlgorithmId>,
    /// The server's GSS hint (SPNEGO NegTokenInit) from NEGOTIATE.
    pub security_buffer: Bytes,
}

/// Marker source on errors for requests that never reached the socket, so
/// callers know a retry cannot duplicate a non-idempotent operation.
#[derive(Debug)]
pub(crate) struct NotSent;

impl std::fmt::Display for NotSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request was not sent")
    }
}

impl std::error::Error for NotSent {}

/// Whether `e` failed before its request was transmitted.
pub(crate) fn was_not_sent(e: &Error) -> bool {
    std::error::Error::source(e).is_some_and(|s| s.is::<NotSent>())
}

/// A response routed to its caller.
#[derive(Debug)]
struct Delivered {
    msg: RawMessage,
    encrypted: bool,
}

/// One request waiting for its response.
struct Pending {
    tx: Option<oneshot::Sender<Result<Delivered>>>,
    /// Credits the request charged (returned once, by the first response).
    charge: u32,
    settled: bool,
    /// The request went out encrypted: its response must be encrypted too.
    encrypted: bool,
    /// Set by an interim `STATUS_PENDING` response.
    async_id: Option<u64>,
    session_id: u64,
}

/// State shared by the connection's tasks and its callers.
pub(crate) struct Shared {
    /// For logs.
    pub id: u64,
    pub peer: String,
    pub credits: Credits,
    pending: Mutex<HashMap<u64, Pending>>,
    tx: mpsc::UnboundedSender<OutgoingFrame>,
    dead: AtomicBool,
    death: Mutex<Option<String>>,
    shutdown: watch::Sender<bool>,
    /// The session's keys, for decrypting in the reader task.
    crypto: RwLock<Option<Arc<SessionCrypto>>>,
    /// Header `CreditCharge` is meaningful (2.1+).
    multi_credit: AtomicBool,
    started: Instant,
    /// Milliseconds since `started` when the last frame arrived.
    last_rx: AtomicU64,
    request_timeout: Option<Duration>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("id", &self.id)
            .field("peer", &self.peer)
            .field("dead", &self.is_dead())
            .field("credits", &self.credits.available())
            .field("in_flight", &self.pending.lock().len())
            .finish()
    }
}

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// An SMB connection (tasks are aborted when it is dropped).
pub(crate) struct Connection {
    pub shared: Arc<Shared>,
    pub negotiated: OnceLock<Negotiated>,
    _tasks: Vec<AbortOnDrop<()>>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.shared.fmt(f)
    }
}

impl Connection {
    /// Start the reader and writer tasks on `stream`.
    pub fn start(
        stream: TcpStream,
        peer: String,
        max_credits: u16,
        request_timeout: Option<Duration>,
        keepalive: Option<Duration>,
    ) -> Connection {
        let _ = stream.set_nodelay(true);
        let (rd, wr) = stream.into_split();
        let (tx, rx) = mpsc::unbounded_channel();
        let (shutdown, _) = watch::channel(false);
        let shared = Arc::new(Shared {
            id: NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed),
            peer,
            credits: Credits::new(max_credits),
            pending: Mutex::new(HashMap::new()),
            tx,
            dead: AtomicBool::new(false),
            death: Mutex::new(None),
            shutdown,
            crypto: RwLock::new(None),
            multi_credit: AtomicBool::new(false),
            started: Instant::now(),
            last_rx: AtomicU64::new(0),
            request_timeout,
        });
        let mut tasks = vec![
            AbortOnDrop::spawn(reader_loop(shared.clone(), rd)),
            AbortOnDrop::spawn(writer_loop(shared.clone(), wr, rx)),
        ];
        if let Some(every) = keepalive {
            tasks.push(AbortOnDrop::spawn(keepalive_loop(
                Arc::downgrade(&shared),
                every,
            )));
        }
        tracing::debug!(conn = shared.id, peer = %shared.peer, "SMB connection started");
        Connection {
            shared,
            negotiated: OnceLock::new(),
            _tasks: tasks,
        }
    }

    /// Whether the connection can no longer be used.
    pub fn is_dead(&self) -> bool {
        self.shared.is_dead()
    }

    /// Negotiated parameters (panics before NEGOTIATE completed; the pool
    /// only hands out negotiated connections).
    pub fn neg(&self) -> &Negotiated {
        self.negotiated
            .get()
            .expect("connection used before NEGOTIATE completed")
    }

    /// Record the NEGOTIATE result.
    pub fn set_negotiated(&self, n: Negotiated) {
        self.shared
            .multi_credit
            .store(n.dialect.supports_multi_credit(), Ordering::Release);
        let _ = self.negotiated.set(n);
    }

    /// Install the session keys (after SESSION_SETUP).
    pub fn set_crypto(&self, c: Option<Arc<SessionCrypto>>) {
        *self.shared.crypto.write() = c;
    }

    /// Requests in flight.
    pub fn in_flight(&self) -> usize {
        self.shared.pending.lock().len()
    }

    /// Mark the connection dead (closing it).
    pub fn kill(&self, why: &str) {
        self.shared.fail(why);
    }
}

impl Shared {
    /// Whether the connection can no longer be used.
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    fn dead_error(&self) -> Error {
        let why = self
            .death
            .lock()
            .clone()
            .unwrap_or_else(|| "connection closed".into());
        Error::connection(format!("SMB connection to {} lost: {why}", self.peer))
    }

    /// Mark the connection dead and fail every waiting request.
    pub fn fail(&self, why: &str) {
        if self.dead.swap(true, Ordering::AcqRel) {
            return;
        }
        tracing::debug!(conn = self.id, peer = %self.peer, why, "SMB connection failed");
        *self.death.lock() = Some(why.to_owned());
        self.credits.close();
        let _ = self.shutdown.send(true);
        let drained: Vec<Pending> = self.pending.lock().drain().map(|(_, p)| p).collect();
        for p in drained {
            if let Some(tx) = p.tx {
                let _ = tx.send(Err(self.dead_error()));
            }
        }
    }

    fn touch_rx(&self) {
        let ms = self.started.elapsed().as_millis() as u64;
        self.last_rx.store(ms, Ordering::Relaxed);
    }

    fn since_rx(&self) -> Duration {
        let now = self.started.elapsed().as_millis() as u64;
        Duration::from_millis(now.saturating_sub(self.last_rx.load(Ordering::Relaxed)))
    }

    /// Whether `CreditCharge` is used (2.1+).
    pub fn multi_credit(&self) -> bool {
        self.multi_credit.load(Ordering::Acquire)
    }

    /// Send `msgs` as one frame (a single request or a compound chain built
    /// with `CompoundBuilder`) and return one [`Response`] per message.
    ///
    /// Headers must carry everything but `MessageId` and `CreditRequest`,
    /// which are assigned here; `CreditCharge` must already hold the
    /// request's charge on 2.1+ (0 on 2.0.2).
    pub async fn send(
        self: &Arc<Self>,
        msgs: Vec<EncodedMessage>,
        sec: &Security,
    ) -> Result<Vec<Response>> {
        self.send_inner(msgs, sec, false).await.map(|(r, _)| r)
    }

    /// [`Shared::send`] that also returns each message exactly as sent
    /// (input to the 3.1.1 preauth integrity hash).
    pub async fn send_capture(
        self: &Arc<Self>,
        msgs: Vec<EncodedMessage>,
        sec: &Security,
    ) -> Result<(Vec<Response>, Vec<Bytes>)> {
        self.send_inner(msgs, sec, true).await
    }

    async fn send_inner(
        self: &Arc<Self>,
        mut msgs: Vec<EncodedMessage>,
        sec: &Security,
        capture: bool,
    ) -> Result<(Vec<Response>, Vec<Bytes>)> {
        if self.is_dead() {
            return Err(self.dead_error().with_source(NotSent));
        }
        let charges: Vec<u32> = msgs
            .iter()
            .map(|m| {
                let c = u16::from_le_bytes([
                    m.head[CREDIT_CHARGE_OFFSET],
                    m.head[CREDIT_CHARGE_OFFSET + 1],
                ]);
                u32::from(c.max(1))
            })
            .collect();
        let total: u32 = charges.iter().sum();
        let permit = self
            .credits
            .acquire(total)
            .await
            .map_err(|e| e.with_source(NotSent))?;

        // ---- From here on nothing awaits: MessageIds taken are always sent.
        let session = sec.session.as_ref();
        let encrypt = sec.encrypt
            && session.is_some_and(|s| s.encryptor.is_some() && s.session_id != 0);
        if sec.encrypt && !encrypt {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "SMB encryption is required but the session has no encryption keys",
            )
            .with_source(NotSent));
        }
        let base = self.credits.commit(permit, total);
        let mut mid = base;
        let mut mids = Vec::with_capacity(msgs.len());
        for (i, m) in msgs.iter_mut().enumerate() {
            let charge = charges[i];
            m.head[MESSAGE_ID_OFFSET..MESSAGE_ID_OFFSET + 8].copy_from_slice(&mid.to_le_bytes());
            let req = if i == 0 {
                self.credits.request_for(total.min(u32::from(u16::MAX)) as u16)
            } else {
                charge as u16
            };
            m.head[CREDIT_REQUEST_OFFSET..CREDIT_REQUEST_OFFSET + 2]
                .copy_from_slice(&req.to_le_bytes());
            mids.push((mid, charge));
            mid += u64::from(charge);
        }
        let mut sign_err = None;
        if !encrypt
            && let Some(s) = session
            && (s.signing || sec.force_sign)
            && let Some(signer) = &s.signer
        {
            for m in msgs.iter_mut() {
                let h = m.header();
                if h.session_id != 0 && h.command != Command::NEGOTIATE {
                    if let Err(e) = signer.sign(m) {
                        sign_err = Some(e);
                        break;
                    }
                }
            }
        }
        let captured: Vec<Bytes> = if capture {
            msgs.iter()
                .map(|m| m.clone().into_contiguous().freeze())
                .collect()
        } else {
            Vec::new()
        };
        let frame = match sign_err {
            Some(e) => Err(Error::from(e)),
            None if encrypt => {
                let s = session.expect("checked above");
                s.encryptor
                    .as_ref()
                    .expect("checked above")
                    .encrypt_messages(s.session_id, &msgs)
                    .map_err(Error::from)
                    .and_then(|b| OutgoingFrame::from_bytes(b.freeze()).map_err(Error::from))
            }
            None => OutgoingFrame::from_messages(msgs).map_err(Error::from),
        };
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                // The MessageIds are burnt: keep the window consistent by
                // failing the connection rather than leaving a hole.
                self.fail(&format!("could not build a request frame: {e}"));
                return Err(e.with_source(NotSent));
            }
        };
        let session_id = session.map_or(0, |s| s.session_id);
        let mut responses = Vec::with_capacity(mids.len());
        {
            let mut pending = self.pending.lock();
            for &(mid, charge) in &mids {
                let (tx, rx) = oneshot::channel();
                pending.insert(
                    mid,
                    Pending {
                        tx: Some(tx),
                        charge,
                        settled: false,
                        encrypted: encrypt,
                        async_id: None,
                        session_id,
                    },
                );
                responses.push(Response {
                    shared: self.clone(),
                    rx: Some(rx),
                    mid,
                    session: sec.session.clone(),
                });
            }
        }
        if self.tx.send(frame).is_err() {
            self.fail("writer task stopped");
            return Err(self.dead_error().with_source(NotSent));
        }
        if self.is_dead() {
            // `fail` may have drained the map before our entries went in.
            for &(mid, _) in &mids {
                if let Some(p) = self.pending.lock().remove(&mid)
                    && let Some(tx) = p.tx
                {
                    let _ = tx.send(Err(self.dead_error()));
                }
            }
        }
        Ok((responses, captured))
    }

    /// Handle one received frame (reader task).
    fn on_frame(&self, frame: BytesMut) {
        self.touch_rx();
        let (plain, encrypted) = if frame.starts_with(&TRANSFORM_PROTOCOL_ID) {
            let crypto = self.crypto.read().clone();
            let Some(c) = crypto.filter(|c| c.decryptor.is_some()) else {
                self.fail("encrypted message received without session keys");
                return;
            };
            let dec = c.decryptor.as_ref().expect("filtered above");
            match dec.decrypt_in_place(frame) {
                Ok((hdr, plain)) if hdr.session_id == c.session_id => (plain.freeze(), true),
                Ok((hdr, _)) => {
                    self.fail(&format!(
                        "encrypted message for unknown session {:#x}",
                        hdr.session_id
                    ));
                    return;
                }
                Err(e) => {
                    self.fail(&format!("decryption failed: {e}"));
                    return;
                }
            }
        } else if frame.starts_with(&COMPRESSION_PROTOCOL_ID) {
            self.fail("compressed message received although compression was not negotiated");
            return;
        } else {
            (frame.freeze(), false)
        };
        for m in split_compound(plain) {
            match m {
                Ok(m) => self.on_message(m, encrypted),
                Err(e) => {
                    self.fail(&format!("malformed response: {e}"));
                    return;
                }
            }
        }
    }

    fn on_message(&self, m: RawMessage, encrypted: bool) {
        let h: Header = *m.header();
        if !h.is_response() {
            self.fail("server sent a request");
            return;
        }
        if h.message_id == UNSOLICITED_MESSAGE_ID {
            // Oplock/lease break notification: we never request oplocks or
            // leases, so there is nothing to acknowledge.
            self.credits.on_response(h.credits, 0);
            tracing::debug!(conn = self.id, command = ?h.command, "ignoring unsolicited message");
            return;
        }
        let mut pending = self.pending.lock();
        let Some(p) = pending.get_mut(&h.message_id) else {
            drop(pending);
            self.credits.on_response(h.credits, 0);
            tracing::debug!(conn = self.id, mid = h.message_id, "response for unknown MessageId");
            return;
        };
        let settle = if p.settled {
            0
        } else {
            p.settled = true;
            p.charge
        };
        self.credits.on_response(h.credits, settle);
        if h.is_interim() {
            p.async_id = h.async_id();
            return;
        }
        let p = pending.remove(&h.message_id).expect("present above");
        drop(pending);
        if p.encrypted && !encrypted {
            if let Some(tx) = p.tx {
                let _ = tx.send(Err(Error::protocol(
                    "unencrypted SMB response to an encrypted request",
                )
                .with_retryable(false)));
            }
            self.fail("unencrypted response to an encrypted request");
            return;
        }
        if let Some(tx) = p.tx {
            let _ = tx.send(Ok(Delivered { msg: m, encrypted }));
        }
    }

    /// Forget the caller of `mid` (its future was dropped); CANCEL it if the
    /// server turned it into an async operation.
    fn abandon(&self, mid: u64, session: Option<&Arc<SessionCrypto>>) {
        let cancel = {
            let mut pending = self.pending.lock();
            match pending.get_mut(&mid) {
                Some(p) => {
                    p.tx = None;
                    p.async_id.map(|a| (a, p.session_id, p.encrypted))
                }
                None => None,
            }
        };
        if let Some((async_id, session_id, encrypted)) = cancel
            && !self.is_dead()
        {
            self.send_cancel(mid, async_id, session_id, encrypted, session);
        }
    }

    /// CANCEL ([MS-SMB2] §3.2.4.24): no credits, the MessageId of the
    /// original request, async form with its AsyncId.
    fn send_cancel(
        &self,
        mid: u64,
        async_id: u64,
        session_id: u64,
        encrypted: bool,
        session: Option<&Arc<SessionCrypto>>,
    ) {
        let mut h = Header::request(Command::CANCEL);
        h.message_id = mid;
        h.session_id = session_id;
        h.id = HeaderId::Async { async_id };
        h.flags |= HeaderFlags::ASYNC_COMMAND;
        let Ok(mut m) = encode_message(&h, &CancelRequest) else {
            return;
        };
        let frame = match session {
            Some(s) if encrypted && s.encryptor.is_some() => s
                .encryptor
                .as_ref()
                .and_then(|e| e.encrypt_messages(session_id, &[m]).ok())
                .and_then(|b| OutgoingFrame::from_bytes(b.freeze()).ok()),
            Some(s) if s.signing => {
                if let Some(signer) = &s.signer {
                    let _ = signer.sign(&mut m);
                }
                OutgoingFrame::from_messages([m]).ok()
            }
            _ => OutgoingFrame::from_messages([m]).ok(),
        };
        if let Some(f) = frame {
            tracing::debug!(conn = self.id, mid, async_id, "cancelling abandoned async request");
            let _ = self.tx.send(f);
        }
    }

    /// Whether the request `mid` was turned async by the server.
    fn went_async(&self, mid: u64) -> bool {
        self.pending
            .lock()
            .get(&mid)
            .is_some_and(|p| p.async_id.is_some())
    }

    /// Send an ECHO (no session) and wait for its response.
    pub async fn echo(self: &Arc<Self>) -> Result<()> {
        let mut h = Header::request(Command::ECHO);
        h.credit_charge = u16::from(self.multi_credit());
        let m = encode_message(&h, &EchoRequest)?;
        let mut r = self.send(vec![m], &Security::none()).await?;
        let raw = r.pop().expect("one response").recv().await?;
        let _: EchoResponse = raw.into_result()?;
        Ok(())
    }
}

/// The pending response to one request message.
pub(crate) struct Response {
    shared: Arc<Shared>,
    rx: Option<oneshot::Receiver<Result<Delivered>>>,
    mid: u64,
    session: Option<Arc<SessionCrypto>>,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response").field("mid", &self.mid).finish()
    }
}

impl Response {
    /// Wait for the response and verify its signature.
    ///
    /// Error statuses are returned as `Ok` (callers map them with the path
    /// they know); `Err` means the request failed at the connection level.
    pub async fn recv(mut self) -> Result<RawMessage> {
        // `rx` stays in `self` while waiting, so dropping this future runs
        // `Drop`, which abandons (and if needed CANCELs) the request.
        let timeout = self.shared.request_timeout;
        let shared = self.shared.clone();
        let mid = self.mid;
        let rx = self.rx.as_mut().expect("recv called once");
        let res = match timeout {
            None => rx.await,
            Some(limit) => loop {
                match tokio::time::timeout(limit, &mut *rx).await {
                    Ok(r) => break r,
                    // An async (STATUS_PENDING) operation may legitimately
                    // take longer; wait without a limit.
                    Err(_) if shared.went_async(mid) => break rx.await,
                    Err(_) => {
                        let msg = format!("no SMB response from {} within {limit:?}", shared.peer);
                        shared.fail(&msg);
                        self.rx = None;
                        return Err(Error::timeout(msg));
                    }
                }
            },
        };
        self.rx = None;
        let delivered = match res {
            Ok(r) => r?,
            Err(_) => return Err(self.shared.dead_error()),
        };
        if !delivered.encrypted {
            self.verify(&delivered.msg)?;
        }
        Ok(delivered.msg)
    }

    /// [MS-SMB2] §3.2.5.1.3: verify signed responses; on a signing session
    /// reject unsigned ones (except session-expiry errors, which servers send
    /// unsigned and which only lead to a reconnect).
    fn verify(&self, m: &RawMessage) -> Result<()> {
        let Some(s) = &self.session else {
            return Ok(());
        };
        let h = m.header();
        if h.session_id == 0 {
            return Ok(());
        }
        if h.is_signed() {
            if let Some(signer) = &s.signer
                && let Err(e) = signer.verify(m.bytes())
            {
                self.shared
                    .fail(&format!("bad signature on {:?} response: {e}", h.command));
                return Err(Error::protocol(format!(
                    "SMB {:?} response signature verification failed",
                    h.command
                ))
                .with_retryable(false));
            }
            return Ok(());
        }
        if s.signing
            && !matches!(
                h.status,
                NtStatus::USER_SESSION_DELETED | NtStatus::NETWORK_SESSION_EXPIRED
            )
        {
            self.shared.fail(&format!(
                "unsigned {:?} response on a signing session",
                h.command
            ));
            return Err(Error::protocol(format!(
                "unsigned SMB {:?} response on a session that requires signing",
                h.command
            ))
            .with_retryable(false));
        }
        Ok(())
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        if self.rx.is_some() {
            self.shared.abandon(self.mid, self.session.as_ref());
        }
    }
}

/// Wait for all responses of a frame, in order. A connection-level failure
/// of any of them is returned as the error.
pub(crate) async fn recv_all(responses: Vec<Response>) -> Result<Vec<RawMessage>> {
    let results = futures::future::join_all(responses.into_iter().map(Response::recv)).await;
    results.into_iter().collect()
}

async fn reader_loop(shared: Arc<Shared>, mut rd: OwnedReadHalf) {
    let mut shutdown = shared.shutdown.subscribe();
    let mut buf = BytesMut::with_capacity(READ_BUF);
    let mut dec = FrameDecoder::new();
    let why = loop {
        match dec.decode(&mut buf) {
            Ok(Some(frame)) => {
                shared.on_frame(frame);
                if shared.is_dead() {
                    return;
                }
                continue;
            }
            Ok(None) => {}
            Err(e) => break format!("bad transport frame: {e}"),
        }
        // `decode` reserved room for a partially received frame; make sure a
        // header-sized read always has space too.
        let need = dec.bytes_needed(&buf);
        if buf.capacity() - buf.len() < need.max(4096) {
            buf.reserve(need.max(READ_BUF));
        }
        tokio::select! {
            r = rd.read_buf(&mut buf) => match r {
                Ok(0) => break "server closed the connection".to_owned(),
                Ok(_) => {}
                Err(e) => break format!("read failed: {e}"),
            },
            _ = shutdown.changed() => return,
        }
    };
    shared.fail(&why);
}

async fn writer_loop(
    shared: Arc<Shared>,
    mut wr: OwnedWriteHalf,
    mut rx: mpsc::UnboundedReceiver<OutgoingFrame>,
) {
    let mut shutdown = shared.shutdown.subscribe();
    let mut queue: VecDeque<OutgoingFrame> = VecDeque::new();
    loop {
        tokio::select! {
            f = rx.recv() => match f {
                Some(f) => queue.push_back(f),
                None => break,
            },
            _ = shutdown.changed() => break,
        }
        while queue.len() < WRITE_BATCH {
            match rx.try_recv() {
                Ok(f) => queue.push_back(f),
                Err(_) => break,
            }
        }
        if let Err(e) = write_frames(&mut wr, &mut queue).await {
            shared.fail(&format!("write failed: {e}"));
            break;
        }
    }
    let _ = wr.shutdown().await;
}

/// Write every queued frame with vectored writes.
async fn write_frames(
    wr: &mut OwnedWriteHalf,
    queue: &mut VecDeque<OutgoingFrame>,
) -> std::io::Result<()> {
    while !queue.is_empty() {
        let written = {
            let mut slices = [IoSlice::new(&[]); WRITE_BATCH];
            let mut n = 0;
            for f in queue.iter() {
                n += f.chunks_vectored(&mut slices[n..]);
                if n == slices.len() {
                    break;
                }
            }
            wr.write_vectored(&slices[..n]).await?
        };
        if written == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        let mut left = written;
        while left > 0 {
            let front = queue.front_mut().expect("written bytes belong to queued frames");
            let r = front.remaining();
            if left >= r {
                left -= r;
                queue.pop_front();
            } else {
                front.advance(left);
                left = 0;
            }
        }
    }
    Ok(())
}

/// Probe a silent connection with ECHO; an unanswered probe kills it.
async fn keepalive_loop(shared: std::sync::Weak<Shared>, every: Duration) {
    let tick = (every / 2).max(Duration::from_millis(100));
    loop {
        tokio::time::sleep(tick).await;
        let Some(s) = shared.upgrade() else { return };
        if s.is_dead() {
            return;
        }
        if s.since_rx() < every {
            continue;
        }
        match tokio::time::timeout(every, s.echo()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                s.fail(&format!("keepalive ECHO failed: {e}"));
                return;
            }
            Err(_) => {
                s.fail("keepalive ECHO unanswered");
                return;
            }
        }
    }
}
