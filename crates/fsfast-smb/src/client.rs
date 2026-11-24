//! Connection/session/tree pool and the per-operation context.
//!
//! A [`Client`] owns `connections` slots. Each slot lazily holds one live
//! connection with one authenticated session ([`Live`]); trees are connected
//! lazily per share and shared by every caller. Concurrent operations share
//! connections (requests are multiplexed by MessageId), and a slot whose
//! connection died is re-established on next use, with fsspec's
//! `register_session_retries` policy.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use fsfast_core::{Detail, Error, ErrorKind, Result};
use fsfast_engine::stats::Stats;
use fsfast_smb_proto::compound::CompoundBuilder;
use fsfast_smb_proto::msg::{EncodedMessage, Message, RawMessage};
use fsfast_smb_proto::{Dialect, NtStatus};
use parking_lot::{Mutex, RwLock};
use tokio::net::TcpStream;
use tokio::sync::OnceCell;

use crate::config::SmbConfig;
use crate::conn::{Connection, Security, SessionCrypto, recv_all, was_not_sent};
use crate::session::{self, Tree, header_for};

/// A connected, authenticated connection.
pub(crate) struct Live {
    pub conn: Connection,
    pub crypto: Arc<SessionCrypto>,
    trees: Mutex<HashMap<String, Arc<OnceCell<Arc<Tree>>>>>,
    vni: OnceCell<()>,
}

impl std::fmt::Debug for Live {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Live")
            .field("conn", &self.conn)
            .field("session", &self.crypto)
            .finish_non_exhaustive()
    }
}

impl Live {
    /// The tree for `share`, connecting it on first use.
    pub async fn tree(&self, cfg: &SmbConfig, share: &str) -> Result<Arc<Tree>> {
        let cell = self
            .trees
            .lock()
            .entry(share.to_ascii_lowercase())
            .or_default()
            .clone();
        let tree = cell
            .get_or_try_init(|| async {
                session::tree_connect(&self.conn, &self.crypto, cfg, share)
                    .await
                    .map(Arc::new)
            })
            .await?
            .clone();
        // FSCTL_VALIDATE_NEGOTIATE_INFO once per connection on 3.0/3.0.2.
        let d = self.conn.neg().dialect;
        if (d == Dialect::SMB_3_0 || d == Dialect::SMB_3_0_2) && self.crypto.signer.is_some() {
            self.vni
                .get_or_try_init(|| session::validate_negotiate(&self.conn, &self.crypto, &tree))
                .await?;
        }
        Ok(tree)
    }

    /// Forget the tree of `share` (the server disconnected it).
    pub fn drop_tree(&self, share: &str) {
        self.trees.lock().remove(&share.to_ascii_lowercase());
    }
}

/// One connection slot.
#[derive(Default)]
struct Slot {
    current: RwLock<Option<Arc<Live>>>,
    connecting: tokio::sync::Mutex<()>,
}

impl Slot {
    fn live(&self) -> Option<Arc<Live>> {
        self.current
            .read()
            .as_ref()
            .filter(|l| !l.conn.is_dead())
            .cloned()
    }
}

/// The connection pool of one filesystem instance.
pub(crate) struct Client {
    pub cfg: Arc<SmbConfig>,
    slots: Vec<Slot>,
    pub stats: Arc<Stats>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("host", &self.cfg.host)
            .field("port", &self.cfg.port())
            .field("connections", &self.slots.len())
            .finish()
    }
}

/// Everything an operation needs: a live session and a connected tree.
#[derive(Clone, Debug)]
pub(crate) struct Ctx {
    pub live: Arc<Live>,
    pub tree: Arc<Tree>,
}

impl Ctx {
    /// How requests on this tree are protected.
    pub fn sec(&self) -> Security {
        Security {
            session: Some(self.live.crypto.clone()),
            encrypt: self.tree.encrypt,
            force_sign: false,
        }
    }

    /// A new compound chain on this tree.
    pub fn chain(&self) -> Chain {
        Chain {
            b: CompoundBuilder::new(),
            session_id: self.live.crypto.session_id,
            tree_id: self.tree.tree_id,
            multi_credit: self.live.conn.shared.multi_credit(),
        }
    }

    /// Send a chain and wait for every response.
    pub async fn exec(&self, chain: Chain) -> Result<Vec<RawMessage>> {
        let msgs = chain.into_messages();
        let r = self.live.conn.shared.send(msgs, &self.sec()).await?;
        recv_all(r).await
    }

    /// Negotiated `MaxReadSize`.
    pub fn max_read(&self) -> usize {
        self.live.conn.neg().max_read_size as usize
    }

    /// Negotiated `MaxWriteSize`.
    pub fn max_write(&self) -> usize {
        self.live.conn.neg().max_write_size as usize
    }

    /// Negotiated `MaxTransactSize`.
    pub fn max_transact(&self) -> usize {
        self.live.conn.neg().max_transact_size as usize
    }

    /// Whether multi-credit (large MTU) requests are possible.
    pub fn multi_credit(&self) -> bool {
        self.live.conn.shared.multi_credit()
    }

    /// Largest payload one request may move given the current credit window.
    pub fn credit_limited(&self, want: usize) -> usize {
        if !self.multi_credit() {
            return want.min(65536);
        }
        let cap = usize::from(self.live.conn.shared.credits.max_charge()) * 65536;
        want.min(cap).max(1)
    }
}

/// A compound request under construction: the first message is unrelated,
/// later ones are related to it (`FileId::RELATED`).
pub(crate) struct Chain {
    b: CompoundBuilder,
    session_id: u64,
    tree_id: u32,
    multi_credit: bool,
}

impl Chain {
    /// Append a request (related to the previous one unless it is the first).
    pub fn push<M: Message>(&mut self, body: &M) -> Result<&mut Self> {
        let h = header_for(body, self.session_id, self.tree_id, self.multi_credit);
        if self.b.is_empty() {
            self.b.push(h, body)?;
        } else {
            self.b.push_related(h, body)?;
        }
        Ok(self)
    }

    /// The finished chain (padded, `NextCommand` set), ready to send.
    pub fn into_messages(self) -> Vec<EncodedMessage> {
        self.b.finish()
    }
}

/// NTSTATUS attached to an error.
pub(crate) fn status_of(e: &Error) -> Option<NtStatus> {
    e.details().iter().find_map(|d| match d {
        Detail::NtStatus(s) => Some(NtStatus(*s)),
        _ => None,
    })
}

impl Client {
    /// A pool for `cfg` (nothing connects until first use).
    pub fn new(cfg: SmbConfig) -> Client {
        let n = cfg.connections.max(1);
        Client {
            cfg: Arc::new(cfg),
            slots: (0..n).map(|_| Slot::default()).collect(),
            stats: Arc::new(Stats::new()),
        }
    }

    /// Establish (or reuse) the connection of the first slot.
    pub async fn connect(&self) -> Result<()> {
        self.live_in(&self.slots[0]).await.map(|_| ())
    }

    /// A live connection: the least busy established one, or a new one when
    /// every established connection is busy and a slot is free.
    pub async fn live(&self) -> Result<Arc<Live>> {
        let mut best: Option<(usize, Arc<Live>)> = None;
        let mut idle_slot = None;
        for (i, s) in self.slots.iter().enumerate() {
            match s.live() {
                Some(l) => {
                    let load = l.conn.in_flight();
                    if best.as_ref().is_none_or(|(b, _)| load < *b) {
                        best = Some((load, l));
                    }
                }
                None if idle_slot.is_none() => idle_slot = Some(i),
                None => {}
            }
        }
        match (best, idle_slot) {
            (Some((0, l)), _) | (Some((_, l)), None) => Ok(l),
            (_, Some(i)) => self.live_in(&self.slots[i]).await,
            (None, None) => unreachable!("at least one slot"),
        }
    }

    async fn live_in(&self, slot: &Slot) -> Result<Arc<Live>> {
        if let Some(l) = slot.live() {
            return Ok(l);
        }
        let _guard = slot.connecting.lock().await;
        if let Some(l) = slot.live() {
            return Ok(l);
        }
        let live = Arc::new(self.establish_with_retries().await?);
        *slot.current.write() = Some(live.clone());
        Ok(live)
    }

    /// fsspec's `_connect` loop: `register_session_retries` extra attempts
    /// with exponentially growing waits; authentication failures and invalid
    /// configurations fail at once.
    async fn establish_with_retries(&self) -> Result<Live> {
        let retries = self.cfg.register_session_retries.max(0) as u32;
        let mut attempt = 0u32;
        loop {
            match self.establish().await {
                Ok(l) => return Ok(l),
                Err(e) => {
                    let fatal = matches!(
                        e.kind(),
                        ErrorKind::PermissionDenied
                            | ErrorKind::InvalidInput
                            | ErrorKind::Unsupported
                            | ErrorKind::NotFound
                    ) || (e.kind() == ErrorKind::Protocol && !e.is_retryable());
                    if fatal || attempt >= retries {
                        return Err(e);
                    }
                    let wait = self.cfg.retry_wait(attempt);
                    tracing::debug!(host = %self.cfg.host, attempt, ?wait, error = %e, "SMB connection attempt failed; retrying");
                    self.stats.add_retry();
                    attempt += 1;
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }

    /// One connection attempt: TCP connect, NEGOTIATE, SESSION_SETUP, all
    /// within `timeout`.
    async fn establish(&self) -> Result<Live> {
        let cfg = &self.cfg;
        let addr = (cfg.connect_host().to_owned(), cfg.port());
        let peer = format!("{}:{}", cfg.host, cfg.port());
        let fut = async {
            let stream = TcpStream::connect(addr).await.map_err(|e| {
                Error::from(e).with_kind(ErrorKind::ConnectionFailed).with_path(peer.clone())
            })?;
            let conn = Connection::start(
                stream,
                peer.clone(),
                cfg.max_credits,
                cfg.request_timeout,
                cfg.keepalive_interval,
            );
            let (neg, preauth) = session::negotiate(&conn, cfg).await?;
            conn.set_negotiated(neg.clone());
            let crypto = session::session_setup(&conn, cfg, &neg, &preauth).await?;
            conn.set_crypto(Some(crypto.clone()));
            Ok::<_, Error>(Live {
                conn,
                crypto,
                trees: Mutex::new(HashMap::new()),
                vni: OnceCell::new(),
            })
        };
        match tokio::time::timeout(cfg.timeout, fut).await {
            Ok(r) => r,
            Err(_) => Err(Error::timeout(format!(
                "SMB connection to {peer} timed out after {:?}",
                cfg.timeout
            ))),
        }
    }

    /// An operation context for `share`.
    pub async fn ctx(&self, share: &str) -> Result<Ctx> {
        let live = self.live().await?;
        let tree = live.tree(&self.cfg, share).await?;
        Ok(Ctx { live, tree })
    }

    /// Two contexts on the same session (server-side copy across shares).
    pub async fn ctx_pair(&self, a: &str, b: &str) -> Result<(Ctx, Ctx)> {
        let live = self.live().await?;
        let ta = live.tree(&self.cfg, a).await?;
        let tb = live.tree(&self.cfg, b).await?;
        Ok((
            Ctx {
                live: live.clone(),
                tree: ta,
            },
            Ctx { live, tree: tb },
        ))
    }

    /// Run `f` with a context for `share`, retrying when the attempt failed
    /// without side effects: the request never went out, the server dropped
    /// the tree or session (the request was refused before it ran), or —
    /// for `idempotent` operations only — the connection was lost while the
    /// request was in flight.
    pub async fn run<T, F, Fut>(&self, share: &str, idempotent: bool, f: F) -> Result<T>
    where
        F: Fn(Ctx) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        const ATTEMPTS: u32 = 3;
        let mut attempt = 1;
        loop {
            let ctx = self.ctx(share).await?;
            let live = ctx.live.clone();
            let err = match f(ctx).await {
                Ok(v) => return Ok(v),
                Err(e) => e,
            };
            let status = status_of(&err);
            let tree_gone = status == Some(NtStatus::NETWORK_NAME_DELETED);
            let session_gone = matches!(
                status,
                Some(NtStatus::USER_SESSION_DELETED | NtStatus::NETWORK_SESSION_EXPIRED)
            );
            if tree_gone {
                live.drop_tree(share);
            }
            if session_gone {
                live.conn.kill("session expired");
            }
            let retry = was_not_sent(&err)
                || tree_gone
                || session_gone
                || (idempotent && err.kind() == ErrorKind::ConnectionFailed);
            if !retry || attempt >= ATTEMPTS {
                return Err(err);
            }
            tracing::debug!(share, attempt, error = %err, "retrying SMB operation");
            self.stats.add_retry();
            attempt += 1;
        }
    }

    /// Disconnect everything (TREE_DISCONNECT, LOGOFF, close the sockets).
    /// The pool reconnects on next use.
    pub async fn close(&self) {
        for s in &self.slots {
            let _guard = s.connecting.lock().await;
            let Some(live) = s.current.write().take() else {
                continue;
            };
            if live.conn.is_dead() {
                continue;
            }
            let trees: Vec<Arc<Tree>> = live
                .trees
                .lock()
                .drain()
                .filter_map(|(_, c)| c.get().cloned())
                .collect();
            for t in &trees {
                session::tree_disconnect(&live.conn, &live.crypto, t).await;
            }
            session::logoff(&live.conn, &live.crypto).await;
            live.conn.kill("closed by the client");
        }
    }
}
