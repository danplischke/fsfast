//! A pool of SFTP sessions, one per SSH connection.
//!
//! Each SSH connection carries one SFTP channel, so every session has its
//! own server process and its own encryption pipeline on both ends (russh
//! runs one task per connection): parallel transfers of many files then use
//! several cores instead of sharing one.
//!
//! The pool starts with one connection and grows on demand: when an
//! operation starts while every session is already busy, an extra
//! connection is opened *in the background* (up to `connections`) and the
//! operation proceeds on the least-loaded existing session, so nobody waits
//! for a handshake except the very first operation. Dead sessions are
//! dropped and replaced lazily.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use fsfast_core::{Error, Result};
use fsfast_engine::retry::{RetryPolicy, retry};

use crate::options::SftpConfig;
use crate::session::{Extensions, Session, SessionOptions};
use crate::ssh::connect::{SshConnection, Target};

/// Wait this long after a failed background connection before trying to
/// grow the pool again.
const GROW_BACKOFF: Duration = Duration::from_secs(5);

/// Capability bits learned from connected servers.
const CAP_KNOWN: u8 = 1;
const CAP_POSIX_RENAME: u8 = 2;
const CAP_COPY_DATA: u8 = 4;
const CAP_FSYNC: u8 = 8;

/// A session in use. Dropping it releases the session's load count.
#[derive(Debug)]
pub struct Lease {
    session: Session,
}

impl Lease {
    pub(crate) fn new(session: Session) -> Self {
        session.acquire();
        Lease { session }
    }
}

impl std::ops::Deref for Lease {
    type Target = Session;
    fn deref(&self) -> &Session {
        &self.session
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.session.release();
    }
}

struct PoolInner {
    cfg: Arc<SftpConfig>,
    target: tokio::sync::OnceCell<Arc<Target>>,
    sessions: Mutex<Vec<Session>>,
    connect_lock: tokio::sync::Mutex<()>,
    growing: AtomicBool,
    last_grow_failure: Mutex<Option<Instant>>,
    caps: AtomicU8,
    seq: AtomicU64,
    /// Incremented (under the `sessions` lock) by every `close`, so a
    /// background grow that finishes its handshake after a close drops its
    /// connection instead of putting it back into the closed pool.
    epoch: AtomicU64,
}

/// The session pool of one filesystem.
#[derive(Clone)]
pub struct Pool {
    inner: Arc<PoolInner>,
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("host", &self.inner.cfg.host)
            .field("sessions", &self.inner.sessions.lock().len())
            .finish()
    }
}

impl Pool {
    /// A pool for `cfg`; nothing connects until the first [`Pool::get`].
    pub fn new(cfg: Arc<SftpConfig>) -> Self {
        Pool {
            inner: Arc::new(PoolInner {
                cfg,
                target: tokio::sync::OnceCell::new(),
                sessions: Mutex::new(Vec::new()),
                connect_lock: tokio::sync::Mutex::new(()),
                growing: AtomicBool::new(false),
                last_grow_failure: Mutex::new(None),
                caps: AtomicU8::new(0),
                seq: AtomicU64::new(0),
                epoch: AtomicU64::new(0),
            }),
        }
    }

    /// The configuration.
    pub fn config(&self) -> &SftpConfig {
        &self.inner.cfg
    }

    /// Extensions of the connected server, or `None` before the first
    /// connection.
    pub fn known_extensions(&self) -> Option<(bool, bool, bool)> {
        let c = self.inner.caps.load(Ordering::Relaxed);
        (c & CAP_KNOWN != 0).then_some((
            c & CAP_POSIX_RENAME != 0,
            c & CAP_COPY_DATA != 0,
            c & CAP_FSYNC != 0,
        ))
    }

    /// Number of live sessions.
    pub fn size(&self) -> usize {
        let mut s = self.inner.sessions.lock();
        s.retain(|s| !s.is_closed());
        s.len()
    }

    /// A session for one operation (or one open handle).
    pub async fn get(&self) -> Result<Lease> {
        loop {
            let (best, live) = {
                let mut s = self.inner.sessions.lock();
                s.retain(|s| !s.is_closed());
                let best = s.iter().min_by_key(|s| s.active()).cloned();
                (best, s.len())
            };
            if let Some(best) = best {
                if best.active() > 0 && live < self.inner.cfg.connections {
                    self.grow_in_background();
                }
                return Ok(Lease::new(best));
            }
            // No session: connect in the foreground; concurrent callers wait
            // for the same attempt.
            let _g = self.inner.connect_lock.lock().await;
            if self.inner.sessions.lock().iter().any(|s| !s.is_closed()) {
                continue;
            }
            let policy = RetryPolicy::default()
                .with_max_attempts(3)
                .with_base_delay(Duration::from_millis(100))
                .with_max_delay(Duration::from_secs(1));
            let s = retry(&policy, || self.inner.connect()).await?;
            self.inner.sessions.lock().push(s.clone());
            return Ok(Lease::new(s));
        }
    }

    fn grow_in_background(&self) {
        if let Some(t) = *self.inner.last_grow_failure.lock()
            && t.elapsed() < GROW_BACKOFF
        {
            return;
        }
        if self.inner.growing.swap(true, Ordering::AcqRel) {
            return;
        }
        let inner = self.inner.clone();
        // Taken before anything awaits: a close() after this point (even
        // before the task runs) cancels the grow.
        let epoch = inner.epoch.load(Ordering::Acquire);
        tokio::spawn(async move {
            {
                let _g = inner.connect_lock.lock().await;
                let live = {
                    let mut s = inner.sessions.lock();
                    s.retain(|s| !s.is_closed());
                    s.len()
                };
                if live < inner.cfg.connections && inner.epoch.load(Ordering::Acquire) == epoch {
                    match inner.connect().await {
                        Ok(s) => {
                            let mut v = inner.sessions.lock();
                            if inner.epoch.load(Ordering::Acquire) == epoch {
                                v.push(s);
                            } else {
                                // The pool was closed during the handshake.
                                drop(v);
                                drop(s);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("sftp: opening an extra connection failed: {e}");
                            *inner.last_grow_failure.lock() = Some(Instant::now());
                        }
                    }
                }
            }
            inner.growing.store(false, Ordering::Release);
        });
    }

    /// Close every session (the pool reconnects on the next `get`).
    pub async fn close(&self) {
        let sessions: Vec<Session> = {
            let mut v = self.inner.sessions.lock();
            self.inner.epoch.fetch_add(1, Ordering::AcqRel);
            std::mem::take(&mut *v)
        };
        drop(sessions);
    }
}

impl PoolInner {
    async fn target(&self) -> Result<Arc<Target>> {
        self.target
            .get_or_try_init(|| async {
                // ssh_config and the passwd file are read from disk: keep that
                // off the async workers.
                let cfg = self.cfg.clone();
                tokio::task::spawn_blocking(move || Target::resolve(&cfg).map(Arc::new))
                    .await
                    .map_err(|e| Error::new(fsfast_core::ErrorKind::Other, e.to_string()))?
            })
            .await
            .cloned()
    }

    async fn connect(&self) -> Result<Session> {
        let t = self.target().await?;
        let conn = Arc::new(SshConnection::connect(&t).await?);
        let (rx, tx) = conn.open_sftp_channel(t.channel_timeout).await?;
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let label = format!("{}#{n}", conn.describe());
        let keep: Arc<dyn Send + Sync> = conn.clone();
        let mut s = Session::start(
            tx,
            rx,
            SessionOptions {
                read_chunk: self.cfg.read_chunk_size,
                write_chunk: self.cfg.write_chunk_size,
                request_timeout: self.cfg.request_timeout,
                handshake_timeout: Some(t.channel_timeout),
            },
            label,
            Some(keep),
        )
        .await?;
        s.set_negotiated(conn.negotiated());
        let e: Extensions = s.extensions();
        let mut caps = CAP_KNOWN;
        if e.posix_rename {
            caps |= CAP_POSIX_RENAME;
        }
        if e.copy_data {
            caps |= CAP_COPY_DATA;
        }
        if e.fsync {
            caps |= CAP_FSYNC;
        }
        self.caps.store(caps, Ordering::Relaxed);
        Ok(s)
    }
}
