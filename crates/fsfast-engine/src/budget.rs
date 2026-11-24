//! Byte-granular memory budget shared by prefetch, cache fills and uploads.
//!
//! A [`MemoryBudget`] is an async byte semaphore. Work that holds memory for
//! a while (readahead chunks, cached blocks, multipart parts in flight)
//! acquires a [`BudgetGuard`] for the bytes it holds; dropping the guard
//! returns them.
//!
//! Three acquisition flavours cover the engine's needs:
//!
//! * [`MemoryBudget::acquire`] waits (FIFO-fair) — backpressure, e.g. for
//!   multipart uploads.
//! * [`MemoryBudget::try_acquire`] never waits — speculative work such as
//!   prefetch simply does not happen under pressure.
//! * [`MemoryBudget::force_acquire`] never waits and may over-commit — used
//!   so that mandatory work always makes progress. The over-commit is
//!   recorded and repaid before anyone else can acquire again, so accounting
//!   stays exact.
//!
//! Requests larger than the whole budget are clamped to the budget: they run
//! alone instead of deadlocking.
//!
//! A process-wide instance is available through [`MemoryBudget::global`];
//! independent budgets can be created with [`MemoryBudget::new`].
//!
//! ```
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() {
//! use fsfast_engine::MemoryBudget;
//!
//! let budget = MemoryBudget::new(64 << 20);
//! let part = budget.acquire(8 << 20).await; // waits if necessary
//! assert_eq!(budget.available(), 56 << 20);
//! assert!(budget.try_acquire(100 << 20).is_none()); // clamped to 64 MiB: not free now
//! drop(part);
//! assert_eq!(budget.available(), 64 << 20);
//! # }
//! ```

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use fsfast_core::{Error, Result};
use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::elastic::{ElasticSemaphore, MAX_PERMITS};

/// Environment variable that overrides the size of the global budget
/// (bytes, or a size with a binary suffix such as `512MiB` or `4G`).
pub const GLOBAL_BUDGET_ENV: &str = "FSFAST_MEMORY_BUDGET";

/// Upper bound of the default global budget.
pub const DEFAULT_GLOBAL_MAX: usize = 2 << 30;

/// Default global budget when the machine's memory cannot be determined.
const FALLBACK_GLOBAL: usize = 1 << 30;

const CHUNK: usize = u32::MAX as usize;

struct Inner {
    sem: ElasticSemaphore,
    capacity: AtomicUsize,
    /// Signalled on resize so waiters re-clamp their request.
    resized: Notify,
    resize_lock: Mutex<()>,
}

/// An async byte semaphore. Cheap to clone; clones share the same budget.
#[derive(Clone)]
pub struct MemoryBudget {
    inner: Arc<Inner>,
}

impl fmt::Debug for MemoryBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryBudget")
            .field("capacity", &self.capacity())
            .field("available", &self.available())
            .field("in_use", &self.in_use())
            .finish()
    }
}

impl MemoryBudget {
    /// A budget of `bytes` bytes (at least 1).
    pub fn new(bytes: usize) -> Self {
        let cap = bytes.clamp(1, MAX_PERMITS);
        MemoryBudget {
            inner: Arc::new(Inner {
                sem: ElasticSemaphore::new(cap),
                capacity: AtomicUsize::new(cap),
                resized: Notify::new(),
                resize_lock: Mutex::new(()),
            }),
        }
    }

    /// A budget so large it never limits anything (accounting still works).
    pub fn unlimited() -> Self {
        MemoryBudget::new(MAX_PERMITS)
    }

    /// The process-wide default budget.
    ///
    /// Its size is taken from the `FSFAST_MEMORY_BUDGET` environment variable
    /// when set, otherwise `min(2 GiB, RAM / 4)` (RAM honours cgroup limits on
    /// Linux). It can be changed at runtime with [`MemoryBudget::resize`].
    pub fn global() -> &'static MemoryBudget {
        static GLOBAL: OnceLock<MemoryBudget> = OnceLock::new();
        GLOBAL.get_or_init(|| {
            let size = match std::env::var(GLOBAL_BUDGET_ENV) {
                Ok(v) => match parse_size(&v) {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::warn!(value = %v, error = %e, "ignoring invalid {GLOBAL_BUDGET_ENV}");
                        default_global_size()
                    }
                },
                Err(_) => default_global_size(),
            };
            tracing::debug!(bytes = size, "global memory budget initialised");
            MemoryBudget::new(size)
        })
    }

    /// Total size of the budget in bytes.
    pub fn capacity(&self) -> usize {
        self.inner.capacity.load(Ordering::Acquire)
    }

    /// Bytes that can be acquired right now.
    pub fn available(&self) -> usize {
        self.inner.sem.available()
    }

    /// Bytes currently held by guards (may exceed the capacity while
    /// over-committed by [`MemoryBudget::force_acquire`]).
    pub fn in_use(&self) -> usize {
        // Invariant: raw_available + held - debt == capacity.
        (self.capacity() + self.inner.sem.debt()).saturating_sub(self.inner.sem.raw_available())
    }

    /// Whether forced acquisitions currently exceed the capacity.
    pub fn is_overcommitted(&self) -> bool {
        self.inner.sem.debt() > 0
    }

    /// Whether `self` and `other` are the same budget.
    pub fn same_budget(&self, other: &MemoryBudget) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Change the capacity. Shrinking below the bytes currently held takes
    /// effect as guards are released; waiters re-clamp their requests.
    pub fn resize(&self, bytes: usize) {
        let new = bytes.clamp(1, MAX_PERMITS);
        {
            let _l = self.inner.resize_lock.lock();
            let old = self.inner.capacity.load(Ordering::Acquire);
            if new > old {
                self.inner.sem.give(new - old);
            } else if new < old {
                self.inner.sem.take(old - new);
            }
            self.inner.capacity.store(new, Ordering::Release);
        }
        self.inner.resized.notify_waiters();
    }

    fn guard(&self, bytes: usize) -> BudgetGuard {
        BudgetGuard {
            inner: Some(self.inner.clone()),
            bytes,
        }
    }

    /// Wait until `bytes` (clamped to the capacity) are available and take
    /// them. FIFO-fair: a large request at the head of the queue is not
    /// starved by smaller ones. Cancellation-safe.
    ///
    /// A [`resize`](MemoryBudget::resize) only restarts waiters whose clamped
    /// request changes; the others keep their place in the queue and the
    /// bytes already granted to them.
    ///
    /// A request above `u32::MAX` bytes (the most a tokio semaphore grants
    /// at once) waits for its first `u32::MAX` bytes and takes the rest as
    /// over-commit, like [`force_acquire`](MemoryBudget::force_acquire).
    pub async fn acquire(&self, bytes: usize) -> BudgetGuard {
        loop {
            let resized = self.inner.resized.notified();
            tokio::pin!(resized);
            resized.as_mut().enable();
            let want = bytes.min(self.capacity());
            let acquire = self.acquire_exact(want);
            tokio::pin!(acquire);
            loop {
                tokio::select! {
                    biased;
                    g = &mut acquire => return g,
                    () = &mut resized => {
                        // Re-arm before reading the capacity so that no
                        // resize can slip in between.
                        resized.set(self.inner.resized.notified());
                        resized.as_mut().enable();
                        if bytes.min(self.capacity()) != want {
                            // Restart with the new clamp (dropping
                            // `acquire` returns its partial grant).
                            break;
                        }
                    }
                }
            }
        }
    }

    async fn acquire_exact(&self, want: usize) -> BudgetGuard {
        // Tokio takes at most `u32::MAX` permits per acquisition. A larger
        // request waits (in FIFO order) for its first `CHUNK` and then takes
        // the remainder as recorded over-commit, repaid before anyone else
        // acquires. Waiting for further chunks while holding the first would
        // be hold-and-wait: a waiter queued in between could deadlock with
        // it.
        let first = want.min(CHUNK);
        self.inner.sem.acquire(first as u32).await;
        if want > first {
            self.inner.sem.take(want - first);
        }
        self.guard(want)
    }

    /// Take `bytes` (clamped to the capacity) if available right now.
    pub fn try_acquire(&self, bytes: usize) -> Option<BudgetGuard> {
        let want = bytes.min(self.capacity());
        if want <= CHUNK {
            return self
                .inner
                .sem
                .try_acquire(want as u32)
                .then(|| self.guard(want));
        }
        // Never waits, so taking several chunks cannot deadlock; a failure
        // releases the chunks already taken.
        let mut g = self.guard(0);
        while g.bytes < want {
            let c = (want - g.bytes).min(CHUNK);
            if !self.inner.sem.try_acquire(c as u32) {
                return None; // `g` releases the partial grant
            }
            g.bytes += c;
        }
        Some(g)
    }

    /// Take `bytes` immediately, over-committing the budget if necessary.
    ///
    /// Used for mandatory work so it always makes progress. The over-commit
    /// is repaid from the next releases before other acquirers proceed.
    pub fn force_acquire(&self, bytes: usize) -> BudgetGuard {
        self.inner.sem.take(bytes);
        self.guard(bytes)
    }
}

/// Bytes held from a [`MemoryBudget`]; returned when dropped.
#[must_use = "dropping the guard releases the bytes immediately"]
pub struct BudgetGuard {
    inner: Option<Arc<Inner>>,
    bytes: usize,
}

impl BudgetGuard {
    /// A guard holding nothing.
    pub fn empty() -> Self {
        BudgetGuard {
            inner: None,
            bytes: 0,
        }
    }

    /// Bytes held by this guard.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Move `n` bytes (at most [`BudgetGuard::bytes`]) into a new guard.
    pub fn split(&mut self, n: usize) -> BudgetGuard {
        let n = n.min(self.bytes);
        self.bytes -= n;
        BudgetGuard {
            inner: self.inner.clone(),
            bytes: n,
        }
    }
}

impl fmt::Debug for BudgetGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BudgetGuard")
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl Drop for BudgetGuard {
    fn drop(&mut self) {
        if let Some(inner) = &self.inner
            && self.bytes > 0
        {
            inner.sem.give(self.bytes);
        }
    }
}

/// `min(2 GiB, RAM / 4)`, where RAM honours cgroup memory limits on Linux;
/// 1 GiB if the amount of memory cannot be determined.
pub fn default_global_size() -> usize {
    match total_memory() {
        Some(ram) => usize::try_from(ram / 4)
            .unwrap_or(usize::MAX)
            .clamp(64 << 20, DEFAULT_GLOBAL_MAX),
        None => FALLBACK_GLOBAL,
    }
}

/// Physical memory available to this process, if it can be determined.
///
/// Reads `/proc/meminfo` and the cgroup v2/v1 memory limits once (these are
/// in-memory pseudo files; the read happens only when the global budget is
/// first initialised).
fn total_memory() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let mem = std::fs::read_to_string("/proc/meminfo").ok().and_then(|s| {
            s.lines().find_map(|l| {
                let rest = l.strip_prefix("MemTotal:")?;
                let kb: u64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
                Some(kb * 1024)
            })
        });
        let cgroup = [
            "/sys/fs/cgroup/memory.max",
            "/sys/fs/cgroup/memory/memory.limit_in_bytes",
        ]
        .iter()
        .find_map(|p| {
            let v: u64 = std::fs::read_to_string(p).ok()?.trim().parse().ok()?;
            // cgroup v1 reports "unlimited" as a huge page-aligned number.
            (v > 0 && v < (1u64 << 60)).then_some(v)
        });
        match (mem, cgroup) {
            (Some(m), Some(c)) => Some(m.min(c)),
            (m, c) => m.or(c),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Parse a byte size: a plain number of bytes, or a number (fractions
/// allowed) followed by `k`, `m`, `g` or `t` with an optional `b`/`ib`
/// suffix. All suffixes are binary (`1k` = 1024).
pub fn parse_size(s: &str) -> Result<usize> {
    let t = s.trim();
    let err = || Error::invalid_input(format!("invalid size {s:?}"));
    let split = t
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    if num.is_empty() {
        return Err(err());
    }
    let mult: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        "t" | "tb" | "tib" => 1 << 40,
        _ => return Err(err()),
    };
    let bytes = if num.contains('.') {
        let v: f64 = num.parse().map_err(|_| err())?;
        let b = v * mult as f64;
        if !b.is_finite() || b < 0.0 || b > u64::MAX as f64 {
            return Err(err());
        }
        b as u64
    } else {
        let v: u64 = num.parse().map_err(|_| err())?;
        v.checked_mul(mult).ok_or_else(err)?
    };
    usize::try_from(bytes).map_err(|_| err())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn acquire_release_accounting() {
        let b = MemoryBudget::new(100);
        let g1 = b.try_acquire(30).unwrap();
        let g2 = b.try_acquire(70).unwrap();
        assert_eq!(b.available(), 0);
        assert_eq!(b.in_use(), 100);
        assert!(b.try_acquire(1).is_none());
        drop(g1);
        assert_eq!(b.available(), 30);
        drop(g2);
        assert_eq!(b.available(), 100);
        assert_eq!(b.in_use(), 0);
    }

    #[test]
    fn zero_byte_requests_are_free() {
        let b = MemoryBudget::new(10);
        let _all = b.try_acquire(10).unwrap();
        let g = b.try_acquire(0).unwrap();
        assert_eq!(g.bytes(), 0);
        assert_eq!(BudgetGuard::empty().bytes(), 0);
    }

    #[test]
    fn oversized_request_is_clamped_and_runs_alone() {
        let b = MemoryBudget::new(100);
        let g = b.try_acquire(1_000).unwrap();
        assert_eq!(g.bytes(), 100);
        assert!(b.try_acquire(1).is_none());
        drop(g);
        let small = b.try_acquire(1).unwrap();
        // Oversized request cannot proceed while anything else is held.
        assert!(b.try_acquire(1_000).is_none());
        drop(small);
    }

    #[tokio::test(start_paused = true)]
    async fn oversized_acquire_does_not_deadlock() {
        let b = MemoryBudget::new(100);
        let small = b.acquire(40).await;
        let b2 = b.clone();
        let big = tokio::spawn(async move { b2.acquire(10_000).await.bytes() });
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(!big.is_finished());
        drop(small);
        assert_eq!(big.await.unwrap(), 100);
        assert_eq!(b.available(), 100);
    }

    #[test]
    fn force_acquire_overcommits_and_repays() {
        let b = MemoryBudget::new(100);
        let g1 = b.try_acquire(80).unwrap();
        let f = b.force_acquire(50);
        assert!(b.is_overcommitted());
        assert_eq!(b.available(), 0);
        assert_eq!(b.in_use(), 130);
        drop(g1); // pays 30 of debt, 50 become available
        assert!(!b.is_overcommitted());
        assert_eq!(b.available(), 50);
        drop(f);
        assert_eq!(b.available(), 100);
        assert_eq!(b.in_use(), 0);
    }

    #[test]
    fn split_guard() {
        let b = MemoryBudget::new(100);
        let mut g = b.try_acquire(60).unwrap();
        let h = g.split(25);
        assert_eq!((g.bytes(), h.bytes()), (35, 25));
        drop(h);
        assert_eq!(b.available(), 65);
        let too_much = g.split(1_000);
        assert_eq!(too_much.bytes(), 35);
        assert_eq!(g.bytes(), 0);
        drop((g, too_much));
        assert_eq!(b.available(), 100);
    }

    #[tokio::test(start_paused = true)]
    async fn fifo_waiters_and_cancellation_do_not_leak() {
        let b = MemoryBudget::new(10);
        let all = b.acquire(10).await;
        let b1 = b.clone();
        let w1 = tokio::spawn(async move { b1.acquire(6).await });
        let b2 = b.clone();
        let w2 = tokio::spawn(async move { b2.acquire(6).await });
        tokio::time::sleep(Duration::from_millis(1)).await;
        // Cancel the first waiter while it is queued.
        w1.abort();
        let _ = w1.await;
        drop(all);
        let g2 = w2.await.unwrap();
        assert_eq!(g2.bytes(), 6);
        assert_eq!(b.available(), 4);
        drop(g2);
        assert_eq!(b.available(), 10);
    }

    #[tokio::test(start_paused = true)]
    async fn resize_reclamps_waiters() {
        let b = MemoryBudget::new(100);
        let held = b.acquire(10).await;
        let b2 = b.clone();
        let waiter = tokio::spawn(async move { b2.acquire(100).await.bytes() });
        tokio::time::sleep(Duration::from_millis(1)).await;
        // Shrinking below the waiter's (clamped) request must not strand it.
        b.resize(50);
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(!waiter.is_finished());
        drop(held);
        assert_eq!(waiter.await.unwrap(), 50);
        assert_eq!(b.available(), 50);
        b.resize(200);
        assert_eq!(b.capacity(), 200);
        assert_eq!(b.available(), 200);
    }

    /// A resize that leaves a waiter's (clamped) request unchanged must not
    /// cost it its place in the queue or its partial grant.
    #[tokio::test(start_paused = true)]
    async fn resize_keeps_fifo_order_of_unaffected_waiters() {
        use std::sync::Arc;

        let b = MemoryBudget::new(100);
        let held = b.acquire(60).await;
        let order = Arc::new(Mutex::new(Vec::new()));
        let (b2, o) = (b.clone(), order.clone());
        let big = tokio::spawn(async move {
            let g = b2.acquire(100).await;
            o.lock().push("big");
            tokio::time::sleep(Duration::from_millis(5)).await;
            drop(g);
        });
        tokio::time::sleep(Duration::from_millis(1)).await;
        let (b3, o) = (b.clone(), order.clone());
        let small = tokio::spawn(async move {
            let g = b3.acquire(10).await;
            o.lock().push("small");
            drop(g);
        });
        tokio::time::sleep(Duration::from_millis(1)).await;
        // Repeated capacity changes that never drop below either request.
        for _ in 0..5 {
            b.resize(150);
            tokio::time::sleep(Duration::from_millis(1)).await;
            b.resize(100);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert!(
            order.lock().is_empty(),
            "{:?} overtook the head",
            order.lock()
        );
        drop(held);
        big.await.unwrap();
        small.await.unwrap();
        assert_eq!(*order.lock(), vec!["big", "small"]);
        assert_eq!(b.available(), 100);
        assert!(!b.is_overcommitted());
    }

    /// Regression (found by `concurrent_ops_never_deadlock_or_leak`): a
    /// cancelled waiter's partial grant returns to the semaphore while debt
    /// is outstanding; waiters that repay debt from their grant must not
    /// keep the rest while queueing again (hold-and-wait), or the new head
    /// of the queue can wait forever for permits they hold.
    #[tokio::test(start_paused = true)]
    async fn debt_repayment_by_waiters_does_not_deadlock() {
        let b = MemoryBudget::new(129);
        let g = b.try_acquire(1).unwrap();
        let t0 = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            drop(g);
        });
        let b1 = b.clone();
        let a = tokio::spawn(async move { b1.acquire(130).await.bytes() });
        tokio::time::sleep(Duration::from_millis(1)).await;
        let f = b.force_acquire(25);
        let tf = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            drop(f);
        });
        let b2 = b.clone();
        let w2 = tokio::spawn(async move { b2.acquire(13).await.bytes() });
        let b3 = b.clone();
        let w3 = tokio::spawn(async move { b3.acquire(141).await.bytes() });
        b.resize(26);
        let all = async {
            t0.await.unwrap();
            tf.await.unwrap();
            (a.await.unwrap(), w2.await.unwrap(), w3.await.unwrap())
        };
        let got = tokio::time::timeout(Duration::from_secs(60), all)
            .await
            .expect("waiters deadlocked");
        assert_eq!(got, (26, 13, 26));
        assert_eq!(b.available(), 26);
        assert!(!b.is_overcommitted());
    }

    /// Requests above `u32::MAX` bytes cannot be taken from tokio in one
    /// step; holding the first chunk while queueing for the next must not
    /// deadlock against a waiter that queued in between.
    #[tokio::test(start_paused = true)]
    async fn huge_acquire_does_not_deadlock_with_interleaved_waiter() {
        const GIB: usize = 1 << 30;
        let b = MemoryBudget::new(6 * GIB);
        let h = b.try_acquire(3 * GIB).unwrap();
        let b1 = b.clone();
        let big = tokio::spawn(async move {
            let g = b1.acquire(6 * GIB).await;
            tokio::time::sleep(Duration::from_millis(1)).await;
            g.bytes()
        });
        tokio::time::sleep(Duration::from_millis(1)).await;
        let b2 = b.clone();
        let other = tokio::spawn(async move { b2.acquire(3 * GIB).await.bytes() });
        tokio::time::sleep(Duration::from_millis(1)).await;
        drop(h);
        let both = async { (big.await.unwrap(), other.await.unwrap()) };
        let got = tokio::time::timeout(Duration::from_secs(60), both)
            .await
            .expect("huge acquisition deadlocked");
        assert_eq!(got, (6 * GIB, 3 * GIB));
        assert_eq!(b.available(), 6 * GIB);
        assert!(!b.is_overcommitted());
    }

    #[test]
    fn shrink_while_held_takes_effect_on_release() {
        let b = MemoryBudget::new(100);
        let g = b.try_acquire(90).unwrap();
        b.resize(20);
        assert_eq!(b.available(), 0);
        drop(g);
        assert_eq!(b.available(), 20);
        assert_eq!(b.capacity(), 20);
    }

    #[test]
    fn global_budget_is_sane() {
        let g = MemoryBudget::global();
        assert!(g.capacity() >= 1);
        assert!(MemoryBudget::global().same_budget(g));
        let d = default_global_size();
        assert!((64 << 20..=DEFAULT_GLOBAL_MAX).contains(&d));
    }

    #[test]
    fn parse_sizes() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("64k").unwrap(), 64 << 10);
        assert_eq!(parse_size("512MiB").unwrap(), 512 << 20);
        assert_eq!(parse_size(" 2G ").unwrap(), 2 << 30);
        assert_eq!(parse_size("1.5g").unwrap(), 3 << 29);
        assert_eq!(parse_size("1tb").unwrap(), 1 << 40);
        for bad in ["", "abc", "12x", "-5", "1.2.3m", "99999999999999999999t"] {
            assert!(parse_size(bad).is_err(), "{bad}");
        }
    }

    #[derive(Debug, Clone)]
    enum BudgetOp {
        /// Spawn a task that waits for `bytes` (possibly more than the
        /// capacity), holds them for `hold` ms, then releases them.
        Acquire {
            bytes: usize,
            hold: u64,
        },
        /// Like `Acquire`, but the task is aborted after `after` ms.
        AcquireAbort {
            bytes: usize,
            hold: u64,
            after: u64,
        },
        Try {
            bytes: usize,
            hold: u64,
        },
        Force {
            bytes: usize,
            hold: u64,
        },
        Resize(usize),
        Sleep(u64),
    }

    fn budget_op() -> impl proptest::strategy::Strategy<Value = BudgetOp> {
        use proptest::prelude::*;
        prop_oneof![
            4 => (0usize..250, 0u64..20).prop_map(|(bytes, hold)| BudgetOp::Acquire { bytes, hold }),
            2 => (0usize..250, 0u64..20, 0u64..20)
                .prop_map(|(bytes, hold, after)| BudgetOp::AcquireAbort { bytes, hold, after }),
            2 => (0usize..150, 0u64..20).prop_map(|(bytes, hold)| BudgetOp::Try { bytes, hold }),
            1 => (0usize..150, 0u64..20).prop_map(|(bytes, hold)| BudgetOp::Force { bytes, hold }),
            1 => (1usize..200).prop_map(BudgetOp::Resize),
            2 => (0u64..10).prop_map(BudgetOp::Sleep),
        ]
    }

    /// Run `ops` against a budget; returns the peak of bytes held through
    /// `acquire`/`try_acquire` guards. Panics on deadlock or leaks.
    fn run_budget_ops(cap: usize, ops: Vec<BudgetOp>) -> usize {
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        rt.block_on(async move {
            let b = MemoryBudget::new(cap);
            let held = Arc::new(AtomicUsize::new(0));
            let peak = Arc::new(AtomicUsize::new(0));
            let mut tasks = Vec::new();
            let mut aborts = Vec::new();
            let mut final_cap = cap;
            /// Keeps a guard alive and its bytes counted in `held` (`n`; 0
            /// for forced guards) until dropped, also when the holding task
            /// is aborted.
            struct Counted {
                held: Arc<AtomicUsize>,
                n: usize,
                _guard: BudgetGuard,
            }
            impl Drop for Counted {
                fn drop(&mut self) {
                    self.held.fetch_sub(self.n, Ordering::SeqCst);
                }
            }
            let (held2, peak2) = (held.clone(), peak.clone());
            let hold_for = move |g: BudgetGuard, ms: u64, counted: bool| {
                let (held, peak) = (held2.clone(), peak2.clone());
                async move {
                    let n = if counted { g.bytes() } else { 0 };
                    let now = held.fetch_add(n, Ordering::SeqCst) + n;
                    peak.fetch_max(now, Ordering::SeqCst);
                    let _counted = Counted { held, n, _guard: g };
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                }
            };
            for op in ops {
                match op {
                    BudgetOp::Acquire { bytes, hold }
                    | BudgetOp::AcquireAbort { bytes, hold, .. } => {
                        let b2 = b.clone();
                        let hold_for = hold_for.clone();
                        let t = tokio::spawn(async move {
                            let g = b2.acquire(bytes).await;
                            assert!(g.bytes() <= bytes);
                            hold_for(g, hold, true).await;
                        });
                        if let BudgetOp::AcquireAbort { after, .. } = op {
                            let h = t.abort_handle();
                            aborts.push(tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(after)).await;
                                h.abort();
                            }));
                            tasks.push((t, true));
                        } else {
                            tasks.push((t, false));
                        }
                    }
                    BudgetOp::Try { bytes, hold } => {
                        if let Some(g) = b.try_acquire(bytes) {
                            tasks.push((tokio::spawn(hold_for(g, hold, true)), false));
                        }
                    }
                    BudgetOp::Force { bytes, hold } => {
                        let g = b.force_acquire(bytes);
                        tasks.push((tokio::spawn(hold_for(g, hold, false)), false));
                    }
                    BudgetOp::Resize(n) => {
                        b.resize(n);
                        final_cap = n;
                    }
                    BudgetOp::Sleep(ms) => tokio::time::sleep(Duration::from_millis(ms)).await,
                }
            }
            // Every waiter finishes in bounded (virtual) time: no deadlock.
            let all = async {
                for (t, abortable) in tasks {
                    match t.await {
                        Ok(()) => {}
                        Err(e) if abortable && e.is_cancelled() => {}
                        Err(e) => std::panic::resume_unwind(e.into_panic()),
                    }
                }
            };
            tokio::time::timeout(Duration::from_secs(3600), all)
                .await
                .expect("budget waiters deadlocked");
            for a in aborts {
                a.await.unwrap();
            }
            assert_eq!(held.load(Ordering::SeqCst), 0);
            assert_eq!(b.capacity(), final_cap);
            assert_eq!(b.available(), final_cap, "budget leaked");
            assert_eq!(b.in_use(), 0);
            assert!(!b.is_overcommitted());
            peak.load(Ordering::SeqCst)
        })
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(crate::proptest_cases(256)))]

        /// Concurrent waiters (including requests larger than the budget),
        /// cancellation, forced over-commit and resizes never deadlock or
        /// leak, and without forced acquisitions or resizes the guards
        /// handed out never exceed the capacity.
        #[test]
        fn concurrent_ops_never_deadlock_or_leak(
            cap in 1usize..200,
            ops in proptest::collection::vec(budget_op(), 1..40),
        ) {
            let bounded = !ops
                .iter()
                .any(|o| matches!(o, BudgetOp::Force { .. } | BudgetOp::Resize(_)));
            let peak = run_budget_ops(cap, ops);
            if bounded {
                proptest::prop_assert!(peak <= cap, "peak {} > capacity {}", peak, cap);
            }
        }
    }

    #[test]
    fn guard_is_send_sync() {
        fn check<T: Send + Sync + 'static>() {}
        check::<BudgetGuard>();
        check::<MemoryBudget>();
    }
}
