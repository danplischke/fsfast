//! The fork gate: `os.fork()` waits until no backend code driven by this
//! module is running, so the child never inherits a lock that another
//! thread held at the moment of the fork.
//!
//! A forked child contains only the thread that called `fork()`. A lock held
//! by any other thread at that instant (for example the memory store's
//! `RwLock`, taken by every memory operation) stays locked in the child
//! forever, and the child's first operation that needs it deadlocks. Backends
//! only hold such locks *while being polled* (never across an `.await`,
//! which the fsfast conventions require), so it is enough that no poll is in
//! progress when `fork()` runs:
//!
//! * every poll of a backend future that this crate drives (sync calls,
//!   inline first polls, the inner future of async calls, the background
//!   close of a dropped writer) runs inside [`enter`] / [`try_enter`];
//! * the `os.register_at_fork(before=...)` hook calls [`close_for_fork`]
//!   with the interpreter released: it stops new polls from starting and
//!   waits for the ones in progress to finish (polls are short: they never
//!   block on I/O);
//! * the `after_in_parent` hook reopens the gate ([`reopen_after_fork`]),
//!   the `after_in_child` hook resets it ([`reset_in_child`]).
//!
//! The gate is a flag plus per-thread-shard counters of polls in progress,
//! all plain atomics: entering costs one uncontended atomic increment on a
//! cache line shared by few threads, and nothing in it can be left locked
//! across a fork (waiters sleep; there are no parking queues to inherit).
//!
//! Re-entrancy: code running inside a poll can reach Python (releasing a
//! buffer re-attaches to the interpreter, which may run the garbage
//! collector and thus `__del__` methods calling back into fsfast). Nested
//! entries on a thread already inside the gate pass straight through, and so
//! do the helper threads such a nested call may use (see
//! [`with_inherited_depth`]); waiting there would deadlock with the forking
//! thread waiting for the outer poll.
//!
//! Not covered: tasks that backends or the engine spawn on the runtime
//! themselves (e.g. read-ahead prefetches). The local and memory backends
//! take no locks in those.

use std::cell::Cell;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

/// Number of counter shards (threads are assigned round-robin).
const SHARDS: usize = 64;

/// How long the fork hook waits for polls in progress before forking
/// anyway (a safety valve: polls take microseconds; something is wrong if
/// they do not drain, and hanging the parent would be worse than the risk
/// of an inherited lock in the child).
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// One cache line per shard, so threads in different shards never contend.
#[repr(align(128))]
struct Shard(AtomicUsize);

/// Polls in progress, per shard.
static ACTIVE: [Shard; SHARDS] = [const { Shard(AtomicUsize::new(0)) }; SHARDS];

/// Set while a fork is pending: no new poll may start.
static CLOSED: AtomicBool = AtomicBool::new(false);

/// Round-robin shard assignment.
static NEXT_SHARD: AtomicUsize = AtomicUsize::new(0);

/// PID of the process whose `before` hook ran last (0: none yet), so that
/// [`reset_in_child`] only acts in an actual child.
static FORKING_PID: AtomicU32 = AtomicU32::new(0);

thread_local! {
    /// This thread's shard (assigned on first use).
    static SHARD: Cell<Option<usize>> = const { Cell::new(None) };
    /// Gate entries this thread currently holds (0 = outside the gate).
    static DEPTH: Cell<u32> = const { Cell::new(0) };
    /// Whether this thread's fork hook closed the gate (`before` and
    /// `after_in_parent` run on the forking thread).
    static CLOSED_BY_ME: Cell<bool> = const { Cell::new(false) };
}

fn shard() -> usize {
    SHARD.with(|s| match s.get() {
        Some(i) => i,
        None => {
            let i = NEXT_SHARD.fetch_add(1, Ordering::Relaxed) % SHARDS;
            s.set(Some(i));
            i
        }
    })
}

/// Proof of being inside the gate; leaving happens on drop. Not `Send`:
/// the entry is recorded per thread.
#[must_use = "the gate is left when the guard is dropped"]
pub(crate) struct GateGuard {
    /// The shard counted for the outermost entry; `None` for a nested one.
    shard: Option<usize>,
    _not_send: PhantomData<*const ()>,
}

impl Drop for GateGuard {
    fn drop(&mut self) {
        if let Some(s) = self.shard {
            ACTIVE[s].0.fetch_sub(1, Ordering::Release);
        }
        DEPTH.with(|d| d.set(d.get() - 1));
    }
}

/// Enter the gate without waiting: `None` while a fork is pending. For code
/// running with the interpreter attached, which must never wait here (the
/// forking thread needs the interpreter back to return from `fork()`).
pub(crate) fn try_enter() -> Option<GateGuard> {
    let depth = DEPTH.with(Cell::get);
    if depth > 0 {
        DEPTH.with(|d| d.set(depth + 1));
        return Some(GateGuard {
            shard: None,
            _not_send: PhantomData,
        });
    }
    let s = shard();
    // SeqCst on both sides (here: increment, then read the flag; in
    // `close_for_fork`: set the flag, then read the counters) guarantees
    // that either this poll sees the fork pending or the fork sees this
    // poll in progress.
    ACTIVE[s].0.fetch_add(1, Ordering::SeqCst);
    if CLOSED.load(Ordering::SeqCst) {
        ACTIVE[s].0.fetch_sub(1, Ordering::Release);
        return None;
    }
    DEPTH.with(|d| d.set(1));
    Some(GateGuard {
        shard: Some(s),
        _not_send: PhantomData,
    })
}

/// Enter the gate, waiting while a fork is pending. Only for threads that
/// are detached from the interpreter (or runtime workers).
pub(crate) fn enter() -> GateGuard {
    let mut backoff = Backoff::new();
    loop {
        if let Some(g) = try_enter() {
            return g;
        }
        backoff.wait();
    }
}

/// Number of gate entries this thread holds.
pub(crate) fn depth() -> u32 {
    DEPTH.with(Cell::get)
}

/// Run `f` (on a helper thread) as if nested in the caller's gate entries:
/// a thread spawned to finish work for a poll that is itself inside the gate
/// must not wait for a pending fork, which waits for that very poll.
pub(crate) fn with_inherited_depth<T>(depth: u32, f: impl FnOnce() -> T) -> T {
    let before = DEPTH.with(|d| d.replace(d.get() + depth));
    let out = f();
    DEPTH.with(|d| d.set(before));
    out
}

/// `os.register_at_fork(before=...)`: stop new polls and wait (up to
/// [`DRAIN_TIMEOUT`]) for those in progress. Must run with the interpreter
/// released, so that polls needing it can finish. Does nothing when called
/// from inside a poll (the thread cannot wait for itself).
pub(crate) fn close_for_fork() {
    FORKING_PID.store(std::process::id(), Ordering::SeqCst);
    if depth() > 0 {
        return;
    }
    let deadline = Instant::now() + DRAIN_TIMEOUT;
    let mut backoff = Backoff::new();
    // Another thread may be forking at the same time: take turns.
    while CLOSED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        if Instant::now() >= deadline {
            tracing::warn!("fsfast: another fork kept the fork gate closed; forking anyway");
            return;
        }
        backoff.wait();
    }
    CLOSED_BY_ME.with(|c| c.set(true));
    let mut backoff = Backoff::new();
    while ACTIVE.iter().any(|s| s.0.load(Ordering::SeqCst) != 0) {
        if Instant::now() >= deadline {
            tracing::warn!(
                "fsfast: operations still running after {DRAIN_TIMEOUT:?}; forking anyway"
            );
            return;
        }
        backoff.wait();
    }
}

/// `after_in_parent`: reopen the gate if this thread's `before` hook closed it.
pub(crate) fn reopen_after_fork() {
    if CLOSED_BY_ME.with(|c| c.replace(false)) {
        CLOSED.store(false, Ordering::SeqCst);
    }
}

/// `after_in_child`: only the forking thread exists. Polls of other threads
/// that were waiting to start are gone; if the fork happened from inside a
/// poll (see [`close_for_fork`]), that poll's entry is kept. Does nothing
/// unless this process is a child of the one whose `before` hook ran (the
/// hook may be called by hand; resetting under live entries would corrupt
/// the counts). Returns whether this process is such a child.
pub(crate) fn reset_in_child() -> bool {
    let parent = FORKING_PID.load(Ordering::SeqCst);
    if parent == 0 || parent == std::process::id() {
        return false;
    }
    // One reset per fork.
    FORKING_PID.store(0, Ordering::SeqCst);
    for s in &ACTIVE {
        s.0.store(0, Ordering::SeqCst);
    }
    if depth() > 0 {
        ACTIVE[shard()].0.store(1, Ordering::SeqCst);
    }
    CLOSED_BY_ME.with(|c| c.set(false));
    CLOSED.store(false, Ordering::SeqCst);
    true
}

/// Spin briefly, then yield, then sleep with growing pauses (up to 1 ms).
struct Backoff(u32);

impl Backoff {
    fn new() -> Self {
        Backoff(0)
    }

    fn wait(&mut self) {
        match self.0 {
            0..10 => std::hint::spin_loop(),
            10..20 => std::thread::yield_now(),
            n => std::thread::sleep(Duration::from_micros(u64::from((n - 19) * 50).min(1000))),
        }
        self.0 = self.0.saturating_add(1);
    }
}

/// A future whose every poll runs inside the gate (waiting while a fork is
/// pending). For futures polled by runtime workers.
pub(crate) struct Gated<F>(pub(crate) Pin<Box<F>>);

impl<F: Future> Future for Gated<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let _gate = enter();
        self.0.as_mut().poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier, Mutex};

    // The gate is process-wide: tests that close it must not overlap.
    static SERIAL: Mutex<()> = Mutex::new(());

    #[test]
    fn nested_entries_count_once_and_unwind() {
        let _s = SERIAL.lock().unwrap();
        assert_eq!(depth(), 0);
        let a = try_enter().unwrap();
        let b = enter();
        assert_eq!(depth(), 2);
        drop(b);
        assert_eq!(depth(), 1);
        drop(a);
        assert_eq!(depth(), 0);
        assert!(ACTIVE.iter().all(|s| s.0.load(Ordering::SeqCst) == 0));
    }

    #[test]
    fn a_pending_fork_waits_for_polls_and_blocks_new_ones() {
        let _s = SERIAL.lock().unwrap();
        let start = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let (s2, r2) = (start.clone(), release.clone());
        // A poll in progress on another thread.
        let poller = std::thread::spawn(move || {
            let _g = enter();
            s2.wait();
            r2.wait();
            std::thread::sleep(Duration::from_millis(50));
        });
        start.wait();
        let closer = std::thread::spawn(|| {
            let t = Instant::now();
            close_for_fork();
            let waited = t.elapsed();
            // While closed, nothing new starts (on this or other threads).
            assert!(try_enter().is_none());
            assert!(std::thread::spawn(|| try_enter().is_none()).join().unwrap());
            reopen_after_fork();
            waited
        });
        std::thread::sleep(Duration::from_millis(20));
        release.wait();
        let waited = closer.join().unwrap();
        poller.join().unwrap();
        assert!(waited >= Duration::from_millis(40), "{waited:?}");
        // Reopened: entering works again.
        drop(try_enter().expect("gate reopened"));
    }

    #[test]
    fn waiting_entries_proceed_after_the_fork() {
        let _s = SERIAL.lock().unwrap();
        close_for_fork();
        let waiter = std::thread::spawn(|| {
            let t = Instant::now();
            let _g = enter();
            t.elapsed()
        });
        std::thread::sleep(Duration::from_millis(30));
        reopen_after_fork();
        assert!(waiter.join().unwrap() >= Duration::from_millis(20));
    }

    #[test]
    fn nested_entries_and_inherited_depth_never_wait() {
        let _s = SERIAL.lock().unwrap();
        let outer = enter();
        // A fork from inside a poll does not try to wait for itself.
        close_for_fork();
        assert!(!CLOSED.load(Ordering::SeqCst));
        // Another thread closes the gate while this one is inside it...
        let closer = std::thread::spawn(|| {
            close_for_fork();
            std::thread::sleep(Duration::from_millis(20));
            reopen_after_fork();
        });
        while !CLOSED.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        // ...nested entries (here and on helper threads working for this
        // poll) pass, where waiting would deadlock.
        drop(try_enter().expect("nested entry"));
        let d = depth();
        std::thread::spawn(move || with_inherited_depth(d, || drop(enter())))
            .join()
            .unwrap();
        drop(outer);
        closer.join().unwrap();
    }

    /// Make [`reset_in_child`] believe this process is a forked child.
    fn pretend_forked() {
        FORKING_PID.store(std::process::id().wrapping_add(1), Ordering::SeqCst);
    }

    #[test]
    fn child_reset_reopens_and_keeps_the_forking_poll() {
        let _s = SERIAL.lock().unwrap();
        close_for_fork();
        pretend_forked();
        assert!(reset_in_child());
        assert!(!CLOSED.load(Ordering::SeqCst));
        drop(try_enter().expect("open after reset"));
        // Forking from inside a poll: its entry survives the reset.
        let g = enter();
        pretend_forked();
        assert!(reset_in_child());
        assert_eq!(ACTIVE[shard()].0.load(Ordering::SeqCst), 1);
        drop(g);
        assert!(ACTIVE.iter().all(|s| s.0.load(Ordering::SeqCst) == 0));
    }

    #[test]
    fn reset_outside_a_child_changes_nothing() {
        let _s = SERIAL.lock().unwrap();
        // The hooks run in the parent (or by hand): live entries and a
        // pending fork are left alone.
        close_for_fork();
        let entered = std::thread::spawn(|| {
            let g = enter(); // waits for the reopen below
            drop(g);
        });
        assert!(!reset_in_child());
        assert!(
            CLOSED.load(Ordering::SeqCst),
            "reset outside a child reopened the gate"
        );
        reopen_after_fork();
        entered.join().unwrap();
        assert!(ACTIVE.iter().all(|s| s.0.load(Ordering::SeqCst) == 0));
    }
}
