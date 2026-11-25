//! Running blocking work (filesystem syscalls) from backend futures.
//!
//! Backends must never block an async runtime worker, so blocking work
//! normally goes to tokio's blocking pool ([`spawn_blocking`]). That costs a
//! thread hand-off and a wake-up per call — far more than a `stat` or a
//! small `pread` takes. When the future is instead driven by a thread that
//! is *not* a runtime worker and that waits for this one result anyway (the
//! Python bindings' synchronous executor), running the work inline on that
//! thread is both safe and much cheaper.
//!
//! [`blocking`] makes that choice per call: it runs the closure inline when
//! the thread polling the future has opted in with [`allow_inline`], and in
//! the blocking pool otherwise. The opt-in is a thread-local flag scoped to
//! one poll, so it can only apply to the thread that set it: futures spawned
//! onto the runtime (polled by its workers) never see it.
//!
//! Rules for backends:
//! * use [`blocking`] for the short, sequential steps of one operation
//!   (`stat`, `open`+small `read`, small `write`, `unlink`, ...);
//! * use [`spawn_blocking`] for work that must run in parallel with other
//!   blocking work of the same operation (fan-out over several pool threads)
//!   or that can take long (large copies): inline it would serialise or hold
//!   the caller for longer than a signal check interval.
//!
//! Rules for executors that call [`allow_inline`]: the thread must not be a
//! runtime worker, and the future it polls must be one operation whose
//! sub-futures are not meant to run concurrently (a batch of operations
//! polled together would serialise their blocking steps).

use std::cell::Cell;

use crate::{Error, ErrorKind, Result};

thread_local! {
    /// Whether [`blocking`] may run its closure on this thread.
    static INLINE: Cell<bool> = const { Cell::new(false) };
    /// How many [`blocking`] calls polled on this thread sent their closure
    /// to the blocking pool (see [`pool_dispatches`]).
    static DISPATCHED: Cell<u64> = const { Cell::new(0) };
}

/// Restores the previous flag value on drop (also during unwinding).
struct Restore(bool);

impl Drop for Restore {
    fn drop(&mut self) {
        INLINE.with(|c| c.set(self.0));
    }
}

/// Run `f` (typically one `Future::poll`) with inline blocking allowed or
/// forbidden on this thread, restoring the previous setting afterwards.
///
/// Only an executor that owns the current thread and is not a runtime
/// worker may pass `true` (see the module documentation).
pub fn allow_inline<R>(allow: bool, f: impl FnOnce() -> R) -> R {
    let prev = INLINE.with(|c| c.replace(allow));
    let _restore = Restore(prev);
    f()
}

/// Whether [`blocking`] would run its closure inline on this thread now.
pub fn inline_allowed() -> bool {
    INLINE.with(Cell::get)
}

/// How many [`blocking`] calls polled on this thread so far sent their
/// (short, by contract) closure to the blocking pool; a wrapping counter.
///
/// An executor compares the value before and after a poll that returned
/// `Pending` to learn whether the future now only waits for a short
/// blocking step (a local `stat`, a small read), whose completion is worth
/// a brief busy-wait, rather than for network I/O or a timer.
/// [`spawn_blocking`] (long or parallel work) is not counted.
pub fn pool_dispatches() -> u64 {
    DISPATCHED.with(Cell::get)
}

/// Run blocking work for the current operation: inline when the polling
/// thread allowed it ([`allow_inline`]), else on tokio's blocking pool.
///
/// The decision is taken when the returned future is first polled. While
/// the closure runs inline the flag is cleared, so nothing it reaches can
/// inline further work. A panic in the closure propagates to the caller in
/// both modes.
pub async fn blocking<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    if inline_allowed() {
        return allow_inline(false, f);
    }
    DISPATCHED.with(|c| c.set(c.get().wrapping_add(1)));
    spawn_blocking(f).await
}

/// What a step run by [`blocking_deferrable`] did.
#[derive(Debug)]
pub enum Attempt<T> {
    /// The step ran (successfully or not).
    Done(Result<T>),
    /// Running inline, the step found it could block for an unbounded time
    /// (e.g. opening a named pipe, which waits for the other end): nothing
    /// was done, run it on the blocking pool instead.
    Defer,
}

/// [`blocking`] for a step that can only tell once it starts whether it is
/// short: `f(true)` runs inline (when allowed) and may return
/// [`Attempt::Defer`], after which `f(false)` runs on the blocking pool,
/// where it must not defer. With inline blocking not allowed, only
/// `f(false)` runs, on the pool.
///
/// Inline steps hold a thread that cannot check for signals meanwhile, so
/// a step that may wait indefinitely (on another process, a device) must
/// defer rather than block.
pub async fn blocking_deferrable<T, F>(mut f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnMut(bool) -> Attempt<T> + Send + 'static,
{
    if inline_allowed() {
        match allow_inline(false, || f(true)) {
            Attempt::Done(r) => return r,
            Attempt::Defer => {}
        }
    }
    DISPATCHED.with(|c| c.set(c.get().wrapping_add(1)));
    spawn_blocking(move || match f(false) {
        Attempt::Done(r) => r,
        Attempt::Defer => Err(Error::new(
            ErrorKind::Other,
            "blocking step deferred while running on the blocking pool",
        )),
    })
    .await
}

/// Run blocking work on tokio's blocking pool, always (see the module
/// documentation for when to prefer this over [`blocking`]). A panic in the
/// closure is resumed in the caller; a pool shutting down is
/// [`ErrorKind::Cancelled`].
pub async fn spawn_blocking<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(e) => Err(Error::new(
            ErrorKind::Cancelled,
            format!("blocking task cancelled: {e}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::ThreadId;

    fn thread_of() -> impl FnOnce() -> Result<ThreadId> + Send + 'static {
        || Ok(std::thread::current().id())
    }

    /// Finish a future whose first poll (on this thread) gave `first`: a
    /// pool thread may already have completed it then, so it must not be
    /// polled again in that case.
    fn finish<T>(
        rt: &tokio::runtime::Runtime,
        first: std::task::Poll<T>,
        fut: std::pin::Pin<&mut impl Future<Output = T>>,
    ) -> T {
        match first {
            std::task::Poll::Ready(v) => v,
            std::task::Poll::Pending => rt.block_on(fut),
        }
    }

    #[test]
    fn flag_is_scoped_and_restored() {
        assert!(!inline_allowed());
        allow_inline(true, || {
            assert!(inline_allowed());
            allow_inline(false, || assert!(!inline_allowed()));
            assert!(inline_allowed());
        });
        assert!(!inline_allowed());
    }

    #[test]
    fn flag_is_restored_after_a_panic() {
        let r = std::panic::catch_unwind(|| allow_inline(true, || panic!("boom")));
        assert!(r.is_err());
        assert!(!inline_allowed());
    }

    #[test]
    fn runs_on_the_pool_by_default_and_inline_when_allowed() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build()
            .unwrap();
        let _ctx = rt.enter();
        let me = std::thread::current().id();
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);

        // Inline: completes in the first poll, on this thread.
        let mut fut = std::pin::pin!(blocking(thread_of()));
        let polled = allow_inline(true, || fut.as_mut().poll(&mut cx));
        match polled {
            std::task::Poll::Ready(Ok(id)) => assert_eq!(id, me),
            other => panic!("not completed inline: {other:?}"),
        }

        // Default: the blocking pool, another thread.
        let id = rt.block_on(blocking(thread_of())).unwrap();
        assert_ne!(id, me);
        // The flag set by another thread's poll does not leak to workers.
        let id = rt
            .block_on(async { tokio::spawn(blocking(thread_of())).await.unwrap() })
            .unwrap();
        assert_ne!(id, me);
        // `spawn_blocking` ignores the flag.
        let mut fut = std::pin::pin!(spawn_blocking(thread_of()));
        let polled = allow_inline(true, || fut.as_mut().poll(&mut cx));
        assert_ne!(finish(&rt, polled, fut).unwrap(), me);
    }

    #[test]
    fn pool_dispatches_count_only_short_steps_sent_to_the_pool() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build()
            .unwrap();
        let _ctx = rt.enter();
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let before = pool_dispatches();
        // Inline: not dispatched.
        let mut fut = std::pin::pin!(blocking(thread_of()));
        assert!(allow_inline(true, || fut.as_mut().poll(&mut cx)).is_ready());
        assert_eq!(pool_dispatches(), before);
        // `spawn_blocking` (long work): not counted. (Whether the first poll
        // is already ready depends on the pool's timing: not checked.)
        let mut fut = std::pin::pin!(spawn_blocking(thread_of()));
        let first = fut.as_mut().poll(&mut cx);
        assert_eq!(pool_dispatches(), before);
        finish(&rt, first, fut).unwrap();
        // A short step sent to the pool: counted once, on the polling thread.
        let mut fut = std::pin::pin!(blocking(thread_of()));
        let first = fut.as_mut().poll(&mut cx);
        assert_eq!(pool_dispatches(), before.wrapping_add(1));
        finish(&rt, first, fut).unwrap();
        assert_eq!(pool_dispatches(), before.wrapping_add(1));
    }

    #[test]
    fn deferrable_steps_retry_on_the_pool() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build()
            .unwrap();
        let _ctx = rt.enter();
        let me = std::thread::current().id();
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let step = |defer: bool| {
            move |inline: bool| {
                if inline && defer {
                    Attempt::Defer
                } else {
                    Attempt::Done(Ok((inline, std::thread::current().id())))
                }
            }
        };
        // Not deferred: done inline, in the first poll.
        let mut fut = std::pin::pin!(blocking_deferrable(step(false)));
        match allow_inline(true, || fut.as_mut().poll(&mut cx)) {
            std::task::Poll::Ready(Ok((true, id))) => assert_eq!(id, me),
            other => panic!("not inline: {other:?}"),
        }
        // Deferred: redone on the pool (counted as a dispatch).
        let before = pool_dispatches();
        let mut fut = std::pin::pin!(blocking_deferrable(step(true)));
        let first = allow_inline(true, || fut.as_mut().poll(&mut cx));
        assert_eq!(pool_dispatches(), before.wrapping_add(1));
        let (inline, id) = finish(&rt, first, fut).unwrap();
        assert!(!inline);
        assert_ne!(id, me);
        // Inline not allowed: straight to the pool.
        let (inline, id) = rt.block_on(blocking_deferrable(step(false))).unwrap();
        assert!(!inline);
        assert_ne!(id, me);
    }

    #[test]
    fn nested_blocking_inside_inline_work_is_not_inlined() {
        let me = std::thread::current().id();
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut fut = std::pin::pin!(blocking(|| Ok(inline_allowed())));
        match allow_inline(true, || fut.as_mut().poll(&mut cx)) {
            std::task::Poll::Ready(Ok(nested)) => assert!(!nested),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(std::thread::current().id(), me);
    }

    #[test]
    fn panics_propagate_in_both_modes() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(blocking(|| -> Result<()> { panic!("pool") }))
        }));
        assert!(r.is_err());
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut fut = std::pin::pin!(blocking(|| -> Result<()> { panic!("inline") }));
            allow_inline(true, || fut.as_mut().poll(&mut cx))
        }));
        assert!(r.is_err());
        assert!(!inline_allowed());
    }
}
