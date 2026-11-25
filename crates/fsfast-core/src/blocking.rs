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
    spawn_blocking(f).await
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
        assert!(polled.is_pending());
        assert_ne!(rt.block_on(fut).unwrap(), me);
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
