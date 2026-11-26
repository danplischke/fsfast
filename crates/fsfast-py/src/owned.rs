//! [`OwnedMutex`]: a mutex that knows which thread holds it.
//!
//! File objects hold their state lock while an operation runs detached, and
//! the sync bridge re-attaches every 100 ms on that same thread to run
//! Python signal handlers. A handler that touches the same file (`f.tell()`,
//! `f.close()`, ...) would then wait for a lock its own thread holds: a
//! deadlock nothing can interrupt, since signal checks stop while it waits.
//! [`OwnedMutex::held_by_current_thread`] lets callers detect that case
//! before waiting and raise instead, as CPython's buffered files do
//! (`RuntimeError: reentrant call inside ...`).

use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::{Mutex, MutexGuard};

/// No thread (thread ids start at 1).
const NOBODY: u64 = 0;

/// A small, process-unique id for the current thread.
fn current_thread() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    thread_local! {
        static ID: u64 = NEXT.fetch_add(1, Ordering::Relaxed);
    }
    // During thread-local teardown no id is available; such a thread
    // cannot be inside a file operation, so "nobody" is never a false
    // match for a reentrancy check (and it is never stored as an owner by
    // a live operation of another thread).
    ID.try_with(|id| *id).unwrap_or(u64::MAX)
}

/// A [`parking_lot::Mutex`] that records the thread holding it.
pub(crate) struct OwnedMutex<T> {
    inner: Mutex<T>,
    owner: AtomicU64,
}

/// Guard of an [`OwnedMutex`]; clears the owner when dropped.
pub(crate) struct OwnedGuard<'a, T> {
    guard: MutexGuard<'a, T>,
    owner: &'a AtomicU64,
}

impl<T> OwnedMutex<T> {
    pub(crate) fn new(value: T) -> Self {
        OwnedMutex {
            inner: Mutex::new(value),
            owner: AtomicU64::new(NOBODY),
        }
    }

    /// Whether the calling thread holds the lock (an outer frame of this
    /// thread is inside an operation). Only the holder ever stores its own
    /// id, and it clears it before unlocking, so a `true` here is exact.
    pub(crate) fn held_by_current_thread(&self) -> bool {
        self.owner.load(Ordering::Relaxed) == current_thread()
    }

    fn guard<'a>(&'a self, guard: MutexGuard<'a, T>) -> OwnedGuard<'a, T> {
        self.owner.store(current_thread(), Ordering::Relaxed);
        OwnedGuard {
            guard,
            owner: &self.owner,
        }
    }

    /// Lock without blocking.
    pub(crate) fn try_lock(&self) -> Option<OwnedGuard<'_, T>> {
        self.inner.try_lock().map(|g| self.guard(g))
    }

    /// Lock, waiting for other threads. Callers check
    /// [`OwnedMutex::held_by_current_thread`] first: waiting for a lock this
    /// thread holds never returns.
    pub(crate) fn lock(&self) -> OwnedGuard<'_, T> {
        debug_assert!(!self.held_by_current_thread(), "reentrant lock");
        let g = self.inner.lock();
        self.guard(g)
    }

    /// Mutable access without locking (exclusive borrow).
    pub(crate) fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }
}

impl<T> Drop for OwnedGuard<'_, T> {
    fn drop(&mut self) {
        self.owner.store(NOBODY, Ordering::Relaxed);
    }
}

impl<T> Deref for OwnedGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T> DerefMut for OwnedGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_is_tracked_per_thread() {
        let m = std::sync::Arc::new(OwnedMutex::new(1));
        assert!(!m.held_by_current_thread());
        let g = m.lock();
        assert!(m.held_by_current_thread());
        let m2 = m.clone();
        let other = std::thread::spawn(move || m2.held_by_current_thread())
            .join()
            .unwrap();
        assert!(!other, "another thread does not hold it");
        assert!(m.try_lock().is_none());
        drop(g);
        assert!(!m.held_by_current_thread());
        let g = m.try_lock().expect("free");
        assert_eq!(*g, 1);
        assert!(m.held_by_current_thread());
    }
}
