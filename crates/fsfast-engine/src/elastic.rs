//! A semaphore whose capacity can shrink while permits are held.
//!
//! Tokio's [`Semaphore`] can only grow. Both the memory budget (resizable,
//! with forced over-commit) and the AIMD limiter (multiplicative decrease
//! while requests are in flight) need to *remove* permits that are currently
//! held. We do that lazily with a debt counter:
//!
//! * [`ElasticSemaphore::take`] removes `n` permits immediately: whatever is
//!   available is forgotten now, the remainder becomes debt.
//! * [`ElasticSemaphore::give`] returns `n` permits, paying off debt first.
//!
//! Invariant (eventually, under concurrent updates):
//! `available + held - debt == capacity`.
//!
//! Callers that acquire through the semaphore immediately `forget` the tokio
//! permit and later return the count through [`ElasticSemaphore::give`], so
//! every release path goes through the debt check.
//!
//! One path bypasses `give`: tokio grants permits to the head waiter
//! incrementally, and when such a waiter is cancelled its partial grant goes
//! straight back into the semaphore. While debt is outstanding those permits
//! must repay it rather than be handed out, so [`ElasticSemaphore::acquire`]
//! and [`ElasticSemaphore::try_acquire`] reconcile debt against available
//! permits before acquiring, and repay debt from a grant they receive while
//! debt is outstanding.
//!
//! A waiter whose grant was (partly) used to repay debt hands the rest back
//! and queues again for its full request. It must never keep permits while
//! queued: that is hold-and-wait, and the new head of the queue could wait
//! forever for the permits it holds.

use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Semaphore;

/// Upper bound on permits (tokio's limit).
pub(crate) const MAX_PERMITS: usize = Semaphore::MAX_PERMITS;

#[derive(Debug)]
pub(crate) struct ElasticSemaphore {
    sem: Semaphore,
    debt: AtomicUsize,
}

impl ElasticSemaphore {
    pub(crate) fn new(permits: usize) -> Self {
        ElasticSemaphore {
            sem: Semaphore::new(permits.min(MAX_PERMITS)),
            debt: AtomicUsize::new(0),
        }
    }

    /// Reduce the debt by up to `n`; returns the amount repaid.
    fn repay(&self, n: usize) -> usize {
        let mut debt = self.debt.load(Ordering::Acquire);
        loop {
            let pay = debt.min(n);
            if pay == 0 {
                return 0;
            }
            match self.debt.compare_exchange_weak(
                debt,
                debt - pay,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return pay,
                Err(actual) => debt = actual,
            }
        }
    }

    /// Use available permits to pay outstanding debt.
    fn reconcile(&self) {
        while self.debt.load(Ordering::Acquire) > 0 {
            let got = self.sem.forget_permits(self.debt.load(Ordering::Acquire));
            if got == 0 {
                return;
            }
            let paid = self.repay(got);
            if paid < got {
                // Someone else repaid concurrently: return the excess.
                self.sem.add_permits(got - paid);
            }
        }
    }

    /// Wait for `n` permits (FIFO-fair) and take them. Cancellation-safe:
    /// nothing is held across the await except tokio's own partial grant,
    /// which tokio returns if the future is dropped.
    pub(crate) async fn acquire(&self, n: u32) {
        if n == 0 {
            return;
        }
        loop {
            self.reconcile();
            // The semaphore is never closed, so `acquire_many` cannot fail.
            if let Ok(p) = self.sem.acquire_many(n).await {
                p.forget();
            }
            // A grant received while debt is outstanding repays it first.
            let paid = self.repay(n as usize);
            if paid == 0 {
                return;
            }
            // Hand the rest back and queue again for all `n`; keeping it
            // while queued would be hold-and-wait (see the module docs).
            self.give(n as usize - paid);
        }
    }

    /// Take `n` permits if they are available right now.
    pub(crate) fn try_acquire(&self, n: u32) -> bool {
        if n == 0 {
            return true;
        }
        self.reconcile();
        match self.sem.try_acquire_many(n) {
            Ok(p) => {
                p.forget();
                let paid = self.repay(n as usize);
                if paid == 0 {
                    return true;
                }
                // Debt appeared concurrently: it takes precedence.
                self.give(n as usize - paid);
                false
            }
            Err(_) => false,
        }
    }

    /// Remove `n` permits without waiting: available permits are forgotten
    /// now and the rest is recorded as debt, paid by future [`give`]s.
    ///
    /// [`give`]: ElasticSemaphore::give
    pub(crate) fn take(&self, n: usize) {
        if n == 0 {
            return;
        }
        let got = self.sem.forget_permits(n);
        if got < n {
            self.debt.fetch_add(n - got, Ordering::AcqRel);
        }
    }

    /// Return `n` permits, paying off outstanding debt first.
    pub(crate) fn give(&self, n: usize) {
        let left = n - self.repay(n);
        if left > 0 {
            self.sem.add_permits(left);
        }
    }

    /// Permits that can be acquired right now (net of debt).
    pub(crate) fn available(&self) -> usize {
        self.sem
            .available_permits()
            .saturating_sub(self.debt.load(Ordering::Acquire))
    }

    /// Permits sitting in the semaphore, not net of debt.
    pub(crate) fn raw_available(&self) -> usize {
        self.sem.available_permits()
    }

    /// Outstanding debt (permits handed out beyond capacity, not yet repaid).
    pub(crate) fn debt(&self) -> usize {
        self.debt.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    #[test]
    fn take_and_give_keep_invariant() {
        let s = ElasticSemaphore::new(10);
        assert!(s.try_acquire(4));
        assert_eq!(s.available(), 6);
        // Shrink by 8 while 4 are held: 6 forgotten now, 2 as debt.
        s.take(8);
        assert_eq!(s.available(), 0);
        assert_eq!(s.debt(), 2);
        // Releasing the 4 held permits pays the debt first.
        s.give(4);
        assert_eq!(s.debt(), 0);
        assert_eq!(s.available(), 2);
        // Grow back.
        s.give(8);
        assert_eq!(s.available(), 10);
    }

    #[test]
    fn zero_sized_operations() {
        let s = ElasticSemaphore::new(1);
        assert!(s.try_acquire(0));
        s.take(0);
        s.give(0);
        assert_eq!(s.available(), 1);
    }

    #[tokio::test]
    async fn acquire_waits_for_give() {
        let s = Arc::new(ElasticSemaphore::new(1));
        s.acquire(1).await;
        let s2 = s.clone();
        let waiter = tokio::spawn(async move { s2.acquire(1).await });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        s.give(1);
        waiter.await.unwrap();
        assert_eq!(s.available(), 0);
    }

    /// A cancelled waiter's partial grant must repay debt, not be handed out.
    #[tokio::test(start_paused = true)]
    async fn cancelled_partial_grant_repays_debt() {
        let s = Arc::new(ElasticSemaphore::new(100));
        s.acquire(10).await; // held: 10, available 90
        let s2 = s.clone();
        let big = tokio::spawn(async move { s2.acquire(100).await });
        tokio::time::sleep(Duration::from_millis(1)).await;
        // tokio has assigned the 90 available permits to the queued waiter.
        assert_eq!(s.raw_available(), 0);
        s.take(50); // nothing available to forget: all debt
        assert_eq!(s.debt(), 50);
        big.abort();
        let _ = big.await;
        // The 90 permits came back raw; only 40 may be acquired.
        assert!(s.try_acquire(40));
        assert!(!s.try_acquire(1));
        assert_eq!(s.debt(), 0);
        s.give(40);
        s.give(10);
        assert_eq!(s.available(), 50);
    }

    #[tokio::test(start_paused = true)]
    async fn grant_received_with_debt_outstanding_waits_for_repayment() {
        let s = Arc::new(ElasticSemaphore::new(10));
        s.acquire(10).await;
        let s2 = s.clone();
        let w = tokio::spawn(async move { s2.acquire(5).await });
        tokio::time::sleep(Duration::from_millis(1)).await;
        // Permits returned via the raw path while debt exists.
        s.take(3);
        s.sem.add_permits(5); // simulate a cancelled waiter's return
        tokio::time::sleep(Duration::from_millis(1)).await;
        // The waiter got 5 raw permits, repaid 3, handed 2 back and queued
        // again for 5 (tokio re-granted the 2): it needs 3 more.
        assert!(!w.is_finished());
        assert_eq!(s.debt(), 0);
        s.give(3);
        w.await.unwrap();
        assert_eq!(s.available(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_acquire_returns_partial_progress() {
        let s = Arc::new(ElasticSemaphore::new(10));
        s.acquire(10).await;
        s.take(3); // debt 3
        let s2 = s.clone();
        let w = tokio::spawn(async move { s2.acquire(5).await });
        tokio::time::sleep(Duration::from_millis(1)).await;
        s.sem.add_permits(5); // raw return: waiter repays 3, re-queues with 2 granted
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(!w.is_finished());
        w.abort();
        let _ = w.await;
        // The 2 granted permits were returned.
        assert_eq!(s.available(), 2);
    }
}
