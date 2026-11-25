//! SMB2 credit accounting ([MS-SMB2] §3.2.4.1.5, §3.2.5.1.4).
//!
//! Every request consumes `max(1, CreditCharge)` credits (and as many
//! consecutive MessageIds); every response returns `CreditResponse` new
//! credits. The client may only send a request when it holds enough credits,
//! and must never use a MessageId outside the window the server granted.
//!
//! Available credits live in a FIFO-fair async semaphore, so requests that
//! need many credits (8 MiB READs charge 128) are not starved by streams of
//! one-credit metadata requests, and callers simply `await` when the window
//! is exhausted. MessageIds are handed out from an atomic counter only after
//! the credits are held, which keeps every id inside the granted window even
//! when frames reach the socket in a different order than ids were taken
//! (servers track the window as a bitmap, so any order inside it is valid).

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use fsfast_core::{Error, ErrorKind, Result};
use tokio::sync::{Semaphore, SemaphorePermit};

/// Bytes covered by one credit.
pub const CREDIT_BYTES: usize = 65536;

/// `CreditCharge` for a request moving `bytes` in its larger direction
/// ([MS-SMB2] §3.1.5.2): `(max(send, recv) - 1) / 65536 + 1`, at least 1.
pub fn charge_for(bytes: usize) -> u16 {
    let c = bytes.saturating_sub(1) / CREDIT_BYTES + 1;
    c.min(u16::MAX as usize) as u16
}

/// Credit window state of one connection.
#[derive(Debug)]
pub(crate) struct Credits {
    sem: Semaphore,
    /// Credits charged by requests that have not been answered yet.
    outstanding: AtomicI64,
    /// Next MessageId to hand out.
    next_mid: AtomicU64,
    /// Credits the client tries to hold (available + outstanding).
    target: u32,
}

impl Credits {
    /// A fresh connection: one implicit credit for the NEGOTIATE (MessageId 0).
    pub fn new(target: u16) -> Self {
        Credits {
            sem: Semaphore::new(1),
            outstanding: AtomicI64::new(0),
            next_mid: AtomicU64::new(0),
            target: u32::from(target.max(1)),
        }
    }

    /// Credits available right now.
    pub fn available(&self) -> usize {
        self.sem.available_permits()
    }

    /// Credits charged by unanswered requests.
    pub fn outstanding(&self) -> usize {
        self.outstanding.load(Ordering::Acquire).max(0) as usize
    }

    /// The current window: credits available plus credits in flight (which
    /// come back with their responses).
    pub fn window(&self) -> usize {
        self.available() + self.outstanding()
    }

    /// The largest charge one request should use so that it can always be
    /// granted: half the current window (at least 1), so several large
    /// requests fit in flight at once.
    pub fn max_charge(&self) -> u16 {
        (self.window() / 2).clamp(1, u16::MAX as usize) as u16
    }

    /// Wait until `n` credits are available and reserve them.
    ///
    /// Fails with `ConnectionFailed` once the connection is closed, and with
    /// `Throttled` if the request can never be granted because the server
    /// shrank the window below `n` while nothing is in flight (which would
    /// otherwise wait forever).
    pub async fn acquire(&self, n: u32) -> Result<SemaphorePermit<'_>> {
        let n = n.max(1);
        let acquire = self.sem.acquire_many(n);
        tokio::pin!(acquire);
        loop {
            tokio::select! {
                r = &mut acquire => {
                    return r.map_err(|_| {
                        Error::connection("SMB connection closed while waiting for credits")
                    });
                }
                _ = tokio::time::sleep(Duration::from_secs(2)) => {
                    if n as usize > self.window() && self.outstanding() == 0 {
                        return Err(Error::new(
                            ErrorKind::Throttled,
                            format!(
                                "SMB server credit window ({}) is smaller than the request's charge ({n})",
                                self.window()
                            ),
                        ));
                    }
                }
            }
        }
    }

    /// Commit `permit` (charging `n` credits) and allocate `n` consecutive
    /// MessageIds, returning the first. Must be called synchronously right
    /// before the request is queued for sending.
    pub fn commit(&self, permit: SemaphorePermit<'_>, n: u32) -> u64 {
        permit.forget();
        self.outstanding.fetch_add(i64::from(n), Ordering::AcqRel);
        self.next_mid.fetch_add(u64::from(n), Ordering::AcqRel)
    }

    /// A response arrived: `granted` new credits, and (once per request)
    /// the request's `charge` is settled.
    pub fn on_response(&self, granted: u16, settled_charge: u32) {
        if settled_charge > 0 {
            self.outstanding
                .fetch_sub(i64::from(settled_charge), Ordering::AcqRel);
        }
        if granted > 0 {
            self.sem.add_permits(usize::from(granted));
        }
    }

    /// The `CreditRequest` for a request charging `charge`: the charge plus
    /// a share of the deficit towards the target window, so the window grows
    /// quickly to the target and then stays there.
    pub fn request_for(&self, charge: u16) -> u16 {
        let window = self.window() as u32;
        let deficit = self.target.saturating_sub(window).min(512);
        (u32::from(charge.max(1)) + deficit).min(u32::from(u16::MAX)) as u16
    }

    /// Fail every current and future `acquire`.
    pub fn close(&self) {
        self.sem.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charge_formula() {
        assert_eq!(charge_for(0), 1);
        assert_eq!(charge_for(1), 1);
        assert_eq!(charge_for(65536), 1);
        assert_eq!(charge_for(65537), 2);
        assert_eq!(charge_for(8 << 20), 128);
        assert_eq!(charge_for((8 << 20) + 1), 129);
    }

    #[tokio::test]
    async fn window_accounting_and_message_ids() {
        let c = Credits::new(64);
        assert_eq!(c.window(), 1);
        let p = c.acquire(1).await.unwrap();
        assert_eq!(c.commit(p, 1), 0);
        assert_eq!((c.available(), c.outstanding()), (0, 1));
        // NEGOTIATE response grants 10 credits.
        c.on_response(10, 1);
        assert_eq!((c.available(), c.outstanding()), (10, 0));
        // A multi-credit request takes consecutive ids.
        let p = c.acquire(4).await.unwrap();
        assert_eq!(c.commit(p, 4), 1);
        let p = c.acquire(1).await.unwrap();
        assert_eq!(c.commit(p, 1), 5);
        assert_eq!(c.window(), 10);
        assert_eq!(c.request_for(4), 4 + 54);
    }

    #[tokio::test]
    async fn waiters_block_until_credits_return_fifo() {
        let c = std::sync::Arc::new(Credits::new(64));
        c.on_response(3, 0); // 4 available
        let p = c.acquire(4).await.unwrap();
        c.commit(p, 4);
        let c2 = c.clone();
        let big = tokio::spawn(async move {
            let p = c2.acquire(3).await.unwrap();
            c2.commit(p, 3)
        });
        tokio::task::yield_now().await;
        let c3 = c.clone();
        let small = tokio::spawn(async move {
            let p = c3.acquire(1).await.unwrap();
            c3.commit(p, 1)
        });
        tokio::task::yield_now().await;
        assert!(!big.is_finished() && !small.is_finished());
        // Two credits come back: not enough for the 3-credit waiter, and the
        // 1-credit waiter queued behind it must not overtake (FIFO).
        c.on_response(2, 2);
        tokio::task::yield_now().await;
        assert!(!big.is_finished() && !small.is_finished());
        c.on_response(2, 2);
        assert_eq!(big.await.unwrap(), 4);
        assert_eq!(small.await.unwrap(), 7);
    }

    #[tokio::test]
    async fn close_fails_waiters() {
        let c = std::sync::Arc::new(Credits::new(64));
        let p = c.acquire(1).await.unwrap();
        c.commit(p, 1);
        let c2 = c.clone();
        let w = tokio::spawn(async move { c2.acquire(1).await.map(|_| ()) });
        tokio::task::yield_now().await;
        c.close();
        let e = w.await.unwrap().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ConnectionFailed);
    }

    #[tokio::test(start_paused = true)]
    async fn impossible_charge_is_reported_not_hung() {
        let c = Credits::new(64);
        // Window of 1, nothing outstanding: a 4-credit request can never be granted.
        let e = c.acquire(4).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Throttled);
    }

    #[test]
    fn max_charge_is_half_the_window() {
        let c = Credits::new(64);
        assert_eq!(c.max_charge(), 1);
        c.on_response(255, 0);
        assert_eq!(c.max_charge(), 128);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Random request/response sequences: MessageIds are contiguous and
        /// unique, credits never go negative, the window is exactly
        /// "granted minus consumed", and charges are settled exactly once.
        #[test]
        fn window_invariants(ops in proptest::collection::vec((1u32..8, 0u16..16), 1..200)) {
            let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
            rt.block_on(async {
                let c = Credits::new(4096);
                c.on_response(64, 0); // 65 available
                let mut granted: i64 = 65;
                let mut consumed: i64 = 0;
                let mut next_mid = 0u64;
                let mut inflight: Vec<u32> = Vec::new();
                for (charge, grant) in ops {
                    if c.available() >= charge as usize {
                        let p = c.acquire(charge).await.unwrap();
                        let mid = c.commit(p, charge);
                        prop_assert_eq!(mid, next_mid);
                        next_mid += u64::from(charge);
                        consumed += i64::from(charge);
                        inflight.push(charge);
                    } else if let Some(ch) = inflight.pop() {
                        // Answer one request; never let the window collapse.
                        let g = grant.max(1);
                        c.on_response(g, ch);
                        granted += i64::from(g);
                    }
                    prop_assert_eq!(c.available() as i64, granted - consumed);
                    prop_assert_eq!(c.outstanding() as u32, inflight.iter().sum::<u32>());
                    prop_assert!(c.request_for(charge as u16) >= charge as u16);
                }
                Ok(())
            })?;
        }
    }
}
