//! Adaptive concurrency limiting (AIMD).
//!
//! An [`AimdLimiter`] bounds the number of requests in flight to an endpoint
//! and adapts the bound to what the endpoint tolerates:
//!
//! * **Additive increase**: after `limit` successful requests (about one
//!   round trip's worth) the limit grows by one, but only while the limiter is
//!   actually utilized (at least half the permits in use when the request
//!   started), so an idle limiter does not drift to its maximum.
//! * **Multiplicative decrease**: a throttling signal ([`Outcome::Throttled`],
//!   e.g. HTTP 503 SlowDown / 429) or latency inflation (short-term latency
//!   average above `latency_tolerance` times the long-term average)
//!   multiplies the limit by `backoff_ratio`. Only requests started *after*
//!   the last decrease can trigger another one, so a burst of throttles from
//!   one window shrinks the limit once, not once per request.
//!
//! The fast path is lock-free: permits come from a tokio semaphore, and the
//! limit, epoch and latency averages are atomics. Shrinking while permits are
//! held is handled by the internal elastic semaphore's debt counter.

use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use fsfast_core::{ErrorKind, Result};
use tokio::time::Instant;

use crate::elastic::{ElasticSemaphore, MAX_PERMITS};

/// Smoothing factor of the short-term latency average.
const ALPHA_SHORT: f64 = 0.2;
/// Smoothing factor of the long-term latency average.
const ALPHA_LONG: f64 = 0.02;

/// Configuration of an [`AimdLimiter`].
#[derive(Debug, Clone, PartialEq)]
pub struct AimdConfig {
    /// Lower bound of the limit (at least 1).
    pub min_limit: usize,
    /// Starting limit (clamped to `[min_limit, max_limit]`).
    pub initial_limit: usize,
    /// Upper bound of the limit.
    pub max_limit: usize,
    /// Factor applied on a congestion signal, in `(0, 1)`.
    pub backoff_ratio: f64,
    /// Treat a request as a congestion signal when the short-term latency
    /// average exceeds this multiple of the long-term average. `None`
    /// disables latency-based decrease (useful when request sizes vary
    /// wildly).
    pub latency_tolerance: Option<f64>,
    /// Latency inflation must also exceed the long-term average by at least
    /// this much (ignores jitter on sub-millisecond requests).
    pub latency_floor: Duration,
    /// Samples needed before latency inflation is evaluated.
    pub latency_warmup: u32,
}

impl Default for AimdConfig {
    /// `1..=256`, starting at 16, backoff 0.7, latency tolerance 2x (1 ms
    /// floor, 20 samples warm-up).
    fn default() -> Self {
        AimdConfig {
            min_limit: 1,
            initial_limit: 16,
            max_limit: 256,
            backoff_ratio: 0.7,
            latency_tolerance: Some(2.0),
            latency_floor: Duration::from_millis(1),
            latency_warmup: 20,
        }
    }
}

impl AimdConfig {
    fn normalized(mut self) -> Self {
        self.min_limit = self.min_limit.clamp(1, MAX_PERMITS);
        self.max_limit = self.max_limit.clamp(self.min_limit, MAX_PERMITS);
        self.initial_limit = self.initial_limit.clamp(self.min_limit, self.max_limit);
        if !(self.backoff_ratio > 0.0 && self.backoff_ratio < 1.0) {
            self.backoff_ratio = AimdConfig::default().backoff_ratio;
        }
        if let Some(t) = self.latency_tolerance
            && !(t.is_finite() && t > 1.0)
        {
            self.latency_tolerance = None;
        }
        self
    }
}

/// How a request guarded by an [`AimdPermit`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Completed normally; counts toward additive increase and latency tracking.
    Success,
    /// The endpoint signalled overload (throttling, timeout): multiplicative
    /// decrease.
    Throttled,
    /// No signal about load (cancelled, or failed for an unrelated reason such
    /// as `NotFound`): the limit is unchanged. This is the default when a
    /// permit is dropped without reporting.
    Dropped,
}

impl Outcome {
    /// Classify a request result: `Ok` is a success, `Throttled` and
    /// `Timeout` errors are congestion signals, anything else is neutral.
    pub fn from_result<T>(r: &Result<T>) -> Outcome {
        match r {
            Ok(_) => Outcome::Success,
            Err(e) if matches!(e.kind(), ErrorKind::Throttled | ErrorKind::Timeout) => {
                Outcome::Throttled
            }
            Err(_) => Outcome::Dropped,
        }
    }
}

struct Inner {
    cfg: AimdConfig,
    sem: ElasticSemaphore,
    limit: AtomicUsize,
    in_flight: AtomicUsize,
    /// Incremented on every decrease; permits remember the epoch they were
    /// acquired in.
    epoch: AtomicU64,
    successes: AtomicUsize,
    /// f64 bits of the latency averages in microseconds; 0 = no sample yet.
    lat_short: AtomicU64,
    lat_long: AtomicU64,
    samples: AtomicU32,
}

/// Adaptive concurrency limiter. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct AimdLimiter {
    inner: Arc<Inner>,
}

impl fmt::Debug for AimdLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AimdLimiter")
            .field("limit", &self.limit())
            .field("in_flight", &self.in_flight())
            .finish()
    }
}

impl Default for AimdLimiter {
    fn default() -> Self {
        AimdLimiter::new(AimdConfig::default())
    }
}

impl AimdLimiter {
    /// Build a limiter; out-of-range configuration values are clamped.
    pub fn new(cfg: AimdConfig) -> Self {
        let cfg = cfg.normalized();
        let initial = cfg.initial_limit;
        AimdLimiter {
            inner: Arc::new(Inner {
                sem: ElasticSemaphore::new(initial),
                limit: AtomicUsize::new(initial),
                in_flight: AtomicUsize::new(0),
                epoch: AtomicU64::new(0),
                successes: AtomicUsize::new(0),
                lat_short: AtomicU64::new(0),
                lat_long: AtomicU64::new(0),
                samples: AtomicU32::new(0),
                cfg,
            }),
        }
    }

    /// The (normalized) configuration.
    pub fn config(&self) -> &AimdConfig {
        &self.inner.cfg
    }

    /// Current concurrency limit.
    pub fn limit(&self) -> usize {
        self.inner.limit.load(Ordering::Acquire)
    }

    /// Requests currently holding a permit (may briefly exceed the limit
    /// right after a decrease).
    pub fn in_flight(&self) -> usize {
        self.inner.in_flight.load(Ordering::Acquire)
    }

    /// Permits that can be acquired without waiting.
    pub fn available(&self) -> usize {
        self.inner.sem.available()
    }

    /// Wait for a permit (FIFO-fair, cancellation-safe).
    pub async fn acquire(&self) -> AimdPermit {
        self.inner.sem.acquire(1).await;
        self.permit()
    }

    /// A permit if one is available right now.
    pub fn try_acquire(&self) -> Option<AimdPermit> {
        self.inner.sem.try_acquire(1).then(|| self.permit())
    }

    fn permit(&self) -> AimdPermit {
        let inner = &self.inner;
        let in_flight = inner.in_flight.fetch_add(1, Ordering::AcqRel) + 1;
        let limit = inner.limit.load(Ordering::Acquire);
        AimdPermit {
            inner: inner.clone(),
            epoch: inner.epoch.load(Ordering::Acquire),
            start: Instant::now(),
            utilized: in_flight * 2 >= limit,
        }
    }

    /// Run `fut` under a permit and report its outcome via
    /// [`Outcome::from_result`].
    pub async fn run<T, Fut>(&self, fut: Fut) -> Result<T>
    where
        Fut: Future<Output = Result<T>>,
    {
        let permit = self.acquire().await;
        let res = fut.await;
        permit.record(&res);
        res
    }
}

impl Inner {
    fn on_success(&self, epoch: u64, latency: Duration, utilized: bool) {
        if self.latency_inflated(latency) {
            self.decrease(epoch, "latency inflation");
            return;
        }
        if !utilized {
            return;
        }
        let limit = self.limit.load(Ordering::Acquire);
        if limit >= self.cfg.max_limit {
            return;
        }
        let s = self.successes.fetch_add(1, Ordering::AcqRel) + 1;
        if s >= limit
            && self
                .successes
                .compare_exchange(s, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.increase();
        }
    }

    fn increase(&self) {
        let mut cur = self.limit.load(Ordering::Acquire);
        while cur < self.cfg.max_limit {
            match self.limit.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.sem.give(1);
                    tracing::trace!(limit = cur + 1, "aimd increase");
                    return;
                }
                Err(actual) => cur = actual,
            }
        }
    }

    fn decrease(&self, epoch: u64, reason: &'static str) {
        // Only one decrease per epoch: requests issued before the last
        // decrease reflect the old limit and must not shrink it again.
        if self
            .epoch
            .compare_exchange(epoch, epoch + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let mut cur = self.limit.load(Ordering::Acquire);
        loop {
            let new = ((cur as f64 * self.cfg.backoff_ratio) as usize).max(self.cfg.min_limit);
            if new >= cur {
                break;
            }
            match self
                .limit
                .compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    self.sem.take(cur - new);
                    tracing::debug!(from = cur, to = new, reason, "aimd decrease");
                    break;
                }
                Err(actual) => cur = actual,
            }
        }
        self.successes.store(0, Ordering::Release);
        // New latency evidence must accumulate before the next latency-based
        // decrease.
        self.lat_short
            .store(self.lat_long.load(Ordering::Acquire), Ordering::Release);
    }

    /// Update the latency averages; true when the sample indicates inflation.
    fn latency_inflated(&self, latency: Duration) -> bool {
        let Some(tol) = self.cfg.latency_tolerance else {
            return false;
        };
        let us = latency.as_secs_f64() * 1e6;
        let n = self
            .samples
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_or(u32::MAX, |n| n + 1);
        let long = ewma(&self.lat_long, us, ALPHA_LONG);
        let short = ewma(&self.lat_short, us, ALPHA_SHORT);
        let floor = self.cfg.latency_floor.as_secs_f64() * 1e6;
        n >= self.cfg.latency_warmup && short > long * tol && short - long > floor
    }
}

/// Lock-free exponentially weighted moving average over f64 bits.
fn ewma(cell: &AtomicU64, sample: f64, alpha: f64) -> f64 {
    let mut cur = cell.load(Ordering::Acquire);
    loop {
        let old = f64::from_bits(cur);
        let new = if cur == 0 {
            sample
        } else {
            old + alpha * (sample - old)
        };
        match cell.compare_exchange_weak(cur, new.to_bits(), Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return new,
            Err(actual) => cur = actual,
        }
    }
}

/// A slot in an [`AimdLimiter`]. Report how the request ended with one of
/// the consuming methods; dropping it without reporting counts as
/// [`Outcome::Dropped`].
#[must_use = "a permit is released as soon as it is dropped"]
pub struct AimdPermit {
    inner: Arc<Inner>,
    epoch: u64,
    start: Instant,
    utilized: bool,
}

impl fmt::Debug for AimdPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AimdPermit")
            .field("epoch", &self.epoch)
            .field("elapsed", &self.start.elapsed())
            .finish()
    }
}

impl AimdPermit {
    /// The request succeeded; latency is measured from acquisition.
    pub fn success(self) {
        let latency = self.start.elapsed();
        self.success_with_latency(latency);
    }

    /// The request succeeded with the given latency (e.g. time to first byte).
    pub fn success_with_latency(self, latency: Duration) {
        self.inner.on_success(self.epoch, latency, self.utilized);
    }

    /// The endpoint signalled overload.
    pub fn throttled(self) {
        self.inner.decrease(self.epoch, "throttled");
    }

    /// No load signal (cancelled or unrelated failure).
    pub fn dropped(self) {}

    /// Report an explicit outcome.
    pub fn report(self, outcome: Outcome) {
        match outcome {
            Outcome::Success => self.success(),
            Outcome::Throttled => self.throttled(),
            Outcome::Dropped => self.dropped(),
        }
    }

    /// Report the outcome of `res` via [`Outcome::from_result`].
    pub fn record<T>(self, res: &Result<T>) {
        self.report(Outcome::from_result(res));
    }
}

impl Drop for AimdPermit {
    fn drop(&mut self) {
        self.inner.in_flight.fetch_sub(1, Ordering::AcqRel);
        self.inner.sem.give(1);
    }
}

#[cfg(test)]
mod tests {
    use fsfast_core::Error;

    use super::*;

    fn cfg(min: usize, initial: usize, max: usize) -> AimdConfig {
        AimdConfig {
            min_limit: min,
            initial_limit: initial,
            max_limit: max,
            backoff_ratio: 0.5,
            latency_tolerance: None,
            ..AimdConfig::default()
        }
    }

    #[test]
    fn normalizes_config() {
        let l = AimdLimiter::new(AimdConfig {
            min_limit: 0,
            initial_limit: 1000,
            max_limit: 10,
            backoff_ratio: 7.0,
            latency_tolerance: Some(0.5),
            ..AimdConfig::default()
        });
        let c = l.config();
        assert_eq!((c.min_limit, c.initial_limit, c.max_limit), (1, 10, 10));
        assert_eq!(c.backoff_ratio, 0.7);
        assert_eq!(c.latency_tolerance, None);
        assert_eq!(l.limit(), 10);
        assert_eq!(l.available(), 10);
    }

    #[tokio::test(start_paused = true)]
    async fn enforces_limit() {
        let l = AimdLimiter::new(cfg(1, 2, 10));
        let a = l.acquire().await;
        let b = l.acquire().await;
        assert!(l.try_acquire().is_none());
        let l2 = l.clone();
        let waiter = tokio::spawn(async move { l2.acquire().await.dropped() });
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(!waiter.is_finished());
        assert_eq!(l.in_flight(), 2);
        a.dropped();
        waiter.await.unwrap();
        b.dropped();
        assert_eq!(l.in_flight(), 0);
        assert_eq!(l.available(), 2);
    }

    #[tokio::test]
    async fn additive_increase_needs_utilization() {
        let l = AimdLimiter::new(cfg(1, 4, 6));
        // Fully utilized: hold all permits, complete them, repeat. Permits
        // acquired while less than half the limit is in use do not count, so
        // 3 of every 4 successes count here and the limit grows in round 2.
        for _ in 0..2 {
            let permits: Vec<_> = (0..l.limit()).map(|_| l.try_acquire().unwrap()).collect();
            for p in permits {
                p.success();
            }
        }
        assert_eq!(l.limit(), 5);
        // Capped at max.
        for _ in 0..10 {
            let permits: Vec<_> = (0..l.limit()).map(|_| l.try_acquire().unwrap()).collect();
            permits.into_iter().for_each(AimdPermit::success);
        }
        assert_eq!(l.limit(), 6);
        assert_eq!(l.available(), 6);

        // Under-utilized (one request at a time with limit 6): no growth.
        let l = AimdLimiter::new(cfg(1, 6, 100));
        for _ in 0..100 {
            l.acquire().await.success();
        }
        assert_eq!(l.limit(), 6);
    }

    #[tokio::test]
    async fn multiplicative_decrease_once_per_epoch() {
        let l = AimdLimiter::new(cfg(2, 16, 64));
        let old: Vec<_> = (0..4).map(|_| l.try_acquire().unwrap()).collect();
        let mut old = old.into_iter();
        old.next().unwrap().throttled();
        assert_eq!(l.limit(), 8);
        // Other requests from the same window do not shrink it again.
        old.next().unwrap().throttled();
        old.next().unwrap().report(Outcome::Throttled);
        assert_eq!(l.limit(), 8);
        // A request started after the decrease does.
        l.try_acquire().unwrap().throttled();
        assert_eq!(l.limit(), 4);
        l.try_acquire().unwrap().throttled();
        l.try_acquire().unwrap().throttled();
        l.try_acquire().unwrap().throttled();
        assert_eq!(l.limit(), 2, "never below min");
        old.next().unwrap().dropped();
        assert_eq!(l.in_flight(), 0);
        assert_eq!(l.available(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn decrease_while_permits_are_held() {
        let l = AimdLimiter::new(cfg(1, 8, 8));
        let mut held: Vec<_> = (0..8).map(|_| l.try_acquire().unwrap()).collect();
        assert!(l.try_acquire().is_none());
        // A fresh-epoch throttle from one of the held permits halves the limit.
        held.pop().unwrap().throttled();
        assert_eq!(l.limit(), 4);
        // 7 still in flight against a limit of 4: nothing new may start until
        // in_flight drops below 4.
        for _ in 0..3 {
            held.pop().unwrap().dropped();
            assert!(l.try_acquire().is_none(), "in flight {}", l.in_flight());
        }
        assert_eq!(l.in_flight(), 4);
        held.pop().unwrap().dropped();
        let p = l.try_acquire().expect("below the limit again");
        drop(p);
        drop(held);
        assert_eq!(l.in_flight(), 0);
        assert_eq!(l.available(), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn latency_inflation_decreases() {
        let l = AimdLimiter::new(AimdConfig {
            min_limit: 1,
            initial_limit: 10,
            max_limit: 10,
            backoff_ratio: 0.5,
            latency_tolerance: Some(2.0),
            latency_floor: Duration::from_millis(1),
            latency_warmup: 10,
        });
        for _ in 0..50 {
            l.acquire()
                .await
                .success_with_latency(Duration::from_millis(10));
        }
        assert_eq!(l.limit(), 10);
        // Latency jumps 5x: the short-term average crosses 2x quickly.
        let mut decreased_after = None;
        for i in 0..20 {
            l.acquire()
                .await
                .success_with_latency(Duration::from_millis(50));
            if l.limit() < 10 {
                decreased_after = Some(i);
                break;
            }
        }
        assert!(
            decreased_after.is_some_and(|i| i < 10),
            "{decreased_after:?}"
        );
        assert_eq!(l.limit(), 5);

        // Disabled tolerance: no decrease.
        let l = AimdLimiter::new(cfg(1, 10, 10));
        for _ in 0..50 {
            l.acquire()
                .await
                .success_with_latency(Duration::from_millis(10));
        }
        for _ in 0..50 {
            l.acquire()
                .await
                .success_with_latency(Duration::from_secs(5));
        }
        assert_eq!(l.limit(), 10);
    }

    #[tokio::test(start_paused = true)]
    async fn measured_latency_uses_tokio_clock() {
        let l = AimdLimiter::new(AimdConfig {
            latency_warmup: 1,
            ..cfg(1, 4, 4)
        });
        let p = l.acquire().await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        p.success();
        assert_eq!(l.limit(), 4);
    }

    #[tokio::test]
    async fn run_classifies_results() {
        let l = AimdLimiter::new(cfg(1, 8, 8));
        assert_eq!(l.run(async { Ok(1) }).await.unwrap(), 1);
        assert_eq!(l.limit(), 8);
        let e = l
            .run(async { Err::<(), _>(Error::not_found("x")) })
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotFound);
        assert_eq!(l.limit(), 8, "neutral errors do not decrease");
        let _ = l.run(async { Err::<(), _>(Error::timeout("t")) }).await;
        assert_eq!(l.limit(), 4);
        let _ = l
            .run(async { Err::<(), _>(Error::new(ErrorKind::Throttled, "slow")) })
            .await;
        assert_eq!(l.limit(), 2);
        assert_eq!(l.in_flight(), 0);
        assert_eq!(Outcome::from_result::<()>(&Ok(())), Outcome::Success);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_stress_keeps_accounting_consistent() {
        let l = AimdLimiter::new(cfg(2, 8, 32));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for t in 0..16 {
            let l = l.clone();
            let max_seen = max_seen.clone();
            tasks.push(tokio::spawn(async move {
                for i in 0..300u32 {
                    let p = l.acquire().await;
                    max_seen.fetch_max(l.in_flight(), Ordering::Relaxed);
                    tokio::task::yield_now().await;
                    match (i + t) % 50 {
                        0 => p.throttled(),
                        1 => p.dropped(),
                        _ => p.success(),
                    }
                }
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(l.in_flight(), 0);
        let limit = l.limit();
        assert!((2..=32).contains(&limit));
        assert_eq!(l.available(), limit);
        assert!(max_seen.load(Ordering::Relaxed) <= 32);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(crate::proptest_cases(256)))]

        /// Under any sequence of acquisitions and outcomes the limit stays in
        /// `[min, max]`, a throttle never raises it, no new permit is handed
        /// out while `limit` or more are held (also right after a decrease),
        /// and once everything is released exactly `limit` permits are free.
        #[test]
        fn accounting_survives_any_outcome_sequence(
            min in 1usize..4,
            initial in 1usize..20,
            max in 1usize..24,
            steps in proptest::collection::vec((0u8..6, 0usize..8), 1..200),
        ) {
            let l = AimdLimiter::new(cfg(min, initial, max));
            let c = l.config().clone();
            let mut held: Vec<AimdPermit> = Vec::new();
            for (action, n) in steps {
                match action {
                    0 | 1 => {
                        while let Some(p) = l.try_acquire() {
                            held.push(p);
                            if held.len() > n { break; }
                        }
                    }
                    _ if held.is_empty() => {}
                    2 => held.remove(n % held.len()).success(),
                    3 => {
                        let before = l.limit();
                        held.remove(n % held.len()).throttled();
                        proptest::prop_assert!(l.limit() >= c.min_limit);
                        proptest::prop_assert!(l.limit() <= before);
                    }
                    4 => held.remove(n % held.len()).dropped(),
                    _ => drop(held.remove(n % held.len())),
                }
                let limit = l.limit();
                proptest::prop_assert!((c.min_limit..=c.max_limit).contains(&limit));
                proptest::prop_assert_eq!(l.in_flight(), held.len());
                // New permits only while below the limit.
                if l.try_acquire().is_some() {
                    proptest::prop_assert!(held.len() < limit, "{} held, limit {}", held.len(), limit);
                }
            }
            drop(held);
            proptest::prop_assert_eq!(l.in_flight(), 0);
            proptest::prop_assert_eq!(l.available(), l.limit());
        }
    }

    #[test]
    fn permit_is_send() {
        fn check<T: Send + Sync + 'static>() {}
        check::<AimdPermit>();
        check::<AimdLimiter>();
    }
}
