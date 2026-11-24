//! Retries with exponential backoff and full jitter.
//!
//! [`retry`] re-runs an operation while it fails with an error for which
//! [`Error::is_retryable`] holds (timeouts, throttling, connection failures,
//! HTTP 500/502/503/504, or an explicit override). Delays follow the "full
//! jitter" scheme: before retry `k` (0-based) the delay is uniform in
//! `[0, min(max_delay, base_delay * 2^k)]`, which spreads synchronized
//! clients apart better than equal or decorrelated jitter.
//!
//! A server-provided `Retry-After` hint is honoured when the backend attaches
//! a [`RetryAfter`] to the error's source chain
//! (`Error::new(..).with_source(RetryAfter(d))`).
//!
//! **Idempotency is the caller's responsibility**: only wrap operations that
//! are safe to repeat (GET, HEAD, part uploads, PUT of a whole object, ...).

use std::fmt;
use std::future::Future;
use std::time::Duration;

use fsfast_core::{Error, ErrorKind, Result};
use tokio::time::Instant;

use crate::stats::Stats;

/// How often and how patiently to retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts including the first one; `1` disables retries
    /// (`0` is treated as `1`).
    pub max_attempts: u32,
    /// Backoff cap before the first retry.
    pub base_delay: Duration,
    /// Upper bound for any single delay (also caps `Retry-After` hints).
    pub max_delay: Duration,
    /// Deadline for the whole call, including attempts in flight. When it
    /// expires during an attempt the call fails with
    /// [`ErrorKind::Timeout`]; when the next backoff would cross it, the last
    /// error is returned without sleeping.
    pub total_timeout: Option<Duration>,
}

impl Default for RetryPolicy {
    /// 5 attempts, 100 ms base delay, 20 s maximum delay, no deadline.
    fn default() -> Self {
        RetryPolicy {
            max_attempts: 5,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(20),
            total_timeout: None,
        }
    }
}

impl RetryPolicy {
    /// A policy that never retries.
    pub fn none() -> Self {
        RetryPolicy {
            max_attempts: 1,
            ..RetryPolicy::default()
        }
    }

    /// Default policy with `max_attempts` total attempts.
    pub fn with_max_attempts(mut self, max_attempts: u32) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    /// Set the base delay.
    pub fn with_base_delay(mut self, d: Duration) -> Self {
        self.base_delay = d;
        self
    }

    /// Set the maximum single delay.
    pub fn with_max_delay(mut self, d: Duration) -> Self {
        self.max_delay = d;
        self
    }

    /// Set (or clear) the overall deadline.
    pub fn with_total_timeout(mut self, d: Option<Duration>) -> Self {
        self.total_timeout = d;
        self
    }

    /// Upper bound of the jittered delay before retry `retry` (0-based):
    /// `min(max_delay, base_delay * 2^retry)`.
    pub fn backoff_cap(&self, retry: u32) -> Duration {
        let factor = 1u32.checked_shl(retry.min(31)).unwrap_or(u32::MAX);
        self.base_delay
            .checked_mul(factor)
            .unwrap_or(self.max_delay)
            .min(self.max_delay)
    }

    /// A full-jitter delay for retry `retry` (0-based): uniform in
    /// `[0, backoff_cap(retry)]`.
    pub fn delay_for(&self, retry: u32) -> Duration {
        let cap = u64::try_from(self.backoff_cap(retry).as_nanos()).unwrap_or(u64::MAX);
        Duration::from_nanos(fastrand::u64(0..=cap))
    }
}

/// A server's request to wait before retrying (HTTP `Retry-After`, S3
/// `SlowDown` hints, ...). Attach it as the source of the returned error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryAfter(pub Duration);

impl fmt::Display for RetryAfter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "retry after {:?}", self.0)
    }
}

impl std::error::Error for RetryAfter {}

/// The [`RetryAfter`] hint in `err`'s source chain, if any.
pub fn retry_after_hint(err: &Error) -> Option<Duration> {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(err);
    while let Some(e) = cur {
        if let Some(r) = e.downcast_ref::<RetryAfter>() {
            return Some(r.0);
        }
        cur = e.source();
    }
    None
}

/// Information passed to a [`retry_notify`] callback before each retry.
#[derive(Debug)]
pub struct RetryEvent<'a> {
    /// The attempt that failed (1-based).
    pub attempt: u32,
    /// Its error.
    pub error: &'a Error,
    /// How long we wait before the next attempt.
    pub delay: Duration,
}

/// Run `op` until it succeeds, fails with a non-retryable error, or the
/// policy is exhausted. Returns the last error on failure.
pub async fn retry<T, F, Fut>(policy: &RetryPolicy, op: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    retry_notify(policy, op, |_| {}).await
}

/// [`retry`] that also counts retries and throttling errors in `stats`.
pub async fn retry_with_stats<T, F, Fut>(
    policy: &RetryPolicy,
    stats: &Stats,
    mut op: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    retry_notify(
        policy,
        || {
            let fut = op();
            async move {
                let res = fut.await;
                if let Err(e) = &res
                    && e.kind() == ErrorKind::Throttled
                {
                    stats.add_throttle();
                }
                res
            }
        },
        |_| stats.add_retry(),
    )
    .await
}

/// [`retry`] with a callback invoked before every retry (for logging or
/// metrics).
pub async fn retry_notify<T, F, Fut, N>(policy: &RetryPolicy, mut op: F, mut notify: N) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
    N: FnMut(&RetryEvent<'_>),
{
    let max_attempts = policy.max_attempts.max(1);
    // A deadline too far away to represent is no deadline.
    let deadline = policy
        .total_timeout
        .and_then(|t| Instant::now().checked_add(t));
    let mut attempt = 1u32;
    loop {
        let res = match deadline {
            None => op().await,
            Some(d) => match tokio::time::timeout_at(d, op()).await {
                Ok(r) => r,
                Err(_) => {
                    return Err(Error::timeout(format!(
                        "operation did not complete within {:?} ({attempt} attempt{})",
                        policy.total_timeout.unwrap_or_default(),
                        if attempt == 1 { "" } else { "s" }
                    )));
                }
            },
        };
        let err = match res {
            Ok(v) => return Ok(v),
            Err(e) => e,
        };
        if attempt >= max_attempts || !err.is_retryable() {
            return Err(err);
        }
        let mut delay = policy.delay_for(attempt - 1);
        if let Some(hint) = retry_after_hint(&err) {
            delay = delay.max(hint.min(policy.max_delay));
        }
        if let Some(d) = deadline
            && Instant::now()
                .checked_add(delay)
                .is_none_or(|wake| wake >= d)
        {
            return Err(err);
        }
        notify(&RetryEvent {
            attempt,
            error: &err,
            delay,
        });
        tracing::debug!(attempt, ?delay, error = %err, "retrying");
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        attempt += 1;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use fsfast_core::Detail;

    use super::*;

    fn throttled() -> Error {
        Error::new(ErrorKind::Throttled, "slow down").with_detail(Detail::Http(503))
    }

    #[tokio::test(start_paused = true)]
    async fn retries_until_success() {
        let calls = AtomicU32::new(0);
        let policy = RetryPolicy::default();
        let start = Instant::now();
        let v = retry(&policy, || async {
            if calls.fetch_add(1, Ordering::SeqCst) < 3 {
                Err(throttled())
            } else {
                Ok(42)
            }
        })
        .await
        .unwrap();
        assert_eq!(v, 42);
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        // Three delays, each bounded by its cap: 100 + 200 + 400 ms.
        assert!(start.elapsed() <= Duration::from_millis(700));
    }

    #[tokio::test(start_paused = true)]
    async fn non_retryable_fails_fast() {
        let calls = AtomicU32::new(0);
        let err = retry(&RetryPolicy::default(), || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(Error::not_found("k"))
        })
        .await
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn explicit_override_is_respected() {
        let calls = AtomicU32::new(0);
        let _ = retry(&RetryPolicy::default(), || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(Error::timeout("t").with_retryable(false))
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        calls.store(0, Ordering::SeqCst);
        let _ = retry(&RetryPolicy::default().with_max_attempts(3), || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(Error::new(ErrorKind::Io, "flaky").with_retryable(true))
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn attempts_exhausted_returns_last_error() {
        let calls = AtomicU32::new(0);
        let mut events = Vec::new();
        let err = retry_notify(
            &RetryPolicy::default().with_max_attempts(3),
            || async {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                Err::<(), _>(Error::connection(format!("attempt {n}")))
            },
            |ev| events.push((ev.attempt, ev.delay)),
        )
        .await
        .unwrap_err();
        assert_eq!(err.message(), "attempt 2");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, 1);
        assert!(events[0].1 <= Duration::from_millis(100));
        assert!(events[1].1 <= Duration::from_millis(200));
        assert_eq!(RetryPolicy::none().max_attempts, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn zero_attempts_means_one() {
        let calls = AtomicU32::new(0);
        let _ = retry(&RetryPolicy::default().with_max_attempts(0), || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(throttled())
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn backoff_caps_and_jitter_bounds() {
        let p = RetryPolicy::default()
            .with_base_delay(Duration::from_millis(10))
            .with_max_delay(Duration::from_secs(1));
        assert_eq!(p.backoff_cap(0), Duration::from_millis(10));
        assert_eq!(p.backoff_cap(3), Duration::from_millis(80));
        assert_eq!(p.backoff_cap(10), Duration::from_secs(1));
        assert_eq!(p.backoff_cap(u32::MAX), Duration::from_secs(1));
        for k in 0..40 {
            assert!(p.delay_for(k) <= p.backoff_cap(k));
        }
        // Full jitter actually varies.
        let samples: std::collections::HashSet<_> = (0..64).map(|_| p.delay_for(5)).collect();
        assert!(samples.len() > 10);
        // Huge base delays saturate at max_delay instead of overflowing.
        let big = RetryPolicy::default().with_base_delay(Duration::MAX);
        assert_eq!(big.backoff_cap(5), big.max_delay);
    }

    #[tokio::test(start_paused = true)]
    async fn retry_after_hint_is_honoured() {
        let calls = AtomicU32::new(0);
        let policy = RetryPolicy::default().with_base_delay(Duration::from_millis(1));
        let start = Instant::now();
        retry(&policy, || async {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(throttled().with_source(RetryAfter(Duration::from_secs(3))))
            } else {
                Ok(())
            }
        })
        .await
        .unwrap();
        assert!(start.elapsed() >= Duration::from_secs(3));
        let e =
            Error::new(ErrorKind::Throttled, "x").with_source(RetryAfter(Duration::from_secs(2)));
        assert_eq!(retry_after_hint(&e), Some(Duration::from_secs(2)));
        assert_eq!(retry_after_hint(&throttled()), None);
        // Hints are capped by max_delay.
        calls.store(0, Ordering::SeqCst);
        let capped = policy.clone().with_max_delay(Duration::from_millis(50));
        let start = Instant::now();
        retry(&capped, || async {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(throttled().with_source(RetryAfter(Duration::from_secs(3600))))
            } else {
                Ok(())
            }
        })
        .await
        .unwrap();
        assert!(start.elapsed() <= Duration::from_millis(50));
    }

    #[tokio::test(start_paused = true)]
    async fn total_timeout_bounds_attempts_and_backoff() {
        // A hanging attempt is cut off with a Timeout error.
        let policy = RetryPolicy::default().with_total_timeout(Some(Duration::from_secs(1)));
        let start = Instant::now();
        let err = retry(&policy, || async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok::<_, Error>(())
        })
        .await
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Timeout);
        assert_eq!(start.elapsed(), Duration::from_secs(1));

        // A backoff that would cross the deadline returns the last error now.
        let policy = RetryPolicy::default()
            .with_max_attempts(100)
            .with_base_delay(Duration::from_secs(10))
            .with_max_delay(Duration::from_secs(10))
            .with_total_timeout(Some(Duration::from_millis(500)));
        let calls = AtomicU32::new(0);
        let err = retry(&policy, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(
                Error::new(ErrorKind::Throttled, "slow")
                    .with_source(RetryAfter(Duration::from_secs(10))),
            )
        })
        .await
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Throttled);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// An absurd hint (or `max_delay = Duration::MAX`) with a deadline must
    /// give up cleanly instead of overflowing `Instant` arithmetic.
    #[tokio::test(start_paused = true)]
    async fn huge_delays_with_a_deadline_do_not_overflow() {
        let policy = RetryPolicy::default()
            .with_base_delay(Duration::MAX)
            .with_max_delay(Duration::MAX)
            .with_total_timeout(Some(Duration::from_secs(1)));
        let calls = AtomicU32::new(0);
        let err = retry(&policy, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(throttled().with_source(RetryAfter(Duration::MAX)))
        })
        .await
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Throttled);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Same with an overflowing deadline: it is treated as no deadline.
        let policy = RetryPolicy::default()
            .with_max_attempts(2)
            .with_base_delay(Duration::from_millis(1))
            .with_total_timeout(Some(Duration::MAX));
        calls.store(0, Ordering::SeqCst);
        let _ = retry(&policy, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(throttled())
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(crate::proptest_cases(256)))]

        /// Caps grow monotonically as `base * 2^k` up to `max_delay`, and
        /// full-jitter delays stay within `[0, cap]`.
        #[test]
        fn backoff_is_bounded_and_monotone(
            base_us in 0u64..10_000_000,
            max_us in 0u64..100_000_000,
            k in 0u32..80,
        ) {
            let p = RetryPolicy::default()
                .with_base_delay(Duration::from_micros(base_us))
                .with_max_delay(Duration::from_micros(max_us));
            let cap = p.backoff_cap(k);
            proptest::prop_assert!(cap <= p.max_delay);
            proptest::prop_assert!(cap <= p.backoff_cap(k + 1));
            let exact = u64::try_from(1u128 << k.min(31))
                .ok()
                .and_then(|f| base_us.checked_mul(f))
                .map(Duration::from_micros);
            if let Some(e) = exact.filter(|_| k <= 31) {
                proptest::prop_assert_eq!(cap, e.min(p.max_delay));
            }
            for _ in 0..8 {
                proptest::prop_assert!(p.delay_for(k) <= cap);
            }
        }

        /// The operation runs exactly `min(failures + 1, max_attempts)`
        /// times for retryable errors (once for others), succeeds iff it
        /// got to an attempt that does not fail, and every retry is counted.
        #[test]
        fn attempts_are_counted_exactly(
            max_attempts in 0u32..8,
            failures in 0u32..10,
            retryable in proptest::bool::ANY,
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .start_paused(true)
                .build()
                .unwrap();
            let stats = Stats::new();
            let calls = AtomicU32::new(0);
            let res = rt.block_on(retry_with_stats(&RetryPolicy::default().with_max_attempts(max_attempts), &stats, || async {
                if calls.fetch_add(1, Ordering::SeqCst) < failures {
                    Err(Error::new(ErrorKind::Io, "x").with_retryable(retryable))
                } else {
                    Ok(())
                }
            }));
            let attempts = max_attempts.max(1);
            let expect_calls = if retryable { (failures + 1).min(attempts) } else { 1 };
            let calls = calls.load(Ordering::SeqCst);
            proptest::prop_assert_eq!(calls, expect_calls);
            proptest::prop_assert_eq!(res.is_ok(), calls > failures);
            proptest::prop_assert_eq!(stats.snapshot().retries, u64::from(calls - 1));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stats_hooks_count_retries_and_throttles() {
        let stats = Stats::new();
        let calls = AtomicU32::new(0);
        let r = retry_with_stats(&RetryPolicy::default(), &stats, || async {
            match calls.fetch_add(1, Ordering::SeqCst) {
                0 | 1 => Err(throttled()),
                2 => Err(Error::connection("reset")),
                _ => Ok(7),
            }
        })
        .await
        .unwrap();
        assert_eq!(r, 7);
        let s = stats.snapshot();
        assert_eq!(s.retries, 3);
        assert_eq!(s.throttles, 2);

        // A final throttled failure is counted as a throttle but not a retry.
        let stats = Stats::new();
        let _ = retry_with_stats(&RetryPolicy::none(), &stats, || async {
            Err::<(), _>(throttled())
        })
        .await;
        assert_eq!(stats.snapshot().throttles, 1);
        assert_eq!(stats.snapshot().retries, 0);
    }
}
