//! Request counters and latency histograms (`fs.stats()` in Python).
//!
//! [`Stats`] is lock-free: every update is a relaxed atomic add, so it can be
//! shared (`Arc<Stats>`) by every request of a filesystem instance without
//! contention. [`Stats::snapshot`] produces a plain [`StatsSnapshot`].
//!
//! Counting conventions:
//! * `requests` / `errors` and the per-operation latency histograms are
//!   recorded by the backend once per wire request
//!   ([`Stats::record_request`] or [`Stats::measure`]), including each retry
//!   attempt.
//! * `retries` / `throttles` are recorded by
//!   [`retry_with_stats`](crate::retry::retry_with_stats).
//! * `bytes_read` / `bytes_written` count payload bytes on the wire.

use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

use fsfast_core::Result;
use tokio::time::Instant;

/// Operation category for latency histograms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OpKind {
    /// Metadata lookup (HEAD, stat, QUERY_INFO).
    Info,
    /// Directory / prefix listing.
    List,
    /// Data read (ranged GET, SMB READ, SFTP READ).
    Read,
    /// Data write (PUT, part upload, SMB WRITE).
    Write,
    /// Deletion (single or batch).
    Delete,
    /// Server-side copy or rename.
    Copy,
    /// Opening a handle / session setup.
    Open,
    /// Closing a handle, completing an upload.
    Close,
    /// Anything else.
    Other,
}

impl OpKind {
    /// Number of variants.
    pub const COUNT: usize = 9;

    /// All variants in declaration order.
    pub const ALL: [OpKind; OpKind::COUNT] = [
        OpKind::Info,
        OpKind::List,
        OpKind::Read,
        OpKind::Write,
        OpKind::Delete,
        OpKind::Copy,
        OpKind::Open,
        OpKind::Close,
        OpKind::Other,
    ];

    /// Stable lower-case name (used as dict key in Python).
    pub fn as_str(self) -> &'static str {
        match self {
            OpKind::Info => "info",
            OpKind::List => "list",
            OpKind::Read => "read",
            OpKind::Write => "write",
            OpKind::Delete => "delete",
            OpKind::Copy => "copy",
            OpKind::Open => "open",
            OpKind::Close => "close",
            OpKind::Other => "other",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

impl fmt::Display for OpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// Log-linear buckets over microseconds: values below 4 µs get one bucket
// each; above that every power of two is split into 4 linear sub-buckets
// (relative error <= 25%). Values >= 2^40 µs (~12.7 days) share the last
// bucket.
const SUB_BITS: u32 = 2;
const SUB: usize = 1 << SUB_BITS;
const MAX_EXP: u32 = 40;
const BUCKETS: usize = SUB + (MAX_EXP - SUB_BITS) as usize * SUB;

fn bucket_index(us: u64) -> usize {
    if us < SUB as u64 {
        return us as usize;
    }
    let exp = 63 - us.leading_zeros();
    if exp >= MAX_EXP {
        return BUCKETS - 1;
    }
    let sub = ((us >> (exp - SUB_BITS)) & (SUB as u64 - 1)) as usize;
    SUB + (exp - SUB_BITS) as usize * SUB + sub
}

/// `[lo, hi)` in microseconds covered by bucket `i`.
fn bucket_bounds(i: usize) -> (u64, u64) {
    if i < SUB {
        return (i as u64, i as u64 + 1);
    }
    let exp = ((i - SUB) / SUB) as u32 + SUB_BITS;
    let s = ((i - SUB) % SUB) as u64;
    let shift = exp - SUB_BITS;
    ((SUB as u64 + s) << shift, (SUB as u64 + s + 1) << shift)
}

/// Lock-free latency histogram with log-linear microsecond buckets.
pub struct LatencyHistogram {
    count: AtomicU64,
    sum_us: AtomicU64,
    min_us: AtomicU64,
    max_us: AtomicU64,
    buckets: Box<[AtomicU64]>,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        LatencyHistogram {
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
            min_us: AtomicU64::new(u64::MAX),
            max_us: AtomicU64::new(0),
            buckets: (0..BUCKETS).map(|_| AtomicU64::new(0)).collect(),
        }
    }
}

impl fmt::Debug for LatencyHistogram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.snapshot(), f)
    }
}

impl LatencyHistogram {
    /// Record one sample.
    pub fn record(&self, latency: Duration) {
        let us = u64::try_from(latency.as_micros()).unwrap_or(u64::MAX);
        self.count.fetch_add(1, Relaxed);
        self.sum_us.fetch_add(us, Relaxed);
        self.min_us.fetch_min(us, Relaxed);
        self.max_us.fetch_max(us, Relaxed);
        self.buckets[bucket_index(us)].fetch_add(1, Relaxed);
    }

    /// Number of samples recorded.
    pub fn count(&self) -> u64 {
        self.count.load(Relaxed)
    }

    /// Point-in-time copy (individual fields are read independently, so a
    /// snapshot taken during concurrent updates may be off by in-flight samples).
    pub fn snapshot(&self) -> HistogramSnapshot {
        let count = self.count.load(Relaxed);
        if count == 0 {
            return HistogramSnapshot::default();
        }
        let buckets = self
            .buckets
            .iter()
            .enumerate()
            .filter_map(|(i, b)| {
                let n = b.load(Relaxed);
                (n > 0).then_some((i as u16, n))
            })
            .collect();
        HistogramSnapshot {
            count,
            sum_us: self.sum_us.load(Relaxed),
            min_us: self.min_us.load(Relaxed),
            max_us: self.max_us.load(Relaxed),
            buckets,
        }
    }

    fn reset(&self) {
        self.count.store(0, Relaxed);
        self.sum_us.store(0, Relaxed);
        self.min_us.store(u64::MAX, Relaxed);
        self.max_us.store(0, Relaxed);
        for b in self.buckets.iter() {
            b.store(0, Relaxed);
        }
    }
}

/// Immutable copy of a [`LatencyHistogram`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistogramSnapshot {
    /// Number of samples.
    pub count: u64,
    /// Sum of all samples in microseconds.
    pub sum_us: u64,
    /// Smallest sample in microseconds (0 when empty).
    pub min_us: u64,
    /// Largest sample in microseconds.
    pub max_us: u64,
    /// Non-empty buckets as `(bucket index, count)`, ascending.
    buckets: Vec<(u16, u64)>,
}

impl HistogramSnapshot {
    /// Mean latency, `None` when empty.
    pub fn mean(&self) -> Option<Duration> {
        (self.count > 0).then(|| Duration::from_micros(self.sum_us / self.count))
    }

    /// Smallest sample, `None` when empty.
    pub fn min(&self) -> Option<Duration> {
        (self.count > 0).then(|| Duration::from_micros(self.min_us))
    }

    /// Largest sample, `None` when empty.
    pub fn max(&self) -> Option<Duration> {
        (self.count > 0).then(|| Duration::from_micros(self.max_us))
    }

    /// Estimated quantile (`q` in `[0, 1]`, e.g. `0.99`), interpolated
    /// linearly within a bucket and clamped to the observed min/max.
    pub fn quantile(&self, q: f64) -> Option<Duration> {
        if self.count == 0 {
            return None;
        }
        let q = if q.is_nan() { 0.5 } else { q.clamp(0.0, 1.0) };
        if q == 0.0 {
            return self.min();
        }
        if q == 1.0 {
            return self.max();
        }
        let rank = ((q * self.count as f64).ceil() as u64).clamp(1, self.count);
        let mut seen = 0u64;
        for &(i, n) in &self.buckets {
            if seen + n >= rank {
                let (lo, hi) = bucket_bounds(i as usize);
                let frac = (rank - seen) as f64 / n as f64;
                let est = lo as f64 + (hi - lo) as f64 * frac;
                let est = (est as u64).clamp(self.min_us, self.max_us);
                return Some(Duration::from_micros(est));
            }
            seen += n;
        }
        self.max()
    }

    /// Non-empty buckets as `(lower bound, upper bound, count)` in
    /// microseconds, ascending; bounds are `[lo, hi)`.
    pub fn buckets(&self) -> impl Iterator<Item = (u64, u64, u64)> + '_ {
        self.buckets.iter().map(|&(i, n)| {
            let (lo, hi) = bucket_bounds(i as usize);
            (lo, hi, n)
        })
    }
}

/// Atomic counters plus one latency histogram per [`OpKind`].
#[derive(Default)]
pub struct Stats {
    requests: AtomicU64,
    errors: AtomicU64,
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
    retries: AtomicU64,
    throttles: AtomicU64,
    latency: [LatencyHistogram; OpKind::COUNT],
}

impl fmt::Debug for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.snapshot(), f)
    }
}

impl Stats {
    /// Fresh, zeroed counters.
    pub fn new() -> Self {
        Stats::default()
    }

    /// Record one completed wire request.
    pub fn record_request(&self, op: OpKind, latency: Duration, ok: bool) {
        self.requests.fetch_add(1, Relaxed);
        if !ok {
            self.errors.fetch_add(1, Relaxed);
        }
        self.latency[op.index()].record(latency);
    }

    /// Run `fut` as one request of kind `op`, recording its latency and
    /// whether it failed.
    pub async fn measure<T, Fut>(&self, op: OpKind, fut: Fut) -> Result<T>
    where
        Fut: Future<Output = Result<T>>,
    {
        let start = Instant::now();
        let res = fut.await;
        self.record_request(op, start.elapsed(), res.is_ok());
        res
    }

    /// Count payload bytes received.
    pub fn add_bytes_read(&self, n: u64) {
        self.bytes_read.fetch_add(n, Relaxed);
    }

    /// Count payload bytes sent.
    pub fn add_bytes_written(&self, n: u64) {
        self.bytes_written.fetch_add(n, Relaxed);
    }

    /// Count one retry attempt.
    pub fn add_retry(&self) {
        self.retries.fetch_add(1, Relaxed);
    }

    /// Count one throttling response (HTTP 429/503 SlowDown, SMB credit stall).
    pub fn add_throttle(&self) {
        self.throttles.fetch_add(1, Relaxed);
    }

    /// Count one failed request that was not recorded through
    /// [`Stats::record_request`].
    pub fn add_error(&self) {
        self.errors.fetch_add(1, Relaxed);
    }

    /// The histogram for `op`.
    pub fn latency(&self, op: OpKind) -> &LatencyHistogram {
        &self.latency[op.index()]
    }

    /// Point-in-time copy of every counter and histogram.
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            requests: self.requests.load(Relaxed),
            errors: self.errors.load(Relaxed),
            bytes_read: self.bytes_read.load(Relaxed),
            bytes_written: self.bytes_written.load(Relaxed),
            retries: self.retries.load(Relaxed),
            throttles: self.throttles.load(Relaxed),
            latency: std::array::from_fn(|i| self.latency[i].snapshot()),
        }
    }

    /// Zero every counter and histogram.
    pub fn reset(&self) {
        for c in [
            &self.requests,
            &self.errors,
            &self.bytes_read,
            &self.bytes_written,
            &self.retries,
            &self.throttles,
        ] {
            c.store(0, Relaxed);
        }
        for h in &self.latency {
            h.reset();
        }
    }
}

/// Plain copy of [`Stats`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// Wire requests issued (each retry attempt counts).
    pub requests: u64,
    /// Requests that failed.
    pub errors: u64,
    /// Payload bytes received.
    pub bytes_read: u64,
    /// Payload bytes sent.
    pub bytes_written: u64,
    /// Retry attempts.
    pub retries: u64,
    /// Throttling responses.
    pub throttles: u64,
    latency: [HistogramSnapshot; OpKind::COUNT],
}

impl StatsSnapshot {
    /// Latency histogram for `op`.
    pub fn latency(&self, op: OpKind) -> &HistogramSnapshot {
        &self.latency[op.index()]
    }

    /// Requests recorded for `op`.
    pub fn requests_for(&self, op: OpKind) -> u64 {
        self.latency[op.index()].count
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use fsfast_core::Error;
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn bucket_layout_is_contiguous() {
        let mut expect_lo = 0;
        for i in 0..BUCKETS {
            let (lo, hi) = bucket_bounds(i);
            assert_eq!(lo, expect_lo, "bucket {i}");
            assert!(hi > lo);
            assert_eq!(bucket_index(lo), i);
            assert_eq!(bucket_index(hi - 1), i);
            expect_lo = hi;
        }
        assert_eq!(bucket_index(u64::MAX), BUCKETS - 1);
    }

    proptest! {
        #[test]
        fn value_falls_in_its_bucket(us in 0u64..(1u64 << 40)) {
            let (lo, hi) = bucket_bounds(bucket_index(us));
            prop_assert!(lo <= us && us < hi);
            // relative bucket width <= 25% above the exact range
            if us >= 4 { prop_assert!((hi - lo) * 4 <= lo); }
        }
    }

    #[test]
    fn quantiles() {
        let h = LatencyHistogram::default();
        assert_eq!(h.snapshot().quantile(0.5), None);
        for ms in 1..=100u64 {
            h.record(Duration::from_millis(ms));
        }
        let s = h.snapshot();
        assert_eq!(s.count, 100);
        assert_eq!(s.min(), Some(Duration::from_millis(1)));
        assert_eq!(s.max(), Some(Duration::from_millis(100)));
        assert_eq!(s.mean(), Some(Duration::from_micros(50_500)));
        let p50 = s.quantile(0.5).unwrap().as_micros() as f64;
        assert!((p50 - 50_000.0).abs() / 50_000.0 < 0.25, "{p50}");
        let p99 = s.quantile(0.99).unwrap().as_micros() as f64;
        assert!((p99 - 99_000.0).abs() / 99_000.0 < 0.25, "{p99}");
        assert_eq!(s.quantile(1.0), Some(Duration::from_millis(100)));
        assert_eq!(s.quantile(0.0), Some(Duration::from_millis(1)));
        assert_eq!(s.buckets().map(|b| b.2).sum::<u64>(), 100);
    }

    #[tokio::test(start_paused = true)]
    async fn counters_and_measure() {
        let st = Arc::new(Stats::new());
        st.add_bytes_read(10);
        st.add_bytes_written(20);
        st.add_retry();
        st.add_throttle();
        st.add_error();
        let ok: Result<u8> = st
            .measure(OpKind::Read, async {
                tokio::time::sleep(Duration::from_millis(5)).await;
                Ok(1)
            })
            .await;
        assert_eq!(ok.unwrap(), 1);
        let err: Result<u8> = st
            .measure(OpKind::Info, async { Err(Error::not_found("x")) })
            .await;
        assert!(err.is_err());
        let s = st.snapshot();
        assert_eq!(s.requests, 2);
        assert_eq!(s.errors, 2);
        assert_eq!((s.bytes_read, s.bytes_written), (10, 20));
        assert_eq!((s.retries, s.throttles), (1, 1));
        assert_eq!(s.requests_for(OpKind::Read), 1);
        assert_eq!(s.requests_for(OpKind::Info), 1);
        assert_eq!(
            s.latency(OpKind::Read).min(),
            Some(Duration::from_millis(5))
        );
        assert_eq!(st.latency(OpKind::Write).count(), 0);
        st.reset();
        assert_eq!(st.snapshot(), StatsSnapshot::default());
    }

    #[test]
    fn opkind_names() {
        for (i, op) in OpKind::ALL.iter().enumerate() {
            assert_eq!(op.index(), i);
            assert!(!op.as_str().is_empty());
        }
    }
}
