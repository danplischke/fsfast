//! In-memory mocks for tests and benchmarks (feature `testing`).
//!
//! * [`MemReadHandle`]: a [`ReadHandle`] over a `Bytes` buffer with optional
//!   latency (tokio time, so `start_paused` tests run instantly), jitter,
//!   bandwidth limit, fault injection, and counters (requests, bytes,
//!   in-flight peak, request log).
//! * [`MemPartSink`]: a [`PartSink`] that stores parts in memory, with the
//!   same latency/fault/counter knobs.
//! * [`pattern`]: deterministic test data in which every offset is
//!   distinguishable.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use fsfast_core::{Error, ErrorKind, FileInfo, IoHints, ReadHandle, Result};
use parking_lot::Mutex;

use crate::upload::{PartOutcome, PartSink};

/// `len` deterministic pseudo-random bytes (a prefix of one fixed stream)
/// without any structured period, so data read from the wrong offset is
/// detected: for any shift only ~1/256 of the bytes coincide.
///
/// (An arithmetic pattern such as `i % 251 + i / 251` repeats under shifts
/// that are multiples of 250, which includes common test block sizes.)
pub fn pattern(len: usize) -> Bytes {
    /// SplitMix64 finalizer.
    fn mix(word: u64) -> u64 {
        let mut z = word.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    let mut v = Vec::with_capacity(len);
    let mut word = 0u64;
    while v.len() < len {
        let take = (len - v.len()).min(8);
        v.extend_from_slice(&mix(word).to_le_bytes()[..take]);
        word += 1;
    }
    Bytes::from(v)
}

/// Describes one read request, for fault injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadRequest {
    /// 0-based sequence number of the request on this handle.
    pub index: u64,
    /// Requested offset.
    pub offset: u64,
    /// Requested length.
    pub len: usize,
}

type ReadFault = Box<dyn Fn(&ReadRequest) -> Option<Error> + Send + Sync>;

/// Increments a gauge for the lifetime of the value and tracks its peak.
struct Gauge<'a>(&'a AtomicUsize);

impl<'a> Gauge<'a> {
    fn enter(cur: &'a AtomicUsize, peak: &AtomicUsize) -> Self {
        let n = cur.fetch_add(1, Ordering::SeqCst) + 1;
        peak.fetch_max(n, Ordering::SeqCst);
        Gauge(cur)
    }
}

impl Drop for Gauge<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn delay(latency: Duration, jitter: Duration, bandwidth: Option<u64>, len: usize) -> Duration {
    let mut d = latency;
    if !jitter.is_zero() {
        d += Duration::from_nanos(fastrand::u64(0..=jitter.as_nanos() as u64));
    }
    if let Some(bps) = bandwidth.filter(|b| *b > 0) {
        d += Duration::from_secs_f64(len as f64 / bps as f64);
    }
    d
}

/// In-memory [`ReadHandle`] with latency and fault injection.
pub struct MemReadHandle {
    info: FileInfo,
    data: Bytes,
    hints: IoHints,
    latency: Duration,
    jitter: Duration,
    bandwidth: Option<u64>,
    fault: Mutex<Option<ReadFault>>,
    log_requests: bool,
    log: Mutex<Vec<Range<u64>>>,
    requests: AtomicU64,
    bytes: AtomicU64,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
}

impl fmt::Debug for MemReadHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemReadHandle")
            .field("size", &self.data.len())
            .field("requests", &self.requests())
            .finish()
    }
}

impl MemReadHandle {
    /// A handle named `mem/file` over `data`, with default [`IoHints`].
    pub fn new(data: impl Into<Bytes>) -> Self {
        let data = data.into();
        MemReadHandle {
            info: FileInfo::file("mem/file", data.len() as u64),
            data,
            hints: IoHints::default(),
            latency: Duration::ZERO,
            jitter: Duration::ZERO,
            bandwidth: None,
            fault: Mutex::new(None),
            log_requests: true,
            log: Mutex::new(Vec::new()),
            requests: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(0),
        }
    }

    /// Override the I/O hints.
    pub fn with_hints(mut self, hints: IoHints) -> Self {
        self.hints = hints;
        self
    }

    /// Every request sleeps `latency` plus a uniform random `[0, jitter]`.
    pub fn with_latency(mut self, latency: Duration, jitter: Duration) -> Self {
        self.latency = latency;
        self.jitter = jitter;
        self
    }

    /// Add `len / bytes_per_sec` to every request's delay.
    pub fn with_bandwidth(mut self, bytes_per_sec: u64) -> Self {
        self.bandwidth = Some(bytes_per_sec);
        self
    }

    /// Disable the request log (benchmarks).
    pub fn without_log(mut self) -> Self {
        self.log_requests = false;
        self
    }

    /// Fail requests for which `f` returns an error (checked after the delay).
    pub fn set_fault(&self, f: impl Fn(&ReadRequest) -> Option<Error> + Send + Sync + 'static) {
        *self.fault.lock() = Some(Box::new(f));
    }

    /// Remove the fault injector.
    pub fn clear_fault(&self) {
        *self.fault.lock() = None;
    }

    /// The underlying data.
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Requests started.
    pub fn requests(&self) -> u64 {
        self.requests.load(Ordering::SeqCst)
    }

    /// Bytes returned.
    pub fn bytes_served(&self) -> u64 {
        self.bytes.load(Ordering::SeqCst)
    }

    /// Requests currently running (dropped futures count as finished).
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Peak of [`MemReadHandle::in_flight`].
    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(Ordering::SeqCst)
    }

    /// Ranges requested so far, in start order.
    pub fn requested(&self) -> Vec<Range<u64>> {
        self.log.lock().clone()
    }

    /// Reset counters and the request log.
    pub fn reset_counters(&self) {
        self.requests.store(0, Ordering::SeqCst);
        self.bytes.store(0, Ordering::SeqCst);
        self.max_in_flight.store(self.in_flight(), Ordering::SeqCst);
        self.log.lock().clear();
    }
}

#[async_trait]
impl ReadHandle for MemReadHandle {
    fn info(&self) -> &FileInfo {
        &self.info
    }

    fn io_hints(&self) -> IoHints {
        self.hints
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        let index = self.requests.fetch_add(1, Ordering::SeqCst);
        let _g = Gauge::enter(&self.in_flight, &self.max_in_flight);
        if self.log_requests {
            self.log
                .lock()
                .push(offset..offset.saturating_add(len as u64));
        }
        let size = self.data.len() as u64;
        let s = offset.min(size);
        let e = s.saturating_add(len as u64).min(size);
        let d = delay(self.latency, self.jitter, self.bandwidth, (e - s) as usize);
        if !d.is_zero() {
            tokio::time::sleep(d).await;
        }
        let req = ReadRequest { index, offset, len };
        if let Some(err) = self.fault.lock().as_ref().and_then(|f| f(&req)) {
            return Err(err.with_path(self.info.name.clone()));
        }
        self.bytes.fetch_add(e - s, Ordering::SeqCst);
        Ok(self.data.slice(s as usize..e as usize))
    }
}

type PartFault = Box<dyn Fn(u32, &Bytes) -> Option<Error> + Send + Sync>;

/// In-memory [`PartSink`].
pub struct MemPartSink {
    parts: Mutex<BTreeMap<u32, Bytes>>,
    latency: Duration,
    jitter: Duration,
    fault: Option<PartFault>,
    start_error: Option<ErrorKind>,
    starts: AtomicU32,
    calls: AtomicU64,
    duplicates: AtomicU64,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
}

impl fmt::Debug for MemPartSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemPartSink")
            .field("parts", &self.parts.lock().len())
            .finish()
    }
}

impl Default for MemPartSink {
    fn default() -> Self {
        MemPartSink::new()
    }
}

impl MemPartSink {
    /// An instant, always-succeeding sink.
    pub fn new() -> Self {
        MemPartSink {
            parts: Mutex::new(BTreeMap::new()),
            latency: Duration::ZERO,
            jitter: Duration::ZERO,
            fault: None,
            start_error: None,
            starts: AtomicU32::new(0),
            calls: AtomicU64::new(0),
            duplicates: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(0),
        }
    }

    /// Every part upload sleeps `latency` plus a uniform random `[0, jitter]`.
    pub fn with_latency(mut self, latency: Duration, jitter: Duration) -> Self {
        self.latency = latency;
        self.jitter = jitter;
        self
    }

    /// Fail part uploads for which `f` returns an error (after the delay).
    pub fn with_fault(
        mut self,
        f: impl Fn(u32, &Bytes) -> Option<Error> + Send + Sync + 'static,
    ) -> Self {
        self.fault = Some(Box::new(f));
        self
    }

    /// Make [`PartSink::start`] fail with `kind`.
    pub fn with_start_error(mut self, kind: ErrorKind) -> Self {
        self.start_error = Some(kind);
        self
    }

    /// Times [`PartSink::start`] was called.
    pub fn starts(&self) -> u32 {
        self.starts.load(Ordering::SeqCst)
    }

    /// Part uploads started.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    /// Part numbers uploaded more than once.
    pub fn duplicates(&self) -> u64 {
        self.duplicates.load(Ordering::SeqCst)
    }

    /// Part uploads currently running.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Peak of [`MemPartSink::in_flight`].
    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(Ordering::SeqCst)
    }

    /// Stored parts by part number.
    pub fn parts(&self) -> BTreeMap<u32, Bytes> {
        self.parts.lock().clone()
    }

    /// Stored parts concatenated in part-number order.
    pub fn assembled(&self) -> Bytes {
        let parts = self.parts.lock();
        let mut out = BytesMut::with_capacity(parts.values().map(Bytes::len).sum());
        for p in parts.values() {
            out.extend_from_slice(p);
        }
        out.freeze()
    }
}

#[async_trait]
impl PartSink for MemPartSink {
    type Outcome = PartOutcome;

    async fn start(&self) -> Result<()> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        match self.start_error {
            Some(kind) => Err(Error::new(kind, "cannot start upload")),
            None => Ok(()),
        }
    }

    async fn upload_part(&self, part_number: u32, data: Bytes) -> Result<PartOutcome> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let _g = Gauge::enter(&self.in_flight, &self.max_in_flight);
        let d = delay(self.latency, self.jitter, None, data.len());
        if !d.is_zero() {
            tokio::time::sleep(d).await;
        }
        if let Some(err) = self.fault.as_ref().and_then(|f| f(part_number, &data)) {
            return Err(err);
        }
        if self.parts.lock().insert(part_number, data).is_some() {
            self.duplicates.fetch_add(1, Ordering::SeqCst);
        }
        Ok(PartOutcome {
            etag: format!("\"etag-{part_number}\""),
            checksum: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_distinguishes_offsets() {
        let p = pattern(200_000);
        assert_eq!(p.len(), 200_000);
        assert_eq!(pattern(1000), p.slice(..1000), "deterministic prefix");
        // Data read from the wrong offset must not look right: for any shift
        // (block sizes used by tests, multiples of 250/251/256, ...) only
        // about 1/256 of the bytes may coincide.
        let mut shifts: Vec<usize> = (1..=600).collect();
        shifts.extend([1000, 1004, 4096, 8000, 64_256, 65_536, 100_000]);
        for shift in shifts {
            let window = 2_000;
            let same = (0..window).filter(|&i| p[i] == p[i + shift]).count();
            assert!(
                same * 20 < window,
                "shift {shift}: {same}/{window} bytes equal"
            );
        }
        // Short reads at nearby offsets differ too.
        for off in [0usize, 5, 250, 251, 1000, 2000] {
            assert_ne!(&p[off..off + 4], &p[off + 1000..off + 1004], "at {off}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn mem_handle_semantics() {
        let h =
            MemReadHandle::new(pattern(100)).with_latency(Duration::from_millis(5), Duration::ZERO);
        assert_eq!(h.size(), 100);
        assert_eq!(h.read_at(10, 5).await.unwrap(), pattern(100).slice(10..15));
        assert_eq!(h.read_at(95, 50).await.unwrap().len(), 5);
        assert!(h.read_at(100, 5).await.unwrap().is_empty());
        assert!(h.read_at(500, 5).await.unwrap().is_empty());
        assert_eq!(h.requests(), 4);
        assert_eq!(h.bytes_served(), 10);
        assert_eq!(h.requested()[0], 10..15);
        h.set_fault(|r| (r.offset == 0).then(|| Error::new(ErrorKind::Io, "bad")));
        let e = h.read_at(0, 1).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Io);
        assert_eq!(e.path(), Some("mem/file"));
        h.clear_fault();
        assert!(h.read_at(0, 1).await.is_ok());
        h.reset_counters();
        assert_eq!(h.requests(), 0);
        assert_eq!(h.max_in_flight(), 0);
    }
}
