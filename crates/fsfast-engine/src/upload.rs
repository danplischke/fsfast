//! Concurrent multipart uploads for S3/GCS/Azure-style backends.
//!
//! A backend's `WriteHandle` feeds every `write` into a [`PartUploader`],
//! which
//!
//! * accepts arbitrary write sizes and cuts parts of the configured size
//!   (large aligned writes are sliced without copying; small writes are
//!   copied once, straight into a part-sized buffer),
//! * uploads up to `concurrency` parts at a time through a [`PartSink`],
//!   with the bytes of parts in flight accounted against a [`MemoryBudget`]
//!   (writers block when the budget is exhausted: backpressure),
//! * surfaces the first part failure from the next `write`/`finish` call,
//!   after cancelling the remaining parts,
//! * returns the completed parts in part-number order from
//!   [`PartUploader::finish`] — or [`UploadResult::Single`] when the whole
//!   object fits in one part and nothing was uploaded yet, so the backend can
//!   use a single PUT and never create a multipart upload.
//!
//! Part sizes follow a [`PartSizer`]: the configured size, enlarged up front
//! when the expected object size would otherwise need more than `max_parts`
//! parts, and doubled every `max_parts / 10` parts beyond that (or beyond the
//! expected size) so streams of unknown length fit in 10,000 parts up to
//! ~8 TiB with an 8 MiB base.
//!
//! Each part upload is idempotent (re-uploading a part number replaces it),
//! so sinks should wrap their request in [`retry`](crate::retry::retry).
//!
//! ```
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> fsfast_core::Result<()> {
//! use std::sync::Arc;
//!
//! use bytes::Bytes;
//! use fsfast_engine::testing::MemPartSink;
//! use fsfast_engine::{PartUploader, UploadConfig, UploadResult};
//!
//! // A backend implements `PartSink` (CreateMultipartUpload in `start`,
//! // UploadPart in `upload_part`); here an in-memory sink.
//! let sink = Arc::new(MemPartSink::new());
//! let mut up = PartUploader::new(sink.clone(), UploadConfig::default())?;
//! for _ in 0..3 {
//!     up.write(Bytes::from(vec![7u8; 4 << 20])).await?;
//! }
//! match up.finish().await? {
//!     UploadResult::Single(data) => { /* one PUT of `data` */ }
//!     UploadResult::Multipart(parts) => {
//!         // CompleteMultipartUpload with the parts' ETags, in order.
//!         assert_eq!(parts.len(), 2); // 8 MiB + 4 MiB
//!     }
//! }
//! # Ok(()) }
//! ```

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use fsfast_core::{Error, ErrorKind, Result};
use tokio::task::{JoinError, JoinSet};

use crate::budget::{BudgetGuard, MemoryBudget};
use crate::concurrency::join_error;

/// Destination of a multipart upload (one per object being written).
#[async_trait]
pub trait PartSink: Send + Sync + 'static {
    /// What the service returns per part (ETag, checksum, block id, ...),
    /// needed to complete the upload.
    type Outcome: Send + 'static;

    /// Called once, before the first part is uploaded (e.g. S3
    /// `CreateMultipartUpload`). Never called for [`UploadResult::Single`].
    async fn start(&self) -> Result<()> {
        Ok(())
    }

    /// Upload part `part_number` (1-based, contiguous).
    async fn upload_part(&self, part_number: u32, data: Bytes) -> Result<Self::Outcome>;
}

/// A ready-made per-part outcome for S3-compatible services.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartOutcome {
    /// The part's ETag as returned by the service.
    pub etag: String,
    /// Checksum value echoed by the service (e.g. `ChecksumCRC32C`).
    pub checksum: Option<String>,
}

/// One uploaded part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedPart<O> {
    /// 1-based part number.
    pub part_number: u32,
    /// Offset of the part within the object.
    pub offset: u64,
    /// Size of the part in bytes.
    pub size: u64,
    /// What the sink returned.
    pub outcome: O,
}

/// Result of [`PartUploader::finish`].
#[derive(Debug)]
pub enum UploadResult<O> {
    /// Nothing was uploaded: the whole object (possibly empty) fits in one
    /// part. Upload it with a single PUT.
    Single(Bytes),
    /// Parts uploaded, ordered by part number; complete the multipart upload.
    Multipart(Vec<CompletedPart<O>>),
}

impl<O> UploadResult<O> {
    /// Whether the object should be written with a single PUT.
    pub fn is_single(&self) -> bool {
        matches!(self, UploadResult::Single(_))
    }
}

/// Configuration of a [`PartUploader`].
#[derive(Debug, Clone)]
pub struct UploadConfig {
    /// Desired part size (clamped to `[min_part_size, max_part_size]`).
    pub part_size: usize,
    /// Smallest part the service accepts (except the last). S3: 5 MiB.
    pub min_part_size: usize,
    /// Largest part the service accepts. S3: 5 GiB.
    pub max_part_size: usize,
    /// Maximum number of parts. S3/GCS: 10,000.
    pub max_parts: u32,
    /// Parts uploaded concurrently (`0` is treated as `1`).
    pub concurrency: usize,
    /// Total object size when known up front (enlarges parts to fit).
    pub expected_size: Option<u64>,
    /// Budget for the bytes of parts in flight; `None` uses
    /// [`MemoryBudget::global`].
    pub budget: Option<MemoryBudget>,
}

impl Default for UploadConfig {
    /// S3 limits, 8 MiB parts, 8 concurrent uploads, global budget.
    fn default() -> Self {
        UploadConfig {
            part_size: 8 << 20,
            min_part_size: 5 << 20,
            max_part_size: 5 << 30,
            max_parts: 10_000,
            concurrency: 8,
            expected_size: None,
            budget: None,
        }
    }
}

/// Part-size schedule; see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartSizer {
    base: u64,
    max: u64,
    max_parts: u32,
    /// Parts at the base size before doubling starts.
    uniform_parts: u32,
    /// Parts per doubling after that.
    interval: u32,
}

impl PartSizer {
    /// Build the schedule for `cfg`, validating it.
    pub fn new(cfg: &UploadConfig) -> Result<Self> {
        if cfg.min_part_size == 0 || cfg.min_part_size > cfg.max_part_size {
            return Err(Error::invalid_input(format!(
                "invalid part size limits: min {} max {}",
                cfg.min_part_size, cfg.max_part_size
            )));
        }
        if cfg.max_parts == 0 {
            return Err(Error::invalid_input("max_parts must be at least 1"));
        }
        let (min, max) = (cfg.min_part_size as u64, cfg.max_part_size as u64);
        let mut base = (cfg.part_size as u64).clamp(min, max);
        let interval = (cfg.max_parts / 10).max(1);
        let mut uniform_parts = interval.min(cfg.max_parts);
        if let Some(expected) = cfg.expected_size {
            let needed = expected.div_ceil(cfg.max_parts as u64);
            if needed > base {
                let granule = if needed >= 1 << 20 { 1 << 20 } else { 1 };
                base = needed
                    .div_ceil(granule)
                    .saturating_mul(granule)
                    .clamp(min, max);
            }
            let parts = expected.div_ceil(base).max(1);
            uniform_parts = u32::try_from(parts).unwrap_or(u32::MAX).min(cfg.max_parts);
        }
        let sizer = PartSizer {
            base,
            max,
            max_parts: cfg.max_parts,
            uniform_parts,
            interval,
        };
        if let Some(expected) = cfg.expected_size
            && expected > sizer.capacity()
        {
            return Err(Error::invalid_input(format!(
                "object of {expected} bytes exceeds the multipart limits ({} parts of at most {max} bytes)",
                cfg.max_parts
            )));
        }
        Ok(sizer)
    }

    /// Size of part `part_number` (1-based).
    pub fn part_size(&self, part_number: u32) -> u64 {
        if part_number <= self.uniform_parts {
            return self.base;
        }
        let doublings = 1 + (part_number - 1 - self.uniform_parts) / self.interval;
        self.base
            .checked_shl(doublings)
            .filter(|s| s >> doublings == self.base)
            .unwrap_or(self.max)
            .min(self.max)
    }

    /// Maximum number of parts.
    pub fn max_parts(&self) -> u32 {
        self.max_parts
    }

    /// Largest object the schedule can hold within `max_parts` parts
    /// (saturating at `u64::MAX`).
    pub fn capacity(&self) -> u64 {
        // Closed form, one step per doubling (at most ~64): `PartSizer::new`
        // evaluates this, and `max_parts` may be large.
        let uniform = self.uniform_parts.min(self.max_parts);
        let mut total = self.base.saturating_mul(u64::from(uniform));
        let mut counted = uniform;
        while counted < self.max_parts {
            let size = self.part_size(counted + 1);
            let left = self.max_parts - counted;
            if size >= self.max {
                return total.saturating_add(size.saturating_mul(u64::from(left)));
            }
            // Parts `counted + 1 ..= counted + interval` share one size.
            let n = self.interval.min(left);
            total = total.saturating_add(size.saturating_mul(u64::from(n)));
            counted += n;
        }
        total
    }
}

type PartResult<O> = (u32, u64, u64, Result<O>);

/// Streams writes into concurrently uploaded parts. See the module docs.
///
/// `write` is not cancellation-safe: if a `write` future is dropped before it
/// completes, part of its data may have been consumed. The uploader is then
/// poisoned: later `write`/`finish` calls fail with
/// [`ErrorKind::Cancelled`] (so an object with bytes missing is never
/// completed) and the upload must be aborted. Dropping the uploader aborts
/// parts still in flight.
pub struct PartUploader<S: PartSink> {
    sink: Arc<S>,
    sizer: PartSizer,
    concurrency: usize,
    budget: MemoryBudget,
    /// Part being filled from small writes (capacity reserved up front).
    buf: BytesMut,
    /// A complete part not yet dispatched because it might be the only one.
    held: Option<Bytes>,
    next_part: u32,
    next_offset: u64,
    accepted: u64,
    started: bool,
    in_flight: JoinSet<PartResult<S::Outcome>>,
    completed: Vec<CompletedPart<S::Outcome>>,
    failed: Option<(ErrorKind, String)>,
    /// A `write` started and has not returned yet; still set on the next
    /// call only if that write's future was dropped half-way.
    writing: bool,
}

impl<S: PartSink> fmt::Debug for PartUploader<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartUploader")
            .field("accepted", &self.accepted)
            .field("next_part", &self.next_part)
            .field("in_flight", &self.in_flight.len())
            .field("started", &self.started)
            .field("failed", &self.failed)
            .finish()
    }
}

impl<S: PartSink> PartUploader<S> {
    /// Create an uploader; fails with `InvalidInput` for inconsistent limits
    /// or an expected size beyond them.
    pub fn new(sink: Arc<S>, cfg: UploadConfig) -> Result<Self> {
        let sizer = PartSizer::new(&cfg)?;
        Ok(PartUploader {
            sink,
            sizer,
            concurrency: cfg.concurrency.max(1),
            budget: cfg.budget.unwrap_or_else(|| MemoryBudget::global().clone()),
            buf: BytesMut::new(),
            held: None,
            next_part: 1,
            next_offset: 0,
            accepted: 0,
            started: false,
            in_flight: JoinSet::new(),
            completed: Vec::new(),
            failed: None,
            writing: false,
        })
    }

    /// The sink.
    pub fn sink(&self) -> &Arc<S> {
        &self.sink
    }

    /// The part-size schedule.
    pub fn part_sizer(&self) -> &PartSizer {
        &self.sizer
    }

    /// Bytes accepted by [`PartUploader::write`].
    pub fn bytes_written(&self) -> u64 {
        self.accepted
    }

    /// Whether the multipart upload has started (at least one part was
    /// dispatched). While false, [`PartUploader::finish`] returns
    /// [`UploadResult::Single`].
    pub fn is_multipart(&self) -> bool {
        self.started
    }

    /// Parts handed to the sink so far.
    pub fn parts_dispatched(&self) -> u32 {
        self.next_part - 1
    }

    /// Part uploads currently in flight.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// Fail if a previous call failed or a previous `write` was cancelled.
    async fn check_usable(&mut self) -> Result<()> {
        if let Some((kind, msg)) = &self.failed {
            return Err(Error::new(
                *kind,
                format!("multipart upload already failed: {msg}"),
            ));
        }
        if self.writing {
            return self.fail(Error::new(
                ErrorKind::Cancelled,
                "a previous write was cancelled before it completed; the upload must be aborted",
            ))
            .await;
        }
        Ok(())
    }

    /// Accept `data`, uploading every part that is complete. Waits when
    /// `concurrency` parts are in flight or the memory budget is exhausted.
    pub async fn write(&mut self, data: Bytes) -> Result<()> {
        self.check_usable().await?;
        if data.is_empty() {
            return Ok(());
        }
        // Cleared only if `write_inner` runs to completion (successfully or
        // not): a dropped future leaves it set and poisons the uploader.
        self.writing = true;
        let res = self.write_inner(data).await;
        self.writing = false;
        res
    }

    async fn write_inner(&mut self, mut data: Bytes) -> Result<()> {
        self.reap().await?;
        self.accepted += data.len() as u64;
        if let Some(part) = self.held.take() {
            self.dispatch(part).await?;
        }
        loop {
            let part_size =
                usize::try_from(self.sizer.part_size(self.next_part)).unwrap_or(usize::MAX);
            if self.buf.is_empty() && data.len() >= part_size {
                // Zero-copy: the part is a slice of the caller's buffer.
                let part = data.split_to(part_size);
                if data.is_empty() {
                    self.held = Some(part);
                    return Ok(());
                }
                self.dispatch(part).await?;
                continue;
            }
            if self.buf.is_empty() && self.buf.capacity() < part_size {
                // One allocation per part: small writes are copied straight
                // into their final buffer, which is never re-grown (the part
                // number, hence the size, is fixed while it fills).
                self.buf = BytesMut::with_capacity(part_size);
            }
            let take = (part_size - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data.advance(take);
            if self.buf.len() == part_size {
                let part = self.buf.split().freeze();
                if data.is_empty() {
                    self.held = Some(part);
                    return Ok(());
                }
                self.dispatch(part).await?;
            }
            if data.is_empty() {
                return Ok(());
            }
        }
    }

    /// Flush the remaining data and wait for every part.
    ///
    /// On failure, no part upload is still running when the error is
    /// returned, so the backend can abort the multipart upload right away.
    pub async fn finish(mut self) -> Result<UploadResult<S::Outcome>> {
        self.check_usable().await?;
        if !self.started {
            let data = match self.held.take() {
                Some(part) => part,
                None => self.buf.split().freeze(),
            };
            return Ok(UploadResult::Single(data));
        }
        if let Some(part) = self.held.take() {
            self.dispatch(part).await?;
        }
        if !self.buf.is_empty() {
            let part = self.buf.split().freeze();
            self.dispatch(part).await?;
        }
        while let Some(r) = self.in_flight.join_next().await {
            if let Err(e) = self.absorb(r) {
                return self.fail(e).await;
            }
        }
        let mut parts = std::mem::take(&mut self.completed);
        parts.sort_unstable_by_key(|p| p.part_number);
        debug_assert!(
            parts
                .iter()
                .enumerate()
                .all(|(i, p)| p.part_number as usize == i + 1)
        );
        Ok(UploadResult::Multipart(parts))
    }

    /// Cancel every part in flight and wait until they have stopped.
    pub async fn abort(mut self) {
        self.in_flight.abort_all();
        while self.in_flight.join_next().await.is_some() {}
    }

    async fn dispatch(&mut self, part: Bytes) -> Result<()> {
        let n = self.next_part;
        if n > self.sizer.max_parts() {
            return self
                .fail(Error::invalid_input(format!(
                    "upload exceeds the maximum of {} parts",
                    self.sizer.max_parts()
                )))
                .await;
        }
        if !self.started {
            self.started = true;
            if let Err(e) = self.sink.start().await {
                return self.fail(e).await;
            }
        }
        while self.in_flight.len() >= self.concurrency {
            self.join_one().await?;
        }
        let len = part.len();
        let guard = self.reserve(len).await?;
        let sink = self.sink.clone();
        let offset = self.next_offset;
        self.in_flight.spawn(async move {
            let _guard = guard;
            let res = sink.upload_part(n, part).await;
            (n, offset, len as u64, res)
        });
        tracing::trace!(part = n, len, offset, "part dispatched");
        self.next_part += 1;
        self.next_offset += len as u64;
        Ok(())
    }

    /// Budget for one part: wait for budget or for one of our own parts to
    /// finish; with nothing in flight, over-commit so the upload progresses.
    async fn reserve(&mut self, len: usize) -> Result<BudgetGuard> {
        loop {
            if let Some(g) = self.budget.try_acquire(len) {
                return Ok(g);
            }
            if self.in_flight.is_empty() {
                return Ok(self.budget.force_acquire(len));
            }
            let budget = self.budget.clone();
            tokio::select! {
                biased;
                r = self.in_flight.join_next() => {
                    if let Some(r) = r
                        && let Err(e) = self.absorb(r)
                    {
                        return self.fail(e).await;
                    }
                }
                g = budget.acquire(len) => return Ok(g),
            }
        }
    }

    async fn join_one(&mut self) -> Result<()> {
        match self.in_flight.join_next().await {
            None => Ok(()),
            Some(r) => match self.absorb(r) {
                Ok(()) => Ok(()),
                Err(e) => self.fail(e).await,
            },
        }
    }

    /// Collect parts that already finished, without waiting.
    async fn reap(&mut self) -> Result<()> {
        while let Some(r) = self.in_flight.try_join_next() {
            if let Err(e) = self.absorb(r) {
                return self.fail(e).await;
            }
        }
        Ok(())
    }

    fn absorb(&mut self, r: std::result::Result<PartResult<S::Outcome>, JoinError>) -> Result<()> {
        let (part_number, offset, size, res) = r.map_err(join_error)?;
        let outcome = res?;
        self.completed.push(CompletedPart {
            part_number,
            offset,
            size,
            outcome,
        });
        Ok(())
    }

    /// Record the first failure, stop every part in flight, return `e`.
    async fn fail<T>(&mut self, e: Error) -> Result<T> {
        if self.failed.is_none() {
            self.failed = Some((e.kind(), e.to_string()));
        }
        tracing::debug!(error = %e, "multipart upload failed");
        self.in_flight.abort_all();
        while self.in_flight.join_next().await.is_some() {}
        self.held = None;
        self.buf = BytesMut::new();
        Err(e)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use proptest::prelude::*;

    use super::*;
    use crate::testing::{MemPartSink, pattern};

    fn small_cfg(part: usize, conc: usize, budget: &MemoryBudget) -> UploadConfig {
        UploadConfig {
            part_size: part,
            min_part_size: 1,
            max_part_size: 1 << 30,
            max_parts: 10_000,
            concurrency: conc,
            expected_size: None,
            budget: Some(budget.clone()),
        }
    }

    async fn upload_chunks(
        sink: &Arc<MemPartSink>,
        cfg: UploadConfig,
        chunks: &[Bytes],
    ) -> Result<UploadResult<PartOutcome>> {
        let mut up = PartUploader::new(sink.clone(), cfg)?;
        for c in chunks {
            up.write(c.clone()).await?;
        }
        up.finish().await
    }

    #[tokio::test]
    async fn small_totals_are_single_put() {
        let budget = MemoryBudget::new(1 << 20);
        for total in [0usize, 1, 99, 100] {
            let sink = Arc::new(MemPartSink::new());
            let data = pattern(total);
            let chunks: Vec<Bytes> = data.chunks(7).map(Bytes::copy_from_slice).collect();
            let r = upload_chunks(&sink, small_cfg(100, 4, &budget), &chunks)
                .await
                .unwrap();
            match r {
                UploadResult::Single(b) => assert_eq!(b, data, "total {total}"),
                UploadResult::Multipart(_) => panic!("total {total} should be single"),
            }
            assert_eq!(sink.starts(), 0);
            assert_eq!(sink.calls(), 0);
        }
        assert_eq!(budget.available(), 1 << 20);
    }

    #[tokio::test]
    async fn one_byte_over_is_multipart() {
        let budget = MemoryBudget::new(1 << 20);
        let sink = Arc::new(MemPartSink::new());
        let data = pattern(101);
        let r = upload_chunks(
            &sink,
            small_cfg(100, 4, &budget),
            std::slice::from_ref(&data),
        )
        .await
        .unwrap();
        let UploadResult::Multipart(parts) = r else {
            panic!("expected multipart")
        };
        assert_eq!(
            parts
                .iter()
                .map(|p| (p.part_number, p.offset, p.size))
                .collect::<Vec<_>>(),
            vec![(1, 0, 100), (2, 100, 1)]
        );
        assert_eq!(parts[0].outcome.etag, "\"etag-1\"");
        assert_eq!(sink.starts(), 1);
        assert_eq!(sink.assembled(), data);
    }

    #[tokio::test]
    async fn large_writes_are_sliced_without_copying() {
        let budget = MemoryBudget::new(1 << 20);
        let sink = Arc::new(MemPartSink::new());
        let data = pattern(1000);
        let mut up = PartUploader::new(sink.clone(), small_cfg(100, 3, &budget)).unwrap();
        up.write(data.clone()).await.unwrap();
        assert!(up.is_multipart());
        assert_eq!(up.bytes_written(), 1000);
        let UploadResult::Multipart(parts) = up.finish().await.unwrap() else {
            panic!()
        };
        assert_eq!(parts.len(), 10);
        for (n, p) in sink.parts() {
            let off = (n as usize - 1) * 100;
            assert_eq!(p.as_ptr(), data[off..].as_ptr(), "part {n} was copied");
        }
        assert_eq!(budget.available(), 1 << 20);
    }

    #[tokio::test]
    async fn small_writes_fill_one_buffer_per_part() {
        let budget = MemoryBudget::new(1 << 20);
        let sink = Arc::new(MemPartSink::new());
        let data = pattern(1050);
        let chunks: Vec<Bytes> = data.chunks(3).map(Bytes::copy_from_slice).collect();
        let r = upload_chunks(&sink, small_cfg(100, 2, &budget), &chunks)
            .await
            .unwrap();
        let UploadResult::Multipart(parts) = r else {
            panic!()
        };
        assert_eq!(parts.len(), 11);
        assert_eq!(parts.last().unwrap().size, 50);
        assert_eq!(sink.assembled(), data);
    }

    #[tokio::test(start_paused = true)]
    async fn bounded_concurrency_and_budget() {
        let budget = MemoryBudget::new(250);
        let sink = Arc::new(
            MemPartSink::new().with_latency(Duration::from_millis(10), Duration::from_millis(5)),
        );
        let data = pattern(5_000);
        let chunks: Vec<Bytes> = data.chunks(33).map(Bytes::copy_from_slice).collect();
        let r = upload_chunks(&sink, small_cfg(100, 8, &budget), &chunks)
            .await
            .unwrap();
        let UploadResult::Multipart(parts) = r else {
            panic!()
        };
        assert_eq!(parts.len(), 50);
        // Budget of 250 bytes allows two 100-byte parts in flight.
        assert!(sink.max_in_flight() <= 2, "{}", sink.max_in_flight());
        assert_eq!(sink.assembled(), data);
        assert_eq!(budget.available(), 250);

        let budget = MemoryBudget::unlimited();
        let sink =
            Arc::new(MemPartSink::new().with_latency(Duration::from_millis(10), Duration::ZERO));
        upload_chunks(
            &sink,
            small_cfg(100, 3, &budget),
            std::slice::from_ref(&data),
        )
        .await
        .unwrap();
        assert_eq!(sink.max_in_flight(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn tiny_budget_still_progresses() {
        // Budget smaller than one part: parts go one at a time, over-committed.
        let budget = MemoryBudget::new(10);
        let sink =
            Arc::new(MemPartSink::new().with_latency(Duration::from_millis(1), Duration::ZERO));
        let data = pattern(1_000);
        upload_chunks(
            &sink,
            small_cfg(100, 4, &budget),
            std::slice::from_ref(&data),
        )
        .await
        .unwrap();
        assert_eq!(sink.assembled(), data);
        assert_eq!(budget.available(), 10);
        assert!(!budget.is_overcommitted());
    }

    #[tokio::test(start_paused = true)]
    async fn failing_part_surfaces_first_error_and_quiesces() {
        let budget = MemoryBudget::new(1 << 20);
        let sink = Arc::new(
            MemPartSink::new()
                .with_latency(Duration::from_millis(5), Duration::from_millis(5))
                .with_fault(|n, _| {
                    (n == 4).then(|| Error::new(ErrorKind::PermissionDenied, "denied"))
                }),
        );
        let mut up = PartUploader::new(sink.clone(), small_cfg(100, 3, &budget)).unwrap();
        let mut first_err = None;
        for c in pattern(10_000).chunks(250) {
            if let Err(e) = up.write(Bytes::copy_from_slice(c)).await {
                first_err = Some(e);
                break;
            }
        }
        let err = match first_err {
            Some(e) => e,
            None => up.finish().await.unwrap_err(),
        };
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        assert_eq!(sink.in_flight(), 0, "parts still running after the error");
        assert_eq!(budget.available(), 1 << 20);
    }

    #[tokio::test(start_paused = true)]
    async fn errors_are_sticky() {
        let budget = MemoryBudget::new(1 << 20);
        let sink = Arc::new(
            MemPartSink::new().with_fault(|n, _| (n == 1).then(|| Error::connection("reset"))),
        );
        let mut up = PartUploader::new(sink.clone(), small_cfg(10, 1, &budget)).unwrap();
        let mut errs = 0;
        for c in pattern(200).chunks(10) {
            if up.write(Bytes::copy_from_slice(c)).await.is_err() {
                errs += 1;
            }
        }
        assert!(errs > 0);
        let e = up.write(Bytes::from_static(b"x")).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ConnectionFailed);
        assert!(e.message().contains("already failed"));
        let e = up.finish().await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ConnectionFailed);
    }

    #[tokio::test]
    async fn start_failure_is_reported() {
        let budget = MemoryBudget::new(1 << 20);
        let sink = Arc::new(MemPartSink::new().with_start_error(ErrorKind::PermissionDenied));
        let mut up = PartUploader::new(sink.clone(), small_cfg(10, 1, &budget)).unwrap();
        up.write(pattern(10)).await.unwrap(); // held, not dispatched yet
        let e = up.write(pattern(5)).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PermissionDenied);
        assert_eq!(sink.calls(), 0);
    }

    #[tokio::test]
    async fn too_many_parts_is_invalid_input() {
        let budget = MemoryBudget::new(1 << 20);
        let sink = Arc::new(MemPartSink::new());
        let cfg = UploadConfig {
            max_parts: 3,
            ..small_cfg(10, 2, &budget)
        };
        // Growth rule: parts of 10, 20 and 40 bytes hold at most 70 bytes.
        assert_eq!(PartSizer::new(&cfg).unwrap().capacity(), 70);
        let r = upload_chunks(&sink, cfg.clone(), &[pattern(70)]).await;
        assert!(r.is_ok());
        let r = upload_chunks(&sink, cfg, &[pattern(71)]).await;
        assert_eq!(r.unwrap_err().kind(), ErrorKind::InvalidInput);
        assert_eq!(budget.available(), 1 << 20);
    }

    #[tokio::test(start_paused = true)]
    async fn drop_and_abort_cancel_parts_in_flight() {
        let budget = MemoryBudget::new(1 << 20);
        let sink =
            Arc::new(MemPartSink::new().with_latency(Duration::from_secs(60), Duration::ZERO));
        let mut up = PartUploader::new(sink.clone(), small_cfg(100, 4, &budget)).unwrap();
        up.write(pattern(450)).await.unwrap();
        assert_eq!(up.in_flight(), 4);
        up.abort().await;
        assert_eq!(sink.in_flight(), 0);
        assert_eq!(budget.available(), 1 << 20);

        let mut up = PartUploader::new(sink.clone(), small_cfg(100, 4, &budget)).unwrap();
        up.write(pattern(450)).await.unwrap();
        drop(up);
        tokio::task::yield_now().await;
        assert_eq!(sink.in_flight(), 0);
        assert_eq!(budget.available(), 1 << 20);
    }

    /// `write` is not cancellation-safe: a write dropped half-way has lost
    /// data, so the upload is poisoned and `finish` cannot complete an
    /// object with bytes missing.
    #[tokio::test(start_paused = true)]
    async fn cancelled_write_poisons_the_upload() {
        let budget = MemoryBudget::new(1 << 20);
        let sink =
            Arc::new(MemPartSink::new().with_latency(Duration::from_millis(10), Duration::ZERO));
        let mut up = PartUploader::new(sink.clone(), small_cfg(100, 1, &budget)).unwrap();
        // Part 1 is dispatched; part 2 waits for it (concurrency 1).
        let r = tokio::time::timeout(Duration::from_millis(5), up.write(pattern(450))).await;
        assert!(r.is_err(), "the write should still have been waiting");
        let e = up.write(pattern(10)).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Cancelled);
        assert_eq!(sink.in_flight(), 0, "parts stopped once poisoned");
        let e = up.finish().await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Cancelled);
        assert_eq!(budget.available(), 1 << 20);

        // `finish` right after a cancelled write fails the same way.
        let mut up = PartUploader::new(sink.clone(), small_cfg(100, 1, &budget)).unwrap();
        let r = tokio::time::timeout(Duration::from_millis(5), up.write(pattern(450))).await;
        assert!(r.is_err());
        assert_eq!(up.finish().await.unwrap_err().kind(), ErrorKind::Cancelled);
        assert_eq!(sink.in_flight(), 0);
        assert_eq!(budget.available(), 1 << 20);
    }

    #[test]
    fn part_sizer_schedule() {
        let cfg = UploadConfig::default();
        let s = PartSizer::new(&cfg).unwrap();
        assert_eq!(s.part_size(1), 8 << 20);
        assert_eq!(s.part_size(1000), 8 << 20);
        assert_eq!(s.part_size(1001), 16 << 20);
        assert_eq!(s.part_size(2001), 32 << 20);
        assert_eq!(s.part_size(10_000), 4 << 30);
        assert!(
            s.capacity() > 5u64 << 40,
            "streams up to S3's 5 TiB limit fit"
        );

        // Known size: parts enlarged to fit, uniform up to the expected size.
        let cfg = UploadConfig {
            expected_size: Some(200 << 30),
            ..UploadConfig::default()
        };
        let s = PartSizer::new(&cfg).unwrap();
        assert_eq!(s.part_size(1), 21 << 20);
        let parts = (200u64 << 30).div_ceil(21 << 20) as u32;
        assert!(parts <= 10_000);
        assert_eq!(s.part_size(parts), 21 << 20);
        assert_eq!(s.part_size(parts + 1), 42 << 20);

        // Clamping of the configured size.
        let s = PartSizer::new(&UploadConfig {
            part_size: 1,
            ..UploadConfig::default()
        })
        .unwrap();
        assert_eq!(s.part_size(1), 5 << 20);

        // Too large for the limits.
        let e = PartSizer::new(&UploadConfig {
            expected_size: Some(u64::MAX),
            ..UploadConfig::default()
        })
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput);
        // Inconsistent limits.
        for bad in [
            UploadConfig {
                min_part_size: 0,
                ..UploadConfig::default()
            },
            UploadConfig {
                min_part_size: 10,
                max_part_size: 5,
                ..UploadConfig::default()
            },
            UploadConfig {
                max_parts: 0,
                ..UploadConfig::default()
            },
        ] {
            assert_eq!(
                PartSizer::new(&bad).unwrap_err().kind(),
                ErrorKind::InvalidInput
            );
        }
        // Doubling saturates at max_part_size and never overflows.
        let s = PartSizer::new(&UploadConfig {
            part_size: 1 << 30,
            min_part_size: 1,
            max_part_size: usize::MAX,
            max_parts: 1000,
            ..UploadConfig::default()
        })
        .unwrap();
        assert_eq!(s.part_size(1000), 1 << 39);
    }

    /// `capacity()` (also evaluated by `PartSizer::new` for a known size)
    /// must not iterate over every part number.
    #[test]
    fn part_sizer_capacity_is_closed_form() {
        let cfg = UploadConfig {
            part_size: 1,
            min_part_size: 1,
            max_part_size: 1 << 20,
            max_parts: u32::MAX,
            expected_size: Some(1),
            ..UploadConfig::default()
        };
        let start = std::time::Instant::now();
        let s = PartSizer::new(&cfg).unwrap();
        // One 1-byte part, then levels of `interval` parts of 2, 4, 8, ...
        // bytes (capped at 1 MiB) until `max_parts` is reached.
        let interval = u64::from(u32::MAX / 10);
        let (mut left, mut expect, mut size) = (u64::from(u32::MAX) - 1, 1u64, 1u64);
        while left > 0 {
            size = (size * 2).min(1 << 20);
            let n = left.min(interval);
            expect += n * size;
            left -= n;
        }
        assert_eq!(s.capacity(), expect);
        // Unbounded part sizes saturate instead of overflowing.
        let s = PartSizer::new(&UploadConfig {
            part_size: 1 << 40,
            max_part_size: usize::MAX,
            ..cfg
        })
        .unwrap();
        assert_eq!(s.capacity(), u64::MAX);
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "{:?}",
            start.elapsed()
        );
        // Matches the definition on small schedules.
        for max_parts in 1..60u32 {
            for (part, max) in [(1usize, 1usize), (3, 40), (5, 1 << 20), (7, 7)] {
                for expected in [None, Some(0u64), Some(10), Some(100)] {
                    let cfg = UploadConfig {
                        part_size: part,
                        min_part_size: 1,
                        max_part_size: max,
                        max_parts,
                        expected_size: expected,
                        ..UploadConfig::default()
                    };
                    let Ok(s) = PartSizer::new(&cfg) else {
                        continue;
                    };
                    let naive = (1..=max_parts).map(|n| s.part_size(n)).sum::<u64>();
                    assert_eq!(s.capacity(), naive, "{cfg:?}");
                }
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn growth_rule_applies_while_streaming() {
        let budget = MemoryBudget::new(1 << 20);
        let sink = Arc::new(MemPartSink::new());
        let cfg = UploadConfig {
            max_parts: 20, // doubling every 2 parts
            ..small_cfg(10, 2, &budget)
        };
        let data = pattern(150);
        let r = upload_chunks(&sink, cfg, std::slice::from_ref(&data))
            .await
            .unwrap();
        let UploadResult::Multipart(parts) = r else {
            panic!()
        };
        let sizes: Vec<u64> = parts.iter().map(|p| p.size).collect();
        assert_eq!(sizes, vec![10, 10, 20, 20, 40, 40, 10]);
        assert_eq!(sink.assembled(), data);
    }

    #[test]
    fn uploader_is_send() {
        fn check<T: Send>(_: &T) {}
        let sink = Arc::new(MemPartSink::new());
        let mut up = PartUploader::new(sink, UploadConfig::default()).unwrap();
        check(&up);
        check(&up.write(Bytes::new()));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(crate::proptest_cases(64)))]
        #[test]
        fn arbitrary_writes_reassemble(
            total in 0usize..3000,
            part in 1usize..300,
            conc in 1usize..5,
            budget_bytes in 1usize..2000,
            cuts in proptest::collection::vec(0usize..500, 0..40),
            fail_at in proptest::option::of(1u32..20),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().enable_time().start_paused(true).build().unwrap();
            rt.block_on(async {
                let budget = MemoryBudget::new(budget_bytes);
                let mut sink = MemPartSink::new().with_latency(Duration::from_millis(1), Duration::from_millis(3));
                if let Some(f) = fail_at {
                    sink = sink.with_fault(move |n, _| (n == f).then(|| Error::new(ErrorKind::Io, "boom")));
                }
                let sink = Arc::new(sink);
                let data = pattern(total);
                let mut chunks = Vec::new();
                let mut off = 0;
                for c in cuts {
                    if off >= total { break; }
                    let e = (off + c).min(total);
                    chunks.push(data.slice(off..e));
                    off = e;
                }
                if off < total { chunks.push(data.slice(off..)); }
                let cfg = small_cfg(part, conc, &budget);
                let sizer = PartSizer::new(&cfg).unwrap();
                let mut parts_needed = 0usize;
                let mut covered = 0u64;
                while covered < total as u64 {
                    parts_needed += 1;
                    covered += sizer.part_size(parts_needed as u32);
                }
                let res = upload_chunks(&sink, cfg, &chunks).await;
                match res {
                    Ok(UploadResult::Single(b)) => {
                        prop_assert!(total <= part);
                        prop_assert_eq!(b, data);
                        prop_assert_eq!(sink.calls(), 0);
                    }
                    Ok(UploadResult::Multipart(parts)) => {
                        prop_assert!(total > part);
                        prop_assert!(fail_at.is_none_or(|f| f as usize > parts_needed));
                        prop_assert_eq!(parts.len(), parts_needed);
                        let mut off = 0;
                        for (i, p) in parts.iter().enumerate() {
                            prop_assert_eq!(p.part_number as usize, i + 1);
                            prop_assert_eq!(p.offset, off);
                            if i + 1 < parts.len() {
                                prop_assert_eq!(p.size, sizer.part_size(p.part_number));
                            }
                            off += p.size;
                        }
                        prop_assert_eq!(sink.assembled(), data);
                        prop_assert!(sink.max_in_flight() <= conc);
                    }
                    Err(e) => {
                        prop_assert_eq!(e.kind(), ErrorKind::Io);
                        prop_assert!(fail_at.is_some_and(|f| f as usize <= parts_needed));
                    }
                }
                prop_assert_eq!(sink.in_flight(), 0);
                prop_assert_eq!(budget.available(), budget_bytes);
                Ok(())
            })?;
        }
    }
}
