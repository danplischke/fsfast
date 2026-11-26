//! Parallel ranged reads ("automatic ranged GET").
//!
//! A large read is split into parts of `part_size` bytes. Up to
//! `concurrency` parts are fetched at once, each in its own tokio task (so
//! CPU work inside a backend's `read_at` — TLS, decryption, decompression —
//! runs in parallel too).
//!
//! [`read_parallel`] allocates **one** buffer for the whole range and hands
//! each task a disjoint view of it (`BytesMut::split_to`); a task copies its
//! part into place as soon as it arrives, so the copy (and the first-touch
//! page faults of a fresh allocation, which dominate assembly cost for large
//! reads) is spread over the runtime's worker threads. The views are then
//! re-joined in O(1) (`BytesMut::unsplit` of contiguous pieces) and frozen:
//! one allocation, one copy, no `unsafe`. A read that fits in a single part
//! returns the backend's buffer as-is, with no copy at all.
//!
//! [`read_parallel_into`] writes into a caller-provided buffer (Python
//! `readinto`); parts are copied into place by the calling task as they
//! complete, in any order.
//!
//! The bytes of parts in flight are accounted against an optional
//! [`MemoryBudget`]. Additional parts are only started while budget is
//! available; the first part always proceeds (over-committing if needed), so
//! a read never deadlocks against memory held elsewhere and simply runs with
//! less concurrency under pressure. Dropping the returned future aborts every
//! part still in flight.

use std::future::Future;
use std::ops::Range;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use fsfast_core::{Error, ErrorKind, ReadHandle, Result};
use tokio::task::JoinSet;

use crate::budget::{BudgetGuard, MemoryBudget};
use crate::concurrency::join_error;

/// Fetch `range` (clamped to the handle's size) with up to `concurrency`
/// parts of `part_size` bytes in flight, assembled into one buffer.
///
/// `part_size` and `concurrency` of `0` are treated as `1`. A reversed range
/// selects nothing.
pub async fn read_parallel(
    handle: &Arc<dyn ReadHandle>,
    range: Range<u64>,
    part_size: usize,
    concurrency: usize,
    budget: Option<&MemoryBudget>,
) -> Result<Bytes> {
    read_parallel_within(handle, range, handle.size(), part_size, concurrency, budget).await
}

/// [`read_parallel`] clamped to `size` instead of the size at open: the
/// caller knows the current size of a handle that is not pinned
/// ([`ReadHandle::current_size`]).
pub(crate) async fn read_parallel_within(
    handle: &Arc<dyn ReadHandle>,
    range: Range<u64>,
    size: u64,
    part_size: usize,
    concurrency: usize,
    budget: Option<&MemoryBudget>,
) -> Result<Bytes> {
    let range = clamp(range, size);
    let len = to_usize(range.end - range.start)?;
    if len == 0 {
        return Ok(Bytes::new());
    }
    let part_size = part_size.max(1);
    if len <= part_size {
        // Single request: hand the backend's buffer through untouched.
        let data = handle.read_at(range.start, len).await?;
        check_len(range.start, len, data.len())?;
        return Ok(data);
    }
    // `BytesMut::zeroed` maps fresh zero pages for large sizes (no memset).
    let mut rest = BytesMut::zeroed(len);
    let mut pieces: Vec<Option<BytesMut>> = (0..len.div_ceil(part_size)).map(|_| None).collect();
    run_parts(
        range.clone(),
        part_size,
        concurrency,
        budget,
        |off, n| {
            // Parts are started in offset order, so successive `split_to`
            // calls hand out contiguous, disjoint views of the buffer.
            let mut piece = rest.split_to(n);
            let h = handle.clone();
            async move {
                let data = h.read_at(off, n).await?;
                check_len(off, n, data.len())?;
                piece.copy_from_slice(&data);
                Ok(piece)
            }
        },
        |rel, _, piece| pieces[rel / part_size] = Some(piece),
    )
    .await?;
    let mut parts = pieces.into_iter();
    let mut out = parts.next().flatten().ok_or_else(missing_part)?;
    for p in parts {
        // O(1): each piece directly follows the previous one in memory.
        out.unsplit(p.ok_or_else(missing_part)?);
    }
    Ok(out.freeze())
}

fn missing_part() -> Error {
    Error::new(
        ErrorKind::Other,
        "parallel read finished with a part missing",
    )
}

/// Read up to `dst.len()` bytes at `offset` straight into `dst` (Python
/// `readinto`), fetching parts concurrently. Returns the number of bytes
/// read: `min(dst.len(), size - offset)`, 0 at or after EOF.
pub async fn read_parallel_into(
    handle: &Arc<dyn ReadHandle>,
    offset: u64,
    dst: &mut [u8],
    part_size: usize,
    concurrency: usize,
    budget: Option<&MemoryBudget>,
) -> Result<usize> {
    read_parallel_into_within(
        handle,
        offset,
        dst,
        handle.size(),
        part_size,
        concurrency,
        budget,
    )
    .await
}

/// [`read_parallel_into`] bounded by `size` instead of the size at open
/// (see [`read_parallel_within`]).
pub(crate) async fn read_parallel_into_within(
    handle: &Arc<dyn ReadHandle>,
    offset: u64,
    dst: &mut [u8],
    size: u64,
    part_size: usize,
    concurrency: usize,
    budget: Option<&MemoryBudget>,
) -> Result<usize> {
    let n = (dst.len() as u64).min(size.saturating_sub(offset)) as usize;
    if n == 0 {
        return Ok(0);
    }
    if n <= part_size.max(1) {
        let data = handle.read_at(offset, n).await?;
        check_len(offset, n, data.len())?;
        dst[..n].copy_from_slice(&data);
        return Ok(n);
    }
    run_parts(
        offset..offset + n as u64,
        part_size.max(1),
        concurrency,
        budget,
        |off, len| {
            let h = handle.clone();
            async move {
                let data = h.read_at(off, len).await?;
                check_len(off, len, data.len())?;
                Ok(data)
            }
        },
        |rel, len, data: Bytes| dst[rel..rel + len].copy_from_slice(&data),
    )
    .await?;
    Ok(n)
}

fn clamp(range: Range<u64>, size: u64) -> Range<u64> {
    let start = range.start.min(size);
    start..range.end.min(size).max(start)
}

fn to_usize(n: u64) -> Result<usize> {
    usize::try_from(n)
        .map_err(|_| Error::invalid_input(format!("read of {n} bytes does not fit in memory")))
}

/// Error unless a backend returned exactly the requested length (the
/// `ReadHandle::read_at` contract once the range is clamped to the size).
pub(crate) fn check_len(offset: u64, expected: usize, got: usize) -> Result<()> {
    if got == expected {
        return Ok(());
    }
    let what = if got < expected {
        "short read"
    } else {
        "oversized read"
    };
    Err(Error::protocol(format!(
        "{what} at offset {offset}: expected {expected} bytes, got {got}"
    )))
}

/// Split `range` into parts and run `start(offset, len)` for each as a
/// spawned task, at most `concurrency` at a time and within `budget`, in
/// offset order. `place(offset_in_range, len, output)` is called on the
/// calling task as parts complete (in completion order); each part's budget
/// is released after its `place`. Stops at the first error; parts still in
/// flight are aborted when the join set is dropped.
async fn run_parts<T, S, Fut, P>(
    range: Range<u64>,
    part_size: usize,
    concurrency: usize,
    budget: Option<&MemoryBudget>,
    mut start: S,
    mut place: P,
) -> Result<()>
where
    T: Send + 'static,
    S: FnMut(u64, usize) -> Fut,
    Fut: Future<Output = Result<T>> + Send + 'static,
    P: FnMut(usize, usize, T),
{
    let part_size = part_size.max(1) as u64;
    let concurrency = concurrency.max(1);
    let mut set: JoinSet<(u64, usize, Result<T>, BudgetGuard)> = JoinSet::new();
    let mut next = range.start;
    loop {
        while next < range.end && set.len() < concurrency {
            let len = (range.end - next).min(part_size) as usize;
            let guard = match budget {
                None => BudgetGuard::empty(),
                Some(b) => match b.try_acquire(len) {
                    Some(g) => g,
                    // Progress guarantee: with nothing in flight, go ahead.
                    None if set.is_empty() => b.force_acquire(len),
                    // Otherwise wait for one of our parts to free its share.
                    None => break,
                },
            };
            let off = next;
            let fut = start(off, len);
            set.spawn(async move { (off, len, fut.await, guard) });
            next += len as u64;
        }
        let Some(joined) = set.join_next().await else {
            return Ok(());
        };
        let (off, len, res, guard) = joined.map_err(join_error)?;
        place((off - range.start) as usize, len, res?);
        drop(guard);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use fsfast_core::ErrorKind;
    use proptest::prelude::*;

    use super::*;
    use crate::testing::{MemReadHandle, pattern};

    fn handle(len: usize) -> (Arc<MemReadHandle>, Arc<dyn ReadHandle>) {
        let m = Arc::new(
            MemReadHandle::new(pattern(len))
                .with_latency(Duration::from_millis(2), Duration::from_millis(8)),
        );
        let h: Arc<dyn ReadHandle> = m.clone();
        (m, h)
    }

    #[tokio::test(start_paused = true)]
    async fn assembles_out_of_order_parts() {
        let (m, h) = handle(10_000);
        let budget = MemoryBudget::new(1 << 20);
        let out = read_parallel(&h, 123..9_876, 500, 4, Some(&budget))
            .await
            .unwrap();
        assert_eq!(out, m.data().slice(123..9_876));
        assert_eq!(m.requests(), (9_876u64 - 123).div_ceil(500));
        assert!(m.max_in_flight() <= 4);
        assert_eq!(m.max_in_flight(), 4);
        assert_eq!(budget.available(), 1 << 20);
    }

    #[tokio::test(start_paused = true)]
    async fn single_part_is_zero_copy() {
        let (m, h) = handle(1000);
        let out = read_parallel(&h, 100..600, 500, 4, None).await.unwrap();
        assert_eq!(out.as_ptr(), m.data()[100..].as_ptr());
        assert_eq!(m.requests(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn clamps_to_size_and_handles_empty_ranges() {
        let (m, h) = handle(1000);
        assert_eq!(
            read_parallel(&h, 900..5_000, 30, 3, None).await.unwrap(),
            m.data().slice(900..)
        );
        assert!(
            read_parallel(&h, 2_000..3_000, 30, 3, None)
                .await
                .unwrap()
                .is_empty()
        );
        #[allow(clippy::reversed_empty_ranges)]
        let reversed = 500..100;
        assert!(
            read_parallel(&h, reversed, 30, 3, None)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            read_parallel(&h, 10..10, 30, 3, None)
                .await
                .unwrap()
                .is_empty()
        );
        // Degenerate parameters are treated as 1.
        assert_eq!(
            read_parallel(&h, 0..7, 0, 0, None).await.unwrap(),
            m.data().slice(0..7)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn into_caller_buffer() {
        let (m, h) = handle(5_000);
        let mut buf = vec![0xAAu8; 3_000];
        let n = read_parallel_into(&h, 4_000, &mut buf, 256, 3, None)
            .await
            .unwrap();
        assert_eq!(n, 1_000);
        assert_eq!(&buf[..1_000], &m.data()[4_000..]);
        assert!(
            buf[1_000..].iter().all(|b| *b == 0xAA),
            "bytes past EOF untouched"
        );
        let n = read_parallel_into(&h, 10, &mut buf, 256, 3, None)
            .await
            .unwrap();
        assert_eq!(n, 3_000);
        assert_eq!(&buf[..], &m.data()[10..3_010]);
        assert_eq!(
            read_parallel_into(&h, 5_000, &mut buf, 256, 3, None)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            read_parallel_into(&h, 0, &mut [], 256, 3, None)
                .await
                .unwrap(),
            0
        );
        let mut small = [0u8; 10];
        assert_eq!(
            read_parallel_into(&h, 0, &mut small, 256, 3, None)
                .await
                .unwrap(),
            10
        );
        assert_eq!(&small, &m.data()[..10]);
    }

    #[tokio::test(start_paused = true)]
    async fn first_error_wins_and_aborts_the_rest() {
        let (m, h) = handle(10_000);
        m.set_fault(|r| {
            (r.offset == 3_000).then(|| fsfast_core::Error::new(ErrorKind::PermissionDenied, "no"))
        });
        let budget = MemoryBudget::new(1 << 20);
        let e = read_parallel(&h, 0..10_000, 1_000, 4, Some(&budget))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PermissionDenied);
        tokio::task::yield_now().await;
        assert_eq!(m.in_flight(), 0, "parts leaked");
        assert_eq!(Arc::strong_count(&m), 2);
        assert_eq!(budget.available(), 1 << 20);
    }

    #[derive(Debug)]
    struct ShortReads(Arc<MemReadHandle>);

    #[async_trait::async_trait]
    impl ReadHandle for ShortReads {
        fn info(&self) -> &fsfast_core::FileInfo {
            self.0.info()
        }
        async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
            let b = self.0.read_at(offset, len).await?;
            Ok(b.slice(..b.len().saturating_sub(1)))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn short_reads_are_protocol_errors() {
        let (m, _) = handle(1_000);
        let h: Arc<dyn ReadHandle> = Arc::new(ShortReads(m));
        let e = read_parallel(&h, 0..1_000, 100, 4, None).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol);
        let e = read_parallel(&h, 0..50, 100, 4, None).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol);
        let mut buf = [0u8; 10];
        let e = read_parallel_into(&h, 0, &mut buf, 100, 4, None)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol);
        assert!(
            check_len(0, 5, 6)
                .unwrap_err()
                .message()
                .contains("oversized")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn budget_limits_parts_in_flight() {
        let (m, h) = handle(10_000);
        // Room for two 1000-byte parts.
        let budget = MemoryBudget::new(2_500);
        let out = read_parallel(&h, 0..10_000, 1_000, 8, Some(&budget))
            .await
            .unwrap();
        assert_eq!(out, *m.data());
        assert_eq!(m.max_in_flight(), 2);
        assert_eq!(budget.available(), 2_500);

        // An exhausted budget still makes progress, one part at a time.
        m.reset_counters();
        let hog = budget.force_acquire(2_500);
        let out = read_parallel(&h, 0..10_000, 1_000, 8, Some(&budget))
            .await
            .unwrap();
        assert_eq!(out, *m.data());
        assert_eq!(m.max_in_flight(), 1);
        drop(hog);
        assert_eq!(budget.available(), 2_500);
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_releases_everything() {
        let m = Arc::new(
            MemReadHandle::new(pattern(10_000))
                .with_latency(Duration::from_secs(10), Duration::ZERO),
        );
        let h: Arc<dyn ReadHandle> = m.clone();
        let budget = MemoryBudget::new(1 << 20);
        let fut = read_parallel(&h, 0..10_000, 1_000, 4, Some(&budget));
        let r = tokio::time::timeout(Duration::from_secs(1), fut).await;
        assert!(r.is_err());
        tokio::task::yield_now().await;
        assert_eq!(m.in_flight(), 0);
        assert_eq!(budget.available(), 1 << 20);
        assert_eq!(Arc::strong_count(&m), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn multi_thread_runtime() {
        let m = Arc::new(MemReadHandle::new(pattern(1 << 20)));
        let h: Arc<dyn ReadHandle> = m.clone();
        let out = read_parallel(&h, 0..(1 << 20), 4096, 16, Some(MemoryBudget::global()))
            .await
            .unwrap();
        assert_eq!(out, *m.data());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(crate::proptest_cases(128)))]
        #[test]
        fn matches_reference(
            size in 0usize..5_000,
            start in 0u64..6_000,
            len in 0u64..6_000,
            part in 1usize..700,
            conc in 1usize..6,
            budget_bytes in 1usize..3_000,
            into in any::<bool>(),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().enable_time().start_paused(true).build().unwrap();
            rt.block_on(async {
                let (m, h) = handle(size);
                let budget = MemoryBudget::new(budget_bytes);
                let s = (start as usize).min(size);
                let e = ((start + len) as usize).min(size).max(s);
                if into {
                    let mut buf = vec![0u8; len as usize];
                    let n = read_parallel_into(&h, start, &mut buf, part, conc, Some(&budget)).await.unwrap();
                    prop_assert_eq!(n, e - s);
                    prop_assert_eq!(&buf[..n], &m.data()[s..e]);
                } else {
                    let out = read_parallel(&h, start..start + len, part, conc, Some(&budget)).await.unwrap();
                    prop_assert_eq!(&out[..], &m.data()[s..e]);
                }
                prop_assert!(m.max_in_flight() <= conc);
                prop_assert_eq!(budget.available(), budget_bytes);
                Ok(())
            })?;
        }
    }
}
