use std::io::SeekFrom;
use std::sync::Arc;
use std::time::Duration;

use fsfast_core::{Error, ErrorKind, IoHints, ReadHandle};
use proptest::prelude::*;

use super::*;
use crate::testing::{MemReadHandle, pattern};

fn mem(size: usize, latency_ms: u64, jitter_ms: u64) -> Arc<MemReadHandle> {
    Arc::new(
        MemReadHandle::new(pattern(size))
            .with_latency(
                Duration::from_millis(latency_ms),
                Duration::from_millis(jitter_ms),
            )
            .with_hints(IoHints {
                request_size: 1000,
                max_concurrency: 4,
                ..IoHints::default()
            }),
    )
}

fn reader(m: &Arc<MemReadHandle>, cache: CacheMode, budget: &MemoryBudget) -> FileReader {
    let h: Arc<dyn ReadHandle> = m.clone();
    FileReader::new(
        h,
        ReaderConfig {
            cache,
            request_size: Some(1000),
            concurrency: Some(4),
            min_readahead: 100,
            max_readahead: Some(8000),
            budget: Some(budget.clone()),
        },
    )
}

fn blocks(block_size: usize, max_blocks: usize, prefetch: bool) -> CacheMode {
    CacheMode::Blocks(BlockCacheConfig {
        block_size: Some(block_size),
        max_blocks,
        prefetch,
    })
}

const ALL_MODES: [CacheMode; 6] = [
    CacheMode::None,
    CacheMode::Readahead,
    CacheMode::Whole,
    CacheMode::Blocks(BlockCacheConfig {
        block_size: Some(300),
        max_blocks: 3,
        prefetch: false,
    }),
    CacheMode::Blocks(BlockCacheConfig {
        block_size: Some(300),
        max_blocks: 3,
        prefetch: true,
    }),
    CacheMode::Blocks(BlockCacheConfig {
        block_size: None,
        max_blocks: 1,
        prefetch: true,
    }),
];

/// Read sequentially until a prefetch request is outstanding.
async fn read_until_prefetching(r: &mut FileReader, m: &MemReadHandle) {
    for _ in 0..200 {
        r.read(Some(100)).await.unwrap();
        settle().await;
        if m.in_flight() > 0 {
            return;
        }
    }
    panic!("no prefetch issued");
}

/// Let aborted tasks run their drop glue.
async fn settle() {
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn every_mode_reads_correct_bytes() {
    for mode in ALL_MODES {
        let budget = MemoryBudget::new(1 << 20);
        let m = mem(10_000, 1, 2);
        let data = m.data().clone();
        let mut r = reader(&m, mode, &budget);
        assert_eq!(r.size(), 10_000);
        assert_eq!(
            r.read(Some(10)).await.unwrap(),
            data.slice(0..10),
            "{mode:?}"
        );
        assert_eq!(
            r.read(Some(500)).await.unwrap(),
            data.slice(10..510),
            "{mode:?}"
        );
        let mut buf = vec![0u8; 2_345];
        assert_eq!(r.read_into(&mut buf).await.unwrap(), 2_345);
        assert_eq!(&buf[..], &data[510..2_855], "{mode:?}");
        assert_eq!(r.seek(SeekFrom::Start(7_000)).unwrap(), 7_000);
        assert_eq!(
            r.read(Some(5_000)).await.unwrap(),
            data.slice(7_000..),
            "{mode:?}"
        );
        assert_eq!(r.tell(), 10_000);
        assert!(r.read(Some(1)).await.unwrap().is_empty());
        assert_eq!(r.read_into(&mut buf).await.unwrap(), 0);
        r.seek(SeekFrom::End(-3)).unwrap();
        assert_eq!(r.read(None).await.unwrap(), data.slice(9_997..), "{mode:?}");
        r.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(r.read(None).await.unwrap(), data, "{mode:?}");
        drop(r);
        settle().await;
        assert_eq!(m.in_flight(), 0, "{mode:?}");
        assert_eq!(budget.available(), 1 << 20, "{mode:?}");
        assert_eq!(Arc::strong_count(&m), 1, "{mode:?}: task leaked");
    }
}

#[tokio::test(start_paused = true)]
async fn seek_semantics() {
    let budget = MemoryBudget::new(1 << 20);
    let m = mem(100, 0, 0);
    let mut r = reader(&m, CacheMode::Readahead, &budget);
    assert_eq!(r.seek(SeekFrom::Current(10)).unwrap(), 10);
    assert_eq!(r.seek(SeekFrom::Current(-5)).unwrap(), 5);
    assert_eq!(r.seek(SeekFrom::End(0)).unwrap(), 100);
    assert_eq!(r.seek(SeekFrom::End(50)).unwrap(), 150);
    assert!(r.read(Some(10)).await.unwrap().is_empty());
    assert_eq!(r.tell(), 150, "reading past EOF does not move the position");
    let e = r.seek(SeekFrom::Current(-151)).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
    assert_eq!(r.tell(), 150, "failed seek leaves the position");
    assert_eq!(r.seek(SeekFrom::End(-100)).unwrap(), 0);
    assert!(r.seek(SeekFrom::End(-101)).is_err());
    assert!(r.seek(SeekFrom::Start(u64::MAX)).is_ok());
    assert!(r.seek(SeekFrom::Current(1)).is_err(), "overflow");
    assert!(r.read(Some(0)).await.unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn readahead_prefetches_sequential_reads() {
    let budget = MemoryBudget::new(1 << 20);
    let m = mem(100_000, 5, 0);
    let data = m.data().clone();
    let mut r = reader(&m, CacheMode::Readahead, &budget);
    let mut off = 0;
    while off < 100_000 {
        let b = r.read(Some(100)).await.unwrap();
        assert_eq!(b, data.slice(off..off + 100));
        off += 100;
    }
    // 1000 reads of 100 bytes served by ~100 requests of <= 1000 bytes.
    let reqs = m.requests();
    assert!(reqs <= 110, "{reqs} requests");
    // The window grew to keep several requests in flight.
    assert!(
        m.max_in_flight() >= 4,
        "max in flight {}",
        m.max_in_flight()
    );
    assert!(m.max_in_flight() <= 4 + 1);
    // No byte fetched twice, nothing fetched past EOF.
    let mut ranges = m.requested();
    ranges.sort_by_key(|r| r.start);
    for w in ranges.windows(2) {
        assert!(w[0].end <= w[1].start, "overlapping fetches {w:?}");
    }
    assert!(ranges.iter().all(|r| r.end <= 100_000));
    if let State::Readahead(ra) = &r.state {
        assert_eq!(ra.window(), 8000, "window grew to the max");
    }
}

#[tokio::test(start_paused = true)]
async fn readahead_window_grows_gradually() {
    let budget = MemoryBudget::new(1 << 20);
    let m = mem(1_000_000, 1, 0);
    let mut r = reader(&m, CacheMode::Readahead, &budget);
    let mut windows = Vec::new();
    for _ in 0..200 {
        r.read(Some(50)).await.unwrap();
        if let State::Readahead(ra) = &r.state {
            windows.push(ra.window());
        }
    }
    // init: 50 -> 64 * 4 = 256; then 4x while < max/16, then 2x, capped.
    windows.dedup();
    assert_eq!(windows, vec![256, 1024, 2048, 4096, 8000]);
}

#[tokio::test(start_paused = true)]
async fn readahead_random_reads_are_exact() {
    let budget = MemoryBudget::new(1 << 20);
    let m = mem(100_000, 1, 0);
    let data = m.data().clone();
    let mut r = reader(&m, CacheMode::Readahead, &budget);
    let offsets = [50_000u64, 10_000, 90_000, 30_000, 70_000];
    for &o in &offsets {
        r.seek(SeekFrom::Start(o)).unwrap();
        let b = r.read(Some(64)).await.unwrap();
        assert_eq!(b, data.slice(o as usize..o as usize + 64));
    }
    let expected: Vec<_> = offsets.iter().map(|&o| o..o + 64).collect();
    assert_eq!(m.requested(), expected, "random reads fetch exactly");
    settle().await;
    assert_eq!(m.in_flight(), 0);
}

#[tokio::test(start_paused = true)]
async fn readahead_starts_after_two_sequential_reads() {
    let budget = MemoryBudget::new(1 << 20);
    let m = mem(100_000, 1, 0);
    let mut r = reader(&m, CacheMode::Readahead, &budget);
    r.seek(SeekFrom::Start(5_000)).unwrap();
    r.read(Some(100)).await.unwrap(); // random: exact
    assert_eq!(m.requested(), vec![5_000..5_100]);
    r.read(Some(100)).await.unwrap(); // sequential: readahead kicks in
    let reqs = m.requested();
    assert!(reqs.len() >= 2);
    assert_eq!(reqs[1].start, 5_100);
    if let State::Readahead(ra) = &r.state {
        assert!(ra.window() > 0);
        assert!(ra.buffered_chunks() > 0);
    }
}

#[tokio::test(start_paused = true)]
async fn readahead_seek_away_cancels_prefetch() {
    let budget = MemoryBudget::new(1 << 20);
    let m = mem(100_000, 50, 0);
    let mut r = reader(&m, CacheMode::Readahead, &budget);
    read_until_prefetching(&mut r, &m).await;
    assert!(budget.available() < 1 << 20);
    // A seek within the prefetched range keeps it.
    r.seek(SeekFrom::Current(50)).unwrap();
    assert!(m.in_flight() > 0);
    // A far seek cancels everything immediately.
    r.seek(SeekFrom::Start(80_000)).unwrap();
    settle().await;
    assert_eq!(m.in_flight(), 0);
    assert_eq!(budget.available(), 1 << 20);
    assert_eq!(Arc::strong_count(&m), 2, "only the reader holds the handle");
    if let State::Readahead(ra) = &r.state {
        assert_eq!(ra.buffered_chunks(), 0);
    }
    let b = r.read(Some(10)).await.unwrap();
    assert_eq!(b, m.data().slice(80_000..80_010));
}

#[tokio::test(start_paused = true)]
async fn readahead_backward_seek_within_chunk_is_served_from_cache() {
    let budget = MemoryBudget::new(1 << 20);
    let m = mem(100_000, 1, 0);
    let mut r = reader(&m, CacheMode::Readahead, &budget);
    r.read(Some(10)).await.unwrap();
    r.read(Some(10)).await.unwrap();
    let before = m.requests();
    r.seek(SeekFrom::Start(5)).unwrap();
    assert_eq!(r.read(Some(10)).await.unwrap(), m.data().slice(5..15));
    assert_eq!(m.requests(), before, "served from the front chunk");
}

#[tokio::test(start_paused = true)]
async fn readahead_small_reads_are_zero_copy() {
    let budget = MemoryBudget::new(1 << 20);
    let m = mem(10_000, 1, 0);
    let mut r = reader(&m, CacheMode::Readahead, &budget);
    let mut zero_copy = 0;
    for i in 0..100usize {
        let b = r.read(Some(37)).await.unwrap();
        assert_eq!(b, m.data().slice(i * 37..i * 37 + 37));
        // Inside one chunk, the result is a slice of the backend's buffer.
        if b.as_ptr() == m.data()[i * 37..].as_ptr() {
            zero_copy += 1;
        }
    }
    // Chunks are >= 256 bytes, so at most one read in seven straddles two.
    assert!(zero_copy >= 85, "{zero_copy} of 100 reads were zero-copy");
}

#[tokio::test(start_paused = true)]
async fn large_reads_use_parallel_parts() {
    for mode in ALL_MODES {
        let budget = MemoryBudget::new(1 << 20);
        let m = mem(50_000, 10, 0);
        let mut r = reader(&m, mode, &budget);
        r.seek(SeekFrom::Start(1_234)).unwrap();
        let b = r.read(Some(20_000)).await.unwrap();
        assert_eq!(b, m.data().slice(1_234..21_234), "{mode:?}");
        if mode == CacheMode::Whole {
            assert_eq!(m.requested().len(), 50, "whole file in 1000-byte parts");
        } else {
            assert!(m.max_in_flight() >= 4, "{mode:?}: {}", m.max_in_flight());
            assert!(
                m.requested().iter().all(|r| r.end - r.start <= 1000),
                "{mode:?}"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn none_mode_fetches_exactly() {
    let budget = MemoryBudget::new(1 << 20);
    let m = mem(10_000, 1, 0);
    let mut r = reader(&m, CacheMode::None, &budget);
    r.read(Some(10)).await.unwrap();
    r.read(Some(10)).await.unwrap();
    r.seek(SeekFrom::Start(500)).unwrap();
    let mut buf = [0u8; 7];
    r.read_into(&mut buf).await.unwrap();
    assert_eq!(m.requested(), vec![0..10, 10..20, 500..507]);
}

#[tokio::test(start_paused = true)]
async fn whole_mode_fetches_once() {
    let budget = MemoryBudget::new(1 << 20);
    let m = mem(1_500, 1, 0);
    let mut r = reader(&m, CacheMode::Whole, &budget);
    for _ in 0..10 {
        r.read(Some(100)).await.unwrap();
    }
    r.seek(SeekFrom::Start(3)).unwrap();
    let b = r.read(Some(10)).await.unwrap();
    assert_eq!(
        b.as_ptr(),
        m.data()[3..].as_ptr(),
        "slices of the cached file"
    );
    assert_eq!(m.requested(), vec![0..1_500]);
    assert_eq!(budget.available(), (1 << 20) - 1_500);
    r.clear_cache();
    assert_eq!(budget.available(), 1 << 20);
}

/// The whole-file cache accounts every byte of the file up front; fetching
/// it must not take budget per part as well, or a file larger than the free
/// budget would be fetched one part at a time.
#[tokio::test(start_paused = true)]
async fn whole_file_fetch_is_not_serialized_by_its_own_accounting() {
    let budget = MemoryBudget::new(5_000);
    let m = mem(20_000, 10, 0);
    let mut r = reader(&m, CacheMode::Whole, &budget);
    assert_eq!(r.read(Some(10)).await.unwrap(), m.data().slice(0..10));
    assert_eq!(m.requests(), 20);
    assert_eq!(
        m.max_in_flight(),
        4,
        "parts fetched with the reader's concurrency"
    );
    // The file is accounted once (over-committing this small budget).
    assert_eq!(budget.in_use(), 20_000);
    drop(r);
    assert_eq!(budget.available(), 5_000);
    assert!(!budget.is_overcommitted());
}

#[tokio::test(start_paused = true)]
async fn blocks_are_aligned_cached_and_evicted_lru() {
    let budget = MemoryBudget::new(1 << 20);
    let m = mem(10_000, 1, 0);
    let mut r = reader(&m, blocks(1000, 2, false), &budget);
    r.seek(SeekFrom::Start(1_500)).unwrap();
    r.read(Some(10)).await.unwrap();
    assert_eq!(m.requested(), vec![1_000..2_000]);
    r.read(Some(1_000)).await.unwrap(); // 1510..2510: block 1 cached, block 2 fetched
    assert_eq!(m.requested(), vec![1_000..2_000, 2_000..3_000]);
    if let State::Blocks(b) = &r.state {
        assert_eq!(b.cached_blocks(), vec![1, 2]);
    }
    r.seek(SeekFrom::Start(5_000)).unwrap();
    r.read(Some(1)).await.unwrap(); // evicts block 1 (LRU)
    if let State::Blocks(b) = &r.state {
        assert_eq!(b.cached_blocks(), vec![2, 5]);
    }
    r.seek(SeekFrom::Start(2_100)).unwrap();
    r.read(Some(1)).await.unwrap(); // hit
    assert_eq!(m.requests(), 3);
    assert_eq!(budget.available(), (1 << 20) - 2_000);
    // Partial last block.
    r.seek(SeekFrom::Start(9_999)).unwrap();
    assert_eq!(r.read(None).await.unwrap(), m.data().slice(9_999..));
    assert_eq!(m.requested().last().unwrap(), &(9_000..10_000));
    drop(r);
    assert_eq!(budget.available(), 1 << 20);
}

#[tokio::test(start_paused = true)]
async fn blocks_background_prefetch() {
    let budget = MemoryBudget::new(1 << 20);
    let m = mem(10_000, 10, 0);
    let mut r = reader(&m, blocks(1000, 4, true), &budget);
    r.read(Some(10)).await.unwrap();
    settle().await;
    // Block 1 is being prefetched.
    assert_eq!(m.requested(), vec![0..1_000, 1_000..2_000]);
    tokio::time::sleep(Duration::from_millis(20)).await;
    r.seek(SeekFrom::Start(1_500)).unwrap();
    r.read(Some(10)).await.unwrap();
    settle().await;
    assert_eq!(m.requested(), vec![0..1_000, 1_000..2_000, 2_000..3_000]);
    // No prefetch past EOF.
    r.seek(SeekFrom::Start(9_500)).unwrap();
    r.read(Some(10)).await.unwrap();
    assert!(m.requested().iter().all(|r| r.end <= 10_000));
}

#[tokio::test(start_paused = true)]
async fn blocks_pending_fetch_is_shared() {
    let budget = MemoryBudget::new(1 << 20);
    let m = mem(10_000, 10, 0);
    let mut r = reader(&m, blocks(1000, 4, true), &budget);
    r.read(Some(10)).await.unwrap();
    // Read block 1 while its prefetch is still in flight: no second request.
    r.seek(SeekFrom::Start(1_000)).unwrap();
    r.read(Some(10)).await.unwrap();
    let reqs = m.requested();
    assert_eq!(reqs.iter().filter(|r| r.start == 1_000).count(), 1);
}

#[tokio::test(start_paused = true)]
async fn blocks_large_runs_bypass_cache() {
    let budget = MemoryBudget::new(1 << 20);
    let m = mem(50_000, 1, 0);
    let mut r = reader(&m, blocks(500, 8, false), &budget);
    r.read(Some(10)).await.unwrap(); // caches block 0
    r.seek(SeekFrom::Start(0)).unwrap();
    let b = r.read(Some(10_000)).await.unwrap();
    assert_eq!(b, m.data().slice(0..10_000));
    if let State::Blocks(blk) = &r.state {
        assert_eq!(blk.cached_blocks(), vec![0], "large run not cached");
    }
    // Block 0 came from the cache; the rest was read directly in parts.
    assert_eq!(m.requested()[0], 0..500);
    assert!(m.requested()[1..].iter().all(|r| r.start >= 500));
}

#[tokio::test(start_paused = true)]
async fn large_blocks_are_fetched_in_parallel_parts() {
    let budget = MemoryBudget::new(1 << 20);
    let m = mem(50_000, 5, 0);
    // 8000-byte blocks with 1000-byte requests: one block = 8 parallel parts.
    let mut r = reader(&m, blocks(8_000, 4, false), &budget);
    r.seek(SeekFrom::Start(8_100)).unwrap();
    assert_eq!(
        r.read(Some(10)).await.unwrap(),
        m.data().slice(8_100..8_110)
    );
    let reqs = m.requested();
    assert_eq!(reqs.len(), 8);
    assert!(
        reqs.iter()
            .all(|q| q.start >= 8_000 && q.end <= 16_000 && q.end - q.start == 1_000)
    );
    assert_eq!(m.max_in_flight(), 4, "bounded by the reader's concurrency");
    // The whole block is cached.
    assert_eq!(
        r.read(Some(7_000)).await.unwrap(),
        m.data().slice(8_110..15_110)
    );
    assert_eq!(m.requests(), 8);
}

#[tokio::test(start_paused = true)]
async fn prefetch_respects_budget() {
    // Budget smaller than one chunk: acquisitions are clamped to the whole
    // budget, so chunks (speculative or not) run alone, one in flight at a
    // time, and reads still succeed.
    let budget = MemoryBudget::new(50);
    let m = mem(20_000, 1, 0);
    let mut r = reader(&m, CacheMode::Readahead, &budget);
    let mut off = 0;
    while off < 5_000 {
        assert_eq!(
            r.read(Some(100)).await.unwrap(),
            m.data().slice(off..off + 100)
        );
        off += 100;
    }
    assert!(m.max_in_flight() <= 1, "{}", m.max_in_flight());
    drop(r);
    settle().await;
    assert_eq!(budget.available(), 50);
    assert!(!budget.is_overcommitted());

    // Blocks under a tiny budget still work (most recent blocks over-commit).
    let m = mem(5_000, 1, 0);
    let mut r = reader(&m, blocks(1000, 4, true), &budget);
    r.read(Some(4_500)).await.unwrap();
    r.seek(SeekFrom::Start(0)).unwrap();
    assert_eq!(r.read(None).await.unwrap(), *m.data());
    drop(r);
    assert_eq!(budget.available(), 50);
}

/// A readahead window smaller than the request size bounds *speculative*
/// prefetch only: bytes the caller asked for are still fetched in
/// request-sized pieces, not split into window-sized ones.
#[tokio::test(start_paused = true)]
async fn readahead_small_window_does_not_fragment_requested_bytes() {
    let budget = MemoryBudget::new(1 << 30);
    let m = Arc::new(MemReadHandle::new(pattern(100_000)));
    let h: Arc<dyn ReadHandle> = m.clone();
    let mut r = FileReader::new(
        h,
        ReaderConfig {
            cache: CacheMode::Readahead,
            request_size: Some(10_000),
            concurrency: Some(4),
            min_readahead: 1,
            max_readahead: Some(16),
            budget: Some(budget.clone()),
        },
    );
    // Sequential (first read at 0) but below the "large" threshold.
    assert_eq!(
        r.read(Some(15_000)).await.unwrap(),
        m.data().slice(0..15_000)
    );
    let reqs = m.requested();
    assert!(reqs.len() <= 3, "{} requests: {reqs:?}", reqs.len());
    assert!(reqs.iter().all(|q| q.end - q.start <= 10_000));
    // The next sequential read: same story.
    m.reset_counters();
    assert_eq!(
        r.read(Some(15_000)).await.unwrap(),
        m.data().slice(15_000..30_000)
    );
    assert!(m.requests() <= 3, "{} requests", m.requests());
    drop(r);
    settle().await;
    assert_eq!(budget.available(), 1 << 30);
}

/// Consecutive missing blocks smaller than the request size are fetched
/// together (one request per request-sized group), not one request per
/// block all at once; every block is still cached individually.
#[tokio::test(start_paused = true)]
async fn blocks_missing_runs_are_fetched_in_request_sized_groups() {
    let budget = MemoryBudget::new(1 << 30);
    let m = mem(100_000, 5, 0);
    let h: Arc<dyn ReadHandle> = m.clone();
    let mut r = FileReader::new(
        h,
        ReaderConfig {
            cache: blocks(100, 32, false),
            request_size: Some(1000),
            concurrency: Some(2),
            min_readahead: 1,
            max_readahead: None,
            budget: Some(budget.clone()),
        },
    );
    r.seek(SeekFrom::Start(250)).unwrap();
    assert_eq!(
        r.read(Some(1_500)).await.unwrap(),
        m.data().slice(250..1_750)
    );
    // Blocks 2..=17 (200..1800): 1600 bytes in groups of <= 1000 bytes.
    let reqs = m.requested();
    assert_eq!(reqs.len(), 2, "{reqs:?}");
    assert_eq!(reqs[0].start, 200);
    assert_eq!(reqs.last().unwrap().end, 1_800);
    assert!(reqs.iter().all(|q| q.end - q.start <= 1000));
    assert!(m.max_in_flight() <= 2, "{}", m.max_in_flight());
    if let State::Blocks(b) = &r.state {
        assert_eq!(b.cached_blocks(), (2..18).collect::<Vec<u64>>());
    }
    // Every block is served from the cache now, zero-copy within a block.
    r.seek(SeekFrom::Start(1_210)).unwrap();
    let b = r.read(Some(50)).await.unwrap();
    assert_eq!(b, m.data().slice(1_210..1_260));
    r.seek(SeekFrom::Start(200)).unwrap();
    assert_eq!(
        r.read(Some(1_600)).await.unwrap(),
        m.data().slice(200..1_800)
    );
    assert_eq!(m.requests(), 2, "cache hits issue no requests");
    // Evicting some blocks of a group releases their share of the budget.
    let held = (1 << 30) - budget.available();
    assert_eq!(held, 1_600);
    r.clear_cache();
    assert_eq!(budget.available(), 1 << 30);
    // A failing group fails the read; the reader recovers.
    m.set_fault(|q| (q.offset >= 5_000).then(|| Error::new(ErrorKind::Io, "bad")));
    r.seek(SeekFrom::Start(5_050)).unwrap();
    assert_eq!(r.read(Some(300)).await.unwrap_err().kind(), ErrorKind::Io);
    m.clear_fault();
    assert_eq!(
        r.read(Some(300)).await.unwrap(),
        m.data().slice(5_050..5_350)
    );
    drop(r);
    settle().await;
    assert_eq!(budget.available(), 1 << 30);
    assert_eq!(Arc::strong_count(&m), 1);
}

/// Blocks fetched together share one buffer (zero-copy slices), so the
/// group's budget is released only when its last block leaves the cache:
/// the accounting follows the memory that is actually held.
#[tokio::test(start_paused = true)]
async fn grouped_blocks_hold_budget_until_the_last_one_is_evicted() {
    let budget = MemoryBudget::new(1 << 30);
    let m = mem(100_000, 1, 0);
    let mut r = reader(&m, blocks(100, 4, false), &budget);
    let held = |b: &MemoryBudget| (1usize << 30) - b.available();
    r.read(Some(400)).await.unwrap(); // blocks 0..=3, one request
    assert_eq!(m.requests(), 1);
    assert_eq!(held(&budget), 400);
    for (i, block) in [9u64, 20, 30].into_iter().enumerate() {
        r.seek(SeekFrom::Start(block * 100)).unwrap();
        r.read(Some(1)).await.unwrap(); // evicts one block of the group
        // The group's 400 bytes stay accounted while any block holds them.
        assert_eq!(held(&budget), 400 + 100 * (i + 1), "after block {block}");
    }
    r.seek(SeekFrom::Start(4_000)).unwrap();
    r.read(Some(1)).await.unwrap(); // evicts the group's last block
    if let State::Blocks(b) = &r.state {
        assert_eq!(b.cached_blocks(), vec![9, 20, 30, 40]);
    }
    assert_eq!(held(&budget), 400);
    drop(r);
    assert_eq!(budget.available(), 1 << 30);
}

#[tokio::test(start_paused = true)]
async fn errors_surface_and_reader_recovers() {
    for mode in ALL_MODES {
        let budget = MemoryBudget::new(1 << 20);
        let m = mem(10_000, 1, 1);
        let mut r = reader(&m, mode, &budget);
        m.set_fault(|_| Some(Error::new(ErrorKind::ConnectionFailed, "reset")));
        let e = r.read(Some(100)).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ConnectionFailed, "{mode:?}");
        assert_eq!(r.tell(), 0, "position unchanged on error");
        let mut buf = [0u8; 50];
        assert!(r.read_into(&mut buf).await.is_err());
        m.clear_fault();
        assert_eq!(
            r.read(Some(100)).await.unwrap(),
            m.data().slice(0..100),
            "{mode:?}"
        );
        // A fault beyond 5000 surfaces when a read needs uncached data
        // there (the whole-file cache already holds everything).
        m.set_fault(|req| {
            (req.offset + req.len as u64 > 5_000).then(|| Error::new(ErrorKind::Io, "bad sector"))
        });
        let mut failed = false;
        while r.tell() < 10_000 {
            let pos = r.tell() as usize;
            match r.read(Some(100)).await {
                Ok(b) => assert_eq!(b, m.data().slice(pos..pos + 100), "{mode:?}"),
                Err(e) => {
                    assert_eq!(e.kind(), ErrorKind::Io);
                    assert_eq!(r.tell() as usize, pos);
                    failed = true;
                    break;
                }
            }
        }
        assert_eq!(failed, mode != CacheMode::Whole, "{mode:?}");
        drop(r);
        settle().await;
        assert_eq!(budget.available(), 1 << 20, "{mode:?}");
        assert_eq!(Arc::strong_count(&m), 1, "{mode:?}");
    }
}

#[derive(Debug)]
struct ShortChunks(Arc<MemReadHandle>);

#[async_trait::async_trait]
impl ReadHandle for ShortChunks {
    fn info(&self) -> &fsfast_core::FileInfo {
        self.0.info()
    }
    async fn read_at(&self, offset: u64, len: usize) -> fsfast_core::Result<Bytes> {
        let b = self.0.read_at(offset, len).await?;
        Ok(b.slice(..b.len() / 2))
    }
}

#[tokio::test(start_paused = true)]
async fn short_backend_reads_are_protocol_errors() {
    for mode in ALL_MODES {
        let budget = MemoryBudget::new(1 << 20);
        let h: Arc<dyn ReadHandle> = Arc::new(ShortChunks(mem(10_000, 0, 0)));
        let mut r = FileReader::new(
            h,
            ReaderConfig {
                cache: mode,
                budget: Some(budget.clone()),
                ..ReaderConfig::default()
            },
        );
        let e = r.read(Some(100)).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{mode:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn close_cancels_and_closes() {
    let budget = MemoryBudget::new(1 << 20);
    let m = mem(100_000, 100, 0);
    let mut r = reader(&m, CacheMode::Readahead, &budget);
    read_until_prefetching(&mut r, &m).await;
    r.close().await.unwrap();
    assert!(r.is_closed());
    r.close().await.unwrap();
    settle().await;
    assert_eq!(m.in_flight(), 0);
    assert_eq!(budget.available(), 1 << 20);
    assert_eq!(
        r.read(Some(1)).await.unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        r.read_into(&mut [0u8; 4]).await.unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        r.seek(SeekFrom::Start(0)).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(r.cache_mode(), CacheMode::Readahead);
}

#[tokio::test(start_paused = true)]
async fn cancelled_read_leaves_reader_consistent() {
    for mode in ALL_MODES {
        let budget = MemoryBudget::new(1 << 20);
        let m = mem(20_000, 10, 5);
        let mut r = reader(&m, mode, &budget);
        r.read(Some(100)).await.unwrap();
        // Cancel a read mid-flight (cached modes may complete it at once),
        // then continue reading.
        match tokio::time::timeout(Duration::from_millis(3), r.read(Some(3_000))).await {
            Ok(b) => {
                assert_eq!(b.unwrap(), m.data().slice(100..3_100), "{mode:?}");
                assert_eq!(r.tell(), 3_100);
            }
            Err(_) => assert_eq!(r.tell(), 100, "{mode:?}"),
        }
        let pos = r.tell() as usize;
        assert_eq!(
            r.read(Some(3_000)).await.unwrap(),
            m.data().slice(pos..pos + 3_000),
            "{mode:?}"
        );
        drop(r);
        settle().await;
        assert_eq!(budget.available(), 1 << 20, "{mode:?}");
        assert_eq!(m.in_flight(), 0, "{mode:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn defaults_derive_from_hints() {
    let m = Arc::new(MemReadHandle::new(pattern(100)).with_hints(IoHints {
        request_size: 7,
        max_concurrency: 3,
        ..IoHints::default()
    }));
    let h: Arc<dyn ReadHandle> = m.clone();
    let r = FileReader::new(h, ReaderConfig::with_cache(CacheMode::Readahead));
    assert_eq!(r.ctx.request_size, 7);
    assert_eq!(r.ctx.concurrency, 3);
    assert!(r.ctx.budget.same_budget(MemoryBudget::global()));
    assert!(format!("{r:?}").contains("mem/file"));
}

#[test]
fn fsspec_cache_type_names() {
    assert_eq!(
        CacheMode::from_fsspec("none", None, None).unwrap(),
        CacheMode::None
    );
    assert_eq!(
        CacheMode::from_fsspec("readahead", None, None).unwrap(),
        CacheMode::Readahead
    );
    assert_eq!(
        CacheMode::from_fsspec("bytes", None, None).unwrap(),
        CacheMode::Readahead
    );
    assert_eq!(
        CacheMode::from_fsspec("all", None, None).unwrap(),
        CacheMode::Whole
    );
    assert_eq!(
        CacheMode::from_fsspec("blockcache", Some(5 << 20), Some(8)).unwrap(),
        blocks(5 << 20, 8, false)
    );
    assert_eq!(
        CacheMode::from_fsspec("Background", None, None).unwrap(),
        CacheMode::Blocks(BlockCacheConfig {
            block_size: None,
            max_blocks: 32,
            prefetch: true
        })
    );
    assert_eq!(
        CacheMode::from_fsspec("parts", None, None)
            .unwrap_err()
            .kind(),
        ErrorKind::Unsupported
    );
    assert_eq!(
        CacheMode::from_fsspec("nope", None, None)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(CacheMode::default(), CacheMode::Readahead);
    // Every cache type registered by the reference fsspec (2026.9:
    // `fsspec.caching.caches`) is accepted, except `parts`, which needs
    // data supplied up front.
    for name in [
        "none",
        "mmap",
        "bytes",
        "readahead",
        "adaptive",
        "blockcache",
        "first",
        "all",
        "background",
    ] {
        assert!(
            CacheMode::from_fsspec(name, None, None).is_ok(),
            "fsspec cache_type {name:?} rejected"
        );
    }
    assert_eq!(
        CacheMode::from_fsspec("adaptive", None, None).unwrap(),
        CacheMode::Readahead
    );
}

#[test]
fn futures_are_send() {
    fn check<T: Send>(_: &T) {}
    let m = mem(10, 0, 0);
    let budget = MemoryBudget::new(10);
    let mut r = reader(&m, CacheMode::Readahead, &budget);
    check(&r);
    check(&r.read(Some(1)));
    let mut buf = [0u8; 1];
    check(&r.read_into(&mut buf));
    check(&r.close());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_thread_sequential_and_random() {
    for mode in ALL_MODES {
        let m = Arc::new(MemReadHandle::new(pattern(2 << 20)).with_hints(IoHints {
            request_size: 64 << 10,
            max_concurrency: 8,
            ..IoHints::default()
        }));
        let h: Arc<dyn ReadHandle> = m.clone();
        let budget = MemoryBudget::new(1 << 20);
        let mut r = FileReader::new(
            h,
            ReaderConfig {
                cache: mode,
                budget: Some(budget.clone()),
                ..ReaderConfig::default()
            },
        );
        let mut out = Vec::with_capacity(2 << 20);
        loop {
            let b = r.read(Some(10_000)).await.unwrap();
            if b.is_empty() {
                break;
            }
            out.extend_from_slice(&b);
        }
        assert_eq!(&out[..], &m.data()[..], "{mode:?}");
        for i in 0..50u64 {
            let off = (i * 7919 * 13) % (2 << 20);
            r.seek(SeekFrom::Start(off)).unwrap();
            let b = r.read(Some(5_000)).await.unwrap();
            let e = (off as usize + 5_000).min(2 << 20);
            assert_eq!(&b[..], &m.data()[off as usize..e], "{mode:?}");
        }
        drop(r);
        for _ in 0..100 {
            if Arc::strong_count(&m) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(Arc::strong_count(&m), 1, "{mode:?}");
        assert_eq!(budget.available(), 1 << 20, "{mode:?}");
    }
}

#[derive(Debug, Clone)]
enum Op {
    Read(Option<usize>),
    ReadInto(usize),
    Seek(SeekFrom),
    Sleep(u64),
    /// `read(n)` whose future is dropped after `ms` milliseconds unless it
    /// completed by then.
    CancelRead(Option<usize>, u64),
    /// `read_into` of `n` bytes, dropped after `ms` milliseconds.
    CancelReadInto(usize, u64),
    ClearCache,
    /// Fail every request overlapping `[at, at + 1000)` until `ClearFault`.
    SetFault(u64),
    ClearFault,
}

fn op_strategy(size: usize) -> impl Strategy<Value = Op> {
    let s = size as u64 + 50;
    prop_oneof![
        4 => (0usize..400).prop_map(|n| Op::Read(Some(n))),
        1 => Just(Op::Read(None)),
        3 => (0usize..400).prop_map(Op::ReadInto),
        1 => (0usize..3000).prop_map(|n| Op::Read(Some(n))),
        2 => (0..s).prop_map(|p| Op::Seek(SeekFrom::Start(p))),
        2 => (-300i64..300).prop_map(|d| Op::Seek(SeekFrom::Current(d))),
        1 => (-(s as i64)..20).prop_map(|d| Op::Seek(SeekFrom::End(d))),
        1 => (0u64..30).prop_map(Op::Sleep),
        2 => (proptest::option::of(0usize..3000), 0u64..15)
            .prop_map(|(n, ms)| Op::CancelRead(n, ms)),
        1 => (0usize..3000, 0u64..15).prop_map(|(n, ms)| Op::CancelReadInto(n, ms)),
        1 => Just(Op::ClearCache),
        2 => (0..s).prop_map(Op::SetFault),
        2 => Just(Op::ClearFault),
    ]
}

fn mode_strategy() -> impl Strategy<Value = CacheMode> {
    prop_oneof![
        Just(CacheMode::None),
        Just(CacheMode::Readahead),
        Just(CacheMode::Whole),
        (1usize..400, 1usize..6, any::<bool>()).prop_map(|(bs, mb, p)| blocks(bs, mb, p)),
    ]
}

/// Reference model of fsspec file positioning.
fn model_seek(pos: u64, size: u64, to: SeekFrom) -> Option<u64> {
    match to {
        SeekFrom::Start(n) => Some(n),
        SeekFrom::Current(d) => pos.checked_add_signed(d),
        SeekFrom::End(d) => size.checked_add_signed(d),
    }
}

fn run_ops(
    size: usize,
    mode: CacheMode,
    request: usize,
    conc: usize,
    max_ra: usize,
    budget_bytes: usize,
    ops: Vec<Op>,
) -> Result<(), TestCaseError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    rt.block_on(async {
        let m = Arc::new(
            MemReadHandle::new(pattern(size))
                .with_latency(Duration::from_millis(1), Duration::from_millis(10)),
        );
        let data = m.data().clone();
        let budget = MemoryBudget::new(budget_bytes);
        let h: Arc<dyn ReadHandle> = m.clone();
        let mut r = FileReader::new(
            h,
            ReaderConfig {
                cache: mode,
                request_size: Some(request),
                concurrency: Some(conc),
                min_readahead: 1,
                max_readahead: Some(max_ra),
                budget: Some(budget.clone()),
            },
        );
        let mut pos = 0u64;
        // A fault is active now / was active at some point.
        let (mut fault_active, mut faulted) = (false, false);
        // A read error is allowed only as the injected `Io` failure; it must
        // leave the position alone, and with no fault active an immediate
        // retry of the same read must succeed (no stale errors).
        macro_rules! on_error {
            ($e:expr, $retry:expr) => {{
                let e = $e;
                prop_assert_eq!(e.kind(), ErrorKind::Io, "unexpected error {}", e);
                prop_assert!(faulted, "error without an injected fault: {}", e);
                prop_assert_eq!(r.tell(), pos, "failed read moved the position");
                if fault_active {
                    None
                } else {
                    match $retry {
                        Ok(v) => Some(v),
                        Err(e) => {
                            return Err(TestCaseError::fail(format!("retry failed: {e}")));
                        }
                    }
                }
            }};
        }
        for op in ops {
            match op {
                Op::Read(n) => {
                    let got = match r.read(n).await {
                        Ok(b) => Some(b),
                        Err(e) => on_error!(e, r.read(n).await),
                    };
                    if let Some(b) = got {
                        let s = (pos as usize).min(size);
                        let e = n.map_or(size, |n| s.saturating_add(n).min(size));
                        prop_assert_eq!(&b[..], &data[s..e], "read {:?} at {}", n, pos);
                        pos += (e - s) as u64;
                    }
                }
                Op::ReadInto(n) => {
                    let mut buf = vec![0xEEu8; n];
                    let got = match r.read_into(&mut buf).await {
                        Ok(k) => Some(k),
                        Err(e) => on_error!(e, r.read_into(&mut buf).await),
                    };
                    if let Some(got) = got {
                        let s = (pos as usize).min(size);
                        let e = s.saturating_add(n).min(size);
                        prop_assert_eq!(got, e - s);
                        prop_assert_eq!(&buf[..got], &data[s..e]);
                        prop_assert!(buf[got..].iter().all(|b| *b == 0xEE));
                        pos += got as u64;
                    }
                }
                Op::Seek(to) => match model_seek(pos, size as u64, to) {
                    Some(p) => {
                        prop_assert_eq!(r.seek(to).unwrap(), p);
                        pos = p;
                    }
                    None => prop_assert!(r.seek(to).is_err()),
                },
                Op::Sleep(ms) => tokio::time::sleep(Duration::from_millis(ms)).await,
                Op::CancelRead(n, ms) => {
                    let res = tokio::time::timeout(Duration::from_millis(ms), r.read(n)).await;
                    // Timed out (future dropped): the position must not move,
                    // which the check after the match verifies.
                    let got = match res {
                        Err(_) => None,
                        Ok(Ok(b)) => Some(b),
                        Ok(Err(e)) => on_error!(e, r.read(n).await),
                    };
                    if let Some(b) = got {
                        let s = (pos as usize).min(size);
                        let e = n.map_or(size, |n| s.saturating_add(n).min(size));
                        prop_assert_eq!(&b[..], &data[s..e], "read {:?} at {}", n, pos);
                        pos += (e - s) as u64;
                    }
                }
                Op::CancelReadInto(n, ms) => {
                    let mut buf = vec![0xEEu8; n];
                    let res =
                        tokio::time::timeout(Duration::from_millis(ms), r.read_into(&mut buf))
                            .await;
                    let got = match res {
                        Err(_) => None,
                        Ok(Ok(k)) => Some(k),
                        Ok(Err(e)) => on_error!(e, r.read_into(&mut buf).await),
                    };
                    if let Some(got) = got {
                        let s = (pos as usize).min(size);
                        let e = s.saturating_add(n).min(size);
                        prop_assert_eq!(got, e - s);
                        prop_assert_eq!(&buf[..got], &data[s..e]);
                        pos += got as u64;
                    }
                }
                Op::ClearCache => r.clear_cache(),
                Op::SetFault(at) => {
                    m.set_fault(move |q| {
                        (q.offset < at + 1000 && q.offset + q.len as u64 > at)
                            .then(|| Error::new(ErrorKind::Io, "injected"))
                    });
                    fault_active = true;
                    faulted = true;
                }
                Op::ClearFault => {
                    m.clear_fault();
                    fault_active = false;
                }
            }
            prop_assert_eq!(r.tell(), pos);
        }
        drop(r);
        settle().await;
        prop_assert_eq!(m.in_flight(), 0, "requests still running after drop");
        prop_assert_eq!(Arc::strong_count(&m), 1, "background task leaked");
        prop_assert_eq!(budget.available(), budget_bytes, "budget leaked");
        prop_assert!(!budget.is_overcommitted());
        Ok(())
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(crate::proptest_cases(256)))]

    #[test]
    fn random_ops_match_reference(
        size in 0usize..4_000,
        mode in mode_strategy(),
        request in 1usize..300,
        conc in 1usize..6,
        max_ra in 1usize..2_000,
        budget_bytes in prop_oneof![1usize..200, 200usize..5_000, Just(1usize << 30)],
        ops in proptest::collection::vec(op_strategy(4_000), 1..40),
    ) {
        run_ops(size, mode, request, conc, max_ra, budget_bytes, ops)?;
    }

    #[test]
    fn sequential_scans_match_reference(
        size in 0usize..20_000,
        mode in mode_strategy(),
        request in 1usize..2_000,
        read in 1usize..1_500,
        budget_bytes in prop_oneof![1usize..500, Just(1usize << 30)],
    ) {
        let ops = vec![Op::Read(Some(read)); size / read + 2];
        run_ops(size, mode, request, 4, request * 8, budget_bytes, ops)?;
    }
}
