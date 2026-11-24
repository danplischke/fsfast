//! Concurrency stress test: many readers (all cache modes) and uploaders
//! sharing one small memory budget on a multi-threaded runtime, with
//! simulated latency. Gated on `FSFAST_ENGINE_STRESS=1` because it takes a
//! few seconds.

use std::io::SeekFrom;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use fsfast_core::{IoHints, ReadHandle};
use fsfast_engine::testing::{MemPartSink, MemReadHandle, pattern};
use fsfast_engine::{
    BlockCacheConfig, CacheMode, FileReader, MemoryBudget, PartUploader, ReaderConfig,
    UploadConfig, UploadResult,
};

fn enabled() -> bool {
    if std::env::var("FSFAST_ENGINE_STRESS").is_ok_and(|v| v == "1") {
        return true;
    }
    eprintln!("skipping stress test: set FSFAST_ENGINE_STRESS=1 to run it");
    false
}

#[test]
fn shared_budget_under_load() {
    if !enabled() {
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        const SIZE: usize = 16 << 20;
        let budget = MemoryBudget::new(2 << 20);
        let mem = Arc::new(
            MemReadHandle::new(pattern(SIZE))
                .with_latency(Duration::from_micros(200), Duration::from_micros(800))
                .without_log()
                .with_hints(IoHints {
                    request_size: 256 << 10,
                    max_concurrency: 8,
                    ..IoHints::default()
                }),
        );
        let data = mem.data().clone();
        let modes = [
            CacheMode::None,
            CacheMode::Readahead,
            CacheMode::Whole,
            CacheMode::Blocks(BlockCacheConfig {
                block_size: Some(128 << 10),
                max_blocks: 8,
                prefetch: true,
            }),
        ];
        let mut tasks = Vec::new();
        for t in 0..16u64 {
            let h: Arc<dyn ReadHandle> = mem.clone();
            let data = data.clone();
            let budget = budget.clone();
            let mode = modes[t as usize % modes.len()];
            tasks.push(tokio::spawn(async move {
                let mut rng = fastrand::Rng::with_seed(t);
                let mut r = FileReader::new(
                    h,
                    ReaderConfig {
                        cache: mode,
                        budget: Some(budget),
                        ..ReaderConfig::default()
                    },
                );
                for _ in 0..200 {
                    if rng.u8(..) < 40 {
                        r.seek(SeekFrom::Start(rng.u64(0..SIZE as u64))).unwrap();
                    }
                    let pos = r.tell() as usize;
                    let n = if rng.bool() {
                        rng.usize(1..64 << 10)
                    } else {
                        rng.usize(1..2 << 20)
                    };
                    let b = r.read(Some(n)).await.unwrap();
                    let end = (pos + n).min(SIZE);
                    assert!(
                        b == data.slice(pos.min(SIZE)..end),
                        "mode {mode:?} pos {pos} n {n}"
                    );
                }
            }));
        }
        for t in 0..4u64 {
            let budget = budget.clone();
            tasks.push(tokio::spawn(async move {
                let sink = Arc::new(
                    MemPartSink::new()
                        .with_latency(Duration::from_micros(500), Duration::from_millis(1)),
                );
                let mut up = PartUploader::new(
                    sink.clone(),
                    UploadConfig {
                        part_size: 256 << 10,
                        min_part_size: 1,
                        concurrency: 8,
                        budget: Some(budget),
                        ..UploadConfig::default()
                    },
                )
                .unwrap();
                let data = pattern(8 << 20);
                let mut rng = fastrand::Rng::with_seed(100 + t);
                let mut off = 0;
                while off < data.len() {
                    let n = rng.usize(1..200_000).min(data.len() - off);
                    up.write(data.slice(off..off + n)).await.unwrap();
                    off += n;
                }
                let UploadResult::Multipart(parts) = up.finish().await.unwrap() else {
                    panic!("expected multipart");
                };
                assert_eq!(parts.len(), 32);
                assert!(sink.assembled() == data);
                assert_eq!(sink.duplicates(), 0);
                let _: Bytes = sink.assembled();
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        // Everything released; no task still holds the handle.
        for _ in 0..100 {
            if Arc::strong_count(&mem) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(Arc::strong_count(&mem), 1);
        assert_eq!(budget.available(), 2 << 20);
        assert!(!budget.is_overcommitted());
    });
}
