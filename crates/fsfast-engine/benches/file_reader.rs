//! `FileReader` sequential read throughput over an in-memory handle that
//! simulates object-store behaviour: 1 ms latency per request plus a
//! per-request bandwidth of 512 MiB/s (so concurrency pays off), using real
//! tokio time.

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fsfast_core::{IoHints, ReadHandle};
use fsfast_engine::testing::{MemReadHandle, pattern};
use fsfast_engine::{BlockCacheConfig, CacheMode, FileReader, MemoryBudget, ReaderConfig};

const SIZE: usize = 32 << 20;

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let data = pattern(SIZE);
    let modes = [
        ("none", CacheMode::None),
        ("readahead", CacheMode::Readahead),
        (
            "blockcache",
            CacheMode::Blocks(BlockCacheConfig {
                block_size: Some(4 << 20),
                max_blocks: 32,
                prefetch: false,
            }),
        ),
        (
            "background",
            CacheMode::Blocks(BlockCacheConfig {
                block_size: Some(4 << 20),
                max_blocks: 32,
                prefetch: true,
            }),
        ),
    ];
    let mut g = c.benchmark_group("file_reader_sequential");
    g.throughput(Throughput::Bytes(SIZE as u64));
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(4));
    for (name, mode) in modes {
        for read_size in [64usize << 10, 1 << 20] {
            g.bench_with_input(
                BenchmarkId::new(name, read_size),
                &read_size,
                |b, &read_size| {
                    b.to_async(&rt).iter(|| {
                        let data = data.clone();
                        async move {
                            let h: Arc<dyn ReadHandle> = Arc::new(
                                MemReadHandle::new(data)
                                    .with_latency(Duration::from_millis(1), Duration::ZERO)
                                    .with_bandwidth(512 << 20)
                                    .without_log()
                                    .with_hints(IoHints {
                                        request_size: 4 << 20,
                                        max_concurrency: 16,
                                        ..IoHints::default()
                                    }),
                            );
                            let mut r = FileReader::new(
                                h,
                                ReaderConfig {
                                    cache: mode,
                                    budget: Some(MemoryBudget::unlimited()),
                                    ..ReaderConfig::default()
                                },
                            );
                            let mut buf = vec![0u8; read_size];
                            let mut total = 0;
                            loop {
                                let n = r.read_into(&mut buf).await.unwrap();
                                if n == 0 {
                                    break;
                                }
                                total += n;
                                black_box(&buf);
                            }
                            assert_eq!(total, SIZE);
                        }
                    })
                },
            );
        }
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
