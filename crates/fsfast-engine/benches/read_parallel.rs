//! `read_parallel` of a 64 MiB range over a simulated object store (1 ms
//! latency, 512 MiB/s per request) for several part sizes and concurrency
//! levels, plus the zero-latency assembly cost.

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fsfast_core::ReadHandle;
use fsfast_engine::testing::{MemReadHandle, pattern};
use fsfast_engine::{MemoryBudget, read_parallel, read_parallel_into};

const SIZE: usize = 64 << 20;

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let data = pattern(SIZE);
    let budget = MemoryBudget::unlimited();

    let slow: Arc<dyn ReadHandle> = Arc::new(
        MemReadHandle::new(data.clone())
            .with_latency(Duration::from_millis(1), Duration::ZERO)
            .with_bandwidth(512 << 20)
            .without_log(),
    );
    let mut g = c.benchmark_group("read_parallel_simulated");
    g.throughput(Throughput::Bytes(SIZE as u64));
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(4));
    for (part, conc) in [(8 << 20, 1), (8 << 20, 8), (4 << 20, 16), (1 << 20, 16)] {
        let id = BenchmarkId::from_parameter(format!("part{}MiB_x{conc}", part >> 20));
        g.bench_function(id, |b| {
            b.to_async(&rt).iter(|| async {
                let out = read_parallel(&slow, 0..SIZE as u64, part, conc, Some(&budget))
                    .await
                    .unwrap();
                black_box(out.len())
            })
        });
    }
    g.finish();

    // No latency: measures task spawning plus in-place assembly.
    let fast: Arc<dyn ReadHandle> = Arc::new(MemReadHandle::new(data).without_log());
    let mut g = c.benchmark_group("read_parallel_assembly");
    g.throughput(Throughput::Bytes(SIZE as u64));
    g.sample_size(20);
    g.bench_function("bytes_part1MiB_x8", |b| {
        b.to_async(&rt).iter(|| async {
            let out = read_parallel(&fast, 0..SIZE as u64, 1 << 20, 8, Some(&budget))
                .await
                .unwrap();
            black_box(out.len())
        })
    });
    let mut dst = vec![0u8; SIZE];
    g.bench_function("into_part1MiB_x8", |b| {
        b.iter(|| {
            rt.block_on(async {
                let n = read_parallel_into(&fast, 0, &mut dst, 1 << 20, 8, Some(&budget))
                    .await
                    .unwrap();
                black_box(n)
            })
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
