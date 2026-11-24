//! `coalesce_ranges` over 10k ranges: random (unsorted, overlapping) and
//! zarr-like (sorted chunks with small gaps).

use std::hint::black_box;
use std::ops::Range;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use fsfast_core::coalesce_ranges;

fn random_ranges(n: usize, seed: u64) -> Vec<Range<u64>> {
    let mut rng = fastrand::Rng::with_seed(seed);
    (0..n)
        .map(|_| {
            let s = rng.u64(0..10_000_000_000);
            s..s + rng.u64(1..1_000_000)
        })
        .collect()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("coalesce_ranges");
    g.throughput(Throughput::Elements(10_000));
    let random = random_ranges(10_000, 1);
    let sorted: Vec<Range<u64>> = (0..10_000u64)
        .map(|i| i * 1_100_000..i * 1_100_000 + 1_000_000)
        .collect();
    let mut shuffled = sorted.clone();
    fastrand::Rng::with_seed(2).shuffle(&mut shuffled);
    g.bench_function("random_10k", |b| {
        b.iter(|| coalesce_ranges(black_box(&random), 1 << 20, 32 << 20))
    });
    g.bench_function("sorted_chunks_10k", |b| {
        b.iter(|| coalesce_ranges(black_box(&sorted), 1 << 20, 32 << 20))
    });
    g.bench_function("shuffled_chunks_10k", |b| {
        b.iter(|| coalesce_ranges(black_box(&shuffled), 1 << 20, 32 << 20))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
