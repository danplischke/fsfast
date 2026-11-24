//! Read-path checks: whole-file round trips, ranges, positional reads.

use std::ops::Range;

use bytes::Bytes;
use fsfast_core::{ByteRange, ErrorKind, ReadOptions, path};

use crate::ctx::{CheckResult, Context, Ctx, compare_bytes, expect_err, verify_pattern};
use crate::pattern::{self, XorShift};

/// Locally computed `cat_file` result for `range` of `data`.
fn slice_for(data: &[u8], range: ByteRange) -> &[u8] {
    let r = range.resolve(data.len() as u64);
    &data[r.start as usize..r.end as usize]
}

/// Locally computed `cat_ranges` result for one requested range.
fn clamp(data_len: u64, r: &Range<u64>) -> Range<usize> {
    let s = r.start.min(data_len);
    let e = r.end.min(data_len).max(s);
    s as usize..e as usize
}

pub(crate) async fn pipe_cat_roundtrip(ctx: &Ctx) -> CheckResult {
    let all_256: Vec<u8> = (0..=255u8).collect();
    let all_256_mixed: Vec<u8> = (0..=255u8)
        .rev()
        .chain(0..=255u8)
        .cycle()
        .take(4 * 256 + 3)
        .collect();
    let small = ctx.path("small.txt");
    let cases: Vec<(String, Bytes)> = vec![
        (ctx.path("empty"), Bytes::new()),
        (ctx.path("one_byte"), Bytes::from_static(&[0x5a])),
        (small.clone(), ctx.pattern(&small, 1000)),
        (ctx.path("all_256_values.bin"), Bytes::from(all_256)),
        (ctx.path("all_256_mixed.bin"), Bytes::from(all_256_mixed)),
        (
            ctx.path("nul_ff.bin"),
            Bytes::from_static(&[0, 0xff, 0, 0, 0xff, b'\n', b'\r']),
        ),
        (
            ctx.path("nested/deeper/file.bin"),
            Bytes::from_static(b"nested"),
        ),
    ];
    for (p, data) in &cases {
        ctx.put(p, data.clone()).await?;
        ctx.expect_content(p, data).await?;
        ctx.expect_file(p, data.len() as u64).await?;
    }
    // Overwriting with shorter content must truncate.
    ctx.put(&small, Bytes::from_static(b"short")).await?;
    ctx.expect_content(&small, b"short").await?;
    ctx.expect_file(&small, 5).await?;
    // Overwriting with empty content.
    ctx.put(&small, Bytes::new()).await?;
    ctx.expect_content(&small, b"").await?;
    Ok(())
}

pub(crate) async fn cat_file_ranges(ctx: &Ctx) -> CheckResult {
    const N: u64 = 10_007;
    let p = ctx.path("ranges.bin");
    let data = ctx.pattern(&p, N as usize);
    ctx.put(&p, data.clone()).await?;

    let ranges = [
        ByteRange::Full,
        ByteRange::Bounded { start: 0, end: N },
        ByteRange::Bounded { start: 0, end: 1 },
        ByteRange::Bounded {
            start: 10,
            end: 100,
        },
        ByteRange::Bounded {
            start: N - 1,
            end: N,
        },
        // Past-EOF clamping.
        ByteRange::Bounded {
            start: N - 5,
            end: N + 100,
        },
        ByteRange::Bounded {
            start: 0,
            end: N + 1_000_000,
        },
        // Start at / beyond EOF.
        ByteRange::Bounded {
            start: N,
            end: N + 10,
        },
        ByteRange::Bounded {
            start: N + 10,
            end: N + 20,
        },
        // Empty and inverted ranges.
        ByteRange::Bounded { start: 0, end: 0 },
        ByteRange::Bounded { start: 50, end: 50 },
        ByteRange::Bounded { start: 60, end: 50 },
        ByteRange::From(0),
        ByteRange::From(1),
        ByteRange::From(N - 1),
        ByteRange::From(N),
        ByteRange::From(N + 5),
        ByteRange::Suffix(0),
        ByteRange::Suffix(1),
        ByteRange::Suffix(10),
        ByteRange::Suffix(N),
        ByteRange::Suffix(N + 100),
    ];
    for r in ranges {
        let got = ctx
            .fs
            .cat_file(&p, r)
            .await
            .ctx(format_args!("cat_file({p:?}, {r:?})"))?;
        let resolved = r.resolve(N);
        compare_bytes(
            &format!("cat_file({p:?}, {r:?})"),
            resolved.start,
            slice_for(&data, r),
            &got,
        )?;
    }

    // Every range of an empty file is empty.
    let empty = ctx.path("empty.bin");
    ctx.put(&empty, Bytes::new()).await?;
    for r in [
        ByteRange::Full,
        ByteRange::From(0),
        ByteRange::From(3),
        ByteRange::Suffix(5),
        ByteRange::Bounded { start: 0, end: 10 },
    ] {
        let got = ctx
            .fs
            .cat_file(&empty, r)
            .await
            .ctx(format_args!("cat_file({empty:?}, {r:?})"))?;
        ensure!(
            got.is_empty(),
            "cat_file({empty:?}, {r:?}) on an empty file returned {} bytes",
            got.len()
        );
    }

    let missing = ctx.path("missing.bin");
    expect_err(
        format!("cat_file({missing:?})"),
        ctx.fs.cat_file(&missing, ByteRange::Full).await,
        &[ErrorKind::NotFound],
    )
}

pub(crate) async fn cat_ranges(ctx: &Ctx) -> CheckResult {
    // Large enough that "far apart" ranges exceed the backend's coalescing
    // gap, so both merged and separate fetches are exercised.
    let gap = ctx.hints.coalesce_gap;
    let size = gap
        .saturating_mul(3)
        .saturating_add(64 << 10)
        .clamp(256 << 10, 8 << 20)
        + 13;
    let p = ctx.path("cat_ranges.bin");
    let data = ctx.pattern(&p, size as usize);
    ctx.put(&p, data.clone()).await?;

    let ranges: Vec<Range<u64>> = vec![
        0..1000,
        500..1500, // overlaps the previous one
        2000..3000,
        2000..3000, // duplicate
        50_000..51_000,
        10_000..11_000, // out of order
        4000..5000,
        5000..6000, // adjacent to the previous one
        0..10,
        size - 10..size,        // far apart from the previous one
        size - 100..size + 100, // crosses EOF: truncated
        size + 10..size + 20,   // entirely past EOF: empty
        7000..7000,             // empty
        Range {
            start: 9000,
            end: 8000,
        }, // inverted: empty
        100..size / 2,          // large
        size / 2 - 1..size / 2 + 1,
    ];

    let check = |what: &str, got: &[Bytes]| -> CheckResult {
        ensure_eq!(
            got.len(),
            ranges.len(),
            "{what}: number of returned buffers"
        );
        for (i, (r, g)) in ranges.iter().zip(got).enumerate() {
            let c = clamp(size, r);
            compare_bytes(
                &format!("{what}: range #{i} ({r:?})"),
                c.start as u64,
                &data[c],
                g,
            )?;
        }
        Ok(())
    };

    let got = ctx
        .fs
        .cat_ranges(&p, &ranges)
        .await
        .ctx(format_args!("cat_ranges({p:?})"))?;
    check(&format!("cat_ranges({p:?})"), &got)?;

    let h = ctx
        .fs
        .open_read(&p, &ReadOptions::default())
        .await
        .ctx(format_args!("open_read({p:?})"))?;
    let got = h
        .read_ranges(&ranges)
        .await
        .ctx(format_args!("read_ranges({p:?})"))?;
    check(&format!("ReadHandle::read_ranges({p:?})"), &got)?;
    h.close().await.ctx("ReadHandle::close")?;

    let none = ctx
        .fs
        .cat_ranges(&p, &[])
        .await
        .ctx(format_args!("cat_ranges({p:?}, [])"))?;
    ensure!(
        none.is_empty(),
        "cat_ranges with no ranges returned {} buffers",
        none.len()
    );

    let missing = ctx.path("missing.bin");
    expect_err(
        format!("cat_ranges({missing:?})"),
        ctx.fs
            .cat_ranges(&missing, std::slice::from_ref(&(0..1)))
            .await,
        &[ErrorKind::NotFound],
    )
}

pub(crate) async fn open_read_errors(ctx: &Ctx) -> CheckResult {
    let missing = ctx.path("missing");
    expect_err(
        format!("open_read({missing:?})"),
        ctx.fs.open_read(&missing, &ReadOptions::default()).await,
        &[ErrorKind::NotFound],
    )?;
    let deep = ctx.path("missing_dir/child");
    expect_err(
        format!("open_read({deep:?})"),
        ctx.fs.open_read(&deep, &ReadOptions::default()).await,
        &[ErrorKind::NotFound],
    )?;

    // A directory cannot be read as a file. Hierarchical backends report
    // IsADirectory (or NotFound, as fsspec's memory filesystem does for
    // implied directories); object stores have no such key: NotFound.
    let dir = ctx.path("a_dir");
    ctx.ensure_dir(&dir).await?;
    ctx.put(&path::join(&dir, "child"), Bytes::from_static(b"c"))
        .await?;
    expect_err(
        format!("open_read({dir:?}) of a directory"),
        ctx.fs.open_read(&dir, &ReadOptions::default()).await,
        &[ErrorKind::IsADirectory, ErrorKind::NotFound],
    )?;
    expect_err(
        format!("cat_file({dir:?}) of a directory"),
        ctx.fs.cat_file(&dir, ByteRange::Full).await,
        &[ErrorKind::IsADirectory, ErrorKind::NotFound],
    )
}

pub(crate) async fn read_at_eof(ctx: &Ctx) -> CheckResult {
    const N: u64 = 1000;
    let p = ctx.path("eof.bin");
    let data = ctx.pattern(&p, N as usize);
    ctx.put(&p, data.clone()).await?;
    let h = ctx
        .fs
        .open_read(&p, &ReadOptions::default())
        .await
        .ctx(format_args!("open_read({p:?})"))?;
    ensure_eq!(h.size(), N, "ReadHandle::size()");
    ensure_eq!(
        h.info().name,
        path::normalize(&p),
        "ReadHandle::info().name"
    );
    ensure!(
        h.info().is_file(),
        "ReadHandle::info() is not a file: {:?}",
        h.info().file_type
    );

    let cases: [(u64, usize, Range<usize>); 8] = [
        (N, 10, 0..0),                              // at EOF
        (N + 100, 10, 0..0),                        // past EOF
        (u64::MAX / 2, 10, 0..0),                   // far past EOF
        (N - 5, 100, (N - 5) as usize..N as usize), // spans EOF: truncated
        (0, 0, 0..0),                               // zero-length
        (0, N as usize, 0..N as usize),             // exactly the file
        (0, N as usize + 50, 0..N as usize),
        (17, 1, 17..18),
    ];
    for (off, len, exp) in cases {
        let got = h
            .read_at(off, len)
            .await
            .ctx(format_args!("read_at({off}, {len})"))?;
        compare_bytes(
            &format!("read_at({off}, {len}) on a {N}-byte file"),
            exp.start as u64,
            &data[exp],
            &got,
        )?;
    }
    h.close().await.ctx("ReadHandle::close")?;

    let empty = ctx.path("empty.bin");
    ctx.put(&empty, Bytes::new()).await?;
    let h = ctx
        .fs
        .open_read(&empty, &ReadOptions::default())
        .await
        .ctx(format_args!("open_read({empty:?})"))?;
    ensure_eq!(h.size(), 0, "ReadHandle::size() of an empty file");
    let got = h
        .read_at(0, 10)
        .await
        .ctx("read_at(0, 10) on an empty file")?;
    ensure!(
        got.is_empty(),
        "read_at(0, 10) on an empty file returned {} bytes",
        got.len()
    );
    h.close().await.ctx("ReadHandle::close")?;
    Ok(())
}

pub(crate) async fn concurrent_read_at(ctx: &Ctx) -> CheckResult {
    let size: u64 = (4 << 20) + 4093;
    let p = ctx.path("concurrent.bin");
    let seed = pattern::seed_for(&p);
    ctx.put(&p, pattern::generate_bytes(seed, 0, size as usize))
        .await?;
    let h = ctx
        .fs
        .open_read(&p, &ReadOptions::default())
        .await
        .ctx(format_args!("open_read({p:?})"))?;
    ensure_eq!(h.size(), size, "ReadHandle::size()");

    let n = ctx.cfg.concurrent_reads.max(1);
    let mut rng = XorShift::new(seed);
    let mut tasks = Vec::with_capacity(n);
    for i in 0..n {
        // Every eighth read straddles or starts past EOF.
        let (off, len) = if i % 8 == 7 {
            (size - rng.range(0, 512), rng.range(1, 4096) as usize + 512)
        } else {
            (rng.range(0, size - 1), rng.range(1, 256 << 10) as usize)
        };
        let h = h.clone();
        // Spawned so that multi-threaded runtimes issue the calls truly in
        // parallel on the one handle.
        tasks.push(tokio::spawn(async move {
            (off, len, h.read_at(off, len).await)
        }));
    }
    for t in tasks {
        let (off, len, r) = match t.await {
            Ok(v) => v,
            Err(e) => fail!("concurrent read_at task failed: {e}"),
        };
        let got = r.ctx(format_args!("concurrent read_at({off}, {len})"))?;
        let expected_len = len.min(size.saturating_sub(off) as usize);
        verify_pattern(
            &format!("concurrent read_at({off}, {len})"),
            seed,
            off,
            expected_len,
            &got,
        )?;
    }
    h.close().await.ctx("ReadHandle::close")?;
    Ok(())
}

pub(crate) async fn read_ranges_large(ctx: &Ctx) -> CheckResult {
    let size = ctx.cfg.large_file_bytes.max(1 << 20);
    let p = ctx.path("large_ranges.bin");
    let seed = pattern::seed_for(&p);
    ctx.put(&p, pattern::generate_bytes(seed, 0, size as usize))
        .await?;
    let req = ctx.hints.request_size.max(1) as u64;

    let mut ranges: Vec<Range<u64>> = vec![
        0..1,
        1..(req + 1).min(size),
        size - 1..size,
        0..size / 2,
        size / 2..size,
        size - 3..size + 3,
        size / 3..size / 3 + 1,
    ];
    let mut rng = XorShift::new(seed ^ 0x5eed);
    for _ in 0..40 {
        let start = rng.range(0, size - 1);
        let len = rng.range(1, 2 << 20);
        ranges.push(start..start + len);
    }
    let h = ctx
        .fs
        .open_read(&p, &ReadOptions::default())
        .await
        .ctx(format_args!("open_read({p:?})"))?;
    let got = h
        .read_ranges(&ranges)
        .await
        .ctx(format_args!("read_ranges({p:?})"))?;
    h.close().await.ctx("ReadHandle::close")?;
    ensure_eq!(
        got.len(),
        ranges.len(),
        "read_ranges: number of returned buffers"
    );
    for (i, (r, g)) in ranges.iter().zip(&got).enumerate() {
        let c = clamp(size, r);
        verify_pattern(
            &format!("read_ranges range #{i} ({r:?})"),
            seed,
            c.start as u64,
            c.len(),
            g,
        )?;
    }
    drop(got);

    // The same through the filesystem-level batch API, minus the two halves
    // to keep memory use moderate.
    let subset: Vec<Range<u64>> = ranges
        .iter()
        .filter(|r| r.end - r.start < size / 4)
        .cloned()
        .collect();
    let got = ctx
        .fs
        .cat_ranges(&p, &subset)
        .await
        .ctx(format_args!("cat_ranges({p:?})"))?;
    ensure_eq!(
        got.len(),
        subset.len(),
        "cat_ranges: number of returned buffers"
    );
    for (i, (r, g)) in subset.iter().zip(&got).enumerate() {
        let c = clamp(size, r);
        verify_pattern(
            &format!("cat_ranges range #{i} ({r:?})"),
            seed,
            c.start as u64,
            c.len(),
            g,
        )?;
    }
    Ok(())
}
