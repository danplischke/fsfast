//! `fsf bench`: named workloads against any URL.
//!
//! Every workload runs `warmup` untimed iterations, then `iterations`
//! measured ones. Per iteration it records the wall time, the operations
//! and bytes it moved, and (for multi-operation workloads) the latency of
//! every single operation. Engine counters (requests, retries, bytes on the
//! wire) are snapshotted around the timed section of every measured
//! iteration only, so setup, warm-up and per-iteration preparation/cleanup
//! never pollute them.
//!
//! Everything is created under a unique prefix
//! `<URL>/fsf-bench-<millis>-<pid>-<rand>` that is deleted at the end (also
//! after an error or Ctrl-C) unless `--keep` is given.
//!
//! Throughput is reported in decimal MB/s (10^6 bytes per second) as
//! s5cmd, azcopy and fio do; sizes on the command line accept binary and
//! decimal units (see [`crate::units::parse_size`]).

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use fsfast_core::{
    ByteRange, Error, ErrorKind, FileSystem, FindOptions, ReadOptions, Result, WriteOptions,
};
use fsfast_engine::Stats;
use futures::{StreamExt, TryStreamExt, stream};

use crate::ops::{self, CopyMethod, Counters};
use crate::target::{Resolved, Session, child_path};
use crate::units::{format_bytes, format_duration, rfc3339};

/// A named benchmark workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Workload {
    /// Large sequential read of one file.
    W1,
    /// Large sequential write of one file.
    W2,
    /// Many small files read.
    W3,
    /// Many small files written.
    W4,
    /// Metadata: `info` on every file, `ls` of every directory, one `find`.
    W5,
    /// Random ranged reads of one large file.
    W6,
    /// Parallel multi-file copy (server-side on one filesystem, streamed
    /// across filesystems with `--dest`).
    W7,
    /// Delete many files in one batch.
    W8,
}

impl Workload {
    /// All workloads in order.
    pub const ALL: [Workload; 8] = [
        Workload::W1,
        Workload::W2,
        Workload::W3,
        Workload::W4,
        Workload::W5,
        Workload::W6,
        Workload::W7,
        Workload::W8,
    ];

    /// `W1` ... `W8`.
    pub fn id(self) -> &'static str {
        match self {
            Workload::W1 => "W1",
            Workload::W2 => "W2",
            Workload::W3 => "W3",
            Workload::W4 => "W4",
            Workload::W5 => "W5",
            Workload::W6 => "W6",
            Workload::W7 => "W7",
            Workload::W8 => "W8",
        }
    }

    /// Short name.
    pub fn name(self) -> &'static str {
        match self {
            Workload::W1 => "seq-read",
            Workload::W2 => "seq-write",
            Workload::W3 => "small-read",
            Workload::W4 => "small-write",
            Workload::W5 => "metadata",
            Workload::W6 => "random-read",
            Workload::W7 => "copy",
            Workload::W8 => "delete",
        }
    }

    /// One-line description.
    pub fn description(self) -> &'static str {
        match self {
            Workload::W1 => "large sequential read of one --size file (parallel ranged reads)",
            Workload::W2 => "large sequential write of one --size file (--block-size chunks)",
            Workload::W3 => "read --count files of --file-size, --concurrency in flight",
            Workload::W4 => "write --count files of --file-size, --concurrency in flight",
            Workload::W5 => "info on --count files, ls of --dirs directories, one recursive find",
            Workload::W6 => "--ranges random reads of --range-size from one --size file",
            Workload::W7 => "copy --count files of --file-size (to --dest when given)",
            Workload::W8 => "delete --count files in one batch (rm_files)",
        }
    }

    /// Parse `W3`, `w3`, `3` or a short name such as `small-read`.
    pub fn parse(s: &str) -> Result<Workload> {
        let t = s.trim();
        let id = t.strip_prefix(['W', 'w']).unwrap_or(t);
        Workload::ALL
            .into_iter()
            .find(|w| &w.id()[1..] == id || w.name().eq_ignore_ascii_case(t))
            .ok_or_else(|| {
                Error::invalid_input(format!(
                    "unknown workload {s:?} (use W1..W8, a name such as small-read, or all)"
                ))
            })
    }

    /// Parse a comma-separated list (`all` for every workload); duplicates
    /// are removed and the order is W1..W8.
    pub fn parse_list(s: &str) -> Result<Vec<Workload>> {
        let mut out = Vec::new();
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            if part.eq_ignore_ascii_case("all") {
                out.extend(Workload::ALL);
            } else {
                out.push(Workload::parse(part)?);
            }
        }
        if out.is_empty() {
            return Err(Error::invalid_input("no workload given"));
        }
        out.sort();
        out.dedup();
        Ok(out)
    }
}

/// Benchmark parameters.
#[derive(Debug, Clone)]
pub struct BenchConfig {
    /// Workloads to run.
    pub workloads: Vec<Workload>,
    /// Size of the large file (W1, W2, W6).
    pub size: u64,
    /// Size of each small file (W3, W4, W5, W7, W8).
    pub file_size: u64,
    /// Number of small files.
    pub count: usize,
    /// Operations in flight for multi-operation workloads.
    pub concurrency: usize,
    /// Requests in flight within one large read (W1); `None` uses the
    /// backend's I/O hints.
    pub io_concurrency: Option<usize>,
    /// Request size of W1 reads and chunk size of W2 writes; `None` uses the
    /// backend's I/O hints.
    pub block_size: Option<usize>,
    /// Length of each W6 read.
    pub range_size: u64,
    /// Reads per W6 iteration.
    pub ranges: usize,
    /// Directories of the W5 tree; `None` means one per 64 files.
    pub dirs: Option<usize>,
    /// Measured iterations.
    pub iterations: usize,
    /// Untimed warm-up iterations.
    pub warmup: usize,
    /// Seed of the random offsets (W6) and the payload.
    pub seed: u64,
    /// Keep the benchmark prefix instead of deleting it.
    pub keep: bool,
    /// Create the target directory/bucket when missing (and remove it
    /// afterwards when it was created and is empty).
    pub create: bool,
    /// Destination URL for W7 (another filesystem).
    pub dest: Option<String>,
}

impl Default for BenchConfig {
    fn default() -> Self {
        BenchConfig {
            workloads: Workload::ALL.to_vec(),
            size: 64 << 20,
            file_size: 16 << 10,
            count: 256,
            concurrency: 16,
            io_concurrency: None,
            block_size: None,
            range_size: 256 << 10,
            ranges: 256,
            dirs: None,
            iterations: 3,
            warmup: 1,
            seed: 0x5eed,
            keep: false,
            create: false,
            dest: None,
        }
    }
}

impl BenchConfig {
    /// Reject parameter combinations that cannot run.
    pub fn validate(&self) -> Result<()> {
        let bad = |m: &str| Err(Error::invalid_input(m.to_owned()));
        if self.iterations == 0 {
            return bad("--iterations must be at least 1");
        }
        if self.concurrency == 0 || self.io_concurrency == Some(0) {
            return bad("concurrency must be at least 1");
        }
        if self.block_size == Some(0) {
            return bad("--block-size must be positive");
        }
        let uses = |w: Workload| self.workloads.contains(&w);
        if uses(Workload::W6) {
            if self.range_size == 0 || self.ranges == 0 {
                return bad("--range-size and --ranges must be positive for W6");
            }
            if self.range_size > self.size {
                return bad("--range-size must not exceed --size for W6");
            }
        }
        if self.dirs == Some(0) {
            return bad("--dirs must be at least 1");
        }
        if usize::try_from(self.size).is_err() || usize::try_from(self.file_size).is_err() {
            return bad("sizes must fit in memory addresses");
        }
        Ok(())
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "workloads": self.workloads.iter().map(|w| w.id()).collect::<Vec<_>>(),
            "size": self.size,
            "file_size": self.file_size,
            "count": self.count,
            "concurrency": self.concurrency,
            "io_concurrency": self.io_concurrency,
            "block_size": self.block_size,
            "range_size": self.range_size,
            "ranges": self.ranges,
            "dirs": self.dirs,
            "iterations": self.iterations,
            "warmup": self.warmup,
            "seed": self.seed,
            "dest": self.dest,
        })
    }
}

/// What a latency sample measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatencyKind {
    /// One file system operation (one `cat_file`, `read_at`, `info`, ...).
    Op,
    /// One batch call covering all operations of the iteration (W8).
    Batch,
    /// One whole iteration (W1, W2: a single large transfer).
    Iteration,
}

impl LatencyKind {
    fn as_str(self) -> &'static str {
        match self {
            LatencyKind::Op => "op",
            LatencyKind::Batch => "batch",
            LatencyKind::Iteration => "iteration",
        }
    }
}

/// One measured iteration.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    /// Wall time of the timed section.
    pub secs: f64,
    /// Operations performed.
    pub ops: u64,
    /// Payload bytes moved.
    pub bytes: u64,
    /// Entries returned (listing workloads), else 0.
    pub items: u64,
}

/// The result of one workload (W5 produces three: info, ls, find).
#[derive(Debug, Clone)]
pub struct WorkloadResult {
    /// `W1`...`W8`.
    pub id: &'static str,
    /// Name (`seq-read`, `metadata-info`, ...).
    pub name: String,
    /// One-line description.
    pub description: &'static str,
    /// Workload-specific parameters.
    pub params: serde_json::Value,
    /// Warm-up iterations run.
    pub warmup: usize,
    /// Measured iterations.
    pub samples: Vec<Sample>,
    /// What `latencies_ns` measures.
    pub latency_kind: LatencyKind,
    /// Latency samples in nanoseconds over all measured iterations.
    pub latencies_ns: Vec<u64>,
    /// Engine counters of the filesystem (none for in-process backends).
    pub counters: Option<Counters>,
    /// Engine counters of the W7 destination filesystem.
    pub dest_counters: Option<Counters>,
}

/// Summary statistics of a set of values (nearest-rank percentiles).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Summary {
    /// Number of values.
    pub count: usize,
    /// Smallest.
    pub min: f64,
    /// Arithmetic mean.
    pub mean: f64,
    /// Median (p50).
    pub p50: f64,
    /// 90th percentile.
    pub p90: f64,
    /// 99th percentile.
    pub p99: f64,
    /// Largest.
    pub max: f64,
}

/// Nearest-rank percentile of sorted values (`q` in `[0, 1]`).
pub fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = (q * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// Median: the mean of the two middle values for an even count.
pub fn median(sorted: &[f64]) -> f64 {
    let n = sorted.len();
    match n {
        0 => f64::NAN,
        _ if n % 2 == 1 => sorted[n / 2],
        _ => (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0,
    }
}

/// Summary of `values` (need not be sorted).
pub fn summarize(values: &[f64]) -> Option<Summary> {
    if values.is_empty() {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_by(f64::total_cmp);
    Some(Summary {
        count: v.len(),
        min: v[0],
        mean: v.iter().sum::<f64>() / v.len() as f64,
        p50: percentile(&v, 0.5),
        p90: percentile(&v, 0.9),
        p99: percentile(&v, 0.99),
        max: v[v.len() - 1],
    })
}

impl WorkloadResult {
    fn sorted_times(&self) -> Vec<f64> {
        let mut t: Vec<f64> = self.samples.iter().map(|s| s.secs).collect();
        t.sort_by(f64::total_cmp);
        t
    }

    /// Fastest iteration time.
    pub fn best_secs(&self) -> f64 {
        self.sorted_times().first().copied().unwrap_or(f64::NAN)
    }

    /// Median iteration time.
    pub fn median_secs(&self) -> f64 {
        median(&self.sorted_times())
    }

    fn per_iter(&self, f: impl Fn(&Sample) -> u64) -> u64 {
        self.samples.first().map_or(0, f)
    }

    fn rate(&self, amount: u64, secs: f64) -> f64 {
        if secs > 0.0 {
            amount as f64 / secs
        } else {
            f64::NAN
        }
    }

    /// Latency summary in milliseconds.
    pub fn latency_ms(&self) -> Option<Summary> {
        let ms: Vec<f64> = self.latencies_ns.iter().map(|&n| n as f64 / 1e6).collect();
        summarize(&ms)
    }

    /// JSON object for the benchmark harness.
    pub fn to_json(&self) -> serde_json::Value {
        let bytes = self.per_iter(|s| s.bytes);
        let ops = self.per_iter(|s| s.ops);
        let items = self.per_iter(|s| s.items);
        let (best, med) = (self.best_secs(), self.median_secs());
        let num =
            |x: f64| serde_json::Number::from_f64(x).map_or(serde_json::Value::Null, Into::into);
        let lat = self.latency_ms().map(|s| {
            serde_json::json!({
                "kind": self.latency_kind.as_str(),
                "count": s.count,
                "min": num(s.min),
                "mean": num(s.mean),
                "p50": num(s.p50),
                "p90": num(s.p90),
                "p99": num(s.p99),
                "max": num(s.max),
            })
        });
        let mut v = serde_json::json!({
            "workload": self.id,
            "name": self.name,
            "description": self.description,
            "params": self.params,
            "warmup": self.warmup,
            "iterations": self.samples.len(),
            "times_s": self.samples.iter().map(|s| num(s.secs)).collect::<Vec<_>>(),
            "best_s": num(best),
            "median_s": num(med),
            "bytes_per_iter": bytes,
            "ops_per_iter": ops,
            // null for workloads that move no payload (metadata, delete).
            "mb_per_s": (bytes > 0).then(|| serde_json::json!({
                "best": num(self.rate(bytes, best) / 1e6),
                "median": num(self.rate(bytes, med) / 1e6),
            })),
            "ops_per_s": {"best": num(self.rate(ops, best)), "median": num(self.rate(ops, med))},
            "latency_ms": lat,
            "stats": self.counters.map(|c| c.to_json()),
        });
        if items > 0 {
            v["items_per_iter"] = items.into();
            v["items_per_s"] = serde_json::json!({
                "best": num(self.rate(items, best)),
                "median": num(self.rate(items, med)),
            });
        }
        if let Some(d) = &self.dest_counters {
            v["dest_stats"] = d.to_json();
        }
        v
    }

    /// Human-readable report block.
    pub fn human(&self) -> String {
        let bytes = self.per_iter(|s| s.bytes);
        let ops = self.per_iter(|s| s.ops);
        let items = self.per_iter(|s| s.items);
        let (best, med) = (self.best_secs(), self.median_secs());
        let d = |s: f64| format_duration(Duration::from_secs_f64(s.max(0.0)));
        let mut out = format!(
            "{} {:<16} {} iteration(s), {} warm-up\n  time      best {}  median {}\n",
            self.id,
            self.name,
            self.samples.len(),
            self.warmup,
            d(best),
            d(med)
        );
        if bytes > 0 {
            out.push_str(&format!(
                "  rate      {:.1} MB/s best, {:.1} MB/s median ({} per iteration)\n",
                self.rate(bytes, best) / 1e6,
                self.rate(bytes, med) / 1e6,
                format_bytes(bytes)
            ));
        }
        if ops > 1 {
            out.push_str(&format!(
                "  ops       {:.0} ops/s best, {:.0} ops/s median ({} per iteration)\n",
                self.rate(ops, best),
                self.rate(ops, med),
                ops
            ));
        }
        if items > 0 {
            out.push_str(&format!(
                "  entries   {:.0}/s best, {:.0}/s median ({} per iteration)\n",
                self.rate(items, best),
                self.rate(items, med),
                items
            ));
        }
        if let Some(l) = self.latency_ms() {
            let ms = |x: f64| d(x / 1e3);
            out.push_str(&format!(
                "  latency   ({}, n={}) p50 {}  p90 {}  p99 {}  max {}  mean {}\n",
                self.latency_kind.as_str(),
                l.count,
                ms(l.p50),
                ms(l.p90),
                ms(l.p99),
                ms(l.max),
                ms(l.mean)
            ));
        }
        match &self.counters {
            Some(c) => out.push_str(&format!("  stats     {}\n", c.line())),
            None => out.push_str("  stats     n/a (in-process backend)\n"),
        }
        if let Some(c) = &self.dest_counters {
            out.push_str(&format!("  dest      {}\n", c.line()));
        }
        out
    }
}

/// The full benchmark report.
#[derive(Debug, Clone)]
pub struct BenchReport {
    /// Target URL as given.
    pub url: String,
    /// Canonical protocol.
    pub protocol: &'static str,
    /// Unique prefix (backend path form).
    pub prefix: String,
    /// Start time.
    pub started: SystemTime,
    /// Parameters.
    pub config: BenchConfig,
    /// Results in order.
    pub results: Vec<WorkloadResult>,
    /// Cleanup outcome.
    pub cleanup: Cleanup,
    /// Error that stopped the run, if any.
    pub error: Option<String>,
    /// Whether the run was stopped by the cancel future (Ctrl-C).
    pub interrupted: bool,
}

/// What cleanup did.
#[derive(Debug, Clone, Default)]
pub struct Cleanup {
    /// Whether cleanup ran (`--keep` skips it).
    pub ran: bool,
    /// Files deleted.
    pub files: usize,
    /// Directories deleted.
    pub dirs: usize,
    /// Cleanup failures.
    pub errors: Vec<String>,
}

impl BenchReport {
    /// JSON document for the benchmark harness.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "tool": "fsf",
            "version": env!("CARGO_PKG_VERSION"),
            "url": self.url,
            "protocol": self.protocol,
            "prefix": self.prefix,
            "started_at": rfc3339(self.started),
            "config": self.config.to_json(),
            "results": self.results.iter().map(WorkloadResult::to_json).collect::<Vec<_>>(),
            "cleanup": {
                "ran": self.cleanup.ran,
                "removed_files": self.cleanup.files,
                "removed_dirs": self.cleanup.dirs,
                "errors": self.cleanup.errors,
            },
            "error": self.error,
            "interrupted": self.interrupted,
        })
    }
}

/// Times one batch of operations: runs `f(i)` for `i in 0..n` with
/// `concurrency` in flight, timing each operation. Returns the per-op
/// latencies (ns) and the sum of the bytes each operation reports.
async fn timed_ops<F, Fut>(n: usize, concurrency: usize, f: F) -> Result<(Vec<u64>, u64)>
where
    F: Fn(usize) -> Fut,
    Fut: Future<Output = Result<u64>>,
{
    let results: Vec<(u64, u64)> = stream::iter((0..n).map(|i| {
        let fut = f(i);
        async move {
            let t = Instant::now();
            let b = fut.await?;
            Ok::<_, Error>((t.elapsed().as_nanos() as u64, b))
        }
    }))
    .buffer_unordered(concurrency.max(1))
    .try_collect()
    .await?;
    let bytes = results.iter().map(|r| r.1).sum();
    Ok((results.into_iter().map(|r| r.0).collect(), bytes))
}

fn counters(stats: &Option<Arc<Stats>>) -> Option<Counters> {
    stats.as_ref().map(|s| Counters::of(&s.snapshot()))
}

/// Accumulates the samples of one workload.
struct Recorder {
    stats: Option<Arc<Stats>>,
    dest_stats: Option<Arc<Stats>>,
    warmup: usize,
    samples: Vec<Sample>,
    latencies: Vec<u64>,
    counters: Option<Counters>,
    dest_counters: Option<Counters>,
}

/// State captured when a timed section starts.
struct Begin {
    t: Instant,
    c: Option<Counters>,
    dc: Option<Counters>,
}

impl Recorder {
    fn new(stats: Option<Arc<Stats>>, dest_stats: Option<Arc<Stats>>, warmup: usize) -> Self {
        Recorder {
            counters: stats.as_ref().map(|_| Counters::default()),
            dest_counters: dest_stats.as_ref().map(|_| Counters::default()),
            stats,
            dest_stats,
            warmup,
            samples: Vec::new(),
            latencies: Vec::new(),
        }
    }

    fn begin(&self) -> Begin {
        Begin {
            c: counters(&self.stats),
            dc: counters(&self.dest_stats),
            t: Instant::now(),
        }
    }

    /// End a timed section; warm-up iterations are discarded.
    fn end(&mut self, b: Begin, measured: bool, mut s: Sample, lat: Vec<u64>) {
        let secs = b.t.elapsed().as_secs_f64();
        if !measured {
            return;
        }
        s.secs = secs;
        if let (Some(acc), Some(before), Some(after)) =
            (self.counters.as_mut(), b.c, counters(&self.stats))
        {
            acc.add(&after.since(&before));
        }
        if let (Some(acc), Some(before), Some(after)) = (
            self.dest_counters.as_mut(),
            b.dc,
            counters(&self.dest_stats),
        ) {
            acc.add(&after.since(&before));
        }
        self.samples.push(s);
        self.latencies.extend(lat);
    }

    fn finish(
        self,
        w: Workload,
        name: String,
        params: serde_json::Value,
        latency_kind: LatencyKind,
    ) -> WorkloadResult {
        WorkloadResult {
            id: w.id(),
            name,
            description: w.description(),
            params,
            warmup: self.warmup,
            samples: self.samples,
            latency_kind,
            latencies_ns: self.latencies,
            counters: self.counters,
            dest_counters: self.dest_counters,
        }
    }
}

/// Where W7 copies to.
struct Dest {
    target: Resolved,
    base: String,
}

/// Benchmark state.
struct Ctx<'a> {
    cfg: &'a BenchConfig,
    target: Resolved,
    fs: Arc<dyn FileSystem>,
    stats: Option<Arc<Stats>>,
    hierarchical: bool,
    base: String,
    dest: Option<Dest>,
    /// Random payload, at least as long as the largest single write.
    payload: Bytes,
    write_chunk: usize,
    large_ready: bool,
    small_ready: bool,
    progress: &'a (dyn Fn(&str) + Sync),
}

fn not_measured(it: usize, warmup: usize) -> bool {
    it < warmup
}

fn random_payload(len: usize, seed: u64) -> Bytes {
    let mut rng = fastrand::Rng::with_seed(seed);
    let mut v = vec![0u8; len];
    rng.fill(&mut v);
    Bytes::from(v)
}

impl Ctx<'_> {
    fn path(&self, rel: &str) -> String {
        child_path(self.target.loc.backend, &self.base, rel)
    }

    async fn ensure_dir(&self, path: &str) -> Result<()> {
        if self.hierarchical {
            self.fs.makedirs(path, true).await?;
        }
        Ok(())
    }

    fn small_path(&self, i: usize) -> String {
        self.path(&format!("small/f{i:06}"))
    }

    /// Write one file of `size` bytes streaming `write_chunk` slices of the
    /// shared payload (zero-copy: every chunk is a `Bytes::slice`).
    async fn write_large(&self, path: &str, size: u64) -> Result<()> {
        let mut w = self.fs.open_write(path, &WriteOptions::default()).await?;
        let res = async {
            let mut left = size;
            while left > 0 {
                let n = left.min(self.write_chunk as u64) as usize;
                w.write(self.payload.slice(..n)).await?;
                left -= n as u64;
            }
            w.close().await
        }
        .await;
        if res.is_err() {
            let _ = w.abort().await;
        }
        res
    }

    fn small_data(&self) -> Bytes {
        self.payload.slice(..self.cfg.file_size as usize)
    }

    async fn write_small_set(&self, paths: &[String]) -> Result<()> {
        let data = self.small_data();
        ops::for_each_concurrent(paths.len(), self.cfg.concurrency, |i| {
            let data = data.clone();
            let p = &paths[i];
            async move { self.fs.pipe_file(p, data, &WriteOptions::default()).await }
        })
        .await
    }

    async fn delete_set(&self, dir: &str, paths: &[String]) -> Result<()> {
        for (r, p) in self.fs.rm_files(paths).await.into_iter().zip(paths) {
            match r {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e.with_path(p.clone())),
            }
        }
        if self.hierarchical {
            match self.fs.rmdir(dir).await {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    async fn ensure_large(&mut self) -> Result<String> {
        let p = self.path("large/data.bin");
        if !self.large_ready {
            (self.progress)(&format!(
                "setup: writing {} large file",
                format_bytes(self.cfg.size)
            ));
            self.ensure_dir(&self.path("large")).await?;
            self.write_large(&p, self.cfg.size).await?;
            self.large_ready = true;
        }
        Ok(p)
    }

    async fn ensure_small(&mut self) -> Result<Vec<String>> {
        let paths: Vec<String> = (0..self.cfg.count).map(|i| self.small_path(i)).collect();
        if !self.small_ready {
            (self.progress)(&format!(
                "setup: writing {} files of {}",
                self.cfg.count,
                format_bytes(self.cfg.file_size)
            ));
            self.ensure_dir(&self.path("small")).await?;
            self.write_small_set(&paths).await?;
            self.small_ready = true;
        }
        Ok(paths)
    }

    fn rounds(&self) -> usize {
        self.cfg.warmup + self.cfg.iterations
    }

    fn recorder(&self) -> Recorder {
        Recorder::new(self.stats.clone(), None, self.cfg.warmup)
    }

    async fn w1(&mut self) -> Result<Vec<WorkloadResult>> {
        let p = self.ensure_large().await?;
        let size = self.cfg.size;
        let mut rec = self.recorder();
        for it in 0..self.rounds() {
            let b = rec.begin();
            let got = ops::read_streaming(
                self.fs.as_ref(),
                &p,
                0..size,
                self.cfg.block_size,
                self.cfg.io_concurrency,
                |_| Ok(()),
            )
            .await?;
            check_len(&p, got, size)?;
            let lat = b.t.elapsed().as_nanos() as u64;
            rec.end(
                b,
                !not_measured(it, self.cfg.warmup),
                Sample {
                    secs: 0.0,
                    ops: 1,
                    bytes: size,
                    items: 0,
                },
                vec![lat],
            );
        }
        let params = serde_json::json!({
            "size": size,
            "block_size": self.cfg.block_size,
            "io_concurrency": self.cfg.io_concurrency,
        });
        Ok(vec![rec.finish(
            Workload::W1,
            "seq-read".into(),
            params,
            LatencyKind::Iteration,
        )])
    }

    async fn w2(&mut self) -> Result<Vec<WorkloadResult>> {
        let size = self.cfg.size;
        let dir = self.path("w2");
        self.ensure_dir(&dir).await?;
        let mut rec = self.recorder();
        for it in 0..self.rounds() {
            let p = self.path(&format!("w2/it{it:04}.bin"));
            let b = rec.begin();
            self.write_large(&p, size).await?;
            let lat = b.t.elapsed().as_nanos() as u64;
            rec.end(
                b,
                !not_measured(it, self.cfg.warmup),
                Sample {
                    secs: 0.0,
                    ops: 1,
                    bytes: size,
                    items: 0,
                },
                vec![lat],
            );
            // Do not let large files accumulate across iterations.
            self.fs.rm_file(&p).await?;
        }
        let params = serde_json::json!({"size": size, "block_size": self.write_chunk});
        Ok(vec![rec.finish(
            Workload::W2,
            "seq-write".into(),
            params,
            LatencyKind::Iteration,
        )])
    }

    async fn w3(&mut self) -> Result<Vec<WorkloadResult>> {
        let paths = self.ensure_small().await?;
        let fsize = self.cfg.file_size;
        let fs = &self.fs.clone();
        let mut rec = self.recorder();
        for it in 0..self.rounds() {
            let b = rec.begin();
            let (lat, bytes) = timed_ops(paths.len(), self.cfg.concurrency, |i| {
                let p = &paths[i];
                async move {
                    let d = fs.cat_file(p, ByteRange::Full).await?;
                    check_len(p, d.len() as u64, fsize)?;
                    Ok(d.len() as u64)
                }
            })
            .await?;
            rec.end(
                b,
                !not_measured(it, self.cfg.warmup),
                Sample {
                    secs: 0.0,
                    ops: paths.len() as u64,
                    bytes,
                    items: 0,
                },
                lat,
            );
        }
        let params = serde_json::json!({
            "count": self.cfg.count, "file_size": fsize, "concurrency": self.cfg.concurrency,
        });
        Ok(vec![rec.finish(
            Workload::W3,
            "small-read".into(),
            params,
            LatencyKind::Op,
        )])
    }

    async fn w4(&mut self) -> Result<Vec<WorkloadResult>> {
        let fsize = self.cfg.file_size;
        let data = self.small_data();
        let fs = &self.fs.clone();
        let mut rec = self.recorder();
        for it in 0..self.rounds() {
            let dir = self.path(&format!("w4/it{it:04}"));
            self.ensure_dir(&dir).await?;
            let paths: Vec<String> = (0..self.cfg.count)
                .map(|i| self.path(&format!("w4/it{it:04}/f{i:06}")))
                .collect();
            let b = rec.begin();
            let (lat, bytes) = timed_ops(paths.len(), self.cfg.concurrency, |i| {
                let p = &paths[i];
                let data = data.clone();
                async move {
                    fs.pipe_file(p, data, &WriteOptions::default()).await?;
                    Ok(fsize)
                }
            })
            .await?;
            rec.end(
                b,
                !not_measured(it, self.cfg.warmup),
                Sample {
                    secs: 0.0,
                    ops: paths.len() as u64,
                    bytes,
                    items: 0,
                },
                lat,
            );
            self.delete_set(&dir, &paths).await?;
        }
        let params = serde_json::json!({
            "count": self.cfg.count, "file_size": fsize, "concurrency": self.cfg.concurrency,
        });
        Ok(vec![rec.finish(
            Workload::W4,
            "small-write".into(),
            params,
            LatencyKind::Op,
        )])
    }

    async fn w5(&mut self) -> Result<Vec<WorkloadResult>> {
        let count = self.cfg.count;
        let ndirs = self.cfg.dirs.unwrap_or(count.div_ceil(64)).max(1);
        let root = self.path("meta");
        let dirs: Vec<String> = (0..ndirs)
            .map(|d| self.path(&format!("meta/d{d:04}")))
            .collect();
        let files: Vec<String> = (0..count)
            .map(|i| self.path(&format!("meta/d{:04}/f{i:06}", i % ndirs)))
            .collect();
        (self.progress)(&format!(
            "setup: writing {count} files in {ndirs} directories"
        ));
        self.ensure_dir(&root).await?;
        for d in &dirs {
            self.ensure_dir(d).await?;
        }
        self.write_small_set(&files).await?;
        let fs = &self.fs.clone();
        let conc = self.cfg.concurrency;

        let mut info_rec = self.recorder();
        let mut ls_rec = self.recorder();
        let mut find_rec = self.recorder();
        for it in 0..self.rounds() {
            let measured = !not_measured(it, self.cfg.warmup);
            // info on every file
            let b = info_rec.begin();
            let (lat, _) = timed_ops(files.len(), conc, |i| {
                let p = &files[i];
                async move {
                    let info = fs.info(p).await?;
                    if info.is_dir() {
                        return Err(Error::protocol(format!("{p}: expected a file")));
                    }
                    Ok(0)
                }
            })
            .await?;
            let n = files.len() as u64;
            info_rec.end(
                b,
                measured,
                Sample {
                    secs: 0.0,
                    ops: n,
                    bytes: 0,
                    items: 0,
                },
                lat,
            );

            // ls of every directory
            let b = ls_rec.begin();
            let (lat, entries) = timed_ops(dirs.len(), conc, |i| {
                let d = &dirs[i];
                async move { Ok(fs.ls(d).await?.len() as u64) }
            })
            .await?;
            check_len(&root, entries, count as u64)?;
            let n = dirs.len() as u64;
            ls_rec.end(
                b,
                measured,
                Sample {
                    secs: 0.0,
                    ops: n,
                    bytes: 0,
                    items: entries,
                },
                lat,
            );

            // one recursive find
            let b = find_rec.begin();
            let t = Instant::now();
            let found = self.fs.find(&root, &FindOptions::default()).await?;
            let lat = t.elapsed().as_nanos() as u64;
            check_len(&root, found.len() as u64, count as u64)?;
            find_rec.end(
                b,
                measured,
                Sample {
                    secs: 0.0,
                    ops: 1,
                    bytes: 0,
                    items: found.len() as u64,
                },
                vec![lat],
            );
        }
        let params = serde_json::json!({
            "count": count, "dirs": ndirs, "file_size": self.cfg.file_size, "concurrency": conc,
        });
        Ok(vec![
            info_rec.finish(
                Workload::W5,
                "metadata-info".into(),
                params.clone(),
                LatencyKind::Op,
            ),
            ls_rec.finish(
                Workload::W5,
                "metadata-ls".into(),
                params.clone(),
                LatencyKind::Op,
            ),
            find_rec.finish(
                Workload::W5,
                "metadata-find".into(),
                params,
                LatencyKind::Op,
            ),
        ])
    }

    async fn w6(&mut self) -> Result<Vec<WorkloadResult>> {
        let p = self.ensure_large().await?;
        let size = self.cfg.size;
        let len = self.cfg.range_size;
        let n = self.cfg.ranges;
        let mut rec = self.recorder();
        for it in 0..self.rounds() {
            let mut rng = fastrand::Rng::with_seed(self.cfg.seed.wrapping_add(it as u64));
            let offsets: Vec<u64> = (0..n).map(|_| rng.u64(0..=size - len)).collect();
            let b = rec.begin();
            // Opening the handle is part of the iteration time (it is a
            // HEAD/stat on most backends) but not of the per-read latency.
            let h = self.fs.open_read(&p, &ReadOptions::default()).await?;
            let res = timed_ops(n, self.cfg.concurrency, |i| {
                let h = &h;
                let off = offsets[i];
                let p = &p;
                async move {
                    let d = h.read_at(off, len as usize).await?;
                    check_len(p, d.len() as u64, len)?;
                    Ok(len)
                }
            })
            .await;
            let closed = h.close().await;
            let (lat, bytes) = res?;
            closed?;
            rec.end(
                b,
                !not_measured(it, self.cfg.warmup),
                Sample {
                    secs: 0.0,
                    ops: n as u64,
                    bytes,
                    items: 0,
                },
                lat,
            );
        }
        let params = serde_json::json!({
            "size": size, "range_size": len, "ranges": n, "concurrency": self.cfg.concurrency,
            "seed": self.cfg.seed,
        });
        Ok(vec![rec.finish(
            Workload::W6,
            "random-read".into(),
            params,
            LatencyKind::Op,
        )])
    }

    async fn w7(&mut self) -> Result<Vec<WorkloadResult>> {
        let paths = self.ensure_small().await?;
        let fsize = self.cfg.file_size;
        let (dfs, dstats, dbackend, dbase, method) = match &self.dest {
            Some(d) => (
                d.target.built.fs.clone(),
                d.target.built.stats.clone(),
                d.target.loc.backend,
                d.base.clone(),
                ops::copy_method(&self.target, &d.target),
            ),
            None => (
                self.fs.clone(),
                None,
                self.target.loc.backend,
                self.base.clone(),
                CopyMethod::SameFs,
            ),
        };
        let dhier = dfs.capabilities().hierarchical;
        let fs = &self.fs.clone();
        let mut rec = Recorder::new(self.stats.clone(), dstats, self.cfg.warmup);
        for it in 0..self.rounds() {
            let dir = child_path(dbackend, &dbase, &format!("w7/it{it:04}"));
            if dhier {
                dfs.makedirs(&dir, true).await?;
            }
            let dsts: Vec<String> = (0..paths.len())
                .map(|i| child_path(dbackend, &dir, &format!("f{i:06}")))
                .collect();
            let b = rec.begin();
            let (lat, bytes) = timed_ops(paths.len(), self.cfg.concurrency, |i| {
                let (s, d) = (&paths[i], &dsts[i]);
                let dfs = &dfs;
                async move { ops::copy_file(method, fs, s, dfs, d, fsize).await }
            })
            .await?;
            rec.end(
                b,
                !not_measured(it, self.cfg.warmup),
                Sample {
                    secs: 0.0,
                    ops: paths.len() as u64,
                    bytes,
                    items: 0,
                },
                lat,
            );
            ops::remove_tree_quiet(dfs.as_ref(), &dir).await?;
        }
        let params = serde_json::json!({
            "count": self.cfg.count, "file_size": fsize, "concurrency": self.cfg.concurrency,
            "method": format!("{method:?}"),
            "dest": self.dest.as_ref().map(|d| d.target.loc.url.clone()),
        });
        Ok(vec![rec.finish(
            Workload::W7,
            "copy".into(),
            params,
            LatencyKind::Op,
        )])
    }

    async fn w8(&mut self) -> Result<Vec<WorkloadResult>> {
        let mut rec = self.recorder();
        for it in 0..self.rounds() {
            let dir = self.path(&format!("w8/it{it:04}"));
            self.ensure_dir(&dir).await?;
            let paths: Vec<String> = (0..self.cfg.count)
                .map(|i| self.path(&format!("w8/it{it:04}/f{i:06}")))
                .collect();
            self.write_small_set(&paths).await?;
            let b = rec.begin();
            let t = Instant::now();
            let results = self.fs.rm_files(&paths).await;
            let lat = t.elapsed().as_nanos() as u64;
            for (r, p) in results.into_iter().zip(&paths) {
                r.map_err(|e| e.with_path(p.clone()))?;
            }
            rec.end(
                b,
                !not_measured(it, self.cfg.warmup),
                Sample {
                    secs: 0.0,
                    ops: paths.len() as u64,
                    bytes: 0,
                    items: 0,
                },
                vec![lat],
            );
            self.delete_set(&dir, &[]).await?;
        }
        let params = serde_json::json!({"count": self.cfg.count, "file_size": self.cfg.file_size});
        Ok(vec![rec.finish(
            Workload::W8,
            "delete".into(),
            params,
            LatencyKind::Batch,
        )])
    }

    async fn run(&mut self, w: Workload) -> Result<Vec<WorkloadResult>> {
        match w {
            Workload::W1 => self.w1().await,
            Workload::W2 => self.w2().await,
            Workload::W3 => self.w3().await,
            Workload::W4 => self.w4().await,
            Workload::W5 => self.w5().await,
            Workload::W6 => self.w6().await,
            Workload::W7 => self.w7().await,
            Workload::W8 => self.w8().await,
        }
    }
}

fn check_len(path: &str, got: u64, want: u64) -> Result<()> {
    if got == want {
        Ok(())
    } else {
        Err(Error::protocol(format!(
            "{path}: expected {want} bytes/entries, got {got}"
        )))
    }
}

/// Remove the tree at `path` until it stays gone. After an error or an
/// interrupt, operations that were in flight when the workload future was
/// dropped can still land: blocking-pool writes (local disk) and requests
/// already on the wire are not cancellable. So the tree is removed, checked,
/// and removed again (a few times, with a short pause) until nothing
/// reappears.
async fn remove_settled(fs: &dyn FileSystem, path: &str) -> Result<ops::Removed> {
    let mut total = ops::Removed::default();
    let mut last_err = None;
    for attempt in 0..8u32 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(50 << attempt.min(4))).await;
        }
        match ops::remove_tree_quiet(fs, path).await {
            Ok(r) => {
                total.files += r.files;
                total.dirs += r.dirs;
                last_err = None;
            }
            Err(e) => last_err = Some(e),
        }
        if last_err.is_none() && !fs.exists(path).await? {
            return Ok(total);
        }
    }
    match last_err {
        Some(e) => Err(e),
        None => Err(Error::new(
            ErrorKind::Other,
            format!("{path} keeps reappearing after removal"),
        )),
    }
}

/// A unique benchmark directory name.
pub fn unique_name() -> String {
    let ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!(
        "fsf-bench-{ms}-{}-{:08x}",
        std::process::id(),
        fastrand::u32(..)
    )
}

/// Run a benchmark against `url`. `progress` receives status lines (setup
/// steps, cleanup) and `on_result` every finished workload result. Cleanup always runs unless
/// `cfg.keep`, also when a workload fails or `cancel` resolves first; the
/// report then carries the error and the results gathered so far.
pub async fn run_bench(
    session: &Session,
    url: &str,
    cfg: &BenchConfig,
    progress: &(dyn Fn(&str) + Sync),
    on_result: &(dyn Fn(&WorkloadResult) + Sync),
    cancel: impl Future<Output = ()>,
) -> Result<BenchReport> {
    cfg.validate()?;
    let mut urls = vec![url];
    if let Some(d) = &cfg.dest {
        urls.push(d.as_str());
    }
    let mut resolved = session.resolve_all(&urls)?;
    let dest_target = (resolved.len() > 1).then(|| resolved.pop().expect("dest"));
    let target = resolved.pop().expect("target");
    let fs = target.built.fs.clone();
    let caps = fs.capabilities();
    if !caps.hierarchical && target.path().trim_matches('/').is_empty() {
        return Err(Error::invalid_input(format!(
            "{url}: give a bucket/container (e.g. {}://bucket/prefix)",
            target.loc.backend.name()
        )));
    }

    // The target directory must exist (or be created with --create).
    let mut created_root = false;
    match fs.info(target.path()).await {
        Ok(i) if i.is_dir() => {}
        Ok(_) => {
            return Err(Error::not_a_directory(target.path()).with_path(url.to_owned()));
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            if cfg.create {
                ops::mkdir_p(fs.as_ref(), target.path()).await?;
                created_root = true;
            } else {
                return Err(e.with_path(url.to_owned()).with_kind(ErrorKind::NotFound));
            }
        }
        Err(e) => return Err(e),
    }

    let name = unique_name();
    let base = child_path(target.loc.backend, target.path(), &name);
    let dest = match dest_target {
        Some(t) => {
            let dbase = child_path(t.loc.backend, t.path(), &name);
            if t.built.fs.capabilities().hierarchical {
                t.built.fs.makedirs(&dbase, true).await?;
            }
            Some(Dest {
                target: t,
                base: dbase,
            })
        }
        None => None,
    };
    let write_chunk = cfg
        .block_size
        .unwrap_or_else(|| fs.io_hints().request_size)
        .clamp(1, cfg.size.max(1) as usize);
    let payload_len = write_chunk.max(cfg.file_size as usize).max(1);
    let mut ctx = Ctx {
        cfg,
        stats: target.built.stats.clone(),
        hierarchical: caps.hierarchical,
        fs: fs.clone(),
        target: target.clone(),
        base: base.clone(),
        dest,
        payload: random_payload(payload_len, cfg.seed),
        write_chunk,
        large_ready: false,
        small_ready: false,
        progress,
    };
    let started = SystemTime::now();
    progress(&format!("benchmark prefix: {base}"));
    let mut results = Vec::new();
    let mut interrupted = false;
    let outcome = {
        let work = async {
            ctx.ensure_dir(&base).await?;
            for &w in &cfg.workloads {
                progress(&format!("running {} {}", w.id(), w.name()));
                for r in ctx.run(w).await? {
                    on_result(&r);
                    results.push(r);
                }
            }
            Ok::<(), Error>(())
        };
        tokio::select! {
            r = work => r,
            () = cancel => {
                interrupted = true;
                Err(Error::new(ErrorKind::Cancelled, "interrupted"))
            }
        }
    };
    let mut cleanup = Cleanup::default();
    if !cfg.keep {
        progress("cleanup: removing the benchmark prefix");
        cleanup.ran = true;
        let mut targets: Vec<(Arc<dyn FileSystem>, String)> = vec![(fs.clone(), base.clone())];
        if let Some(d) = &ctx.dest {
            targets.push((d.target.built.fs.clone(), d.base.clone()));
        }
        for (f, p) in targets {
            match remove_settled(f.as_ref(), &p).await {
                Ok(r) => {
                    cleanup.files += r.files;
                    cleanup.dirs += r.dirs;
                }
                Err(e) => cleanup.errors.push(format!("{p}: {e}")),
            }
        }
        if created_root {
            match remove_settled(fs.as_ref(), target.path()).await {
                Ok(r) => {
                    cleanup.files += r.files;
                    cleanup.dirs += r.dirs;
                }
                Err(e) => cleanup.errors.push(format!("{}: {e}", target.path())),
            }
        }
    }
    Ok(BenchReport {
        url: url.to_owned(),
        protocol: target.loc.backend.name(),
        prefix: base,
        started,
        config: cfg.clone(),
        results,
        cleanup,
        interrupted,
        error: outcome.err().map(|e| e.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_parsing() {
        assert_eq!(Workload::parse("W3").unwrap(), Workload::W3);
        assert_eq!(Workload::parse("w8").unwrap(), Workload::W8);
        assert_eq!(Workload::parse("5").unwrap(), Workload::W5);
        assert_eq!(Workload::parse("random-read").unwrap(), Workload::W6);
        assert!(Workload::parse("W9").is_err());
        assert!(Workload::parse("").is_err());
        assert_eq!(Workload::parse_list("all").unwrap().len(), 8);
        assert_eq!(
            Workload::parse_list("W7, w1,W7").unwrap(),
            vec![Workload::W1, Workload::W7]
        );
        assert!(Workload::parse_list(" , ").is_err());
    }

    #[test]
    fn statistics() {
        let v = [5.0, 1.0, 3.0, 2.0, 4.0];
        let s = summarize(&v).unwrap();
        assert_eq!((s.min, s.p50, s.max, s.mean), (1.0, 3.0, 5.0, 3.0));
        assert_eq!(s.p99, 5.0);
        let sorted: Vec<f64> = (1..=100).map(f64::from).collect();
        assert_eq!(percentile(&sorted, 0.5), 50.0);
        assert_eq!(percentile(&sorted, 0.99), 99.0);
        assert_eq!(percentile(&sorted, 0.9), 90.0);
        assert_eq!(percentile(&sorted, 0.0), 1.0);
        assert_eq!(median(&[1.0, 2.0, 3.0, 10.0]), 2.5);
        assert!(median(&[]).is_nan());
        assert!(summarize(&[]).is_none());
    }

    #[test]
    fn config_validation() {
        let mut c = BenchConfig::default();
        assert!(c.validate().is_ok());
        c.iterations = 0;
        assert!(c.validate().is_err());
        let c = BenchConfig {
            range_size: 2 << 30,
            ..Default::default()
        };
        assert!(c.validate().is_err());
        let c = BenchConfig {
            range_size: 2 << 30,
            workloads: vec![Workload::W1],
            ..Default::default()
        };
        assert!(c.validate().is_ok());
        let c = BenchConfig {
            concurrency: 0,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn result_rates() {
        let r = WorkloadResult {
            id: "W3",
            name: "small-read".into(),
            description: "",
            params: serde_json::json!({}),
            warmup: 1,
            samples: vec![
                Sample {
                    secs: 2.0,
                    ops: 100,
                    bytes: 4_000_000,
                    items: 0,
                },
                Sample {
                    secs: 1.0,
                    ops: 100,
                    bytes: 4_000_000,
                    items: 0,
                },
                Sample {
                    secs: 4.0,
                    ops: 100,
                    bytes: 4_000_000,
                    items: 0,
                },
            ],
            latency_kind: LatencyKind::Op,
            latencies_ns: vec![1_000_000, 2_000_000, 3_000_000],
            counters: None,
            dest_counters: None,
        };
        let j = r.to_json();
        assert_eq!(j["best_s"], 1.0);
        assert_eq!(j["median_s"], 2.0);
        assert_eq!(j["mb_per_s"]["best"], 4.0);
        assert_eq!(j["mb_per_s"]["median"], 2.0);
        assert_eq!(j["ops_per_s"]["best"], 100.0);
        assert_eq!(j["latency_ms"]["p50"], 2.0);
        assert_eq!(j["latency_ms"]["p99"], 3.0);
        assert_eq!(j["latency_ms"]["kind"], "op");
        assert!(j["stats"].is_null());
        assert!(j.get("items_per_s").is_none());
        let h = r.human();
        assert!(h.contains("4.0 MB/s best"), "{h}");
        assert!(h.contains("n/a"), "{h}");
    }

    #[test]
    fn unique_names_differ() {
        let a = unique_name();
        assert!(a.starts_with("fsf-bench-"));
        assert_ne!(a, unique_name());
    }
}
