//! Shared performance machinery for fsfast backends (docs/PLAN.md §4.5–4.6).
//!
//! Every backend composes the same building blocks instead of re-implementing
//! them:
//!
//! * [`retry`](mod@retry) — [`RetryPolicy`] with exponential backoff and full jitter,
//!   retrying only errors for which [`Error::is_retryable`](fsfast_core::Error::is_retryable)
//!   holds, honouring server [`RetryAfter`] hints.
//! * [`aimd`] — [`AimdLimiter`], an adaptive concurrency limiter (additive
//!   increase, multiplicative decrease on throttling or latency inflation).
//! * [`budget`] — [`MemoryBudget`], an async byte semaphore bounding
//!   prefetch, cache fills and multipart buffers, with a process-wide
//!   [`MemoryBudget::global`] instance.
//! * [`parallel`] — [`read_parallel`] / [`read_parallel_into`]: one large
//!   read split into concurrently fetched parts assembled in place.
//! * [`reader`] — [`FileReader`], the engine behind Python file objects, with
//!   fsspec-style cache modes (none, adaptive readahead, block LRU, whole file).
//! * [`upload`] — [`PartUploader`], a concurrent multipart upload helper for
//!   S3/GCS/Azure-style backends.
//! * [`stats`] — [`Stats`]: atomic counters and per-operation latency
//!   histograms.
//! * [`concurrency`] — small helpers (order-preserving bounded concurrent
//!   map, abort-on-drop task handles).
//!
//! # Memory accounting model
//!
//! Memory that is *retained* or *speculative* (readahead chunks, cached
//! blocks, multipart parts in flight, parts of a parallel read in flight) is
//! accounted against a [`MemoryBudget`]. Speculative work only proceeds when
//! budget is available ([`MemoryBudget::try_acquire`]); mandatory work (the
//! bytes a caller actually asked for) always makes progress, overcommitting by
//! at most one request when the budget is exhausted
//! ([`MemoryBudget::force_acquire`]). Under memory pressure the engine
//! therefore reduces concurrency and prefetch depth instead of deadlocking or
//! running out of memory.

//!
//! # Example
//!
//! ```
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> fsfast_core::Result<()> {
//! use std::io::SeekFrom;
//! use std::sync::Arc;
//!
//! use fsfast_core::ReadHandle;
//! use fsfast_engine::testing::{MemReadHandle, pattern};
//! use fsfast_engine::{FileReader, ReaderConfig, RetryPolicy, retry};
//!
//! // Any backend handle; here an in-memory mock.
//! let handle: Arc<dyn ReadHandle> = Arc::new(MemReadHandle::new(pattern(1 << 20)));
//!
//! // Backends wrap idempotent requests in `retry`.
//! let first = retry(&RetryPolicy::default(), || handle.read_at(0, 4)).await?;
//!
//! // Python file objects are thin wrappers around a `FileReader`.
//! let mut file = FileReader::new(handle, ReaderConfig::default());
//! assert_eq!(file.read(Some(4)).await?, first);
//! file.seek(SeekFrom::End(-8))?;
//! let mut footer = [0u8; 8];
//! assert_eq!(file.read_into(&mut footer).await?, 8);
//! file.close().await?;
//! # Ok(()) }
//! ```

#![warn(missing_docs)]

pub mod aimd;
pub mod budget;
pub mod concurrency;
mod elastic;
pub mod parallel;
pub mod reader;
pub mod retry;
pub mod stats;
pub mod upload;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// Property-test case count: `PROPTEST_CASES` when set, else `default`
/// (an explicit `ProptestConfig::with_cases` ignores the variable).
#[cfg(test)]
pub(crate) fn proptest_cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

pub use aimd::{AimdConfig, AimdLimiter, AimdPermit, Outcome};
pub use budget::{BudgetGuard, MemoryBudget};
pub use concurrency::{AbortOnDrop, map_ordered, try_map_ordered};
pub use parallel::{read_parallel, read_parallel_into};
pub use reader::{BlockCacheConfig, CacheMode, FileReader, ReaderConfig};
pub use retry::{
    RetryAfter, RetryEvent, RetryPolicy, retry, retry_after_hint, retry_notify, retry_with_stats,
};
pub use stats::{HistogramSnapshot, LatencyHistogram, OpKind, Stats, StatsSnapshot};
pub use upload::{
    CompletedPart, PartOutcome, PartSink, PartSizer, PartUploader, UploadConfig, UploadResult,
};
