//! Small concurrency helpers shared by the engine and backends.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use fsfast_core::{Error, ErrorKind, Result};
use futures::{StreamExt, TryStreamExt, stream};
use tokio::task::{JoinError, JoinHandle};

/// Apply `f` to every item with at most `concurrency` futures in flight,
/// returning results in input order (`0` is treated as `1`).
///
/// The futures run on the calling task (no spawning), which suits I/O-bound
/// work whose heavy lifting happens elsewhere (connection tasks, the
/// kernel).
pub async fn map_ordered<I, F, Fut, T>(items: I, concurrency: usize, f: F) -> Vec<T>
where
    I: IntoIterator,
    F: FnMut(I::Item) -> Fut,
    Fut: Future<Output = T>,
{
    stream::iter(items)
        .map(f)
        .buffered(concurrency.max(1))
        .collect()
        .await
}

/// Like [`map_ordered`] for fallible work: stops at the first error (dropping
/// the futures still in flight) and returns it.
pub async fn try_map_ordered<I, F, Fut, T>(items: I, concurrency: usize, f: F) -> Result<Vec<T>>
where
    I: IntoIterator,
    F: FnMut(I::Item) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    stream::iter(items)
        .map(f)
        .buffered(concurrency.max(1))
        .try_collect()
        .await
}

/// A [`JoinHandle`] that aborts its task when dropped, so speculative work
/// (prefetch, background uploads) never outlives its owner.
pub struct AbortOnDrop<T>(JoinHandle<T>);

impl<T: Send + 'static> AbortOnDrop<T> {
    /// Spawn `fut` on the current tokio runtime.
    ///
    /// # Panics
    /// Outside a tokio runtime (like [`tokio::spawn`]).
    pub fn spawn<F>(fut: F) -> Self
    where
        F: Future<Output = T> + Send + 'static,
    {
        AbortOnDrop(tokio::spawn(fut))
    }
}

impl<T> AbortOnDrop<T> {
    /// Wrap an existing handle.
    pub fn new(handle: JoinHandle<T>) -> Self {
        AbortOnDrop(handle)
    }

    /// Whether the task has finished (successfully, by panic or by abort).
    pub fn is_finished(&self) -> bool {
        self.0.is_finished()
    }

    /// Abort the task now.
    pub fn abort(&self) {
        self.0.abort();
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl<T> fmt::Debug for AbortOnDrop<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AbortOnDrop")
            .field("finished", &self.0.is_finished())
            .finish()
    }
}

impl<T> Future for AbortOnDrop<T> {
    type Output = std::result::Result<T, JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

/// Turn a task's [`JoinError`] into the engine's error model: a panic is
/// re-raised on the joining task (it is a bug, not an I/O failure); an
/// aborted task becomes [`ErrorKind::Cancelled`].
pub(crate) fn join_error(e: JoinError) -> Error {
    match e.try_into_panic() {
        Ok(payload) => std::panic::resume_unwind(payload),
        Err(e) => Error::new(
            ErrorKind::Cancelled,
            format!("background task cancelled: {e}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn map_ordered_preserves_order_and_bounds_concurrency() {
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let out = map_ordered(0..20u64, 4, |i| {
            let (live, peak) = (live.clone(), peak.clone());
            async move {
                let n = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(n, Ordering::SeqCst);
                // Later items finish first.
                tokio::time::sleep(Duration::from_millis(100 - i)).await;
                live.fetch_sub(1, Ordering::SeqCst);
                i * 2
            }
        })
        .await;
        assert_eq!(out, (0..20).map(|i| i * 2).collect::<Vec<_>>());
        assert_eq!(peak.load(Ordering::SeqCst), 4);
        assert!(
            map_ordered(Vec::<u8>::new(), 0, |x| async move { x })
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn try_map_ordered_stops_at_first_error() {
        let started = AtomicUsize::new(0);
        let r = try_map_ordered(0..100, 2, |i| {
            started.fetch_add(1, Ordering::SeqCst);
            async move {
                if i == 3 {
                    Err(Error::not_found(format!("{i}")))
                } else {
                    Ok(i)
                }
            }
        })
        .await;
        assert_eq!(r.unwrap_err().path(), Some("3"));
        assert!(started.load(Ordering::SeqCst) < 10);
        assert_eq!(
            try_map_ordered(0..5, 3, |i| async move { Ok(i) })
                .await
                .unwrap(),
            vec![0, 1, 2, 3, 4]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn abort_on_drop_cancels_task() {
        let marker = Arc::new(());
        let m = marker.clone();
        let h = AbortOnDrop::spawn(async move {
            let _m = m;
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });
        assert!(!h.is_finished());
        drop(h);
        tokio::task::yield_now().await;
        assert_eq!(Arc::strong_count(&marker), 1, "task future dropped");

        let h = AbortOnDrop::spawn(async { 5 });
        assert_eq!(h.await.unwrap(), 5);

        let h = AbortOnDrop::new(tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }));
        h.abort();
        let e = join_error(h.await.unwrap_err());
        assert_eq!(e.kind(), ErrorKind::Cancelled);
    }

    #[tokio::test]
    #[should_panic(expected = "boom")]
    async fn join_error_propagates_panics() {
        let h = tokio::spawn(async { panic!("boom") });
        let e = h.await.unwrap_err();
        let _ = join_error(e);
    }
}
