//! The read (idle) timeout: how long a request may go without progress.
//!
//! reqwest's own `read_timeout` is a fixed deadline from sending a request
//! to receiving the response head. An upload that takes longer than that to
//! transmit is cut off however steadily it progresses (a multi-GiB
//! `put_file`, an `open_write` stream fed over minutes). fsfast therefore
//! enforces the timeout itself:
//!
//! * While the request is in flight, every request-body chunk handed to
//!   hyper marks [`Activity`]; the wait for the response head fails only
//!   after `read_timeout` without any (see [`until_idle`]). Stream bodies
//!   (files, chunk lists, streams, and in-memory buffers too large to keep
//!   resendable) are fed in [`SLICE`]-sized pieces (zero-copy
//!   [`Bytes::slice`]s) so progress stays visible. While hyper waits for the *caller* to produce the next
//!   body chunk (a streaming upload fed by a slow computation), the clock is
//!   stopped: only waits on the server count.
//! * Response-body reads time out when no chunk arrives for `read_timeout`
//!   ([`crate::Response`], [`crate::BodyStream`]).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use fsfast_core::Error;
use futures::{Stream, StreamExt};
use tokio::time::Instant;

/// Request-body chunks larger than this are handed to hyper in slices, so
/// upload progress is observed at least this often. hyper buffers a few
/// hundred KiB before it polls the body again, so this tracks the socket.
pub(crate) const SLICE: usize = 1 << 20;

/// When a request last made progress (shared with its body stream).
#[derive(Debug, Clone)]
pub(crate) struct Activity {
    base: Instant,
    /// Nanoseconds since `base` of the last progress.
    last: Arc<AtomicU64>,
    /// hyper is waiting for the request body's producer, not for the server.
    producer_wait: Arc<AtomicBool>,
}

impl Activity {
    /// Activity starting now.
    pub(crate) fn new() -> Self {
        Activity {
            base: Instant::now(),
            last: Arc::new(AtomicU64::new(0)),
            producer_wait: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Record progress now.
    pub(crate) fn touch(&self) {
        let nanos = u64::try_from(self.base.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.last.fetch_max(nanos, Ordering::Relaxed);
    }

    fn waiting_for_producer(&self) -> bool {
        self.producer_wait.load(Ordering::Relaxed)
    }

    fn last(&self) -> Instant {
        self.base + Duration::from_nanos(self.last.load(Ordering::Relaxed))
    }
}

/// A request body stream that records progress in an [`Activity`]: every
/// item (and the end) counts as progress, and a pending poll means hyper is
/// waiting for the producer, which stops the idle clock.
pub(crate) struct Tracked<S> {
    inner: S,
    activity: Activity,
}

impl<S> Tracked<S> {
    pub(crate) fn new(inner: S, activity: Activity) -> Self {
        Tracked { inner, activity }
    }
}

impl<S: Stream + Unpin> Stream for Tracked<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        let polled = self.inner.poll_next_unpin(cx);
        let waiting = polled.is_pending();
        if !waiting {
            self.activity.touch();
        }
        self.activity
            .producer_wait
            .store(waiting, Ordering::Relaxed);
        polled
    }
}

/// `b` as pieces of at most [`SLICE`] bytes (no copies).
pub(crate) fn slices(b: Bytes) -> impl Iterator<Item = Bytes> {
    let len = b.len();
    (0..len.div_ceil(SLICE).max(1)).map(move |i| b.slice(i * SLICE..((i + 1) * SLICE).min(len)))
}

/// Run `fut` (sending a request and waiting for its response head) until it
/// completes, or until `idle` passes without `activity`. `None` for `idle`
/// waits indefinitely.
pub(crate) async fn until_idle<F: Future>(
    fut: F,
    idle: Option<Duration>,
    activity: &Activity,
) -> Result<F::Output, Elapsed> {
    let Some(idle) = idle else {
        return Ok(fut.await);
    };
    tokio::pin!(fut);
    loop {
        let deadline = activity.last() + idle;
        tokio::select! {
            biased;
            out = &mut fut => return Ok(out),
            () = tokio::time::sleep_until(deadline) => {
                if activity.waiting_for_producer() {
                    // The caller, not the server, is slow: restart the clock.
                    activity.touch();
                } else if activity.last() + idle <= Instant::now() {
                    // (Otherwise the body progressed while we slept.)
                    return Err(Elapsed(idle));
                }
            }
        }
    }
}

/// No progress for the read timeout.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Elapsed(pub(crate) Duration);

impl Elapsed {
    /// The fsfast error (`Timeout`, retryable like any timeout).
    pub(crate) fn into_error(self, what: &str, path: &str) -> Error {
        Error::timeout(format!(
            "{what}: no progress for {:?} (read_timeout)",
            self.0
        ))
        .with_path(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_cover_the_buffer_without_copies() {
        let b = Bytes::from(vec![5u8; 2 * SLICE + 3]);
        let parts: Vec<Bytes> = slices(b.clone()).collect();
        assert_eq!(
            parts.iter().map(Bytes::len).collect::<Vec<_>>(),
            [SLICE, SLICE, 3]
        );
        assert_eq!(parts[1].as_ptr(), b[SLICE..].as_ptr());
        assert_eq!(slices(Bytes::new()).count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_deadline_moves_with_activity() {
        let a = Activity::new();
        let toucher = {
            let a = a.clone();
            async move {
                for _ in 0..10 {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    a.touch();
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        };
        let start = Instant::now();
        let r = until_idle(toucher, Some(Duration::from_millis(100)), &a).await;
        assert!(r.is_err());
        // 500 ms of activity, then 100 ms idle.
        let took = start.elapsed();
        assert!(
            took >= Duration::from_millis(600) && took < Duration::from_millis(700),
            "{took:?}"
        );
        assert_eq!(
            until_idle(async { 7 }, Some(Duration::ZERO), &Activity::new())
                .await
                .unwrap(),
            7
        );
        assert_eq!(until_idle(async { 8 }, None, &a).await.unwrap(), 8);
    }
}
