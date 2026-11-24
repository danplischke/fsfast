//! Adaptive sequential readahead (Linux-style window growth).
//!
//! State: a deque of contiguous [`Fetch`] chunks `[front.start, back.end)`
//! that starts at (or before) the next expected read position, the current
//! window size (0 = random mode, no prefetch) and the end of the previous
//! read for sequential detection.

use std::collections::VecDeque;

use bytes::Bytes;
use fsfast_core::Result;

use super::{Ctx, Fetch};

pub(super) struct Readahead {
    chunks: VecDeque<Fetch>,
    /// Target bytes to keep prefetched beyond the read position; 0 = random.
    window: u64,
    /// End of the previous completed read.
    last_end: Option<u64>,
    /// Bytes consumed since the window last grew.
    consumed: u64,
    min_window: u64,
    max_window: u64,
}

impl Readahead {
    pub(super) fn new(min_window: u64, max_window: u64) -> Self {
        Readahead {
            chunks: VecDeque::new(),
            window: 0,
            last_end: None,
            consumed: 0,
            min_window: min_window.clamp(1, max_window.max(1)),
            max_window: max_window.max(1),
        }
    }

    pub(super) fn clear(&mut self) {
        self.chunks.clear();
    }

    fn covers(&self, pos: u64) -> bool {
        match (self.chunks.front(), self.chunks.back()) {
            (Some(f), Some(b)) => f.start <= pos && pos < b.end,
            _ => false,
        }
    }

    /// A seek away from the prefetched range cancels the prefetches now, so
    /// their bandwidth is freed even if no read follows.
    pub(super) fn on_seek(&mut self, pos: u64) {
        if !self.covers(pos) && self.last_end != Some(pos) && !self.chunks.is_empty() {
            tracing::trace!(pos, "readahead: seek away, cancelling prefetch");
            self.chunks.clear();
        }
    }

    /// Linux `get_init_ra_size`: 4x small reads, 2x medium ones, else max.
    fn init_window(&self, n: usize) -> u64 {
        let req = (n as u64)
            .max(1)
            .checked_next_power_of_two()
            .unwrap_or(u64::MAX);
        let max = self.max_window;
        let w = if req <= max / 32 {
            req * 4
        } else if req <= max / 4 {
            req * 2
        } else {
            max
        };
        w.clamp(self.min_window, max)
    }

    /// Linux `get_next_ra_size`: 4x while small, then 2x, capped.
    fn next_window(&self, cur: u64) -> u64 {
        let max = self.max_window;
        let w = if cur < max / 16 {
            cur.saturating_mul(4)
        } else if cur <= max / 2 {
            cur.saturating_mul(2)
        } else {
            max
        };
        w.min(max)
    }

    /// Classify the read at `pos` and drop/cancel what it makes useless.
    fn observe(&mut self, pos: u64, n: usize) {
        if self.covers(pos) {
            while self.chunks.front().is_some_and(|c| c.end <= pos) {
                self.chunks.pop_front();
            }
            if self.window == 0 {
                self.window = self.init_window(n);
            }
            return;
        }
        self.chunks.clear();
        let sequential = match self.last_end {
            Some(end) => end == pos,
            None => pos == 0,
        };
        if sequential {
            if self.window == 0 {
                self.window = self.init_window(n);
                self.consumed = 0;
                tracing::trace!(
                    pos,
                    window = self.window,
                    "readahead: sequential access detected"
                );
            }
        } else {
            self.window = 0;
            self.consumed = 0;
        }
    }

    fn chunk_size(&self, ctx: &Ctx) -> u64 {
        (ctx.request_size as u64)
            .min(self.window.max(self.min_window))
            .max(1)
    }

    /// Extend the pipeline from its end (or `from` if empty): chunks below
    /// `need_until` are mandatory (always issued, budget force-acquired);
    /// chunks up to `need_until + window` are speculative (only while budget
    /// is available and fewer than `concurrency` requests are in flight).
    ///
    /// The window only sizes *speculative* chunks. Mandatory bytes go out in
    /// pieces of up to `request_size` even when the window is smaller,
    /// otherwise a small `max_readahead` would split one read into
    /// thousands of tiny requests (and tasks).
    fn issue(&mut self, ctx: &Ctx, from: u64, need_until: u64) {
        let mut next = self.chunks.back().map_or(from, |c| c.end);
        let ahead_until = need_until.saturating_add(self.window).min(ctx.size);
        let chunk = self.chunk_size(ctx);
        let mut in_flight = self.chunks.iter().filter(|c| c.in_flight()).count();
        while next < ahead_until {
            let mandatory = next < need_until;
            if !mandatory && in_flight >= ctx.concurrency {
                break;
            }
            let want = if mandatory {
                chunk.max((need_until - next).min(ctx.request_size as u64))
            } else {
                chunk
            };
            let len = want.min(ctx.size - next) as usize;
            let guard = if mandatory {
                ctx.budget.force_acquire(len)
            } else {
                match ctx.budget.try_acquire(len) {
                    Some(g) => g,
                    None => break,
                }
            };
            self.chunks.push_back(Fetch::spawn(ctx, next, len, guard));
            next += len as u64;
            in_flight += 1;
        }
    }

    /// Book-keeping after a completed read ending at `end`: grow the window
    /// and top up the prefetch pipeline.
    fn after_read(&mut self, ctx: &Ctx, end: u64, n: u64) {
        self.last_end = Some(end);
        if self.window == 0 {
            return;
        }
        self.consumed += n;
        if self.consumed >= self.window / 2 {
            let w = self.next_window(self.window);
            if w != self.window {
                tracing::trace!(from = self.window, to = w, "readahead: window grows");
            }
            self.window = w;
            self.consumed = 0;
        }
        if end < ctx.size {
            self.issue(ctx, end, end);
        }
    }

    /// Copy from the front of the pipeline into `dst`, starting at `cursor`,
    /// awaiting chunks still in flight. Fully consumed chunks are popped.
    async fn serve(&mut self, cursor: u64, dst: &mut [u8]) -> Result<usize> {
        let mut done = 0;
        while done < dst.len() {
            let at = cursor + done as u64;
            let Some(front) = self.chunks.front_mut() else {
                break;
            };
            if at < front.start || at >= front.end {
                break;
            }
            let end = front.end;
            let off = (at - front.start) as usize;
            let data = front.ready().await?;
            let take = (dst.len() - done).min(data.len() - off);
            dst[done..done + take].copy_from_slice(&data[off..off + take]);
            done += take;
            if at + take as u64 >= end {
                self.chunks.pop_front();
            }
        }
        Ok(done)
    }

    async fn fill(&mut self, ctx: &Ctx, pos: u64, dst: &mut [u8]) -> Result<()> {
        let mut done = 0;
        loop {
            done += self.serve(pos + done as u64, &mut dst[done..]).await?;
            if done == dst.len() {
                return Ok(());
            }
            debug_assert!(self.chunks.is_empty(), "pipeline must be exhausted here");
            let cursor = pos + done as u64;
            let rest = &mut dst[done..];
            if self.window == 0 || ctx.is_large(rest.len()) {
                // Random access, or too large to be worth staging: fetch
                // directly (in parallel parts when large).
                return ctx.fetch_into(cursor, rest).await;
            }
            self.issue(ctx, cursor, cursor + rest.len() as u64);
        }
    }

    pub(super) async fn read_into(&mut self, ctx: &Ctx, pos: u64, dst: &mut [u8]) -> Result<()> {
        self.observe(pos, dst.len());
        if let Err(e) = self.fill(ctx, pos, dst).await {
            self.chunks.clear();
            return Err(e);
        }
        self.after_read(ctx, pos + dst.len() as u64, dst.len() as u64);
        Ok(())
    }

    pub(super) async fn read_bytes(&mut self, ctx: &Ctx, pos: u64, n: usize) -> Result<Bytes> {
        match self.read_bytes_inner(ctx, pos, n).await {
            Ok(b) => {
                self.after_read(ctx, pos + n as u64, n as u64);
                Ok(b)
            }
            Err(e) => {
                self.chunks.clear();
                Err(e)
            }
        }
    }

    async fn read_bytes_inner(&mut self, ctx: &Ctx, pos: u64, n: usize) -> Result<Bytes> {
        self.observe(pos, n);
        if self.chunks.is_empty() {
            if self.window == 0 || ctx.is_large(n) {
                // Direct fetch; the backend's buffer is returned as-is.
                return ctx.fetch(pos, n).await;
            }
            self.issue(ctx, pos, pos + n as u64);
        }
        // Zero-copy when the read falls inside the front chunk.
        if let Some(front) = self.chunks.front_mut()
            && front.start <= pos
            && pos + n as u64 <= front.end
        {
            let end = front.end;
            let off = (pos - front.start) as usize;
            let out = front.ready().await?.slice(off..off + n);
            if pos + n as u64 == end {
                self.chunks.pop_front();
            }
            return Ok(out);
        }
        let mut buf = vec![0u8; n];
        self.fill(ctx, pos, &mut buf).await?;
        Ok(Bytes::from(buf))
    }

    #[cfg(test)]
    pub(super) fn window(&self) -> u64 {
        self.window
    }

    #[cfg(test)]
    pub(super) fn buffered_chunks(&self) -> usize {
        self.chunks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_sizing_follows_linux() {
        let ra = Readahead::new(1, 1 << 20);
        // Small reads: 4x the rounded-up size.
        assert_eq!(ra.init_window(1000), 4096);
        // Medium reads: 2x.
        assert_eq!(ra.init_window(100 << 10), 256 << 10);
        // Large reads: max.
        assert_eq!(ra.init_window(512 << 10), 1 << 20);
        assert_eq!(ra.init_window(0), 4);
        assert_eq!(ra.next_window(4096), 16384);
        assert_eq!(ra.next_window(64 << 10), 128 << 10);
        assert_eq!(ra.next_window(512 << 10), 1 << 20);
        assert_eq!(ra.next_window(1 << 20), 1 << 20);
        let ra = Readahead::new(256 << 10, 1 << 20);
        assert_eq!(ra.init_window(1), 256 << 10, "clamped to the minimum");
        let ra = Readahead::new(10, 5);
        assert_eq!((ra.min_window, ra.max_window), (5, 5));
        assert_eq!(ra.init_window(usize::MAX), 5);
    }
}
