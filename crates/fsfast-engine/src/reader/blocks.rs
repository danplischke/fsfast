//! LRU cache of fixed-size, aligned blocks (fsspec `blockcache` /
//! `background`).
//!
//! Missing blocks needed by a read are fetched as background tasks and
//! inserted as pending entries, so a later read of a block that is still in
//! flight waits for it instead of fetching it again. Consecutive missing
//! blocks are grouped into requests of up to the request size (one request
//! and task per group, each block caching its slice), so small blocks do not
//! multiply requests. Runs of missing blocks that are large (>= 2x the
//! request size, or more blocks than the cache holds) are read in parallel
//! straight into the destination and not cached. With `prefetch`, the block
//! after the last one read is fetched in the background.
//!
//! When a read fails, the fetches it was waiting for that are not complete,
//! and every fetch already known to have failed, are dropped, so retrying
//! the read issues fresh requests instead of reporting a stale error.
//!
//! Eviction is least-recently-used. Blocks touched by the current read are
//! never evicted while it runs (the cache may exceed `max_blocks` for the
//! duration of one read and is trimmed afterwards).

use std::collections::{BTreeMap, HashMap};

use bytes::Bytes;
use fsfast_core::{Error, ErrorKind, Result};

use super::{Ctx, Fetch};
use crate::budget::BudgetGuard;

struct Entry {
    tick: u64,
    fetch: Fetch,
}

pub(super) struct Blocks {
    block_size: u64,
    max_blocks: usize,
    prefetch: bool,
    map: HashMap<u64, Entry>,
    /// tick -> block index, oldest first.
    lru: BTreeMap<u64, u64>,
    tick: u64,
}

impl Blocks {
    pub(super) fn new(block_size: u64, max_blocks: usize, prefetch: bool) -> Self {
        Blocks {
            block_size: block_size.max(1),
            max_blocks: max_blocks.max(1),
            prefetch,
            map: HashMap::new(),
            lru: BTreeMap::new(),
            tick: 0,
        }
    }

    pub(super) fn clear(&mut self) {
        self.map.clear();
        self.lru.clear();
    }

    fn next_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    fn touch(&mut self, idx: u64) {
        let t = self.next_tick();
        if let Some(e) = self.map.get_mut(&idx) {
            self.lru.remove(&e.tick);
            e.tick = t;
            self.lru.insert(t, idx);
        }
    }

    fn remove(&mut self, idx: u64) {
        if let Some(e) = self.map.remove(&idx) {
            self.lru.remove(&e.tick);
        }
    }

    /// Evict the least recently used block if it was last used before
    /// `floor`. Returns whether something was evicted.
    fn evict_older_than(&mut self, floor: u64) -> bool {
        match self.lru.first_key_value() {
            Some((&t, &idx)) if t < floor => {
                self.remove(idx);
                true
            }
            _ => false,
        }
    }

    fn block_range(&self, ctx: &Ctx, idx: u64) -> (u64, usize) {
        let start = idx * self.block_size;
        (start, self.block_size.min(ctx.size - start) as usize)
    }

    /// Budget for a block the current read needs: free our own older blocks
    /// if necessary, over-commit as a last resort (the bytes are needed).
    fn guard_for(&mut self, ctx: &Ctx, len: usize, floor: u64) -> BudgetGuard {
        loop {
            if let Some(g) = ctx.budget.try_acquire(len) {
                return g;
            }
            if !self.evict_older_than(floor) {
                return ctx.budget.force_acquire(len);
            }
        }
    }

    /// Insert pending entries for the missing blocks `from..to`, fetched in
    /// groups of up to `max(request_size, block_size)` bytes.
    fn insert_run(&mut self, ctx: &Ctx, from: u64, to: u64, floor: u64) {
        let limit = (ctx.request_size as u64).max(self.block_size);
        let mut idx = from;
        while idx < to {
            let first = idx;
            let mut lens = Vec::new();
            let mut total = 0u64;
            while idx < to {
                let (_, len) = self.block_range(ctx, idx);
                if !lens.is_empty() && total + len as u64 > limit {
                    break;
                }
                lens.push(len);
                total += len as u64;
                idx += 1;
            }
            while self.map.len() + lens.len() > self.max_blocks && self.evict_older_than(floor) {}
            let guard = self.guard_for(ctx, total as usize, floor);
            let (start, _) = self.block_range(ctx, first);
            for (b, fetch) in (first..).zip(Fetch::spawn_shared(ctx, start, &lens, guard)) {
                let t = self.next_tick();
                self.map.insert(b, Entry { tick: t, fetch });
                self.lru.insert(t, b);
            }
        }
    }

    /// After a failed read of blocks `first..=last`: drop the entries of
    /// that range that are not ready (failed, or still in flight while the
    /// read gave up) and every other entry whose fetch is known to have
    /// failed, so a retry fetches them afresh instead of reporting a stale
    /// error. Finished successful fetches are kept.
    fn forget_failed(&mut self, first: u64, last: u64) {
        let mut drop = Vec::new();
        for (&idx, e) in self.map.iter_mut() {
            let in_read = (first..=last).contains(&idx);
            match e.fetch.settle() {
                Some(true) => {}
                Some(false) => drop.push(idx),
                None if in_read => drop.push(idx),
                None => {}
            }
        }
        for idx in drop {
            self.remove(idx);
        }
    }

    /// Background fetch of block `idx` if it is useful and affordable.
    fn maybe_prefetch(&mut self, ctx: &Ctx, idx: u64, floor: u64) {
        if idx * self.block_size >= ctx.size || self.map.contains_key(&idx) {
            return;
        }
        if self.map.len() >= self.max_blocks && !self.evict_older_than(floor) {
            return;
        }
        let (start, len) = self.block_range(ctx, idx);
        let Some(guard) = ctx.budget.try_acquire(len) else {
            return;
        };
        let fetch = Fetch::spawn(ctx, start, len, guard);
        let t = self.next_tick();
        self.map.insert(idx, Entry { tick: t, fetch });
        self.lru.insert(t, idx);
    }

    fn trim(&mut self) {
        while self.map.len() > self.max_blocks && self.evict_older_than(u64::MAX) {}
    }

    fn finish_read(&mut self, ctx: &Ctx, last: u64, floor: u64) {
        self.trim();
        if self.prefetch {
            self.maybe_prefetch(ctx, last + 1, floor);
        }
    }

    async fn block_data(&mut self, idx: u64) -> Result<&Bytes> {
        let res = match self.map.get_mut(&idx) {
            None => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("block {idx} missing from cache"),
                ));
            }
            Some(e) => e.fetch.ready().await.map(|_| ()),
        };
        if let Err(e) = res {
            self.remove(idx);
            return Err(e);
        }
        match self.map.get(&idx).map(|e| &e.fetch.state) {
            Some(super::FetchState::Ready(b)) => Ok(b),
            _ => Err(Error::new(
                ErrorKind::Other,
                format!("block {idx} not ready"),
            )),
        }
    }

    pub(super) async fn read_into(&mut self, ctx: &Ctx, pos: u64, dst: &mut [u8]) -> Result<()> {
        let bs = self.block_size;
        let (first, last) = (pos / bs, (pos + dst.len() as u64 - 1) / bs);
        let res = self.read_into_inner(ctx, pos, dst).await;
        if res.is_err() {
            self.forget_failed(first, last);
        }
        res
    }

    async fn read_into_inner(&mut self, ctx: &Ctx, pos: u64, dst: &mut [u8]) -> Result<()> {
        let bs = self.block_size;
        let end = pos + dst.len() as u64;
        let (first, last) = (pos / bs, (end - 1) / bs);
        let floor = self.tick + 1;

        // 1. Classify blocks: cached (touch), small missing runs (spawn
        //    fetches into the cache), large missing runs (direct).
        let mut direct: Vec<(u64, u64)> = Vec::new();
        let mut idx = first;
        while idx <= last {
            if self.map.contains_key(&idx) {
                self.touch(idx);
                idx += 1;
                continue;
            }
            let run_start = idx;
            while idx <= last && !self.map.contains_key(&idx) {
                idx += 1;
            }
            let lo = pos.max(run_start * bs);
            let hi = end.min(idx * bs);
            if ctx.is_large((hi - lo) as usize) || (idx - run_start) as usize > self.max_blocks {
                direct.push((run_start, idx));
            } else {
                self.insert_run(ctx, run_start, idx, floor);
            }
        }

        // 2. Large runs straight into the destination, while the small
        //    fetches proceed in the background.
        for &(a, b) in &direct {
            let lo = pos.max(a * bs);
            let hi = end.min(b * bs);
            ctx.fetch_into(lo, &mut dst[(lo - pos) as usize..(hi - pos) as usize])
                .await?;
        }

        // 3. Copy cached blocks.
        for idx in first..=last {
            if direct.iter().any(|&(a, b)| (a..b).contains(&idx)) {
                continue;
            }
            let block_start = idx * bs;
            let lo = pos.max(block_start);
            let hi = end.min(block_start + bs);
            let data = self.block_data(idx).await?;
            dst[(lo - pos) as usize..(hi - pos) as usize]
                .copy_from_slice(&data[(lo - block_start) as usize..(hi - block_start) as usize]);
        }

        self.finish_read(ctx, last, floor);
        Ok(())
    }

    pub(super) async fn read_bytes(&mut self, ctx: &Ctx, pos: u64, n: usize) -> Result<Bytes> {
        let bs = self.block_size;
        let (first, last) = (pos / bs, (pos + n as u64 - 1) / bs);
        let cached = self.map.contains_key(&first);
        if first != last || (!cached && ctx.is_large(n)) {
            let mut buf = vec![0u8; n];
            self.read_into(ctx, pos, &mut buf).await?;
            return Ok(Bytes::from(buf));
        }
        // Single block: return a slice of the cached block (zero-copy).
        let floor = self.tick + 1;
        if cached {
            self.touch(first);
        } else {
            self.insert_run(ctx, first, first + 1, floor);
        }
        let off = (pos - first * bs) as usize;
        let out = match self.block_data(first).await {
            Ok(b) => b.slice(off..off + n),
            Err(e) => {
                self.forget_failed(first, last);
                return Err(e);
            }
        };
        self.finish_read(ctx, last, floor);
        Ok(out)
    }

    #[cfg(test)]
    pub(super) fn cached_blocks(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.map.keys().copied().collect();
        v.sort_unstable();
        v
    }
}
