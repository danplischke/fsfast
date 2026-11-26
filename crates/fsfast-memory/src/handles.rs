//! Read and write handles.

use std::fmt;
use std::ops::Range;
use std::ptr::NonNull;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use fsfast_core::{Error, FileInfo, IoHints, ReadHandle, Result, WriteHandle};

use crate::Store;
use crate::store::MemFile;

/// A read handle over an immutable snapshot of the file taken at open time.
/// Reads are zero-copy slices and see no later writes (they are pinned to the
/// version observed at open, like fsspec's `MemoryFile` object captured by
/// `open`).
#[derive(Debug)]
pub(crate) struct MemoryReadHandle {
    pub info: FileInfo,
    pub data: Bytes,
    pub hints: IoHints,
}

/// `data[range]`, clamped to the buffer.
pub(crate) fn clamped_slice(data: &Bytes, range: &Range<u64>) -> Bytes {
    let len = data.len() as u64;
    let start = range.start.min(len);
    let end = range.end.min(len).max(start);
    data.slice(start as usize..end as usize)
}

#[fsfast_core::async_trait]
impl ReadHandle for MemoryReadHandle {
    fn info(&self) -> &FileInfo {
        &self.info
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    fn io_hints(&self) -> IoHints {
        self.hints
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        Ok(clamped_slice(
            &self.data,
            &(offset..offset.saturating_add(len as u64)),
        ))
    }

    /// Slicing is free, so no coalescing: every range is an independent
    /// zero-copy slice.
    async fn read_ranges(&self, ranges: &[Range<u64>]) -> Result<Vec<Bytes>> {
        Ok(ranges
            .iter()
            .map(|r| clamped_slice(&self.data, r))
            .collect())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Open,
    Closed,
    Aborted,
}

/// One fixed-capacity allocation that is only ever appended to.
///
/// Bytes `[0, len)` written so far are immutable; published snapshots
/// ([`Prefix`]) share the allocation and only read below the length they were
/// created with, while the single writer ([`AppendBuf`]) only writes at or
/// above its current length. Reads and writes therefore never overlap.
struct Region {
    ptr: NonNull<u8>,
    cap: usize,
}

// SAFETY: `Region` owns its allocation like a `Vec<u8>` does. Shared access
// only happens through `Prefix::as_ref` (reads of bytes that were fully
// written before the prefix was created, and are never written again) and
// `AppendBuf::extend` (writes, from the one `&mut AppendBuf`, to bytes no
// prefix covers), so moving it or sharing it between threads is sound.
unsafe impl Send for Region {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for Region {}

impl Drop for Region {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`cap` come from a `Vec<u8>` leaked in
        // `AppendBuf::with_capacity`; a length of 0 means no element needs
        // dropping (and no byte needs to be initialised).
        drop(unsafe { Vec::from_raw_parts(self.ptr.as_ptr(), 0, self.cap) });
    }
}

/// A published, immutable view of the first `len` bytes of a [`Region`].
struct Prefix {
    region: Arc<Region>,
    len: usize,
}

impl AsRef<[u8]> for Prefix {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: `len <= cap`, the first `len` bytes were initialised by
        // `AppendBuf::extend` before this prefix was created, and they are
        // never written again (see `Region`).
        unsafe { std::slice::from_raw_parts(self.region.ptr.as_ptr(), self.len) }
    }
}

/// The writer side of a [`Region`].
struct AppendBuf {
    region: Arc<Region>,
    len: usize,
}

impl AppendBuf {
    fn with_capacity(cap: usize) -> Self {
        let mut v = std::mem::ManuallyDrop::new(Vec::<u8>::with_capacity(cap.max(1)));
        let region = Region {
            ptr: NonNull::new(v.as_mut_ptr()).expect("Vec pointers are non-null"),
            cap: v.capacity(),
        };
        AppendBuf {
            region: Arc::new(region),
            len: 0,
        }
    }

    fn capacity(&self) -> usize {
        self.region.cap
    }

    fn remaining(&self) -> usize {
        self.region.cap - self.len
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: as for `Prefix::as_ref`: `[0, len)` is initialised.
        unsafe { std::slice::from_raw_parts(self.region.ptr.as_ptr(), self.len) }
    }

    fn extend(&mut self, src: &[u8]) {
        assert!(src.len() <= self.remaining(), "AppendBuf overflow");
        // SAFETY: the destination `[len, len + src.len())` is inside the
        // allocation (checked above), is covered by no `Prefix` (they all end
        // at or below `len`), and `src` cannot alias it: callers' slices are
        // either other allocations or prefixes, which end at or below `len`.
        unsafe {
            std::ptr::copy_nonoverlapping(
                src.as_ptr(),
                self.region.ptr.as_ptr().add(self.len),
                src.len(),
            );
        }
        self.len += src.len();
    }

    /// A zero-copy snapshot of everything written so far.
    fn snapshot(&self) -> Bytes {
        Bytes::from_owner(Prefix {
            region: self.region.clone(),
            len: self.len,
        })
    }
}

/// A write handle. As in fsspec, the file exists from the moment it is
/// opened; written data becomes visible on `flush`, `close` or drop.
///
/// Chunks are kept as the caller's `Bytes` until published. A file written
/// with a single `write` and then closed is stored without any copy.
///
/// Performance: `flush` must not re-copy what was already published (fsspec's
/// `MemoryFile.flush` is O(1); copying `base + pending` on every flush made a
/// log-style writer quadratic). Once a file is flushed, its content lives in
/// an append-only [`AppendBuf`] whose capacity doubles when full: each flush
/// copies only the new chunks and publishes a zero-copy prefix of the
/// buffer, so N bytes cost O(N) copying in total. On close, a buffer that is
/// mostly spare capacity is compacted once so the store does not keep up to
/// 2x the file size alive.
pub(crate) struct MemoryWriteHandle {
    pub store: Arc<Store>,
    pub path: String,
    /// Generation of the store entry this handle owns.
    pub generation: u64,
    /// The entry to put back on abort (append to an existing file).
    pub restore: Option<MemFile>,
    /// Content already published (or pre-existing, in append mode) while no
    /// append buffer exists yet.
    base: Bytes,
    /// Everything published so far, once a flush needed to concatenate.
    buf: Option<AppendBuf>,
    chunks: Vec<Bytes>,
    pending: usize,
    written: u64,
    state: State,
}

impl fmt::Debug for MemoryWriteHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryWriteHandle")
            .field("path", &self.path)
            .field("written", &self.written)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Smallest append buffer worth allocating on a flush.
const MIN_APPEND_CAPACITY: usize = 64 * 1024;

impl MemoryWriteHandle {
    pub fn new(store: Arc<Store>, path: String, slot: crate::store::WriteSlot) -> Self {
        MemoryWriteHandle {
            store,
            path,
            generation: slot.generation,
            restore: slot.restore,
            base: slot.base,
            buf: None,
            chunks: Vec::new(),
            pending: 0,
            written: 0,
            state: State::Open,
        }
    }

    fn closed_error(&self) -> Error {
        Error::invalid_input(match self.state {
            State::Aborted => "write handle was aborted",
            _ => "I/O operation on closed file",
        })
        .with_path(self.path.clone())
    }

    /// Concatenate `published` and the pending chunks into one exact-size
    /// buffer (one copy).
    fn assemble_exact(&mut self, published: &[u8]) -> Bytes {
        let mut out = BytesMut::with_capacity(published.len() + self.pending);
        out.extend_from_slice(published);
        for c in self.chunks.drain(..) {
            out.extend_from_slice(&c);
        }
        self.pending = 0;
        out.freeze()
    }

    /// The content to publish: everything published so far plus the pending
    /// chunks. `last` is set by `close`/drop, when no further appends follow.
    fn assemble(&mut self, last: bool) -> Bytes {
        if self.buf.is_none() && self.base.is_empty() && self.chunks.len() == 1 {
            // A single write: store the caller's buffer itself.
            self.pending = 0;
            let data = self.chunks.pop().expect("one chunk");
            self.base = data.clone();
            return data;
        }
        let published = match &self.buf {
            Some(b) => b.len,
            None => self.base.len(),
        };
        let needed = published + self.pending;
        let fits = self
            .buf
            .as_ref()
            .is_some_and(|b| b.remaining() >= self.pending);
        if last && !fits {
            // No later appends: one exact-size copy beats growing a buffer.
            let data = match self.buf.take() {
                Some(b) => self.assemble_exact(b.as_slice()),
                None => {
                    let base = std::mem::take(&mut self.base);
                    self.assemble_exact(&base)
                }
            };
            self.base = data.clone();
            return data;
        }
        if !fits {
            // Grow geometrically so the copies of old content add up to O(N).
            let cap = self
                .buf
                .as_ref()
                .map_or(0, |b| b.capacity().saturating_mul(2))
                .max(needed.saturating_mul(2))
                .max(MIN_APPEND_CAPACITY);
            let mut grown = AppendBuf::with_capacity(cap);
            match self.buf.take() {
                Some(old) => grown.extend(old.as_slice()),
                None => grown.extend(&std::mem::take(&mut self.base)),
            }
            self.buf = Some(grown);
        }
        let buf = self.buf.as_mut().expect("append buffer");
        for c in self.chunks.drain(..) {
            buf.extend(&c);
        }
        self.pending = 0;
        buf.snapshot()
    }

    /// On close: if the append buffer is mostly spare capacity, copy its
    /// content into an exact-size buffer once and return it for publishing.
    fn compact(&mut self) -> Option<Bytes> {
        let b = self.buf.as_ref()?;
        if b.capacity() - b.len <= b.len / 2 {
            return None;
        }
        let data = Bytes::copy_from_slice(b.as_slice());
        self.buf = None;
        self.base = data.clone();
        Some(data)
    }

    fn publish(&mut self, last: bool) {
        let data = if self.chunks.is_empty() {
            match last.then(|| self.compact()).flatten() {
                Some(d) => d,
                None => return,
            }
        } else {
            let d = self.assemble(last);
            match last.then(|| self.compact()).flatten() {
                Some(c) => c,
                None => d,
            }
        };
        let committed = self
            .store
            .inner
            .write()
            .commit(&self.path, self.generation, data);
        match committed {
            Some(g) => self.generation = g,
            None => tracing::debug!(
                path = %self.path,
                "memory file was replaced or deleted while open; dropping its writes"
            ),
        }
    }
}

#[fsfast_core::async_trait]
impl WriteHandle for MemoryWriteHandle {
    async fn write(&mut self, data: Bytes) -> Result<()> {
        if self.state != State::Open {
            return Err(self.closed_error());
        }
        self.written += data.len() as u64;
        if !data.is_empty() {
            self.pending += data.len();
            self.chunks.push(data);
        }
        Ok(())
    }

    async fn flush(&mut self) -> Result<()> {
        if self.state != State::Open {
            return Err(self.closed_error());
        }
        self.publish(false);
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        match self.state {
            State::Closed => Ok(()),
            State::Aborted => Err(self.closed_error()),
            State::Open => {
                self.publish(true);
                self.state = State::Closed;
                Ok(())
            }
        }
    }

    async fn abort(&mut self) -> Result<()> {
        if self.state == State::Open {
            self.chunks.clear();
            self.pending = 0;
            self.buf = None;
            self.store
                .inner
                .write()
                .abort(&self.path, self.generation, self.restore.take());
            self.state = State::Aborted;
        }
        Ok(())
    }

    fn bytes_written(&self) -> u64 {
        self.written
    }
}

impl Drop for MemoryWriteHandle {
    /// Like a Python file object being garbage collected: pending data is
    /// published (cheap, no I/O), never silently lost.
    fn drop(&mut self) {
        if self.state == State::Open {
            self.publish(true);
        }
    }
}
