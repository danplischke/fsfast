//! Read and write handles.

use std::fmt;
use std::ops::Range;
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

/// A write handle. As in fsspec, the file exists from the moment it is
/// opened; written data becomes visible on `flush`, `close` or drop.
///
/// Chunks are kept as the caller's `Bytes` and concatenated once when
/// published; a file written with a single `write` is stored without any
/// copy.
pub(crate) struct MemoryWriteHandle {
    pub store: Arc<Store>,
    pub path: String,
    /// Generation of the store entry this handle owns.
    pub generation: u64,
    /// The entry to put back on abort (append to an existing file).
    pub restore: Option<MemFile>,
    /// Content already published (or pre-existing, in append mode).
    pub base: Bytes,
    pub chunks: Vec<Bytes>,
    pub pending: usize,
    pub written: u64,
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

impl MemoryWriteHandle {
    pub fn new(store: Arc<Store>, path: String, slot: crate::store::WriteSlot) -> Self {
        MemoryWriteHandle {
            store,
            path,
            generation: slot.generation,
            restore: slot.restore,
            base: slot.base,
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

    /// Concatenate `base` and the pending chunks (one copy at most).
    fn assemble(&mut self) -> Bytes {
        if self.base.is_empty() && self.chunks.len() == 1 {
            self.pending = 0;
            return self.chunks.pop().expect("one chunk");
        }
        let mut buf = BytesMut::with_capacity(self.base.len() + self.pending);
        buf.extend_from_slice(&self.base);
        for c in self.chunks.drain(..) {
            buf.extend_from_slice(&c);
        }
        self.pending = 0;
        buf.freeze()
    }

    fn publish(&mut self) {
        if self.chunks.is_empty() {
            return;
        }
        let data = self.assemble();
        self.base = data.clone();
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
        self.publish();
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        match self.state {
            State::Closed => Ok(()),
            State::Aborted => Err(self.closed_error()),
            State::Open => {
                self.publish();
                self.state = State::Closed;
                Ok(())
            }
        }
    }

    async fn abort(&mut self) -> Result<()> {
        if self.state == State::Open {
            self.chunks.clear();
            self.pending = 0;
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
            self.publish();
        }
    }
}
