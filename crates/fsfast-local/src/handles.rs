//! Read and write handles over `std::fs::File`.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use futures::{StreamExt, stream};
use fsfast_core::{
    CoalescedRange, Error, ErrorKind, FileInfo, IoHints, ReadHandle, Result, WriteHandle,
    WriteMode, coalesce_ranges,
};
use tokio::task::JoinHandle;

use crate::blocking;
use crate::stat::io_err;

/// `pread` at an absolute offset; safe to call concurrently on one `File`.
#[cfg(unix)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buf, offset)
}

/// Positional read on Windows (`ReadFile` with an explicit offset). It also
/// moves the file cursor, which no other code path of the handle uses.
#[cfg(windows)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buf, offset)
}

/// Fill as much of `buf` as the file provides from `offset`; returns the
/// number of bytes read (short only at end of file).
fn pread_full(file: &File, mut offset: u64, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match read_at(file, &mut buf[filled..], offset) {
            Ok(0) => break,
            Ok(n) => {
                filled += n;
                offset += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Read `len` bytes at `offset` into a new buffer, truncated at end of file.
pub(crate) fn read_range(file: &File, offset: u64, len: usize) -> io::Result<Bytes> {
    // `vec![0; n]` is calloc: large buffers come straight from zeroed pages
    // without a separate memset pass.
    let mut buf = vec![0u8; len];
    let n = pread_full(file, offset, &mut buf)?;
    buf.truncate(n);
    Ok(Bytes::from(buf))
}

/// A read handle. All reads are positional (`pread`), so any number of
/// `read_at` calls may run concurrently on the shared file descriptor, each
/// in its own blocking task.
#[derive(Debug)]
pub(crate) struct LocalReadHandle {
    pub file: Arc<File>,
    pub info: FileInfo,
    pub hints: IoHints,
}

#[async_trait::async_trait]
impl ReadHandle for LocalReadHandle {
    fn info(&self) -> &FileInfo {
        &self.info
    }

    fn io_hints(&self) -> IoHints {
        self.hints
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        let size = self.info.size;
        if len == 0 || offset >= size {
            return Ok(Bytes::new());
        }
        let n = (len as u64).min(size - offset) as usize;
        let file = self.file.clone();
        let name = self.info.name.clone();
        blocking(move || read_range(&file, offset, n).map_err(|e| io_err(e, &name))).await
    }

    /// Coalesce nearby ranges (64 KiB gap by default), then pack the merged
    /// reads into batches of about `request_size` bytes: each batch is one
    /// blocking task doing sequential `pread`s, and batches run concurrently.
    /// Many tiny ranges thus cost a few thread hops instead of one each, and
    /// large ranges still read in parallel.
    async fn read_ranges(&self, ranges: &[Range<u64>]) -> Result<Vec<Bytes>> {
        let size = self.info.size;
        let clamped: Vec<Range<u64>> = ranges
            .iter()
            .map(|r| {
                let s = r.start.min(size);
                s..r.end.min(size).max(s)
            })
            .collect();
        let groups = coalesce_ranges(
            &clamped,
            self.hints.coalesce_gap,
            self.hints.max_coalesced.max(1),
        );
        let mut batches: Vec<Vec<CoalescedRange>> = Vec::new();
        let mut batch_bytes = u64::MAX;
        for g in groups {
            let len = g.range.end - g.range.start;
            if batch_bytes >= self.hints.request_size as u64 {
                batches.push(Vec::new());
                batch_bytes = 0;
            }
            batch_bytes += len;
            batches.last_mut().expect("pushed above").push(g);
        }

        let fetched: Vec<Result<Vec<(CoalescedRange, Bytes)>>> =
            stream::iter(batches.into_iter().map(|batch| {
                let file = self.file.clone();
                let name = self.info.name.clone();
                blocking(move || {
                    batch
                        .into_iter()
                        .map(|g| {
                            let len = (g.range.end - g.range.start) as usize;
                            let data = if len == 0 {
                                Bytes::new()
                            } else {
                                read_range(&file, g.range.start, len).map_err(|e| io_err(e, &name))?
                            };
                            Ok((g, data))
                        })
                        .collect()
                })
            }))
            .buffer_unordered(self.hints.max_concurrency.max(1))
            .collect()
            .await;

        let mut out = vec![Bytes::new(); ranges.len()];
        for batch in fetched {
            for (g, data) in batch? {
                for i in g.members {
                    let r = &clamped[i];
                    if r.end <= r.start {
                        continue;
                    }
                    let s = (r.start - g.range.start) as usize;
                    let e = ((r.end - g.range.start) as usize).min(data.len());
                    if s < e {
                        out[i] = data.slice(s..e);
                    }
                }
            }
        }
        Ok(out)
    }
}

/// Writes smaller than this are gathered in a buffer; larger ones are handed
/// to the blocking writer as is (no copy).
const DIRECT_WRITE: usize = 256 << 10;
/// Buffered bytes that trigger a write to disk.
const WRITE_BUFFER: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Open,
    Closed,
    Aborted,
}

/// A write handle. Small writes are gathered into a 1 MiB buffer; disk
/// writes run in blocking tasks with one write in flight while the caller
/// produces the next chunk (double buffering), preserving order.
#[derive(Debug)]
pub(crate) struct LocalWriteHandle {
    pub path: String,
    pub os_path: PathBuf,
    pub file: Option<Arc<File>>,
    pub mode: WriteMode,
    /// File length at open (append mode), restored by `abort`.
    pub original_len: u64,
    buf: Vec<u8>,
    in_flight: Option<JoinHandle<io::Result<()>>>,
    written: u64,
    state: State,
}

impl LocalWriteHandle {
    pub fn new(path: String, os_path: PathBuf, file: File, mode: WriteMode, original_len: u64) -> Self {
        LocalWriteHandle {
            path,
            os_path,
            file: Some(Arc::new(file)),
            mode,
            original_len,
            buf: Vec::new(),
            in_flight: None,
            written: 0,
            state: State::Open,
        }
    }

    fn not_open(&self) -> Error {
        Error::invalid_input(match self.state {
            State::Aborted => "write handle was aborted",
            _ => "I/O operation on closed file",
        })
        .with_path(self.path.clone())
    }

    /// Wait for the write in flight, if any.
    async fn wait(&mut self) -> Result<()> {
        if let Some(h) = self.in_flight.take() {
            match h.await {
                Ok(r) => r.map_err(|e| io_err(e, &self.path))?,
                Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
                Err(e) => {
                    return Err(Error::new(ErrorKind::Cancelled, format!("write task cancelled: {e}"))
                        .with_path(self.path.clone()));
                }
            }
        }
        Ok(())
    }

    /// Start writing `head` then `tail` after the previous write completes.
    async fn dispatch(&mut self, head: Vec<u8>, tail: Option<Bytes>) -> Result<()> {
        self.wait().await?;
        if head.is_empty() && tail.as_ref().is_none_or(|t| t.is_empty()) {
            return Ok(());
        }
        let file = self.file.clone().expect("open handle has a file");
        self.in_flight = Some(tokio::task::spawn_blocking(move || {
            let mut f: &File = &file;
            if !head.is_empty() {
                f.write_all(&head)?;
            }
            if let Some(t) = tail {
                f.write_all(&t)?;
            }
            Ok(())
        }));
        Ok(())
    }

    async fn drain(&mut self) -> Result<()> {
        let head = std::mem::take(&mut self.buf);
        self.dispatch(head, None).await?;
        self.wait().await
    }

    /// Close the descriptor off the runtime thread (close(2) can block on
    /// network filesystems).
    async fn release_file(&mut self) {
        if let Some(f) = self.file.take() {
            let _ = tokio::task::spawn_blocking(move || drop(f)).await;
        }
    }
}

#[async_trait::async_trait]
impl WriteHandle for LocalWriteHandle {
    async fn write(&mut self, data: Bytes) -> Result<()> {
        if self.state != State::Open {
            return Err(self.not_open());
        }
        self.written += data.len() as u64;
        if data.len() >= DIRECT_WRITE {
            let head = std::mem::take(&mut self.buf);
            return self.dispatch(head, Some(data)).await;
        }
        self.buf.extend_from_slice(&data);
        if self.buf.len() >= WRITE_BUFFER {
            let head = std::mem::replace(&mut self.buf, Vec::with_capacity(WRITE_BUFFER));
            self.dispatch(head, None).await?;
        }
        Ok(())
    }

    async fn flush(&mut self) -> Result<()> {
        if self.state != State::Open {
            return Err(self.not_open());
        }
        self.drain().await
    }

    async fn close(&mut self) -> Result<()> {
        match self.state {
            State::Closed => Ok(()),
            State::Aborted => Err(self.not_open()),
            State::Open => {
                let r = self.drain().await;
                if r.is_ok() {
                    self.state = State::Closed;
                    self.release_file().await;
                }
                r
            }
        }
    }

    /// Discard the write: wait for pending I/O, then delete the file this
    /// handle created or truncated (modes `wb`/`xb`), or cut an appended file
    /// back to its length at open (mode `ab`).
    async fn abort(&mut self) -> Result<()> {
        if self.state != State::Open {
            return Ok(());
        }
        self.state = State::Aborted;
        self.buf = Vec::new();
        let _ = self.wait().await;
        self.release_file().await;
        let (os_path, path, mode, len) = (
            self.os_path.clone(),
            self.path.clone(),
            self.mode,
            self.original_len,
        );
        blocking(move || {
            let r = match mode {
                WriteMode::Overwrite | WriteMode::CreateNew => std::fs::remove_file(&os_path),
                WriteMode::Append => OpenOptions::new()
                    .write(true)
                    .open(&os_path)
                    .and_then(|f| f.set_len(len)),
            };
            match r {
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                r => r.map_err(|e| io_err(e, &path)),
            }
        })
        .await
    }

    fn bytes_written(&self) -> u64 {
        self.written
    }
}

impl Drop for LocalWriteHandle {
    /// Dropped without `close`: finish the pending writes in the background
    /// (like a buffered file flushing on destruction) without blocking the
    /// runtime thread.
    fn drop(&mut self) {
        if self.state != State::Open {
            return;
        }
        let Some(file) = self.file.take() else { return };
        let in_flight = self.in_flight.take();
        let buf = std::mem::take(&mut self.buf);
        let path = self.path.clone();
        let finish = move || {
            if !buf.is_empty()
                && let Err(e) = (&*file).write_all(&buf)
            {
                tracing::warn!(%path, "write handle dropped without close; final write failed: {e}");
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                rt.spawn(async move {
                    if let Some(h) = in_flight {
                        let _ = h.await;
                    }
                    let _ = tokio::task::spawn_blocking(finish).await;
                });
            }
            Err(_) => finish(),
        }
    }
}
