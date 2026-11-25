//! Read and write handles over `std::fs::File`.

use std::fs::File;
use std::io::{self, Write};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use fsfast_core::{
    CoalescedRange, Error, ErrorKind, FileInfo, IoHints, ReadHandle, Result, WriteHandle,
    WriteMode, coalesce_ranges,
};
use futures::{StreamExt, stream};
use tokio::task::JoinHandle;

use crate::stat::io_err;
use crate::{blocking, spawn_blocking};

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

/// Read `len` bytes at `offset` (truncated at end of file) from a shared
/// file, using several blocking tasks for large reads.
///
/// Reads of at most `2 * chunk` bytes are one `pread` loop in one blocking
/// task. Larger reads allocate the result buffer once, split it into
/// disjoint `chunk`-sized `BytesMut` pieces, fill the pieces with concurrent
/// positional reads (up to `concurrency` at a time) and rejoin them with
/// `BytesMut::unsplit`, which is O(1) for adjacent pieces of one allocation:
/// no copy, and NVMe queues / the page cache are used from several cores.
pub(crate) async fn read_parallel(
    file: Arc<File>,
    name: Arc<str>,
    offset: u64,
    len: usize,
    chunk: usize,
    concurrency: usize,
) -> Result<Bytes> {
    if len == 0 {
        return Ok(Bytes::new());
    }
    let chunk = chunk.max(64 << 10);
    if concurrency <= 1 || len <= chunk.saturating_mul(2) {
        return blocking(move || read_range(&file, offset, len).map_err(|e| io_err(e, &name)))
            .await;
    }
    let mut rest = BytesMut::zeroed(len);
    let mut pieces = Vec::with_capacity(len.div_ceil(chunk));
    let mut off = offset;
    while !rest.is_empty() {
        let piece = rest.split_to(chunk.min(rest.len()));
        let piece_len = piece.len() as u64;
        pieces.push((off, piece));
        off += piece_len;
    }
    let filled: Vec<Result<(BytesMut, usize)>> =
        stream::iter(pieces.into_iter().map(|(off, mut piece)| {
            let file = file.clone();
            let name = name.clone();
            // The pool, not inline: the pieces are read in parallel.
            spawn_blocking(move || {
                let n = pread_full(&file, off, &mut piece).map_err(|e| io_err(e, &name))?;
                Ok((piece, n))
            })
        }))
        .buffered(concurrency)
        .collect()
        .await;

    let mut out: Option<BytesMut> = None;
    for r in filled {
        let (mut piece, n) = r?;
        let short = n < piece.len();
        piece.truncate(n);
        match out.as_mut() {
            None => out = Some(piece),
            Some(o) => o.unsplit(piece),
        }
        if short {
            // End of file (the file shrank since its size was taken): the
            // remaining pieces lie beyond it.
            break;
        }
    }
    Ok(out.map(BytesMut::freeze).unwrap_or_default())
}

/// A read handle. All reads are positional (`pread`), so any number of
/// `read_at` calls may run concurrently on the shared file descriptor, each
/// in its own blocking task.
#[derive(Debug)]
pub(crate) struct LocalReadHandle {
    pub file: Arc<File>,
    /// `info.name`, shared cheaply with blocking tasks for error messages.
    pub name: Arc<str>,
    pub info: FileInfo,
    pub hints: IoHints,
}

impl LocalReadHandle {
    pub fn new(file: File, info: FileInfo, hints: IoHints) -> Self {
        LocalReadHandle {
            file: Arc::new(file),
            name: Arc::from(info.name.as_str()),
            info,
            hints,
        }
    }
}

#[async_trait::async_trait]
impl ReadHandle for LocalReadHandle {
    fn info(&self) -> &FileInfo {
        &self.info
    }

    fn io_hints(&self) -> IoHints {
        self.hints
    }

    /// Reads are limited to the size observed at open (the contract's
    /// `min(len, size - offset)`); large reads are split across several
    /// blocking tasks ([`read_parallel`]).
    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        let size = self.info.size;
        if len == 0 || offset >= size {
            return Ok(Bytes::new());
        }
        let n = (len as u64).min(size - offset) as usize;
        read_parallel(
            self.file.clone(),
            self.name.clone(),
            offset,
            n,
            self.hints.request_size,
            self.hints.max_concurrency,
        )
        .await
    }

    /// Coalesce nearby ranges (64 KiB gap by default), then read: merged
    /// ranges above `2 × request_size` with [`read_parallel`], smaller ones
    /// packed into batches of about `request_size` bytes, each batch one
    /// blocking task of sequential `pread`s, batches running concurrently.
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
        // Large merged ranges are read one after another, each split across
        // several blocking tasks by `read_parallel`; small ones are packed
        // into batches of about `request_size` bytes, one blocking task per
        // batch, several batches at once. Both run concurrently.
        let large_threshold = (self.hints.request_size as u64).saturating_mul(2);
        let (large, small): (Vec<CoalescedRange>, Vec<CoalescedRange>) = groups
            .into_iter()
            .partition(|g| g.range.end - g.range.start > large_threshold);
        let mut batches: Vec<Vec<CoalescedRange>> = Vec::new();
        let mut batch_bytes = u64::MAX;
        for g in small {
            let len = g.range.end - g.range.start;
            if batch_bytes >= self.hints.request_size as u64 {
                batches.push(Vec::new());
                batch_bytes = 0;
            }
            batch_bytes += len;
            batches.last_mut().expect("pushed above").push(g);
        }

        let small_reads = stream::iter(batches.into_iter().map(|batch| {
            let file = self.file.clone();
            let name = self.name.clone();
            // The pool, not inline: batches are read in parallel.
            spawn_blocking(move || {
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
                    .collect::<Result<Vec<_>>>()
            })
        }))
        .buffer_unordered(self.hints.max_concurrency.max(1))
        .collect::<Vec<_>>();
        let large_reads = async {
            let mut done = Vec::with_capacity(large.len());
            for g in large {
                let data = read_parallel(
                    self.file.clone(),
                    self.name.clone(),
                    g.range.start,
                    (g.range.end - g.range.start) as usize,
                    self.hints.request_size,
                    self.hints.max_concurrency,
                )
                .await?;
                done.push((g, data));
            }
            Ok::<_, Error>(done)
        };
        let (small_done, large_done) = futures::join!(small_reads, large_reads);
        let mut fetched = large_done?;
        for batch in small_done {
            fetched.extend(batch?);
        }

        let mut out = vec![Bytes::new(); ranges.len()];
        for (g, data) in fetched {
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
        Ok(out)
    }
}

/// Whether `path` (not following symlinks) is still the file open as `file`.
#[cfg(unix)]
fn still_linked_at(file: &File, path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (file.metadata(), std::fs::symlink_metadata(path)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// Windows cannot rename or delete a file that is open without
/// `FILE_SHARE_DELETE` (std's default), so the path cannot have been
/// replaced while the handle was open.
#[cfg(not(unix))]
fn still_linked_at(_file: &File, _path: &std::path::Path) -> bool {
    true
}

/// Writes smaller than this are gathered in a buffer; larger ones are handed
/// to the blocking writer as is (no copy).
pub(crate) const DIRECT_WRITE: usize = 256 << 10;
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
///
/// Cancellation: if a `write`, `flush` or `close` future is dropped before
/// it completes, the data it carried may or may not have reached the file,
/// so the handle is *poisoned*: every later `write`/`flush`/`close` fails
/// and only `abort` (which still cleans up) is accepted. Silently carrying
/// on would produce a file with a hole in it.
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
    /// Set while a `write`/`flush`/`close` runs; still set afterwards only
    /// if that operation was cancelled (see the type docs).
    busy: bool,
    /// The runtime the handle was opened on, which owns the write in flight;
    /// `Drop` finishes pending writes there whatever thread drops the handle.
    runtime: Option<tokio::runtime::Handle>,
}

impl LocalWriteHandle {
    pub fn new(
        path: String,
        os_path: PathBuf,
        file: File,
        mode: WriteMode,
        original_len: u64,
    ) -> Self {
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
            busy: false,
            runtime: tokio::runtime::Handle::try_current().ok(),
        }
    }

    /// Refuse to start an operation on a closed, aborted or poisoned handle,
    /// and mark one as running.
    fn begin(&mut self) -> Result<()> {
        if self.state != State::Open {
            return Err(self.not_open());
        }
        if self.busy {
            return Err(Error::new(
                ErrorKind::Io,
                "an earlier write, flush or close on this handle was cancelled; \
                 the file content is undefined (abort the handle)",
            )
            .with_path(self.path.clone()));
        }
        self.busy = true;
        Ok(())
    }

    fn not_open(&self) -> Error {
        Error::invalid_input(match self.state {
            State::Aborted => "write handle was aborted",
            _ => "I/O operation on closed file",
        })
        .with_path(self.path.clone())
    }

    /// Wait for the write in flight, if any. Cancel safe: the join handle is
    /// only released once the write has finished, so a later `wait` (e.g. by
    /// `abort`) still waits for it.
    async fn wait(&mut self) -> Result<()> {
        if let Some(h) = self.in_flight.as_mut() {
            let joined = h.await;
            self.in_flight = None;
            match joined {
                Ok(r) => r.map_err(|e| io_err(e, &self.path))?,
                Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
                Err(e) => {
                    return Err(Error::new(
                        ErrorKind::Cancelled,
                        format!("write task cancelled: {e}"),
                    )
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

    async fn write_inner(&mut self, data: Bytes) -> Result<()> {
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
}

#[async_trait::async_trait]
impl WriteHandle for LocalWriteHandle {
    async fn write(&mut self, data: Bytes) -> Result<()> {
        self.begin()?;
        let r = self.write_inner(data).await;
        self.busy = false;
        r
    }

    async fn flush(&mut self) -> Result<()> {
        self.begin()?;
        let r = self.drain().await;
        self.busy = false;
        r
    }

    async fn close(&mut self) -> Result<()> {
        if self.state == State::Closed {
            return Ok(());
        }
        self.begin()?;
        let r = self.drain().await;
        if r.is_ok() {
            self.state = State::Closed;
            self.release_file().await;
        }
        self.busy = false;
        r
    }

    /// Discard the write: wait for pending I/O, then delete the file this
    /// handle created or truncated (modes `wb`/`xb`), or cut an appended file
    /// back to its length at open (mode `ab`, through the handle's own
    /// descriptor). If the path no longer refers to the handle's file (it was
    /// replaced or renamed meanwhile), the new file is left alone.
    async fn abort(&mut self) -> Result<()> {
        if self.state != State::Open {
            return Ok(());
        }
        self.state = State::Aborted;
        self.buf = Vec::new();
        let _ = self.wait().await;
        let file = self.file.take();
        let (os_path, path, mode, len) = (
            self.os_path.clone(),
            self.path.clone(),
            self.mode,
            self.original_len,
        );
        blocking(move || {
            let r = match (&file, mode) {
                (Some(f), WriteMode::Append) => f.set_len(len),
                (None, WriteMode::Append) => Ok(()),
                (Some(f), _) if !still_linked_at(f, &os_path) => Ok(()),
                (_, WriteMode::Overwrite | WriteMode::CreateNew) => std::fs::remove_file(&os_path),
            };
            // close(2) inside the blocking task as well.
            drop(file);
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
    /// (like a buffered file flushing on destruction), strictly after the
    /// write in flight, without blocking the dropping thread. That thread
    /// may be outside any runtime (a Python thread collecting an unclosed
    /// file), so the work goes to the runtime the handle was opened on.
    fn drop(&mut self) {
        if self.state != State::Open || self.busy {
            // Closed, aborted, or poisoned by a cancelled operation (the
            // content is undefined already; do not write past a hole).
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
            // close(2) happens here too, off the runtime threads.
        };
        let runtime = self
            .runtime
            .take()
            .or_else(|| tokio::runtime::Handle::try_current().ok());
        match runtime {
            Some(rt) => {
                rt.spawn(async move {
                    if let Some(h) = in_flight {
                        let _ = h.await;
                    }
                    let _ = tokio::task::spawn_blocking(finish).await;
                });
            }
            // No runtime known (not reachable through `open_write`): wait for
            // the write in flight on a helper thread, then write the tail.
            None => {
                std::thread::spawn(move || {
                    if let Some(h) = in_flight {
                        let _ = futures::executor::block_on(h);
                    }
                    finish();
                });
            }
        }
    }
}
