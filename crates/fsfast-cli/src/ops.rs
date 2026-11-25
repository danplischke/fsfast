//! Filesystem operations shared by the commands and the benchmarks: copies
//! between any two locations, recursive delete, stats snapshots.

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use fsfast_core::{
    Error, ErrorKind, FileSystem, FindOptions, ReadOptions, Result, WriteOptions, path as fspath,
    split_range,
};
use fsfast_engine::{OpKind, StatsSnapshot};
use futures::{StreamExt, TryStreamExt, stream};

use crate::target::Resolved;

/// How bytes move for one file copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyMethod {
    /// Same filesystem instance: `cp_file` (server-side where supported).
    SameFs,
    /// Local file to a remote filesystem: `put_file`.
    Upload,
    /// Remote file to a local file: `get_file`.
    Download,
    /// Between two different filesystems: ranged reads streamed into a
    /// write handle.
    Stream,
}

/// The method `cp` uses between `src` and `dst`.
pub fn copy_method(src: &Resolved, dst: &Resolved) -> CopyMethod {
    if src.same_fs(dst) {
        CopyMethod::SameFs
    } else if src.is_local() {
        CopyMethod::Upload
    } else if dst.is_local() {
        CopyMethod::Download
    } else {
        CopyMethod::Stream
    }
}

/// Copy one file `src_path` (on `src`'s filesystem) to `dst_path` (on
/// `dst`'s) with `method`. Returns the bytes copied, as reported by the
/// source size at open time (or the source `info` for same-fs copies).
pub async fn copy_file(
    method: CopyMethod,
    src: &Arc<dyn FileSystem>,
    src_path: &str,
    dst: &Arc<dyn FileSystem>,
    dst_path: &str,
    size: u64,
) -> Result<u64> {
    match method {
        CopyMethod::SameFs => src.cp_file(src_path, dst_path).await.map(|()| size),
        CopyMethod::Upload => dst
            .put_file(&PathBuf::from(src_path), dst_path, &WriteOptions::default())
            .await
            .map(|()| size),
        CopyMethod::Download => src
            .get_file(src_path, &PathBuf::from(dst_path))
            .await
            .map(|()| size),
        CopyMethod::Stream => stream_copy(src.as_ref(), src_path, dst.as_ref(), dst_path).await,
    }
}

/// Copy between two filesystems: read `request_size` chunks with up to
/// `max_concurrency` reads in flight (in order) and hand each chunk to the
/// destination writer as-is (no re-buffering; the writer's part uploader
/// does its own batching).
pub async fn stream_copy(
    src: &dyn FileSystem,
    src_path: &str,
    dst: &dyn FileSystem,
    dst_path: &str,
) -> Result<u64> {
    let h = src.open_read(src_path, &ReadOptions::default()).await?;
    if h.info().is_dir() {
        let _ = h.close().await;
        return Err(Error::is_a_directory(src_path));
    }
    let hints = h.io_hints();
    let size = h.size();
    let mut w = match dst.open_write(dst_path, &WriteOptions::default()).await {
        Ok(w) => w,
        Err(e) => {
            let _ = h.close().await;
            return Err(e);
        }
    };
    let res = async {
        let chunks = split_range(0..size, hints.request_size.max(1) as u64);
        let mut s = stream::iter(chunks.into_iter().map(|r| {
            let h = &h;
            async move { h.read_at(r.start, (r.end - r.start) as usize).await }
        }))
        .buffered(hints.max_concurrency.max(1));
        while let Some(chunk) = s.next().await {
            w.write(chunk?).await?;
        }
        w.close().await
    }
    .await;
    let closed = h.close().await;
    if let Err(e) = res {
        let _ = w.abort().await;
        return Err(e);
    }
    closed?;
    Ok(size)
}

/// Read a whole file streaming, calling `sink` with each chunk in order
/// (bounded memory: at most `max_concurrency` chunks in flight).
pub async fn read_streaming<F>(
    fs: &dyn FileSystem,
    path: &str,
    range: std::ops::Range<u64>,
    request_size: Option<usize>,
    concurrency: Option<usize>,
    mut sink: F,
) -> Result<u64>
where
    F: FnMut(Bytes) -> Result<()>,
{
    let h = fs.open_read(path, &ReadOptions::default()).await?;
    if h.info().is_dir() {
        let _ = h.close().await;
        return Err(Error::is_a_directory(path));
    }
    let hints = h.io_hints();
    let size = h.size();
    let range = range.start.min(size)..range.end.min(size);
    let chunk = request_size.unwrap_or(hints.request_size).max(1) as u64;
    let conc = concurrency.unwrap_or(hints.max_concurrency).max(1);
    let res = async {
        let mut total = 0u64;
        let mut s = stream::iter(split_range(range, chunk).into_iter().map(|r| {
            let h = &h;
            async move { h.read_at(r.start, (r.end - r.start) as usize).await }
        }))
        .buffered(conc);
        while let Some(c) = s.next().await {
            let c = c?;
            total += c.len() as u64;
            sink(c)?;
        }
        Ok::<_, Error>(total)
    }
    .await;
    let closed = h.close().await;
    let total = res?;
    closed?;
    Ok(total)
}

/// `mkdir -p`: succeed when `path` already is a directory, otherwise
/// `mkdir(path, create_parents=true)`. Unlike [`FileSystem::makedirs`] this
/// also creates a bucket on object stores whose `makedirs` is a no-op
/// (gcsfs semantics).
pub async fn mkdir_p(fs: &dyn FileSystem, path: &str) -> Result<()> {
    match fs.info(path).await {
        Ok(i) if i.is_dir() => Ok(()),
        Ok(_) => Err(Error::already_exists(path)),
        Err(e) if e.kind() == ErrorKind::NotFound => match fs.mkdir(path, true).await {
            Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(()),
            other => other,
        },
        Err(e) => Err(e),
    }
}

/// Result of a recursive delete.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Removed {
    /// Files deleted.
    pub files: usize,
    /// Directories (or buckets) removed.
    pub dirs: usize,
}

/// Delete `path` (a file, or with `recursive` a whole tree) like fsspec's
/// `rm`: files are deleted in one `rm_files` batch (backends use their
/// batch APIs), then directories deepest first on hierarchical backends.
/// On object stores a bucket/container path is removed as well, as s3fs
/// does. A missing path is `NotFound`.
pub async fn remove(fs: &dyn FileSystem, path: &str, recursive: bool) -> Result<Removed> {
    let info = fs.info(path).await?;
    if !info.is_dir() {
        fs.rm_file(path).await?;
        return Ok(Removed { files: 1, dirs: 0 });
    }
    if !recursive {
        return Err(Error::is_a_directory(path).with_path(path));
    }
    let entries = fs
        .find(
            path,
            &FindOptions {
                maxdepth: None,
                withdirs: true,
            },
        )
        .await?;
    let root = fspath::normalize(path);
    let (mut dirs, files): (Vec<_>, Vec<_>) = entries
        .into_iter()
        .filter(|e| fspath::normalize(&e.name) != root)
        .partition(|e| e.is_dir());
    let files: Vec<String> = files.into_iter().map(|e| e.name).collect();
    let mut out = Removed::default();
    for (r, p) in fs.rm_files(&files).await.into_iter().zip(&files) {
        match r {
            Ok(()) => out.files += 1,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e.with_path(p.clone())),
        }
    }
    let caps = fs.capabilities();
    if caps.hierarchical {
        dirs.sort_by_key(|d| std::cmp::Reverse(fspath::depth_below(&root, &d.name)));
        for d in dirs {
            match fs.rmdir(&d.name).await {
                Ok(()) => out.dirs += 1,
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        match fs.rmdir(path).await {
            Ok(()) => out.dirs += 1,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    } else if !root.trim_start_matches('/').contains('/') && !root.is_empty() {
        // Object store bucket/container (s3fs `_rm` removes it too).
        match fs.rmdir(path).await {
            Ok(()) => out.dirs += 1,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    fs.invalidate_cache(Some(path));
    Ok(out)
}

/// Delete everything under `path` best-effort (benchmark cleanup): never
/// fails on a missing path.
pub async fn remove_tree_quiet(fs: &dyn FileSystem, path: &str) -> Result<Removed> {
    match remove(fs, path, true).await {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(Removed::default()),
        other => other,
    }
}

/// Run `f(i)` for `i in 0..n` with at most `concurrency` in flight, failing
/// fast on the first error.
pub async fn for_each_concurrent<F, Fut>(n: usize, concurrency: usize, f: F) -> Result<()>
where
    F: Fn(usize) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    stream::iter((0..n).map(&f))
        .buffer_unordered(concurrency.max(1))
        .try_collect::<Vec<()>>()
        .await
        .map(|_| ())
}

/// Engine counters of one filesystem over a measured interval.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    /// Wire requests (each retry attempt counts).
    pub requests: u64,
    /// Failed requests.
    pub errors: u64,
    /// Retry attempts.
    pub retries: u64,
    /// Throttling responses.
    pub throttles: u64,
    /// Payload bytes received.
    pub bytes_read: u64,
    /// Payload bytes sent.
    pub bytes_written: u64,
    /// Requests per [`OpKind`] (in [`OpKind::ALL`] order).
    pub by_op: [u64; OpKind::COUNT],
}

impl Counters {
    /// Counters of a snapshot.
    pub fn of(s: &StatsSnapshot) -> Self {
        let mut by_op = [0; OpKind::COUNT];
        for (slot, op) in by_op.iter_mut().zip(OpKind::ALL) {
            *slot = s.requests_for(op);
        }
        Counters {
            requests: s.requests,
            errors: s.errors,
            retries: s.retries,
            throttles: s.throttles,
            bytes_read: s.bytes_read,
            bytes_written: s.bytes_written,
            by_op,
        }
    }

    /// `self - before`, saturating.
    pub fn since(&self, before: &Counters) -> Counters {
        let mut by_op = [0; OpKind::COUNT];
        for (i, slot) in by_op.iter_mut().enumerate() {
            *slot = self.by_op[i].saturating_sub(before.by_op[i]);
        }
        Counters {
            requests: self.requests.saturating_sub(before.requests),
            errors: self.errors.saturating_sub(before.errors),
            retries: self.retries.saturating_sub(before.retries),
            throttles: self.throttles.saturating_sub(before.throttles),
            bytes_read: self.bytes_read.saturating_sub(before.bytes_read),
            bytes_written: self.bytes_written.saturating_sub(before.bytes_written),
            by_op,
        }
    }

    /// Add `other` into `self`.
    pub fn add(&mut self, other: &Counters) {
        self.requests += other.requests;
        self.errors += other.errors;
        self.retries += other.retries;
        self.throttles += other.throttles;
        self.bytes_read += other.bytes_read;
        self.bytes_written += other.bytes_written;
        for (a, b) in self.by_op.iter_mut().zip(other.by_op) {
            *a += b;
        }
    }

    /// As JSON (`requests_by_op` lists only operations with requests).
    pub fn to_json(&self) -> serde_json::Value {
        let by_op: serde_json::Map<String, serde_json::Value> = OpKind::ALL
            .iter()
            .zip(self.by_op)
            .filter(|(_, n)| *n > 0)
            .map(|(op, n)| (op.as_str().to_owned(), n.into()))
            .collect();
        serde_json::json!({
            "requests": self.requests,
            "errors": self.errors,
            "retries": self.retries,
            "throttles": self.throttles,
            "bytes_read": self.bytes_read,
            "bytes_written": self.bytes_written,
            "requests_by_op": by_op,
        })
    }

    /// On one line.
    pub fn line(&self) -> String {
        let by_op: Vec<String> = OpKind::ALL
            .iter()
            .zip(self.by_op)
            .filter(|(_, n)| *n > 0)
            .map(|(op, n)| format!("{op} {n}"))
            .collect();
        let mut s = format!(
            "requests {} (errors {}, retries {}, throttles {}), read {}, written {}",
            self.requests,
            self.errors,
            self.retries,
            self.throttles,
            crate::units::format_bytes(self.bytes_read),
            crate::units::format_bytes(self.bytes_written)
        );
        if !by_op.is_empty() {
            s.push_str(&format!(" [{}]", by_op.join(", ")));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "memory")]
    #[tokio::test]
    async fn recursive_remove_and_stream_copy() {
        use fsfast_memory::MemoryFileSystem;
        let fs = MemoryFileSystem::new_isolated();
        for p in ["/t/a", "/t/d/b", "/t/d/e/c"] {
            fs.pipe_file(p, Bytes::from_static(b"xyz"), &WriteOptions::default())
                .await
                .unwrap();
        }
        let other = MemoryFileSystem::new_isolated();
        let n = stream_copy(&fs, "/t/d/b", &other, "/copy").await.unwrap();
        assert_eq!(n, 3);
        assert_eq!(
            other
                .cat_file("/copy", fsfast_core::ByteRange::Full)
                .await
                .unwrap(),
            Bytes::from_static(b"xyz")
        );
        let mut seen = Vec::new();
        let n = read_streaming(&fs, "/t/a", 1..u64::MAX, Some(1), Some(2), |c| {
            seen.extend_from_slice(&c);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!((n, seen.as_slice()), (2, &b"yz"[..]));

        let e = remove(&fs, "/t", false).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::IsADirectory);
        let r = remove(&fs, "/t", true).await.unwrap();
        assert_eq!(r.files, 3);
        assert!(!fs.exists("/t").await.unwrap());
        assert_eq!(
            remove(&fs, "/t", true).await.unwrap_err().kind(),
            ErrorKind::NotFound
        );
        assert_eq!(
            remove_tree_quiet(&fs, "/t").await.unwrap(),
            Removed::default()
        );
    }

    #[test]
    fn counters_math() {
        let a = Counters {
            requests: 10,
            bytes_read: 100,
            ..Default::default()
        };
        let mut b = a;
        b.requests = 15;
        b.bytes_read = 400;
        b.retries = 2;
        b.by_op[2] = 5;
        let d = b.since(&a);
        assert_eq!((d.requests, d.bytes_read, d.retries), (5, 300, 2));
        let mut acc = Counters::default();
        acc.add(&d);
        acc.add(&d);
        assert_eq!(acc.requests, 10);
        let j = acc.to_json();
        assert_eq!(j["bytes_read"], 600);
        assert_eq!(j["requests_by_op"]["read"], 10);
        assert!(j["requests_by_op"].get("info").is_none());
        assert!(acc.line().contains("[read 10]"), "{}", acc.line());
        let s = fsfast_engine::Stats::new();
        s.record_request(OpKind::Info, std::time::Duration::from_millis(1), true);
        s.add_bytes_read(7);
        let c = Counters::of(&s.snapshot());
        assert_eq!((c.requests, c.bytes_read, c.by_op[0]), (1, 7, 1));
    }
}
