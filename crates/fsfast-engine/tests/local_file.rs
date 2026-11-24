//! End-to-end tests of the public API over real local files: a pread-backed
//! `ReadHandle` (blocking I/O on `spawn_blocking`) under `FileReader` /
//! `read_parallel`, and a `PartSink` that stages parts as files the way an
//! object store stages multipart parts.
#![cfg(unix)]

use std::io::SeekFrom;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use fsfast_core::{Error, ErrorKind, FileInfo, IoHints, ReadHandle, Result};
use fsfast_engine::testing::pattern;
use fsfast_engine::{
    BlockCacheConfig, CacheMode, FileReader, MemoryBudget, PartOutcome, PartSink, PartUploader,
    ReaderConfig, UploadConfig, UploadResult, read_parallel,
};

/// A unique scratch directory removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "fsfast-engine-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug)]
struct PreadHandle {
    file: Arc<std::fs::File>,
    info: FileInfo,
}

impl PreadHandle {
    fn open(path: &Path) -> Arc<dyn ReadHandle> {
        let file = std::fs::File::open(path).unwrap();
        let size = file.metadata().unwrap().len();
        Arc::new(PreadHandle {
            file: Arc::new(file),
            info: FileInfo::file(path.to_string_lossy(), size),
        })
    }
}

#[async_trait]
impl ReadHandle for PreadHandle {
    fn info(&self) -> &FileInfo {
        &self.info
    }

    fn io_hints(&self) -> IoHints {
        IoHints {
            request_size: 128 << 10,
            max_concurrency: 8,
            ..IoHints::default()
        }
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        let file = self.file.clone();
        let len = len.min(self.info.size.saturating_sub(offset) as usize);
        tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; len];
            let mut filled = 0;
            while filled < len {
                let n = file.read_at(&mut buf[filled..], offset + filled as u64)?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            buf.truncate(filled);
            Ok(Bytes::from(buf))
        })
        .await
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
    }
}

/// Stages each part as `part-<n>` in a directory.
struct DirSink {
    dir: PathBuf,
}

#[async_trait]
impl PartSink for DirSink {
    type Outcome = PartOutcome;

    async fn upload_part(&self, part_number: u32, data: Bytes) -> Result<PartOutcome> {
        let path = self.dir.join(format!("part-{part_number}"));
        let len = data.len();
        tokio::fs::write(&path, data).await?;
        Ok(PartOutcome {
            etag: format!("{part_number}:{len}"),
            checksum: None,
        })
    }
}

fn modes() -> Vec<CacheMode> {
    vec![
        CacheMode::None,
        CacheMode::Readahead,
        CacheMode::Whole,
        CacheMode::Blocks(BlockCacheConfig {
            block_size: Some(64 << 10),
            max_blocks: 8,
            prefetch: true,
        }),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_reader_over_real_file() {
    let dir = Scratch::new("reader");
    let path = dir.0.join("data.bin");
    let data = pattern(3 << 20);
    std::fs::write(&path, &data).unwrap();
    let budget = MemoryBudget::new(4 << 20);
    for mode in modes() {
        let mut r = FileReader::new(
            PreadHandle::open(&path),
            ReaderConfig {
                cache: mode,
                budget: Some(budget.clone()),
                ..ReaderConfig::default()
            },
        );
        // Sequential scan with readinto-sized reads.
        let mut out = Vec::new();
        let mut buf = vec![0u8; 50_000];
        loop {
            let n = r.read_into(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        assert_eq!(out.len(), data.len(), "{mode:?}");
        assert!(out == data, "{mode:?}");
        // Parquet-like access: footer, then column chunks.
        r.seek(SeekFrom::End(-8)).unwrap();
        assert_eq!(r.read(Some(8)).await.unwrap(), data.slice(data.len() - 8..));
        for start in [100_000usize, 1_500_000, 700_000, 2_900_000] {
            r.seek(SeekFrom::Start(start as u64)).unwrap();
            let b = r.read(Some(300_000)).await.unwrap();
            let end = (start + 300_000).min(data.len());
            assert!(b == data.slice(start..end), "{mode:?} at {start}");
        }
        r.close().await.unwrap();
    }
    assert_eq!(budget.available(), 4 << 20);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_parallel_over_real_file() {
    let dir = Scratch::new("parallel");
    let path = dir.0.join("data.bin");
    let data = pattern(5 << 20);
    std::fs::write(&path, &data).unwrap();
    let h = PreadHandle::open(&path);
    let out = read_parallel(&h, 12_345..(5 << 20) - 777, 256 << 10, 8, None)
        .await
        .unwrap();
    assert!(out == data.slice(12_345..(5 << 20) - 777));
}

async fn upload(dir: &Path, data: &Bytes, write_size: usize, budget: &MemoryBudget) -> Vec<u8> {
    let sink = Arc::new(DirSink {
        dir: dir.to_path_buf(),
    });
    let mut up = PartUploader::new(
        sink,
        UploadConfig {
            part_size: 256 << 10,
            min_part_size: 1,
            concurrency: 4,
            budget: Some(budget.clone()),
            ..UploadConfig::default()
        },
    )
    .unwrap();
    for chunk in data.chunks(write_size) {
        up.write(data.slice_ref(chunk)).await.unwrap();
    }
    assert_eq!(up.bytes_written(), data.len() as u64);
    match up.finish().await.unwrap() {
        UploadResult::Single(b) => b.to_vec(),
        UploadResult::Multipart(parts) => {
            // "CompleteMultipartUpload": concatenate staged parts in order.
            let mut out = Vec::new();
            for p in parts {
                assert_eq!(p.offset, out.len() as u64);
                assert_eq!(p.outcome.etag, format!("{}:{}", p.part_number, p.size));
                let staged = tokio::fs::read(dir.join(format!("part-{}", p.part_number)))
                    .await
                    .unwrap();
                assert_eq!(staged.len() as u64, p.size);
                out.extend_from_slice(&staged);
            }
            out
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn part_uploader_into_staged_files() {
    let budget = MemoryBudget::new(1 << 20);
    for (total, write_size) in [
        (0usize, 1usize),
        (1000, 7),
        (256 << 10, 4096),
        (3_000_000, 65_537),
        (3_000_000, 3_000_000),
    ] {
        let dir = Scratch::new("upload");
        let data = pattern(total);
        let out = upload(&dir.0, &data, write_size.max(1), &budget).await;
        assert!(out == data, "total {total} write {write_size}");
    }
    assert_eq!(budget.available(), 1 << 20);
}
