//! Write-path checks: streaming writes, write modes, abort, put/get.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use bytes::Bytes;
use fsfast_core::{ByteRange, ErrorKind, WriteHandle, WriteMode, WriteOptions};

use crate::ctx::{CheckError, CheckResult, Context, Ctx, expect_err, verify_pattern};
use crate::pattern::{self, XorShift};

fn opts(mode: WriteMode) -> WriteOptions {
    WriteOptions::default().with_mode(mode)
}

/// Write `chunks` through `w` and close it; abort on failure.
async fn write_all_close(
    w: &mut Box<dyn WriteHandle>,
    chunks: &[Bytes],
) -> fsfast_core::Result<()> {
    let res = async {
        for c in chunks {
            w.write(c.clone()).await?;
        }
        w.close().await
    }
    .await;
    if res.is_err() {
        let _ = w.abort().await;
    }
    res
}

pub(crate) async fn open_write_stream(ctx: &Ctx) -> CheckResult {
    let req = ctx.hints.request_size.max(1) as u64;
    let target = (2 * req + 12_345)
        .max(1 << 20)
        .min(ctx.cfg.max_stream_bytes.max(1 << 20));
    let p = ctx.path("stream.bin");
    let seed = pattern::seed_for(&p);

    // Odd-sized writes: many tiny ones, some medium, a few large (up to half
    // a request), plus one zero-length write. Sizes never align with the
    // backend's part/request size.
    let mut rng = XorShift::new(seed);
    let mut sizes = Vec::new();
    let mut total = 0u64;
    while total < target {
        let n = match rng.range(0, 9) {
            0..=4 => rng.range(1, 17),
            5..=7 => rng.range(1000, 70_000),
            _ => rng.range(1, (req / 2).max(2)),
        } | 1;
        sizes.push(n as usize);
        total += n;
        if sizes.len() == 3 {
            sizes.push(0);
        }
    }
    let data = pattern::generate_bytes(seed, 0, total as usize);
    let mut chunks = Vec::with_capacity(sizes.len());
    let mut off = 0usize;
    for n in &sizes {
        chunks.push(data.slice(off..off + n));
        off += n;
    }

    let mut w = ctx
        .fs
        .open_write(&p, &WriteOptions::default())
        .await
        .ctx(format_args!("open_write({p:?})"))?;
    let mut written = 0u64;
    for (i, c) in chunks.iter().enumerate() {
        if let Err(e) = w.write(c.clone()).await {
            let _ = w.abort().await;
            fail!(
                "write #{i} ({} bytes) to {p:?} failed: {e} [kind: {:?}]",
                c.len(),
                e.kind()
            );
        }
        written += c.len() as u64;
        ensure_eq!(
            w.bytes_written(),
            written,
            "bytes_written() after write #{i}"
        );
    }
    if let Err(e) = w.close().await {
        let _ = w.abort().await;
        fail!(
            "close() of {p:?} after {} writes failed: {e} [kind: {:?}]",
            chunks.len(),
            e.kind()
        );
    }
    w.close().await.ctx("second close() (must be idempotent)")?;

    ctx.expect_file(&p, total).await?;
    let got = ctx
        .fs
        .cat_file(&p, ByteRange::Full)
        .await
        .ctx(format_args!("cat_file({p:?})"))?;
    verify_pattern(
        &format!("cat_file({p:?}) after {} odd-sized writes", chunks.len()),
        seed,
        0,
        total as usize,
        &got,
    )?;

    // open_write in the default mode replaces an existing file.
    let small = ctx.path("replace.txt");
    ctx.put(&small, Bytes::from_static(b"old content that is longer"))
        .await?;
    let mut w = ctx
        .fs
        .open_write(&small, &WriteOptions::default())
        .await
        .ctx(format_args!("open_write({small:?}) over an existing file"))?;
    write_all_close(&mut w, &[Bytes::from_static(b"new")])
        .await
        .ctx(format_args!("writing {small:?}"))?;
    ctx.expect_content(&small, b"new").await
}

pub(crate) async fn open_write_create_new(ctx: &Ctx) -> CheckResult {
    if !ctx.caps.conditional_create {
        skip!("backend has no atomic create-if-absent (capabilities.conditional_create = false)");
    }
    let p = ctx.path("exclusive");
    ctx.put(&p, Bytes::from_static(b"original")).await?;

    // The conflict may be reported by open_write or, for object stores that
    // check the precondition on upload, by close.
    match ctx.fs.open_write(&p, &opts(WriteMode::CreateNew)).await {
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => fail!(
            "open_write({p:?}, CreateNew) of an existing file: expected AlreadyExists, got {:?}: {e}",
            e.kind()
        ),
        Ok(mut w) => match write_all_close(&mut w, &[Bytes::from_static(b"clobbered")]).await {
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
            Err(e) => fail!(
                "CreateNew write over an existing file: expected AlreadyExists, got {:?}: {e}",
                e.kind()
            ),
            Ok(()) => fail!("open_write({p:?}, CreateNew) over an existing file succeeded"),
        },
    }
    ctx.expect_content(&p, b"original").await?;

    expect_err(
        format!("pipe_file({p:?}, CreateNew) of an existing file"),
        ctx.fs
            .pipe_file(
                &p,
                Bytes::from_static(b"clobbered"),
                &opts(WriteMode::CreateNew),
            )
            .await,
        &[ErrorKind::AlreadyExists],
    )?;
    ctx.expect_content(&p, b"original").await?;

    let fresh = ctx.path("fresh");
    let mut w = ctx
        .fs
        .open_write(&fresh, &opts(WriteMode::CreateNew))
        .await
        .ctx(format_args!(
            "open_write({fresh:?}, CreateNew) of a new file"
        ))?;
    write_all_close(
        &mut w,
        &[Bytes::from_static(b"new "), Bytes::from_static(b"file")],
    )
    .await
    .ctx(format_args!("writing {fresh:?}"))?;
    ctx.expect_content(&fresh, b"new file").await?;

    let fresh2 = ctx.path("fresh2");
    ctx.fs
        .pipe_file(
            &fresh2,
            Bytes::from_static(b"piped"),
            &opts(WriteMode::CreateNew),
        )
        .await
        .ctx(format_args!(
            "pipe_file({fresh2:?}, CreateNew) of a new file"
        ))?;
    ctx.expect_content(&fresh2, b"piped").await?;

    if ctx.caps.hierarchical {
        let dir = ctx.path("a_dir");
        ctx.ensure_dir(&dir).await?;
        expect_err(
            format!("open_write({dir:?}, CreateNew) of a directory"),
            ctx.fs.open_write(&dir, &opts(WriteMode::CreateNew)).await,
            &[ErrorKind::AlreadyExists, ErrorKind::IsADirectory],
        )?;
    }
    Ok(())
}

pub(crate) async fn open_write_append(ctx: &Ctx) -> CheckResult {
    if !ctx.caps.append {
        skip!("backend does not support append (capabilities.append = false)");
    }
    let p = ctx.path("appended");
    ctx.put(&p, Bytes::from_static(b"hello")).await?;
    let mut w = ctx
        .fs
        .open_write(&p, &opts(WriteMode::Append))
        .await
        .ctx(format_args!("open_write({p:?}, Append)"))?;
    write_all_close(
        &mut w,
        &[Bytes::from_static(b" wor"), Bytes::from_static(b"ld")],
    )
    .await
    .ctx(format_args!("appending to {p:?}"))?;
    ensure_eq!(w.bytes_written(), 6, "bytes_written() after appending");
    ctx.expect_content(&p, b"hello world").await?;

    // A second, larger append.
    let tail = ctx.pattern(&p, 100_001);
    let mut w = ctx
        .fs
        .open_write(&p, &opts(WriteMode::Append))
        .await
        .ctx(format_args!("open_write({p:?}, Append) again"))?;
    write_all_close(&mut w, std::slice::from_ref(&tail))
        .await
        .ctx(format_args!("appending to {p:?} again"))?;
    let mut expected = b"hello world".to_vec();
    expected.extend_from_slice(&tail);
    ctx.expect_content(&p, &expected).await?;

    // Append creates a missing file.
    let fresh = ctx.path("fresh");
    let mut w = ctx
        .fs
        .open_write(&fresh, &opts(WriteMode::Append))
        .await
        .ctx(format_args!(
            "open_write({fresh:?}, Append) of a missing file"
        ))?;
    write_all_close(&mut w, &[Bytes::from_static(b"abc")])
        .await
        .ctx(format_args!("appending to new file {fresh:?}"))?;
    ctx.expect_content(&fresh, b"abc").await
}

pub(crate) async fn open_write_abort(ctx: &Ctx) -> CheckResult {
    let p = ctx.path("aborted.bin");
    let data = ctx.pattern(&p, 300_001);
    let mut w = ctx
        .fs
        .open_write(&p, &WriteOptions::default())
        .await
        .ctx(format_args!("open_write({p:?})"))?;
    w.write(data.slice(..100_000))
        .await
        .ctx("write before abort")?;
    w.write(data.slice(100_000..))
        .await
        .ctx("write before abort")?;
    w.abort().await.ctx(format_args!("abort() of {p:?}"))?;
    // Nothing of an aborted write to a new path may remain: object stores
    // make data visible only on close, hierarchical backends must remove the
    // partial file ("discard the write and clean up partial state").
    ctx.expect_missing(&p).await?;

    // The path is fully usable after an abort.
    ctx.put(&p, Bytes::from_static(b"after")).await?;
    ctx.expect_content(&p, b"after").await?;

    if !ctx.caps.hierarchical {
        // Aborting an overwrite keeps the previous object.
        let mut w = ctx
            .fs
            .open_write(&p, &WriteOptions::default())
            .await
            .ctx(format_args!("open_write({p:?}) over an existing object"))?;
        w.write(Bytes::from_static(b"replacement"))
            .await
            .ctx("write before abort")?;
        w.abort().await.ctx(format_args!("abort() of {p:?}"))?;
        ctx.expect_content(&p, b"after").await?;
    }

    if ctx.caps.append {
        // Aborting an append discards the appended data only.
        let mut w = ctx
            .fs
            .open_write(&p, &WriteOptions::default().with_mode(WriteMode::Append))
            .await
            .ctx(format_args!("open_write({p:?}, Append)"))?;
        w.write(data.slice(..1000))
            .await
            .ctx("append before abort")?;
        w.abort()
            .await
            .ctx(format_args!("abort() of an append to {p:?}"))?;
        ctx.expect_content(&p, b"after").await?;
    }
    Ok(())
}

/// A local scratch directory, removed when the check ends (also on panic).
struct LocalScratch(Option<PathBuf>);

impl LocalScratch {
    async fn create(ctx: &Ctx) -> Result<Self, CheckError> {
        let base = ctx
            .cfg
            .local_temp_dir
            .clone()
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join(format!(
            "fsfast-testkit-local-{}-{}",
            std::process::id(),
            pattern::seed_for(&ctx.dir)
        ));
        let d = dir.clone();
        blocking(move || std::fs::create_dir_all(&d))
            .await
            .map_err(|e| CheckError::Failed(format!("creating local scratch dir {dir:?}: {e}")))?;
        Ok(LocalScratch(Some(dir)))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.as_ref().expect("scratch dir is live").join(name)
    }

    async fn remove(mut self) {
        if let Some(d) = self.0.take() {
            let _ = blocking(move || std::fs::remove_dir_all(d)).await;
        }
    }
}

impl Drop for LocalScratch {
    fn drop(&mut self) {
        if let Some(d) = self.0.take() {
            // Only reached on panic; do not block the runtime thread.
            match tokio::runtime::Handle::try_current() {
                Ok(h) => {
                    h.spawn_blocking(move || std::fs::remove_dir_all(d));
                }
                Err(_) => {
                    let _ = std::fs::remove_dir_all(d);
                }
            }
        }
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> std::io::Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e)))
}

fn write_local_pattern(path: &Path, seed: u64, size: u64) -> std::io::Result<()> {
    let mut f = std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(path)?);
    let mut buf = vec![0u8; 1 << 20];
    let mut off = 0u64;
    while off < size {
        let n = ((size - off) as usize).min(buf.len());
        pattern::fill(seed, off, &mut buf[..n]);
        f.write_all(&buf[..n])?;
        off += n as u64;
    }
    f.flush()
}

/// `Ok(None)` if the local file holds exactly the pattern, else a description.
fn verify_local_pattern(path: &Path, seed: u64, size: u64) -> std::io::Result<Option<String>> {
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len != size {
        return Ok(Some(format!("local file has {len} bytes, expected {size}")));
    }
    let mut buf = vec![0u8; 1 << 20];
    let mut off = 0u64;
    loop {
        let mut filled = 0;
        while filled < buf.len() {
            let n = f.read(&mut buf[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            return Ok(None);
        }
        if let Some(at) = pattern::first_mismatch(seed, off, &buf[..filled]) {
            return Ok(Some(format!(
                "first mismatch at file offset {at} (expected byte {:02x}, got {:02x})",
                pattern::byte_at(seed, at),
                buf[(at - off) as usize]
            )));
        }
        off += filled as u64;
    }
}

pub(crate) async fn put_get_large(ctx: &Ctx) -> CheckResult {
    let scratch = LocalScratch::create(ctx).await?;
    let res = put_get_inner(ctx, &scratch).await;
    scratch.remove().await;
    res
}

async fn put_get_inner(ctx: &Ctx, scratch: &LocalScratch) -> CheckResult {
    let size = ctx.cfg.large_file_bytes;
    let remote = ctx.path("large/put.bin");
    let seed = pattern::seed_for(&remote);
    let src = scratch.path("src.bin");
    let s = src.clone();
    blocking(move || write_local_pattern(&s, seed, size))
        .await
        .map_err(|e| CheckError::Failed(format!("writing local source {src:?}: {e}")))?;

    ctx.ensure_parent(&remote).await?;
    ctx.fs
        .put_file(&src, &remote, &WriteOptions::default())
        .await
        .ctx(format_args!("put_file({src:?}, {remote:?})"))?;
    ctx.expect_file(&remote, size).await?;

    let mid = size / 2;
    let r = ByteRange::Bounded {
        start: mid.saturating_sub(1000),
        end: mid + 1000,
    };
    let resolved = r.resolve(size);
    let got = ctx
        .fs
        .cat_file(&remote, r)
        .await
        .ctx(format_args!("cat_file({remote:?}, {r:?})"))?;
    verify_pattern(
        &format!("cat_file({remote:?}, {r:?}) after put_file"),
        seed,
        resolved.start,
        (resolved.end - resolved.start) as usize,
        &got,
    )?;

    let dst = scratch.path("dst.bin");
    ctx.fs
        .get_file(&remote, &dst)
        .await
        .ctx(format_args!("get_file({remote:?}, {dst:?})"))?;
    let d = dst.clone();
    let problem = blocking(move || verify_local_pattern(&d, seed, size))
        .await
        .map_err(|e| CheckError::Failed(format!("reading downloaded file {dst:?}: {e}")))?;
    if let Some(problem) = problem {
        fail!("get_file({remote:?}) after put_file: {problem}");
    }

    // Empty file round trip.
    let empty_src = scratch.path("empty_src");
    let e = empty_src.clone();
    blocking(move || std::fs::write(e, b""))
        .await
        .map_err(|e| CheckError::Failed(format!("writing local empty file: {e}")))?;
    let empty_remote = ctx.path("large/empty.bin");
    ctx.fs
        .put_file(&empty_src, &empty_remote, &WriteOptions::default())
        .await
        .ctx(format_args!("put_file({empty_src:?}, {empty_remote:?})"))?;
    ctx.expect_file(&empty_remote, 0).await?;
    let empty_dst = scratch.path("empty_dst");
    ctx.fs
        .get_file(&empty_remote, &empty_dst)
        .await
        .ctx(format_args!("get_file({empty_remote:?})"))?;
    let e = empty_dst.clone();
    let len = blocking(move || std::fs::metadata(e).map(|m| m.len()))
        .await
        .map_err(|e| CheckError::Failed(format!("stat of downloaded empty file: {e}")))?;
    ensure_eq!(len, 0, "size of downloaded empty file");

    // Errors: a missing remote leaves no local file behind; a missing local
    // source creates no remote file.
    let missing_remote = ctx.path("large/missing.bin");
    let never = scratch.path("never");
    expect_err(
        format!("get_file({missing_remote:?})"),
        ctx.fs.get_file(&missing_remote, &never).await,
        &[ErrorKind::NotFound],
    )?;
    let n = never.clone();
    let left = blocking(move || Ok(n.exists())).await.unwrap_or(false);
    ensure!(
        !left,
        "get_file of a missing remote file left a local file {never:?}"
    );
    let missing_local = scratch.path("no_such_local_file");
    let target = ctx.path("large/never.bin");
    expect_err(
        format!("put_file({missing_local:?}, {target:?})"),
        ctx.fs
            .put_file(&missing_local, &target, &WriteOptions::default())
            .await,
        &[ErrorKind::NotFound],
    )?;
    ctx.expect_missing(&target).await
}
