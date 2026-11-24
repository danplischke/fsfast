//! Mutation checks: rm_file, rm_files, cp_file, mv_file, touch.

use bytes::Bytes;
use fsfast_core::{ErrorKind, FindOptions, path};

use crate::ctx::{CheckResult, Context, Ctx, expect_err};

pub(crate) async fn rm_file(ctx: &Ctx) -> CheckResult {
    let f = ctx.path("victim");
    ctx.put(&f, Bytes::from_static(b"bye")).await?;
    ctx.fs
        .rm_file(&f)
        .await
        .ctx(format_args!("rm_file({f:?})"))?;
    ctx.expect_missing(&f).await?;
    expect_err(
        format!("rm_file({f:?}) of an already deleted file"),
        ctx.fs.rm_file(&f).await,
        &[ErrorKind::NotFound],
    )?;
    let missing = ctx.path("never/existed");
    expect_err(
        format!("rm_file({missing:?})"),
        ctx.fs.rm_file(&missing).await,
        &[ErrorKind::NotFound],
    )?;

    // rm_file on a directory must fail (the kind is backend-specific) and
    // must not remove the directory or its contents.
    let dir = ctx.path("dir");
    ctx.ensure_dir(&dir).await?;
    let child = path::join(&dir, "child");
    ctx.put(&child, Bytes::from_static(b"c")).await?;
    if ctx.fs.rm_file(&dir).await.is_ok() {
        fail!("rm_file({dir:?}) of a directory succeeded");
    }
    ctx.expect_dir(&dir).await?;
    ctx.expect_content(&child, b"c").await
}

pub(crate) async fn rm_files_batch(ctx: &Ctx) -> CheckResult {
    let (a, b, c) = (ctx.path("a"), ctx.path("b"), ctx.path("c"));
    let missing = ctx.path("missing");
    for p in [&a, &b, &c] {
        ctx.put(p, Bytes::copy_from_slice(p.as_bytes())).await?;
    }
    let paths = vec![a.clone(), missing.clone(), b.clone(), c.clone()];
    let results = ctx.fs.rm_files(&paths).await;
    ensure_eq!(results.len(), paths.len(), "rm_files: number of results");
    for (i, (p, r)) in paths.iter().zip(results).enumerate() {
        if *p == missing {
            expect_err(
                format!("rm_files result #{i} for missing {p:?}"),
                r,
                &[ErrorKind::NotFound],
            )?;
        } else {
            r.ctx(format_args!("rm_files result #{i} for {p:?}"))?;
            ctx.expect_missing(p).await?;
        }
    }

    let none = ctx.fs.rm_files(&[]).await;
    ensure!(
        none.is_empty(),
        "rm_files([]) returned {} results",
        none.len()
    );

    // A larger batch, to exercise native batching / concurrency.
    let many: Vec<String> = (0..120)
        .map(|i| ctx.path(&format!("many/{i:04}")))
        .collect();
    for p in &many {
        ctx.put(p, Bytes::from_static(b"m")).await?;
    }
    let results = ctx.fs.rm_files(&many).await;
    ensure_eq!(
        results.len(),
        many.len(),
        "rm_files: number of results for a large batch"
    );
    for (p, r) in many.iter().zip(results) {
        r.ctx(format_args!("rm_files({p:?})"))?;
    }
    let left = ctx
        .fs
        .find(&ctx.path("many"), &FindOptions::default())
        .await
        .ctx("find after rm_files")?;
    ensure!(
        left.is_empty(),
        "{} files left after rm_files, e.g. {:?}",
        left.len(),
        left[0].name
    );
    Ok(())
}

pub(crate) async fn cp_file(ctx: &Ctx) -> CheckResult {
    let src = ctx.path("src.bin");
    let data = ctx.pattern(&src, 4097);
    ctx.put(&src, data.clone()).await?;

    let dst = ctx.path("dst.bin");
    ctx.fs
        .cp_file(&src, &dst)
        .await
        .ctx(format_args!("cp_file({src:?}, {dst:?})"))?;
    ctx.expect_content(&dst, &data).await?;
    ctx.expect_content(&src, &data).await?;
    ctx.expect_file(&dst, data.len() as u64).await?;

    // Overwrite a larger existing destination: it must be truncated.
    let big = ctx.path("big.bin");
    ctx.put(&big, ctx.pattern(&big, 10_000)).await?;
    ctx.fs.cp_file(&src, &big).await.ctx(format_args!(
        "cp_file({src:?}, {big:?}) over an existing file"
    ))?;
    ctx.expect_content(&big, &data).await?;

    // Onto itself: may succeed or fail (fsspec's local filesystem raises
    // SameFileError, S3 refuses), but must never truncate or corrupt the
    // file (a naive "open destination for writing, then read source").
    let _ = ctx.fs.cp_file(&src, &src).await;
    ctx.expect_content(&src, &data).await?;

    // Into a sub-directory.
    let nested = ctx.path("sub/dir/copy.bin");
    ctx.ensure_parent(&nested).await?;
    ctx.fs
        .cp_file(&src, &nested)
        .await
        .ctx(format_args!("cp_file({src:?}, {nested:?})"))?;
    ctx.expect_content(&nested, &data).await?;

    // An empty file.
    let empty = ctx.path("empty");
    let empty_copy = ctx.path("empty_copy");
    ctx.put(&empty, Bytes::new()).await?;
    ctx.fs
        .cp_file(&empty, &empty_copy)
        .await
        .ctx(format_args!("cp_file({empty:?}, {empty_copy:?})"))?;
    ctx.expect_file(&empty_copy, 0).await?;

    let missing = ctx.path("missing");
    let target = ctx.path("never_created");
    expect_err(
        format!("cp_file({missing:?}, {target:?})"),
        ctx.fs.cp_file(&missing, &target).await,
        &[ErrorKind::NotFound],
    )?;
    ctx.expect_missing(&target).await
}

pub(crate) async fn mv_file(ctx: &Ctx) -> CheckResult {
    let src = ctx.path("src.bin");
    let data = ctx.pattern(&src, 3001);
    ctx.put(&src, data.clone()).await?;
    let dst = ctx.path("dst.bin");
    ctx.fs
        .mv_file(&src, &dst)
        .await
        .ctx(format_args!("mv_file({src:?}, {dst:?})"))?;
    ctx.expect_missing(&src).await?;
    ctx.expect_content(&dst, &data).await?;

    // Overwrite an existing destination.
    let src2 = ctx.path("src2.bin");
    let data2 = ctx.pattern(&src2, 77);
    ctx.put(&src2, data2.clone()).await?;
    ctx.fs.mv_file(&src2, &dst).await.ctx(format_args!(
        "mv_file({src2:?}, {dst:?}) over an existing file"
    ))?;
    ctx.expect_missing(&src2).await?;
    ctx.expect_content(&dst, &data2).await?;

    // Into a sub-directory, and onto itself (a no-op).
    let nested = ctx.path("sub/moved.bin");
    ctx.ensure_parent(&nested).await?;
    ctx.fs
        .mv_file(&dst, &nested)
        .await
        .ctx(format_args!("mv_file({dst:?}, {nested:?})"))?;
    ctx.expect_missing(&dst).await?;
    ctx.expect_content(&nested, &data2).await?;
    ctx.fs
        .mv_file(&nested, &nested)
        .await
        .ctx(format_args!("mv_file({nested:?}, {nested:?}) onto itself"))?;
    ctx.expect_content(&nested, &data2).await?;

    let missing = ctx.path("missing");
    let target = ctx.path("never_created");
    expect_err(
        format!("mv_file({missing:?}, {target:?})"),
        ctx.fs.mv_file(&missing, &target).await,
        &[ErrorKind::NotFound],
    )?;
    ctx.expect_missing(&target).await
}

pub(crate) async fn touch(ctx: &Ctx) -> CheckResult {
    let p = ctx.path("touched");
    ctx.fs
        .touch(&p, true)
        .await
        .ctx(format_args!("touch({p:?}, truncate=true)"))?;
    ctx.expect_file(&p, 0).await?;

    ctx.put(&p, Bytes::from_static(b"some data")).await?;
    ctx.fs.touch(&p, true).await.ctx(format_args!(
        "touch({p:?}, truncate=true) of a non-empty file"
    ))?;
    ctx.expect_file(&p, 0).await?;
    ctx.expect_content(&p, b"").await?;

    // Without truncation an existing file keeps its content; backends that
    // cannot update timestamps report Unsupported (fsspec: NotImplementedError).
    let keep = ctx.path("kept");
    ctx.put(&keep, Bytes::from_static(b"keep")).await?;
    match ctx.fs.touch(&keep, false).await {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::Unsupported => {}
        Err(e) => fail!(
            "touch({keep:?}, truncate=false): expected Ok or Unsupported, got {:?}: {e}",
            e.kind()
        ),
    }
    ctx.expect_content(&keep, b"keep").await?;

    // Without truncation a missing file is created empty.
    let fresh = ctx.path("fresh");
    ctx.fs.touch(&fresh, false).await.ctx(format_args!(
        "touch({fresh:?}, truncate=false) of a missing file"
    ))?;
    ctx.expect_file(&fresh, 0).await
}
