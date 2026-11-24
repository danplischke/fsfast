//! Directory checks: mkdir, makedirs, rmdir.

use bytes::Bytes;
use fsfast_core::{ErrorKind, path};

use crate::ctx::{CheckResult, Context, Ctx, expect_err};

pub(crate) async fn mkdir_rmdir(ctx: &Ctx) -> CheckResult {
    let d = ctx.path("m");
    if !ctx.caps.hierarchical {
        // Emulated directories: mkdir below the top level is a no-op and a
        // directory exists while keys exist below it. rmdir semantics differ
        // between object stores, but it must never delete data.
        ctx.fs
            .mkdir(&d, true)
            .await
            .ctx(format_args!("mkdir({d:?}, create_parents=true)"))?;
        let f = path::join(&d, "f");
        ctx.put(&f, Bytes::from_static(b"data")).await?;
        ctx.expect_dir(&d).await?;
        let _ = ctx.fs.rmdir(&d).await;
        ctx.expect_content(&f, b"data").await?;
        return Ok(());
    }

    ctx.fs
        .mkdir(&d, false)
        .await
        .ctx(format_args!("mkdir({d:?}, create_parents=false)"))?;
    ctx.expect_dir(&d).await?;
    let entries = ctx.fs.ls(&d).await.ctx(format_args!("ls({d:?})"))?;
    ensure!(entries.is_empty(), "a new directory is not empty: {entries:?}");

    // mkdir of an existing directory fails, with or without create_parents.
    for parents in [false, true] {
        expect_err(
            format!("mkdir({d:?}, create_parents={parents}) of an existing directory"),
            ctx.fs.mkdir(&d, parents).await,
            &[ErrorKind::AlreadyExists],
        )?;
    }

    // create_parents builds the whole chain.
    let nested = path::join(&d, "a/b/c");
    ctx.fs
        .mkdir(&nested, true)
        .await
        .ctx(format_args!("mkdir({nested:?}, create_parents=true)"))?;
    for p in ["a", "a/b", "a/b/c"] {
        ctx.expect_dir(&path::join(&d, p)).await?;
    }

    // mkdir on top of a file fails.
    let file = path::join(&d, "f");
    ctx.put(&file, Bytes::from_static(b"x")).await?;
    expect_err(
        format!("mkdir({file:?}) of an existing file"),
        ctx.fs.mkdir(&file, false).await,
        &[ErrorKind::AlreadyExists],
    )?;

    // rmdir of a non-empty directory fails and deletes nothing.
    expect_err(
        format!("rmdir({d:?}) of a non-empty directory"),
        ctx.fs.rmdir(&d).await,
        &[ErrorKind::DirectoryNotEmpty],
    )?;
    ctx.expect_content(&file, b"x").await?;
    ctx.expect_dir(&nested).await?;

    // Empty the tree bottom-up, then rmdir succeeds.
    ctx.fs.rm_file(&file).await.ctx(format_args!("rm_file({file:?})"))?;
    for p in ["a/b/c", "a/b", "a"] {
        let p = path::join(&d, p);
        ctx.fs.rmdir(&p).await.ctx(format_args!("rmdir({p:?})"))?;
        ctx.expect_missing(&p).await?;
    }
    ctx.fs.rmdir(&d).await.ctx(format_args!("rmdir({d:?})"))?;
    ctx.expect_missing(&d).await?;

    let missing = ctx.path("missing");
    expect_err(
        format!("rmdir({missing:?}) of a missing directory"),
        ctx.fs.rmdir(&missing).await,
        &[ErrorKind::NotFound],
    )
}

pub(crate) async fn makedirs(ctx: &Ctx) -> CheckResult {
    let p = ctx.path("md/x/y");
    if !ctx.caps.hierarchical {
        // Emulated directories: makedirs is a no-op and must not fail, also
        // when repeated.
        for _ in 0..2 {
            ctx.fs
                .makedirs(&p, true)
                .await
                .ctx(format_args!("makedirs({p:?}, exist_ok=true)"))?;
        }
        return Ok(());
    }

    ctx.fs
        .makedirs(&p, false)
        .await
        .ctx(format_args!("makedirs({p:?}, exist_ok=false)"))?;
    for d in ["md", "md/x", "md/x/y"] {
        ctx.expect_dir(&ctx.path(d)).await?;
    }
    ctx.fs
        .makedirs(&p, true)
        .await
        .ctx(format_args!("makedirs({p:?}, exist_ok=true) of an existing directory"))?;
    expect_err(
        format!("makedirs({p:?}, exist_ok=false) of an existing directory"),
        ctx.fs.makedirs(&p, false).await,
        &[ErrorKind::AlreadyExists],
    )?;

    // A file in the way: never silently replaced. (fsspec's local filesystem
    // raises FileExistsError; its memory filesystem ignores the error when
    // exist_ok=True. Either way the file must survive.)
    let file = ctx.path("md/file");
    ctx.put(&file, Bytes::from_static(b"keep")).await?;
    match ctx.fs.makedirs(&file, true).await {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => fail!(
            "makedirs({file:?}, exist_ok=true) over a file: expected Ok or AlreadyExists, got {:?}: {e}",
            e.kind()
        ),
    }
    expect_err(
        format!("makedirs({file:?}, exist_ok=false) over a file"),
        ctx.fs.makedirs(&file, false).await,
        &[ErrorKind::AlreadyExists],
    )?;
    ctx.expect_content(&file, b"keep").await?;
    ctx.expect_file(&file, 4).await
}
