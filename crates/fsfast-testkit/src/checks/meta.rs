//! Metadata checks: info, ls, find, exists, unusual names.

use bytes::Bytes;
use fsfast_core::{ErrorKind, FileInfo, FindOptions, path};

use crate::ctx::{CheckResult, Context, Ctx, expect_err};

fn names(entries: &[FileInfo]) -> Vec<String> {
    entries.iter().map(|e| e.name.clone()).collect()
}

fn sorted_names(entries: &[FileInfo]) -> Vec<String> {
    let mut v = names(entries);
    v.sort();
    v
}

pub(crate) async fn info(ctx: &Ctx) -> CheckResult {
    let file = ctx.path("f.bin");
    ctx.put(&file, ctx.pattern(&file, 123)).await?;
    let i = ctx.fs.info(&file).await.ctx(format_args!("info({file:?})"))?;
    ensure_eq!(i.name, path::normalize(&file), "info({file:?}).name");
    ensure_eq!(i.size, 123, "info({file:?}).size");
    ensure!(i.is_file(), "info({file:?}).file_type: expected File, got {:?}", i.file_type);

    // A directory: real on hierarchical backends, implied by a child key on
    // object stores.
    let dir = ctx.path("sub");
    if ctx.caps.hierarchical {
        ctx.fs
            .mkdir(&dir, false)
            .await
            .ctx(format_args!("mkdir({dir:?})"))?;
    } else {
        ctx.put(&path::join(&dir, "child"), Bytes::from_static(b"x"))
            .await?;
    }
    for p in [dir.clone(), format!("{dir}/")] {
        let i = ctx.fs.info(&p).await.ctx(format_args!("info({p:?})"))?;
        ensure_eq!(i.name, path::normalize(&dir), "info({p:?}).name");
        ensure!(i.is_dir(), "info({p:?}).file_type: expected Directory, got {:?}", i.file_type);
    }
    // The check's own directory.
    ctx.put(&ctx.path("keep"), Bytes::from_static(b"k")).await?;
    ctx.expect_dir(&ctx.dir).await?;

    for missing in [ctx.path("missing"), ctx.path("missing/deeper/still")] {
        expect_err(
            format!("info({missing:?})"),
            ctx.fs.info(&missing).await,
            &[ErrorKind::NotFound],
        )?;
    }
    Ok(())
}

pub(crate) async fn ls(ctx: &Ctx) -> CheckResult {
    let dir = ctx.path("tree");
    let (a, b, s, c) = (
        path::join(&dir, "a"),
        path::join(&dir, "b.txt"),
        path::join(&dir, "s"),
        path::join(&dir, "s/c"),
    );
    if ctx.caps.hierarchical {
        ctx.fs.mkdir(&dir, false).await.ctx(format_args!("mkdir({dir:?})"))?;
        ctx.fs.mkdir(&s, false).await.ctx(format_args!("mkdir({s:?})"))?;
    }
    ctx.put(&a, Bytes::from_static(b"aaa")).await?;
    ctx.put(&b, Bytes::from_static(b"bbbbb")).await?;
    ctx.put(&c, Bytes::from_static(b"c")).await?;

    for p in [dir.clone(), format!("{dir}/")] {
        let entries = ctx.fs.ls(&p).await.ctx(format_args!("ls({p:?})"))?;
        ensure_eq!(
            sorted_names(&entries),
            vec![a.clone(), b.clone(), s.clone()],
            "ls({p:?}) names"
        );
        for e in &entries {
            if e.name == a {
                ensure!(e.is_file() && e.size == 3, "ls({p:?}): bad entry for {a:?}: {e:?}");
            } else if e.name == b {
                ensure!(e.is_file() && e.size == 5, "ls({p:?}): bad entry for {b:?}: {e:?}");
            } else {
                ensure!(e.is_dir(), "ls({p:?}): {s:?} should be a directory: {e:?}");
            }
        }
    }

    // Listing a file returns the file itself.
    let entries = ctx.fs.ls(&a).await.ctx(format_args!("ls({a:?}) of a file"))?;
    ensure_eq!(names(&entries), vec![a.clone()], "ls({a:?}) of a file");
    ensure!(
        entries[0].is_file() && entries[0].size == 3,
        "ls({a:?}) of a file: bad entry {:?}",
        entries[0]
    );

    let sub = ctx.fs.ls(&s).await.ctx(format_args!("ls({s:?})"))?;
    ensure_eq!(names(&sub), vec![c.clone()], "ls({s:?})");

    if ctx.caps.hierarchical {
        let empty = ctx.path("empty");
        ctx.fs.mkdir(&empty, false).await.ctx(format_args!("mkdir({empty:?})"))?;
        let entries = ctx.fs.ls(&empty).await.ctx(format_args!("ls({empty:?})"))?;
        ensure!(entries.is_empty(), "ls of an empty directory returned {:?}", names(&entries));
    }

    let missing = ctx.path("missing");
    expect_err(
        format!("ls({missing:?})"),
        ctx.fs.ls(&missing).await,
        &[ErrorKind::NotFound],
    )
}

/// Run `find(root, maxdepth, withdirs)` and compare with `expected`.
async fn expect_find(
    ctx: &Ctx,
    root: &str,
    files: &[(String, usize)],
    maxdepth: Option<usize>,
    withdirs: bool,
    mut expected: Vec<String>,
) -> CheckResult {
    expected.sort();
    let what = format!("find({root:?}, maxdepth={maxdepth:?}, withdirs={withdirs})");
    let got = ctx
        .fs
        .find(root, &FindOptions { maxdepth, withdirs })
        .await
        .ctx(&what)?;
    let got_names = names(&got);
    let mut sorted = got_names.clone();
    sorted.sort();
    ensure!(got_names == sorted, "{what}: result is not sorted by name: {got_names:?}");
    ensure_eq!(got_names, expected, "{what} names");
    for e in &got {
        match files.iter().find(|(f, _)| *f == e.name) {
            Some((_, size)) => ensure!(
                e.is_file() && e.size == *size as u64,
                "{what}: bad file entry {e:?} (expected a file of {size} bytes)"
            ),
            None => ensure!(e.is_dir(), "{what}: {:?} should be a directory: {e:?}", e.name),
        }
    }
    Ok(())
}

pub(crate) async fn find(ctx: &Ctx) -> CheckResult {
    let root = ctx.path("ftree");
    let p = |rel: &str| path::join(&root, rel);
    let files: Vec<(String, usize)> = vec![
        (p("f1"), 1),
        (p("d1/f2"), 2),
        (p("d1/d2/f3"), 3),
        (p("d1/d2/d3/f4"), 4),
    ];
    for (f, n) in &files {
        ctx.put(f, ctx.pattern(f, *n)).await?;
    }
    let hier = ctx.caps.hierarchical;
    if hier {
        ctx.fs
            .mkdir(&p("empty"), false)
            .await
            .ctx(format_args!("mkdir({:?})", p("empty")))?;
    }
    // Expected names: `rels` below the root, plus the empty directory
    // (hierarchical backends only) and the root itself when `withdirs`.
    let v = |rels: &[&str], withdirs: bool| -> Vec<String> {
        let mut out: Vec<String> = rels.iter().map(|r| p(r)).collect();
        if withdirs {
            out.push(root.clone());
            if hier {
                out.push(p("empty"));
            }
        }
        out
    };

    let all_files = ["f1", "d1/f2", "d1/d2/f3", "d1/d2/d3/f4"];
    expect_find(ctx, &root, &files, None, false, v(&all_files, false)).await?;
    expect_find(ctx, &root, &files, Some(1), false, v(&["f1"], false)).await?;
    expect_find(ctx, &root, &files, Some(2), false, v(&["f1", "d1/f2"], false)).await?;
    let mut everything = all_files.to_vec();
    everything.extend(["d1", "d1/d2", "d1/d2/d3"]);
    expect_find(ctx, &root, &files, None, true, v(&everything, true)).await?;
    expect_find(ctx, &root, &files, Some(1), true, v(&["d1", "f1"], true)).await?;
    expect_find(ctx, &root, &files, Some(2), true, v(&["d1", "d1/d2", "f1", "d1/f2"], true))
        .await?;

    // A file root returns just the file; a missing root returns nothing.
    let f1 = p("f1");
    let missing = p("missing");
    for withdirs in [false, true] {
        expect_find(ctx, &f1, &files, None, withdirs, vec![f1.clone()]).await?;
        expect_find(ctx, &missing, &files, None, withdirs, vec![]).await?;
    }
    Ok(())
}

pub(crate) async fn exists(ctx: &Ctx) -> CheckResult {
    let file = ctx.path("present");
    ctx.put(&file, Bytes::from_static(b"here")).await?;
    let dir = ctx.path("dir");
    if ctx.caps.hierarchical {
        ctx.fs.mkdir(&dir, false).await.ctx(format_args!("mkdir({dir:?})"))?;
    } else {
        ctx.put(&path::join(&dir, "child"), Bytes::from_static(b"c"))
            .await?;
    }
    for (p, want) in [
        (file.clone(), true),
        (dir.clone(), true),
        (ctx.path("absent"), false),
        (ctx.path("absent/child"), false),
        (format!("{file}/child"), false),
    ] {
        let got = ctx.fs.exists(&p).await.ctx(format_args!("exists({p:?})"))?;
        ensure_eq!(got, want, "exists({p:?})");
    }
    Ok(())
}

pub(crate) async fn special_names(ctx: &Ctx) -> CheckResult {
    // Characters that need escaping in URLs, XML or shells, plus non-ASCII.
    // Avoids characters that are invalid on common filesystems (`?*:<>|"\`).
    let names_ = [
        "with space.txt",
        "ünïcödé-名前.bin",
        "plus+sign",
        "percent%20encoded",
        "equals=amp&semi;",
        "tilde~hash#",
        "quote'single",
        "parens (1) [2] {3}",
        "dollar$and@at",
        "comma,dot.dot..",
    ];
    for n in names_ {
        let p = ctx.path(n);
        ctx.put(&p, Bytes::copy_from_slice(n.as_bytes())).await?;
        ctx.expect_content(&p, n.as_bytes()).await?;
        let i = ctx.fs.info(&p).await.ctx(format_args!("info({p:?})"))?;
        ensure_eq!(i.name, path::normalize(&p), "info({p:?}).name");
        ensure_eq!(i.size, n.len() as u64, "info({p:?}).size");
    }
    let listed = ctx.fs.ls(&ctx.dir).await.ctx(format_args!("ls({:?})", ctx.dir))?;
    let got = sorted_names(&listed);
    let mut want: Vec<String> = names_.iter().map(|n| ctx.path(n)).collect();
    want.sort();
    ensure_eq!(got, want, "ls of a directory with unusual names");
    for n in names_ {
        let p = ctx.path(n);
        ctx.fs.rm_file(&p).await.ctx(format_args!("rm_file({p:?})"))?;
        ctx.expect_missing(&p).await?;
    }
    Ok(())
}
