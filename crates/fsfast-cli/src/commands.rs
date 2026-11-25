//! The manual-use commands: `ls`, `info`, `find`, `cat`, `cp`, `rm`,
//! `mkdir`.

use std::collections::BTreeSet;
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

use fsfast_core::{Error, ErrorKind, FileInfo, FileSystem, FindOptions, Result, path as fspath};

use crate::ops::{self, CopyMethod};
use crate::target::{Resolved, Session, child_path};
use crate::units::{format_bytes, info_to_json, rfc3339};

const BROKEN_PIPE: &str = "output closed (broken pipe)";

/// Map a failed write to the output stream (a closed pipe, as in
/// `fsf cat x | head`, becomes a recognisable `Cancelled` error).
pub fn out_err(e: std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        Error::new(ErrorKind::Cancelled, BROKEN_PIPE)
    } else {
        Error::from(e)
    }
}

/// Whether `e` came from writing to a closed pipe.
pub fn is_broken_pipe(e: &Error) -> bool {
    e.kind() == ErrorKind::Cancelled && e.message() == BROKEN_PIPE
}

fn print_json(out: &mut dyn Write, v: &serde_json::Value) -> Result<()> {
    serde_json::to_writer_pretty(&mut *out, v)
        .map_err(|e| Error::new(ErrorKind::Io, e.to_string()))?;
    writeln!(out).map_err(out_err)
}

/// One `ls -l` line: type, size, modification time, name.
fn long_line(i: &FileInfo) -> String {
    let t = match i.file_type {
        fsfast_core::FileType::Directory => 'd',
        fsfast_core::FileType::Symlink => 'l',
        fsfast_core::FileType::File => '-',
        fsfast_core::FileType::Other => '?',
    };
    let m = i
        .modified
        .map(|m| rfc3339(m)[..19].replace('T', " "))
        .unwrap_or_else(|| "-".repeat(19));
    format!("{t} {:>14} {m} {}", i.size, i.name)
}

fn print_listing(out: &mut dyn Write, entries: &[FileInfo], long: bool, json: bool) -> Result<()> {
    if json {
        let v: Vec<_> = entries.iter().map(info_to_json).collect();
        return print_json(out, &serde_json::Value::Array(v));
    }
    for e in entries {
        if long {
            writeln!(out, "{}", long_line(e)).map_err(out_err)?;
        } else {
            writeln!(out, "{}", e.name).map_err(out_err)?;
        }
    }
    Ok(())
}

/// `fsf ls URL`.
pub async fn ls(
    session: &Session,
    url: &str,
    long: bool,
    json: bool,
    out: &mut dyn Write,
) -> Result<()> {
    let r = one(session, url)?;
    let mut entries = r.built.fs.ls(r.path()).await?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    print_listing(out, &entries, long, json)
}

/// `fsf info URL` (always JSON: it is fsspec's `info()` dict).
pub async fn info(session: &Session, url: &str, out: &mut dyn Write) -> Result<()> {
    let r = one(session, url)?;
    let i = r.built.fs.info(r.path()).await?;
    print_json(out, &info_to_json(&i))
}

/// `fsf find URL`.
#[allow(clippy::too_many_arguments)]
pub async fn find(
    session: &Session,
    url: &str,
    maxdepth: Option<usize>,
    withdirs: bool,
    long: bool,
    json: bool,
    out: &mut dyn Write,
) -> Result<()> {
    let r = one(session, url)?;
    let entries = r
        .built
        .fs
        .find(r.path(), &FindOptions { maxdepth, withdirs })
        .await?;
    print_listing(out, &entries, long, json)
}

/// `fsf cat URL [--start N] [--end N]`: streams the bytes to `out` with
/// bounded memory.
pub async fn cat(
    session: &Session,
    url: &str,
    start: Option<u64>,
    end: Option<u64>,
    out: &mut dyn Write,
) -> Result<()> {
    let r = one(session, url)?;
    let range = start.unwrap_or(0)..end.unwrap_or(u64::MAX);
    ops::read_streaming(r.built.fs.as_ref(), r.path(), range, None, None, |c| {
        out.write_all(&c).map_err(out_err)
    })
    .await?;
    out.flush().map_err(out_err)
}

/// `fsf mkdir [-p] URL...`.
pub async fn mkdir(session: &Session, urls: &[&str], parents: bool) -> Result<()> {
    for r in session.resolve_all(urls)? {
        if parents {
            ops::mkdir_p(r.built.fs.as_ref(), r.path()).await?;
        } else {
            r.built.fs.mkdir(r.path(), false).await?;
        }
    }
    Ok(())
}

/// `fsf rm [-r] URL...`.
pub async fn rm(
    session: &Session,
    urls: &[&str],
    recursive: bool,
    quiet: bool,
    err: &mut dyn Write,
) -> Result<()> {
    for r in session.resolve_all(urls)? {
        let removed = ops::remove(r.built.fs.as_ref(), r.path(), recursive)
            .await
            .map_err(|e| {
                if e.path().is_none() {
                    e.with_path(r.loc.url.clone())
                } else {
                    e
                }
            })?;
        if !quiet && recursive {
            writeln!(
                err,
                "removed {}: {} file(s), {} director(y/ies)",
                r.loc.url, removed.files, removed.dirs
            )
            .map_err(out_err)?;
        }
    }
    Ok(())
}

/// One planned file copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyJob {
    /// Source path (source backend form).
    pub src: String,
    /// Destination path (destination backend form).
    pub dst: String,
    /// Source size.
    pub size: u64,
}

/// A planned `cp`: the files to copy and the destination directories to
/// create first (hierarchical destinations only).
#[derive(Debug, Clone, Default)]
pub struct CopyPlan {
    /// Files, in source order.
    pub jobs: Vec<CopyJob>,
    /// Directories to create, parents before children.
    pub dirs: Vec<String>,
}

/// Work out what `cp src dst` copies, following `cp`/fsspec rules: when the
/// destination is an existing directory (or is written with a trailing
/// `/`), the source is copied *into* it under its base name; otherwise the
/// destination is the copy. Directories need `recursive`.
pub async fn plan_copy(src: &Resolved, dst: &Resolved, recursive: bool) -> Result<CopyPlan> {
    let sfs = &src.built.fs;
    let dfs = &dst.built.fs;
    let src_info = sfs.info(src.path()).await?;
    let dst_is_dir = dst.loc.trailing_slash
        || match dfs.info(dst.path()).await {
            Ok(i) => i.is_dir(),
            Err(e) if e.kind() == ErrorKind::NotFound => false,
            Err(e) => return Err(e),
        };
    let base_name = fspath::basename(src.path()).to_owned();
    let into = |name: &str| child_path(dst.loc.backend, dst.path(), name);
    let hierarchical = dfs.capabilities().hierarchical;
    let mut plan = CopyPlan::default();
    if !src_info.is_dir() {
        let target = if dst_is_dir {
            into(&base_name)
        } else {
            dst.path().to_owned()
        };
        if hierarchical {
            let parent = fspath::parent(&target);
            if dst_is_dir && !parent.is_empty() && parent != "/" {
                plan.dirs.push(parent);
            }
        }
        plan.jobs.push(CopyJob {
            src: src.path().to_owned(),
            dst: target,
            size: src_info.size,
        });
        return Ok(plan);
    }
    if !recursive {
        return Err(Error::is_a_directory(src.path())
            .with_path(src.loc.url.clone())
            .with_kind(ErrorKind::IsADirectory));
    }
    let dst_root = if dst_is_dir {
        into(&base_name)
    } else {
        dst.path().to_owned()
    };
    let src_root = fspath::normalize(src.path());
    let entries = sfs
        .find(
            src.path(),
            &FindOptions {
                maxdepth: None,
                withdirs: true,
            },
        )
        .await?;
    let mut dirs = BTreeSet::new();
    if hierarchical {
        dirs.insert(dst_root.clone());
    }
    for e in entries {
        let name = fspath::normalize(&e.name);
        let Some(rel) = name.strip_prefix(src_root.as_str()) else {
            continue;
        };
        let rel = rel.trim_start_matches('/');
        if rel.is_empty() {
            continue;
        }
        let target = child_path(dst.loc.backend, &dst_root, rel);
        if e.is_dir() {
            if hierarchical {
                dirs.insert(target);
            }
        } else {
            if hierarchical {
                dirs.insert(fspath::parent(&target));
            }
            plan.jobs.push(CopyJob {
                src: e.name.clone(),
                dst: target,
                size: e.size,
            });
        }
    }
    // BTreeSet order puts parents before their children.
    plan.dirs = dirs
        .into_iter()
        .filter(|d| !d.is_empty() && d != "/")
        .collect();
    Ok(plan)
}

/// Summary of a finished copy.
#[derive(Debug, Clone, Copy)]
pub struct CopySummary {
    /// Files copied.
    pub files: usize,
    /// Bytes copied (source sizes).
    pub bytes: u64,
    /// Wall time.
    pub elapsed: std::time::Duration,
    /// How the bytes moved.
    pub method: CopyMethod,
}

/// Execute a plan with up to `jobs` files in flight.
pub async fn run_copy(
    src: &Resolved,
    dst: &Resolved,
    plan: &CopyPlan,
    jobs: usize,
) -> Result<CopySummary> {
    let method = ops::copy_method(src, dst);
    let t0 = Instant::now();
    let dfs = &dst.built.fs;
    for d in &plan.dirs {
        dfs.makedirs(d, true).await?;
    }
    let sfs: &Arc<dyn FileSystem> = &src.built.fs;
    ops::for_each_concurrent(plan.jobs.len(), jobs, |i| {
        let job = &plan.jobs[i];
        async move {
            ops::copy_file(method, sfs, &job.src, dfs, &job.dst, job.size)
                .await
                .map(|_| ())
                .map_err(|e| {
                    if e.path().is_none() {
                        e.with_path(job.src.clone())
                    } else {
                        e
                    }
                })
        }
    })
    .await?;
    Ok(CopySummary {
        files: plan.jobs.len(),
        bytes: plan.jobs.iter().map(|j| j.size).sum(),
        elapsed: t0.elapsed(),
        method,
    })
}

/// `fsf cp [-r] [-j N] SRC DST`.
pub async fn cp(
    session: &Session,
    src: &str,
    dst: &str,
    recursive: bool,
    jobs: usize,
    quiet: bool,
    err: &mut dyn Write,
) -> Result<()> {
    let mut r = session.resolve_all(&[src, dst])?;
    let dst = r.pop().expect("two locations");
    let src = r.pop().expect("two locations");
    let plan = plan_copy(&src, &dst, recursive).await?;
    let s = run_copy(&src, &dst, &plan, jobs).await?;
    if !quiet {
        let secs = s.elapsed.as_secs_f64().max(1e-9);
        writeln!(
            err,
            "copied {} file(s), {} in {:.3} s ({:.1} MB/s, {:?})",
            s.files,
            format_bytes(s.bytes),
            secs,
            s.bytes as f64 / secs / 1e6,
            s.method
        )
        .map_err(out_err)?;
    }
    Ok(())
}

fn one(session: &Session, url: &str) -> Result<Resolved> {
    Ok(session.resolve_all(&[url])?.pop().expect("one location"))
}

#[cfg(all(test, feature = "memory", feature = "local"))]
mod tests {
    use super::*;
    use crate::options::OptionSet;
    use bytes::Bytes;
    use fsfast_core::WriteOptions;

    async fn put(s: &Session, url: &str, data: &'static [u8]) {
        let r = one(s, url).unwrap();
        r.built
            .fs
            .pipe_file(r.path(), Bytes::from_static(data), &WriteOptions::default())
            .await
            .unwrap();
    }

    fn uniq(tag: &str) -> String {
        format!(
            "memory://fsf-cmd-test-{tag}-{}-{}",
            std::process::id(),
            fastrand::u64(..)
        )
    }

    #[tokio::test]
    async fn plan_file_into_dir_and_rename() {
        let s = Session::new(OptionSet::default());
        let root = uniq("plan");
        put(&s, &format!("{root}/src/a.txt"), b"hello").await;
        mkdir(&s, &[&format!("{root}/dst")], true).await.unwrap();
        let r = s
            .resolve_all(&[&format!("{root}/src/a.txt"), &format!("{root}/dst")])
            .unwrap();
        let p = plan_copy(&r[0], &r[1], false).await.unwrap();
        assert_eq!(p.jobs.len(), 1);
        assert!(p.jobs[0].dst.ends_with("/dst/a.txt"), "{:?}", p.jobs);
        let r = s
            .resolve_all(&[&format!("{root}/src/a.txt"), &format!("{root}/new.txt")])
            .unwrap();
        let p = plan_copy(&r[0], &r[1], false).await.unwrap();
        assert!(p.jobs[0].dst.ends_with("/new.txt"));
        // Trailing slash means "into".
        let r = s
            .resolve_all(&[&format!("{root}/src/a.txt"), &format!("{root}/nd/")])
            .unwrap();
        let p = plan_copy(&r[0], &r[1], false).await.unwrap();
        assert!(p.jobs[0].dst.ends_with("/nd/a.txt"), "{:?}", p.jobs);
        // Directories need -r.
        let r = s
            .resolve_all(&[&format!("{root}/src"), &format!("{root}/x")])
            .unwrap();
        let e = plan_copy(&r[0], &r[1], false).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::IsADirectory);
    }

    #[tokio::test]
    async fn recursive_copy_memory_local_round_trip() {
        let s = Session::new(OptionSet::default());
        let root = uniq("rt");
        put(&s, &format!("{root}/tree/a"), b"A").await;
        put(&s, &format!("{root}/tree/sub/b"), b"BB").await;
        put(&s, &format!("{root}/tree/sub/deep/c"), b"CCC").await;
        let tmp = tempfile::tempdir().unwrap();
        let local = tmp.path().join("out");
        let local_s = local.to_str().unwrap().to_owned();
        let mut sink = Vec::new();
        // memory -> new local dir (the copy is named `out`).
        cp(
            &s,
            &format!("{root}/tree"),
            &local_s,
            true,
            4,
            false,
            &mut sink,
        )
        .await
        .unwrap();
        assert!(String::from_utf8_lossy(&sink).contains("copied 3 file(s)"));
        assert_eq!(std::fs::read(local.join("sub/deep/c")).unwrap(), b"CCC");
        assert_eq!(std::fs::read(local.join("a")).unwrap(), b"A");
        // local -> existing memory dir: copied into it under `out`.
        mkdir(&s, &[&format!("{root}/back")], true).await.unwrap();
        cp(
            &s,
            &local_s,
            &format!("{root}/back"),
            true,
            2,
            true,
            &mut sink,
        )
        .await
        .unwrap();
        let mut out = Vec::new();
        cat(&s, &format!("{root}/back/out/sub/b"), None, None, &mut out)
            .await
            .unwrap();
        assert_eq!(out, b"BB");
        // Ranged cat.
        let mut out = Vec::new();
        cat(
            &s,
            &format!("{root}/back/out/sub/deep/c"),
            Some(1),
            Some(2),
            &mut out,
        )
        .await
        .unwrap();
        assert_eq!(out, b"C");
        // Same-fs copy.
        cp(
            &s,
            &format!("{root}/back/out/a"),
            &format!("{root}/a2"),
            false,
            1,
            true,
            &mut sink,
        )
        .await
        .unwrap();
        let mut out = Vec::new();
        ls(&s, &root, false, false, &mut out).await.unwrap();
        let listing = String::from_utf8(out).unwrap();
        assert!(listing.contains("/a2\n"), "{listing}");
        let mut out = Vec::new();
        find(
            &s,
            &format!("{root}/back"),
            None,
            false,
            false,
            true,
            &mut out,
        )
        .await
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 3);
        let mut out = Vec::new();
        info(&s, &format!("{root}/a2"), &mut out).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["size"], 1);
        assert_eq!(v["type"], "file");
        // rm -r
        rm(&s, &[&root], true, true, &mut sink).await.unwrap();
        let e = info(&s, &root, &mut Vec::new()).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotFound);
    }

    #[test]
    fn long_lines() {
        let mut i = FileInfo::file("/x", 12);
        i.modified = Some(std::time::UNIX_EPOCH);
        assert_eq!(long_line(&i), "-             12 1970-01-01 00:00:00 /x");
        let d = FileInfo::directory("/d");
        assert!(long_line(&d).starts_with("d              0 ----"));
    }
}
