//! `info`, `ls`, `find`, `exists`: listings with s3fs semantics.

use std::collections::{BTreeMap, HashSet};
use std::ops::ControlFlow;

use fsfast_core::{Error, ErrorKind, FileInfo, FindOptions, Result};
use fsfast_http_transport::Method;
use futures::{StreamExt, stream};

use crate::client::Call;
use crate::info::{
    ObjectMeta, bucket_info, dir_info, listed_bucket_info, listed_dir_info, object_info, root_info,
};
use crate::params::{Op, Params};
use crate::path::{S3Path, split_path, strip_protocol};
use crate::xml::{ListPage, parse_list_buckets};
use crate::{S3FileSystem, State};

/// What a listing request asks for.
#[derive(Debug, Clone, Default)]
pub(crate) struct ListRequest<'a> {
    pub bucket: &'a str,
    pub prefix: &'a str,
    pub delimiter: Option<&'a str>,
    /// `ListObjectVersions` instead of `ListObjectsV2`.
    pub versions: bool,
    pub max_keys: Option<u32>,
    pub start_after: Option<&'a str>,
}

impl S3FileSystem {
    /// Fetch listing pages, passing each to `on_page` until it breaks or the
    /// listing ends. Pages are fetched one after another (continuation
    /// tokens are sequential).
    pub(crate) async fn list_pages(
        &self,
        st: &State,
        req: &ListRequest<'_>,
        path: &str,
        mut on_page: impl FnMut(ListPage) -> ControlFlow<()>,
    ) -> Result<()> {
        let mut token: Option<String> = None;
        let mut key_marker: Option<String> = None;
        let mut version_marker: Option<String> = None;
        loop {
            let mut call = Call::new(
                if req.versions {
                    Op::ListObjectVersions
                } else {
                    Op::ListObjectsV2
                },
                Method::GET,
                path,
            )
            .bucket(req.bucket);
            if req.versions {
                call = call.query("versions", "");
            } else {
                call = call.query("list-type", "2");
            }
            call = call.query("prefix", req.prefix);
            if let Some(d) = req.delimiter.filter(|d| !d.is_empty()) {
                call = call.query("delimiter", d);
            }
            if let Some(m) = req.max_keys {
                call = call.query("max-keys", m.to_string());
            }
            if req.versions {
                if let Some(k) = &key_marker {
                    call = call.query("key-marker", k.clone());
                }
                if let Some(v) = &version_marker {
                    call = call.query("version-id-marker", v.clone());
                }
            } else {
                if let Some(t) = &token {
                    call = call.query("continuation-token", t.clone());
                }
                if let Some(s) = req.start_after
                    && token.is_none()
                {
                    call = call.query("start-after", s);
                }
            }
            // URL-encoded keys survive characters XML 1.0 cannot carry.
            call = call.query("encoding-type", "url");
            let page = st
                .client
                .execute(call, |resp| async move {
                    let body = resp.bytes().await?;
                    ListPage::parse(&body)
                })
                .await?;
            let truncated = page.is_truncated;
            let next_token = page.next_continuation_token.clone();
            let next_key = page.next_key_marker.clone();
            let next_version = page.next_version_id_marker.clone();
            if on_page(page).is_break() || !truncated {
                return Ok(());
            }
            if req.versions {
                if next_key.is_none() || (next_key == key_marker && next_version == version_marker)
                {
                    return Err(Error::protocol(
                        "truncated version listing without a new NextKeyMarker",
                    )
                    .with_path(path));
                }
                key_marker = next_key;
                version_marker = next_version;
            } else {
                match next_token {
                    Some(t) if Some(&t) != token.as_ref() => token = Some(t),
                    _ => {
                        return Err(Error::protocol(
                            "truncated listing without a new NextContinuationToken",
                        )
                        .with_path(path));
                    }
                }
            }
        }
    }

    /// s3fs `_lsdir` / `_iterdir`: the entries under `key/` (a delimiter
    /// listing, or a flat one with `delimiter = None`), sorted by name, files
    /// before directories of the same name.
    pub(crate) async fn lsdir(
        &self,
        st: &State,
        bucket: &str,
        key: &str,
        delimiter: Option<&str>,
        versions: bool,
        path: &str,
    ) -> Result<Vec<FileInfo>> {
        self.lsdir_stem(st, bucket, key, "", delimiter, versions, path)
            .await
    }

    /// [`Self::lsdir`] restricted to names starting with `key/stem` (s3fs's
    /// `prefix=` argument).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn lsdir_stem(
        &self,
        st: &State,
        bucket: &str,
        key: &str,
        stem: &str,
        delimiter: Option<&str>,
        versions: bool,
        path: &str,
    ) -> Result<Vec<FileInfo>> {
        let version_aware = self.inner.opts.version_aware;
        let mut prefix = if key.is_empty() {
            String::new()
        } else {
            format!("{}/", key.trim_start_matches('/'))
        };
        prefix.push_str(stem);
        let mut files = Vec::new();
        let mut dirs = Vec::new();
        self.list_pages(
            st,
            &ListRequest {
                bucket,
                prefix: &prefix,
                delimiter,
                versions: version_aware,
                ..ListRequest::default()
            },
            path,
            |page| {
                for p in &page.prefixes {
                    // s3fs drops the last character (the delimiter).
                    let k = match p.char_indices().last() {
                        Some((i, _)) => &p[..i],
                        None => "",
                    };
                    dirs.push(listed_dir_info(format!("{bucket}/{k}")));
                }
                for o in &page.objects {
                    if !version_aware || o.is_latest == Some(true) || versions {
                        files.push(object_info(bucket, o, versions));
                    }
                }
                ControlFlow::Continue(())
            },
        )
        .await?;
        files.extend(dirs);
        files.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(files)
    }

    pub(crate) async fn head_object(
        &self,
        st: &State,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        extra: Option<&Params>,
        path: &str,
    ) -> Result<ObjectMeta> {
        let mut call = Call::new(Op::HeadObject, Method::HEAD, path)
            .bucket(bucket)
            .key(key)
            .extra(extra);
        if let Some(v) = version_id {
            call = call.query("versionId", v);
        }
        st.client
            .execute(call, |resp| async move {
                ObjectMeta::from_headers(resp.headers(), path)
            })
            .await
    }

    /// The `LIST(prefix=key/, max-keys=1)` probe s3fs uses to tell a
    /// directory from a missing path.
    async fn dir_probe(&self, st: &State, bucket: &str, key: &str, path: &str) -> Result<bool> {
        let prefix = if key.is_empty() {
            String::new()
        } else {
            format!("{}/", key.trim_end_matches('/'))
        };
        let mut found = false;
        self.list_pages(
            st,
            &ListRequest {
                bucket,
                prefix: &prefix,
                delimiter: Some("/"),
                max_keys: Some(1),
                ..ListRequest::default()
            },
            path,
            |page| {
                found = page.key_count.is_some_and(|k| k > 0)
                    || !page.objects.is_empty()
                    || !page.prefixes.is_empty();
                ControlFlow::Break(())
            },
        )
        .await?;
        Ok(found)
    }

    /// `info()` of `bucket/key` (key non-empty): HEAD, then the directory
    /// probe on 404 — or both at once with `speculative_info`.
    async fn info_key(&self, st: &State, sp: &S3Path, path: &str) -> Result<FileInfo> {
        let name = format!("{}/{}", sp.bucket, sp.key);
        let head = self.head_object(
            st,
            &sp.bucket,
            &sp.key,
            sp.version_id.as_deref(),
            None,
            path,
        );
        let dir_name = name.clone();
        let probe = || async {
            match self.dir_probe(st, &sp.bucket, &sp.key, path).await {
                Ok(true) => Ok(dir_info(dir_name.clone())),
                Ok(false) => Err(Error::not_found(path)),
                Err(e) => Err(e),
            }
        };
        if self.inner.opts.speculative_info {
            // Race both requests: identical results, one round trip.
            let probe_fut = probe();
            tokio::pin!(head);
            tokio::pin!(probe_fut);
            let mut probe_result = None;
            let head_result = tokio::select! {
                h = &mut head => h,
                p = &mut probe_fut => {
                    probe_result = Some(p);
                    head.await
                }
            };
            return match head_result {
                Ok(m) => Ok(m.to_info(name)),
                Err(e) if e.kind() == ErrorKind::NotFound => match probe_result {
                    Some(p) => p,
                    None => probe_fut.await,
                },
                Err(e) => Err(e),
            };
        }
        match head.await {
            Ok(m) => Ok(m.to_info(name)),
            Err(e) if e.kind() == ErrorKind::NotFound => probe().await,
            Err(e) => Err(e),
        }
    }

    pub(crate) async fn info_impl(&self, path: &str) -> Result<FileInfo> {
        let p = strip_protocol(path);
        if p.is_empty() || p == "/" {
            return Ok(root_info(&p));
        }
        let sp = split_path(&p, self.inner.opts.version_aware);
        let st = self.state().await?;
        if sp.key.is_empty() {
            let call = Call::new(Op::HeadBucket, Method::HEAD, &p).bucket(&sp.bucket);
            st.client.execute(call, |_resp| async { Ok(()) }).await?;
            return Ok(bucket_info(&sp.bucket));
        }
        self.info_key(&st, &sp, &p).await
    }

    async fn list_buckets(&self, st: &State) -> Result<Vec<FileInfo>> {
        if self.inner.opts.anon {
            // Anonymous users cannot list buckets (s3fs returns nothing).
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut call = Call::new(Op::ListBuckets, Method::GET, "");
            if let Some(t) = &token {
                call = call.query("continuation-token", t.clone());
            }
            let res = st
                .client
                .execute(call, |resp| async move {
                    let body = resp.bytes().await?;
                    parse_list_buckets(&body)
                })
                .await;
            let (buckets, next) = match res {
                Ok(v) => v,
                // s3fs: a missing ListAllMyBuckets permission lists nothing.
                Err(e) if e.http_status().is_some() => {
                    tracing::debug!(error = %e, "ListBuckets failed; listing no buckets");
                    return Ok(Vec::new());
                }
                Err(e) => return Err(e),
            };
            out.extend(buckets.iter().map(listed_bucket_info));
            match next {
                Some(t) if Some(&t) != token.as_ref() => token = Some(t),
                _ => break,
            }
        }
        Ok(out)
    }

    pub(crate) async fn ls_impl(&self, path: &str) -> Result<Vec<FileInfo>> {
        let p = strip_protocol(path);
        let st = self.state().await?;
        if p.is_empty() || p == "/" {
            return self.list_buckets(&st).await;
        }
        let sp = split_path(&p, self.inner.opts.version_aware);
        let files = self
            .lsdir(&st, &sp.bucket, &sp.key, Some("/"), false, &p)
            .await?;
        if !files.is_empty() || !p.contains('/') {
            return Ok(files);
        }
        // s3fs lists the parent and keeps the entry named `path` that is not
        // a directory. The first key of a listing with `prefix=key` is that
        // entry if it exists, so one bounded request finds the same entry.
        let lookup = self.entry_lookup(&st, &sp, &p).await.unwrap_or_default();
        let files: Vec<FileInfo> = lookup
            .into_iter()
            .filter(|o| o.name.trim_end_matches('/') == p && !o.is_dir())
            .collect();
        if files.is_empty() {
            return Err(Error::not_found(p));
        }
        Ok(files)
    }

    /// The listing entry for exactly `bucket/key`, if any.
    async fn entry_lookup(&self, st: &State, sp: &S3Path, path: &str) -> Result<Vec<FileInfo>> {
        let version_aware = self.inner.opts.version_aware;
        let mut out = Vec::new();
        let key = sp.key.trim_start_matches('/');
        self.list_pages(
            st,
            &ListRequest {
                bucket: &sp.bucket,
                prefix: key,
                delimiter: Some("/"),
                versions: version_aware,
                max_keys: Some(1),
                ..ListRequest::default()
            },
            path,
            |page| {
                for o in &page.objects {
                    if !version_aware || o.is_latest == Some(true) {
                        out.push(object_info(&sp.bucket, o, false));
                    }
                }
                ControlFlow::Break(())
            },
        )
        .await?;
        Ok(out)
    }

    pub(crate) async fn find_impl(&self, path: &str, opts: &FindOptions) -> Result<Vec<FileInfo>> {
        let p = strip_protocol(path);
        let sp = split_path(&p, self.inner.opts.version_aware);
        if sp.bucket.is_empty() {
            return Err(Error::invalid_input("Cannot traverse all of S3"));
        }
        // s3fs: `if maxdepth:` — 0 means unlimited.
        if let Some(depth) = opts.maxdepth.filter(|d| *d > 0) {
            return self
                .walk_find(&format!("{}/{}", sp.bucket, sp.key), depth, opts.withdirs)
                .await;
        }
        let st = self.state().await?;
        let mut out = self
            .lsdir(&st, &sp.bucket, &sp.key, None, false, &p)
            .await?;
        if out.is_empty() && !sp.key.is_empty() {
            match self.info_impl(&p).await {
                Ok(i) => out.push(i),
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        // s3fs sets `o["Key"] = o["name"]` on every entry while inferring
        // directories (visible when the result came from `info`).
        for o in &mut out {
            let name = o.name.clone();
            o.set("Key", name);
        }
        if !opts.withdirs {
            return Ok(out);
        }
        let dirs = infer_dirs(&out, &p);
        out.extend(dirs);
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// fsspec's generic `_find` with `maxdepth` (s3fs delegates to it): a
    /// walk of delimiter listings, each level listed concurrently.
    async fn walk_find(
        &self,
        root: &str,
        maxdepth: usize,
        withdirs: bool,
    ) -> Result<Vec<FileInfo>> {
        let root = strip_protocol(root);
        let mut out: BTreeMap<String, FileInfo> = BTreeMap::new();
        if withdirs && !root.is_empty() && self.isdir(&root).await? {
            let i = self.info_impl(&root).await?;
            out.insert(root.clone(), i);
        }
        let conc = self.inner.opts.max_concurrency.max(1);
        let mut frontier = vec![root.clone()];
        let mut depth = 0usize;
        while !frontier.is_empty() && depth < maxdepth {
            depth += 1;
            let dirs = std::mem::take(&mut frontier);
            let listings: Vec<(String, Result<Vec<FileInfo>>)> =
                stream::iter(dirs.into_iter().map(|d| async move {
                    let r = self.ls_impl(&d).await;
                    (d, r)
                }))
                .buffer_unordered(conc)
                .collect()
                .await;
            for (dir, listing) in listings {
                // fsspec's walk omits directories it cannot list.
                let Ok(listing) = listing else { continue };
                let mut files: BTreeMap<String, FileInfo> = BTreeMap::new();
                let mut subdirs: BTreeMap<String, (String, FileInfo)> = BTreeMap::new();
                for info in listing {
                    let pathname = info.name.trim_end_matches('/').to_owned();
                    let base = pathname.rsplit('/').next().unwrap_or("").to_owned();
                    if info.is_dir() && pathname != dir {
                        subdirs.insert(base, (pathname, info));
                    } else if pathname == dir {
                        files.insert(String::new(), info);
                    } else {
                        files.insert(base, info);
                    }
                }
                for (full, _) in subdirs.values() {
                    frontier.push(full.clone());
                }
                if withdirs {
                    for (base, (_, info)) in subdirs {
                        files.insert(base, info);
                    }
                }
                for (_, info) in files {
                    out.insert(info.name.clone(), info);
                }
            }
        }
        if out.is_empty() {
            match self.info_impl(&root).await {
                Ok(i) if i.is_file() => {
                    out.insert(root.clone(), i);
                }
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out.into_values().collect())
    }

    /// s3fs `_isdir` (without its listings cache).
    pub(crate) async fn isdir(&self, path: &str) -> Result<bool> {
        let p = strip_protocol(path);
        let p = p.trim_matches('/');
        if p.is_empty() {
            return Ok(true);
        }
        let sp = split_path(p, self.inner.opts.version_aware);
        let st = self.state().await?;
        match self
            .lsdir(&st, &sp.bucket, &sp.key, Some("/"), false, p)
            .await
        {
            Ok(v) => Ok(!p.contains('/') || !v.is_empty()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub(crate) async fn exists_impl(&self, path: &str) -> Result<bool> {
        if path.is_empty() || path == "/" {
            return Ok(true);
        }
        let p = strip_protocol(path);
        let sp = split_path(&p, self.inner.opts.version_aware);
        if sp.bucket.is_empty() {
            return Ok(true);
        }
        if !sp.key.is_empty() {
            return match self.info_impl(&p).await {
                Ok(_) => Ok(true),
                Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
                Err(e) => Err(e),
            };
        }
        let st = self.state().await?;
        // s3fs probes HeadBucket, then GetBucketLocation (and a one-key
        // listing for requester-pays buckets); any failure means "no".
        let head = Call::new(Op::HeadBucket, Method::HEAD, &p).bucket(&sp.bucket);
        if st.client.execute(head, |_r| async { Ok(()) }).await.is_ok() {
            return Ok(true);
        }
        let loc = Call::new(Op::GetBucketLocation, Method::GET, &p)
            .bucket(&sp.bucket)
            .query("location", "");
        if st
            .client
            .execute(loc, |r| async move { r.bytes().await.map(|_| ()) })
            .await
            .is_ok()
        {
            return Ok(true);
        }
        if self.inner.opts.requester_pays {
            let found = self
                .list_pages(
                    &st,
                    &ListRequest {
                        bucket: &sp.bucket,
                        max_keys: Some(1),
                        ..ListRequest::default()
                    },
                    &p,
                    |_| ControlFlow::Break(()),
                )
                .await
                .is_ok();
            return Ok(found);
        }
        Ok(false)
    }

    /// All versions of objects under `path` (s3fs `object_version_info`):
    /// one entry per version, named with a `?versionId=` suffix. Requires
    /// `version_aware`.
    pub async fn object_versions(&self, path: &str) -> Result<Vec<FileInfo>> {
        if !self.inner.opts.version_aware {
            return Err(Error::invalid_input(
                "version specific functionality is disabled for non-version aware filesystems",
            ));
        }
        let sp = split_path(path, true);
        let st = self.state().await?;
        let mut out = Vec::new();
        let p = sp.full();
        self.list_pages(
            &st,
            &ListRequest {
                bucket: &sp.bucket,
                prefix: &sp.key,
                versions: true,
                ..ListRequest::default()
            },
            &p,
            |page| {
                out.extend(
                    page.objects
                        .iter()
                        .map(|o| object_info(&sp.bucket, o, true)),
                );
                ControlFlow::Continue(())
            },
        )
        .await?;
        Ok(out)
    }

    /// s3fs `ls(path, versions=True)`: every version of the entries under
    /// `path`, named with `?versionId=` suffixes. Requires `version_aware`.
    pub async fn ls_versions(&self, path: &str) -> Result<Vec<FileInfo>> {
        if !self.inner.opts.version_aware {
            return Err(Error::invalid_input(
                "versions cannot be specified if the filesystem is not version aware",
            ));
        }
        let p = strip_protocol(path);
        let sp = split_path(&p, true);
        let st = self.state().await?;
        self.lsdir(&st, &sp.bucket, &sp.key, Some("/"), true, &p)
            .await
    }
}

/// The directories s3fs's `_find(withdirs=True)` infers from a flat listing:
/// every ancestor of every entry that is at least as long as `path` (so the
/// root itself is included when it is below the bucket, but never the
/// bucket).
pub(crate) fn infer_dirs(out: &[FileInfo], path: &str) -> Vec<FileInfo> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut dirs = Vec::new();
    for o in out {
        let mut par = match o.name.rsplit_once('/') {
            Some((p, _)) => p.to_owned(),
            None => o.name.clone(),
        };
        while par.contains('/') {
            if !seen.insert(par.clone()) {
                // Ancestors of a seen directory were seen with it.
                break;
            }
            if path.len() <= par.len() {
                dirs.push(listed_dir_info(par.clone()));
            }
            par = match par.rsplit_once('/') {
                Some((p, _)) => p.to_owned(),
                None => break,
            };
        }
    }
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[FileInfo]) -> Vec<&str> {
        v.iter().map(|i| i.name.as_str()).collect()
    }

    #[test]
    fn inferred_dirs_match_s3fs() {
        let files: Vec<FileInfo> = [
            "b/a/b/c.txt",
            "b/a/x.txt",
            "b/emptydir/",
            "b/top.txt",
            "b/d//double",
        ]
        .iter()
        .map(|n| FileInfo::file(*n, 1))
        .collect();
        let mut d = infer_dirs(&files, "b");
        d.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(names(&d), vec!["b/a", "b/a/b", "b/d", "b/d/", "b/emptydir"]);
        let sub: Vec<FileInfo> = ["b/a/b/c.txt", "b/a/x.txt"]
            .iter()
            .map(|n| FileInfo::file(*n, 1))
            .collect();
        let mut d = infer_dirs(&sub, "b/a");
        d.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(names(&d), vec!["b/a", "b/a/b"]);
        // A file root: its parent is shorter than the path.
        assert!(infer_dirs(&[FileInfo::file("b/a/x", 1)], "b/a/x").is_empty());
    }
}
