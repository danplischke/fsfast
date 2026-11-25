//! Metadata and listings with gcsfs semantics: `info`, `ls`, `find`.
//!
//! * `info(bucket/key)` sends the object `GET` and a one-entry delimited
//!   listing of `key/` concurrently (gcsfs `_info`), so files and
//!   directories both cost one round trip. A file wins over a directory of
//!   the same name; a directory marker (`key/`, empty) counts as a
//!   directory. An object `GET` refused with 403 falls back to a listing
//!   (gcsfs: for users with `storage.objects.list` only).
//! * `info(bucket)` is the bucket resource (`GET b/{bucket}`); without
//!   permission for it, a non-empty listing still makes it a directory.
//! * `ls` is a delimited listing (1000 entries per page) of `key/`; implied
//!   directories come from `prefixes`, a listed directory's own marker
//!   becomes an entry for the directory itself (as gcsfs reports it), and
//!   listing a file returns the file. `ls("")` lists the project's buckets.
//! * `find` is one flat listing of `key/` (or of `key` when that is a
//!   file), with the directories derived from the object names.

use std::collections::{BTreeMap, BTreeSet};

use fsfast_core::{Error, ErrorKind, FileInfo, FindOptions, Result};
use fsfast_http_transport::Method;
use serde_json::{Map, Value as Json};

use crate::GCSFileSystem;
use crate::client::Query;
use crate::info::{bucket_info, find_dir, is_directory_marker, object_info, pseudo_dir};
use crate::path::{check_object_name, parent, split_path, strip_protocol};

/// Entries per listing request (the JSON API's maximum).
pub(crate) const PAGE_SIZE: usize = 1000;

/// One page of `objects.list`.
#[derive(Debug, Default)]
pub(crate) struct Page {
    pub items: Vec<FileInfo>,
    pub prefixes: Vec<String>,
    pub next: Option<String>,
}

/// Parameters of a listing.
#[derive(Debug, Clone, Default)]
pub(crate) struct ListArgs<'a> {
    pub prefix: Option<&'a str>,
    pub delimiter: Option<&'a str>,
    pub versions: bool,
    /// Stop after this many entries (items + prefixes).
    pub limit: Option<usize>,
    /// A JSON API `fields` selection, for listings that only need to know
    /// what exists (the full resources are ~1 KiB per object).
    pub fields: Option<&'a str>,
}

/// `fields` of existence probes: names and sizes (enough to tell a
/// directory marker from an object) and the prefixes.
const PROBE_FIELDS: &str = "items(name,size),prefixes,nextPageToken";

fn parse_page(bucket: &str, mut m: Map<String, Json>) -> Result<Page> {
    let mut page = Page::default();
    if let Some(Json::Array(items)) = m.remove("items") {
        page.items.reserve(items.len());
        for it in items {
            match it {
                Json::Object(o) => page.items.push(object_info(bucket, o)?),
                _ => return Err(Error::protocol("listing item is not an object")),
            }
        }
    }
    if let Some(Json::Array(prefixes)) = m.remove("prefixes") {
        page.prefixes = prefixes
            .into_iter()
            .filter_map(|p| match p {
                Json::String(s) => Some(s),
                _ => None,
            })
            .collect();
    }
    page.next = match m.remove("nextPageToken") {
        Some(Json::String(t)) if !t.is_empty() => Some(t),
        _ => None,
    };
    Ok(page)
}

impl GCSFileSystem {
    /// One `objects.list` request.
    pub(crate) async fn list_page(
        &self,
        bucket: &str,
        args: &ListArgs<'_>,
        max_results: usize,
        token: Option<&str>,
    ) -> Result<Page> {
        let c = &self.inner.client;
        let mut q = Query::new();
        q.opt("delimiter", args.delimiter.filter(|d| !d.is_empty()))
            .opt("prefix", args.prefix.filter(|p| !p.is_empty()))
            .push("maxResults", &max_results.to_string())
            .opt("pageToken", token)
            .opt("fields", args.fields);
        if args.versions {
            q.push("versions", "true");
        }
        let url = format!("{}/o", c.bucket_url(bucket));
        let req = c
            .request(Method::GET, &url, &q)?
            .op(fsfast_engine::stats::OpKind::List)
            .path(bucket.to_owned());
        let m = c.json(req).await?;
        parse_page(bucket, m)
    }

    /// Every page of a listing (or up to `args.limit` entries).
    pub(crate) async fn list_all(
        &self,
        bucket: &str,
        args: &ListArgs<'_>,
    ) -> Result<(Vec<FileInfo>, Vec<String>)> {
        let mut items = Vec::new();
        let mut prefixes = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let got = items.len() + prefixes.len();
            let want = match args.limit {
                Some(l) if got >= l => break,
                Some(l) => (l - got).min(PAGE_SIZE),
                None => PAGE_SIZE,
            };
            let page = self.list_page(bucket, args, want, token.as_deref()).await?;
            items.extend(page.items);
            prefixes.extend(page.prefixes);
            match page.next {
                Some(t) => token = Some(t),
                None => break,
            }
        }
        Ok((items, prefixes))
    }

    /// `GET b/{bucket}/o/{key}` (gcsfs `_get_object`), falling back to a
    /// listing when the GET is forbidden.
    pub(crate) async fn get_object(
        &self,
        bucket: &str,
        key: &str,
        generation: Option<&str>,
    ) -> Result<FileInfo> {
        let name = format!("{bucket}/{key}");
        if key.is_empty() {
            // gcsfs `_get_object`: a bucket root is not an object (and
            // `GET b/{bucket}/o/` would be a listing).
            return Err(Error::not_found(bucket.to_owned()));
        }
        check_object_name(key, &name)?;
        let c = &self.inner.client;
        let q = Query::new().with_opt("generation", generation);
        let req = c
            .request(Method::GET, &c.object_url(bucket, key), &q)?
            .op(fsfast_engine::stats::OpKind::Info)
            .path(name.clone());
        match c.json(req).await {
            Ok(m) => object_info(bucket, m),
            Err(e) if e.kind() == ErrorKind::PermissionDenied && e.http_status() == Some(403) => {
                let args = ListArgs {
                    prefix: Some(key),
                    versions: generation.is_some(),
                    limit: generation.is_none().then_some(1),
                    ..ListArgs::default()
                };
                let (items, _) = self.list_all(bucket, &args).await?;
                items
                    .into_iter()
                    .find(|i| {
                        i.name == name && generation.is_none_or(|g| i.version.as_deref() == Some(g))
                    })
                    .ok_or_else(|| Error::not_found(name))
            }
            Err(e) => Err(e),
        }
    }

    pub(crate) async fn info_impl(&self, path: &str) -> Result<FileInfo> {
        let p = strip_protocol(path).trim_end_matches('/');
        if p.is_empty() {
            return Ok(FileInfo::directory(""));
        }
        if !p.contains('/') {
            return self.bucket_info(p).await;
        }
        let sp = split_path(p, self.inner.opts.version_aware);
        if sp.bucket.is_empty() {
            return Err(Error::not_found(p));
        }
        let name = sp.full();
        let obj = self.get_object(&sp.bucket, &sp.key, sp.generation.as_deref());
        let dir = self.dir_probe(&sp.bucket, &sp.key, &name);
        tokio::pin!(obj, dir);
        // The object GET decides first (an object shadows a directory of
        // the same name); the listing result is kept if it arrives earlier.
        let mut dir_res: Option<Result<DirProbe>> = None;
        let obj_res = loop {
            tokio::select! {
                r = &mut obj => break r,
                r = &mut dir, if dir_res.is_none() => dir_res = Some(r),
            }
        };
        let not_found = match obj_res {
            Ok(i) if !is_directory_marker(&i) => return Ok(i),
            Ok(_) => Error::not_found(name.clone()),
            Err(e) if e.kind() == ErrorKind::NotFound => e,
            Err(e) => return Err(e),
        };
        let probe = match dir_res {
            Some(r) => r,
            None => dir.await,
        }?;
        match probe {
            DirProbe::Exact(i) => Ok(i),
            DirProbe::Dir => Ok(pseudo_dir(&sp.bucket, name.clone())),
            DirProbe::Empty => Err(not_found),
        }
    }

    /// gcsfs `_get_directory_info`: one entry of the delimited listing of
    /// `key/`.
    async fn dir_probe(&self, bucket: &str, key: &str, name: &str) -> Result<DirProbe> {
        // gcsfs `_do_list_objects`: the bucket root lists everything.
        let prefix = if key.is_empty() {
            String::new()
        } else {
            format!("{}/", key.trim_end_matches('/'))
        };
        let args = ListArgs {
            prefix: Some(&prefix),
            delimiter: Some("/"),
            fields: Some(PROBE_FIELDS),
            ..ListArgs::default()
        };
        let page = self.list_page(bucket, &args, 1, None).await?;
        if page
            .items
            .iter()
            .any(|i| i.name.trim_end_matches('/') == name && !is_directory_marker(i))
        {
            // A non-empty object named `key/` (rare): gcsfs reports it, with
            // its full resource, which the probe did not ask for.
            return Ok(DirProbe::Exact(
                self.get_object(bucket, &prefix, None).await?,
            ));
        }
        if page.items.is_empty() && page.prefixes.is_empty() {
            Ok(DirProbe::Empty)
        } else {
            Ok(DirProbe::Dir)
        }
    }

    /// `info(bucket)`.
    async fn bucket_info(&self, bucket: &str) -> Result<FileInfo> {
        let c = &self.inner.client;
        let req = c
            .request(Method::GET, &c.bucket_url(bucket), &Query::new())?
            .op(fsfast_engine::stats::OpKind::Info)
            .path(bucket.to_owned());
        match c.json(req).await {
            Ok(m) => Ok(bucket_info(bucket.to_owned(), m)),
            // A missing bucket: gcsfs lists it anyway, which fails the same
            // way; skip that request.
            Err(e) if e.kind() == ErrorKind::NotFound => Err(e.with_path(bucket)),
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                let args = ListArgs {
                    limit: Some(1),
                    delimiter: Some("/"),
                    fields: Some(PROBE_FIELDS),
                    ..ListArgs::default()
                };
                let (items, prefixes) = self.list_all(bucket, &args).await?;
                if items.is_empty() && prefixes.is_empty() {
                    Err(Error::not_found(bucket))
                } else {
                    Ok(FileInfo::directory(bucket))
                }
            }
            Err(e) => Err(e),
        }
    }

    /// The project's buckets, named `bucket/` like gcsfs's `ls("")`.
    pub(crate) async fn list_buckets(&self) -> Result<Vec<FileInfo>> {
        let c = &self.inner.client;
        let project = c.project().await?.unwrap_or_default();
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let q = Query::new()
                .with("project", &project)
                .with_opt("pageToken", token.as_deref());
            let req = c
                .request(Method::GET, &c.buckets_url(), &q)?
                .op(fsfast_engine::stats::OpKind::List)
                .path(String::new());
            let mut m = c.json(req).await?;
            if let Some(Json::Array(items)) = m.remove("items") {
                for it in items {
                    if let Json::Object(o) = it {
                        let name = o
                            .get("name")
                            .and_then(Json::as_str)
                            .unwrap_or_default()
                            .to_owned();
                        out.push(bucket_info(format!("{name}/"), o));
                    }
                }
            }
            match m.remove("nextPageToken") {
                Some(Json::String(t)) if !t.is_empty() => token = Some(t),
                _ => break,
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    pub(crate) async fn ls_impl(&self, path: &str) -> Result<Vec<FileInfo>> {
        let p = strip_protocol(path).trim_end_matches('/');
        if p.is_empty() {
            return self.list_buckets().await;
        }
        let sp = split_path(p, self.inner.opts.version_aware);
        if !sp.key.is_empty() {
            check_object_name(&sp.key, p)?;
        }
        let prefix = if sp.key.is_empty() {
            String::new()
        } else {
            format!("{}/", sp.key.trim_end_matches('/'))
        };
        let args = ListArgs {
            prefix: Some(&prefix),
            delimiter: Some("/"),
            ..ListArgs::default()
        };
        let (items, prefixes) = self.list_all(&sp.bucket, &args).await?;
        if items.is_empty() && prefixes.is_empty() {
            if sp.key.is_empty() {
                return Ok(Vec::new());
            }
            // Listing a file returns the file (or NotFound).
            return Ok(vec![
                self.get_object(&sp.bucket, &sp.key, sp.generation.as_deref())
                    .await?,
            ]);
        }
        let listed = p.to_owned();
        let mut out = Vec::with_capacity(items.len() + prefixes.len());
        let mut dir_names = BTreeSet::new();
        let dirs = prefixes.iter().map(|pre| {
            pseudo_dir(
                &sp.bucket,
                format!("{}/{}", sp.bucket, pre.trim_matches('/')),
            )
        });
        for entry in dirs.chain(items) {
            let entry = if is_directory_marker(&entry) {
                pseudo_dir(&sp.bucket, listed.clone())
            } else {
                entry
            };
            if entry.is_dir() && !dir_names.insert(entry.name.clone()) {
                continue;
            }
            out.push(entry);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    pub(crate) async fn find_impl(&self, path: &str, opts: &FindOptions) -> Result<Vec<FileInfo>> {
        if opts.maxdepth == Some(0) {
            return Err(Error::invalid_input("maxdepth must be at least 1"));
        }
        let p = strip_protocol(path);
        let sp = split_path(p, self.inner.opts.version_aware);
        if sp.bucket.is_empty() {
            return Err(Error::invalid_input("find needs a bucket"));
        }
        if !sp.key.is_empty() {
            check_object_name(&sp.key, p)?;
        }
        // As a directory first, then as a file.
        let dir_prefix = if sp.key.is_empty() {
            String::new()
        } else {
            format!("{}/", sp.key.trim_end_matches('/'))
        };
        let args = ListArgs {
            prefix: Some(&dir_prefix),
            ..ListArgs::default()
        };
        let (mut objects, _) = self.list_all(&sp.bucket, &args).await?;
        if objects.is_empty() && !sp.key.is_empty() {
            let args = ListArgs {
                prefix: Some(&sp.key),
                ..ListArgs::default()
            };
            objects = self.list_all(&sp.bucket, &args).await?.0;
        }
        let root = p.trim_end_matches('/');
        let root_slash = format!("{root}/");
        objects.retain(|o| o.name.starts_with(&root_slash) || o.name == p);

        let mut dirs: BTreeMap<String, FileInfo> = BTreeMap::new();
        if opts.withdirs {
            for o in &objects {
                let mut par = parent(&o.name);
                while !par.is_empty() && par.len() >= root.len() {
                    if dirs.contains_key(par) {
                        // Its ancestors were added with it.
                        break;
                    }
                    let key = split_path(par, false).key;
                    if !key.is_empty() {
                        dirs.insert(par.to_owned(), find_dir(par.to_owned(), &key));
                    }
                    par = parent(par);
                }
            }
        }
        let mut out = objects;
        out.extend(dirs.into_values());
        if let Some(maxdepth) = opts.maxdepth {
            let depth = root.matches('/').count() + maxdepth;
            out.retain(|o| o.name.matches('/').count() <= depth);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}

/// Outcome of the directory half of `info`.
enum DirProbe {
    /// A non-marker object named `key/` (gcsfs returns it).
    Exact(FileInfo),
    /// Something below `key/`.
    Dir,
    /// Nothing.
    Empty,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pages() {
        let Json::Object(m) = json!({
            "kind": "storage#objects",
            "items": [{"name": "a/b", "size": "1"}],
            "prefixes": ["a/c/"],
            "nextPageToken": "tok",
        }) else {
            unreachable!()
        };
        let p = parse_page("bk", m).unwrap();
        assert_eq!(p.items[0].name, "bk/a/b");
        assert_eq!(p.prefixes, vec!["a/c/"]);
        assert_eq!(p.next.as_deref(), Some("tok"));
        let Json::Object(m) = json!({"kind": "storage#objects"}) else {
            unreachable!()
        };
        let p = parse_page("bk", m).unwrap();
        assert!(p.items.is_empty() && p.prefixes.is_empty() && p.next.is_none());
        let Json::Object(m) = json!({"items": [1]}) else {
            unreachable!()
        };
        assert!(parse_page("bk", m).is_err());
    }
}
