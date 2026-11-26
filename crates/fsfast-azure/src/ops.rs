//! Metadata and namespace operations with adlfs semantics: `info`, `ls`,
//! `find`, `mkdir`, `rmdir`, `rm`, `cp_file`, `sign`.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant, SystemTime};

use fsfast_core::{Error, ErrorKind, FileInfo, FindOptions, Result, path as fpath};
use fsfast_engine::stats::OpKind;
use fsfast_http_transport::Method;
use fsfast_http_transport::header::{HeaderName, HeaderValue};
use futures::{StreamExt, stream};

use crate::AzureBlobFileSystem;
use crate::auth::sas::BlobSas;
use crate::auth::{API_VERSION, SharedKey};
use crate::client::Query;
use crate::info::{BlobProps, ContainerProps, prefix_dir, root_info, synthetic_dir};
use crate::list::{ListBlobs, ListEntry};
use crate::path::{BlobPath, split_dir_path, split_path};

/// How long `cp_file` waits for a pending (asynchronous) copy.
const COPY_TIMEOUT: Duration = Duration::from_secs(3600);

impl AzureBlobFileSystem {
    /// Get Blob Properties.
    pub(crate) async fn head_blob(
        &self,
        container: &str,
        blob: &str,
        version: Option<&str>,
        path: &str,
    ) -> Result<BlobProps> {
        let q = Query::new().with_opt("versionid", version);
        let req = self
            .sh
            .client
            .request(Method::HEAD, &self.sh.client.blob_url(container, blob), &q)?
            .op(OpKind::Info)
            .path(path.to_owned());
        let head = self.sh.client.send_headers(req).await?;
        BlobProps::from_headers(blob, &head.headers).map_err(|e| e.with_path(path))
    }

    /// Get Container Properties.
    pub(crate) async fn container_props(&self, container: &str) -> Result<ContainerProps> {
        let q = Query::new().with("restype", "container");
        let req = self
            .sh
            .client
            .request(Method::HEAD, &self.sh.client.container_url(container), &q)?
            .op(OpKind::Info)
            .path(container.to_owned());
        let head = self.sh.client.send_headers(req).await?;
        Ok(ContainerProps::from_headers(container, &head.headers))
    }

    /// adlfs `_dir_exists`: any blob under `blob/`.
    pub(crate) async fn dir_exists(&self, container: &str, blob: &str, path: &str) -> Result<bool> {
        let prefix = format!("{}/", blob.trim_end_matches('/'));
        let page = self
            .sh
            .client
            .list_blobs_page(
                &ListBlobs {
                    container,
                    prefix: &prefix,
                    max_results: Some(1),
                    path,
                    ..ListBlobs::default()
                },
                None,
            )
            .await;
        match page {
            Ok(p) => Ok(!p.entries.is_empty()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// adlfs `_container_exists` (honours `assume_container_exists`).
    pub(crate) async fn container_exists(&self, container: &str) -> Result<bool> {
        if self.sh.cfg.assume_container_exists == Some(true) {
            return Ok(true);
        }
        match self.container_props(container).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => match self.sh.cfg.assume_container_exists {
                None => {
                    tracing::warn!(
                        container,
                        error = %e,
                        "Failed to fetch container properties. Assume it exists already"
                    );
                    Ok(true)
                }
                _ => Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Failed to fetch container properties for {container} for {e}"),
                )
                .with_path(container)),
            },
        }
    }

    pub(crate) async fn info_impl(&self, path: &str) -> Result<FileInfo> {
        let p = split_dir_path(path, self.sh.cfg.version_aware);
        let full = p.full();
        if p.container.is_empty() {
            return Ok(root_info());
        }
        if p.blob.is_empty() {
            return match self.container_props(p.container).await {
                Ok(c) => Ok(c.to_info()),
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    Err(Error::new(ErrorKind::NotFound, "No such container")
                        .with_path(p.container)
                        .with_details_from(&e))
                }
                Err(e) => Err(e),
            };
        }
        match self
            .head_blob(p.container, p.blob, p.version_id, &full)
            .await
        {
            Ok(props) => Ok(props.to_info(p.container, self.sh.cfg.version_aware)),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if p.version_id.is_none() && self.dir_exists(p.container, p.blob, &full).await? {
                    Ok(prefix_dir(full))
                } else {
                    Err(Error::not_found(full).with_details_from(&e))
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Convert one level of a delimiter listing below `prefix` into infos:
    /// prefixes and marker blobs are directories (deduplicated by name,
    /// preferring the marker's properties), the `prefix/` marker itself is
    /// skipped.
    fn level_entries(
        &self,
        container: &str,
        prefix: &str,
        entries: Vec<ListEntry>,
    ) -> Vec<FileInfo> {
        let va = self.sh.cfg.version_aware;
        let mut out: Vec<FileInfo> = Vec::with_capacity(entries.len());
        let mut dir_index: BTreeMap<String, usize> = BTreeMap::new();
        for e in entries {
            let (info, from_blob) = match e {
                ListEntry::Prefix(n) => {
                    let name = format!("{container}/{}", n.trim_end_matches('/'));
                    (prefix_dir(name), false)
                }
                ListEntry::Blob(b) => {
                    if b.name == prefix || b.name.trim_end_matches('/').is_empty() {
                        continue;
                    }
                    let mut i = b.to_info(container, va);
                    if b.name.ends_with('/') && i.is_file() {
                        i.file_type = fsfast_core::FileType::Directory;
                        i.size = 0;
                        i.set("size", fsfast_core::Value::Null);
                    }
                    (i, true)
                }
            };
            if info.name.is_empty() || info.name == container {
                continue;
            }
            if info.is_dir() {
                if let Some(&at) = dir_index.get(&info.name) {
                    if from_blob {
                        out[at] = info;
                    }
                    continue;
                }
                dir_index.insert(info.name.clone(), out.len());
            }
            out.push(info);
        }
        out
    }

    pub(crate) async fn ls_impl(&self, path: &str) -> Result<Vec<FileInfo>> {
        let p = split_dir_path(path, self.sh.cfg.version_aware);
        let full = p.full();
        if p.container.is_empty() {
            let cs = self.sh.client.list_containers_all().await?;
            return Ok(cs.iter().map(ContainerProps::to_info).collect());
        }
        if p.blob.is_empty() {
            let entries = self
                .sh
                .client
                .list_blobs_all(&ListBlobs {
                    container: p.container,
                    prefix: "",
                    delimiter: Some("/"),
                    max_results: self.sh.cfg.list_page_size,
                    path: &full,
                    ..ListBlobs::default()
                })
                .await
                .map_err(|e| not_found_as(e, &full))?;
            return Ok(self.level_entries(p.container, "", entries));
        }
        // The blob itself and its children, concurrently: a file wins (adlfs
        // `filter_blobs` returns the exact file), else the children.
        let prefix = format!("{}/", p.blob);
        let listing = ListBlobs {
            container: p.container,
            prefix: &prefix,
            delimiter: Some("/"),
            max_results: self.sh.cfg.list_page_size,
            path: &full,
            ..ListBlobs::default()
        };
        let (head, children) = futures::join!(
            self.head_blob(p.container, p.blob, p.version_id, &full),
            self.sh.client.list_blobs_all(&listing)
        );
        let head = match head {
            Ok(h) => Some(h),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        if let Some(h) = &head
            && !h.is_dir_marker()
        {
            // adlfs answers from the listing, where `deleted` is None.
            let mut i = h.to_info(p.container, self.sh.cfg.version_aware);
            i.set("deleted", fsfast_core::Value::Null);
            return Ok(vec![i]);
        }
        let children = match children {
            Ok(c) => c,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(Error::not_found(full).with_details_from(&e));
            }
            Err(e) => return Err(e),
        };
        let raw_nonempty = !children.is_empty();
        let out = self.level_entries(p.container, &prefix, children);
        if !out.is_empty() || raw_nonempty || head.is_some() {
            return Ok(out);
        }
        Err(Error::not_found(full))
    }

    pub(crate) async fn find_impl(&self, path: &str, opts: &FindOptions) -> Result<Vec<FileInfo>> {
        if opts.maxdepth == Some(0) {
            return Err(Error::invalid_input("maxdepth must be at least 1"));
        }
        let p = split_dir_path(path, self.sh.cfg.version_aware);
        if p.container.is_empty() {
            return self.find_account(opts).await;
        }
        let root = p.full();
        let va = self.sh.cfg.version_aware;
        let prefix = if p.blob.is_empty() {
            String::new()
        } else {
            format!("{}/", p.blob)
        };
        // One level is cheapest with a delimiter listing.
        let delimiter = (opts.maxdepth == Some(1)).then_some("/");
        let listing = ListBlobs {
            container: p.container,
            prefix: &prefix,
            delimiter,
            max_results: self.sh.cfg.list_page_size,
            path: &root,
            ..ListBlobs::default()
        };
        let head_fut = async {
            if p.blob.is_empty() {
                Ok(None)
            } else {
                match self
                    .head_blob(p.container, p.blob, p.version_id, &root)
                    .await
                {
                    Ok(h) => Ok(Some(h)),
                    Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(e),
                }
            }
        };
        let (head, listed) = futures::join!(head_fut, self.sh.client.list_blobs_all(&listing));
        let head = head?;
        if let Some(h) = &head
            && !h.is_dir_marker()
        {
            return Ok(vec![h.to_info(p.container, va)]);
        }
        let (entries, container_ok) = match listed {
            Ok(e) => (e, true),
            Err(e) if e.kind() == ErrorKind::NotFound => (Vec::new(), false),
            Err(e) => return Err(e),
        };
        let mut root_exists = (p.blob.is_empty() && container_ok) || head.is_some();
        let mut files: BTreeMap<String, FileInfo> = BTreeMap::new();
        let mut dirs: BTreeMap<String, FileInfo> = BTreeMap::new();
        for e in entries {
            match e {
                ListEntry::Prefix(n) => {
                    let name = format!("{}/{}", p.container, n.trim_end_matches('/'));
                    dirs.entry(name.clone()).or_insert_with(|| prefix_dir(name));
                }
                ListEntry::Blob(b) => {
                    if b.name == prefix {
                        // The directory's own marker.
                        root_exists = true;
                        continue;
                    }
                    let mut i = b.to_info(p.container, va);
                    if b.name.ends_with('/') && i.is_file() {
                        i.file_type = fsfast_core::FileType::Directory;
                        i.size = 0;
                        i.set("size", fsfast_core::Value::Null);
                    }
                    if i.is_dir() {
                        dirs.insert(i.name.clone(), i);
                    } else {
                        files.insert(i.name.clone(), i);
                    }
                }
            }
        }
        if !files.is_empty() || !dirs.is_empty() {
            root_exists = true;
        }
        // Intermediate directories (adlfs synthesises them with size 0).
        let names: Vec<String> = files.keys().chain(dirs.keys()).cloned().collect();
        for n in names {
            let mut cur = fpath::parent(&n);
            while cur.len() > root.len() && cur.starts_with(&root) {
                if dirs.contains_key(&cur) {
                    break;
                }
                dirs.insert(cur.clone(), synthetic_dir(cur.clone()));
                cur = fpath::parent(&cur);
            }
        }
        let depth_ok = |name: &str| match opts.maxdepth {
            None => true,
            Some(m) => fpath::depth_below(&root, name) <= m,
        };
        // A blob may share its name with a directory (`d/a` next to
        // `d/a/b`, legal in the flat namespace): both are returned, the
        // directory first. (adlfs keys its result by name and lets the
        // directory win with `withdirs`, the file without; fsfast's Python
        // layer always asks for directories and filters them itself, so
        // dropping the file here would lose it from `find`/`du`/`rm`. Name
        // -keyed consumers that keep the last entry keep the file.)
        let mut out: Vec<FileInfo> = files.into_values().filter(|i| depth_ok(&i.name)).collect();
        if opts.withdirs {
            out.extend(dirs.into_values().filter(|d| depth_ok(&d.name)));
            if root_exists {
                let root_info = match head {
                    Some(h) => h.to_info(p.container, va),
                    None => prefix_dir(root.clone()),
                };
                out.push(root_info);
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name).then(a.is_file().cmp(&b.is_file())));
        Ok(out)
    }

    /// `find("")`: every container.
    async fn find_account(&self, opts: &FindOptions) -> Result<Vec<FileInfo>> {
        let cs = self.sh.client.list_containers_all().await?;
        let sub = FindOptions {
            maxdepth: opts.maxdepth.map(|m| m - 1),
            withdirs: false,
        };
        let mut out = Vec::new();
        let conc = self.sh.cfg.max_concurrency;
        let withdirs = opts.withdirs;
        let futs: Vec<_> = cs
            .iter()
            .map(|c| {
                let name = c.name.clone();
                async move {
                    if sub.maxdepth == Some(0) {
                        return Ok(Vec::new());
                    }
                    self.find_impl(&name, &FindOptions { withdirs, ..sub })
                        .await
                }
            })
            .collect();
        let results: Vec<Result<Vec<FileInfo>>> = stream::iter(futs).buffered(conc).collect().await;
        for (c, r) in cs.iter().zip(results) {
            let mut v = r?;
            if opts.withdirs && !v.iter().any(|i| i.name == c.name) {
                out.push(c.to_info());
            }
            out.append(&mut v);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    pub(crate) async fn mkdir_impl(&self, path: &str, create_parents: bool) -> Result<()> {
        let p = split_dir_path(path, self.sh.cfg.version_aware);
        if p.container.is_empty() {
            return Err(Error::already_exists(""));
        }
        let exists = self.container_exists(p.container).await?;
        if !create_parents && !exists {
            return Err(Error::permission_denied(
                "Azure Container does not exist.  Set create_parents=True to create!!",
            )
            .with_path(p.container));
        }
        if !exists {
            self.create_container(p.container).await?;
        }
        Ok(())
    }

    /// Create Container (an existing one is not an error: adlfs checks
    /// first, and a concurrent creation is equivalent).
    pub(crate) async fn create_container(&self, container: &str) -> Result<()> {
        self.create_container_with_access(container, None).await
    }

    /// Create Container with `x-ms-blob-public-access` (`container` or
    /// `blob`), tolerating an existing container.
    pub async fn create_container_with_access(
        &self,
        container: &str,
        public: Option<&str>,
    ) -> Result<()> {
        let q = Query::new().with("restype", "container");
        let mut req = self
            .sh
            .client
            .request(Method::PUT, &self.sh.client.container_url(container), &q)?
            .op(OpKind::Write)
            .path(container.to_owned());
        if let Some(level) = public {
            req = req.header(
                HeaderName::from_static("x-ms-blob-public-access"),
                HeaderValue::from_str(level)
                    .map_err(|_| Error::invalid_input("invalid public access level"))?,
            );
        }
        match self.sh.client.send_headers(req).await {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Delete Container.
    pub(crate) async fn delete_container(&self, container: &str) -> Result<()> {
        let q = Query::new().with("restype", "container");
        let req = self
            .sh
            .client
            .request(Method::DELETE, &self.sh.client.container_url(container), &q)?
            .op(OpKind::Delete)
            .path(container.to_owned());
        self.sh.client.send_headers(req).await.map(|_| ())
    }

    pub(crate) async fn rmdir_impl(&self, path: &str) -> Result<()> {
        let p = split_dir_path(path, self.sh.cfg.version_aware);
        let full = p.full();
        if p.container.is_empty() {
            return Err(Error::permission_denied("cannot remove the account root"));
        }
        let full_ref = &full;
        let probe = |prefix: String| async move {
            self.sh
                .client
                .list_blobs_page(
                    &ListBlobs {
                        container: p.container,
                        prefix: &prefix,
                        max_results: Some(2),
                        path: full_ref,
                        ..ListBlobs::default()
                    },
                    None,
                )
                .await
        };
        if p.blob.is_empty() {
            // Deliberate difference from adlfs, which deletes a container
            // with everything in it: rmdir only removes empty containers.
            let page = probe(String::new()).await?;
            if !page.entries.is_empty() {
                return Err(
                    Error::new(ErrorKind::DirectoryNotEmpty, "container is not empty")
                        .with_path(full),
                );
            }
            return self.delete_container(p.container).await;
        }
        let prefix = format!("{}/", p.blob);
        let (head, page) = futures::join!(
            self.head_blob(p.container, p.blob, None, &full),
            probe(prefix.clone())
        );
        let page = page?;
        let mut slash_marker = false;
        for e in &page.entries {
            match e {
                ListEntry::Blob(b) if b.name == prefix => slash_marker = true,
                _ => {
                    return Err(
                        Error::new(ErrorKind::DirectoryNotEmpty, "directory not empty")
                            .with_path(full),
                    );
                }
            }
        }
        let marker = match head {
            Ok(h) if h.is_dir_marker() => true,
            Ok(_) => return Err(Error::not_a_directory(full)),
            Err(e) if e.kind() == ErrorKind::NotFound => false,
            Err(e) => return Err(e),
        };
        if !marker && !slash_marker {
            return Err(Error::not_found(full));
        }
        if marker {
            self.delete_blob(p.container, p.blob, None, &full).await?;
        }
        if slash_marker {
            self.delete_blob(p.container, &prefix, None, &full).await?;
        }
        Ok(())
    }

    /// Delete Blob.
    pub(crate) async fn delete_blob(
        &self,
        container: &str,
        blob: &str,
        version: Option<&str>,
        path: &str,
    ) -> Result<()> {
        let q = Query::new().with_opt("versionid", version);
        let req = self
            .sh
            .client
            .request(
                Method::DELETE,
                &self.sh.client.blob_url(container, blob),
                &q,
            )?
            .op(OpKind::Delete)
            .path(path.to_owned());
        self.sh.client.send_headers(req).await.map(|_| ())
    }

    pub(crate) async fn rm_file_impl(&self, path: &str) -> Result<()> {
        let p = split_path(path, self.sh.cfg.version_aware);
        let full = p.full();
        if p.blob.is_empty() {
            return Err(Error::is_a_directory(full));
        }
        self.delete_blob(p.container, p.blob, p.version_id, &full)
            .await
            .map_err(|e| {
                if e.kind() == ErrorKind::NotFound {
                    Error::not_found(path.to_owned()).with_details_from(&e)
                } else {
                    e
                }
            })
    }

    /// adlfs `_rm_files`: files (and markers of empty directories)
    /// concurrently, then markers of non-empty directories deepest first.
    pub(crate) async fn rm_files_impl(&self, paths: &[String]) -> Vec<Result<()>> {
        let names: Vec<String> = paths
            .iter()
            .map(|p| p.trim_end_matches('/').to_owned())
            .collect();
        let set: BTreeSet<&str> = names.iter().map(String::as_str).collect();
        // A name is a directory marker when another name lies below it. The
        // first name after `n/` in sort order tells (siblings like `n-x`
        // sort between `n` and `n/...`, so adjacent pairs are not enough).
        let markers: BTreeSet<&str> = set
            .iter()
            .copied()
            .filter(|n| {
                let below = format!("{n}/");
                set.range::<&str, _>(below.as_str()..)
                    .next()
                    .is_some_and(|m| m.starts_with(below.as_str()))
            })
            .collect();
        let conc = self.sh.cfg.max_concurrency.max(1);
        let mut out: Vec<Option<Result<()>>> = (0..paths.len()).map(|_| None).collect();
        let mut futs = Vec::new();
        for (i, n) in names.iter().enumerate() {
            if !markers.contains(n.as_str()) {
                let p = paths[i].as_str();
                futs.push(async move { (i, self.rm_file_impl(p).await) });
            }
        }
        let first: Vec<(usize, Result<()>)> =
            stream::iter(futs).buffer_unordered(conc).collect().await;
        for (i, r) in first {
            out[i] = Some(r);
        }
        let mut later: Vec<usize> = (0..names.len())
            .filter(|&i| markers.contains(names[i].as_str()))
            .collect();
        later.sort_by(|&a, &b| names[b].cmp(&names[a]));
        for i in later {
            out[i] = Some(self.rm_file_impl(&paths[i]).await);
        }
        out.into_iter().map(|r| r.unwrap_or(Ok(()))).collect()
    }

    /// The URL of `p` as a copy source (with the SAS when requests are SAS
    /// authorised, and `versionid`).
    fn copy_source(&self, p: &BlobPath<'_>) -> Result<String> {
        let mut url = self.sh.client.blob_url(p.container, p.blob);
        crate::client::check_url(&url).map_err(|e| e.with_path(p.full()))?;
        let mut q = Vec::new();
        if let Some(v) = p.version_id {
            q.push(format!("versionid={}", crate::path::quote(v, false)));
        }
        if let Some(sas) = self.sh.client.cred.sas() {
            q.push(sas.to_owned());
        }
        if !q.is_empty() {
            url.push('?');
            url.push_str(&q.join("&"));
        }
        Ok(url)
    }

    /// Copy Blob (server-side), waiting for a pending copy to finish.
    pub(crate) async fn cp_file_impl(&self, src: &str, dst: &str) -> Result<()> {
        let va = self.sh.cfg.version_aware;
        let s = split_path(src, va);
        let d = split_path(dst, va);
        if s.blob.is_empty() {
            return Err(Error::is_a_directory(s.full()));
        }
        if d.blob.is_empty() {
            return Err(Error::is_a_directory(d.full()));
        }
        let (sfull, dfull) = (s.full(), d.full());
        if s.container == d.container && s.blob == d.blob && s.version_id.is_none() {
            // Copying a blob onto itself would only reset its properties.
            return self
                .head_blob(s.container, s.blob, None, &sfull)
                .await
                .map(|_| ());
        }
        let source = self.copy_source(&s)?;
        let req = self
            .sh
            .client
            .request(
                Method::PUT,
                &self.sh.client.blob_url(d.container, d.blob),
                &Query::new(),
            )?
            .op(OpKind::Copy)
            .path(sfull.clone())
            .header(HeaderName::from_static("x-ms-copy-source"), {
                let mut v = HeaderValue::from_str(&source)
                    .map_err(|_| Error::invalid_input("invalid copy source URL"))?;
                // It can carry the SAS token: keep it out of HPACK tables.
                v.set_sensitive(true);
                v
            });
        let head = self.sh.client.send_headers(req).await.map_err(|e| {
            // A missing destination container is about `dst`; anything else
            // that is "not found" is about the source.
            let code_is = |c: &str| {
                e.details()
                    .iter()
                    .any(|x| matches!(x, fsfast_core::Detail::Code(k) if k == c))
            };
            if code_is("ContainerNotFound") {
                Error::not_found(dfull.clone()).with_details_from(&e)
            } else if e.kind() == ErrorKind::NotFound || code_is("CannotVerifyCopySource") {
                Error::not_found(sfull.clone()).with_details_from(&e)
            } else {
                e
            }
        })?;
        let mut status = head
            .header("x-ms-copy-status")
            .unwrap_or("success")
            .to_owned();
        let copy_id = head.header("x-ms-copy-id").map(str::to_owned);
        let started = Instant::now();
        let mut delay = Duration::from_millis(50);
        while status == "pending" {
            if started.elapsed() > COPY_TIMEOUT {
                return Err(Error::timeout("copy did not finish in time").with_path(dfull));
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(2));
            let q = Query::new();
            let req = self
                .sh
                .client
                .request(
                    Method::HEAD,
                    &self.sh.client.blob_url(d.container, d.blob),
                    &q,
                )?
                .op(OpKind::Info)
                .path(dfull.clone());
            let h = self.sh.client.send_headers(req).await?;
            if let (Some(want), Some(got)) = (&copy_id, h.header("x-ms-copy-id"))
                && want != got
            {
                return Err(Error::new(
                    ErrorKind::Io,
                    "the destination was replaced by another copy",
                )
                .with_path(dfull));
            }
            status = h.header("x-ms-copy-status").unwrap_or("success").to_owned();
            if status != "pending" && status != "success" {
                let desc = h
                    .header("x-ms-copy-status-description")
                    .unwrap_or("")
                    .to_owned();
                return Err(
                    Error::new(ErrorKind::Io, format!("copy {status}: {desc}")).with_path(dfull)
                );
            }
        }
        if status != "success" {
            return Err(Error::new(ErrorKind::Io, format!("copy {status}")).with_path(dfull));
        }
        Ok(())
    }

    /// ADLS Gen2 Path Rename (`PUT {dfs}/{fs}/{dst}?mode=legacy` with
    /// `x-ms-rename-source: /{fs}/{src}`): one atomic server-side move.
    pub(crate) fn dfs_rename_request(
        &self,
        src: &BlobPath<'_>,
        dst: &BlobPath<'_>,
    ) -> Result<fsfast_http_transport::Request> {
        let dfs = self.sh.cfg.dfs_endpoint.as_deref().ok_or_else(|| {
            Error::unsupported("hns rename without a DFS endpoint (set dfs_endpoint)")
        })?;
        let url = format!(
            "{dfs}/{}/{}",
            crate::path::quote(dst.container, false),
            crate::path::quote(dst.blob, true)
        );
        crate::client::check_url(&self.sh.client.blob_url(src.container, src.blob))
            .map_err(|e| e.with_path(src.full()))?;
        let source = format!(
            "/{}/{}",
            crate::path::quote(src.container, false),
            crate::path::quote(src.blob, true)
        );
        Ok(self
            .sh
            .client
            .request(Method::PUT, &url, &Query::new().with("mode", "legacy"))?
            .op(OpKind::Copy)
            .path(src.full())
            .header(
                HeaderName::from_static("x-ms-rename-source"),
                HeaderValue::from_str(&source)
                    .map_err(|_| Error::invalid_input("invalid rename source"))?,
            ))
    }

    /// `mv_file`: an atomic DFS rename on hierarchical-namespace accounts
    /// (`hns=True`), falling back to copy + delete when the endpoint does
    /// not support it; copy + delete otherwise (as adlfs).
    pub(crate) async fn mv_file_impl(&self, src: &str, dst: &str) -> Result<()> {
        let va = self.sh.cfg.version_aware;
        let (s, d) = (split_path(src, va), split_path(dst, va));
        if s.container == d.container && s.blob == d.blob && s.version_id == d.version_id {
            return Ok(());
        }
        if self.sh.cfg.hns && !s.blob.is_empty() && !d.blob.is_empty() && s.version_id.is_none() {
            let req = self.dfs_rename_request(&s, &d)?;
            match self.sh.client.send_headers(req).await {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == ErrorKind::Unsupported => {
                    tracing::debug!(error = %e, "DFS rename unsupported; copying instead");
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    return Err(Error::not_found(s.full()).with_details_from(&e));
                }
                Err(e) => return Err(e),
            }
        }
        self.cp_file_impl(src, dst).await?;
        self.rm_file_impl(src).await
    }

    /// adlfs `sign` / `url`: a read-only blob SAS signed with the account
    /// key.
    pub(crate) fn sign_impl(&self, path: &str, expires: Duration) -> Result<String> {
        let p = split_path(path, self.sh.cfg.version_aware);
        if p.blob.is_empty() {
            return Err(Error::invalid_input("sign needs a blob path"));
        }
        let Some((account, key)) = &self.sh.cfg.signing_key else {
            return Err(Error::invalid_input(
                "sign requires an account key (account_key or a connection string with AccountKey)",
            ));
        };
        let key = SharedKey::new(account.clone(), key)?;
        let sas = BlobSas {
            container: p.container,
            blob: p.blob,
            permission: "r",
            expiry: Some(SystemTime::now() + expires),
            version: API_VERSION,
            version_id: p.version_id,
            ..BlobSas::default()
        };
        let (_, token) = sas.sign(&key);
        // The primary endpoint, like the SDK's `BlobClient.url`.
        let url = format!(
            "{}/{}/{}",
            self.sh.cfg.endpoint,
            crate::path::quote(p.container, false),
            crate::path::quote(p.blob, true)
        );
        crate::client::check_url(&url).map_err(|e| e.with_path(p.full()))?;
        // A version SAS (`sr=bv`) only authorizes requests for that version,
        // so the URL must name it.
        match p.version_id {
            Some(v) => Ok(format!(
                "{url}?versionid={}&{token}",
                crate::path::quote(v, false)
            )),
            None => Ok(format!("{url}?{token}")),
        }
    }
}

/// A listing's "container not found" reported for the listed path.
fn not_found_as(e: Error, path: &str) -> Error {
    if e.kind() == ErrorKind::NotFound {
        Error::not_found(path.to_owned()).with_details_from(&e)
    } else {
        e
    }
}

/// Copy HTTP/code details from another error.
pub(crate) trait WithDetails {
    fn with_details_from(self, other: &Error) -> Self;
}

impl WithDetails for Error {
    fn with_details_from(mut self, other: &Error) -> Self {
        for d in other.details() {
            self = self.with_detail(d.clone());
        }
        self
    }
}
