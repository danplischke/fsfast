//! Deletes, copies, buckets and pre-signed URLs.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use fsfast_core::{Error, ErrorKind, Result, path as fspath};
use fsfast_http_transport::Method;
use fsfast_http_transport::header::HeaderMap;
use futures::{StreamExt, stream};

use crate::client::Call;
use crate::error::{classify, response_error};
use crate::list::ListRequest;
use crate::params::Op;
use crate::path::{split_path, strip_protocol};
use crate::sigv4::MAX_PRESIGN_EXPIRES;
use crate::write::{MAX_PART, MAX_PARTS, S3PartSinkBuilder, copy_source, preserved_headers};
use crate::xml::{
    DeleteOutcome, DeleteTarget, create_bucket_body, delete_objects_body, parse_delete_result,
    parse_result_etag,
};
use crate::{S3FileSystem, State};

/// Keys per `DeleteObjects` request (the S3 maximum).
const DELETE_BATCH: usize = 1000;
/// `DeleteObjects` requests in flight (s3fs: 3).
const DELETE_CONCURRENCY: usize = 16;
/// Existence checks by listing need at least this many keys to beat HEADs.
const LIST_CHECK_MIN: usize = 32;

/// The result of an existence check of one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    File,
    Directory,
    Missing,
}

impl S3FileSystem {
    /// Whether `bucket/key` exists as an object, a directory (prefix), or
    /// not at all.
    async fn presence(&self, st: &State, bucket: &str, key: &str, path: &str) -> Result<Presence> {
        match self.head_object(st, bucket, key, None, None, path).await {
            Ok(_) => Ok(Presence::File),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if self.prefix_has_keys(st, bucket, key, path).await? {
                    Ok(Presence::Directory)
                } else {
                    Ok(Presence::Missing)
                }
            }
            Err(e) => Err(e),
        }
    }

    async fn prefix_has_keys(
        &self,
        st: &State,
        bucket: &str,
        key: &str,
        path: &str,
    ) -> Result<bool> {
        let prefix = format!("{}/", key.trim_end_matches('/'));
        let mut found = false;
        match self
            .list_pages(
                st,
                &ListRequest {
                    bucket,
                    prefix: &prefix,
                    max_keys: Some(1),
                    ..ListRequest::default()
                },
                path,
                |page| {
                    found = !page.objects.is_empty() || !page.prefixes.is_empty();
                    ControlFlow::Break(())
                },
            )
            .await
        {
            Ok(()) => Ok(found),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub(crate) async fn rm_file_impl(&self, path: &str) -> Result<()> {
        let sp = split_path(path, self.inner.opts.version_aware);
        if sp.key.is_empty() {
            return Err(Error::is_a_directory(path)
                .with_detail(fsfast_core::Detail::Code("bucket (use rmdir)".into())));
        }
        let st = self.state().await?;
        let name = sp.full();
        if self.inner.opts.strict_delete {
            match self.presence(&st, &sp.bucket, &sp.key, &name).await? {
                Presence::File => {}
                Presence::Directory => return Err(Error::is_a_directory(name)),
                Presence::Missing => return Err(Error::not_found(name)),
            }
        }
        self.delete_object(&st, &sp.bucket, &sp.key, &name).await
    }

    async fn delete_object(&self, st: &State, bucket: &str, key: &str, path: &str) -> Result<()> {
        let call = Call::new(Op::DeleteObject, Method::DELETE, path)
            .bucket(bucket)
            .key(key);
        st.client.execute(call, |_| async { Ok(()) }).await
    }

    /// Which of `keys` (sorted, unique) exist, decided by listing the key
    /// range they span: a few `LIST` pages instead of one `HEAD` per key for
    /// the usual dense batches (`rm` of a directory tree). Keys the listing
    /// did not reach within its page budget are left undecided (`None`).
    async fn list_presence(
        &self,
        st: &State,
        bucket: &str,
        keys: &[String],
        path: &str,
    ) -> Result<Vec<Option<bool>>> {
        let mut decided: Vec<Option<bool>> = vec![None; keys.len()];
        let (Some(first), Some(last)) = (keys.first(), keys.last()) else {
            return Ok(decided);
        };
        // Longest common prefix, cut at a character boundary.
        let mut lcp = first.len();
        for k in keys {
            lcp = lcp.min(
                first
                    .bytes()
                    .zip(k.bytes())
                    .take_while(|(a, b)| a == b)
                    .count(),
            );
        }
        while !first.is_char_boundary(lcp) {
            lcp -= 1;
        }
        let prefix = &first[..lcp];
        // Start just before `first`: any proper prefix of it sorts before it.
        let start_after: Option<String> = first
            .char_indices()
            .last()
            .map(|(i, _)| first[..i].to_owned())
            .filter(|s| !s.is_empty() && s.as_str() >= prefix);
        let budget = keys.len() / DELETE_BATCH + 2;
        let mut pages = 0usize;
        let mut listed: HashSet<String> = HashSet::new();
        let mut reached = String::new();
        let mut complete = false;
        self.list_pages(
            st,
            &ListRequest {
                bucket,
                prefix,
                start_after: start_after.as_deref(),
                ..ListRequest::default()
            },
            path,
            |page| {
                pages += 1;
                for o in &page.objects {
                    listed.insert(o.key.clone());
                }
                if let Some(o) = page.objects.last() {
                    reached = o.key.clone();
                }
                if !page.is_truncated {
                    complete = true;
                }
                if complete || reached.as_str() >= last.as_str() || pages >= budget {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            },
        )
        .await?;
        for (i, k) in keys.iter().enumerate() {
            if listed.contains(k) {
                decided[i] = Some(true);
            } else if complete || k.as_str() <= reached.as_str() {
                decided[i] = Some(false);
            }
        }
        Ok(decided)
    }

    pub(crate) async fn rm_files_impl(&self, paths: &[String]) -> Vec<Result<()>> {
        let mut results: Vec<Option<Result<()>>> = (0..paths.len()).map(|_| None).collect();
        let st = match self.state().await {
            Ok(s) => s,
            Err(e) => {
                return paths
                    .iter()
                    .map(|p| Err(Error::new(e.kind(), e.message().to_owned()).with_path(p.clone())))
                    .collect();
            }
        };
        // Group by bucket; keys keep the indices of every path naming them.
        let mut by_bucket: BTreeMap<String, BTreeMap<String, Vec<usize>>> = BTreeMap::new();
        for (i, p) in paths.iter().enumerate() {
            let sp = split_path(p, self.inner.opts.version_aware);
            if sp.key.is_empty() {
                results[i] = Some(Err(Error::is_a_directory(p.clone())));
                continue;
            }
            if sp.is_arn() {
                results[i] = Some(Err(
                    Error::unsupported("S3 access point ARNs").with_path(p.clone())
                ));
                continue;
            }
            by_bucket
                .entry(sp.bucket)
                .or_default()
                .entry(sp.key)
                .or_default()
                .push(i);
        }
        let strict = self.inner.opts.strict_delete;
        for (bucket, keys) in by_bucket {
            let keys: Vec<(String, Vec<usize>)> = keys.into_iter().collect();
            let mut to_delete: Vec<usize> = (0..keys.len()).collect();
            if strict {
                let names: Vec<String> = keys.iter().map(|(k, _)| k.clone()).collect();
                match self.check_existence(&st, &bucket, &names).await {
                    Ok(presence) => {
                        to_delete.clear();
                        for (j, p) in presence.into_iter().enumerate() {
                            let path = format!("{bucket}/{}", keys[j].0);
                            let e = match p {
                                Presence::File => {
                                    to_delete.push(j);
                                    continue;
                                }
                                Presence::Directory => Error::is_a_directory(path),
                                Presence::Missing => Error::not_found(path),
                            };
                            for &i in &keys[j].1 {
                                results[i] = Some(Err(clone_error(&e)));
                            }
                        }
                    }
                    Err(e) => {
                        for (_, idx) in &keys {
                            for &i in idx {
                                results[i] = Some(Err(clone_error(&e)));
                            }
                        }
                        continue;
                    }
                }
            }
            let batches: Vec<Vec<usize>> = to_delete
                .chunks(DELETE_BATCH)
                .map(<[usize]>::to_vec)
                .collect();
            let st2 = &st;
            let bucket2 = &bucket;
            let keys2 = &keys;
            let futs: Vec<_> = batches
                .into_iter()
                .map(|batch| self.delete_indexed(st2, bucket2, keys2, batch))
                .collect();
            let outcomes: Vec<(Vec<usize>, Result<Vec<DeleteOutcome>>)> = stream::iter(futs)
                .buffer_unordered(DELETE_CONCURRENCY)
                .collect()
                .await;
            for (batch, outcome) in outcomes {
                match outcome {
                    Ok(list) => {
                        let failed: HashMap<&str, (&str, &str)> = list
                            .iter()
                            .filter_map(|o| match o {
                                DeleteOutcome::Failed { key, code, message } => {
                                    Some((key.as_str(), (code.as_str(), message.as_str())))
                                }
                                DeleteOutcome::Deleted { .. } => None,
                            })
                            .collect();
                        for j in batch {
                            let (key, idx) = &keys[j];
                            let r: Result<()> = match failed.get(key.as_str()) {
                                None => Ok(()),
                                Some((code, message)) => {
                                    let cl = classify(400, Some(code), None);
                                    let mut e = Error::new(cl.kind, (*message).to_owned())
                                        .with_path(format!("{bucket}/{key}"))
                                        .with_detail(fsfast_core::Detail::Code((*code).to_owned()));
                                    if let Some(n) = cl.errno {
                                        e = e.with_detail(fsfast_core::Detail::Errno(n));
                                    }
                                    Err(e)
                                }
                            };
                            for &i in idx {
                                results[i] = Some(r.as_ref().map(|_| ()).map_err(clone_error));
                            }
                        }
                    }
                    Err(e) => {
                        for j in batch {
                            for &i in &keys[j].1 {
                                results[i] =
                                    Some(Err(clone_error(&e)
                                        .with_path(format!("{bucket}/{}", keys[j].0))));
                            }
                        }
                    }
                }
            }
        }
        results
            .into_iter()
            .map(|r| r.unwrap_or_else(|| Err(Error::new(ErrorKind::Other, "not processed"))))
            .collect()
    }

    /// Existence of `keys` (sorted, unique) in `bucket`: listing for dense
    /// batches, `HEAD` for the rest, a prefix probe for missing ones.
    async fn check_existence(
        &self,
        st: &State,
        bucket: &str,
        keys: &[String],
    ) -> Result<Vec<Presence>> {
        let path = bucket.to_owned();
        let decided = if keys.len() >= LIST_CHECK_MIN {
            match self.list_presence(st, bucket, keys, &path).await {
                Ok(d) => d,
                Err(e) if e.kind() == ErrorKind::PermissionDenied => vec![None; keys.len()],
                Err(e) => return Err(e),
            }
        } else {
            vec![None; keys.len()]
        };
        let conc = self.inner.opts.max_concurrency.max(4);
        let futs: Vec<_> = keys
            .iter()
            .zip(decided)
            .map(|(k, d)| self.presence_decided(st, bucket, k, d))
            .collect();
        let checks: Vec<Result<Presence>> = stream::iter(futs).buffered(conc).collect().await;
        checks.into_iter().collect()
    }

    async fn presence_decided(
        &self,
        st: &State,
        bucket: &str,
        k: &str,
        d: Option<bool>,
    ) -> Result<Presence> {
        let path = format!("{bucket}/{k}");
        {
            {
                match d {
                    Some(true) => Ok(Presence::File),
                    Some(false) => {
                        if self.prefix_has_keys(st, bucket, k, &path).await? {
                            Ok(Presence::Directory)
                        } else {
                            Ok(Presence::Missing)
                        }
                    }
                    None => self.presence(st, bucket, k, &path).await,
                }
            }
        }
    }

    async fn delete_indexed(
        &self,
        st: &State,
        bucket: &str,
        keys: &[(String, Vec<usize>)],
        batch: Vec<usize>,
    ) -> (Vec<usize>, Result<Vec<DeleteOutcome>>) {
        let targets: Vec<DeleteTarget<'_>> = batch
            .iter()
            .map(|&j| DeleteTarget {
                key: &keys[j].0,
                version_id: None,
            })
            .collect();
        let r = self.delete_batch(st, bucket, &targets).await;
        (batch, r)
    }

    async fn delete_batch(
        &self,
        st: &State,
        bucket: &str,
        targets: &[DeleteTarget<'_>],
    ) -> Result<Vec<DeleteOutcome>> {
        let body = Bytes::from(delete_objects_body(targets));
        let call = Call::new(Op::DeleteObjects, Method::POST, bucket)
            .bucket(bucket)
            .query("delete", "")
            .header("content-type", "application/xml")?
            .body(body)
            .content_md5()
            .retry_safe(true);
        st.client
            .execute(call, |resp| async move {
                let body = resp.bytes().await?;
                parse_delete_result(&body)
            })
            .await
    }

    pub(crate) async fn mkdir_impl(&self, path: &str, create_parents: bool) -> Result<()> {
        let p = strip_protocol(path);
        let p = p.trim_end_matches('/');
        if p.is_empty() {
            return Err(Error::invalid_input("mkdir: empty path"));
        }
        let sp = split_path(p, self.inner.opts.version_aware);
        if self.exists_impl(&sp.bucket).await? {
            if sp.key.is_empty() {
                return Err(Error::already_exists(p));
            }
            // Directories below a bucket are implied by keys: nothing to do.
            return Ok(());
        }
        if !sp.key.is_empty() && !create_parents {
            // s3fs lists the bucket, which fails for a missing bucket.
            return self.ls_impl(&sp.bucket).await.map(|_| ());
        }
        let st = self.state().await?;
        let mut call = Call::new(Op::CreateBucket, Method::PUT, &sp.bucket).bucket(&sp.bucket);
        if let Some(region) = st.bucket_region.as_deref().filter(|r| *r != "us-east-1") {
            // us-east-1 takes no location constraint (AWS rejects it).
            call = call
                .header("content-type", "application/xml")?
                .body(Bytes::from(create_bucket_body(region)));
        }
        st.client.execute(call, |_| async { Ok(()) }).await
    }

    pub(crate) async fn rmdir_impl(&self, path: &str) -> Result<()> {
        let sp = split_path(path, self.inner.opts.version_aware);
        if !sp.key.is_empty() {
            // s3fs: an existing "directory" may have been meant for
            // rm(recursive=True); emulated directories cannot be removed.
            if self.exists_impl(path).await? {
                return Err(Error::already_exists(strip_protocol(path)).with_detail(
                    fsfast_core::Detail::Code("directory below a bucket (use rm recursive)".into()),
                ));
            }
            return Err(Error::not_found(strip_protocol(path)));
        }
        let st = self.state().await?;
        let call = Call::new(Op::DeleteBucket, Method::DELETE, &sp.bucket).bucket(&sp.bucket);
        st.client.execute(call, |_| async { Ok(()) }).await
    }

    pub(crate) async fn cp_file_impl(&self, src: &str, dst: &str) -> Result<()> {
        let s = split_path(&strip_protocol(src), self.inner.opts.version_aware);
        let d = split_path(dst, self.inner.opts.version_aware);
        if d.version_id.is_some() {
            return Err(Error::invalid_input("Cannot copy to a versioned file!"));
        }
        if s.key.is_empty() {
            return Err(Error::is_a_directory(s.bucket));
        }
        if d.key.is_empty() {
            return Err(Error::invalid_input(format!(
                "Copy failed ({src:?} -> {dst:?}): destination is not a key"
            )));
        }
        let st = self.state().await?;
        let src_name = s.full();
        let dst_name = d.full();
        let meta = self
            .head_object(
                &st,
                &s.bucket,
                &s.key,
                s.version_id.as_deref(),
                None,
                &src_name,
            )
            .await?;
        let source = copy_source(&s.bucket, &s.key, s.version_id.as_deref());
        let source_headers = self.copy_source_sse_headers(None);
        if meta.size <= self.inner.opts.copy_threshold {
            let mut call = Call::new(Op::CopyObject, Method::PUT, &dst_name)
                .bucket(&d.bucket)
                .key(&d.key)
                .header("x-amz-copy-source", &source)?;
            for (n, v) in &source_headers {
                call.headers.insert(n.clone(), v.clone());
            }
            let path = dst_name.clone();
            return st
                .client
                .execute(call, |resp| {
                    let path = path.clone();
                    async move {
                        let status = resp.status().as_u16();
                        let body = resp.bytes().await?;
                        match parse_result_etag(&body) {
                            Ok(_) => Ok(()),
                            Err(doc) => Err(response_error(status, &doc, &path)),
                        }
                    }
                })
                .await;
        }
        // Multipart server-side copy, parts in parallel. CopyObject would
        // carry the metadata over; a multipart upload must set it itself.
        let part = self
            .inner
            .opts
            .copy_part_size
            .max(meta.size.div_ceil(u64::from(MAX_PARTS)).div_ceil(1 << 20) << 20)
            .min(MAX_PART);
        let sink = Arc::new(
            S3PartSinkBuilder {
                st: st.clone(),
                bucket: d.bucket.clone(),
                key: d.key.clone(),
                path: dst_name.clone(),
                create_headers: preserved_headers(&meta),
                extra: None,
            }
            .build(),
        );
        let ranges = fsfast_core::split_range(0..meta.size, part);
        let res = async {
            let sink2 = &sink;
            let source2 = &source;
            let headers2: &HeaderMap = &source_headers;
            let futs: Vec<_> = ranges
                .into_iter()
                .enumerate()
                .map(|(i, r)| {
                    let n = i as u32 + 1;
                    async move {
                        sink2
                            .copy_part(n, source2, Some((r.start, r.end - 1)), headers2)
                            .await
                            .map(|e| (n, e))
                    }
                })
                .collect();
            let parts: Vec<Result<(u32, String)>> = stream::iter(futs)
                .buffer_unordered(self.inner.opts.max_concurrency.max(1))
                .collect()
                .await;
            let mut parts: Vec<(u32, String)> = parts.into_iter().collect::<Result<_>>()?;
            parts.sort_by_key(|p| p.0);
            sink.complete(&parts, false).await
        }
        .await;
        if res.is_err() {
            let _ = sink.abort().await;
        }
        res
    }

    pub(crate) async fn mv_file_impl(&self, src: &str, dst: &str) -> Result<()> {
        if fspath::normalize(&strip_protocol(src)) == fspath::normalize(&strip_protocol(dst)) {
            return Ok(());
        }
        self.cp_file_impl(src, dst).await?;
        // The copy proved the source exists: delete it without a check.
        let s = split_path(&strip_protocol(src), self.inner.opts.version_aware);
        let st = self.state().await?;
        self.delete_object(&st, &s.bucket, &s.key, &s.full()).await
    }

    pub(crate) async fn sign_impl(&self, path: &str, expires: Duration) -> Result<String> {
        let sp = split_path(path, self.inner.opts.version_aware);
        if sp.key.is_empty() {
            return Err(Error::invalid_input(format!(
                "cannot sign a URL for a bucket: {path}"
            )));
        }
        if expires > MAX_PRESIGN_EXPIRES {
            return Err(Error::invalid_input(format!(
                "pre-signed URLs expire after at most 7 days ({} s), got {} s",
                MAX_PRESIGN_EXPIRES.as_secs(),
                expires.as_secs()
            )));
        }
        let st = self.state().await?;
        let region = st.client.region_for(Some(&sp.bucket)).await;
        let mut query = Vec::new();
        if let Some(v) = &sp.version_id {
            query.push(("versionId".to_owned(), v.clone()));
        }
        let url = st
            .client
            .endpoint
            .url(Some(&sp.bucket), Some(&sp.key), &query, &region)?;
        let Some(cache) = &st.client.creds else {
            return Ok(url.to_string());
        };
        let creds = cache.get().await?;
        let secs = Duration::from_secs(expires.as_secs_f64().round().max(1.0) as u64);
        let signed =
            st.client
                .signer
                .presign("GET", &url, &creds, &region, SystemTime::now(), secs)?;
        Ok(signed.to_string())
    }
}

/// Errors are not `Clone`; rebuild one keeping kind, message, path and
/// details.
pub(crate) fn clone_error(e: &Error) -> Error {
    let mut out = Error::new(e.kind(), e.message().to_owned()).with_retryable(e.is_retryable());
    if let Some(p) = e.path() {
        out = out.with_path(p.to_owned());
    }
    for d in e.details() {
        out = out.with_detail(d.clone());
    }
    out
}
