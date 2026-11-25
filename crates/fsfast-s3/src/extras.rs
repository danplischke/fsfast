//! s3fs methods beyond the fsspec API: `find(prefix=...)`, object metadata
//! and tags, canned ACLs and bucket versioning.

use std::collections::BTreeMap;

use bytes::Bytes;
use fsfast_core::{Error, FileInfo, FindOptions, Result};
use fsfast_http_transport::Method;
use futures::{StreamExt, stream};

use crate::S3FileSystem;
use crate::client::Call;
use crate::list::infer_dirs;
use crate::params::{Op, Params};
use crate::path::{split_path, strip_protocol};
use crate::write::{copy_source, preserved_headers};
use crate::xml::{Element, escape_into, parse_result_etag, parse_versioning_status};

/// Canned ACLs s3fs accepts for objects (`key_acls`).
pub const KEY_ACLS: &[&str] = &[
    "private",
    "public-read",
    "public-read-write",
    "authenticated-read",
    "aws-exec-read",
    "bucket-owner-read",
    "bucket-owner-full-control",
];
/// Canned ACLs s3fs accepts for buckets (`buck_acls`).
pub const BUCKET_ACLS: &[&str] = &[
    "private",
    "public-read",
    "public-read-write",
    "authenticated-read",
];

impl S3FileSystem {
    /// s3fs `find(path, prefix=...)`: entries below `path` whose name starts
    /// with `path/prefix` (one server-side filtered listing; with `maxdepth`
    /// a filtered first level, then the matching sub-directories).
    pub async fn find_prefix(
        &self,
        path: &str,
        prefix: &str,
        opts: &FindOptions,
    ) -> Result<Vec<FileInfo>> {
        if prefix.is_empty() {
            return self.find_impl(path, opts).await;
        }
        let p = strip_protocol(path);
        let sp = split_path(&p, self.inner.opts.version_aware);
        if sp.bucket.is_empty() {
            return Err(Error::invalid_input("Cannot traverse all of S3"));
        }
        let st = self.state().await?;
        if let Some(depth) = opts.maxdepth.filter(|d| *d > 0) {
            let first = self
                .lsdir_stem(&st, &sp.bucket, &sp.key, prefix, Some("/"), false, &p)
                .await?;
            let (dirs, mut out): (Vec<FileInfo>, Vec<FileInfo>) =
                first.into_iter().partition(FileInfo::is_dir);
            let mut out_dirs = dirs.clone();
            if depth > 1 {
                for d in &dirs {
                    let sub = self
                        .find_impl(
                            &d.name,
                            &FindOptions {
                                maxdepth: Some(depth - 1),
                                withdirs: opts.withdirs,
                            },
                        )
                        .await?;
                    for info in sub {
                        if info.name == d.name {
                            continue;
                        }
                        if info.is_dir() {
                            out_dirs.push(info);
                        } else {
                            out.push(info);
                        }
                    }
                }
            }
            if opts.withdirs {
                out.extend(out_dirs);
                out.sort_by(|a, b| a.name.cmp(&b.name));
            }
            return Ok(out);
        }
        let mut out = self
            .lsdir_stem(&st, &sp.bucket, &sp.key, prefix, None, false, &p)
            .await?;
        for o in &mut out {
            let name = o.name.clone();
            o.set("Key", name);
        }
        if opts.withdirs {
            let dirs = infer_dirs(&out, &p);
            out.extend(dirs);
            out.sort_by(|a, b| a.name.cmp(&b.name));
        }
        Ok(out)
    }

    /// s3fs `metadata(path)`: the object's user metadata (`x-amz-meta-*`),
    /// keys lower-case with `_` replaced by `-`.
    pub async fn metadata(&self, path: &str) -> Result<BTreeMap<String, String>> {
        let sp = split_path(path, self.inner.opts.version_aware);
        let st = self.state().await?;
        let name = sp.full();
        let meta = self
            .head_object(
                &st,
                &sp.bucket,
                &sp.key,
                sp.version_id.as_deref(),
                None,
                &name,
            )
            .await?;
        Ok(meta
            .headers
            .iter()
            .filter_map(|(n, v)| {
                let k = n.as_str().strip_prefix("x-amz-meta-")?;
                Some((k.replace('_', "-"), v.to_str().ok()?.to_owned()))
            })
            .collect())
    }

    /// s3fs `getxattr(path, name)`.
    pub async fn getxattr(&self, path: &str, name: &str) -> Result<Option<String>> {
        Ok(self.metadata(path).await?.remove(&name.replace('_', "-")))
    }

    /// s3fs `setxattr(path, copy_kwargs=..., **attrs)`: update the object's
    /// user metadata in place (a self-copy with `MetadataDirective:
    /// REPLACE`); `None` values remove a key. Unlike s3fs, the object's
    /// content type and other headers are kept unless `copy_params`
    /// overrides them.
    pub async fn setxattr(
        &self,
        path: &str,
        attrs: &BTreeMap<String, Option<String>>,
        copy_params: Option<&Params>,
    ) -> Result<()> {
        let sp = split_path(path, self.inner.opts.version_aware);
        let st = self.state().await?;
        let name = sp.full();
        let meta = self
            .head_object(
                &st,
                &sp.bucket,
                &sp.key,
                sp.version_id.as_deref(),
                None,
                &name,
            )
            .await?;
        // s3fs rewrites the whole metadata map with `_` in keys turned into
        // `-` (it reads it back through `metadata()`).
        let mut md: BTreeMap<String, String> = meta
            .headers
            .iter()
            .filter_map(|(n, v)| {
                let k = n.as_str().strip_prefix("x-amz-meta-")?;
                Some((k.replace('_', "-"), v.to_str().ok()?.to_owned()))
            })
            .collect();
        for (k, v) in attrs {
            let k = k.replace('_', "-").to_ascii_lowercase();
            match v {
                Some(v) => md.insert(k, v.clone()),
                None => md.remove(&k),
            };
        }
        let mut headers = preserved_headers(&meta);
        let old: Vec<_> = headers
            .keys()
            .filter(|n| n.as_str().starts_with("x-amz-meta-"))
            .cloned()
            .collect();
        for n in old {
            headers.remove(n);
        }
        for (k, v) in &md {
            headers.insert(
                fsfast_http_transport::header::HeaderName::from_bytes(
                    format!("x-amz-meta-{k}").as_bytes(),
                )
                .map_err(|_| Error::invalid_input(format!("invalid metadata key {k:?}")))?,
                fsfast_http_transport::header::HeaderValue::from_str(v).map_err(|_| {
                    Error::invalid_input(format!("invalid metadata value for {k:?}"))
                })?,
            );
        }
        let mut call = Call::new(Op::CopyObject, Method::PUT, &name)
            .bucket(&sp.bucket)
            .key(&sp.key)
            .extra(copy_params);
        for (n, v) in &headers {
            call.headers.append(n.clone(), v.clone());
        }
        call = call
            .header(
                "x-amz-copy-source",
                &copy_source(&sp.bucket, &sp.key, sp.version_id.as_deref()),
            )?
            .header("x-amz-metadata-directive", "REPLACE")?;
        for (n, v) in &self.copy_source_sse_headers(copy_params) {
            call.headers.insert(n.clone(), v.clone());
        }
        let path = name.clone();
        st.client
            .execute(call, |resp| {
                let path = path.clone();
                async move {
                    let status = resp.status().as_u16();
                    let body = resp.bytes().await?;
                    parse_result_etag(&body)
                        .map(|_| ())
                        .map_err(|doc| crate::error::response_error(status, &doc, &path))
                }
            })
            .await
    }

    /// s3fs `get_tags(path)`.
    pub async fn get_tags(&self, path: &str) -> Result<BTreeMap<String, String>> {
        let sp = split_path(path, self.inner.opts.version_aware);
        let st = self.state().await?;
        let name = sp.full();
        let mut call = Call::new(Op::GetObjectTagging, Method::GET, &name)
            .bucket(&sp.bucket)
            .key(&sp.key)
            .query("tagging", "");
        if let Some(v) = &sp.version_id {
            call = call.query("versionId", v.clone());
        }
        st.client
            .execute(call, |resp| async move {
                let body = resp.bytes().await?;
                let root = Element::parse(&body)?;
                let mut out = BTreeMap::new();
                if let Some(set) = root.find("TagSet") {
                    for t in set.children_named("Tag") {
                        out.insert(
                            t.child_string("Key").unwrap_or_default(),
                            t.child_string("Value").unwrap_or_default(),
                        );
                    }
                }
                Ok(out)
            })
            .await
    }

    /// s3fs `put_tags(path, tags, mode)`: replace the object's tags, or merge
    /// them into the existing ones (`merge`, s3fs mode `"m"`).
    pub async fn put_tags(
        &self,
        path: &str,
        tags: &BTreeMap<String, String>,
        merge: bool,
    ) -> Result<()> {
        let mut all = if merge {
            self.get_tags(path).await?
        } else {
            BTreeMap::new()
        };
        all.extend(tags.iter().map(|(k, v)| (k.clone(), v.clone())));
        let mut body =
            String::from(r#"<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet>"#);
        for (k, v) in &all {
            body.push_str("<Tag><Key>");
            escape_into(&mut body, k);
            body.push_str("</Key><Value>");
            escape_into(&mut body, v);
            body.push_str("</Value></Tag>");
        }
        body.push_str("</TagSet></Tagging>");
        let sp = split_path(path, self.inner.opts.version_aware);
        let st = self.state().await?;
        let name = sp.full();
        let mut call = Call::new(Op::PutObjectTagging, Method::PUT, &name)
            .bucket(&sp.bucket)
            .key(&sp.key)
            .query("tagging", "")
            .header("content-type", "application/xml")?
            .body(Bytes::from(body))
            .content_md5();
        if let Some(v) = &sp.version_id {
            call = call.query("versionId", v.clone());
        }
        st.client.execute(call, |_| async { Ok(()) }).await
    }

    /// s3fs `chmod(path, acl, recursive)`: apply a canned ACL to an object
    /// (or, recursively, to every object below `path`), or to a bucket.
    pub async fn chmod(&self, path: &str, acl: &str, recursive: bool) -> Result<()> {
        let sp = split_path(path, self.inner.opts.version_aware);
        if recursive {
            let all = self.find_impl(path, &FindOptions::default()).await?;
            let futs: Vec<_> = all.iter().map(|i| self.chmod_one(&i.name, acl)).collect();
            let results: Vec<Result<()>> = stream::iter(futs)
                .buffer_unordered(self.inner.opts.max_concurrency.max(1))
                .collect()
                .await;
            results.into_iter().collect::<Result<()>>()?;
        } else if !sp.key.is_empty() {
            self.chmod_one(path, acl).await?;
        }
        if sp.key.is_empty() {
            if !BUCKET_ACLS.contains(&acl) {
                return Err(Error::invalid_input(format!("ACL not in {BUCKET_ACLS:?}")));
            }
            let st = self.state().await?;
            let call = Call::new(Op::PutBucketAcl, Method::PUT, &sp.bucket)
                .bucket(&sp.bucket)
                .query("acl", "")
                .header("x-amz-acl", acl)?;
            st.client.execute(call, |_| async { Ok(()) }).await?;
        }
        Ok(())
    }

    async fn chmod_one(&self, path: &str, acl: &str) -> Result<()> {
        if !KEY_ACLS.contains(&acl) {
            return Err(Error::invalid_input(format!("ACL not in {KEY_ACLS:?}")));
        }
        let sp = split_path(path, self.inner.opts.version_aware);
        let st = self.state().await?;
        let name = sp.full();
        let mut call = Call::new(Op::PutObjectAcl, Method::PUT, &name)
            .bucket(&sp.bucket)
            .key(&sp.key)
            .query("acl", "")
            .header("x-amz-acl", acl)?;
        if let Some(v) = &sp.version_id {
            call = call.query("versionId", v.clone());
        }
        st.client.execute(call, |_| async { Ok(()) }).await
    }

    /// s3fs `is_bucket_versioned(bucket)`.
    pub async fn is_bucket_versioned(&self, bucket: &str) -> Result<bool> {
        let st = self.state().await?;
        let call = Call::new(Op::GetBucketVersioning, Method::GET, bucket)
            .bucket(bucket)
            .query("versioning", "");
        let status = st
            .client
            .execute(call, |resp| async move {
                let body = resp.bytes().await?;
                parse_versioning_status(&body)
            })
            .await?;
        Ok(status == "Enabled")
    }

    /// s3fs `make_bucket_versioned(bucket, versioned)`: enable or suspend
    /// versioning.
    pub async fn make_bucket_versioned(&self, bucket: &str, versioned: bool) -> Result<()> {
        let status = if versioned { "Enabled" } else { "Suspended" };
        let body = format!(
            r#"<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>{status}</Status></VersioningConfiguration>"#
        );
        let st = self.state().await?;
        let call = Call::new(Op::PutBucketVersioning, Method::PUT, bucket)
            .bucket(bucket)
            .query("versioning", "")
            .header("content-type", "application/xml")?
            .body(Bytes::from(body))
            .content_md5();
        st.client.execute(call, |_| async { Ok(()) }).await
    }
}
