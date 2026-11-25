//! Mutations with gcsfs semantics: buckets (`mkdir`/`rmdir`), deletes,
//! server-side copies (`objects.rewrite`), moves (`objects.move`, falling
//! back to copy + delete), `touch` and `merge` (`objects.compose`).

use std::sync::atomic::Ordering;

use bytes::Bytes;
use fsfast_core::{Error, ErrorKind, Result, WriteMode, WriteOptions};
use fsfast_http_transport::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use fsfast_http_transport::Method;
use futures::{StreamExt, stream};
use serde_json::{Value as Json, json};

use crate::GCSFileSystem;
use crate::client::Query;
use crate::path::{check_object_name, split_path, strip_protocol};

/// Concurrent DELETEs of `rm_files` (GCS deletes are cheap; over HTTP/2
/// they share connections).
const DELETE_CONCURRENCY: usize = 32;

fn json_body(v: &Json) -> Bytes {
    Bytes::from(v.to_string())
}

fn app_json() -> HeaderValue {
    HeaderValue::from_static("application/json")
}

/// 16 random bytes as a UUID-shaped hex string (idempotency tokens).
fn random_token() -> String {
    let mut b = [0u8; 16];
    let _ = aws_lc_rs::rand::fill(&mut b);
    let h = hex::encode(b);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

impl GCSFileSystem {
    /// gcsfs `_mkdir`: create a bucket. Below a bucket nothing is created;
    /// a missing bucket is created only with `create_parents`, otherwise
    /// `NotFound`.
    pub(crate) async fn mkdir_impl(&self, path: &str, create_parents: bool) -> Result<()> {
        let raw = strip_protocol(path);
        let sp = split_path(raw, false);
        if sp.bucket.is_empty() || sp.bucket == "/" {
            return Err(Error::invalid_input("Cannot create root bucket"));
        }
        if raw.contains('/') {
            if self.bucket_exists(&sp.bucket).await? {
                return Ok(());
            }
            if !create_parents {
                return Err(Error::not_found(sp.bucket));
            }
        }
        self.create_bucket(&sp.bucket).await
    }

    async fn bucket_exists(&self, bucket: &str) -> Result<bool> {
        match self.info_impl(bucket).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// `POST b` as gcsfs sends it.
    pub(crate) async fn create_bucket(&self, bucket: &str) -> Result<()> {
        let c = &self.inner.client;
        let project = c.project().await?.unwrap_or_default();
        let q = Query::new()
            .with("predefinedAcl", "projectPrivate")
            .with("project", &project)
            .with("predefinedDefaultObjectAcl", "bucketOwnerFullControl")
            .with("enableObjectRetention", "false");
        let mut body = serde_json::Map::new();
        body.insert("name".into(), Json::String(bucket.to_owned()));
        if let Some(loc) = &self.inner.opts.default_location {
            body.insert("location".into(), Json::String(loc.clone()));
        }
        let req = c
            .request(Method::POST, &c.buckets_url(), &q)?
            .header(CONTENT_TYPE, app_json())
            .body(json_body(&Json::Object(body)))
            .status_kind(409, ErrorKind::AlreadyExists)
            .op(fsfast_engine::stats::OpKind::Other)
            .path(bucket.to_owned());
        c.send_ok(req).await
    }

    /// gcsfs `_rmdir`: delete an empty bucket; paths below a bucket are a
    /// no-op (directories are implied by keys).
    pub(crate) async fn rmdir_impl(&self, path: &str) -> Result<()> {
        let b = strip_protocol(path).trim_end_matches('/');
        if b.contains('/') {
            return Ok(());
        }
        if b.is_empty() {
            return Err(Error::invalid_input("rmdir needs a bucket name"));
        }
        let c = &self.inner.client;
        let req = c
            .request(Method::DELETE, &c.bucket_url(b), &Query::new())?
            // GCS answers 409 for a non-empty bucket, fake-gcs-server 412.
            .status_kind(409, ErrorKind::DirectoryNotEmpty)
            .status_kind(412, ErrorKind::DirectoryNotEmpty)
            .path(b.to_owned());
        c.send_ok(req).await
    }

    /// gcsfs `_rm_file`: delete an object (a bare bucket name deletes the
    /// bucket, as in gcsfs). `NotFound` if it does not exist.
    pub(crate) async fn rm_file_impl(&self, path: &str) -> Result<()> {
        let sp = split_path(path, self.inner.opts.version_aware);
        if sp.key.is_empty() {
            return self.rmdir_impl(&sp.bucket).await;
        }
        let name = sp.full();
        check_object_name(&sp.key, &name)?;
        let c = &self.inner.client;
        let q = Query::new().with_opt("generation", sp.generation.as_deref());
        let req = c
            .request(Method::DELETE, &c.object_url(&sp.bucket, &sp.key), &q)?
            .path(name);
        c.send_ok(req).await
    }

    /// Concurrent deletes, one result per path.
    pub(crate) async fn rm_files_impl(&self, paths: &[String]) -> Vec<Result<()>> {
        let futs: Vec<_> = paths.iter().map(|p| self.rm_file_impl(p)).collect();
        stream::iter(futs)
            .buffered(DELETE_CONCURRENCY)
            .collect()
            .await
    }

    /// gcsfs `_cp_file`: `objects.rewrite` until done (large or
    /// cross-location copies take several calls with a `rewriteToken`).
    pub(crate) async fn cp_file_impl(&self, src: &str, dst: &str) -> Result<()> {
        let va = self.inner.opts.version_aware;
        let s = split_path(src, va);
        let d = split_path(dst, va);
        if d.generation.is_some() {
            return Err(Error::invalid_input("Cannot write to specific object generation"));
        }
        if s.key.is_empty() {
            return Err(Error::is_a_directory(s.bucket));
        }
        if d.key.is_empty() {
            return Err(Error::invalid_input(format!("cannot copy {src:?} onto a bucket ({dst:?})")));
        }
        check_object_name(&s.key, &s.full())?;
        check_object_name(&d.key, &d.full())?;
        let c = &self.inner.client;
        let url = format!(
            "{}/rewriteTo/b/{}/o/{}",
            c.object_url(&s.bucket, &s.key),
            crate::path::quote(&d.bucket),
            crate::path::quote(&d.key)
        );
        let mut token: Option<String> = None;
        loop {
            let q = Query::new()
                .with_opt("rewriteToken", token.as_deref())
                .with_opt("sourceGeneration", s.generation.as_deref());
            let req = c
                .request(Method::POST, &url, &q)?
                .header(CONTENT_TYPE, app_json())
                .retry_safe(true)
                .op(fsfast_engine::stats::OpKind::Copy)
                .path(s.full());
            let out = c.json(req).await?;
            if out.get("done").and_then(Json::as_bool) == Some(true) {
                return Ok(());
            }
            match out.get("rewriteToken").and_then(Json::as_str) {
                Some(t) if !t.is_empty() => token = Some(t.to_owned()),
                _ => return Err(Error::protocol("rewrite is not done but returned no rewriteToken").with_path(s.full())),
            }
        }
    }

    /// gcsfs `_mv_file`: `objects.move` within a bucket, else (or when the
    /// server does not offer it) copy and delete.
    pub(crate) async fn mv_file_impl(&self, src: &str, dst: &str) -> Result<()> {
        if strip_protocol(src) == strip_protocol(dst) {
            return Ok(());
        }
        let va = self.inner.opts.version_aware;
        let s = split_path(src, va);
        let d = split_path(dst, va);
        if d.generation.is_some() {
            return Err(Error::invalid_input("Cannot move to specific object generation"));
        }
        if s.full() == d.full() && s.generation.is_none() {
            return Ok(());
        }
        if s.bucket == d.bucket
            && !s.key.is_empty()
            && !d.key.is_empty()
            && !self.inner.move_unsupported.load(Ordering::Relaxed)
        {
            check_object_name(&s.key, &s.full())?;
            check_object_name(&d.key, &d.full())?;
            let c = &self.inner.client;
            let url = format!(
                "{}/moveTo/o/{}",
                c.object_url(&s.bucket, &s.key),
                crate::path::quote(&d.key)
            );
            let q = Query::new().with_opt("sourceGeneration", s.generation.as_deref());
            let token = HeaderValue::try_from(random_token()).map_err(|_| Error::invalid_input("token"))?;
            let req = c
                .request(Method::POST, &url, &q)?
                .header(CONTENT_TYPE, app_json())
                .header(HeaderName::from_static("x-goog-gcs-idempotency-token"), token)
                // The idempotency token makes retries safe.
                .retry_safe(true)
                .op(fsfast_engine::stats::OpKind::Copy)
                .path(s.full());
            match c.send_ok(req).await {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == ErrorKind::NotFound => return Err(e),
                Err(e) => {
                    if matches!(e.http_status(), Some(400 | 405 | 501)) {
                        // Not offered by this server (emulators): stop asking.
                        self.inner.move_unsupported.store(true, Ordering::Relaxed);
                    }
                    tracing::warn!(error = %e, "Failed to move file using moveTo API; falling back to copy/delete");
                }
            }
        }
        self.cp_file_impl(src, dst).await?;
        self.rm_file_impl(src).await
    }

    /// fsspec `touch`: truncate (or create) with `truncate`; otherwise
    /// create only a missing object (atomically, `ifGenerationMatch=0`) and
    /// report `Unsupported` for an existing one (GCS objects have no
    /// settable modification time).
    pub(crate) async fn touch_impl(&self, path: &str, truncate: bool) -> Result<()> {
        if truncate {
            return self.pipe_file_impl(path, Bytes::new(), &WriteOptions::default()).await;
        }
        let opts = WriteOptions::default().with_mode(WriteMode::CreateNew);
        match self.pipe_file_impl(path, Bytes::new(), &opts).await {
            Err(e) if e.kind() == ErrorKind::AlreadyExists => Err(Error::unsupported(
                "touch without truncate on an existing object",
            )),
            other => other,
        }
    }

    /// gcsfs `merge`: concatenate objects of one bucket into `path` with
    /// `objects.compose` (GCS accepts up to 32 sources per call).
    pub async fn merge(&self, path: &str, paths: &[String]) -> Result<()> {
        let (bucket, key, name) = self.write_target(path)?;
        if paths.is_empty() {
            return Err(Error::invalid_input("merge needs at least one source"));
        }
        let sources: Vec<Json> = paths
            .iter()
            .map(|p| {
                let sp = split_path(p, self.inner.opts.version_aware);
                let mut o = serde_json::Map::new();
                o.insert("name".into(), Json::String(sp.key));
                if let Some(g) = sp.generation {
                    o.insert("generation".into(), Json::String(g));
                }
                Json::Object(o)
            })
            .collect();
        let body = json!({
            "sourceObjects": sources,
            "kind": "storage#composeRequest",
            "destination": {"name": key, "bucket": bucket},
        });
        let c = &self.inner.client;
        let url = format!("{}/compose", c.object_url(&bucket, &key));
        let req = c
            .request(Method::POST, &url, &Query::new())?
            .header(CONTENT_TYPE, app_json())
            .body(json_body(&body))
            .retry_safe(true)
            .path(name);
        c.send_ok(req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens() {
        let t = random_token();
        assert_eq!(t.len(), 36);
        assert_eq!(t.matches('-').count(), 4);
        assert_ne!(t, random_token());
    }
}
