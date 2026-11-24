//! The S3 request pipeline: parameters → URL → payload hash → SigV4 →
//! shared HTTP client (retries, adaptive concurrency, stats) → response,
//! with botocore's region redirects and a refresh of rejected temporary
//! credentials.
//!
//! * **Payload hashing** follows botocore: the body's SHA-256 is signed,
//!   except for object data (`PutObject`, `UploadPart`) over HTTPS, which
//!   is sent with `UNSIGNED-PAYLOAD` (TLS protects it in transit), unless
//!   `payload_signing_enabled` says otherwise. Large bodies are hashed on a
//!   blocking thread (SHA-NI makes this ~2 GB/s, but it must not stall the
//!   runtime).
//! * **Region redirects** (botocore `S3RegionRedirectorv2`): a request
//!   answered with a redirect status, `PermanentRedirect`,
//!   `AuthorizationHeaderMalformed` with a `Region`,
//!   `IllegalLocationConstraintException`, or a bodiless 301/400 to a HEAD,
//!   is re-signed for the bucket's region (from `x-amz-bucket-region`, the
//!   error body, or a `HEAD` of the bucket) and sent once more; the region
//!   is cached per bucket. With `cache_regions` the region is discovered up
//!   front, as s3fs's `S3BucketRegionCache` does.
//! * **Expired credentials**: an `ExpiredToken` rejection of temporary
//!   credentials drops them from the cache and retries once with fresh ones.

use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use fsfast_core::{Error, ErrorKind, Result};
use fsfast_engine::stats::OpKind;
use fsfast_http_transport::header::{HeaderMap, HeaderName, HeaderValue};
use fsfast_http_transport::{HttpClient, Method, Request, Response};
use md5::{Digest, Md5};
use parking_lot::{Mutex, RwLock};
use tokio::sync::OnceCell;

use crate::credentials::CredentialsCache;
use crate::encode::b64;
use crate::endpoint::Endpoint;
use crate::error::{error_code, finish_error, response_error};
use crate::params::{Op, Params};
use crate::sigv4::{EMPTY_SHA256, Signer, UNSIGNED_PAYLOAD, sha256_hex};
use crate::xml::S3ErrorDoc;

/// Bodies at least this large are hashed on a blocking thread.
const HASH_INLINE_MAX: usize = 256 << 10;

/// A request body.
#[derive(Debug, Clone, Default)]
pub(crate) enum Body {
    /// No body.
    #[default]
    Empty,
    /// One buffer (zero-copy: shared with the caller and with retries).
    Bytes(Bytes),
}

impl Body {
    fn len(&self) -> usize {
        match self {
            Body::Empty => 0,
            Body::Bytes(b) => b.len(),
        }
    }
}

/// One S3 API call.
#[derive(Debug)]
pub(crate) struct Call<'a> {
    pub op: Op,
    pub method: Method,
    pub bucket: Option<&'a str>,
    pub key: Option<&'a str>,
    /// Unencoded query parameters.
    pub query: Vec<(String, String)>,
    pub headers: HeaderMap,
    pub body: Body,
    /// The fsfast path reported in errors.
    pub path: &'a str,
    /// Per-call parameters overriding `s3_additional_kwargs`.
    pub extra: Option<&'a Params>,
    /// Error statuses handed to the response callback instead of failing.
    pub allow: Vec<u16>,
    /// Override the transport's idempotency-based retry decision.
    pub retry_safe: Option<bool>,
    /// Send `Content-MD5` of the body (required by `DeleteObjects`).
    pub content_md5: bool,
}

impl<'a> Call<'a> {
    pub fn new(op: Op, method: Method, path: &'a str) -> Self {
        Call {
            op,
            method,
            bucket: None,
            key: None,
            query: Vec::new(),
            headers: HeaderMap::new(),
            body: Body::Empty,
            path,
            extra: None,
            allow: Vec::new(),
            retry_safe: None,
            content_md5: false,
        }
    }

    pub fn bucket(mut self, b: &'a str) -> Self {
        self.bucket = Some(b);
        self
    }

    pub fn key(mut self, k: &'a str) -> Self {
        self.key = Some(k);
        self
    }

    pub fn query(mut self, k: &str, v: impl Into<String>) -> Self {
        self.query.push((k.to_owned(), v.into()));
        self
    }

    pub fn header(mut self, name: &'static str, value: &str) -> Result<Self> {
        let v = HeaderValue::from_str(value)
            .map_err(|_| Error::invalid_input(format!("invalid value for header {name}: {value:?}")))?;
        self.headers.insert(HeaderName::from_static(name), v);
        Ok(self)
    }

    pub fn body(mut self, b: Bytes) -> Self {
        self.body = Body::Bytes(b);
        self
    }

    pub fn extra(mut self, p: Option<&'a Params>) -> Self {
        self.extra = p;
        self
    }

    pub fn allow(mut self, status: u16) -> Self {
        self.allow.push(status);
        self
    }

    pub fn retry_safe(mut self, safe: bool) -> Self {
        self.retry_safe = Some(safe);
        self
    }

    pub fn content_md5(mut self) -> Self {
        self.content_md5 = true;
        self
    }
}

fn op_kind(op: Op) -> OpKind {
    match op {
        Op::HeadObject | Op::HeadBucket | Op::GetBucketLocation | Op::GetBucketVersioning => {
            OpKind::Info
        }
        Op::ListBuckets | Op::ListObjectsV2 | Op::ListObjectVersions => OpKind::List,
        Op::GetObject => OpKind::Read,
        Op::PutObject
        | Op::UploadPart
        | Op::CreateMultipartUpload
        | Op::CompleteMultipartUpload
        | Op::CreateBucket => OpKind::Write,
        Op::DeleteObject | Op::DeleteObjects | Op::DeleteBucket | Op::AbortMultipartUpload => {
            OpKind::Delete
        }
        Op::CopyObject | Op::UploadPartCopy => OpKind::Copy,
    }
}

/// Error codes that mean "these temporary credentials are no longer valid".
fn is_expired_credentials(err: &Error) -> bool {
    matches!(
        error_code(err),
        Some("ExpiredToken" | "ExpiredTokenException" | "TokenRefreshRequired" | "RequestExpired")
    )
}

/// The S3 client.
#[derive(Debug)]
pub(crate) struct Client {
    pub http: HttpClient,
    pub endpoint: Endpoint,
    /// Signing region when a bucket's region is not known otherwise.
    pub region: String,
    /// `None`: anonymous (unsigned) requests.
    pub creds: Option<Arc<CredentialsCache>>,
    pub signer: Signer,
    pub payload_signing: Option<bool>,
    pub params: Params,
    /// Learned bucket regions.
    bucket_regions: RwLock<HashMap<String, String>>,
    /// `cache_regions`: discover each bucket's region before the first
    /// request to it.
    discover: bool,
    discovering: Mutex<HashMap<String, Arc<OnceCell<String>>>>,
}

impl Client {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        http: HttpClient,
        endpoint: Endpoint,
        region: String,
        creds: Option<Arc<CredentialsCache>>,
        payload_signing: Option<bool>,
        params: Params,
        discover: bool,
    ) -> Self {
        Client {
            http,
            endpoint,
            region,
            creds,
            signer: Signer::new("s3"),
            payload_signing,
            params,
            bucket_regions: RwLock::new(HashMap::new()),
            discover,
            discovering: Mutex::new(HashMap::new()),
        }
    }

    /// The region requests for `bucket` are signed for.
    pub async fn region_for(&self, bucket: Option<&str>) -> String {
        let Some(b) = bucket else {
            return self.region.clone();
        };
        if let Some(r) = self.bucket_regions.read().get(b) {
            return r.clone();
        }
        if !self.discover {
            return self.region.clone();
        }
        let cell = self
            .discovering
            .lock()
            .entry(b.to_owned())
            .or_default()
            .clone();
        let region = cell
            .get_or_init(|| async {
                match self.discover_region(b).await {
                    Some(r) => r,
                    None => self.region.clone(),
                }
            })
            .await
            .clone();
        self.bucket_regions
            .write()
            .entry(b.to_owned())
            .or_insert_with(|| region.clone());
        region
    }

    /// The bucket's region from `x-amz-bucket-region` of a `HEAD` of the
    /// bucket (sent whatever the status, including 301 and 403).
    pub async fn discover_region(&self, bucket: &str) -> Option<String> {
        let path = bucket.to_owned();
        let url = self.endpoint.url(Some(bucket), None, &[], &self.region).ok()?;
        let mut headers = HeaderMap::new();
        if let Some(c) = &self.creds {
            let creds = c.get().await.ok()?;
            self.signer
                .sign(
                    "HEAD",
                    &url,
                    &mut headers,
                    EMPTY_SHA256,
                    &creds,
                    &self.region,
                    SystemTime::now(),
                )
                .ok()?;
        }
        let mut req = Request::from_url(Method::HEAD, url)
            .ok()?
            .op(OpKind::Info)
            .path(path);
        *req.headers_mut() = headers;
        for s in [301, 302, 307, 400, 403, 404] {
            req = req.allow_status(s);
        }
        let resp = self.http.send(req).await.ok()?;
        let region = resp
            .header_str("x-amz-bucket-region")
            .map(str::to_owned)
            .filter(|r| !r.is_empty());
        tracing::debug!(bucket, region = ?region, "discovered bucket region");
        region
    }

    async fn payload_hash(&self, body: &Body, op: Op, https: bool) -> Result<String> {
        let Body::Bytes(b) = body else {
            return Ok(EMPTY_SHA256.to_owned());
        };
        if b.is_empty() {
            return Ok(EMPTY_SHA256.to_owned());
        }
        let sign = match self.payload_signing {
            Some(v) => v,
            None => !(https && matches!(op, Op::PutObject | Op::UploadPart)),
        };
        if !sign {
            return Ok(UNSIGNED_PAYLOAD.to_owned());
        }
        if b.len() < HASH_INLINE_MAX {
            return Ok(sha256_hex(b));
        }
        let b = b.clone();
        tokio::task::spawn_blocking(move || sha256_hex(&b))
            .await
            .map_err(|e| Error::new(ErrorKind::Other, format!("hashing task failed: {e}")))
    }

    /// Send `call` and process the response with `f`; the whole exchange
    /// (including `f`) is retried on transient failures when the request is
    /// retry-safe.
    pub async fn execute<T, F, Fut>(&self, call: Call<'_>, f: F) -> Result<T>
    where
        F: Fn(Response) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        if let Some(b) = call.bucket
            && b.starts_with("arn:")
        {
            return Err(Error::unsupported("S3 access point / outposts ARNs").with_path(call.path));
        }
        let Call {
            op,
            method,
            bucket,
            key,
            mut query,
            mut headers,
            body,
            path,
            extra,
            allow,
            retry_safe,
            content_md5,
        } = call;
        let params = match extra {
            Some(e) if !e.is_empty() => Cow::Owned(self.params.merged(e)),
            _ => Cow::Borrowed(&self.params),
        };
        params.apply(op, &mut headers, &mut query);
        if content_md5 && let Body::Bytes(b) = &body {
            let v = HeaderValue::from_str(&b64(&Md5::digest(b))).expect("base64 is a valid header");
            headers.insert(HeaderName::from_static("content-md5"), v);
        }
        let https = match &self.endpoint.custom {
            Some(u) => u.scheme() == "https",
            None => self.endpoint.use_ssl,
        };
        let payload_hash = if self.creds.is_some() {
            self.payload_hash(&body, op, https).await?
        } else {
            String::new()
        };
        let mut region = self.region_for(bucket).await;
        let mut redirected = false;
        let mut refreshed = false;
        loop {
            let url = self.endpoint.url(bucket, key, &query, &region)?;
            let mut h = headers.clone();
            if let Some(c) = &self.creds {
                let creds = c.get().await.map_err(|e| finish_error(e, Some(path)))?;
                self.signer.sign(
                    method.as_str(),
                    &url,
                    &mut h,
                    &payload_hash,
                    &creds,
                    &region,
                    SystemTime::now(),
                )?;
            }
            let mut req = Request::from_url(method.clone(), url)?
                .op(op_kind(op))
                .path(path);
            *req.headers_mut() = h;
            if body.len() > 0 || matches!(method, Method::PUT | Method::POST) {
                if let Body::Bytes(b) = &body {
                    req = req.body(b.clone());
                }
            }
            for s in [301u16, 302, 307, 400].iter().chain(allow.iter()) {
                req = req.allow_status(*s);
            }
            if let Some(r) = retry_safe {
                req = req.retry_safe(r);
            }
            let hint: Mutex<Option<Option<String>>> = Mutex::new(None);
            let (allow, hint_ref, f) = (&allow, &hint, &f);
            let res = self
                .http
                .send_with(req, |resp| async move {
                    let status = resp.status().as_u16();
                    if matches!(status, 301 | 302 | 307 | 400) && !allow.contains(&status) {
                        let (err, redirect) = redirect_or_error(resp, op, path).await;
                        if let Some(r) = redirect {
                            *hint_ref.lock() = Some(r);
                        }
                        return Err(err);
                    }
                    f(resp).await
                })
                .await;
            let err = match res {
                Ok(v) => return Ok(v),
                Err(e) => e,
            };
            let redirect = hint.lock().take();
            if let (Some(region_hint), Some(b), false) = (redirect, bucket, redirected) {
                let new = match region_hint {
                    Some(r) => Some(r),
                    None => self.discover_region(b).await,
                };
                if let Some(new) = new.filter(|n| *n != region) {
                    tracing::debug!(
                        bucket = b,
                        from = %region,
                        to = %new,
                        "bucket is in another region; re-signing (configure region_name to avoid redirects)"
                    );
                    self.bucket_regions.write().insert(b.to_owned(), new.clone());
                    region = new;
                    redirected = true;
                    continue;
                }
            }
            if !refreshed
                && is_expired_credentials(&err)
                && let Some(c) = &self.creds
                && c.is_refreshable()
            {
                tracing::debug!("credentials rejected as expired; refreshing");
                c.invalidate();
                refreshed = true;
                continue;
            }
            return Err(finish_error(err, Some(path)));
        }
    }
}

/// Inspect a 301/302/307/400 response: either a region redirect (with the
/// region if the response names it) or a plain error.
async fn redirect_or_error(resp: Response, op: Op, path: &str) -> (Error, Option<Option<String>>) {
    let status = resp.status().as_u16();
    let header_region = resp
        .header_str("x-amz-bucket-region")
        .filter(|r| !r.is_empty())
        .map(str::to_owned);
    let body = resp.bytes_truncated(64 << 10).await.unwrap_or_default();
    let doc = S3ErrorDoc::parse(&body).unwrap_or_default();
    let code = doc.code.as_deref();
    let special_head_object = op == Op::HeadObject && code.is_none() && matches!(status, 301 | 400);
    let special_head_bucket =
        op == Op::HeadBucket && code.is_none() && matches!(status, 301 | 400) && header_region.is_some();
    let wrong_signing_region = code == Some("AuthorizationHeaderMalformed") && doc.region.is_some();
    let redirect_status = matches!(status, 301 | 302 | 307);
    let permanent = code == Some("PermanentRedirect");
    let opt_in = code == Some("IllegalLocationConstraintException") && op != Op::CreateBucket;
    let err = response_error(status, &doc, path).with_retryable(false);
    if special_head_object
        || special_head_bucket
        || wrong_signing_region
        || redirect_status
        || permanent
        || opt_in
    {
        let region = header_region.or_else(|| doc.region.clone());
        return (err, Some(region));
    }
    // A plain 400 error: keep the code's retry classification
    // (`RequestTimeout` is retried).
    (response_error(status, &doc, path), None)
}
