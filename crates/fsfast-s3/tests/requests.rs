//! What goes on the wire: an in-memory fake S3 server records every request
//! so the tests can check headers (SSE-C, requester pays, additional
//! parameters filtered per operation, metadata, conditional writes,
//! payload hashes), request counts (single GET for small objects, batched
//! deletes) and failure handling (multipart abort, retries, error codes).

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use bytes::Bytes;
use fsfast_core::{ByteRange, ErrorKind, FileSystem, Options, Value, WriteMode, WriteOptions};
use fsfast_s3::encode::url_decode_plus;
use fsfast_s3::profile::Env;
use fsfast_s3::{S3FileSystem, S3Options};
use parking_lot::Mutex;

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Seen {
    fn h(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    fn op(&self) -> &'static str {
        let q = |k: &str| self.query.contains_key(k);
        let has_key = self.path.trim_start_matches('/').contains('/');
        match self.method.as_str() {
            "HEAD" if has_key => "HeadObject",
            "HEAD" => "HeadBucket",
            "GET" if q("list-type") => "ListObjectsV2",
            "GET" if q("versions") => "ListObjectVersions",
            "GET" if q("location") => "GetBucketLocation",
            "GET" if has_key => "GetObject",
            "GET" => "ListBuckets",
            "PUT" if q("partNumber") && self.h("x-amz-copy-source").is_some() => "UploadPartCopy",
            "PUT" if q("partNumber") => "UploadPart",
            "PUT" if self.h("x-amz-copy-source").is_some() => "CopyObject",
            "PUT" if has_key => "PutObject",
            "PUT" => "CreateBucket",
            "POST" if q("uploads") => "CreateMultipartUpload",
            "POST" if q("uploadId") => "CompleteMultipartUpload",
            "POST" if q("delete") => "DeleteObjects",
            "DELETE" if q("uploadId") => "AbortMultipartUpload",
            "DELETE" if has_key => "DeleteObject",
            "DELETE" => "DeleteBucket",
            _ => "Unknown",
        }
    }
}

#[derive(Default)]
struct Store {
    objects: BTreeMap<String, (Vec<u8>, HeaderMap)>,
    uploads: HashMap<String, BTreeMap<u32, Vec<u8>>>,
    next_upload: usize,
}

/// Injected faults: (operation, how many times, status, error code).
type Fault = (&'static str, usize, u16, &'static str);

struct Fake {
    base: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    store: Arc<Mutex<Store>>,
    faults: Arc<Mutex<Vec<Fault>>>,
}

impl Fake {
    fn ops(&self) -> Vec<&'static str> {
        self.seen.lock().iter().map(Seen::op).collect()
    }

    fn requests(&self, op: &str) -> Vec<Seen> {
        self.seen
            .lock()
            .iter()
            .filter(|s| s.op() == op)
            .cloned()
            .collect()
    }

    fn clear(&self) {
        self.seen.lock().clear();
    }
}

fn xml_tag_values(body: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    body.split(&open)
        .skip(1)
        .filter_map(|s| s.split(&close).next())
        .map(|s| {
            s.replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
        })
        .collect()
}

fn etag_of(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    format!("\"{}\"", hex::encode(Md5::digest(data)))
}

fn handle(store: &Mutex<Store>, s: &Seen) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut st = store.lock();
    let key = url_decode_plus(s.path.trim_start_matches('/')).into_owned();
    let ok = |body: &str| (200u16, vec![], body.as_bytes().to_vec());
    let not_found = || {
        (
            404u16,
            vec![("content-type".to_owned(), "application/xml".to_owned())],
            b"<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>"
                .to_vec(),
        )
    };
    match s.op() {
        "HeadBucket" | "CreateBucket" | "GetBucketLocation" => ok(""),
        "PutObject" => {
            // Keys under an "ignorecond/" directory: a server that ignores
            // If-None-Match.
            if s.h("if-none-match") == Some("*")
                && st.objects.contains_key(&key)
                && !key.contains("/ignorecond/")
            {
                return (
                    412,
                    vec![],
                    b"<Error><Code>PreconditionFailed</Code><Message>At least one of the pre-conditions you specified did not hold</Message><Condition>If-None-Match</Condition></Error>".to_vec(),
                );
            }
            let etag = etag_of(&s.body);
            let mut meta = HeaderMap::new();
            for (n, v) in &s.headers {
                if n.as_str().starts_with("x-amz-meta-") || n == "content-type" {
                    meta.insert(n.clone(), v.clone());
                }
            }
            st.objects.insert(key, (s.body.clone(), meta));
            (200, vec![("etag".into(), etag)], vec![])
        }
        "HeadObject" | "GetObject" => {
            let Some((data, meta)) = st.objects.get(&key) else {
                return if s.method == "HEAD" {
                    (404, vec![], vec![])
                } else {
                    not_found()
                };
            };
            let etag = etag_of(data);
            if let Some(m) = s.h("if-match")
                && m != etag
            {
                return (
                    412,
                    vec![],
                    b"<Error><Code>PreconditionFailed</Code></Error>".to_vec(),
                );
            }
            let mut headers = vec![
                ("etag".to_owned(), etag),
                (
                    "last-modified".to_owned(),
                    "Tue, 24 Nov 2026 17:27:28 GMT".to_owned(),
                ),
            ];
            for (n, v) in meta {
                headers.push((n.to_string(), v.to_str().unwrap().to_owned()));
            }
            if s.method == "HEAD" {
                headers.push(("content-length".into(), data.len().to_string()));
                return (200, headers, vec![]);
            }
            // Keys containing "norange" are served by a server that ignores
            // Range headers.
            let range = s.h("range").filter(|_| !key.contains("norange"));
            match range {
                Some(r) => {
                    let spec = r.trim_start_matches("bytes=");
                    let (a, b) = spec.split_once('-').unwrap();
                    let len = data.len() as u64;
                    if len == 0 {
                        return (
                            416,
                            vec![],
                            b"<Error><Code>InvalidRange</Code></Error>".to_vec(),
                        );
                    }
                    let (start, end) = if a.is_empty() {
                        let n: u64 = b.parse().unwrap();
                        (len.saturating_sub(n), len.saturating_sub(1))
                    } else {
                        let a: u64 = a.parse().unwrap();
                        let b: u64 = if b.is_empty() {
                            len - 1
                        } else {
                            b.parse::<u64>().unwrap().min(len - 1)
                        };
                        (a, b)
                    };
                    if len == 0 || start >= len {
                        return (
                            416,
                            vec![],
                            b"<Error><Code>InvalidRange</Code></Error>".to_vec(),
                        );
                    }
                    headers.push(("content-range".into(), format!("bytes {start}-{end}/{len}")));
                    (206, headers, data[start as usize..=end as usize].to_vec())
                }
                None => (200, headers, data.clone()),
            }
        }
        "DeleteObject" => {
            st.objects.remove(&key);
            (204, vec![], vec![])
        }
        "DeleteObjects" => {
            let body = String::from_utf8_lossy(&s.body).into_owned();
            let bucket = key.clone();
            for k in xml_tag_values(&body, "Key") {
                st.objects.remove(&format!("{bucket}/{k}"));
            }
            ok("<DeleteResult></DeleteResult>")
        }
        "CreateMultipartUpload" => {
            st.next_upload += 1;
            let id = format!("upload-{}", st.next_upload);
            st.uploads.insert(id.clone(), BTreeMap::new());
            ok(&format!(
                "<InitiateMultipartUploadResult><UploadId>{id}</UploadId></InitiateMultipartUploadResult>"
            ))
        }
        "UploadPart" => {
            let id = &s.query["uploadId"];
            let n: u32 = s.query["partNumber"].parse().unwrap();
            let etag = etag_of(&s.body);
            st.uploads.get_mut(id).unwrap().insert(n, s.body.clone());
            (200, vec![("etag".into(), etag)], vec![])
        }
        "UploadPartCopy" | "CopyObject" => {
            let src = url_decode_plus(s.h("x-amz-copy-source").unwrap()).into_owned();
            let Some((data, meta)) = st.objects.get(&src).cloned() else {
                return not_found();
            };
            let data = match s.h("x-amz-copy-source-range") {
                Some(r) => {
                    let (a, b) = r.trim_start_matches("bytes=").split_once('-').unwrap();
                    data[a.parse::<usize>().unwrap()..=b.parse::<usize>().unwrap()].to_vec()
                }
                None => data,
            };
            let etag = etag_of(&data);
            if s.op() == "CopyObject" {
                st.objects.insert(key, (data, meta));
                ok(&format!(
                    "<CopyObjectResult><ETag>{etag}</ETag></CopyObjectResult>"
                ))
            } else {
                let id = &s.query["uploadId"];
                let n: u32 = s.query["partNumber"].parse().unwrap();
                st.uploads.get_mut(id).unwrap().insert(n, data);
                ok(&format!(
                    "<CopyPartResult><ETag>{etag}</ETag></CopyPartResult>"
                ))
            }
        }
        "CompleteMultipartUpload" => {
            if s.h("if-none-match") == Some("*") && st.objects.contains_key(&key) {
                return (
                    412,
                    vec![],
                    b"<Error><Code>PreconditionFailed</Code></Error>".to_vec(),
                );
            }
            let id = s.query["uploadId"].clone();
            let parts = st.uploads.remove(&id).unwrap();
            let body = String::from_utf8_lossy(&s.body).into_owned();
            let mut data = Vec::new();
            for n in xml_tag_values(&body, "PartNumber") {
                data.extend_from_slice(&parts[&n.parse::<u32>().unwrap()]);
            }
            st.objects.insert(key, (data, HeaderMap::new()));
            ok(
                "<CompleteMultipartUploadResult><ETag>\"x-2\"</ETag></CompleteMultipartUploadResult>",
            )
        }
        "AbortMultipartUpload" => {
            st.uploads.remove(&s.query["uploadId"]);
            (204, vec![], vec![])
        }
        "ListObjectsV2" => {
            let bucket = key.clone();
            let prefix = s.query.get("prefix").cloned().unwrap_or_default();
            let mut out = String::from("<ListBucketResult><IsTruncated>false</IsTruncated>");
            let mut n = 0;
            for (k, (d, _)) in &st.objects {
                if let Some(rest) = k.strip_prefix(&format!("{bucket}/"))
                    && rest.starts_with(&prefix)
                {
                    out.push_str(&format!(
                        "<Contents><Key>{rest}</Key><Size>{}</Size><ETag>{}</ETag></Contents>",
                        d.len(),
                        etag_of(d).replace('"', "&quot;")
                    ));
                    n += 1;
                }
            }
            out.push_str(&format!("<KeyCount>{n}</KeyCount></ListBucketResult>"));
            ok(&out)
        }
        _ => (
            400,
            vec![],
            b"<Error><Code>NotImplemented</Code></Error>".to_vec(),
        ),
    }
}

async fn fake() -> Fake {
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let store: Arc<Mutex<Store>> = Arc::default();
    let faults: Arc<Mutex<Vec<Fault>>> = Arc::default();
    let (log, st, fl) = (seen.clone(), store.clone(), faults.clone());
    let app = Router::new().fallback(move |req: Request| {
        let (log, st, fl) = (log.clone(), st.clone(), fl.clone());
        async move {
            let (parts, body) = req.into_parts();
            let body = axum::body::to_bytes(body, 64 << 20).await.unwrap().to_vec();
            let query = parts
                .uri
                .query()
                .unwrap_or("")
                .split('&')
                .filter(|p| !p.is_empty())
                .map(|p| {
                    let (k, v) = p.split_once('=').unwrap_or((p, ""));
                    (k.to_owned(), url_decode_plus(v).into_owned())
                })
                .collect();
            let s = Seen {
                method: parts.method.to_string(),
                path: parts.uri.path().to_owned(),
                query,
                headers: parts.headers,
                body,
            };
            let injected = {
                let mut f = fl.lock();
                let op = s.op();
                match f.iter_mut().find(|(o, left, _, _)| *o == op && *left > 0) {
                    Some(fault) => {
                        fault.1 -= 1;
                        Some((fault.2, fault.3))
                    }
                    None => None,
                }
            };
            let (status, headers, out) = match injected {
                Some((status, code)) => (
                    status,
                    vec![],
                    format!("<Error><Code>{code}</Code><Message>injected</Message></Error>")
                        .into_bytes(),
                ),
                None => handle(&st, &s),
            };
            log.lock().push(s);
            let mut r = Response::builder().status(StatusCode::from_u16(status).unwrap());
            for (k, v) in headers {
                r = r.header(k, v);
            }
            r.body(Body::from(out)).unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Fake {
        base: format!("http://{addr}"),
        seen,
        store,
        faults,
    }
}

fn s3(f: &Fake, extra: &[(&str, Value)]) -> S3FileSystem {
    let mut o = Options::new();
    o.insert("endpoint_url".into(), Value::from(f.base.as_str()));
    o.insert("key".into(), Value::from("AK"));
    o.insert("secret".into(), Value::from("SK"));
    o.insert("max_retries".into(), Value::Int(2));
    for (k, v) in extra {
        o.insert((*k).into(), v.clone());
    }
    S3FileSystem::with_options(
        S3Options::parse_with_env(o, Env::from_map([("AWS_EC2_METADATA_DISABLED", "true")]))
            .unwrap(),
    )
}

fn map(pairs: &[(&str, Value)]) -> Value {
    Value::Map(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect(),
    )
}

#[tokio::test]
async fn small_cat_is_one_request_and_large_is_parallel_and_pinned() {
    let f = fake().await;
    let fs = s3(&f, &[("request_size", Value::Int(1 << 20))]);
    let w = WriteOptions::default();
    fs.pipe_file("b/small", Bytes::from_static(b"tiny"), &w)
        .await
        .unwrap();
    let big = Bytes::from((0..(5u32 << 20) + 7).map(|i| i as u8).collect::<Vec<_>>());
    fs.pipe_file("b/big", big.clone(), &w).await.unwrap();
    f.clear();
    assert_eq!(
        &fs.cat_file("b/small", ByteRange::Full).await.unwrap()[..],
        b"tiny"
    );
    assert_eq!(f.ops(), vec!["GetObject"], "no HEAD before a small cat");
    f.clear();
    assert_eq!(fs.cat_file("b/big", ByteRange::Full).await.unwrap(), big);
    let gets = f.requests("GetObject");
    assert_eq!(gets.len(), 6);
    assert!(gets[0].h("if-match").is_none());
    let etag = etag_of(&big);
    assert!(
        gets[1..]
            .iter()
            .all(|g| g.h("if-match") == Some(etag.as_str()))
    );
    // Empty objects: the 416 answer to the first range means "empty".
    fs.pipe_file("b/empty", Bytes::new(), &w).await.unwrap();
    assert!(
        fs.cat_file("b/empty", ByteRange::Full)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn additional_kwargs_are_filtered_per_operation() {
    let f = fake().await;
    let fs = s3(
        &f,
        &[
            (
                "s3_additional_kwargs",
                map(&[
                    ("ServerSideEncryption", "aws:kms".into()),
                    ("SSEKMSKeyId", "kms-key".into()),
                    ("ACL", "bucket-owner-full-control".into()),
                    ("StorageClass", "STANDARD_IA".into()),
                ]),
            ),
            ("requester_pays", true.into()),
            ("part_size", Value::Int(5 << 20)),
        ],
    );
    let mut meta = BTreeMap::new();
    meta.insert("Owner".to_owned(), "me".to_owned());
    let w = WriteOptions {
        content_type: Some("text/csv".into()),
        metadata: meta,
        ..WriteOptions::default()
    };
    fs.pipe_file("b/k", Bytes::from_static(b"a,b\n"), &w)
        .await
        .unwrap();
    fs.pipe_file("b/big", Bytes::from(vec![1u8; 11 << 20]), &w)
        .await
        .unwrap();
    fs.info("b/k").await.unwrap();
    fs.cat_file("b/k", ByteRange::Full).await.unwrap();
    let put = &f.requests("PutObject")[0];
    assert_eq!(put.h("x-amz-server-side-encryption"), Some("aws:kms"));
    assert_eq!(
        put.h("x-amz-server-side-encryption-aws-kms-key-id"),
        Some("kms-key")
    );
    assert_eq!(put.h("x-amz-acl"), Some("bucket-owner-full-control"));
    assert_eq!(put.h("x-amz-storage-class"), Some("STANDARD_IA"));
    assert_eq!(put.h("x-amz-request-payer"), Some("requester"));
    assert_eq!(put.h("content-type"), Some("text/csv"));
    assert_eq!(put.h("x-amz-meta-owner"), Some("me"));
    let create = &f.requests("CreateMultipartUpload")[0];
    assert_eq!(create.h("x-amz-server-side-encryption"), Some("aws:kms"));
    assert_eq!(create.h("content-type"), Some("text/csv"));
    for op in [
        "UploadPart",
        "CompleteMultipartUpload",
        "HeadObject",
        "GetObject",
    ] {
        let r = &f.requests(op)[0];
        // Encryption settings belong to the object, not to these calls.
        assert!(r.h("x-amz-server-side-encryption").is_none(), "{op}");
        assert!(r.h("x-amz-acl").is_none(), "{op}");
        assert_eq!(r.h("x-amz-request-payer"), Some("requester"), "{op}");
    }
    assert_eq!(f.requests("UploadPart").len(), 3);
}

#[tokio::test]
async fn sse_c_headers_everywhere_including_copy_sources() {
    let f = fake().await;
    let key = "0123456789abcdef0123456789abcdef";
    let fs = s3(
        &f,
        &[(
            "s3_additional_kwargs",
            map(&[
                ("SSECustomerAlgorithm", "AES256".into()),
                ("SSECustomerKey", key.into()),
            ]),
        )],
    );
    let w = WriteOptions::default();
    fs.pipe_file("b/k", Bytes::from_static(b"secret"), &w)
        .await
        .unwrap();
    fs.cat_file("b/k", ByteRange::Full).await.unwrap();
    fs.info("b/k").await.unwrap();
    fs.cp_file("b/k", "b/k2").await.unwrap();
    for op in ["PutObject", "GetObject", "HeadObject", "CopyObject"] {
        let r = &f.requests(op)[0];
        assert_eq!(
            r.h("x-amz-server-side-encryption-customer-algorithm"),
            Some("AES256"),
            "{op}"
        );
        assert_eq!(
            r.h("x-amz-server-side-encryption-customer-key"),
            Some("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="),
            "{op}"
        );
        assert_eq!(
            r.h("x-amz-server-side-encryption-customer-key-md5"),
            Some("hRasmdxgYDKV3nvbahU1MA=="),
            "{op}"
        );
    }
    let copy = &f.requests("CopyObject")[0];
    assert_eq!(
        copy.h("x-amz-copy-source-server-side-encryption-customer-key"),
        Some("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
    );
    assert_eq!(
        copy.h("x-amz-copy-source-server-side-encryption-customer-algorithm"),
        Some("AES256")
    );
    assert_eq!(
        copy.h("x-amz-copy-source-server-side-encryption-customer-key-md5"),
        Some("hRasmdxgYDKV3nvbahU1MA==")
    );
}

#[tokio::test]
async fn payload_hash_modes() {
    let f = fake().await;
    let fs = s3(&f, &[]);
    fs.pipe_file(
        "b/k",
        Bytes::from_static(b"hello"),
        &WriteOptions::default(),
    )
    .await
    .unwrap();
    // Plain HTTP: the body is signed (botocore).
    assert_eq!(
        f.requests("PutObject")[0].h("x-amz-content-sha256"),
        Some("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    );
    let fs = s3(
        &f,
        &[(
            "config_kwargs",
            map(&[("s3", map(&[("payload_signing_enabled", false.into())]))]),
        )],
    );
    f.clear();
    fs.pipe_file(
        "b/k",
        Bytes::from_static(b"hello"),
        &WriteOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        f.requests("PutObject")[0].h("x-amz-content-sha256"),
        Some("UNSIGNED-PAYLOAD")
    );
}

#[tokio::test]
async fn deletes_are_batched_and_strict() {
    let f = fake().await;
    let fs = s3(&f, &[]);
    let w = WriteOptions::default();
    let mut paths = Vec::new();
    for i in 0..2500 {
        let p = format!("b/dir/{i:05}");
        f.store
            .lock()
            .objects
            .insert(p.clone(), (vec![1], HeaderMap::new()));
        paths.push(p);
    }
    fs.pipe_file("b/other", Bytes::from_static(b"x"), &w)
        .await
        .unwrap();
    paths.push("b/dir/missing".into());
    f.clear();
    let res = fs.rm_files(&paths).await;
    assert_eq!(res.len(), 2501);
    assert!(res[..2500].iter().all(Result::is_ok));
    assert_eq!(res[2500].as_ref().unwrap_err().kind(), ErrorKind::NotFound);
    let deletes = f.requests("DeleteObjects");
    assert_eq!(deletes.len(), 3, "1000 keys per DeleteObjects");
    assert!(deletes.iter().all(|d| d.h("content-md5").is_some()));
    // Existence was checked by listing, not with 2500 HEADs.
    assert!(f.requests("HeadObject").len() <= 1, "{:?}", f.ops().len());
    assert!(f.store.lock().objects.contains_key("b/other"));
    // Non-strict deletes are blind, like s3fs.
    let lax = s3(&f, &[("strict_delete", false.into())]);
    f.clear();
    lax.rm_file("b/never-existed").await.unwrap();
    assert_eq!(f.ops(), vec!["DeleteObject"]);
}

#[tokio::test]
async fn failed_multipart_upload_is_aborted() {
    let f = fake().await;
    let fs = s3(&f, &[("part_size", Value::Int(5 << 20))]);
    f.faults
        .lock()
        .push(("UploadPart", 100, 403, "AccessDenied"));
    let err = fs
        .pipe_file(
            "b/big",
            Bytes::from(vec![0u8; 11 << 20]),
            &WriteOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied, "{err}");
    let ops = f.ops();
    assert!(ops.contains(&"AbortMultipartUpload"), "{ops:?}");
    assert!(!ops.contains(&"CompleteMultipartUpload"));
    assert!(f.store.lock().uploads.is_empty());
}

#[tokio::test]
async fn dropped_write_handle_aborts_its_upload() {
    let f = fake().await;
    let fs = s3(&f, &[("part_size", Value::Int(5 << 20))]);
    let mut w = fs
        .open_write("b/partial", &WriteOptions::default())
        .await
        .unwrap();
    w.write(Bytes::from(vec![0u8; 11 << 20])).await.unwrap();
    drop(w);
    for _ in 0..50 {
        if f.ops().contains(&"AbortMultipartUpload") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(f.ops().contains(&"AbortMultipartUpload"), "{:?}", f.ops());
    assert!(!f.store.lock().objects.contains_key("b/partial"));
}

#[tokio::test]
async fn throttling_is_retried_and_errors_are_mapped() {
    let f = fake().await;
    let fs = s3(&f, &[]);
    fs.pipe_file("b/k", Bytes::from_static(b"v"), &WriteOptions::default())
        .await
        .unwrap();
    f.faults.lock().push(("GetObject", 2, 503, "SlowDown"));
    f.clear();
    assert_eq!(
        &fs.cat_file("b/k", ByteRange::Full).await.unwrap()[..],
        b"v"
    );
    assert_eq!(f.requests("GetObject").len(), 3);
    assert!(fs.stats().snapshot().retries >= 2);
    f.faults.lock().push(("HeadObject", 1, 403, "AccessDenied"));
    let e = fs.info("b/k").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    assert_eq!(e.path(), Some("b/k"));
    f.faults.lock().push(("GetObject", 1, 404, "NoSuchBucket"));
    assert_eq!(
        fs.cat_file("b/k", ByteRange::Full)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    f.faults
        .lock()
        .push(("PutObject", 1, 400, "EntityTooLarge"));
    let e = fs
        .pipe_file("b/k", Bytes::from_static(b"v"), &WriteOptions::default())
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io);
    assert!(
        e.details()
            .iter()
            .any(|d| matches!(d, fsfast_core::Detail::Errno(_))),
        "{e:?}"
    );
    // A copy answered "200 OK" with an <Error> body (S3 does this when an
    // error occurs after the response started) is an error, and retried
    // for InternalError.
    f.faults
        .lock()
        .push(("CopyObject", 1, 200, "InternalError"));
    f.clear();
    fs.cp_file("b/k", "b/k2").await.unwrap();
    assert_eq!(f.requests("CopyObject").len(), 2);
    f.faults.lock().push(("CopyObject", 1, 200, "AccessDenied"));
    let e = fs.cp_file("b/k", "b/k3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn create_only_writes_and_probe() {
    let f = fake().await;
    let fs = s3(&f, &[]);
    let cn = WriteOptions::default().with_mode(WriteMode::CreateNew);
    fs.pipe_file("b/dir/x", Bytes::from_static(b"1"), &cn)
        .await
        .unwrap();
    // The probe ran once, next to the key, and cleaned up after itself.
    let puts = f.requests("PutObject");
    assert!(
        puts[0]
            .path
            .starts_with("/b/dir/.fsfast-conditional-write-probe-"),
        "{}",
        puts[0].path
    );
    assert_eq!(puts[1].h("if-none-match"), Some("*"));
    assert_eq!(f.store.lock().objects.len(), 1);
    f.clear();
    let e = fs
        .pipe_file("b/dir/x", Bytes::from_static(b"2"), &cn)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AlreadyExists);
    assert_eq!(f.ops(), vec!["PutObject"], "the probe is not repeated");
}

#[tokio::test]
async fn speculative_info_races_head_and_list() {
    let f = fake().await;
    let fs = s3(&f, &[("speculative_info", true.into())]);
    fs.pipe_file("b/d/f", Bytes::from_static(b"x"), &WriteOptions::default())
        .await
        .unwrap();
    f.clear();
    let d = fs.info("b/d").await.unwrap();
    assert!(d.is_dir());
    let mut ops = f.ops();
    ops.sort();
    assert_eq!(ops, vec!["HeadObject", "ListObjectsV2"]);
    let fi = fs.info("b/d/f").await.unwrap();
    assert!(fi.is_file());
    assert_eq!(
        fs.info("b/nope").await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn servers_ignoring_ranges_still_get_exact_bytes() {
    let f = fake().await;
    let fs = s3(&f, &[("request_size", Value::Int(1 << 20))]);
    let data = Bytes::from(
        (0..(3u32 << 20) + 5)
            .map(|i| (i % 253) as u8)
            .collect::<Vec<_>>(),
    );
    fs.pipe_file("b/norange.bin", data.clone(), &WriteOptions::default())
        .await
        .unwrap();
    assert_eq!(
        fs.cat_file("b/norange.bin", ByteRange::Full).await.unwrap(),
        data
    );
    assert_eq!(
        fs.cat_file(
            "b/norange.bin",
            ByteRange::Bounded {
                start: 10,
                end: (2 << 20) + 7
            }
        )
        .await
        .unwrap(),
        data.slice(10..(2 << 20) + 7)
    );
    assert_eq!(
        fs.cat_file("b/norange.bin", ByteRange::Suffix(9))
            .await
            .unwrap(),
        data.slice(data.len() - 9..)
    );
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.bin");
    fs.get_file("b/norange.bin", &out).await.unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), data);
    // And through a handle (each read_at cuts its window out of the body).
    let h = fs
        .open_read("b/norange.bin", &Default::default())
        .await
        .unwrap();
    assert_eq!(h.read_at(5, 100).await.unwrap(), data.slice(5..105));
}

#[tokio::test]
async fn servers_ignoring_if_none_match_make_create_only_unsupported() {
    let f = fake().await;
    let fs = s3(&f, &[]);
    let cn = WriteOptions::default().with_mode(WriteMode::CreateNew);
    let e = fs
        .pipe_file("b/ignorecond/x", Bytes::from_static(b"1"), &cn)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
    // Nothing written, the probe object removed.
    assert!(f.store.lock().objects.is_empty());
    // Plain writes still work; the verdict is remembered (no new probe).
    f.clear();
    fs.pipe_file(
        "b/ignorecond/x",
        Bytes::from_static(b"1"),
        &WriteOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        fs.open_write("b/other", &cn).await.unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    assert_eq!(f.ops(), vec!["PutObject"]);
}

#[tokio::test]
async fn multipart_retries_parts_and_complete_errors_in_200_bodies() {
    let f = fake().await;
    let fs = s3(&f, &[("part_size", Value::Int(5 << 20))]);
    let data: Vec<u8> = (0..(11u32 << 20)).map(|i| (i % 251) as u8).collect();
    // One part fails transiently, and CompleteMultipartUpload answers
    // "200 OK" with an <Error> body (S3 does this when the failure happens
    // after the response started): both are retried, nothing else is.
    f.faults
        .lock()
        .push(("UploadPart", 1, 500, "InternalError"));
    f.faults
        .lock()
        .push(("CompleteMultipartUpload", 1, 200, "InternalError"));
    fs.pipe_file("b/big", Bytes::from(data.clone()), &WriteOptions::default())
        .await
        .unwrap();
    assert_eq!(f.requests("CreateMultipartUpload").len(), 1);
    assert_eq!(f.requests("UploadPart").len(), 4, "3 parts + 1 retry");
    assert_eq!(f.requests("CompleteMultipartUpload").len(), 2);
    assert!(!f.ops().contains(&"AbortMultipartUpload"));
    assert_eq!(f.store.lock().objects["b/big"].0, data);
    // A non-retryable error in a 200 body fails the upload and aborts it.
    f.clear();
    f.faults
        .lock()
        .push(("CompleteMultipartUpload", 1, 200, "InvalidPart"));
    let e = fs
        .pipe_file("b/big2", Bytes::from(data), &WriteOptions::default())
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io, "{e}");
    assert_eq!(f.requests("CompleteMultipartUpload").len(), 1);
    assert!(f.ops().contains(&"AbortMultipartUpload"));
    assert!(!f.store.lock().objects.contains_key("b/big2"));
}

#[tokio::test]
async fn multipart_boundaries() {
    let f = fake().await;
    let part = 5usize << 20;
    let fs = s3(&f, &[("part_size", Value::Int(part as i64))]);
    // Exactly one part: a single PutObject, through a handle too.
    for (name, len) in [("b/exact", part), ("b/empty", 0)] {
        f.clear();
        let mut w = fs.open_write(name, &WriteOptions::default()).await.unwrap();
        if len > 0 {
            // Written in uneven pieces.
            let d = vec![7u8; len];
            w.write(Bytes::copy_from_slice(&d[..1000])).await.unwrap();
            w.write(Bytes::copy_from_slice(&d[1000..])).await.unwrap();
        }
        w.close().await.unwrap();
        assert_eq!(f.ops(), vec!["PutObject"], "{name}");
        assert_eq!(f.store.lock().objects[name].0.len(), len);
    }
    // One byte more: two parts, the second of one byte.
    f.clear();
    let d: Vec<u8> = (0..part + 1).map(|i| (i % 253) as u8).collect();
    let mut w = fs
        .open_write("b/plus1", &WriteOptions::default())
        .await
        .unwrap();
    w.write(Bytes::from(d.clone())).await.unwrap();
    w.close().await.unwrap();
    let parts = f.requests("UploadPart");
    assert_eq!(parts.len(), 2);
    let mut sizes: Vec<usize> = parts.iter().map(|p| p.body.len()).collect();
    sizes.sort_unstable();
    assert_eq!(sizes, vec![1, part]);
    assert_eq!(f.store.lock().objects["b/plus1"].0, d);
    // pipe_file of exactly one part is one PutObject as well.
    f.clear();
    fs.pipe_file(
        "b/pipe-exact",
        Bytes::from(vec![1u8; part]),
        &WriteOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(f.ops(), vec!["PutObject"]);
}

/// Handles and filesystems may be `{:?}`-printed by applications (and by
/// `tracing` fields): neither the environment's secrets nor the shared
/// credentials file's contents may show up.
#[tokio::test]
async fn debug_output_never_contains_secrets() {
    let f = fake().await;
    let dir = tempfile::tempdir().unwrap();
    let creds_file = dir.path().join("credentials");
    std::fs::write(
        &creds_file,
        "[other]\naws_access_key_id = AKFILE\naws_secret_access_key = FILESECRET-abc\naws_session_token = FILETOKEN-abc\n",
    )
    .unwrap();
    let env = Env::from_map([
        ("AWS_ACCESS_KEY_ID", "AKENV"),
        ("AWS_SECRET_ACCESS_KEY", "ENVSECRET-xyz"),
        ("AWS_SESSION_TOKEN", "ENVTOKEN-xyz"),
        ("AWS_SHARED_CREDENTIALS_FILE", creds_file.to_str().unwrap()),
        ("AWS_CONFIG_FILE", "/nonexistent"),
        ("AWS_EC2_METADATA_DISABLED", "true"),
    ]);
    let mut o = Options::new();
    o.insert("endpoint_url".into(), Value::from(f.base.as_str()));
    o.insert("part_size".into(), Value::Int(5 << 20));
    o.insert(
        "s3_additional_kwargs".into(),
        map(&[
            ("SSECustomerAlgorithm", Value::from("AES256")),
            (
                "SSECustomerKey",
                Value::from("01234567890123456789012345678901"),
            ),
        ]),
    );
    let fs = S3FileSystem::with_options(S3Options::parse_with_env(o, env).unwrap());
    fs.pipe_file("b/k", Bytes::from_static(b"v"), &WriteOptions::default())
        .await
        .unwrap();
    let r = fs.open_read("b/k", &Default::default()).await.unwrap();
    let mut w = fs
        .open_write("b/w", &WriteOptions::default())
        .await
        .unwrap();
    w.write(Bytes::from(vec![0u8; 6 << 20])).await.unwrap();
    let printed = format!("{fs:?}\n{r:?}\n{w:?}\n{:?}", fs.options());
    w.abort().await.unwrap();
    for secret in [
        "ENVSECRET-xyz",
        "ENVTOKEN-xyz",
        "FILESECRET-abc",
        "FILETOKEN-abc",
        "01234567890123456789012345678901",
        // base64 of the SSE-C key.
        "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
    ] {
        assert!(!printed.contains(secret), "{secret} leaked in Debug output");
    }
}

#[tokio::test]
async fn conditional_write_conflicts_are_retried() {
    let f = fake().await;
    let fs = s3(&f, &[("probe_conditional_writes", false.into())]);
    let cn = WriteOptions::default().with_mode(WriteMode::CreateNew);
    // S3 answers 409 ConditionalRequestConflict when a conditional write
    // races another write of the key; it was not applied, retry it.
    f.faults
        .lock()
        .push(("PutObject", 1, 409, "ConditionalRequestConflict"));
    fs.pipe_file("b/c", Bytes::from_static(b"1"), &cn)
        .await
        .unwrap();
    assert_eq!(f.requests("PutObject").len(), 2);
    // The retry of a lost race is then refused as existing.
    f.faults
        .lock()
        .push(("PutObject", 1, 409, "ConditionalRequestConflict"));
    let e = fs
        .pipe_file("b/c", Bytes::from_static(b"2"), &cn)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AlreadyExists, "{e}");
}
