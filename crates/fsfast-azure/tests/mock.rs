//! Request construction against an in-process mock: Shared Key signatures
//! recomputed from what arrived on the wire, the ADLS Gen2 rename (and its
//! fallback to Copy Blob + Delete), error-code mapping, and retries of
//! throttled requests. Runs without external services.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::mock::{Mock, Reply, Seen};
use fsfast_azure::AzureBlobFileSystem;
use fsfast_azure::auth::SharedKey;
use fsfast_azure::connstr::DEVSTORE_ACCOUNT_KEY;
use fsfast_core::{Detail, ErrorKind, FileSystem, Options, Value};
use fsfast_http_transport::{Method, Request};

fn fs(mock: &Mock, extra: &[(&str, Value)]) -> AzureBlobFileSystem {
    let mut o: Options = extra
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    o.insert("account_name".into(), Value::Str("acct".into()));
    o.insert(
        "account_key".into(),
        Value::Str(DEVSTORE_ACCOUNT_KEY.into()),
    );
    o.insert(
        "account_host".into(),
        Value::Str(format!("{}/acct", mock.url())),
    );
    AzureBlobFileSystem::from_options_with_env(o, &|_| None).unwrap()
}

/// Recompute the Shared Key signature of a request as received.
fn verify_signature(mock: &Mock, s: &Seen) {
    let url = if s.query.is_empty() {
        format!("{}{}", mock.url(), s.path)
    } else {
        format!("{}{}?{}", mock.url(), s.path, s.query)
    };
    let mut req = Request::new(Method::from_bytes(s.method.as_bytes()).unwrap(), &url).unwrap();
    for (k, v) in &s.headers {
        req.headers_mut().insert(k.clone(), v.clone());
    }
    let key = SharedKey::new("acct", DEVSTORE_ACCOUNT_KEY).unwrap();
    let sts = key.string_to_sign(&s.method, req.url(), req.headers(), s.body.len() as u64);
    assert_eq!(
        s.header("authorization"),
        Some(key.authorization(&sts).as_str()),
        "{} {}",
        s.method,
        url
    );
}

#[tokio::test]
async fn hns_rename_is_one_signed_request() {
    let mock = Mock::start(|s: &Seen| {
        if s.method == "PUT" && s.path.starts_with("/dfs/") {
            return Reply::new(201);
        }
        Reply::azure_error(500, "InternalError")
    })
    .await;
    let dfs = format!("{}/dfs/acct", mock.url());
    let fs = fs(
        &mock,
        &[
            ("hns", Value::Bool(true)),
            ("dfs_endpoint", Value::Str(dfs)),
        ],
    );
    assert!(fs.capabilities().atomic_rename);
    fs.mv_file("c/old name/ü", "c/new name").await.unwrap();
    let seen = mock.seen();
    assert_eq!(seen.len(), 1);
    let s = &seen[0];
    assert_eq!(s.path, "/dfs/acct/c/new%20name");
    assert_eq!(s.query, "mode=legacy");
    assert_eq!(s.header("x-ms-rename-source"), Some("/c/old%20name/%C3%BC"));
    verify_signature(&mock, s);
}

#[tokio::test]
async fn hns_rename_falls_back_to_copy() {
    let mock = Mock::start(|s: &Seen| match (s.method.as_str(), s.path.as_str()) {
        ("PUT", p) if p.starts_with("/dfs/") => {
            Reply::azure_error(409, "EndpointUnsupportedAccountFeatures")
        }
        ("PUT", "/acct/c/b") => Reply::new(202)
            .header("x-ms-copy-status", "success")
            .header("x-ms-copy-id", "1"),
        ("DELETE", "/acct/c/a") => Reply::new(202),
        _ => Reply::azure_error(400, "InvalidUri"),
    })
    .await;
    let dfs = format!("{}/dfs/acct", mock.url());
    let fs = fs(
        &mock,
        &[
            ("hns", Value::Bool(true)),
            ("dfs_endpoint", Value::Str(dfs)),
        ],
    );
    fs.mv_file("c/a", "c/b").await.unwrap();
    let seen = mock.seen();
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert_eq!(
        seen[1].header("x-ms-copy-source"),
        Some(format!("{}/acct/c/a", mock.url()).as_str())
    );
    for s in &seen {
        verify_signature(&mock, s);
    }
}

#[tokio::test]
async fn pending_copies_are_polled() {
    let polls = Arc::new(AtomicUsize::new(0));
    let p2 = polls.clone();
    let mock = Mock::start(move |s: &Seen| match s.method.as_str() {
        "PUT" => Reply::new(202)
            .header("x-ms-copy-status", "pending")
            .header("x-ms-copy-id", "cid"),
        "HEAD" => {
            let n = p2.fetch_add(1, Ordering::SeqCst);
            let status = if n < 2 { "pending" } else { "success" };
            Reply::new(200)
                .header("content-length", "1")
                .header("x-ms-copy-status", status)
                .header("x-ms-copy-id", "cid")
        }
        _ => Reply::new(400),
    })
    .await;
    let fs = fs(&mock, &[]);
    fs.cp_file("c/a", "c/b").await.unwrap();
    assert_eq!(polls.load(Ordering::SeqCst), 3);

    let mock = Mock::start(|s: &Seen| match s.method.as_str() {
        "PUT" => Reply::new(202)
            .header("x-ms-copy-status", "pending")
            .header("x-ms-copy-id", "cid"),
        _ => Reply::new(200)
            .header("content-length", "1")
            .header("x-ms-copy-status", "failed")
            .header("x-ms-copy-status-description", "500 InternalError")
            .header("x-ms-copy-id", "cid"),
    })
    .await;
    let e = self::fs(&mock, &[])
        .cp_file("c/a", "c/b")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io);
    assert!(e.to_string().contains("failed"), "{e}");
}

#[tokio::test]
async fn throttling_is_retried_and_codes_are_attached() {
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    let mock = Mock::start(move |s: &Seen| {
        if s.path == "/acct/c/busy" && n2.fetch_add(1, Ordering::SeqCst) < 2 {
            return Reply::azure_error(503, "ServerBusy").header("retry-after", "0");
        }
        match s.path.as_str() {
            "/acct/c/busy" => Reply::new(200)
                .header("content-length", "4")
                .header("etag", "\"0x2\"")
                .header("x-ms-blob-type", "BlockBlob"),
            "/acct/c/locked" => Reply::azure_error(412, "LeaseIdMissing"),
            "/acct/c/denied" => Reply::azure_error(403, "AuthorizationPermissionMismatch"),
            _ => Reply::azure_error(404, "BlobNotFound"),
        }
    })
    .await;
    let fs = fs(&mock, &[]);
    assert_eq!(fs.info("c/busy").await.unwrap().size, 4);
    assert_eq!(n.load(Ordering::SeqCst), 3);
    assert_eq!(fs.stats().snapshot().retries, 2);

    let e = fs.info("c/locked").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    assert!(e.details().contains(&Detail::Code("LeaseIdMissing".into())));
    assert!(e.details().contains(&Detail::Http(412)));
    let e = fs.rm_file("c/denied").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    assert_eq!(e.path(), Some("c/denied"));
}

#[tokio::test]
async fn server_timeout_and_secondary_location() {
    let mock = Mock::start(|_| {
        Reply::new(200)
            .header("content-length", "1")
            .header("etag", "\"0x1\"")
    })
    .await;
    let mut o: Options = Options::new();
    o.insert("connection_string".into(), Value::Str(format!(
        "AccountName=acct;AccountKey={DEVSTORE_ACCOUNT_KEY};BlobEndpoint=http://192.0.2.1/acct;BlobSecondaryEndpoint={}/acct-secondary",
        mock.url()
    )));
    o.insert("location_mode".into(), Value::Str("secondary".into()));
    o.insert("timeout".into(), Value::Int(17));
    let fs = AzureBlobFileSystem::from_options_with_env(o, &|_| None).unwrap();
    fs.info("c/x").await.unwrap();
    let s = &mock.seen()[0];
    assert_eq!(s.path, "/acct-secondary/c/x");
    assert_eq!(s.query, "timeout=17");
}
