//! Behaviour against an in-process mock of GCS, OAuth token endpoints and
//! the GCE metadata server: every credential type, token caching and
//! refresh, requester pays, retries and error mapping, resumable-upload
//! recovery, generation pinning and CRC32C verification. No services
//! needed.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use common::mock::{Mock, Reply, Seen, closed_port, object};
use fsfast_core::{
    ByteRange, Detail, ErrorKind, FileSystem, Options, ReadOptions, Value, WriteMode, WriteOptions,
};
use fsfast_gcs::{GCSFileSystem, GcsEnv, crc32c_b64};
use parking_lot::Mutex;
use serde_json::{Value as Json, json};

const SCOPE: &str = "https://www.googleapis.com/auth/devstorage.full_control";

fn opts(endpoint: &str, pairs: &[(&str, Value)]) -> Options {
    let mut o = Options::new();
    o.insert("endpoint_url".into(), Value::from(endpoint));
    // Never through the developer's proxy.
    let mut sk = BTreeMap::new();
    sk.insert("trust_env".to_owned(), Value::Bool(false));
    o.insert("session_kwargs".into(), Value::Map(sk));
    // Fast retries in tests.
    o.insert("max_retries".into(), Value::Int(2));
    for (k, v) in pairs {
        o.insert((*k).into(), v.clone());
    }
    o
}

fn fs_with(endpoint: &str, pairs: &[(&str, Value)], env: GcsEnv) -> GCSFileSystem {
    GCSFileSystem::from_options_with_env(opts(endpoint, pairs), env).unwrap()
}

fn no_gce() -> GcsEnv {
    GcsEnv::from_pairs([("NO_GCE_CHECK", "true")])
}

fn sa_key(token_uri: &str) -> BTreeMap<String, Value> {
    let v: Json = serde_json::from_str(include_str!("data/vectors.json")).unwrap();
    let mut m: BTreeMap<String, Value> = v["info"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), Value::from(v.as_str().unwrap())))
        .collect();
    m.insert("token_uri".into(), Value::from(token_uri));
    m
}

fn form(s: &Seen) -> BTreeMap<String, String> {
    std::str::from_utf8(&s.body)
        .unwrap()
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| {
            (
                k.to_owned(),
                percent_encoding::percent_decode_str(&v.replace('+', " "))
                    .decode_utf8_lossy()
                    .into_owned(),
            )
        })
        .collect()
}

fn token_reply(token: &str) -> Reply {
    Reply::json(200, json!({"access_token": token, "expires_in": 3599, "token_type": "Bearer"}))
}

fn empty_listing() -> Reply {
    Reply::json(200, json!({"kind": "storage#objects"}))
}

/// A GCS + token endpoint that accepts `Bearer <token>` for objects.
fn gcs_handler(s: &Seen, accept: &str) -> Reply {
    if s.path == "/token" {
        return token_reply(accept);
    }
    if s.header("authorization") != Some(&format!("Bearer {accept}")) {
        return Reply::gcs_error(401, "authError", "Invalid Credentials");
    }
    if s.path == "/storage/v1/b/bkt/o" {
        return empty_listing();
    }
    if s.path == "/storage/v1/b/bkt/o/obj" {
        return Reply::json(200, object("bkt", "obj", 3, 7));
    }
    Reply::gcs_error(404, "notFound", "Not Found")
}

#[tokio::test]
async fn service_account_token_is_fetched_once_and_shared() {
    let mock = Mock::start(|s| gcs_handler(s, "tok-1")).await;
    let fs = fs_with(
        &mock.url(),
        &[("token", Value::Map(sa_key(&format!("{}/token", mock.url()))))],
        no_gce(),
    );
    assert_eq!(fs.auth_method(), "token");
    let futs: Vec<_> = (0..16).map(|_| fs.info("bkt/obj")).collect();
    for r in futures::future::join_all(futs).await {
        let i = r.unwrap();
        assert_eq!(i.size, 3);
        assert_eq!(i.extra["generation"], Value::from("7"));
    }
    let tokens: Vec<Seen> = mock.seen().into_iter().filter(|s| s.path == "/token").collect();
    assert_eq!(tokens.len(), 1, "one token exchange shared by all requests");
    let f = form(&tokens[0]);
    assert_eq!(f["grant_type"], "urn:ietf:params:oauth:grant-type:jwt-bearer");
    assert_eq!(f["assertion"].split('.').count(), 3);
    assert_eq!(tokens[0].header("content-type"), Some("application/x-www-form-urlencoded"));
    // The JWT carries google-auth's claims.
    let payload = f["assertion"].split('.').nth(1).unwrap();
    use base64::Engine as _;
    let claims: Json =
        serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    assert_eq!(claims["scope"], SCOPE);
    assert_eq!(claims["aud"], "https://oauth2.googleapis.com/token");
    assert_eq!(claims["iss"], "tester@fsfast-test.iam.gserviceaccount.com");
    assert_eq!(claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(), 3600);
}

#[tokio::test]
async fn a_401_refreshes_the_token_once() {
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    let mock = Mock::start(move |s| {
        if s.path == "/token" {
            let k = n2.fetch_add(1, Ordering::SeqCst) + 1;
            return token_reply(&format!("tok-{k}"));
        }
        gcs_handler(s, "tok-2")
    })
    .await;
    let fs = fs_with(
        &mock.url(),
        &[("token", Value::Map(sa_key(&format!("{}/token", mock.url()))))],
        no_gce(),
    );
    let i = fs.info("bkt/obj").await.unwrap();
    assert_eq!(i.size, 3);
    assert_eq!(n.load(Ordering::SeqCst), 2, "the stale token was replaced once");
    // Later requests use the fresh token without refreshing again.
    fs.info("bkt/obj").await.unwrap();
    assert_eq!(n.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn authorized_user_refresh_grant_and_quota_project() {
    let mock = Mock::start(|s| gcs_handler(s, "user-tok")).await;
    let mut user = BTreeMap::new();
    user.insert("client_id".to_owned(), Value::from("cid"));
    user.insert("client_secret".to_owned(), Value::from("csecret"));
    user.insert("refresh_token".to_owned(), Value::from("rtok"));
    user.insert("quota_project_id".to_owned(), Value::from("quota-p"));
    user.insert("token_uri".to_owned(), Value::from(format!("{}/token", mock.url())));
    let fs = fs_with(&mock.url(), &[("token", Value::Map(user))], no_gce());
    fs.info("bkt/obj").await.unwrap();
    let seen = mock.seen();
    let tok = seen.iter().find(|s| s.path == "/token").unwrap();
    let f = form(tok);
    assert_eq!(f["grant_type"], "refresh_token");
    assert_eq!(f["client_id"], "cid");
    assert_eq!(f["client_secret"], "csecret");
    assert_eq!(f["refresh_token"], "rtok");
    let get = seen.iter().find(|s| s.path == "/storage/v1/b/bkt/o/obj").unwrap();
    assert_eq!(get.header("x-goog-user-project"), Some("quota-p"));
}

#[tokio::test]
async fn token_endpoint_errors_are_permission_denied() {
    let mock = Mock::start(|s| {
        if s.path == "/token" {
            return Reply::json(400, json!({"error": "invalid_grant", "error_description": "Invalid JWT Signature."}));
        }
        Reply::new(500)
    })
    .await;
    let fs = fs_with(
        &mock.url(),
        &[("token", Value::Map(sa_key(&format!("{}/token", mock.url()))))],
        no_gce(),
    );
    let e = fs.cat_file("bkt/obj", ByteRange::Full).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
    assert!(e.details().contains(&Detail::Code("invalid_grant".into())), "{e:?}");
    assert!(e.to_string().contains("Invalid JWT Signature"), "{e}");
}

#[tokio::test]
async fn raw_tokens_are_sent_as_is_and_never_refreshed() {
    let mock = Mock::start(|s| gcs_handler(s, "ya29.raw")).await;
    let fs = fs_with(&mock.url(), &[("token", Value::from("ya29.raw"))], no_gce());
    assert_eq!(fs.info("bkt/obj").await.unwrap().size, 3);
    let bad = fs_with(&mock.url(), &[("token", Value::from("ya29.expired"))], no_gce());
    let e = bad.info("bkt/obj").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    assert_eq!(e.http_status(), Some(401));
    assert_eq!(mock.count(|s| s.path == "/token"), 0);
}

#[tokio::test]
async fn token_files_are_read_at_construction() {
    let mock = Mock::start(|s| gcs_handler(s, "file-tok")).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.json");
    let key: BTreeMap<String, Json> = sa_key(&format!("{}/token", mock.url()))
        .into_iter()
        .map(|(k, v)| (k, json!(v.as_str().unwrap())))
        .collect();
    std::fs::write(&path, serde_json::to_vec(&key).unwrap()).unwrap();
    let fs = fs_with(&mock.url(), &[("token", Value::from(path.to_str().unwrap()))], no_gce());
    assert!(fs.capabilities().signed_urls);
    assert_eq!(fs.info("bkt/obj").await.unwrap().size, 3);
    // A file that is not JSON fails when the filesystem is built.
    std::fs::write(&path, b"not json").unwrap();
    let e = GCSFileSystem::from_options_with_env(
        opts(&mock.url(), &[("token", Value::from(path.to_str().unwrap()))]),
        no_gce(),
    )
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
}

/// A metadata server (and GCS) on one mock.
async fn metadata_mock(token: &'static str) -> Mock {
    Mock::start(move |s| {
        if s.path == "/" {
            return Reply::new(200).header("metadata-flavor", "Google");
        }
        if s.path.starts_with("/computeMetadata/") {
            if s.header("metadata-flavor") != Some("Google") {
                return Reply::new(403);
            }
            return match s.path.as_str() {
                "/computeMetadata/v1/project/project-id" => {
                    Reply::new(200).header("metadata-flavor", "Google").body("meta-proj")
                }
                "/computeMetadata/v1/instance/service-accounts/default/token" => {
                    Reply::json(200, json!({"access_token": token, "expires_in": 3599, "token_type": "Bearer"}))
                        .header("metadata-flavor", "Google")
                }
                _ => Reply::new(404).header("metadata-flavor", "Google"),
            };
        }
        gcs_handler(s, token)
    })
    .await
}

#[tokio::test]
async fn default_credentials_from_the_metadata_server() {
    let mock = metadata_mock("meta-tok").await;
    let env = GcsEnv::from_pairs([
        ("GCE_METADATA_HOST", mock.host()),
        ("GCE_METADATA_IP", mock.host()),
        ("HOME", "/nonexistent".to_owned()),
    ]);
    let fs = fs_with(&mock.url(), &[], env.clone());
    assert_eq!(fs.auth_method(), "auto");
    assert_eq!(fs.project().await.unwrap().as_deref(), Some("meta-proj"));
    assert_eq!(fs.info("bkt/obj").await.unwrap().size, 3);
    let seen = mock.seen();
    let tok = seen
        .iter()
        .find(|s| s.path.ends_with("/default/token"))
        .expect("token requested from the metadata server");
    assert_eq!(tok.param("scopes").as_deref(), Some(SCOPE));
    assert!(seen.iter().any(|s| s.path == "/"), "residency ping");

    // token="google_default" explicitly, with a matching project.
    let fs = fs_with(
        &mock.url(),
        &[("token", Value::from("google_default")), ("project", Value::from("meta-proj"))],
        env.clone(),
    );
    assert_eq!(fs.info("bkt/obj").await.unwrap().size, 3);
    // A different explicit project is refused (gcsfs: ValueError).
    let fs = fs_with(
        &mock.url(),
        &[("token", Value::from("google_default")), ("project", Value::from("other"))],
        env,
    );
    assert_eq!(fs.info("bkt/obj").await.unwrap_err().kind(), ErrorKind::InvalidInput);
}

#[tokio::test]
async fn without_credentials_requests_are_anonymous() {
    let gcs = Mock::start(|s| {
        if s.header("authorization").is_some() {
            return Reply::new(400);
        }
        if s.path == "/storage/v1/b/bkt/o/obj" {
            return Reply::json(200, object("bkt", "obj", 3, 7));
        }
        empty_listing()
    })
    .await;
    let dead = closed_port().await;
    let dir = tempfile::tempdir().unwrap();
    let env = GcsEnv::from_pairs([
        ("GCE_METADATA_HOST", dead.to_string()),
        ("GCE_METADATA_IP", dead.to_string()),
        ("GCE_METADATA_TIMEOUT", "0.2".to_owned()),
        ("GCE_METADATA_DETECT_RETRIES", "1".to_owned()),
        ("HOME", dir.path().to_str().unwrap().to_owned()),
    ])
    .with_product_name_file(dir.path().join("product_name"));
    let fs = fs_with(&gcs.url(), &[], env.clone());
    assert_eq!(fs.info("bkt/obj").await.unwrap().size, 3);
    // Explicit google_default has nothing to fall back to.
    let fs = fs_with(&gcs.url(), &[("token", Value::from("google_default"))], env.clone());
    assert_eq!(fs.info("bkt/obj").await.unwrap_err().kind(), ErrorKind::PermissionDenied);
    // The DMI product name alone also marks a GCE machine (then the
    // metadata server must answer).
    std::fs::write(dir.path().join("product_name"), "Google Compute Engine\n").unwrap();
    let env2 = GcsEnv::from_pairs([
        ("GCE_METADATA_HOST", dead.to_string()),
        ("GCE_METADATA_IP", format!("{}", dead)),
        ("GCE_METADATA_TIMEOUT", "0.2".to_owned()),
        ("GCE_METADATA_DETECT_RETRIES", "1".to_owned()),
        ("HOME", dir.path().to_str().unwrap().to_owned()),
    ])
    .with_product_name_file(dir.path().join("product_name"));
    let fs = fs_with(&gcs.url(), &[("token", Value::from("google_default"))], env2);
    // Detected as GCE, but no token can be fetched: an error, not anon.
    assert!(fs.info("bkt/obj").await.is_err());
}

#[tokio::test]
async fn token_cloud_needs_googles_endpoint() {
    let mock = Mock::start(|_| Reply::new(500)).await;
    let e = GCSFileSystem::from_options_with_env(opts(&mock.url(), &[("token", Value::from("cloud"))]), no_gce())
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
    for (t, kind) in [("cache", ErrorKind::Unsupported), ("browser", ErrorKind::Unsupported)] {
        let e = GCSFileSystem::from_options_with_env(opts(&mock.url(), &[("token", Value::from(t))]), no_gce())
            .unwrap_err();
        assert_eq!(e.kind(), kind, "{t}");
    }
}

#[tokio::test]
async fn adc_file_from_the_environment() {
    let mock = Mock::start(|s| gcs_handler(s, "adc-tok")).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("adc.json");
    let key: BTreeMap<String, Json> = sa_key(&format!("{}/token", mock.url()))
        .into_iter()
        .map(|(k, v)| (k, json!(v.as_str().unwrap())))
        .collect();
    std::fs::write(&path, serde_json::to_vec(&key).unwrap()).unwrap();
    let env = GcsEnv::from_pairs([
        ("GOOGLE_APPLICATION_CREDENTIALS", path.to_str().unwrap()),
        ("NO_GCE_CHECK", "true"),
    ]);
    let fs = fs_with(&mock.url(), &[], env.clone());
    assert_eq!(fs.auth_method(), "google_default");
    assert_eq!(fs.project().await.unwrap().as_deref(), Some("fsfast-test"));
    assert_eq!(fs.info("bkt/obj").await.unwrap().size, 3);
    // GOOGLE_CLOUD_PROJECT overrides the file's project.
    let env2 = GcsEnv::from_pairs([
        ("GOOGLE_APPLICATION_CREDENTIALS", path.to_str().unwrap()),
        ("GOOGLE_CLOUD_PROJECT", "env-proj"),
        ("NO_GCE_CHECK", "true"),
    ]);
    let fs = fs_with(&mock.url(), &[("token", Value::from("google_default"))], env2);
    assert_eq!(fs.project().await.unwrap().as_deref(), Some("env-proj"));
    // An explicit mismatching project fails at construction for
    // google_default, and silently skips the method for token=None.
    let e = GCSFileSystem::from_options_with_env(
        opts(&mock.url(), &[("token", Value::from("google_default")), ("project", Value::from("x"))]),
        env.clone(),
    )
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
    let fs = fs_with(&mock.url(), &[("project", Value::from("x"))], env);
    assert_eq!(fs.auth_method(), "auto");
}

#[tokio::test]
async fn requester_pays_bills_the_user_project() {
    let mock = Mock::start(|s| {
        if s.path == "/storage/v1/b/bkt/o/obj" {
            return Reply::json(200, object("bkt", "obj", 3, 7));
        }
        if s.path.starts_with("/download/") {
            return Reply::new(200).header("x-goog-generation", "7").body("abc");
        }
        empty_listing()
    })
    .await;
    let fs = fs_with(
        &mock.url(),
        &[("token", Value::from("anon")), ("requester_pays", Value::from("bill-me"))],
        no_gce(),
    );
    fs.info("bkt/obj").await.unwrap();
    assert_eq!(fs.cat_file("bkt/obj", ByteRange::Full).await.unwrap(), Bytes::from_static(b"abc"));
    let seen = mock.seen();
    assert!(seen.len() >= 3);
    for s in &seen {
        assert_eq!(s.param("userProject").as_deref(), Some("bill-me"), "{s:?}");
    }
    let fs = fs_with(
        &mock.url(),
        &[
            ("token", Value::from("anon")),
            ("requester_pays", Value::Bool(true)),
            ("project", Value::from("proj-p")),
        ],
        no_gce(),
    );
    fs.info("bkt/obj").await.unwrap();
    assert_eq!(mock.seen().last().unwrap().param("userProject").as_deref(), Some("proj-p"));
}

/// A minimal resumable-upload server that persists only half of the first
/// chunk it receives.
struct Upload {
    data: Vec<u8>,
    short_once: bool,
    done: Option<Json>,
}

#[tokio::test]
async fn resumable_upload_resends_what_was_not_persisted() {
    let state = Arc::new(Mutex::new(Upload {
        data: Vec::new(),
        short_once: true,
        done: None,
    }));
    let st = state.clone();
    let base = Arc::new(Mutex::new(String::new()));
    let b2 = base.clone();
    let mock = Mock::start(move |s| {
        let mut st = st.lock();
        if s.method == "POST" && s.path == "/upload/storage/v1/b/bkt/o" {
            assert_eq!(s.param("uploadType").as_deref(), Some("resumable"));
            assert_eq!(s.param("name").as_deref(), Some("big.bin"));
            assert_eq!(s.header("x-upload-content-type"), Some("application/octet-stream"));
            return Reply::new(200).header("location", &format!("{}/session/1?upload_id=xyz", b2.lock()));
        }
        if s.method == "PUT" && s.path == "/session/1" {
            let cr = s.header("content-range").unwrap().to_owned();
            let spec = cr.strip_prefix("bytes ").unwrap();
            let (range, total) = spec.split_once('/').unwrap();
            if range != "*" {
                let (a, _b) = range.split_once('-').unwrap();
                let a: usize = a.parse().unwrap();
                assert!(a <= st.data.len(), "gap: chunk at {a}, have {}", st.data.len());
                let mut body = s.body.to_vec();
                if st.short_once && body.len() >= 512 << 10 {
                    // GCS persists multiples of 256 KiB.
                    st.short_once = false;
                    body.truncate(256 << 10);
                }
                st.data.truncate(a);
                st.data.extend_from_slice(&body);
            }
            if total != "*" && st.data.len() == total.parse::<usize>().unwrap() {
                let crc = crc32c_b64(crc32c::crc32c(&st.data));
                let obj = json!({"name": "big.bin", "bucket": "bkt", "size": st.data.len().to_string(), "crc32c": crc, "generation": "9"});
                st.done = Some(obj.clone());
                return Reply::json(200, obj);
            }
            let r = format!("bytes=0-{}", st.data.len() - 1);
            return Reply::new(308).header("range", &r);
        }
        Reply::gcs_error(404, "notFound", "Not Found")
    })
    .await;
    *base.lock() = mock.url();
    let fs = fs_with(
        &mock.url(),
        &[
            ("token", Value::from("anon")),
            ("upload_chunk_size", Value::Int(512 << 10)),
            ("consistency", Value::from("crc32c")),
        ],
        no_gce(),
    );
    let payload: Vec<u8> = (0..(1300 << 10)).map(|i: u32| (i % 251) as u8).collect();
    let mut w = fs.open_write("bkt/big.bin", &WriteOptions::default()).await.unwrap();
    for piece in payload.chunks(10_000) {
        w.write(Bytes::copy_from_slice(piece)).await.unwrap();
    }
    w.close().await.unwrap();
    w.close().await.unwrap();
    let st = state.lock();
    assert!(st.done.is_some());
    assert!(!st.short_once, "the short write happened");
    assert!(
        mock.count(|s| s.header("content-range") == Some("bytes 262144-524287/*")) == 1,
        "the unpersisted half was sent again"
    );
    assert_eq!(st.data, payload);
    // Every non-final chunk was a multiple of 256 KiB.
    for s in mock.seen().iter().filter(|s| s.method == "PUT") {
        let cr = s.header("content-range").unwrap();
        if cr.ends_with("/*") {
            assert_eq!(s.body.len() % (256 << 10), 0, "{cr}");
        }
    }
}

#[tokio::test]
async fn aborted_uploads_cancel_the_session() {
    let base = Arc::new(Mutex::new(String::new()));
    let b2 = base.clone();
    let mock = Mock::start(move |s| match s.method.as_str() {
        "POST" => Reply::new(200).header(
            "location",
            &format!("{}/session?upload_id=1&ifGenerationMatch=0", b2.lock()),
        ),
        "PUT" => Reply::new(308).header("range", &format!("bytes=0-{}", s.body.len() - 1)),
        "DELETE" => Reply::gcs_error(499, "", ""),
        _ => Reply::new(500),
    })
    .await;
    *base.lock() = mock.url();
    let fs = fs_with(
        &mock.url(),
        &[("token", Value::from("anon")), ("upload_chunk_size", Value::Int(256 << 10))],
        no_gce(),
    );
    let opts = WriteOptions::default().with_mode(WriteMode::CreateNew);
    let mut w = fs.open_write("bkt/x.bin", &opts).await.unwrap();
    w.write(Bytes::from(vec![1u8; 300 << 10])).await.unwrap();
    w.flush().await.unwrap();
    w.abort().await.unwrap();
    w.abort().await.unwrap();
    let seen = mock.seen();
    let log: Vec<String> = seen.iter().map(|s| format!("{} {}", s.method, s.path)).collect();
    assert_eq!(log, ["POST /upload/storage/v1/b/bkt/o", "PUT /session", "DELETE /session"]);
    assert_eq!(seen[0].param("ifGenerationMatch").as_deref(), Some("0"));
    // gcsfs drops the precondition when cancelling.
    assert_eq!(seen[2].param("ifGenerationMatch"), None);
    assert!(w.write(Bytes::from_static(b"x")).await.is_err());

    // Dropping an unfinished upload cancels it in the background.
    let mut w = fs.open_write("bkt/y.bin", &WriteOptions::default()).await.unwrap();
    w.write(Bytes::from(vec![1u8; 300 << 10])).await.unwrap();
    w.flush().await.unwrap();
    drop(w);
    for _ in 0..100 {
        if mock.count(|s| s.method == "DELETE") == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(mock.count(|s| s.method == "DELETE"), 2);
}

#[tokio::test]
async fn small_writes_are_one_request_and_create_new_maps_412() {
    let exists = Arc::new(Mutex::new(false));
    let e2 = exists.clone();
    let mock = Mock::start(move |s| {
        if s.method == "POST" && s.path == "/upload/storage/v1/b/bkt/o" {
            let mut ex = e2.lock();
            if s.param("ifGenerationMatch").as_deref() == Some("0") && *ex {
                return Reply::gcs_error(412, "conditionNotMet", "Precondition failed");
            }
            *ex = true;
            let len = s.body.len();
            return Reply::json(200, json!({"name": s.param("name").unwrap_or_default(), "size": len.to_string()}));
        }
        Reply::new(500)
    })
    .await;
    let fs = fs_with(&mock.url(), &[("token", Value::from("anon"))], no_gce());
    let mut w = fs.open_write("bkt/a.csv", &WriteOptions::default()).await.unwrap();
    w.write(Bytes::from_static(b"x,y\n")).await.unwrap();
    w.close().await.unwrap();
    let seen = mock.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].param("uploadType").as_deref(), Some("media"));
    assert_eq!(seen[0].header("content-type"), Some("text/csv"), "guessed from the name");
    assert_eq!(&seen[0].body[..], b"x,y\n");
    let opts = WriteOptions::default().with_mode(WriteMode::CreateNew);
    let e = fs.pipe_file("bkt/a.csv", Bytes::from_static(b"z"), &opts).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AlreadyExists);
    assert_eq!(e.http_status(), Some(412));
    // Metadata makes it a multipart upload with a random boundary.
    let mut o = WriteOptions::default();
    o.metadata.insert("k".into(), "v".into());
    o.content_type = Some("text/plain".into());
    fs.pipe_file("bkt/m.txt", Bytes::from_static(b"payload"), &o).await.unwrap();
    let last = mock.seen().pop().unwrap();
    assert_eq!(last.param("uploadType").as_deref(), Some("multipart"));
    let ct = last.header("content-type").unwrap();
    let boundary = ct.strip_prefix("multipart/related; boundary=").unwrap();
    let body = String::from_utf8(last.body.to_vec()).unwrap();
    assert!(body.starts_with(&format!("--{boundary}\r\n")));
    assert!(body.contains(r#"{"metadata":{"k":"v"},"name":"m.txt"}"#), "{body}");
    assert!(body.contains("Content-Type: text/plain\r\n\r\npayload\r\n"), "{body}");
    assert!(body.ends_with(&format!("--{boundary}--\r\n")));
    // Unknown write options are rejected.
    let mut o = WriteOptions::default();
    o.extra.insert("bogus".into(), Value::Int(1));
    assert_eq!(
        fs.pipe_file("bkt/q", Bytes::new(), &o).await.unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
}

#[tokio::test]
async fn pinned_reads_fail_cleanly_when_the_object_is_replaced() {
    let mock = Mock::start(|s| {
        if s.path == "/storage/v1/b/bkt/o/obj" {
            return Reply::json(200, object("bkt", "obj", 100, 5));
        }
        if s.path == "/download/storage/v1/b/bkt/o/obj" {
            return match s.param("generation").as_deref() {
                Some("5") => Reply::gcs_error(404, "notFound", "No such object"),
                Some(_) => Reply::new(500),
                None => Reply::new(206).header("content-range", "bytes 0-9/100").body(vec![7u8; 10]),
            };
        }
        Reply::new(500)
    })
    .await;
    let fs = fs_with(&mock.url(), &[("token", Value::from("anon"))], no_gce());
    let h = fs.open_read("bkt/obj", &ReadOptions::default()).await.unwrap();
    assert_eq!(h.size(), 100);
    let e = h.read_at(0, 10).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e}");
    let unpinned = ReadOptions {
        pin_version: false,
        ..ReadOptions::default()
    };
    let h = fs.open_read("bkt/obj", &unpinned).await.unwrap();
    assert_eq!(h.read_at(0, 10).await.unwrap().len(), 10);
    // An explicitly requested generation that is gone is NotFound.
    let explicit = ReadOptions {
        version: Some("5".into()),
        ..ReadOptions::default()
    };
    let h = fs.open_read("bkt/obj", &explicit).await.unwrap();
    assert_eq!(h.read_at(0, 10).await.unwrap_err().kind(), ErrorKind::NotFound);
}

#[tokio::test]
async fn cat_ranges_rereads_when_generations_differ() {
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    const LEN: usize = 3 << 20;
    let data_v = |g: u8| -> Vec<u8> { vec![g; LEN] };
    let mock = Mock::start(move |s| {
        if s.path != "/download/storage/v1/b/bkt/o/obj" {
            return Reply::new(500);
        }
        let range = s.header("range").unwrap().strip_prefix("bytes=").unwrap().to_owned();
        let (a, b) = range.split_once('-').unwrap();
        let (a, b): (usize, usize) = (a.parse().unwrap(), b.parse().unwrap());
        let gen_ = match s.param("generation") {
            Some(g) => g.parse::<u8>().unwrap(),
            // Unpinned requests alternate between two versions.
            None => 1 + (n2.fetch_add(1, Ordering::SeqCst) % 2) as u8,
        };
        Reply::new(206)
            .header("content-range", &format!("bytes {a}-{b}/{LEN}"))
            .header("x-goog-generation", &gen_.to_string())
            .body(data_v(gen_)[a..=b].to_vec())
    })
    .await;
    let fs = fs_with(&mock.url(), &[("token", Value::from("anon"))], no_gce());
    // Far apart: two separate GETs.
    let got = fs.cat_ranges("bkt/obj", &[0..10, 3_000_000..3_000_010, 5..5]).await.unwrap();
    assert_eq!(got[0], vec![2u8; 10]);
    assert_eq!(got[1], vec![2u8; 10]);
    assert!(got[2].is_empty());
    let pinned: Vec<_> = mock.seen().into_iter().filter(|s| s.param("generation").is_some()).collect();
    assert_eq!(pinned.len(), 2);
    assert!(pinned.iter().all(|s| s.param("generation").as_deref() == Some("2")));
}

#[tokio::test]
async fn whole_downloads_are_crc32c_checked() {
    let good = b"hello world".to_vec();
    let mock = Mock::start(move |s| {
        let crc = if s.path.ends_with("/bad") {
            crc32c_b64(crc32c::crc32c(b"something else"))
        } else {
            crc32c_b64(crc32c::crc32c(&good))
        };
        Reply::new(206)
            .header("content-range", "bytes 0-10/11")
            .header("x-goog-hash", &format!("crc32c={crc},md5=XrY7u+Ae7tCTyyK7j1rNww=="))
            .header("x-goog-generation", "3")
            .body(good.clone())
    })
    .await;
    let fs = fs_with(&mock.url(), &[("token", Value::from("anon"))], no_gce());
    assert_eq!(&fs.cat_file("bkt/good", ByteRange::Full).await.unwrap()[..], b"hello world");
    let e = fs.cat_file("bkt/bad", ByteRange::Full).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io);
    assert!(e.details().contains(&Detail::Code("ChecksumError".into())));
    // Partial reads are not checked; neither is anything with
    // verify_crc32c=False.
    assert_eq!(fs.cat_file("bkt/bad", ByteRange::Bounded { start: 0, end: 5 }).await.unwrap().len(), 11.min(5));
    let fs = fs_with(
        &mock.url(),
        &[("token", Value::from("anon")), ("verify_crc32c", Value::Bool(false))],
        no_gce(),
    );
    assert!(fs.cat_file("bkt/bad", ByteRange::Full).await.is_ok());
    // get_file checks too, and leaves no file behind on a mismatch.
    let fs = fs_with(&mock.url(), &[("token", Value::from("anon"))], no_gce());
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("sub/out.bin");
    fs.get_file("bkt/good", &local).await.unwrap();
    assert_eq!(std::fs::read(&local).unwrap(), b"hello world");
    let local2 = dir.path().join("out2.bin");
    assert!(fs.get_file("bkt/bad", &local2).await.is_err());
    assert!(!local2.exists());
}

#[tokio::test]
async fn errors_map_to_precise_kinds_and_transient_ones_are_retried() {
    let flaky = Arc::new(AtomicUsize::new(0));
    let f2 = flaky.clone();
    let mock = Mock::start(move |s| match s.path.as_str() {
        "/storage/v1/b/bkt/o/forbidden" => {
            Reply::gcs_error(403, "forbidden", "anon does not have storage.objects.get access")
        }
        "/storage/v1/b/bkt/o" if s.param("prefix").as_deref() == Some("forbidden") => empty_listing(),
        "/storage/v1/b/bkt/o" => empty_listing(),
        "/storage/v1/b/bkt/o/flaky" => {
            if f2.fetch_add(1, Ordering::SeqCst) < 2 {
                Reply::gcs_error(429, "rateLimitExceeded", "slow down")
            } else {
                Reply::json(200, object("bkt", "flaky", 1, 1))
            }
        }
        "/storage/v1/b/full" => Reply::gcs_error(409, "conflict", "The bucket you tried to delete is not empty."),
        "/storage/v1/b/bkt/o/server" => Reply::gcs_error(503, "backendError", "unavailable"),
        _ => Reply::gcs_error(404, "notFound", "Not Found"),
    })
    .await;
    let fs = fs_with(&mock.url(), &[("token", Value::from("anon"))], no_gce());
    // 403 on the object GET falls back to a listing (gcsfs), which finds
    // nothing: NotFound.
    let e = fs.info("bkt/forbidden").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    let e = fs.cat_file("bkt/forbidden", ByteRange::Full).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound, "media GETs go elsewhere in the mock");
    let e = fs.open_read("bkt/missing", &ReadOptions::default()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    assert!(e.details().contains(&Detail::Http(404)));
    assert!(e.details().contains(&Detail::Code("notFound".into())));
    assert_eq!(e.path(), Some("bkt/missing"));
    assert_eq!(fs.info("bkt/flaky").await.unwrap().size, 1);
    assert_eq!(flaky.load(Ordering::SeqCst), 3);
    assert!(fs.stats().snapshot().retries >= 2);
    let e = fs.rmdir("full").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::DirectoryNotEmpty);
    let e = fs.open_read("bkt/server", &ReadOptions::default()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Throttled);
    assert_eq!(e.http_status(), Some(503));
    assert_eq!(mock.count(|s| s.path == "/storage/v1/b/bkt/o/server"), 3, "1 + max_retries attempts");
}

#[tokio::test]
async fn forbidden_object_get_falls_back_to_listing() {
    let mock = Mock::start(|s| match s.path.as_str() {
        "/storage/v1/b/bkt/o/obj" => Reply::gcs_error(403, "forbidden", "no get"),
        "/storage/v1/b/bkt/o" if s.param("prefix").as_deref() == Some("obj") => {
            Reply::json(200, json!({"items": [object("bkt", "obj", 3, 7), object("bkt", "obj2", 1, 1)]}))
        }
        "/storage/v1/b/bkt/o" => empty_listing(),
        _ => Reply::new(500),
    })
    .await;
    let fs = fs_with(&mock.url(), &[("token", Value::from("anon"))], no_gce());
    let i = fs.info("bkt/obj").await.unwrap();
    assert_eq!((i.name.as_str(), i.size), ("bkt/obj", 3));
}

#[tokio::test]
async fn version_aware_paths_address_generations() {
    let mock = Mock::start(|s| match s.path.as_str() {
        "/storage/v1/b/bkt/o/k" => {
            let g: u64 = s.param("generation").unwrap_or_else(|| "9".into()).parse().unwrap();
            Reply::json(200, object("bkt", "k", 3, g))
        }
        "/download/storage/v1/b/bkt/o/k" => Reply::new(206)
            .header("content-range", "bytes 0-2/3")
            .header("x-goog-generation", &s.param("generation").unwrap_or_else(|| "9".into()))
            .body("abc"),
        "/storage/v1/b/bkt/o" => empty_listing(),
        _ => Reply::gcs_error(404, "notFound", "nf"),
    })
    .await;
    let fs = fs_with(
        &mock.url(),
        &[("token", Value::from("anon")), ("version_aware", Value::Bool(true))],
        no_gce(),
    );
    assert!(fs.capabilities().versioning);
    let i = fs.info("gs://bkt/k#123").await.unwrap();
    assert_eq!(i.version.as_deref(), Some("123"));
    fs.cat_file("bkt/k?generation=456", ByteRange::Full).await.unwrap();
    let dl = mock.seen().into_iter().find(|s| s.path.starts_with("/download")).unwrap();
    assert_eq!(dl.param("generation").as_deref(), Some("456"));
    assert_eq!(fs.split_path("bkt/k#77"), ("bkt".into(), "k".into(), Some("77".into())));
    assert_eq!(
        fs.url("bkt/a b#5", None).unwrap(),
        format!("{}/download/storage/v1/b/bkt/o/a%20b?alt=media&generation=5", mock.url())
    );
    let e = fs.pipe_file("bkt/k#5", Bytes::new(), &WriteOptions::default()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
    // Without version awareness '#' is part of the name.
    let plain = fs_with(&mock.url(), &[("token", Value::from("anon"))], no_gce());
    assert_eq!(plain.split_path("bkt/k#77").1, "k#77");
}
