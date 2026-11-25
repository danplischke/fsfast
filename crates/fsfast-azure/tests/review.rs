//! Regression tests for defects found in review: odd blob names, Shared Key
//! canonicalisation of header values, block-list appends next to foreign
//! uncommitted blocks, ambiguous conditional commits after a retry, delete
//! ordering of directory markers, and credentials in `Debug` output.
//!
//! The Azurite tests are gated on `FSFAST_TEST_AZURE_CONNECTION_STRING`
//! (`eval "$(scripts/test-services.sh env)"`); the mock tests always run.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine as _;
use bytes::Bytes;
use common::mock::{Mock, Reply, Seen};
use common::{connection_string, destroy_container, filesystem, skip, unique_container};
use fsfast_azure::AzureBlobFileSystem;
use fsfast_azure::auth::{Credential, SharedKey};
use fsfast_azure::connstr::DEVSTORE_ACCOUNT_KEY;
use fsfast_core::{
    ByteRange, ErrorKind, FileSystem, FindOptions, Options, Value, WriteMode, WriteOptions,
};
use fsfast_http_transport::{HttpClient, HttpConfig, Method, Request};
use parking_lot::Mutex;

macro_rules! setup {
    ($name:literal) => {{
        let Some(cs) = connection_string() else {
            skip($name);
            return;
        };
        let fs = filesystem(&cs, &[]);
        let c = unique_container($name);
        fs.mkdir(&c, true).await.unwrap();
        (cs, fs, c)
    }};
}

fn mock_fs(mock: &Mock, extra: &[(&str, Value)]) -> AzureBlobFileSystem {
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

/// Blob names with `.`/`..` segments cannot be addressed in a URL (they are
/// normalised away, by the URL parser and by the service): writing
/// `a/../b` must fail instead of silently overwriting `b`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dot_segments_are_rejected() {
    let (_cs, fs, c) = setup!("dots");
    for name in ["a/../b", "a/./b", "d/.", "e/..", "./x", "../y"] {
        let p = format!("{c}/{name}");
        let e = fs
            .pipe_file(&p, Bytes::from_static(b"data"), &WriteOptions::default())
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{name}: {e}");
        let e = fs.cat_file(&p, ByteRange::Full).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{name}: {e}");
    }
    // Dots inside names are fine.
    for name in ["dots..", "..x", "a/.hidden", "a/...", "b./c"] {
        let p = format!("{c}/{name}");
        fs.pipe_file(&p, Bytes::from_static(b"ok"), &WriteOptions::default())
            .await
            .unwrap();
        assert_eq!(fs.cat_file(&p, ByteRange::Full).await.unwrap(), "ok");
    }
    let all = fs.find(&c, &FindOptions::default()).await.unwrap();
    let names: Vec<_> = all.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(names.len(), 5, "nothing written elsewhere: {names:?}");
    destroy_container(&fs, &c).await;
}

/// The service trims header values before computing the Shared Key
/// signature; metadata values with surrounding blanks must still
/// authenticate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_values_with_blanks_are_signed_correctly() {
    let (_cs, fs, c) = setup!("blanks");
    let p = format!("{c}/m");
    let mut o = WriteOptions::default();
    o.metadata.insert("k".into(), " spaced value ".into());
    fs.pipe_file(&p, Bytes::from_static(b"x"), &o)
        .await
        .unwrap();
    let mut meta = BTreeMap::new();
    meta.insert("k2".to_owned(), "  v ".to_owned());
    fs.set_metadata(&p, &meta).await.unwrap();
    let i = fs.info(&p).await.unwrap();
    let Value::Map(m) = &i.extra["metadata"] else {
        panic!("{i:?}")
    };
    assert_eq!(m.get("k2"), Some(&Value::Str("v".into())), "{m:?}");
    destroy_container(&fs, &c).await;
}

/// A signed raw request against Azurite (for setting up foreign state).
async fn raw(cs: &str, method: Method, url: &str, body: Bytes) -> (u16, Bytes) {
    let account = std::env::var("FSFAST_TEST_AZURE_ACCOUNT").unwrap_or("devstoreaccount1".into());
    let key = std::env::var("FSFAST_TEST_AZURE_KEY").unwrap_or(DEVSTORE_ACCOUNT_KEY.into());
    let _ = cs;
    let cred = Credential::SharedKey(Arc::new(SharedKey::new(account, &key).unwrap()));
    let http = HttpClient::new(HttpConfig::default()).unwrap();
    let len = body.len() as u64;
    let mut req = Request::new(method, url).unwrap().body(body);
    cred.authorize(&mut req, len).await.unwrap();
    http.send_with(req, |r| async move {
        let s = r.status().as_u16();
        Ok((s, r.bytes().await?))
    })
    .await
    .unwrap()
}

fn committed_ids(xml: &[u8]) -> Vec<String> {
    let s = std::str::from_utf8(xml).unwrap();
    let committed = s
        .split("<CommittedBlocks>")
        .nth(1)
        .unwrap()
        .split("</CommittedBlocks>")
        .next()
        .unwrap();
    committed
        .split("<Name>")
        .skip(1)
        .map(|x| x.split("</Name>").next().unwrap().to_owned())
        .collect()
}

/// A block-list append must commit the blob's existing blocks as
/// `<Committed>`: with `<Latest>`, an uncommitted block another writer
/// staged under the same ID would replace the existing content.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_list_append_keeps_committed_blocks() {
    let (cs, fs, c) = setup!("blkappend");
    let endpoint = fs.endpoint().to_owned();
    let p = format!("{c}/b");
    let url = format!("{endpoint}/{c}/b");
    // A block blob with a block list whose IDs another tool chose.
    let id = base64::engine::general_purpose::STANDARD.encode("block-000000000001");
    let q = |id: &str| {
        format!(
            "{url}?comp=block&blockid={}",
            fsfast_azure::path::quote(id, false)
        )
    };
    let (s, _) = raw(&cs, Method::PUT, &q(&id), Bytes::from_static(b"original")).await;
    assert_eq!(s, 201);
    let list = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList><Latest>{id}</Latest></BlockList>"
    );
    let (s, _) = raw(
        &cs,
        Method::PUT,
        &format!("{url}?comp=blocklist"),
        Bytes::from(list),
    )
    .await;
    assert_eq!(s, 201);
    // That tool starts another upload, staging (not committing) a block
    // with the same ID.
    let (s, _) = raw(&cs, Method::PUT, &q(&id), Bytes::from_static(b"FOREIGN!")).await;
    assert_eq!(s, 201);
    // fsfast appends.
    let ap = WriteOptions::default().with_mode(WriteMode::Append);
    fs.pipe_file(&p, Bytes::from_static(b"+tail"), &ap)
        .await
        .unwrap();
    assert_eq!(
        fs.cat_file(&p, ByteRange::Full).await.unwrap(),
        "original+tail"
    );
    let (_, body) = raw(
        &cs,
        Method::GET,
        &format!("{url}?comp=blocklist&blocklisttype=committed"),
        Bytes::new(),
    )
    .await;
    let ids = committed_ids(&body);
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0], id);
    destroy_container(&fs, &c).await;
}

/// A Put Block List whose first attempt committed but whose response was
/// lost is retried; the retry's `If-None-Match: *` / `If-Match` then fails.
/// The upload's own (unique) block IDs being committed proves it was ours.
#[tokio::test]
async fn ambiguous_conditional_commit_is_recognised() {
    #[derive(Default)]
    struct State {
        committed: Vec<String>,
        attempts: usize,
    }
    let st: Arc<Mutex<State>> = Arc::default();
    let st2 = st.clone();
    let mock = Mock::start(move |s: &Seen| {
        let mut st = st2.lock();
        match (s.method.as_str(), s.param("comp").as_deref()) {
            ("HEAD", _) => Reply::azure_error(404, "BlobNotFound"),
            ("PUT", Some("block")) => Reply::new(201),
            ("PUT", Some("blocklist")) => {
                st.attempts += 1;
                if st.attempts == 1 {
                    // Commit, then "lose" the response.
                    let body = std::str::from_utf8(&s.body).unwrap();
                    st.committed = body
                        .split("<Latest>")
                        .skip(1)
                        .map(|x| x.split("</Latest>").next().unwrap().to_owned())
                        .collect();
                    Reply::azure_error(503, "ServerBusy")
                } else {
                    Reply::azure_error(409, "BlobAlreadyExists")
                }
            }
            ("GET", Some("blocklist")) => {
                let mut x = String::from(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList><CommittedBlocks>",
                );
                for id in &st.committed {
                    x.push_str(&format!("<Block><Name>{id}</Name><Size>4</Size></Block>"));
                }
                x.push_str("</CommittedBlocks></BlockList>");
                Reply::new(200).body(x)
            }
            _ => Reply::azure_error(500, "InternalError"),
        }
    })
    .await;
    let fs = mock_fs(&mock, &[]);
    let x = WriteOptions {
        block_size: Some(4),
        ..WriteOptions::default()
    }
    .with_mode(WriteMode::CreateNew);
    fs.pipe_file("c/new", Bytes::from_static(b"0123456789"), &x)
        .await
        .unwrap();
    assert_eq!(st.lock().attempts, 2);
    // Someone else's commit (different IDs) is still AlreadyExists.
    st.lock().committed = vec!["c29tZW9uZSBlbHNl".into()];
    st.lock().attempts = 1;
    let e = fs
        .pipe_file("c/new", Bytes::from_static(b"0123456789"), &x)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AlreadyExists, "{e}");
}

/// Directory markers are deleted after everything below them, even when a
/// sibling sorts between the marker and its children (`a`, `a-b`, `a/x`).
#[tokio::test]
async fn rm_files_deletes_markers_after_children() {
    let order: Arc<Mutex<Vec<String>>> = Arc::default();
    let o2 = order.clone();
    let mock = Mock::start(move |s: &Seen| {
        if s.method == "DELETE" {
            o2.lock().push(s.path.clone());
            // Slow down children so a concurrently issued marker delete
            // would overtake them.
            if s.path.ends_with("/x") {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        Reply::new(202)
    })
    .await;
    let fs = mock_fs(&mock, &[]);
    let paths: Vec<String> = ["c/a", "c/a-b", "c/a/x"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let res = fs.rm_files(&paths).await;
    assert!(res.iter().all(|r| r.is_ok()), "{res:?}");
    let order = order.lock().clone();
    let pos = |p: &str| order.iter().position(|x| x == p).unwrap();
    assert!(pos("/acct/c/a") > pos("/acct/c/a/x"), "{order:?}");
}

/// Account keys and SAS tokens never appear in `Debug` output.
#[test]
fn debug_output_has_no_secrets() {
    let mut o = Options::new();
    o.insert("account_name".into(), Value::Str("acct".into()));
    o.insert(
        "account_key".into(),
        Value::Str(DEVSTORE_ACCOUNT_KEY.into()),
    );
    let fs = AzureBlobFileSystem::from_options_with_env(o, &|_| None).unwrap();
    for s in [
        format!("{:?}", fs.config()),
        format!("{fs:?}"),
        format!("{:?}", fs.credential()),
    ] {
        assert!(!s.contains(&DEVSTORE_ACCOUNT_KEY[..20]), "{s}");
    }
    let mut o = Options::new();
    o.insert("account_name".into(), Value::Str("acct".into()));
    o.insert(
        "sas_token".into(),
        Value::Str("sv=2024-11-04&sp=r&sig=SECRETSIGNATURE%3D".into()),
    );
    let fs = AzureBlobFileSystem::from_options_with_env(o, &|_| None).unwrap();
    for s in [
        format!("{:?}", fs.config()),
        format!("{fs:?}"),
        format!("{:?}", fs.credential()),
    ] {
        assert!(!s.contains("SECRETSIGNATURE"), "{s}");
    }
    let mut o = Options::new();
    o.insert(
        "connection_string".into(),
        Value::Str(format!(
            "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey={DEVSTORE_ACCOUNT_KEY};EndpointSuffix=core.windows.net"
        )),
    );
    let fs = AzureBlobFileSystem::from_options_with_env(o, &|_| None).unwrap();
    for s in [format!("{:?}", fs.config()), format!("{fs:?}")] {
        assert!(!s.contains(&DEVSTORE_ACCOUNT_KEY[..20]), "{s}");
    }
}

/// A signed URL for a blob version names the version: a version SAS
/// (`sr=bv`) does not authorize the current blob.
#[test]
fn signed_version_urls_name_the_version() {
    let mut o = Options::new();
    o.insert("account_name".into(), Value::Str("acct".into()));
    o.insert(
        "account_key".into(),
        Value::Str(DEVSTORE_ACCOUNT_KEY.into()),
    );
    o.insert("version_aware".into(), Value::Bool(true));
    let fs = AzureBlobFileSystem::from_options_with_env(o, &|_| None).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let v = "2026-01-01T00:00:00.0000000Z";
    let url = rt
        .block_on(fs.sign(
            &format!("c/a b?versionid={v}"),
            std::time::Duration::from_secs(60),
        ))
        .unwrap();
    assert!(
        url.starts_with(
            "https://acct.blob.core.windows.net/c/a%20b?versionid=2026-01-01T00%3A00%3A00.0000000Z&"
        ),
        "{url}"
    );
    assert!(url.contains("&sr=bv&"), "{url}");
    let url = rt
        .block_on(fs.sign("c/a", std::time::Duration::from_secs(60)))
        .unwrap();
    assert!(!url.contains("versionid"), "{url}");
    let e = rt
        .block_on(fs.sign("c/a/../b", std::time::Duration::from_secs(60)))
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
}

/// An overwrite replaces a blob of any type: a multi-block upload over an
/// append blob (Put Block fails with `InvalidBlobType` there) works like a
/// single Put Blob does. Create-only and append writes never delete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overwrite_replaces_append_blobs() {
    let (_cs, fs, c) = setup!("ovappend");
    let p = format!("{c}/x");
    let ap = WriteOptions::default().with_mode(WriteMode::Append);
    let o = WriteOptions {
        block_size: Some(4),
        ..WriteOptions::default()
    };
    fs.pipe_file(&p, Bytes::from_static(b"log"), &ap)
        .await
        .unwrap();
    fs.pipe_file(&p, Bytes::from_static(b"0123456789"), &o)
        .await
        .unwrap();
    assert_eq!(
        fs.cat_file(&p, ByteRange::Full).await.unwrap(),
        "0123456789"
    );
    // Again through a write handle.
    fs.rm_file(&p).await.unwrap();
    fs.pipe_file(&p, Bytes::from_static(b"log"), &ap)
        .await
        .unwrap();
    let mut w = fs.open_write(&p, &o).await.unwrap();
    w.write(Bytes::from_static(b"abcdefghij")).await.unwrap();
    w.close().await.unwrap();
    assert_eq!(
        fs.cat_file(&p, ByteRange::Full).await.unwrap(),
        "abcdefghij"
    );
    // The result is a block blob that appends extend by block list.
    fs.pipe_file(&p, Bytes::from_static(b"+"), &ap)
        .await
        .unwrap();
    assert_eq!(
        fs.cat_file(&p, ByteRange::Full).await.unwrap(),
        "abcdefghij+"
    );
    destroy_container(&fs, &c).await;
}

/// An Append Block that fails its append-position condition is only taken
/// as an earlier attempt's success when the blob holds exactly our bytes
/// there: another writer's append of the same length must not swallow ours.
#[tokio::test]
async fn append_position_conflict_is_not_mistaken_for_success() {
    let blob: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(b"head".to_vec()));
    let b2 = blob.clone();
    let mock = Mock::start(move |s: &Seen| {
        let blob = b2.lock();
        match (s.method.as_str(), s.param("comp").as_deref()) {
            ("HEAD", _) => Reply::new(200)
                .header("content-length", &blob.len().to_string())
                .header("x-ms-blob-type", "AppendBlob")
                .header("etag", "\"0x1\""),
            ("PUT", Some("appendblock")) => {
                Reply::azure_error(412, "AppendPositionConditionNotMet")
            }
            ("GET", None) => {
                let r = s.header("x-ms-range").unwrap();
                let (a, b) = r.trim_start_matches("bytes=").split_once('-').unwrap();
                let (a, b): (usize, usize) = (a.parse().unwrap(), b.parse().unwrap());
                Reply::new(206)
                    .header("content-range", &format!("bytes {a}-{b}/{}", blob.len()))
                    .header("x-ms-blob-type", "AppendBlob")
                    .body(blob[a..=b].to_vec())
            }
            _ => Reply::azure_error(500, "InternalError"),
        }
    })
    .await;
    let fs = mock_fs(&mock, &[]);
    let ap = WriteOptions::default().with_mode(WriteMode::Append);
    // Someone else appended 4 other bytes.
    blob.lock().extend_from_slice(b"XXXX");
    let mut w = fs.open_write("c/log", &ap).await.unwrap();
    // (The handle saw the blob at 8 bytes; make it look like our append
    // raced with theirs at position 8 → 12.)
    blob.lock().extend_from_slice(b"YYYY");
    w.write(Bytes::from_static(b"mine")).await.unwrap();
    let e = w.close().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e}");
    // Our bytes are there (the first attempt went through): success.
    blob.lock().truncate(8);
    blob.lock().extend_from_slice(b"mine");
    let mut w = fs.open_write("c/log", &ap).await.unwrap();
    blob.lock().truncate(8);
    // Re-open saw 12 bytes; pretend our append at 12 landed.
    blob.lock().extend_from_slice(b"mineours");
    w.write(Bytes::from_static(b"ours")).await.unwrap();
    w.close().await.unwrap();
}

/// Appending to a blob that adlfs uploaded (block IDs: base64 of a 32-byte
/// uuid hex, 44 characters with padding) stages IDs of the same decoded
/// length.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_list_append_matches_adlfs_block_ids() {
    let (cs, fs, c) = setup!("adlfsids");
    let url = format!("{}/{c}/b", fs.endpoint());
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
    let ids = [
        b64("0123456789abcdef0123456789abcdef"),
        b64("fedcba9876543210fedcba9876543210"),
    ];
    for (id, data) in ids.iter().zip(["one-", "two-"]) {
        let u = format!(
            "{url}?comp=block&blockid={}",
            fsfast_azure::path::quote(id, false)
        );
        let (s, _) = raw(&cs, Method::PUT, &u, Bytes::from_static(data.as_bytes())).await;
        assert_eq!(s, 201);
    }
    let list = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList><Latest>{}</Latest><Latest>{}</Latest></BlockList>",
        ids[0], ids[1]
    );
    let (s, _) = raw(
        &cs,
        Method::PUT,
        &format!("{url}?comp=blocklist"),
        Bytes::from(list),
    )
    .await;
    assert_eq!(s, 201);
    let ap = WriteOptions::default().with_mode(WriteMode::Append);
    fs.pipe_file(&format!("{c}/b"), Bytes::from_static(b"three"), &ap)
        .await
        .unwrap();
    assert_eq!(
        fs.cat_file(&format!("{c}/b"), ByteRange::Full)
            .await
            .unwrap(),
        "one-two-three"
    );
    let (_, body) = raw(
        &cs,
        Method::GET,
        &format!("{url}?comp=blocklist&blocklisttype=committed"),
        Bytes::new(),
    )
    .await;
    let got = committed_ids(&body);
    assert_eq!(got.len(), 3);
    assert_eq!(&got[..2], &ids[..]);
    let dec = |s: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .unwrap()
            .len()
    };
    assert_eq!(got[2].len(), ids[0].len());
    assert_eq!(dec(&got[2]), 32);
    destroy_container(&fs, &c).await;
}
