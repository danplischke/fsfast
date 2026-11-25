//! Credential providers, region redirects and credential refresh against
//! in-process fake servers (IMDSv2, ECS/EKS container credentials, STS,
//! and a minimal S3 that checks signatures' regions and keys). No external
//! services needed.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use fsfast_core::{ByteRange, ErrorKind, FileSystem, Options, Value};
use fsfast_s3::credentials::{
    ChainContext, ContainerProvider, ImdsProvider, ProvideCredentials, default_chain,
};
use fsfast_s3::profile::{Env, ProfileFiles};
use fsfast_s3::{S3FileSystem, S3Options};
use parking_lot::Mutex;

/// A request as the fake server saw it.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    uri: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

type Reply = (u16, Vec<(&'static str, String)>, String);
type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

struct Fake {
    base: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

async fn serve(handler: Handler) -> Fake {
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let log = seen.clone();
    let app = Router::new().fallback(move |req: Request| {
        let handler = handler.clone();
        let log = log.clone();
        async move {
            let (parts, body) = req.into_parts();
            let body = axum::body::to_bytes(body, 16 << 20).await.unwrap().to_vec();
            let s = Seen {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                headers: parts.headers,
                body,
            };
            let (status, headers, body) = handler(&s);
            log.lock().push(s);
            let mut r = Response::builder().status(StatusCode::from_u16(status).unwrap());
            for (k, v) in headers {
                r = r.header(k, v);
            }
            r.body(Body::from(body)).unwrap()
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
    }
}

fn header(s: &Seen, name: &str) -> String {
    s.headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned()
}

fn creds_json(ak: &str, expires_in: Duration) -> String {
    let exp = fsfast_s3::encode::iso8601(std::time::SystemTime::now() + expires_in);
    format!(
        r#"{{"Code":"Success","AccessKeyId":"{ak}","SecretAccessKey":"secret-{ak}","Token":"token-{ak}","Expiration":"{exp}"}}"#
    )
}

fn env(pairs: &[(&str, &str)]) -> Env {
    Env::from_map(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())))
}

#[tokio::test]
async fn imds_v2_token_then_role_credentials() {
    let fake = serve(Arc::new(|s: &Seen| {
        match (s.method.as_str(), s.uri.as_str()) {
            ("PUT", "/latest/api/token") => {
                assert_eq!(header(s, "x-aws-ec2-metadata-token-ttl-seconds"), "21600");
                (200, vec![], "TOKEN123".into())
            }
            ("GET", "/latest/meta-data/iam/security-credentials/") => {
                assert_eq!(header(s, "x-aws-ec2-metadata-token"), "TOKEN123");
                (200, vec![], "my-role\n".into())
            }
            ("GET", "/latest/meta-data/iam/security-credentials/my-role") => {
                assert_eq!(header(s, "x-aws-ec2-metadata-token"), "TOKEN123");
                (
                    200,
                    vec![],
                    creds_json("ASIAIMDS", Duration::from_secs(6 * 3600)),
                )
            }
            _ => (404, vec![], String::new()),
        }
    }))
    .await;
    let e = env(&[("AWS_EC2_METADATA_SERVICE_ENDPOINT", &fake.base)]);
    let p = ImdsProvider::new(&e, &ProfileFiles::default(), "default");
    let c = p.provide().await.unwrap().unwrap();
    assert_eq!(c.access_key_id(), "ASIAIMDS");
    assert_eq!(c.session_token(), Some("token-ASIAIMDS"));
    assert!(c.expiry().is_some());
    assert_eq!(fake.seen.lock().len(), 3);
}

#[tokio::test]
async fn imds_v1_fallback_and_v1_disabled() {
    let fake = serve(Arc::new(|s: &Seen| {
        match (s.method.as_str(), s.uri.as_str()) {
            ("PUT", _) => (403, vec![], String::new()),
            ("GET", "/latest/meta-data/iam/security-credentials/") => {
                assert_eq!(header(s, "x-aws-ec2-metadata-token"), "");
                (200, vec![], "r".into())
            }
            ("GET", "/latest/meta-data/iam/security-credentials/r") => {
                (200, vec![], creds_json("ASIAV1", Duration::from_secs(3600)))
            }
            _ => (404, vec![], String::new()),
        }
    }))
    .await;
    let e = env(&[("AWS_EC2_METADATA_SERVICE_ENDPOINT", &fake.base)]);
    let c = ImdsProvider::new(&e, &ProfileFiles::default(), "default")
        .provide()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.access_key_id(), "ASIAV1");
    let e = env(&[
        ("AWS_EC2_METADATA_SERVICE_ENDPOINT", &fake.base),
        ("AWS_EC2_METADATA_V1_DISABLED", "true"),
    ]);
    assert!(
        ImdsProvider::new(&e, &ProfileFiles::default(), "default")
            .provide()
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn imds_unreachable_is_quick_and_yields_nothing() {
    // A port nobody listens on: refused at once; a blackholed address would
    // hit the 1 s timeout instead. Either way: no credentials, no error.
    let e = env(&[
        ("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://127.0.0.1:9"),
        ("AWS_METADATA_SERVICE_TIMEOUT", "0.5"),
    ]);
    let t = std::time::Instant::now();
    let r = ImdsProvider::new(&e, &ProfileFiles::default(), "default")
        .provide()
        .await
        .unwrap();
    assert!(r.is_none());
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
}

#[tokio::test]
async fn container_credentials_full_and_relative_uri() {
    let fake = serve(Arc::new(|s: &Seen| {
        assert_eq!(header(s, "authorization"), "Bearer-ish token");
        assert_eq!(header(s, "accept"), "application/json");
        match s.uri.as_str() {
            "/v2/credentials/abc" | "/full" => (
                200,
                vec![],
                creds_json("ASIAECS", Duration::from_secs(3600)),
            ),
            _ => (404, vec![], String::new()),
        }
    }))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("token");
    std::fs::write(&token_file, "Bearer-ish token").unwrap();
    let full = format!("{}/full", fake.base);
    let e = env(&[
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", &full),
        (
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
            token_file.to_str().unwrap(),
        ),
    ]);
    let c = ContainerProvider::new(e, "http://169.254.170.2")
        .provide()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.access_key_id(), "ASIAECS");
    let e = env(&[
        (
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "/v2/credentials/abc",
        ),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", "Bearer-ish token"),
    ]);
    let c = ContainerProvider::new(e, fake.base.clone())
        .provide()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.session_token(), Some("token-ASIAECS"));
    // Non-loopback plain-HTTP full URIs are refused (botocore's rule).
    let e = env(&[(
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "http://example.com/creds",
    )]);
    assert!(
        ContainerProvider::new(e, "http://x")
            .provide()
            .await
            .is_err()
    );
}

#[tokio::test]
async fn container_errors_after_retries() {
    let calls = Arc::new(AtomicUsize::new(0));
    let c2 = calls.clone();
    let fake = serve(Arc::new(move |_s: &Seen| {
        c2.fetch_add(1, Ordering::SeqCst);
        (500, vec![], "boom".into())
    }))
    .await;
    let full = format!("{}/creds", fake.base);
    let e = env(&[("AWS_CONTAINER_CREDENTIALS_FULL_URI", &full)]);
    let err = ContainerProvider::new(e, "http://x")
        .with_retry_sleep(Duration::from_millis(1))
        .provide()
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

fn sts_reply(ak: &str) -> String {
    let exp = fsfast_s3::encode::iso8601(std::time::SystemTime::now() + Duration::from_secs(3600));
    format!(
        r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>{ak}</AccessKeyId><SecretAccessKey>s-{ak}</SecretAccessKey><SessionToken>t-{ak}</SessionToken><Expiration>{exp}</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>"#
    )
}

fn form(body: &[u8]) -> BTreeMap<String, String> {
    String::from_utf8_lossy(body)
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| {
            (
                k.to_owned(),
                fsfast_s3::encode::url_decode_plus(v).into_owned(),
            )
        })
        .collect()
}

#[tokio::test]
async fn assume_role_chain_through_sts() {
    let fake = serve(Arc::new(|s: &Seen| {
        let f = form(&s.body);
        let auth = header(s, "authorization");
        match f.get("RoleArn").map(String::as_str) {
            // Inner role first, signed with the base profile's keys.
            Some("arn:aws:iam::1:role/inner") => {
                assert!(auth.contains("Credential=AKBASE/"), "{auth}");
                assert!(auth.contains("/eu-west-1/sts/aws4_request"), "{auth}");
                assert_eq!(f["Action"], "AssumeRole");
                (200, vec![], sts_reply("ASIAINNER"))
            }
            Some("arn:aws:iam::1:role/outer") => {
                assert!(auth.contains("Credential=ASIAINNER/"), "{auth}");
                assert_eq!(header(s, "x-amz-security-token"), "t-ASIAINNER");
                assert_eq!(f["RoleSessionName"], "outer-session");
                assert_eq!(f["ExternalId"], "ext-1");
                assert_eq!(f["DurationSeconds"], "1800");
                (200, vec![], sts_reply("ASIAOUTER"))
            }
            _ => (
                403,
                vec![],
                "<ErrorResponse><Error><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>"
                    .into(),
            ),
        }
    }))
    .await;
    let config = "\
[profile outer]
role_arn = arn:aws:iam::1:role/outer
source_profile = inner
role_session_name = outer-session
external_id = ext-1
duration_seconds = 1800
[profile inner]
role_arn = arn:aws:iam::1:role/inner
source_profile = base
[profile denied]
role_arn = arn:aws:iam::1:role/nope
source_profile = base
";
    let creds = "[base]\naws_access_key_id = AKBASE\naws_secret_access_key = SKBASE\n";
    let profiles = Arc::new(ProfileFiles::from_texts(Some(config), Some(creds)));
    let mk = |profile: &str| {
        let mut ctx = ChainContext::new(
            env(&[
                ("AWS_ENDPOINT_URL_STS", &fake.base),
                ("AWS_EC2_METADATA_DISABLED", "true"),
            ]),
            profiles.clone(),
            profile.into(),
            true,
        );
        ctx.region = Some("eu-west-1".into());
        default_chain(&ctx)
    };
    let c = mk("outer").provide().await.unwrap().unwrap();
    assert_eq!(c.access_key_id(), "ASIAOUTER");
    assert_eq!(c.session_token(), Some("t-ASIAOUTER"));
    let e = mk("denied").provide().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    assert!(e.to_string().contains("AccessDenied"), "{e}");
}

#[tokio::test]
async fn web_identity_is_unsigned_and_rereads_the_token() {
    let fake = serve(Arc::new(|s: &Seen| {
        let f = form(&s.body);
        assert_eq!(
            header(s, "authorization"),
            "",
            "web identity calls are unsigned"
        );
        assert_eq!(f["Action"], "AssumeRoleWithWebIdentity");
        assert_eq!(f["RoleArn"], "arn:aws:iam::1:role/irsa");
        assert_eq!(f["RoleSessionName"], "pod-session");
        let ak = format!("ASIA{}", f["WebIdentityToken"].to_ascii_uppercase());
        (
            200,
            vec![],
            sts_reply(&ak).replace("AssumeRoleResponse", "AssumeRoleWithWebIdentityResponse"),
        )
    }))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, "one\n").unwrap();
    let e = env(&[
        ("AWS_WEB_IDENTITY_TOKEN_FILE", token.to_str().unwrap()),
        ("AWS_ROLE_ARN", "arn:aws:iam::1:role/irsa"),
        ("AWS_ROLE_SESSION_NAME", "pod-session"),
        ("AWS_ENDPOINT_URL_STS", &fake.base),
        ("AWS_EC2_METADATA_DISABLED", "true"),
    ]);
    let ctx = ChainContext::new(
        e,
        Arc::new(ProfileFiles::default()),
        "default".into(),
        false,
    );
    let chain = default_chain(&ctx);
    assert_eq!(
        chain.provide().await.unwrap().unwrap().access_key_id(),
        "ASIAONE"
    );
    std::fs::write(&token, "two").unwrap();
    // A refresh asks the same provider again, with the rotated token.
    assert_eq!(
        chain.provide().await.unwrap().unwrap().access_key_id(),
        "ASIATWO"
    );
}

/// A fake S3 bucket `eu-bucket` in eu-west-1 behind an endpoint whose
/// default region is us-east-1, accepting only `good_key` credentials and
/// rejecting `old_key` ones as expired.
fn fake_s3(heads_400: bool) -> Handler {
    Arc::new(move |s: &Seen| {
        let auth = header(s, "authorization");
        if auth.contains("Credential=OLDKEY/") {
            return (
                400,
                vec![],
                "<Error><Code>ExpiredToken</Code><Message>The provided token has expired.</Message></Error>".into(),
            );
        }
        if !auth.contains("/eu-west-1/s3/aws4_request") {
            if s.method == "HEAD" {
                // HEAD responses have no body: the region is in a header
                // (HeadBucket) or must be discovered (HeadObject 400).
                if heads_400 && s.uri != "/eu-bucket" {
                    // HeadObject: a bare 400, no hint at all.
                    return (400, vec![], String::new());
                }
                return (
                    301,
                    vec![("x-amz-bucket-region", "eu-west-1".into())],
                    String::new(),
                );
            }
            return (
                400,
                vec![],
                "<Error><Code>AuthorizationHeaderMalformed</Code><Message>wrong region</Message><Region>eu-west-1</Region></Error>".into(),
            );
        }
        match (s.method.as_str(), s.uri.split('?').next().unwrap()) {
            ("HEAD", "/eu-bucket/key.txt") => (
                200,
                vec![
                    ("content-length", "5".into()),
                    ("etag", "\"e\"".into()),
                    ("last-modified", "Tue, 24 Nov 2026 17:27:28 GMT".into()),
                ],
                String::new(),
            ),
            ("GET", "/eu-bucket/key.txt") => (
                206,
                vec![
                    ("content-range", "bytes 0-4/5".into()),
                    ("etag", "\"e\"".into()),
                ],
                "hello".into(),
            ),
            ("HEAD", "/eu-bucket") => (
                200,
                vec![("x-amz-bucket-region", "eu-west-1".into())],
                String::new(),
            ),
            _ => (404, vec![], "<Error><Code>NoSuchKey</Code></Error>".into()),
        }
    })
}

fn fs_for(endpoint: &str, extra: &[(&str, Value)], e: Env) -> S3FileSystem {
    let mut o = Options::new();
    o.insert("endpoint_url".into(), Value::from(endpoint));
    for (k, v) in extra {
        o.insert((*k).into(), v.clone());
    }
    S3FileSystem::with_options(S3Options::parse_with_env(o, e).unwrap())
}

#[tokio::test]
async fn region_redirects_are_followed_and_cached() {
    let fake = serve(fake_s3(false)).await;
    let e = env(&[("AWS_EC2_METADATA_DISABLED", "true")]);
    let fs = fs_for(
        &fake.base,
        &[("key", "AK".into()), ("secret", "SK".into())],
        e,
    );
    // GET answered AuthorizationHeaderMalformed + Region: re-signed once.
    let data = fs
        .cat_file("eu-bucket/key.txt", ByteRange::Full)
        .await
        .unwrap();
    assert_eq!(&data[..], b"hello");
    assert_eq!(fs.bucket_region("eu-bucket").await.unwrap(), "eu-west-1");
    let n = fake.seen.lock().len();
    assert_eq!(n, 2);
    // Later requests go straight to the right region.
    let i = fs.info("eu-bucket/key.txt").await.unwrap();
    assert_eq!(i.size, 5);
    assert_eq!(fake.seen.lock().len(), n + 1);
}

#[tokio::test]
async fn head_redirects_without_body() {
    // HeadObject answered 400 without a body: botocore HEADs the bucket for
    // the region, then retries.
    let fake = serve(fake_s3(true)).await;
    let fs = fs_for(
        &fake.base,
        &[("key", "AK".into()), ("secret", "SK".into())],
        env(&[("AWS_EC2_METADATA_DISABLED", "true")]),
    );
    let i = fs.info("eu-bucket/key.txt").await.unwrap();
    assert_eq!(i.size, 5);
    let seen = fake.seen.lock().clone();
    assert_eq!(seen.len(), 3, "{seen:#?}");
    assert_eq!(seen[1].uri, "/eu-bucket");
}

#[tokio::test]
async fn cache_regions_discovers_up_front() {
    let fake = serve(fake_s3(false)).await;
    // cache_regions is honoured only without endpoint_url in s3fs; the
    // fake endpoint comes from AWS_ENDPOINT_URL_S3 instead.
    let mut o = Options::new();
    o.insert("key".into(), Value::from("AK"));
    o.insert("secret".into(), Value::from("SK"));
    o.insert("cache_regions".into(), Value::Bool(true));
    let e = env(&[
        ("AWS_ENDPOINT_URL_S3", &fake.base),
        ("AWS_EC2_METADATA_DISABLED", "true"),
    ]);
    let fs = S3FileSystem::with_options(S3Options::parse_with_env(o, e).unwrap());
    let data = fs
        .cat_file("eu-bucket/key.txt", ByteRange::Full)
        .await
        .unwrap();
    assert_eq!(&data[..], b"hello");
    let seen = fake.seen.lock().clone();
    assert_eq!(seen.len(), 2, "{seen:#?}");
    assert_eq!(
        (seen[0].method.as_str(), seen[0].uri.as_str()),
        ("HEAD", "/eu-bucket")
    );
}

#[tokio::test]
async fn expired_token_triggers_one_refresh() {
    let fake_s3_server = serve(fake_s3(false)).await;
    // Container credentials: first OLDKEY (rejected by S3 as expired),
    // then GOODKEY.
    let calls = Arc::new(AtomicUsize::new(0));
    let c2 = calls.clone();
    let creds = serve(Arc::new(move |_s: &Seen| {
        let n = c2.fetch_add(1, Ordering::SeqCst);
        let ak = if n == 0 { "OLDKEY" } else { "GOODKEY" };
        (200, vec![], creds_json(ak, Duration::from_secs(3600)))
    }))
    .await;
    let full = format!("{}/creds", creds.base);
    let e = env(&[
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", &full),
        ("AWS_EC2_METADATA_DISABLED", "true"),
        ("AWS_CONFIG_FILE", "/nonexistent"),
        ("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent"),
    ]);
    let fs = fs_for(
        &fake_s3_server.base,
        &[(
            "client_kwargs",
            Value::Map([("region_name".to_owned(), Value::from("eu-west-1"))].into()),
        )],
        e,
    );
    let data = fs
        .cat_file("eu-bucket/key.txt", ByteRange::Full)
        .await
        .unwrap();
    assert_eq!(&data[..], b"hello");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn anonymous_requests_are_unsigned() {
    let fake = serve(Arc::new(|s: &Seen| {
        assert!(s.headers.get("authorization").is_none());
        assert!(s.headers.get("x-amz-date").is_none());
        (
            206,
            vec![
                ("content-range", "bytes 0-1/2".into()),
                ("etag", "\"x\"".into()),
            ],
            "ok".into(),
        )
    }))
    .await;
    let fs = fs_for(&fake.base, &[("anon", true.into())], env(&[]));
    assert_eq!(
        &fs.cat_file("pub/k", ByteRange::Full).await.unwrap()[..],
        b"ok"
    );
    // Anonymous users list no buckets (s3fs).
    assert!(fs.ls("").await.unwrap().is_empty());
}

#[tokio::test]
async fn no_credentials_is_permission_denied() {
    let fake = serve(Arc::new(|_s: &Seen| (200, vec![], String::new()))).await;
    let e = env(&[
        ("AWS_EC2_METADATA_DISABLED", "true"),
        ("AWS_CONFIG_FILE", "/nonexistent"),
        ("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent"),
    ]);
    let fs = fs_for(&fake.base, &[], e);
    let err = fs.info("b/k").await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    assert!(fake.seen.lock().is_empty());
}

#[tokio::test]
async fn profile_supplies_region_endpoint_and_addressing() {
    let fake = serve(Arc::new(|s: &Seen| {
        let auth = header(s, "authorization");
        assert!(auth.contains("Credential=AKPROF/"), "{auth}");
        assert!(auth.contains("/ap-south-1/s3/"), "{auth}");
        (
            200,
            vec![("content-length", "3".into()), ("etag", "\"p\"".into())],
            String::new(),
        )
    }))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config");
    std::fs::write(
        &cfg,
        format!(
            "[profile p]\nregion = ap-south-1\nservices = local\ns3 =\n  addressing_style = path\n\
             [services local]\ns3 =\n  endpoint_url = {}\n",
            fake.base
        ),
    )
    .unwrap();
    let creds = dir.path().join("credentials");
    std::fs::write(
        &creds,
        "[p]\naws_access_key_id = AKPROF\naws_secret_access_key = S\n",
    )
    .unwrap();
    let e = env(&[
        ("AWS_CONFIG_FILE", cfg.to_str().unwrap()),
        ("AWS_SHARED_CREDENTIALS_FILE", creds.to_str().unwrap()),
        ("AWS_EC2_METADATA_DISABLED", "true"),
    ]);
    let mut o = Options::new();
    o.insert("profile".into(), Value::from("p"));
    let fs = S3FileSystem::with_options(S3Options::parse_with_env(o, e).unwrap());
    let i = fs.info("bucket/k").await.unwrap();
    assert_eq!(i.size, 3);
    assert_eq!(fake.seen.lock()[0].uri, "/bucket/k");
}
