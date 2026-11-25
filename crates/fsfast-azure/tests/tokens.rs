//! Entra ID bearer tokens against in-process fake endpoints: client secret,
//! workload identity, managed identity (App Service and IMDS shapes), the
//! Azure CLI, `DefaultAzureCredential` ordering, caching, refresh before
//! expiry, and the retry after a 401. Runs without external services.

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::mock::{Mock, Reply, Seen};
use fsfast_azure::AzureBlobFileSystem;
use fsfast_azure::auth::token::{
    AzureCli, ManagedIdentity, ManagedIdentityEndpoint, TokenHttp, TokenSource,
};
use fsfast_azure::auth::{Credential, TokenCache};
use fsfast_core::{ErrorKind, FileSystem, Options, Value};
use fsfast_http_transport::{HttpClient, HttpConfig, ProxyConfig};

fn http() -> TokenHttp {
    let cfg = HttpConfig {
        proxy: ProxyConfig::Disabled,
        max_retries: 0,
        ..HttpConfig::default()
    };
    TokenHttp {
        aad: HttpClient::new(cfg.clone()).unwrap(),
        local: HttpClient::new(cfg).unwrap(),
    }
}

fn form(body: &[u8]) -> HashMap<String, String> {
    String::from_utf8_lossy(body)
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_owned(), fsfast_azure::path::unquote(v).into_owned()))
        .collect()
}

/// A blob HEAD reply.
fn blob_head() -> Reply {
    Reply::new(200)
        .header("content-length", "3")
        .header("etag", "\"0x1\"")
        .header("last-modified", "Wed, 25 Nov 2026 06:34:00 GMT")
        .header("x-ms-blob-type", "BlockBlob")
}

/// Token endpoint + blob endpoint on one server. Tokens are `tok-<n>`;
/// `reject` lists tokens the blob endpoint answers with 401.
async fn server(reject: &'static [&'static str], expires_in: u64) -> (Mock, Arc<AtomicUsize>) {
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    let mock = Mock::start(move |s: &Seen| {
        if s.path.ends_with("/oauth2/v2.0/token") {
            let f = form(&s.body);
            assert_eq!(f.get("scope").map(String::as_str), Some("https://storage.azure.com/.default"));
            assert_eq!(f.get("grant_type").map(String::as_str), Some("client_credentials"));
            let ok = f.get("client_secret").map(String::as_str) == Some("s3cret")
                || f.get("client_assertion").map(String::as_str) == Some("federated-jwt");
            if !ok {
                return Reply::json(401, serde_json::json!({"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided.\nTrace ID: x"}));
            }
            let i = n2.fetch_add(1, Ordering::SeqCst) + 1;
            return Reply::json(200, serde_json::json!({"token_type": "Bearer", "expires_in": expires_in, "access_token": format!("tok-{i}")}));
        }
        if s.path.starts_with("/acct/") {
            let auth = s.header("authorization").unwrap_or("");
            let tok = auth.strip_prefix("Bearer ").unwrap_or("");
            if tok.is_empty() || reject.contains(&tok) {
                return Reply::azure_error(401, "InvalidAuthenticationInfo");
            }
            assert!(s.header("x-ms-version").is_some());
            return blob_head();
        }
        Reply::new(404)
    })
    .await;
    (mock, n)
}

fn fs_with(mock: &Mock, extra: &[(&str, Value)], env: &[(&str, String)]) -> AzureBlobFileSystem {
    let mut o: Options = extra
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    o.insert("account_name".into(), Value::Str("acct".into()));
    o.insert(
        "account_host".into(),
        Value::Str(format!("{}/acct", mock.url())),
    );
    o.insert("max_retries".into(), Value::Int(0));
    let env: HashMap<String, String> = env
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    AzureBlobFileSystem::from_options_with_env(o, &move |k| env.get(k).cloned()).unwrap()
}

#[tokio::test]
async fn client_secret_tokens_are_cached_and_refreshed_after_401() {
    let (mock, fetched) = server(&["tok-1"], 3600).await;
    let fs = fs_with(
        &mock,
        &[
            ("client_id", "cid".into()),
            ("client_secret", "s3cret".into()),
            ("tenant_id", "tid".into()),
        ],
        &[("AZURE_AUTHORITY_HOST", mock.url())],
    );
    // tok-1 is rejected: the request is retried once with tok-2.
    let i = fs.info("c/blob").await.unwrap();
    assert_eq!(i.size, 3);
    assert_eq!(fetched.load(Ordering::SeqCst), 2);
    // Cached from now on.
    for _ in 0..3 {
        fs.info("c/blob").await.unwrap();
    }
    assert_eq!(fetched.load(Ordering::SeqCst), 2);
    let token_reqs: Vec<Seen> = mock
        .seen()
        .into_iter()
        .filter(|s| s.path == "/tid/oauth2/v2.0/token")
        .collect();
    assert_eq!(token_reqs.len(), 2);
    assert_eq!(form(&token_reqs[0].body)["client_id"], "cid");
}

#[tokio::test]
async fn tokens_near_expiry_are_refreshed() {
    // 100 s lifetime < 5 min refresh margin: every request fetches anew.
    let (mock, fetched) = server(&[], 100).await;
    let fs = fs_with(
        &mock,
        &[
            ("client_id", "cid".into()),
            ("client_secret", "s3cret".into()),
            ("tenant_id", "tid".into()),
        ],
        &[("AZURE_AUTHORITY_HOST", mock.url())],
    );
    fs.info("c/blob").await.unwrap();
    fs.info("c/blob").await.unwrap();
    assert_eq!(fetched.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn bad_secret_is_permission_denied() {
    let (mock, _) = server(&[], 3600).await;
    let fs = fs_with(
        &mock,
        &[
            ("client_id", "cid".into()),
            ("client_secret", "wrong".into()),
            ("tenant_id", "tid".into()),
        ],
        &[("AZURE_AUTHORITY_HOST", mock.url())],
    );
    let e = fs.info("c/blob").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    assert!(e.to_string().contains("invalid_client"), "{e}");
    assert!(
        !e.to_string().contains("wrong"),
        "secrets never appear in errors: {e}"
    );
}

#[tokio::test]
async fn default_chain_uses_workload_identity() {
    let (mock, fetched) = server(&[], 3600).await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("token");
    std::fs::write(&file, "federated-jwt\n").unwrap();
    // No AZURE_CLIENT_SECRET: the environment credential is skipped; the
    // workload identity answers before managed identity / CLI are tried.
    let fs = fs_with(
        &mock,
        &[],
        &[
            ("AZURE_AUTHORITY_HOST", mock.url()),
            ("AZURE_TENANT_ID", "tid".into()),
            ("AZURE_CLIENT_ID", "cid".into()),
            ("AZURE_FEDERATED_TOKEN_FILE", file.display().to_string()),
        ],
    );
    let Credential::Bearer(cache) = fs.credential() else {
        panic!()
    };
    assert_eq!(cache.source().name(), "DefaultAzureCredential");
    fs.info("c/blob").await.unwrap();
    assert_eq!(fetched.load(Ordering::SeqCst), 1);
    let req = mock
        .seen()
        .into_iter()
        .find(|s| s.path.ends_with("/token"))
        .unwrap();
    let f = form(&req.body);
    assert_eq!(
        f["client_assertion_type"],
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    );
}

#[tokio::test]
async fn default_chain_reports_every_failure() {
    let closed = common::mock::closed_port().await;
    let mock = Mock::start(|_| Reply::new(500)).await;
    let fs = fs_with(
        &mock,
        &[("exclude_cli_credential", true.into())],
        &[(
            "AZURE_POD_IDENTITY_AUTHORITY_HOST",
            format!("http://{closed}"),
        )],
    );
    let e = fs.info("c/blob").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    let msg = e.to_string();
    assert!(msg.contains("DefaultAzureCredential"), "{msg}");
    assert!(msg.contains("EnvironmentCredential"), "{msg}");
    assert!(msg.contains("ManagedIdentityCredential"), "{msg}");
}

#[tokio::test]
async fn managed_identity_endpoints() {
    let mock = Mock::start(|s: &Seen| {
        let exp = (SystemTime::now() + Duration::from_secs(3600))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        if s.path == "/msi/token" && s.header("x-identity-header") == Some("hdr") {
            assert_eq!(s.param("api-version").as_deref(), Some("2019-08-01"));
            assert_eq!(s.param("resource").as_deref(), Some("https://storage.azure.com"));
            return Reply::json(200, serde_json::json!({"access_token": "app", "expires_on": exp}));
        }
        if s.path == "/metadata/identity/oauth2/token" && s.header("metadata") == Some("true") {
            assert_eq!(s.param("client_id").as_deref(), Some("uami"));
            return Reply::json(200, serde_json::json!({"access_token": "imds", "expires_on": exp, "expires_in": "3599"}));
        }
        Reply::json(400, serde_json::json!({"error": "invalid_request"}))
    })
    .await;
    let app = ManagedIdentity {
        endpoint: ManagedIdentityEndpoint::AppService {
            endpoint: format!("{}/msi/token", mock.url()),
            header: "hdr".into(),
        },
        client_id: None,
    };
    assert_eq!(app.fetch(&http()).await.unwrap().token.as_str(), "app");
    let imds = ManagedIdentity {
        endpoint: ManagedIdentityEndpoint::Imds(format!(
            "{}/metadata/identity/oauth2/token",
            mock.url()
        )),
        client_id: Some("uami".into()),
    };
    let t = imds.fetch(&http()).await.unwrap();
    assert_eq!(t.token.as_str(), "imds");
    assert!(t.expires_on > SystemTime::now() + Duration::from_secs(3000));
    // An unreachable IMDS fails (fast) instead of hanging.
    let closed = common::mock::closed_port().await;
    let dead = ManagedIdentity {
        endpoint: ManagedIdentityEndpoint::Imds(format!(
            "http://{closed}/metadata/identity/oauth2/token"
        )),
        client_id: None,
    };
    let started = std::time::Instant::now();
    assert!(dead.fetch(&http()).await.is_err());
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[cfg(unix)]
#[tokio::test]
async fn azure_cli_tokens() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let exp = (SystemTime::now() + Duration::from_secs(3600))
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ok = dir.path().join("az-ok");
    std::fs::write(
        &ok,
        format!("#!/bin/sh\n[ \"$1 $2 $5 $6\" = \"account get-access-token --resource https://storage.azure.com\" ] || exit 3\necho '{{\"accessToken\":\"cli-tok\",\"expiresOn\":\"2099-01-01 00:00:00.000000\",\"expires_on\":{exp},\"tokenType\":\"Bearer\"}}'\n"),
    )
    .unwrap();
    let bad = dir.path().join("az-bad");
    std::fs::write(
        &bad,
        "#!/bin/sh\necho 'ERROR: Please run az login to setup account.' >&2\nexit 1\n",
    )
    .unwrap();
    for p in [&ok, &bad] {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let cli = AzureCli {
        tenant_id: None,
        timeout: Duration::from_secs(10),
        program: ok.display().to_string(),
    };
    let cache = TokenCache::new(Box::new(cli), http());
    assert_eq!(cache.token().await.unwrap().as_str(), "cli-tok");
    assert_eq!(cache.token().await.unwrap().as_str(), "cli-tok");
    assert_eq!(cache.fetch_count(), 1);
    let cli = AzureCli {
        tenant_id: None,
        timeout: Duration::from_secs(10),
        program: bad.display().to_string(),
    };
    let e = cli.fetch(&http()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    assert!(e.to_string().contains("az login"), "{e}");
    let missing = AzureCli {
        tenant_id: None,
        timeout: Duration::from_secs(1),
        program: "/nonexistent/az".into(),
    };
    assert!(
        missing
            .fetch(&http())
            .await
            .unwrap_err()
            .to_string()
            .contains("not found")
    );
}

#[tokio::test]
async fn concurrent_requests_share_one_token_fetch() {
    let (mock, fetched) = server(&[], 3600).await;
    let fs = fs_with(
        &mock,
        &[
            ("client_id", "cid".into()),
            ("client_secret", "s3cret".into()),
            ("tenant_id", "tid".into()),
        ],
        &[("AZURE_AUTHORITY_HOST", mock.url())],
    );
    let futs: Vec<_> = (0..16).map(|_| fs.info("c/blob")).collect();
    for r in futures::future::join_all(futs).await {
        r.unwrap();
    }
    assert_eq!(fetched.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn static_token_and_https_rule() {
    let (mock, _) = server(&[], 3600).await;
    let mut cred = std::collections::BTreeMap::new();
    cred.insert("token".to_owned(), Value::Str("tok-9".into()));
    let fs = fs_with(&mock, &[("credential", Value::Map(cred.clone()))], &[]);
    fs.info("c/blob").await.unwrap();
    let seen = mock.seen();
    assert_eq!(
        seen.last().unwrap().header("authorization"),
        Some("Bearer tok-9")
    );

    // Plain HTTP to a non-loopback host never carries a bearer token.
    let mut o: Options = Options::new();
    o.insert("account_name".into(), Value::Str("acct".into()));
    o.insert(
        "account_host".into(),
        Value::Str("http://example.invalid/acct".into()),
    );
    o.insert("credential".into(), Value::Map(cred));
    let fs = AzureBlobFileSystem::from_options_with_env(o, &|_| None).unwrap();
    let e = fs.info("c/blob").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
}
