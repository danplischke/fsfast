//! Certificate handling against a local TLS server with a self-signed
//! certificate (valid 2000..2100, SAN `localhost` and `127.0.0.1`).

mod common;

use common::{CERT, serve_tls};
use fsfast_core::ErrorKind;
use fsfast_http_transport::{HttpClient, HttpConfig, Request};

#[tokio::test]
async fn certificates_are_verified_with_os_and_extra_roots() {
    let port = serve_tls().await;
    let url = format!("https://localhost:{port}/x");

    // Unknown issuer: a TLS failure, not retried.
    let c = HttpClient::new(HttpConfig::default()).unwrap();
    let e = c.send(Request::get(&url).unwrap()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ConnectionFailed, "{e}");
    assert!(!e.is_retryable(), "{e}");
    assert!(e.message().contains("TLS"), "{e}");
    assert_eq!(c.stats().snapshot().retries, 0);

    // The certificate as an extra root (merged with the OS store).
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, CERT).unwrap();
    let c = HttpClient::new(HttpConfig {
        ca_bundle: Some(ca),
        ..HttpConfig::default()
    })
    .unwrap();
    for host in ["localhost", "127.0.0.1"] {
        let r = c
            .send(Request::get(&format!("https://{host}:{port}/x")).unwrap())
            .await
            .unwrap();
        assert_eq!(r.bytes().await.unwrap(), "ok");
    }

    // aiohttp's ssl=False.
    let c = HttpClient::new(HttpConfig {
        tls_verify: false,
        ..HttpConfig::default()
    })
    .unwrap();
    let r = c.send(Request::get(&url).unwrap()).await.unwrap();
    assert_eq!(r.bytes().await.unwrap(), "ok");
}
