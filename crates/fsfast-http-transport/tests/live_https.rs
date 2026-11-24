//! A real HTTPS server, reached with the environment's proxy settings.
//!
//! Gated on `FSFAST_TEST_HTTPS_URL` (e.g. `https://example.com/`).
//! `FSFAST_TEST_CA_BUNDLE` adds trusted roots (e.g. the CA of an
//! intercepting proxy) on top of the OS store.

use std::path::PathBuf;

use fsfast_core::{ByteRange, ErrorKind};
use fsfast_http_transport::{HttpClient, HttpConfig, Request};

#[tokio::test]
async fn real_https_through_the_environment() {
    let Ok(url) = std::env::var("FSFAST_TEST_HTTPS_URL") else {
        eprintln!("skipping: FSFAST_TEST_HTTPS_URL is not set");
        return;
    };
    let ca = std::env::var_os("FSFAST_TEST_CA_BUNDLE").map(PathBuf::from);
    let c = HttpClient::new(HttpConfig {
        ca_bundle: ca.clone(),
        ..HttpConfig::default()
    })
    .unwrap();
    let r = ByteRange::Bounded { start: 0, end: 512 };
    let body = c
        .send_with(Request::get(&url).unwrap().range(r), |resp| async move {
            assert!(resp.status().is_success(), "{}", resp.status());
            resp.range_bytes(r).await
        })
        .await
        .unwrap();
    assert!(!body.data.is_empty() && body.data.len() <= 512);

    let head = c.send(Request::head(&url).unwrap()).await.unwrap();
    assert!(head.status().is_success());

    // Without the extra roots an intercepting proxy's certificate is
    // rejected: a TLS failure, classified as not worth retrying.
    if ca.is_some() {
        let strict = HttpClient::new(HttpConfig::default()).unwrap();
        match strict.send(Request::head(&url).unwrap()).await {
            Ok(_) => eprintln!("note: the OS store already trusts this server"),
            Err(e) => {
                assert_eq!(e.kind(), ErrorKind::ConnectionFailed, "{e}");
                assert!(!e.is_retryable(), "TLS failures are not retried: {e}");
                assert_eq!(strict.stats().snapshot().retries, 0);
            }
        }
    }
}
