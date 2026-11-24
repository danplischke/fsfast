//! Test support shared by several test binaries: a local HTTPS server with
//! a self-signed certificate (valid 2000..2100, SAN `localhost` and
//! `127.0.0.1`).

#![allow(dead_code)]

use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBmjCCAUGgAwIBAgIBATAKBggqhkjOPQQDAjAdMRswGQYDVQQDDBJmc2Zhc3Qg
dGVzdCBzZXJ2ZXIwIBcNMDAwMTAxMDAwMDAwWhgPMjEwMDAxMDEwMDAwMDBaMB0x
GzAZBgNVBAMMEmZzZmFzdCB0ZXN0IHNlcnZlcjBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABCBzczV6ma3am7WCUhkt2Iijc/t9fjE3CeBOtoCTqNleEXKxIFqAWO2R
e3eGuftH040aGI5IKXKfb4m+MgY7rg6jcDBuMBoGA1UdEQQTMBGCCWxvY2FsaG9z
dIcEfwAAATAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAK
BggrBgEFBQcDATAdBgNVHQ4EFgQUWQnSIopZ3yHXBjbXYkm5G6XFZYUwCgYIKoZI
zj0EAwIDRwAwRAIgN7PZSXWpruPukl+OhG6U+Y/HP44A028OSEJTn8IEYNACIHWL
uih8O19dQKrX/0YiGDcK6XsJg/U73F4FjcWjLSBT
-----END CERTIFICATE-----
";

pub const KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRjMsJAjE1MHkeSr8
zD42WgwbGicC89W61qywlvlJIzehRANCAAQgc3M1epmt2pu1glIZLdiIo3P7fX4x
NwngTraAk6jZXhFysSBagFjtkXt3hrn7R9ONGhiOSClyn2+JvjIGO64O
-----END PRIVATE KEY-----
";

/// A minimal HTTPS server answering every request with `ok`.
pub async fn serve_tls() -> u16 {
    let cert = CertificateDer::from_pem_slice(CERT.as_bytes()).unwrap();
    let key = PrivateKeyDer::from_pem_slice(KEY.as_bytes()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return; // the client rejected our certificate
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}
