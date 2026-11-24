//! Environment proxies (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) and their
//! `NO_PROXY` exclusions, with the default `ProxyConfig::Environment`.
//!
//! The variables are read when a client is built, and changing the
//! environment of a running (multi-threaded) test process is unsound, so
//! every case runs this test binary again as a child process with exactly
//! the proxy variables of that case. The parent hosts a target server and a
//! fake proxy (both answer with their name) and checks which one the child
//! reached.

mod common;

use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fsfast_http_transport::{HttpClient, HttpConfig, ProxyConfig, Request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const CHILD: &str = "FSFAST_ENV_PROXY_CHILD";
const PROXY_VARS: &[&str] = &[
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "REQUEST_METHOD",
];

/// A plain HTTP server answering every request with `via=<name>`; a
/// `CONNECT` (an HTTPS tunnel request) is refused with 403 and counted.
async fn named_server(name: &'static str) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connects = Arc::new(AtomicUsize::new(0));
    let counter = connects.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let reply = if buf.starts_with(b"CONNECT ") {
                    counter.fetch_add(1, Ordering::SeqCst);
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_owned()
                } else {
                    let body = format!("via={name}");
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let _ = sock.write_all(reply.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (addr, connects)
}

/// (name, target URL, child mode, proxy variables, expected result prefix)
type Case<'a> = (
    &'static str,
    &'a str,
    &'a str,
    Vec<(&'static str, String)>,
    &'static str,
);

/// Run the child half with `vars` as its only proxy variables; returns what
/// it reached (`via=...`, `error=...`).
fn run_child(target: &str, mode: &str, vars: &[(&str, String)]) -> String {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["child_half", "--exact", "--nocapture", "--test-threads=1"]);
    for v in PROXY_VARS {
        cmd.env_remove(v);
    }
    for (k, v) in vars {
        cmd.env(k, v);
    }
    cmd.env(CHILD, "1")
        .env("FSFAST_ENV_PROXY_TARGET", target)
        .env("FSFAST_ENV_PROXY_MODE", mode);
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "child failed: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
        .lines()
        // The harness prints `test child_half ... ` on the same line.
        .find_map(|l| l.split_once("RESULT ").map(|(_, r)| r))
        .unwrap_or_else(|| panic!("no result from child: {stdout}"))
        .to_owned()
}

/// The child half: does nothing unless started by `environment_proxies`.
#[tokio::test]
async fn child_half() {
    if std::env::var_os(CHILD).is_none() {
        return;
    }
    let target = std::env::var("FSFAST_ENV_PROXY_TARGET").unwrap();
    let mode = std::env::var("FSFAST_ENV_PROXY_MODE").unwrap();
    let mut cfg = HttpConfig {
        max_retries: 0,
        // The HTTPS target has a self-signed certificate; what matters here
        // is only which server answers.
        tls_verify: false,
        ..HttpConfig::default()
    };
    if mode == "disabled" {
        cfg.proxy = ProxyConfig::Disabled;
    } else if let Some(url) = mode.strip_prefix("explicit:") {
        cfg.proxy = ProxyConfig::Url {
            url: url.to_owned(),
            auth: None,
        };
    }
    let c = HttpClient::new(cfg).unwrap();
    let result = match c.send(Request::get(&target).unwrap()).await {
        Ok(r) => String::from_utf8_lossy(&r.bytes().await.unwrap()).into_owned(),
        Err(e) => format!("error={e}"),
    };
    println!("RESULT {result}");
}

#[tokio::test(flavor = "multi_thread")]
async fn environment_proxies() {
    if std::env::var_os(CHILD).is_some() {
        return;
    }
    let (target, _) = named_server("direct").await;
    let (proxy, connects) = named_server("proxy").await;
    let tls_port = common::serve_tls().await;
    let target_url = format!("http://{target}/x");
    let localhost_url = format!("http://localhost:{}/x", target.port());
    let tls_url = format!("https://127.0.0.1:{tls_port}/x");
    let p = format!("http://{proxy}");
    let explicit = format!("explicit:{p}");

    let cases: Vec<Case<'_>> = vec![
        // The environment proxy is used: proves the variables reach the client.
        (
            "HTTP_PROXY",
            &target_url,
            "env",
            vec![("HTTP_PROXY", p.clone())],
            "via=proxy",
        ),
        (
            "lowercase http_proxy",
            &target_url,
            "env",
            vec![("http_proxy", p.clone())],
            "via=proxy",
        ),
        (
            "ALL_PROXY",
            &target_url,
            "env",
            vec![("ALL_PROXY", p.clone())],
            "via=proxy",
        ),
        // NO_PROXY exclusions: IP, CIDR, domain, lowercase variable, `*`.
        (
            "NO_PROXY ip",
            &target_url,
            "env",
            vec![("HTTP_PROXY", p.clone()), ("NO_PROXY", "127.0.0.1".into())],
            "via=direct",
        ),
        (
            "no_proxy cidr",
            &target_url,
            "env",
            vec![
                ("HTTP_PROXY", p.clone()),
                ("no_proxy", "example.com, 127.0.0.0/8".into()),
            ],
            "via=direct",
        ),
        (
            "NO_PROXY localhost",
            &localhost_url,
            "env",
            vec![("ALL_PROXY", p.clone()), ("NO_PROXY", "localhost".into())],
            "via=direct",
        ),
        (
            "NO_PROXY *",
            &target_url,
            "env",
            vec![("HTTP_PROXY", p.clone()), ("NO_PROXY", "*".into())],
            "via=direct",
        ),
        (
            "NO_PROXY other host",
            &target_url,
            "env",
            vec![
                ("HTTP_PROXY", p.clone()),
                ("NO_PROXY", "example.com".into()),
            ],
            "via=proxy",
        ),
        // HTTPS_PROXY applies to https:// only.
        (
            "HTTPS_PROXY for http",
            &target_url,
            "env",
            vec![("HTTPS_PROXY", p.clone())],
            "via=direct",
        ),
        // A local HTTPS service bypasses HTTPS_PROXY through NO_PROXY...
        (
            "HTTPS_PROXY + NO_PROXY",
            &tls_url,
            "env",
            vec![
                ("HTTPS_PROXY", p.clone()),
                ("NO_PROXY", "localhost,127.0.0.1".into()),
            ],
            "ok",
        ),
        // ...and without it the request is tunnelled through the proxy
        // (which refuses the CONNECT here).
        (
            "HTTPS_PROXY",
            &tls_url,
            "env",
            vec![("HTTPS_PROXY", p.clone())],
            "error=",
        ),
        // aiohttp trust_env=False: direct, whatever the environment says.
        (
            "trust_env=False",
            &target_url,
            "disabled",
            vec![("HTTP_PROXY", p.clone())],
            "via=direct",
        ),
        // aiohttp proxy=: always that proxy, NO_PROXY does not apply.
        (
            "explicit proxy",
            &target_url,
            &explicit,
            vec![("NO_PROXY", "127.0.0.1".into())],
            "via=proxy",
        ),
    ];
    for (name, url, mode, vars, want) in cases {
        let url = url.to_owned();
        let mode = mode.to_owned();
        let got = tokio::task::spawn_blocking(move || run_child(&url, &mode, &vars))
            .await
            .unwrap();
        assert!(got.starts_with(want), "{name}: got {got:?}, want {want:?}");
    }
    assert_eq!(
        connects.load(Ordering::SeqCst),
        1,
        "exactly one HTTPS request was tunnelled through the proxy"
    );
}
