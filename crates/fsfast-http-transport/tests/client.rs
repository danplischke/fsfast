//! HttpClient against an in-process axum server: status mapping, retries,
//! ranges, request bodies, timeouts, redirects, proxies, per-host limits.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request as AxRequest, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response as AxResponse};
use bytes::Bytes;
use fsfast_core::{ByteRange, Detail, ErrorKind};
use fsfast_http_transport::header::{AUTHORIZATION, HeaderMap as ReqHeaderMap};
use fsfast_http_transport::{
    ErrorParser, HttpClient, HttpConfig, ProxyConfig, Request, RequestBody, ServiceError,
};
use futures::StreamExt;
use parking_lot::Mutex;

#[derive(Default)]
struct Shared {
    counters: Mutex<HashMap<String, usize>>,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    last_headers: Mutex<Option<HeaderMap>>,
    last_body: Mutex<Option<Bytes>>,
    peer: Mutex<Option<String>>,
}

impl Shared {
    fn bump(&self, key: &str) -> usize {
        let mut c = self.counters.lock();
        let n = c.entry(key.to_owned()).or_default();
        *n += 1;
        *n
    }
}

fn data() -> Vec<u8> {
    (0..10_000u32).map(|i| (i * 7 + i / 251) as u8).collect()
}

fn parse_range(h: &HeaderMap, len: u64) -> Option<(u64, u64)> {
    let v = h
        .get(header::RANGE)?
        .to_str()
        .ok()?
        .strip_prefix("bytes=")?;
    let (a, b) = v.split_once('-')?;
    if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        return Some((len.saturating_sub(n), len));
    }
    let a: u64 = a.parse().ok()?;
    let b = if b.is_empty() {
        len
    } else {
        (b.parse::<u64>().ok()? + 1).min(len)
    };
    Some((a, b))
}

async fn handler(State(st): State<Arc<Shared>>, req: AxRequest) -> AxResponse {
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    let headers = req.headers().clone();
    *st.last_headers.lock() = Some(headers.clone());
    if let Some(host) = req.uri().host() {
        // Absolute-form request target: we are being used as a proxy.
        *st.peer.lock() = Some(format!("{}{}", host, req.uri().path()));
    }
    let body = axum::body::to_bytes(req.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    *st.last_body.lock() = Some(body.clone());
    let d = data();
    match path.as_str() {
        "/data" | "/norange" => {
            let honour = path == "/data";
            match parse_range(&headers, d.len() as u64).filter(|_| honour) {
                Some((a, _)) if a >= d.len() as u64 => (
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    [(header::CONTENT_RANGE, format!("bytes */{}", d.len()))],
                )
                    .into_response(),
                Some((a, b)) => (
                    StatusCode::PARTIAL_CONTENT,
                    [(
                        header::CONTENT_RANGE,
                        format!("bytes {}-{}/{}", a, b - 1, d.len()),
                    )],
                    d[a as usize..b as usize].to_vec(),
                )
                    .into_response(),
                None => d.into_response(),
            }
        }
        "/chunked" => {
            let chunks: Vec<Result<Bytes, std::io::Error>> = d
                .chunks(999)
                .map(|c| Ok(Bytes::copy_from_slice(c)))
                .collect();
            Body::from_stream(futures::stream::iter(chunks)).into_response()
        }
        "/flaky" => {
            let n = st.bump(&path);
            if n <= 2 {
                (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response()
            } else {
                "ok".into_response()
            }
        }
        "/throttle" => {
            let n = st.bump(&path);
            if n == 1 {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(header::RETRY_AFTER, "1")],
                    "slow down",
                )
                    .into_response()
            } else {
                "ok".into_response()
            }
        }
        "/status" => {
            let code: u16 = query.parse().unwrap_or(500);
            (
                StatusCode::from_u16(code).unwrap(),
                [(header::CONTENT_TYPE, "application/xml")],
                format!("<Error><Code>Code{code}</Code><Message>msg {code}</Message></Error>"),
            )
                .into_response()
        }
        "/slow" => {
            let now = st.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            st.max_in_flight.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(query.parse().unwrap_or(100))).await;
            st.in_flight.fetch_sub(1, Ordering::SeqCst);
            "slow".into_response()
        }
        "/echo" => {
            let te = headers
                .get(header::TRANSFER_ENCODING)
                .map(|v| v.to_str().unwrap().to_owned())
                .unwrap_or_default();
            let cl = headers
                .get(header::CONTENT_LENGTH)
                .map(|v| v.to_str().unwrap().to_owned())
                .unwrap_or_default();
            format!("len={} cl={} te={}", body.len(), cl, te).into_response()
        }
        "/headers" => {
            let auth = headers
                .get(header::AUTHORIZATION)
                .map(|v| v.to_str().unwrap().to_owned())
                .unwrap_or_else(|| "none".into());
            format!("auth={auth}").into_response()
        }
        p if p.starts_with("/redirect/") => {
            let target = query.replace("%3A", ":").replace("%2F", "/");
            (StatusCode::FOUND, [(header::LOCATION, target)]).into_response()
        }
        _ => (StatusCode::NOT_FOUND, "no such thing").into_response(),
    }
}

async fn serve() -> (SocketAddr, Arc<Shared>) {
    let st = Arc::new(Shared::default());
    let app = Router::new().fallback(handler).with_state(st.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, st)
}

fn fast_retries() -> HttpConfig {
    HttpConfig {
        retry_base_delay: Duration::from_millis(1),
        retry_max_delay: Duration::from_millis(5),
        ..HttpConfig::default()
    }
}

fn client() -> HttpClient {
    HttpClient::new(fast_retries()).unwrap()
}

#[tokio::test]
async fn collects_bodies_with_and_without_content_length() {
    let (addr, _) = serve().await;
    let c = client();
    for p in ["data", "chunked"] {
        let resp = c
            .send(Request::get(&format!("http://{addr}/{p}")).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.bytes().await.unwrap(), data(), "{p}");
    }
    let snap = c.stats().snapshot();
    assert_eq!(snap.requests, 2);
    assert_eq!(snap.bytes_read, 2 * data().len() as u64);

    // HEAD reports the length without a body.
    let resp = c
        .send(Request::head(&format!("http://{addr}/data")).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.content_length(), Some(data().len() as u64));
    assert!(resp.bytes().await.unwrap().is_empty());

    // Streaming.
    let resp = c
        .send(Request::get(&format!("http://{addr}/chunked")).unwrap())
        .await
        .unwrap();
    let mut s = resp.into_stream();
    let mut all = Vec::new();
    while let Some(chunk) = s.next().await {
        all.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(all, data());
}

#[derive(Debug)]
struct XmlParser;

impl ErrorParser for XmlParser {
    fn parse(
        &self,
        _: fsfast_http_transport::StatusCode,
        _: &ReqHeaderMap,
        body: &[u8],
    ) -> Option<ServiceError> {
        let s = std::str::from_utf8(body).ok()?;
        let between = |a: &str, b: &str| -> Option<String> {
            Some(s.split(a).nth(1)?.split(b).next()?.to_owned())
        };
        Some(ServiceError {
            code: between("<Code>", "</Code>"),
            message: between("<Message>", "</Message>"),
            ..ServiceError::default()
        })
    }
}

#[tokio::test]
async fn statuses_map_to_kinds_with_details() {
    let (addr, _) = serve().await;
    let c = HttpClient::builder(HttpConfig {
        max_retries: 0,
        ..HttpConfig::default()
    })
    .error_parser(Arc::new(XmlParser))
    .build()
    .unwrap();
    let cases = [
        (404, ErrorKind::NotFound),
        (410, ErrorKind::NotFound),
        (401, ErrorKind::PermissionDenied),
        (403, ErrorKind::PermissionDenied),
        (412, ErrorKind::PreconditionFailed),
        (429, ErrorKind::Throttled),
        (503, ErrorKind::Throttled),
        (409, ErrorKind::AlreadyExists),
        (400, ErrorKind::InvalidInput),
        (500, ErrorKind::Io),
    ];
    for (code, kind) in cases {
        let url = format!("http://{addr}/status?{code}");
        let e = c
            .send(Request::get(&url).unwrap().path("my/path"))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), kind, "{code}: {e}");
        assert_eq!(e.http_status(), Some(code));
        assert_eq!(e.path(), Some("my/path"));
        assert!(
            e.details().contains(&Detail::Code(format!("Code{code}"))),
            "{e:?}"
        );
        assert!(e.message().contains(&format!("msg {code}")), "{e}");
    }
    // Per-request override.
    let e = c
        .send(
            Request::get(&format!("http://{addr}/status?409"))
                .unwrap()
                .status_kind(409, ErrorKind::DirectoryNotEmpty),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::DirectoryNotEmpty);
    // Allowed statuses come back as responses.
    let resp = c
        .send(
            Request::get(&format!("http://{addr}/status?404"))
                .unwrap()
                .allow_status(404),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    // Without a path, errors report the URL minus credentials and query.
    let e = c
        .send(Request::get(&format!("http://user:pw@{addr}/missing?sig=x")).unwrap())
        .await
        .unwrap_err();
    assert_eq!(e.path(), Some(format!("http://{addr}/missing").as_str()));
}

#[tokio::test]
async fn retries_only_retry_safe_requests() {
    let (addr, st) = serve().await;
    let c = client();
    let resp = c
        .send(Request::get(&format!("http://{addr}/flaky")).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.bytes().await.unwrap(), "ok");
    assert_eq!(c.stats().snapshot().retries, 2);

    // POST is not idempotent: the first 500 is final.
    st.counters.lock().clear();
    let c = client();
    let e = c
        .send(Request::post(&format!("http://{addr}/flaky")).unwrap())
        .await
        .unwrap_err();
    assert_eq!(e.http_status(), Some(500));
    assert_eq!(c.stats().snapshot().retries, 0);
    // ...unless the caller marks it safe.
    let resp = c
        .send(
            Request::post(&format!("http://{addr}/flaky"))
                .unwrap()
                .retry_safe(true),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn retry_after_is_honoured_and_throttles_counted() {
    let (addr, _) = serve().await;
    let c = HttpClient::new(HttpConfig {
        retry_base_delay: Duration::from_millis(1),
        retry_max_delay: Duration::from_secs(5),
        ..HttpConfig::default()
    })
    .unwrap();
    let start = std::time::Instant::now();
    let resp = c
        .send(Request::get(&format!("http://{addr}/throttle")).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(
        start.elapsed() >= Duration::from_millis(950),
        "{:?}",
        start.elapsed()
    );
    let snap = c.stats().snapshot();
    assert_eq!((snap.retries, snap.throttles), (1, 1));
}

#[tokio::test]
async fn range_bytes_handles_206_200_and_416() {
    let (addr, _) = serve().await;
    let c = client();
    let d = data();
    let n = d.len() as u64;
    let ranges = [
        ByteRange::Bounded { start: 10, end: 20 },
        ByteRange::Bounded {
            start: 9_990,
            end: 20_000,
        },
        ByteRange::From(9_000),
        ByteRange::Suffix(100),
        ByteRange::Suffix(20_000),
        ByteRange::Bounded { start: 0, end: 1 },
        ByteRange::Bounded {
            start: 20_000,
            end: 30_000,
        },
    ];
    for p in ["data", "norange"] {
        for r in ranges {
            let url = format!("http://{addr}/{p}");
            let body = c
                .send_with(Request::get(&url).unwrap().range(r), |resp| async move {
                    resp.range_bytes(r).await
                })
                .await
                .unwrap();
            let w = r.resolve(n);
            assert_eq!(
                &body.data[..],
                &d[w.start as usize..w.end as usize],
                "{p} {r:?}"
            );
            if !body.data.is_empty() {
                assert_eq!(body.offset, w.start, "{p} {r:?}");
            }
            assert_eq!(body.ranged, p == "data", "{p} {r:?}");
        }
    }
    // A suffix of a body of unknown length that ignores ranges.
    let url = format!("http://{addr}/chunked");
    let r = ByteRange::Suffix(5);
    let body = c
        .send_with(Request::get(&url).unwrap().range(r), |resp| async move {
            resp.range_bytes(r).await
        })
        .await
        .unwrap();
    assert_eq!(&body.data[..], &d[d.len() - 5..]);
    assert_eq!(body.offset, n - 5);
}

#[tokio::test]
async fn request_bodies_are_sized_without_copies() {
    let (addr, _) = serve().await;
    let c = client();
    let url = format!("http://{addr}/echo");
    let send = |body: RequestBody| {
        let c = c.clone();
        let url = url.clone();
        async move {
            let resp = c
                .send(Request::put(&url).unwrap().body(body))
                .await
                .unwrap();
            String::from_utf8(resp.bytes().await.unwrap().to_vec()).unwrap()
        }
    };
    assert_eq!(
        send(Bytes::from_static(b"hello").into()).await,
        "len=5 cl=5 te="
    );
    assert_eq!(
        send(RequestBody::chunks(vec![
            Bytes::from_static(b"ab"),
            Bytes::from_static(b"cde"),
            Bytes::from_static(b"f"),
        ]))
        .await,
        "len=6 cl=6 te="
    );
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("f.bin");
    std::fs::write(&file, vec![7u8; 3_000_000]).unwrap();
    assert_eq!(
        send(RequestBody::File {
            path: file.clone(),
            len: 3_000_000
        })
        .await,
        "len=3000000 cl=3000000 te="
    );
    let chunks = || {
        futures::stream::iter(
            [b"xy".as_slice(), b"z".as_slice()]
                .map(|c| Ok::<_, std::io::Error>(Bytes::from_static(c))),
        )
    };
    assert_eq!(
        send(RequestBody::stream(chunks(), None)).await,
        "len=3 cl= te=chunked"
    );
    assert_eq!(
        send(RequestBody::stream(chunks(), Some(3))).await,
        "len=3 cl=3 te="
    );
    assert_eq!(
        c.stats().snapshot().bytes_written,
        5 + 6 + 3_000_000 + 3 + 3
    );

    // A body whose length does not match the declared one fails (not
    // retried) instead of sending something else.
    for len in [10, 3_000_001] {
        let e = c
            .send(Request::put(&url).unwrap().body(RequestBody::File {
                path: file.clone(),
                len,
            }))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Io, "{e}");
        assert!(!e.is_retryable());
        assert!(e.message().contains("declared"), "{e}");
    }
    let e = c
        .send(
            Request::put(&url)
                .unwrap()
                .body(RequestBody::stream(chunks(), Some(2))),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io, "{e}");
}

/// RFC 9110 §8.6: a request whose method defines a meaning for content
/// carries `Content-Length` even when it is 0 (fsspec's `pipe_file` sets it
/// explicitly; S3-style servers answer 411 without it). hyper leaves the
/// header out for an empty body, so the client must add it.
#[tokio::test]
async fn empty_uploads_carry_content_length_zero() {
    let (addr, _) = serve().await;
    let c = client();
    let url = format!("http://{addr}/echo");
    let send = |req: Request| {
        let c = c.clone();
        async move {
            let resp = c.send(req).await.unwrap();
            String::from_utf8(resp.bytes().await.unwrap().to_vec()).unwrap()
        }
    };
    for method in [
        fsfast_http_transport::Method::PUT,
        fsfast_http_transport::Method::POST,
        fsfast_http_transport::Method::PATCH,
    ] {
        for body in [
            RequestBody::Empty,
            RequestBody::Bytes(Bytes::new()),
            RequestBody::chunks(Vec::new()),
            RequestBody::stream(futures::stream::empty(), Some(0)),
        ] {
            let req = Request::new(method.clone(), &url).unwrap().body(body);
            assert_eq!(send(req).await, "len=0 cl=0 te=", "{method}");
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty");
    std::fs::write(&empty, b"").unwrap();
    let req = Request::put(&url).unwrap().body(RequestBody::File {
        path: empty,
        len: 0,
    });
    assert_eq!(send(req).await, "len=0 cl=0 te=");
    // Methods without content semantics stay without the header.
    for req in [Request::get(&url).unwrap(), Request::delete(&url).unwrap()] {
        assert_eq!(send(req).await, "len=0 cl= te=");
    }
}

#[tokio::test]
async fn timeouts_and_refused_connections() {
    let (addr, _) = serve().await;
    let c = HttpClient::new(HttpConfig {
        total_timeout: Some(Duration::from_millis(100)),
        max_retries: 0,
        ..HttpConfig::default()
    })
    .unwrap();
    let e = c
        .send(Request::get(&format!("http://{addr}/slow?2000")).unwrap())
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Timeout, "{e}");
    // Per-request timeout overrides.
    let c = client();
    let e = c
        .send(
            Request::get(&format!("http://{addr}/slow?2000"))
                .unwrap()
                .timeout(Duration::from_millis(50)),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Timeout, "{e}");

    let free = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let e = client()
        .send(Request::get(&format!("http://{free}/x")).unwrap())
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ConnectionFailed, "{e}");
    assert!(e.is_retryable());
}

#[tokio::test]
async fn authorization_is_dropped_on_cross_origin_redirects() {
    let (a, _) = serve().await;
    let (b, _) = serve().await;
    let mut cfg = fast_retries();
    cfg.auth = Some(fsfast_http_transport::BasicAuth::new("u", "p"));
    let c = HttpClient::new(cfg).unwrap();
    let get = |url: String| {
        let c = c.clone();
        async move {
            let r = c.send(Request::get(&url).unwrap()).await.unwrap();
            (
                r.url().to_string(),
                String::from_utf8(r.bytes().await.unwrap().to_vec()).unwrap(),
            )
        }
    };
    let (_, same) = get(format!("http://{a}/redirect/x?http%3A%2F%2F{a}%2Fheaders")).await;
    assert!(same.starts_with("auth=Basic "), "{same}");
    let (final_url, cross) = get(format!("http://{a}/redirect/x?http%3A%2F%2F{b}%2Fheaders")).await;
    assert_eq!(cross, "auth=none");
    assert_eq!(final_url, format!("http://{b}/headers"));

    // With redirects disabled the 3xx itself is returned.
    let c = HttpClient::new(HttpConfig {
        max_redirects: None,
        ..HttpConfig::default()
    })
    .unwrap();
    let r = c
        .send(Request::get(&format!("http://{a}/redirect/x?http%3A%2F%2F{b}%2Fheaders")).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), 302);
}

#[tokio::test]
async fn explicit_proxy_and_default_headers() {
    let (proxy, st) = serve().await;
    let mut cfg = fast_retries();
    cfg.proxy = ProxyConfig::Url {
        url: format!("http://{proxy}"),
        auth: Some(fsfast_http_transport::BasicAuth::new("pu", "pp")),
    };
    cfg.set_header("X-Custom", "yes").unwrap();
    cfg.query = vec![("k".into(), "v w".into())];
    let c = HttpClient::new(cfg).unwrap();
    let r = c
        .send(Request::get("http://example.invalid/headers").unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(st.peer.lock().as_deref(), Some("example.invalid/headers"));
    let h = st.last_headers.lock().clone().unwrap();
    assert_eq!(h["x-custom"], "yes");
    assert!(
        h["proxy-authorization"]
            .to_str()
            .unwrap()
            .starts_with("Basic ")
    );
    assert!(h.get(AUTHORIZATION).is_none());
    assert!(h["user-agent"].to_str().unwrap().starts_with("fsfast/"));

    // Query parameters from the configuration are appended.
    let (addr, st) = serve().await;
    let c = HttpClient::new(HttpConfig {
        query: vec![("k".into(), "v w".into())],
        ..HttpConfig::default()
    })
    .unwrap();
    let r = c
        .send(Request::get(&format!("http://{addr}/headers?a=1")).unwrap())
        .await
        .unwrap();
    assert_eq!(r.url().query(), Some("a=1&k=v+w"));
    drop(st);
}

#[tokio::test]
async fn per_host_concurrency_is_limited() {
    let (addr, st) = serve().await;
    let c = HttpClient::new(HttpConfig {
        max_connections_per_host: 2,
        initial_connections_per_host: 2,
        ..HttpConfig::default()
    })
    .unwrap();
    let url = format!("http://{addr}/slow?50");
    let futs = (0..8).map(|_| {
        let c = c.clone();
        let url = url.clone();
        async move {
            c.send(Request::get(&url).unwrap())
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
        }
    });
    futures::future::join_all(futs).await;
    assert_eq!(st.max_in_flight.load(Ordering::SeqCst), 2);
    assert_eq!(c.host_limit(&url.parse().unwrap()), 2);

    // A held stream does not block further requests to the same host.
    let c = HttpClient::new(HttpConfig {
        max_connections_per_host: 1,
        initial_connections_per_host: 1,
        ..HttpConfig::default()
    })
    .unwrap();
    let held = c
        .send(Request::get(&format!("http://{addr}/chunked")).unwrap())
        .await
        .unwrap()
        .into_stream();
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        c.send(Request::get(&format!("http://{addr}/data")).unwrap()),
    )
    .await
    .expect("second request must not wait for the stream")
    .unwrap();
    assert_eq!(r.bytes().await.unwrap().len(), data().len());
    drop(held);
}

#[tokio::test]
async fn window_stops_early_and_truncation() {
    let (addr, _) = serve().await;
    let c = client();
    let r = c
        .send(Request::get(&format!("http://{addr}/chunked")).unwrap())
        .await
        .unwrap();
    let w = r.bytes_window(1_500, Some(2_000)).await.unwrap();
    assert_eq!(&w[..], &data()[1_500..3_500]);
    let r = c
        .send(Request::get(&format!("http://{addr}/data")).unwrap())
        .await
        .unwrap();
    assert_eq!(&r.bytes_truncated(10).await.unwrap()[..], &data()[..10]);
}

#[tokio::test]
async fn construction_errors_and_dns_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("ca.pem");
    std::fs::write(&bad, "not a certificate").unwrap();
    let e = HttpClient::new(HttpConfig {
        ca_bundle: Some(bad),
        ..HttpConfig::default()
    })
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
    let e = HttpClient::new(HttpConfig {
        ca_bundle: Some(dir.path().join("missing.pem")),
        ..HttpConfig::default()
    })
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
    let e = HttpClient::new(HttpConfig {
        proxy: ProxyConfig::Url {
            url: "::not a url::".into(),
            auth: None,
        },
        ..HttpConfig::default()
    })
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);

    // A client with the rotating resolver reaches "localhost".
    let (addr, _) = serve().await;
    let c = HttpClient::new(HttpConfig {
        rotate_dns: true,
        ..HttpConfig::default()
    })
    .unwrap();
    for _ in 0..3 {
        let r = c
            .send(Request::get(&format!("http://localhost:{}/data", addr.port())).unwrap())
            .await;
        // localhost may resolve to ::1 first while the server listens on
        // IPv4 only; the connector falls back to the next address.
        assert_eq!(r.unwrap().bytes().await.unwrap().len(), data().len());
    }
}

#[tokio::test]
async fn http2_prior_knowledge_multiplexes_ranged_reads() {
    let (addr, _) = serve().await;
    let c = HttpClient::new(HttpConfig {
        http2_prior_knowledge: true,
        ..fast_retries()
    })
    .unwrap();
    let url = format!("http://{addr}/data");
    let d = data();
    let futs = (0..16u64).map(|i| {
        let c = c.clone();
        let url = url.clone();
        async move {
            let r = ByteRange::Bounded {
                start: i * 500,
                end: i * 500 + 700,
            };
            c.send_with(Request::get(&url).unwrap().range(r), |resp| async move {
                assert_eq!(resp.version(), fsfast_http_transport::Version::HTTP_2);
                resp.range_bytes(r).await
            })
            .await
            .unwrap()
        }
    });
    for (i, body) in futures::future::join_all(futs)
        .await
        .into_iter()
        .enumerate()
    {
        let s = i * 500;
        assert_eq!(&body.data[..], &d[s..(s + 700).min(d.len())]);
    }
    // HTTP/1.1 only: never HTTP/2.
    let c = HttpClient::new(HttpConfig {
        http2: false,
        ..HttpConfig::default()
    })
    .unwrap();
    let r = c.send(Request::get(&url).unwrap()).await.unwrap();
    assert_eq!(r.version(), fsfast_http_transport::Version::HTTP_11);
}
