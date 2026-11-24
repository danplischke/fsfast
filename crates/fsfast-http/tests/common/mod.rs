//! In-process HTTP test server.
//!
//! * `/files/...`: a temporary directory served by tower-http's `ServeDir`
//!   (Range, HEAD, Last-Modified, 416: a real static file server).
//! * `/site/...`: generated HTML index pages and files for `ls`/`find`.
//! * `/data/<behaviour>/...`: one generated blob served with a specific
//!   behaviour (ignores Range, no Content-Length, HEAD refused, ...).
//! * `/upload/...`: accepts PUT/POST into memory and serves it back.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use parking_lot::Mutex;
use tower_http::services::ServeDir;

/// Size of the `/data/...` blob: several blocks of the tests' block size.
pub const BLOB_LEN: usize = 3 * (1 << 20) + 12_345;

/// Deterministic content (SplitMix64 bytes, distinct for every offset shift).
pub fn pattern(seed: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut x = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    while out.len() < len {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        for b in z.to_le_bytes() {
            if out.len() < len {
                out.push(b);
            }
        }
    }
    out
}

/// The `/data/...` and `/files/blob.bin` content (generated once).
pub fn blob() -> Vec<u8> {
    blob_bytes().to_vec()
}

fn blob_bytes() -> Bytes {
    static BLOB: std::sync::OnceLock<Bytes> = std::sync::OnceLock::new();
    BLOB.get_or_init(|| Bytes::from(pattern(1, BLOB_LEN)))
        .clone()
}

/// `pattern(100 + version, BLOB_LEN)`, cached.
fn versioned(v: u64) -> Bytes {
    static CACHE: std::sync::OnceLock<Mutex<HashMap<u64, Bytes>>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(Default::default)
        .lock()
        .entry(v)
        .or_insert_with(|| Bytes::from(pattern(100 + v, BLOB_LEN)))
        .clone()
}

/// One request as the server saw it.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: Method,
    pub path: String,
    pub headers: HeaderMap,
    pub body_len: usize,
}

/// A verbatim page: optional Content-Type and body.
pub type Page = (Option<String>, Vec<u8>);

#[derive(Default)]
pub struct Shared {
    pub log: Mutex<Vec<Seen>>,
    pub uploads: Mutex<HashMap<String, (Method, Bytes)>>,
    /// Version of `/data/etag/...` and `/data/weak/...` content.
    pub version: AtomicU64,
    pub counter: AtomicUsize,
    pub port: AtomicU64,
    /// The directory served under `/files`.
    pub root: Mutex<Option<std::path::PathBuf>>,
    /// Pages served verbatim.
    pub pages: Mutex<HashMap<String, Page>>,
}

impl Shared {
    /// Requests whose path starts with `prefix`.
    pub fn requests(&self, prefix: &str) -> Vec<Seen> {
        self.log
            .lock()
            .iter()
            .filter(|s| s.path.starts_with(prefix))
            .cloned()
            .collect()
    }

    pub fn clear_log(&self) {
        self.log.lock().clear();
    }
}

pub struct TestServer {
    pub addr: SocketAddr,
    pub dir: tempfile::TempDir,
    pub state: Arc<Shared>,
}

impl TestServer {
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

fn parse_range(h: &HeaderMap, len: u64) -> Option<Result<(u64, u64), ()>> {
    let v = h
        .get(header::RANGE)?
        .to_str()
        .ok()?
        .strip_prefix("bytes=")?;
    let (a, b) = v.split_once('-')?;
    if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        if n == 0 || len == 0 {
            return Some(Err(()));
        }
        return Some(Ok((len.saturating_sub(n), len)));
    }
    let a: u64 = a.parse().ok()?;
    if a >= len {
        return Some(Err(()));
    }
    let b = if b.is_empty() {
        len
    } else {
        (b.parse::<u64>().ok()? + 1).min(len)
    };
    Some(Ok((a, b)))
}

/// Serve `data` honouring Range (optionally capping parts and hiding the
/// total).
fn ranged(
    method: &Method,
    h: &HeaderMap,
    data: &Bytes,
    extra: &[(header::HeaderName, String)],
    cap: Option<u64>,
    hide_total: bool,
) -> Response {
    let len = data.len() as u64;
    let mut resp = match parse_range(h, len) {
        Some(Err(())) => (
            StatusCode::RANGE_NOT_SATISFIABLE,
            [(header::CONTENT_RANGE, format!("bytes */{len}"))],
        )
            .into_response(),
        Some(Ok((a, b))) => {
            let b = cap.map_or(b, |c| b.min(a + c));
            let total = if hide_total {
                "*".to_owned()
            } else {
                len.to_string()
            };
            let body = if *method == Method::HEAD {
                Bytes::new()
            } else {
                data.slice(a as usize..b as usize)
            };
            let mut r = Response::new(Body::from(body));
            *r.status_mut() = StatusCode::PARTIAL_CONTENT;
            r.headers_mut().insert(
                header::CONTENT_RANGE,
                format!("bytes {a}-{}/{total}", b - 1).parse().unwrap(),
            );
            r.headers_mut()
                .insert(header::CONTENT_LENGTH, (b - a).into());
            r
        }
        None => full(method, data),
    };
    resp.headers_mut()
        .insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());
    for (k, v) in extra {
        resp.headers_mut().insert(k.clone(), v.parse().unwrap());
    }
    resp
}

/// The whole body (a HEAD gets the length without the body).
fn full(method: &Method, data: &Bytes) -> Response {
    let mut r = if *method == Method::HEAD {
        Response::new(Body::empty())
    } else {
        Response::new(Body::from(data.clone()))
    };
    r.headers_mut()
        .insert(header::CONTENT_LENGTH, data.len().into());
    r
}

fn html(body: String) -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
}

fn site(path: &str, port: u64) -> Option<Response> {
    let page = |links: &[&str]| {
        let mut s = String::from("<html><body><h1>Index</h1>\n");
        for l in links {
            s.push_str(&format!("<a href=\"{l}\">{l}</a><br>\n"));
        }
        s.push_str("</body></html>");
        html(s)
    };
    Some(match path {
        "/site/" | "/site" => {
            let cross = format!("https://127.0.0.1:{port}/site/cross.txt");
            let links = [
                "../",
                "?C=N;O=D",
                "a.txt",
                "sub/",
                "/site/abs.bin",
                "/elsewhere/x",
                "http://other.example/x",
                cross.as_str(),
            ];
            let mut s = String::from("<html><body>\n");
            for l in links {
                s.push_str(&format!("<a href=\"{l}\">{l}</a><br>\n"));
            }
            // A bare URL in the text: a link only with simple_links.
            s.push_str(&format!(
                "see http://127.0.0.1:{port}/site/bare.txt\n</body></html>"
            ));
            html(s)
        }
        "/site/simple/" => html(format!(
            "<html>see http://127.0.0.1:{port}/site/simple/bare.txt and \
             <a href=\"linked.txt\">l</a></html>"
        )),
        "/site/sub/" | "/site/sub" => page(&["deep.txt", "deeper/", "../"]),
        "/site/sub/deeper/" | "/site/sub/deeper" => page(&["z.txt"]),
        "/site/empty/" => html("<html>nothing here</html>".to_owned()),
        "/site/empty" => page(&["x"]),
        "/site/dots/" | "/site/dots" | "/site/dots/." => page(&["./", "f.txt"]),
        "/site/latin1/" => (
            [(header::CONTENT_TYPE, "text/html; charset=latin-1")],
            b"<a href=\"caf\xe9.txt\">x</a>".to_vec(),
        )
            .into_response(),
        "/site/a.txt" => ([(header::CONTENT_TYPE, "text/plain")], "aaa").into_response(),
        "/site/abs.bin" => (
            [(header::CONTENT_TYPE, "application/octet-stream")],
            vec![1u8, 2, 3],
        )
            .into_response(),
        "/site/sub/deep.txt" | "/site/sub/deeper/z.txt" | "/site/dots/f.txt" => {
            ([(header::CONTENT_TYPE, "text/plain")], "x").into_response()
        }
        _ => return None,
    })
}

async fn handler(State(st): State<Arc<Shared>>, req: Request) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let h = req.headers().clone();
    if path.starts_with("/upload-slow/") {
        // Let the client's body queue fill up before reading it.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    let body = axum::body::to_bytes(req.into_body(), usize::MAX).await;
    let aborted = body.is_err();
    let body = body.unwrap_or_default();
    st.log.lock().push(Seen {
        method: method.clone(),
        path: path.clone(),
        headers: h.clone(),
        body_len: body.len(),
    });
    if let Some((ctype, page)) = st.pages.lock().get(&path).cloned() {
        let mut r = Response::new(Body::from(page));
        if let Some(ct) = ctype {
            r.headers_mut()
                .insert(header::CONTENT_TYPE, ct.parse().unwrap());
        }
        return r;
    }
    let port = st.port.load(Ordering::Relaxed);
    if let Some(r) = site(&path, port) {
        return r;
    }
    // The `/files` directory served by hand: ignoring Range, or without any
    // Content-Length (chunked, HEAD without length).
    for (prefix, chunked) in [("/static-norange/", false), ("/static-nolength/", true)] {
        if let Some(rel) = path.strip_prefix(prefix) {
            let root = st.root.lock().clone().unwrap();
            let file = root.join(rel);
            let Ok(data) = tokio::fs::read(&file).await else {
                return StatusCode::NOT_FOUND.into_response();
            };
            let data = Bytes::from(data);
            if !chunked {
                return full(&method, &data);
            }
            let chunks: Vec<Result<Bytes, std::io::Error>> = if method == Method::HEAD {
                Vec::new()
            } else {
                (0..data.len())
                    .step_by(50_000)
                    .map(|i| Ok(data.slice(i..(i + 50_000).min(data.len()))))
                    .collect()
            };
            return Body::from_stream(futures::stream::iter(chunks)).into_response();
        }
    }
    let blob = blob_bytes();
    let parts: Vec<&str> = path.trim_start_matches('/').splitn(3, '/').collect();
    match parts.as_slice() {
        ["data", "plain", _] => ranged(&method, &h, &blob, &[], None, false),
        ["data", "norange", _] => full(&method, &blob),
        ["data", "nolength", _] => {
            if method == Method::HEAD {
                // An empty body of unknown size: hyper would add
                // `Content-Length: 0` to `Body::empty()`.
                let none: Vec<Result<Bytes, std::io::Error>> = Vec::new();
                return Body::from_stream(futures::stream::iter(none)).into_response();
            }
            let chunks: Vec<Result<Bytes, std::io::Error>> = (0..blob.len())
                .step_by(64 << 10)
                .map(|i| Ok(blob.slice(i..(i + (64 << 10)).min(blob.len()))))
                .collect();
            Body::from_stream(futures::stream::iter(chunks)).into_response()
        }
        ["data", "nohead", _] => {
            if method == Method::HEAD {
                return StatusCode::METHOD_NOT_ALLOWED.into_response();
            }
            ranged(&method, &h, &blob, &[], None, false)
        }
        ["data", "acceptnone", _] => {
            let mut r = full(&method, &blob);
            r.headers_mut()
                .insert(header::ACCEPT_RANGES, "none".parse().unwrap());
            r
        }
        ["data", "gzip", _] => {
            let mut r = full(&method, &blob);
            r.headers_mut()
                .insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
            r
        }
        // A stored content coding served with Range support (S3 objects
        // uploaded with `Content-Encoding: gzip`, nginx `gzip_static`).
        ["data", "gzip-ranged", _] => ranged(
            &method,
            &h,
            &blob,
            &[(header::CONTENT_ENCODING, "gzip".to_owned())],
            None,
            false,
        ),
        ["data", "capped", _] => ranged(&method, &h, &blob, &[], Some(100_000), false),
        ["data", "unknowntotal", _] => ranged(&method, &h, &blob, &[], None, true),
        ["data", "redirect", name] => (
            StatusCode::FOUND,
            [(header::LOCATION, format!("/data/plain/{name}"))],
        )
            .into_response(),
        ["data", kind @ ("etag" | "weak"), _] => {
            let v = st.version.load(Ordering::SeqCst);
            let data = versioned(v);
            let etag = if *kind == "etag" {
                format!("\"v{v}\"")
            } else {
                format!("W/\"v{v}\"")
            };
            if let Some(m) = h.get(header::IF_MATCH)
                && m.to_str().unwrap() != etag
            {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
            ranged(&method, &h, &data, &[(header::ETAG, etag)], None, false)
        }
        ["data", "flaky", _] => {
            if st.counter.fetch_add(1, Ordering::SeqCst) % 2 == 0 {
                StatusCode::SERVICE_UNAVAILABLE.into_response()
            } else {
                ranged(&method, &h, &blob, &[], None, false)
            }
        }
        ["data", "status", code] => StatusCode::from_u16(code.parse().unwrap())
            .unwrap()
            .into_response(),
        // Uploads moved elsewhere (a 307 keeps the method and the body).
        ["upload-moved", name] => (
            StatusCode::TEMPORARY_REDIRECT,
            [(header::LOCATION, format!("/upload/{name}"))],
        )
            .into_response(),
        ["upload" | "upload-slow", ..] => {
            if aborted {
                // The client hung up mid-body: nothing is stored.
                return StatusCode::BAD_REQUEST.into_response();
            }
            let mut up = st.uploads.lock();
            match method {
                Method::PUT | Method::POST => {
                    if h.get(header::IF_NONE_MATCH).is_some_and(|v| v == "*")
                        && up.contains_key(&path)
                    {
                        return StatusCode::PRECONDITION_FAILED.into_response();
                    }
                    let created = !up.contains_key(&path);
                    up.insert(path.clone(), (method.clone(), body));
                    if created {
                        StatusCode::CREATED.into_response()
                    } else {
                        StatusCode::NO_CONTENT.into_response()
                    }
                }
                Method::GET | Method::HEAD => match up.get(&path) {
                    Some((_, b)) => ranged(&method, &h, b, &[], None, false),
                    None => StatusCode::NOT_FOUND.into_response(),
                },
                _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
            }
        }
        _ => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

pub async fn start() -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("blob.bin"), blob()).unwrap();
    std::fs::write(dir.path().join("empty.bin"), b"").unwrap();
    std::fs::write(dir.path().join("hello.txt"), b"hello world").unwrap();
    std::fs::create_dir(dir.path().join("dir")).unwrap();
    std::fs::write(dir.path().join("dir/inner.txt"), b"inner").unwrap();
    let state = Arc::new(Shared::default());
    *state.root.lock() = Some(dir.path().to_owned());
    let app = Router::new()
        .nest_service("/files", ServeDir::new(dir.path()))
        .fallback(handler)
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    state.port.store(u64::from(addr.port()), Ordering::Relaxed);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    TestServer { addr, dir, state }
}
