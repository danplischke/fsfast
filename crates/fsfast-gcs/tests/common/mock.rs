//! A tiny in-process HTTP server whose replies come from a closure, with a
//! log of every request: stands in for GCS, OAuth token endpoints and the
//! GCE metadata server.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use bytes::Bytes;
use parking_lot::Mutex;

/// One request as the server saw it.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// The decoded value of query parameter `name`.
    pub fn param(&self, name: &str) -> Option<String> {
        self.query.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            (k == name).then(|| {
                percent_encoding::percent_decode_str(&v.replace('+', " "))
                    .decode_utf8_lossy()
                    .into_owned()
            })
        })
    }
}

/// A reply.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    /// Wait this long before answering.
    pub delay: Option<std::time::Duration>,
}

impl Reply {
    pub fn new(status: u16) -> Self {
        Reply {
            status,
            headers: Vec::new(),
            body: Bytes::new(),
            delay: None,
        }
    }

    pub fn json(status: u16, v: serde_json::Value) -> Self {
        Reply::new(status)
            .header("content-type", "application/json")
            .body(v.to_string())
    }

    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.to_owned(), v.to_owned()));
        self
    }

    pub fn delay(mut self, d: std::time::Duration) -> Self {
        self.delay = Some(d);
        self
    }

    pub fn body(mut self, b: impl Into<Bytes>) -> Self {
        self.body = b.into();
        self
    }

    /// The GCS JSON API error shape.
    pub fn gcs_error(status: u16, reason: &str, message: &str) -> Self {
        Reply::json(
            status,
            serde_json::json!({"error": {"code": status, "message": message,
                "errors": [{"domain": "global", "reason": reason, "message": message}]}}),
        )
    }
}

type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

/// A running mock server.
pub struct Mock {
    pub addr: SocketAddr,
    log: Arc<Mutex<Vec<Seen>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Mock {
    pub async fn start(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Mock {
        let handler: Handler = Arc::new(handler);
        let log: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let l2 = log.clone();
        let app = Router::new().fallback(move |req: Request| {
            let handler = handler.clone();
            let log = l2.clone();
            async move {
                let (parts, body) = req.into_parts();
                let body = axum::body::to_bytes(body, 1 << 30)
                    .await
                    .unwrap_or_default();
                let seen = Seen {
                    method: parts.method.to_string(),
                    path: parts.uri.path().to_owned(),
                    query: parts.uri.query().unwrap_or("").to_owned(),
                    headers: parts.headers.clone(),
                    body,
                };
                let reply = handler(&seen);
                log.lock().push(seen);
                if let Some(d) = reply.delay {
                    tokio::time::sleep(d).await;
                }
                let mut resp =
                    Response::builder().status(StatusCode::from_u16(reply.status).unwrap());
                for (k, v) in &reply.headers {
                    resp = resp.header(k.as_str(), v.as_str());
                }
                resp.body(Body::from(reply.body)).unwrap()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Mock { addr, log, task }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn host(&self) -> String {
        self.addr.to_string()
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.log.lock().clone()
    }

    pub fn count(&self, pred: impl Fn(&Seen) -> bool) -> usize {
        self.log.lock().iter().filter(|s| pred(s)).count()
    }
}

/// A local address nothing listens on.
pub async fn closed_port() -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a
}

/// An object resource.
pub fn object(bucket: &str, name: &str, size: usize, generation: u64) -> serde_json::Value {
    serde_json::json!({
        "kind": "storage#object",
        "id": format!("{bucket}/{name}/{generation}"),
        "name": name,
        "bucket": bucket,
        "size": size.to_string(),
        "generation": generation.to_string(),
        "metageneration": "1",
        "contentType": "application/octet-stream",
        "timeCreated": "2026-11-24T19:16:54.877Z",
        "updated": "2026-11-24T19:16:54.877Z",
    })
}
