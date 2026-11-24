//! Credentials in URLs (`user:password@`, presigned query signatures) never
//! reach the logs (PLAN §4.7), even at debug level, while errors keep
//! reporting the URL as the caller wrote it (fsspec parity).

mod common;

use std::fmt::Write as _;
use std::sync::Arc;

use fsfast_core::{ByteRange, FileSystem, ReadOptions, Value};
use fsfast_http::HttpFileSystem;
use parking_lot::Mutex;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

/// Records every event's fields as text.
struct Capture(Arc<Mutex<String>>);

struct Fields<'a>(&'a mut String);

impl Visit for Fields<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, " {}={:?}", field.name(), value);
    }
}

impl Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, span: &Attributes<'_>) -> Id {
        let mut s = self.0.lock();
        span.record(&mut Fields(&mut s));
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, values: &Record<'_>) {
        values.record(&mut Fields(&mut self.0.lock()));
    }
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut s = self.0.lock();
        event.record(&mut Fields(&mut s));
        s.push('\n');
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

#[tokio::test]
async fn urls_are_logged_without_credentials() {
    let s = common::start().await;
    let logs = Arc::new(Mutex::new(String::new()));
    // Current-thread runtime: every event of this test is emitted here.
    let _guard = tracing::subscriber::set_default(Capture(logs.clone()));
    let fs = HttpFileSystem::from_options(
        [("max_retries".to_owned(), Value::Int(0))]
            .into_iter()
            .collect(),
    )
    .unwrap();
    let with_secrets = |path: &str| {
        format!(
            "http://user:hunter2@{}{path}?X-Amz-Signature=sig0123",
            s.addr
        )
    };

    // HEAD refused (debug log of the fallback), then a 404.
    let e = fs
        .info(&with_secrets("/data/status/404"))
        .await
        .unwrap_err();
    // The error still names the URL as given, like fsspec's FileNotFoundError.
    assert_eq!(e.path(), Some(with_secrets("/data/status/404").as_str()));
    fs.info(&with_secrets("/data/nohead/b")).await.unwrap();
    // A server that ignores Range (handle fallback), a refused suffix range
    // and a connection failure.
    let h = fs
        .open_read(&with_secrets("/data/norange/b"), &ReadOptions::default())
        .await
        .unwrap();
    h.read_at(10, 10).await.unwrap();
    let debug = format!("{h:?}");
    assert!(
        !debug.contains("hunter2") && !debug.contains("sig0123"),
        "{debug}"
    );
    fs.cat_file(&with_secrets("/files/hello.txt"), ByteRange::Suffix(100))
        .await
        .unwrap();
    let free = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    fs.info(&format!("http://user:hunter2@{free}/x?sig=sig0123"))
        .await
        .unwrap_err();

    let logs = logs.lock().clone();
    assert!(!logs.is_empty(), "the test must capture some events");
    assert!(
        logs.contains(&format!("http://{}/data/status/404", s.addr)),
        "{logs}"
    );
    for secret in ["hunter2", "sig0123"] {
        assert!(!logs.contains(secret), "{secret} logged:\n{logs}");
    }
}
