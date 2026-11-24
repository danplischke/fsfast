//! Fault injection with a raw TCP server: responses whose body is cut off
//! mid-transfer, as happens when a connection is reset or a server dies.
//! These failures are transient and must be retried by `send_with` for
//! retry-safe requests, like failures before the response head.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fsfast_core::{ByteRange, ErrorKind};
use fsfast_http_transport::{HttpClient, HttpConfig, Request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const BODY_LEN: usize = 64 << 10;

fn body() -> Vec<u8> {
    (0..BODY_LEN).map(|i| (i % 251) as u8).collect()
}

/// Read one request head (up to the blank line).
async fn read_head(sock: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if sock.read(&mut byte).await.unwrap_or(0) == 0 {
            break;
        }
        buf.push(byte[0]);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// A server answering every request with a 200 (or a 206 for a `Range`
/// request) that announces the full length but, for the first `truncate`
/// connections, sends only half of the body before closing the socket.
async fn truncating_server(truncate: usize) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let counter = conns.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let n = counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let head = read_head(&mut sock).await;
                let d = body();
                let ranged = head.to_ascii_lowercase().contains("range: bytes=0-");
                let status = if ranged {
                    format!(
                        "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-{}/{}\r\n",
                        d.len() - 1,
                        d.len()
                    )
                } else {
                    "HTTP/1.1 200 OK\r\n".to_owned()
                };
                let head = format!(
                    "{status}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    d.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                if n < truncate {
                    let _ = sock.write_all(&d[..d.len() / 2]).await;
                    let _ = sock.flush().await;
                    // Give the client time to read the first half before
                    // the connection disappears.
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    let _ = sock.shutdown().await;
                } else {
                    let _ = sock.write_all(&d).await;
                    let _ = sock.shutdown().await;
                }
            });
        }
    });
    (addr, conns)
}

fn client() -> HttpClient {
    HttpClient::new(HttpConfig {
        retry_base_delay: Duration::from_millis(1),
        retry_max_delay: Duration::from_millis(5),
        ..HttpConfig::default()
    })
    .unwrap()
}

#[tokio::test]
async fn truncated_bodies_are_transient_and_retried() {
    let (addr, conns) = truncating_server(2).await;
    let c = client();
    let url = format!("http://{addr}/f");
    let got = c
        .send_with(Request::get(&url).unwrap(), |resp| async move {
            resp.bytes().await
        })
        .await
        .expect("the body transfer is retried");
    assert_eq!(&got[..], &body()[..]);
    assert_eq!(conns.load(Ordering::SeqCst), 3);
    assert_eq!(c.stats().snapshot().retries, 2);

    // The same for a ranged read.
    let (addr, conns) = truncating_server(1).await;
    let url = format!("http://{addr}/f");
    let r = ByteRange::From(0);
    let got = c
        .send_with(Request::get(&url).unwrap().range(r), |resp| async move {
            resp.range_bytes(r).await
        })
        .await
        .expect("the ranged body transfer is retried");
    assert_eq!(&got.data[..], &body()[..]);
    assert_eq!(conns.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn truncated_body_error_is_a_connection_failure() {
    let (addr, _) = truncating_server(usize::MAX).await;
    let c = HttpClient::new(HttpConfig {
        max_retries: 0,
        ..HttpConfig::default()
    })
    .unwrap();
    let url = format!("http://{addr}/f");
    let resp = c.send(Request::get(&url).unwrap()).await.unwrap();
    let e = resp.bytes().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ConnectionFailed, "{e:?}");
    assert!(e.is_retryable(), "{e:?}");
    assert_eq!(e.path(), Some(format!("http://{addr}/f").as_str()));

    // Non-idempotent requests are still not retried, body or not.
    let c = client();
    let e = c
        .send_with(Request::post(&url).unwrap(), |resp| async move {
            resp.bytes().await
        })
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ConnectionFailed, "{e:?}");
    assert_eq!(c.stats().snapshot().retries, 0);
}

/// A server that reads the request head and then never answers.
async fn silent_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let _ = read_head(&mut sock).await;
                tokio::time::sleep(Duration::from_secs(3600)).await;
                drop(sock);
            });
        }
    });
    addr
}

/// A server that sends the head and a first part of the body, then stalls.
async fn stalling_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let _ = read_head(&mut sock).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nfirst part")
                    .await;
                tokio::time::sleep(Duration::from_secs(3600)).await;
                drop(sock);
            });
        }
    });
    addr
}

/// A server that reads a whole (Content-Length) request body as it
/// arrives and answers with its length.
async fn draining_server() -> SocketAddr {
    throttled_server(None).await
}

/// Like [`draining_server`], optionally reading at most 64 KiB per `pace`
/// with a small, fixed receive buffer (loopback buffers otherwise autotune
/// to tens of MiB and swallow the whole upload at once).
async fn throttled_server(pace: Option<Duration>) -> SocketAddr {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    if pace.is_some() {
        socket.set_recv_buffer_size(64 << 10).unwrap();
    }
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(64).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let head = read_head(&mut sock).await.to_ascii_lowercase();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .map_or(0, |v| v.trim().parse().unwrap());
                let mut got = 0;
                let mut buf = vec![0u8; 64 << 10];
                while got < len {
                    if let Some(p) = pace {
                        tokio::time::sleep(p).await;
                    }
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got += n,
                    }
                }
                let body = format!("got {got}");
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(reply.as_bytes()).await;
            });
        }
    });
    addr
}

fn idle_client(read_timeout: Duration) -> HttpClient {
    HttpClient::new(HttpConfig {
        read_timeout: Some(read_timeout),
        max_retries: 0,
        ..HttpConfig::default()
    })
    .unwrap()
}

/// `read_timeout` bounds *idleness*: an upload that keeps sending data for
/// longer than the timeout must not be cut off (a large `put_file`, or an
/// `open_write` stream fed over minutes).
#[tokio::test]
async fn read_timeout_does_not_cut_off_slow_uploads() {
    let addr = draining_server().await;
    let c = idle_client(Duration::from_millis(400));
    let url = format!("http://{addr}/up");
    for len in [Some(12_000), None] {
        let req = Request::put(&url)
            .unwrap()
            .body(fsfast_http_transport::RequestBody::stream(
                slow_upload(),
                len,
            ));
        let resp = c
            .send(req)
            .await
            .expect("a slow but active upload succeeds");
        let body = resp.bytes().await.unwrap();
        if len.is_some() {
            assert_eq!(&body[..], b"got 12000");
        }
    }

    // The *caller* pausing between chunks (an `open_write` fed by a slow
    // computation) is not the server being idle.
    let paused = futures::stream::unfold(0u32, |i| async move {
        match i {
            0 => Some((
                Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"head")),
                1,
            )),
            1 => {
                tokio::time::sleep(Duration::from_millis(1200)).await;
                Some((Ok(bytes::Bytes::from_static(b"tail")), 2))
            }
            _ => None,
        }
    });
    let req = Request::put(&url)
        .unwrap()
        .body(fsfast_http_transport::RequestBody::stream(paused, Some(8)));
    let resp = c
        .send(req)
        .await
        .expect("a pause of the body producer is not a server timeout");
    assert_eq!(&resp.bytes().await.unwrap()[..], b"got 8");
}

/// A large in-memory body to a server that reads it at ~12 MB/s: the upload
/// outlasts the read timeout but never stalls.
#[tokio::test]
async fn read_timeout_does_not_cut_off_large_uploads_to_slow_readers() {
    let addr = throttled_server(Some(Duration::from_millis(5))).await;
    let c = idle_client(Duration::from_secs(2));
    let len = 40 << 20;
    let started = std::time::Instant::now();
    let resp = c
        .send(
            Request::put(&format!("http://{addr}/up"))
                .unwrap()
                .body(bytes::Bytes::from(vec![3u8; len])),
        )
        .await
        .expect("a large but progressing upload succeeds");
    assert_eq!(resp.bytes().await.unwrap(), format!("got {len}").as_bytes());
    assert!(
        started.elapsed() > Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(c.stats().snapshot().bytes_written, len as u64);
}

/// 12 chunks of 1000 bytes, one every 100 ms: 1.2 s in total, never idle
/// for long.
fn slow_upload() -> impl futures::Stream<Item = std::io::Result<bytes::Bytes>> + Send + 'static {
    futures::stream::unfold(0u32, |i| async move {
        if i == 12 {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        Some((Ok(bytes::Bytes::from(vec![7u8; 1000])), i + 1))
    })
}

#[tokio::test]
async fn read_timeout_detects_silent_and_stalled_servers() {
    let c = idle_client(Duration::from_millis(300));
    // No response head at all.
    let addr = silent_server().await;
    let start = std::time::Instant::now();
    let e = c
        .send(Request::get(&format!("http://{addr}/x")).unwrap())
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Timeout, "{e:?}");
    assert!(e.is_retryable());
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
    // No answer after a completely sent upload body.
    let e = c
        .send(
            Request::put(&format!("http://{addr}/x"))
                .unwrap()
                .body(bytes::Bytes::from(vec![1u8; 100_000])),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Timeout, "{e:?}");

    // The body stalls after its first bytes: collected and streamed.
    let addr = stalling_server().await;
    let resp = c
        .send(Request::get(&format!("http://{addr}/x")).unwrap())
        .await
        .unwrap();
    let e = resp.bytes().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Timeout, "{e:?}");
    let resp = c
        .send(Request::get(&format!("http://{addr}/x")).unwrap())
        .await
        .unwrap();
    let mut s = resp.into_stream();
    use futures::StreamExt;
    let first = s.next().await.unwrap().unwrap();
    assert_eq!(&first[..], b"first part");
    let e = tokio::time::timeout(Duration::from_secs(5), s.next())
        .await
        .expect("the stream must time out by itself")
        .unwrap()
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Timeout, "{e:?}");
}
