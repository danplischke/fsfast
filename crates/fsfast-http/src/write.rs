//! Uploads: `pipe_file`, `put_file` and `open_write`.
//!
//! fsspec http writes with a single request: `pipe_file` PUTs the bytes,
//! `put_file` POSTs (or PUTs, `method="put"`) the file. `open(mode="wb")` is
//! not supported by fsspec; fsfast offers it as an extension with the same
//! single-request semantics: data is buffered (without copying) up to the
//! block size and sent with an exact `Content-Length` on close, which every
//! server accepts. A larger file switches to a streaming request (chunked
//! transfer encoding on HTTP/1.1) so memory stays bounded; servers that
//! require a length (e.g. S3 presigned URLs) then need a larger block size.
//!
//! Mode `xb` (create only) sends `If-None-Match: *` (RFC 9110 §13.1.2); a
//! 412 answer becomes `AlreadyExists`. Servers that ignore the header
//! overwrite, so the mode is not advertised as atomic. Append is unsupported.

use std::fmt;
use std::io;

use bytes::Bytes;
use fsfast_core::{
    Detail, Error, ErrorKind, OptionReader, Result, Value, WriteHandle, WriteMode, WriteOptions,
    async_trait,
};
use fsfast_engine::concurrency::AbortOnDrop;
use fsfast_http_transport::header::{CONTENT_TYPE, HeaderValue, IF_NONE_MATCH, LOCATION};
use fsfast_http_transport::{HttpClient, Method, Request, RequestBody, Response};
use tokio::sync::mpsc;

/// Queue depth between `write` and a streaming upload (chunks, not bytes;
/// gives the request task something to send while the caller produces more).
const STREAM_QUEUE: usize = 4;

/// The request template for an upload, built from [`WriteOptions`].
pub(crate) fn upload_request(url: &str, opts: &WriteOptions, default: Method) -> Result<Request> {
    let mut r = OptionReader::new("http", opts.extra.clone());
    let method = match r.string("method")? {
        None => default,
        Some(m) => match m.to_ascii_lowercase().as_str() {
            "put" => Method::PUT,
            "post" => Method::POST,
            other => {
                return Err(Error::invalid_input(format!(
                    "method has to be either 'post' or 'put', not: {other:?}"
                )));
            }
        },
    };
    let headers = r.value("headers");
    r.finish()?;
    if !opts.metadata.is_empty() {
        return Err(Error::unsupported("user metadata on HTTP uploads"));
    }
    let mut req = Request::new(method, url)?.path(url);
    if let Some(h) = headers {
        let Value::Map(m) = h else {
            return Err(Error::invalid_input("option 'headers' must be a dict"));
        };
        for (k, v) in m {
            let Value::Str(v) = v else {
                return Err(Error::invalid_input(format!(
                    "option 'headers': value of {k:?} must be a string"
                )));
            };
            req = req.try_header(&k, &v)?;
        }
    }
    if let Some(ct) = &opts.content_type {
        let v = HeaderValue::try_from(ct.as_str())
            .map_err(|e| Error::invalid_input(format!("invalid content_type: {e}")))?;
        req = req.header(CONTENT_TYPE, v);
    }
    match opts.mode {
        WriteMode::Overwrite => {}
        WriteMode::CreateNew => {
            // A retry after a lost success would see 412 and report
            // AlreadyExists for a file we created: never retry.
            req = req
                .header(IF_NONE_MATCH, HeaderValue::from_static("*"))
                .status_kind(412, ErrorKind::AlreadyExists)
                .retry_safe(false);
        }
        WriteMode::Append => return Err(Error::unsupported("append mode on HTTP")),
    }
    Ok(req)
}

/// Finish an upload response: drain a small body so the connection can be
/// reused.
///
/// A redirect that reaches this point was not followed (redirects are
/// disabled, or the body was a stream that cannot be sent again), so nothing
/// was stored: an error, not a success (fsspec, which only raises for
/// statuses >= 400, would report success).
pub(crate) async fn finish_upload(resp: Response) -> Result<()> {
    let status = resp.status();
    if status.is_redirection() {
        let location = resp
            .header_str(LOCATION)
            .map_or_else(String::new, |l| format!(" to {l}"));
        let path = resp.path().to_owned();
        let _ = resp.bytes_truncated(64 << 10).await;
        return Err(Error::new(
            ErrorKind::Io,
            format!(
                "the server redirected the upload (HTTP {}){location}; it was not stored \
                 (a streamed body cannot be sent again)",
                status.as_u16()
            ),
        )
        .with_path(path)
        .with_detail(Detail::Http(status.as_u16())));
    }
    let _ = resp.bytes_truncated(64 << 10).await?;
    Ok(())
}

enum State {
    Buffering {
        chunks: Vec<Bytes>,
        len: usize,
    },
    Streaming {
        tx: Option<mpsc::Sender<io::Result<Bytes>>>,
        task: AbortOnDrop<Result<()>>,
    },
    Closed,
    Aborted,
    Failed,
}

/// A write handle that uploads on close (or streams once the data exceeds
/// the block size). Dropping it without `close` sends nothing (or aborts the
/// streaming request), so nothing becomes visible.
pub struct HttpWriteHandle {
    client: HttpClient,
    template: Request,
    threshold: usize,
    state: State,
    written: u64,
    /// Set while a `write` awaits; still set at the next call means that
    /// call's predecessor was cancelled mid-way.
    busy: bool,
}

impl fmt::Debug for HttpWriteHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match &self.state {
            State::Buffering { .. } => "buffering",
            State::Streaming { .. } => "streaming",
            State::Closed => "closed",
            State::Aborted => "aborted",
            State::Failed => "failed",
        };
        f.debug_struct("HttpWriteHandle")
            .field("request", &self.template)
            .field("state", &state)
            .field("written", &self.written)
            .finish()
    }
}

impl HttpWriteHandle {
    pub(crate) fn new(client: HttpClient, template: Request, threshold: usize) -> Self {
        HttpWriteHandle {
            client,
            template,
            threshold,
            state: State::Buffering {
                chunks: Vec::new(),
                len: 0,
            },
            written: 0,
            busy: false,
        }
    }

    /// A previous `write` was cancelled after it may have consumed part of
    /// its data: poison the handle (and abort a streaming upload) instead of
    /// silently continuing with a hole in the stream.
    fn check_cancelled(&mut self) -> Result<()> {
        if self.busy {
            self.busy = false;
            self.state = State::Failed;
            return Err(Error::new(
                ErrorKind::Cancelled,
                "a previous write was cancelled; the upload was aborted",
            )
            .with_path(self.template.url().as_str()));
        }
        Ok(())
    }

    fn closed_error(&self) -> Error {
        let what = match self.state {
            State::Closed => "closed",
            State::Aborted => "aborted",
            _ => "failed",
        };
        Error::invalid_input(format!("write handle is {what}"))
            .with_path(self.template.url().as_str())
    }

    fn start_streaming(&mut self) {
        let (tx, mut rx) = mpsc::channel::<io::Result<Bytes>>(STREAM_QUEUE);
        let body = futures::stream::poll_fn(move |cx| rx.poll_recv(cx));
        let req = self.template.clone().body(RequestBody::stream(body, None));
        let client = self.client.clone();
        let task = AbortOnDrop::spawn(async move {
            let resp = client.send(req).await?;
            finish_upload(resp).await
        });
        self.state = State::Streaming { tx: Some(tx), task };
    }
}

#[async_trait]
impl WriteHandle for HttpWriteHandle {
    async fn write(&mut self, data: Bytes) -> Result<()> {
        self.check_cancelled()?;
        self.busy = true;
        let res = self.write_inner(data).await;
        self.busy = false;
        res
    }

    async fn close(&mut self) -> Result<()> {
        self.check_cancelled()?;
        // The state is `Failed` while closing, so a cancelled close poisons
        // the handle (and drops a streaming upload) by itself.
        self.close_inner().await
    }

    async fn abort(&mut self) -> Result<()> {
        self.busy = false;
        // Dropping the streaming task aborts the request mid-body, so the
        // server never sees a complete upload.
        if !matches!(self.state, State::Closed) {
            self.state = State::Aborted;
        }
        Ok(())
    }

    fn bytes_written(&self) -> u64 {
        self.written
    }
}

impl HttpWriteHandle {
    async fn write_inner(&mut self, data: Bytes) -> Result<()> {
        if data.is_empty() {
            return match self.state {
                State::Buffering { .. } | State::Streaming { .. } => Ok(()),
                _ => Err(self.closed_error()),
            };
        }
        let n = data.len();
        match self.state {
            State::Buffering { .. } => {
                let State::Buffering { chunks, len } = &mut self.state else {
                    unreachable!("matched above");
                };
                chunks.push(data);
                *len += n;
                if *len > self.threshold {
                    // Switch to a streaming request; what was buffered goes
                    // first.
                    let chunks = std::mem::take(chunks);
                    self.start_streaming();
                    for c in chunks {
                        self.send(c).await?;
                    }
                }
            }
            State::Streaming { .. } => self.send(data).await?,
            _ => return Err(self.closed_error()),
        }
        self.written += n as u64;
        Ok(())
    }

    async fn close_inner(&mut self) -> Result<()> {
        match std::mem::replace(&mut self.state, State::Failed) {
            State::Buffering { chunks, .. } => {
                let req = self.template.clone().body(RequestBody::chunks(chunks));
                let res = self.client.send(req).await;
                let res = match res {
                    Ok(resp) => finish_upload(resp).await,
                    Err(e) => Err(e),
                };
                self.state = if res.is_ok() {
                    State::Closed
                } else {
                    State::Failed
                };
                res
            }
            State::Streaming { tx, task } => {
                drop(tx);
                let res = join(task).await;
                self.state = if res.is_ok() {
                    State::Closed
                } else {
                    State::Failed
                };
                res
            }
            State::Closed => {
                self.state = State::Closed;
                Ok(())
            }
            other => {
                self.state = other;
                Err(self.closed_error())
            }
        }
    }

    /// Send one chunk to the streaming request; if the request already
    /// ended (the server answered early or the connection failed), report
    /// its error.
    async fn send(&mut self, data: Bytes) -> Result<()> {
        let State::Streaming { tx, .. } = &mut self.state else {
            return Err(self.closed_error());
        };
        let Some(sender) = tx.as_ref() else {
            return Err(self.closed_error());
        };
        if sender.send(Ok(data)).await.is_ok() {
            return Ok(());
        }
        // The body receiver is gone: the request finished or failed.
        let State::Streaming { task, .. } = std::mem::replace(&mut self.state, State::Failed)
        else {
            unreachable!("state checked above");
        };
        Err(match join(task).await {
            Err(e) => e,
            Ok(()) => Error::protocol("server answered before the upload was complete")
                .with_path(self.template.url().as_str()),
        })
    }
}

async fn join(task: AbortOnDrop<Result<()>>) -> Result<()> {
    match task.await {
        Ok(r) => r,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(_) => Err(Error::new(
            ErrorKind::Cancelled,
            "upload task was cancelled",
        )),
    }
}
