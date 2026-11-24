//! fsspec's `http`/`https` filesystem (`fsspec.implementations.http`).
//!
//! Paths are full URLs and are used exactly as given (fsspec's
//! `_strip_protocol` returns them unchanged), so `FileInfo::name` is the URL
//! the caller passed.
//!
//! | fsspec | fsfast |
//! |---|---|
//! | `info` | HEAD (`Accept-Encoding: identity`), then GET when HEAD fails or gives no size. The GET asks for `bytes=0-0` so the size comes from `Content-Range` without downloading the body. Keys: `name`, `size` (`None` when unknown), `type` (`"file"`), `mimetype`, `partial` (`False` for `Accept-Ranges: none`), `url` (after redirects), `ETag`, `Content-MD5`, `Digest`, `Last-Modified` |
//! | `ls` | GET the page; links scraped with fsspec's regexes and resolution rules ([`links`]); names of directories end with `/`, sizes are `None`; a page without links whose URL ends with `/` is retried without the slash |
//! | `find` | fsspec's `_walk` over `ls` (sibling pages listed concurrently) |
//! | `exists` | GET `bytes=0-0`: true below 400 (and for 416, an empty file) |
//! | `cat_file` | ranged GET; servers that ignore `Range` (200) still give the right bytes; large reads continue with parallel ranged GETs pinned to the first response's ETag |
//! | `open` (read) | ranged reads pinned with `If-Match` on strong ETags; one shared full download when ranges are unavailable or the size is unknown |
//! | `pipe_file` | PUT (`method="post"` via `WriteOptions::extra`) |
//! | `put_file` | POST by default like fsspec (`method="put"`), streamed from disk with a `Content-Length` |
//! | `get_file` | streamed to disk; large files with parallel ranged GETs |
//! | `open` (write) | extension (fsspec raises `NotImplementedError`), see [`write`](mod@write) |
//! | `mkdir`, `makedirs`, `rmdir` | no-ops, as in fsspec |
//! | `rm_file`, `cp_file`, `mv_file`, `touch` | `Unsupported`, as fsspec raises `NotImplementedError` |
//!
//! Error kinds: 404/410 are `NotFound`, other statuses map precisely (see
//! [`fsfast_http_transport::error`]). `info` follows fsspec in reporting any
//! 4xx as `NotFound` (with the status attached); server errors (5xx, 429)
//! and transport failures keep their own kinds instead of masquerading as a
//! missing file, a deliberate difference from fsspec (which turns *every*
//! failure of `info` into `FileNotFoundError`).
//!
//! Options are fsspec's (`simple_links`, `block_size`, `same_scheme`,
//! `cache_type`, `cache_options`, `client_kwargs`, `encoded`, and the
//! per-request aiohttp keywords such as `headers`, `auth`, `ssl`, `proxy`,
//! `timeout`, `allow_redirects`, `params`, `cookies`), plus fsfast's
//! transport options; see [`HttpFileSystem::from_options`].

#![warn(missing_docs)]

mod handle;
pub mod info;
pub mod links;
pub mod write;

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use fsfast_core::{
    ByteRange, Capabilities, Error, ErrorKind, FileInfo, FileSystem, FindOptions, IoHints,
    OptionReader, Options, ReadHandle, ReadOptions, Result, WriteHandle, WriteOptions, async_trait,
    split_range,
};
use fsfast_engine::reader::CacheMode;
use fsfast_engine::stats::OpKind;
use fsfast_http_transport::header::CONTENT_TYPE;
use fsfast_http_transport::{
    BodyStream, HttpClient, HttpConfig, Method, Request, RequestBody, log_display, redact_url,
};
use futures::{StreamExt, TryStreamExt, stream};
use tokio::io::AsyncWriteExt;

pub use handle::HttpReadHandle;
pub use info::{is_strong_etag, known_size};
pub use write::HttpWriteHandle;

/// fsspec's default block size (`fsspec.utils.DEFAULT_BLOCK_SIZE`).
pub const DEFAULT_BLOCK_SIZE: usize = 5 << 20;

/// Index pages larger than this are only scanned for links up to this size.
pub const MAX_INDEX_PAGE: usize = 256 << 20;

/// Concurrency used for parallel ranged GETs and sibling listings.
const DEFAULT_CONCURRENCY: usize = 8;

/// `AbstractFileSystem`/`AsyncFileSystem` options handled by the Python layer
/// (instance and listing caches, event loop), and fsspec http's deprecated
/// `size_policy`.
const IGNORED_OPTIONS: &[&str] = &[
    "skip_instance_cache",
    "use_listings_cache",
    "listings_expiry_time",
    "max_paths",
    "asynchronous",
    "loop",
    "batch_size",
    "size_policy",
];

/// fsspec's HTTP(S) filesystem. Cloning is cheap (shared client and pool).
#[derive(Debug, Clone)]
pub struct HttpFileSystem {
    inner: Arc<Inner>,
}

/// The name of the fsspec class.
pub type HTTPFileSystem = HttpFileSystem;

#[derive(Debug)]
struct Inner {
    client: HttpClient,
    simple_links: bool,
    same_scheme: bool,
    block_size: usize,
    cache_type: String,
    cache_options: Option<Options>,
    encoded: bool,
    hints: IoHints,
}

/// What the first request of a large read produced.
enum First {
    /// The whole answer (the server ignored the range, or it is complete).
    Done(Bytes),
    /// The first part of a ranged answer.
    Part {
        data: Bytes,
        offset: u64,
        total: Option<u64>,
        etag: Option<String>,
    },
}

impl HttpFileSystem {
    /// A filesystem with fsspec's default options.
    pub fn new() -> Result<Self> {
        Self::from_options(Options::new())
    }

    /// Build from fsspec `storage_options`.
    ///
    /// * fsspec http: `simple_links` (default true), `block_size` (default
    ///   5 MiB; also the request size of ranged reads and the buffering
    ///   threshold of uploads; 0 means "stream" to fsspec's `open`, see
    ///   [`HttpFileSystem::block_size`]), `same_scheme`, `cache_type`
    ///   (validated, default `"bytes"`), `cache_options`, `encoded`
    ///   (URLs are always parsed with WHATWG rules: existing `%XX` escapes are
    ///   kept, unsafe characters encoded, for either value), `client_kwargs`
    ///   (aiohttp `ClientSession` keywords, see
    ///   [`HttpConfig::apply_client_kwargs`]).
    /// * aiohttp request keywords fsspec forwards to every request:
    ///   `headers`, `auth`, `timeout`, `ssl`/`verify_ssl`, `proxy`,
    ///   `proxy_auth`, `allow_redirects`, `max_redirects`, `cookies`,
    ///   `params` ([`HttpConfig::apply_request_kwargs`]).
    /// * fsfast transport tuning: `max_retries`, `connect_timeout`,
    ///   `read_timeout`, `total_timeout`, `limit_per_host`, `http2`,
    ///   `ca_bundle`, `user_agent`, `rotate_dns`
    ///   ([`HttpConfig::apply_fsfast_options`]).
    /// * Accepted and ignored (handled by the Python layer):
    ///   `skip_instance_cache`, `use_listings_cache`,
    ///   `listings_expiry_time`, `max_paths`, `asynchronous`, `loop`,
    ///   `batch_size`, and the deprecated `size_policy`.
    ///
    /// Anything else, including fsspec's `get_client` callable, is an error.
    pub fn from_options(opts: Options) -> Result<Self> {
        let mut r = OptionReader::new("http", opts);
        let simple_links = r.bool("simple_links")?.unwrap_or(true);
        let block_size = r.usize("block_size")?.unwrap_or(DEFAULT_BLOCK_SIZE);
        let same_scheme = r.bool("same_scheme")?.unwrap_or(true);
        let cache_type = r
            .string("cache_type")?
            .unwrap_or_else(|| "bytes".to_owned());
        CacheMode::from_fsspec(&cache_type, Some(block_size).filter(|b| *b > 0), None)?;
        let cache_options = r.map("cache_options")?;
        let encoded = r.bool("encoded")?.unwrap_or(false);
        r.accept_ignored(IGNORED_OPTIONS);
        let cfg = HttpConfig::from_options(&mut r)?;
        r.finish()?;
        let client = HttpClient::new(Self::http_defaults(cfg)?)?;
        let mut fs = Self::with_client(client);
        let inner = Arc::get_mut(&mut fs.inner).expect("freshly built");
        inner.simple_links = simple_links;
        inner.same_scheme = same_scheme;
        inner.block_size = block_size;
        inner.cache_type = cache_type;
        inner.cache_options = cache_options;
        inner.encoded = encoded;
        inner.hints.request_size = if block_size > 0 {
            block_size
        } else {
            DEFAULT_BLOCK_SIZE
        };
        Ok(fs)
    }

    /// Settings every HTTP filesystem client gets on top of `cfg`: ask for
    /// the identity encoding so sizes and byte ranges refer to the stored
    /// bytes (fsspec does this for `info`; fsfast never decompresses).
    pub fn http_defaults(mut cfg: HttpConfig) -> Result<HttpConfig> {
        cfg.set_header_if_absent("Accept-Encoding", "identity")?;
        Ok(cfg)
    }

    /// A filesystem using `client` (fsspec's default options otherwise).
    /// Build the client from [`HttpFileSystem::http_defaults`] to keep
    /// fsspec's size semantics.
    pub fn with_client(client: HttpClient) -> Self {
        let concurrency = client
            .config()
            .max_connections_per_host
            .clamp(1, DEFAULT_CONCURRENCY);
        HttpFileSystem {
            inner: Arc::new(Inner {
                client,
                simple_links: true,
                same_scheme: true,
                block_size: DEFAULT_BLOCK_SIZE,
                cache_type: "bytes".to_owned(),
                cache_options: None,
                encoded: false,
                hints: IoHints {
                    request_size: DEFAULT_BLOCK_SIZE,
                    max_concurrency: concurrency,
                    ..IoHints::default()
                },
            }),
        }
    }

    /// The HTTP client (statistics via `client().stats()`).
    pub fn client(&self) -> &HttpClient {
        &self.inner.client
    }

    /// fsspec `block_size`: 0 asks fsspec's `open` for a streaming file
    /// ([`HttpFileSystem::stream_file`]) instead of a random-access one.
    pub fn block_size(&self) -> usize {
        self.inner.block_size
    }

    /// Default `cache_type` for `open`.
    pub fn cache_type(&self) -> &str {
        &self.inner.cache_type
    }

    /// Default `cache_options` for `open`.
    pub fn cache_options(&self) -> Option<&Options> {
        self.inner.cache_options.as_ref()
    }

    /// fsspec `simple_links`.
    pub fn simple_links(&self) -> bool {
        self.inner.simple_links
    }

    /// fsspec `same_scheme`.
    pub fn same_scheme(&self) -> bool {
        self.inner.same_scheme
    }

    /// fsspec `encoded`.
    pub fn encoded(&self) -> bool {
        self.inner.encoded
    }

    /// fsspec's `_parent`: the URL up to its last `/`, or `""` when that
    /// would leave no more than `scheme:/`.
    pub fn parent(path: &str) -> String {
        let par = match path.rfind('/') {
            Some(i) => &path[..i],
            None => "",
        };
        if par.chars().count() > 7 {
            par.to_owned()
        } else {
            String::new()
        }
    }

    /// fsspec http `isdir`: whether the URL's page lists any links. Missing
    /// pages and invalid URLs are not directories.
    pub async fn isdir(&self, url: &str) -> Result<bool> {
        match self.ls_names(url).await {
            Ok(v) => Ok(!v.is_empty()),
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::InvalidInput) => {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Stream a URL's body (fsspec's `HTTPStreamFile`, used for
    /// `block_size=0` and unknown sizes).
    pub async fn stream_file(&self, url: &str) -> Result<BodyStream> {
        let resp = self.client().send(self.get(url)?).await?;
        Ok(resp.into_stream())
    }

    fn get(&self, url: &str) -> Result<Request> {
        Ok(Request::get(url)?.path(url))
    }

    /// One HEAD or GET (`bytes=0-0`) probe for `info`.
    async fn probe(&self, method: Method, url: &str) -> Result<info::Probe> {
        let mut req = Request::new(method.clone(), url)?
            .path(url)
            .op(OpKind::Info);
        if method == Method::GET {
            req = req.range(ByteRange::Bounded { start: 0, end: 1 });
        }
        self.client()
            .send_with(req, |resp| async move {
                let p = info::probe_response(&resp, url);
                if resp.status().as_u16() != 200 {
                    // A one-byte part: read it so the connection is reused.
                    // A 200 would be the whole file: dropped unread.
                    resp.bytes_truncated(1024).await?;
                }
                Ok(p)
            })
            .await
    }

    async fn info_impl(&self, url: &str) -> Result<FileInfo> {
        let mut probe = info::Probe::default();
        match self.probe(Method::HEAD, url).await {
            Ok(p) if p.size.is_some() => return Ok(info::build_info(url, &p)),
            Ok(p) => probe = p,
            // Could not even connect: a GET would fail the same way.
            Err(e) if e.kind() == ErrorKind::ConnectionFailed && e.http_status().is_none() => {
                return Err(e);
            }
            Err(e) if e.kind() == ErrorKind::InvalidInput && e.http_status().is_none() => {
                return Err(e);
            }
            Err(e) => tracing::debug!(
                error = %log_display(&e),
                url = %log_url(url),
                "HEAD failed, trying GET"
            ),
        }
        match self.probe(Method::GET, url).await {
            Ok(p) => {
                probe.update(p);
                Ok(info::build_info(url, &probe))
            }
            Err(e) => Err(match e.http_status() {
                // fsspec raises FileNotFoundError when the GET fails.
                Some(s) if (400..500).contains(&s) && !matches!(s, 408 | 429) => {
                    e.with_kind(ErrorKind::NotFound)
                }
                _ => e,
            }),
        }
    }

    /// The links of one page, without fsspec's trailing-slash retry.
    async fn scrape(&self, url: &str) -> Result<BTreeSet<String>> {
        let req = self.get(url)?.op(OpKind::List);
        let simple = self.inner.simple_links;
        let same = self.inner.same_scheme;
        self.client()
            .send_with(req, |resp| async move {
                let ctype = resp
                    .headers()
                    .get(CONTENT_TYPE)
                    .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
                let mimetype = ctype.as_deref().map(|c| c.split(';').next().unwrap_or(""));
                if !matches!(mimetype, None | Some("text/html")) {
                    // Not a page: fsspec does not read the body either.
                    return Ok(BTreeSet::new());
                }
                let body = resp.bytes_truncated(MAX_INDEX_PAGE).await?;
                let text = links::decode_page(&body, ctype.as_deref());
                Ok(links::resolve_links(
                    url,
                    links::extract_links(&text, simple),
                    same,
                ))
            })
            .await
    }

    /// fsspec `_ls_real(url, detail=False)`.
    async fn ls_names(&self, url: &str) -> Result<BTreeSet<String>> {
        let out = self.scrape(url).await?;
        if out.is_empty() && url.ends_with('/') {
            return self.scrape(url.trim_end_matches('/')).await;
        }
        Ok(out)
    }

    /// Read `range` with as few round trips as possible, then in parallel.
    async fn fetch(&self, url: &str, range: ByteRange) -> Result<Bytes> {
        if range.is_empty() {
            return Ok(Bytes::new());
        }
        let part = self.inner.hints.request_size.max(1) as u64;
        let (start, want_end) = match range {
            ByteRange::Suffix(_) => return self.fetch_single(url, range).await,
            ByteRange::Full => (0, None),
            ByteRange::From(s) => (s, None),
            ByteRange::Bounded { start, end } => (start, Some(end)),
        };
        let first_end = start.saturating_add(part).min(want_end.unwrap_or(u64::MAX));
        let first = ByteRange::Bounded {
            start,
            end: first_end,
        };
        let got = self
            .client()
            .send_with(self.get(url)?.range(first), |resp| async move {
                if !matches!(resp.status().as_u16(), 206 | 416) {
                    // Range ignored (200 or another success): the whole
                    // representation is coming; cut the requested window out.
                    return Ok(First::Done(resp.range_bytes(range).await?.data));
                }
                let etag = resp.etag().map(str::to_owned);
                let b = resp.range_bytes(first).await?;
                Ok(First::Part {
                    data: b.data,
                    offset: b.offset,
                    total: b.total,
                    etag,
                })
            })
            .await?;
        let (data, offset, total, etag) = match got {
            First::Done(d) => return Ok(d),
            First::Part {
                data,
                offset,
                total,
                etag,
            } => (data, offset, total, etag),
        };
        let got_end = offset + data.len() as u64;
        let Some(total) = total else {
            // Unknown size: a short first part means we reached the end;
            // otherwise fetch the rest with one more request.
            if got_end < first_end || want_end == Some(got_end) {
                return Ok(data);
            }
            let rest = match want_end {
                Some(e) => ByteRange::Bounded {
                    start: got_end,
                    end: e,
                },
                None => ByteRange::From(got_end),
            };
            let rest = self.fetch_single(url, rest).await?;
            return Ok(concat(&[data, rest]));
        };
        let end = want_end.map_or(total, |e| e.min(total));
        if got_end >= end || data.is_empty() {
            return Ok(data);
        }
        // The rest in parallel parts, pinned to the first response's ETag
        // (and checked against its size) so a concurrent overwrite cannot
        // produce a mix of two versions.
        let handle: Arc<dyn ReadHandle> = Arc::new(HttpReadHandle::new(
            self.client().clone(),
            Arc::from(url),
            FileInfo::file(url, total),
            etag.as_deref(),
            true,
            true,
            self.inner.hints,
        ));
        let len = usize::try_from(end - start)
            .map_err(|_| Error::new(ErrorKind::Io, "range does not fit in memory"))?;
        let mut buf = vec![0u8; len];
        buf[..data.len()].copy_from_slice(&data);
        let n = fsfast_engine::parallel::read_parallel_into(
            &handle,
            got_end,
            &mut buf[data.len()..],
            part as usize,
            self.inner.hints.max_concurrency,
            None,
        )
        .await?;
        if n != len - data.len() {
            return Err(
                Error::protocol(format!("expected {} bytes, got {n}", len - data.len()))
                    .with_path(url),
            );
        }
        Ok(Bytes::from(buf))
    }

    /// One ranged GET (continued while a server sends short parts).
    async fn fetch_single(&self, url: &str, range: ByteRange) -> Result<Bytes> {
        let mut parts: Vec<Bytes> = Vec::new();
        let mut next = range;
        loop {
            let body = self
                .client()
                .send_with(self.get(url)?.range(next), |resp| async move {
                    resp.range_bytes(next).await
                })
                .await?;
            if let ByteRange::Suffix(n) = next
                && n > 0
                && body.ranged
                && body.data.is_empty()
                && body.total != Some(0)
            {
                // RFC 9110 §14.1.2: a suffix longer than the representation
                // selects all of it; some servers (tower-http) answer 416.
                tracing::debug!(
                    url = %log_url(url),
                    "suffix range refused; reading the tail of the whole file"
                );
                let body = self
                    .client()
                    .send_with(self.get(url)?, |resp| async move {
                        resp.range_bytes(ByteRange::Suffix(n)).await
                    })
                    .await?;
                parts.push(body.data);
                break;
            }
            let window = fsfast_http_transport::range::requested_window(next, body.total);
            let got_end = body.offset + body.data.len() as u64;
            let more = body.ranged
                && !body.data.is_empty()
                && body.total.is_some()
                && window
                    .as_ref()
                    .is_some_and(|w: &Range<u64>| got_end < w.end);
            parts.push(body.data);
            if !more {
                break;
            }
            let end = window.map_or(u64::MAX, |w| w.end);
            next = ByteRange::Bounded {
                start: got_end,
                end,
            };
        }
        Ok(concat(&parts))
    }

    /// Download into `w` from a response, skipping `skip` bytes.
    async fn stream_to<W: tokio::io::AsyncWrite + Unpin>(
        w: &mut W,
        resp: fsfast_http_transport::Response,
        mut skip: u64,
    ) -> Result<()> {
        let mut s = resp.into_stream();
        while let Some(chunk) = s.next().await {
            let mut c = chunk?;
            if skip > 0 {
                let n = skip.min(c.len() as u64);
                skip -= n;
                c = c.slice(n as usize..);
            }
            if !c.is_empty() {
                w.write_all(&c).await?;
            }
        }
        Ok(())
    }

    async fn download(
        &self,
        remote: &str,
        w: &mut (impl tokio::io::AsyncWrite + Unpin),
    ) -> Result<()> {
        let part = self.inner.hints.request_size.max(1) as u64;
        let first = ByteRange::Bounded {
            start: 0,
            end: part,
        };
        let resp = self.client().send(self.get(remote)?.range(first)).await?;
        match resp.status().as_u16() {
            416 => Ok(()),
            206 => {
                let etag = resp.etag().map(str::to_owned);
                let body = resp.range_bytes(first).await?;
                w.write_all(&body.data).await?;
                let got = body.offset + body.data.len() as u64;
                match body.total {
                    Some(total) if total > got && !body.data.is_empty() => {
                        let handle = HttpReadHandle::new(
                            self.client().clone(),
                            Arc::from(remote),
                            FileInfo::file(remote, total),
                            etag.as_deref(),
                            true,
                            true,
                            self.inner.hints,
                        );
                        let handle = &handle;
                        // In-order writes with up to `max_concurrency` parts
                        // in flight (memory: concurrency x block size).
                        let mut parts =
                            stream::iter(split_range(got..total, part).into_iter().map(
                                |r| async move {
                                    handle.read_at(r.start, (r.end - r.start) as usize).await
                                },
                            ))
                            .buffered(self.inner.hints.max_concurrency.max(1));
                        while let Some(p) = parts.next().await {
                            w.write_all(&p?).await?;
                        }
                        Ok(())
                    }
                    None if got == part => {
                        let rest = ByteRange::From(got);
                        let resp = self.client().send(self.get(remote)?.range(rest)).await?;
                        match resp.status().as_u16() {
                            416 => Ok(()),
                            206 => Self::stream_to(w, resp, 0).await,
                            _ => Self::stream_to(w, resp, got).await,
                        }
                    }
                    _ => Ok(()),
                }
            }
            _ => Self::stream_to(w, resp, 0).await,
        }
    }
}

/// `url` for a log line: without user info, query or fragment, which may
/// carry credentials (paths and errors keep the URL as given).
pub(crate) fn log_url(url: &str) -> String {
    match fsfast_http_transport::Url::parse(url) {
        Ok(u) => redact_url(&u),
        Err(_) => "<invalid URL>".to_owned(),
    }
}

fn concat(parts: &[Bytes]) -> Bytes {
    match parts {
        [] => Bytes::new(),
        [one] => one.clone(),
        _ => {
            let mut buf = BytesMut::with_capacity(parts.iter().map(Bytes::len).sum());
            for p in parts {
                buf.extend_from_slice(p);
            }
            buf.freeze()
        }
    }
}

/// `url` with `.` and `..` path segments resolved and trailing slashes
/// removed: detects listing loops through `./` links.
fn normalize_dots(url: &str) -> String {
    let (prefix, path) = match url.find("://") {
        Some(i) => {
            let after = &url[i + 3..];
            let split = after.find('/').map_or(url.len(), |j| i + 3 + j);
            url.split_at(split)
        }
        None => ("", url),
    };
    let mut segs: Vec<&str> = Vec::new();
    for s in path.split('/') {
        match s {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    format!("{prefix}/{}", segs.join("/"))
}

#[async_trait]
impl FileSystem for HttpFileSystem {
    fn protocols(&self) -> &'static [&'static str] {
        &["http", "https"]
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            pinned_reads: true,
            ..Capabilities::default()
        }
    }

    fn io_hints(&self) -> IoHints {
        self.inner.hints
    }

    async fn info(&self, path: &str) -> Result<FileInfo> {
        self.info_impl(path).await
    }

    /// fsspec http `ls`: scraped links, sorted (fsspec returns them in set
    /// order). A URL that is not an HTML page lists as empty.
    async fn ls(&self, path: &str) -> Result<Vec<FileInfo>> {
        Ok(self
            .ls_names(path)
            .await?
            .into_iter()
            .map(info::link_info)
            .collect())
    }

    /// fsspec's `_find`/`_walk` over `ls`. Pages whose listing is missing
    /// (404) are skipped, as fsspec's walk does; other errors propagate.
    /// Unlike fsspec, entries are keyed by full URL (fsspec's walk keys them
    /// by basename, so same-named entries at different depths of one page
    /// shadow each other in hash order), and a page is not listed again
    /// through `./` links (fsspec would recurse forever).
    async fn find(&self, path: &str, opts: &FindOptions) -> Result<Vec<FileInfo>> {
        let mut out: BTreeMap<String, FileInfo> = BTreeMap::new();
        let root = match self.ls_names(path).await {
            Ok(v) => Some(v),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        if opts.withdirs && !path.is_empty() && root.as_ref().is_some_and(|v| !v.is_empty()) {
            out.insert(path.to_owned(), self.info(path).await?);
        }
        let mut visited: BTreeSet<String> = BTreeSet::new();
        visited.insert(normalize_dots(path));
        let mut level: Vec<(String, BTreeSet<String>)> = match root {
            Some(v) => vec![(path.to_owned(), v)],
            None => Vec::new(),
        };
        let mut depth = 1usize;
        while !level.is_empty() {
            let mut next_dirs: Vec<String> = Vec::new();
            for (dir, listing) in level {
                for u in listing {
                    let entry = info::link_info(u);
                    let pathname = entry.name.trim_end_matches('/').to_owned();
                    if entry.is_dir() && pathname != dir {
                        if visited.insert(normalize_dots(&pathname)) {
                            next_dirs.push(pathname);
                        }
                        if opts.withdirs {
                            out.insert(entry.name.clone(), entry);
                        }
                    } else {
                        out.insert(entry.name.clone(), entry);
                    }
                }
            }
            if opts.maxdepth.is_some_and(|m| depth >= m) {
                break;
            }
            depth += 1;
            level = stream::iter(next_dirs.into_iter().map(|d| async move {
                match self.ls_names(&d).await {
                    Ok(v) => Ok(Some((d, v))),
                    Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(e),
                }
            }))
            .buffered(self.inner.hints.max_concurrency.max(1))
            .try_filter_map(|x| async move { Ok(x) })
            .try_collect()
            .await?;
        }
        if out.is_empty() && self.exists(path).await? {
            let mut i = FileInfo::file(path, 0);
            info::set_unknown_size(&mut i);
            out.insert(path.to_owned(), i);
        }
        Ok(out.into_values().collect())
    }

    /// fsspec http `exists`: a GET (here `bytes=0-0`) with a status below
    /// 400; 416 (an empty file) also exists. Any other 4xx and invalid URLs
    /// are `false`; server errors, throttling and transport failures are
    /// errors (fsspec returns `False` for those too).
    async fn exists(&self, path: &str) -> Result<bool> {
        let req = match Request::get(path) {
            Ok(r) => r
                .path(path)
                .op(OpKind::Info)
                .range(ByteRange::Bounded { start: 0, end: 1 }),
            Err(_) => return Ok(false),
        };
        let res = self
            .client()
            .send_with(req, |resp| async move {
                if resp.status().as_u16() != 200 {
                    resp.bytes_truncated(1024).await?;
                }
                Ok(())
            })
            .await;
        match res {
            Ok(()) => Ok(true),
            Err(e) => match e.http_status() {
                Some(s) if (400..500).contains(&s) && !matches!(s, 408 | 429) => Ok(false),
                _ => Err(e),
            },
        }
    }

    async fn open_read(&self, path: &str, opts: &ReadOptions) -> Result<Arc<dyn ReadHandle>> {
        if opts.version.is_some() {
            return Err(Error::unsupported("reading a specific version over HTTP"));
        }
        let mut hints = self.inner.hints;
        if let Some(b) = opts.block_size.filter(|b| *b > 0) {
            hints.request_size = b;
        }
        let mut info = self.info_impl(path).await?;
        let url: Arc<str> = Arc::from(path);
        match known_size(&info) {
            Some(_) => {
                let ranged = info.extra.get("partial") != Some(&fsfast_core::Value::Bool(false));
                let etag = info.version.clone();
                Ok(Arc::new(HttpReadHandle::new(
                    self.client().clone(),
                    url,
                    info,
                    etag.as_deref(),
                    opts.pin_version,
                    ranged,
                    hints,
                )))
            }
            None => {
                // Unknown size: random access needs the whole content.
                let data = self
                    .client()
                    .send_with(self.get(path)?, |resp| async move { resp.bytes().await })
                    .await?;
                info.extra.remove("size");
                info.size = data.len() as u64;
                Ok(Arc::new(HttpReadHandle::from_bytes(
                    self.client().clone(),
                    url,
                    info,
                    data,
                    hints,
                )))
            }
        }
    }

    async fn open_write(&self, path: &str, opts: &WriteOptions) -> Result<Box<dyn WriteHandle>> {
        let req = write::upload_request(path, opts, Method::PUT)?;
        let threshold = opts.block_size.unwrap_or(self.inner.hints.request_size);
        Ok(Box::new(HttpWriteHandle::new(
            self.client().clone(),
            req,
            threshold,
        )))
    }

    async fn cat_file(&self, path: &str, range: ByteRange) -> Result<Bytes> {
        self.fetch(path, range).await
    }

    /// fsspec http `pipe_file`: one PUT with `Content-Length`.
    async fn pipe_file(&self, path: &str, data: Bytes, opts: &WriteOptions) -> Result<()> {
        let req = write::upload_request(path, opts, Method::PUT)?.body(data);
        let resp = self.client().send(req).await?;
        write::finish_upload(resp).await
    }

    async fn rm_file(&self, path: &str) -> Result<()> {
        Err(Error::unsupported("rm_file on HTTP").with_path(path))
    }

    /// A no-op, as in fsspec (HTTP has no directories to create).
    async fn mkdir(&self, _path: &str, _create_parents: bool) -> Result<()> {
        Ok(())
    }

    /// A no-op, as in fsspec.
    async fn makedirs(&self, _path: &str, _exist_ok: bool) -> Result<()> {
        Ok(())
    }

    /// A no-op, as in fsspec.
    async fn rmdir(&self, _path: &str) -> Result<()> {
        Ok(())
    }

    async fn cp_file(&self, src: &str, _dst: &str) -> Result<()> {
        Err(Error::unsupported("cp_file on HTTP").with_path(src))
    }

    async fn mv_file(&self, src: &str, _dst: &str) -> Result<()> {
        Err(Error::unsupported("mv_file on HTTP").with_path(src))
    }

    /// fsspec http `put_file`: POST by default (`method="put"` in
    /// `WriteOptions::extra`), streamed from disk with a `Content-Length`
    /// (fsspec sends chunked; a length is accepted by more servers).
    async fn put_file(&self, local: &Path, remote: &str, opts: &WriteOptions) -> Result<()> {
        let meta = tokio::fs::metadata(local).await?;
        if meta.is_dir() {
            return Err(Error::is_a_directory(local.to_string_lossy().into_owned()));
        }
        let req = write::upload_request(remote, opts, Method::POST)?.body(RequestBody::File {
            path: local.to_owned(),
            len: meta.len(),
        });
        let resp = self.client().send(req).await?;
        write::finish_upload(resp).await
    }

    /// Download to a local file. The file is created only once the server
    /// answered successfully, and removed again if the transfer fails.
    async fn get_file(&self, remote: &str, local: &Path) -> Result<()> {
        // Probe before creating the file so a 404 leaves nothing behind.
        let mut created = false;
        let res = async {
            let mut sink = LazyFile::new(local, &mut created);
            self.download(remote, &mut sink).await?;
            sink.finish().await
        }
        .await;
        if res.is_err() && created {
            let _ = tokio::fs::remove_file(local).await;
        }
        res
    }

    async fn touch(&self, path: &str, _truncate: bool) -> Result<()> {
        Err(Error::unsupported("touch on HTTP").with_path(path))
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// A local file created on the first write (or at `finish`), buffered in
/// 1 MiB blocks so a stream of small network chunks does not cost one
/// blocking-pool hop each.
struct LazyFile<'a> {
    path: &'a Path,
    created: &'a mut bool,
    file: Option<tokio::io::BufWriter<tokio::fs::File>>,
    pending: Option<
        std::pin::Pin<
            Box<dyn std::future::Future<Output = std::io::Result<tokio::fs::File>> + Send>,
        >,
    >,
}

impl<'a> LazyFile<'a> {
    fn new(path: &'a Path, created: &'a mut bool) -> Self {
        LazyFile {
            path,
            created,
            file: None,
            pending: None,
        }
    }

    async fn finish(mut self) -> Result<()> {
        if self.file.is_none() {
            let f = tokio::fs::File::create(self.path).await?;
            *self.created = true;
            self.file = Some(tokio::io::BufWriter::with_capacity(1 << 20, f));
        }
        if let Some(f) = self.file.as_mut() {
            f.flush().await?;
        }
        Ok(())
    }
}

impl tokio::io::AsyncWrite for LazyFile<'_> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let this = &mut *self;
        if this.file.is_none() {
            if this.pending.is_none() {
                let path = this.path.to_owned();
                this.pending = Some(Box::pin(tokio::fs::File::create(path)));
            }
            let fut = this.pending.as_mut().expect("set above");
            match fut.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    this.pending = None;
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(f)) => {
                    this.pending = None;
                    *this.created = true;
                    this.file = Some(tokio::io::BufWriter::with_capacity(1 << 20, f));
                }
            }
        }
        let f = this.file.as_mut().expect("created above");
        std::pin::Pin::new(f).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.file.as_mut() {
            Some(f) => std::pin::Pin::new(f).poll_flush(cx),
            None => std::task::Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.file.as_mut() {
            Some(f) => std::pin::Pin::new(f).poll_shutdown(cx),
            None => std::task::Poll::Ready(Ok(())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsfast_core::Value;

    fn opts(pairs: &[(&str, Value)]) -> Options {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    #[test]
    fn options_follow_fsspec() {
        let fs = HttpFileSystem::from_options(opts(&[
            ("simple_links", Value::Bool(false)),
            ("block_size", Value::Int(1 << 20)),
            ("same_scheme", Value::Bool(false)),
            ("cache_type", "readahead".into()),
            ("cache_options", Value::Map(Default::default())),
            ("encoded", Value::Bool(true)),
            ("size_policy", "head".into()),
            ("use_listings_cache", Value::Bool(false)),
            ("skip_instance_cache", Value::Bool(true)),
            (
                "client_kwargs",
                Value::Map(
                    [("trust_env".to_owned(), Value::Bool(true))]
                        .into_iter()
                        .collect(),
                ),
            ),
            (
                "headers",
                Value::Map([("X-Token".to_owned(), "t".into())].into_iter().collect()),
            ),
            ("max_retries", Value::Int(1)),
        ]))
        .unwrap();
        assert!(!fs.simple_links());
        assert!(!fs.same_scheme());
        assert!(fs.encoded());
        assert_eq!(fs.block_size(), 1 << 20);
        assert_eq!(fs.io_hints().request_size, 1 << 20);
        assert_eq!(fs.cache_type(), "readahead");
        let h = &fs.client().config().headers;
        assert_eq!(h["x-token"], "t");
        assert_eq!(h["accept-encoding"], "identity");

        for bad in [
            opts(&[("get_client", "x".into())]),
            opts(&[("cache_type", "bogus".into())]),
            opts(&[(
                "client_kwargs",
                Value::Map(
                    [
                        ("connector".to_owned(), Value::Null),
                        ("x".to_owned(), Value::Int(1)),
                    ]
                    .into_iter()
                    .collect(),
                ),
            )]),
            opts(&[("block_size", Value::Int(-1))]),
            opts(&[("typo", Value::Int(1))]),
        ] {
            assert!(
                HttpFileSystem::from_options(bad.clone()).is_err(),
                "{bad:?}"
            );
        }
        // block_size=0 keeps a usable request size.
        let fs = HttpFileSystem::from_options(opts(&[("block_size", Value::Int(0))])).unwrap();
        assert_eq!(fs.block_size(), 0);
        assert_eq!(fs.io_hints().request_size, DEFAULT_BLOCK_SIZE);
        // A user-supplied Accept-Encoding wins.
        let fs = HttpFileSystem::from_options(opts(&[(
            "headers",
            Value::Map(
                [("Accept-Encoding".to_owned(), "gzip".into())]
                    .into_iter()
                    .collect(),
            ),
        )]))
        .unwrap();
        assert_eq!(fs.client().config().headers["accept-encoding"], "gzip");
    }

    #[test]
    fn parent_like_fsspec() {
        assert_eq!(HttpFileSystem::parent("http://h/a/b"), "http://h/a");
        assert_eq!(HttpFileSystem::parent("http://h/a/"), "http://h/a");
        assert_eq!(HttpFileSystem::parent("http://h"), "");
        assert_eq!(HttpFileSystem::parent("https://h"), "");
        assert_eq!(HttpFileSystem::parent("https://h/a"), "https://h");
        assert_eq!(HttpFileSystem::parent("x"), "");
    }

    #[test]
    fn dot_normalization() {
        assert_eq!(normalize_dots("http://h/a/./b/../c/"), "http://h/a/c");
        assert_eq!(normalize_dots("http://h/a/."), "http://h/a");
        assert_eq!(normalize_dots("http://h"), "http://h/");
    }

    #[test]
    fn capabilities() {
        let fs = HttpFileSystem::new().unwrap();
        assert_eq!(fs.protocols(), &["http", "https"]);
        let c = fs.capabilities();
        assert!(c.pinned_reads && !c.hierarchical && !c.append && !c.conditional_create);
    }
}
