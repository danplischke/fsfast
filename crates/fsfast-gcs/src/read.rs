//! Reads: generation-pinned ranged GETs, parallel ranged GETs for large
//! reads, `cat_file`/`cat_ranges`/`get_file` without a metadata request
//! first, and CRC32C verification of whole-object downloads.
//!
//! * A read handle opens with the object's metadata and pins every GET to
//!   the generation it saw (`generation=N`), so bytes always come from one
//!   version. On a versioned bucket the pinned generation stays readable
//!   after an overwrite; otherwise the read fails with
//!   `PreconditionFailed` instead of mixing versions.
//! * `cat_file` and `get_file` start with one ranged GET of the first
//!   `request_size` bytes: small objects are done in that request, larger
//!   ones are fetched in parallel parts pinned to the generation of the
//!   first response (`X-Goog-Generation`).
//! * `cat_ranges` fetches the coalesced ranges directly (no metadata
//!   request); if the responses come from different generations (a
//!   concurrent overwrite), they are fetched again pinned to the newest.
//! * Whole-object downloads are checked against the CRC32C GCS reports in
//!   `X-Goog-Hash` (hardware CRC32C; parts of parallel downloads are
//!   combined, never re-read). Objects served with decompressive
//!   transcoding are not checked (the hash covers the stored bytes).

use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use fsfast_core::{ByteRange, Detail, Error, ErrorKind, FileInfo, IoHints, ReadHandle, ReadOptions, Result};
use fsfast_engine::budget::MemoryBudget;
use fsfast_engine::parallel::{read_parallel, read_parallel_into};
use fsfast_http_transport::{Method, RangeBody, Response};
use futures::{StreamExt, stream};

use crate::GCSFileSystem;
use crate::client::{Client, Query};
use crate::path::{check_object_name, split_path};

/// The response to one ranged GET.
#[derive(Debug)]
pub(crate) struct Fetched {
    pub body: RangeBody,
    /// `X-Goog-Generation`.
    pub generation: Option<String>,
    /// CRC32C of the whole stored object (`X-Goog-Hash`).
    pub crc32c: Option<u32>,
    /// Whether the bytes are the stored bytes (no transcoding), so the
    /// hash applies.
    pub hashable: bool,
}

/// Parse the CRC32C out of `X-Goog-Hash` values (`crc32c=<b64>,md5=<b64>`).
pub fn goog_hash_crc32c(resp_headers: &fsfast_http_transport::header::HeaderMap) -> Option<u32> {
    for v in resp_headers.get_all("x-goog-hash") {
        let Ok(s) = v.to_str() else { continue };
        for part in s.split(',') {
            if let Some(b64) = part.trim().strip_prefix("crc32c=") {
                let raw = base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok()?;
                let arr: [u8; 4] = raw.try_into().ok()?;
                return Some(u32::from_be_bytes(arr));
            }
        }
    }
    None
}

/// The base64 CRC32C GCS uses in object resources and headers.
pub fn crc32c_b64(crc: u32) -> String {
    base64::engine::general_purpose::STANDARD.encode(crc.to_be_bytes())
}

fn is_hashable(resp: &Response) -> bool {
    let stored_identity = resp
        .header_str("x-goog-stored-content-encoding")
        .is_none_or(|e| e.eq_ignore_ascii_case("identity"));
    let no_coding = resp
        .header_str("content-encoding")
        .is_none_or(|e| e.eq_ignore_ascii_case("identity"));
    stored_identity && no_coding
}

/// How a 404 on a generation-pinned GET is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinKind {
    /// No generation.
    None,
    /// A generation the caller asked for: a 404 is `NotFound`.
    Requested,
    /// The generation observed when reading started: a 404 means the
    /// object changed underneath (`PreconditionFailed`).
    Observed,
}

/// One ranged GET of `bucket/key` (gcsfs's media URL).
pub(crate) async fn get_range(
    client: &Client,
    bucket: &str,
    key: &str,
    range: ByteRange,
    generation: Option<&str>,
    pin: PinKind,
    path: &str,
) -> Result<Fetched> {
    let q = Query::new().with("alt", "media").with_opt("generation", generation);
    let req = client
        .request(Method::GET, &client.download_url(bucket, key), &q)?
        .range(range)
        .path(path.to_owned());
    let res = client
        .execute(req, |resp| async move {
            let generation = resp.header_str("x-goog-generation").map(str::to_owned);
            let crc32c = goog_hash_crc32c(resp.headers());
            let hashable = is_hashable(&resp);
            let body = resp.range_bytes(range).await?;
            Ok(Fetched {
                body,
                generation,
                crc32c,
                hashable,
            })
        })
        .await;
    match res {
        Err(e) if e.kind() == ErrorKind::NotFound && pin == PinKind::Observed => Err(Error::new(
            ErrorKind::PreconditionFailed,
            format!(
                "generation {} of the object no longer exists: it was replaced or deleted while \
                 being read",
                generation.unwrap_or("?")
            ),
        )
        .with_path(path)
        .with_detail(Detail::Http(404))
        .with_retryable(false)),
        other => other,
    }
}

/// A single-GET reader (the engine's parallel reader splits large reads
/// into calls of this one).
#[derive(Debug)]
pub(crate) struct RangeReader {
    pub fs: GCSFileSystem,
    pub bucket: String,
    pub key: String,
    pub path: String,
    pub info: FileInfo,
    pub generation: Option<String>,
    pub pin: PinKind,
    pub hints: IoHints,
}

#[async_trait]
impl ReadHandle for RangeReader {
    fn info(&self) -> &FileInfo {
        &self.info
    }

    fn io_hints(&self) -> IoHints {
        self.hints
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        let size = self.info.size;
        let end = offset.saturating_add(len as u64).min(size);
        if offset >= end {
            return Ok(Bytes::new());
        }
        let mut pos = offset;
        let mut parts: Vec<Bytes> = Vec::new();
        // A server may answer with fewer bytes than asked; ask for the rest
        // (bounded, never spinning on a broken server).
        for _ in 0..8 {
            let f = get_range(
                &self.fs.inner.client,
                &self.bucket,
                &self.key,
                ByteRange::Bounded { start: pos, end },
                self.generation.as_deref(),
                self.pin,
                &self.path,
            )
            .await?;
            let got = f.body.data;
            if got.is_empty() {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    format!("object ended at {pos} bytes, but it had {size} bytes when it was opened"),
                )
                .with_path(&self.path));
            }
            pos += got.len() as u64;
            if pos >= end && parts.is_empty() {
                return Ok(got);
            }
            parts.push(got);
            if pos >= end {
                return Ok(concat(&parts, (end - offset) as usize));
            }
        }
        Err(Error::protocol("server keeps returning short ranges").with_path(&self.path))
    }
}

fn concat(parts: &[Bytes], len: usize) -> Bytes {
    let mut buf = Vec::with_capacity(len);
    for p in parts {
        buf.extend_from_slice(p);
    }
    Bytes::from(buf)
}

/// An open GCS object for reading.
///
/// `read_at` calls up to 2 × `request_size` are one ranged GET; larger ones
/// become concurrent `request_size` GETs assembled in one buffer
/// (`fsfast_engine::read_parallel`) within the global memory budget. All
/// GETs are pinned to the generation observed at open time (unless pinning
/// was turned off).
#[derive(Debug, Clone)]
pub struct GcsReadHandle {
    inner: Arc<RangeReader>,
    budget: MemoryBudget,
}

impl GcsReadHandle {
    /// The generation reads are pinned to (if pinned).
    pub fn generation(&self) -> Option<&str> {
        self.inner.generation.as_deref()
    }

    /// Whether reads are pinned to a generation.
    pub fn is_pinned(&self) -> bool {
        self.inner.generation.is_some()
    }
}

#[async_trait]
impl ReadHandle for GcsReadHandle {
    fn info(&self) -> &FileInfo {
        &self.inner.info
    }

    fn io_hints(&self) -> IoHints {
        self.inner.hints
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        let hints = self.inner.hints;
        let part = hints.request_size.max(1);
        let size = self.inner.info.size;
        let end = offset.saturating_add(len as u64).min(size);
        if offset >= end {
            return Ok(Bytes::new());
        }
        if (end - offset) as usize <= part.saturating_mul(2) {
            return self.inner.read_at(offset, len).await;
        }
        let dyn_inner: Arc<dyn ReadHandle> = self.inner.clone();
        read_parallel(&dyn_inner, offset..end, part, hints.max_concurrency, Some(&self.budget)).await
    }

    async fn read_ranges(&self, ranges: &[Range<u64>]) -> Result<Vec<Bytes>> {
        fsfast_core::read_ranges_coalesced(self, ranges).await
    }
}

impl GCSFileSystem {
    pub(crate) async fn open_read_impl(&self, path: &str, opts: &ReadOptions) -> Result<GcsReadHandle> {
        let sp = split_path(path, self.inner.opts.version_aware);
        if sp.key.is_empty() {
            return Err(Error::is_a_directory(sp.bucket.clone()).with_detail(Detail::Code(
                "Attempt to open a bucket".into(),
            )));
        }
        if !opts.extra.is_empty() {
            let keys: Vec<&str> = opts.extra.keys().map(String::as_str).collect();
            return Err(Error::invalid_input(format!(
                "gcs: unsupported open() option(s) for reading: {}",
                keys.join(", ")
            )));
        }
        let requested = coalesce_generation(opts.version.as_deref(), sp.generation.as_deref())?;
        let info = self.get_object(&sp.bucket, &sp.key, requested.as_deref()).await?;
        let (generation, pin) = match requested {
            Some(g) => (Some(g), PinKind::Requested),
            None if opts.pin_version => match &info.version {
                Some(g) => (Some(g.clone()), PinKind::Observed),
                None => (None, PinKind::None),
            },
            None => (None, PinKind::None),
        };
        let mut hints = self.inner.hints;
        if let Some(b) = opts.block_size.filter(|b| *b > 0) {
            hints.request_size = b;
        }
        Ok(GcsReadHandle {
            inner: Arc::new(RangeReader {
                fs: self.clone(),
                bucket: sp.bucket.clone(),
                key: sp.key.clone(),
                path: info.name.clone(),
                info,
                generation,
                pin,
                hints,
            }),
            budget: self.inner.budget.clone(),
        })
    }

    /// Fetch `[start, end)` (`end` `None`: to the end of the object): one
    /// GET of up to `request_size` bytes, then the rest concurrently, pinned
    /// to the first response's generation. Verifies the CRC32C when the
    /// whole object was read.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_window(
        &self,
        bucket: &str,
        key: &str,
        generation: Option<&str>,
        start: u64,
        end: Option<u64>,
        path: &str,
    ) -> Result<Bytes> {
        let client = &self.inner.client;
        let part = self.inner.hints.request_size.max(1) as u64;
        let first_end = start.saturating_add(part).min(end.unwrap_or(u64::MAX));
        if first_end <= start {
            return Ok(Bytes::new());
        }
        let first_pin = if generation.is_some() {
            PinKind::Requested
        } else {
            PinKind::None
        };
        let first = get_range(
            client,
            bucket,
            key,
            ByteRange::Bounded {
                start,
                end: first_end,
            },
            generation,
            first_pin,
            path,
        )
        .await?;
        let crc = first.crc32c.filter(|_| first.hashable && self.inner.opts.verify_crc32c);
        let data = first.body.data;
        if !first.body.ranged {
            // The server ignored the range and sent the whole object, of
            // which only the window's first part was kept: fetch the window.
            if (data.len() as u64) < first_end - start {
                return Ok(data);
            }
            let window = match end {
                Some(e) => ByteRange::Bounded { start, end: e },
                None => ByteRange::From(start),
            };
            return Ok(get_range(client, bucket, key, window, generation, first_pin, path)
                .await?
                .body
                .data);
        }
        let Some(total) = first.body.total else {
            return Err(Error::protocol("ranged response without the object size").with_path(path));
        };
        let want_end = end.unwrap_or(total).min(total);
        let whole = start == 0 && want_end == total;
        if start + data.len() as u64 >= want_end {
            if whole {
                verify_crc(crc, &data, path)?;
            }
            return Ok(data);
        }
        let (pin_gen, pin) = match (generation, &first.generation) {
            (Some(g), _) => (Some(g.to_owned()), PinKind::Requested),
            (None, Some(g)) => (Some(g.clone()), PinKind::Observed),
            (None, None) => (None, PinKind::None),
        };
        let reader: Arc<dyn ReadHandle> = Arc::new(RangeReader {
            fs: self.clone(),
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            path: path.to_owned(),
            info: FileInfo::file(path, total),
            generation: pin_gen,
            pin,
            hints: self.inner.hints,
        });
        let len = usize::try_from(want_end - start)
            .map_err(|_| Error::new(ErrorKind::Io, "object too large for memory").with_path(path))?;
        let mut buf = Vec::new();
        buf.try_reserve_exact(len)
            .map_err(|_| Error::new(ErrorKind::Io, format!("cannot allocate {len} bytes")).with_path(path))?;
        buf.extend_from_slice(&data);
        buf.resize(len, 0);
        let got = read_parallel_into(
            &reader,
            start + data.len() as u64,
            &mut buf[data.len()..],
            part as usize,
            self.inner.hints.max_concurrency,
            Some(&self.inner.budget),
        )
        .await?;
        buf.truncate(data.len() + got);
        if whole {
            verify_crc(crc, &buf, path)?;
        }
        Ok(Bytes::from(buf))
    }

    pub(crate) async fn cat_file_impl(&self, path: &str, range: ByteRange) -> Result<Bytes> {
        let sp = split_path(path, self.inner.opts.version_aware);
        if sp.key.is_empty() {
            return Err(Error::is_a_directory(sp.bucket.clone()));
        }
        let name = sp.full();
        check_object_name(&sp.key, &name)?;
        if range.is_empty() {
            return Ok(Bytes::new());
        }
        let generation = sp.generation.as_deref();
        match range {
            ByteRange::Full => self.fetch_window(&sp.bucket, &sp.key, generation, 0, None, &name).await,
            ByteRange::From(s) => self.fetch_window(&sp.bucket, &sp.key, generation, s, None, &name).await,
            ByteRange::Bounded { start, end } => {
                self.fetch_window(&sp.bucket, &sp.key, generation, start, Some(end), &name)
                    .await
            }
            ByteRange::Suffix(_) => {
                let pin = if generation.is_some() {
                    PinKind::Requested
                } else {
                    PinKind::None
                };
                Ok(get_range(&self.inner.client, &sp.bucket, &sp.key, range, generation, pin, &name)
                    .await?
                    .body
                    .data)
            }
        }
    }

    /// `cat_ranges` for one object without a metadata request: coalesced
    /// ranged GETs in parallel, re-fetched pinned to one generation if a
    /// concurrent overwrite mixed versions.
    pub(crate) async fn cat_ranges_impl(&self, path: &str, ranges: &[Range<u64>]) -> Result<Vec<Bytes>> {
        let sp = split_path(path, self.inner.opts.version_aware);
        if sp.key.is_empty() {
            return Err(Error::is_a_directory(sp.bucket.clone()));
        }
        let name = sp.full();
        check_object_name(&sp.key, &name)?;
        if ranges.is_empty() {
            return Ok(Vec::new());
        }
        let hints = self.inner.hints;
        let groups = fsfast_core::coalesce_ranges(ranges, hints.coalesce_gap, hints.max_coalesced.max(1));
        let fetch_all = |generation: Option<String>, pin: PinKind| {
            let groups = &groups;
            let sp = &sp;
            let name = &name;
            async move {
                let futs: Vec<_> = groups.iter().map(|g| {
                    let generation = generation.clone();
                    async move {
                        if g.range.end <= g.range.start {
                            return Ok::<_, Error>((Bytes::new(), None));
                        }
                        let f = get_range(
                            &self.inner.client,
                            &sp.bucket,
                            &sp.key,
                            ByteRange::Bounded {
                                start: g.range.start,
                                end: g.range.end,
                            },
                            generation.as_deref(),
                            pin,
                            name,
                        )
                        .await?;
                        Ok((f.body.data, f.generation))
                    }
                }).collect();
                stream::iter(futs)
                    .buffered(hints.max_concurrency.max(1))
                    .collect::<Vec<_>>()
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>>>()
            }
        };
        let requested = sp.generation.clone();
        let first_pin = if requested.is_some() {
            PinKind::Requested
        } else {
            PinKind::None
        };
        let mut fetched = fetch_all(requested.clone(), first_pin).await?;
        if requested.is_none() {
            let gens: BTreeSet<&str> = fetched.iter().filter_map(|(_, g)| g.as_deref()).collect();
            if gens.len() > 1 {
                // Mixed versions: read everything again from the newest.
                let newest = gens
                    .iter()
                    .max_by_key(|g| g.parse::<u128>().unwrap_or(0))
                    .map(|g| (*g).to_owned());
                tracing::debug!(path = %name, "object changed during cat_ranges; re-reading pinned");
                fetched = fetch_all(newest, PinKind::Observed).await?;
            }
        }
        let mut out = vec![Bytes::new(); ranges.len()];
        for (g, (data, _)) in groups.iter().zip(fetched) {
            for &i in &g.members {
                let r = &ranges[i];
                if r.end <= r.start || r.start < g.range.start {
                    continue;
                }
                let s = ((r.start - g.range.start) as usize).min(data.len());
                let e = ((r.end - g.range.start) as usize).min(data.len());
                if s < e {
                    out[i] = data.slice(s..e);
                }
            }
        }
        Ok(out)
    }

    pub(crate) async fn get_file_impl(&self, remote: &str, local: &Path) -> Result<()> {
        if tokio::fs::metadata(local).await.is_ok_and(|m| m.is_dir()) {
            // gcsfs: downloading onto an existing directory does nothing.
            return Ok(());
        }
        let sp = split_path(remote, self.inner.opts.version_aware);
        if sp.key.is_empty() {
            return Err(Error::is_a_directory(sp.bucket.clone()));
        }
        let name = sp.full();
        check_object_name(&sp.key, &name)?;
        let client = &self.inner.client;
        let part = self.inner.hints.request_size.max(1) as u64;
        let first_pin = if sp.generation.is_some() {
            PinKind::Requested
        } else {
            PinKind::None
        };
        let first = get_range(
            client,
            &sp.bucket,
            &sp.key,
            ByteRange::Bounded { start: 0, end: part },
            sp.generation.as_deref(),
            first_pin,
            &name,
        )
        .await?;
        let first = if !first.body.ranged && first.body.data.len() as u64 >= part {
            // The server ignores ranges: fetch the object whole.
            get_range(client, &sp.bucket, &sp.key, ByteRange::Full, sp.generation.as_deref(), first_pin, &name)
                .await?
        } else {
            first
        };
        if let Some(dir) = local.parent().filter(|d| !d.as_os_str().is_empty()) {
            tokio::fs::create_dir_all(dir).await?;
        }
        let res = async {
            let total = match (first.body.ranged, first.body.total) {
                (true, Some(t)) => t,
                _ => first.body.data.len() as u64,
            };
            let expected_crc = first.crc32c.filter(|_| first.hashable && self.inner.opts.verify_crc32c);
            let file = Arc::new(tokio::fs::File::create(local).await?.into_std().await);
            let first_data = first.body.data.clone();
            let mut crc = crc32c::crc32c(&first_data);
            {
                let f = file.clone();
                blocking(move || {
                    f.set_len(total)?;
                    write_all_at(&f, 0, &first_data)
                })
                .await?;
            }
            let done = first.body.data.len() as u64;
            if done < total {
                let (generation, pin) = match (&sp.generation, &first.generation) {
                    (Some(g), _) => (Some(g.clone()), PinKind::Requested),
                    (None, Some(g)) => (Some(g.clone()), PinKind::Observed),
                    (None, None) => (None, PinKind::None),
                };
                let reader = RangeReader {
                    fs: self.clone(),
                    bucket: sp.bucket.clone(),
                    key: sp.key.clone(),
                    path: name.clone(),
                    info: FileInfo::file(name.clone(), total),
                    generation,
                    pin,
                    hints: self.inner.hints,
                };
                let reader = &reader;
                let budget = &self.inner.budget;
                // Parts are fetched concurrently and written at their
                // offsets as they arrive (positional writes on a blocking
                // thread); each part's CRC32C is computed there too and the
                // results are combined in order afterwards.
                let futs: Vec<_> = fsfast_core::split_range(done..total, part)
                    .into_iter()
                    .map(|r| {
                        let f = file.clone();
                        async move {
                            let _guard = budget.acquire((r.end - r.start) as usize).await;
                            let data = reader.read_at(r.start, (r.end - r.start) as usize).await?;
                            let n = data.len();
                            let part_crc = tokio::task::spawn_blocking(move || {
                                write_all_at(&f, r.start, &data).map(|()| crc32c::crc32c(&data))
                            })
                            .await
                            .map_err(|e| Error::new(ErrorKind::Other, format!("file task failed: {e}")))??;
                            Ok::<_, Error>((r.start, part_crc, n))
                        }
                    })
                    .collect();
                let mut parts: Vec<(u64, u32, usize)> = stream::iter(futs)
                    .buffer_unordered(self.inner.hints.max_concurrency.max(1))
                    .collect::<Vec<_>>()
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>>>()?;
                parts.sort_unstable_by_key(|p| p.0);
                for (_, c, n) in parts {
                    crc = crc32c::crc32c_combine(crc, c, n);
                }
            }
            if let Some(want) = expected_crc
                && want != crc
            {
                return Err(checksum_error(&name, want, crc));
            }
            Ok::<_, Error>(())
        }
        .await;
        if res.is_err() {
            let _ = tokio::fs::remove_file(local).await;
        }
        res
    }
}

use std::collections::BTreeSet;

/// gcsfs `_coalesce_generation`: one generation from the argument and the
/// path, which must agree.
pub(crate) fn coalesce_generation(a: Option<&str>, b: Option<&str>) -> Result<Option<String>> {
    match (a, b) {
        (Some(x), Some(y)) if x != y => Err(Error::invalid_input(format!(
            "Cannot coalesce generations where more than one are defined, {{'{x}', '{y}'}}"
        ))),
        (Some(x), _) | (None, Some(x)) => Ok(Some(x.to_owned())),
        (None, None) => Ok(None),
    }
}

fn checksum_error(path: &str, want: u32, got: u32) -> Error {
    Error::new(
        ErrorKind::Io,
        format!(
            "CRC32C checksum mismatch: GCS reports {}, the downloaded data has {}",
            crc32c_b64(want),
            crc32c_b64(got)
        ),
    )
    .with_path(path)
    .with_detail(Detail::Code("ChecksumError".into()))
}

fn verify_crc(expected: Option<u32>, data: &[u8], path: &str) -> Result<()> {
    if let Some(want) = expected {
        let got = crc32c::crc32c(data);
        if got != want {
            return Err(checksum_error(path, want, got));
        }
    }
    Ok(())
}

/// Run blocking file I/O on tokio's blocking pool.
async fn blocking<F>(f: F) -> Result<()>
where
    F: FnOnce() -> std::io::Result<()> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("file task failed: {e}")))?
        .map_err(Error::from)
}

/// Write all of `data` at `offset` (positional: concurrent writers of one
/// file do not interfere).
fn write_all_at(f: &std::fs::File, offset: u64, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        f.write_all_at(data, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0;
        while done < data.len() {
            let n = f.seek_write(&data[done..], offset + done as u64)?;
            if n == 0 {
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            done += n;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsfast_http_transport::header::{HeaderMap, HeaderValue};

    #[test]
    fn goog_hash() {
        let mut h = HeaderMap::new();
        h.insert("x-goog-hash", HeaderValue::from_static("crc32c=yZRlqg==,md5=XrY7u+Ae7tCTyyK7j1rNww=="));
        assert_eq!(goog_hash_crc32c(&h), Some(crc32c::crc32c(b"hello world")));
        let mut h = HeaderMap::new();
        h.append("x-goog-hash", HeaderValue::from_static("md5=XrY7u+Ae7tCTyyK7j1rNww=="));
        h.append("x-goog-hash", HeaderValue::from_static("crc32c=yZRlqg=="));
        assert_eq!(goog_hash_crc32c(&h), Some(crc32c::crc32c(b"hello world")));
        let mut h = HeaderMap::new();
        h.insert("x-goog-hash", HeaderValue::from_static("crc32c=!!"));
        assert_eq!(goog_hash_crc32c(&h), None);
        assert_eq!(goog_hash_crc32c(&HeaderMap::new()), None);
        assert_eq!(crc32c_b64(crc32c::crc32c(b"hello world")), "yZRlqg==");
        assert_eq!(crc32c_b64(0), "AAAAAA==");
    }

    #[test]
    fn crc_combine_matches_whole() {
        let data: Vec<u8> = (0..100_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let (a, b) = data.split_at(33_333);
        let combined = crc32c::crc32c_combine(crc32c::crc32c(a), crc32c::crc32c(b), b.len());
        assert_eq!(combined, crc32c::crc32c(&data));
        assert!(verify_crc(Some(crc32c::crc32c(&data)), &data, "p").is_ok());
        assert!(verify_crc(Some(1), &data, "p").is_err());
        assert!(verify_crc(None, &data, "p").is_ok());
    }

    #[test]
    fn generations() {
        assert_eq!(coalesce_generation(None, None).unwrap(), None);
        assert_eq!(coalesce_generation(Some("1"), None).unwrap().as_deref(), Some("1"));
        assert_eq!(coalesce_generation(None, Some("2")).unwrap().as_deref(), Some("2"));
        assert_eq!(coalesce_generation(Some("3"), Some("3")).unwrap().as_deref(), Some("3"));
        assert!(coalesce_generation(Some("1"), Some("2")).is_err());
    }
}
