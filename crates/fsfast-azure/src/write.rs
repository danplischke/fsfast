//! Writes: block blobs (Put Blob for small data; Put Block in parallel via
//! [`fsfast_engine::PartUploader`] + Put Block List for large), create-only
//! writes (`If-None-Match: *`), and appends (Append Block on append blobs;
//! block-list appends on block blobs).
//!
//! * Block IDs are base64 of fixed-length ASCII strings (a random per-upload
//!   prefix and the block number), as the service requires all IDs of a blob
//!   to have the same length. Uncommitted blocks of an aborted upload are
//!   garbage-collected by the service (there is no API to delete them).
//! * adlfs writes `metadata={"is_directory": "false"}` on every blob it
//!   creates; so does fsfast, unless the caller passes its own metadata
//!   (adlfs file objects: `metadata or {"is_directory": "false"}`).
//! * Append to an **append blob**: data is buffered and appended in blocks of
//!   up to 4 MiB with `x-ms-blob-condition-appendpos` (a retried append whose
//!   first attempt succeeded is recognised by the blob's length). Buffered
//!   data is pushed on `flush`, when 4 MiB accumulate, and on `close`; `abort`
//!   discards what was not pushed yet. A missing blob is created as an append
//!   blob (adlfs `create_append_blob`) on the first push.
//! * Append to a **block blob** (adlfs fails here): the new data is staged as
//!   blocks and committed after the existing blocks with `If-Match` on the
//!   ETag seen at open, keeping the blob's metadata and content settings, so
//!   it is atomic and `abort` leaves the blob untouched. A blob uploaded in
//!   one Put Blob has no block list; its content is first re-staged as blocks
//!   (pinned to the ETag), which costs one download of the existing data.

use std::collections::BTreeMap;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine as _;
use bytes::{Bytes, BytesMut};
use fsfast_core::{
    Error, ErrorKind, OptionReader, ReadHandle, ReadOptions, Result, Value, WriteHandle, WriteMode,
    WriteOptions,
};
use fsfast_engine::stats::OpKind;
use fsfast_engine::{PartSink, PartUploader, UploadConfig, UploadResult};
use fsfast_http_transport::Method;
use fsfast_http_transport::header::{
    CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, IF_MATCH, IF_NONE_MATCH,
};
use futures::{StreamExt, stream};

use crate::client::Query;
use crate::info::{BlobProps, BlobType};
use crate::options::MAX_BLOCKS;
use crate::path::split_path;
use crate::xml::escape_into;
use crate::{AzureBlobFileSystem, Shared};

/// Largest Append Block payload fsfast sends (the 4 MiB limit of older API
/// versions and of Azurite; newer service versions allow 100 MiB).
pub const APPEND_CHUNK: usize = 4 << 20;

/// Raw length of fsfast's block IDs (base64: 32 characters).
const BLOCK_ID_RAW: usize = 24;

/// A random 64-bit value (per-process random keys, a counter and the time).
fn random_u64() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut h = RandomState::new().build_hasher();
    h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    h.write_u128(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    h.finish()
}

/// Block IDs of one upload: base64 of `raw_len` ASCII characters, the block
/// number in decimal at the end and the upload's random prefix in hex in
/// front.
#[derive(Debug, Clone)]
pub struct BlockIds {
    prefix: String,
    raw_len: usize,
}

impl BlockIds {
    /// IDs with fsfast's default length.
    pub fn new() -> Self {
        Self::with_raw_len(BLOCK_ID_RAW).expect("default length is valid")
    }

    /// IDs shaped like `existing` (an ID of the blob's committed blocks):
    /// the same decoded length, hence the same encoded length and padding
    /// (all block IDs of a blob must have the same length; the service
    /// checks the decoded value). `None` if `existing` is not base64 or
    /// too short to leave room for a unique prefix and a block number.
    pub fn matching(existing: &str) -> Option<Self> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(existing)
            .ok()?;
        let ids = Self::with_raw_len(raw.len())?;
        (ids.id(1).len() == existing.len()).then_some(ids)
    }

    fn with_raw_len(raw_len: usize) -> Option<Self> {
        if !(12..=48).contains(&raw_len) {
            return None;
        }
        let hex = format!(
            "{:016x}{:016x}{:016x}",
            random_u64(),
            random_u64(),
            random_u64()
        );
        // 6 digits for the block number (up to 50,000 blocks).
        let prefix_len = raw_len - 6;
        Some(BlockIds {
            prefix: hex[..prefix_len.min(hex.len())].to_owned()
                + &"0".repeat(prefix_len.saturating_sub(hex.len())),
            raw_len,
        })
    }

    /// The ID of block `n`.
    pub fn id(&self, n: u32) -> String {
        let raw = format!("{}{:06}", self.prefix, n);
        debug_assert_eq!(raw.len(), self.raw_len);
        base64::engine::general_purpose::STANDARD.encode(raw)
    }
}

impl Default for BlockIds {
    fn default() -> Self {
        Self::new()
    }
}

/// Headers for the blob being created: content settings, metadata, and
/// the create-only condition.
#[derive(Debug, Clone, Default)]
pub(crate) struct BlobHeaders {
    pub headers: HeaderMap,
}

fn hv(v: &str, what: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(v).map_err(|_| Error::invalid_input(format!("invalid {what}: {v:?}")))
}

impl BlobHeaders {
    fn set(&mut self, name: &'static str, v: &str, what: &str) -> Result<()> {
        self.headers
            .insert(HeaderName::from_static(name), hv(v, what)?);
        Ok(())
    }

    fn set_metadata(&mut self, meta: &BTreeMap<String, String>) -> Result<()> {
        for (k, v) in meta {
            let name = HeaderName::from_bytes(format!("x-ms-meta-{k}").as_bytes())
                .map_err(|_| Error::invalid_input(format!("invalid metadata name {k:?}")))?;
            self.headers.insert(name, hv(v, "metadata value")?);
        }
        Ok(())
    }

    /// From write options (adlfs: `content_settings`, `metadata`).
    pub fn from_options(opts: &WriteOptions) -> Result<Self> {
        let mut h = BlobHeaders::default();
        let mut r = OptionReader::new("abfs", opts.extra.clone());
        if let Some(mut cs) = r.nested("content_settings")? {
            for (key, header) in [
                ("content_type", "x-ms-blob-content-type"),
                ("content_encoding", "x-ms-blob-content-encoding"),
                ("content_language", "x-ms-blob-content-language"),
                ("content_disposition", "x-ms-blob-content-disposition"),
                ("cache_control", "x-ms-blob-cache-control"),
            ] {
                if let Some(v) = cs.string(key)? {
                    h.set(header, &v, key)?;
                }
            }
            match cs.value("content_md5") {
                None => {}
                Some(Value::Bytes(b)) => {
                    let v = base64::engine::general_purpose::STANDARD.encode(b);
                    h.set("x-ms-blob-content-md5", &v, "content_md5")?;
                }
                Some(Value::Str(s)) => h.set("x-ms-blob-content-md5", &s, "content_md5")?,
                Some(other) => {
                    return Err(Error::invalid_input(format!(
                        "abfs: content_md5 must be bytes or a base64 string, got {}",
                        other.type_name()
                    )));
                }
            }
            cs.finish()?;
        }
        // adlfs `open(..., metadata=...)` / `pipe_file(..., metadata=...)`
        // arrive as a per-call extra; they add to `WriteOptions::metadata`.
        let mut metadata = opts.metadata.clone();
        if let Some(m) = r.string_map("metadata")? {
            metadata.extend(m);
        }
        // Accepted for adlfs compatibility; concurrency comes from the
        // filesystem settings.
        r.accept_ignored(&["max_concurrency", "overwrite"]);
        r.finish()?;
        if let Some(ct) = &opts.content_type {
            h.set("x-ms-blob-content-type", ct, "content type")?;
        }
        if metadata.is_empty() {
            let mut m = BTreeMap::new();
            m.insert("is_directory".to_owned(), "false".to_owned());
            h.set_metadata(&m)?;
        } else {
            h.set_metadata(&metadata)?;
        }
        Ok(h)
    }

    /// The existing blob's metadata and content settings (preserved by a
    /// block-list append, which otherwise replaces them).
    fn from_props(p: &BlobProps) -> Result<Self> {
        let mut h = BlobHeaders::default();
        let c = &p.content;
        for (v, header) in [
            (&c.content_type, "x-ms-blob-content-type"),
            (&c.content_encoding, "x-ms-blob-content-encoding"),
            (&c.content_language, "x-ms-blob-content-language"),
            (&c.content_disposition, "x-ms-blob-content-disposition"),
            (&c.cache_control, "x-ms-blob-cache-control"),
        ] {
            if let Some(v) = v {
                h.set(header, v, header)?;
            }
        }
        h.set_metadata(&p.metadata)?;
        Ok(h)
    }
}

/// Common write conditions.
#[derive(Debug, Clone, Default)]
pub(crate) struct Conditions {
    /// `If-None-Match: *`.
    pub create_new: bool,
    /// `If-Match: <etag>`.
    pub if_match: Option<String>,
}

impl Conditions {
    fn apply(&self, h: &mut HeaderMap) -> Result<()> {
        if self.create_new {
            h.insert(IF_NONE_MATCH, HeaderValue::from_static("*"));
        }
        if let Some(e) = &self.if_match {
            h.insert(IF_MATCH, hv(e, "ETag")?);
        }
        Ok(())
    }

    /// Map a conflict of a create-only write to `AlreadyExists`.
    fn map_err(&self, e: Error) -> Error {
        if self.create_new
            && matches!(
                e.kind(),
                ErrorKind::PreconditionFailed | ErrorKind::AlreadyExists
            )
        {
            e.with_kind(ErrorKind::AlreadyExists)
        } else {
            e
        }
    }
}

/// The blob being written.
#[derive(Debug, Clone)]
pub(crate) struct Target {
    pub sh: Arc<Shared>,
    pub container: String,
    pub blob: String,
    pub path: String,
    /// A plain overwrite: an existing append or page blob (on which Put
    /// Block fails with `InvalidBlobType`) is deleted so that the upload
    /// can replace it, as a single Put Blob would.
    pub replace_other_types: bool,
}

impl Target {
    fn url(&self) -> String {
        self.sh.client.blob_url(&self.container, &self.blob)
    }

    /// Put Blob of a block blob.
    async fn put_blob(&self, data: Bytes, hdr: &BlobHeaders, cond: &Conditions) -> Result<()> {
        let mut req = self
            .sh
            .client
            .request(Method::PUT, &self.url(), &Query::new())?
            .op(OpKind::Write)
            .path(self.path.clone())
            .body(data);
        let h = req.headers_mut();
        h.extend(hdr.headers.clone());
        h.insert(
            HeaderName::from_static("x-ms-blob-type"),
            HeaderValue::from_static("BlockBlob"),
        );
        cond.apply(h)?;
        self.sh
            .client
            .send_headers(req)
            .await
            .map(|_| ())
            .map_err(|e| cond.map_err(e))
    }

    /// Put Block.
    async fn put_block(&self, id: &str, data: Bytes) -> Result<()> {
        let q = Query::new().with("comp", "block").with("blockid", id);
        let req = self
            .sh
            .client
            .request(Method::PUT, &self.url(), &q)?
            .op(OpKind::Write)
            .path(self.path.clone())
            .body(data);
        let retry = self.replace_other_types.then(|| req.clone());
        match self.sh.client.send_headers(req).await {
            Ok(_) => Ok(()),
            Err(e) if retry.is_some() && has_code(&e, "InvalidBlobType") => {
                // Overwriting an append/page blob: blocks cannot be staged on
                // it, so remove it first (concurrent parts may race to do so).
                tracing::debug!(path = %self.path, "replacing a blob of another type");
                match self
                    .sh
                    .fs()
                    .delete_blob(&self.container, &self.blob, None, &self.path)
                    .await
                {
                    Ok(()) => {}
                    Err(d) if d.kind() == ErrorKind::NotFound => {}
                    Err(d) => return Err(d),
                }
                let retry = retry.expect("checked above");
                self.sh.client.send_headers(retry).await.map(|_| ())
            }
            Err(e) => Err(e),
        }
    }

    /// Put Block List. The first `committed` IDs are the blob's existing
    /// committed blocks (a block-list append) and are listed as
    /// `<Committed>`: with `<Latest>`, an uncommitted block that another
    /// writer staged under the same ID would silently replace that content.
    /// Our own blocks are `<Latest>`.
    ///
    /// A conditional commit (`If-None-Match: *` / `If-Match`) whose first
    /// attempt succeeded but whose response was lost fails its retry with a
    /// condition error; the committed block list then equals `ids` (which
    /// contain this upload's random ID prefix), so that case is recognised
    /// as success.
    async fn put_block_list(
        &self,
        ids: &[String],
        committed: usize,
        hdr: &BlobHeaders,
        cond: &Conditions,
    ) -> Result<()> {
        let mut body = String::with_capacity(64 + ids.len() * 48);
        body.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList>");
        for (i, id) in ids.iter().enumerate() {
            let tag = if i < committed { "Committed" } else { "Latest" };
            body.push('<');
            body.push_str(tag);
            body.push('>');
            escape_into(&mut body, id);
            body.push_str("</");
            body.push_str(tag);
            body.push('>');
        }
        body.push_str("</BlockList>");
        let q = Query::new().with("comp", "blocklist");
        let mut req = self
            .sh
            .client
            .request(Method::PUT, &self.url(), &q)?
            .op(OpKind::Write)
            .path(self.path.clone())
            .body(Bytes::from(body));
        let h = req.headers_mut();
        h.extend(hdr.headers.clone());
        h.insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));
        cond.apply(h)?;
        match self.sh.client.send_headers(req).await {
            Ok(_) => Ok(()),
            Err(e)
                if (cond.create_new || cond.if_match.is_some())
                    && matches!(
                        e.kind(),
                        ErrorKind::PreconditionFailed | ErrorKind::AlreadyExists
                    )
                    && ids.len() > committed =>
            {
                match self.committed_blocks().await {
                    Ok(now)
                        if now.len() == ids.len()
                            && now.iter().zip(ids).all(|(a, b)| &a.0 == b) =>
                    {
                        tracing::debug!(
                            path = %self.path,
                            "conditional Put Block List failed on retry, but our block list is committed"
                        );
                        Ok(())
                    }
                    _ => Err(cond.map_err(e)),
                }
            }
            Err(e) => Err(cond.map_err(e)),
        }
    }

    /// Committed block IDs and sizes (Get Block List).
    async fn committed_blocks(&self) -> Result<Vec<(String, u64)>> {
        let q = Query::new()
            .with("comp", "blocklist")
            .with("blocklisttype", "committed");
        let req = self
            .sh
            .client
            .request(Method::GET, &self.url(), &q)?
            .op(OpKind::Info)
            .path(self.path.clone());
        let (_, body) = self.sh.client.send_body(req).await?;
        let root = crate::xml::Element::parse(&body)?;
        let mut out = Vec::new();
        if let Some(c) = root.child("CommittedBlocks") {
            for b in c.children_named("Block") {
                let id = b.child_text("Name").unwrap_or("").to_owned();
                let size = b
                    .child_text("Size")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                out.push((id, size));
            }
        }
        Ok(out)
    }

    /// Create an empty append blob.
    async fn create_append_blob(&self, hdr: &BlobHeaders, create_new: bool) -> Result<()> {
        let mut req = self
            .sh
            .client
            .request(Method::PUT, &self.url(), &Query::new())?
            .op(OpKind::Write)
            .path(self.path.clone());
        let h = req.headers_mut();
        h.extend(hdr.headers.clone());
        h.insert(
            HeaderName::from_static("x-ms-blob-type"),
            HeaderValue::from_static("AppendBlob"),
        );
        if create_new {
            h.insert(IF_NONE_MATCH, HeaderValue::from_static("*"));
        }
        self.sh.client.send_headers(req).await.map(|_| ())
    }

    /// Append Block at `pos`; returns the new length.
    async fn append_block(&self, pos: u64, data: Bytes) -> Result<u64> {
        let len = data.len() as u64;
        let sent = data.clone();
        let q = Query::new().with("comp", "appendblock");
        let req = self
            .sh
            .client
            .request(Method::PUT, &self.url(), &q)?
            .op(OpKind::Write)
            .path(self.path.clone())
            .header(
                HeaderName::from_static("x-ms-blob-condition-appendpos"),
                HeaderValue::from(pos),
            )
            .body(data)
            // A retry after a lost response fails the append-position
            // condition; that case is recognised below.
            .retry_safe(true);
        match self.sh.client.send_headers(req).await {
            Ok(_) => Ok(pos + len),
            Err(e) if e.kind() == ErrorKind::PreconditionFailed => {
                // Did an earlier attempt of this request succeed? Then the
                // blob holds exactly our bytes at `pos`. (Its length alone
                // does not tell: another writer may have appended as many
                // bytes, and ours would be silently lost.)
                let f = crate::read::get_range(
                    &self.sh,
                    &self.container,
                    &self.blob,
                    fsfast_core::ByteRange::Bounded {
                        start: pos,
                        end: pos + len,
                    },
                    &crate::read::Pin::None,
                    &self.path,
                )
                .await?;
                match f.props {
                    Some(p) if p.size == pos + len && f.body.data == sent => Ok(pos + len),
                    _ => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }
}

/// Whether `e` carries the service error code `code`.
fn has_code(e: &Error, code: &str) -> bool {
    e.details()
        .iter()
        .any(|d| matches!(d, fsfast_core::Detail::Code(c) if c == code))
}

/// Stages parts as blocks for a [`PartUploader`].
struct BlockSink {
    target: Target,
    ids: BlockIds,
    /// Block numbers already used before the uploader's parts (re-staged
    /// content of a block-blob append).
    offset: u32,
}

#[async_trait]
impl PartSink for BlockSink {
    type Outcome = String;

    async fn upload_part(&self, part_number: u32, data: Bytes) -> Result<String> {
        let id = self.ids.id(self.offset + part_number);
        self.target.put_block(&id, data).await?;
        Ok(id)
    }
}

enum State {
    /// Block blob upload (overwrite, create-only, or block-list append).
    Blocks {
        up: Option<Box<PartUploader<BlockSink>>>,
        /// Blocks that precede the new ones (block-list append).
        base: Vec<String>,
        /// How many of `base` are committed blocks of the existing blob
        /// (the rest are re-staged, uncommitted ones).
        base_committed: usize,
        hdr: BlobHeaders,
        cond: Conditions,
        /// A block-list append: always commit a block list (with the IDs
        /// of the sink, for a tail that never filled a part).
        appending: Option<BlockIds>,
    },
    /// Append blob.
    Append {
        pending: BytesMut,
        /// Current blob length (`None`: the blob must be created first).
        pos: Option<u64>,
        hdr: BlobHeaders,
    },
    /// Closed or aborted.
    Done,
}

/// An open blob for writing.
pub struct AzureWriteHandle {
    target: Target,
    state: State,
    written: u64,
}

impl std::fmt::Debug for AzureWriteHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.state {
            State::Blocks {
                appending: Some(_), ..
            } => "block-list append",
            State::Blocks { .. } => "block blob",
            State::Append { .. } => "append blob",
            State::Done => "closed",
        };
        f.debug_struct("AzureWriteHandle")
            .field("path", &self.target.path)
            .field("kind", &kind)
            .field("written", &self.written)
            .finish()
    }
}

impl AzureWriteHandle {
    async fn push_append(&mut self, all: bool) -> Result<()> {
        let State::Append { pending, pos, hdr } = &mut self.state else {
            return Ok(());
        };
        if pos.is_none() {
            match self.target.create_append_blob(hdr, true).await {
                Ok(()) => *pos = Some(0),
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    // Created concurrently: append to it if it is an append blob.
                    let p = self
                        .target
                        .sh
                        .fs()
                        .head_blob(
                            &self.target.container,
                            &self.target.blob,
                            None,
                            &self.target.path,
                        )
                        .await?;
                    if p.blob_type != BlobType::Append {
                        return Err(e);
                    }
                    *pos = Some(p.size);
                }
                Err(e) => return Err(e),
            }
        }
        while pending.len() >= APPEND_CHUNK || (all && !pending.is_empty()) {
            let n = pending.len().min(APPEND_CHUNK);
            let chunk = pending.split_to(n).freeze();
            let at = pos.unwrap_or(0);
            *pos = Some(self.target.append_block(at, chunk).await?);
        }
        Ok(())
    }
}

#[async_trait]
impl WriteHandle for AzureWriteHandle {
    async fn write(&mut self, data: Bytes) -> Result<()> {
        let n = data.len() as u64;
        match &mut self.state {
            State::Blocks { up: Some(up), .. } => up.write(data).await?,
            State::Append { pending, .. } => {
                pending.extend_from_slice(&data);
                if pending.len() >= APPEND_CHUNK {
                    self.push_append(false).await?;
                }
            }
            _ => {
                return Err(
                    Error::invalid_input("write to a closed file").with_path(&self.target.path)
                );
            }
        }
        self.written += n;
        Ok(())
    }

    async fn flush(&mut self) -> Result<()> {
        if matches!(self.state, State::Append { .. }) {
            self.push_append(true).await?;
        }
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        match std::mem::replace(&mut self.state, State::Done) {
            State::Done => Ok(()),
            State::Blocks {
                up,
                base,
                base_committed,
                hdr,
                cond,
                appending,
            } => {
                let Some(up) = up else { return Ok(()) };
                match (*up).finish().await? {
                    UploadResult::Single(data) => match appending {
                        None => self.target.put_blob(data, &hdr, &cond).await,
                        Some(sink_ids) => {
                            // Block-list append of a small tail: one more block.
                            if data.is_empty() {
                                // Nothing appended: leave the blob untouched.
                                return Ok(());
                            }
                            let mut ids = base;
                            let id = sink_ids.id(ids.len() as u32 + 1);
                            self.target.put_block(&id, data).await?;
                            ids.push(id);
                            self.target
                                .put_block_list(&ids, base_committed, &hdr, &cond)
                                .await
                        }
                    },
                    UploadResult::Multipart(parts) => {
                        let mut ids = base;
                        ids.extend(parts.into_iter().map(|p| p.outcome));
                        if ids.len() > MAX_BLOCKS as usize {
                            return Err(Error::invalid_input(format!(
                                "blob would have {} blocks (the limit is {MAX_BLOCKS})",
                                ids.len()
                            ))
                            .with_path(&self.target.path));
                        }
                        self.target
                            .put_block_list(&ids, base_committed, &hdr, &cond)
                            .await
                    }
                }
            }
            state @ State::Append { .. } => {
                self.state = state;
                let r = self.push_append(true).await;
                self.state = State::Done;
                r
            }
        }
    }

    async fn abort(&mut self) -> Result<()> {
        if let State::Blocks { up: Some(up), .. } = std::mem::replace(&mut self.state, State::Done)
        {
            (*up).abort().await;
        }
        Ok(())
    }

    fn bytes_written(&self) -> u64 {
        self.written
    }
}

impl AzureBlobFileSystem {
    fn upload_config(&self, expected: Option<u64>) -> UploadConfig {
        UploadConfig {
            part_size: self.sh.cfg.upload_block_size(),
            min_part_size: 1,
            max_part_size: crate::options::MAX_BLOCK_SIZE,
            max_parts: MAX_BLOCKS,
            concurrency: self.sh.cfg.upload_concurrency,
            expected_size: expected,
            budget: Some(self.sh.budget.clone()),
        }
    }

    fn target(&self, path: &str) -> Result<Target> {
        let p = split_path(path, self.sh.cfg.version_aware);
        let full = p.full();
        if p.container.is_empty() || p.blob.is_empty() {
            return Err(Error::is_a_directory(full));
        }
        Ok(Target {
            sh: self.sh.clone(),
            container: p.container.to_owned(),
            blob: p.blob.to_owned(),
            path: full,
            replace_other_types: false,
        })
    }

    pub(crate) async fn open_write_impl(
        &self,
        path: &str,
        opts: &WriteOptions,
    ) -> Result<AzureWriteHandle> {
        let mut target = self.target(path)?;
        target.replace_other_types = opts.mode == WriteMode::Overwrite;
        let hdr = BlobHeaders::from_options(opts)?;
        let mut cfg = self.upload_config(None);
        if let Some(b) = opts.block_size {
            cfg.part_size = b.clamp(1, crate::options::MAX_BLOCK_SIZE);
        }
        let state = match opts.mode {
            WriteMode::Overwrite | WriteMode::CreateNew => {
                let create_new = opts.mode == WriteMode::CreateNew;
                if create_new {
                    // Fail fast instead of uploading everything first; the
                    // commit is still conditional.
                    match self
                        .head_blob(&target.container, &target.blob, None, &target.path)
                        .await
                    {
                        Ok(_) => return Err(Error::already_exists(target.path.clone())),
                        Err(e) if e.kind() == ErrorKind::NotFound => {}
                        Err(e) => return Err(e),
                    }
                }
                let sink = BlockSink {
                    target: target.clone(),
                    ids: BlockIds::new(),
                    offset: 0,
                };
                State::Blocks {
                    up: Some(Box::new(PartUploader::new(Arc::new(sink), cfg)?)),
                    base: Vec::new(),
                    base_committed: 0,
                    hdr,
                    cond: Conditions {
                        create_new,
                        if_match: None,
                    },
                    appending: None,
                }
            }
            WriteMode::Append => self.open_append(&target, hdr, opts, cfg).await?,
        };
        Ok(AzureWriteHandle {
            target,
            state,
            written: 0,
        })
    }

    async fn open_append(
        &self,
        target: &Target,
        hdr: BlobHeaders,
        opts: &WriteOptions,
        cfg: UploadConfig,
    ) -> Result<State> {
        let props = match self
            .head_blob(&target.container, &target.blob, None, &target.path)
            .await
        {
            Ok(p) => p,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Ok(State::Append {
                    pending: BytesMut::new(),
                    pos: None,
                    hdr,
                });
            }
            Err(e) => return Err(e),
        };
        match props.blob_type {
            BlobType::Append => Ok(State::Append {
                pending: BytesMut::new(),
                pos: Some(props.size),
                hdr,
            }),
            BlobType::Page => {
                Err(Error::unsupported("append to a page blob").with_path(&target.path))
            }
            BlobType::Block => {
                let etag = props
                    .etag
                    .clone()
                    .ok_or_else(|| Error::protocol("blob has no ETag").with_path(&target.path))?;
                let committed = target.committed_blocks().await?;
                let covered: u64 = committed.iter().map(|(_, s)| s).sum();
                let matching = committed.first().and_then(|(id, _)| BlockIds::matching(id));
                let (base, base_committed, ids) = match matching {
                    Some(ids) if covered == props.size && !committed.is_empty() => {
                        let n = committed.len();
                        (
                            committed.into_iter().map(|(id, _)| id).collect::<Vec<_>>(),
                            n,
                            ids,
                        )
                    }
                    _ => {
                        // No usable block list: re-stage the content as blocks.
                        let ids = BlockIds::new();
                        let base = self
                            .restage(target, &props, &etag, &ids, cfg.part_size)
                            .await?;
                        (base, 0, ids)
                    }
                };
                let offset = base.len() as u32;
                let sink = BlockSink {
                    target: target.clone(),
                    ids: ids.clone(),
                    offset,
                };
                // Put Block List replaces properties and metadata: keep the
                // blob's own, overridden by settings given for this write.
                let mut keep = BlobHeaders::from_props(&props)?;
                if !opts.metadata.is_empty() {
                    let old: Vec<_> = keep
                        .headers
                        .keys()
                        .filter(|k| k.as_str().starts_with("x-ms-meta-"))
                        .cloned()
                        .collect();
                    for k in old {
                        keep.headers.remove(k);
                    }
                }
                for (k, v) in hdr.headers.iter() {
                    if !k.as_str().starts_with("x-ms-meta-") || !opts.metadata.is_empty() {
                        keep.headers.insert(k.clone(), v.clone());
                    }
                }
                Ok(State::Blocks {
                    up: Some(Box::new(PartUploader::new(Arc::new(sink), cfg)?)),
                    base,
                    base_committed,
                    hdr: keep,
                    cond: Conditions {
                        create_new: false,
                        if_match: Some(etag),
                    },
                    appending: Some(ids),
                })
            }
        }
    }

    /// Download `props.size` bytes (pinned to `etag`) and stage them as
    /// blocks; returns their IDs in order.
    async fn restage(
        &self,
        target: &Target,
        props: &BlobProps,
        etag: &str,
        ids: &BlockIds,
        part: usize,
    ) -> Result<Vec<String>> {
        if props.size == 0 {
            return Ok(Vec::new());
        }
        let opts = ReadOptions::default();
        let handle = self.open_read_impl(&target.path, &opts).await?;
        if handle.pinned_etag() != Some(etag) {
            return Err(Error::new(
                ErrorKind::PreconditionFailed,
                "blob changed while opening for append",
            )
            .with_path(&target.path));
        }
        let part = part.max(1) as u64;
        let ranges: Vec<(u32, u64, u64)> = (0..props.size.div_ceil(part))
            .map(|i| (i as u32 + 1, i * part, ((i + 1) * part).min(props.size)))
            .collect();
        let conc = self.sh.cfg.upload_concurrency;
        let results: Vec<Result<String>> = stream::iter(ranges.into_iter().map(|(n, s, e)| {
            let handle = &handle;
            async move {
                let data = handle.read_at(s, (e - s) as usize).await?;
                let id = ids.id(n);
                target.put_block(&id, data).await?;
                Ok(id)
            }
        }))
        .buffered(conc)
        .collect()
        .await;
        results.into_iter().collect()
    }

    /// pipe_file: one Put Blob for small data, otherwise blocks staged in
    /// parallel (slices of `data`, no copies) and one Put Block List.
    pub(crate) async fn pipe_file_impl(
        &self,
        path: &str,
        data: Bytes,
        opts: &WriteOptions,
    ) -> Result<()> {
        let mut target = self.target(path)?;
        target.replace_other_types = opts.mode == WriteMode::Overwrite;
        let hdr = BlobHeaders::from_options(opts)?;
        let cond = Conditions {
            create_new: opts.mode == WriteMode::CreateNew,
            if_match: None,
        };
        let block = opts
            .block_size
            .unwrap_or_else(|| self.sh.cfg.upload_block_size())
            .max(1);
        if data.len() <= block {
            return target.put_blob(data, &hdr, &cond).await;
        }
        let sizer =
            fsfast_engine::upload::PartSizer::new(&self.upload_config(Some(data.len() as u64)))?;
        let ids = BlockIds::new();
        let mut parts = Vec::new();
        let mut off = 0usize;
        let mut n = 1u32;
        while off < data.len() {
            let len = (sizer.part_size(n) as usize).min(data.len() - off).max(1);
            parts.push((n, data.slice(off..off + len)));
            off += len;
            n += 1;
        }
        let conc = self.sh.cfg.upload_concurrency;
        let staged: Vec<Result<String>> = stream::iter(parts.into_iter().map(|(n, chunk)| {
            let ids = &ids;
            let target = &target;
            async move {
                let id = ids.id(n);
                target.put_block(&id, chunk).await?;
                Ok(id)
            }
        }))
        .buffered(conc)
        .collect()
        .await;
        let ids: Vec<String> = staged.into_iter().collect::<Result<_>>()?;
        target.put_block_list(&ids, 0, &hdr, &cond).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_ids_have_equal_length() {
        let ids = BlockIds::new();
        let a = ids.id(1);
        let b = ids.id(49_999);
        assert_eq!(a.len(), 32);
        assert_eq!(a.len(), b.len());
        assert_ne!(a, b);
        assert_ne!(BlockIds::new().id(1), a, "prefixes are random per upload");
        // Matching an existing blob's IDs: same decoded and encoded length.
        let b64 = |s: &[u8]| base64::engine::general_purpose::STANDARD.encode(s);
        let dec = |s: &str| {
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .unwrap()
                .len()
        };
        for existing in [
            // adlfs: uuid4().hex (32 bytes; 44 characters with padding).
            b64(b"0123456789abcdef0123456789abcdef"),
            // azure-storage-blob's chunked upload: 48 digits.
            b64(&[b'7'; 48]),
            // fsfast's own.
            BlockIds::new().id(3),
            b64(b"block-000000000001"),
        ] {
            let m = BlockIds::matching(&existing).unwrap();
            assert_eq!(m.id(7).len(), existing.len(), "{existing}");
            assert_eq!(dec(&m.id(7)), dec(&existing), "{existing}");
        }
        // Too short, not base64.
        assert!(BlockIds::matching(&b64(b"0000000")).is_none());
        assert!(BlockIds::matching("not base64!").is_none());
        assert!(BlockIds::matching(&b64(&[b'x'; 60])).is_none());
    }

    #[test]
    fn headers_from_options() {
        let mut o = WriteOptions::default();
        let h = BlobHeaders::from_options(&o).unwrap();
        assert_eq!(h.headers["x-ms-meta-is_directory"], "false");
        o.metadata.insert("k".into(), "v".into());
        o.content_type = Some("text/plain".into());
        let mut cs = BTreeMap::new();
        cs.insert("cache_control".to_owned(), Value::Str("no-cache".into()));
        o.extra.insert("content_settings".into(), Value::Map(cs));
        let h = BlobHeaders::from_options(&o).unwrap();
        assert!(!h.headers.contains_key("x-ms-meta-is_directory"));
        assert_eq!(h.headers["x-ms-meta-k"], "v");
        assert_eq!(h.headers["x-ms-blob-content-type"], "text/plain");
        assert_eq!(h.headers["x-ms-blob-cache-control"], "no-cache");
        o.extra.insert("bogus".into(), Value::Int(1));
        assert!(BlobHeaders::from_options(&o).is_err());
    }

    #[test]
    fn metadata_from_extra() {
        // adlfs `open(..., metadata={...})` arrives as a per-call extra.
        let mut o = WriteOptions::default();
        let mut m = BTreeMap::new();
        m.insert("user".to_owned(), Value::Str("x".into()));
        o.extra.insert("metadata".into(), Value::Map(m));
        let h = BlobHeaders::from_options(&o).unwrap();
        assert_eq!(h.headers["x-ms-meta-user"], "x");
        assert!(!h.headers.contains_key("x-ms-meta-is_directory"));
        // Merged with WriteOptions::metadata.
        o.metadata.insert("k".into(), "v".into());
        let h = BlobHeaders::from_options(&o).unwrap();
        assert_eq!(h.headers["x-ms-meta-user"], "x");
        assert_eq!(h.headers["x-ms-meta-k"], "v");
        // Values must be strings.
        let mut bad = BTreeMap::new();
        bad.insert("n".to_owned(), Value::Int(1));
        o.extra.insert("metadata".into(), Value::Map(bad));
        assert!(BlobHeaders::from_options(&o).is_err());
    }
}
