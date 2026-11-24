//! Server-side copy: FSCTL_SRV_REQUEST_RESUME_KEY on the source and
//! FSCTL_SRV_COPYCHUNK_WRITE on the destination ([MS-SMB2] §3.2.4.20.2,
//! §2.2.31.1), as smbclient's `copyfile` does, but with fewer round trips:
//!
//! 1. CREATE(source, share READ) + IOCTL(REQUEST_RESUME_KEY),
//! 2. CREATE(destination, OVERWRITE_IF) + the first COPYCHUNK_WRITE batch,
//! 3. further batches pipelined (a few in flight),
//! 4. CLOSE both handles concurrently.
//!
//! Batches follow the server's limits (256 chunks of 1 MiB, 16 MiB per
//! request by default; a server that answers `STATUS_INVALID_PARAMETER`
//! reports its own limits, which are then used).
//!
//! The source stays open without write sharing while the destination is
//! opened, so copying a file onto itself (under any alias) fails with a
//! sharing violation instead of truncating it.

use std::collections::VecDeque;

use bytes::Bytes;
use fsfast_core::{Error, ErrorKind, Result};
use fsfast_smb_proto::fscc::{CreateDisposition, ShareAccess};
use fsfast_smb_proto::msg::{
    CreateResponse, FsctlData, IoctlRequest, IoctlResponse, RawMessage, SrvCopyChunk,
    SrvCopyChunkCopy, SrvCopyChunkResponse, SrvRequestResumeKeyResponse, fsctl,
};
use fsfast_smb_proto::{FileId, NtStatus};

use crate::client::Ctx;
use crate::config::SmbPath;
use crate::conn::{Response, recv_all};
use crate::ops;

/// Copy-chunk limits ([MS-SMB2] §3.3.3 defaults, also Samba's).
#[derive(Debug, Clone, Copy)]
struct Limits {
    max_chunks: u32,
    max_chunk_size: u32,
    max_total: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_chunks: 256,
            max_chunk_size: 1 << 20,
            max_total: 16 << 20,
        }
    }
}

/// Batches of copy-chunk requests in flight at once.
const BATCHES_IN_FLIGHT: usize = 4;

/// Result of a server-side copy attempt.
pub(crate) enum CopyOutcome {
    Done,
    /// The server cannot copy server-side; nothing was created.
    Unsupported,
}

fn unsupported_status(s: NtStatus) -> bool {
    matches!(
        s,
        NtStatus::NOT_SUPPORTED
            | NtStatus::INVALID_DEVICE_REQUEST
            | NtStatus::NOT_IMPLEMENTED
            | NtStatus::INVALID_INFO_CLASS
    )
}

/// The chunks covering `[from, size)` for one request.
fn batch(from: u64, size: u64, l: &Limits) -> Vec<SrvCopyChunk> {
    let mut out = Vec::new();
    let mut off = from;
    let mut total = 0u64;
    while off < size && (out.len() as u32) < l.max_chunks && total < u64::from(l.max_total) {
        let len = (size - off)
            .min(u64::from(l.max_chunk_size))
            .min(u64::from(l.max_total) - total) as u32;
        out.push(SrvCopyChunk {
            source_offset: off,
            target_offset: off,
            length: len,
        });
        off += u64::from(len);
        total += u64::from(len);
    }
    out
}

fn copychunk_req(key: [u8; 24], chunks: Vec<SrvCopyChunk>, fid: FileId) -> Result<IoctlRequest> {
    let input = SrvCopyChunkCopy {
        source_key: key,
        chunks,
    }
    .to_bytes()?;
    Ok(IoctlRequest::fsctl(fsctl::SRV_COPYCHUNK_WRITE, fid, input, 12))
}

/// Server-side copy of `src` (on `sctx`'s tree) to `dst` (on `dctx`'s tree;
/// both trees belong to one session).
pub(crate) async fn server_side_copy(
    sctx: &Ctx,
    dctx: &Ctx,
    src: &SmbPath,
    dst: &SmbPath,
) -> Result<CopyOutcome> {
    // 1. Open the source and get its resume key.
    let mut chain = sctx.chain();
    chain
        .push(&ops::read_open_req(&src.rel, ShareAccess::READ))?
        .push(&IoctlRequest::fsctl(
            fsctl::SRV_REQUEST_RESUME_KEY,
            FileId::RELATED,
            Bytes::new(),
            32,
        ))?;
    let r = sctx.exec(chain).await?;
    let c: CreateResponse = ops::decode(&r[0], &src.name)?;
    let sfid = c.file_id;
    let size = c.end_of_file;
    let res = async {
        if r[1].is_error_response() && unsupported_status(r[1].status()) {
            return Ok(CopyOutcome::Unsupported);
        }
        let io: IoctlResponse = ops::decode(&r[1], &src.name)?;
        let key = SrvRequestResumeKeyResponse::decode(&io.output)?.resume_key;
        copy_to(dctx, dst, key, size).await
    }
    .await;
    let closed = ops::close(sctx, sfid, &src.name).await;
    let out = res?;
    if let Err(e) = closed {
        tracing::debug!(path = src.name, error = %e, "closing the copy source failed");
    }
    Ok(out)
}

/// Steps 2–4 for the destination.
async fn copy_to(dctx: &Ctx, dst: &SmbPath, key: [u8; 24], size: u64) -> Result<CopyOutcome> {
    let mut limits = Limits::default();
    let first = batch(0, size, &limits);
    let mut chain = dctx.chain();
    chain.push(&ops::write_open_req(
        &dst.rel,
        ShareAccess::READ,
        CreateDisposition::OVERWRITE_IF,
    ))?;
    let first_len: u64 = first.iter().map(|c| u64::from(c.length)).sum();
    if !first.is_empty() {
        chain.push(&copychunk_req(key, first, FileId::RELATED)?)?;
    }
    let r = dctx.exec(chain).await?;
    let c: CreateResponse = ops::decode(&r[0], &dst.name)?;
    let dfid = c.file_id;
    let res = async {
        let mut done = 0u64;
        if r.len() > 1 {
            match chunk_result(&r[1], &dst.name, &mut limits)? {
                Some(n) => done = n,
                None if r[1].is_error_response() && unsupported_status(r[1].status()) => {
                    return Ok(CopyOutcome::Unsupported);
                }
                None => {}
            }
            // A partial first batch (or new limits) continues from `done`.
            done = done.min(first_len);
        }
        // 3. The rest, a few batches in flight. Each batch is independent
        //    (explicit offsets), so they may complete in any order.
        let mut next = done;
        let mut refusals = 0u32;
        let mut inflight: VecDeque<(u64, u64, Response)> = VecDeque::new();
        while next < size || !inflight.is_empty() {
            while next < size && inflight.len() < BATCHES_IN_FLIGHT {
                let chunks = batch(next, size, &limits);
                let len: u64 = chunks.iter().map(|c| u64::from(c.length)).sum();
                let mut chain = dctx.chain();
                chain.push(&copychunk_req(key, chunks, dfid)?)?;
                let mut resp = dctx
                    .live
                    .conn
                    .shared
                    .send(chain.into_messages(), &dctx.sec())
                    .await?;
                inflight.push_back((next, len, resp.pop().expect("one response")));
                next += len;
            }
            let Some((at, len, resp)) = inflight.pop_front() else {
                break;
            };
            let raw = resp.recv().await?;
            match chunk_result(&raw, &dst.name, &mut limits)? {
                Some(n) if n >= len => refusals = 0,
                Some(0) => {
                    return Err(Error::new(ErrorKind::Io, "server-side copy made no progress")
                        .with_path(dst.name.as_str()));
                }
                // Short batch, or refused with new limits: let the rest of
                // the window finish, then resume after what was written
                // (re-copying a completed later batch is harmless).
                other => {
                    refusals += 1;
                    if refusals > 3 {
                        return Err(Error::new(
                            ErrorKind::Io,
                            "server-side copy keeps refusing copy-chunk requests",
                        )
                        .with_path(dst.name.as_str()));
                    }
                    let _ = recv_all(inflight.drain(..).map(|(_, _, r)| r).collect()).await;
                    next = at + other.unwrap_or(0);
                }
            }
        }
        Ok(CopyOutcome::Done)
    }
    .await;
    let closed = ops::close(dctx, dfid, &dst.name).await;
    match res {
        Ok(CopyOutcome::Done) => {
            closed?;
            Ok(CopyOutcome::Done)
        }
        // The destination was created (and truncated) by us: remove it so a
        // failed or unsupported copy leaves nothing behind.
        other => {
            let _ = ops::delete(dctx, dst, Some(false)).await;
            other
        }
    }
}

/// Bytes written by one COPYCHUNK_WRITE, `None` when the server refused the
/// request with its limits (which replace `limits`).
fn chunk_result(raw: &RawMessage, path: &str, limits: &mut Limits) -> Result<Option<u64>> {
    if raw.status() == NtStatus::INVALID_PARAMETER && !raw.is_error_response() {
        let io: IoctlResponse = raw.decode()?;
        let l = SrvCopyChunkResponse::decode(&io.output)?;
        *limits = Limits {
            max_chunks: l.chunks_written.max(1),
            max_chunk_size: l.chunk_bytes_written.max(1),
            max_total: l.total_bytes_written.max(1),
        };
        tracing::debug!(?limits, "server copy-chunk limits");
        return Ok(None);
    }
    if raw.is_error_response() && unsupported_status(raw.status()) {
        return Ok(None);
    }
    let io: IoctlResponse = ops::decode(raw, path)?;
    let r = SrvCopyChunkResponse::decode(&io.output)?;
    Ok(Some(u64::from(r.total_bytes_written)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batches_respect_limits() {
        let l = Limits::default();
        let b = batch(0, 40 << 20, &l);
        assert_eq!(b.len(), 16);
        assert!(b.iter().all(|c| c.length == 1 << 20));
        assert_eq!(b[15].source_offset, 15 << 20);
        let b = batch(16 << 20, (16 << 20) + 10, &l);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].length, 10);
        assert!(batch(5, 5, &l).is_empty());
        let small = Limits {
            max_chunks: 2,
            max_chunk_size: 100,
            max_total: 150,
        };
        let b = batch(0, 1000, &small);
        assert_eq!(
            b.iter().map(|c| c.length).collect::<Vec<_>>(),
            vec![100, 50]
        );
    }
}
