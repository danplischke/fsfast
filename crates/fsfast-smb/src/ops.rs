//! Compound request recipes: every metadata operation is one round trip.
//!
//! | operation | compound |
//! |---|---|
//! | info | CREATE + CLOSE (the CREATE response carries times, size, attributes) |
//! | ls | CREATE + QUERY_DIRECTORY ×3 + CLOSE (a QUERY_DIRECTORY loop on an open handle beyond ~45k entries) |
//! | small cat | CREATE + READ + CLOSE |
//! | small pipe | CREATE + WRITE + CLOSE |
//! | rm / rmdir | CREATE + SET_INFO(FileDispositionInformation) + CLOSE |
//! | mv | CREATE + SET_INFO(FileRenameInformation) + CLOSE |
//! | mkdir | CREATE(FILE_CREATE, directory) + CLOSE |
//! | touch | CREATE(OPEN_IF) + SET_INFO(FileBasicInformation) + CLOSE |

use bytes::Bytes;
use fsfast_core::{Error, ErrorKind, FileInfo, Result, Value};
use fsfast_smb_proto::fscc::{
    AccessMask, CreateDisposition, CreateOptions, DirEntry, FileAttributes, FileBasicInformation,
    FileDispositionInformation, FileEndOfFileInformation, FileInfoClass, FileRenameInformation,
    FileTime, ImpersonationLevel, OplockLevel, ShareAccess,
};
use fsfast_smb_proto::msg::{
    CloseFlags, CloseRequest, CloseResponse, CreateRequest, CreateResponse, Message,
    QueryDirectoryFlags, QueryDirectoryRequest, QueryDirectoryResponse, RawMessage, ReadRequest,
    ReadResponse, SetInfoRequest, WriteRequest, WriteResponse,
};
use fsfast_smb_proto::{FileId, NtStatus};

use crate::client::Ctx;
use crate::config::SmbPath;

/// Share mode of internal metadata opens: never conflicts with other opens.
pub(crate) const SHARE_ALL: ShareAccess = ShareAccess::all();

/// Directory information class used for listings: like smbclient's
/// `scandir`, `FileIdFullDirectoryInformation` (no 8.3 names, which Samba
/// would otherwise have to generate for every entry).
const LIST_CLASS: FileInfoClass = FileInfoClass::ID_FULL_DIRECTORY;

/// Output buffer of the first QUERY_DIRECTORY in the listing compound
/// (about 9,000 entries with short names).
const LIST_BUFFER: usize = 1 << 20;

/// Output buffer of the second QUERY_DIRECTORY and of later pages. Servers
/// fill responses to the entries' size, so a large buffer only reserves
/// credits while the request is in flight.
const LIST_BUFFER_2: usize = 4 << 20;

/// Fail with the status of an error response, naming `path`.
pub(crate) fn check(raw: &RawMessage, path: &str) -> Result<()> {
    if raw.is_error_response() {
        Err(raw.status().to_error(Some(path)))
    } else {
        Ok(())
    }
}

/// Decode a response body after checking its status.
pub(crate) fn decode<M: Message>(raw: &RawMessage, path: &str) -> Result<M> {
    check(raw, path)?;
    Ok(raw.decode::<M>()?)
}

/// A CREATE request with smbclient's conventions (impersonation level
/// Impersonation, no oplock).
pub(crate) fn create_req(
    rel: &str,
    desired_access: AccessMask,
    share_access: ShareAccess,
    disposition: CreateDisposition,
    options: CreateOptions,
    attributes: FileAttributes,
) -> CreateRequest {
    CreateRequest {
        requested_oplock_level: OplockLevel::NONE,
        impersonation_level: ImpersonationLevel::IMPERSONATION,
        desired_access,
        file_attributes: attributes,
        share_access,
        create_disposition: disposition,
        create_options: options,
        name: rel.to_owned(),
        ..Default::default()
    }
}

fn close_related() -> CloseRequest {
    CloseRequest {
        flags: CloseFlags::empty(),
        file_id: FileId::RELATED,
    }
}

/// FILETIME → seconds since the Unix epoch, as smbclient computes
/// `st_mtime` (including the negative value of an unset time).
fn unix_secs(t: FileTime) -> f64 {
    t.to_unix_f64()
        .unwrap_or_else(|| (t.0 as i128 - 116_444_736_000_000_000) as f64 / 1e7)
}

/// The metadata fields of a CREATE response or a directory entry.
pub(crate) struct Meta {
    pub attributes: FileAttributes,
    pub end_of_file: u64,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
}

impl Meta {
    pub fn from_create(c: &CreateResponse) -> Meta {
        Meta {
            attributes: c.file_attributes,
            end_of_file: c.end_of_file,
            creation_time: c.creation_time,
            last_access_time: c.last_access_time,
            last_write_time: c.last_write_time,
            change_time: c.change_time,
        }
    }

    fn from_entry(e: &DirEntry) -> Meta {
        Meta {
            attributes: e.file_attributes,
            end_of_file: e.end_of_file,
            creation_time: e.creation_time,
            last_access_time: e.last_access_time,
            last_write_time: e.last_write_time,
            change_time: e.change_time,
        }
    }

    pub fn is_dir(&self) -> bool {
        self.attributes.contains(FileAttributes::DIRECTORY)
    }

    /// The fsspec `SMBFileSystem.info()` record: `size` from the end of
    /// file, `type` from the attributes, and the native keys `uid`, `gid`
    /// (always 0, as smbclient reports), `time` (last access) and `mtime`
    /// (last write) as float seconds. fsspec names directories with a
    /// trailing `/`; `FileInfo::name` stays canonical (no slash, as the
    /// core contract requires) and the slashed form goes into `extra["name"]`,
    /// which overrides the dict's `name` key (`{"name": name, ..., **extra}`).
    pub fn to_info(&self, name: String) -> FileInfo {
        let is_dir = self.is_dir();
        let mut fi = if is_dir {
            let mut d = FileInfo::directory(name.clone());
            d.size = self.end_of_file;
            d.set("name", Value::Str(format!("{name}/")));
            d
        } else {
            FileInfo::file(name, self.end_of_file)
        };
        fi.modified = self.last_write_time.to_system_time();
        fi.created = self.creation_time.to_system_time();
        fi.version = Some(format!("{:x}-{:x}", self.change_time.0, self.end_of_file));
        fi.set("uid", Value::Int(0));
        fi.set("gid", Value::Int(0));
        fi.set("time", Value::Float(unix_secs(self.last_access_time)));
        fi.set("mtime", Value::Float(unix_secs(self.last_write_time)));
        fi
    }
}

/// info: CREATE(FILE_READ_ATTRIBUTES) + CLOSE. Attribute-only opens never
/// conflict with other handles' share modes.
pub(crate) async fn stat(ctx: &Ctx, p: &SmbPath) -> Result<Meta> {
    let mut chain = ctx.chain();
    chain
        .push(&create_req(
            &p.rel,
            AccessMask::FILE_READ_ATTRIBUTES,
            SHARE_ALL,
            CreateDisposition::OPEN,
            CreateOptions::empty(),
            FileAttributes::empty(),
        ))?
        .push(&close_related())?;
    let r = ctx.exec(chain).await?;
    let c: CreateResponse = decode(&r[0], &p.name)?;
    Ok(Meta::from_create(&c))
}

/// Outcome of the listing compound.
pub(crate) enum Listing {
    /// The path is a directory with these children.
    Dir(Vec<FileInfo>),
    /// The path is a file.
    File(Meta),
}

/// ls: CREATE + QUERY_DIRECTORY ×3 + CLOSE in one round trip.
///
/// The CREATE has no directory option, so a file opens too and is reported
/// as [`Listing::File`]. Only `STATUS_NO_MORE_FILES` proves a listing
/// complete, so after a 1 MiB and a 4 MiB page a small probe page asks
/// once more: up to ~45,000 entries (short names) take one round trip.
/// Larger directories are listed again with an open handle and a
/// QUERY_DIRECTORY loop. The CLOSE is always part of an awaited request, so
/// a later operation on another connection never races it.
pub(crate) async fn list(ctx: &Ctx, p: &SmbPath) -> Result<Listing> {
    let first = list_buffer(ctx, LIST_BUFFER);
    let second = list_buffer(ctx, LIST_BUFFER_2);
    let mut chain = ctx.chain();
    chain.push(&list_open(&p.rel, CreateOptions::empty()))?;
    chain.push(&query_dir(FileId::RELATED, true, first))?;
    chain.push(&query_dir(FileId::RELATED, false, second))?;
    // A small probe that answers STATUS_NO_MORE_FILES when the first two
    // pages held everything.
    chain.push(&query_dir(FileId::RELATED, false, list_buffer(ctx, 4096)))?;
    chain.push(&close_related())?;
    let r = ctx.exec(chain).await?;
    let c: CreateResponse = match decode(&r[0], &p.name) {
        Ok(c) => c,
        // A file held open without read sharing cannot be opened for
        // FILE_LIST_DIRECTORY (= FILE_READ_DATA); an attribute open can.
        Err(e)
            if e.kind() == ErrorKind::PermissionDenied
                && r[0].status() == NtStatus::SHARING_VIOLATION =>
        {
            let m = stat(ctx, p).await?;
            if m.is_dir() {
                return Err(e);
            }
            return Ok(Listing::File(m));
        }
        Err(e) => return Err(e),
    };
    let meta = Meta::from_create(&c);
    if !meta.is_dir() {
        return Ok(Listing::File(meta));
    }
    let mut out = Vec::new();
    if let Page::Done = dir_entries(&r[1], p, &mut out)? {
        return Ok(Listing::Dir(out));
    }
    if let Page::Done = dir_entries(&r[2], p, &mut out)? {
        return Ok(Listing::Dir(out));
    }
    if let Page::Done = dir_entries(&r[3], p, &mut out)? {
        return Ok(Listing::Dir(out));
    }
    list_large(ctx, p).await.map(Listing::Dir)
}

fn list_open(rel: &str, options: CreateOptions) -> CreateRequest {
    create_req(
        rel,
        AccessMask::FILE_LIST_DIRECTORY
            | AccessMask::FILE_READ_ATTRIBUTES
            | AccessMask::SYNCHRONIZE,
        SHARE_ALL,
        CreateDisposition::OPEN,
        options,
        FileAttributes::empty(),
    )
}

/// Listing of a directory too large for the one-round-trip compound: an
/// open handle and QUERY_DIRECTORY until `STATUS_NO_MORE_FILES`.
async fn list_large(ctx: &Ctx, p: &SmbPath) -> Result<Vec<FileInfo>> {
    let buf = list_buffer(ctx, LIST_BUFFER_2);
    let mut chain = ctx.chain();
    chain.push(&list_open(&p.rel, CreateOptions::DIRECTORY_FILE))?;
    chain.push(&query_dir(FileId::RELATED, true, buf))?;
    let r = ctx.exec(chain).await?;
    let c: CreateResponse = decode(&r[0], &p.name)?;
    let fid = c.file_id;
    let mut out = Vec::new();
    let res = async {
        let mut page = dir_entries(&r[1], p, &mut out)?;
        while let Page::More = page {
            let mut chain = ctx.chain();
            chain.push(&query_dir(fid, false, buf))?;
            let r = ctx.exec(chain).await?;
            page = dir_entries(&r[0], p, &mut out)?;
        }
        Ok::<_, Error>(())
    }
    .await;
    let closed = close(ctx, fid, &p.name).await;
    res?;
    closed?;
    Ok(out)
}

/// Send a CLOSE without waiting for its response (errors are irrelevant for
/// a read-only handle; the reader task discards the answer). When credits
/// are available the CLOSE is queued right away, so it reaches the server
/// before any later request of the caller.
pub(crate) fn close_detached(ctx: &Ctx, fid: FileId) {
    use futures::FutureExt;
    let mut chain = ctx.chain();
    if chain
        .push(&CloseRequest {
            flags: CloseFlags::empty(),
            file_id: fid,
        })
        .is_err()
    {
        return;
    }
    let shared = ctx.live.conn.shared.clone();
    let sec = ctx.sec();
    let msgs = chain.into_messages();
    let mut fut = Box::pin(async move {
        let _ = shared.send(msgs, &sec).await;
    });
    if (&mut fut).now_or_never().is_none()
        && let Ok(rt) = tokio::runtime::Handle::try_current()
    {
        rt.spawn(fut);
    }
}

/// QUERY_DIRECTORY output buffer: 1 MiB, within MaxTransactSize (64 KiB on
/// 2.0.2).
fn list_buffer(ctx: &Ctx, want: usize) -> u32 {
    let cap = if ctx.multi_credit() {
        ctx.max_transact()
    } else {
        65536
    };
    ctx.credit_limited(want.min(cap).max(4096)) as u32
}

fn query_dir(file_id: FileId, restart: bool, buf: u32) -> QueryDirectoryRequest {
    QueryDirectoryRequest {
        file_information_class: LIST_CLASS,
        flags: if restart {
            QueryDirectoryFlags::RESTART_SCANS
        } else {
            QueryDirectoryFlags::empty()
        },
        file_index: 0,
        file_id,
        file_name: "*".into(),
        output_buffer_length: buf,
    }
}

enum Page {
    /// Enumeration finished.
    Done,
    /// Entries were returned; more may follow.
    More,
}

/// Append the entries of one QUERY_DIRECTORY response.
fn dir_entries(raw: &RawMessage, dir: &SmbPath, out: &mut Vec<FileInfo>) -> Result<Page> {
    match raw.status() {
        // [MS-SMB2] §3.3.5.18: both end an enumeration (NO_SUCH_FILE when
        // the pattern matches nothing).
        NtStatus::NO_MORE_FILES | NtStatus::NO_SUCH_FILE => return Ok(Page::Done),
        _ => {}
    }
    let q: QueryDirectoryResponse = decode(raw, &dir.name)?;
    let mut any = false;
    for e in q.entries(LIST_CLASS)? {
        let e = e?;
        any = true;
        if e.is_dot_or_dot_dot() {
            continue;
        }
        let name = e.file_name.to_string_lossy();
        out.push(Meta::from_entry(&e).to_info(format!("{}/{name}", dir.name)));
    }
    Ok(if any { Page::More } else { Page::Done })
}

/// CLOSE a handle.
pub(crate) async fn close(ctx: &Ctx, file_id: FileId, path: &str) -> Result<()> {
    let mut chain = ctx.chain();
    chain.push(&CloseRequest {
        flags: CloseFlags::empty(),
        file_id,
    })?;
    let r = ctx.exec(chain).await?;
    let _: CloseResponse = decode(&r[0], path)?;
    Ok(())
}

/// Open a handle.
pub(crate) async fn open(ctx: &Ctx, req: CreateRequest, path: &str) -> Result<CreateResponse> {
    let mut chain = ctx.chain();
    chain.push(&req)?;
    let r = ctx.exec(chain).await?;
    decode(&r[0], path)
}

fn read_data(raw: &RawMessage, path: &str) -> Result<Bytes> {
    if raw.status() == NtStatus::END_OF_FILE {
        return Ok(Bytes::new());
    }
    let rd: ReadResponse = decode(raw, path)?;
    Ok(rd.data)
}

/// One WRITE on an open handle.
pub(crate) async fn write(
    ctx: &Ctx,
    fid: FileId,
    offset: u64,
    data: Bytes,
    path: &str,
) -> Result<()> {
    let len = data.len();
    let mut chain = ctx.chain();
    chain.push(&WriteRequest {
        offset,
        file_id: fid,
        data,
        ..Default::default()
    })?;
    let r = ctx.exec(chain).await?;
    let w: WriteResponse = decode(&r[0], path)?;
    if w.count as usize != len {
        return Err(Error::new(
            ErrorKind::Io,
            format!("short SMB write: {} of {len} bytes", w.count),
        )
        .with_path(path));
    }
    Ok(())
}

/// small cat: CREATE + READ + CLOSE. Returns the open's metadata and the
/// data read at `offset` (at most `len` bytes).
pub(crate) async fn read_small(
    ctx: &Ctx,
    p: &SmbPath,
    share: ShareAccess,
    offset: u64,
    len: usize,
) -> Result<(Meta, Bytes)> {
    let mut chain = ctx.chain();
    chain.push(&read_open_req(&p.rel, share))?;
    if len > 0 {
        chain.push(&ReadRequest {
            length: len as u32,
            offset,
            file_id: FileId::RELATED,
            ..Default::default()
        })?;
    }
    chain.push(&close_related())?;
    let r = ctx.exec(chain).await?;
    let c: CreateResponse = decode(&r[0], &p.name)?;
    let data = if len > 0 {
        read_data(&r[1], &p.name)?
    } else {
        Bytes::new()
    };
    Ok((Meta::from_create(&c), data))
}

/// The CREATE of a file opened for reading (smbclient mode `rb`).
pub(crate) fn read_open_req(rel: &str, share: ShareAccess) -> CreateRequest {
    create_req(
        rel,
        AccessMask::FILE_READ_DATA | AccessMask::FILE_READ_ATTRIBUTES | AccessMask::FILE_READ_EA,
        share,
        CreateDisposition::OPEN,
        CreateOptions::NON_DIRECTORY_FILE,
        FileAttributes::NORMAL,
    )
}

/// The CREATE of a file opened for writing (smbclient modes `wb`/`xb`/`ab`).
pub(crate) fn write_open_req(
    rel: &str,
    share: ShareAccess,
    disposition: CreateDisposition,
) -> CreateRequest {
    create_req(
        rel,
        AccessMask::FILE_WRITE_DATA | AccessMask::FILE_WRITE_ATTRIBUTES | AccessMask::FILE_WRITE_EA,
        share,
        disposition,
        CreateOptions::NON_DIRECTORY_FILE,
        FileAttributes::NORMAL,
    )
}

/// small pipe: CREATE + WRITE + CLOSE (CREATE + CLOSE for empty data).
pub(crate) async fn write_small(
    ctx: &Ctx,
    p: &SmbPath,
    share: ShareAccess,
    disposition: CreateDisposition,
    data: Bytes,
) -> Result<()> {
    let len = data.len();
    let mut chain = ctx.chain();
    chain.push(&write_open_req(&p.rel, share, disposition))?;
    if len > 0 {
        chain.push(&WriteRequest {
            offset: 0,
            file_id: FileId::RELATED,
            data,
            ..Default::default()
        })?;
    }
    chain.push(&close_related())?;
    let r = ctx.exec(chain).await?;
    let _: CreateResponse = decode(&r[0], &p.name)?;
    if len > 0 {
        let w: WriteResponse = decode(&r[1], &p.name)?;
        if w.count as usize != len {
            return Err(Error::new(
                ErrorKind::Io,
                format!("short SMB write: {} of {len} bytes", w.count),
            )
            .with_path(p.name.as_str()));
        }
    }
    check(&r[r.len() - 1], &p.name)
}

/// rm / rmdir: CREATE(DELETE, FILE_OPEN_REPARSE_POINT) +
/// SET_INFO(FileDispositionInformation) + CLOSE, like smbclient's `_delete`
/// (a symlink is removed itself, not its target). `directory`: `Some(true)`
/// for rmdir, `Some(false)` for files only, `None` for either (fsspec's
/// `rm_file` removes empty directories too).
///
/// A read-only file (`STATUS_CANNOT_DELETE`) has its attribute cleared
/// first, as smbclient does, in a second round trip.
pub(crate) async fn delete(ctx: &Ctx, p: &SmbPath, directory: Option<bool>) -> Result<()> {
    let mut options = CreateOptions::OPEN_REPARSE_POINT;
    match directory {
        Some(true) => options |= CreateOptions::DIRECTORY_FILE,
        Some(false) => options |= CreateOptions::NON_DIRECTORY_FILE,
        None => {}
    }
    let open = |access| {
        create_req(
            &p.rel,
            access,
            SHARE_ALL,
            CreateDisposition::OPEN,
            options,
            FileAttributes::empty(),
        )
    };
    let disposition = SetInfoRequest::new(
        FileId::RELATED,
        &FileDispositionInformation {
            delete_pending: true,
        },
    )?;
    let mut chain = ctx.chain();
    chain
        .push(&open(AccessMask::DELETE | AccessMask::FILE_READ_ATTRIBUTES))?
        .push(&disposition)?
        .push(&close_related())?;
    let r = ctx.exec(chain).await?;
    let c: CreateResponse = decode(&r[0], &p.name)?;
    if r[1].status() != NtStatus::CANNOT_DELETE
        || !c.file_attributes.contains(FileAttributes::READONLY)
    {
        check(&r[1], &p.name)?;
        return check(&r[2], &p.name);
    }
    let mut attrs = c.file_attributes - FileAttributes::READONLY;
    if attrs.is_empty() {
        attrs = FileAttributes::NORMAL;
    }
    let basic = SetInfoRequest::new(
        FileId::RELATED,
        &FileBasicInformation {
            file_attributes: attrs,
            ..Default::default()
        },
    )?;
    let mut chain = ctx.chain();
    chain
        .push(&open(
            AccessMask::DELETE
                | AccessMask::FILE_READ_ATTRIBUTES
                | AccessMask::FILE_WRITE_ATTRIBUTES,
        ))?
        .push(&basic)?
        .push(&disposition)?
        .push(&close_related())?;
    let r = ctx.exec(chain).await?;
    for m in &r {
        check(m, &p.name)?;
    }
    Ok(())
}

/// mkdir of one directory: CREATE(directory, `disposition`) + CLOSE.
pub(crate) async fn mkdir_one(
    ctx: &Ctx,
    p: &SmbPath,
    disposition: CreateDisposition,
) -> Result<()> {
    let mut chain = ctx.chain();
    chain
        .push(&create_req(
            &p.rel,
            AccessMask::FILE_READ_ATTRIBUTES,
            SHARE_ALL,
            disposition,
            CreateOptions::DIRECTORY_FILE,
            FileAttributes::DIRECTORY,
        ))?
        .push(&close_related())?;
    let r = ctx.exec(chain).await?;
    check(&r[0], &p.name)?;
    check(&r[1], &p.name)
}

/// mv: CREATE(src, DELETE) + SET_INFO(FileRenameInformation) + CLOSE.
/// `dst_rel` is the destination below the share root.
pub(crate) async fn rename(ctx: &Ctx, src: &SmbPath, dst: &SmbPath, replace: bool) -> Result<()> {
    let set = SetInfoRequest::new(
        FileId::RELATED,
        &FileRenameInformation {
            replace_if_exists: replace,
            root_directory: 0,
            file_name: dst.rel.clone(),
        },
    )?;
    let mut chain = ctx.chain();
    chain
        .push(&create_req(
            &src.rel,
            AccessMask::DELETE | AccessMask::FILE_READ_ATTRIBUTES,
            SHARE_ALL,
            CreateDisposition::OPEN,
            CreateOptions::OPEN_REPARSE_POINT,
            FileAttributes::empty(),
        ))?
        .push(&set)?
        .push(&close_related())?;
    let r = ctx.exec(chain).await?;
    check(&r[0], &src.name)?;
    check(&r[1], &dst.name)?;
    check(&r[2], &src.name)
}

/// touch without truncation: CREATE(OPEN_IF) + SET_INFO(last write and
/// access time = now) + CLOSE; creates a missing file empty.
pub(crate) async fn touch(ctx: &Ctx, p: &SmbPath) -> Result<()> {
    let now = FileTime::now();
    let set = SetInfoRequest::new(
        FileId::RELATED,
        &FileBasicInformation {
            last_access_time: now,
            last_write_time: now,
            ..Default::default()
        },
    )?;
    let mut chain = ctx.chain();
    chain
        .push(&create_req(
            &p.rel,
            AccessMask::FILE_WRITE_ATTRIBUTES | AccessMask::FILE_READ_ATTRIBUTES,
            SHARE_ALL,
            CreateDisposition::OPEN_IF,
            CreateOptions::NON_DIRECTORY_FILE,
            FileAttributes::NORMAL,
        ))?
        .push(&set)?
        .push(&close_related())?;
    let r = ctx.exec(chain).await?;
    for m in &r {
        check(m, &p.name)?;
    }
    Ok(())
}

/// Truncate or extend an open file (FileEndOfFileInformation).
pub(crate) async fn set_end_of_file(ctx: &Ctx, fid: FileId, eof: u64, path: &str) -> Result<()> {
    let mut chain = ctx.chain();
    chain.push(&SetInfoRequest::new(
        fid,
        &FileEndOfFileInformation { end_of_file: eof },
    )?)?;
    let r = ctx.exec(chain).await?;
    check(&r[0], path)
}
