# ADR-0001: A handle-based core contract with capability flags

- Status: accepted
- Date: 2026-11-24

## Context

fsfast has to serve two very different protocol families behind one fsspec
API:

- **Stateless object stores** (S3, GCS, Azure Blob, HTTP): every request names
  the object by path; random access is a ranged GET.
- **Stateful file protocols** (SMB, SFTP, local, NFS later): performance comes
  from an open handle, from pipelining many reads/writes on it, and from
  compounding (SMB CREATE+READ+CLOSE in one round trip).

The object-store-shaped abstractions in the Rust ecosystem (`object_store`,
OpenDAL) are path-only. Mapping SMB/SFTP onto them forces an open/close per
request and throws away the protocols' main performance levers.

## Decision

`fsfast-core` defines three async traits (`async_trait`, boxed futures,
object-safe so the Python bindings can hold `Arc<dyn FileSystem>`):

- `FileSystem`: path-level operations (`info`, `ls`, `find`, `cat_file`,
  `cat_ranges`, `pipe_file`, `rm_file(s)`, `mkdir`, `rmdir`, `cp_file`,
  `mv_file`, `put_file`, `get_file`, `touch`, `sign`) plus `open_read` and
  `open_write`.
- `ReadHandle`: `read_at(offset, len)` and `read_ranges`, safe to call
  concurrently. Object stores implement it as "key + version token" and pin
  reads with `If-Match`/generation; stateful protocols keep a real handle.
- `WriteHandle`: `write`/`flush`/`close`/`abort`. Object stores upload parts
  concurrently; hierarchical filesystems write progressively.

Every path-level method has a correct default built on the handles, so a new
backend works as soon as it implements the required methods. Backends then
override the defaults with native fast paths (server-side copy, batch delete,
compounding, suffix ranges).

`Capabilities` flags (hierarchical, atomic rename, server-side copy, append,
conditional create, pinned reads, ...) and `IoHints` (request size,
concurrency, coalescing gap) let the engine and the Python layer pick
strategies without naming backends.

Other conventions fixed here:

- Paths are fsspec-style protocol-stripped strings. URL/protocol parsing stays
  in Python, which reuses the reference implementations' `_strip_protocol`.
- `FileInfo` carries the reference implementation's native `info()` keys in
  `extra`, so user code that reads `info()["ETag"]` keeps working.
- One `Error` type with an `ErrorKind` that maps 1:1 onto Python exception
  types, plus a native `Detail` (HTTP status, NTSTATUS, SFTP status, errno).
- Backends are built from `storage_options` through a strict `OptionReader`:
  unknown options are errors, and compatibility-only options must be accepted
  explicitly.

## Consequences

- SMB and SFTP can pipeline and compound; object stores pay nothing extra
  (a handle is a struct holding a key and an ETag).
- Boxed futures cost an allocation per call. That is negligible next to any
  I/O and buys object safety.
- Directory semantics differ by backend; the conformance suite reads
  `Capabilities` to decide what to expect.
