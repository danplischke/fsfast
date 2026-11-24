# fsfast — Project Plan

> A Rust engine for the most important fsspec filesystems. It plugs into existing
> Python code without changes, has complete protocol support, and every
> performance claim is backed by a benchmark.

Status: draft v1 · 2026-11-24

---

## 0. Summary

- **What we ship:** a Rust core (a Cargo workspace) exposed to Python as a
  native extension (PyO3, built with maturin, abi3 wheels plus free-threaded
  wheels). It provides `fsspec.AbstractFileSystem` subclasses that replace
  `s3fs`, `gcsfs`, `adlfs` and fsspec's built-in `http`, `smb`, `sftp`, `ftp`
  and `local` filesystems without code changes. The same core also builds a
  standalone `fsf` CLI, which we use for benchmarks and copying.
- **The core idea:** speeding up the per-request calls alone gains almost
  nothing. obstore found this when it put Rust behind fsspec's adapter. Their
  docs call the fsspec route a "last resort" that is "unlikely to yield
  performance improvements". fsspec's sync↔async bridge, its Python file
  objects and its Python caches use up the gains. **We therefore own the whole
  path in Rust:** the public sync methods, the async methods, the file objects,
  the caches and the I/O scheduling. Only a thin Python class stays, so that
  `isinstance` checks, the protocol registry and pickling keep working.
- **Handle-based core, not object-store-shaped.** SMB and SFTP get their speed
  from stateful handles, pipelining and compounding. A path-only object-store
  abstraction (the model used by object_store and OpenDAL) cannot express
  that. Object stores map onto handles cheaply: a handle is a key plus an
  ETag or generation.
- **The first filesystems, in order:** `local`/`memory` (the foundation), then
  **HTTP(S)**, **S3**, **SMB 2/3** (our flagship, on its own parallel track),
  **GCS**, **Azure Blob/ADLS Gen2** and **SFTP**. Tier 2 is the reference
  filesystem (kerchunk), zip/tar, Hugging Face, FTP/FTPS, WebDAV and HDFS.
- **Compliance has two layers:** (1) wire-protocol conformance, traced back to
  the specs (MS-SMB2, the RFCs, the cloud API docs), and (2) fsspec semantic
  conformance: we behave exactly like `s3fs`/`gcsfs`/… as user code observes
  it. We check this with fsspec's abstract test suite, the upstream projects'
  own test suites and differential testing.
- **Benchmarks come first.** Phase 0 measures and profiles today's fsspec
  stack before we write any backend code. Every later milestone has numeric
  exit criteria, compared both with fsspec and with the best native tool for
  that protocol (s5cmd/CRT, the kernel CIFS client, OpenSSH `sftp`, azcopy,
  and so on).

---

## 1. Goals and non-goals

### Goals
1. **Drop-in fsspec compatibility.** Same protocols, same `storage_options`
   names, the same `info()` dict keys, error types and directory semantics as
   the reference implementations. Works with pandas, xarray/zarr (v3 async
   store), pyarrow (through `FSSpecHandler`), dask, polars and duckdb (fsspec
   registration).
2. **Performance close to the hardware limit.** For large transfers, aim for
   line rate or the best native tool. For small operations, cut the
   per-operation CPU and round trips by an order of magnitude.
3. **Complete protocol support** for each backend we ship, written down as a
   traceability matrix from spec requirement to test.
4. **Secure defaults:** TLS verification on, strict SSH host-key checking, no
   SMB dialect downgrade, no NTLMv1 and no SMB1.
5. **Reproducible benchmarks**, published continuously, with regression gates
   in CI.

### Non-goals (for 1.0)
- SMB1/CIFS, SMB Direct (RDMA) and ADLS Gen1 (`adl://`, retired Feb 2024).
- A FUSE mount, a sync daemon or a GUI.
- Replacing obstore's native API. We are fsspec-first; a native Rust and
  Python API exists, but it is secondary.
- Wrapping GPL C libraries (for example `libsmbclient`). The wheel stays
  permissively licensed.

---

## 2. Why fsspec leaves performance on the table (hypotheses for Phase 0)

We profile each hypothesis with `py-spy --native`, request counters and
packet captures before building anything:

| # | Hypothesis | Where it shows up | How we fix it |
|---|---|---|---|
| H1 | **Per-request Python CPU.** For every request, botocore builds, serializes, signs and parses the XML response in Python (s3fs → aiobotocore). gcsfs and adlfs have similar layers. | small GET/HEAD/LIST, listings of millions of keys | Native request building, signing and XML/JSON parsing (≈µs per request) |
| H2 | **The sync bridge.** Each sync call goes through `fsspec.asyn.sync()`: the coroutine is posted to an event-loop thread, the caller waits on a threading event, and both sides contend for the GIL. | every sync API call, worse with many threads | The GIL is released and a Rust future is awaited directly. There is no asyncio on the sync path. |
| H3 | **File objects and caches in Python.** `AbstractBufferedFile` and its caches fetch one block at a time when a read misses the cache. They do not pipeline prefetches, and bytes are sliced and concatenated, which copies them. | `open()` and `read()` loops, Parquet footers, CSV streaming | A Rust file object with adaptive readahead, range coalescing and `readinto` with zero extra copies |
| H4 | **Concurrency limited to coarse batches.** Bulk calls use gather with `batch_size`. A single large object is never fetched as parallel ranged GETs. Uploads through file objects upload one part per flush. | large single-file reads, uploads through `open('wb')` | Automatic parallel ranged GETs, concurrent multipart upload under a global memory budget |
| H5 | **Protocol stacks written in pure Python** (smbprotocol, paramiko, ftplib): framing and credit/window handling happen in Python, with little or no request pipelining. | SMB and SFTP throughput, small-file storms | Native protocol clients with credit-window and request pipelining, compounding |
| H6 | **Round trips for metadata.** For example, `info()` on an object store can take HEAD followed by LIST. On SMB, an open-stat-close sequence costs several round trips. `glob` expands to a full `find`. | `exists`, `isdir`, `info`, `glob` | SMB compounding, speculative HEAD+LIST in parallel, glob that lists only the matching prefix |
| H7 | **Copies and allocations** along the path socket → aiohttp buffer → `bytes` → `BytesIO` → caller. | high-throughput reads | One copy into `bytes`, or zero extra copies into a caller buffer, with decryption in place for SMB |

Phase 0 output: a short report that attributes the time per workload (where
the time goes: network, Python CPU, waiting on the GIL, serialization). It
tells us which of these matter most for each backend.

---

## 3. Prior art and positioning

| Project | What it is | How fsfast relates |
|---|---|---|
| **obstore** (Development Seed, Rust `object_store`; ~13M downloads/mo) | Fast, stateless object-store API for S3, GCS and Azure; its fsspec adapter is "best effort" | It shows that Rust only pays off if fsspec's own machinery is bypassed. We aim for full fsspec fidelity and more protocols. It is a benchmark baseline. |
| **fsspec-rs** (1kbgz, v0.4) | fsspec classes backed by Rust; local + S3 only | Early-stage, narrow scope. Baseline only. |
| **rfsspec** (Martin Durant, the fsspec author) | Experimental Rust S3/GCS/Azure/HTTP for fsspec | Appears inactive. It confirms that the idea is sound (~4× faster on S3 in its own numbers). |
| **OpenDAL** (Python bindings) | Broad set of services, its own API | Path-only, object-store-shaped model; no SMB. Not fsspec. |
| **pyarrow.fs** | C++ S3, GCS, Azure and HDFS | Strong baseline for large reads. API built around Arrow, not fsspec. |
| **hdfs-native** | Pure-Rust HDFS client with an fsspec layer | **We reuse it** as our HDFS backend instead of writing our own. |
| **smb-rs** (`smb` crate 0.12) | Pure-Rust SMB2/3 client (TCP/NetBIOS/QUIC, NTLM/Kerberos through `sspi`) | We use it as a reference implementation and a differential-interop oracle. We evaluate it in Phase 0 (see §6.5). |
| **AWS CRT (`aws-c-s3`)**, s5cmd | State of the art for S3 throughput | The ceilings we compare against. We adopt their techniques: spreading connections across resolved IPs, automatic ranged GETs. |

**What makes fsfast different:** (1) end-to-end fsspec fidelity in Rust, not
just faster primitives; (2) a core built around file handles, which stateful
protocols need; (3) one shared I/O engine (coalescing, prefetch, caching,
adaptive concurrency) behind every backend; (4) compliance first, with a
published interop matrix and continuous benchmarks.

---

## 4. Architecture

### 4.1 Layers

```
 Python user code (pandas, xarray/zarr, pyarrow, dask, duckdb, …)
        │  fsspec API (sync + async)
 ┌──────▼─────────────────────────────────────────────────────────┐
 │ python/fsfast: thin AbstractFileSystem / AsyncFileSystem        │
 │ subclasses, registry hooks, pickling, option translation         │
 └──────┬─────────────────────────────────────────────────────────┘
        │  PyO3 (GIL released; async → asyncio futures)
 ┌──────▼─────────────────────────────────────────────────────────┐
 │ fsfast-py: Rust FileSystem/File objects, buffer protocol,       │
 │ error mapping, runtime ownership, fork safety                    │
 ├─────────────────────────────────────────────────────────────────┤
 │ fsfast-engine: range coalescing · adaptive readahead ·          │
 │ automatic ranged GET · multipart · memory budget · AIMD          │
 │ concurrency · retries/hedging · batch ops                        │
 │ fsfast-cache: memory block LRU · disk block cache · whole-file   │
 ├─────────────────────────────────────────────────────────────────┤
 │ fsfast-core: FileSystem / ReadHandle / WriteHandle traits,      │
 │ FileInfo, Capabilities, paths & URL chaining, errors, config     │
 ├──────────┬──────────┬──────────┬──────────┬──────────┬──────────┤
 │ local    │ http     │ s3       │ gcs      │ azure    │ smb      │ sftp · ftp · webdav · hdfs · zip/tar · reference
 │ memory   │  └─ fsfast-http-transport (hyper, rustls, multi-IP pool)│
 └──────────┴─────────────────────────────────────────────────────┘
```

### 4.2 Workspace layout

```
crates/
  fsfast-core/            traits, FileInfo, Capabilities, Path/URL model, errors, config
  fsfast-engine/          I/O scheduler (see 4.5)
  fsfast-cache/           memory + disk block caches, whole-file cache
  fsfast-http-transport/  hyper 1.x client, custom pool/connector, TLS, proxy, retry policy
  fsfast-local/  fsfast-memory/
  fsfast-http/   fsfast-s3/  fsfast-gcs/  fsfast-azure/  fsfast-webdav/
  fsfast-smb-proto/       I/O-free codec: MS-SMB2 messages, MS-FSCC info classes, MS-XCA compression
  fsfast-smb/             SMB client: transport, session, tree, credits, crypto, DFS, handles
  fsfast-sftp/            SFTP v3 codec + client on russh
  fsfast-ftp/  fsfast-archive/ (zip, tar)  fsfast-reference/  fsfast-hdfs/ (wraps hdfs-native)
  fsfast-testkit/         backend conformance suite, fault injection, golden FileInfo schemas
  fsfast-bench/           macro-benchmark runner (Rust side)
  fsfast-cli/             `fsf` binary: ls/cat/cp/sync/bench
  fsfast-py/              PyO3 module `fsfast._core`
python/fsfast/            fsspec subclasses, registration, .pyi stubs
bench/                    workloads, docker-compose emulators, netem scripts, baseline runners
docs/                     this plan, ADRs (docs/adr/), compliance matrices
```

### 4.3 Core abstractions (sketch)

```rust
pub trait FileSystem: Send + Sync + 'static {
    fn capabilities(&self) -> &Capabilities;          // hierarchical? atomic rename? server copy?
    async fn info(&self, p: &FsPath) -> Result<FileInfo>;
    fn list(&self, p: &FsPath, o: ListOptions) -> BoxStream<'_, Result<FileInfo>>; // streaming; recursive or delimited
    async fn open_read(&self, p: &FsPath, o: ReadOptions) -> Result<Arc<dyn ReadHandle>>;
    async fn open_write(&self, p: &FsPath, o: WriteOptions) -> Result<Box<dyn WriteHandle>>;
    async fn delete_many(&self, ps: &[FsPath], o: DeleteOptions) -> Vec<Result<()>>; // batched natively where possible
    async fn copy(&self, src: &FsPath, dst: &FsPath, o: CopyOptions) -> Result<()>;   // server-side when possible
    async fn rename(&self, src: &FsPath, dst: &FsPath) -> Result<()>;
    async fn mkdir(&self, p: &FsPath, parents: bool) -> Result<()>;
    // Defaulted helpers that backends override when they can do better:
    async fn read_ranges(&self, p: &FsPath, r: &[Range<u64>]) -> Result<Vec<Bytes>>;
    async fn put_bytes(&self, p: &FsPath, data: Bytes, o: WriteOptions) -> Result<()>;
    async fn get_bytes(&self, p: &FsPath, r: Option<Range<u64>>) -> Result<Bytes>;
}

pub trait ReadHandle: Send + Sync {
    fn size(&self) -> u64;
    fn version(&self) -> Option<&Version>;            // ETag / generation / SMB file id: reads are pinned
    fn preferred_io(&self) -> IoHints;                // ideal request size, max in-flight requests
    async fn read_at(&self, off: u64, dst: &mut ReadBuf<'_>) -> Result<usize>; // writes into caller memory
    async fn read_vectored(&self, r: &[Range<u64>]) -> Result<Vec<Bytes>>;
}
```

Key decisions:
- **`FileInfo` is typed, plus a per-backend "native fields" map.** The Python
  layer turns it into exactly the dict keys the reference implementation
  returns: s3fs `ETag`/`LastModified`/`VersionId`, gcsfs
  `generation`/`md5Hash`, adlfs `etag`/`last_modified`, and so on. We check
  these against recorded "golden" schemas.
- **Reads are pinned to a version.** Once opened, a handle reads with
  `If-Match`/generation preconditions, so a concurrent overwrite produces a
  clean error instead of mixed bytes. fsspec does not do this today. It is
  on by default and can be turned off.
- **Capabilities drive strategy.** The engine picks coalescing gaps, request
  sizes, prefetch depth and the delete/copy paths from capabilities and IO
  hints, not from backend-specific code.
- **Paths and URLs** reproduce each fsspec protocol's
  `_strip_protocol`/`_get_kwargs_from_urls` behaviour, plus URL chaining
  (`blockcache::s3://…`, `zip://a.csv::s3://bucket/x.zip`) with storage
  options for each protocol in the chain.

### 4.4 Runtime and the Python bridge

- **One tokio multi-thread runtime per process**, created lazily. Its size
  follows the CPU count and can be configured. Fork safety: `os.register_at_fork`
  plus a PID check rebuild the runtime and the connection pools in the child,
  because Dask and multiprocessing fork.
- **Sync API:** release the GIL, run the Rust future, return. There is no
  event loop, no thread hop through Python, and no `fsspec.asyn.sync`.
  Phase 0 decides by measurement whether we drive the future on the calling
  thread with `Handle::block_on` or use a oneshot channel.
- **Async API:** the `_cat_file`, `_cat_ranges`, `_info`, … coroutines
  return asyncio futures through `pyo3-async-runtimes`. The class sets
  `async_impl = True`, so zarr v3's `FsspecStore` uses it natively. We
  override every public sync method, so fsspec's `mirror_sync_methods`
  never wraps them.
- **Batch APIs amortize the boundary crossing:** `cat(paths)`,
  `cat_ranges`, `info_many`, `rm(paths)`, `put/get(lists)`. Each is a single
  Rust call that fans out internally.
- **Buffers:**
  - Default `bytes` results are built with `PyBytes::new_with`: one copy,
    straight from the network buffer.
  - `readinto(buf)` and the opt-in `fsfast.Buffer` (buffer protocol over
    `Bytes`) avoid any extra copy.
  - SMB decrypts AES-GCM directly into the destination buffer.
- **Free-threaded CPython (3.13t/3.14t):** the module is declared
  `gil_used = false` from day one, and all state is `Send + Sync`.
- **The Python class layer is thin.** It inherits from fsspec's
  `AsyncFileSystem`, so instance caching/tokenization,
  `fsspec.filesystem()`, `url_to_fs`, `get_mapper` and pickling via
  `__reduce__` (with lazy reconnect) all keep working. Python never touches
  the data path.
- **Registration:** opt-in, so behaviour never changes by surprise:
  - `fsfast.install(["s3", "gcs", ...])` or the environment variable
    `FSFAST_OVERRIDE=s3,gcs` swaps the implementations in fsspec's registry.
  - The classes can also be imported directly (`fsfast.S3FileSystem`).
  - Entry points (`fsspec.specs`) register `fsfast-*` aliases.

### 4.5 I/O engine (the shared performance layer)

| Feature | Behaviour |
|---|---|
| **Range coalescing** | Merges vectored reads whose gap is under a threshold (backend-tuned, e.g. 1 MiB for S3, ~0 for SMB/local) and splits merged ranges larger than the ideal request size. Used by `cat_ranges`, Parquet footers, and zarr/kerchunk chunk reads. |
| **Adaptive readahead** | Detects sequential reads per file handle. The window doubles (Linux-style) up to a cap, with several requests in flight. It shrinks again on random access. |
| **Automatic ranged GET** | A large read is split into parts of 8–16 MiB, fetched over several connections and reassembled in order (the technique AWS CRT uses). Concurrency is derived from a configurable `target_throughput`. |
| **Multipart/parallel upload** | Parts upload concurrently under a memory budget. Part size adapts to the object size and stays within the API limits. Checksums (CRC32C/CRC64NVME) are computed while streaming, with hardware acceleration. |
| **Global memory budget** | A byte semaphore across prefetch, multipart and cache fills. Under pressure, the engine reduces concurrency instead of running out of memory. |
| **Adaptive concurrency** | AIMD per endpoint: 503 SlowDown / 429 / latency inflation lowers concurrency, success raises it. Separate limits apply per host and per bucket prefix. |
| **Retries** | The transport classifies errors as retryable or not; exponential backoff with full jitter; idempotency-aware. Server `Retry-After` hints are honoured. |
| **Hedged requests** | Optional (they cost extra requests): when a small GET is slower than p95, a duplicate request is sent and the first response wins. Reduces tail latency on object stores. |
| **Batching** | Native batch deletes (S3 DeleteObjects with 1000 keys), concurrent HEADs for `info_many`, SMB compound chains. |
| **Parallel listing** | Splits a listing by delimiter-discovered prefixes, or by key-range sharding with `start-after` for flat buckets. Results are merged into stable, sorted order and streamed to Python. |

### 4.6 Caching (`simplecache`, `filecache` and `blockcache`, implemented natively)

- **Memory block cache:** a sharded LRU shared by all open files, within the
  global memory budget.
- **Disk block cache:** sparse block files keyed by (canonical URL,
  version). It is safe to share across processes (atomic renames, lock
  files), which suits several Dask workers on one node, unlike fsspec's JSON
  metadata file.
- **Whole-file cache:** `simplecache` semantics. Entries are validated by
  ETag/generation/mtime, with a configurable time-to-live.
- **Metadata cache:** directory listings and file info, matching fsspec
  `dircache` semantics (`use_listings_cache`, `listings_expiry_time`,
  `invalidate_cache`). It is invalidated on our own writes.
- All of these are reachable through fsspec's chained-URL syntax.

### 4.7 Errors, configuration, observability, security

- **Errors** map to `FileNotFoundError`, `PermissionError`,
  `FileExistsError`, `IsADirectoryError`, `NotADirectoryError`,
  `TimeoutError` and `OSError(errno)`, matching what each reference
  implementation raises. The backend detail (HTTP status, NTSTATUS, SFTP
  status) is attached as attributes.
- **Configuration:**
  - Each backend has a translation table from the reference package's
    `storage_options` (s3fs `key`/`secret`/`endpoint_url`/`client_kwargs`/
    `config_kwargs`/`requester_pays`/`version_aware`/
    `s3_additional_kwargs`, etc.) to typed Rust configuration.
  - **Unknown or unsupported options fail loudly** instead of being silently
    ignored.
  - The standard environment variables are respected (`AWS_*`, `HTTPS_PROXY`,
    `NO_PROXY`, `SSL_CERT_FILE`, …).
- **Observability:**
  - `tracing` spans for every operation and request.
  - `fs.stats()` exposes request, byte, retry and throttle counters and
    latency histograms per operation.
  - OpenTelemetry export is optional.
  - Request counts matter because they are cloud cost, and the benchmarks
    report them.
- **Security:**
  - TLS: rustls with aws-lc-rs and the OS trust store (`rustls-platform-verifier`).
    certifi or a custom CA can be used instead.
  - Credentials are zeroized and never logged.
  - Unsafe options (no TLS verify, accept unknown host keys, no SMB signing)
    are explicit and loud.

### 4.8 Key dependencies (recommended)

| Need | Choice | Notes |
|---|---|---|
| Async runtime | tokio | |
| HTTP | hyper 1.x + hyper-util, our own connector/pool | We need control over spreading connections across IPs (hickory-resolver), pool sizing and HTTP/2 for GCS |
| TLS | rustls + aws-lc-rs | Fast AES-GCM; a FIPS build is possible |
| AWS auth | `aws-sigv4` + `aws-config` (credential chain) | Complete chain: SSO, IRSA, ECS, IMDSv2, credential_process. Signing is ours, through the official crate. |
| GCP/Azure auth | official `google-cloud-auth`, `azure_identity` | Evaluated in Phase 0 for weight and completeness; fallback is a thin implementation of our own |
| XML/JSON | quick-xml (borrowed parsing), serde_json | Listing parse speed matters |
| SMB/NTLM/Kerberos | `sspi` (pure Rust SPNEGO/NTLM/Kerberos), optional system GSSAPI | Uses the existing `kinit` ticket cache and keytabs on Linux/macOS |
| SMB crypto | aws-lc-rs (AES-GCM), RustCrypto `aes`/`ccm`/`cmac` | Hardware AES |
| SMB compression | Our own MS-XCA implementation (LZ77, LZ77+Huffman, LZNT1, Pattern_V1) | No solid crates exist |
| SSH | `russh` (pure Rust, async) + our own SFTP codec | Phase 0 spike measures channel throughput against OpenSSH |
| HDFS | `hdfs-native` | Reused, not reimplemented |
| Checksums | `crc32c`, `crc-fast` (CRC64NVME), `md-5`, `sha2` | |
| Python | pyo3, pyo3-async-runtimes, maturin | abi3 (3.10+) plus separate free-threaded wheels |
| Allocator | mimalloc (feature flag) | |
| Testing | proptest, cargo-fuzz, criterion, testcontainers; pytest, hypothesis | |

---

## 5. Filesystem priorities

Ranking criteria: **(a) usage**, **(b) the size of today's performance gap**
(how much time goes to Python overhead or a pure-Python protocol stack),
**(c) strategic value** (it is the flagship, it underpins other backends, or
nobody else does it well), and **(d) effort**.

PyPI downloads, last 30 days (pypistats, 2026-11-24): s3fs **259M**, gcsfs
**30M**, adlfs **11M**, smbprotocol **8M** (not all of it through fsspec),
paramiko **113M** (mostly not through fsspec), webdav4 **0.4M**, ocifs 0.26M,
hdfs-native 14k. fsspec itself has 587M. HTTP and local are built in, so
there is no separate signal for them, but they are used everywhere.

### Tier 0: foundations (they ship first, other backends depend on them)

| FS | Protocols | Why |
|---|---|---|
| **Local** | `file`, `local` | The other end of every `get`/`put`, a performance reference, and the fixture for our conformance suite. Fast paths: `copy_file_range`/`clonefile`/reflink, large aligned I/O, parallel directory walk. |
| **Memory** | `memory` | The test oracle and a fast scratch space. |

### Tier 1: the launch set (in build order)

| # | FS | Replaces | Usage | Gap | Effort | Why this position |
|---|---|---|---|---|---|---|
| 1 | **HTTP(S)** | fsspec `http`/`https` (aiohttp) | built in, everywhere | Med | M | The simplest HTTP backend. It forces us to build the shared transport and engine (ranged reads, coalescing, readahead) on an easy target. Public datasets, presigned URLs, COG/Zarr over HTTP. |
| 2 | **S3** (+ S3-compatible: MinIO, R2, Ceph, Wasabi, OCI/OSS compatibility endpoints) | `s3fs` | **259M/mo** | **High** (botocore is CPU-heavy) | L | By far the most used. The biggest absolute win. |
| 3 | **SMB 2/3** | fsspec `smb` (smbprotocol) | 8M/mo, enterprise | **Very high** (pure Python, no pipelining) | **XL** | **The flagship.** The largest gap, nobody ships a fast and compliant SMB client for Python, and you asked for it. It runs on a parallel track from Phase 1 because it is the longest task. |
| 4 | **GCS** | `gcsfs` | 30M/mo | High | M | Reuses the transport and engine. Adds the JSON API, the XML multipart API, HTTP/2 and generations. |
| 5 | **Azure Blob + ADLS Gen2** | `adlfs` (`abfs`, `az`) | 11M/mo | High | M–L | Two APIs (Blob plus the DFS endpoint for the hierarchical namespace: real directories, atomic rename). Many authentication modes. |
| 6 | **SFTP** | fsspec `sftp` (paramiko), `sshfs` (asyncssh) | broad in ingestion pipelines | **High** (paramiko is far slower than OpenSSH) | L | A common pain point in ETL. Pipelined SFTP can match OpenSSH. |

Cross-cutting tier-1 features: the caching layer (§4.6), URL chaining, and
`compression=` codecs (gzip with zlib-rs, zstd, bz2, xz, lz4, snappy).

### Tier 2: after the launch set

| # | FS | Replaces | Why |
|---|---|---|---|
| 7 | **Reference FS** (kerchunk/VirtualiZarr) | fsspec `reference` | It is a meta-filesystem whose cost is almost entirely Python per-chunk overhead. Rust coalescing across thousands of chunk references gives very large wins for xarray/zarr. Parses JSON and Parquet reference files. |
| 8 | **Zip / Tar** (over any backend) | fsspec `zip`, `tar` | Reads the zip central directory with one ranged read from the end of the file (Zip64 supported). Stored entries are read directly with ranges. Makes Zarr-in-zip practical on remote storage. |
| 9 | **Hugging Face** (`hf://`) | `huggingface_hub.HfFileSystem` | Very high usage (~297M/mo for the package). Gains come from listing, metadata and HTTP ranged reads. For Xet-backed storage we coordinate with `hf_xet` (already Rust) instead of duplicating it. |
| 10 | **FTP/FTPS** | fsspec `ftp` (ftplib) | Older systems, but common in science and government (NOAA, NCBI) and in enterprises. Supports MLSD, EPSV, REST, AUTH TLS and parallel data connections. |
| 11 | **WebDAV** | `webdav4` | Nextcloud/ownCloud/generic DAV. Built cheaply on the shared transport: PROPFIND with Depth control, chunked uploads. |
| 12 | **HDFS** | fsspec `hdfs`/`arrow_hdfs`/`webhdfs` | **We wrap the `hdfs-native` crate** (Kerberos, HA, EC). The work is integration only. |

### Tier 3: opportunistic, driven by demand
Native OCI, Alibaba OSS, Tencent COS and Volcengine TOS signing (their
S3-compatible endpoints already work from Tier 1), **NFSv4.1** (a
user-space client; no fsspec implementation exists today, so this would be
new), XRootD (`root://`, physics), and cloud drives (Dropbox, Google Drive,
OneDrive/SharePoint through Graph).

### Explicitly not doing
SMB1, ADLS Gen1 (`adl`), `dask`/`jupyter`/`git`/`github` (performance does
not matter for them), and `libarchive` (zip/tar cover the common cases).

---

## 6. Per-filesystem plans

Each backend is finished when it meets the "Definition of done" in §6.8.

### 6.1 Local and memory
- `info` uses `statx`, `ls` uses `getdents` with a parallel walk for `find`
  and `du`. `copy` uses `copy_file_range`, or `clonefile` on macOS and
  reflink on Btrfs/XFS. Large `get`/`put` stream with aligned buffers.
  io_uring stays an experiment behind a flag.
- Windows: long paths (`\\?\`), UNC paths, case insensitivity, and the
  fsspec path conventions.

### 6.2 HTTP(S)
- `info` uses HEAD, falling back to `GET Range: bytes=0-0` when HEAD is
  missing or wrong. Fallback chain for the size: Content-Length, then
  Content-Range, then reading the whole body.
- Detects whether the server supports ranges (`Accept-Ranges` and a probe).
  Without range support, reads are buffered sequentially.
- Directory listing works like fsspec, by scraping links from HTML index
  pages, and the regex is compatible.
- Handles redirects (keeping authentication only on the same origin),
  `Content-Encoding` (fsspec semantics: compressed sizes), HTTP/2 when
  negotiated, cookies, and custom headers and auth per request through
  `client_kwargs`.

### 6.3 S3
- **Operations:** ListObjectsV2 and ListObjectVersions, Head/Get (ranges,
  `versionId`, SSE-C, requester pays), Put, the full multipart lifecycle,
  CopyObject and UploadPartCopy (for copies over 5 GB), DeleteObjects
  (1000 keys per call, concurrent), bucket list/create/delete, tagging,
  ACL get/put (s3fs parity) and presigned URLs (`sign`).
- **Modern S3 features:**
  - Conditional writes: `If-None-Match: *` backs mode `xb` atomically, and
    `If-Match` gives safe overwrites.
  - Default checksums (CRC64NVME/CRC32C, including full-object checksums
    for multipart).
  - S3 Express One Zone (session authentication, directory buckets).
  - Dual-stack, FIPS and Transfer Acceleration endpoints.
  - Path-style and virtual-hosted addressing.
  - SigV4a for Multi-Region Access Points (later).
- **Performance:**
  - Spread connections across all resolved IPs.
  - Automatic ranged GETs for large objects.
  - Parallel prefix listing.
  - Race HEAD and `LIST(prefix, max-keys=1)` in parallel to settle
    "file or directory?" in one round trip (configurable, because it costs
    an extra request).
  - Native batch delete.
  - Concurrent multipart uploads from `open('wb')`.
- **Semantics:** s3fs directory emulation exactly (empty `dir/` markers,
  `mkdir` behaviour, `ls` of prefixes), `version_aware`, the `info()` keys,
  transactions (`autocommit=False` completes multipart uploads at commit).
- **Compatibility matrix:** AWS, MinIO, Ceph RGW, Cloudflare R2, Wasabi,
  Backblaze B2, GCS's S3 interop and OCI's S3 compatibility. Each has a
  quirks table (no `ListObjectsV2`, no checksums, path-style only, and so
  on).

### 6.4 GCS and Azure
- **GCS:**
  - The JSON API for metadata and listing (as gcsfs uses).
  - The XML multipart API for parallel uploads, resumable uploads for
    streaming.
  - `compose` for `cat`/merge.
  - `ifGenerationMatch=0` for `xb`, generation-pinned reads, CRC32C
    verification.
  - HTTP/2 multiplexing.
  - Later: gRPC/DirectPath via tonic, if the benchmarks justify it.
- **Azure:**
  - Block blobs: Put Block and Put Block List, in parallel.
  - The ADLS Gen2 DFS endpoint for accounts with a hierarchical namespace:
    real directories, atomic rename and recursive delete.
  - Append blobs for mode `ab`.
  - Authentication: account key/shared key, SAS, connection strings, and
    Entra ID (client secret, certificate, managed identity, workload
    identity, Azure CLI). The `account_name`/`account_key`/
    `credential`/`anon` options are compatible with adlfs.
  - Tested against Azurite and real storage accounts, with and without a
    hierarchical namespace.

### 6.5 SMB 2/3: the flagship

**Build or adopt?** Our recommendation is to **build our own stack**
(`fsfast-smb-proto` plus `fsfast-smb`), reuse `sspi` for authentication and
use `smb-rs` as a reference and differential-interop oracle. The reason:
the performance we want depends on controlling credits, pipelining,
compounding and buffer ownership. Decrypting straight into the caller's
memory is the kind of thing that is hard to retrofit. **Phase 0 go/no-go
check:** benchmark `smb-rs` on our SMB workloads and review its design for
zero-copy I/O and credit management. If it meets about 80% of the targets
and its maintainers accept upstream work, we contribute upstream instead.

**Design points**
- **The codec has no I/O** (`fsfast-smb-proto`). It parses with zero copies
  where possible, payloads stay in `Bytes`, and it is fuzzed. Every message
  and info class traces back to a section of MS-SMB2 or MS-FSCC.
- **Credits drive pipelining.** The client asks for generous credit grants,
  keeps N reads/writes of the server's maximum size (typically 8 MiB)
  in flight per handle, and charges multi-credit (large MTU) requests
  correctly.
- **Compounding for everything that costs round trips:**
  - `info` = CREATE + QUERY_INFO + CLOSE, in one round trip.
  - `cat` of a small file = CREATE + READ + CLOSE.
  - `pipe` of a small file = CREATE + WRITE + CLOSE.
  - `ls` = CREATE + QUERY_DIRECTORY (large buffer, `FileIdBothDirectoryInformation`).
- **Connection, session and tree pooling** per (server, credentials,
  share), with reconnect and replay through durable handles.
- **Crypto is fast:** AES-128-GCM is preferred, with hardware AES and
  decryption in place into the destination buffer. Crypto can move to
  worker threads when one core cannot keep up with a 25/100 GbE line.

**Feature checklist by milestone**

| Milestone | Scope |
|---|---|
| **SMB-1: core** | TCP 445 (NetBIOS 139 optional). NEGOTIATE for 2.0.2/2.1/3.0/3.0.2/3.1.1 with negotiate contexts (preauth integrity SHA-512, encryption, signing). SESSION_SETUP through SPNEGO with NTLMv2; guest and anonymous with the correct signing rules. SP800-108 key derivation. Signing: HMAC-SHA256, AES-CMAC, AES-GMAC. TREE_CONNECT. CREATE (with contexts), CLOSE, READ, WRITE, FLUSH, QUERY_INFO, SET_INFO, QUERY_DIRECTORY, IOCTL, ECHO, LOGOFF, CANCEL. Interim/async responses (STATUS_PENDING). Message-ID and credit accounting. NTSTATUS → errno mapping. FSCTL_VALIDATE_NEGOTIATE_INFO for 3.0/3.0.2. |
| **SMB-2: throughput** | Encryption (TRANSFORM_HEADER) with AES-128/256-GCM/CCM. Large-MTU multi-credit I/O. Credit-window pipelining. Compound chains for every metadata operation. Server-side copy (FSCTL_SRV_COPYCHUNK_WRITE) for `copy`. `readinto` with zero extra copies. Delete and rename through SET_INFO, with POSIX semantics (`FileDispositionInformationEx`, `FileRenameInformationEx`) where supported. Truncate and sparse files. |
| **SMB-3: enterprise** | Kerberos (`sspi`, plus system ccache/keytab through GSSAPI). **DFS** (FSCTL_DFS_GET_REFERRALS, domain-based and standalone namespaces, referral cache, failover to another target). Durable handles v1/v2 with reconnect on network blips. Resilient handles. **Leases** (R/H/W) and lease/oplock break handling, so client caching is safe. Reparse points/symlinks. Alternate data streams (`path:stream`). Share flags (encrypt-data, continuous availability). A database of server quirks. |
| **SMB-4: advanced** | **Multichannel** (FSCTL_QUERY_NETWORK_INTERFACE_INFO, session binding, I/O spread across channels, channel failover). **Compression** (MS-XCA: LZ77, LZ77+Huffman, LZNT1, Pattern_V1, chained). **SMB over QUIC** (quinn, port 443; Windows Server 2025, and 2022 Azure Edition). SMB 3.1.1 POSIX extensions (Samba). Change notify (an extra `watch()` API outside fsspec). |
| Never / later | SMB1. SMB Direct (RDMA): it needs rdma-core and few users have the hardware. We revisit it if users ask. |

**Interop matrix (CI and nightly):**
- **Servers:** Windows Server 2019, 2022 and 2025 (GitHub Windows runners
  can host shares via `New-SmbShare`), Samba (latest plus the oldest
  version in a supported LTS distro), ksmbd, Azure Files (requires
  encryption), the macOS SMB server, and NAS appliances where we can get
  access (NetApp ONTAP simulator, TrueNAS/Synology).
- **Configurations:** signing required, encryption required, SMB2-only,
  Kerberos-only (a Samba AD DC container), a DFS namespace, guest disabled,
  and high latency through netem.

**How we verify compliance:**
- A spec traceability matrix: each client requirement in MS-SMB2 §3.2 maps
  to a test or to an explicit "not applicable".
- Every CI capture goes through `tshark` and fails on any malformed or
  expert-error packet.
- Codec fuzzing.
- Differential runs against `smb-rs` and the Linux kernel client.

### 6.6 SFTP
- **Transport:** russh. AEAD ciphers are preferred (aes128-gcm@openssh.com,
  chacha20-poly1305@openssh.com), with large channel windows. Several
  channels or connections are used for parallel transfers of many files.
- **SFTP v3 (as OpenSSH implements it), plus these extensions:**
  `limits@openssh.com` (read/write lengths of up to ~256 KiB),
  `posix-rename@`, `statvfs@`, `fsync@`, `hardlink@`, `copy-data` (copying
  on the server) and `expand-path@`.
- **Pipelining:** many READ/WRITE requests in flight. OpenSSH's own client
  defaults to 64 × 32 KiB; we tune this adaptively by RTT. Out-of-order
  replies are reassembled.
- **Authentication and configuration:** password, public key (OpenSSH and
  PEM formats, encrypted keys; PPK later), ssh-agent, keyboard-interactive,
  certificates. `~/.ssh/config` support: Host aliases, IdentityFile,
  **ProxyJump** and Port.
- **Host keys:** strict checking against `known_hosts` (hashed entries
  supported) by default.
- **Phase 0 spike:** raw russh channel throughput against OpenSSH on a
  1 Gbps link with 20 ms RTT. If russh is the bottleneck, we fix it upstream
  (window and buffer handling).

### 6.7 Tier 2 notes
- **Reference FS:** loads references lazily from Parquet (Rust `parquet`),
  groups chunk reads by target URL, coalesces them and hands them to the
  Rust backend in one call. No Python runs per chunk.
- **Zip/Tar:** zip uses the end-of-central-directory search, Zip64, and
  stored/deflate/zstd entries. Tar builds an index in one pass and can
  cache it next to the archive.
- **FTP:** passive and EPSV, MLSD/MLST with LIST parsing as a fallback,
  REST for ranged reads, AUTH TLS (RFC 4217) with session reuse on data
  connections, and a pool of control connections for parallelism.
- **WebDAV:** PROPFIND (Depth 1, plus Depth infinity when allowed), MOVE,
  COPY, MKCOL, ranged GET, and the Nextcloud chunked-upload protocol.

### 6.8 Definition of done (per backend)
1. **API coverage:** every public fsspec method, sync and async (the list is
   in Appendix A), works or raises the same error as the reference
   implementation.
2. **fsspec semantics:**
   - fsspec's abstract test suite (`fsspec.tests.abstract`) passes.
   - The upstream package's own test suite (s3fs/gcsfs/adlfs/sshfs/fsspec
     smb tests) runs against our class. Every exclusion is listed and
     explained, for example tests that reach into botocore internals.
3. **Differential testing:** hypothesis stateful tests run the same random
   sequence of operations against our implementation and the reference,
   then compare the normalized results.
4. **Protocol:** the traceability matrix is complete, the interop matrix is
   green, and the decoders have been fuzzed for at least 24 hours of CPU
   time with no findings.
5. **Performance:** the targets in §8.4 are met, measured on the standard
   hardware.
6. **Docs:** an options table (a mapping from the reference package's
   options), known differences, and tuning guidance.

---

## 7. Compliance strategy (summary)

| Layer | Source of truth | How we test |
|---|---|---|
| Wire protocol | MS-SMB2, MS-FSCC, MS-DTYP, MS-ERREF, MS-SPNG, MS-NLMP, MS-KILE, MS-DFSC, MS-XCA; SFTP draft-02 plus the OpenSSH PROTOCOL files; RFC 959/2228/2389/2428/3659/4217 (FTP); RFC 9110–9112 (HTTP); RFC 4918 (WebDAV); the AWS, GCS and Azure REST references | Traceability matrices, interop matrices, `tshark` validation, fuzzing, fault injection (resets, slow servers, partial responses, throttling) |
| fsspec semantics | The behaviour of fsspec plus s3fs/gcsfs/adlfs/sshfs, recorded | Abstract suite, upstream suites, differential hypothesis tests, golden `info()` schemas |
| Robustness | — | Chaos tests (toxiproxy/netem: latency, loss, resets), long soak tests (24 h of mixed load, with RSS and file-descriptor leak checks), fork and pickle tests, free-threaded stress tests |

---

## 8. Benchmarking methodology

### 8.1 Workloads

| ID | Workload | Represents |
|---|---|---|
| W1 | Large sequential read/write (1–50 GiB single object) | Bulk ETL, model checkpoints |
| W2 | Random ranged reads, 4 MiB, concurrency 1/16/64/256 | Parquet row groups |
| W3 | Random small ranged reads, 16–256 KiB | Zarr/COG chunks, kerchunk |
| W4 | Many small files (10k–1M × 4–64 KiB): cat, pipe, put, get | Image datasets, logs |
| W5 | Listing: 1M keys flat, deep trees; `ls`/`find`/`glob`/`walk`/`du` | Dataset discovery |
| W6 | Metadata storms: `info`/`exists`/`isdir` × 100k | Planner and catalog code |
| W7 | Copy/move within the backend (server-side) and across backends | Data management |
| W8 | Real stacks: `pd.read_parquet`, `xr.open_zarr` (v3), pyarrow dataset scan through `FSSpecHandler`, a dask read/write pipeline, duckdb through fsspec | End-to-end proof |

### 8.2 Environments
- **Local emulators** via docker-compose: MinIO, fake-gcs-server, Azurite,
  Samba (several configurations), ksmbd, OpenSSH, vsftpd/pure-ftpd, Apache
  mod_dav and an HDFS minicluster. **Latency is always shaped with `tc
  netem`** to RTTs of 0.2, 2, 20 and 80 ms, plus bandwidth caps. On
  loopback, emulators hide exactly the costs we are trying to remove.
- **Real cloud runs** use fixed instance types in the same region as the
  storage (for example a 25 Gbps instance), and all three clouds. For SMB:
  Windows Server and Azure Files, plus a bare-metal 10/25 GbE pair for
  line-rate tests.
- `iperf3` measures the network limit before every run.

### 8.3 Baselines and metrics
- **Baselines:**
  - The fsspec implementation each backend replaces (s3fs, gcsfs, adlfs,
    fsspec smb/smbprotocol, fsspec sftp/paramiko and sshfs/asyncssh, ftp,
    webdav4, http/aiohttp), on its latest release.
  - pyarrow.fs, obstore and OpenDAL.
- **Ceilings (the best native tool per protocol):** s5cmd and the AWS
  CRT-based CLI, `gcloud storage`, azcopy, the Linux kernel CIFS client and
  `smbclient`, OpenSSH `sftp -R 64+`, curl/aria2.
- **Metrics:**
  - Throughput, ops/s, p50/p99/p99.9 latency.
  - **CPU-seconds per GiB and per 1k operations.**
  - Peak RSS.
  - **Request count**, which is cloud cost.
  - Fraction of the network limit and fraction of the native-tool ceiling.
- **Tooling:**
  - criterion for micro-benchmarks (codec, signing, CRC, coalescing),
    tracked in CI with CodSpeed or Bencher.
  - A macro harness driven from Python (`fsf bench` plus pytest-benchmark
    runners).
  - flamegraphs and `perf`, tokio-console, `py-spy --native`.
- **Regression gates:**
  - Micro-benchmarks run on every PR.
  - Macro-benchmarks run nightly on dedicated runners.
  - Throughput more than 5% below the trailing median fails the run.
  - Results are published to a dashboard.

### 8.4 Initial targets (recalibrated after the Phase 0 baselines)

| Workload | Target |
|---|---|
| W1, S3/GCS/Azure, same region | ≥ 90% of NIC line rate, or ≥ s5cmd/CRT/azcopy, whichever is lower |
| W2, S3, concurrency 64 | ≥ 5× s3fs throughput at ≤ ⅕ of the CPU per GiB |
| W3, S3, 64 KiB | ≥ 10× s3fs ops/s |
| W5, 1M-key `find` | ≥ 5× s3fs; memory per page is constant (streaming) |
| W4, 10k × 16 KiB `pipe` | ≥ 5× s3fs |
| SMB W1, 10 GbE, 3.1.1 + AES-128-GCM | ≥ 90% of line rate; ≥ the kernel CIFS client |
| SMB W4/W6, 1 ms RTT | ≥ 10× fsspec `smb` |
| SFTP W1, 1 Gbps / 20 ms RTT | ≥ OpenSSH `sftp` defaults |
| Python boundary | Cached `info` < 5 µs; per-call overhead for a small operation < 20 µs plus the network |

---

## 9. Roadmap

Indicative schedule for **2 senior Rust engineers**. Double it for one. The
SMB track runs alongside the main track from Phase 1.

| Phase | Weeks | Scope | Exit criteria |
|---|---|---|---|
| **0: Foundations and baselines** | 0–3 | Workspace, CI (Linux/macOS/Windows), cargo-deny, the emulator compose file and netem scripts, the benchmark harness, **baseline measurements and the time-attribution report (§2)**. Spike: Rust↔Python call overhead (block_on vs channel). Spike: russh throughput. Evaluation of smb-rs. ADRs for the core traits, the HTTP stack and the authentication crates. | Baseline report published; ADRs accepted; the hypotheses in §2 confirmed or revised |
| **1: Core and the first read path** | 3–9 | `fsfast-core`, the engine (coalescing, readahead, automatic ranged GET, memory budget), the transport, local/memory/HTTP, the S3 read path (list/info/get/ranges), the Python layer (sync and async, file objects, error mapping, pickling, fork safety), the memory block cache | **v0.1 (internal):** abstract suite passes read-only for local/memory/http/s3; W1/W2/W3/W5 targets met on S3 |
| **SMB track S1–S2** | 4–14 | Core plus throughput milestones (§6.5) | Abstract suite green against Samba and Windows; SMB W1 and W4 targets met |
| **2: Complete S3 and alpha** | 9–14 | S3 writes, multipart, copy, delete, versioning, conditional writes, checksums, s3fs option translation, the s3fs test suite, differential tests, disk and whole-file caches, URL chaining | **v0.2 public alpha** on PyPI: S3, HTTP, local and memory; SMB in preview |
| **3: GCS and Azure; SMB enterprise** | 14–21 | GCS, Azure Blob plus ADLS Gen2. SMB S3 milestone (Kerberos, DFS, durable handles, leases). | **v0.3 beta:** all clouds plus SMB at definition-of-done level |
| **4: SFTP and the remaining tier-1 polish** | 21–27 | SFTP, compression codecs, free-threaded wheels, a Windows/macOS performance pass, SMB S4 (multichannel, compression, QUIC) | **v0.4:** the full tier-1 set |
| **5: Tier 2 and hardening, then 1.0** | 27–38 | Reference FS, zip/tar, HF, FTP/FTPS, WebDAV, HDFS (wrap). Sustained fuzzing, an external security review, docs site, published benchmarks. | **v1.0:** tier 1 + 2 stable; API frozen; semver |

Release engineering: maturin wheels for manylinux and musllinux
(x86_64/aarch64), macOS (x86_64/arm64) and Windows (x86_64/arm64); abi3 for
3.10+, plus wheels for free-threaded 3.13t/3.14t. A conda-forge feedstock
follows from v0.2.

---

## 10. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Server quirks in SMB (Windows vs Samba vs NAS) | Slips in the flagship | Interop matrix from SMB-1 onward, a quirks database, the smb-rs and kernel client as oracles, `tshark` validation |
| Kerberos across platforms | Enterprise adoption is blocked | `sspi` (pure Rust) everywhere, plus system GSSAPI on Unix; a Samba AD DC in CI |
| Drift in fsspec or upstream semantics (s3fs changes behaviour) | Breaks drop-in compatibility | Pinned upstream suites run against both the pinned and the latest versions, nightly; golden schemas; differential tests |
| The Python bridge eats the gains (the obstore lesson) | The value proposition fails | Spike in Phase 0; Rust owns the sync methods, file objects and caches; batch APIs; per-call overhead budget in CI |
| Aggressive parallelism raises memory use or cloud cost | Out-of-memory failures; billing surprises | Global memory budget; request counts in every benchmark; conservative defaults with documented tuning profiles (`profile="throughput"`) |
| Asyncio, fork and threading pitfalls | Hangs in Dask or multiprocessing | Fork hooks, runtime rebuild, dedicated tests (fork, spawn, forkserver, threads, free-threaded) |
| Scope (12+ backends) | The launch slips | Strict tier order; Tier 2 reuses the transport, engine and crates (HDFS is wrapped); each backend gated by the definition of done |
| Weight or gaps in auth crates (aws-config, Azure, GCP) | Wheel size; edge cases | Evaluate in Phase 0; feature-gate them; fall back to thin credential chains of our own |
| Licensing contamination | A permissive wheel cannot ship | cargo-deny license allowlist; no GPL dependencies (excludes libsmbclient-based crates) |

---

## 11. Engineering conventions
- **License:** Apache-2.0 OR MIT.
- **Code quality:** an MSRV policy (stable minus 2), and clippy (pedantic
  where sensible) and rustfmt in CI.
- **`unsafe`:** forbidden outside `fsfast-py` and explicitly audited
  modules. Every `unsafe` block carries a `// SAFETY:` comment.
- **Python tooling:** uv for development, ruff and mypy for the Python
  layer, `.pyi` stubs shipped.
- **Decisions:** ADRs in `docs/adr/`; every performance-motivated design
  change links a benchmark.
- **Tests:** each crate has unit tests plus property tests. Integration
  tests are gated by Cargo features and environment variables, so a plain
  `cargo test` never needs Docker.

---

## 12. The first two weeks (concrete)
1. Workspace skeleton (the crates in §4.2 as stubs), CI matrix, cargo-deny,
   rustfmt/clippy, maturin build of an empty `fsfast._core`.
2. `bench/compose.yml` with MinIO, fake-gcs-server, Azurite, Samba (with
   signing and encryption variants), OpenSSH and vsftpd, plus
   `bench/netem.sh`.
3. Baseline harness: W1–W6 against s3fs, gcsfs, adlfs, fsspec smb and
   fsspec sftp, and the native ceilings, recording throughput, CPU,
   requests and RSS.
4. Profiling pass: py-spy flamegraphs per workload, then a draft of the
   time-attribution report.
5. Spike A: a minimal Rust S3 GET exposed to Python three ways (fsspec
   `_cat_file` adapter, direct sync with the GIL released, direct asyncio),
   to measure the cost of the boundary.
6. Spike B: russh against OpenSSH SFTP throughput. Spike C: smb-rs on the
   SMB workloads, plus a design review.
7. ADR-0001 (core traits), ADR-0002 (HTTP stack and auth crates), ADR-0003
   (SMB: build or adopt).

---

## 13. Open decisions (owner input wanted)
1. **Default override:** should `import fsfast` take over the fsspec
   protocols automatically, or stay opt-in (`fsfast.install()`)?
   *Recommendation: opt-in.*
2. **The minimum Python version** and how much free-threading matters at
   launch.
3. **Test infrastructure budget:** Windows Server, Azure Files,
   NAS-appliance access, cloud accounts and a bare-metal 25 GbE pair for
   benchmarks.
4. **The `fsf` CLI:** a product of its own (rclone/s5cmd-like), or just a
   benchmark tool? *Recommendation: a benchmark tool until 1.0.*
5. **License:** Apache-2.0 OR MIT. *Recommended.*

---

## Appendix A: the fsspec API surface to cover

**Filesystem, sync (each also has its async `_name` counterpart):**
`ls`, `info`, `exists`, `lexists`, `isdir`, `isfile`, `size`, `sizes`,
`cat`, `cat_file`, `cat_ranges`, `pipe`, `pipe_file`, `put`, `put_file`,
`get`, `get_file`, `open` (modes `rb`/`wb`/`ab`/`xb`, with text mode
through `TextIOWrapper`), `rm`, `rm_file`, `rmdir`, `mkdir`, `makedirs`,
`mv`, `copy`/`cp_file`, `find`, `glob` (including `**` and `maxdepth`),
`walk`, `du`, `expand_path`, `checksum`, `ukey`, `modified`, `created`,
`sign`, `touch`, `head`, `tail`, `read_block`, `read_text`/`write_text`,
`read_bytes`/`write_bytes`, `upload`/`download`, `transaction` and
`start_transaction`/`end_transaction`, `invalidate_cache`,
`to_json`/`from_json`, `to_dict`/`from_dict`, `get_mapper` (FSMap).

**File objects:**
`read`, `read1`, `readinto`, `readline(s)`, iteration, `seek`/`tell`,
`write`, `flush`, `close`, `commit`/`discard`, `readable`/`writable`/
`seekable`, context manager. Attributes: `path`, `fs`, `mode`, `size`,
`loc`, `blocksize`, `details`, `autocommit`, plus the cache types and
`cache_options`.

**Module level:** `fsspec.open`, `open_files`, `url_to_fs`, `filesystem`,
chained URLs, `fsspec.parquet.open_parquet_file` (through `cat_ranges`),
pickling, and instance caching.
