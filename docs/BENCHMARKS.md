# Benchmarks: fsfast against the reference implementations

This page compares fsfast's Python classes with the fsspec implementations
they replace, with the `fsf` CLI (the Rust engine without Python) and with
native tools. Every number below comes from `bench/run.py`, run against
the local test services on one shared 4-core VM. The raw documents are in
[`bench/results/`](../bench/results). Read the [caveats](#caveats) before
quoting a number: the services run on loopback, and three of them are
emulators.

## Summary

The table shows fsfast's median speedup over the reference implementation
(fsfast ÷ reference, median of 3 timed iterations each, `default` profile).
Values below 1 mean fsfast is slower. "n/a" means the reference cannot do
the workload. **Bold** cells were re-measured on 2026-11-26 after the fixes
for the findings ([before and after](#after-the-fixes-2026-11-26)); the
others are the 2026-11-25 run. For smb, smb-enc and sftp only fsfast and
fsf were re-run (the references are unchanged and slow), so those bold
ratios divide the new fsfast figure by the 2026-11-25 reference figure.

| workload | s3 | smb | smb-enc | sftp | http | gcs | azure | local | memory |
|---|---|---|---|---|---|---|---|---|---|
| W1 seq-read | **1.81x** | **7.03x** | **6.31x** | **119.56x** | **1.70x** | **1.76x** | **1.81x** | **1.80x** | **2.48x** |
| W1 seq-read-open | **2.02x** | **7.96x** | **5.28x** | **175.31x** | **4.80x** | **1.54x** | **1.73x** | **1.09x** | **0.71x** |
| W2 seq-write | 2.81x | 6.00x | 6.73x | 747.25x | 1.12x | 1.33x | 1.19x | 0.81x | 1.05x |
| W3 small-read | **17.08x** | 46.85x | 55.26x | 52.60x | **6.05x** | **4.70x** | **4.92x** | 0.82x | 1.18x |
| W4 small-write | **3.83x** | 16.69x | 5.38x | 2.97x | **3.93x** | **1.44x** | **1.62x** | 1.13x | 2.18x |
| W5 metadata-info | 4.09x | 20.68x | 16.47x | 1.59x | 2.77x | 1.70x | 2.40x | 0.92x | 31.48x |
| W5 metadata-ls | 2.81x | 228.70x | 216.34x | 2.37x | 0.88x | 0.94x | 3.45x | 0.89x | 0.78x |
| W5 metadata-find | 2.56x | 207.42x | 201.83x | 2.36x | 0.98x | 0.85x | 3.56x | 1.74x | 1.23x |
| W6 random-read | **3.08x** | **36.10x** | **24.96x** | **124.43x** | **2.50x** | **3.99x** | **1.76x** | **1.16x** | **4.15x** |
| W7 copy | **1.35x** | **8.28x** | **10.20x** | **5156.55x** | n/a | **1.09x** | **2.57x** | **3.66x** | **0.63x** |
| W8 delete | **1.12x** | **50.00x** | **51.06x** | **43.56x** | n/a | **1.90x** | **3.87x** | **1.20x** | **76.67x** |

Against sshfs (the second SFTP reference), fsfast is 3.2–4.9× faster on large reads and writes, 3–4× on metadata, 21× on small reads, 5× on small writes and 25× on deletes; sshfs cannot do W6 (its ranged reads return whole objects) or W7 at this concurrency (see [findings](#findings-and-follow-ups)). The sftp W7 ratio compares fsfast's server-side copy with the client-side copy paramiko forces (it has no `cp_file`).

What the numbers say:

* **Network backends.** fsfast is faster than the reference on almost
  every workload. The largest gains come where the reference makes one
  blocking round trip per call: fsspec's smb (smbprotocol) is 5–230× slower
  than fsfast, and fsspec's sftp (paramiko) 1.6–750× slower. On S3, GCS
  and Azure the gains are 1.2–12×, because s3fs, gcsfs and adlfs are
  already asynchronous. The exceptions:
  * Before the fixes of 2026-11-26, GCS W8 delete was 5× slower than
    gcsfs (0.18×, finding 3) and HTTP W6 random reads were slower than
    fsspec (0.72×, finding 2); both are now faster (1.90× and 2.50×).
  * **Azure W6 random reads lost 25%** with the coalescing guard (finding
    2): Azurite answers 325 small requests more slowly than 61 large ones
    on loopback; fsfast is still 1.76× adlfs.
  * **Ties, within the noise of this machine:**
    * S3 W7 (1.35×) and W8 (1.12×): RustFS's CopyObject and DeleteObjects
      are the limit, and `fsf` is no faster. Before the 2026-11-26 fixes
      these were 1.03× and 0.87×.
    * GCS W7 (1.09×), and GCS ls/find (0.94×/0.85×): fake-gcs-server is
      CPU-bound, and `fsf` is no faster.
    * HTTP ls/find (0.88×/0.98×): the HTML parsing. HTTP W4 was a tie
      (0.96×) before the batch-size fix; it is now 3.93×.
* **Local and memory.** The reference is a thin wrapper around the
  operating system or a Python dict. fsfast's per-call bridge (about
  2–5 µs) shows in the metadata loops, and its extra copy shows in
  `open().read()`. fsfast is ahead on writes of many files, on copies and
  deletes, and on `find`.
* **fsfast against fsf.** fsfast from Python reaches 0.4–1.3× of the
  Rust-only CLI, and 0.6–1.0× on most workloads. The large gaps:
  * `cat_file` of a 256 MiB object, 0.25–0.9× (finding 1; fsf discards its
    chunks instead of building one buffer);
  * `cat_ranges` on SFTP, SMB and GCS, 0.38–0.63×: one Python `bytes` per
    range, plus the coalescing differences of finding 2;
  * `rm` of many files on SMB, SFTP, GCS and Azure (finding 3).

## After the fixes (2026-11-26)

The findings below were fixed in python/fsfast, crates/fsfast-py,
crates/fsfast-smb (counters only) and crates/fsfast-local (FIFO), and the
affected rows re-run with `bench/run.py` (same method and `default`
profile; documents `bench/results/bench-20261126T*-fixes-*.json`, load
average 0.5–4.6, apart from one burst to 9.7 during the GCS run; the W6
rows come from the `fixes-w6-*` documents, memory W1/W6 from
`fixes-w1w6-memory`). "÷ ref" columns divide by the reference measured in
the same document, except where marked * (the 2026-11-25 reference figure).
The last column is fsfast's `stats()["requests"]` for the last iteration,
which now counts wire requests (finding 5).

| target | workload | unit | fsfast before | fsfast after | ÷ ref before | ÷ ref after | ÷ fsf after | wire requests (last iter) |
|---|---|---|---|---|---|---|---|---|
| azure | W1 seq-read | MB/s | 421 | 406 | 1.70x | 1.81x | 0.50x | 34 |
| azure | W1 seq-read-open | MB/s | 513 | 551 | 1.79x | 1.73x |  | 33 |
| azure | W3 small-read | ops/s | 1,057 | 1,272 | 4.17x | 4.92x | 0.89x | 1000 |
| azure | W4 small-write | ops/s | 807 | 751 | 1.74x | 1.62x | 1.25x | 1000 |
| azure | W6 random-read | MB/s | 73.0 | 54.8 | 2.18x | 1.76x | 0.86x | 325 |
| azure | W7 copy | MB/s | 2,722 | 4,150 | 1.76x | 2.57x | 0.88x | 64 |
| azure | W8 delete | ops/s | 442 | 714 | 2.40x | 3.87x | 1.08x | 5000 |
| gcs | W1 seq-read | MB/s | 608 | 1,217 | 1.17x | 1.76x | 0.82x | 35 |
| gcs | W1 seq-read-open | MB/s | 1,713 | 1,658 | 2.08x | 1.54x |  | 33 |
| gcs | W3 small-read | ops/s | 7,081 | 10,975 | 3.48x | 4.70x | 1.25x | 1000 |
| gcs | W4 small-write | ops/s | 340 | 318 | 1.39x | 1.44x | 1.02x | 1000 |
| gcs | W6 random-read | MB/s | 179 | 460 | 1.46x | 3.99x | 1.17x | 325 |
| gcs | W7 copy | MB/s | 151 | 151 | 1.00x | 1.09x | 1.01x | 64 |
| gcs | W8 delete | ops/s | 167 | 2,047 | 0.18x | 1.90x | 0.96x | 5000 |
| http | W1 seq-read | MB/s | 943 | 1,581 | 1.71x | 1.70x |  | 57 |
| http | W1 seq-read-open | MB/s | 2,473 | 3,222 | 3.53x | 4.80x |  | 53 |
| http | W3 small-read | ops/s | 26,405 | 39,698 | 3.41x | 6.05x |  | 1000 |
| http | W4 small-write | ops/s | 2,050 | 16,762 | 0.96x | 3.93x |  | 1000 |
| http | W6 random-read | MB/s | 210 | 747 | 0.72x | 2.50x |  | 325 |
| local | W1 seq-read | MB/s | 2,174 | 3,074 | 1.33x | 1.80x | 0.36x | 3 |
| local | W1 seq-read-open | MB/s | 5,187 | 6,552 | 0.90x | 1.09x |  | 1 |
| local | W6 random-read | MB/s | 1,428 | 1,383 | 0.93x | 1.16x | 0.45x | 1 |
| local | W7 copy | MB/s | 7,173 | 7,266 | 2.93x | 3.66x | 1.04x | 128 |
| local | W8 delete | ops/s | 166,555 | 173,370 | 1.47x | 1.20x | 0.46x | 1 |
| memory | W1 seq-read | MB/s | 4,331 | 4,093 | 2.94x | 2.48x | 0.00x | 1 |
| memory | W1 seq-read-open | MB/s | 6,492 | 6,993 | 0.70x | 0.71x |  | 1 |
| memory | W6 random-read | MB/s | 4,939 | 6,980 | 2.17x | 4.15x | 0.02x | 1 |
| memory | W7 copy | MB/s | 925,898 | 911,384 | 0.74x | 0.63x | 0.16x | 128 |
| memory | W8 delete | ops/s | 167,525 | 214,643 | 61.33x | 76.67x | 0.06x | 10001 |
| s3 | W1 seq-read | MB/s | 533 | 623 | 1.85x | 1.81x | 0.71x | 35 |
| s3 | W1 seq-read-open | MB/s | 892 | 880 | 2.12x | 2.02x |  | 33 |
| s3 | W3 small-read | ops/s | 5,327 | 7,295 | 12.01x | 17.08x | 1.02x | 1000 |
| s3 | W4 small-write | ops/s | 1,610 | 2,313 | 2.68x | 3.83x | 1.18x | 1000 |
| s3 | W6 random-read | MB/s | 140 | 135 | 2.91x | 3.08x | 1.28x | 325 |
| s3 | W7 copy | MB/s | 370 | 497 | 1.03x | 1.35x | 1.12x | 128 |
| s3 | W8 delete | ops/s | 824 | 868 | 0.87x | 1.12x | 0.89x | 5 |
| sftp | W1 seq-read | MB/s | 673 | 507 | 158.68x | 119.56x* | 0.63x | 62 |
| sftp | W1 seq-read-open | MB/s | 839 | 796 | 184.70x | 175.31x* |  | 67 |
| sftp | W6 random-read | MB/s | 401 | 584 | 85.36x | 124.43x* | 0.63x | 334 |
| sftp | W7 copy | MB/s | 4,160 | 4,514 | 4752.34x | 5156.55x* | 0.76x | 65 |
| sftp | W8 delete | ops/s | 40,147 | 95,583 | 18.30x | 43.56x* | 0.79x | 1 |
| smb | W1 seq-read | MB/s | 866 | 1,273 | 4.78x | 7.03x* | 0.75x | 133 |
| smb | W1 seq-read-open | MB/s | 1,909 | 2,157 | 7.04x | 7.96x* |  | 130 |
| smb | W6 random-read | MB/s | 818 | 878 | 33.63x | 36.10x* | 0.68x | 401 |
| smb | W7 copy | MB/s | 6,170 | 5,010 | 10.20x | 8.28x* | 1.06x | 65 |
| smb | W8 delete | ops/s | 8,365 | 9,436 | 44.33x | 50.00x* | 0.78x | 5000 |
| smb-enc | W1 seq-read | MB/s | 821 | 1,112 | 4.66x | 6.31x* | 0.75x | 133 |
| smb-enc | W1 seq-read-open | MB/s | 1,465 | 1,510 | 5.12x | 5.28x* |  | 130 |
| smb-enc | W6 random-read | MB/s | 738 | 603 | 30.55x | 24.96x* | 0.58x | 401 |
| smb-enc | W7 copy | MB/s | 4,215 | 6,350 | 6.77x | 10.20x* | 1.36x | 65 |
| smb-enc | W8 delete | ops/s | 7,442 | 10,295 | 36.92x | 51.06x* | 0.89x | 5000 |

What changed, by finding:

* **1. `cat_file` copy.** The sync `cat_file` reads results of 16 MiB or
  more straight into the final `bytes` object (`ops::cat_file_start` +
  `DirectCat::fill`, the engine's `read_parallel_into` through a read
  handle). Network backends first read 16 MiB with the backend's
  `cat_file`, so smaller files remain one call (one GET on object stores);
  local looks the size up with a `stat`. Backends whose handles pin a
  version (S3, GCS, Azure, HTTP) read that first part again through the
  pinned handle, so the result is one consistent object version, at the
  cost of 16 MiB and one HEAD per large read. The memory store keeps the
  plain path (its `cat_file` is already a zero-copy slice). W1 `cat_file`
  went from 0.4–0.6× of `open().read()` to 0.9–1.0× on SMB and SFTP
  (direct probe: SMB 1,229–1,416 against 1,305–1,544 MB/s; S3 716
  against 873). The async `_cat_file` still copies (see gaps).
* **2. Coalescing.** The backends' gap and maximum (`IoHints`) are kept,
  plus an amplification guard in fsfast-py (`ops::plan_ranges`): a hole is
  bridged only if it is no larger than the requested bytes it joins (or
  64 KiB). Dense ranges merge exactly as before; when the guard splits a
  group the backend would have merged, the planned requests go through one
  read handle (4 KiB-aligned, `max_concurrency` in flight), otherwise the
  backend's `cat_ranges` runs unchanged. On W6's offsets this fetches
  about 42 MiB in about 320 requests instead of 163 MiB in 61, for 31 MiB
  requested. Loopback results: HTTP 3.6× faster (0.72× → 2.50× of
  fsspec), GCS 2.6× faster, S3 unchanged, Azure 25% slower (Azurite's
  per-request cost).
* **3. rm/copy/get.** `_expand_kinds` expands paths exactly like fsspec's
  `expand_path` but keeps the types its `find`/`glob` listings already
  returned; paths given literally are not looked up. Deletes, copies and
  downloads run as files first, and only the paths that fail are looked
  up (a directory then gets the directory step: `rmdir`, `makedirs` or a
  local directory; anything else raises the original error). Reference
  semantics and exceptions are unchanged: the parity tests (tests/python)
  and every compliance suite pass as before. GCS W8: 167 → 2,047 files/s
  (0.18× → 1.90× of gcsfs); Azure W8 442 → 714 (now 1.08× of fsf); SFTP
  W8 40k → 96k files/s.
* **4. Batch sizes.** Classes whose reference is an fsspec
  `AsyncFileSystem` (S3, GCS, Azure, HTTP) now default to
  `fsspec.asyn._get_batch_size()`, honouring `conf["gather_batch_size"]`,
  `conf["nofiles_gather_batch_size"]`, the instance's `batch_size` and the
  calls' `batch_size` arguments (remote-only batches: 1280; transfers with
  local files: `RLIMIT_NOFILE // 8`). Wire concurrency stays bounded by the
  HTTP transport's per-host connection limit (64). SMB, SFTP, local and
  memory, whose references are synchronous, keep the backend hints. HTTP
  W4 went from 2,050 to 16,762 files/s; S3 W3/W4 +37%/+44%.
* **5. `stats()`.** For network backends the top-level counters are the
  backend's wire counters (`source: "wire"`): a 256 MiB `cat_file` now
  shows 33–35 requests on S3/GCS/Azure, 62 SFTP and 133 SMB messages;
  `calls` keeps the per-call counters. fsfast-smb now counts the inline
  compound read of `cat_file` (it counted nothing), every READ message of
  a pipelined read (it counted one per call) and handle opens/closes, and
  no longer counts the bytes of a handle read twice. Local and memory
  report calls (`source: "calls"`).
* **Local FIFO.** `cat_file` of a FIFO or character device reads it as a
  stream (it returned `b""`, its stat size). Note: fsspec's own
  `LocalFileSystem.cat_file` (2026.9.0) raises `io.UnsupportedOperation`
  on a FIFO (it seeks to the end); fsfast deliberately returns the content.
* **New finding: HTTP ranged reads that start mid-page stall ~44 ms.**
  Against nginx (sendfile), a ranged GET such as `bytes=1234-66769` takes
  44 ms with fsfast's HTTP client and 0.3 ms with urllib; ranges starting
  on a 4 KiB boundary never stalled in the probes. It looks like a delayed
  ACK interaction in fsfast-http-transport (reqwest/hyper); it affects any
  small unaligned `cat_file`/`read_at` over HTTP, not only `cat_ranges`.
  The guarded `cat_ranges` path aligns its requests, which avoids it there;
  the transport itself was not changed (another engineer's crate).

## Method

`bench/run.py` (see [bench/README.md](../bench/README.md)) runs each
workload through every implementation, against the same service and with
the same parameters:

| impl | what runs |
|---|---|
| `fsfast` | `fsfast.<Name>FileSystem`, from Python |
| `reference` | fsspec `LocalFileSystem`, `MemoryFileSystem`, `HTTPFileSystem` (aiohttp), `SMBFileSystem` (smbprotocol), `SFTPFileSystem` (paramiko); s3fs; gcsfs; adlfs |
| `sshfs` | sshfs (asyncssh), a second SFTP reference |
| `fsf` | `fsf bench --json` (crates/fsfast-cli), Rust only |
| `native` | coreutils `cat`/`cp`/`ls`/`find`/`rm` (local), `smbclient`, OpenSSH `sftp`, `curl` |

Workloads, `default` profile (`bench/benchcfg.py`):

| id | name | timed call (Python) | size |
|---|---|---|---|
| W1 | seq-read | `cat_file(path)` | one 256 MiB object |
| W1 | seq-read-open | `with open(path, "rb")`: `read(8 MiB)` until EOF | same object |
| W2 | seq-write | `with open(path, "wb")`: `write(8 MiB)` × 32 (http: `put_file` from a local file) | 256 MiB |
| W3 | small-read | `cat([...])` | 1000 × 4 KiB |
| W4 | small-write | `pipe({path: data, ...})` | 1000 × 4 KiB |
| W5 | metadata-info | `info()` on 1000 files, one call after another | a 1000-file directory, removed before the next one is created |
| W5 | metadata-ls | `ls(dir, detail=True)` | 10,000 entries |
| W5 | metadata-find | `find(dir)` | 10,000 entries |
| W6 | random-read | `cat_ranges([path]*500, starts, ends)` | 500 × 64 KiB at seeded random offsets of the 256 MiB object |
| W7 | copy | `copy(srcs, dsts)` | 64 × 4 MiB, within the filesystem |
| W8 | delete | `rm([...])` | 5000 files |

How the runs are done:

* **Iterations.** Every workload runs one untimed warm-up iteration and
  three timed ones. The tables show the **median (best)** iteration. MB/s
  are decimal (10^6 bytes/s). ops/s count files or calls, and entries/s count
  listing entries.
* **Untimed work.** Setup (writing the test data), verification and cleanup
  are not timed. Before every iteration the listing caches are cleared
  (`invalidate_cache()`) and the garbage collector runs.
* **Verification.** Byte and entry counts are checked after every
  iteration, so a broken implementation fails instead of reporting a fast
  number. This caught sshfs returning whole objects for ranged reads.
* **Isolation.** Each (target, implementation) pair runs in a fresh
  interpreter (`bench/pyworker.py`) under its own unique root (bucket,
  container or directory), which is removed afterwards. A sweep with
  `fsf rm -r` removes whatever a crashed worker left behind.
* **CPU.** The document also records client CPU seconds per iteration (user
  + system, all threads of the worker process) and fsfast's per-call
  counters (`stats()`). In the 2026-11-25 documents those counters count
  calls into the Rust layer, not wire requests; since 2026-11-26 they are
  wire requests for network backends (finding 5), like `fsf`'s.
* **The fsf CLI** cannot vary file sizes within one invocation, so
  `run.py` calls `fsf bench` once per group with the same parameters: W1/W2/W6;
  W3/W4; W5 info with 1000 files and `-c 1` (sequential, like the Python
  loop); W5 ls/find of a 10,000-entry directory; W7; W8. Its multi-operation
  workloads use 32 operations in flight (`-c 32`). The Python
  implementations use their own defaults (fsspec's batch size for the
  async references, fsfast's backend concurrency hints). fsf's W1 is a
  parallel ranged read whose chunks are discarded. It never builds one
  contiguous buffer, so it is an upper bound for `cat_file`. fsf's W6 calls
  `read_at` per range on one handle, with no coalescing.
* **Native tools** run once per iteration as a subprocess. Their times include
  process start, connection and authentication. The measured connect-only
  time is recorded in each result's `note` (about 30 ms for smbclient and
  about 315 ms for sftp through sshpass), which matters at 256 MiB.
* **Exceptions to the default sizes.** Paramiko (fsspec's sftp) writes at
  about 1 MB/s because it does not pipeline. For it, W1/W2/W6 use a 32 MiB
  object and W7 uses 64 × 1 MiB, which is recorded as `params_override` in
  the document. Its MB/s figures are still comparable.
* **Missing cells.** `fsf bench` needs a writable directory target, so it
  does not run on http. fsspec's http has no `cp_file`/`rm_file`, so W7 and
  W8 are n/a there. sshfs's `_cat_file` ignores `start`/`end`, so its W6
  is not run: the harness found that it returns the whole object for every
  range, and gathering 500 whole objects ran the machine out of memory.

## Environment

Measured on 2026-11-25 between 22:12 and 23:34 UTC. The documents are `bench/results/bench-20261125T2*-default-*.json`; their `meta` holds everything below.

* **Machine.** A shared KVM VM: Intel Xeon @ 2.10 GHz, 4 vCPUs, 15.7 GB RAM, Linux 6.18.44, Ubuntu 24.04 userland, Python 3.13.18.
* **Load.** The 1-minute load average was 0.5–9.4 across the runs (per run: `loadavg_before`/`loadavg_after`). The S3 and SMB runs started right after a burst at 9.4; every other run was below 5.5.
* **Builds.** fsfast at commit 10cff48 plus the uncommitted working tree of that evening (the Wave 3 bridge and compliance work in progress), as noted in `meta.git.dirty`. Release builds: `cargo build --release -p fsfast-cli` (thin LTO) and `maturin develop --release` (abi3 wheel).
* **Reference packages.** fsspec 2026.9.0, s3fs 2026.9.0 (aiobotocore 3.10.0, botocore 1.43.117), gcsfs 2026.8.2, adlfs 2026.8.0 (azure-storage-blob 12.31.1), smbprotocol 1.17.0, paramiko 5.1.0, sshfs 2026.11.0 (asyncssh 2.24.1), aiohttp 3.14.5.
* **Services**, all on 127.0.0.1, started by `scripts/test-services.sh`:

  | service | version | storage |
  |---|---|---|
  | S3 | RustFS 1.0.6 (`rustfs/rustfs` image) | docker volume |
  | GCS | fake-gcs-server 1.56.1 | `-data /data` |
  | Azure | Azurite 3.38.0 (blob) | — |
  | SMB | Samba 4.19.5, SMB 3.1.1; share `data` with signing required (AES-GMAC), share `enc` with encryption required (AES-128-GCM) | ext4 |
  | SFTP | OpenSSH 9.6p1 `internal-sftp` | ext4 (`/tmp`) |
  | HTTP | nginx 1.24.0, started by `run.py`: 2 workers, sendfile, autoindex listings, WebDAV PUT | ext4 (`/tmp`) |
* **Local target.** `/dev/shm` (tmpfs). The VM's ext4 disk creates new files at only 2–3k/s, and that rate swung by 20× between runs.
* **Native tools.** smbclient 4.19.5, OpenSSH 9.6p1 `sftp` (through `sshpass`), curl 8.5.0, GNU coreutils.

## Results per backend

Each cell shows **median (best)** of 3 timed iterations. The ratio
columns divide medians. `n/a`: the implementation does not offer the
operation. An empty cell means the workload has no equivalent for that
implementation.

### S3 (RustFS)

| workload | unit | fsfast | reference | fsf | native | fsfast / ref | fsfast / fsf |
|---|---|---|---|---|---|---|---|
| W1 seq-read | MB/s | 533 (566) | 288 (305) | 897 (930) |  | 1.85x | 0.59x |
| W1 seq-read-open | MB/s | 892 (900) | 420 (423) |  |  | 2.12x |  |
| W2 seq-write | MB/s | 350 (375) | 125 (128) | 343 (366) |  | 2.81x | 1.02x |
| W3 small-read | ops/s | 5,327 (5,355) | 444 (452) | 8,832 (8,953) |  | 12.01x | 0.60x |
| W4 small-write | ops/s | 1,610 (1,613) | 600 (608) | 1,884 (2,019) |  | 2.68x | 0.85x |
| W5 metadata-info | ops/s | 1,613 (1,772) | 394 (397) | 2,045 (2,303) |  | 4.09x | 0.79x |
| W5 metadata-ls | entries/s | 24,275 (25,856) | 8,650 (9,205) | 21,746 (24,305) |  | 2.81x | 1.12x |
| W5 metadata-find | entries/s | 22,675 (23,289) | 8,853 (9,218) | 24,587 (24,903) |  | 2.56x | 0.92x |
| W6 random-read | MB/s | 140 (143) | 48.0 (48.3) | 113 (116) |  | 2.91x | 1.23x |
| W7 copy | MB/s | 370 (397) | 359 (363) | 430 (434) |  | 1.03x | 0.86x |
| W8 delete | ops/s | 824 (836) | 942 (1,018) | 803 (909) |  | 0.87x | 1.03x |

### SMB, signed share `data`

| workload | unit | fsfast | reference | fsf | native | fsfast / ref | fsfast / fsf |
|---|---|---|---|---|---|---|---|
| W1 seq-read | MB/s | 866 (907) | 181 (182) | 1,713 (2,079) | 887 (920) | 4.78x | 0.51x |
| W1 seq-read-open | MB/s | 1,909 (2,050) | 271 (290) |  |  | 7.04x |  |
| W2 seq-write | MB/s | 1,499 (2,619) | 250 (342) | 1,395 (2,492) | 706 (848) | 6.00x | 1.07x |
| W3 small-read | ops/s | 17,372 (18,956) | 371 (376) | 25,678 (27,171) |  | 46.85x | 0.68x |
| W4 small-write | ops/s | 4,971 (5,425) | 298 (305) | 1,781 (2,006) |  | 16.69x | 2.79x |
| W5 metadata-info | ops/s | 6,979 (7,041) | 337 (338) | 4,137 (4,263) |  | 20.68x | 1.69x |
| W5 metadata-ls | entries/s | 82,498 (87,384) | 361 (368) | 85,269 (91,551) | 59,199 (60,290) | 228.70x | 0.97x |
| W5 metadata-find | entries/s | 70,874 (82,198) | 342 (343) | 82,711 (91,318) |  | 207.42x | 0.86x |
| W6 random-read | MB/s | 818 (893) | 24.3 (24.6) | 1,297 (1,303) |  | 33.63x | 0.63x |
| W7 copy | MB/s | 6,170 (6,179) | 605 (646) | 4,766 (5,134) |  | 10.20x | 1.29x |
| W8 delete | ops/s | 8,365 (8,776) | 189 (195) | 10,349 (11,926) |  | 44.33x | 0.81x |

### SMB, encrypted share `enc`

| workload | unit | fsfast | reference | fsf | native | fsfast / ref | fsfast / fsf |
|---|---|---|---|---|---|---|---|
| W1 seq-read | MB/s | 821 (889) | 176 (181) | 1,321 (1,384) | 714 (756) | 4.66x | 0.62x |
| W1 seq-read-open | MB/s | 1,465 (1,480) | 286 (314) |  |  | 5.12x |  |
| W2 seq-write | MB/s | 1,326 (1,440) | 197 (218) | 1,494 (1,499) | 449 (494) | 6.73x | 0.89x |
| W3 small-read | ops/s | 19,195 (21,966) | 347 (347) | 21,972 (22,502) |  | 55.26x | 0.87x |
| W4 small-write | ops/s | 1,595 (1,600) | 297 (307) | 1,869 (1,912) |  | 5.38x | 0.85x |
| W5 metadata-info | ops/s | 6,173 (6,699) | 375 (396) | 5,404 (5,796) |  | 16.47x | 1.14x |
| W5 metadata-ls | entries/s | 77,649 (82,153) | 359 (367) | 91,540 (92,559) | 54,109 (59,561) | 216.34x | 0.85x |
| W5 metadata-find | entries/s | 72,883 (72,928) | 361 (394) | 89,821 (89,938) |  | 201.83x | 0.81x |
| W6 random-read | MB/s | 738 (846) | 24.2 (24.2) | 1,198 (1,257) |  | 30.55x | 0.62x |
| W7 copy | MB/s | 4,215 (4,652) | 622 (652) | 4,331 (5,106) |  | 6.77x | 0.97x |
| W8 delete | ops/s | 7,442 (7,503) | 202 (217) | 12,054 (12,629) |  | 36.92x | 0.62x |

### SFTP (OpenSSH)

| workload | unit | fsfast | reference | sshfs | fsf | native | fsfast / ref | fsfast / sshfs | fsfast / fsf |
|---|---|---|---|---|---|---|---|---|---|
| W1 seq-read | MB/s | 673 (675) | 4.24 (4.27) | 212 (216) | 750 (761) | 291 (307) | 158.68x | 3.18x | 0.90x |
| W1 seq-read-open | MB/s | 839 (873) | 4.54 (4.60) | 170 (174) |  |  | 184.70x | 4.94x |  |
| W2 seq-write | MB/s | 834 (983) | 1.12 (1.12) | 190 (199) | 872 (918) | 238 (241) | 747.25x | 4.40x | 0.96x |
| W3 small-read | ops/s | 30,374 (32,138) | 578 (586) | 1,452 (1,491) | 33,448 (42,034) |  | 52.60x | 20.92x | 0.91x |
| W4 small-write | ops/s | 2,195 (2,294) | 740 (754) | 421 (439) | 2,403 (2,446) |  | 2.97x | 5.21x | 0.91x |
| W5 metadata-info | ops/s | 6,975 (7,694) | 4,376 (4,824) | 1,963 (2,132) | 6,926 (6,984) |  | 1.59x | 3.55x | 1.01x |
| W5 metadata-ls | entries/s | 180,068 (191,319) | 76,015 (80,485) | 44,443 (49,043) | 157,600 (183,874) | 16,437 (17,265) | 2.37x | 4.05x | 1.14x |
| W5 metadata-find | entries/s | 144,867 (190,500) | 61,316 (65,140) | 46,018 (52,645) | 153,810 (193,628) |  | 2.36x | 3.15x | 0.94x |
| W6 random-read | MB/s | 401 (442) | 4.69 (4.73) | n/a | 1,058 (1,091) |  | 85.36x |  | 0.38x |
| W7 copy | MB/s | 4,160 (4,235) | 0.88 (0.88) | error | 5,856 (6,401) |  | 4752.34x |  | 0.71x |
| W8 delete | ops/s | 40,147 (46,045) | 2,194 (2,214) | 1,594 (1,817) | 79,903 (90,540) |  | 18.30x | 25.18x | 0.50x |

Note: reference: run with {'size': 33554432, 'copy_size': 1048576} (too slow for the profile's sizes).

### HTTP (nginx)

| workload | unit | fsfast | reference | fsf | native | fsfast / ref | fsfast / fsf |
|---|---|---|---|---|---|---|---|
| W1 seq-read | MB/s | 943 (1,004) | 551 (553) |  | 2,339 (2,562) | 1.71x |  |
| W1 seq-read-open | MB/s | 2,473 (2,511) | 701 (741) |  |  | 3.53x |  |
| W2 seq-write | MB/s | 2,181 (2,333) | 1,944 (2,088) |  | 790 (1,018) | 1.12x |  |
| W3 small-read | ops/s | 26,405 (28,543) | 7,750 (8,321) |  |  | 3.41x |  |
| W4 small-write | ops/s | 2,050 (2,145) | 2,142 (2,165) |  |  | 0.96x |  |
| W5 metadata-info | ops/s | 6,428 (6,711) | 2,317 (2,386) |  |  | 2.77x |  |
| W5 metadata-ls | entries/s | 226,933 (228,184) | 256,719 (264,996) |  |  | 0.88x |  |
| W5 metadata-find | entries/s | 193,212 (218,714) | 197,991 (201,657) |  |  | 0.98x |  |
| W6 random-read | MB/s | 210 (213) | 292 (297) |  |  | 0.72x |  |
| W7 copy |  | n/a | n/a |  |  |  |  |
| W8 delete |  | n/a | n/a |  |  |  |  |

### GCS (fake-gcs-server)

| workload | unit | fsfast | reference | fsf | native | fsfast / ref | fsfast / fsf |
|---|---|---|---|---|---|---|---|
| W1 seq-read | MB/s | 608 (671) | 519 (606) | 1,311 (1,489) |  | 1.17x | 0.46x |
| W1 seq-read-open | MB/s | 1,713 (1,724) | 823 (901) |  |  | 2.08x |  |
| W2 seq-write | MB/s | 28.2 (28.2) | 21.2 (21.5) | 31.7 (31.7) |  | 1.33x | 0.89x |
| W3 small-read | ops/s | 7,081 (7,453) | 2,037 (2,317) | 7,193 (8,005) |  | 3.48x | 0.98x |
| W4 small-write | ops/s | 340 (380) | 245 (258) | 270 (290) |  | 1.39x | 1.26x |
| W5 metadata-info | ops/s | 545 (548) | 321 (333) | 573 (594) |  | 1.70x | 0.95x |
| W5 metadata-ls | entries/s | 4,246 (4,529) | 4,512 (4,656) | 3,254 (3,437) |  | 0.94x | 1.30x |
| W5 metadata-find | entries/s | 3,950 (4,404) | 4,622 (4,797) | 4,220 (4,305) |  | 0.85x | 0.94x |
| W6 random-read | MB/s | 179 (183) | 123 (131) | 414 (432) |  | 1.46x | 0.43x |
| W7 copy | MB/s | 151 (154) | 152 (159) | 174 (174) |  | 1.00x | 0.87x |
| W8 delete | ops/s | 167 (167) | 909 (953) | 1,915 (2,012) |  | 0.18x | 0.09x |

### Azure Blob (Azurite)

| workload | unit | fsfast | reference | fsf | native | fsfast / ref | fsfast / fsf |
|---|---|---|---|---|---|---|---|
| W1 seq-read | MB/s | 421 (435) | 247 (254) | 895 (934) |  | 1.70x | 0.47x |
| W1 seq-read-open | MB/s | 513 (525) | 287 (328) |  |  | 1.79x |  |
| W2 seq-write | MB/s | 54.9 (55.8) | 45.9 (46.1) | 59.0 (59.3) |  | 1.19x | 0.93x |
| W3 small-read | ops/s | 1,057 (1,074) | 253 (268) | 1,243 (1,384) |  | 4.17x | 0.85x |
| W4 small-write | ops/s | 807 (886) | 463 (463) | 658 (705) |  | 1.74x | 1.23x |
| W5 metadata-info | ops/s | 755 (801) | 315 (326) | 869 (963) |  | 2.40x | 0.87x |
| W5 metadata-ls | entries/s | 10,017 (12,428) | 2,907 (3,114) | 10,733 (12,463) |  | 3.45x | 0.93x |
| W5 metadata-find | entries/s | 11,101 (11,224) | 3,122 (3,240) | 12,328 (12,460) |  | 3.56x | 0.90x |
| W6 random-read | MB/s | 73.0 (77.7) | 33.5 (35.1) | 58.3 (60.8) |  | 2.18x | 1.25x |
| W7 copy | MB/s | 2,722 (2,724) | 1,549 (1,766) | 4,359 (4,842) |  | 1.76x | 0.62x |
| W8 delete | ops/s | 442 (460) | 184 (186) | 671 (752) |  | 2.40x | 0.66x |

### local (tmpfs)

| workload | unit | fsfast | reference | fsf | native | fsfast / ref | fsfast / fsf |
|---|---|---|---|---|---|---|---|
| W1 seq-read | MB/s | 2,174 (2,284) | 1,633 (1,709) | 8,665 (9,334) | 5,355 (5,492) | 1.33x | 0.25x |
| W1 seq-read-open | MB/s | 5,187 (5,761) | 5,739 (6,560) |  |  | 0.90x |  |
| W2 seq-write | MB/s | 2,918 (3,229) | 3,582 (3,617) | 2,361 (2,591) | 2,098 (2,381) | 0.81x | 1.24x |
| W3 small-read | ops/s | 49,810 (69,167) | 61,000 (69,503) | 84,053 (84,449) | 71,709 (73,590) | 0.82x | 0.59x |
| W4 small-write | ops/s | 61,453 (65,191) | 54,174 (55,050) | 93,729 (106,856) |  | 1.13x | 0.66x |
| W5 metadata-info | ops/s | 224,574 (225,191) | 244,020 (247,559) | 25,575 (28,209) |  | 0.92x | 8.78x |
| W5 metadata-ls | entries/s | 182,401 (183,764) | 205,612 (208,393) | 219,698 (279,360) | 242,444 (246,732) | 0.89x | 0.83x |
| W5 metadata-find | entries/s | 320,688 (346,851) | 183,784 (186,464) | 272,163 (349,381) | 1,058,194 (1,112,397) | 1.74x | 1.18x |
| W6 random-read | MB/s | 1,428 (1,853) | 1,537 (1,540) | 3,013 (5,220) |  | 0.93x | 0.47x |
| W7 copy | MB/s | 7,173 (7,273) | 2,448 (2,572) | 7,764 (7,808) | 2,518 (2,571) | 2.93x | 0.92x |
| W8 delete | ops/s | 166,555 (166,664) | 113,508 (122,000) | 363,070 (371,795) | 29,057 (36,016) | 1.47x | 0.46x |

### memory

| workload | unit | fsfast | reference | fsf | native | fsfast / ref | fsfast / fsf |
|---|---|---|---|---|---|---|---|
| W1 seq-read | MB/s | 4,331 (4,352) | 1,473 (1,484) | 20,922,483 (21,090,152) |  | 2.94x | 0.00x |
| W1 seq-read-open | MB/s | 6,492 (6,578) | 9,301 (9,497) |  |  | 0.70x |  |
| W2 seq-write | MB/s | 1,975 (2,011) | 1,875 (1,907) | 2,015 (2,093) |  | 1.05x | 0.98x |
| W3 small-read | ops/s | 426,620 (464,802) | 361,510 (368,545) | 2,773,240 (2,899,921) |  | 1.18x | 0.15x |
| W4 small-write | ops/s | 294,485 (402,039) | 135,137 (136,479) | 549,396 (570,403) |  | 2.18x | 0.54x |
| W5 metadata-info | ops/s | 494,426 (498,003) | 15,704 (15,776) | 795,117 (822,477) |  | 31.48x | 0.62x |
| W5 metadata-ls | entries/s | 1,143,883 (1,186,238) | 1,469,461 (1,487,780) | 1,246,772 (1,263,596) |  | 0.78x | 0.92x |
| W5 metadata-find | entries/s | 1,649,491 (1,683,949) | 1,346,392 (1,352,317) | 1,547,988 (1,571,657) |  | 1.23x | 1.07x |
| W6 random-read | MB/s | 4,939 (5,196) | 2,277 (2,370) | 303,444 (305,957) |  | 2.17x | 0.02x |
| W7 copy | MB/s | 925,898 (938,736) | 1,249,560 (1,418,575) | 5,555,370 (5,769,455) |  | 0.74x | 0.17x |
| W8 delete | ops/s | 167,525 (211,325) | 2,731 (2,857) | 6,423,400 (6,654,821) |  | 61.33x | 0.03x |


## Findings and follow-ups

Investigated with the request counters of `fsf --json`, fsfast's `stats()`,
direct timing probes (`cat_file` against `open().read()` on the same
object) and the source code. py-spy was installed, but no Python-level
hotspot was needed: every gap below is explained by what the code does.

**1. `cat_file` of a large object costs one extra copy (fsfast-py).**

*Status:* Fixed on 2026-11-26 for the sync `cat_file` (see [after the fixes](#after-the-fixes-2026-11-26)).

* **Symptom.** W1 `cat_file` runs at 0.4–0.6× of `open().read()` on the
  same object (median MB/s, cat_file / open().read()):

  | backend | cat_file | open().read() |
  |---|---|---|
  | SMB | 866 | 1,909 |
  | S3 | 533 | 892 |
  | GCS | 608 | 1,713 |
  | HTTP | 943 | 2,473 |

  It is also 0.25–0.9× of fsf's W1.
* **Cause.** The backends' `cat_file` already uses parallel ranged reads into
  one buffer: S3/GCS `fetch_window`, SMB `read_pipelined`, both in one
  freshly allocated buffer. fsfast-py's `cat_file` then copies that buffer
  into a new Python `bytes` (`bytes_to_py`). That is a second 256 MiB
  allocation with its page faults, plus one memcpy. `RustReader.read`
  avoids both: above `DIRECT_READ_MIN` it reads straight into the `bytes`
  object (`read_direct`).
* **Probe** (SMB, same object, 4 runs each): `cat_file` took 300–363 ms.
  `open().read()` of the whole object took 195–221 ms. `cat_file` of the
  first 200 MiB took 234–249 ms.
* **Suggested fix.** In fsfast-py's `cat_file`, read large objects the way
  `read_direct` does. Make a first bounded read (which also reveals the
  size, as `fetch_window` does), then read the rest straight into a
  pre-sized `bytes`. Alternatively, add a `cat_file_into` to the core
  `FileSystem` trait.
* **Not changed here.** The bindings are another engineer's area and were
  being modified during this task.

**2. Range coalescing reads 5× the requested bytes on random 64 KiB
reads (S3, GCS, Azure, HTTP).**

*Status:* addressed on 2026-11-26 with an amplification guard on top of the backend gaps (HTTP W6 0.72× → 2.50×; Azure W6 25% slower on loopback).

* **Settings.** These backends merge ranges whose gap is at most 1 MiB, into
  requests of up to 32 MiB (HTTP inherits `IoHints::default()`).
* **Effect on W6.** For the 500 random 64 KiB ranges of the 256 MiB object,
  that rule makes 61 requests that fetch 163 MiB in order to return
  31 MiB. SMB and local, with a 64 KiB gap, make 392 requests for 31.4 MiB.
  The numbers were computed with the same rule on the benchmark's seeded
  offsets.
* **Loopback results.** On loopback this is cheap for S3, GCS and Azure: W6
  is still 1.8–2.9× faster than the reference. On HTTP it makes fsfast
  slower than fsspec's http (0.72×), which sends 500 small GETs to a fast
  nginx.
* **Trade-off.** On a real network the trade-off reverses for latency
  (PLAN.md §4.5 chose 1 MiB for S3 on purpose: a round trip costs 10–30 ms).
  However, it multiplies egress bytes and caps parallelism at the number
  of merged groups.
* **Suggestion.** Make the gap adaptive, for example no larger than the mean
  requested range (Arrow uses 8 KiB holes), or expose it as an option.
  Measure with `tc netem` before changing the defaults. No change was made
  here, because it is a design decision.

**3. `rm()` and `copy()` of many files do one `info()` per path first
(python/fsfast).**

*Status:* Fixed on 2026-11-26 (rm, copy and get).

* **Where.** `FsfastFileSystem.rm` (used by SMB and SFTP) and
  `ObjectStoreFileSystem._rm_expanded` (used by GCS and Azure; S3 overrides
  it and does not) call `_kinds(paths)`. `_kinds` is one `info_many`, that
  is one metadata request per path, made to decide which paths are
  directories. Only then do they batch-delete. `copy()` does the same for
  its sources.
* **References.** s3fs, gcsfs and adlfs delete lists of paths without
  per-path lookups.
* **Measured.**
  * GCS W8: fsfast 167 files/s against gcsfs 909. In the first
    run, where the bucket also held the W5 tree of 10,000 objects,
    fsfast reached 62 files/s against gcsfs's 1,059: fake-gcs-server
    answers `info` more slowly as a bucket grows.
  * Azure W8: 442 against fsf's 671.
  * SMB W8: 8,365 against fsf's 10,349.
  * SFTP W8: 40,147 against fsf's 79,903.
  * A direct probe on GCS (500 files, small bucket): `fs.rm(list)` deleted
    703 files/s with 500 `info` calls, `fs.rust.rm_files(list)` 2,034
    files/s, and gcsfs 872 files/s.
* **Suggested fix.** Delete everything as files first, and look up only the
  paths that fail (`NotFoundError`/`IsADirectoryError`). Azure needs care:
  a directory-marker blob deleted as a file would skip the "directory not
  empty" check that `rmdir` makes.
* **Not changed here.** This code (rm semantics, `_rm_skips_nonempty_dirs`)
  was being edited by the compliance work in the same files.

**4. Batch concurrency defaults to the per-transfer hint.**

*Status:* Fixed on 2026-11-26: fsspec's batch sizes for the async-reference classes.

* **Behaviour.** With `batch_size=None`, fsfast's many-file calls (`cat`,
  `pipe`, `copy`, `info_many`, `rm_files` on backends without a batch API)
  run `io_hints().max_concurrency` operations at a time (fsfast-py
  `ops::concurrency`). That is 16 for S3, GCS, Azure and HTTP, and 8 for
  local. fsspec's async implementations gather 128 at a time
  (`gather_batch_size`).
* **Loopback.** No difference: on Azure, `batch_size=128` was not faster
  than the default for `copy` of 64 × 4 MiB or `cat` of 1000 × 4 KiB,
  because Azurite is the bottleneck.
* **Expected on a real network.** At 20 ms RTT the 16-way limit caps W3/W4
  at about 800 files/s, against about 6,400 for the references. This
  needs a netem run to confirm.

**5. fsfast's `stats()` counts calls, not wire requests.**

*Status:* Fixed on 2026-11-26: `stats()` reports wire requests for network backends.

* **Behaviour.** The Python `stats()` counters come from the bindings' own
  `Stats`. A 256 MiB `cat_file` (32 ranged GETs) counts as 1 request, and
  an `rm` of 5000 keys (5 DeleteObjects) counts as 1 `delete`.
* **Impact.** The docstring says "request counters". The engine's wire
  counters, which `fsf --json` reports, are not reachable from Python.
* **Benchmark consequence.** The documents call them `stats_last_iter` and
  use fsf's counters for request counts.

**6. The local and memory references are hard to beat per call.**

* **Local.** fsspec's `LocalFileSystem` calls `os.stat` and `open`
  directly. fsfast is 0.8–0.93× of it on:
  * `info` (W5), `cat` of small files (W3), `ls` and `cat_ranges` (W6),
    where it pays its bridge (about 2–5 µs per call; see the bridge
    report of wave 3);
  * `open().read()` and `open().write()` (W1-open, W2), where it reads
    into a zero-filled `bytes` and writes through the Rust buffer.
* **Memory.** fsspec's memory store is a dict. `open().read()` and
  `copy` share the stored `bytes` without copying, and `ls` is a dict
  scan, so the reference wins W1-open (0.70×), W7 (0.74×) and ls (0.78×).
* **Where fsfast wins.** fsfast wins W4 (1.1–2.2×) and `find` (1.2–1.7×) on
  both targets, and also `cat_file` (W1), W7 and W8 on local.
* **fsf's own W5 info on local** (about 25,000/s) is the CLI's tokio
  `spawn_blocking` hop per call; the Python bindings run such steps inline.

**7. Reference implementation defects found by the harness.**

* **sshfs.** `_cat_file` ignores `start`/`end`. `cat_ranges` returned the
  whole object for each range, and gathering 500 of them was killed by the
  kernel at 13.8 GB RSS, so W6 is not run for sshfs. sshfs's `copy` runs
  `cp` through one SSH exec channel per file, and 64 concurrent copies
  exceed OpenSSH's default `MaxSessions` of 10 (`ChannelOpenError`).
* **paramiko (fsspec sftp).** It writes at about 1 MB/s because it does
  not pipeline, and has no `cp_file`; the harness copies through the
  client.
* **fsspec smb.** Its `copy()` takes one pair only. With lists it fails
  inside `_as_unc_path`, so the harness calls `copy(src, dst)` per file;
  that copy is server-side.

**Fixes made in this task.** These are all in the harness: none of the
findings above needed, or was safe to make, a backend-crate change during
this task.

* Each workload's data is removed once the workload is done. W5 `info` runs
  on its own 1000-file directory, so Python and fsf see buckets of the same
  size. Without this, emulator costs that grow with the bucket size made
  fsfast look up to 4× slower than fsf.
* The local target runs on tmpfs. New-file creation on the VM's ext4 disk
  ran at 2–3k files/s and swung by 20× between runs.
* W6 is not run for sshfs (see item 7).
* The paramiko size override.

## Caveats

* **Loopback understates network latency.** Every service runs on the same
  VM as the client. Round trips cost 50–300 µs instead of 1–80 ms, and
  bandwidth is a memory copy. The reference implementations that pay one
  round trip per call (paramiko, smbprotocol, sequential `info()`) would
  fall further behind on a real network. Conversely, fsfast's 1 MiB
  coalescing gap for object stores pays off only when round trips are
  expensive (finding 2). PLAN.md §8.2 asks for `tc netem` shaping (0.2, 2,
  20 and 80 ms); that has not been done here.
* **Emulators are not the cloud.** RustFS (S3), fake-gcs-server (GCS) and
  Azurite (Azure) have their own bottlenecks. fake-gcs-server is CPU bound
  (it used up to 3.5 cores during listings of 10,000 objects). Azurite's
  block commit limits uploads to about 50–60 MB/s. RustFS's DeleteObjects
  handles about 800–1000 keys/s. These ceilings flatten the differences between
  clients on W2, W7 and W8, so they say little about AWS, GCS or Azure.
* **Shared 4-core machine.** The services, the client and the native tools
  share 4 cores and 15 GB with other engineers' builds and tests. The
  document records the load average before and after each run. It ranged
  from about 0.5 to 9.4 (the S3 and SMB runs started right after a burst at
  9.4). Run-to-run variation is about ±20% for throughput on this machine,
  and up to 2× for disk-backed writes (Samba, local), which depend on page
  cache writeback. Small ratios (0.8–1.25×) should be read as ties.
* **Page cache and tmpfs.** The services' disks are warm, so W1 reads come
  from memory, and Samba/OpenSSH writes land in the page cache. The local
  target is tmpfs (`/dev/shm`), so it measures the client's overhead, not
  a disk.
* **Bucket sizes and fsf.** `fsf` runs each workload group in its own
  bucket or directory; the Python worker removes each workload's data when
  it finishes, so the bucket sizes roughly match. They still differ by the
  one 256 MiB object, which stays until W6 is done. On fake-gcs-server and
  Azurite, whose per-request cost grows with the bucket size, compare
  fsfast with fsf only within about ±20%.
* **Memory fsf numbers** (TB/s for W1, W6 and W7) are zero-copy slices of
  the in-process store. They show that the engine adds nothing, not a
  throughput anyone can reach.
* **One client process.** Each Python implementation runs in one process
  with its default concurrency. Nothing was tuned for either side, beyond
  the paramiko size override above.
* **Not measured:** 1 GiB objects (the `large` profile exists but was not
  run, for time); PLAN.md §8's W8 (pandas/xarray/duckdb stacks); peak RSS
  per workload (only per process: `max_rss_mib`); pyarrow.fs, obstore,
  s5cmd, azcopy and aws-cli (not installed).

## Reproducing

```sh
# services (shared; start only starts what is down)
scripts/test-services.sh status
eval "$(scripts/test-services.sh env)"

# builds
cargo build --release -p fsfast-cli
. .venv/bin/activate && maturin develop --release -m crates/fsfast-py/Cargo.toml

# nginx for the http target (no root needed)
mkdir -p /tmp/nginx && (cd /tmp/nginx && apt-get download nginx && dpkg -x nginx_*.deb root)

# every target, one document per target (about 2.5 hours in total)
for t in s3 smb smb-enc sftp http gcs azure local memory; do
  extra=(); [ $t = local ] && extra=(--local-dir /dev/shm)
  .venv/bin/python bench/run.py --targets $t --profile default --timeout 5400 "${extra[@]}" \
    --nginx /tmp/nginx/root/usr/sbin/nginx --out bench/results --label default-$t
done

# tables from the documents (later documents replace earlier runs of the
# same target and implementation)
.venv/bin/python bench/run.py --report bench/results/bench-*-default-*.json

# a quick subset
.venv/bin/python bench/run.py --targets s3 smb --impls fsfast,reference -w W1,W3,W5 --profile default
```

`bench/run.py --help` lists every option. `--set size=1G --set repeat=5`
overrides profile parameters, and `--full-size` turns off the paramiko size
override. `bench/compare.py NEW.json --baseline OLD.json` reports
regressions between two documents.
