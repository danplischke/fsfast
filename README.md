# fsfast

fsfast reimplements the most used [fsspec](https://github.com/fsspec/filesystem_spec)
filesystems in Rust and exposes them to Python as drop-in replacements. The
Python classes are `fsspec.AsyncFileSystem` subclasses and keep the reference
implementation's protocol names, `storage_options`, `info()` keys, exceptions
and path rules. The work behind every method runs in Rust: the sync and async
methods, file objects, batching, retries, parallel ranged reads and multipart
uploads. The same engine also builds `fsf`, a command-line tool for copying
files and running benchmarks.

> **Status: alpha (0.1.0).** All eight backends work, and they pass fsspec's
> abstract test suite and most of the references' own test suites. All of this
> testing ran against local servers and emulators. Nothing has run against real
> AWS, GCS, Azure or Windows SMB servers yet. Read
> [Status and limitations](#status-and-limitations) before you depend on it.
> The full per-item status is in [docs/STATUS.md](docs/STATUS.md).

## Supported protocols

| fsspec protocols | fsfast class | replaces (reference) | Rust crate |
|---|---|---|---|
| `file`, `local` | `fsfast.LocalFileSystem` | `fsspec.implementations.local.LocalFileSystem` | fsfast-local |
| `memory` | `fsfast.MemoryFileSystem` | `fsspec.implementations.memory.MemoryFileSystem` | fsfast-memory |
| `http`, `https` | `fsfast.HTTPFileSystem` | `fsspec.implementations.http.HTTPFileSystem` (aiohttp) | fsfast-http |
| `s3`, `s3a` | `fsfast.S3FileSystem` | `s3fs.S3FileSystem` | fsfast-s3 |
| `smb` | `fsfast.SMBFileSystem` | `fsspec.implementations.smb.SMBFileSystem` (smbprotocol) | fsfast-smb, fsfast-smb-proto |
| `sftp`, `ssh` | `fsfast.SFTPFileSystem` | `fsspec.implementations.sftp.SFTPFileSystem` (paramiko) | fsfast-sftp |
| `gs`, `gcs` | `fsfast.GCSFileSystem` | `gcsfs.GCSFileSystem` | fsfast-gcs |
| `abfs`, `az`, `abfss` | `fsfast.AzureBlobFileSystem` | `adlfs.AzureBlobFileSystem` (Blob API) | fsfast-azure |

`fsfast.LocalFileSystem` is a subclass of fsspec's `LocalFileSystem`. The other
classes are not subclasses of their references, so fsfast does not need s3fs,
gcsfs, adlfs, smbprotocol, paramiko or aiohttp installed.

## Install and build

There is no release on PyPI yet, so you build from source. You need a Rust
toolchain (edition 2024, see `rust-version` in `Cargo.toml`), Python 3.10 or
later, and [maturin](https://www.maturin.rs/) 1.7 or later.

```sh
python -m venv .venv && . .venv/bin/activate
pip install maturin fsspec
maturin develop --release -m crates/fsfast-py/Cargo.toml   # editable install into the venv
# or build a wheel:
maturin build --release -m crates/fsfast-py/Cargo.toml --out dist
```

The wheel is abi3: one wheel per platform covers CPython 3.10 and later. The
extension module is `fsfast._core`, and the Python package is in
`python/fsfast`.

**Wheel features.** Each backend is a cargo feature of `crates/fsfast-py`, and
all of them are on by default: `local`, `memory`, `http`, `s3`, `smb`, `sftp`,
`gcs`, `azure`. A smaller wheel leaves some out. Keep `extension-module` in the
list:

```sh
maturin build --release -m crates/fsfast-py/Cargo.toml \
  --no-default-features --features extension-module,local,memory,s3 --out dist
```

`fsfast.available_protocols()` lists the protocols compiled into a build.
`fsfast.CLASSES` and `install()` only offer those protocols.

## Quick start

### Direct use

```python
import fsfast

fs = fsfast.MemoryFileSystem()
fs.pipe("/demo/hello.txt", b"hello, fsfast\n")
fs.cat("/demo/hello.txt")              # b'hello, fsfast\n'
fs.ls("/demo", detail=False)           # ['/demo/hello.txt']
with fs.open("/demo/hello.txt", "rb") as f:
    f.read(5)                          # b'hello'

local = fsfast.LocalFileSystem()
local.makedirs("/tmp/fsfast-demo", exist_ok=True)
local.pipe_file("/tmp/fsfast-demo/a.bin", b"x" * 1024)
local.info("/tmp/fsfast-demo/a.bin")["size"]   # 1024
local.rm("/tmp/fsfast-demo", recursive=True)
```

Network backends take the reference's constructor arguments. For example, the
s3fs arguments for an S3-compatible endpoint:

```python
s3 = fsfast.S3FileSystem(endpoint_url="http://127.0.0.1:9000", key="...", secret="...")
s3.mkdir("my-bucket")
s3.pipe("my-bucket/data/part-0.bin", b"abc" * 1000)
s3.info("my-bucket/data/part-0.bin")["size"]   # 3000
```

### Making existing fsspec code use fsfast

`fsfast.install()` registers fsfast's classes in fsspec's registry, so
`fsspec.filesystem`, `fsspec.open`, `url_to_fs`, pandas, xarray, dask and other
fsspec users pick them up:

```python
import fsspec, fsfast

fsfast.install()                      # every compiled-in protocol
# fsfast.install(["s3", "memory"])    # or only some
with fsspec.open("memory://demo/hello.txt", "rt") as f:
    print(f.read())
fs, path = fsspec.core.url_to_fs("s3://my-bucket/data", endpoint_url="http://127.0.0.1:9000",
                                 key="...", secret="...")
fsfast.installed()                    # protocols currently served by fsfast
fsfast.uninstall()                    # restore fsspec's previous registrations
```

With `FSFAST_OVERRIDE`, fsfast does this itself when it is imported:
`FSFAST_OVERRIDE=all`, `1` or `*` installs every protocol, and
`FSFAST_OVERRIDE=s3,memory` installs the listed ones. **Something must still
`import fsfast`.** fsfast registers no fsspec entry point, so setting the
variable alone does not change what `fsspec.filesystem("memory")` returns.

fsspec's own layers work on top of fsfast: text mode, `compression=`, chained
URLs such as `simplecache::s3://...` and `blockcache::s3://...`, `get_mapper`,
transactions and pickling. For example:

```python
with fsspec.open("memory://c/x.csv.gz", "wt", compression="infer") as f:
    f.write("a,b\n1,2\n")
```

Two more module functions: `fsfast.stats(fs)` reports request counters and
latency quantiles (wire requests for network backends), and `fsfast.runtime_info()`
describes the Rust runtime.

## The `fsf` CLI

`crates/fsfast-cli` builds `fsf`, which runs every backend without Python.

```sh
cargo build --release -p fsfast-cli
target/release/fsf --help
target/release/fsf protocols
target/release/fsf ls -l ./some/dir
target/release/fsf cp -r -j 32 ./data s3://bucket/ --opt endpoint_url=http://127.0.0.1:9000 --opt key=K --opt secret=S
target/release/fsf bench memory://bench --create --size 16MiB --count 64 -n 2
target/release/fsf --test-services bench s3://bucket --create --workloads W1,W3,W6 --json
```

- **Commands:** `ls`, `info`, `find`, `cat`, `cp`, `rm`, `mkdir`, `protocols`
  and `bench`.
- **Options** use the reference's `storage_options` names. Pass them as
  `--opt [PROTO:]KEY=VALUE`, or put them in the `FSF_OPTS` /
  `FSF_OPTS_<PROTO>` JSON environment variables. `--test-services` takes them
  from `scripts/test-services.sh env`.
- **`bench`** creates everything under a unique prefix and removes it
  afterwards. It needs a writable directory, bucket or container. Add
  `--create` when the target does not exist yet.

`fsf --help` and `fsf bench --help` show the full syntax. The exit codes and
the CI use are described in [docs/dev/ci.md](docs/dev/ci.md#the-fsf-cli-in-ci).

## Benchmarks

The table shows fsfast's median speedup over the reference implementation
(fsfast ÷ reference, median of 3 timed iterations, `default` profile). It is
copied from [docs/BENCHMARKS.md](docs/BENCHMARKS.md), which also has the
method, the raw numbers and the findings. Values below 1 mean fsfast is slower.
"n/a" means the reference cannot do the workload. Most cells were re-measured
on 2026-11-26 after the performance fixes; the rest come from the 2026-11-25
run. For smb, smb-enc and sftp, the 2026-11-26 ratios divide the new fsfast
figure by the 2026-11-25 reference figure.

| workload | s3 | smb | smb-enc | sftp | http | gcs | azure | local | memory |
|---|---|---|---|---|---|---|---|---|---|
| W1 seq-read | 1.81x | 7.03x | 6.31x | 119.56x | 1.70x | 1.76x | 1.81x | 1.80x | 2.48x |
| W1 seq-read-open | 2.02x | 7.96x | 5.28x | 175.31x | 4.80x | 1.54x | 1.73x | 1.09x | 0.71x |
| W2 seq-write | 2.81x | 6.00x | 6.73x | 747.25x | 1.12x | 1.33x | 1.19x | 0.81x | 1.05x |
| W3 small-read | 17.08x | 46.85x | 55.26x | 52.60x | 6.05x | 4.70x | 4.92x | 0.82x | 1.18x |
| W4 small-write | 3.83x | 16.69x | 5.38x | 2.97x | 3.93x | 1.44x | 1.62x | 1.13x | 2.18x |
| W5 metadata-info | 4.09x | 20.68x | 16.47x | 1.59x | 2.77x | 1.70x | 2.40x | 0.92x | 31.48x |
| W5 metadata-ls | 2.81x | 228.70x | 216.34x | 2.37x | 0.88x | 0.94x | 3.45x | 0.89x | 0.78x |
| W5 metadata-find | 2.56x | 207.42x | 201.83x | 2.36x | 0.98x | 0.85x | 3.56x | 1.74x | 1.23x |
| W6 random-read | 3.08x | 36.10x | 24.96x | 124.43x | 2.50x | 3.99x | 1.76x | 1.16x | 4.15x |
| W7 copy | 1.35x | 8.28x | 10.20x | 5156.55x | n/a | 1.09x | 2.57x | 3.66x | 0.63x |
| W8 delete | 1.12x | 50.00x | 51.06x | 43.56x | n/a | 1.90x | 3.87x | 1.20x | 76.67x |

The references are fsspec's local, memory, http (aiohttp), smb (smbprotocol)
and sftp (paramiko), plus s3fs, gcsfs and adlfs. The workload IDs are the
benchmark harness's own (`bench/README.md`). They do not match the W1–W8 of
`docs/PLAN.md` §8.1.

**Caveats, from docs/BENCHMARKS.md:**
- All services ran on loopback on one shared 4-core VM. Round trips cost
  50–300 µs instead of 1–80 ms, and no `tc netem` latency shaping was applied.
  The references that pay one round trip per call would fall further behind
  on a real network.
- S3, GCS and Azure are emulators (RustFS, fake-gcs-server, Azurite). Their
  own limits flatten the differences on writes, copies and deletes, so the
  numbers say little about AWS, GCS or Azure.
- Run-to-run variation on this machine is about ±20%, and up to 2× for
  disk-backed writes. Read ratios between 0.8 and 1.25 as ties.
- Local and memory measure the per-call bridge (about 2–5 µs) against thin
  Python wrappers. fsfast is slower there in some metadata loops and in memory
  `open().read()`.
- Not measured: 1 GiB objects, real application stacks (pandas, xarray,
  duckdb), pyarrow.fs, obstore, s5cmd and azcopy.

## Python parity and compliance

- **Parity.** [docs/dev/python-parity.md](docs/dev/python-parity.md) explains
  how each class is compared with its reference on the same live service:
  about 70 read operations, 30–40 write steps, integration through
  `fsspec.open`/`url_to_fs`, async methods, pickling and fork safety. It also
  lists every intentional deviation per backend. Examples: more precise
  exception subclasses, a working recursive `mv` on S3 and Azure where the
  references fail, server-side copy on SMB and SFTP, and methods that raise
  `NotImplementedError` (such as s3fs `merge` and `get_delegated_s3pars`,
  gcsfs `setxattrs`, and `open_async`).
- **Compliance.** [docs/dev/compliance.md](docs/dev/compliance.md) has the
  results of fsspec's abstract test suite and the references' own test suites
  run against fsfast. Last full run: every fsfast suite passes with 0 failures
  and 0 errors.
  - abstract: 1096 passed (137 per backend for local, memory, s3, gcs, azure,
    smb `data`, smb `enc` and sftp)
  - s3fs: 307
  - fsspec local/memory/http: 533
  - fsspec smb/sftp: 23
  - gcsfs: 272
  - adlfs: 131

  Every skipped or xfailed upstream test is listed with its reason. The skips
  cover reference internals such as botocore clients and aiohttp sessions,
  emulator limits, and documented deviations.

## Development

Read [CLAUDE.md](CLAUDE.md) for the conventions and [docs/PLAN.md](docs/PLAN.md)
for the architecture. The backend contract is in `crates/fsfast-core/src/fs.rs`.

```sh
# test services: RustFS (S3), Samba, OpenSSH, fake-gcs-server, Azurite
scripts/test-services.sh status          # what is listening
scripts/test-services.sh start           # starts only services that are down
eval "$(scripts/test-services.sh env)"   # FSFAST_TEST_* settings and NO_PROXY

# Rust: one crate at a time
cargo test -p fsfast-s3
cargo clippy -p fsfast-s3 --all-targets -- -D warnings

# Python
. .venv/bin/activate
maturin develop --release -m crates/fsfast-py/Cargo.toml
FSFAST_TEST_FSSPEC_PYTHON=$PWD/.venv/bin/python FSFAST_TEST_MOTO=1 \
  python -m pytest tests/python -q --timeout=120

# compliance suites (fetches the upstream test sources on first use)
tests/compliance/run.sh            # add --ref to run the references as well

# benchmarks
python bench/run.py --targets s3 smb --impls fsfast,reference -w W1,W3 --profile default
```

- **Integration tests skip without services.** They read the
  `FSFAST_TEST_*` variables. When those are unset, they print a skip message
  and pass, so a plain `cargo test` or `pytest` works on any machine.
- **Differential tests** compare against the reference packages in `.venv`.
  They need `FSFAST_TEST_FSSPEC_PYTHON`. The S3 tests that use moto need
  `FSFAST_TEST_MOTO=1`.
- **CI** (`.github/workflows/ci.yml`, described in
  [docs/dev/ci.md](docs/dev/ci.md)):
  - fmt and clippy;
  - `cargo test` with and without the services;
  - the Python tests and the abstract compliance suite against the services;
  - an `fsf` smoke benchmark;
  - abi3 wheels for Linux x86_64/aarch64 and macOS universal2, plus Windows
    as best effort.

  `bench.yml` runs nightly benchmarks with a regression report. The
  workflows were validated locally (actionlint, and the job commands run on
  the development machine), but they have not yet run on GitHub's runners.

## Status and limitations

fsfast is alpha software. [docs/STATUS.md](docs/STATUS.md) has the status of
every backend and every definition-of-done item, with the evidence. In short:

- **Tested only against local servers and emulators:** RustFS and moto for
  S3, fake-gcs-server, Azurite (Blob only, no ADLS Gen2/DFS), Samba 4.19, and
  OpenSSH 9.6. fsfast has **not been run against real AWS S3, Google Cloud
  Storage, Azure Storage, Windows Server or Azure Files SMB, macOS SMB, or NAS
  appliances**. Region redirects, IMDS/STS, Entra ID and GCE metadata
  credentials were exercised only against fakes. No test has injected network
  latency.
- **Linux only in practice.** macOS wheels are built in CI. Windows is best
  effort, and only the local backend has Windows path handling.
  Free-threaded (3.13t/3.14t) wheels are not built, although the module
  declares itself free-threading safe.
- **Not implemented from the plan:**
  - Tier-2 backends: reference/kerchunk, zip/tar, Hugging Face, FTP/FTPS,
    WebDAV, HDFS.
  - SMB enterprise and advanced milestones (SMB-3, SMB-4): Kerberos, DFS,
    durable/resilient handles, leases, reparse points/symlinks, alternate data
    streams, multichannel, compression, SMB over QUIC, POSIX extensions, share
    enumeration. Without a user name the session is anonymous.
  - S3: S3 Express One Zone, SigV4a, the SSO credential provider, and CRC
    default checksums (fsfast sends Content-MD5).
  - GCS: zonal and HNS buckets, `token="cache"`/`"browser"`, external-account
    and impersonated credentials (they raise an error), gRPC.
  - Azure: ADLS Gen2 beyond an atomic rename with `hns=True`, certificate
    credentials, version listings.
  - SFTP: ProxyJump/ProxyCommand, SSH certificates, PuTTY keys, update modes
    (`r+b`).
  - Native Rust caches (`simplecache`/`filecache`/`blockcache` run as fsspec's
    Python layers on top of fsfast), native compression codecs, and
    `open_async`.
  - Spec traceability matrices, fuzzing, interop matrices, chaos and soak
    tests (PLAN §6.8 items 4 and §7).
- **Known open issues:**
  - **SFTP:** `open(...).read()` stops at the size seen at open. A file that
    reports size 0 (such as `/proc/version`) reads as empty, and a file that
    shrinks after open raises `OSError(EPROTO)`. `cat_file` and `get_file`
    read to EOF. Fixing this needs a change to the core `ReadHandle`
    contract (see docs/STATUS.md).
  - **HTTP:** a ranged GET that starts in the middle of a 4 KiB page stalls
    about 44 ms against nginx. `cat_ranges` avoids this by aligning its
    requests, but small unaligned `cat_file` and `read` calls still hit it.
  - **Large reads on object stores and HTTP:** a large `cat_file` reads its
    first 16 MiB twice so the result comes from a single object version. The
    async `_cat_file` still copies the result once more.
  - **Azure:** metadata key case is lost, because the HTTP stack lowercases
    header names.
- **Benchmarks** come from loopback and emulators (see above). The PLAN §8.4
  targets (line rate, the s5cmd/CRT and kernel CIFS comparisons) have not been
  measured on the hardware the plan specifies.

## License

Apache-2.0 OR MIT.
