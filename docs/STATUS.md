# fsfast status (2026-11-26)

This page records where fsfast stands against [PLAN.md](PLAN.md): per backend,
per definition-of-done item (§6.8), per SMB milestone and per roadmap phase.
Each status is **done**, **partial** or **not done**, with the evidence (a
test file, a document or a code location). The claims were checked against
the code and the test files in the working tree on 2026-11-26, not copied from
the reports. Where only a report backs a claim, the text says so.

The last section holds the results of the final adversarial review and of the
performance fixes.

## Summary

- **Done:** all eight launch backends (local, memory, HTTP, S3, SMB 2/3, SFTP,
  GCS, Azure Blob) as Rust crates, Python drop-in classes, and the `fsf` CLI.
  Each has the Rust conformance suite and differential tests against its
  reference, Python parity tests on live services, fsspec's abstract suite
  (137/137 per backend), and benchmarks against the reference.
- **Partial:** upstream test suites (they run with listed exclusions; there
  is no suite for SMB/SFTP beyond fsspec's own `test_smb.py`/`test_sftp.py`),
  hypothesis stateful differential tests (memory and local only), ADLS Gen2,
  the SMB-2 milestone (POSIX rename/delete and sparse files missing), and the
  performance targets (measured on loopback and emulators only).
- **Not done:** Tier-2 backends, the SMB-3 and SMB-4 milestones, spec
  traceability matrices, fuzzing, interop matrices against real servers,
  `tc netem` and real-cloud benchmarks, chaos and soak tests, native Rust
  caches and compression codecs, free-threaded wheels, and a PyPI release.
- **Testing environment:** every test ran on one Linux VM against local
  services: RustFS 1.0.6 and moto (S3), fake-gcs-server 1.56.1, Azurite 3.38.0
  (Blob only), Samba 4.19.5, OpenSSH 9.6p1, nginx, and test servers started by
  the tests. Nothing has run against real AWS, GCS, Azure, Windows/Azure Files
  SMB, macOS, or NAS servers.

## Verification run for this page

Run on 2026-11-26 in this tree, with the test services up:

| command | result |
|---|---|
| `cargo build --release -j 2 -p fsfast-cli` | built |
| `maturin develop --release -m crates/fsfast-py/Cargo.toml` | built and installed (abi3 wheel) |
| `maturin build --release -m crates/fsfast-py/Cargo.toml --no-default-features --features extension-module,local,memory,s3` | built; in a clean environment `fsfast.available_protocols()` was `['file', 'local', 'memory', 's3', 's3a']` |
| `FSFAST_TEST_FSSPEC_PYTHON=$PWD/.venv/bin/python FSFAST_TEST_MOTO=1 python -m pytest tests/python -q --timeout=120` | **745 passed, 2 skipped** (the skips are permission tests that need a non-root user) |
| README quick start: memory, local, `install()`, `fsspec.open`, `url_to_fs`, `FSFAST_OVERRIDE`, `compression=`, `simplecache::`/`blockcache::`, `get_mapper` | all work as shown; `FSFAST_OVERRIDE` takes effect only on `import fsfast` |
| README S3 snippet against RustFS (temporary bucket, removed) | works |
| `fsf --help`, `fsf bench --help`, `fsf protocols`, `fsf ls/info/cat/cp` on local and memory | work |
| `fsf bench memory://bench --create --size 16MiB --count 64 -n 2` | all eight workloads ran, prefix removed, exit 0 (without `--create` it fails with "no such file or directory", as documented) |
| `fsf --test-services bench s3://readme-fsf-check --create -w W3,W4 --count 32 -n 1 --json` | ran, cleaned up |

Not run again for this page; these figures come from the latest reports:

- `cargo test --workspace`: 967 tests, 0 failures without services, per
  [dev/ci.md](dev/ci.md). The per-crate runs after the review fixes are in
  the fix reports.
- `tests/compliance/run.sh`: run after the performance fixes on 2026-11-26,
  with the same counts as [dev/compliance.md](dev/compliance.md).
- The benchmarks in [BENCHMARKS.md](BENCHMARKS.md).

## Per backend

Evidence keys:
- **conf.**: `fsfast-testkit` conformance suite, `crates/<crate>/tests/conformance.rs` (S3: `rustfs.rs`, `moto.rs`).
- **diff.**: Rust differential test against the reference package (`*_differential.rs`).
- **parity**: `tests/python/test_net_<backend>.py`, or `test_parity.py` for local and memory.
- **abstract**: fsspec abstract suite, `tests/compliance/abstract`.
- **upstream**: the reference's own suite, `tests/compliance/upstream`.

| backend | crate(s) | Python class | conf. | diff. | parity | abstract | upstream | bench | status |
|---|---|---|---|---|---|---|---|---|---|
| local | fsfast-local | `LocalFileSystem` (subclass of fsspec's) | yes | `fsspec_differential.rs` | `test_parity.py` (incl. hypothesis stateful) | 137/137 | fsspec `implementations/tests` (local part of 533 passed) | yes | **done** |
| memory | fsfast-memory | `MemoryFileSystem` | yes, plus `testkit_detects_faults.rs` | `fsspec_differential.rs` | `test_parity.py` (incl. hypothesis stateful) | 137/137 | fsspec (memory part) | yes | **done** |
| HTTP(S) | fsfast-http, fsfast-http-transport | `HTTPFileSystem` | yes (read-only) | `fsspec_differential.rs` | `test_net_http.py` | not run (the suite needs `makedirs`/`rm`, which fsspec's HTTP lacks) | fsspec http tests (part of 533; 20 xfails documented) | yes | **done**, with an open 44 ms stall on unaligned ranged reads (see "Open issues") |
| S3 | fsfast-s3 | `S3FileSystem` | `rustfs.rs`, `moto.rs` | `s3fs_differential.rs` | `test_net_s3.py` | 137/137 | s3fs: 307 passed, 48 skipped, 27 xfailed | yes | **done** for the s3fs surface; S3 Express, SigV4a and SSO not done |
| SMB 2/3 | fsfast-smb, fsfast-smb-proto | `SMBFileSystem` | yes (both shares) | `fsspec_differential.rs` | `test_net_smb.py` (both shares) | 137/137 per share | fsspec `test_smb.py` (part of 23) | yes | **done** for SMB-1 and most of SMB-2; SMB-3/4 not done |
| SFTP | fsfast-sftp | `SFTPFileSystem` | yes | `fsspec_differential.rs` | `test_net_sftp.py` | 137/137 | fsspec `test_sftp.py` (part of 23) | yes | **done**, with one partly open read issue |
| GCS | fsfast-gcs | `GCSFileSystem` | yes | `gcsfs_differential.rs` | `test_net_gcs.py` | 137/137 | gcsfs: 272 passed, 118 skipped, 3 xfailed | yes | **done** on the emulator; zonal/HNS buckets not done |
| Azure Blob | fsfast-azure | `AzureBlobFileSystem` | yes | `adlfs_differential.rs` | `test_net_azure.py` | 137/137 | adlfs: 131 passed, 55 skipped, 6 xfailed | yes | **done** for Blob; ADLS Gen2 **partial** |

Python layer (`crates/fsfast-py`, `python/fsfast`): sync and async methods,
the `FsfastFile` file object (readahead, `readinto`, block cache modes, a
working `_fetch_range` for fsspec's `blockcache::`), pickling, fork safety
(`test_net_smb.py`/`test_net_sftp.py::test_fork_rebuilds_connections`),
listings cache for object stores, transactions, `install()`/`FSFAST_OVERRIDE`,
and cargo-feature backend selection. Status: **done**, except `open_async`
(raises `NotImplementedError`) and free-threaded wheels (see Cross-cutting).

CLI (`crates/fsfast-cli`): `ls`/`info`/`find`/`cat`/`cp`/`rm`/`mkdir`/
`protocols`/`bench`. `tests/cli.rs` and `tests/regressions.rs` cover the 14
review findings. Status: **done**.

## Definition of done (§6.8)

| # | item | local | memory | http | s3 | smb | sftp | gcs | azure |
|---|---|---|---|---|---|---|---|---|---|
| 1 | API coverage (Appendix A, sync and async) | done | done | done¹ | done² | done | done³ | done² | done² |
| 2a | fsspec abstract suite passes | done | done | n/a⁴ | done | done | done | done | done |
| 2b | upstream suite runs, exclusions listed | done | done | done | done | partial⁵ | partial⁵ | done | done |
| 3 | hypothesis stateful differential tests | done | done | not done | not done | not done | not done | not done | not done |
| 4 | traceability matrix, interop matrix, 24 h fuzzing | not done | not done | not done | not done | not done⁶ | not done | not done | not done |
| 5 | §8.4 performance targets on standard hardware | not done⁷ | not done⁷ | not done⁷ | not done⁷ | not done⁷ | not done⁷ | not done⁷ | not done⁷ |
| 6 | docs: options table, known differences, tuning | partial⁸ | partial⁸ | partial⁸ | partial⁸ | partial⁸ | partial⁸ | partial⁸ | partial⁸ |

1. Every Appendix A method exists on every class (checked with `hasattr` on
   2026-11-26). Gaps that are documented deviations or raise
   `NotImplementedError`:
   - all classes: `open_async`;
   - http: `get_client`, and HTTP listings are not cached.
2. These raise `NotImplementedError` and are listed in
   [dev/python-parity.md](dev/python-parity.md):
   - s3: `merge`, `get_delegated_s3pars`, `list/clear_multipart_uploads`,
     `session=`;
   - gcs: `setxattrs`, `ls(versions=)`;
   - azure: `ls(versions=)`, async credentials, `f.version_id`.
3. Only modes `rb`/`wb`/`ab`/`xb`; paramiko's `r+b` is not supported.
4. fsspec's HTTP filesystem cannot do the operations the abstract suite needs.
5. fsspec's `test_smb.py`/`test_sftp.py` run (23 passed, 9 skipped). sshfs's
   own suite and the Samba/smbprotocol suites were not adapted.
6. What exists for SMB:
   - codec property tests (`crates/fsfast-smb-proto/tests/proptest_codec.rs`);
   - reference vectors generated with smbprotocol (`tests/reference/gen_vectors.py`);
   - a live Samba smoke test.

   There is no cargo-fuzz target, no MS-SMB2 §3.2 traceability matrix and no
   `tshark` capture validation. The other backends have unit, vector and
   property tests (S3 SigV4 against botocore vectors, GCS/Azure vectors), but
   no formal matrix.
7. Benchmarks exist for every backend ([BENCHMARKS.md](BENCHMARKS.md)), but
   they ran on loopback against emulators on a shared 4-core VM, not on the
   hardware §8.2 specifies. They measured no `tc netem` latency, no real
   cloud, and no line rate or s5cmd/CRT/kernel CIFS ceilings. Against those
   proxies, most targets are not met (for example S3 W3 is 17× s3fs against
   a target of 10×, and SMB metadata is 16–230× fsspec smb), but none was
   measured as specified.
8. The intentional differences are documented per backend in
   [dev/python-parity.md](dev/python-parity.md). The options are documented
   in each crate's top-level rustdoc (e.g. `crates/fsfast-smb/src/lib.rs`
   "Options", `crates/fsfast-s3/src/options.rs`). There is no user-facing
   options mapping table or tuning guide per backend yet.

## Per-backend plan items (§6.1–6.6)

### Local and memory (§6.1)

| item | status | evidence |
|---|---|---|
| `copy` in the kernel | done | `copy_file_range(2)` (`crates/fsfast-local/src/ops.rs`, `lib.rs`); `tests/cross_device.rs` |
| parallel `find`/`du` walk | done | `crates/fsfast-local/src/lib.rs` (parallel directory listing) |
| `statx`, `getdents` directly, macOS `clonefile`, io_uring | not done | std/tokio file APIs are used |
| Windows paths | partial | path handling and tests in fsfast-local; Windows wheels are best effort and untested on a runner |
| FIFO/char-device `cat_file` | done (deliberate deviation) | `crates/fsfast-local/src/tests.rs::cat_file_reads_a_fifo_as_a_stream`; fsspec 2026.9.0 raises `io.UnsupportedOperation` instead |

### HTTP (§6.2)

| item | status | evidence |
|---|---|---|
| HEAD, falling back to `Range: bytes=0-0`; size fallbacks | done | `crates/fsfast-http/src/info.rs` |
| `Accept-Ranges` detection, buffered reads without range support | done | `crates/fsfast-http/src/handle.rs`, `info.rs` |
| fsspec-compatible link scraping | done | `fsspec_differential.rs`, `test_net_http.py` |
| redirects with same-origin auth, Content-Encoding, HTTP/2, cookies, proxies | done | fsfast-http-transport (`tests/env_proxy.rs`, `tls.rs`, `faults.rs`), [adr/0002-http-client.md](adr/0002-http-client.md) |
| per-call request options (`headers=`, `auth=`, `params=`) | done | python review fix `http-per-call-request-kwargs-dropped` (`python/fsfast/_http.py`, `tests/python/test_review_fixes.py`) |
| 44 ms stall on ranged GETs that start mid-page | **open** | found by the performance work; it is in fsfast-http-transport. `cat_ranges` aligns to 4 KiB to avoid it ([BENCHMARKS.md](BENCHMARKS.md)) |

### S3 (§6.3)

| item | status | evidence |
|---|---|---|
| List V2 / ListObjectVersions, Head/Get with ranges, versionId, SSE-C, requester pays | done | `crates/fsfast-s3/src/{list,read,params}.rs`; `tests/moto.rs`, `requests.rs` |
| Put, multipart lifecycle, CopyObject/UploadPartCopy, DeleteObjects, bucket ops, tagging, ACL, presign | done | `write.rs`, `client.rs`, `extras.rs`; `tests/requests.rs`, `sigv4_vectors.rs` |
| multipart copies pinned to the source ETag | done (review fix) | `tests/requests.rs::multipart_copies_are_pinned_to_the_source_etag`, `tests/rustfs.rs::copy_parts_are_pinned_to_the_source_version` |
| conditional writes (`If-None-Match: *` for `xb`, `If-Match`) | done | `write.rs`, `read.rs` |
| integrity checksums | partial | Content-MD5 on object data (Object Lock works: `tests/moto.rs::object_lock_bucket_uploads`); CRC32C/CRC64NVME default and full-object checksums not done |
| S3 Express One Zone, SigV4a | not done | SigV4a options are rejected as Unsupported (`options.rs`) |
| dual-stack, FIPS, Transfer Acceleration, path/virtual addressing | done | `endpoint.rs`, `options.rs` |
| credential chain (env, profiles, process, web identity, IMDS, ECS, assume-role) | done, tested only with fakes | `tests/credentials.rs`; SSO and the `login` provider not done |
| spreading connections over resolved IPs | not done | no per-IP spreading in fsfast-s3 or the transport |
| parallel ranged GETs, concurrent multipart from `open('wb')`, native batch delete | done | fsfast-engine `read_parallel`, part uploader; `tests/budget.rs` (memory budget) |
| HEAD+LIST race for `info` | done (opt-in) | `speculative_info` option (`options.rs`, `list.rs`) |
| s3fs directory semantics, `version_aware`, `info()` keys, transactions | done | s3fs suite (307 passed), `test_net_s3.py` |
| compatibility matrix (AWS, MinIO, Ceph, R2, ...) | not done | only RustFS and moto |

### GCS and Azure (§6.4)

| item | status | evidence |
|---|---|---|
| GCS JSON API, XML multipart, resumable uploads, compose, `ifGenerationMatch=0`, generation-pinned reads, CRC32C, HTTP/2 | done | `crates/fsfast-gcs/src/{ops,write,read}.rs`; `tests/mock.rs`, `emulator.rs`; versioning only on mocks (the emulator has none) |
| GCS auth: anon, token file/dict, service account JWT, ADC, metadata server | done, real Google not tested | `crates/fsfast-gcs/src/auth`; unsupported ADC types now raise an error (review fix) |
| GCS `token="cache"`/`"browser"`, external account, impersonation, zonal/HNS, gRPC | not done | crate docs |
| Azure block blobs (parallel Put Block / Put Block List), append blobs for `ab`, copy, SAS, shared key, connection strings | done | `crates/fsfast-azure/src/write.rs`, `ops.rs`; `tests/azurite.rs`, `review.rs` |
| Azure Entra ID (client secret, managed identity, workload identity, Azure CLI) | done, tested only against in-process fakes | `crates/fsfast-azure/src/auth/token.rs`, `tests/tokens.rs` |
| Azure certificate credentials, other DefaultAzureCredential sources | not done | `options.rs` returns Unsupported for `AZURE_CLIENT_CERTIFICATE_PATH` |
| ADLS Gen2 (DFS endpoint) | partial | `hns=True` gives an atomic rename (mock-tested only). DFS listing, mkdir/rmdir and recursive delete not done. Azurite has no DFS |
| metadata key case | open | keys come back lowercased (checked on Azurite 2026-11-26) |

### SMB 2/3 (§6.5): milestones

**SMB-1 (core): done, except NetBIOS.**

| item | status | evidence |
|---|---|---|
| TCP 445 | done | |
| NetBIOS over port 139 (optional) | not done | |
| NEGOTIATE 2.0.2–3.1.1 with contexts (preauth SHA-512, encryption, signing) | done | `crates/fsfast-smb-proto/src/msg/negotiate.rs`, `crates/fsfast-smb/src/session.rs` |
| NTLMv2 through SPNEGO; guest and anonymous with the correct signing rules | done | `fsfast-smb-proto` auth, reference vectors |
| SP800-108 KDF; HMAC-SHA256/AES-CMAC/AES-GMAC signing | done | `crypto/` with smbprotocol reference vectors |
| CREATE (with contexts), CLOSE, READ, WRITE, QUERY_INFO, SET_INFO, QUERY_DIRECTORY, IOCTL, ECHO, LOGOFF, CANCEL | done | `crates/fsfast-smb/src/{conn,ops,session,client}.rs` |
| FLUSH | encoded in fsfast-smb-proto, not sent by the client | |
| STATUS_PENDING interim responses, CANCEL of abandoned requests (also when the interim arrives late) | done | `src/tests.rs::abandoned_request_is_cancelled_when_the_interim_arrives_later` |
| MessageId and credit accounting | done | `credits.rs`, mock-server tests |
| NTSTATUS → errno | done | |
| VALIDATE_NEGOTIATE_INFO on 3.0/3.0.2 | done | |

**SMB-2 (throughput): partial.**

| item | status | evidence |
|---|---|---|
| encryption with AES-128/256-GCM/CCM | done | live test against the `enc` share |
| large-MTU multi-credit I/O | done | gated on the server's `SMB2_GLOBAL_CAP_LARGE_MTU`, review fix: `src/tests.rs::multi_credit_requires_the_servers_large_mtu_capability` |
| credit-window pipelining | done | |
| compound chains for metadata, small `cat` and small `pipe` | done | |
| server-side copy (FSCTL_SRV_COPYCHUNK_WRITE) | done | `copy.rs` |
| decryption in place; zero-copy `readinto` path | partial | frames are decrypted in place and READ data is sliced without copying. Python `readinto` and large `cat_file` fill the destination directly, but decryption does not write straight into the caller's buffer |
| delete and rename through SET_INFO | done | |
| POSIX `FileDispositionInformationEx`/`FileRenameInformationEx` | not done | |
| truncate (FileEndOfFileInformation) | done | |
| sparse files | not done | |

**SMB-3 (enterprise): not done.** Kerberos (without a user name the session is
anonymous), DFS, durable/resilient handles (open handles fail after a
reconnect; idempotent metadata calls retry), leases/oplocks, reparse
points/symlinks, alternate data streams, share flags beyond encryption, a
quirks database.

**SMB-4 (advanced): not done.** Multichannel, compression (fsfast-smb-proto has
the compression header codec only), SMB over QUIC, POSIX extensions, change
notify.

**Interop matrix: not done.** Only Samba 4.19 (signing-required and
encryption-required shares) was tested. The plan also lists Windows Server,
ksmbd, Azure Files, macOS, NAS appliances, Kerberos-only, DFS and netem.

### SFTP (§6.6)

| item | status | evidence |
|---|---|---|
| russh transport with AEAD ciphers, connection pool | done | `crates/fsfast-sftp/src/{ssh,pool}.rs` |
| extensions: `limits@`, `posix-rename@`, `statvfs@`, `fsync@`, `hardlink@`, `copy-data`, `expand-path@` | done | `src/proto`, `session.rs`, `fs.rs` |
| pipelined READ/WRITE with out-of-order reassembly | done | `handle.rs`, `tests/bench.rs` |
| auth: password, keys (OpenSSH/PEM, encrypted), agent, keyboard-interactive | done | `ssh/auth.rs`; `tests/key_auth.rs` (runs as root in CI) |
| certificates, PPK | not done | |
| `~/.ssh/config` (Host, IdentityFile, Port, HostKeyAlias, `IdentityAgent $VAR`) | done | `ssh/config.rs`; HostKeyAlias with a non-22 port fixed in review (`tests/host_keys.rs`) |
| ProxyJump/ProxyCommand | not done | the connection fails with Unsupported instead of connecting directly |
| strict known_hosts checking (hashed entries) | done | `ssh/known_hosts.rs`, `tests/host_keys.rs` |
| non-UTF-8 file names | done (review fix) | names are no longer decoded lossily |
| reads to EOF | partial | see "Open issues" |

## Roadmap phases (§9)

| phase | status | notes |
|---|---|---|
| 0: foundations and baselines | partial | Done: workspace, CI workflows, test-services script, benchmark harness, ADRs 0001–0003. Not done: the netem scripts, the macOS/Windows test matrix, cargo-deny, the Phase-0 time-attribution report as a separate document (BENCHMARKS.md's findings cover part of it) |
| 1: core and the first read path | done | core, engine, transport, local/memory/HTTP, S3 read path, Python layer |
| SMB track S1–S2 | mostly done | SMB-1 done except NetBIOS; SMB-2 partial (see above); tested against Samba only, not Windows |
| 2: complete S3 and alpha | partial | S3 writes, multipart, copy, versioning, s3fs suite, differential tests, URL chaining (through fsspec) done. Native disk/whole-file caches and default CRC checksums not done. **No PyPI release** |
| 3: GCS and Azure; SMB enterprise | partial | GCS and Azure Blob done; ADLS Gen2 partial; SMB-3 not done |
| 4: SFTP and tier-1 polish | partial | SFTP done. Not done: native compression codecs, free-threaded wheels, the Windows/macOS performance pass, SMB-4 |
| 5: Tier 2, hardening, 1.0 | not done | no Tier-2 backends, no sustained fuzzing, no security review, no docs site |

## Cross-cutting

| item | status | evidence |
|---|---|---|
| engine: retry/backoff, adaptive concurrency, memory budget, parallel ranged reads, readahead, part uploader, stats | done | `crates/fsfast-engine` (unit, `tests/stress.rs`, `tests/local_file.rs`, criterion benches `benches/`) |
| caching (§4.6) | partial | in-file cache modes in Rust (`readahead`, `blockcache`, `background`, `mmap`; `crates/fsfast-py/src/file.rs`). fsspec's `simplecache::`/`filecache::`/`blockcache::` work on top of fsfast, but are not native |
| URL chaining | done (fsspec) | checked 2026-11-26 with `simplecache::memory://` and `blockcache::memory://` |
| `compression=` codecs | done through fsspec's Python codecs; native codecs not done | checked with `compression="infer"` |
| free-threaded Python | partial | the module declares `gil_used = false`; no 3.13t/3.14t wheels are built |
| wheels | partial | CI builds abi3 wheels for manylinux x86_64/aarch64 and macOS universal2; Windows is best effort. The CI workflows have not run on GitHub yet ([dev/ci.md](dev/ci.md)) |
| CI | done locally | `.github/workflows/ci.yml` (fmt, clippy, tests with and without services, SFTP key auth as root, pytest, `bench/test_bench.py`, `tests/compliance/test_runner.py`, abstract compliance suite, fsf smoke bench, wheels), `bench.yml` (nightly, regression report, `continue-on-error` on shared runners) |
| benchmarks (§8) | partial | harness and results ([BENCHMARKS.md](BENCHMARKS.md)). Missing: netem, real cloud, iperf3, native ceilings other than smbclient/sftp/curl/coreutils, real-stack workloads, CPU/GiB targets, a dashboard |
| robustness (§7): chaos, soak, free-threaded stress | partial | fork and pickle tests exist; transport fault injection exists (`fsfast-http-transport/tests/faults.rs`); no toxiproxy/netem chaos or 24 h soak |
| security defaults: TLS verification, strict host keys, no SMB1/NTLMv1, no dialect downgrade | done | transport TLS tests, `tests/host_keys.rs`, VALIDATE_NEGOTIATE |

## Final review results

An adversarial review of every area found the defects below. The area
owners fixed them, with regression tests where the reports say so. "Not
fixed" lists what remains. Severities are the reviewers'.

| area | confirmed | fixed | not fixed |
|---|---:|---:|---|
| smb | 4 (2 major, 2 minor) | 4 | none |
| s3 | 7 (2 major, 5 minor) | 7 | none |
| sftp | 8 (3 major, 5 minor) | 8 (one of them only partly) | `size-at-open-bounds-reads`, partly (below) |
| gcs-azure | 5 (1 critical, 1 major, 3 minor) | 5 | none |
| http-engine-core | 3 (2 major, 1 minor) | 3 | none |
| python | 9 (4 major, 5 minor) | 9 | none |
| cli-ci-bench | 14 (3 critical, 5 major, 6 minor) | 14 | none |

Confirmed findings, all reported fixed:

- **smb:**
  - a cancelled CREATE leaked the server handle, and the file stayed locked;
  - `cat_file` of files over 1 MiB read the data twice (2.2× slower);
  - an abandoned async operation was not CANCELled when its interim response
    arrived late;
  - multi-credit mode ignored the server's LARGE_MTU capability.
- **s3:**
  - multipart server-side copies were not pinned to the source ETag;
  - PutObject sent no Content-MD5, so writes to Object Lock buckets failed;
  - a provider that returned expired credentials was called on every
    request;
  - a missing `AWS_PROFILE` was silently ignored;
  - `s3_additional_kwargs` overrode per-call headers;
  - `ab` append of a small SSE-C object failed with a per-call key;
  - `get_file` bypassed the memory budget.
- **sftp:**
  - HostKeyAlias with a non-22 port skipped the pinned key (MITM accepted
    under `auto_add`);
  - reads were bounded by the size at open;
  - non-UTF-8 names were decoded lossily;
  - `SSH_FX_BAD_MESSAGE` became `ValueError`;
  - a cancelled `close()` lost pending WRITE statuses;
  - `close()` raced a pool grow;
  - a request submitted during session shutdown could hang;
  - `IdentityAgent $VAR` was treated as a literal path.
- **gcs-azure:**
  - a failed Append Block dropped its 4 MiB chunk, and `close()` then saved a
    file with a hole (critical);
  - `find(withdirs)` let a directory shadow a blob of the same name;
  - a second `close()` after a failure returned success;
  - concurrent requests each repeated a failing token fetch;
  - an unsupported ADC type silently fell back to anonymous access.
- **http-engine-core:**
  - memory `flush()` was quadratic;
  - local `open('rb')` did not see data appended after open;
  - a failed write through a symlink deleted the symlink.
- **python:**
  - copy/put/mv left stale cached listings on object stores;
  - a signal handler that touched a blocked file deadlocked;
  - HTTP per-call request options were dropped;
  - files lacked `_fetch_range` for `blockcache::`;
  - `readlines(hint)` stopped one line early;
  - local reads stopped at the size seen at open;
  - transaction temporary files were visible;
  - invalidation wrappers ignored keyword destinations;
  - memory files raised on a negative relative seek.
- **cli-ci-bench:**
  - `fsf rm -r` on a symlink deleted the link target's contents (critical);
  - `rm -r abfs://` deleted every container (critical);
  - location parsing panicked on multi-byte UTF-8 (critical);
  - `cp -r` failed on folder markers;
  - `rm -r` left the prefix marker behind;
  - fail-fast `cp` left truncated files;
  - `cp -r src/` copied the directory instead of its contents;
  - `run.sh` passed on a stale JUnit XML;
  - `bench --create` leaked buckets;
  - single-file `cp` did not create parents and named the wrong path;
  - W7 with `--dest` double-counted requests;
  - CI gaps;
  - failed nightly runs polluted the baseline;
  - URL passwords were echoed into output.

Spot checks for this page: the regression tests named above exist in the tree
(SMB `src/tests.rs` and `tests/live.rs::cancelled_opens_do_not_leave_the_file_locked`;
S3 `tests/requests.rs`, `tests/rustfs.rs`, `tests/moto.rs`, `tests/credentials.rs`,
`tests/budget.rs`; CLI `tests/regressions.rs`; Python `tests/python/test_review_fixes.py`).
The Python suite passed in full (745 passed). I did not re-run every Rust
crate's tests for this page.

**Not fixed: SFTP reads bounded by the size at open (partly fixed).**
`cat_file` and `get_file` now read to EOF, which covers files that report
size 0 (such as `/proc`), files that grow and files that shrink. Through the
Python file object, two cases still fail:

- `open('/proc/version').read()` returns 0 bytes (re-checked on 2026-11-26:
  `cat_file` returns 124 bytes, `open().read()` returns 0);
- a file that shrank after open raises `OSError(EPROTO, 'short read ...')`.

Both follow from the core `ReadHandle` contract: `read_at` returns exactly
`min(len, size - offset)`, and `size()` is the size at open. The engine's
readahead and `read_parallel_into` depend on that contract. A fix needs a
decision in fsfast-core, the engine and fsfast-py, for example a "size
unknown, read to EOF" handle flag, or treating a short read as EOF in the
file reader. fsspec's `AbstractBufferedFile` bounds reads of files that grow
after open in the same way.

## Performance fixes (2026-11-26)

Six benchmark findings were fixed in python/fsfast, crates/fsfast-py,
crates/fsfast-smb (counters) and crates/fsfast-local (FIFO). The affected rows
were re-run; [BENCHMARKS.md](BENCHMARKS.md), section "After the fixes", has
the full before/after table. Headline changes, fsfast ÷ reference:

- GCS W8 delete: 0.18× to 1.90×.
- HTTP W6 random reads: 0.72× to 2.50×.
- HTTP W4: 2,050 to 16,762 files/s.
- SMB W1 `cat_file`: 866 to 1,273 MB/s.

The fixes:
1. rm/copy/get without an `info()` per path.
2. Large `cat_file` read directly into the result `bytes`.
3. fsspec's batch sizes for the async-reference backends.
4. `stats()` reports wire requests.
5. Local FIFO `cat_file` reads the content.
6. A read-amplification guard for `cat_ranges`.

The perf owner reported 715 passed / 2 skipped in `tests/python` and
unchanged compliance counts. This page's run gave 745 passed / 2 skipped,
which includes the review-fix tests added since.

Open after the performance work:
- the HTTP mid-page ranged read stall (fsfast-http-transport);
- async `_cat_file` still copies;
- large `cat_file` on S3/GCS/Azure/HTTP reads the first 16 MiB twice plus a
  HEAD, to stay on one object version (a cleaner fix needs a core API);
- the `cat_ranges` guard makes many more small requests (Azure W6 −25% on
  Azurite) and was not measured under real latency;
- the wire counters of SFTP/GCS/Azure/HTTP/S3 were not audited;
- smb/smb-enc/sftp "after" ratios divide by the previous day's reference
  figures;
- some regressions are attributed to noise without proof (SFTP W1, smb-enc
  W6, memory W7).

## Open issues (user-visible)

- **SFTP:** reads through `open()` are bounded by the size at open (see
  above).
- **HTTP:** a ranged GET that starts mid-page stalls about 44 ms against
  nginx. Small unaligned `cat_file`/`read` calls are affected.
- **Azure:** metadata keys are lowercased.
- **All network backends:** never run against the real services.
