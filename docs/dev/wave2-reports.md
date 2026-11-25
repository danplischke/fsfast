# Wave-2 reports (network backends)

Condensed from the implementer and adversarial-reviewer reports. Read this before wiring these crates into fsfast-py, benchmarking, or extending them.


## smb


### Public API

crate fsfast_smb:
- `pub struct SmbFileSystem` (Clone; clones share the pool) and `pub type SMBFileSystem = SmbFileSystem`. Implements `fsfast_core::FileSystem`: protocols() = ["smb"]; capabilities hierarchical, atomic_rename, server_side_copy, append, conditional_create and random_write are all true.
  - `pub fn new(cfg: SmbConfig) -> Self`
  - `pub fn from_options(opts: fsfast_core::Options) -> fsfast_core::Result<Self>` (strict: unknown keys fail)
  - `pub async fn connect(&self) -> Result<()>`: fsspec's eager `register_session`. It does nothing when `register_session_retries < 0`. The Python constructor should call it so bad credentials fail at construction, as in fsspec.
  - `pub fn config(&self) -> &SmbConfig`
  - `pub fn stats(&self) -> &Arc<fsfast_engine::stats::Stats>`
  - `pub async fn connection_info(&self, share: &str) -> Result<ConnectionInfo>`: diagnostics with fields dialect, signing_algorithm, signing, cipher, encrypt_all, share_encrypted, max_read_size, max_write_size, max_transact_size, credit_window, frames_sent, local_addr, direct_reads, connections.
- `pub const INFO_KEYS: &[&str] = &["uid","gid","time","mtime"]`: the `info_keys` value for the fsfast-py registry. Directories also carry `extra["name"]` (the path with a trailing `/`), which overrides `name` in the dict.
- `pub struct SmbReadHandle` (a ReadHandle) and `pub struct SmbWriteHandle` (a WriteHandle).
- `pub mod config`:
  - `pub struct SmbConfig` with public fields, plus `SmbConfig::new(host)`, `with_credentials(user, pw)`, `with_port(p)`, `from_options(Options)` and `port()`.
  - `pub fn strip_protocol(&str) -> String` (fsspec `_strip_protocol`)
  - `pub fn get_kwargs_from_urls(&str) -> Options` (fsspec `_get_kwargs_from_urls`; keys host, port, username, password, url_query, url_fragment)
  - `pub fn parent(&str) -> String` (fsspec `_parent`)
  - `pub fn parse_dialect(&str) -> Result<Dialect>`
  - `DEFAULT_PORT`
- `pub mod credits`: `pub fn charge_for(bytes) -> u16`, `CREDIT_BYTES`.

Accepted options:
- fsspec's: `host` (required), `port`, `username`, `password`, `timeout` (connection timeout in seconds, default 60), `encrypt`, `share_access` (letters r/w/d; none means exclusive), `register_session_retries` (default 4), `register_session_retry_wait` (default 1), `register_session_retry_factor` (default 10), `auto_mkdir`, `temppath`.
- Accepted and ignored: `skip_instance_cache`, `use_listings_cache`, `listings_expiry_time`, `max_paths`, `asynchronous`, `loop`, `url_query`, `url_fragment`.
- fsfast extras:
  - `require_signing` (bool, default true, like smbprotocol)
  - `min_dialect` and `max_dialect` ("2.0.2", "2.1", "3.0", "3.0.2", "3.1.1")
  - `max_credits` (default 2048)
  - `read_chunk_size` and `write_chunk_size` (4 KiB–8 MiB, default 2 MiB)
  - `max_inflight` (default 16)
  - `connections` (default 4, opened lazily, chosen by path)
  - `request_timeout` (seconds, default none)
  - `keepalive_interval` (seconds, default 60; 0 disables)

Bindings notes: in the fsfast-py registry, use `rebuild_after_fork: true` (the instance holds sockets and tasks) and `INFO_KEYS` as the info key order.

### Known gaps (implementer)

- The testkit check `special_names` is skipped on Samba: Samba lists names Windows cannot represent (the testkit's `comma,dot.dot..` with trailing dots) under mangled 8.3 aliases, exactly as smbclient sees them. tests/live.rs `unusual_names_round_trip` covers all the other names and checks the trailing-dot name by path. Fixing it needs the SMB 3.1.1 POSIX extensions (SMB-4).
- The Python layer must be wired up in crates/fsfast-py, which I did not touch: a `smb` feature, a registry entry with `info_keys = fsfast_smb::INFO_KEYS` and `rebuild_after_fork: true`, an eager `connect()` in the constructor (as fsspec's `register_session` does), `strip_protocol`/`get_kwargs_from_urls`, and `temppath` for non-autocommit writes. Directory names in dicts depend on `extra["name"]` overriding `name`, which works with the current `info_to_py` because extra keys are written after `name`.
- Not implemented (SMB-3/4 scope): Kerberos/integrated authentication (no user name gives an anonymous session, which Samba with mandatory signing refuses), DFS referrals, durable/resilient handles (open handles fail with ConnectionFailed after a reconnect; idempotent metadata operations retry transparently), leases/oplocks (never requested), reparse points/symlinks (`type: link` is never reported; smbclient follows links too), multichannel, compression, QUIC, POSIX extensions, and share enumeration (`ls('/')` raises InvalidInput, like fsspec's ValueError).
- Interop has only been run against Samba 4.19. Windows Server, Azure Files, ksmbd and NAS servers are untested; the CCM peek path and the copy-chunk limit renegotiation path have only been exercised by unit tests or not at all live.
- Deliberate behaviour differences from fsspec smb (documented in lib.rs): mv_file replaces an existing destination (the testkit requires it); cross-share mv falls back to copy+delete; ls of a file returns its info (core contract); touch(truncate=False) updates mtime; `workgroup;user` is split into domain and user; mkdir of a missing child under a file gives NotFound, as smbclient does. cat_file with a negative range or start>end is not compared: fsspec smb itself fails there (AttributeError/ValueError) and core ByteRange semantics apply.
- Performance notes: an encrypted WRITE copies its payload once before sealing (smb-proto's encrypt API has no out-of-place mode). Reads into a fresh large buffer pay page faults, roughly 30% below zero-copy slices. Sequential per-operation latency (about 150–270 µs on loopback) includes three tokio task hops (caller, writer, reader); writing inline from the caller is a possible follow-up. Benchmarks ran on a shared 4-core VM without netem, so numbers vary by up to 2× between runs.
- The memory budget only covers in-flight WRITE payloads. Read destinations are mandatory buffers and are not counted, following the engine's model. CLOSEs of handles dropped without close() are sent in the background, ordered per path; the server sees them before the next operation on that path from the same filesystem.

### Review findings

- [critical] FIXED: Signature check skipped when a response's unauthenticated SessionId is 0, so a MITM can inject unsigned responses (including direct READ data) on a signing session (conn.rs verify/verify_parts). Regression test: forged_session_id_does_not_bypass_signature_checks
- [minor] FIXED: A sealed (GCM) READ response whose caller was dropped was discarded without authentication, after its unauthenticated credit grant had been applied (route_sealed). Regression test: sealed_reads_of_dropped_callers_are_still_authenticated
- [minor] FIXED: The ls compound could cost more credits than the granted window (each QUERY_DIRECTORY capped at half the window on its own), so on low-credit servers ls waited and then failed with Throttled. Regression test: listing_compound_fits_the_credit_window (fails on window 5 with the old sizing)
- [minor] OPEN: STATUS_NETWORK_SESSION_EXPIRED / USER_SESSION_DELETED reconnect instead of re-authenticating the session (MS-SMB2 §3.2.4.2.3). Open handles and non-idempotent operations in flight on that connection fail with ConnectionFailed; idempotent operations retry transparently
- [minor] OPEN: Unsigned USER_SESSION_DELETED / NETWORK_SESSION_EXPIRED responses are accepted on signing sessions (needed for interop), so an attacker can force reconnects; denial of service only
- [minor] OPEN: Cancelling SmbWriteHandle::write mid-call can drop already-coalesced buffered bytes (bytes_written still counts them); only matters if callers cancel write futures
- [minor] OPEN: Implementer's sequential-write number (about 1,400 MB/s) is not reproducible as a steady figure: Samba write throughput swings 352 to 1,729 MB/s between identical runs; reads are steady

### Remaining risks (reviewer)

- Session expiry is handled by reconnecting, not by re-authenticating the existing SessionId, so open handles do not survive STATUS_NETWORK_SESSION_EXPIRED. This could not be tested live because Samba does not expire NTLM sessions.
- Small race: if a GCM READ caller is dropped after the reader has routed the sealed frame to it but before it authenticates it, that one frame is never authenticated. It is discarded and nothing is delivered.
- Responses to abandoned requests or to unknown MessageIds still return their (unauthenticated) credit grants without signature checks; a forged grant can at worst make the client exceed the window, and the server then drops the connection.
- Interop has only been run against Samba 4.19 (Windows, Azure Files, ksmbd and NAS servers untested). The CCM path, the copy-chunk limit renegotiation path and low-credit servers are covered only by unit tests.
- Throughput numbers come from a shared 4-core VM; write throughput is dominated by Samba's disk writeback and varies 3× between runs.
- Not implemented, as the implementer reported: Kerberos, DFS, durable handles, leases, reparse points, multichannel, the POSIX extensions (testkit special_names is skipped on Samba) and the Python bindings in fsfast-py.

### Performance (reviewer)

Method: `FSFAST_TEST_SMB_BENCH=1 FSFAST_TEST_SMB_BENCH_CONNS=4 FSFAST_TEST_FSSPEC_PYTHON=.venv/bin/python cargo test --release -p fsfast-smb --test bench bench_against_fsspec -- --nocapture`. Release build, local Samba over loopback, SMB 3.1.1. The `data` share uses AES-GMAC signing; `enc` uses AES-128-GCM. fsspec SMBFileSystem ran the same workloads against the same server, timed with perf_counter. The load average was 1.4–2.2, with another engineer's fake-gcs-server using about 25% of a core.

| workload | data: fsfast | data: fsspec | enc: fsfast | enc: fsspec |
|---|---|---|---|---|
| sequential read, 256 MiB | 1302 MB/s | 135 MB/s (9.7×) | 778 MB/s | 136 MB/s (5.7×) |
| sequential write, 256 MiB | 352 MB/s | 133 MB/s | 282 MB/s | 126 MB/s |
| server-side copy, 256 MiB | 2226 MB/s | not measured | 928 MB/s | not measured |
| info on 1000 files, sequential | 6228 ops/s | 367 (17×) | 5646 ops/s | 399 (14×) |
| info on 1000 files, 64 concurrent | 46,348 ops/s | — | 51,335 ops/s | — |
| cat of 1000 × 4 KiB, sequential | 2783 ops/s | 363 (7.7×) | 3114 ops/s | 319 (9.8×) |
| cat of 1000 × 4 KiB, 64 concurrent | 21,762 ops/s | — | 27,818 ops/s | — |
| pipe of 1000 × 4 KiB, sequential | 1268 ops/s | 311 (4×) | 810 ops/s | 258 (3.1×) |
| ls of 10,000 entries (with details) | 102 ms | 26.7 s (260×); names only 215 ms | 111 ms | 24.5 s; names only 222 ms |

Reads, metadata, small files and listing confirm the implementer's numbers, and better than 10× faster than fsspec on reads shows that requests are kept in flight.

Sequential write does not reproduce the claimed ~1,400 MB/s as a steady figure. In this run it was 352 MB/s on data and 282 MB/s on enc, which was the first large write of the run. `bench_chunk_sizes` run straight afterwards gave 589–1,729 MB/s on data and 776–1,713 MB/s on enc, swinging up to 3× between neighbouring configurations with no pattern by chunk size, while reads stayed at 1.17–1.42 GB/s on data and 0.76–1.04 GB/s on enc. That points to Samba's disk writeback, not the client, as the variable. Writes are still 2–13× faster than fsspec.

None of my changes touch the hot path: they add an integer comparison per response and change the size of the `ls` buffers only when the credit window is small.

## s3


### Public API

Crate `fsfast_s3`. All public items have doc comments.

Construction:
- `pub struct S3FileSystem` (Clone; type alias `S3FS`). Implements `fsfast_core::FileSystem`; `protocols()` = ["s3", "s3a"].
- `pub fn from_options(opts: fsfast_core::Options) -> fsfast_core::Result<S3FileSystem>`: parses through OptionReader and calls finish(). No I/O; configuration is resolved on the first operation.
- `pub fn with_options(opts: S3Options) -> S3FileSystem`.
- `S3Options::parse(Options) -> Result<S3Options>` and `S3Options::parse_with_env(Options, profile::Env) -> Result<S3Options>` (the second is for tests).

Capabilities and hints:
- Capabilities: hierarchical=false, atomic_rename=false, server_side_copy=true, append=true (s3fs-style, not atomic), conditional_create=true, random_write=false, versioning=version_aware, signed_urls=true, pinned_reads=true.
- io_hints: request_size 8 MiB (option `request_size`), max_concurrency = `max_concurrency` (default 16), coalesce_gap 1 MiB, max_coalesced max(request_size, 32 MiB).

Accepted options:
- s3fs top level: anon, endpoint_url, key, secret, token, username, password (giving both key and username, or both secret and password, is an error), use_ssl, client_kwargs, config_kwargs, s3_additional_kwargs, requester_pays, version_aware, cache_regions, default_block_size, default_fill_cache, default_cache_type (validated), fixed_upload_size, local_expiry_check, max_concurrency (>= 1), profile.
- Accepted and ignored: asynchronous, loop, session, skip_instance_cache, use_listings_cache, listings_expiry_time, max_paths.
- client_kwargs: region_name, endpoint_url, use_ssl, verify (bool or CA path), aws_access_key_id, aws_secret_access_key, aws_session_token, config (a botocore Config converted to a dict), plus api_version and aws_account_id (ignored).
- config_kwargs:
  - Used: region_name, signature_version ('s3v4'/'v4'; 'unsigned'/'UNSIGNED' means anon; 's3' is Unsupported), connect_timeout, read_timeout, max_pool_connections, user_agent, user_agent_extra, user_agent_appid, proxies, use_dualstack_endpoint, use_fips_endpoint.
  - `s3` dict: addressing_style, use_accelerate_endpoint, use_dualstack_endpoint, payload_signing_enabled, us_east_1_regional_endpoint; use_arn_region and s3_disable_multiregion_access_points are ignored.
  - `retries` dict: max_attempts, total_max_attempts, mode.
  - Rejected as Unsupported: client_cert, sigv4a_signing_region_set.
  - Ignored on purpose: parameter_validation, inject_host_prefix, tcp_keepalive, endpoint_discovery_enabled, proxies_config, request_min_compression_size_bytes, disable_request_compression, request_checksum_calculation, response_checksum_validation, account_id_endpoint_mode, auth_scheme_preference, client_context_params, defaults_mode, ignore_configured_endpoint_urls.
- s3_additional_kwargs: any of the 45 botocore parameter names in params_table.rs (ServerSideEncryption, SSEKMSKeyId, SSECustomerAlgorithm, SSECustomerKey (str or bytes), ACL, StorageClass, ContentType, Metadata, Tagging, RequestPayer, ExpectedBucketOwner, ...). Unknown names are an error.
- fsfast-only options: connect_timeout, read_timeout, total_timeout, max_retries, limit_per_host, http2, ca_bundle, user_agent, rotate_dns, request_size, part_size, speculative_info, strict_delete (default true), probe_conditional_writes (default true), copy_threshold, copy_part_size.

Per-call extras:
- `ReadOptions.extra` and `WriteOptions.extra` take botocore parameter names (e.g. ServerSideEncryption) and override s3_additional_kwargs.
- `WriteOptions.content_type` and `WriteOptions.metadata` map to Content-Type and x-amz-meta-*.
- `ReadOptions.version` reads a specific version (version_aware only); `pin_version=false` disables If-Match pinning.

Inherent methods on S3FileSystem:
- `options() -> &S3Options`
- `stats() -> &Arc<fsfast_engine::stats::Stats>`
- `default_block_size() -> usize`, `default_cache_type() -> &str`, `default_fill_cache() -> bool`, `version_aware() -> bool`
- `split_path(&str) -> (String, String, Option<String>)`
- `async bucket_region(&str) -> Result<String>`, `async http_client() -> Result<HttpClient>`
- `async object_versions(path) -> Result<Vec<FileInfo>>` (s3fs object_version_info)
- `async ls_versions(path) -> Result<Vec<FileInfo>>` (s3fs ls(versions=True))
- `async find_prefix(path, prefix: &str, opts: &FindOptions) -> Result<Vec<FileInfo>>`
- `async metadata(path) -> Result<BTreeMap<String,String>>`, `async getxattr(path, name) -> Result<Option<String>>`
- `async setxattr(path, attrs: &BTreeMap<String, Option<String>>, copy_params: Option<&params::Params>) -> Result<()>`
- `async get_tags(path) -> Result<BTreeMap<String,String>>`, `async put_tags(path, tags: &BTreeMap<String,String>, merge: bool) -> Result<()>`
- `async chmod(path, acl: &str, recursive: bool) -> Result<()>` (validated against `KEY_ACLS` / `BUCKET_ACLS`)
- `async is_bucket_versioned(bucket) -> Result<bool>`, `async make_bucket_versioned(bucket, versioned: bool) -> Result<()>`

Handles:
- `S3ReadHandle` (ReadHandle; `etag()`, `is_pinned()`).
- `S3WriteHandle` (WriteHandle).

Public modules:
- `path`: PROTOCOLS, strip_protocol, parent, split_path, S3Path, is_virtual_hostable.
- `info`: s3fs dict layouts.
- `error`: classify, S3ErrorParser, errno.
- `credentials`: Credentials, ProvideCredentials, CredentialsCache, ChainContext, default_chain, each provider.
- `sigv4`: Signer::sign / presign, sha256_hex.
- Also `profile` (Env, ProfileFiles, configured_endpoint), `endpoint`, `xml`, `params`, `encode`, `options`.

FileInfo dicts:
- extra holds s3fs's keys.
- HEAD of a file: ETag, LastModified (datetime, or "" if missing), StorageClass (default STANDARD), VersionId (None), ContentType (None).
- Listings: Key, Size, LastModified, ETag, StorageClass, plus optional ChecksumAlgorithm, ChecksumType, Owner, RestoreStatus, VersionId, IsLatest.
- Directories: Key, Size, StorageClass=DIRECTORY. Buckets: StorageClass=DIRECTORY and VersionId=None from info; CreationDate and StorageClass=BUCKET from ls("").
- FileInfo.version = ETag, FileInfo.modified = LastModified.

Wiring into fsfast-py was not done (outside this task's directories). It needs `s3 = ["dep:fsfast-s3"]` in crates/fsfast-py and a registry entry. The Python class should translate botocore.UNSIGNED to the string 'unsigned' and a botocore Config object to a dict.

### Known gaps (implementer)

- Not wired into the Python bindings: crates/fsfast-py needs an `s3` feature and registry entry, and python/fsfast an S3FileSystem class (outside this task's directories). Python-layer work still to do: listings cache/dircache, transactions (autocommit=False), checksum/ukey from ETag, translating botocore.UNSIGNED and Config objects, `session` objects, and choosing `strict_delete=False` if exact s3fs rm semantics are wanted.
- No default request checksums (CRC32/CRC32C/CRC64NVME, which botocore >= 1.36 sends) and no aws-chunked streaming SigV4 (STREAMING-AWS4-HMAC-SHA256-PAYLOAD). Bodies are always in memory or read in parts, so header signing with SHA-256 or UNSIGNED-PAYLOAD covers every request this crate makes.
- Credential providers not implemented: AWS SSO (sso_session / sso_start_url token cache), the `login` provider, and the boto2 config files. assume-role profiles with mfa_serial return Unsupported (they need interactive MFA). credential_process uses POSIX shlex splitting on every platform. IMDS-based default region discovery is not done.
- Unsupported: S3 Express One Zone, SigV4a/Multi-Region Access Points, and requests to access-point/outposts/object-lambda ARNs (paths are split like s3fs, requests return Unsupported). Keys with '.' or '..' path segments are rejected (InvalidInput) because URL normalization would address another object.
- No parallel prefix-sharded listing (PLAN §4.5): find and ls paginate one page at a time; only find(maxdepth) lists each level concurrently.
- cat_file of large objects copies each byte twice (network chunk → part Bytes → final buffer), because the core ReadHandle::read_at returns Bytes and I reused fsfast_engine::read_parallel_into as CLAUDE.md requires. A read-into-buffer method on ReadHandle (a core change) would remove one copy.
- SSE-C was verified only at the request-header level (recording fake server). moto does not enforce SSE-C, and RustFS (like MinIO) requires TLS for it. Requester-pays headers are likewise verified by the fake; moto accepts them without enforcement.
- Interop was tested only against RustFS, moto and fake servers, not real AWS, MinIO, Ceph, R2 or GCS interop. Global-endpoint redirects, IMDS on EC2 and real STS were exercised only with fakes. RustFS rejects keys with empty path segments ('a//b'), so those are covered by unit and fake tests only.
- Deliberate differences from s3fs, documented in the crate docs: strict_delete (NotFound/IsADirectory on rm, default on); cat_file of a range past EOF returns b'' (s3fs: OSError EINVAL); touch(truncate=False) on an existing object is Unsupported (s3fs: ValueError); open of a directory prefix is NotFound; presigned URLs use SigV4 with the regional host; multipart copy and setxattr keep content type and metadata; mkdir in us-east-1 sends no LocationConstraint.
- The conditional-write probe writes and deletes a small object (`.fsfast-conditional-write-probe-<hex>`) next to the key, once per filesystem. If writing the probe is not permitted, fsfast trusts the server. It can be turned off with probe_conditional_writes=False.
- Benchmarks are indicative only: loopback HTTP to a RustFS server on the same 4-core machine, which was heavily loaded by other builds (load average 3–7). There are no AWS numbers and no netem latency shaping, and rm throughput is limited by the RustFS server.

### Review findings

- [major] FIXED: Concurrent requests rejected with ExpiredToken throw away each other's refresh. A later rejection called CredentialsCache::invalidate() after another request had already stored fresh credentials, and is_refreshable() could then see an empty cache, so the request returned ExpiredToken instead of retrying. Fix: the retry is tied to the credentials that attempt was signed with (new invalidate_if_current); test: concurrent_expired_token_rejections_share_one_refresh, 64 concurrent requests, exactly one refresh.
- [major] FIXED: Credential leak in Debug output: Env and ProfileFiles derived Debug, and they sit inside the credential chain that S3FileSystem/State, S3ReadHandle and S3WriteHandle print. {:?} of a handle printed AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN and the shared credentials file's secrets. Fix: custom Debug that shows names only; test: debug_output_never_contains_secrets (also checks the SSE-C key).
- [major] FIXED: Refresh storm: when a refresh fails, or returns credentials that are still inside the refresh window (short-lived credentials, local clock running ahead), every later request called the provider (STS/IMDS/container) again. Fix: a 30 s cool-down while the current credentials are still valid; expired credentials are never served. Test: short_lived_credentials_do_not_cause_a_refresh_storm.
- [minor] FIXED: s3fs parity: ls_versions of a plain file path returned [] where s3fs raises FileNotFoundError. Fix: implemented s3fs _ls's parent-listing fallback, so only an exact ?versionId= path matches. Found by the new version_aware_matches_s3fs differential on moto.
- [minor] FIXED: 409 ConditionalRequestConflict (a conditional write that raced another write of the key and was not applied) mapped to a non-retryable error. AWS documents it as safe to retry; it is now retried and still maps to EBUSY. Test: conditional_write_conflicts_are_retried.
- [minor] FIXED: Test gaps closed: botocore vectors for presigned URLs of all 16 awkward keys (session token, 604800 s expiry), metadata/tagging header canonicalisation (mixed case, tabs, empty value) and STS AssumeRole signing; multipart boundary tests (exactly part_size, empty file, part_size+1) and part-retry / Complete 200-with-error tests; version_aware differential against s3fs on moto; trailing-slash and protocol-prefixed paths in the RustFS differential. The same differential also passes against moto. All passed: no further bugs in these areas.
- [minor] OPEN: Not fixed: a create-only (If-None-Match: *) PutObject or CompleteMultipartUpload whose first attempt succeeded but lost its response is retried, gets 412, and reports AlreadyExists for an object this client wrote. botocore has the same ambiguity. Turning the 412 into success after an ETag check would break exclusive-create locks, so I left it.
- [minor] OPEN: Not fixed, by design: with strict_delete (the default), a recursive rm built from find + rm_files checks existence again with LIST pages it does not need, because the rm_files contract requires NotFound. The Python layer could pass strict_delete=False for recursive deletes.

### Remaining risks (reviewer)

- A create-only write retried after its first attempt succeeded server-side but lost the response reports AlreadyExists (same ambiguity in botocore).
- A proxy URL with embedded credentials from config_kwargs['proxies'] ends up in fsfast-http-transport's ProxyConfig, whose Debug is outside this crate. The BasicAuth form is redacted; user:pass inside the URL string may not be.
- RequestTimeTooSkewed is not corrected automatically: with a clock off by more than 15 min every signed request fails (botocore does not correct it either).
- Per-key transient errors in a DeleteObjects result (SlowDown/InternalError for single keys) are reported to the caller, not retried (s3fs does the same).
- Benchmarks are loopback-only on a heavily shared 4-core machine; get_file on loopback is only at parity with s3fs. No AWS or latency-shaped numbers.
- Still untested against real AWS, MinIO, Ceph or R2: region redirects, IMDS/STS, SSE-C enforcement and requester-pays were checked only with fake servers or moto. Gaps the implementer already listed remain: no default CRC checksums, no SSO, no S3 Express or SigV4a, no Python bindings yet.
- With strict_delete on, a recursive rm built from find + rm_files repeats the existence check with extra LIST requests; the Python layer should consider strict_delete=False for recursive deletes.

### Performance (reviewer)

Method: `cargo build --release -p fsfast-s3 --example s3_bench && ./target/release/examples/s3_bench 256 3` against `.venv/bin/python crates/fsfast-s3/tools/bench_s3fs.py 256 3` (s3fs, default options, no listings cache), same RustFS at http://127.0.0.1:9000 on loopback, best of N runs. Other engineers' builds kept the 4-core machine at load average 0.6–8 during the runs, so expect about ±25% noise. Large objects were also run twice more, interleaved with s3fs, best of 5 (FSFAST_BENCH_ONLY=large).

Results (fsfast vs s3fs):
- pipe_file 256 MiB: 305–433 vs 232–248 MB/s (~1.6x)
- cat_file 256 MiB: 520–635 vs 286–341 MB/s (~1.9x)
- put_file: 317–383 vs 194–250 MB/s (~1.5x)
- get_file: 482–709 vs 459–606 MB/s. This is roughly parity under this load, not the ~1.4x the implementer reported: on loopback, s3fs's single streaming GET is already efficient, and the parallel ranged GETs compete with RustFS for 4 cores. No defect found in the code path (zero-copy part buffers, positional writes on the blocking pool).
- 1000 × 4 KiB cat: 1074 vs 199 files/s sequential; 6100 (64 in flight) vs 437 (fs.cat).
- info on 1000 keys: 2287 vs 356 ops/s sequential; 12175 vs 942 with 64 concurrent.
- rm 5000 keys: 5.14 s vs 6.11 s (fsfast includes its strict existence check; RustFS deletes at roughly 1k keys/s either way).
- Client CPU for the full benchmark: fsfast user 3.2 s + sys 4.9 s, vs s3fs user 49.4 s + sys 10.3 s.
- 28,333 requests, 0 retries.

These confirm the implementer's figures except get_file. No performance fixes were needed; the refresh cool-down removes a potential provider call on every request.

## sftp


### Public API

Crate fsfast_sftp:
- `pub struct SftpFileSystem` and `pub type SFTPFileSystem = SftpFileSystem`, implementing fsfast_core::FileSystem.
  - `pub fn new(cfg: SftpConfig) -> Self`
  - `pub fn from_options(opts: fsfast_core::Options) -> fsfast_core::Result<Self>`
  - `pub fn config(&self) -> &SftpConfig`
  - `pub fn temppath(&self) -> &str`
  - `pub fn stats(&self) -> &Arc<fsfast_engine::Stats>`
  - `pub fn connections(&self) -> usize`
  - `pub async fn connection_info(&self) -> Result<ConnectionInfo>`
  - `pub async fn lstat_info(&self, p: &str) -> Result<FileInfo>`
  - `pub async fn readlink(&self, p: &str) -> Result<String>`
  - `pub async fn symlink(&self, target: &str, link: &str) -> Result<()>`
  - `pub async fn hardlink(&self, old: &str, new: &str) -> Result<()>`
  - `pub async fn statvfs(&self, p: &str) -> Result<Statvfs>`
  - `pub async fn realpath(&self, p: &str) -> Result<String>`
  - `pub async fn expand_path(&self, p: &str) -> Result<String>`
  - `pub async fn home_directory(&self, user: &str) -> Result<String>`
  - `pub async fn chmod(&self, p: &str, mode: u32) -> Result<()>`
  - `pub async fn set_times(&self, p: &str, atime: u32, mtime: u32) -> Result<()>`
  - `close()` comes from the trait.
- `pub struct SftpConfig` with `new(host)`, `with_credentials(user, pw)`, `with_port(port)`, `from_options(opts) -> Result<Self>` and `disabled(category)`.
- `pub enum HostKeyPolicy { AutoAdd, Warning, Reject }` with `parse(&str)` and `as_str()`.
- `pub enum SshConfigSource`.
- `pub fn strip_protocol(path: &str) -> String`, `pub fn parent(path: &str) -> String`, `pub fn get_kwargs_from_urls(url: &str) -> Options`.
- `pub const INFO_KEYS`.
- `SftpReadHandle` / `SftpWriteHandle`.
- Modules: proto, session, pool, ssh, error, info, options, handle.

Accepted options:
- fsspec/paramiko names:
  - Connection and auth: host (required), port, username, password, pkey (key text), key_filename (str or list), passphrase, allow_agent, look_for_keys, compress.
  - Timeouts: timeout, banner_timeout, auth_timeout, channel_timeout.
  - Other: disabled_algorithms (dict of category -> list), host_key_policy ("auto_add" default | "warning" | "reject"), temppath.
- AbstractFileSystem cache options are accepted and ignored: skip_instance_cache, use_listings_cache, and the rest of the IGNORED_BASE_OPTIONS list in options.rs. paramiko-only gss* options are also accepted and ignored.
- Rejected when set (Python objects): sock, transport_factory, auth_strategy.
- fsfast extensions:
  - Connection and config: known_hosts (path, list, or False), ssh_config (path(s) or False), connections (pool size, default 4), keepalive_interval.
  - Transfer tuning: max_inflight (default 64), read_chunk_size, write_chunk_size, request_timeout, fsync_on_close.
- Unknown options are errors (OptionReader::finish).

protocols(): sftp, ssh. info()/ls() keys exactly as fsspec `_decode_stat`: name, size, type (file / directory / link in ls), uid, gid, time (atime), mtime. Error codes are attached as Detail::Sftp(code).

### Known gaps (implementer)

- ProxyJump/ProxyCommand are not implemented. A configured jump host makes the connection fail with ErrorKind::Unsupported rather than connect directly.
- SSH user certificates and PuTTY .ppk keys are not supported (PLAN §6.6 lists certificates and 'PPK later').
- The READ window is adaptive up to a fixed cap (max_inflight, default 64, of the server's max read length). It is not tuned by measured RTT as PLAN §6.6 suggests. Only loopback was benchmarked, not the planned 20 ms RTT link.
- Known exception-type divergences from fsspec are documented in lib.rs:
- mkdir/makedirs under a regular file: fsfast raises NotADirectoryError, fsspec FileNotFoundError.
- rmdir of a non-empty directory: ENOTEMPTY; of a file: NotADirectoryError.
- rm_file of a directory: IsADirectoryError.
- `xb` on an existing file: FileExistsError.
- makedirs(file, exist_ok=True) raises.
These are precision choices; if strict parity is required, they need flipping in src/fs.rs.
- Not run: fsspec's abstract test suite and sshfs' own test suite against the Python bindings, the hypothesis stateful differential tests, and 24 h of decoder fuzzing (PLAN §6.8). Codec robustness is covered only by the proptests.
- Benchmarks used loopback on a shared 4-core machine, so numbers vary by about ±30% between runs. The pool reaches 4 connections only after background handshakes finish, so very short bursts run on 1 connection.

### Review findings

- [major] FIXED: Security: under host_key_policy='reject', a host key that an auto_add filesystem in the same process had accepted unverified was treated as known, so a man-in-the-middle on the first auto_add connection could get past 'reject'. Now under 'reject' only known_hosts files vouch for a key; learned keys still block a different key in every mode (unit test policy_matrix and live test host_keys.rs updated)
- [major] FIXED: Server handles leaked when ls(), cp_file() or an append-mode open_write() was cancelled while a directory or destination handle was open (cancellation is not safe). Added a HandleGuard that sends CLOSE on drop; tests/resources.rs failed before the fix and passes now
- [major] FIXED: Lost write error: SftpWriteHandle::reap_one took the pending WRITE off the queue before awaiting it. If write() was cancelled while waiting for window space, that WRITE's status was dropped and a later close() reported success even though the WRITE had failed. The call now stays queued until its reply arrives (unit test cancelled_write_keeps_the_pending_write_status)
- [minor] FIXED: OPEN/OPENDIR handle leaked when the HANDLE reply had already reached a pending call that was then dropped without being polled, or in the race between the reader taking the slot and sending the reply. Drop now closes the receiver and closes any reply already received, and dispatch closes a handle it could not deliver (unit test dropped_unpolled_open_with_delivered_handle_is_closed)
- [minor] FIXED: Hang: the SFTP handshake (INIT/VERSION and the limits@openssh.com query) had no timeout, so a server that accepts the subsystem but never answers would block pool connects forever while holding the connect lock. Added SessionOptions::handshake_timeout, which the pool sets from channel_timeout (unit test silent_server_handshake_times_out)
- [minor] FIXED: fsspec exception parity: mkdir/makedirs below a regular file and rmdir of a file raised NotADirectoryError; fsspec raises FileNotFoundError (OpenSSH reports ENOTDIR as NO_SUCH_FILE). The kind is now NotFound with the native code attached and a message naming the component that is not a directory; the differential test checks these cases exactly
- [minor] OPEN: The host key is not checked when the server rekeys: russh 0.65.4 calls check_server_key only during the first key exchange and kex_done receives no key. Only a server that already holds the session keys can start a rekey, so the risk is limited, but OpenSSH would reject a key change here

### Remaining risks (reviewer)

- russh does not re-verify the host key when the server rekeys (upstream limitation, described in the findings).
- There is no default request_timeout or keepalive, as with paramiko. A silently dead TCP connection hangs in-flight requests until the OS gives up, unless request_timeout or keepalive_interval (or ssh_config ServerAliveInterval) is set.
- Under auto_add, if the host has known keys only of other types, a key of a new type is accepted. This matches paramiko and is documented, but a man-in-the-middle that offers only that new type would be accepted.
- If close() fails before CLOSE is sent (a WRITE failed), the server handle stays open until abort() or drop. Drop does release it.
- If a server sends an empty DATA reply in the middle of a file, it is treated as EOF (paramiko does the same), so read_at may return fewer bytes than the contract requires. OpenSSH never sends empty DATA.
- A hostile server that announces a 4 MiB max read length can make one pipeline hold up to max_inflight x 4 MiB of buffered data (about 256 MiB at the default 64).
- ssh_config `Match final`/`canonical` blocks never match, so a ProxyJump set only inside such a block would be bypassed instead of refused.
- Not run: fsspec's abstract test suite and sshfs' own tests through the Python bindings, long fuzzing of the decoders, and a benchmark on a link with real latency.

### Performance (reviewer)

Setup: loopback OpenSSH on 127.0.0.1:2222, password auth, shared 4-core machine, so expect ±30% between runs. My review changes do not touch any hot path; the only addition is one cheap check when a pending call is dropped.

Methods:
- fsfast: `FSFAST_SFTP_BENCH=1 cargo test --release -p fsfast-sftp --test bench -- --nocapture --test-threads=1`
- reference: `.venv/bin/python -I crates/fsfast-sftp/tests/python/reference_bench.py paramiko 32 1000`, then the same with `sshfs 256 1000`
- paramiko used a 32 MiB file because its writes run at about 1 MB/s; fsfast and sshfs used 256 MiB.

Large file (two rounds, MB/s):
| operation | fsfast | paramiko (fsspec sftp) | sshfs |
|---|---|---|---|
| write | 452–604 | 1.1 | 143–163 |
| cat_file | 577–750 | 4.1–4.3 | 120–161 |
| get_file | 711–716 | 116–146 | 141–167 |
| put_file | 271–598 | 96–150 | 137–154 |
| cp_file (server-side copy-data) | 1083–3114 | NotImplementedError | not measured |

1000 x 16 KiB files, one at a time:
| operation | fsfast | paramiko | sshfs |
|---|---|---|---|
| pipe (files/s) | 2811 | 1161 | 161 |
| cat (files/s) | 3346 | 211 | 559 |
| info (ops/s) | 6573 | 5699 | 1670 |

32 concurrent (fsfast pool grew to 4 connections; sshfs through its async API):
| operation | fsfast | sshfs |
|---|---|---|
| pipe (files/s) | 19,085 | 412 |
| cat (files/s) | 26,768 | 1525 |
| info (ops/s) | 94,341 | 4926 |

Other operations:
| operation | fsfast | paramiko | sshfs |
|---|---|---|---|
| ls of 1000 entries | 4.0 ms | 50 ms (under concurrent load) | 20 ms |
| rm 1000 files (files/s) | 9917 (pipelined rm_files) | 2726 | 882 |

These confirm the implementer's figures within run-to-run variance. I found no performance defects: AEAD ciphers come first, the channel window is 64 MiB, up to 64 reads of 255 KiB are in flight, small requests are coalesced, DATA payloads are not copied, and metadata requests are batched.

## gcs


### Public API

crate fsfast_gcs:

Types:
- `pub struct GCSFileSystem` (Clone, Debug); alias `pub type GcsFileSystem = GCSFileSystem`
- `impl FileSystem for GCSFileSystem` (protocols ["gs","gcs"]; overrides info, ls, find, open_read, open_write, cat_file, cat_ranges, pipe_file, rm_file, rm_files, mkdir, makedirs (no-op as in gcsfs), rmdir, cp_file, mv_file, put_file, get_file, touch, sign)
- Capabilities: server_side_copy, conditional_create and pinned_reads are true; versioning is true when version_aware; signed_urls is true when a service-account key is known.

Constructors:
- `pub fn from_options(opts: fsfast_core::Options) -> fsfast_core::Result<Self>`
- `pub fn from_options_with_env(opts: Options, env: GcsEnv) -> Result<Self>` (explicit environment snapshot)
- `pub fn with_options(opts: GcsOptions) -> Result<Self>`

Accessors and helpers:
- `pub fn options(&self) -> &GcsOptions`
- `pub fn stats(&self) -> &Arc<fsfast_engine::stats::Stats>`
- `pub fn http_client(&self) -> &HttpClient`
- `pub fn location(&self) -> &str`
- `pub fn on_google(&self) -> bool`
- `pub fn default_block_size(&self) -> usize`
- `pub fn version_aware(&self) -> bool`
- `pub fn auth_method(&self) -> &'static str`
- `pub async fn project(&self) -> Result<Option<String>>`
- `pub fn split_path(&self, path: &str) -> (String, String, Option<String>)`
- `pub fn url(&self, path: &str, generation: Option<&str>) -> Result<String>`
- `pub async fn buckets(&self) -> Result<Vec<String>>`
- `pub fn sign_with(&self, path: &str, method: &str, expires: Duration, now: SystemTime) -> Result<String>`
- `pub async fn merge(&self, path: &str, paths: &[String]) -> Result<()>` (objects.compose)

Handles:
- `GcsReadHandle` (ReadHandle; `generation()`, `is_pinned()`)
- `GcsWriteHandle` (WriteHandle; `session_url()`, `chunk_size()`)

Other public items:
- `GcsEnv` (`from_process`, `from_pairs`, `with_product_name_file`)
- `GcsOptions` (pub fields), `options::{Consistency, RequesterPays, DEFAULT_BLOCK_SIZE, round_chunk}`
- `path::{strip_protocol, split_path, parent, quote, GcsPath}`
- `info::{object_info, parse_timestamp, ...}`
- `error::GcsErrorParser`
- `auth::{TokenSpec, Credentials, AccessToken, jwt::ServiceAccountKey, jwt::parse_private_key, ...}`
- `sign::{signed_url_v4, v4_timestamp}`
- `crc32c_b64`, `goog_hash_crc32c`

Storage options accepted:
- gcsfs options: project, access (read_only|read_write|full_control), token (None|"google_default"|"cloud"|"anon"|path|dict|raw token; "cache"/"browser" are Unsupported), consistency (none|size|md5|crc32c), requests_timeout, requester_pays (bool or project id), session_kwargs (aiohttp ClientSession kwargs via HttpConfig::apply_client_kwargs), endpoint_url (else $STORAGE_EMULATOR_HOST, else https://storage.$GOOGLE_CLOUD_UNIVERSE_DOMAIN), default_location, version_aware, block_size.
- Accepted and ignored (Python-layer or no effect): cache_timeout, secure_serialize, check_connection, timeout, asynchronous, loop, batch_size, skip_instance_cache, use_listings_cache, listings_expiry_time, max_paths.
- fsfast tuning: request_size (default 8 MiB), max_concurrency (default 16), upload_chunk_size (default 16 MiB, rounded to 256 KiB), simple_upload_threshold (default 16 MiB), verify_crc32c (default true), plus HttpConfig::apply_fsfast_options (connect_timeout, read_timeout, total_timeout, max_retries, limit_per_host, http2, ca_bundle, user_agent, rotate_dns).
- Unknown options are errors.

Write options (WriteOptions.extra): metadata, fixed_key_metadata (content_encoding, cache_control, content_disposition, content_language, custom_time), kms_key_name, content_type, consistency, acl (accepted, ignored as in gcsfs). Others are errors.

Read options: ReadOptions.version is the generation; extra must be empty.

### Known gaps (implementer)

- Not tested against real Google Cloud Storage (no credentials available here). Auth flows are covered by the mock server and the google-auth vectors; data operations by fake-gcs-server only.
- fake-gcs-server quirks (the tests accept both behaviours; our semantics are unchanged): (1) a delimited listing leaves out the object equal to the prefix, so a directory marker does not show in ls; (2) the object `d/` disappears once `d/x` is written; (3) the `fields` parameter is ignored; (4) objects.move is not implemented, so mv falls back to copy+delete, cached per filesystem; (5) a non-empty bucket delete answers 412 instead of 409. gcsfs sees the same behaviour on this emulator.
- gcsfs 2026.8.2 defaults to ExtendedGcsFileSystem, which probes each bucket's type over gRPC and stalls 60 s per bucket on the emulator. The differential test and the benchmark set GCSFS_EXPERIMENTAL_ZB_HNS_SUPPORT=false. Zonal/HNS bucket features (zonal_file, the gRPC paths) are not implemented in fsfast-gcs.
- The JSON batch API is not used for rm_files (concurrent single DELETEs, 32 in flight); a possible follow-up for very large deletes on real GCS.
- merge/compose does not split more than 32 sources into several compose calls (gcsfs does not either; GCS rejects the call).
- token='cache' and 'browser' are Unsupported. Raw-token expiry is not looked up at tokeninfo. External-account / workload identity federation and impersonated credentials are not implemented. The gcloud project is read from gcloud's config files instead of running `gcloud config get project`.
- Credential files and gcloud config files are read synchronously in from_options (small files, at construction, as gcsfs does); everything that needs the network is async and happens on first use.
- Upload throughput numbers come from an emulator whose cost per chunk grows with object size; they say little about real-GCS upload performance. The XML multipart upload API with parallel parts (PartUploader) was deliberately not used; the reasons are in the write.rs docs.
- versioning listings (ls/find with versions=True as gcsfs offers) are not exposed through the FileSystem trait. Generations work through paths and ReadOptions.version when version_aware.

### Review findings

- [major] FIXED: Resumable upload: a failed chunk PUT (5xx or connection reset) was re-sent blindly from its old offset by the transport, which can overlap bytes GCS already saved (a strict server rejects this and the upload fails). Now the session status is queried (bytes */N) and only the missing bytes are sent again, under the client's retry policy. Test: interrupted_chunks_resume_from_the_persisted_offset
- [major] FIXED: Cancel-safety bug in GcsWriteHandle::close: finish() takes the buffered tail before its first await, so a cancelled close followed by a second close saved an empty object (one-request path) or finalized the session without its tail. close() now marks the handle failed first; abort or drop cancels the session. Test: cancelled_close_never_commits_a_truncated_object
- [minor] FIXED: info('/bucket') sent GET b/{bucket}/o/ (an empty object name) and the dir probe used prefix '/', so the call failed with a Protocol error ('object resource without a name') on the emulator. An empty key is now NotFound (as gcsfs _get_object does) and the probe lists from the bucket root
- [minor] FIXED: Retry policy did not match gcsfs: with a 500 ms full-jitter base, the expected total wait was about 8 s, against about 33 s in gcsfs (2**(n-1)+rand, capped at 32 s), so short GCS outages failed sooner than with gcsfs. The base is now 2 s (caps 2..32 s); new option retry_base_delay
- [minor] FIXED: GOOGLE_CLOUD_QUOTA_PROJECT was captured from the environment but never applied. google-auth default() applies it, so ADC and metadata credentials now send it as x-goog-user-project
- [minor] FIXED: Token refresh: during the 5-minute refresh window, a failed refresh (a token endpoint or metadata server hiccup) failed requests although the cached token was still valid, and every concurrent request queued behind the refresh. Now one request refreshes while the others use the valid token; after a failure the cached token stays in use and the next attempt waits 10 s
- [minor] FIXED: pipe_file sent Content-Range 'a-b/*' for intermediate chunks although the size is known. It now sends the total in every chunk, as gcsfs does, so GCS can check the upload against it; upload_span also refuses a chunk that ends past the total
- [minor] OPEN: Accepted without change: objects.move with a 400 permanently disables move for this filesystem instance (it falls back to copy+delete). A one-off invalid-argument 400 on real GCS therefore also disables it
- [minor] OPEN: Accepted without change: info('/bucket') names the entry 'bucket'; gcsfs returns '/bucket'

### Remaining risks (reviewer)

- Not tested against real Google Cloud Storage; there are no credentials here. Real-GCS behaviour of the new resume path (308 Range after a status query) follows the documented protocol, and is tested only with the strict mock and the emulator.
- fake-gcs-server does not support object versioning (bucket creation with versioning returns 500 'not implemented'). Generation pinning and version_aware paths are covered only by mock tests.
- A resumable session expired on the server (404/410) surfaces as NotFound on the write path; gcsfs does the same (FileNotFoundError).
- A pipe_file or put_file cancelled mid-upload leaves its resumable session to expire on the server (about a week); write handles cancel theirs on drop. An initiate_upload cancelled mid-request can likewise leak a session.
- simple_upload with ifGenerationMatch=0 is retried: if the first attempt succeeded but its response was lost, the retry reports a false AlreadyExists. gcsfs behaves the same.
- fsfast-http-transport's HttpConfig derives Debug, so custom headers from session_kwargs and proxy URLs with credentials could appear if GcsOptions is debug-printed. This is a transport-crate issue and was not changed here.
- Documented deviations from the implementer's report still apply: V4 instead of V2 signed URLs, no batch API for rm_files, token='cache' and 'browser' are Unsupported, and zonal/HNS buckets are not implemented.

### Performance (reviewer)

Method: `cargo run --release -p fsfast-gcs --example gcs_bench -- 128 3` against `GCSFS_EXPERIMENTAL_ZB_HNS_SUPPORT=false .venv/bin/python -I crates/fsfast-gcs/tools/bench_gcsfs.py 128 3`. Both ran on the same local fake-gcs-server with anonymous access; each workload ran 3 times and the best run was kept. The two sides ran one after the other, with a load average of about 1. I did two fsfast runs (before and after my fixes) and two gcsfs runs. The single-number pipe_file and cat_file rows are from the interleaved after-fixes pair.

| workload | fsfast | gcsfs |
|---|---|---|
| put 128 MiB, pipe_file | 66 MB/s (56 before the fixes; repeat runs 61 and 72) | 65 MB/s (74 in the first gcsfs run) |
| get 128 MiB, cat_file | 891 MB/s (655 before the fixes) | 650 MB/s (697 in the first gcsfs run) |
| put_file | 51-67 MB/s | 60-77 MB/s |
| get_file | 845-938 MB/s | 759-781 MB/s |
| open_write in 1 MiB writes | 37-42 MB/s | 25-27 MB/s |
| 1000 x 4 KiB, sequential: pipe / cat / info | 322-357 / 1893-1916 / 677-685 ops/s | 216-263 / 601-614 / 276-315 ops/s |
| 1000 x 4 KiB, concurrency 64: pipe / cat / info | 392-467 / 7330-9095 / 752-896 ops/s | 365-444 / 1873-1922 / 625-639 ops/s |
| ls of 1000 entries | 25.7-25.8 ms | 27.3-33.9 ms |
| find of 1001 entries | 36-38 ms | 48.8-59 ms |
| rm of 1000 objects | 1829-1924 objects/s | 870-997 objects/s |

There were 0 retries and 0 throttles in about 20k requests. This confirms the implementer's numbers in shape.

- Uploads are limited by the emulator, and the run-to-run variance is ±15%. pipe_file and put_file are at parity with gcsfs; reads and small-object and metadata operations are 1.3-5x faster.
- My fixes add no request on the success path. The status query happens only after a failure.
- I found no performance defects.

## azure


### Public API

Crate `fsfast_azure` (crates/fsfast-azure/src/lib.rs).

`pub struct AzureBlobFileSystem` (Clone, Debug) implements `fsfast_core::FileSystem`:
- `protocols()` = `["abfs", "az", "abfss"]`.
- capabilities: `{hierarchical: false, atomic_rename: hns, server_side_copy: true, append: true, conditional_create: true, random_write: false, versioning: version_aware, signed_urls: <an account key is known>, pinned_reads: true}`.
- Overrides: info, ls, find, open_read, open_write, cat_file, pipe_file, rm_file, rm_files, mkdir, rmdir, cp_file, mv_file, sign. touch, makedirs, cat_ranges, get_file and put_file use the core defaults.

Constructors and getters:
- `pub fn from_options(opts: fsfast_core::Options) -> fsfast_core::Result<Self>` — reads the process environment.
- `pub fn from_options_with_env(opts: Options, env: &dyn Fn(&str) -> Option<String>) -> Result<Self>`
- `pub fn from_config(cfg: options::AzureConfig) -> Result<Self>`
- `pub fn config(&self) -> &AzureConfig`; `pub fn endpoint(&self) -> &str`; `pub fn account_name(&self) -> Option<&str>`
- `pub fn blocksize(&self) -> usize` (default 50 MiB); `pub fn default_fill_cache(&self) -> bool`; `pub fn default_cache_type(&self) -> &str`; `pub fn version_aware(&self) -> bool`
- `pub fn stats(&self) -> &Arc<fsfast_engine::stats::Stats>`; `pub fn credential(&self) -> &auth::Credential`

Path helpers:
- `pub fn strip_protocol(path: &str) -> String` (adlfs `_strip_protocol`; also `path::strip_protocol`)
- `pub fn kwargs_from_url(url: &str) -> (Option<String>, bool)` (adlfs `_get_kwargs_from_urls`: account_name, version_aware)

Extra operations:
- `pub async fn open(&self, path: &str, opts: &ReadOptions) -> Result<AzureReadHandle>` (`AzureReadHandle::pinned_etag()`)
- `pub async fn set_metadata(&self, path: &str, metadata: &BTreeMap<String, String>) -> Result<()>` (adlfs `setxattrs`)
- `pub async fn create_container_raw(&self, container: &str) -> Result<()>`
- `pub async fn create_container_with_access(&self, container: &str, public: Option<&str>) -> Result<()>`
- `pub async fn delete_container_raw(&self, container: &str) -> Result<()>` (adlfs `rmdir(container)` semantics: deletes everything)

Constants and other public items:
- `pub const INFO_KEYS: &[&str]` — adlfs key order for the fsfast-py registry: metadata, creation_time, deleted, deleted_time, last_modified, content_time, content_settings, remaining_retention_days, archive_status, last_accessed_on, etag, tags, tag_count, version_id, is_current_version.
- `pub const PROTOCOLS`, `pub const DEFAULT_BLOCK_SIZE`, `pub enum LocationMode`.
- Modules: `auth::{API_VERSION, Credential, SharedKey, TokenCache, sas::BlobSas, token::*}`, `connstr::{ConnectionString, is_sas_token, DEVSTORE_*}`, `error::{AzureErrorParser, code_kind}`, `path::{strip_protocol, split_path, split_dir_path, quote, unquote, kwargs_from_url}`, `options::AzureConfig`.

Accepted options, consumed with these effects:
- account_name, account_key, connection_string, sas_token, client_id, client_secret, tenant_id, anon, credential (str / dict forms above), account_host, location_mode ('primary' / 'secondary').
- blocksize: file-object block size; when set, also the upload block size. Uploads default to 8 MiB blocks otherwise.
- default_fill_cache, default_cache_type, version_aware, assume_container_exists.
- max_concurrency (default 16).
- timeout: server-side, sent as a query parameter.
- connection_timeout, read_timeout.

Environment variables read: AZURE_STORAGE_ACCOUNT_NAME, AZURE_STORAGE_ACCOUNT_KEY, AZURE_STORAGE_CONNECTION_STRING, AZURE_STORAGE_SAS_TOKEN, AZURE_STORAGE_CLIENT_ID, AZURE_STORAGE_CLIENT_SECRET, AZURE_STORAGE_TENANT_ID, AZURE_STORAGE_ANON. The default chain also reads AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_AUTHORITY_HOST, AZURE_FEDERATED_TOKEN_FILE, IDENTITY_ENDPOINT, IDENTITY_HEADER and AZURE_POD_IDENTITY_AUTHORITY_HOST.

DefaultAzureCredential keywords consumed: exclude_environment_credential, exclude_workload_identity_credential, exclude_managed_identity_credential, exclude_cli_credential, managed_identity_client_id, workload_identity_client_id, workload_identity_tenant_id, authority, process_timeout.

Accepted without effect: socket_timeout, request_session, loop, asynchronous, use_listings_cache, listings_expiry_time, max_paths, skip_instance_cache, and the DefaultAzureCredential keywords for credentials fsfast does not implement (exclude_shared_token_cache_credential, exclude_visual_studio_code_credential, exclude_powershell_credential, exclude_developer_cli_credential, exclude_interactive_browser_credential, exclude_broker_credential, interactive_browser_tenant_id, interactive_browser_client_id, shared_cache_username, shared_cache_tenant_id, visual_studio_code_tenant_id, additionally_allowed_tenants).

fsfast extras: request_size, upload_concurrency, list_page_size (1–5000), hns, dfs_endpoint, and HttpConfig::apply_fsfast_options (connect_timeout, total_timeout, max_retries, limit_per_host, http2, ca_bundle, user_agent, rotate_dns).

Any other option is an InvalidInput error.

WriteOptions:
- `content_type` → `x-ms-blob-content-type`; `metadata` → `x-ms-meta-*`.
- `extra`: `content_settings` (dict: content_type, content_encoding, content_language, content_disposition, cache_control, content_md5); `max_concurrency` and `overwrite` are accepted and ignored.
- WriteMode: Overwrite, CreateNew, Append.

ReadOptions:
- `version` requires `version_aware` (otherwise InvalidInput, like adlfs).
- `pin_version` (default true) pins reads with If-Match on the ETag.
- `block_size` sets the size of each ranged GET.
- Any `extra` key is rejected.

To register in the Python bindings (not done): add the crate to fsfast-py's Cargo.toml features and a `Backend::new(&["abfs","az","abfss"], build_azure, ..., INFO_KEYS)` entry in registry.rs. The Python layer must convert azure.core credential objects to the dict forms.

### Known gaps (implementer)

- ADLS Gen2 through the DFS endpoint is minimal: only `hns=True` makes mv_file one atomic Path Rename, with a fallback to copy + delete. Recursive directory delete, real mkdir/rmdir of directories, and listing through the DFS API are not implemented, and capabilities.hierarchical stays false. The rename is tested only against a mock server, because Azurite has no DFS.
- Entra ID tokens are only tested against in-process fakes (Azurite supports OAuth only over HTTPS with --oauth). No real AAD, IMDS, workload identity or Azure CLI login was exercised. Certificate credentials (AZURE_CLIENT_CERTIFICATE_PATH) and the other DefaultAzureCredential sources (VS Code, PowerShell, azd, shared token cache, interactive browser, broker) are not implemented; their keywords are accepted without effect.
- If `az` prints only `expiresOn` (CLI versions before 2.54), the local-time value is read as UTC and the expiry is capped at 30 minutes; a 401 then triggers a refresh.
- Appending to a block blob that was uploaded with a single Put Blob re-stages the existing content: it is downloaded (pinned to the ETag) and staged again as blocks, costing one download of that content. Put Block From URL was not used: Azurite rejects it with CannotVerifyCopySource, and the real service would need a source SAS.
- Appends to append blobs become visible once 4 MiB is buffered, on flush, and on close; abort only discards data not yet pushed. Append blocks are capped at 4 MiB (the limit of older API versions and probably of Azurite) even though newer service versions allow 100 MiB.
- Blob Batch delete is not used. rm_files runs concurrent DELETEs (up to max_concurrency in flight), then deletes markers of non-empty directories deepest first, as adlfs orders them.
- Python-layer work not done here (fsfast-py and python/ are outside this task): registering the backend in fsfast-py, converting azure.core credential objects to the dict forms, the listings cache, glob/expand_path, adlfs's `cat(on_error)` behaviour, and `url()` keywords (content_disposition and similar; BlobSas supports them, but sign() does not expose them).
- Metadata names are sent lowercase, because the HTTP stack lowercases header names, so the case of metadata keys written by fsfast is lost; adlfs keeps it. Metadata read from HEAD responses is lowercase too (reads from listings keep the original case). hdi_isfolder detection is case-insensitive, so marker detection is unaffected.
- Shared Key signatures are computed once per request; transport retries reuse them, so a request delayed more than 15 minutes (the service's limit on x-ms-date) before a retry would fail authentication.
- copy_source puts the SAS on the source URL only for SAS authorization. Cross-account copies with Shared Key or bearer auth (a source that needs its own SAS or x-ms-copy-source-authorization) are not supported. cp_file always uses async Copy Blob with polling; Copy Blob From URL is not used.
- Benchmarks ran only on Azurite on a shared 4-core machine, not on real Azure Storage, so the large-upload comparison mostly reflects Azurite's commit cost. fsspec's abstract test suite and adlfs's own test suite were not run against this class: that needs the Python bindings.

### Review findings

- [major] FIXED: Blob names with '.'/'..' segments were resolved away by the URL parser, so the request silently addressed a different blob (pipe 'c/a/../b' overwrote 'c/b'). Now InvalidInput, including copy sources, DFS rename sources and sign().
- [major] FIXED: Block-list append listed the blob's existing blocks as <Latest>: an uncommitted block another writer staged under the same ID silently replaced existing content (seen on Azurite). Now <Committed>.
- [major] FIXED: Append Block conflict was taken as success when the blob length equalled pos+len; another writer's append of the same length made fsfast report success and lose our data. Now the bytes at pos are read back and compared.
- [major] FIXED: Shared Key canonicalisation did not trim header values; metadata values with leading or trailing blanks failed with 403 AuthorizationFailure on Azurite.
- [major] FIXED: Credential's Debug printed the SAS token (fs.credential() is public); Used::Token's Debug printed the bearer token.
- [major] FIXED: A conditional Put Block List (create-only or If-Match) whose first attempt committed but whose response was lost was retried by the transport and failed its condition, reporting AlreadyExists/PreconditionFailed for a successful write. Now recognised by checking that the committed block list is exactly our IDs.
- [major] FIXED: An Overwrite that needed several blocks failed with 409 InvalidBlobType when the existing blob was an append or page blob (small overwrites worked). The old blob is now deleted and the Put Block retried; create-only and append writes never delete.
- [minor] FIXED: Block IDs for a block-list append matched the existing IDs' encoded length but not their decoded length (adlfs uuid-hex IDs: 32 vs 33 bytes). Now the decoded length (and so the encoded length and padding) matches.
- [minor] FIXED: TokenCache held its lock across the token fetch, so every request waited for a refresh while the current token was still valid (inside the 5-minute margin). Others now use the valid token while one caller refreshes.
- [minor] FIXED: rm_files found directory markers only by comparing neighbours in sort order; with siblings like 'a-b' the marker 'a' was deleted at the same time as 'a/x' instead of after it.
- [minor] FIXED: sign() on a versioned path made a version SAS (sr=bv) without versionid in the URL, so the URL could not authorize the request.
- [minor] FIXED: The x-ms-copy-source header, which can carry the SAS token, was not marked sensitive (HPACK indexing).
- [minor] OPEN: A create-only single Put Blob (data up to one block) whose response is lost and retried still reports AlreadyExists; it cannot be told apart from another writer without comparing content.
- [minor] OPEN: A DELETE whose response is lost and retried reports NotFound for a delete that succeeded (same as the Azure SDK).
- [minor] OPEN: cp_file's 1-hour copy timeout returns an error without sending Abort Copy Blob.

### Remaining risks (reviewer)

- Overwriting an append or page blob with a multi-block upload now deletes the old blob before the commit; if that upload is then aborted, the old content is gone. Before this fix the overwrite failed outright.
- Not fixed: a create-only single Put Blob, or a DELETE, whose first attempt succeeded but whose response was lost and retried still reports AlreadyExists or NotFound.
- Not fixed: metadata key case is lost on HEAD reads and on writes, because the HTTP stack lowercases header names. Known gap.
- Only exercised on Azurite and mocks. Real-service behaviour has not been checked: Entra ID tokens, ADLS Gen2/DFS, whether the service checks block ID lengths by decoded or encoded length, and its handling of dot-segment names.
- Not fixed: cp_file does not abort a copy that is still pending when its 1-hour timeout expires.
- Not fixed: Shared Key signatures are computed once per request; a request queued or retried more than 15 minutes after signing would fail authentication.

### Performance (reviewer)

Method:
- Both sides ran on the same local Azurite on the shared 4-core machine, two alternating runs each.
- fsfast: `target/release/examples/bench 256 500 2000`.
- adlfs: `.venv/bin/python crates/fsfast-azure/tools/bench_adlfs.py 256 500 2000`.
- Workload: one 256 MiB blob written then read; 500 blobs of 4 KiB (put, get, info); find and ls over 2000 blobs; delete of 2501 blobs.

| workload | fsfast run 1 / run 2 | adlfs run 1 / run 2 |
|---|---|---|
| large put | 60.8 / 62.5 MB/s | 61.9 / 65.5 MB/s |
| large get | 398 / 304 MB/s | 183 / 223 MB/s |
| small put | 622 / 724 ops/s | 465 / 466 ops/s |
| small get | 1147 / 1096 ops/s | 230 / 257 ops/s |
| info | 1290 / 1246 ops/s (concurrent) | 274 / 281 ops/s (sequential) |
| find | 10021 / 14079 entries/s | 3735 / 3652 entries/s |
| ls ×20 | 10601 / 11981 entries/s | 2459 / 2785 entries/s |
| rm | 853 / 1007 ops/s | 351 / 346 ops/s |

These confirm the implementer's numbers within run-to-run noise.

The large-put limit is Azurite, as the implementer said:
- One Put Blob of the whole 256 MiB (`FSFAST_BENCH_OPTS=blocksize=1073741824`) reached 133 MB/s.
- Staged blocks stay at about 63–67 MB/s whether 2 or 16 blocks are in flight, so the cost is Azurite's commit, not the client.

I found no performance defect in the read, list or upload hot paths. The fixes do not touch the hot paths: the new URL check is one string comparison per request, and the new verifications only run after a failed condition. The token refresh fix removes stalls during the refresh window.
