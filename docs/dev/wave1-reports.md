# Wave-1 reports (reference for wave-2 engineers)

Reports from the engineers who built and reviewed the wave-1 crates. The code in the tree is the source of truth; these notes tell you where to look.


## testkit + memory + local

### Public API

fsfast_testkit (crates/fsfast-testkit/src/lib.rs):
  pub async fn run_suite(fs: Arc<dyn FileSystem>, root: &str, cfg: SuiteConfig) -> SuiteReport
  pub async fn assert_suite(fs: Arc<dyn FileSystem>, root: &str, cfg: SuiteConfig) -> SuiteReport   // panics with a multi-line report on any failure
  pub fn check_names() -> Vec<&'static str>
  pub struct SuiteConfig { pub large_file_bytes: u64 /*24 MiB*/, pub skip: BTreeSet<String>, pub only: BTreeSet<String>, pub parallelism: usize /*1*/, pub check_timeout: Duration /*600s*/, pub concurrent_reads: usize /*32*/, pub max_stream_bytes: u64 /*64 MiB*/, pub local_temp_dir: Option<PathBuf>, pub keep_files: bool }
    builders: .skip(names) .only(names) .large_file_bytes(n) .parallelism(n); Default
  pub struct SuiteReport { pub backend: String, pub root: String, pub outcomes: Vec<CheckOutcome>, pub setup_error: Option<String>, pub cleanup_errors: Vec<String>, pub duration: Duration }
    fn is_success(&self) -> bool; passed()/failed()/skipped() -> impl Iterator<Item=&CheckOutcome>; outcome(name) -> Option<&CheckOutcome>; impl Display (the readable report)
  pub struct CheckOutcome { pub name: &'static str, pub status: CheckStatus, pub duration: Duration }
  pub enum CheckStatus { Passed, Failed(String), Skipped(String) }
  pub mod pattern { seed_for(&str)->u64; byte_at; fill; generate; generate_bytes; first_mismatch; first_difference; struct XorShift { new, next_u64, range } }
  `root` must be given in the backend's canonical path form (what info() reports as name). The suite needs a tokio runtime with the time driver.

fsfast_memory (crates/fsfast-memory/src/lib.rs):
  pub struct MemoryFileSystem (Clone, Debug, Default) implementing fsfast_core::FileSystem; protocols() = ["memory"]
  pub fn new() -> Self                    // process-wide shared store (fsspec default)
  pub fn new_isolated() -> Self           // fsspec global_store=False
  pub fn from_options(opts: Options) -> Result<Self>   // accepts global_store plus AbstractFileSystem base options (ignored); anything else -> InvalidInput
  pub fn is_global(&self) -> bool; pub fn clear(&self); pub fn clear_global(); pub fn file_count(&self) -> usize
  pub fn strip_protocol(&str) -> Cow<str>; pub mod paths { strip_protocol, parent }

fsfast_local (crates/fsfast-local/src/lib.rs):
  pub struct LocalFileSystem (Clone, Debug, Default) implementing fsfast_core::FileSystem; protocols() = ["file", "local"]
  pub const DEFAULT_IO_HINTS: IoHints   // 4 MiB requests, 8 in flight, 64 KiB coalesce gap, 16 MiB max coalesced
  pub fn new() -> Self
  pub fn from_options(opts: Options) -> Result<Self>   // accepts auto_mkdir plus AbstractFileSystem base options (ignored); anything else -> InvalidInput
  pub fn with_auto_mkdir(self, bool) -> Self; pub fn with_io_hints(self, IoHints) -> Self; pub fn auto_mkdir(&self) -> bool
  re-exports: strip_protocol(&str) -> Cow<str>, parent(&str) -> String, make_path_posix(path, PathStyle, cwd: &dyn Fn()->String, home: Option<&str>) -> String, enum PathStyle { Posix, Windows }
  pub mod paths { strip_protocol_with, parent_with, ... }

### Known gaps

- Windows: the cfg(windows) code (stat mode from attributes, seek_read, utime via set_times, the directory-open mapping) is type-checked and clippy-clean but has never been run. On Windows `ino` is reported as 0 and `nlink` as 1 because stable Rust exposes neither without extra syscalls. No long-path (\\?\) or UNC-specific handling beyond fsspec's path rules.
- The `find_omits_unreadable_subdirectories_like_fsspec_walk` test cannot exercise the permission path here because the tests run as root; it detects this and only checks the readable case.
- Not done from PLAN §6.1: statx/getdents-specific fast paths (std's readdir + fstatat are used), reflink/clonefile beyond what copy_file_range gives, and an io_uring experiment.
- Known core/Python-layer issue, not fixable in these crates: fsspec's generic `cat_file(path, start, end)` with start > end on local returns everything from start to EOF (it reads read(negative)), while fsfast_core::ByteRange::from_fsspec turns it into an empty range. Memory matches fsfast (its cat_file uses Python slicing). The Python layer should decide which to follow.
- ByteRange::from_fsspec needs the file size for a negative start combined with an explicit end; the Python layer must look the size up (the differential harness does), as the core API already documents.
- Deliberate fsspec deviations, documented on the methods: mv_file takes the exact destination (the caller resolves moving *into* an existing directory); local pipe_file(CreateNew) is atomic O_EXCL (differs from fsspec only for a dangling symlink); abort deletes or truncates back; a failed copy leaves no partial file; memory moves trees atomically and publishes writes on flush/close/drop.
- Reads cannot be pinned on local or memory (memory handles are snapshots; local sees in-place modifications). ReadOptions::version gives Unsupported; pin_version is ignored. WriteOptions content_type and metadata are ignored by local, as fsspec ignores unknown open() arguments.

## smb-proto

### Public API

Crate fsfast_smb_proto (re-exports at root: ProtoError, Result, Command, Header, HeaderFlags, HeaderId, NtStatus, Capabilities, Dialect, FileId, SecurityMode, Guid, Utf16Name).

framing:
  fn transport_header(len: usize) -> Result<[u8; 4]>
  FrameDecoder::new() / with_max_frame_len(max) / set_max_frame_len
  FrameDecoder::decode(&mut self, buf: &mut BytesMut) -> Result<Option<BytesMut>>   // splits a whole frame off the front of buf, no copy
  FrameDecoder::bytes_needed(&self, buf: &BytesMut) -> usize

header:
  struct Header { credit_charge, status: NtStatus, command: Command, credits, flags: HeaderFlags, next_command, message_id, id: HeaderId /*Sync{process_id,tree_id} | Async{async_id}*/, session_id, signature: [u8;16] }
  Header::request(Command), decode(&[u8]) -> Result<Header>, encode(&mut BytesMut), to_bytes(), is_interim(), set_tree_id(), set_channel_sequence()
  fn credit_charge_for(bytes: usize) -> u16

msg:
  trait Message { const COMMAND; const RESPONSE; fn encode_body(&self,&mut BytesMut)->Result<()>; fn payload(&self)->Option<&Bytes>; fn decode_body(&Bytes)->Result<Self>; fn credit_charge(&self)->u16 }
  fn encode_message<M: Message>(&Header, &M) -> Result<EncodedMessage>
  struct EncodedMessage { head: BytesMut, payload: Option<Bytes> /* WRITE data stays separate, zero-copy */, padding: usize }  // segments(), write_to(), into_contiguous(), header()
  OutgoingFrame::from_messages(impl IntoIterator<Item=EncodedMessage>) -> Result<Self>; from_bytes(Bytes); implements bytes::Buf + chunks_vectored for writev
  RawMessage::parse(Bytes), header(), bytes() /* exact bytes, input to verification */, decode::<M>() -> Result<M>, into_result::<M>() /* Err(ProtoError::Status) for error bodies */, is_error_response(), decode_error() -> Result<ErrorResponse>
  BreakMessage::decode(&RawMessage)  // tells oplock/lease notifications apart from responses
  Message types (request and response for each): Negotiate (with NegotiateContext: PreauthIntegrity, Encryption, Compression, NetName, Transport, RdmaTransform, Signing, Unknown), SessionSetup, Logoff, TreeConnect, TreeDisconnect, Create (CreateRequestContext / CreateResponseContext, Lease::V1/V2), Close, Flush, Read (ReadResponse.data is a slice of the received frame), Write, Lock, Ioctl, Cancel, Echo, QueryDirectory, ChangeNotify, QueryInfo, SetInfo, OplockBreak*, LeaseBreak*, ErrorResponse (+ SymlinkErrorResponse, ShareRedirect)
  FSCTL payloads (trait FsctlData { encode, decode, to_bytes }): ValidateNegotiateInfoRequest/Response, SrvRequestResumeKeyResponse, SrvCopyChunkCopy, SrvCopyChunkResponse, DfsReferralRequest(Ex), DfsReferralResponse (v1-v4); decode_network_interfaces(&[u8]) -> Result<Vec<NetworkInterfaceInfo>>

compound:
  CompoundBuilder::new(); push(Header, &M); push_related(Header, &M); push_encoded(EncodedMessage); finish() -> Vec<EncodedMessage>  // 8-byte padding + NextCommand set; sign each member after finish()
  fn split_compound(frame: Bytes) -> CompoundIter (Iterator<Item = Result<RawMessage>>)

fscc: FileTime (to/from SystemTime), FileAttributes, AccessMask, ShareAccess, CreateOptions, CreateDisposition, etc.; trait InfoClass { INFO_TYPE; CLASS; decode; encode; to_bytes } for FileBasic, FileStandard, FileNetworkOpen, FileAll, FileAttributeTag, FileEndOfFile, FileRename, FileRenameEx, FileDisposition(Ex), FileStream, FileFsSize, FileFsFullSize, FileFsAttribute and more; DirectoryEntries::new(FileInfoClass, Bytes) -> Iterator<Item=Result<DirEntry>> (bounds-checked NextEntryOffset chain); encode_directory_entries

status:
  NtStatus consts; NtStatus::kind() -> ErrorKind; NtStatus::to_error(path: Option<&str>) -> fsfast_core::Error (attaches Detail::NtStatus)
  impl From<ProtoError> for fsfast_core::Error

crypto:
  fn derive_session_keys(dialect: Dialect, session_key: &[u8], preauth_hash: Option<&[u8;64]>, cipher: Option<Cipher>) -> Result<SessionKeys>   // SessionKeys { session_key, signing_key, application_key, encryption_key, decryption_key }
  PreauthHasher::new(); update(&[u8]); update_parts(&[&[u8]]); value() -> &[u8;64]
  SigningAlgorithm::for_dialect(Dialect, Option<SigningAlgorithmId>) -> Result<SigningAlgorithm>
  Signer::new(alg, key: &[u8]) -> Result<Signer>; sign(&mut EncodedMessage); sign_in_place(&mut [u8]); compute(&[&[u8]]) -> Result<[u8;16]>; verify(&[u8]) -> Result<()>  // constant-time compare
  Cipher::{Aes128Ccm, Aes128Gcm, Aes256Ccm, Aes256Gcm}; SmbCipher::new(Cipher, key) -> Result<Self>
  SmbCipher::encrypt(session_id, parts: &[&[u8]]) -> Result<BytesMut>; encrypt_messages(session_id, &[EncodedMessage])
  SmbCipher::decrypt_in_place(BytesMut) -> Result<(TransformHeader, BytesMut)>
  SmbCipher::decrypt_into(&[u8], &mut [u8]) -> Result<(TransformHeader, usize)>
  SmbCipher::decrypt_into_parts(&[u8], &mut [&mut [u8]]) -> Result<(TransformHeader, usize)>
  CompressionTransform::parse(&Bytes) / decompress() / encode(); sp800_108_hmac_sha256(key, label, context, out)

auth:
  trait Authenticator: Send { fn step(&mut self, input: &[u8]) -> Result<AuthStep>; fn is_complete(&self) -> bool; fn session_key(&self) -> Option<&[u8]>; fn is_anonymous(&self) -> bool; fn mechanism(&self) -> &'static str }
  enum AuthStep { Continue(Vec<u8>), Done(Option<Vec<u8>>) }
  trait GssMechanism: Authenticator { fn oid(&self) -> &'static [u8]; fn wants_mech_list_mic(&self) -> bool; fn get_mic(&mut self, &[u8]) -> Result<Vec<u8>>; fn verify_mic(&mut self, &[u8], &[u8]) -> Result<()> }
  SpnegoClient::ntlm(NtlmCredentials); ntlm_with_config(NtlmCredentials, NtlmConfig); new(Vec<Box<dyn GssMechanism>>)   // first step() takes NegotiateResponse.security_buffer; session_key() is available before the server's final reply, so the 3.1.1 final response signature can be verified
  NtlmCredentials::new("DOMAIN\\user", pw) / with_domain / from_nt_hash / anonymous
  NtlmConfig { flags, version, workstation, target_spn, channel_bindings_hash, require_128bit }
  NtlmClient (also Authenticator + GssMechanism); spnego::{NegTokenInit, NegTokenResp, NegotiationToken}; ntlm::{NegotiateMessage, ChallengeMessage, AuthenticateMessage, AvPairs, NtlmMac, ntowfv2, ntlmv2_response}

### Known gaps

- SMB compression algorithms (LZNT1, LZ77, LZ77+Huffman, LZ4) are not implemented. COMPRESSION_TRANSFORM_HEADER parse/encode (chained and unchained) is complete, but only NONE and Pattern_V1 decompress; the others return ProtoError::Unsupported. Clients must not offer them.
- Kerberos is not implemented. The GssMechanism trait and the SPNEGO mechanism switching are designed for it. NTLMv1/LM responses are deliberately not implemented.
- NTLM signing without extended session security is not supported. The client refuses a CHALLENGE that grants SIGN/SEAL without ESS, or without 128-bit keys unless require_128bit is false.
- Two differences from the Python references, both documented and checked field by field: (1) our client's SPNEGO NegTokenResp omits negState (pyspnego sends accept-incomplete; Samba and Windows clients omit it); (2) smbprotocol sets the empty IOCTL OutputOffset to the buffer offset, while we send 0 as [MS-SMB2] recommends.
- The 3.1.1 TREE_CONNECT extension (EXTENSION_PRESENT flag with tree connect contexts) has the flag constant only; the extension structure is not encoded or decoded. SMB 3.1.1 POSIX extensions are not implemented (the negotiate context is kept raw).
- Interop is proven against Samba only, not Windows or ksmbd. This Samba version returns STATUS_INVALID_INFO_CLASS for FileIdExtdDirectoryInformation, so that class is covered only by unit and property tests.
- DFS referral decoding (v1–v4), CHANGE_NOTIFY and oplock/lease break handling are covered by unit and property tests, but there is no live DFS namespace and no live break test.
- Split-destination decryption for AES-CCM decrypts into a scratch buffer and copies once; AES-GCM writes straight into the caller's buffers. The client must give the header part the right size (OriginalMessageSize - DataLength, normally 80) and handle a server that uses a non-standard READ DataOffset.
- Robustness is covered by proptest no-panic properties only; no cargo-fuzz targets were added.
- The fsfast-smb client crate does not use this crate yet; that is the next engineer's task.

## engine

### Public API

// retry
pub struct RetryPolicy { pub max_attempts: u32, pub base_delay: Duration, pub max_delay: Duration, pub total_timeout: Option<Duration> } // Default 5 / 100ms / 20s / None; ::none(), with_* builders, backoff_cap(k), delay_for(k)
pub async fn retry<T, F: FnMut() -> Fut, Fut: Future<Output = Result<T>>>(policy: &RetryPolicy, op: F) -> Result<T>;
pub async fn retry_with_stats<T, F, Fut>(policy: &RetryPolicy, stats: &Stats, op: F) -> Result<T>;
pub async fn retry_notify<T, F, Fut, N: FnMut(&RetryEvent<'_>)>(policy: &RetryPolicy, op: F, notify: N) -> Result<T>;
pub struct RetryAfter(pub Duration); // attach via Error::with_source(RetryAfter(d))
pub fn retry_after_hint(err: &Error) -> Option<Duration>;

// aimd
pub struct AimdConfig { pub min_limit, pub initial_limit, pub max_limit: usize, pub backoff_ratio: f64, pub latency_tolerance: Option<f64>, pub latency_floor: Duration, pub latency_warmup: u32 }
impl AimdLimiter { pub fn new(AimdConfig) -> Self; pub async fn acquire(&self) -> AimdPermit; pub fn try_acquire(&self) -> Option<AimdPermit>; pub async fn run<T, Fut>(&self, fut: Fut) -> Result<T>; pub fn limit(&self) -> usize; pub fn in_flight(&self) -> usize; pub fn available(&self) -> usize } // Clone
impl AimdPermit { pub fn success(self); pub fn success_with_latency(self, Duration); pub fn throttled(self); pub fn dropped(self); pub fn report(self, Outcome); pub fn record<T>(self, &Result<T>) }
pub enum Outcome { Success, Throttled, Dropped } // Outcome::from_result(&Result<T>)

// budget
impl MemoryBudget { pub fn new(bytes: usize) -> Self; pub fn unlimited() -> Self; pub fn global() -> &'static MemoryBudget; pub async fn acquire(&self, bytes: usize) -> BudgetGuard; pub fn try_acquire(&self, bytes: usize) -> Option<BudgetGuard>; pub fn force_acquire(&self, bytes: usize) -> BudgetGuard; pub fn resize(&self, bytes: usize); pub fn capacity/available/in_use(&self) -> usize; pub fn is_overcommitted(&self) -> bool; pub fn same_budget(&self, &MemoryBudget) -> bool } // Clone
impl BudgetGuard { pub fn empty() -> Self; pub fn bytes(&self) -> usize; pub fn split(&mut self, n: usize) -> BudgetGuard } // released on Drop
budget::{GLOBAL_BUDGET_ENV = "FSFAST_MEMORY_BUDGET", default_global_size() -> usize, parse_size(&str) -> Result<usize>}

// parallel
pub async fn read_parallel(handle: &Arc<dyn ReadHandle>, range: Range<u64>, part_size: usize, concurrency: usize, budget: Option<&MemoryBudget>) -> Result<Bytes>;
pub async fn read_parallel_into(handle: &Arc<dyn ReadHandle>, offset: u64, dst: &mut [u8], part_size: usize, concurrency: usize, budget: Option<&MemoryBudget>) -> Result<usize>;

// reader
pub enum CacheMode { None, Readahead /*default*/, Blocks(BlockCacheConfig), Whole } // CacheMode::from_fsspec(cache_type: &str, block_size: Option<usize>, max_blocks: Option<usize>) -> Result<CacheMode>
pub struct BlockCacheConfig { pub block_size: Option<usize>, pub max_blocks: usize /*32*/, pub prefetch: bool }
pub struct ReaderConfig { pub cache: CacheMode, pub request_size: Option<usize>, pub concurrency: Option<usize>, pub min_readahead: usize /*256KiB*/, pub max_readahead: Option<usize>, pub budget: Option<MemoryBudget> } // None => from handle IoHints / global budget; ReaderConfig::with_cache(mode)
impl FileReader { pub fn new(handle: Arc<dyn ReadHandle>, cfg: ReaderConfig) -> Self; pub async fn read(&mut self, n: Option<usize>) -> Result<Bytes>; pub async fn read_into(&mut self, buf: &mut [u8]) -> Result<usize>; pub fn seek(&mut self, SeekFrom) -> Result<u64>; pub fn tell(&self) -> u64; pub fn size(&self) -> u64; pub fn handle(&self) -> &Arc<dyn ReadHandle>; pub fn cache_mode(&self) -> CacheMode; pub fn clear_cache(&mut self); pub async fn close(&mut self) -> Result<()>; pub fn is_closed(&self) -> bool } // Send + Sync

// upload
#[async_trait] pub trait PartSink: Send + Sync + 'static { type Outcome: Send + 'static; async fn start(&self) -> Result<()> { Ok(()) } async fn upload_part(&self, part_number: u32, data: Bytes) -> Result<Self::Outcome>; }
pub struct PartOutcome { pub etag: String, pub checksum: Option<String> }
pub struct CompletedPart<O> { pub part_number: u32, pub offset: u64, pub size: u64, pub outcome: O }
pub enum UploadResult<O> { Single(Bytes), Multipart(Vec<CompletedPart<O>>) } // is_single()
pub struct UploadConfig { pub part_size /*8MiB*/, pub min_part_size /*5MiB*/, pub max_part_size /*5GiB*/: usize, pub max_parts: u32 /*10_000*/, pub concurrency: usize /*8*/, pub expected_size: Option<u64>, pub budget: Option<MemoryBudget> }
impl<S: PartSink> PartUploader<S> { pub fn new(sink: Arc<S>, cfg: UploadConfig) -> Result<Self>; pub async fn write(&mut self, data: Bytes) -> Result<()>; pub async fn finish(self) -> Result<UploadResult<S::Outcome>>; pub async fn abort(self); pub fn is_multipart(&self) -> bool; pub fn bytes_written(&self) -> u64; pub fn parts_dispatched(&self) -> u32; pub fn in_flight(&self) -> usize; pub fn part_sizer(&self) -> &PartSizer }
impl PartSizer { pub fn new(&UploadConfig) -> Result<Self>; pub fn part_size(&self, part_number: u32) -> u64; pub fn max_parts(&self) -> u32; pub fn capacity(&self) -> u64 }

// stats
pub enum OpKind { Info, List, Read, Write, Delete, Copy, Open, Close, Other } // ALL, COUNT, as_str()
impl Stats { pub fn new() -> Self; pub fn record_request(&self, op: OpKind, latency: Duration, ok: bool); pub async fn measure<T, Fut>(&self, op: OpKind, fut: Fut) -> Result<T>; pub fn add_bytes_read/add_bytes_written(&self, u64); pub fn add_retry/add_throttle/add_error(&self); pub fn latency(&self, OpKind) -> &LatencyHistogram; pub fn snapshot(&self) -> StatsSnapshot; pub fn reset(&self) } // share as Arc<Stats>
pub struct StatsSnapshot { pub requests, pub errors, pub bytes_read, pub bytes_written, pub retries, pub throttles: u64, .. } // latency(op) -> &HistogramSnapshot, requests_for(op)
impl HistogramSnapshot { pub fn quantile(&self, q: f64) -> Option<Duration>; pub fn mean/min/max(&self) -> Option<Duration>; pub fn buckets(&self) -> impl Iterator<Item=(u64,u64,u64)>; pub count, sum_us, min_us, max_us }

// concurrency
pub async fn map_ordered<I, F, Fut, T>(items: I, concurrency: usize, f: F) -> Vec<T>;
pub async fn try_map_ordered<I, F, Fut, T>(items: I, concurrency: usize, f: F) -> Result<Vec<T>>;
pub struct AbortOnDrop<T>; // ::spawn(fut), ::new(JoinHandle), Future<Output = Result<T, JoinError>>, aborts on drop

// testing (feature "testing"): MemReadHandle::new(data).with_latency(base, jitter).with_bandwidth(bps).with_hints(h).without_log(); set_fault(|&ReadRequest| Option<Error>); requests(), in_flight(), max_in_flight(), requested(); MemPartSink::new().with_latency(..).with_fault(|n, &Bytes| ..).with_start_error(kind); assembled(), parts(), calls(), in_flight(); pattern(len) -> Bytes

### Known gaps

- Not implemented from PLAN §4.5: hedged requests; deriving concurrency from a target throughput; separate limits per host or bucket prefix (one `AimdLimiter` per endpoint works; no keyed map is provided); parallel listing; batch helpers beyond `map_ordered`.
- The block cache is per reader. PLAN §4.6's sharded block LRU shared by all open files and the disk cache belong to the planned `fsfast-cache` crate and are not here.
- Nothing is wired together automatically: `read_parallel` and `FileReader` don't use `AimdLimiter`, `retry` or `Stats` themselves. Backends are expected to apply retry, stats and limiting inside their `read_at` / `upload_part`.
- Budget accounting has known holes: the user-requested bytes of exact reads, the destination buffer of a parallel read, and the one part-sized buffer each `PartUploader` is filling are not counted. A slice returned from a prefetched chunk without copying keeps the whole chunk allocated after its budget has been released. `MemoryBudget::in_use()` can over-report while a waiter holds a partial grant from tokio.
- Latency-based decrease in the AIMD limiter is on by default (2x tolerance). Endpoints with very different request sizes may want to set `latency_tolerance: None`; this has not been tuned against real services.
- `PartUploader::write` is not safe to cancel: if the future is dropped mid-write the upload should be aborted (documented). A sink's `start` call is awaited inside the `write` that dispatches the first part.
- Detecting total RAM for the default global budget is Linux-only (`/proc/meminfo` plus cgroup v2/v1 limits). Elsewhere the default is 1 GiB unless `FSFAST_MEMORY_BUDGET` is set.
- Benchmarks were run only in criterion's `--quick` mode on a shared machine, so the numbers are indicative, not statistically rigorous. The coalesce benchmark suggests `fsfast_core::coalesce_ranges` could be sped up (e.g. `sort_unstable_by_key`, fewer per-group allocations). That function lives in fsfast-core, so I left it alone.
- `crates/fsfast-engine/proptest-regressions/upload.txt` holds a seed from a bug in an earlier version of one of my test expectations, not in the uploader. It passes now and is kept so proptest replays it.

## http-transport + http

### Public API

fsfast_http_transport:
  pub struct HttpConfig { connect_timeout/read_timeout/total_timeout/pool_idle_timeout: Option<Duration>, pool_max_idle_per_host, max_connections_per_host, initial_connections_per_host: usize, http2, http2_prior_knowledge, tls_verify: bool, ca_bundle: Option<PathBuf>, headers: HeaderMap, auth: Option<BasicAuth>, cookies, query: Vec<(String,String)>, user_agent: Option<String>, proxy: ProxyConfig, max_retries: u32, retry_base_delay, retry_max_delay: Duration, max_redirects: Option<usize>, rotate_dns, latency_aimd: bool } // Default
    fn from_options(r: &mut OptionReader) -> Result<HttpConfig>
    fn apply_client_kwargs(&mut self, r: &mut OptionReader) -> Result<()>
    fn apply_request_kwargs(&mut self, r: &mut OptionReader) -> Result<()>
    fn apply_fsfast_options(&mut self, r: &mut OptionReader) -> Result<()>
    fn set_header(&mut self, &str, &str) -> Result<()>
    fn set_header_if_absent(&mut self, &str, &str) -> Result<()>
    fn validate(&self) -> Result<()>
    fn effective_headers(&self) -> Result<HeaderMap>
  pub enum ProxyConfig { Environment /*default*/, Disabled, Url { url: String, auth: Option<BasicAuth> } }
  pub struct BasicAuth { login, password: String, encoding: AuthEncoding }; BasicAuth::new(l, p); header_value() -> Result<HeaderValue>
  pub struct HttpClient // Clone
    fn new(HttpConfig) -> Result<Self>
    fn builder(HttpConfig) -> HttpClientBuilder // .stats(Arc<Stats>) .error_parser(Arc<dyn ErrorParser>) .build()
    async fn send(&self, Request) -> Result<Response>
    async fn send_once(&self, &Request) -> Result<Response>
    async fn send_with<T, F: Fn(Response) -> Fut, Fut: Future<Output = Result<T>>>(&self, Request, F) -> Result<T> // retries body processing too
    fn stats(&self) -> &Arc<Stats>; fn config(&self) -> &HttpConfig; fn retry_policy(&self) -> &RetryPolicy; fn host_limit(&self, &Url) -> usize
  pub struct Request // Clone
    new(Method, &str) / from_url(Method, Url) / get / head / put / post / delete -> Result<Request>
    builders: .header(HeaderName, HeaderValue) .try_header(&str, &str)? .range(ByteRange) /*also allows 416*/ .body(impl Into<RequestBody>) .op(OpKind) .retry_safe(bool) .allow_status(u16) .status_kind(u16, ErrorKind) .timeout(Duration) .path(String) .error_parser(Arc<dyn ErrorParser>)
    accessors: method(), url(), url_mut(), headers(), headers_mut(), body_ref(), is_retry_safe()
  pub enum RequestBody { Empty, Bytes(Bytes), Chunks(Arc<[Bytes]>), File { path, len }, Stream(..) }
    RequestBody::chunks(Vec<Bytes>); RequestBody::stream(S, Option<u64>); len(); is_replayable()
  pub struct Response
    status(), headers(), url() /*final*/, version(), path(), header_str(), content_length(), content_range(), etag()
    async fn chunk(&mut self) -> Result<Option<Bytes>>
    async fn bytes(self) -> Result<Bytes>
    async fn bytes_truncated(self, usize) -> Result<Bytes>
    async fn bytes_window(self, skip: u64, take: Option<u64>) -> Result<Bytes>
    async fn range_bytes(self, ByteRange) -> Result<RangeBody>
    fn into_stream(self) -> BodyStream // Stream<Item = Result<Bytes>>
  pub struct RangeBody { data: Bytes, offset: u64, total: Option<u64>, ranged: bool }
  pub trait ErrorParser: Send + Sync + Debug { fn parse(&self, StatusCode, &HeaderMap, &[u8]) -> Option<ServiceError>; }
  pub struct ServiceError { code: Option<String>, message: Option<String>, kind: Option<ErrorKind>, retryable: Option<bool> }
  status_kind(u16) -> ErrorKind; status_retryable(u16) -> bool; parse_retry_after(&str, SystemTime) -> Option<Duration>; error::MAX_ERROR_BODY
  range::{ContentRange { Bytes{start,end,total} | Unsatisfied{total} }, parse_content_range(&str), content_range(&HeaderMap), content_length(&HeaderMap), has_content_coding(&HeaderMap), RangeReply { Partial{start,len,total} | Full{total} | NotSatisfiable{total} }, classify_range_response(StatusCode, &HeaderMap, ByteRange) -> Result<RangeReply>, requested_window(ByteRange, Option<u64>)}
  RotatingResolver::new() (impl reqwest::dns::Resolve); BodyLengthMismatch; re-exports Method, StatusCode, Url, Version, header

fsfast_http:
  pub struct HttpFileSystem /*Clone*/; pub type HTTPFileSystem = HttpFileSystem; impl fsfast_core::FileSystem; protocols() = ["http", "https"]; capabilities: pinned_reads only
    fn new() -> Result<Self>
    fn from_options(opts: Options) -> Result<Self>
    fn with_client(HttpClient) -> Self
    fn http_defaults(HttpConfig) -> Result<HttpConfig>
    fn client(&self) -> &HttpClient
    fn block_size(&self) -> usize; fn cache_type(&self) -> &str; fn cache_options(&self) -> Option<&Options>; fn simple_links(&self) -> bool; fn same_scheme(&self) -> bool; fn encoded(&self) -> bool
    fn parent(&str) -> String
    async fn isdir(&self, url: &str) -> Result<bool>
    async fn stream_file(&self, url: &str) -> Result<BodyStream>
  pub fn known_size(&FileInfo) -> Option<u64>; pub fn is_strong_etag(&str) -> bool; DEFAULT_BLOCK_SIZE (5 MiB), MAX_INDEX_PAGE (256 MiB)
  pub mod info { Probe, probe_response, size_from_headers, set_unknown_size, build_info, link_info, CHECKSUM_FIELDS }
  pub mod links { extract_links(&str, simple_links) -> Vec<&str>, resolve_links(url, links, same_scheme) -> BTreeSet<String>, decode_page(&[u8], Option<&str>) -> Cow<str>, scheme_and_netloc }
  pub mod write { HttpWriteHandle }
  HttpReadHandle (is_pinned(), is_ranged())

### Known gaps

- Cookie persistence: only static cookies (the `cookies` option) are sent. aiohttp's CookieJar, which stores Set-Cookie headers across requests, is not implemented; it would need reqwest's `cookies` feature (cookie_store) plus a store that merges static cookies.
- No automatic decompression. If a server ignores `Accept-Encoding: identity` and sends gzip anyway, fsfast returns the encoded bytes, while fsspec/aiohttp would decompress them.
- Memory accounting: whole-file fallback downloads (unknown size, or ranges unsupported) and the cat_file result buffer are not counted against fsfast_engine::MemoryBudget. A large file without range support is held fully in memory, as fsspec also does.
- `open_write` past the block size uses chunked transfer encoding (HTTP/1.1). Servers that require Content-Length (e.g. S3 presigned PUT) then fail; a larger block_size is the workaround. This is an extension, since fsspec has no HTTP open('wb').
- `find` does not reproduce fsspec's quirk of keying walk entries by basename, which drops same-named entries in hash order. It also stops `./` link loops that would make fsspec recurse forever. Both are documented.
- `encoded` is accepted, but URLs are always parsed with WHATWG rules through the url crate: existing %XX escapes are kept and unsafe characters are encoded. yarl's requoting differs in rare cases, e.g. it decodes %7E to ~.
- The Python layer must turn aiohttp objects into plain data: ClientTimeout → dict or number, BasicAuth → list (its namedtuple converts naturally). SSLContext objects, `connector`, `cookie_jar`, `base_url` and `get_client` are rejected as unsupported options.
- Python-layer responsibilities not implemented here: listings cache (use_listings_cache is accepted and ignored, like local/memory), `ukey` tokenization, glob without `?` as magic, and isdir via `HttpFileSystem::isdir`, because http info always reports type 'file'.
- Not implemented from PLAN: hedged requests; deriving concurrency from target throughput; CRT-style connection placement per IP beyond resolver rotation; HTTP/3. The AIMD latency signal is off by default (`latency_aimd`) and untuned against real services.
- Small-file performance has not been benchmarked against fsspec. Benchmarks for the HTTP backend (PLAN §8) remain to be done.
- `ca_bundle` is read synchronously when the client is constructed (construction-time only; documented).

## python bindings

### Public API

Rust (crates/fsfast-py, extension module `fsfast._core`; Rust modules are private):
  #[pymodule(gil_used = false)] fn _core
  #[pyfunction] make_filesystem(protocol: &str, options: Option<dict>) -> RustFileSystem
  #[pyfunction] available_protocols() -> list[str]; runtime_info() -> dict; _after_fork_child()
  PreconditionFailed(OSError), module "fsfast"
  #[pyclass(frozen)] RustFileSystem, frozen pyclass:
    - Properties and diagnostics: protocol, protocols, options (properties); capabilities() -> dict; io_hints() -> dict; stats(); reset_stats(); invalidate_cache(path=None); close(); __reduce__.
    - Sync methods (each also has a `*_async` twin returning an awaitable):
      - info(path), info_many(paths, on_error="raise", batch_size=None), times(path) -> (modified, created)
      - ls(path, detail=True), find(path, maxdepth=None, withdirs=False, detail=False), exists(path)
      - cat_file(path, start=None, end=None, seek_read=False), cat_many(paths, on_error, batch_size)
      - cat_ranges(paths, starts, ends, on_error="return", batch_size=None, seek_read=False)
      - open_read(path, cache_type="readahead", block_size=None, max_blocks=None, request_size=None, concurrency=None, version=None) -> RustReader
      - pipe_file(path, data, mode="overwrite"), pipe_many(paths, datas, mode, on_error, batch_size)
      - open_write(path, mode="wb", block_size=None, buffer_size=None) -> RustWriter, touch(path, truncate=True)
      - rm_file(path), rm_files(paths, on_error), rmdir(path), rmdir_many(paths, on_error, ignore_missing)
      - mkdir(path, create_parents=True), makedirs(path, exist_ok=False), makedirs_many(paths, exist_ok=True, on_error, batch_size)
      - cp_file(src, dst), cp_files(srcs, dsts, on_error, batch_size), mv_file(src, dst), mv_files(srcs, dsts, on_error, batch_size)
      - put_file(lpath, rpath, mode="overwrite"), put_files(...), get_file(rpath, lpath), get_files(...)
      - sign(path, expiration=100.0)
  #[pyclass(frozen)] RustReader: read(n=None), readinto(buf), readline(limit=None), readuntil(delim=b"\n", limit=None), lines() -> LineIter, seek(offset, whence=0), tell(), read_ranges([(start,end)]), clear_cache(), info(), close(); size/path/closed/cache_mode
  #[pyclass(frozen)] LineIter (__iter__/__next__)
  #[pyclass(frozen)] RustWriter: write(buffer) -> int, flush(), close() (commit), abort(); bytes_written/closed/path
  Adding a backend: in crates/fsfast-py/Cargo.toml add `http = ["dep:fsfast-http"]` (plus to default); in src/registry.rs add `static HTTP: Backend = Backend::new(&["http","https"], build_http, true, &[...info key order...]);` and `&HTTP` to BACKENDS.

Python (python/fsfast):
  fsfast.LocalFileSystem(auto_mkdir=False, **opts), subclass of fsfast.FsfastFileSystem and fsspec's LocalFileSystem; protocol ("file","local")
  fsfast.MemoryFileSystem(global_store=True, **opts); protocol "memory"
  fsfast.FsfastFileSystem(AsyncFileSystem): class attrs _rust_protocol, _seek_read_ranges; hooks _rust_options(storage_options) -> dict, _transaction_temp_path(path); .rust -> RustFileSystem; .stats(), .reset_stats(); all fsspec sync methods plus async `_` methods
  fsfast.FsfastFile(io.RawIOBase): AbstractBufferedFile-compatible
  fsfast.install(protocols=None) -> list[str]; uninstall(protocols=None); installed(); stats(fs); reset_stats(fs); PreconditionFailed; available_protocols(); runtime_info(); CLASSES; __version__
  Environment variables: FSFAST_OVERRIDE=file,memory|all; FSFAST_WORKER_THREADS; FSFAST_MAX_BLOCKING_THREADS (FSFAST_MEMORY_BUDGET comes from the engine)
Root pyproject.toml: maturin backend; python-source="python", module-name="fsfast._core", manifest-path="crates/fsfast-py/Cargo.toml", features=["extension-module"]; abi3-py310 comes from the crate's pyo3 feature.

### Known gaps

- Small local operations are slower than fsspec: about 20-25 µs per info() or small cat_file(), against 3-15 µs for fsspec. fsfast-local sends every syscall to tokio's blocking pool, so each call costs a thread wake-up. The new executor removed the return trip (from about 40 µs per call), but the outbound hop is inside fsfast-local, which I may not change. Proposed fix: a small helper in fsfast-core that runs blocking work inline when a thread-local flag is set, used by fsfast-local and set by the bindings' sync executor. My attempt to queue this as a suggested task timed out, so it is not filed. Batched calls (cat of many paths, find) hide the cost through concurrency.
- Async calls that have to wait cost about 100-145 µs each on this machine (local backend and any network backend). pyo3-async-runtimes hops from the Python thread to a tokio worker, then to the blocking pool to take the GIL, then to the event loop. Calls that finish immediately (memory, cached data) take about 2 µs, and batched async calls (_cat_ranges, _cat) about 1.5 µs per item. A custom completion queue (eventfd registered with loop.add_reader, results collected on the loop thread) would remove most of the hops; it is not done because the task asked for pyo3-async-runtimes.
- Binary line iteration is still about 1.7x slower than CPython's C BufferedReader (21.9 ms vs 12.6 ms for 300k lines), although much faster than fsspec's Python AbstractBufferedFile.
- open_async is not implemented; fsspec's default raises NotImplementedError too.
- Free-threaded CPython (3.13t/3.14t) was not tested because no such interpreter is installed. The module declares gil_used = false and all state is Send + Sync behind locks.
- Python 3.10 and Windows were not run. The abi3 wheel is tested on 3.11, 3.12 and 3.13. The Windows code (buffer access through memoryview, with one extra copy) only passes a cross type-check.
- Batch operations finish the remaining items when one fails, unlike fsspec's sync loop, which stops at the failing item (fsspec's async _put/_get/_copy behave like fsfast). Documented in python/README.md.
- The writer flushes to the backend on every flush() call. For the memory backend each flush copies the whole file content so far (a known fsfast-memory cost), so code that flushes after every small write gets quadratic cost on memory.
- A file object opened before a fork and then used in the child is not supported: its background tasks belong to the parent's abandoned runtime. Filesystem objects do work after a fork.
- MemoryFileSystem has no store / pseudo_dirs attributes (the store lives in Rust); fsspec code that clears those dicts directly will not affect fsfast's store. fsfast's local put_file(mode='create') raises FileExistsError for an existing target, where fsspec's local version ignores mode.
- Transactions (autocommit=False) write to a hidden sibling .<name>.fsfast-<id>.tmp, which is visible in listings until the commit renames it. Only wb is deferred, as with fsspec's local opener.

## Review 1: remaining risks

Summary: Independent review of fsfast-testkit, fsfast-memory and fsfast-local. Read all three crates, the fsfast-core contract and fsspec's memory.py/local.py (+ shutil/os semantics), and probed reference behaviour with throwaway scripts in the scratchpad. Found and fixed 12 real defects, each with a test that failed first and passes now: 9 in fsfast-local and fsfast-memory, and 3 testkit checks that let broken backends pass (see findings). Changes (all uncommitted, no core changes): crates/fsfast-local/src/{handles.rs,lib.rs,ops.rs,stat.rs,tests.rs}, crates/fsfast-local/tests/fsspec_differential.rs, c

- Memory write handles copy the whole accumulated content on every flush(); if the Python file layer calls flush per block (as fsspec's AbstractBufferedFile does for remote stores), large writes to memory become O(n^2). Fixing it needs publish-on-close or chunked storage, a design change.
- Workspace build instability: another engineer's crates/fsfast-engine/Cargo.toml was intermittently unparseable, so the final verification ran in an isolated copy of the workspace (my crates and core symlinked, the same Cargo.lock, a separate target dir). The orchestrator should re-run `cargo test -p fsfast-testkit -p fsfast-memory -p fsfast-local` in the main tree once the engine crate is fixed.
- Testkit expectation changes affect future backends: aborting a write to a new path must leave nothing behind (all backends), aborting an append must keep the original content (append-capable backends), cp_file onto itself must not destroy data, and special_names now writes a 200-byte name and a '.hidden' file. No other backend implements abort yet, but SMB/SFTP implementers must delete the file on abort.
- A write handle dropped after its runtime has shut down cannot finish its pending writes (the spawned task is dropped), so the buffered tail is lost silently; this only matters at process teardown.
- Windows code (stat-mode mapping, seek_read, utime, directory-open mapping, O_NONBLOCK skipped) is type-checked and clippy-clean but has never run; ino/nlink are reported as 0/1 on Windows.
- Known open items outside these crates: core's From<io::Error> keeps both the io message and the io source, so Display still repeats the OS message once; core ByteRange::from_fsspec gives an empty range for start > end while fsspec local reads from start to EOF; non-UTF-8 local file names are listed lossily (Rust strings cannot carry Python's surrogate escapes); `~user` home lookup and an unset-HOME passwd fallback are not implemented.
- fsfast-memory mv of a directory into its own subtree raises InvalidInput (ValueError) while fsfast-local raises Io (OSError); fsspec memory silently destroys the tree in that case, so there is no fsspec behaviour to match, but the two backends differ.

## Review 2: remaining risks

Summary: I reviewed crates/fsfast-smb-proto end to end and checked it against MS-SMB2 §2.2 and §3.1.4, MS-NLMP, RFC 4178, and the installed smbprotocol and pyspnego sources. The codec is solid: every structure size, offset and alignment I checked is correct, and the decoders handle hostile input without panicking. I found no critical or major defects. I found five real minor defects and fixed them; each fix has a test that failed before the change and passes after. Two smaller items are documented but not fixed.

The implementer's claims hold up. The live Samba test really runs (Samba was already up on

- Interop is proven against Samba only; Windows, ksmbd and NAS servers are untested.
- NTLM KEY_EXCH without SIGN/SEAL would likely give a different session key than a Windows server in that non-default configuration; the default flags avoid it.
- The new SPNEGO downgrade check is only tested with mock mechanisms, because no second real mechanism (Kerberos) exists yet.
- FileAllInformation decoding fails with Truncated when a server returns STATUS_BUFFER_OVERFLOW with a cut-off name; the client must retry with a bigger buffer. Names in FILE_NOTIFY_INFORMATION and FileNameInformation are decoded strictly, so one unpaired UTF-16 surrogate fails the whole decode (directory listings keep raw names and are not affected).
- Hostile-input coverage comes from proptest (random plus mutation-based); there are no coverage-guided cargo-fuzz targets.
- The implementer's stated gaps still stand: compression algorithms other than NONE/Pattern_V1, Kerberos, the 3.1.1 TREE_CONNECT extension and POSIX extensions are not implemented, and DFS, CHANGE_NOTIFY and lease/oplock breaks are not exercised live.

## Review 3: remaining risks

Summary: Independent review of crates/fsfast-engine. I read the whole crate, checked it against the fsfast-core contract and the installed fsspec reference, and probed suspected problems empirically. I found 11 real defects and fixed all of them; each fix has a test that failed on the original code and passes now. A few more fixes are to the tests themselves.

The implementer's claims about cancellation safety of FileReader held up: a new property test that drops reads mid-await in every cache mode found no corruption, budget leak or task leak, even before any change. The claim that MemoryBudget cannot

- Semantics change: MemoryBudget::acquire above u32::MAX bytes now waits for the first u32::MAX bytes and takes the remainder as recorded over-commit (repaid before other acquirers), instead of waiting for every chunk.
- A waiter whose grant was partly used to repay debt queues again at the back of the queue (rare, but it costs that waiter its FIFO position under sustained force_acquire).
- Block-cache groups share one buffer: with blocks much smaller than request_size, cached memory can reach max_blocks x request_size. It is counted in the budget, but it is more than max_blocks x block_size.
- Errors from shared block-group fetches are rebuilt from an Arc: kind, message, path, details and retryability are kept, but the source object is folded into the message (a RetryAfter source is lost there; the reader does not use it).
- The concurrency limit is approximate in Blocks mode (a few groups per read, plus prefetch) and for mandatory readahead chunks.
- Errors from speculative prefetch surface once, to the next read that needs those bytes; a retry of that read refetches.
- MemoryBudget::in_use() over-reports while a waiter holds a tokio partial grant (known from the implementer's report).
- PLAN §4.5 items are still missing (hedged requests, per-host/prefix limits, parallel listing). FileReader and read_parallel do not apply retry, Stats or AIMD themselves; backends must.
- Benchmarks are criterion --quick runs on a shared 4-core machine, so the numbers are indicative only. No before/after benchmark was run for the small-block grouping; its gain is shown only by request counts in the tests.
- proptest-regressions/budget.txt includes one seed that came from a bug in my test harness rather than the budget; it passes and was kept as an extra abort-accounting case.

## Review 4: remaining risks

Summary: I reviewed crates/fsfast-http-transport and crates/fsfast-http in full against the fsfast-core contract, fsspec http.py, aiohttp/yarl and the reqwest, hyper-util and tower-http sources. I found 9 real defects and fixed 8 of them. For each fix I first wrote a test that failed, then fixed the code and confirmed the test passes. For the large-body slicing I also broke the fix on purpose and checked that the test fails. The full suites, clippy -D warnings, rustfmt and rustdoc -D warnings are clean. Changes are limited to the two crates; the root Cargo.toml and the dependencies are unchanged, and t

- docs/adr/0002-http-client.md (outside the reviewed crates, so not edited) still credits reqwest with read-timeout handling. It should mention fsfast's own idle timeout and the 16 MiB limit for resendable in-memory bodies.
- On a 307/308, stream bodies and in-memory bodies over 16 MiB are not resent. This now fails with an error instead of a silent success. Following redirects for them would need our own redirect handling, which would have to repeat reqwest's stripping of credentials across origins.
- Upload progress inside the kernel send buffer (up to 4 MiB) cannot be seen, so after the last chunk is handed over the server must answer within read_timeout. At the default 120 s this matters only on links below about 35 kB/s.
- fsfast does not decompress Content-Encoding responses (see findings). Adding flate2 or similar would add dependencies to the shared Cargo.lock.
- yarl's requoting of query strings still differs in rare cases: a raw space becomes '+', and '/' or '?' escapes are decoded in queries.
- A server that caps 206 parts and also hides the total (`bytes a-b/*`) makes cat_file and get_file stop at the first short part. They cannot tell this from EOF without an extra request.
- Large cat_file reads copy each part twice: once into the part buffer, once into the destination. This is a performance cost only.
- A HEAD request that hangs is retried up to 4 times, each waiting the full read_timeout, before the GET fallback.
- reqwest and hyper-util log through the `log` crate. The tracing-based credential test does not cover those logs.
- Gaps the implementer listed, still open: no cookie jar; hedged requests and HTTP/3 not implemented; no benchmarks yet.