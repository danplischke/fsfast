# fsfast — engineering conventions

fsfast is a Rust engine for fsspec filesystems, exposed to Python as drop-in
replacements. **Read `docs/PLAN.md`** for the architecture and priorities; this
file is the day-to-day contract.

## Layout
- `crates/fsfast-core` — the backend contract: `FileSystem`, `ReadHandle`,
  `WriteHandle` (`src/fs.rs`), `FileInfo`, `Error`/`ErrorKind`,
  `OptionReader`, `ByteRange`/`coalesce_ranges`. **Read `src/fs.rs` before
  implementing or calling a backend.** Changing core is a cross-cutting
  decision: prefer adding to your own crate; if core truly must change, keep it
  backwards compatible and say so in your report.
- `crates/fsfast-engine` — shared performance machinery (retry/backoff,
  adaptive concurrency, memory budget, parallel ranged reads, readahead file
  reader, concurrent part uploader, stats).
- `crates/fsfast-testkit` — backend conformance suite every backend must pass.
- `crates/fsfast-<backend>` — one crate per backend (`local`, `memory`,
  `http`, `s3`, `smb` + `smb-proto`, `sftp`, ...). `fsfast-http-transport` is
  the shared HTTP client for all HTTP-based backends.
- `crates/fsfast-py` — PyO3 extension module `fsfast._core`;
  `python/fsfast/` — thin fsspec-compatible Python classes.
- `scripts/test-services.sh` — local S3 (RustFS container), Samba, sshd.

## Backend crate conventions
- Public type `<Name>FileSystem` implementing `fsfast_core::FileSystem`, with
  `pub fn from_options(opts: fsfast_core::Options) -> fsfast_core::Result<Self>`
  that reads options through `OptionReader` and calls `finish()` (unknown
  options are errors). **Option names match the reference fsspec
  implementation** (s3fs, gcsfs, adlfs, fsspec's built-in smb/sftp/http/local)
  so `storage_options` dicts carry over unchanged.
- `protocols()` returns the fsspec protocol names.
- Paths, `FileInfo.name` and the `FileInfo.extra` keys follow the **reference
  implementation exactly** (e.g. s3fs `ETag`/`LastModified`/`StorageClass`).
  The reference sources are installed: `.venv/lib/python3.13/site-packages/`
  (`fsspec/implementations/*.py`, `s3fs/`, `smbclient/`, `smbprotocol/`,
  `paramiko/`, `sshfs/`). Read them instead of guessing.
- Map every native failure to the most precise `ErrorKind`, attach the native
  code as a `Detail`, and set the path when known.
- Never block the async runtime: blocking syscalls go through
  `tokio::task::spawn_blocking`/`tokio::fs`. Handles must support concurrent
  `read_at` calls.
- Reuse `fsfast-engine` for retries, concurrency limits, parallel reads and
  part uploads instead of re-implementing them.
- Performance is a feature: avoid needless copies (`Bytes::slice`, write
  payloads straight into one buffer), pipeline requests, use the protocol's
  batching/compounding. Comment non-obvious performance decisions.

## Testing
- Unit tests live in the crate. Integration tests go in `tests/` and are
  **gated on environment variables**: if the variables are unset, print a skip
  message and return (a plain `cargo test` must pass without services).
- Test services are normally already running. Load their settings with
  `eval "$(scripts/test-services.sh env)"`. Check a service with `ss -ltn`
  before assuming it is down; only run `scripts/test-services.sh start` if it
  really is down, and never stop services (other engineers share them).
  - S3: `$FSFAST_TEST_S3_ENDPOINT` (RustFS), key/secret in env.
  - SMB: Samba on 127.0.0.1:445, shares `data` (signing mandatory) and `enc`
    (encryption required), user `fsfast` / `fsfastpw`.
  - SFTP: OpenSSH on 127.0.0.1:2222, user `fsfast` / `fsfastpw`.
- Local services need `NO_PROXY=127.0.0.1,localhost` (outbound HTTPS goes via
  a proxy configured in `HTTPS_PROXY`). HTTP clients must honour
  `HTTP(S)_PROXY`/`NO_PROXY`.
- Every backend runs the `fsfast-testkit` conformance suite in an integration
  test.
- Python: the virtualenv is `.venv` (`. .venv/bin/activate`); it has maturin,
  fsspec, s3fs, smbprotocol, paramiko, sshfs, pytest, hypothesis, moto.

## Build hygiene (several engineers work in this tree at once)
- **Do not edit the root `Cargo.toml`.** Add dependencies to your crate's
  `Cargo.toml` (use `x.workspace = true` for deps already in
  `[workspace.dependencies]`).
- Build and test **only your crates**: `cargo test -p fsfast-<name>`,
  `cargo clippy -p fsfast-<name> --all-targets -- -D warnings`. If another
  crate is temporarily broken, do not touch it.
- **Do not commit or push**; the orchestrator commits.
- Only edit files in the crates/directories your task names. Do not create
  files outside them except where the task says so.
- Edition 2024, `cargo fmt`, clippy clean, `tracing` for logs, doc comments on
  public items. No `unsafe` outside `fsfast-py` without a `// SAFETY:` comment.
- Machine: 4 cores, 15 GB RAM. Avoid running more than one heavy build at a time
  from a single task.
