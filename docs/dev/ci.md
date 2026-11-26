# Continuous integration

Workflows live in `.github/workflows/`:

* `ci.yml`: every push to `main`, every pull request, and manual runs.
* `bench.yml`: nightly macro benchmarks, and manual runs with a choice of profile.

Helper files:

* `.github/scripts/ci-services.sh` starts the test services on a runner.
* `.github/requirements-test.txt` pins the Python test dependencies.
* `bench/` holds the benchmark harness (see `bench/README.md`).

## ci.yml jobs

| job | runner | what it runs |
|---|---|---|
| `fmt` | ubuntu-latest | `cargo fmt --all --check` |
| `clippy` | ubuntu-latest | `cargo clippy --workspace --all-targets --locked -- -D warnings`, then `fsf` with only `local,memory` (feature-gating check) |
| `test` | ubuntu-latest | `cargo test --workspace --locked` with no `FSFAST_TEST_*` set: every service-backed test must print a skip message and pass |
| `services` | ubuntu-latest | starts all test services in the runner, then runs `cargo test --workspace` again with the services, runs the SFTP public-key auth tests as root, builds the extension (`maturin develop --release`), runs `pytest tests/python`, the harness tests (`bench/test_bench.py`, `tests/compliance/test_runner.py`) and the abstract compliance suite (`tests/compliance/run.sh abstract`), and runs a tiny `fsf bench` on every service (the bench JSON and the compliance reports are uploaded as artifacts) |
| `wheels` | see the next table | builds the abi3 wheel with `PyO3/maturin-action`, installs it in a clean environment, runs `pytest tests/python` against it, and uploads it |
| `sdist` | ubuntu-latest | `maturin sdist` |

### Wheel matrix

| name | runner | target | notes |
|---|---|---|---|
| linux-x86_64 | ubuntu-latest | x86_64, manylinux_2_28 | built in maturin-action's manylinux container |
| linux-aarch64 | ubuntu-24.04-arm | aarch64, manylinux_2_28 | GitHub's native arm64 runner, so the wheel is tested on the machine that built it (no QEMU) |
| macos-universal2 | macos-latest (arm64) | universal2-apple-darwin | one wheel for arm64 and x86_64; tested on arm64 |
| windows-x64 | windows-latest | x64 | **best effort**: `continue-on-error`, so a failure is shown but does not fail the workflow |

Why Windows is best effort:

* `aws-lc-sys` (rustls and russh go through aws-lc-rs) needs CMake and NASM there. The `prebuilt-nasm` feature, enabled through fsfast-gcs, covers NASM.
* Only fsfast-local has Windows path handling with tests. SMB, SFTP and the object stores are platform-neutral Rust, but nothing has run them on Windows.
* Parts of `tests/python` assume POSIX (fork gate, signals).

When a backend is known not to build on Windows, give that matrix entry `args: --release --locked --out dist --no-default-features --features extension-module,local,memory,...`. No such case is known yet.

All wheels are abi3 for CPython 3.10 and later, through PyO3's `abi3-py310` feature in `crates/fsfast-py`. One wheel per platform covers every supported Python. The wheels are tested with Python 3.13.

### Caching

`Swatinem/rust-cache@v2` caches `~/.cargo` and `target/`:

* Each job type (`clippy`, `test`, `services`, `bench`) has its own key, because their build profiles and features differ.
* Caches are only saved from `main` (`save-if`), so pull requests restore them but do not evict each other's.
* `CARGO_INCREMENTAL=0` and `CARGO_PROFILE_{DEV,TEST}_DEBUG=line-tables-only` keep the cache and the runner's disk usage small. Incremental state does not help a fresh checkout.

maturin-action builds the wheels without a cache. Each wheel is one release build of the whole extension.

## The services job

### Reusing scripts/test-services.sh

The job reuses `scripts/test-services.sh` unchanged, so CI and development machines run the same service configuration:

* the same RustFS, fake-gcs-server and Azurite containers;
* the same `smb.conf`, with the `data` share (signing mandatory) and the `enc` share (encryption required);
* the same `sshd_config`;
* the same user, `fsfast` / `fsfastpw`.

The script works on `ubuntu-latest`:

* it only needs `docker`, which the runner has, plus `smbd`, `smbpasswd` and `sshd`, which are installed from apt;
* it needs root for `useradd`, `chpasswd`, binding port 445 and starting sshd, which the runner gets through password-less `sudo`.

A separate CI variant of the script was not needed.

### What ci-services.sh adds

`.github/scripts/ci-services.sh` wraps the script and adds only what a fresh runner needs:

1. Under GitHub Actions only:
   * It installs `samba` and `openssh-server`.
   * It stops and disables the distribution's `smbd`/`nmbd` units. The samba package starts them on port 445, and `test-services.sh start` leaves any port that is already listening alone, so without this step the tests would talk to the distribution's Samba, which has no `fsfast` user or shares.
   * It pre-pulls the three images.
2. It runs `sudo test-services.sh start`. It waits until every port listens and the three HTTP services answer. RustFS takes a few seconds after the port opens.
3. It appends the `scripts/test-services.sh env` settings (`FSFAST_TEST_*`, `NO_PROXY`) to `$GITHUB_ENV`, so later steps see them as they would after `eval "$(scripts/test-services.sh env)"`.

Outside GitHub Actions the wrapper skips step 1. What remains is safe on a shared development machine: `start` never touches a running service, and the wrapper prints the settings with the secrets masked instead of exporting them.

### Python environment for this job

The job also creates `.venv` from `.github/requirements-test.txt`, as in development. It sets these variables:

* `FSFAST_TEST_FSSPEC_PYTHON=.venv/bin/python` for the differential tests against s3fs, gcsfs, adlfs, smbprotocol, paramiko and sshfs;
* `FSFAST_TEST_MOTO=1` for the S3 tests against `moto_server` from the venv.

The steps run in this order, so the services do not compete with the compiler for the runner's cores:

1. Build the test binaries.
2. Start the services.
3. Run the tests.

## bench.yml

The benchmark workflow runs nightly and on demand. It takes two inputs: a profile (`tiny`, `default` or `large`) and a list of targets. Each run does the following:

1. Builds `fsf` in release mode and starts the services with `ci-services.sh`.
2. Runs `bench/run.py`, which runs `fsf bench --json` once per target.
3. Compares the result with the trailing median of up to 20 earlier runs, which are kept in the Actions cache (`bench/compare.py --history`, 5% threshold).
4. Uploads the JSON as an artifact.

Shared runners are noisy, so the comparison step is `continue-on-error`. It reports regressions without failing the workflow. docs/PLAN.md §8.3 asks for a hard gate on dedicated runners. To get one, point `runs-on` at a self-hosted runner and drop `continue-on-error`.

## The fsf CLI in CI

`crates/fsfast-cli` builds the `fsf` binary on every backend crate. Each backend is a default-on cargo feature. The commands are:

* `ls`, `info`, `find`, `cat`, `cp`, `rm`, `mkdir` and `protocols` for manual use;
* `bench` for the workloads.

Run `fsf --help` and `fsf bench --help` for the full syntax. A few points matter for CI.

Locations:

* A location is a URL whose protocol is compiled in, or a local path.
* The path the backend sees is the backend's own fsspec `_strip_protocol` of the URL.
* Options inferred from the URL (SMB/SFTP host, port and credentials; the Azure account) come from the backend's `_get_kwargs_from_urls`. If one of them is also given with `--opt` and the values differ, `fsf` reports an error, as `fsspec.url_to_fs` does.

Options:

* Options use the reference implementation's names and are checked strictly by each backend's `from_options`.
* They are given as repeated `--opt [PROTO:]KEY=VALUE`. A VALUE that is a JSON number, bool, null, object or array is read as JSON, and `KEY:=JSON` forces JSON.
* Defaults come from three places, with later ones overriding earlier ones:
  * `--test-services`, which maps the `FSFAST_TEST_*` settings to each backend's options;
  * `FSF_OPTS`, a JSON object;
  * `FSF_OPTS_<PROTO>`, a JSON object for one protocol.
* Unscoped options apply to the network backends of a command, not to `file` or `memory`.

Exit codes are 0 for success, 1 for an error, 2 for a usage error, and 130 for a benchmark interrupted with Ctrl-C (the benchmark prefix is still removed).

`crates/fsfast-cli/tests/cli.rs` has two kinds of tests:

* Tests that always run: a tiny bench of every workload against `memory://` and a temporary local directory, a cross-backend W7 (memory to local), cleanup after SIGINT, the manual commands, and the exit codes.
* Tests that need services: a bench against S3, GCS, Azure, SMB and SFTP, and an S3 `cp` round trip. These run when the `FSFAST_TEST_*` variables are set, which they are in the `services` job.

## Validating the workflows locally

GitHub Actions cannot run here. The workflows were checked as follows.

### Workflow syntax

* `python -c 'import yaml; yaml.safe_load(...)'` parses both workflow files.
* `actionlint` (from `uv pip install actionlint-py`) reports nothing. shellcheck (`shellcheck-py`) was on its `PATH`, so the embedded `run:` scripts were checked too.
* `shellcheck` passes on `.github/scripts/ci-services.sh` and `scripts/test-services.sh`.

### Job commands

Each job's commands were run locally on the 4-core development machine with `-j 2`:

* `fmt`: `cargo fmt --all --check` passes for every crate this work touched. When this was written it failed only on files another engineer was editing at the same time (`crates/fsfast-py/src/ext.rs`).
* `clippy`:
  * `cargo clippy -j 2 --workspace --all-targets --locked -- -D warnings` passes.
  * `cargo clippy -p fsfast-cli --no-default-features --features local,memory --all-targets -- -D warnings` passes.
* `test`: `cargo test -j 2 --workspace --locked` with no `FSFAST_TEST_*` variables set passed: 81 test targets, 967 tests, 0 failures. Every service-backed test skipped cleanly.
* `services`:
  * `.github/scripts/ci-services.sh` ran in its non-Actions mode against the already running shared services.
  * `cargo test -p fsfast-cli` passed with the services exported (`eval "$(scripts/test-services.sh env)"`), all 13 integration tests including the five live benches and the S3 `cp` round trip.
  * `python bench/run.py --fsf target/debug/fsf --profile tiny --targets all` completed every workload on memory, local, S3, GCS, Azure, SMB (both shares) and SFTP, and cleaned up after itself.
  * `bench/compare.py` was checked with an identical baseline (no regression) and with a document whose MB/s values were halved (regressions reported, exit status 1).
* `wheels`, `sdist` and `bench.yml`: not run. The commands are the standard maturin-action ones, and `maturin develop --release` was exercised in the services path.

### Never exercised on a real runner

* the apt install and stopping the distribution's `smbd`;
* Docker pulls;
* the manylinux, macOS and Windows wheel builds.

The first run on GitHub may need small fixes in those steps.
