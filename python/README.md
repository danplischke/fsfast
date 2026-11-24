# fsfast (Python package)

Drop-in replacements for fsspec filesystems, implemented in Rust. The Python
classes are thin `fsspec.asyn.AsyncFileSystem` subclasses; every method,
file object, cache and batch operation runs in the `fsfast._core` extension
module (crate `crates/fsfast-py`).

Implemented so far: `file`/`local` (`fsfast.LocalFileSystem`) and `memory`
(`fsfast.MemoryFileSystem`). More backends (http, s3, smb, ...) plug into the
same machinery: one cargo feature plus one table entry in
`crates/fsfast-py/src/registry.rs`, and a small protocol class here.

## Build and test

From the repository root, inside the virtualenv:

```sh
. .venv/bin/activate
maturin develop --release          # builds fsfast._core (abi3, CPython >= 3.10) into the venv
pytest tests/python                # Python tests (fsspec abstract suite, parity, ...)

# Rust side of the bindings (embeds the venv's interpreter):
PYO3_PYTHON=$PWD/.venv/bin/python cargo test -p fsfast-py
PYO3_PYTHON=$PWD/.venv/bin/python cargo clippy -p fsfast-py --all-targets -- -D warnings
```

`maturin build --release` produces the wheel (`fsfast-*-cp310-abi3-*.whl`).
Larger randomized parity runs: `FSFAST_HYPOTHESIS_EXAMPLES=1000 pytest
tests/python/test_parity.py -k Stateful`.

## Usage

```python
import fsfast

fs = fsfast.LocalFileSystem()            # same constructor options as fsspec's
fs.cat_file("/data/file.bin", 0, 1024)
with fs.open("/data/file.bin") as f:     # Rust reader: adaptive readahead, parallel reads
    header = f.read(16)

fsfast.install()                         # fsspec.filesystem("file"/"memory") -> fsfast
fsfast.install(["memory"])               # only some protocols
fsfast.uninstall()
```

`FSFAST_OVERRIDE=file,memory` (or `all`) installs the classes when `fsfast`
is imported. `fsfast.LocalFileSystem` is a subclass of fsspec's
`LocalFileSystem`, so `isinstance` checks keep working.

Tuning and diagnostics:

* `fs.stats()` / `fsfast.stats(fs)`: request, error, byte counters and
  latency quantiles per operation kind; `fs.reset_stats()`.
* `fsfast.runtime_info()`: the shared tokio runtime (pid, workers, tasks).
* `FSFAST_WORKER_THREADS`, `FSFAST_MAX_BLOCKING_THREADS`: runtime sizes.
* `FSFAST_MEMORY_BUDGET`: memory budget for prefetching and caches.
* `open(..., cache_type=...)` accepts fsspec's cache names (`readahead`
  default, `none`, `blockcache`, `background`, `mmap`, `bytes`, `first`,
  `all`); `cache_options` takes `maxblocks`, `request_size`, `concurrency`.
* `fs.rust` is the underlying `fsfast._core.RustFileSystem` with batch
  methods (`cat_many`, `info_many`, `pipe_many`, `cp_files`, ...) taking
  `on_error="raise" | "return"` and `batch_size`.

## How it works (docs/PLAN.md §4.4)

* **Sync methods** never touch fsspec's `sync()` event-loop bridge. Each one
  calls Rust, which releases the GIL and drives the future on the calling
  thread with a small executor (no thread hop of its own, no timer per call),
  waking every 100 ms to run Python's signal handlers so Ctrl-C works.
* **Async methods** (`_cat_file`, `_cat_ranges`, `_info`, `_find`, `_rm`,
  ...) return asyncio futures through `pyo3-async-runtimes` on the same
  runtime; zarr v3's `FsspecStore` uses them directly. An operation that
  completes without waiting (memory, cached data) returns an
  already-resolved future without any thread hop.
* **Bulk operations** (`cat`, `cat_ranges`, `pipe`, `rm`, `copy`, `put`,
  `get`, `sizes`) expand paths with fsspec's own rules, then run all
  per-file operations as one concurrent Rust call.
* **Files** are `io.RawIOBase` objects over Rust readers and writers:
  `read(n)` of 2 MiB or more fills the result `bytes` directly (parallel
  ranged reads), `readinto` writes straight into the caller's buffer with the
  GIL released, line iteration runs in Rust, small writes are batched.
* **Errors** map to `FileNotFoundError`, `PermissionError`,
  `FileExistsError`, `IsADirectoryError`, `NotADirectoryError`,
  `OSError(ENOTEMPTY)`, `ValueError`, `NotImplementedError`, `TimeoutError`,
  `ConnectionError` and `fsfast.PreconditionFailed` (an `OSError`), with
  `errno`, `strerror`, `filename` and the attributes `http_status`,
  `ntstatus`, `sftp_status`, `code`.
* **Fork safety**: one runtime per process; a forked child abandons the
  parent's runtime and builds its own (`os.register_at_fork` plus a PID
  check). Filesystem objects created before a fork keep working in the child.
  Files opened for reading before a fork keep working too (the DataLoader
  pattern): the child leaks the parent's prefetch state, which belongs to
  the parent's runtime, and continues at the same position. A file opened
  for writing belongs to the parent: in the child, `write`/`flush` raise
  `OSError` and `close` gives the file up without committing it.
* **Free-threaded CPython**: the module is declared `gil_used = false`.

## Performance status (local and memory, shared 4-core VM)

Relative to fsspec's reference classes, best of several runs:

* memory `info`: about 60x faster; memory `cat_file`: about 1.3x slower
  (both around 1-2 µs per call; the Python wrapper's path handling dominates).
* 256 MiB `cat_file` / `open().read()`: 1.2x faster; `readinto`: equal
  (memory-bandwidth bound).
* Binary line iteration: about 1.7x slower than CPython's C `BufferedReader`
  (fsspec's local files are plain OS files), much faster than fsspec's
  Python `AbstractBufferedFile`.
* Local small operations (`info`, small `cat_file`): about 20-25 µs per call
  against 3-15 µs for fsspec, because fsfast-local runs every syscall on
  tokio's blocking pool, a thread hop per call. Batched calls (`cat` of many
  paths, `find`) hide it with concurrency.
* Async calls that complete without waiting (memory, cached data) take
  about 2 µs; calls that must wait pay `pyo3-async-runtimes`' thread hops
  (about 100 µs per call on this machine). Batched async calls (`_cat_ranges`,
  `_cat`) cost about 1.5 µs per item.

## Known differences from fsspec

* Bulk operations run their items concurrently. When one item fails, fsspec's
  sync loop stops at that item. `copy`, `put`, `get` and `rm` complete the
  other items and then raise (like fsspec's own async `_put`/`_get`/`_copy`);
  `pipe` (and the Rust batch methods with `on_error="raise"`) start no new
  item after the failure but let the writes already in flight finish, so a
  target is never left half-written, then raise the first error in input
  order.
* `LocalFileSystem.put_file(..., mode="create")` raises `FileExistsError`
  for an existing target (fsspec's local `put_file` ignores `mode`).
* `MemoryFileSystem` has no `store`/`pseudo_dirs` attributes; empty it with
  `fs.rm("", recursive=True)`. Pickling an instance with
  `global_store=False` carries its files and directories along, as fsspec
  does.
* Transactions (`autocommit=False`) write to a hidden sibling
  `.<name>.fsfast-<id>.tmp` that is renamed into place on commit.
* `open_async` is not implemented (fsspec's default raises
  `NotImplementedError` too).
* On Windows the buffer protocol is reached through `memoryview` (one extra
  copy in `readinto` and for non-`bytes` writes), because the abi3 target
  (CPython 3.10) lacks it in `python3.dll`. Windows has not been tested.
