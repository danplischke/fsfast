"""Micro-benchmark of the Python-to-Rust call overhead on small operations.

Not a test (pytest does not collect it: the file name does not start with
``test_``). Run it directly::

    . .venv/bin/activate
    maturin develop --release -m crates/fsfast-py/Cargo.toml
    python tests/python/bench_overhead.py            # all rows
    python tests/python/bench_overhead.py --json out.json --repeat 7

Every row times one small operation (``info``, ``cat_file`` of a 100-byte
file, ``pipe_file`` of 100 bytes) in a tight loop and reports the median
over ``--repeat`` runs of the per-call time in microseconds:

* ``os``: plain ``os.stat`` / ``open().read()`` / ``open('wb').write()``
  (the floor for local files), and ``asyncio.to_thread`` around them (the
  usual way to make them awaitable);
* ``fsspec``: fsspec's ``LocalFileSystem`` / ``MemoryFileSystem``;
* ``fsfast``: the fsfast classes, sync and async (``await fs._info(...)``);
* ``rust``: the bare ``fsfast._core.RustFileSystem`` methods, which isolate
  the bridge from the Python class layer.

Async rows await one call at a time inside a running event loop, so they
measure the latency of one call, including the event-loop wake-up. The
``gather100`` rows run 100 calls concurrently (``asyncio.gather``) and
report the time per call: ``fsfast`` wraps coroutines in tasks (how fsspec
code batches), ``rust`` passes the 100 awaitables created up front.

``--compare`` runs the fsfast rows once per bridge configuration, each in
a fresh interpreter with the runtime's diagnostic switches set, and prints
them side by side:

* ``wave1``: ``FSFAST_SYNC_INLINE=0 FSFAST_ASYNC_COMPLETION=pyo3`` (sync
  calls hand blocking steps to the blocking pool; pending async calls go
  through ``pyo3-async-runtimes``): the bridge as measured in wave 1;
* ``nospin``: ``FSFAST_ASYNC_SPIN_US=0`` (inline sync steps, eventfd
  completion queue, no busy-wait);
* ``default``: the shipped configuration.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import fsfast
import fsspec.implementations.local as fs_local
import fsspec.implementations.memory as fs_memory

PAYLOAD = b"x" * 100
GATHER = 100

#: --compare configurations: name -> environment overrides.
CONFIGS: dict[str, dict[str, str]] = {
    "wave1": {"FSFAST_SYNC_INLINE": "0", "FSFAST_ASYNC_COMPLETION": "pyo3"},
    "nospin": {"FSFAST_ASYNC_SPIN_US": "0"},
    "default": {},
}
_SWITCHES = ("FSFAST_SYNC_INLINE", "FSFAST_ASYNC_COMPLETION", "FSFAST_ASYNC_SPIN_US")


def _time_sync(fn: Callable[[], Any], n: int) -> float:
    """Seconds per call of ``fn`` over ``n`` calls."""
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - t0) / n


async def _time_async_inner(fn: Callable[[], Awaitable[Any]], n: int) -> float:
    t0 = time.perf_counter()
    for _ in range(n):
        await fn()
    return (time.perf_counter() - t0) / n


def _calibrate(run: Callable[[int], float], target: float) -> int:
    """Number of calls that takes about ``target`` seconds."""
    n = 10
    while True:
        dt = run(n) * n
        if dt >= target / 4 or n >= 1_000_000:
            return max(10, int(n * target / max(dt, 1e-9)))
        n *= 4


def measure(run: Callable[[int], float], repeat: int, target: float) -> float:
    """Median µs per call over ``repeat`` runs of about ``target`` seconds."""
    run(50)  # warm-up
    n = _calibrate(run, target)
    return statistics.median(run(n) for _ in range(repeat)) * 1e6


def bench(
    repeat: int,
    target: float,
    only: str | None,
    fsfast_only: bool = False,
    directory: str | None = None,
) -> list[dict[str, Any]]:
    tmp = tempfile.mkdtemp(prefix="fsfast-bench-", dir=directory)
    small = os.path.join(tmp, "small.bin")
    out = os.path.join(tmp, "out.bin")
    with open(small, "wb") as f:
        f.write(PAYLOAD)

    mem_root = f"/bench-{uuid.uuid4().hex}"
    mem_small = f"{mem_root}/small.bin"
    mem_out = f"{mem_root}/out.bin"

    ref_local = fs_local.LocalFileSystem()
    ref_mem = fs_memory.MemoryFileSystem()
    ref_mem.pipe_file(mem_small, PAYLOAD)
    ff_local = fsfast.LocalFileSystem(skip_instance_cache=True)
    ff_mem = fsfast.MemoryFileSystem(skip_instance_cache=True)
    ff_mem.pipe_file(mem_small, PAYLOAD)
    r_local = ff_local.rust
    r_mem = ff_mem.rust

    def os_read() -> bytes:
        with open(small, "rb") as f:
            return f.read()

    def os_write() -> None:
        with open(out, "wb") as f:
            f.write(PAYLOAD)

    sync_cases: list[tuple[str, str, str, Callable[[], Any]]] = [
        ("os", "local", "info", lambda: os.stat(small)),
        ("os", "local", "cat_file", os_read),
        ("os", "local", "pipe_file", os_write),
        ("fsspec", "local", "info", lambda: ref_local.info(small)),
        ("fsspec", "local", "cat_file", lambda: ref_local.cat_file(small)),
        ("fsspec", "local", "pipe_file", lambda: ref_local.pipe_file(out, PAYLOAD)),
        ("fsfast", "local", "info", lambda: ff_local.info(small)),
        ("fsfast", "local", "cat_file", lambda: ff_local.cat_file(small)),
        ("fsfast", "local", "pipe_file", lambda: ff_local.pipe_file(out, PAYLOAD)),
        ("rust", "local", "info", lambda: r_local.info(small)),
        ("rust", "local", "cat_file", lambda: r_local.cat_file(small)),
        ("rust", "local", "pipe_file", lambda: r_local.pipe_file(out, PAYLOAD)),
        ("fsspec", "memory", "info", lambda: ref_mem.info(mem_small)),
        ("fsspec", "memory", "cat_file", lambda: ref_mem.cat_file(mem_small)),
        ("fsspec", "memory", "pipe_file", lambda: ref_mem.pipe_file(mem_out, PAYLOAD)),
        ("fsfast", "memory", "info", lambda: ff_mem.info(mem_small)),
        ("fsfast", "memory", "cat_file", lambda: ff_mem.cat_file(mem_small)),
        ("fsfast", "memory", "pipe_file", lambda: ff_mem.pipe_file(mem_out, PAYLOAD)),
        ("rust", "memory", "info", lambda: r_mem.info(mem_small)),
        ("rust", "memory", "cat_file", lambda: r_mem.cat_file(mem_small)),
        ("rust", "memory", "pipe_file", lambda: r_mem.pipe_file(mem_out, PAYLOAD)),
    ]

    async_cases: list[tuple[str, str, str, Callable[[], Awaitable[Any]]]] = [
        ("os+to_thread", "local", "info", lambda: asyncio.to_thread(os.stat, small)),
        ("os+to_thread", "local", "cat_file", lambda: asyncio.to_thread(os_read)),
        ("os+to_thread", "local", "pipe_file", lambda: asyncio.to_thread(os_write)),
        ("fsfast", "local", "info", lambda: ff_local._info(small)),
        ("fsfast", "local", "cat_file", lambda: ff_local._cat_file(small)),
        ("fsfast", "local", "pipe_file", lambda: ff_local._pipe_file(out, PAYLOAD)),
        ("rust", "local", "info", lambda: r_local.info_async(small)),
        ("rust", "local", "cat_file", lambda: r_local.cat_file_async(small)),
        ("rust", "local", "pipe_file", lambda: r_local.pipe_file_async(out, PAYLOAD)),
        ("fsfast", "memory", "info", lambda: ff_mem._info(mem_small)),
        ("fsfast", "memory", "cat_file", lambda: ff_mem._cat_file(mem_small)),
        ("fsfast", "memory", "pipe_file", lambda: ff_mem._pipe_file(mem_out, PAYLOAD)),
        ("rust", "memory", "info", lambda: r_mem.info_async(mem_small)),
        ("rust", "memory", "cat_file", lambda: r_mem.cat_file_async(mem_small)),
        (
            "rust",
            "memory",
            "pipe_file",
            lambda: r_mem.pipe_file_async(mem_out, PAYLOAD),
        ),
    ]

    def gather_tasks(fs: Any, path: str) -> Callable[[], Awaitable[Any]]:
        return lambda: asyncio.gather(*(fs._info(path) for _ in range(GATHER)))

    def gather_eager(rfs: Any, path: str) -> Callable[[], Awaitable[Any]]:
        return lambda: asyncio.gather(*[rfs.info_async(path) for _ in range(GATHER)])

    # Each fn() makes GATHER calls; rows report the time per call.
    gather_cases: list[tuple[str, str, str, Callable[[], Awaitable[Any]]]] = [
        ("fsfast", "local", "gather100", gather_tasks(ff_local, small)),
        ("rust", "local", "gather100", gather_eager(r_local, small)),
        ("fsfast", "memory", "gather100", gather_tasks(ff_mem, mem_small)),
        ("rust", "memory", "gather100", gather_eager(r_mem, mem_small)),
    ]

    rows: list[dict[str, Any]] = []

    def keep(impl: str, backend: str, op: str) -> bool:
        if fsfast_only and impl not in ("fsfast", "rust"):
            return False
        return only is None or only in f"{impl}/{backend}/{op}"

    for impl, backend, op, fn in sync_cases:
        if keep(impl, backend, op):
            us = measure(lambda n, fn=fn: _time_sync(fn, n), repeat, target)
            rows.append(
                {"mode": "sync", "impl": impl, "backend": backend, "op": op, "us": us}
            )

    async def run_async() -> None:
        cases = [(*c, 1) for c in async_cases] + [(*c, GATHER) for c in gather_cases]
        for impl, backend, op, fn, per in cases:
            if not keep(impl, backend, op):
                continue
            # One event loop for all async rows; each run awaits serially.
            samples: list[float] = []
            await _time_async_inner(fn, 50)  # warm-up
            n = 10
            while True:
                dt = await _time_async_inner(fn, n) * n
                if dt >= target / 4 or n >= 1_000_000:
                    n = max(10, int(n * target / max(dt, 1e-9)))
                    break
                n *= 4
            for _ in range(repeat):
                samples.append(await _time_async_inner(fn, n))
            rows.append(
                {
                    "mode": "async",
                    "impl": impl,
                    "backend": backend,
                    "op": op,
                    "us": statistics.median(samples) * 1e6 / per,
                }
            )

    asyncio.run(run_async())

    for p in (small, out):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
    os.rmdir(tmp)
    ref_mem.rm(mem_root, recursive=True)
    try:
        ff_mem.rm(mem_root, recursive=True)
    except FileNotFoundError:
        pass
    return rows


def print_table(rows: list[dict[str, Any]]) -> None:
    print(f"{'mode':<6} {'backend':<7} {'op':<10} {'impl':<13} {'us/op':>9}")
    for r in sorted(rows, key=lambda r: (r["mode"] != "sync", r["backend"], r["op"])):
        print(
            f"{r['mode']:<6} {r['backend']:<7} {r['op']:<10} {r['impl']:<13} {r['us']:>9.2f}"
        )


def compare(args: argparse.Namespace) -> list[dict[str, Any]]:
    """Run the benchmark once per entry of ``CONFIGS`` (fresh interpreters:
    the switches are read once per process) and merge the rows."""
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="fsfast-bench-cmp-") as tmp:
        for name, env_over in CONFIGS.items():
            env = {k: v for k, v in os.environ.items() if k not in _SWITCHES}
            env.update(env_over)
            out = os.path.join(tmp, f"{name}.json")
            cmd = [sys.executable, os.path.abspath(__file__), "--json", out, "--quiet"]
            cmd += ["--repeat", str(args.repeat), "--target", str(args.target)]
            # Reference rows (os, fsspec) do not depend on the switches.
            if name != "default":
                cmd += ["--fsfast-only"]
            if args.only:
                cmd += ["--only", args.only]
            if args.dir:
                cmd += ["--dir", args.dir]
            subprocess.run(cmd, env=env, check=True)
            with open(out) as f:
                for r in json.load(f):
                    r["config"] = name if r["impl"] in ("fsfast", "rust") else "-"
                    rows.append(r)
    return rows


def print_compare(rows: list[dict[str, Any]]) -> None:
    names = list(CONFIGS)
    table: dict[tuple[str, str, str, str], dict[str, float]] = {}
    for r in rows:
        key = (r["mode"], r["backend"], r["op"], r["impl"])
        table.setdefault(key, {})[r["config"]] = r["us"]
    head = f"{'mode':<6} {'backend':<7} {'op':<10} {'impl':<13}"
    print(head + "".join(f" {n:>9}" for n in names) + "   (us/op)")
    for key in sorted(table, key=lambda k: (k[0] != "sync", k[1], k[2], k[3])):
        vals = table[key]
        cells = []
        for n in names:
            v = vals.get(n, vals.get("-"))
            cells.append(f" {v:>9.2f}" if v is not None else f" {'':>9}")
        mode, backend, op, impl = key
        print(f"{mode:<6} {backend:<7} {op:<10} {impl:<13}" + "".join(cells))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--repeat", type=int, default=5, help="runs per row (median is reported)"
    )
    ap.add_argument("--target", type=float, default=0.2, help="seconds per run")
    ap.add_argument(
        "--only", help="substring filter on impl/backend/op, e.g. 'rust/local'"
    )
    ap.add_argument("--json", help="also write the rows to this file")
    ap.add_argument(
        "--dir",
        help="directory for the local files (default: the temp dir; a tmpfs such as "
        "/dev/shm takes disk latency out of pipe_file)",
    )
    ap.add_argument(
        "--compare",
        action="store_true",
        help="fsfast rows per bridge configuration (CONFIGS)",
    )
    ap.add_argument("--fsfast-only", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--quiet", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    if not args.quiet:
        print(
            f"python {sys.version.split()[0]}, fsfast {fsfast.__version__}, {os.cpu_count()} CPUs"
        )
    if args.compare:
        rows = compare(args)
        print_compare(rows)
    else:
        rows = bench(args.repeat, args.target, args.only, args.fsfast_only, args.dir)
        if not args.quiet:
            print_table(rows)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(rows, f, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
