#!/usr/bin/env python3
"""One Python implementation against one target: the W1-W8 workloads.

``bench/run.py`` starts this script in a fresh interpreter for every
(target, implementation) pair so caches, event loops, connection pools and
memory never leak from one implementation into the next::

    python bench/pyworker.py --target s3 --impl reference --root BUCKET \\
        --params '{"size": ...}'

It prints one JSON document (``{"impl", "target", "results": [...], ...}``)
on stdout; progress goes to stderr. Every workload uses the plain fsspec API
a user would call (``cat_file``, ``open``, ``cat``, ``pipe``, ``info``,
``ls``, ``find``, ``cat_ranges``, ``copy``, ``rm``), so fsfast's classes and
the reference implementations run exactly the same code. Results are
verified (byte and entry counts) so a broken implementation cannot report a
fast but wrong number.
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import random
import resource
import shutil
import statistics
import sys
import tempfile
import time
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from benchcfg import WORKLOADS, Params, smb_share, storage_options

#: Targets with real directories (parents must exist before writing).
HIERARCHICAL = {"local", "memory", "smb", "smb-enc", "sftp"}
#: Targets whose root is a bucket/container.
BUCKETS = {"s3", "gcs", "azure"}

DESCRIPTIONS = {(w, n): d for w, n, d in WORKLOADS}


class Unsupported(Exception):
    """The implementation does not offer the operation."""


def log(msg: str) -> None:
    print(f"[pyworker] {msg}", file=sys.stderr, flush=True)


def make_fs(target: str, impl: str) -> Any:
    """The filesystem instance for ``impl`` (fsfast / reference / sshfs)."""
    opts = storage_options(target)
    if impl == "fsfast":
        import fsfast

        cls = {
            "local": fsfast.LocalFileSystem,
            "memory": fsfast.MemoryFileSystem,
            "http": fsfast.HTTPFileSystem,
            "s3": fsfast.S3FileSystem,
            "gcs": fsfast.GCSFileSystem,
            "azure": fsfast.AzureBlobFileSystem,
            "smb": fsfast.SMBFileSystem,
            "smb-enc": fsfast.SMBFileSystem,
            "sftp": fsfast.SFTPFileSystem,
        }[target]
        return cls(skip_instance_cache=True, **opts)
    if impl == "sshfs":
        import sshfs

        host = opts.pop("host")
        return sshfs.SSHFileSystem(
            host, known_hosts=None, skip_instance_cache=True, **opts
        )
    if impl != "reference":
        raise SystemExit(f"unknown impl {impl!r}")
    if target == "local":
        from fsspec.implementations.local import LocalFileSystem

        return LocalFileSystem(skip_instance_cache=True)
    if target == "memory":
        from fsspec.implementations.memory import MemoryFileSystem

        return MemoryFileSystem(skip_instance_cache=True)
    if target == "http":
        from fsspec.implementations.http import HTTPFileSystem

        return HTTPFileSystem(skip_instance_cache=True)
    if target == "s3":
        import s3fs

        return s3fs.S3FileSystem(skip_instance_cache=True, **opts)
    if target == "gcs":
        os.environ.setdefault("GCSFS_EXPERIMENTAL_ZB_HNS_SUPPORT", "false")
        import gcsfs

        return gcsfs.GCSFileSystem(skip_instance_cache=True, **opts)
    if target == "azure":
        import adlfs

        return adlfs.AzureBlobFileSystem(skip_instance_cache=True, **opts)
    if target in ("smb", "smb-enc"):
        from fsspec.implementations.smb import SMBFileSystem

        return SMBFileSystem(skip_instance_cache=True, **opts)
    if target == "sftp":
        from fsspec.implementations.sftp import SFTPFileSystem

        host = opts.pop("host")
        return SFTPFileSystem(host, skip_instance_cache=True, **opts)
    raise SystemExit(f"unknown target {target!r}")


def summarize(
    times: list[float], cpus: list[float], nbytes: int, ops: int, items: int | None
) -> dict[str, Any]:
    """The result fields shared with ``fsf bench --json``."""
    best, med = min(times), statistics.median(times)
    out: dict[str, Any] = {
        "iterations": len(times),
        "times_s": [round(t, 6) for t in times],
        "best_s": round(best, 6),
        "median_s": round(med, 6),
        "bytes_per_iter": nbytes,
        "ops_per_iter": ops,
        "mb_per_s": (
            {"best": nbytes / best / 1e6, "median": nbytes / med / 1e6}
            if nbytes
            else None
        ),
        "ops_per_s": {"best": ops / best, "median": ops / med},
        "cpu_s": {
            "best": round(min(cpus), 6),
            "median": round(statistics.median(cpus), 6),
        },
    }
    if items is not None:
        out["items_per_iter"] = items
        out["items_per_s"] = {"best": items / best, "median": items / med}
    return out


def cpu_now() -> float:
    """User + system CPU seconds of this process (every thread: Rust
    runtime workers, fsspec's IO thread, the main thread)."""
    r = resource.getrusage(resource.RUSAGE_SELF)
    return r.ru_utime + r.ru_stime


class Worker:
    def __init__(
        self, target: str, impl: str, root: str, p: Params, disk_root: str | None
    ) -> None:
        self.target, self.impl, self.root, self.p = target, impl, root, p
        #: http: the server's document directory for ``root`` (setup writes
        #: go straight to disk, the server has no fast bulk upload).
        self.disk_root = Path(disk_root) if disk_root else None
        self.fs = make_fs(target, impl)
        self.results: list[dict[str, Any]] = []
        self.chunk = random.Random(p.seed).randbytes(p.chunk)
        self.small = (
            self.chunk[: p.small_size]
            if p.small_size <= p.chunk
            else os.urandom(p.small_size)
        )
        self._large: str | None = None
        self._small: list[str] | None = None
        self.tmpdir = Path(
            tempfile.mkdtemp(
                prefix="fsbench-", dir="/dev/shm" if os.path.isdir("/dev/shm") else None
            )
        )

    # -- paths and setup --------------------------------------------------

    def path(self, rel: str) -> str:
        return f"{self.root}/{rel}"

    def makedirs(self, rel: str) -> None:
        if self.target in HIERARCHICAL:
            self.fs.makedirs(self.path(rel), exist_ok=True)
        elif self.disk_root is not None:
            (self.disk_root / rel).mkdir(parents=True, exist_ok=True)

    def create_root(self) -> None:
        if self.target in BUCKETS:
            self.fs.mkdir(self.root)
        elif self.target in HIERARCHICAL:
            self.fs.makedirs(self.root, exist_ok=True)
        elif self.disk_root is not None:
            self.disk_root.mkdir(parents=True, exist_ok=True)

    def cleanup(self) -> None:
        try:
            if self.disk_root is None:
                self.fs.rm(self.root, recursive=True)
        except Exception as e:  # noqa: BLE001 - run.py sweeps leftovers with fsf
            log(f"cleanup of {self.root} failed: {type(e).__name__}: {e}")
        for f in self.tmpdir.iterdir():
            f.unlink()
        self.tmpdir.rmdir()

    def drop(self, rel: str, files: list[str]) -> None:
        """Remove a workload's data once it is done (untimed), so later
        workloads run against a bucket/directory of the same size as
        ``fsf bench``'s (emulators slow down as a bucket grows)."""
        try:
            if self.disk_root is not None:
                shutil.rmtree(self.disk_root / rel, ignore_errors=True)
            elif self.target in HIERARCHICAL:
                self.fs.rm(self.path(rel), recursive=True)
            elif files:
                self.fs.rm(files)
        except Exception as e:  # noqa: BLE001 - cleanup() removes the rest
            log(f"removing {rel} failed: {type(e).__name__}: {e}")
        self.invalidate()

    def write_large(self, rel: str, size: int) -> None:
        """Write ``size`` bytes (``chunk`` repeated) through ``open('wb')``."""
        n, rest = divmod(size, len(self.chunk))
        if self.disk_root is not None:
            with open(self.disk_root / rel, "wb") as f:
                f.writelines(self.chunk for _ in range(n))
                f.write(self.chunk[:rest])
            return
        with self.fs.open(self.path(rel), "wb") as f:
            for _ in range(n):
                f.write(self.chunk)
            if rest:
                f.write(self.chunk[:rest])

    def write_many(self, rels: list[str], data: bytes) -> None:
        if self.disk_root is not None:
            for r in rels:
                (self.disk_root / r).write_bytes(data)
            return
        self.fs.pipe({self.path(r): data for r in rels})

    def large(self) -> str:
        if self._large is None:
            log(f"setup: {self.p.size} B object")
            self.makedirs("large")
            self.write_large("large/data.bin", self.p.size)
            self._large = self.path("large/data.bin")
        return self._large

    def small_files(self) -> list[str]:
        if self._small is None:
            log(f"setup: {self.p.small_count} small files")
            self.makedirs("small")
            rels = [f"small/f{i:06d}" for i in range(self.p.small_count)]
            self.write_many(rels, self.small)
            self._small = [self.path(r) for r in rels]
        return self._small

    # -- the timing loop --------------------------------------------------

    def invalidate(self) -> None:
        try:
            self.fs.invalidate_cache()
        except Exception as e:  # noqa: BLE001 - not every implementation has one
            log(f"invalidate_cache: {type(e).__name__}: {e}")

    def measure(
        self,
        wid: str,
        name: str,
        body: Callable[[Any], Any],
        *,
        nbytes: int,
        ops: int,
        items: int | None = None,
        prepare: Callable[[int], Any] = lambda it: None,
        verify: Callable[[Any, Any], None] = lambda ctx, out: None,
        teardown: Callable[[Any], None] = lambda ctx: None,
        params: dict[str, Any] | None = None,
        method: str | None = None,
    ) -> None:
        """Run ``warmup`` untimed and ``repeat`` timed iterations of ``body``.

        ``prepare(it)`` (untimed) returns the iteration's context, ``body``
        is timed, ``verify`` checks the result (untimed) and ``teardown``
        removes what the iteration created (untimed)."""
        res: dict[str, Any] = {
            "workload": wid,
            "name": name,
            "description": DESCRIPTIONS.get((wid, name), ""),
            "impl": self.impl,
            "params": params or {},
            "warmup": self.p.warmup,
        }
        if method:
            res["method"] = method
        times: list[float] = []
        cpus: list[float] = []
        stats = None
        try:
            for it in range(self.p.warmup + self.p.repeat):
                ctx = prepare(it)
                self.invalidate()
                gc.collect()
                has_stats = hasattr(self.fs, "reset_stats")
                if has_stats:
                    self.fs.reset_stats()
                c0, t0 = cpu_now(), time.perf_counter()
                out = body(ctx)
                t, c = time.perf_counter() - t0, cpu_now() - c0
                if has_stats:
                    stats = self.fs.stats()
                verify(ctx, out)
                del out
                teardown(ctx)
                if it >= self.p.warmup:
                    times.append(t)
                    cpus.append(c)
            res.update(summarize(times, cpus, nbytes, ops, items))
            if stats is not None:
                res["stats_last_iter"] = compact_stats(stats)
            log(
                f"{wid} {name}: best {min(times):.4f}s median {statistics.median(times):.4f}s"
            )
        except Unsupported as e:
            res["unsupported"] = str(e)
            log(f"{wid} {name}: unsupported: {e}")
        except NotImplementedError as e:
            res["unsupported"] = f"NotImplementedError: {e}".rstrip(": ")
            log(f"{wid} {name}: unsupported: {res['unsupported']}")
        except Exception as e:  # noqa: BLE001 - recorded, the next workload still runs
            res["error"] = f"{type(e).__name__}: {e}"[:2000]
            res["traceback"] = traceback.format_exc(limit=8)[-4000:]
            log(f"{wid} {name}: ERROR {res['error']}")
        self.results.append(res)

    # -- workloads --------------------------------------------------------

    def w1(self) -> None:
        p = self.large()
        size = self.p.size

        def check(_ctx: Any, n: int) -> None:
            expect(n, size, "bytes")

        self.measure(
            "W1",
            "seq-read",
            lambda _: len(self.fs.cat_file(p)),
            nbytes=size,
            ops=1,
            verify=check,
            params={"size": size},
        )

        def via_open(_: Any) -> int:
            total = 0
            with self.fs.open(p, "rb") as f:
                while True:
                    b = f.read(self.p.chunk)
                    if not b:
                        return total
                    total += len(b)

        self.measure(
            "W1",
            "seq-read-open",
            via_open,
            nbytes=size,
            ops=1,
            verify=check,
            params={"size": size, "read_size": self.p.chunk},
        )

    def w2(self) -> None:
        size = self.p.size
        self.makedirs("w2")
        rel = lambda it: f"w2/it{it:04d}.bin"

        if self.target == "http":
            # fsspec's HTTPFileSystem cannot open files for writing; both
            # implementations upload from a local file with PUT.
            src = self.tmpdir / "w2-src.bin"
            with open(src, "wb") as f:
                f.writelines(self.chunk for _ in range(size // len(self.chunk)))
                f.write(self.chunk[: size % len(self.chunk)])

            def body(it: int) -> None:
                self.fs.put_file(str(src), self.path(rel(it)), method="put")

            method = "put_file (PUT) from a local file"
        else:

            def body(it: int) -> None:
                self.write_large_timed(self.path(rel(it)), size)

            method = None

        def verify(it: int, _out: Any) -> None:
            if it == 0:
                expect(self.fs.info(self.path(rel(it)))["size"], size, "bytes")

        def teardown(it: int) -> None:
            if self.disk_root is not None:
                (self.disk_root / rel(it)).unlink(missing_ok=True)
            else:
                self.fs.rm_file(self.path(rel(it)))

        self.measure(
            "W2",
            "seq-write",
            body,
            nbytes=size,
            ops=1,
            prepare=lambda it: it,
            verify=verify,
            teardown=teardown,
            params={"size": size, "write_size": self.p.chunk},
            method=method,
        )

    def write_large_timed(self, path: str, size: int) -> None:
        n, rest = divmod(size, len(self.chunk))
        with self.fs.open(path, "wb") as f:
            for _ in range(n):
                f.write(self.chunk)
            if rest:
                f.write(self.chunk[:rest])

    def w3(self) -> None:
        paths = self.small_files()
        n, sz = self.p.small_count, self.p.small_size

        def verify(_ctx: Any, out: dict[str, bytes]) -> None:
            expect(len(out), n, "files")
            expect(sum(len(v) for v in out.values()), n * sz, "bytes")

        self.measure(
            "W3",
            "small-read",
            lambda _: self.fs.cat(paths),
            nbytes=n * sz,
            ops=n,
            verify=verify,
            params={"count": n, "file_size": sz},
        )
        self.drop("small", paths)
        self._small = None

    def w4(self) -> None:
        n, sz = self.p.small_count, self.p.small_size
        self.makedirs("w4")

        def prepare(it: int) -> tuple[str, dict[str, bytes]]:
            d = f"w4/it{it:04d}"
            self.makedirs(d)
            return d, {self.path(f"{d}/f{i:06d}"): self.small for i in range(n)}

        def verify(ctx: tuple[str, dict[str, bytes]], _out: Any) -> None:
            if ctx[0].endswith("0000"):
                self.invalidate()
                expect(len(self.fs.find(self.path(ctx[0]))), n, "files")

        def teardown(ctx: tuple[str, dict[str, bytes]]) -> None:
            if (
                self.disk_root is not None
            ):  # http has no rm: remove on the server's disk
                shutil.rmtree(self.disk_root / ctx[0])
            else:
                self.fs.rm(list(ctx[1]))

        self.measure(
            "W4",
            "small-write",
            lambda ctx: self.fs.pipe(ctx[1]),
            nbytes=n * sz,
            ops=n,
            prepare=prepare,
            verify=verify,
            teardown=teardown,
            params={"count": n, "file_size": sz},
        )

    def w5(self) -> None:
        n, ni = self.p.ls_entries, self.p.info_count
        # info() runs on its own info_count-file directory (as fsf's W5
        # info group does): emulators answer info() slower in a bigger
        # bucket, so both see the same bucket size.
        log(f"setup: {ni} files for info()")
        self.makedirs("info")
        irels = [f"info/f{i:06d}" for i in range(ni)]
        self.write_many(irels, self.small[:100])
        infos = [self.path(r) for r in irels]

        def info_loop(_: Any) -> int:
            info = self.fs.info
            k = 0
            for q in infos:
                if info(q)["type"] != "file":
                    raise AssertionError(f"{q}: not a file")
                k += 1
            return k

        self.measure(
            "W5",
            "metadata-info",
            info_loop,
            nbytes=0,
            ops=ni,
            verify=lambda _c, k: expect(k, ni, "info calls"),
            params={"count": ni},
        )
        self.drop("info", infos)

        log(f"setup: {n}-entry directory")
        self.makedirs("meta")
        rels = [f"meta/f{i:06d}" for i in range(n)]
        self.write_many(rels, self.small[:100])
        d = self.path("meta")
        self.measure(
            "W5",
            "metadata-ls",
            lambda _: self.fs.ls(d, detail=True),
            nbytes=0,
            ops=1,
            items=n,
            verify=lambda _c, out: expect(len(out), n, "entries"),
            params={"entries": n},
        )
        self.measure(
            "W5",
            "metadata-find",
            lambda _: self.fs.find(d),
            nbytes=0,
            ops=1,
            items=n,
            verify=lambda _c, out: expect(len(out), n, "entries"),
            params={"entries": n},
        )
        self.drop("meta", [self.path(r) for r in rels])

    def w6(self) -> None:
        if self.impl == "sshfs":
            # sshfs's _cat_file ignores start/end: every "range" would be the
            # whole object, and cat_ranges gathers them all at once (500 x
            # 256 MiB in memory). Not run.
            self.results.append(
                {
                    "workload": "W6",
                    "name": "random-read",
                    "impl": self.impl,
                    "unsupported": "sshfs's _cat_file ignores start/end (returns the whole object)",
                }
            )
            return
        p = self.large()
        size, ln, k = self.p.size, self.p.range_size, self.p.ranges

        def prepare(it: int) -> tuple[list[int], list[int]]:
            rng = random.Random(self.p.seed + it)
            starts = [rng.randrange(0, size - ln + 1) for _ in range(k)]
            return starts, [s + ln for s in starts]

        def verify(_ctx: Any, out: list[Any]) -> None:
            for o in out:
                if isinstance(o, BaseException):
                    raise o
            expect(sum(len(o) for o in out), k * ln, "bytes")

        self.measure(
            "W6",
            "random-read",
            lambda ctx: self.fs.cat_ranges([p] * k, ctx[0], ctx[1]),
            nbytes=k * ln,
            ops=k,
            prepare=prepare,
            verify=verify,
            params={"size": size, "range_size": ln, "ranges": k, "seed": self.p.seed},
        )
        self.drop("large", [p])
        self._large = None

    def w7(self) -> None:
        n, sz = self.p.copy_count, self.p.copy_size
        log(f"setup: {n} x {sz} B copy sources")
        self.makedirs("copy/src")
        data = (self.chunk * (sz // len(self.chunk) + 1))[:sz]
        srcs_rel = [f"copy/src/f{i:04d}" for i in range(n)]
        self.write_many(srcs_rel, data)
        srcs = [self.path(r) for r in srcs_rel]
        del data
        if self.target == "http":
            raise_unsupported = (
                "fsspec's HTTPFileSystem has no cp_file (and no rm to clean up)"
            )
        else:
            raise_unsupported = None
        method = ["copy(list, list)"]

        def prepare(it: int) -> tuple[str, list[str]]:
            d = f"copy/it{it:04d}"
            self.makedirs(d)
            return d, [self.path(f"{d}/f{i:04d}") for i in range(n)]

        def body(ctx: tuple[str, list[str]]) -> None:
            if raise_unsupported:
                raise Unsupported(raise_unsupported)
            # The first (warm-up) iteration finds what the implementation
            # offers, falling back as a user would: fsspec's smb copy()
            # takes one pair only (server-side smbclient.copyfile); fsspec's
            # sftp has no cp_file at all, so the files go through the client.
            if method[0] == "copy(list, list)":
                try:
                    self.fs.copy(srcs, ctx[1])
                    return
                except (NotImplementedError, TypeError, AttributeError) as e:
                    log(
                        f"copy(list, list) failed ({type(e).__name__}: {e}); trying copy() per file"
                    )
                    done = [t for t in ctx[1] if self.fs.exists(t)]
                    if done:
                        self.fs.rm(done)
                    method[0] = "copy() per file"
            if method[0] == "copy() per file":
                try:
                    for s, t in zip(srcs, ctx[1]):
                        self.fs.copy(s, t)
                    return
                except (NotImplementedError, TypeError, AttributeError) as e:
                    log(
                        f"copy() failed ({type(e).__name__}: {e}); client-side copy instead"
                    )
                    method[0] = "client-side cat_file + pipe_file (no cp_file)"
            for s, t in zip(srcs, ctx[1]):
                self.fs.pipe_file(t, self.fs.cat_file(s))

        def verify(ctx: tuple[str, list[str]], _out: Any) -> None:
            if ctx[0].endswith("0000") or ctx[0].endswith(f"{self.p.warmup:04d}"):
                self.invalidate()
                found = self.fs.find(self.path(ctx[0]), detail=True)
                expect(len(found), n, "files")
                expect(sum(v["size"] for v in found.values()), n * sz, "bytes")

        def teardown(ctx: tuple[str, list[str]]) -> None:
            self.fs.rm(ctx[1])

        self.measure(
            "W7",
            "copy",
            body,
            nbytes=n * sz,
            ops=n,
            prepare=prepare,
            verify=verify,
            teardown=teardown,
            params={"count": n, "file_size": sz},
        )
        if self.results[-1].get("times_s"):
            self.results[-1]["method"] = method[0]
        self.drop("copy", srcs)

    def w8(self) -> None:
        n = self.p.delete_count
        if self.target == "http":
            self.results.append(
                {
                    "workload": "W8",
                    "name": "delete",
                    "impl": self.impl,
                    "unsupported": "fsspec's HTTPFileSystem has no rm_file",
                }
            )
            return

        def prepare(it: int) -> list[str]:
            d = f"w8/it{it:04d}"
            self.makedirs(d)
            rels = [f"{d}/f{i:06d}" for i in range(n)]
            self.write_many(rels, self.small)
            return [self.path(r) for r in rels]

        def verify(ctx: list[str], _out: Any) -> None:
            self.invalidate()
            parent = ctx[0].rsplit("/", 1)[0]
            left = self.fs.find(parent) if self.fs.exists(parent) else []
            expect(len(left), 0, "files left")

        self.measure(
            "W8",
            "delete",
            lambda paths: self.fs.rm(paths),
            nbytes=0,
            ops=n,
            prepare=prepare,
            verify=verify,
            params={"count": n, "file_size": self.p.small_size},
        )


def expect(got: int, want: int, what: str) -> None:
    if got != want:
        raise AssertionError(f"expected {want} {what}, got {got}")


def compact_stats(s: Any) -> Any:
    """fsfast's stats() without the latency quantiles (request counters are
    what the report needs)."""
    if not isinstance(s, dict):
        return s
    return {k: v for k, v in s.items() if not k.startswith("latency")}


ORDER = ["W1", "W2", "W3", "W4", "W5", "W6", "W7", "W8"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--target", required=True)
    ap.add_argument("--impl", required=True, choices=["fsfast", "reference", "sshfs"])
    ap.add_argument("--root", required=True, help="scratch root (created and removed)")
    ap.add_argument("--disk-root", help="http: server directory that serves --root")
    ap.add_argument("--params", required=True, help="JSON Params")
    ap.add_argument("--workloads", default=",".join(ORDER))
    a = ap.parse_args(argv)

    p = Params.from_json(json.loads(a.params))
    wanted = [w.strip().upper() for w in a.workloads.split(",") if w.strip()]
    t0 = time.monotonic()
    doc: dict[str, Any] = {
        "impl": a.impl,
        "target": a.target,
        "root": a.root,
        "results": [],
    }
    if a.target in ("smb", "smb-enc"):
        doc["share"] = smb_share(a.target)
    try:
        w = Worker(a.target, a.impl, a.root, p, a.disk_root)
    except Exception as e:  # noqa: BLE001
        doc["error"] = f"cannot create the filesystem: {type(e).__name__}: {e}"
        print(json.dumps(doc))
        return 1
    doc["class"] = f"{type(w.fs).__module__}.{type(w.fs).__qualname__}"
    try:
        w.create_root()
        for wid in ORDER:
            if wid in wanted:
                getattr(w, wid.lower())()
    except Exception as e:  # noqa: BLE001 - setup failure: report what ran
        doc["error"] = f"{type(e).__name__}: {e}"
        doc["traceback"] = traceback.format_exc(limit=8)
        log(f"ERROR {doc['error']}")
    finally:
        w.cleanup()
    doc["results"] = w.results
    doc["wall_s"] = round(time.monotonic() - t0, 3)
    doc["max_rss_mib"] = round(
        resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1
    )
    print(json.dumps(doc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
