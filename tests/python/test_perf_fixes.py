"""Regression tests for the benchmark findings (docs/BENCHMARKS.md):
large ``cat_file`` read into the result directly, batch sizes matching
fsspec, ``stats()`` reporting wire requests, rm/copy/get without a lookup
per path, and local ``cat_file`` of a FIFO.

The network parts are gated on the test-service variables
(``eval "$(scripts/test-services.sh env)"``).
"""

from __future__ import annotations

import io
import os
import threading

import fsspec
import fsspec.config
import pytest
from fsspec.asyn import _get_batch_size
from fsspec.implementations.local import LocalFileSystem as RefLocal

import fsfast
from fsfast import _core

MIB = 1 << 20


def pattern(n: int, seed: int = 0) -> bytes:
    block = bytes((i * 31 + seed) & 0xFF for i in range(4096))
    return (block * (n // 4096 + 1))[:n]


# ---------------------------------------------------------------------------
# cat_file of large results


@pytest.mark.parametrize("size", [16 * MIB - 1, 16 * MIB, 16 * MIB + 1, 40 * MIB + 123])
def test_large_cat_file_local(tmp, size):
    path = os.path.join(tmp, "big")
    data = pattern(size)
    with open(path, "wb") as f:
        f.write(data)
    fs = fsfast.LocalFileSystem()
    ref = RefLocal()
    assert fs.cat_file(path) == data
    for start, end in [(None, None), (5, None), (3, 20 * MIB), (-17 * MIB, None), (1, -1), (0, size + 9)]:
        assert fs.cat_file(path, start, end) == ref.cat_file(path, start, end), (start, end)


def test_large_cat_file_memory(isolated_memory_fs):
    fs = isolated_memory_fs
    data = pattern(33 * MIB + 7, seed=3)
    fs.pipe_file("/big", data)
    assert fs.cat_file("/big") == data
    assert fs.cat_file("/big", 10, 30 * MIB) == data[10 : 30 * MIB]
    assert fs.cat_file("/big", start=-20 * MIB) == data[-20 * MIB :]
    with pytest.raises(FileNotFoundError):
        fs.cat_file("/missing")


def test_large_cat_file_result_is_exact_bytes(tmp):
    path = os.path.join(tmp, "big")
    data = pattern(20 * MIB)
    with open(path, "wb") as f:
        f.write(data)
    out = fsfast.LocalFileSystem().cat_file(path)
    assert type(out) is bytes and len(out) == len(data) and out == data


# ---------------------------------------------------------------------------
# local FIFO


def _read_fifo(fs, fifo: str, payload: bytes):
    def feed():
        try:
            with open(fifo, "wb") as f:
                f.write(payload)
        except BrokenPipeError:
            pass  # the reader gave up (fsspec's local, see below)

    t = threading.Thread(target=feed, daemon=True)
    t.start()
    try:
        return fs.cat_file(fifo)
    finally:
        t.join(10)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs")
def test_local_cat_file_reads_fifo(tmp):
    """``cat_file`` of a FIFO returns what is written into it, as
    ``open(path, "rb").read()`` does (it used to return ``b""``: the stat
    size of a FIFO is 0).

    fsspec's own ``LocalFileSystem.cat_file`` (2025.x) raises
    ``io.UnsupportedOperation`` here instead, because its file object seeks
    to the end to learn the size; fsfast deliberately reads the content.
    """
    fifo = os.path.join(tmp, "pipe")
    os.mkfifo(fifo)
    payload = pattern(200_000, seed=9)
    assert _read_fifo(fsfast.LocalFileSystem(), fifo, payload) == payload
    try:
        ref = _read_fifo(RefLocal(), fifo, payload)
    except io.UnsupportedOperation:
        pass
    else:
        assert ref == payload


# ---------------------------------------------------------------------------
# batch sizes


def test_batch_size_defaults_follow_fsspec(monkeypatch):
    http = fsfast.HTTPFileSystem(skip_instance_cache=True)
    assert http._batch_size() == _get_batch_size(nofiles=True)
    assert http._batch_size(nofiles=False) == _get_batch_size(nofiles=False)
    assert http._batch_size(7) == 7
    monkeypatch.setitem(fsspec.config.conf, "nofiles_gather_batch_size", 5)
    monkeypatch.setitem(fsspec.config.conf, "gather_batch_size", 3)
    assert http._batch_size() == 5
    assert http._batch_size(nofiles=False) == 3
    inst = fsfast.HTTPFileSystem(skip_instance_cache=True, batch_size=11)
    assert inst._batch_size() == 11 and inst._batch_size(2) == 2
    # Classes whose reference is synchronous keep the backend's tuning.
    assert fsfast.MemoryFileSystem()._batch_size() is None
    assert fsfast.LocalFileSystem()._batch_size() is None


def test_batch_size_argument_reaches_the_bindings(memory_fs, monkeypatch):
    seen = []
    real = memory_fs._rfs

    class Spy:
        def __getattr__(self, name):
            attr = getattr(real, name)
            if not callable(attr):
                return attr

            def call(*a, **k):
                if "batch_size" in k:
                    seen.append((name, k["batch_size"]))
                return attr(*a, **k)

            return call

    monkeypatch.setattr(memory_fs, "_rfs", Spy())
    memory_fs.pipe({"/a": b"1", "/b": b"2"}, batch_size=3)
    memory_fs.cat(["/a", "/b"], batch_size=4)
    memory_fs.cat_ranges(["/a", "/b"], 0, 1, batch_size=5)
    memory_fs.copy(["/a"], ["/c"], batch_size=6)
    assert ("pipe_many", 3) in seen and ("cat_many", 4) in seen
    assert ("cat_ranges", 5) in seen and ("cp_files", 6) in seen


# ---------------------------------------------------------------------------
# stats


def test_stats_of_in_process_backend_count_calls(isolated_memory_fs):
    fs = isolated_memory_fs
    fs.reset_stats()
    fs.pipe_file("/s", b"12345")
    fs.cat_file("/s")
    s = fs.stats()
    assert s["source"] == "calls"
    assert s["requests"] == s["calls"]["requests"] >= 2
    assert s["bytes_read"] == 5


# ---------------------------------------------------------------------------
# rm / copy / get without one lookup per path


class NetLikeFS(fsfast.FsfastFileSystem):
    """The base class's rm/copy/get over the memory backend, configured like
    a network class (real directories, no cheap lookups)."""

    protocol = ("netlike",)
    _rust_protocol = "memory"
    _put_makes_parents = True
    root_marker = "/"


class Counting:
    def __init__(self, real):
        self.real = real
        self.lookups = 0

    def __getattr__(self, name):
        attr = getattr(self.real, name)
        if name in ("info", "info_many", "exists"):

            def counted(paths, *a, **k):
                self.lookups += len(paths) if name == "info_many" else 1
                return attr(paths, *a, **k)

            return counted
        return attr


def netlike_with_files(n: int) -> tuple[NetLikeFS, Counting, list[str]]:
    fs = NetLikeFS(global_store=False, skip_instance_cache=True)
    fs.pipe({f"/d/f{i:03}": b"x" for i in range(n)})
    spy = Counting(fs._rfs)
    fs._rfs = spy
    return fs, spy, [f"/d/f{i:03}" for i in range(n)]


def test_rm_list_does_not_look_paths_up():
    fs, spy, paths = netlike_with_files(50)
    fs.rm(paths)
    assert spy.lookups == 0
    assert fs.find("/d") == []


def test_rm_missing_path_still_raises():
    fs, spy, paths = netlike_with_files(3)
    with pytest.raises(FileNotFoundError):
        fs.rm([*paths, "/d/nope"])
    assert spy.lookups == 1  # only the failure is looked up


def test_rm_recursive_uses_the_listing():
    fs, spy, _ = netlike_with_files(30)
    fs.pipe_file("/d/sub/g", b"y")
    fs.rm("/d", recursive=True)
    assert not fs.exists("/d")
    spy.lookups = 0


def test_rm_directory_given_literally_falls_back_to_rmdir():
    fs, spy, paths = netlike_with_files(2)
    fs.makedirs("/empty", exist_ok=True)
    fs.rm(["/empty", paths[0]])
    assert spy.lookups <= 1  # only the directory (its delete as a file failed)
    assert not fs.exists("/empty") and not fs.exists(paths[0])


def test_copy_list_does_not_look_paths_up():
    fs, spy, paths = netlike_with_files(40)
    fs.copy(paths, [p.replace("/d/", "/e/") for p in paths])
    assert spy.lookups == 0
    assert fs.cat_file("/e/f007") == b"x"


def test_get_list_does_not_look_paths_up(tmp):
    fs, spy, paths = netlike_with_files(20)
    fs.get(paths, [os.path.join(tmp, os.path.basename(p)) for p in paths])
    assert spy.lookups == 0
    assert open(os.path.join(tmp, "f005"), "rb").read() == b"x"


def test_get_recursive_creates_directories(tmp):
    fs, spy, _ = netlike_with_files(3)
    fs.makedirs("/d/emptydir", exist_ok=True)
    fs.get("/d", tmp + "/out", recursive=True)
    assert sorted(os.listdir(tmp + "/out")) == ["emptydir", "f000", "f001", "f002"]
    assert os.path.isdir(tmp + "/out/emptydir")


# ---------------------------------------------------------------------------
# network: wire request counters and large cat_file

S3 = os.environ.get("FSFAST_TEST_S3_ENDPOINT")


@pytest.mark.skipif(not S3, reason="FSFAST_TEST_S3_ENDPOINT not set")
def test_s3_stats_count_wire_requests_and_large_cat_file():
    import uuid

    fs = fsfast.S3FileSystem(
        skip_instance_cache=True,
        key=os.environ["FSFAST_TEST_S3_KEY"],
        secret=os.environ["FSFAST_TEST_S3_SECRET"],
        endpoint_url=S3,
    )
    bucket = f"fsfast-perf-{uuid.uuid4().hex[:10]}"
    fs.mkdir(bucket)
    try:
        data = pattern(40 * MIB + 5, seed=1)
        fs.pipe_file(f"{bucket}/big", data)
        fs.reset_stats()
        assert fs.cat_file(f"{bucket}/big") == data
        s = fs.stats()
        assert s["source"] == "wire"
        # 40 MiB in parts of 8 MiB plus the first window and a HEAD: many
        # wire requests for one call.
        assert s["requests"] >= 5, s
        assert s["calls"]["requests"] <= 3, s["calls"]
        assert fs.cat_file(f"{bucket}/big", start=100, end=30 * MIB) == data[100 : 30 * MIB]
        fs.pipe({f"{bucket}/k{i}": b"v" for i in range(30)})
        fs.reset_stats()
        fs.rm([f"{bucket}/k{i}" for i in range(30)])
        s = fs.stats()
        assert s["requests"] <= 2, s  # one DeleteObjects, no HEAD per key
    finally:
        fs.rm(bucket, recursive=True)
