"""Threads, fork and multiprocessing, pickling, signals."""

from __future__ import annotations

import multiprocessing as mp
import os
import pickle
import signal
import sys
import threading
import time

import pytest

import fsfast

# The runtime's worker threads exist by design; forking after it started is
# exactly what these tests exercise.
pytestmark = pytest.mark.filterwarnings("ignore:This process .* is multi-threaded:DeprecationWarning")


def test_eight_threads_hammer_one_filesystem(tmp):
    fs = fsfast.LocalFileSystem()
    mem = fsfast.MemoryFileSystem(global_store=False, skip_instance_cache=True)
    errors: list[BaseException] = []
    barrier = threading.Barrier(8)

    def worker(k: int) -> None:
        try:
            fs.makedirs(f"{tmp}/t{k}", exist_ok=True)
            barrier.wait()
            for i in range(150):
                for f, root in ((fs, tmp), (mem, "/mem")):
                    p = f"{root}/t{k}/f{i}"
                    data = f"{k}-{i}".encode() * (i % 7 + 1)
                    f.pipe_file(p, data)
                    assert f.cat_file(p) == data
                    assert f.info(p)["size"] == len(data)
                    with f.open(p) as fh:
                        assert fh.read() == data
                    if i % 10 == 0:
                        assert len(f.find(f"{root}/t{k}")) == i + 1
                        f.cat_ranges([p, p], [0, 1], [1, 2])
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(k,)) for k in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    assert not errors, errors[:3]
    assert len(fs.find(tmp)) == 8 * 150
    assert len(mem.find("/mem")) == 8 * 150


def test_threads_share_one_file_object(memory_fs):
    data = os.urandom(1 << 20)
    memory_fs.pipe_file("/shared", data)
    f = memory_fs.open("/shared", cache_type="blockcache", block_size=4096)
    errors: list[BaseException] = []

    def reader() -> None:
        try:
            for _ in range(200):
                chunk = f.read_ranges([(1000, 2000)])[0]
                assert chunk == data[1000:2000]
                f.seek(0)
                f.read(100)  # interleaved positional use: no crash, no corruption
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    f.close()
    assert not errors, errors[:3]


def _child_work(path: str, q) -> None:  # runs in a child process
    import fsfast as f2

    fs = f2.LocalFileSystem()
    fs.pipe_file(path + ".child", b"from child")
    q.put((os.getpid(), fs.cat_file(path), f2.runtime_info()["pid"]))


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork")
def test_os_fork_after_runtime_started(tmp):
    fs = fsfast.LocalFileSystem()
    p = f"{tmp}/forked"
    fs.pipe_file(p, b"parent data")  # runtime is running in the parent
    parent_rt = fsfast.runtime_info()["pid"]
    assert parent_rt == os.getpid()
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:  # child
        code = 1
        try:
            os.close(r)
            # The instance created before the fork keeps working.
            ok = fs.cat_file(p) == b"parent data"
            fs.pipe_file(p + ".c", b"child")
            info = fsfast.runtime_info()
            async_ok = True
            import asyncio

            async def go():
                return await fs._cat_file(p)

            async_ok = asyncio.run(go()) == b"parent data"
            os.write(w, f"{int(ok)}{int(async_ok)}{int(info['pid'] == os.getpid())}".encode())
            code = 0
        finally:
            os._exit(code)
    os.close(w)
    _, status = os.waitpid(pid, 0)
    out = os.read(r, 100).decode()
    os.close(r)
    assert os.WEXITSTATUS(status) == 0
    assert out == "111", out
    assert fs.cat_file(p + ".c") == b"child"
    # the parent's runtime is untouched
    assert fsfast.runtime_info()["pid"] == os.getpid()
    assert fs.cat_file(p) == b"parent data"


@pytest.mark.parametrize("method", ["fork", "spawn", "forkserver"])
def test_multiprocessing(tmp, method):
    if method not in mp.get_all_start_methods():
        pytest.skip(f"{method} unavailable")
    fs = fsfast.LocalFileSystem()
    p = f"{tmp}/mp-{method}"
    fs.pipe_file(p, b"shared")
    ctx = mp.get_context(method)
    q = ctx.Queue()
    procs = [ctx.Process(target=_child_work, args=(f"{p}", q)) for _ in range(3)]
    for pr in procs:
        pr.start()
    results = [q.get(timeout=60) for _ in procs]
    for pr in procs:
        pr.join(timeout=60)
        assert pr.exitcode == 0
    for child_pid, data, rt_pid in results:
        assert data == b"shared"
        assert rt_pid == child_pid  # each child built its own runtime
    assert fs.cat_file(p + ".child") == b"from child"


def _pool_cat(args):
    fs, path = args
    return fs.cat_file(path)


@pytest.mark.parametrize("method", ["fork", "spawn"])
def test_filesystem_pickled_to_pool(tmp, method):
    if method not in mp.get_all_start_methods():
        pytest.skip(f"{method} unavailable")
    fs = fsfast.LocalFileSystem()
    paths = []
    for i in range(6):
        fs.pipe_file(f"{tmp}/p{i}", str(i).encode())
        paths.append(f"{tmp}/p{i}")
    with mp.get_context(method).Pool(3) as pool:
        out = pool.map(_pool_cat, [(fs, p) for p in paths])
    assert out == [str(i).encode() for i in range(6)]


def test_pickle_round_trips(tmp, memory_fs):
    fs = fsfast.LocalFileSystem(auto_mkdir=True)
    fs2 = pickle.loads(pickle.dumps(fs))
    assert fs2 is fs  # instance cache, like fsspec
    assert fs2.auto_mkdir is True
    memory_fs.pipe_file("/pk", b"global")
    m2 = pickle.loads(pickle.dumps(memory_fs))
    assert m2.cat_file("/pk") == b"global"
    iso = fsfast.MemoryFileSystem(global_store=False, skip_instance_cache=True)
    iso.pipe({"/a/b": b"1", "/c": b"22"})
    iso.mkdir("/empty")
    iso2 = pickle.loads(pickle.dumps(iso))
    assert iso2 is not iso
    assert iso2.cat_file("/a/b") == b"1" and iso2.cat_file("/c") == b"22"
    assert iso2.isdir("/empty")
    iso2.pipe_file("/only-in-copy", b"x")
    assert not iso.exists("/only-in-copy")
    # Rust objects themselves pickle as a factory call
    r = pickle.loads(pickle.dumps(fs.rust))
    assert r.protocol == "file" and r.options["auto_mkdir"] is True
    # to_json / from_json
    from fsspec import AbstractFileSystem

    assert AbstractFileSystem.from_json(fs.to_json()) is fs


@pytest.mark.skipif(sys.platform == "win32" or not hasattr(os, "mkfifo"), reason="needs FIFOs and SIGINT")
def test_ctrl_c_interrupts_a_blocked_call(tmp):
    """A sync call blocked in Rust (opening a FIFO with no writer) is
    interrupted by SIGINT within the signal-check interval."""
    if threading.current_thread() is not threading.main_thread():
        pytest.skip("signals are delivered to the main thread")
    fifo = f"{tmp}/fifo"
    os.mkfifo(fifo)
    fs = fsfast.LocalFileSystem()
    timer = threading.Timer(0.3, lambda: os.kill(os.getpid(), signal.SIGINT))
    start = time.monotonic()
    timer.start()
    try:
        with pytest.raises(KeyboardInterrupt):
            fs.cat_file(fifo)
    finally:
        timer.cancel()
        # Unblock the abandoned blocking-pool thread.
        try:
            fd = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
            os.close(fd)
        except OSError:
            pass
    elapsed = time.monotonic() - start
    assert elapsed < 3.0, elapsed
    fs.pipe_file(f"{tmp}/after", b"still works")
    assert fs.cat_file(f"{tmp}/after") == b"still works"


def _fork_and_run(child, timeout: float = 20.0) -> int:
    """Run ``child()`` in a forked child (exit status 0 = success; a hang is
    killed by SIGALRM). Returns the exit status, or -signal if killed."""
    pid = os.fork()
    if pid == 0:  # child
        code = 1
        try:
            signal.alarm(int(timeout))
            code = 0 if child() else 3
        except BaseException:  # noqa: BLE001
            import traceback

            traceback.print_exc()
            code = 4
        finally:
            os._exit(code)
    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        return -os.WTERMSIG(status)
    return os.WEXITSTATUS(status)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork")
@pytest.mark.parametrize("cache_type", ["readahead", "background", "blockcache", "none", "all"])
@pytest.mark.parametrize("backend", ["local", "memory"])
def test_file_opened_before_fork_is_usable_in_the_child(tmp, backend, cache_type):
    """A file object opened (and read from, so prefetches are in flight)
    before ``os.fork()`` keeps working in the child - the DataLoader-style
    pattern. Its background fetches belong to the parent's runtime, which
    does not run in the child; waiting for them used to hang forever."""
    if backend == "local":
        fs = fsfast.LocalFileSystem()
        path = f"{tmp}/big"
    else:
        fs = fsfast.MemoryFileSystem(global_store=False, skip_instance_cache=True)
        path = "/big"
    data = os.urandom(48 << 20)
    fs.pipe_file(path, data)
    for _ in range(3):  # several tries: the race needs prefetches in flight
        f = fs.open(path, "rb", cache_type=cache_type, block_size=1 << 20)
        for _ in range(3):
            f.read(2 << 20)
        pos = f.tell()

        def child() -> bool:
            ok = f.read(8 << 20) == data[pos : pos + (8 << 20)]
            rest = data[pos + (8 << 20) :]
            nl = rest.find(b"\n", 0, 10)
            ok = ok and f.readline(10) == (rest[: nl + 1] if nl >= 0 else rest[:10])
            f.seek(1000)
            buf = bytearray(4096)
            ok = ok and f.readinto(buf) == 4096 and bytes(buf) == data[1000:5096]
            ok = ok and f.read_ranges([(5, 10)]) == [data[5:10]]
            f.seek(-3, 2)
            ok = ok and f.read() == data[-3:]
            f.close()
            return ok

        assert _fork_and_run(child) == 0
        # The parent's file is unaffected.
        assert f.read(1 << 20) == data[pos : pos + (1 << 20)]
        f.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork")
@pytest.mark.parametrize("backend", ["local", "memory"])
def test_reader_dropped_in_child_does_not_hang(tmp, backend):
    if backend == "local":
        fs = fsfast.LocalFileSystem()
        path = f"{tmp}/big"
    else:
        fs = fsfast.MemoryFileSystem(global_store=False, skip_instance_cache=True)
        path = "/big"
    fs.pipe_file(path, os.urandom(32 << 20))
    files = []
    for ct in ("readahead", "background"):
        f = fs.open(path, "rb", cache_type=ct, block_size=1 << 20)
        f.read(4 << 20)
        files.append(f)

    def child() -> bool:
        import gc

        files.clear()  # drop (and close via __del__) the pre-fork files
        gc.collect()
        return fs.cat_file(path, 0, 10) is not None

    assert _fork_and_run(child) == 0
    for f in files:
        f.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork")
@pytest.mark.parametrize("backend", ["local", "memory"])
def test_writer_opened_before_fork(tmp, backend):
    """A file being written by the parent belongs to the parent: in the
    child, writing raises instead of hanging, closing abandons it (no
    commit), and the parent's file is committed intact."""
    if backend == "local":
        fs = fsfast.LocalFileSystem()
        path = f"{tmp}/w"
    else:
        fs = fsfast.MemoryFileSystem()
        path = "/fork-writer"
    w = fs.open(path, "wb", block_size=1 << 20)
    w.write(b"p" * (3 << 20))  # data handed to the backend, maybe in flight

    def child() -> bool:
        try:
            w.write(b"child data")
        except OSError:
            pass
        else:
            return False
        w.close()  # abandons the parent's file in this process
        return w.closed

    assert _fork_and_run(child) == 0

    def child_gc() -> bool:
        import gc

        nonlocal w
        w = None  # garbage-collect the parent's writer in the child
        gc.collect()
        return True

    assert _fork_and_run(child_gc) == 0
    w.write(b"q")
    w.close()
    if backend == "local":
        with open(path, "rb") as fh:
            assert fh.read() == b"p" * (3 << 20) + b"q"
    else:
        assert fs.cat_file(path) == b"p" * (3 << 20) + b"q"


def _gil_probe(blocking_call, release) -> int:
    """Count how often another Python thread runs while ``blocking_call``
    blocks in Rust; ``release`` unblocks it from outside the interpreter
    (a subprocess), so a call holding the GIL cannot deadlock the test."""
    counter = [0]
    stop = threading.Event()

    def spin() -> None:
        while not stop.is_set():
            counter[0] += 1

    t = threading.Thread(target=spin)
    t.start()
    time.sleep(0.05)
    before = counter[0]
    proc = release()
    try:
        blocking_call()
    finally:
        after = counter[0]
        stop.set()
        t.join()
        proc.wait(timeout=30)
    return after - before


@pytest.mark.skipif(sys.platform == "win32" or not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_blocking_calls_release_the_gil(tmp, isolated_memory_fs):
    import subprocess

    fifo = f"{tmp}/gil-fifo"
    os.mkfifo(fifo)
    fs = fsfast.LocalFileSystem()

    def writer():  # opens the FIFO for writing after a delay, outside Python
        return subprocess.Popen(["sh", "-c", f"sleep 0.4; printf payload > '{fifo}'"])

    def reader():  # opens it for reading after a delay
        return subprocess.Popen(["sh", "-c", f"sleep 0.4; cat '{fifo}' > /dev/null"])

    calls = [
        ("cat_file", lambda: fs.cat_file(fifo), writer),
        ("open", lambda: fs.open(fifo, "rb").close(), writer),
        ("put_file", lambda: isolated_memory_fs.put_file(fifo, "/from-fifo"), writer),
        ("pipe_file", lambda: fs.pipe_file(fifo, b"x"), reader),
        ("get_file", lambda: isolated_memory_fs.get_file("/from-fifo", fifo), reader),
    ]
    for name, call, release in calls:
        ran = _gil_probe(call, release)
        # Holding the GIL for the ~0.4 s wait would leave the spinner at ~0
        # (it only gets the GIL at the end); released, it runs thousands of
        # times.
        assert ran > 1000, (name, ran)


def test_large_buffer_arguments_are_copied_without_the_gil(isolated_memory_fs):
    """``pipe_file`` of a large mutable buffer copies it once; the copy runs
    with the GIL released, so other threads are not stalled for its
    duration."""
    data = bytearray(os.urandom(1 << 20)) * 256  # 256 MiB
    t0 = time.perf_counter()
    bytes(data)  # a copy holding the GIL, for scale
    copy_time = time.perf_counter() - t0
    if copy_time < 0.02:
        pytest.skip(f"copy too fast to measure ({copy_time:.3f}s)")
    gaps = [0.0]
    stop = threading.Event()

    def spin() -> None:
        last = time.perf_counter()
        while not stop.is_set():
            now = time.perf_counter()
            gaps.append(now - last)
            last = now

    t = threading.Thread(target=spin)
    t.start()
    time.sleep(0.05)
    gaps.clear()
    isolated_memory_fs.pipe_file("/big", data)
    stop.set()
    t.join()
    assert isolated_memory_fs.size("/big") == len(data)
    assert max(gaps) < copy_time * 0.6, (max(gaps), copy_time)


def test_zarr_like_use_from_a_loop_in_another_thread(tmp):
    """zarr v3 drives an ``asynchronous=True`` filesystem from its own event
    loop thread: many concurrent ranged reads, ``_cat_ranges`` with missing
    keys, listing, deletes - on a filesystem created in the main thread."""
    import asyncio

    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    data = os.urandom(1 << 16)
    local = fsfast.LocalFileSystem(asynchronous=True, auto_mkdir=True, skip_instance_cache=True)
    mem = fsfast.MemoryFileSystem(asynchronous=True, global_store=False, skip_instance_cache=True)

    async def store_roundtrip(fs, root):
        await fs._pipe_file(f"{root}/zarr.json", b"{}")
        keys = [f"{root}/c/{i}" for i in range(150)]
        await asyncio.gather(*(fs._pipe_file(k, data[i : i + 500]) for i, k in enumerate(keys)))
        got = await asyncio.gather(*(fs._cat_file(k, start=10, end=20) for k in keys))
        assert got == [data[i + 10 : i + 20] for i in range(150)]
        out = await fs._cat_ranges(
            keys[:2] + [f"{root}/c/missing"], [0, 5, 0], [4, None, 1], on_error="return"
        )
        assert out[:2] == [data[0:4], data[6:501]]
        assert isinstance(out[2], FileNotFoundError)
        assert await fs._exists(f"{root}/zarr.json")
        assert len(await fs._ls(f"{root}/c", detail=False)) == 150
        await fs._rm(keys[:50])
        return sorted(await fs._find(root))

    try:
        for fs, root in ((local, f"{tmp}/store"), (mem, "/store")):
            names = asyncio.run_coroutine_threadsafe(store_roundtrip(fs, root), loop).result(60)
            assert len(names) == 101 and names[-1].endswith("zarr.json")
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(10)
        loop.close()
