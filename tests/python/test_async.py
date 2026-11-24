"""The async API: ``_``-prefixed coroutines awaiting Rust futures."""

from __future__ import annotations

import asyncio
import inspect
import os
import time

import pytest
from fsspec.asyn import async_methods

import fsfast

pytestmark = pytest.mark.asyncio


@pytest.fixture
def afs(memory_fs):
    return fsfast.MemoryFileSystem(asynchronous=True)


async def test_async_methods_are_coroutines(afs):
    for name in async_methods:
        m = getattr(afs, name)
        assert inspect.iscoroutinefunction(m) or inspect.isasyncgenfunction(m), name
    assert afs.async_impl and afs.asynchronous


async def test_basic_async_roundtrip(afs):
    await afs._pipe_file("/a/b", b"hello")
    await afs._pipe({"/a/c": b"c1", "/a/d/e": b"e1"})
    assert await afs._cat_file("/a/b") == b"hello"
    assert await afs._cat_file("/a/b", 1, 3) == b"el"
    assert await afs._cat_file("/a/b", -2) == b"lo"
    info = await afs._info("/a/b")
    assert info["size"] == 5 and info["type"] == "file"
    assert sorted(await afs._ls("/a", detail=False)) == ["/a/b", "/a/c", "/a/d"]
    assert await afs._find("/a") == ["/a/b", "/a/c", "/a/d/e"]
    assert set(await afs._find("/a", withdirs=True, detail=True)) == {
        "/a",
        "/a/b",
        "/a/c",
        "/a/d",
        "/a/d/e",
    }
    assert await afs._exists("/a/b") and not await afs._exists("/nope")
    assert await afs._isfile("/a/b") and await afs._isdir("/a/d")
    assert await afs._size("/a/b") == 5
    assert await afs._sizes(["/a/b", "/a/c"]) == [5, 2]
    assert await afs._du("/a") == 9
    assert await afs._cat("/a", recursive=True, on_error="omit") == {
        "/a/b": b"hello",
        "/a/c": b"c1",
        "/a/d/e": b"e1",
    }
    assert await afs._cat("/a/b") == b"hello"
    out = await afs._cat_ranges(["/a/b", "/a/c", "/nope"], [0, 1, 0], [2, None, 1])
    assert out[:2] == [b"he", b"1"]
    assert isinstance(out[2], FileNotFoundError)
    with pytest.raises(FileNotFoundError):
        await afs._cat_ranges(["/nope"], [0], [1], on_error="raise")
    assert await afs._glob("/a/*") == ["/a/b", "/a/c", "/a/d"]
    walked = [x async for x in afs._walk("/a")]
    assert walked[0][0] == "/a"
    assert await afs._expand_path("/a", recursive=True) == ["/a", "/a/b", "/a/c", "/a/d", "/a/d/e"]


async def test_async_mutations(afs, tmp):
    await afs._mkdir("/m/n")
    await afs._makedirs("/m/n", exist_ok=True)
    with pytest.raises(FileExistsError):
        await afs._makedirs("/m/n")
    await afs._pipe_file("/m/f", b"x")
    await afs._cp_file("/m/f", "/m/g")
    await afs._mv_file("/m/g", "/m/h")
    assert await afs._cat_file("/m/h") == b"x"
    await afs._copy("/m", "/copy", recursive=True)
    assert await afs._cat_file("/copy/f") == b"x"
    await afs._rm_file("/m/h")
    await afs._rm("/copy", recursive=True)
    assert not await afs._exists("/copy")
    await afs._put_file(__file__, "/up/test_async.py")
    assert (await afs._cat_file("/up/test_async.py")).startswith(b'"""The async API')
    await afs._get_file("/m/f", f"{tmp}/got")
    with open(f"{tmp}/got", "rb") as f:
        assert f.read() == b"x"
    await afs._put(tmp, "/putdir", recursive=True)
    assert await afs._cat_file("/putdir/got") == b"x"
    await afs._get("/putdir", f"{tmp}/back", recursive=True)
    with open(f"{tmp}/back/got", "rb") as f:
        assert f.read() == b"x"
    with pytest.raises(NotImplementedError):
        await afs._sign("/m/f")
    await afs._rmdir("/m/n")
    assert not await afs._exists("/m/n")
    m = await afs._modified("/m/f")
    assert m.tzinfo is not None


async def test_async_errors_map(afs):
    with pytest.raises(FileNotFoundError):
        await afs._info("/missing")
    with pytest.raises(FileNotFoundError):
        await afs._cat_file("/missing")


async def test_async_local(tmp):
    fs = fsfast.LocalFileSystem(asynchronous=True)
    await fs._pipe_file(f"{tmp}/x", b"abc")
    assert await fs._cat_file(f"{tmp}/x", 2, 1) == b"c"  # fsspec local: read(-1)
    with pytest.raises(ValueError):
        await fs._cat_file(f"{tmp}/x", 3, 1)
    info = await fs._info(f"{tmp}/x")
    assert info["mtime"] > 0
    assert (await fs._modified(f"{tmp}/x")).timestamp() == pytest.approx(info["mtime"])
    await fs._rm(tmp, recursive=True)
    assert not await fs._exists(tmp)


async def test_many_concurrent_tasks(afs):
    n = 200
    await asyncio.gather(*(afs._pipe_file(f"/c/{i}", str(i).encode()) for i in range(n)))
    got = await asyncio.gather(*(afs._cat_file(f"/c/{i}") for i in range(n)))
    assert got == [str(i).encode() for i in range(n)]


async def test_cancellation_drops_the_rust_future(afs):
    await afs._pipe_file("/x", b"1")
    task = asyncio.ensure_future(afs._cat_file("/x"))
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # the filesystem keeps working
    assert await afs._cat_file("/x") == b"1"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
async def test_cancelling_an_in_flight_call_is_prompt_and_never_blocks_the_loop(tmp):
    """A call really waiting in Rust (opening a FIFO without a writer) must
    neither block the event loop while pending nor delay cancellation."""
    fs = fsfast.LocalFileSystem(asynchronous=True, skip_instance_cache=True)
    fifo = f"{tmp}/fifo"
    os.mkfifo(fifo)
    try:
        task = asyncio.ensure_future(fs._cat_file(fifo))
        ticks, t0 = 0, time.monotonic()
        while time.monotonic() - t0 < 0.3:
            await asyncio.sleep(0.005)
            ticks += 1
        assert not task.done()
        assert ticks > 20, ticks  # the loop kept running
        t1 = time.monotonic()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert time.monotonic() - t1 < 0.5
        await fs._pipe_file(f"{tmp}/after", b"ok")
        assert await fs._cat_file(f"{tmp}/after") == b"ok"
    finally:
        # Release the blocking-pool thread still opening the FIFO.
        fd = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
        os.close(fd)


async def test_sync_api_from_async_context_works(memory_fs):
    # The sync methods never touch an event loop, so calling them from a
    # coroutine (blocking it briefly) is safe - unlike fsspec's sync() bridge.
    memory_fs.pipe_file("/s", b"ok")
    assert memory_fs.cat_file("/s") == b"ok"


async def test_resolved_and_pending_paths_behave_alike(afs, tmp):
    # memory completes inline (already-resolved future); local goes through
    # the runtime. Results, errors and cancellation look the same.
    local = fsfast.LocalFileSystem(asynchronous=True, skip_instance_cache=True)
    await afs._pipe_file("/same", b"data")
    await local._pipe_file(f"{tmp}/same", b"data")
    for fs, p in ((afs, "/same"), (local, f"{tmp}/same")):
        fut = fs._cat_file(p)
        assert inspect.isawaitable(fut)
        assert await fut == b"data"
        with pytest.raises(FileNotFoundError) as ei:
            await fs._cat_file(p + ".missing")
        assert ei.value.filename.endswith(".missing")
