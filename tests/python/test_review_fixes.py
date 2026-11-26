"""Regression tests for the wave-3 review findings fixed in fsfast-py and
python/fsfast:

* object stores: recursive copy/put/mv into a tree whose subdirectory
  listing is cached, and keyword destinations of the invalidating wrappers;
* a signal handler touching a file that is blocked in an operation on the
  same thread raises ``RuntimeError`` instead of deadlocking;
* HTTP per-call request options (``headers=`` ...) on every request;
* fsspec's ``blockcache::`` layer over fsfast files (``_fetch_range``);
* ``readlines(hint)``, negative relative seeks on memory files, local reads
  of a growing file, and deferred (transaction) writes on local/memory.

The object-store parts need the test services (``eval "$(scripts/
test-services.sh env)"``) and are skipped otherwise.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import textwrap
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import fsfast
import fsspec
import pytest
from fsspec.implementations.cached import CachingFileSystem
from fsspec.implementations.local import LocalFileSystem as RefLocal
from fsspec.implementations.memory import MemoryFileSystem as RefMemory

# ---------------------------------------------------------------------------
# object stores


def _s3():
    ep = os.environ.get("FSFAST_TEST_S3_ENDPOINT")
    if not ep:
        return None
    return fsfast.S3FileSystem(
        key=os.environ["FSFAST_TEST_S3_KEY"],
        secret=os.environ["FSFAST_TEST_S3_SECRET"],
        endpoint_url=ep,
        skip_instance_cache=True,
    )


def _gcs():
    ep = os.environ.get("FSFAST_TEST_GCS_ENDPOINT")
    if not ep:
        return None
    return fsfast.GCSFileSystem(
        endpoint_url=ep, token="anon", project="test", skip_instance_cache=True
    )


def _azure():
    conn = os.environ.get("FSFAST_TEST_AZURE_CONNECTION_STRING")
    if not conn:
        return None
    return fsfast.AzureBlobFileSystem(connection_string=conn, skip_instance_cache=True)


@pytest.fixture(params=["s3", "gcs", "azure"])
def objstore(request):
    fs = {"s3": _s3, "gcs": _gcs, "azure": _azure}[request.param]()
    if fs is None:
        pytest.skip(f"{request.param} test service not configured")
    bucket = f"fsfast-rev-{uuid.uuid4().hex[:12]}"
    fs.mkdir(bucket)
    try:
        yield fs, bucket
    finally:
        try:
            fs.rm(bucket, recursive=True)
        except FileNotFoundError:
            pass
        try:
            fs.rmdir(bucket)
        except (FileNotFoundError, OSError):
            pass


def test_recursive_copy_put_mv_refresh_cached_subdirectory_listings(objstore, tmp):
    fs, b = objstore
    for d in ("dst", "dst2", "dst3"):
        fs.pipe(f"{b}/{d}/sub/old", b"old")
    fs.pipe(f"{b}/src/sub/new", b"new")
    fs.pipe(f"{b}/srcm/sub/new", b"new")
    local = os.path.join(tmp, "src", "sub")
    os.makedirs(local)
    with open(os.path.join(local, "new"), "wb") as f:
        f.write(b"new")
    for d in ("dst", "dst2", "dst3", "srcm"):
        assert fs.ls(f"{b}/{d}/sub")  # cache the listings

    fs.copy(f"{b}/src/", f"{b}/dst/", recursive=True)
    fs.put(os.path.join(tmp, "src") + "/", f"{b}/dst2/", recursive=True)
    fs.mv(f"{b}/srcm/", f"{b}/dst3/", recursive=True)

    for d in ("dst", "dst2", "dst3"):
        assert fs.exists(f"{b}/{d}/sub/new"), d
        assert sorted(fs.ls(f"{b}/{d}/sub")) == [f"{b}/{d}/sub/new", f"{b}/{d}/sub/old"], d
    # The moved source's cached listing is gone too.
    assert not fs.exists(f"{b}/srcm/sub/new")


def test_invalidating_wrappers_accept_keyword_paths(objstore, tmp):
    fs, b = objstore
    fs.pipe(f"{b}/a", b"a")
    fs.pipe(f"{b}/d/sub/z", b"z")
    assert fs.ls(f"{b}/d/sub") == [f"{b}/d/sub/z"]

    fs.cp_file(path1=f"{b}/a", path2=f"{b}/kw")
    assert fs.cat(f"{b}/kw") == b"a"

    fs.cp_file(f"{b}/a", path2=f"{b}/d/sub/b")
    assert fs.exists(f"{b}/d/sub/b")
    assert sorted(fs.ls(f"{b}/d/sub")) == [f"{b}/d/sub/b", f"{b}/d/sub/z"]

    local = os.path.join(tmp, "l")
    with open(local, "wb") as f:
        f.write(b"l")
    fs.put_file(local, rpath=f"{b}/d/sub/l")
    assert fs.exists(f"{b}/d/sub/l")

    fs.pipe_file(path=f"{b}/d/sub/p", value=b"p")
    assert fs.exists(f"{b}/d/sub/p")
    fs.rm_file(path=f"{b}/d/sub/p")
    assert not fs.exists(f"{b}/d/sub/p")


def test_invalidating_wrappers_keep_their_signature():
    # Offline: passing the first path by keyword must not raise TypeError.
    import inspect

    from fsfast._objstore import ObjectStoreFileSystem

    for name in ("cp_file", "pipe_file", "rm_file", "put_file", "touch", "mkdir"):
        params = list(inspect.signature(getattr(ObjectStoreFileSystem, name)).parameters)
        assert params[0] == "self" and params[1] in ("path", "path1", "lpath"), (name, params)


# ---------------------------------------------------------------------------
# signal handlers re-entering a file blocked on the same thread


class _SlowHandler(BaseHTTPRequestHandler):
    body = b"x" * 1_000_000
    delay = 2.0

    def log_message(self, *args):
        pass

    def _head(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.body)))
        self.send_header("Accept-Ranges", "bytes")
        self.end_headers()

    def do_HEAD(self):
        self._head()

    def do_GET(self):
        import time

        time.sleep(self.delay)
        rng = self.headers.get("Range")
        data = self.body
        if rng:
            s, e = rng.split("=")[1].split("-")
            data = self.body[int(s) : int(e) + 1]
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {s}-{int(s) + len(data) - 1}/{len(self.body)}")
        else:
            self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except OSError:
            pass

    def do_PUT(self):
        import time

        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        time.sleep(self.delay)
        self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture
def slow_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _SlowHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/f"
    srv.shutdown()
    srv.server_close()


def _run_isolated(code: str, timeout: float = 30) -> str:
    """Run ``code`` in a child interpreter (a deadlock must not hang the
    test run): returns its stdout; fails on a timeout or error."""
    env = dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost")
    try:
        out = subprocess.run(
            [sys.executable, "-c", textwrap.dedent(code)],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        pytest.fail(f"deadlocked (killed after {timeout}s): {e.stdout!r} {e.stderr!r}")
    assert out.returncode == 0, out.stderr
    return out.stdout


@pytest.mark.parametrize("call", ["tell", "close", "seek", "read"])
def test_signal_handler_reentering_a_blocked_read_raises(slow_server, call):
    out = _run_isolated(
        f"""
        import signal, fsfast
        fs = fsfast.HTTPFileSystem(skip_instance_cache=True)
        f = fs.open({slow_server!r}, "rb", cache_type="none")
        seen = []
        def handler(signum, frame):
            try:
                f.{call}({"0" if call == "seek" else "1" if call == "read" else ""})
                seen.append("no error")
            except RuntimeError as e:
                seen.append(str(e))
                raise
        signal.signal(signal.SIGALRM, handler)
        signal.setitimer(signal.ITIMER_REAL, 0.3)
        try:
            f.read(1000)
            print("read finished")
        except RuntimeError as e:
            print("raised", e)
        print("handler", seen)
        # The file stays usable (and open) afterwards.
        print("closed", f.closed)
        print("tell", f.tell())
        print("data", len(f.read(10)))
        f.close()
        """
    )
    assert "raised reentrant call" in out, out
    assert "closed False" in out, out
    assert "data 10" in out, out


def test_signal_handler_reentering_a_blocked_write_raises(slow_server):
    out = _run_isolated(
        f"""
        import signal, fsfast
        fs = fsfast.HTTPFileSystem(skip_instance_cache=True)
        f = fs.open({slow_server!r}, "wb")
        f.write(b"abc")
        def handler(signum, frame):
            f.tell()
        signal.signal(signal.SIGALRM, handler)
        signal.setitimer(signal.ITIMER_REAL, 0.3)
        try:
            f.close()
            print("closed without error")
        except RuntimeError as e:
            print("raised", e)
        """
    )
    assert "raised reentrant call" in out, out


# ---------------------------------------------------------------------------
# HTTP per-call request options


class _TokenHandler(BaseHTTPRequestHandler):
    body = b"secret-data"

    def log_message(self, *args):
        pass

    def _ok(self) -> bool:
        if self.headers.get("X-Token") != "s3cret" and "tok=1" not in self.path:
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False
        return True

    def do_HEAD(self):
        if self._ok():
            self.send_response(200)
            self.send_header("Content-Length", str(len(self.body)))
            self.end_headers()

    def do_GET(self):
        if not self._ok():
            return
        rng = self.headers.get("Range")
        data = self.body
        if rng:
            s, e = rng.split("=")[1].split("-")
            e = int(e) if e else len(self.body) - 1
            data = self.body[int(s) : e + 1]
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {s}-{int(s) + len(data) - 1}/{len(self.body)}")
        else:
            self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def token_server(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _TokenHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/data.bin"
    srv.shutdown()
    srv.server_close()


H = {"headers": {"X-Token": "s3cret"}}


def test_http_per_call_headers_apply_to_every_request(token_server, tmp):
    fs = fsfast.HTTPFileSystem(skip_instance_cache=True)
    url = token_server
    with pytest.raises(PermissionError):
        fs.cat_file(url)  # the option is per call, not sticky
    assert fs.cat_file(url, **H) == b"secret-data"
    assert fs.cat_file(url, start=1, end=4, **H) == b"ecr"
    assert fs.cat(url, **H) == b"secret-data"
    assert fs.info(url, **H)["size"] == len(b"secret-data")
    assert fs.exists(url, **H)
    with fs.open(url, "rb", **H) as f:
        assert f.read() == b"secret-data"
    with fs.open(url, "rb", block_size=4, **H) as f:
        f.seek(7)
        assert f.read(2) == b"da"
    lp = os.path.join(tmp, "got")
    fs.get_file(url, lp, **H)
    with open(lp, "rb") as f:
        assert f.read() == b"secret-data"
    # Query parameters work the same way.
    assert fs.cat_file(url, params={"tok": "1"}) == b"secret-data"
    with pytest.raises(PermissionError):
        fs.cat_file(url)


async def _async_cat(url):
    fs = fsfast.HTTPFileSystem(asynchronous=True, skip_instance_cache=True)
    return await fs._cat_file(url, **H), (await fs._info(url, **H))["size"]


def test_http_per_call_headers_async(token_server):
    import asyncio

    data, size = asyncio.run(_async_cat(token_server))
    assert data == b"secret-data" and size == 11


def test_http_per_call_headers_match_fsspec(token_server):
    ref = fsspec.implementations.http.HTTPFileSystem(skip_instance_cache=True)
    assert ref.cat_file(token_server, **H) == b"secret-data"
    with ref.open(token_server, "rb", **H) as f:
        assert f.read() == b"secret-data"


# ---------------------------------------------------------------------------
# fsspec blockcache over fsfast files


@pytest.mark.parametrize("which", ["memory", "local"])
def test_blockcache_layer(which, tmp, isolated_memory_fs):
    data = b"0123456789" * 100_000
    if which == "memory":
        fs = isolated_memory_fs
        path = f"/bc-{uuid.uuid4().hex}"
    else:
        fs = fsfast.LocalFileSystem()
        path = os.path.join(tmp, "src.bin")
    fs.pipe(path, data)
    store = os.path.join(tmp, "cache")
    cfs = CachingFileSystem(fs=fs, cache_storage=store, skip_instance_cache=True)
    with cfs.open(path, "rb", block_size=4096) as f:
        f.seek(500_000)
        assert f.read(10) == b"0123456789"
        assert f.tell() == 500_010
        assert f.cache.blocks, "blocks were stored in the local cache"
        buf = bytearray(5)
        assert f.readinto(buf) == 5 and bytes(buf) == b"01234"
        assert f._fetch_range(3, 8) == data[3:8]
        assert f.tell() == 500_015
        f.seek(0)
        assert f.read() == data


def test_fetch_range_does_not_move_the_position(memory_fs):
    memory_fs.pipe("/x", b"abcdefgh")
    with memory_fs.open("/x", "rb") as f:
        f.read(2)
        assert f._fetch_range(4, 7) == b"efg"
        assert f._fetch_range(7, 100) == b"h"
        assert f._fetch_range(5, 5) == b""
        assert f.tell() == 2


# ---------------------------------------------------------------------------
# file-object parity


@pytest.mark.parametrize(
    "content,hint",
    [
        (b"\nxyz\nab\n", 1),
        (b"ab\ncd\nef\n", 3),
        (b"ab\ncd\nef\n", 2),
        (b"ab\ncd\nef\n", 4),
        (b"abc", 3),
    ],
)
def test_readlines_hint_matches_the_references(tmp, content, hint, isolated_memory_fs):
    p = os.path.join(tmp, "f")
    with open(p, "wb") as f:
        f.write(content)
    with RefLocal().open(p, "rb") as f:
        ref = f.readlines(hint), f.tell()
    with fsfast.LocalFileSystem().open(p, "rb") as f:
        assert (f.readlines(hint), f.tell()) == ref
    rm = RefMemory(skip_instance_cache=True)
    rm.store = {}
    rm.pipe("/f", content)
    with rm.open("/f", "rb") as f:
        mref = f.readlines(hint), f.tell()
    isolated_memory_fs.pipe("/f", content)
    with isolated_memory_fs.open("/f", "rb") as f:
        assert (f.readlines(hint), f.tell()) == mref


def test_memory_negative_relative_seek_clamps_like_bytesio(isolated_memory_fs):
    isolated_memory_fs.pipe("/x", b"abc")
    with isolated_memory_fs.open("/x", "rb") as f:
        assert f.seek(-82, 1) == 0
        f.read(2)
        assert f.seek(-1, 1) == 1
        assert f.seek(-10, 2) == 0
        assert f.seek(-1, 2) == 2
        with pytest.raises(ValueError):
            f.seek(-1, 0)
    ref = io.BytesIO(b"abc")
    assert ref.seek(-82, 1) == 0 and ref.seek(-10, 2) == 0


def test_remote_style_files_still_raise_on_negative_seek(local_fs, tmp):
    # Only memory files are BytesIO in the reference.
    p = os.path.join(tmp, "x")
    local_fs.pipe(p, b"abc")
    with local_fs.open(p, "rb") as f, pytest.raises((ValueError, OSError)):
        f.seek(-82, 1)


def test_local_read_follows_appended_data(tmp, local_fs):
    p = os.path.join(tmp, "log")
    with open(p, "wb") as w:
        w.write(b"line1\n")
    with local_fs.open(p, "rb") as f, RefLocal().open(p, "rb") as ref:
        assert f.read() == ref.read() == b"line1\n"
        with open(p, "ab") as w:
            w.write(b"line2\n")
        assert f.read() == ref.read() == b"line2\n"
        with open(p, "ab") as w:
            w.write(b"line3\nline4\n")
        assert f.readline() == ref.readline() == b"line3\n"
        assert f.readline() == ref.readline() == b"line4\n"
        assert f.readline() == ref.readline() == b""
        with open(p, "ab") as w:
            w.write(b"tail")
        assert f.seek(-2, 2) == ref.seek(-2, 2)
        assert f.read() == ref.read() == b"il"
        # A large append (read straight into the result).
        big = os.urandom(5 << 20)
        with open(p, "ab") as w:
            w.write(big)
        assert f.read() == big


@pytest.mark.parametrize("which", ["local", "memory"])
def test_transaction_writes_are_invisible_until_commit(which, tmp, isolated_memory_fs):
    if which == "local":
        fs = fsfast.LocalFileSystem()
        base = os.path.join(tmp, "tx")
        os.makedirs(base)
    else:
        fs = isolated_memory_fs
        base = "/tx"
        fs.mkdir(base)
    with fs.transaction:
        with fs.open(f"{base}/a", "wb") as f:
            f.write(b"data")
        assert fs.ls(base, detail=False) == []
        assert fs.find(base) == []
    assert fs.cat(f"{base}/a") == b"data"
    assert fs.ls(base, detail=False) == [f"{base}/a"]

    # A discarded transaction leaves nothing behind.
    class Boom(Exception):
        pass

    with pytest.raises(Boom), fs.transaction:
        with fs.open(f"{base}/b", "wb") as f:
            f.write(b"x")
        raise Boom
    assert fs.ls(base, detail=False) == [f"{base}/a"]


def test_local_transaction_temp_files_are_cleaned_up(tmp):
    import tempfile

    fs = fsfast.LocalFileSystem()
    before = {n for n in os.listdir(tempfile.gettempdir()) if n.startswith("fsfast-")}
    p = os.path.join(tmp, "c")
    with fs.transaction, fs.open(p, "wb") as f:
        f.write(b"1")
    with pytest.raises(ZeroDivisionError), fs.transaction:
        with fs.open(os.path.join(tmp, "d"), "wb") as f:
            f.write(b"2")
        raise ZeroDivisionError
    after = {n for n in os.listdir(tempfile.gettempdir()) if n.startswith("fsfast-")}
    assert after <= before
    assert sorted(os.listdir(tmp)) == ["c"]


def test_local_transaction_with_auto_mkdir_creates_the_target_parent(tmp):
    fs = fsfast.LocalFileSystem(auto_mkdir=True, skip_instance_cache=True)
    p = os.path.join(tmp, "new", "dir", "f")
    with fs.transaction, fs.open(p, "wb") as f:
        f.write(b"z")
    with open(p, "rb") as f:
        assert f.read() == b"z"
