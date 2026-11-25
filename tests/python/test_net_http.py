"""Parity of fsfast.HTTPFileSystem with fsspec's HTTPFileSystem (aiohttp)
against a local HTTP server started by the test (ranges, ETags, HTML
directory listings, PUT/POST uploads).

Runs without external services.
"""

from __future__ import annotations

import email.utils
import hashlib
import html
import os
import shutil
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import fsfast
import netparity as np_

pytest.importorskip("aiohttp")
from fsspec.implementations.http import HTTPFileSystem as RefHTTP  # noqa: E402


class Handler(BaseHTTPRequestHandler):
    """GET/HEAD with byte ranges and ETags, HTML listings for directories,
    PUT/POST writes, DELETE."""

    root = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # quiet
        pass

    def _local(self) -> str:
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        return os.path.join(self.root, path.lstrip("/"))

    def _send(self, code: int, body: bytes = b"", headers: dict | None = None, head: bool = False) -> None:
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def _get(self, head: bool) -> None:
        p = self._local()
        if os.path.isdir(p):
            if not self.path.split("?")[0].endswith("/"):
                self._send(301, headers={"Location": self.path + "/"}, head=head)
                return
            links = []
            for name in sorted(os.listdir(p)):
                href = urllib.parse.quote(name) + ("/" if os.path.isdir(os.path.join(p, name)) else "")
                links.append(f'<a href="{href}">{html.escape(name)}</a>')
            body = ("<html><body>" + "<br>".join(links) + "</body></html>").encode()
            self._send(200, body, {"Content-Type": "text/html; charset=utf-8"}, head)
            return
        if not os.path.isfile(p):
            self._send(404, b"not found", head=head)
            return
        with open(p, "rb") as f:
            data = f.read()
        st = os.stat(p)
        headers = {
            "Content-Type": "application/octet-stream",
            "ETag": '"' + hashlib.md5(data).hexdigest() + '"',
            "Last-Modified": email.utils.formatdate(st.st_mtime, usegmt=True),
            "Accept-Ranges": "bytes",
        }
        rng = self.headers.get("Range")
        if rng and rng.startswith("bytes="):
            spec = rng[6:]
            a, _, b = spec.partition("-")
            size = len(data)
            if a == "":
                start, end = max(size - int(b), 0), size - 1
            else:
                start = int(a)
                end = min(int(b), size - 1) if b else size - 1
            if start >= size:
                self._send(416, b"", {"Content-Range": f"bytes */{size}"}, head)
                return
            headers["Content-Range"] = f"bytes {start}-{end}/{size}"
            self._send(206, data[start : end + 1], headers, head)
            return
        self._send(200, data, headers, head)

    def do_GET(self):  # noqa: N802
        self._get(False)

    def do_HEAD(self):  # noqa: N802
        self._get(True)

    def _write(self) -> None:
        n = int(self.headers.get("Content-Length") or 0)
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks = []
            while True:
                size = int(self.rfile.readline().strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.readline()
            data = b"".join(chunks)
        else:
            data = self.rfile.read(n)
        p = self._local()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        self._send(201)

    def do_PUT(self):  # noqa: N802
        self._write()

    def do_POST(self):  # noqa: N802
        self._write()


@pytest.fixture(scope="module")
def server():
    root = tempfile.mkdtemp(prefix="fsfast-http-")
    handler = type("H", (Handler,), {"root": root})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", root
    httpd.shutdown()
    shutil.rmtree(root, ignore_errors=True)


def backend(base: str) -> np_.Backend:
    def new_root(fs):
        return f"{base}/{np_.unique('par')}"

    return np_.Backend(
        name="http",
        make_ref=lambda: RefHTTP(skip_instance_cache=True),
        make_fast=lambda: fsfast.HTTPFileSystem(skip_instance_cache=True),
        new_root=new_root,
        cleanup=lambda fs, root: None,
        known={
            # aiohttp raises ClientResponseError for 416; fsfast returns b""
            # for a range starting past EOF.
            "cat_file past eof": "fsspec http raises ClientResponseError",
            "cat_file open end": "fsspec http raises ClientResponseError (416)",
            # fsspec http cannot write files (NotImplementedError); fsfast
            # PUTs them.
            "open wb": "fsspec http: NotImplementedError",
            "open w text": "fsspec http: NotImplementedError",
            "open xb existing": "fsspec http: NotImplementedError",
            "open ab": "fsspec http: NotImplementedError",
            "transaction": "fsspec http: NotImplementedError",
            # fsspec http has no modified(); fsfast reads Last-Modified.
            "modified type": "fsspec http: NotImplementedError",
            "modified missing": "fsspec http: NotImplementedError",
            # Both fail to download a directory page recursively (fsspec:
            # IsADirectoryError, fsfast: FileNotFoundError for the missing
            # local parent).
            "get recursive": "both raise, different OSError subclasses",
        },
        volatile=frozenset({"Last-Modified"}),
        # fsspec's http listing comes from a set: arbitrary order.
        unordered=frozenset({"ls detail", "ls subdir", "walk", "ls file", "ls slash"}),
        ignore_tree=frozenset({"/w/written.bin", "/w/text.txt", "/w/tx.bin"}),
    )


@pytest.mark.parametrize(
    "path",
    ["http://host/a/b", "https://host/a/b/", "http://host", "http://host/x?y=1#z", "http://host/"],
)
def test_paths(path):
    ref = RefHTTP(skip_instance_cache=True)
    fast = fsfast.HTTPFileSystem(skip_instance_cache=True)
    assert fast._strip_protocol(path) == ref._strip_protocol(path)
    assert fast._get_kwargs_from_urls(path) == ref._get_kwargs_from_urls(path)
    assert fast._parent(path) == ref._parent(path)
    assert fast.unstrip_protocol(path) == ref.unstrip_protocol(path)
    assert fast.ukey(path) == ref.ukey(path)
    assert fast.protocol == ref.protocol
    assert fast.fsid == ref.fsid


def test_reads(server):
    base, _ = server
    b = backend(base)
    ref, fast = b.make_ref(), b.make_fast()
    root = b.new_root(ref)
    np_.build_tree(ref, root, False)
    problems = np_.check_reads(b, ref, fast, root)
    assert not problems, "\n".join(problems)
    for label, op in [
        ("glob query", lambda fs: fs.glob(f"{root}/a.txt?x=1")),
        ("info listing", lambda fs: {k: v for k, v in fs.info(f"{root}/d/").items() if k != "Last-Modified"}),
        ("ls slash", lambda fs: fs.ls(f"{root}/d/")),
        ("exists 404", lambda fs: fs.exists(f"{base}/nope/nope")),
    ]:
        msg = np_.compare(b, label, np_.run(lambda: op(ref)), np_.run(lambda: op(fast)))
        assert msg is None, msg


def test_writes(server):
    base, _ = server
    b = backend(base)
    ref, fast = b.make_ref(), b.make_fast()
    problems = np_.check_writes(b, ref, fast, b.new_root(ref), b.new_root(ref))
    assert not problems, "\n".join(problems)


def test_write_file_extension(server):
    base, local = server
    fast = fsfast.HTTPFileSystem(skip_instance_cache=True)
    url = f"{base}/{np_.unique('w')}/f.bin"
    with fast.open(url, "wb") as f:
        f.write(b"x" * 100_000)
    assert fast.cat(url) == b"x" * 100_000
    fast.pipe_file(url, b"posted", method="post")
    assert fast.cat(url) == b"posted"


def test_fsspec_integration(server):
    base, _ = server
    url = f"{base}/{np_.unique('i')}/x.bin"
    fsfast.HTTPFileSystem(skip_instance_cache=True).pipe_file(url, b"via fsspec")
    np_.check_fsspec_integration("http", {}, url, b"via fsspec", fsfast.HTTPFileSystem)


def test_async_and_pickle(server):
    base, _ = server
    import asyncio

    url = f"{base}/{np_.unique('a')}/x.bin"
    fast = fsfast.HTTPFileSystem(skip_instance_cache=True)
    fast.pipe_file(url, b"async data")

    async def main():
        fs = fsfast.HTTPFileSystem(asynchronous=True, skip_instance_cache=True)
        assert await fs._cat_file(url) == b"async data"
        assert await fs._cat_file(url, start=6, end=10) == b"data"
        assert (await fs._info(url))["size"] == 10
        assert await fs._exists(url)
        assert await fs._cat_ranges([url, url], [0, 6], [2, 10]) == [b"as", b"data"]

    asyncio.run(main())
    np_.check_pickle(fast, url, b"async data")


def test_get_client_rejected():
    with pytest.raises(NotImplementedError):
        fsfast.HTTPFileSystem(get_client=lambda **kw: None, skip_instance_cache=True)
