"""File-object semantics (``fs.open``): AbstractBufferedFile compatibility."""

from __future__ import annotations

import array
import gzip
import io
import os
import pickle

import pytest

import fsfast
from fsfast import FsfastFile

DATA = bytes(range(256)) * 64 + b"tail line\nlast"  # 16 KiB + a bit


@pytest.fixture(params=["local", "memory"])
def fs_and_path(request, tmp, memory_fs):
    if request.param == "local":
        fs = fsfast.LocalFileSystem()
        path = f"{tmp}/f.bin"
    else:
        fs = memory_fs
        path = "/files/f.bin"
    fs.pipe_file(path, DATA)
    return fs, path


@pytest.mark.parametrize(
    "cache_type", ["readahead", "none", "blockcache", "background", "bytes", "first", "all", "mmap"]
)
def test_read_semantics_every_cache_type(fs_and_path, cache_type):
    fs, path = fs_and_path
    with fs.open(path, "rb", cache_type=cache_type, block_size=4096) as f:
        assert isinstance(f, FsfastFile)
        assert isinstance(f, io.RawIOBase)
        assert f.size == len(DATA) == f.info()["size"]
        assert f.read(10) == DATA[:10]
        assert f.tell() == f.loc == 10
        assert f.seek(5, 1) == 15
        assert f.read(5) == DATA[15:20]
        assert f.seek(-4, 2) == len(DATA) - 4
        assert f.read() == DATA[-4:]
        assert f.read(10) == b""
        assert f.seek(len(DATA) + 100) == len(DATA) + 100
        assert f.read() == b""
        f.seek(0)
        assert f.read(None) == DATA
        f.seek(100)
        assert f.read(-1) == DATA[100:]
        f.seek(3)
        assert f.read(0) == b""
        assert f.tell() == 3
        with pytest.raises(ValueError, match="Seek before start of file"):
            f.seek(-1)
        with pytest.raises(ValueError, match="invalid whence"):
            f.seek(0, 3)
        assert f.cache.name in {"readahead", "none", "blockcache", "background", "all"}
        assert f.readable() and f.seekable() and not f.writable()
    assert f.closed
    assert not f.readable()


def test_readinto_any_buffer(fs_and_path):
    fs, path = fs_and_path
    with fs.open(path) as f:
        b = bytearray(1000)
        assert f.readinto(b) == 1000
        assert bytes(b) == DATA[:1000]
        mv = memoryview(bytearray(50))[10:30]
        assert f.readinto(mv) == 20
        assert bytes(mv) == DATA[1000:1020]
        arr = array.array("i", [0] * 4)  # typed buffers are raw bytes
        assert f.readinto(arr) == 16
        assert arr.tobytes() == DATA[1020:1036]
        f.seek(len(DATA) - 3)
        big = bytearray(10)
        assert f.readinto(big) == 3
        assert bytes(big[:3]) == DATA[-3:]
        assert f.readinto(bytearray(4)) == 0
        # Python's file objects and fsspec's raise TypeError (not BufferError)
        with pytest.raises(TypeError, match="read-write bytes-like object, not bytes"):
            f.readinto(b"read-only")
        with pytest.raises(TypeError):
            f.readinto(None)
    try:
        import numpy as np
    except ImportError:  # pragma: no cover
        return
    with fs.open(path) as f:
        out = np.zeros(64, dtype=np.uint8)
        assert f.readinto(out) == 64
        assert out.tobytes() == DATA[:64]


def test_lines_and_iteration(fs_and_path):
    fs, path = fs_and_path
    text = b"one\ntwo\n\nthree" + b"x" * 20000 + b"\nlast"
    fs.pipe_file(path, text)
    with fs.open(path) as f:
        assert f.readline() == b"one\n"
        assert f.readline(2) == b"tw"
        assert f.readline() == b"o\n"
        assert f.tell() == 8
        rest = list(f)
        assert rest == [b"\n", b"three" + b"x" * 20000 + b"\n", b"last"]
        assert f.readline() == b""
    with fs.open(path) as f:
        assert f.readlines() == text.splitlines(keepends=True)
        assert f.readlines() == []  # at EOF, like Python's files
    fs.pipe_file(path + ".cr", b"a\rb\r\nc")
    with fs.open(path + ".cr") as f:
        assert f.readlines() == [b"a\rb\r\n", b"c"]  # binary: b"\n" only
    fs.pipe_file(path + ".empty", b"")
    with fs.open(path + ".empty") as f:
        assert f.readlines() == [] and f.readlines(10) == []
        assert list(f) == [] and f.readline() == b""
    with fs.open(path) as f:
        assert f.readlines(5) == [b"one\n", b"two\n"]
        assert f.readuntil(b"ree") == b"\nthree"
        f.seek(0)
        assert f.read(2) == b"on"
        assert f.readline() == b"e\n"  # pending scan data stays consistent
        f.seek(1)
        assert f.read(3) == b"ne\n"
    with fs.open(path, "r") as t:  # text mode via TextIOWrapper
        assert t.readline() == "one\n"
        assert t.read(3) == "two"


def test_read_ranges_does_not_move(fs_and_path):
    fs, path = fs_and_path
    with fs.open(path) as f:
        f.seek(7)
        out = f.read_ranges([(0, 4), (100, 110), (len(DATA) - 2, len(DATA) + 50), (5, 5)])
        assert out == [DATA[:4], DATA[100:110], DATA[-2:], b""]
        assert f.tell() == 7


def test_write_modes(fs_and_path):
    fs, path = fs_and_path
    target = path + ".w"
    with fs.open(target, "wb") as f:
        assert f.writable() and not f.readable() and not f.seekable()
        assert f.write(b"abc") == 3
        assert f.write(bytearray(b"de")) == 2
        assert f.write(memoryview(b"xfgx")[1:3]) == 2
        assert f.tell() == f.loc == 7
        with pytest.raises(OSError):
            f.seek(0)
        with pytest.raises(ValueError, match="not in read mode"):
            f.read()
        with pytest.raises(ValueError, match="Info not available while writing"):
            f.info()
        f.flush()
    assert fs.cat_file(target) == b"abcdefg"
    with pytest.raises(ValueError):
        f.write(b"more")
    with fs.open(target, "ab") as f:
        f.write(b"hij")
    assert fs.cat_file(target) == b"abcdefghij"
    with pytest.raises(FileExistsError):
        fs.open(target, "xb")
    with fs.open(target + "x", "xb") as f:
        f.write(b"new")
    assert fs.cat_file(target + "x") == b"new"
    with pytest.raises(TypeError):
        with fs.open(target, "wb") as f:
            f.write("str is not bytes")
    with pytest.raises(NotImplementedError):
        FsfastFile(fs, target, "rw")


def test_large_writes_and_buffering(fs_and_path):
    fs, path = fs_and_path
    target = path + ".big"
    chunks = [os.urandom(n) for n in (1, 100, 70000, 5 << 20, 3, 9 << 20, 12)]
    with fs.open(target, "wb", block_size=1 << 20) as f:
        for c in chunks:
            assert f.write(c) == len(c)
    expected = b"".join(chunks)
    assert fs.cat_file(target) == expected
    with fs.open(target, "rb") as f:
        assert f.read() == expected
        f.seek(5 << 20)
        assert f.read(1 << 20) == expected[5 << 20 : 6 << 20]


def test_text_and_compression(fs_and_path):
    fs, path = fs_and_path
    target = path + ".txt.gz"
    with fs.open(target, "wt", compression="gzip", encoding="utf-8") as f:
        f.write("héllo\nwörld\n")
    assert gzip.decompress(fs.cat_file(target)).decode() == "héllo\nwörld\n"
    with fs.open(target, "rt", compression="infer", encoding="utf-8") as f:
        assert f.read() == "héllo\nwörld\n"
    assert fs.read_text(target, compression="gzip") == "héllo\nwörld\n"
    fs.write_text(path + ".t", "plain")
    assert fs.read_text(path + ".t") == "plain"


def test_closed_file_errors(fs_and_path):
    fs, path = fs_and_path
    f = fs.open(path)
    f.close()
    f.close()  # idempotent
    for call in (lambda: f.read(), lambda: f.seek(0), lambda: f.tell(), lambda: f.readline()):
        with pytest.raises(ValueError):
            call()
    with pytest.raises(ValueError):
        with f:
            pass


def test_pickle_read_file_reopens_at_position(fs_and_path):
    fs, path = fs_and_path
    with fs.open(path, cache_type="blockcache") as f:
        f.seek(1234)
        g = pickle.loads(pickle.dumps(f))
        assert isinstance(g, FsfastFile)
        assert g.tell() == 1234
        assert g.read(10) == DATA[1234:1244]
        assert g.path == f.path and g.size == f.size
        g.close()
    with fs.open(path + ".w", "wb") as w:
        with pytest.raises(RuntimeError):
            pickle.dumps(w)


def test_attributes_and_details(fs_and_path):
    fs, path = fs_and_path
    with fs.open(path, block_size=12345) as f:
        assert f.path == fs._strip_protocol(path)
        assert f.fs is fs
        assert f.mode == "rb"
        assert f.blocksize == 12345
        assert f.autocommit is True
        assert f.details["name"] == f.path
        assert f.full_name == fs.unstrip_protocol(f.path)
        assert str(f).startswith("<File-like object")
        assert hash(f) == hash(f)
    with fs.open(path, cache_options={"maxblocks": 2, "request_size": 1024}) as f:
        assert f.read(5) == DATA[:5]


def test_unclosed_writer_is_committed_on_gc(fs_and_path):
    fs, path = fs_and_path
    target = path + ".gc"
    f = fs.open(target, "wb")
    f.write(b"committed by __del__")
    del f
    import gc

    gc.collect()
    assert fs.cat_file(target) == b"committed by __del__"


def test_transactions(fs_and_path):
    fs, path = fs_and_path
    target = path + ".tx"
    with fs.transaction:
        with fs.open(target, "wb") as f:
            f.write(b"deferred")
        assert not fs.exists(target)
    assert fs.cat_file(target) == b"deferred"
    # leftovers of temp files must not remain
    parent = fs._parent(fs._strip_protocol(target))
    assert not [p for p in fs.ls(parent, detail=False) if ".fsfast-" in p]

    with pytest.raises(RuntimeError):
        with fs.transaction:
            with fs.open(target, "wb") as f:
                f.write(b"discarded")
            raise RuntimeError("boom")
    assert fs.cat_file(target) == b"deferred"
    assert not [p for p in fs.ls(parent, detail=False) if ".fsfast-" in p]

    fs.start_transaction()
    with fs.open(target, "wb") as f:
        f.write(b"manual")
    fs.end_transaction()
    assert fs.cat_file(target) == b"manual"


def test_local_extra_modes_fall_back_to_os_file(tmp):
    fs = fsfast.LocalFileSystem()
    p = f"{tmp}/rw"
    fs.pipe_file(p, b"0123456789")
    with fs.open(p, "r+b") as f:
        f.seek(2)
        f.write(b"ab")
    assert fs.cat_file(p) == b"01ab456789"


def test_reader_and_writer_objects_directly(tmp):
    rfs = fsfast.LocalFileSystem().rust
    p = f"{tmp}/direct"
    w = rfs.open_write(p, "wb", buffer_size=4)
    assert w.write(b"ab") == 2
    assert w.write(b"cdefgh") == 6
    assert w.bytes_written == 8
    w.close()
    assert w.closed
    r = rfs.open_read(p)
    assert r.size == 8
    assert r.read(3) == b"abc"
    assert r.info()["size"] == 8
    r.close()
    assert r.closed
    w = rfs.open_write(p + "2", "wb")
    w.write(b"never")
    w.abort()
    assert not os.path.exists(p + "2")


def test_line_iterator_shares_position_with_the_file(fs_and_path):
    fs, path = fs_and_path
    text = b"".join(b"line %d\n" % i for i in range(5000)) + b"no newline at end"
    fs.pipe_file(path, text)
    expected = text.splitlines(keepends=True)
    with fs.open(path, cache_type="none") as f:
        it = iter(f)
        assert next(it) == expected[0]
        assert f.tell() == len(expected[0])
        assert f.read(5) == expected[1][:5]  # mixes with buffered scan data
        assert next(it) == expected[1][5:]
        f.seek(len(expected[0]))
        assert f.readline() == expected[1]
        assert next(f) == expected[2]  # the file itself is an iterator too
        rest = list(it)
        assert rest == expected[3:]
        assert f.tell() == len(text)
        assert list(iter(f)) == []
    with fs.open(path) as f:
        assert [line for line in f] == expected
    with fs.open(path) as f:
        f.seek(len(text) - 3)
        assert f.readline() == b"end"
        f.seek(0)
        assert f.readline(3) == b"lin"
        assert f.readuntil(b" 1\n") == b"e 0\nline 1\n"


def test_threads_iterating_one_file_see_every_line_once(memory_fs):
    import threading

    n = 20000
    memory_fs.pipe_file("/lines", b"".join(b"%d\n" % i for i in range(n)))
    f = memory_fs.open("/lines")
    seen: list[bytes] = []
    lock = threading.Lock()

    def consume():
        local = [line for line in iter(f)]
        with lock:
            seen.extend(local)

    threads = [threading.Thread(target=consume) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    f.close()
    assert sorted(int(x) for x in seen) == list(range(n))
