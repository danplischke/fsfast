"""``FsfastFile``: an ``io.RawIOBase`` over a Rust reader or writer.

The object is compatible with fsspec's ``AbstractBufferedFile`` (attributes
``path``, ``fs``, ``mode``, ``size``, ``loc``, ``blocksize``, ``details``,
``autocommit``, ``kwargs``, ``cache``; methods ``commit``/``discard``,
``info``, ``readuntil``, ...), but no data passes through Python caches or
buffers:

* reads go through ``fsfast._core.RustReader`` (the engine's ``FileReader``
  with fsspec's cache types: adaptive readahead by default, block LRU, whole
  file, none; large reads become parallel ranged requests);
* ``readinto`` fills the caller's buffer directly with the GIL released;
* ``readline``/iteration scan for newlines in Rust;
* writes go to ``fsfast._core.RustWriter``, which batches small writes into
  one buffer and passes large ones straight through.
"""

from __future__ import annotations

import io
import os
import tempfile
from errno import ESPIPE
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from fsspec.spec import reopen
from fsspec.utils import tokenize

if TYPE_CHECKING:  # pragma: no cover
    from ._base import FsfastFileSystem

__all__ = ["FsfastFile"]

_WRITE_MODES = frozenset({"wb", "ab", "xb"})


class _WritePickleError(ValueError, RuntimeError):
    """Pickling a write-mode file: fsspec's local files raise ``ValueError``,
    s3fs's and fsspec's buffered files ``RuntimeError``; this is both."""


class FsfastFile(io.RawIOBase):
    """A file of an fsfast filesystem, opened in mode ``rb``, ``wb``, ``ab``
    or ``xb``.

    Parameters match fsspec's ``AbstractBufferedFile``: ``block_size`` is the
    cache block size for block caches (``cache_type="blockcache"``,
    ``"background"``, ``"mmap"``) and the part-size hint for writes;
    ``cache_type`` takes fsspec's names; ``cache_options`` accepts
    ``maxblocks`` plus fsfast's ``request_size`` and ``concurrency``;
    ``autocommit=False`` defers a ``wb`` write until :meth:`commit`.
    """

    DEFAULT_BLOCK_SIZE = 5 * 2**20
    _details: dict[str, Any] | None = None
    #: An fsspec cache object installed by a caching layer (fsspec's
    #: ``blockcache::`` sets ``f.cache = MMapCache(..., f._fetch_range,
    #: ...)``); when set, ``read``/``readinto`` are served through it.
    _py_cache: Any = None

    def __init__(
        self,
        fs: FsfastFileSystem,
        path: str,
        mode: str = "rb",
        block_size: int | str | None = "default",
        autocommit: bool = True,
        cache_type: str = "readahead",
        cache_options: dict[str, Any] | None = None,
        size: int | None = None,
        version: str | None = None,
        extra: dict[str, Any] | None = None,
        rust_fs: Any = None,
        **kwargs: Any,
    ) -> None:
        self.path = path
        self.fs = fs
        self.mode = mode
        if mode not in {"rb"} | _WRITE_MODES:
            raise NotImplementedError("File mode not supported")
        explicit_block = block_size if isinstance(block_size, int) and block_size > 0 else None
        self.blocksize = explicit_block or self.DEFAULT_BLOCK_SIZE
        self.autocommit = autocommit
        self.cache_type = cache_type
        self.cache_options = dict(cache_options or {})
        if "trim" in kwargs:  # fsspec's deprecated spelling of a cache option
            self.cache_options["trim"] = kwargs.pop("trim")
        self.kwargs = kwargs
        self._closed = False
        self._reader: Any = None
        self._writer: Any = None
        self._target = path
        self._committed = False
        self._discarded = False
        #: Deferred write of a backend without rename (object stores): the
        #: data is spooled locally and uploaded by :meth:`commit`.
        self._spool: Any = None
        self._extra = extra
        #: Position of the first byte this handle writes (see
        #: ``FsfastFileSystem._append_tell_from_end``).
        self._tell_base = 0
        # ``rust_fs``: a client carrying per-call request options (http).
        rfs = fs._rfs if rust_fs is None else rust_fs
        if mode == "rb":
            self._reader = rfs.open_read(
                path,
                cache_type=cache_type,
                block_size=explicit_block,
                max_blocks=self.cache_options.get("maxblocks"),
                request_size=self.cache_options.get("request_size"),
                concurrency=self.cache_options.get("concurrency"),
                version=version,
                extra=extra,
            )
            self.size = self._reader.size
        else:
            if not autocommit and mode == "wb":
                if fs._spool_transactions:
                    self._spool = tempfile.NamedTemporaryFile(prefix="fsfast-", delete=False)
                    return
                # Deferred write: a hidden sibling renamed into place at commit.
                self._target = fs._transaction_temp_path(path)
            if mode == "ab" and fs._append_tell_from_end:
                try:
                    found = rfs.info(path)
                except FileNotFoundError:
                    found = None
                if found is not None and found["type"] == "file":
                    self._tell_base = found["size"]
            self._writer = rfs.open_write(
                self._target, mode, block_size=explicit_block, extra=extra
            )

    # ------------------------------------------------------------------
    # fsspec attributes

    @property
    def closed(self) -> bool:  # type: ignore[override]
        return getattr(self, "_closed", True)

    @closed.setter
    def closed(self, value: bool) -> None:
        # fsspec's caching layers set ``f.closed = True`` after closing a
        # file (``AbstractBufferedFile.closed`` is a plain attribute).
        self._closed = bool(value)

    @property
    def loc(self) -> int:
        """Current position (bytes written, in write mode)."""
        return self.tell()

    @loc.setter
    def loc(self, value: int) -> None:
        self.seek(value)

    @property
    def details(self) -> dict[str, Any]:
        """The file's info dict (observed at open in read mode)."""
        if self._details is None:
            if self._reader is not None:
                self._details = self._reader.info()
            else:
                self._details = self.fs.info(self.path)
        return self._details

    @details.setter
    def details(self, value: dict[str, Any]) -> None:
        self._details = value
        self.size = value["size"]

    @property
    def full_name(self) -> str:
        return self.fs.unstrip_protocol(self.path)

    @property
    def name(self) -> str:
        return self.path

    @property
    def cache(self) -> Any:
        """Description of the read cache (fsspec files expose their cache
        object; here the caching happens in Rust), or the fsspec cache
        object a caching layer installed."""
        if self._py_cache is not None:
            return self._py_cache
        if self._reader is None:
            return None
        return SimpleNamespace(name=self._reader.cache_mode, blocksize=self.blocksize)

    @cache.setter
    def cache(self, value: Any) -> None:
        # fsspec's CachingFileSystem (``blockcache::``) replaces the file's
        # cache with an MMapCache over ``_fetch_range``: honour it, so its
        # local block store is used (AbstractBufferedFile reads through
        # ``self.cache._fetch``).
        self._py_cache = value

    def _fetch_range(self, start: int, end: int) -> bytes:
        """Bytes ``[start, end)`` from the backend, without moving the
        position (fsspec's ``AbstractBufferedFile._fetch_range``, the
        fetcher fsspec caches are built on)."""
        reader = self._check_read()
        if end <= start:
            return b""
        return reader.read_ranges([(start, end)])[0]

    def _cached_read(self, length: int) -> bytes:
        """``read`` through an installed fsspec cache (see ``cache``)."""
        reader = self._reader
        loc = reader.tell()
        end = self.size if length < 0 else min(self.size, loc + length)
        if end <= loc:
            return b""
        out = self._py_cache._fetch(loc, end)
        reader.seek(loc + len(out))
        return out

    def url(self, **kwargs: Any) -> str:
        """HTTP(S) URL of this file (s3fs/gcsfs files offer this), from the
        filesystem's ``url``."""
        url = getattr(self.fs, "url", None)
        if url is None:
            raise NotImplementedError(f"{type(self.fs).__name__} has no url()")
        return url(self.path, **kwargs)

    def info(self) -> dict[str, Any]:
        """File information about this path."""
        if self.readable():
            return self.details
        raise ValueError("Info not available while writing")

    # ------------------------------------------------------------------
    # capability queries (fsspec semantics: False once closed)

    def readable(self) -> bool:
        return "r" in self.mode and not self.closed

    def writable(self) -> bool:
        return self.mode in _WRITE_MODES and not self.closed

    def seekable(self) -> bool:
        return self.readable()

    # ------------------------------------------------------------------
    # reading

    def _check_read(self) -> Any:
        if self.mode != "rb":
            raise ValueError("File not in read mode")
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return self._reader

    def read(self, length: int | None = -1) -> bytes:  # type: ignore[override]
        """Read ``length`` bytes (all remaining if ``-1`` or ``None``; other
        negative values read everything too, or raise ``ValueError`` where
        the reference implementation's files are CPython file objects)."""
        length = -1 if length is None else int(length)
        reader = self._check_read()
        if length == 0:
            return b""
        if length < -1 and self.fs._strict_negative_read:
            raise ValueError("read length must be non-negative or -1")
        if self._py_cache is not None:
            return self._cached_read(length)
        return reader.read(length if length > 0 else None)

    def read1(self, size: int = -1) -> bytes:
        """Same as :meth:`read`: the Rust reader has no partial-read mode."""
        return self.read(size if size >= 0 else -1)

    def readall(self) -> bytes:
        """Read to the end of the file."""
        return self.read(-1)

    def readinto(self, b: Any) -> int:  # type: ignore[override]
        """Fill ``b`` (any writable buffer) without intermediate copies."""
        reader = self._check_read()
        if self._py_cache is not None:
            view = memoryview(b).cast("B")
            data = self._cached_read(len(view))
            view[: len(data)] = data
            return len(data)
        return reader.readinto(b)

    def readinto1(self, b: Any) -> int:  # type: ignore[override]
        """Same as :meth:`readinto`."""
        return self.readinto(b)

    def readline(self, size: int | None = -1) -> bytes:  # type: ignore[override]
        reader = self._check_read()
        size = -1 if size is None else int(size)
        if size == 0:
            return b""
        return reader.readline(size if size > 0 else None)

    def readuntil(self, char: bytes = b"\n", blocks: int | None = None) -> bytes:
        """Read up to and including the first occurrence of ``char``."""
        return self._check_read().readuntil(char)

    def readlines(self, hint: int | None = -1) -> list[bytes]:  # type: ignore[override]
        reader = self._check_read()
        if hint is None or hint <= 0:
            data = reader.read(None)
            if not data:
                # Like Python's file objects (the reference for local and
                # memory files): no lines at EOF, not ``[b""]``.
                return []
            # Binary lines end at b"\n" only (bytes.splitlines would also
            # split at b"\r").
            lines = data.split(b"\n")
            out = [line + b"\n" for line in lines[:-1]]
            return out if data.endswith(b"\n") else out + [lines[-1]]
        out, total = [], 0
        # io.IOBase (CPython files, fsspec's local files) stops once the
        # total *exceeds* the hint; BytesIO (fsspec's memory files) once it
        # reaches it.
        stop_at = hint if self.fs._readlines_bytesio else hint + 1
        while total < stop_at:
            line = reader.readline(None)
            if not line:
                break
            out.append(line)
            total += len(line)
        return out

    def __iter__(self) -> Any:
        # A Rust iterator sharing this file's position: no Python frame per
        # line (``next(f)`` on the file itself works too).
        return self._check_read().lines()

    def __next__(self) -> bytes:
        line = self._check_read().readline(None)
        if line:
            return line
        raise StopIteration

    def read_ranges(self, ranges: list[tuple[int, int]]) -> list[bytes]:
        """Read several ``(start, end)`` ranges without moving the position
        (coalesced and fetched concurrently)."""
        return self._check_read().read_ranges(ranges)

    def seek(self, loc: int, whence: int = 0) -> int:
        """Set the position (``whence`` 0: start, 1: current, 2: end)."""
        loc = int(loc)
        if self.mode != "rb":
            # Even a no-op seek raises: callers such as zipfile probe
            # ``seek(tell())`` to decide whether they may later seek back,
            # and fsfast write handles cannot (they stream).
            raise OSError(ESPIPE, "Seek only available in read mode")
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if loc < 0 and whence in (1, 2) and self.fs._seek_clamps_negative:
            # BytesIO (fsspec's memory files) clamps a relative seek before
            # the start to 0; only a negative absolute position raises.
            base = self._reader.tell() if whence == 1 else self._reader.seek(0, 2)
            if base + loc < 0:
                return self._reader.seek(0, 0)
            return self._reader.seek(base + loc, 0)
        return self._reader.seek(loc, whence)

    def tell(self) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if self._reader is not None:
            return self._reader.tell()
        if self._spool is not None:
            return self._spool.tell()
        return self._tell_base + self._writer.bytes_written

    # ------------------------------------------------------------------
    # writing

    def write(self, data: Any) -> int:  # type: ignore[override]
        """Write a bytes-like object; returns the number of bytes written."""
        if not self.writable():
            if self.closed:
                raise ValueError("I/O operation on closed file.")
            raise ValueError("File not in write mode")
        if self._spool is not None:
            return self._spool.write(data)
        return self._writer.write(data)

    def flush(self, force: bool = False) -> None:
        """Push buffered data to the backend (a no-op in read mode)."""
        if self.closed:
            raise ValueError("Flush on closed file")
        if self._writer is not None:
            self._writer.flush()

    def close(self) -> None:
        """Close the file; in write mode this commits the data (unless the
        write is deferred to a transaction)."""
        if getattr(self, "_unclosable", False) or self.closed:
            return
        reentrant = False
        try:
            if self._reader is not None:
                self._reader.close()
            elif self._spool is not None:
                pass  # uploaded by commit()
            elif self._writer is not None:
                self._writer.close()
                if self.autocommit or self._target == self.path:
                    self._invalidate()
        except RuntimeError as e:
            # Called by a signal handler while this thread is inside an
            # operation on the file: nothing was closed (CPython's buffered
            # files raise the same and stay open).
            reentrant = str(e).startswith("reentrant call")
            raise
        finally:
            if not reentrant:
                self._closed = True

    def _invalidate(self) -> None:
        fs = self.fs
        if fs is not None:
            fs.invalidate_cache(self.path)
            fs.invalidate_cache(fs._parent(self.path))

    def commit(self) -> None:
        """Make a deferred (``autocommit=False``) write visible."""
        if self._discarded:
            # s3fs (whose discard drops the upload) raises here too; the
            # data is gone, so committing must not report success.
            raise ValueError("Cannot commit a file that was discarded")
        if self._spool is not None:
            if self._committed:
                return
            self._closed = True
            spool, self._spool = self._spool, None
            try:
                spool.close()
                self.fs._rfs.put_file(spool.name, self.path, "overwrite")
            finally:
                os.unlink(spool.name)
            self._committed = True
            self._invalidate()
            return
        if self._target == self.path or self._committed:
            return
        if not self.closed:
            self.close()
        self.fs._rfs.mv_file(self._target, self.path)
        self._committed = True
        self._invalidate()

    def discard(self) -> None:
        """Throw away a deferred write."""
        if not self._committed and (self._spool is not None or self._target != self.path):
            self._discarded = True
        if self._spool is not None:
            self._spool.close()
            os.unlink(self._spool.name)
            self._spool = None
            self._closed = True
            return
        if self._writer is None or self._committed:
            return
        if not self.closed:
            self._writer.abort()
            self._closed = True
        if self._target != self.path:
            try:
                self.fs._rfs.rm_file(self._target)
            except FileNotFoundError:
                pass

    def abort(self) -> None:
        """Discard a write: nothing written becomes visible."""
        if self._spool is not None:
            self.discard()
            return
        if self._writer is not None and not self.closed:
            self._writer.abort()
        self._closed = True

    # ------------------------------------------------------------------
    # object protocol

    def __reduce__(self) -> Any:
        if self.mode != "rb":
            raise _WritePickleError("Pickling a writeable file is not supported")
        return reopen, (
            self.fs,
            self.path,
            self.mode,
            self.blocksize,
            self.tell() if not self.closed else 0,
            self.size,
            self.autocommit,
            self.cache_type,
            self.kwargs,
        )

    def __hash__(self) -> int:
        if "w" in self.mode or self.mode in _WRITE_MODES:
            return id(self)
        return int(tokenize(self.details), 16)

    def __eq__(self, other: object) -> bool:
        if self is other:
            return True
        return (
            isinstance(other, type(self))
            and self.mode == "rb"
            and other.mode == "rb"
            and hash(self) == hash(other)
        )

    def __str__(self) -> str:
        return f"<File-like object {type(self.fs).__name__}, {self.path}>"

    __repr__ = __str__

    def __enter__(self) -> FsfastFile:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __del__(self) -> None:
        # Like fsspec's buffered files (and Python's own), an unclosed file is
        # closed - and a write committed - when garbage collected.
        if not self.closed:
            try:
                self.close()
            except Exception:
                pass
