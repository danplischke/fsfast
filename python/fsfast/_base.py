"""The fsspec base class of every fsfast filesystem.

Design (docs/PLAN.md §4.4): Rust speed is lost if calls go through fsspec's
``sync()`` event-loop bridge or Python file and cache objects, so

* every public **sync** method is overridden and calls the Rust filesystem
  directly; the Rust side releases the GIL and drives the future on the
  calling thread (``fsspec.asyn.mirror_sync_methods`` only replaces methods
  that are still ``AbstractFileSystem``'s defaults, so it leaves these
  alone);
* every **async** ``_method`` awaits an asyncio future produced by Rust, so
  zarr v3's ``FsspecStore`` and other async users get the native path;
* bulk operations (``cat``, ``cat_ranges``, ``pipe``, ``rm``, ``copy``,
  ``put``, ``get``, ``sizes``) expand paths with fsspec's own logic (which
  has intricate trailing-slash / glob / ``maxdepth`` semantics) and then run
  the per-file operations as **one** concurrent Rust batch call;
* files are ``FsfastFile`` objects backed by Rust readers and writers.

The class still derives from ``fsspec.asyn.AsyncFileSystem``, so instance
caching, ``fsspec.filesystem()``, ``url_to_fs``, ``get_mapper``,
``open()`` (text mode, compression, transactions) and pickling keep
working unchanged.
"""

from __future__ import annotations

import bisect
import os
import uuid
from collections.abc import Iterable, Sequence
from glob import has_magic
from typing import Any, ClassVar

from fsspec.asyn import AsyncFileSystem, _get_batch_size, get_loop
from fsspec.callbacks import DEFAULT_CALLBACK
from fsspec.implementations.local import make_path_posix, trailing_sep
from fsspec.spec import AbstractFileSystem
from fsspec.utils import other_paths

try:  # fsspec >= 2025.x
    from fsspec.utils import check_contained
except ImportError:  # pragma: no cover - older fsspec

    def check_contained(root: str, paths: list[str]) -> None:
        return None


from . import _core
from ._file import FsfastFile

__all__ = ["FsfastFileSystem"]

#: ``AbstractFileSystem`` / ``AsyncFileSystem`` constructor options that only
#: concern the Python layer; they are not passed to the Rust backend.
PYTHON_OPTIONS = frozenset(
    {
        "skip_instance_cache",
        "use_listings_cache",
        "listings_expiry_time",
        "max_paths",
        "asynchronous",
        "loop",
        "batch_size",
        "add_docs",
        "add_aliases",
    }
)


def _make_local_parents(lpaths: Iterable[str]) -> None:
    """Create the local parent directory of each path (once per parent)."""
    for parent in {os.path.dirname(p) for p in lpaths}:
        if parent:
            os.makedirs(parent, exist_ok=True)


def _is_exc(x: Any) -> bool:
    return isinstance(x, BaseException)


def _first_exc(items: Iterable[Any]) -> BaseException | None:
    return next((x for x in items if _is_exc(x)), None)


def _bytes_like(value: Any) -> Any:
    """fsspec accepts ``str`` nowhere for data; mirror its TypeError early."""
    if isinstance(value, str):
        raise TypeError("a bytes-like object is required, not 'str'")
    return value


class FsfastFileSystem(AsyncFileSystem):
    """Base class: an fsspec ``AsyncFileSystem`` whose methods run in Rust.

    Subclasses set ``protocol`` (fsspec names), ``_rust_protocol`` (the
    backend in ``fsfast._core``) and, where the reference implementation
    differs from fsspec's defaults, ``_strip_protocol``, ``_parent`` and the
    ``ls`` default for ``detail``.
    """

    #: Backend name passed to ``fsfast._core.make_filesystem``.
    _rust_protocol: ClassVar[str] = ""
    #: ``cat_file`` ranges follow fsspec's generic ``cat_file`` (seek, then
    #: ``read(end - pos)``, as ``LocalFileSystem`` inherits) instead of
    #: Python slicing (``MemoryFileSystem``).
    _seek_read_ranges: ClassVar[bool] = False
    #: ``pipe_file(path, None)`` writes an empty file (fsspec's memory
    #: filesystem) instead of raising ``TypeError`` like a file's ``write``.
    _pipe_none_is_empty: ClassVar[bool] = False
    #: A file's ``read(n)`` with ``n < -1`` raises ``ValueError``, as the
    #: reference implementation's file objects do when they are CPython file
    #: objects (fsspec's local files); otherwise it reads everything, like
    #: ``AbstractBufferedFile`` and ``BytesIO``.
    _strict_negative_read: ClassVar[bool] = False
    #: In mode ``ab``, a file's ``tell()`` counts the existing content (the
    #: reference's file is positioned at the end of the stored data, as in
    #: fsspec's memory filesystem) instead of the bytes this handle wrote.
    _append_tell_from_end: ClassVar[bool] = False
    #: A file's ``readlines(hint)`` stops once the lines read reach
    #: ``hint`` bytes, like ``BytesIO`` (fsspec's memory files), instead of
    #: once they exceed it (``io.IOBase``: CPython files, fsspec's local
    #: files).
    _readlines_bytesio: ClassVar[bool] = False
    #: A file's ``seek(offset, 1 or 2)`` to before the start clamps to 0,
    #: like ``BytesIO`` (fsspec's memory files), instead of raising
    #: ``ValueError`` like ``AbstractBufferedFile``.
    _seek_clamps_negative: ClassVar[bool] = False
    #: ``pipe``/``pipe_file`` inside a transaction are deferred to commit:
    #: the references using fsspec's generic ``pipe_file`` (which writes
    #: through ``open``) do this; object stores and http, whose references
    #: upload directly, turn it off.
    _pipe_defers_in_transaction: ClassVar[bool] = True
    #: ``touch`` inside a transaction is deferred to commit (references
    #: using fsspec's generic touch: memory, smb, sftp).
    _touch_defers_in_transaction: ClassVar[bool] = False
    #: Deferred (``autocommit=False``) writes are spooled locally and
    #: uploaded at commit instead of being renamed into place (backends
    #: without an atomic rename: object stores).
    _spool_transactions: ClassVar[bool] = False
    #: Directories exist only as key prefixes (object stores): copying a
    #: directory entry is a no-op instead of a backend call.
    _implicit_dirs: ClassVar[bool] = False
    #: ``put``/``put_file`` create missing parent directories of the
    #: targets first (fsspec's generic ``put_file`` does, for real
    #: directories; SMB and SFTP inherit it).
    _put_makes_parents: ClassVar[bool] = False

    #: The reference implementation is an fsspec ``AsyncFileSystem`` (s3fs,
    #: gcsfs, adlfs, http): batch calls without ``batch_size`` run as many
    #: operations at a time as fsspec's ``_run_coros_in_chunks`` would
    #: (``fsspec.asyn._get_batch_size``: conf ``gather_batch_size`` /
    #: ``nofiles_gather_batch_size``, else 1280 for remote-only operations
    #: and ``RLIMIT_NOFILE // 8`` for transfers with local files). Classes
    #: whose reference is synchronous (one call at a time: local, memory,
    #: smb, sftp) use the backend's tuned concurrency instead.
    _fsspec_batches: ClassVar[bool] = False
    #: Metadata lookups are a syscall or a map lookup (local, memory), so
    #: batch operations may look every path up front; network classes look
    #: up only the paths whose operation failed (see ``_expand_kinds``).
    _cheap_info: ClassVar[bool] = False

    async_impl = True
    mirror_sync_methods = True

    def __init__(
        self,
        *args: Any,
        asynchronous: bool = False,
        loop: Any = None,
        batch_size: int | None = None,
        **storage_options: Any,
    ) -> None:
        if self._cached:
            return
        # AsyncFileSystem.__init__ would start fsspec's IO thread and event
        # loop eagerly; nothing here needs them, so ``loop`` is lazy.
        self.asynchronous = asynchronous
        self._pid = os.getpid()
        self._loop = loop
        self.batch_size = batch_size
        AbstractFileSystem.__init__(self, *args, **storage_options)
        self._rfs = _core.make_filesystem(
            self._rust_protocol, self._rust_options(dict(storage_options))
        )

    def _rust_options(self, storage_options: dict[str, Any]) -> dict[str, Any]:
        """Translate ``storage_options`` into the backend's options (the
        backend rejects unknown names)."""
        return {k: v for k, v in storage_options.items() if k not in PYTHON_OPTIONS}

    @property
    def loop(self) -> Any:
        """fsspec's event loop, created on first use only (fsfast's own
        sync methods never need it)."""
        if self._pid != os.getpid():
            # Forked: the Rust side is fork-safe; give fsspec a fresh loop.
            self._pid = os.getpid()
            self._loop = None
        if self._loop is None and not self.asynchronous:
            self._loop = get_loop()
        return self._loop

    @property
    def rust(self) -> _core.RustFileSystem:
        """The underlying ``fsfast._core.RustFileSystem``."""
        return self._rfs

    # ------------------------------------------------------------------
    # helpers

    def _strip(self, path: Any) -> str:
        return self._strip_protocol(path)

    def _strip_all(self, paths: Iterable[Any]) -> list[str]:
        strip = self._strip_protocol
        return [strip(p) for p in paths]

    def _batch_size(self, batch_size: int | None = None, nofiles: bool = True) -> int | None:
        """Operations in flight for a batch call: the call's ``batch_size``,
        else the instance's, else fsspec's default (``_fsspec_batches``) or
        ``None`` (the backend's tuned concurrency). ``-1`` means all at
        once, as in fsspec. ``nofiles`` is fsspec's flag: the operation
        involves no local files."""
        # fsspec: ``batch_size = batch_size or self.batch_size``.
        bs = batch_size or self.batch_size
        if bs is None and self._fsspec_batches:
            bs = _get_batch_size(nofiles=nofiles)
        return bs

    def _kinds(self, paths: list[str]) -> list[str | None]:
        """``info()["type"]`` of each path (``None`` if it does not exist),
        with one batched call."""
        infos = self._rfs.info_many(paths, on_error="return")
        return [None if _is_exc(i) else i["type"] for i in infos]

    async def _kinds_async(self, paths: list[str]) -> list[str | None]:
        infos = await self._rfs.info_many_async(paths, on_error="return")
        return [None if _is_exc(i) else i["type"] for i in infos]

    def _expand_kinds(
        self,
        path: Any,
        recursive: bool = False,
        maxdepth: int | None = None,
        assume_literal: bool = False,
        **kwargs: Any,
    ) -> tuple[list[str], dict[str, str]]:
        """fsspec's ``expand_path`` (same rules and results), also
        returning the ``type`` of every path the expansion already saw in a
        listing (``find``/``glob`` with ``detail=True``). Paths given
        literally without ``recursive`` are not looked up (fsspec does not
        either); callers try them and look up only failures."""
        if "expand_path" in self.__dict__ or type(self).expand_path is not FsfastFileSystem.expand_path:
            # ``expand_path`` is overridden (a subclass, or a test patching
            # the instance): honour it; kinds are then unknown.
            return self.expand_path(
                path, recursive=recursive, maxdepth=maxdepth, assume_literal=assume_literal, **kwargs
            ), {}
        if maxdepth is not None and maxdepth < 1:
            raise ValueError("maxdepth must be at least 1")
        kinds: dict[str, str] = {}
        if isinstance(path, (str, os.PathLike)):
            return self._expand_kinds([path], recursive, maxdepth, **kwargs)
        out: set[str] = set()

        def note(found: Any) -> set[str]:
            if isinstance(found, dict):
                for k, v in found.items():
                    if isinstance(v, dict) and "type" in v:
                        kinds[k] = v["type"]
            return set(found)

        for p in [self._strip_protocol(p) for p in path]:
            if not assume_literal and has_magic(p):
                bit = note(self.glob(p, maxdepth=maxdepth, detail=True, **kwargs))
                out |= bit
                if recursive:
                    if maxdepth is not None and maxdepth <= 1:
                        continue
                    sub, subkinds = self._expand_kinds(
                        list(bit),
                        recursive=recursive,
                        maxdepth=maxdepth - 1 if maxdepth is not None else None,
                        assume_literal=True,
                        **kwargs,
                    )
                    out |= set(sub)
                    kinds.update(subkinds)
                continue
            elif recursive:
                out |= note(self.find(p, maxdepth=maxdepth, withdirs=True, detail=True, **kwargs))
            if p not in out and (recursive is False or self.exists(p)):
                out.add(p)
        if not out:
            raise FileNotFoundError(path)
        return sorted(out), kinds

    def _fill_kinds(self, paths: list[str], known: dict[str, str]) -> list[str | None]:
        """The kind of each path: from ``known``, looking the rest up in
        one batch when lookups are cheap (``_cheap_info``); otherwise unknown
        kinds stay ``None`` (tried as files, failures looked up)."""
        kinds: list[str | None] = [known.get(p) for p in paths]
        if self._cheap_info:
            missing = [i for i, k in enumerate(kinds) if k is None]
            if missing:
                for i, k in zip(missing, self._kinds([paths[i] for i in missing])):
                    kinds[i] = k
        return kinds

    def _directories_among(self, failed: list[str]) -> set[str]:
        """Which of the paths whose file operation failed are directories
        (one batched lookup of the failures only)."""
        if not failed:
            return set()
        return {p for p, k in zip(failed, self._kinds(failed)) if k == "directory"}

    def _payload(self, value: Any) -> Any:
        """Data for ``pipe``/``pipe_file`` (see ``_pipe_none_is_empty``)."""
        if value is None and self._pipe_none_is_empty:
            return b""
        return _bytes_like(value)

    @staticmethod
    def _raise_first(results: list[Any]) -> None:
        exc = _first_exc(results)
        if exc is not None:
            raise exc

    def stats(self) -> dict[str, Any]:
        """Request counters and latency quantiles of this instance (see
        ``fsfast._core.RustFileSystem.stats``)."""
        return self._rfs.stats()

    def reset_stats(self) -> None:
        """Zero the counters returned by :meth:`stats`."""
        self._rfs.reset_stats()

    # ------------------------------------------------------------------
    # metadata

    def info(self, path: Any, **kwargs: Any) -> dict[str, Any]:
        return self._rfs.info(self._strip(path))

    async def _info(self, path: Any, **kwargs: Any) -> dict[str, Any]:
        return await self._rfs.info_async(self._strip(path))

    def ls(self, path: Any, detail: bool = True, **kwargs: Any) -> list[Any]:
        return self._rfs.ls(self._strip(path), detail=detail)

    async def _ls(self, path: Any, detail: bool = True, **kwargs: Any) -> list[Any]:
        return await self._rfs.ls_async(self._strip(path), detail=detail)

    def exists(self, path: Any, **kwargs: Any) -> bool:
        try:
            return self._rfs.exists(self._strip(path))
        except Exception:  # fsspec: any error means "does not exist"
            return False

    async def _exists(self, path: Any, **kwargs: Any) -> bool:
        return await self._rfs.exists_async(self._strip(path))

    def lexists(self, path: Any, **kwargs: Any) -> bool:
        return self.exists(path)

    def isdir(self, path: Any) -> bool:
        try:
            return self._rfs.info(self._strip(path))["type"] == "directory"
        except OSError:
            return False

    async def _isdir(self, path: Any) -> bool:
        try:
            return (await self._rfs.info_async(self._strip(path)))["type"] == "directory"
        except OSError:
            return False

    def isfile(self, path: Any) -> bool:
        try:
            return self._rfs.info(self._strip(path))["type"] == "file"
        except Exception:
            return False

    async def _isfile(self, path: Any) -> bool:
        try:
            return (await self._rfs.info_async(self._strip(path)))["type"] == "file"
        except Exception:
            return False

    def size(self, path: Any) -> int | None:
        return self.info(path).get("size", None)

    async def _size(self, path: Any) -> int | None:
        return (await self._info(path)).get("size", None)

    def sizes(self, paths: Iterable[Any], batch_size: int | None = None) -> list[int | None]:
        infos = self._rfs.info_many(
            self._strip_all(paths), on_error="raise", batch_size=self._batch_size(batch_size, nofiles=False)
        )
        return [i.get("size", None) for i in infos]

    async def _sizes(self, paths: Iterable[Any], batch_size: int | None = None) -> list[int | None]:
        infos = await self._rfs.info_many_async(
            self._strip_all(paths), on_error="raise", batch_size=self._batch_size(batch_size, nofiles=False)
        )
        return [i.get("size", None) for i in infos]

    def checksum(self, path: Any) -> int:
        return AbstractFileSystem.checksum(self, path)

    def ukey(self, path: Any) -> str:
        return AbstractFileSystem.ukey(self, path)

    def modified(self, path: Any) -> Any:
        """Last modification time as a timezone-aware UTC ``datetime``."""
        modified, _ = self._rfs.times(self._strip(path))
        if modified is None:
            raise NotImplementedError(f"modification time not available for {path!r}")
        return modified

    async def _modified(self, path: Any) -> Any:
        modified, _ = await self._rfs.times_async(self._strip(path))
        if modified is None:
            raise NotImplementedError(f"modification time not available for {path!r}")
        return modified

    def created(self, path: Any) -> Any:
        """Creation time as a timezone-aware UTC ``datetime``."""
        _, created = self._rfs.times(self._strip(path))
        if created is None:
            raise NotImplementedError(f"creation time not available for {path!r}")
        return created

    async def _created(self, path: Any) -> Any:
        _, created = await self._rfs.times_async(self._strip(path))
        if created is None:
            raise NotImplementedError(f"creation time not available for {path!r}")
        return created

    # ------------------------------------------------------------------
    # listing

    def find(
        self,
        path: Any,
        maxdepth: int | None = None,
        withdirs: bool = False,
        detail: bool = False,
        **kwargs: Any,
    ) -> Any:
        if maxdepth is not None and maxdepth < 1:
            raise ValueError("maxdepth must be at least 1")
        return self._rfs.find(self._strip(path), maxdepth, withdirs, detail)

    async def _find(
        self,
        path: Any,
        maxdepth: int | None = None,
        withdirs: bool = False,
        **kwargs: Any,
    ) -> Any:
        if maxdepth is not None and maxdepth < 1:
            raise ValueError("maxdepth must be at least 1")
        detail = kwargs.pop("detail", False)
        return await self._rfs.find_async(self._strip(path), maxdepth, withdirs, detail)

    def walk(
        self,
        path: Any,
        maxdepth: int | None = None,
        topdown: bool = True,
        on_error: Any = "omit",
        **kwargs: Any,
    ) -> Any:
        # fsspec's algorithm (pruning, on_error, file roots) over Rust ``ls``.
        return AbstractFileSystem.walk(
            self, path, maxdepth=maxdepth, topdown=topdown, on_error=on_error, **kwargs
        )

    def glob(self, path: Any, maxdepth: int | None = None, **kwargs: Any) -> Any:
        # fsspec's pattern logic over one Rust ``find``.
        return AbstractFileSystem.glob(self, path, maxdepth=maxdepth, **kwargs)

    def expand_path(
        self,
        path: Any,
        recursive: bool = False,
        maxdepth: int | None = None,
        assume_literal: bool = False,
        **kwargs: Any,
    ) -> list[str]:
        return AbstractFileSystem.expand_path(
            self, path, recursive, maxdepth, assume_literal=assume_literal, **kwargs
        )

    def _du_sizes(self, found: dict[str, dict[str, Any]], sizes: dict[str, Any]) -> None:
        for name, info in found.items():
            if info.get("type") not in ("file", "directory"):
                # fsspec re-stats every entry with info(), which follows
                # links (and raises for broken ones).
                info = self.info(name)
            sizes[info["name"]] = info["size"]

    def du(
        self,
        path: Any,
        total: bool = True,
        maxdepth: int | None = None,
        withdirs: bool = False,
        **kwargs: Any,
    ) -> Any:
        sizes: dict[str, Any] = {}
        if withdirs and self.isdir(path):
            info = self.info(path)
            sizes[info["name"]] = info["size"]
        found = self.find(path, maxdepth=maxdepth, withdirs=withdirs, detail=True)
        self._du_sizes(found, sizes)
        return sum(sizes.values()) if total else sizes

    async def _du(
        self, path: Any, total: bool = True, maxdepth: int | None = None, **kwargs: Any
    ) -> Any:
        sizes: dict[str, Any] = {}
        found = await self._find(path, maxdepth=maxdepth, detail=True, **kwargs)
        for name, info in found.items():
            if info.get("type") not in ("file", "directory"):
                info = await self._info(name)
            sizes[info["name"]] = info["size"]
        return sum(sizes.values()) if total else sizes

    # ------------------------------------------------------------------
    # reading

    def cat_file(self, path: Any, start: int | None = None, end: int | None = None, **kwargs: Any) -> bytes:
        return self._rfs.cat_file(self._strip(path), start, end, self._seek_read_ranges)

    async def _cat_file(
        self, path: Any, start: int | None = None, end: int | None = None, **kwargs: Any
    ) -> bytes:
        return await self._rfs.cat_file_async(
            self._strip(path), start, end, self._seek_read_ranges
        )

    def read_bytes(self, path: Any, start: int | None = None, end: int | None = None, **kwargs: Any) -> bytes:
        return self.cat_file(path, start=start, end=end, **kwargs)

    @staticmethod
    def _range_lists(paths: Any, starts: Any, ends: Any, sync: bool) -> tuple[list, list]:
        if not isinstance(paths, list):
            raise TypeError
        # The sync fsspec API broadcasts non-lists, the async one non-iterables.
        if (not isinstance(starts, list)) if sync else (not isinstance(starts, Iterable)):
            starts = [starts] * len(paths)
        if (not isinstance(ends, list)) if sync else (not isinstance(ends, Iterable)):
            ends = [ends] * len(paths)
        starts, ends = list(starts), list(ends)
        if len(starts) != len(paths) or len(ends) != len(paths):
            raise ValueError
        return starts, ends

    def cat_ranges(
        self,
        paths: list[Any],
        starts: Any,
        ends: Any,
        max_gap: int | None = None,
        on_error: str = "return",
        batch_size: int | None = None,
        **kwargs: Any,
    ) -> list[Any]:
        # ``max_gap`` is accepted and ignored: ranges are coalesced with the
        # backend's tuned gap (with an amplification guard, see the
        # bindings' ``plan_ranges``).
        starts, ends = self._range_lists(paths, starts, ends, sync=True)
        return self._rfs.cat_ranges(
            self._strip_all(paths),
            starts,
            ends,
            on_error="return" if on_error == "return" else "raise",
            batch_size=self._batch_size(batch_size),
            seek_read=self._seek_read_ranges,
        )

    async def _cat_ranges(
        self,
        paths: list[Any],
        starts: Any,
        ends: Any,
        max_gap: int | None = None,
        batch_size: int | None = None,
        on_error: str = "return",
        **kwargs: Any,
    ) -> list[Any]:
        starts, ends = self._range_lists(paths, starts, ends, sync=False)
        return await self._rfs.cat_ranges_async(
            self._strip_all(paths),
            starts,
            ends,
            on_error="return" if on_error == "return" else "raise",
            batch_size=self._batch_size(batch_size),
            seek_read=self._seek_read_ranges,
        )

    def _cat_result(self, path: Any, paths: list[str], out: list[Any], on_error: str) -> Any:
        if len(paths) > 1 or isinstance(path, list) or paths[0] != self._strip_protocol(path):
            return {
                k: v for k, v in zip(paths, out) if on_error != "omit" or not _is_exc(v)
            }
        if _is_exc(out[0]):
            raise out[0]
        return out[0]

    def cat(
        self,
        path: Any,
        recursive: bool = False,
        on_error: str = "raise",
        batch_size: int | None = None,
        **kwargs: Any,
    ) -> Any:
        start, end = kwargs.pop("start", None), kwargs.pop("end", None)
        paths = self.expand_path(path, recursive=recursive, **kwargs)
        mode = "raise" if on_error == "raise" else "return"
        bs = self._batch_size(batch_size)
        if start is None and end is None:
            out = self._rfs.cat_many(paths, on_error=mode, batch_size=bs)
        else:
            out = self._rfs.cat_ranges(
                paths,
                [start] * len(paths),
                [end] * len(paths),
                on_error=mode,
                batch_size=bs,
                seek_read=self._seek_read_ranges,
            )
        return self._cat_result(path, paths, out, on_error)

    async def _cat(
        self,
        path: Any,
        recursive: bool = False,
        on_error: str = "raise",
        batch_size: int | None = None,
        **kwargs: Any,
    ) -> Any:
        start, end = kwargs.pop("start", None), kwargs.pop("end", None)
        paths = await self._expand_path(path, recursive=recursive)
        mode = "raise" if on_error == "raise" else "return"
        bs = self._batch_size(batch_size)
        if start is None and end is None:
            out = await self._rfs.cat_many_async(paths, on_error=mode, batch_size=bs)
        else:
            out = await self._rfs.cat_ranges_async(
                paths,
                [start] * len(paths),
                [end] * len(paths),
                on_error=mode,
                batch_size=bs,
                seek_read=self._seek_read_ranges,
            )
        return self._cat_result(path, paths, out, on_error)

    def head(self, path: Any, size: int = 1024) -> bytes:
        # fsspec: ``f.read(size)``; a negative size reads everything (or is
        # an error below -1, see ``_strict_negative_read``).
        if size < -1 and self._strict_negative_read:
            self.cat_file(path, start=0, end=0)  # fails first like open() would
            raise ValueError("read length must be non-negative or -1")
        return self.cat_file(path) if size < 0 else self.cat_file(path, start=0, end=size)

    def tail(self, path: Any, size: int = 1024) -> bytes:
        # An empty range still raises for a missing path, like open() would.
        if size > 0:
            return self.cat_file(path, start=-size)
        return self.cat_file(path, start=0, end=0)

    # ------------------------------------------------------------------
    # writing

    def _pipe_deferred(self, path: Any, value: Any, mode: str) -> bool:
        """Inside a transaction, write through a deferred file as fsspec's
        generic ``pipe_file`` (``open(path, "wb")``) does, so the data only
        appears at commit. Returns whether it did."""
        if not (self._intrans and self._pipe_defers_in_transaction):
            return False
        if mode == "create" and self.exists(path):
            raise FileExistsError(path)
        with self.open(path, "wb") as f:
            f.write(self._payload(value))
        return True

    def pipe_file(self, path: Any, value: Any, mode: str = "overwrite", **kwargs: Any) -> None:
        if self._pipe_deferred(path, value, mode):
            return
        self._rfs.pipe_file(self._strip(path), self._payload(value), mode)

    async def _pipe_file(self, path: Any, value: Any, mode: str = "overwrite", **kwargs: Any) -> None:
        await self._rfs.pipe_file_async(self._strip(path), self._payload(value), mode)

    def write_bytes(self, path: Any, value: Any, **kwargs: Any) -> None:
        self.pipe_file(path, value, **kwargs)

    def pipe(self, path: Any, value: Any = None, batch_size: int | None = None, **kwargs: Any) -> None:
        """Write bytes: ``pipe(path, value)`` for one file, or
        ``pipe({path: value, ...})`` for many (uploaded concurrently)."""
        if isinstance(path, str):
            self.pipe_file(path, value, **kwargs)
        elif isinstance(path, dict):
            mode = kwargs.get("mode", "overwrite")
            if self._intrans and self._pipe_defers_in_transaction:
                for k, v in path.items():
                    self._pipe_deferred(k, v, mode)
                return
            self._rfs.pipe_many(
                self._strip_all(path.keys()),
                [self._payload(v) for v in path.values()],
                mode=mode,
                on_error="raise",
                batch_size=self._batch_size(batch_size),
            )
        else:
            raise ValueError("path must be str or dict")

    async def _pipe(
        self, path: Any, value: Any = None, batch_size: int | None = None, **kwargs: Any
    ) -> list[Any]:
        if isinstance(path, str):
            path = {path: value}
        mode = kwargs.get("mode", "overwrite")
        return await self._rfs.pipe_many_async(
            self._strip_all(path.keys()),
            [self._payload(v) for v in path.values()],
            mode=mode,
            on_error="raise",
            batch_size=self._batch_size(batch_size),
        )

    def touch(self, path: Any, truncate: bool = True, **kwargs: Any) -> None:
        if self._intrans and self._touch_defers_in_transaction and (truncate or not self.exists(path)):
            # fsspec's generic touch writes through open(path, "wb"), which
            # a transaction defers to commit.
            with self.open(path, "wb"):
                pass
            return
        self._rfs.touch(self._strip(path), truncate)

    async def _touch(self, path: Any, truncate: bool = True, **kwargs: Any) -> None:
        await self._rfs.touch_async(self._strip(path), truncate)

    # ------------------------------------------------------------------
    # directories

    def mkdir(self, path: Any, create_parents: bool = True, **kwargs: Any) -> None:
        self._rfs.mkdir(self._strip(path), create_parents)

    async def _mkdir(self, path: Any, create_parents: bool = True, **kwargs: Any) -> None:
        await self._rfs.mkdir_async(self._strip(path), create_parents)

    def makedirs(self, path: Any, exist_ok: bool = False) -> None:
        self._rfs.makedirs(self._strip(path), exist_ok)

    async def _makedirs(self, path: Any, exist_ok: bool = False) -> None:
        await self._rfs.makedirs_async(self._strip(path), exist_ok)

    def makedir(self, path: Any, create_parents: bool = True, **kwargs: Any) -> None:
        self.mkdir(path, create_parents=create_parents, **kwargs)

    def mkdirs(self, path: Any, exist_ok: bool = False) -> None:
        self.makedirs(path, exist_ok=exist_ok)

    def rmdir(self, path: Any) -> None:
        self._rfs.rmdir(self._strip(path))

    async def _rmdir(self, path: Any) -> None:
        await self._rfs.rmdir_async(self._strip(path))

    # ------------------------------------------------------------------
    # deleting

    def rm_file(self, path: Any) -> None:
        self._rfs.rm_file(self._strip(path))

    async def _rm_file(self, path: Any, **kwargs: Any) -> None:
        await self._rfs.rm_file_async(self._strip(path))

    def _rm_plan(self, paths: list[str], kinds: list[str | None]) -> list[tuple[str, list[str]]]:
        """Group the deletion of expanded ``paths`` (children after parents,
        as ``expand_path`` sorts them) into steps run deepest first: runs of
        non-directories become one batch delete, directories are removed
        one by one."""
        steps: list[tuple[str, list[str]]] = []
        for p, kind in zip(reversed(paths), reversed(kinds)):
            if kind == "directory":
                steps.append(("dir", [p]))
            elif steps and steps[-1][0] == "files":
                steps[-1][1].append(p)
            else:
                steps.append(("files", [p]))
        return steps

    def _rm_dirs(self, items: list[str]) -> None:
        """Directory step of ``rm`` (deepest first)."""
        self._rfs.rmdir_many(items, on_error="raise", ignore_missing=True)

    async def _rm_dirs_async(self, items: list[str]) -> None:
        await self._rfs.rmdir_many_async(items, on_error="raise", ignore_missing=True)

    @staticmethod
    def _has_children(p: str, paths: list[str]) -> bool:
        """Whether sorted ``paths`` holds an entry below ``p``."""
        prefix = p.rstrip("/") + "/"
        i = bisect.bisect_left(paths, prefix)
        return i < len(paths) and paths[i].startswith(prefix)

    def _rm_failed_dirs(self, failed: list[tuple[str, Any]], paths: list[str]) -> set[str]:
        """Which failed file deletions were directories: those with entries
        below them in the expansion (an implicit directory of an object
        store is gone once they are deleted, so a lookup would not find
        it), else by one batched lookup of the remaining failures."""
        dirs = {p for p, _ in failed if self._has_children(p, paths)}
        rest = [p for p, _ in failed if p not in dirs]
        return dirs | self._directories_among(rest)

    def _rm_files_step(self, items: list[str], paths: list[str]) -> None:
        """Files step of ``rm``: one batch delete of paths known (or
        assumed) not to be directories. Only the paths that fail are looked
        up: a directory among them (a path given literally, which fsspec's
        ``rm_file`` would ``stat`` first) gets the directory step, after the
        rest of the batch (its children) is gone; any other failure is
        raised, the first in order."""
        results = self._rfs.rm_files(items, on_error="return")
        failed = [(p, r) for p, r in zip(items, results) if _is_exc(r)]
        if not failed:
            return
        dirs = self._rm_failed_dirs(failed, paths)
        for p, r in failed:
            if p not in dirs:
                raise r
        # ``items`` run deepest first, so the directories do too.
        self._rm_dirs([p for p, _ in failed])

    async def _rm_files_step_async(self, items: list[str], paths: list[str]) -> None:
        results = await self._rfs.rm_files_async(items, on_error="return")
        failed = [(p, r) for p, r in zip(items, results) if _is_exc(r)]
        if not failed:
            return
        dirs = {p for p, _ in failed if self._has_children(p, paths)}
        rest = [p for p, _ in failed if p not in dirs]
        if rest:
            kinds = await self._kinds_async(rest)
            dirs |= {p for p, k in zip(rest, kinds) if k == "directory"}
        for p, r in failed:
            if p not in dirs:
                raise r
        await self._rm_dirs_async([p for p, _ in failed])

    def _rm_run(self, paths: list[str], known: dict[str, str]) -> None:
        """Delete expanded (sorted) ``paths`` (``known``: kinds seen while
        expanding; see ``_rm_plan``)."""
        for step, items in self._rm_plan(paths, [known.get(p) for p in paths]):
            if step == "files":
                self._rm_files_step(items, paths)
            else:
                self._rm_dirs(items)

    async def _rm_run_async(self, paths: list[str], known: dict[str, str]) -> None:
        for step, items in self._rm_plan(paths, [known.get(p) for p in paths]):
            if step == "files":
                await self._rm_files_step_async(items, paths)
            else:
                await self._rm_dirs_async(items)

    def rm(self, path: Any, recursive: bool = False, maxdepth: int | None = None) -> None:
        # No per-path lookup: kinds come from the expansion's listings, and
        # anything else is deleted as a file first (fsspec's rm_file stats
        # every path; that would cost one round trip per path).
        paths, known = self._expand_kinds(path, recursive=recursive, maxdepth=maxdepth)
        self._rm_run(paths, known)

    async def _rm(
        self,
        path: Any,
        recursive: bool = False,
        batch_size: int | None = None,
        maxdepth: int | None = None,
        **kwargs: Any,
    ) -> None:
        paths = await self._expand_path(path, recursive=recursive, maxdepth=maxdepth)
        await self._rm_run_async(paths, {})

    def delete(self, path: Any, recursive: bool = False, maxdepth: int | None = None) -> None:
        self.rm(path, recursive=recursive, maxdepth=maxdepth)

    # ------------------------------------------------------------------
    # copy / move

    def cp_file(self, path1: Any, path2: Any, **kwargs: Any) -> None:
        self._rfs.cp_file(self._strip(path1), self._strip(path2))

    async def _cp_file(self, path1: Any, path2: Any, **kwargs: Any) -> None:
        await self._rfs.cp_file_async(self._strip(path1), self._strip(path2))

    async def _mv_file(self, path1: Any, path2: Any) -> None:
        await self._rfs.mv_file_async(self._strip(path1), self._strip(path2))

    def _copy_pairs(
        self, path1: Any, path2: Any, recursive: bool, maxdepth: int | None, **kwargs: Any
    ) -> tuple[list[str], list[str], dict[str, str]] | None:
        """fsspec's ``AbstractFileSystem.copy`` path expansion (same rules
        for globs, trailing slashes, ``recursive`` and ``maxdepth``), also
        returning the source kinds seen while expanding. ``None`` means
        nothing to copy."""
        if isinstance(path1, list) and isinstance(path2, list):
            return self._strip_all(path1), self._strip_all(path2), {}
        source_is_str = isinstance(path1, str)
        paths1, known = self._expand_kinds(path1, recursive=recursive, maxdepth=maxdepth, **kwargs)
        if source_is_str and (not recursive or maxdepth is not None):
            # Non-recursive glob does not copy directories (fsspec asks
            # isdir() for each path; only paths not seen in a listing are
            # looked up here).
            unknown = [p for p in paths1 if p not in known and not trailing_sep(p)]
            if unknown:
                known = {**known, **{p: k for p, k in zip(unknown, self._kinds(unknown)) if k}}
            paths1 = [
                p for p in paths1 if not (trailing_sep(p) or known.get(p) == "directory")
            ]
            if not paths1:
                return None
        source_is_file = len(paths1) == 1
        dest_is_dir = isinstance(path2, str) and (trailing_sep(path2) or self.isdir(path2))
        exists = source_is_str and (
            (has_magic(path1) and source_is_file)
            or (not has_magic(path1) and dest_is_dir and not trailing_sep(path1))
        )
        paths2 = other_paths(paths1, path2, exists=exists, flatten=not source_is_str)
        return paths1, self._strip_all(paths2), known

    def _run_pairs(
        self,
        batch: Any,
        srcs: list[str],
        dsts: list[str],
        kinds: Sequence[str | None],
        on_error: str = "raise",
    ) -> list[Any]:
        """Run a pairwise batch op, directories first (so that targets of
        the files inside them exist), then everything else; results are
        returned in input order."""
        results: list[Any] = [None] * len(srcs)
        dirs = [i for i, k in enumerate(kinds) if k == "directory"]
        rest = [i for i, k in enumerate(kinds) if k != "directory"]
        for group in (dirs, rest):
            if not group:
                continue
            out = batch([srcs[i] for i in group], [dsts[i] for i in group], on_error=on_error)
            for i, r in zip(group, out):
                results[i] = r
        return results

    def _copy_dirs(self, dsts: list[str]) -> None:
        """Create the targets of copied directories (backends with real
        directories, see ``_put_makes_parents``)."""
        if dsts and self._put_makes_parents:
            self._rfs.makedirs_many(dsts, exist_ok=True, on_error="raise")

    def copy(
        self,
        path1: Any,
        path2: Any,
        recursive: bool = False,
        maxdepth: int | None = None,
        on_error: str | None = None,
        batch_size: int | None = None,
        **kwargs: Any,
    ) -> None:
        if on_error is None and recursive:
            on_error = "ignore"
        elif on_error is None:
            on_error = "raise"
        pairs = self._copy_pairs(path1, path2, recursive, maxdepth, **kwargs)
        if pairs is None:
            return
        srcs, dsts, known = pairs
        if self._implicit_dirs or self._put_makes_parents:
            # Sources not seen in a listing are copied as files; the few
            # that fail are looked up below.
            kinds = [known.get(p) for p in srcs]
        else:
            kinds = self._fill_kinds(srcs, known) if self._cheap_info else self._kinds(srcs)
        if self._implicit_dirs or self._put_makes_parents:
            keep = [i for i, k in enumerate(kinds) if k != "directory"]
            dirs = [d for d, k in zip(dsts, kinds) if k == "directory"]
            srcs, dsts, kinds = [srcs[i] for i in keep], [dsts[i] for i in keep], [kinds[i] for i in keep]
            # Real directories: create the target directories, then copy the
            # files server-side...
            self._copy_dirs(dirs)
            if self._put_makes_parents:
                # ...and the parents of file targets (a file copied into a
                # new directory, as ``put`` does).
                self._make_parents(dsts)
        bs = self._batch_size(batch_size)
        results = self._run_pairs(
            lambda s, d, on_error: self._rfs.cp_files(s, d, on_error=on_error, batch_size=bs),
            srcs,
            dsts,
            kinds,
            on_error="return",
        )
        failed = [i for i, r in enumerate(results) if _is_exc(r) and kinds[i] is None]
        if failed:
            # Sources of unknown kind that failed: a directory gets the
            # directory treatment instead of an error.
            dirs = self._directories_among([srcs[i] for i in failed])
            fixed = [i for i in failed if srcs[i] in dirs]
            self._copy_dirs([dsts[i] for i in fixed])
            for i in fixed:
                results[i] = None
        for r in results:
            if _is_exc(r):
                if on_error == "ignore" and isinstance(r, FileNotFoundError):
                    continue
                raise r

    def cp(self, path1: Any, path2: Any, **kwargs: Any) -> None:
        self.copy(path1, path2, **kwargs)

    def mv(self, path1: Any, path2: Any, recursive: bool = False, maxdepth: int | None = None, **kwargs: Any) -> None:
        if path1 == path2:
            return
        # fsspec's generic move: copy (raising on errors), then delete.
        self.copy(path1, path2, recursive=recursive, maxdepth=maxdepth, on_error="raise")
        self.rm(path1, recursive=recursive)

    def move(self, path1: Any, path2: Any, **kwargs: Any) -> None:
        self.mv(path1, path2, **kwargs)

    def rename(self, path1: Any, path2: Any, **kwargs: Any) -> None:
        self.mv(path1, path2, **kwargs)

    # ------------------------------------------------------------------
    # transfers with the local filesystem

    def put_file(
        self,
        lpath: Any,
        rpath: Any,
        callback: Any = DEFAULT_CALLBACK,
        mode: str = "overwrite",
        **kwargs: Any,
    ) -> None:
        lpath = os.fspath(lpath)
        size = os.path.getsize(lpath) if os.path.isfile(lpath) else 0
        callback.set_size(size)
        if self._put_makes_parents:
            if os.path.isdir(lpath):
                self._rfs.makedirs(self._strip(rpath), True)
                return
            self._make_parents([self._strip(rpath)])
        self._rfs.put_file(lpath, self._strip(rpath), mode)
        callback.relative_update(size)

    def _make_parents(self, rpaths: list[str]) -> None:
        parents = sorted({self._parent(p) for p in rpaths} - {"", self.root_marker})
        if parents:
            self._rfs.makedirs_many(parents, exist_ok=True, on_error="raise")

    async def _put_file(self, lpath: Any, rpath: Any, mode: str = "overwrite", **kwargs: Any) -> None:
        if self._put_makes_parents:
            parent = self._parent(self._strip(rpath))
            if parent:
                await self._rfs.makedirs_async(parent, True)
        await self._rfs.put_file_async(os.fspath(lpath), self._strip(rpath), mode)

    def put(
        self,
        lpath: Any,
        rpath: Any,
        recursive: bool = False,
        callback: Any = DEFAULT_CALLBACK,
        maxdepth: int | None = None,
        batch_size: int | None = None,
        **kwargs: Any,
    ) -> None:
        if isinstance(lpath, list) and isinstance(rpath, list):
            lpaths, rpaths = [os.fspath(p) for p in lpath], self._strip_all(rpath)
        else:
            from ._local import LocalFileSystem

            source_is_str = isinstance(lpath, str)
            if source_is_str:
                lpath = make_path_posix(lpath)
            fs = LocalFileSystem()
            lpaths = fs.expand_path(lpath, recursive=recursive, maxdepth=maxdepth, **kwargs)
            if source_is_str and (not recursive or maxdepth is not None):
                # Non-recursive glob does not copy directories
                lpaths = [p for p in lpaths if not (trailing_sep(p) or fs.isdir(p))]
                if not lpaths:
                    return
            source_is_file = len(lpaths) == 1
            dest_is_dir = isinstance(rpath, str) and (trailing_sep(rpath) or self.isdir(rpath))
            rpath = (
                self._strip_protocol(rpath)
                if isinstance(rpath, str)
                else [self._strip_protocol(p) for p in rpath]
            )
            exists = source_is_str and (
                (has_magic(lpath) and source_is_file)
                or (not has_magic(lpath) and dest_is_dir and not trailing_sep(lpath))
            )
            rpaths = self._strip_all(
                other_paths(lpaths, rpath, exists=exists, flatten=not source_is_str)
            )
        mode = kwargs.get("mode", "overwrite")
        kinds = ["directory" if os.path.isdir(p) else "file" for p in lpaths]
        if self._implicit_dirs:
            # Prefix directories need no creation.
            keep = [i for i, k in enumerate(kinds) if k != "directory"]
            lpaths, rpaths, kinds = [lpaths[i] for i in keep], [rpaths[i] for i in keep], [kinds[i] for i in keep]
        callback.set_size(sum(k != "directory" for k in kinds))
        if self._put_makes_parents and rpaths:
            # Directories (and the parents of files) are created up front;
            # only files go to the backend's put.
            dirs = [r for r, k in zip(rpaths, kinds) if k == "directory"]
            keep = [i for i, k in enumerate(kinds) if k != "directory"]
            lpaths, rpaths, kinds = [lpaths[i] for i in keep], [rpaths[i] for i in keep], [kinds[i] for i in keep]
            if dirs:
                self._rfs.makedirs_many(dirs, exist_ok=True, on_error="raise")
            self._make_parents(rpaths)
        results = self._run_pairs(
            lambda s, d, on_error: self._rfs.put_files(
                s, d, mode=mode, on_error=on_error, batch_size=self._batch_size(batch_size, nofiles=False)
            ),
            lpaths,
            rpaths,
            kinds,
        )
        callback.relative_update(sum(k != "directory" for k in kinds))
        self._raise_first(results)

    def get_file(
        self,
        rpath: Any,
        lpath: Any,
        callback: Any = DEFAULT_CALLBACK,
        outfile: Any = None,
        **kwargs: Any,
    ) -> None:
        from fsspec.utils import isfilelike

        if outfile is None and isfilelike(lpath):
            outfile = lpath
        if outfile is not None:
            with self.open(rpath, "rb") as f:
                callback.set_size(getattr(f, "size", None))
                while True:
                    data = f.read(self.blocksize)
                    if not data:
                        break
                    outfile.write(data)
                    callback.relative_update(len(data))
            return
        lpath = os.fspath(lpath)
        # fsspec's get_file creates the local parent directory.
        _make_local_parents([lpath])
        self._rfs.get_file(self._strip(rpath), lpath)
        if callback is not DEFAULT_CALLBACK:
            # The transfer runs in Rust in one call: report it as one step
            # of the downloaded size (s3fs reports the object size too).
            size = os.path.getsize(lpath)
            callback.set_size(size)
            callback.relative_update(size)

    async def _get_file(self, rpath: Any, lpath: Any, **kwargs: Any) -> None:
        lpath = os.fspath(lpath)
        _make_local_parents([lpath])
        await self._rfs.get_file_async(self._strip(rpath), lpath)

    def get(
        self,
        rpath: Any,
        lpath: Any,
        recursive: bool = False,
        callback: Any = DEFAULT_CALLBACK,
        maxdepth: int | None = None,
        batch_size: int | None = None,
        **kwargs: Any,
    ) -> None:
        if isinstance(lpath, list) and isinstance(rpath, list):
            rpaths, lpaths = self._strip_all(rpath), [os.fspath(p) for p in lpath]
            known: dict[str, str] = {}
        else:
            source_is_str = isinstance(rpath, str)
            rpaths, known = self._expand_kinds(rpath, recursive=recursive, maxdepth=maxdepth, **kwargs)
            if source_is_str and (not recursive or maxdepth is not None):
                # Non-recursive glob does not copy directories (fsspec asks
                # isdir(); only paths not seen in a listing are looked up).
                unknown = [p for p in rpaths if p not in known and not trailing_sep(p)]
                if unknown:
                    known = {**known, **{p: k for p, k in zip(unknown, self._kinds(unknown)) if k}}
                rpaths = [
                    p for p in rpaths if not (trailing_sep(p) or known.get(p) == "directory")
                ]
                if not rpaths:
                    return
            if isinstance(lpath, str):
                lpath = make_path_posix(lpath)
            source_is_file = len(rpaths) == 1
            dest_is_dir = isinstance(lpath, str) and (
                trailing_sep(lpath) or os.path.isdir(lpath)
            )
            exists = source_is_str and (
                (has_magic(rpath) and source_is_file)
                or (not has_magic(rpath) and dest_is_dir and not trailing_sep(rpath))
            )
            lpaths = other_paths(rpaths, lpath, exists=exists, flatten=not source_is_str)
            if isinstance(lpath, str):
                check_contained(lpath, lpaths)
        # Paths not seen in a listing are downloaded as files; the ones that
        # fail are looked up below (a directory is created locally instead).
        kinds = self._fill_kinds(rpaths, known)
        callback.set_size(len(lpaths))
        # Directories are created locally, as fsspec's get_file does; only
        # files go to the backend (object stores have no directory object
        # to download).
        for p, k in zip(lpaths, kinds):
            if k == "directory":
                os.makedirs(p, exist_ok=True)
        files = [i for i, k in enumerate(kinds) if k != "directory"]
        # fsspec (get_file, and AsyncFileSystem._get) creates the local
        # parent directory of every target; one makedirs per distinct parent.
        _make_local_parents([lpaths[i] for i in files])
        bs = self._batch_size(batch_size, nofiles=False)
        results = self._rfs.get_files(
            [rpaths[i] for i in files],
            [lpaths[i] for i in files],
            on_error="return",
            batch_size=bs,
        )
        failed = [j for j, r in enumerate(results) if _is_exc(r) and kinds[files[j]] is None]
        if failed:
            dirs = self._directories_among([rpaths[files[j]] for j in failed])
            for j in failed:
                if rpaths[files[j]] in dirs:
                    os.makedirs(lpaths[files[j]], exist_ok=True)
                    results[j] = None
        callback.relative_update(len(lpaths))
        self._raise_first(results)

    def upload(self, lpath: Any, rpath: Any, recursive: bool = False, **kwargs: Any) -> None:
        self.put(lpath, rpath, recursive=recursive, **kwargs)

    def download(self, rpath: Any, lpath: Any, recursive: bool = False, **kwargs: Any) -> None:
        self.get(rpath, lpath, recursive=recursive, **kwargs)

    # ------------------------------------------------------------------
    # misc

    def sign(self, path: Any, expiration: int = 100, **kwargs: Any) -> str:
        return self._rfs.sign(self._strip(path), float(expiration))

    async def _sign(self, path: Any, expiration: int = 100, **kwargs: Any) -> str:
        return await self._rfs.sign_async(self._strip(path), float(expiration))

    def invalidate_cache(self, path: Any = None) -> None:
        self._rfs.invalidate_cache(None if path is None else self._strip(path))
        AbstractFileSystem.invalidate_cache(self, path)

    def close(self) -> None:
        """Release pooled connections (the filesystem stays usable)."""
        self._rfs.close()

    # ------------------------------------------------------------------
    # files

    def _transaction_temp_path(self, path: str) -> str:
        """Where a deferred (``autocommit=False``) write goes until commit:
        a hidden sibling, so the commit is an atomic rename."""
        parent = self._parent(path).rstrip("/")
        name = path.rsplit("/", 1)[-1]
        return f"{parent}/.{name}.fsfast-{uuid.uuid4().hex}.tmp"

    def _open(
        self,
        path: Any,
        mode: str = "rb",
        block_size: int | str | None = None,
        autocommit: bool = True,
        cache_options: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> FsfastFile:
        return FsfastFile(
            self,
            self._strip(path),
            mode,
            block_size=block_size,
            autocommit=autocommit,
            cache_options=cache_options,
            **kwargs,
        )
