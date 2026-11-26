"""Listings-cache semantics shared by the object-store classes (s3, gs, abfs).

s3fs, gcsfs and adlfs keep directory listings in fsspec's ``dircache`` (on
by default; ``use_listings_cache``, ``listings_expiry_time`` and
``max_paths`` configure it) and answer ``info``/``exists``/``isdir`` from a
cached parent listing when they can. That changes results in ways users
observe - ``info`` after ``ls`` returns the *listing* entry (s3fs: ``Key``,
``Size``, ... instead of the HEAD keys), and a listing made by this instance
hides objects written by someone else until ``invalidate_cache`` or
``refresh=True`` - so fsfast reproduces it here, on top of the Rust
listings.

Every mutating method invalidates the touched paths and their ancestors, as
the references do.
"""

from __future__ import annotations

import errno
import functools
import inspect
import os
from collections.abc import Callable
from glob import has_magic
from typing import Any

from ._base import FsfastFileSystem, _is_exc

__all__ = ["ObjectStoreFileSystem"]


def _touched(method: Callable[..., Any], names: tuple[str, ...]) -> Callable[..., list[Any]]:
    """A function returning the arguments named ``names`` of a call to
    ``method``, however they were passed (positionally or by keyword)."""
    sig = inspect.signature(method)

    def touched(self: Any, args: tuple[Any, ...], kwargs: dict[str, Any]) -> list[Any]:
        try:
            bound = sig.bind_partial(self, *args, **kwargs).arguments
        except TypeError:
            return []
        return [bound[n] for n in names if n in bound]

    return touched


def _first_param(method: Callable[..., Any]) -> tuple[str, ...]:
    return (list(inspect.signature(method).parameters)[1],)


def _invalidating(method: Callable[..., Any], *names: str) -> Callable[..., Any]:
    """Wrap a sync mutating method: invalidate the paths it touched, the
    arguments ``names`` (default: the first after ``self``). The wrapper
    keeps the method's signature, so the paths may be passed by keyword
    (``cp_file(path1=..., path2=...)``, as the references allow)."""
    touched = _touched(method, names or _first_param(method))

    @functools.wraps(method)
    def wrapper(self: ObjectStoreFileSystem, *args: Any, **kwargs: Any) -> Any:
        try:
            return method(self, *args, **kwargs)
        finally:
            self._invalidate_paths(touched(self, args, kwargs))

    return wrapper


def _ainvalidating(method: Callable[..., Any], *names: str) -> Callable[..., Any]:
    """Async twin of :func:`_invalidating`."""
    touched = _touched(method, names or _first_param(method))

    @functools.wraps(method)
    async def wrapper(self: ObjectStoreFileSystem, *args: Any, **kwargs: Any) -> Any:
        try:
            return await method(self, *args, **kwargs)
        finally:
            self._invalidate_paths(touched(self, args, kwargs))

    return wrapper


class ObjectStoreFileSystem(FsfastFileSystem):
    """Base of the object-store classes: ``dircache``-backed ``ls``/``info``.

    Subclasses provide :meth:`_dir_entry` (the reference's dict for a path
    known to be a directory because its own listing is cached) and may
    override :meth:`_listing_key` (the cache key of a path).
    """

    root_marker = ""
    _spool_transactions = True
    # The reference uploads pipe_file directly, even in a transaction.
    _pipe_defers_in_transaction = False
    _implicit_dirs = True
    # s3fs, gcsfs and adlfs are fsspec AsyncFileSystems.
    _fsspec_batches = True
    #: ``rm(dir)`` without ``recursive`` leaves a non-empty directory in
    #: place instead of raising (adlfs: it deletes only the blob named
    #: ``dir``, which does not exist; s3fs/gcsfs never reach a directory
    #: step because their directories are implicit).
    _rm_skips_nonempty_dirs = False

    # ------------------------------------------------------------------
    # cache helpers

    def _listing_key(self, path: Any) -> str:
        """The ``dircache`` key of ``path``: stripped, no trailing slash."""
        return self._strip_protocol(path).rstrip("/")

    def _dir_entry(self, path: str) -> dict[str, Any]:
        return {"name": path, "size": 0, "type": "directory"}

    def _is_listing(self, path: str, out: list[dict[str, Any]]) -> bool:
        """Whether ``out`` (Rust ``ls(path)``) lists a directory rather than
        describing ``path`` itself as a file (the core contract's ``ls`` of
        a file)."""
        return not (
            len(out) == 1 and out[0]["type"] != "directory" and out[0]["name"].rstrip("/") == path
        )

    def _fix(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Adjust one info dict from Rust to the reference's exact value
        types (hook; identity by default)."""
        return entry

    def _fix_all(self, entries: Any) -> Any:
        if type(self)._fix is ObjectStoreFileSystem._fix:
            return entries
        if isinstance(entries, dict):
            return {k: self._fix(v) for k, v in entries.items()}
        return [self._fix(e) for e in entries]

    def _store_listing(self, path: str, out: list[dict[str, Any]]) -> None:
        if out and self._is_listing(path, out):
            self.dircache[path] = out

    def _cached_info(self, path: str) -> dict[str, Any] | None:
        """``info`` from the cache (fsspec ``_ls_from_cache``): the entry in
        the cached parent listing, the directory dict if ``path``'s own
        listing is cached, ``None`` if nothing is known. Raises
        ``FileNotFoundError`` if the parent listing is cached and does not
        contain ``path``, like the references."""
        out = self._ls_from_cache(path)
        if out is None:
            return None
        for o in out:
            if o["name"].rstrip("/") == path and o["type"] != "directory":
                return o
        for o in out:
            if o["name"].rstrip("/") == path:
                return o
        return self._dir_entry(path)

    def _invalidate_paths(self, paths: Any, tree: bool = False) -> None:
        """Invalidate each path (a string, or a list of them, or a list of
        such items) with its ancestors; with ``tree`` also every cached
        listing below it (the destination of a recursive ``copy``/``put``/
        ``mv``, whose subdirectories' cached listings would otherwise hide
        the files just written)."""
        for q in paths if isinstance(paths, list) else [paths]:
            if isinstance(q, list):
                self._invalidate_paths(q, tree)
            elif isinstance(q, str):
                self.invalidate_cache(q)
                if tree:
                    self._invalidate_below(q)

    def _invalidate_below(self, path: str) -> None:
        """Drop the cached listings of everything below ``path``."""
        key = self._listing_key(path)
        prefix = key + "/" if key else ""
        for k in [k for k in self.dircache if k.startswith(prefix) and k != key]:
            self.dircache.pop(k, None)

    def invalidate_cache(self, path: Any = None) -> None:
        """Drop cached listings: everything, or ``path`` and its ancestors."""
        if path is None:
            self.dircache.clear()
        else:
            p = self._listing_key(path)
            if "/" not in p:
                # A bucket/container changed: the root listing (buckets)
                # may be stale too (the references invalidate "" on mkdir
                # and rmdir of a bucket).
                self.dircache.pop("", None)
            while p:
                self.dircache.pop(p, None)
                p = self._parent(p)
        self._rfs.invalidate_cache(None if path is None else self._strip(path))

    # ------------------------------------------------------------------
    # listing

    def _ls_entries(self, path: str, refresh: bool) -> list[dict[str, Any]]:
        if not refresh:
            try:
                return self.dircache[path]
            except KeyError:
                pass
        out = self._fix_all(self._rfs.ls(path, detail=True))
        self._store_listing(path, out)
        return out

    async def _ls_entries_async(self, path: str, refresh: bool) -> list[dict[str, Any]]:
        if not refresh:
            try:
                return self.dircache[path]
            except KeyError:
                pass
        out = self._fix_all(await self._rfs.ls_async(path, detail=True))
        self._store_listing(path, out)
        return out

    @staticmethod
    def _names(out: list[dict[str, Any]]) -> list[str]:
        return sorted(o["name"] for o in out)

    def ls(self, path: Any, detail: bool = False, refresh: bool = False, **kwargs: Any) -> list[Any]:
        out = self._ls_entries(self._listing_key(path), refresh)
        return out if detail else self._names(out)

    async def _ls(self, path: Any, detail: bool = False, refresh: bool = False, **kwargs: Any) -> list[Any]:
        out = await self._ls_entries_async(self._listing_key(path), refresh)
        return out if detail else self._names(out)

    def info(self, path: Any, refresh: bool = False, **kwargs: Any) -> dict[str, Any]:
        p = self._listing_key(path)
        if not refresh and p:
            cached = self._cached_info(p)
            if cached is not None:
                return cached
        return self._fix(self._rfs.info(self._strip(path)))

    async def _info(self, path: Any, refresh: bool = False, **kwargs: Any) -> dict[str, Any]:
        p = self._listing_key(path)
        if not refresh and p:
            cached = self._cached_info(p)
            if cached is not None:
                return cached
        return self._fix(await self._rfs.info_async(self._strip(path)))

    def exists(self, path: Any, **kwargs: Any) -> bool:
        try:
            self.info(path)
            return True
        except FileNotFoundError:
            return False
        except Exception:  # fsspec: any error means "does not exist"
            return False

    async def _exists(self, path: Any, **kwargs: Any) -> bool:
        try:
            await self._info(path)
            return True
        except Exception:
            return False

    def isdir(self, path: Any) -> bool:
        try:
            return self.info(path)["type"] == "directory"
        except OSError:
            return False

    async def _isdir(self, path: Any) -> bool:
        try:
            return (await self._info(path))["type"] == "directory"
        except OSError:
            return False

    def isfile(self, path: Any) -> bool:
        try:
            return self.info(path)["type"] == "file"
        except Exception:
            return False

    async def _isfile(self, path: Any) -> bool:
        try:
            return (await self._info(path))["type"] == "file"
        except Exception:
            return False

    def _kinds(self, paths: list[str]) -> list[str | None]:
        # Cache-aware, like the references' isdir checks.
        out: list[str | None] = []
        missing = []
        for p in paths:
            try:
                info = self._cached_info(self._listing_key(p))
            except FileNotFoundError:
                info = None
            out.append(None if info is None else info["type"])
            if info is None:
                missing.append(len(out) - 1)
        if missing:
            infos = self._rfs.info_many([paths[i] for i in missing], on_error="return")
            for i, inf in zip(missing, infos):
                out[i] = None if _is_exc(inf) else inf["type"]
        return out

    # ------------------------------------------------------------------
    # find: populate the cache with the listings a full recursive listing
    # implies, as s3fs and gcsfs do

    def _cache_tree(self, root: str, entries: list[dict[str, Any]]) -> None:
        # ``entries`` is the full flat listing, where a file ``a`` and the
        # prefix ``a/`` are two entries with the same name; both belong in
        # the parent's listing (file first, as in s3fs's), exactly as a
        # direct ``ls`` returns them.
        listings: dict[str, list[dict[str, Any]]] = {}
        for o in entries:
            name = o["name"]
            if name.endswith("/"):
                continue  # directory placeholders are not listed
            parent = self._parent(name)
            if len(parent) >= len(root):
                listings.setdefault(parent, []).append(o)
            if o["type"] == "directory":
                listings.setdefault(name, [])
        for k, v in listings.items():
            if k and len(k) >= len(root) and k not in self.dircache and v:
                self.dircache[k] = sorted(v, key=lambda x: (x["name"], x["type"] == "directory"))

    def _find_result(
        self,
        root: str,
        found: list[dict[str, Any]],
        maxdepth: int | None,
        withdirs: bool,
        detail: bool,
        cache: bool,
    ) -> Any:
        entries = found
        if cache and maxdepth is None:
            self._cache_tree(root, entries)
        if not withdirs:
            entries = [o for o in entries if o["type"] != "directory"]
        # Entries sharing a name collapse as in the references' dicts (the
        # later one, the directory, wins).
        out = {o["name"]: o for o in entries}
        return out if detail else list(out)

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
        root = self._listing_key(path)
        found = self._fix_all(self._rfs.find(self._strip(path), maxdepth, True, True, as_list=True))
        return self._find_result(root, found, maxdepth, withdirs, detail, True)

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
        root = self._listing_key(path)
        found = self._fix_all(
            await self._rfs.find_async(self._strip(path), maxdepth, True, True, as_list=True)
        )
        return self._find_result(root, found, maxdepth, withdirs, detail, True)

    # ------------------------------------------------------------------
    # uploads with per-call parameters (s3fs ``ContentType=``, adlfs
    # ``content_settings=``): without them the Rust batch upload is used;
    # with them each file streams through a write handle that carries them.

    def _put_streamed(self, lpath: str, rpath: str, mode: str, extra: dict[str, Any]) -> None:
        """Upload one local file through a write handle with ``extra``."""
        if os.path.isdir(lpath):
            return  # prefixes need no object
        wmode = "xb" if mode == "create" else "wb"
        writer = self._rfs.open_write(self._strip(rpath), wmode, block_size=None, extra=extra)
        try:
            chunk_size = getattr(self, "default_block_size", None) or self.blocksize
            with open(lpath, "rb") as f:
                while chunk := f.read(chunk_size):
                    writer.write(chunk)
        except BaseException:
            writer.abort()
            raise
        writer.close()

    def _put_pairs(
        self, lpath: Any, rpath: Any, recursive: bool, maxdepth: int | None
    ) -> list[tuple[str, str]]:
        """``(local, remote)`` pairs of a ``put``, expanded as fsspec's
        ``put`` expands them."""
        if isinstance(lpath, list) and isinstance(rpath, list):
            return list(zip([os.fspath(p) for p in lpath], rpath))
        from fsspec.implementations.local import LocalFileSystem as _Local
        from fsspec.utils import other_paths

        lfs = _Local()
        lpaths = lfs.expand_path(lpath, recursive=recursive, maxdepth=maxdepth)
        if isinstance(lpath, str) and (not recursive or maxdepth is not None):
            lpaths = [p for p in lpaths if not lfs.isdir(p)]
        dest_is_dir = isinstance(rpath, str) and (rpath.endswith("/") or self.isdir(rpath))
        exists = isinstance(lpath, str) and (
            (has_magic(lpath) and len(lpaths) == 1)
            or (not has_magic(lpath) and dest_is_dir and not lpath.endswith("/"))
        )
        rpaths = other_paths(
            lpaths, self._strip_protocol(rpath), exists=exists, flatten=not isinstance(lpath, str)
        )
        return list(zip(lpaths, rpaths))

    # ------------------------------------------------------------------
    # mutations invalidate

    pipe_file = _invalidating(FsfastFileSystem.pipe_file)
    _pipe_file = _ainvalidating(FsfastFileSystem._pipe_file)
    touch = _invalidating(FsfastFileSystem.touch)
    _touch = _ainvalidating(FsfastFileSystem._touch)
    mkdir = _invalidating(FsfastFileSystem.mkdir)
    _mkdir = _ainvalidating(FsfastFileSystem._mkdir)
    makedirs = _invalidating(FsfastFileSystem.makedirs)
    _makedirs = _ainvalidating(FsfastFileSystem._makedirs)
    rmdir = _invalidating(FsfastFileSystem.rmdir)
    _rmdir = _ainvalidating(FsfastFileSystem._rmdir)
    rm_file = _invalidating(FsfastFileSystem.rm_file)
    _rm_file = _ainvalidating(FsfastFileSystem._rm_file)
    cp_file = _invalidating(FsfastFileSystem.cp_file, "path2")
    _cp_file = _ainvalidating(FsfastFileSystem._cp_file, "path2")
    _mv_file = _ainvalidating(FsfastFileSystem._mv_file, "path1", "path2")
    put_file = _invalidating(FsfastFileSystem.put_file, "rpath")
    _put_file = _ainvalidating(FsfastFileSystem._put_file, "rpath")

    def pipe(self, path: Any, value: Any = None, **kwargs: Any) -> None:
        try:
            super().pipe(path, value, **kwargs)
        finally:
            self._invalidate_paths(list(path) if isinstance(path, dict) else path)

    async def _pipe(self, path: Any, value: Any = None, batch_size: int | None = None, **kwargs: Any) -> Any:
        try:
            return await super()._pipe(path, value, batch_size=batch_size, **kwargs)
        finally:
            self._invalidate_paths(list(path) if isinstance(path, dict) else path)

    def rm(self, path: Any, recursive: bool = False, maxdepth: int | None = None) -> Any:
        paths, known = self._expand_kinds(path, recursive=recursive, maxdepth=maxdepth)
        try:
            return self._rm_expanded(paths, known)
        finally:
            for p in paths:
                self.invalidate_cache(p)

    async def _rm(
        self,
        path: Any,
        recursive: bool = False,
        batch_size: int | None = None,
        maxdepth: int | None = None,
        **kwargs: Any,
    ) -> Any:
        paths = await self._expand_path(path, recursive=recursive, maxdepth=maxdepth)
        try:
            return await self._rm_expanded_async(paths)
        finally:
            for p in paths:
                self.invalidate_cache(p)

    def _rm_dir_results(self, results: list[Any]) -> None:
        """Raise the first failure of a directory step of ``rm``; with
        :attr:`_rm_skips_nonempty_dirs` a non-empty directory is left
        alone instead."""
        for r in results:
            if _is_exc(r):
                if self._rm_skips_nonempty_dirs and isinstance(r, OSError) and r.errno == errno.ENOTEMPTY:
                    continue
                raise r

    def _rm_dirs(self, items: list[str]) -> None:
        self._rm_dir_results(self._rfs.rmdir_many(items, on_error="return", ignore_missing=True))

    async def _rm_dirs_async(self, items: list[str]) -> None:
        self._rm_dir_results(
            await self._rfs.rmdir_many_async(items, on_error="return", ignore_missing=True)
        )

    def _rm_expanded(self, paths: list[str], known: dict[str, str] | None = None) -> Any:
        # Paths not seen in a listing are deleted as objects first; only
        # failures (a prefix "directory" has no object: 404) are looked up.
        self._rm_run(paths, known or {})

    async def _rm_expanded_async(self, paths: list[str]) -> Any:
        await self._rm_run_async(paths, {})

    def copy(self, path1: Any, path2: Any, recursive: bool = False, maxdepth: int | None = None, on_error: str | None = None, **kwargs: Any) -> None:
        try:
            super().copy(path1, path2, recursive=recursive, maxdepth=maxdepth, on_error=on_error, **kwargs)
        finally:
            # The batch copy bypasses the per-file invalidating cp_file.
            self._invalidate_paths(path2, tree=True)

    def mv(self, path1: Any, path2: Any, recursive: bool = False, maxdepth: int | None = None, **kwargs: Any) -> None:
        try:
            super().mv(path1, path2, recursive=recursive, maxdepth=maxdepth, **kwargs)
        finally:
            self._invalidate_paths([path1, path2], tree=True)

    def put(self, lpath: Any, rpath: Any, recursive: bool = False, callback: Any = None, maxdepth: int | None = None, **kwargs: Any) -> None:
        from fsspec.callbacks import DEFAULT_CALLBACK

        if recursive and isinstance(lpath, (str, os.PathLike)) and isinstance(rpath, str) and os.path.isdir(lpath):
            # fsspec's put calls makedirs for every directory it uploads,
            # which on s3fs/adlfs creates a missing bucket/container (and is
            # a no-op on gcsfs). Prefixes need nothing, so one makedirs of
            # the target's bucket does the same.
            bucket = self._strip(rpath).split("/", 1)[0]
            if bucket and not self.exists(bucket):
                # Expand while the target is still missing (fsspec copies
                # the directory's contents to a new target), then create
                # the bucket; the expanded lists are uploaded as given.
                pairs = self._put_pairs(lpath, rpath, recursive, maxdepth)
                self.makedirs(bucket, exist_ok=True)
                if not pairs:
                    return
                lpath, rpath = [lp for lp, _ in pairs], [rp for _, rp in pairs]
        try:
            super().put(lpath, rpath, recursive=recursive, callback=callback or DEFAULT_CALLBACK, maxdepth=maxdepth, **kwargs)
        finally:
            # The batch upload bypasses the per-file invalidating put_file.
            self._invalidate_paths(rpath, tree=True)
