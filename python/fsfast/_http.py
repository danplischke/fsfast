"""fsfast's ``http://`` / ``https://`` filesystem: a drop-in for
``fsspec.implementations.http.HTTPFileSystem``."""

from __future__ import annotations

import os
import re
from typing import Any

from fsspec.callbacks import DEFAULT_CALLBACK
from fsspec.spec import AbstractFileSystem
from fsspec.utils import glob_translate, tokenize

from ._base import FsfastFileSystem

__all__ = ["HTTPFileSystem"]

#: fsspec http: "?" is not a glob character in URLs.
_MAGIC = re.compile("([*[])")


def _has_magic(s: str) -> bool:
    return _MAGIC.search(s) is not None


class HTTPFileSystem(FsfastFileSystem):
    """Drop-in replacement for ``fsspec.implementations.http.HTTPFileSystem``.

    Same constructor (``simple_links``, ``block_size``, ``same_scheme``,
    ``cache_type``, ``cache_options``, ``client_kwargs``, ``encoded`` and
    per-request keywords such as ``headers``, ``auth``, ``params``,
    ``timeout``) plus fsfast's transport options. Paths are full URLs.
    ``get_client`` (an aiohttp session factory) cannot be used by the Rust
    client and raises ``NotImplementedError`` when given.

    Unlike fsspec's class, files can also be opened for writing (a PUT, or
    POST with ``method="post"``) and HTTP failures other than 404 raise the
    matching ``OSError`` subclass (``PermissionError`` for 401/403, ...)
    instead of ``aiohttp.ClientResponseError``.
    """

    protocol = ("http", "https")
    sep = "/"
    root_marker = ""
    _rust_protocol = "http"
    # No rename over HTTP: deferred writes are uploaded at commit.
    _spool_transactions = True
    # The reference uploads pipe_file directly, even in a transaction.
    _pipe_defers_in_transaction = False
    # No directories to create: put() skips local directories.
    _implicit_dirs = True

    def __init__(
        self,
        simple_links: bool = True,
        block_size: int | None = None,
        same_scheme: bool = True,
        size_policy: Any = None,
        cache_type: str = "bytes",
        cache_options: dict[str, Any] | None = None,
        asynchronous: bool = False,
        loop: Any = None,
        client_kwargs: dict[str, Any] | None = None,
        get_client: Any = None,
        encoded: bool = False,
        **storage_options: Any,
    ) -> None:
        if self._cached:
            return
        if get_client is not None:
            raise NotImplementedError(
                "fsfast.HTTPFileSystem cannot use an aiohttp get_client factory; "
                "pass client_kwargs / request options instead"
            )
        from fsspec.implementations.http import DEFAULT_BLOCK_SIZE  # noqa: PLC0415

        self.block_size = block_size if block_size is not None else DEFAULT_BLOCK_SIZE
        self.simple_links = simple_links
        self.same_schema = same_scheme
        self.cache_type = cache_type
        self.cache_options = cache_options
        self.client_kwargs = client_kwargs or {}
        self.encoded = encoded
        request_options = storage_options.copy()
        # fsspec's http caches listings only when asked to.
        self.use_listings_cache = request_options.pop("use_listings_cache", False)
        for k in ("listings_expiry_time", "max_paths", "skip_instance_cache"):
            request_options.pop(k, None)
        self.kwargs = request_options
        opts: dict[str, Any] = dict(storage_options)
        opts.update(
            simple_links=simple_links,
            block_size=block_size,
            same_scheme=same_scheme,
            cache_type=cache_type,
            cache_options=cache_options,
            client_kwargs=client_kwargs,
            encoded=encoded,
        )
        opts = {k: v for k, v in opts.items() if v is not None}
        super().__init__(asynchronous=asynchronous, loop=loop, **opts)

    @property
    def fsid(self) -> str:
        return "http"

    @classmethod
    def _strip_protocol(cls, path: Any) -> Any:
        """For HTTP, the full URL is the path."""
        return path

    @classmethod
    def _parent(cls, path: str) -> str:
        par = AbstractFileSystem._parent.__func__(cls, path)  # type: ignore[attr-defined]
        if len(par) > 7:  # "http://..."
            return par
        return ""

    def ukey(self, url: str) -> str:
        """Unique identifier; HTTP files are assumed static."""
        return tokenize(url, self.kwargs, self.protocol)

    # ------------------------------------------------------------------
    # listings (cached in dircache, like fsspec)

    def ls(self, url: Any, detail: bool = True, **kwargs: Any) -> list[Any]:
        if self.use_listings_cache and url in self.dircache:
            out = self.dircache[url]
        else:
            out = self._rfs.ls(url, detail=detail)
            self.dircache[url] = out
        return out

    async def _ls(self, url: Any, detail: bool = True, **kwargs: Any) -> list[Any]:
        if self.use_listings_cache and url in self.dircache:
            out = self.dircache[url]
        else:
            out = await self._rfs.ls_async(url, detail=detail)
            self.dircache[url] = out
        return out

    def isdir(self, path: Any) -> bool:
        try:
            return bool(self.ls(path))
        except (FileNotFoundError, ValueError):
            return False

    async def _isdir(self, path: Any) -> bool:
        try:
            return bool(await self._ls(path))
        except (FileNotFoundError, ValueError):
            return False

    def isfile(self, path: Any, **kwargs: Any) -> bool:
        return self.exists(path, **kwargs)

    async def _isfile(self, path: Any, **kwargs: Any) -> bool:
        return await self._exists(path, **kwargs)

    def exists(self, path: Any, strict: bool = False, **kwargs: Any) -> bool:
        try:
            return self._rfs.exists(path)
        except FileNotFoundError:
            return False
        except Exception:
            if strict:
                raise
            return False

    async def _exists(self, path: Any, strict: bool = False, **kwargs: Any) -> bool:
        try:
            return await self._rfs.exists_async(path)
        except FileNotFoundError:
            return False
        except Exception:
            if strict:
                raise
            return False

    def du(self, path: Any, total: bool = True, maxdepth: int | None = None, withdirs: bool = False, **kwargs: Any) -> Any:
        # Listings carry no sizes: fsspec's (async) du asks info() for each
        # file; fsfast does that as one concurrent batch.
        names = self.find(path, maxdepth=maxdepth, withdirs=withdirs)
        infos = self._rfs.info_many(names, on_error="raise")
        sizes = {i["name"]: i["size"] for i in infos}
        return sum(sizes.values()) if total else sizes

    async def _du(self, path: Any, total: bool = True, maxdepth: int | None = None, **kwargs: Any) -> Any:
        names = await self._find(path, maxdepth=maxdepth, **kwargs)
        infos = await self._rfs.info_many_async(names, on_error="raise")
        sizes = {i["name"]: i["size"] for i in infos}
        return sum(sizes.values()) if total else sizes

    # ------------------------------------------------------------------
    # glob: "?" is literal (query strings)

    def _glob_plan(self, path: str, maxdepth: int | None) -> tuple[str, int | None, bool, str]:
        ends_with_slash = path.endswith("/")
        path = self._strip_protocol(path)
        append_slash = ends_with_slash or path.endswith(("/**", "/*"))
        idx_star = path.find("*") if path.find("*") >= 0 else len(path)
        idx_brace = path.find("[") if path.find("[") >= 0 else len(path)
        min_idx = min(idx_star, idx_brace)
        if "/" in path[:min_idx]:
            min_idx = path[:min_idx].rindex("/")
            root = path[: min_idx + 1]
            depth: int | None = path[min_idx + 1 :].count("/") + 1
        else:
            root = ""
            depth = path[min_idx + 1 :].count("/") + 1
        if "**" in path:
            if maxdepth is not None:
                idx_double_stars = path.find("**")
                depth_double_stars = path[idx_double_stars:].count("/") + 1
                depth = depth - depth_double_stars + maxdepth  # type: ignore[operator]
            else:
                depth = None
        return root, depth, append_slash, path + ("/" if ends_with_slash else "")

    @staticmethod
    def _glob_filter(allpaths: dict[str, Any], pattern_src: str, append_slash: bool, detail: bool) -> Any:
        pattern = re.compile(glob_translate(pattern_src))
        out = {
            (
                p.rstrip("/")
                if not append_slash and info["type"] == "directory" and p.endswith("/")
                else p
            ): info
            for p, info in sorted(allpaths.items())
            if pattern.match(p.rstrip("/"))
        }
        return out if detail else list(out)

    def glob(self, path: Any, maxdepth: int | None = None, **kwargs: Any) -> Any:
        if maxdepth is not None and maxdepth < 1:
            raise ValueError("maxdepth must be at least 1")
        detail = kwargs.pop("detail", False)
        if not _has_magic(path):
            if self.exists(path):
                return {path: self.info(path)} if detail else [path]
            return {} if detail else []
        root, depth, append_slash, pattern = self._glob_plan(path, maxdepth)
        allpaths = self.find(root, maxdepth=depth, withdirs=True, detail=True)
        return self._glob_filter(allpaths, pattern, append_slash, detail)

    async def _glob(self, path: Any, maxdepth: int | None = None, **kwargs: Any) -> Any:
        if maxdepth is not None and maxdepth < 1:
            raise ValueError("maxdepth must be at least 1")
        detail = kwargs.pop("detail", False)
        if not _has_magic(path):
            if await self._exists(path):
                return {path: await self._info(path)} if detail else [path]
            return {} if detail else []
        root, depth, append_slash, pattern = self._glob_plan(path, maxdepth)
        allpaths = await self._find(root, maxdepth=depth, withdirs=True, detail=True)
        return self._glob_filter(allpaths, pattern, append_slash, detail)

    # ------------------------------------------------------------------
    # files

    def put_file(
        self,
        lpath: Any,
        rpath: Any,
        callback: Any = DEFAULT_CALLBACK,
        mode: str = "overwrite",
        **kwargs: Any,
    ) -> None:
        """Upload a local file, or a readable file object as fsspec's http
        allows, with PUT (``method="post"`` to POST); request keywords
        apply to the upload."""
        kwargs.pop("chunk_size", None)
        if not kwargs and not hasattr(lpath, "read"):
            return super().put_file(lpath, rpath, callback=callback, mode=mode)
        source = lpath if hasattr(lpath, "read") else open(os.fspath(lpath), "rb")  # noqa: SIM115
        try:
            writer = self._rfs.open_write(rpath, "xb" if mode == "create" else "wb", block_size=None, extra=kwargs or None)
            try:
                while chunk := source.read(self.block_size or 2**22):
                    writer.write(chunk)
                    callback.relative_update(len(chunk))
            except BaseException:
                writer.abort()
                raise
            writer.close()
        finally:
            if source is not lpath:
                source.close()

    def pipe_file(self, path: Any, value: Any, mode: str = "overwrite", **kwargs: Any) -> None:
        """PUT ``value`` to ``path`` (``method="post"`` to POST)."""
        self._rfs.pipe_file(path, self._payload(value), mode, kwargs or None)

    async def _pipe_file(self, path: Any, value: Any, mode: str = "overwrite", **kwargs: Any) -> None:
        await self._rfs.pipe_file_async(path, self._payload(value), mode, kwargs or None)

    def _open(
        self,
        path: Any,
        mode: str = "rb",
        block_size: int | None = None,
        autocommit: Any = None,
        cache_type: str | None = None,
        cache_options: dict[str, Any] | None = None,
        size: int | None = None,
        **kwargs: Any,
    ) -> Any:
        from ._file import FsfastFile

        if mode == "rb":
            block_size = block_size if block_size is not None else self.block_size
        return FsfastFile(
            self,
            path,
            mode,
            block_size=block_size or None,
            autocommit=True if autocommit is None else autocommit,
            cache_type=cache_type or "readahead",
            cache_options=cache_options or self.cache_options,
            extra=kwargs or None,
        )
