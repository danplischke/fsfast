"""fsfast's ``http://`` / ``https://`` filesystem: a drop-in for
``fsspec.implementations.http.HTTPFileSystem``."""

from __future__ import annotations

import functools
import inspect
import os
import re
from collections.abc import Callable
from typing import Any

from fsspec.callbacks import DEFAULT_CALLBACK
from fsspec.spec import AbstractFileSystem
from fsspec.utils import glob_translate, tokenize

from . import _core
from ._base import FsfastFileSystem

__all__ = ["HTTPFileSystem"]

#: fsspec http: "?" is not a glob character in URLs.
_MAGIC = re.compile("([*[])")

#: Per-call keywords that fsspec's http merges into every request
#: (``kw = self.kwargs.copy(); kw.update(kwargs)``) and the Rust client
#: understands as request options (``apply_request_kwargs``).
_REQUEST_KWARGS = frozenset(
    {
        "headers",
        "auth",
        "timeout",
        "ssl",
        "verify_ssl",
        "proxy",
        "proxy_auth",
        "allow_redirects",
        "max_redirects",
        "cookies",
        "params",
    }
)

#: Clients built for distinct per-call request options kept per instance.
_MAX_REQUEST_CLIENTS = 16


def _per_request(method: Callable[..., Any]) -> Callable[..., Any]:
    """Apply per-call request keywords (``headers=``, ``auth=``, ...) to
    every request ``method`` makes, as fsspec's http does: the method runs
    on a view of the filesystem whose Rust client has the instance's
    options updated with them."""
    if inspect.iscoroutinefunction(method):

        @functools.wraps(method)
        async def awrapper(self: HTTPFileSystem, *args: Any, **kwargs: Any) -> Any:
            return await method(self._for_request(kwargs), *args, **kwargs)

        return awrapper

    @functools.wraps(method)
    def wrapper(self: HTTPFileSystem, *args: Any, **kwargs: Any) -> Any:
        return method(self._for_request(kwargs), *args, **kwargs)

    return wrapper


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
    # fsspec's http is an AsyncFileSystem.
    _fsspec_batches = True

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

    def _rust_options(self, storage_options: dict[str, Any]) -> dict[str, Any]:
        opts = super()._rust_options(storage_options)
        # Kept to build clients for per-call request options.
        self._base_rust_options = dict(opts)
        return opts

    def _request_rfs(self, request: dict[str, Any]) -> Any:
        """The Rust filesystem for per-call request options: the instance's
        options updated with ``request`` (one client per distinct set,
        reused; a few are kept)."""
        clients: dict[str, Any] = self.__dict__.setdefault("_request_clients", {})
        key = tokenize(request)
        rfs = clients.get(key)
        if rfs is None:
            opts = dict(self._base_rust_options)
            opts.update(request)
            rfs = _core.make_filesystem(self._rust_protocol, opts)
            while len(clients) >= _MAX_REQUEST_CLIENTS:
                clients.pop(next(iter(clients))).close()
            clients[key] = rfs
        return rfs

    def _for_request(self, kwargs: dict[str, Any]) -> HTTPFileSystem:
        """Remove the request keywords from ``kwargs``; with any, return a
        view of this filesystem (same state, dircache shared) whose requests
        carry them, else ``self``."""
        request = {k: kwargs.pop(k) for k in [k for k in kwargs if k in _REQUEST_KWARGS]}
        if not request:
            return self
        view = object.__new__(type(self))
        view.__dict__.update(self.__dict__)
        view._rfs = self._request_rfs(request)
        return view

    def close(self) -> None:
        super().close()
        for rfs in list(self.__dict__.get("_request_clients", {}).values()):
            rfs.close()

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

    @_per_request
    def ls(self, url: Any, detail: bool = True, **kwargs: Any) -> list[Any]:
        if self.use_listings_cache and url in self.dircache:
            out = self.dircache[url]
        else:
            out = self._rfs.ls(url, detail=detail)
            self.dircache[url] = out
        return out

    @_per_request
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

    @_per_request
    def exists(self, path: Any, strict: bool = False, **kwargs: Any) -> bool:
        try:
            return self._rfs.exists(path)
        except FileNotFoundError:
            return False
        except Exception:
            if strict:
                raise
            return False

    @_per_request
    async def _exists(self, path: Any, strict: bool = False, **kwargs: Any) -> bool:
        try:
            return await self._rfs.exists_async(path)
        except FileNotFoundError:
            return False
        except Exception:
            if strict:
                raise
            return False

    @_per_request
    def du(self, path: Any, total: bool = True, maxdepth: int | None = None, withdirs: bool = False, **kwargs: Any) -> Any:
        # Listings carry no sizes: fsspec's (async) du asks info() for each
        # file; fsfast does that as one concurrent batch.
        names = self.find(path, maxdepth=maxdepth, withdirs=withdirs)
        infos = self._rfs.info_many(names, on_error="raise")
        sizes = {i["name"]: i["size"] for i in infos}
        return sum(sizes.values()) if total else sizes

    @_per_request
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

    @_per_request
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

    @_per_request
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

        rust_fs = None
        if mode == "rb":
            block_size = block_size if block_size is not None else self.block_size
            # Request options apply to every request of the file (the
            # metadata request at open and the ranged reads).
            rust_fs = self._for_request(kwargs)._rfs
        return FsfastFile(
            self,
            path,
            mode,
            block_size=block_size or None,
            autocommit=True if autocommit is None else autocommit,
            cache_type=cache_type or "readahead",
            cache_options=cache_options or self.cache_options,
            extra=kwargs or None,
            rust_fs=rust_fs,
        )

    # Inherited methods that make requests take per-call request options
    # too (fsspec's http passes ``**kwargs`` to every request).
    info = _per_request(FsfastFileSystem.info)
    _info = _per_request(FsfastFileSystem._info)
    cat_file = _per_request(FsfastFileSystem.cat_file)
    _cat_file = _per_request(FsfastFileSystem._cat_file)
    cat = _per_request(FsfastFileSystem.cat)
    _cat = _per_request(FsfastFileSystem._cat)
    cat_ranges = _per_request(FsfastFileSystem.cat_ranges)
    _cat_ranges = _per_request(FsfastFileSystem._cat_ranges)
    find = _per_request(FsfastFileSystem.find)
    _find = _per_request(FsfastFileSystem._find)
    get_file = _per_request(FsfastFileSystem.get_file)
    _get_file = _per_request(FsfastFileSystem._get_file)
    get = _per_request(FsfastFileSystem.get)
