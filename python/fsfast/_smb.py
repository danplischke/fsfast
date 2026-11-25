"""fsfast's ``smb://`` filesystem: a drop-in for
``fsspec.implementations.smb.SMBFileSystem``."""

from __future__ import annotations

import datetime
from typing import Any

from fsspec.asyn import AsyncFileSystem
from fsspec.spec import AbstractFileSystem
from fsspec.utils import infer_storage_options

from ._base import FsfastFileSystem

__all__ = ["SMBFileSystem"]


def _share_has_path(path: str) -> bool:
    parts = path.count("/")
    if path.endswith("/"):
        return parts > 2
    return parts > 1


def _bare_dir_keys(found: dict[str, Any]) -> dict[str, Any]:
    return {(k.rstrip("/") if v["type"] == "directory" else k): v for k, v in found.items()}


class _GlobView:
    """``glob`` runs fsspec's algorithm over this view of the filesystem,
    whose ``find`` keys directories without the trailing ``/`` that fsspec's
    smb names carry.

    fsspec's smb ``glob("dir/*")`` never matches a subdirectory: its find
    keys are ``"dir/sub/"`` and the pattern does not match the trailing
    ``/``. So ``get``/``cp``/``rm`` of a glob with ``recursive=True``
    silently skip every matched directory there. fsfast matches the
    directories, as fsspec's glob does on every other backend (and as its
    abstract test suite requires); see docs/dev/python-parity.md.
    """

    def __init__(self, fs: SMBFileSystem) -> None:
        self._fs = fs

    def __getattr__(self, name: str) -> Any:
        return getattr(self._fs, name)

    def find(self, path: Any, **kwargs: Any) -> Any:
        return _bare_dir_keys(self._fs.find(path, **kwargs))

    async def _find(self, path: Any, **kwargs: Any) -> Any:
        return _bare_dir_keys(await self._fs._find(path, **kwargs))


class SMBFileSystem(FsfastFileSystem):
    """Drop-in replacement for ``fsspec.implementations.smb.SMBFileSystem``.

    Same constructor (``host``, ``port``, ``username``, ``password``,
    ``timeout``, ``encrypt``, ``share_access``, ``register_session_*``,
    ``auto_mkdir``, ``temppath``) plus fsfast's SMB tuning options
    (``connections``, ``max_inflight``, ``read_chunk_size``, ...). Like
    fsspec's class it authenticates at construction, so bad credentials or
    an unreachable host fail here.

    Paths are ``/share/dir/file``. Failures raise the precise ``OSError``
    subclass (``FileNotFoundError``, ...) with the errno smbprotocol's
    ``SMBOSError`` would carry.
    """

    protocol = "smb"
    root_marker = ""
    _put_makes_parents = True
    # fsspec's generic touch (open(path, "wb")) is deferred in a transaction.
    _touch_defers_in_transaction = True
    _rust_protocol = "smb"

    def __init__(
        self,
        host: str,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        timeout: int = 60,
        encrypt: bool | None = None,
        share_access: str | None = None,
        register_session_retries: int = 4,
        register_session_retry_wait: float = 1,
        register_session_retry_factor: float = 10,
        auto_mkdir: bool = False,
        **kwargs: Any,
    ) -> None:
        if self._cached:
            return
        if register_session_retry_wait < 0:
            raise ValueError("register_session_retry_wait must be a non-negative integer")
        if register_session_retry_factor < 1:
            raise ValueError(
                "register_session_retry_factor must be a positive "
                "integer equal to or greater than 1"
            )
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.encrypt = encrypt
        self.temppath = kwargs.get("temppath", "")
        self.share_access = share_access
        self.register_session_retries = register_session_retries
        self.register_session_retry_wait = register_session_retry_wait
        self.register_session_retry_factor = register_session_retry_factor
        self.auto_mkdir = auto_mkdir
        opts: dict[str, Any] = dict(kwargs)
        opts.update(
            host=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            encrypt=encrypt,
            share_access=share_access,
            register_session_retries=register_session_retries,
            register_session_retry_wait=register_session_retry_wait,
            register_session_retry_factor=register_session_retry_factor,
            auto_mkdir=auto_mkdir,
        )
        super().__init__(**{k: v for k, v in opts.items() if v is not None})
        # fsspec registers the session eagerly (with its retry schedule).
        self._rfs.call("connect")

    @property
    def _port(self) -> int:
        return 445 if self.port is None else self.port

    @classmethod
    def _strip_protocol(cls, path: Any) -> str:
        return infer_storage_options(path)["path"]

    @staticmethod
    def _get_kwargs_from_urls(path: str) -> dict[str, Any]:
        out = infer_storage_options(path)
        out.pop("path", None)
        out.pop("protocol", None)
        return out

    # ------------------------------------------------------------------
    # fsspec smb semantics

    @staticmethod
    def _named(path: str, info: dict[str, Any]) -> dict[str, Any]:
        # fsspec names the entry after the path as given, with "/" appended
        # for directories.
        info["name"] = path + "/" if info["type"] == "directory" else path
        return info

    def info(self, path: Any, **kwargs: Any) -> dict[str, Any]:
        p = self._strip(path)
        return self._named(p, self._rfs.info(p))

    async def _info(self, path: Any, **kwargs: Any) -> dict[str, Any]:
        p = self._strip(path)
        return self._named(p, await self._rfs.info_async(p))

    def _rekey(self, root: str, found: Any, detail: bool) -> Any:
        # fsspec's find keys entries by info["name"] (directories end with
        # "/") and the root by the path as given, sorted by those keys.
        bare = root.rstrip("/")
        out = {}
        for name, info in found.items():
            out[root if name.rstrip("/") == bare else info["name"]] = info
        out = {k: out[k] for k in sorted(out)}
        return out if detail else list(out)

    def find(
        self,
        path: Any,
        maxdepth: int | None = None,
        withdirs: bool = False,
        detail: bool = False,
        **kwargs: Any,
    ) -> Any:
        found = super().find(path, maxdepth=maxdepth, withdirs=withdirs, detail=True)
        return self._rekey(self._strip(path), found, detail)

    async def _find(
        self,
        path: Any,
        maxdepth: int | None = None,
        withdirs: bool = False,
        **kwargs: Any,
    ) -> Any:
        detail = kwargs.pop("detail", False)
        found = await super()._find(path, maxdepth=maxdepth, withdirs=withdirs, detail=True)
        return self._rekey(self._strip(path), found, detail)

    def glob(self, path: Any, maxdepth: int | None = None, **kwargs: Any) -> Any:
        return AbstractFileSystem.glob(_GlobView(self), path, maxdepth=maxdepth, **kwargs)  # type: ignore[arg-type]

    async def _glob(self, path: Any, maxdepth: int | None = None, **kwargs: Any) -> Any:
        return await AsyncFileSystem._glob(_GlobView(self), path, maxdepth=maxdepth, **kwargs)  # type: ignore[arg-type]

    def ls(self, path: Any, detail: bool = True, **kwargs: Any) -> list[Any]:
        p = self._strip(path)
        out = self._rfs.ls(p, detail=True)
        if len(out) == 1 and out[0]["type"] != "directory" and out[0]["name"] == p:
            # The core contract's ls of a file; smbclient refuses it.
            raise NotADirectoryError(20, "Not a directory", p)
        if detail:
            return out
        # fsspec joins the listed names to the path as given.
        base = p.rstrip("/")
        return [f"{base}/{o['name'].rstrip('/').rsplit('/', 1)[-1]}" for o in out]

    async def _ls(self, path: Any, detail: bool = True, **kwargs: Any) -> list[Any]:
        p = self._strip(path)
        out = await self._rfs.ls_async(p, detail=True)
        if len(out) == 1 and out[0]["type"] != "directory" and out[0]["name"] == p:
            # The core contract's ls of a file; smbclient refuses it.
            raise NotADirectoryError(20, "Not a directory", p)
        if detail:
            return out
        base = p.rstrip("/")
        return [f"{base}/{o['name'].rstrip('/').rsplit('/', 1)[-1]}" for o in out]

    def makedirs(self, path: Any, exist_ok: bool = False) -> None:
        if _share_has_path(self._strip(path)):
            super().makedirs(path, exist_ok=exist_ok)

    async def _makedirs(self, path: Any, exist_ok: bool = False) -> None:
        if _share_has_path(self._strip(path)):
            await super()._makedirs(path, exist_ok=exist_ok)

    def rmdir(self, path: Any) -> None:
        if _share_has_path(self._strip(path)):
            super().rmdir(path)

    def modified(self, path: Any) -> datetime.datetime:
        """Last modification time as a timezone-aware UTC datetime."""
        return datetime.datetime.fromtimestamp(self.info(path)["mtime"], tz=datetime.timezone.utc)

    async def _modified(self, path: Any) -> datetime.datetime:
        info = await self._info(path)
        return datetime.datetime.fromtimestamp(info["mtime"], tz=datetime.timezone.utc)

    def mv(self, path1: Any, path2: Any, recursive: Any = None, maxdepth: Any = None, **kwargs: Any) -> None:
        """Rename (one server-side operation; directories move whole)."""
        self._rfs.mv_file(self._strip(path1), self._strip(path2))

    def _open(
        self,
        path: Any,
        mode: str = "rb",
        block_size: int | None = -1,
        autocommit: bool = True,
        cache_options: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        share_access = kwargs.pop("share_access", self.share_access)
        if share_access != self.share_access:
            raise NotImplementedError(
                "fsfast.SMBFileSystem applies share_access per filesystem; create one with "
                f"share_access={share_access!r} instead of overriding it in open()"
            )
        if block_size is not None and block_size < 0:
            block_size = None
        return super()._open(
            path,
            mode=mode,
            block_size=block_size,
            autocommit=autocommit,
            cache_options=cache_options,
            **kwargs,
        )

    def _transaction_temp_path(self, path: str) -> str:
        # fsspec: /<share><temppath>/<uuid>
        import uuid

        share = path.split("/")[1]
        temppath = self.temppath
        return f"/{share}{temppath}/{uuid.uuid4()}"

    def connection_info(self, share: str) -> dict[str, Any]:
        """Diagnostics of the connection serving ``share`` (dialect,
        signing, encryption, server limits)."""
        return self._rfs.call("connection_info", {"share": share.strip("/").split("/")[0]})
