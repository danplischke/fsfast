"""fsfast's ``abfs://`` / ``az://`` / ``abfss://`` filesystem: a drop-in for
``adlfs.AzureBlobFileSystem``."""

from __future__ import annotations

import os
import re
import warnings
from typing import Any
from urllib.parse import parse_qs

from fsspec.callbacks import DEFAULT_CALLBACK
from fsspec.utils import infer_storage_options

from ._objstore import ObjectStoreFileSystem

__all__ = ["AzureBlobFileSystem"]

_ROOT_PATH = "/"
#: adlfs ``_DEFAULT_BLOCK_SIZE`` (the ``blocksize`` attribute of the
#: filesystem and of its files).
_DEFAULT_BLOCK_SIZE = 50 * 2**20
_STORAGE_SCOPE = "https://storage.azure.com/.default"


def _check_maxdepth(maxdepth: int | None) -> None:
    if maxdepth is not None and maxdepth < 1:
        raise ValueError("maxdepth must be at least 1")


def _credential_option(credential: Any) -> Any:
    """adlfs ``credential`` values as fsfast-azure options.

    Strings and dicts pass through. ``azure.core`` credential objects are
    converted: ``AzureNamedKeyCredential`` to ``{"account_name",
    "account_key"}``, ``AzureSasCredential`` to ``{"sas_token"}``, and a
    sync ``TokenCredential`` to a bearer token fetched now (``{"token",
    "expires_on"}``; it is not refreshed after it expires).
    """
    if credential is None or isinstance(credential, (str, dict)):
        return credential
    named = getattr(credential, "named_key", None)
    if named is not None and hasattr(named, "name") and hasattr(named, "key"):
        return {"account_name": named.name, "account_key": named.key}
    signature = getattr(credential, "signature", None)
    if isinstance(signature, str):
        return {"sas_token": signature}
    get_token = getattr(credential, "get_token", None)
    if callable(get_token):
        import inspect

        if inspect.iscoroutinefunction(get_token):
            raise NotImplementedError(
                "fsfast.AzureBlobFileSystem needs a synchronous credential "
                "(azure.identity, not azure.identity.aio)"
            )
        token = get_token(_STORAGE_SCOPE)
        return {"token": token.token, "expires_on": int(token.expires_on)}
    raise NotImplementedError(
        f"fsfast.AzureBlobFileSystem cannot use a {type(credential).__name__} credential"
    )


_CONTENT_SETTINGS: Any = None


def _content_settings(**fields: Any) -> Any:
    """``azure.storage.blob.ContentSettings`` when the Azure SDK is
    installed (adlfs's value type), else a dict with the same keys in the
    same order."""
    global _CONTENT_SETTINGS
    if _CONTENT_SETTINGS is None:
        try:
            from azure.storage.blob import ContentSettings
        except ImportError:  # the SDK is optional
            ContentSettings = dict  # noqa: N806
        _CONTENT_SETTINGS = ContentSettings
    return _CONTENT_SETTINGS(**fields)


_CS_FIELDS = (
    "content_type",
    "content_encoding",
    "content_language",
    "content_md5",
    "content_disposition",
    "cache_control",
)


def _content_settings_option(cs: Any) -> dict[str, Any] | None:
    """adlfs ``content_settings`` (a dict, the documented form, or an
    ``azure.storage.blob.ContentSettings``) as the fsfast-azure write
    option: a dict of the fields that are set."""
    if cs is None:
        return None
    if isinstance(cs, dict):
        fields = dict(cs)
    else:
        fields = {k: getattr(cs, k, None) for k in _CS_FIELDS}
    out = {k: v for k, v in fields.items() if v is not None}
    if isinstance(out.get("content_md5"), bytearray):
        out["content_md5"] = bytes(out["content_md5"])
    return out


def _write_extra(content_settings: Any = None, metadata: dict[str, str] | None = None) -> dict[str, Any] | None:
    """Per-call write options for the Rust backend (``None`` when there are
    none, so the batch paths stay in use)."""
    extra: dict[str, Any] = {}
    cs = _content_settings_option(content_settings)
    if cs:
        extra["content_settings"] = cs
    if metadata:
        extra["metadata"] = {str(k): str(v) for k, v in metadata.items()}
    return extra or None


class AzureBlobFileSystem(ObjectStoreFileSystem):
    """Drop-in replacement for ``adlfs.AzureBlobFileSystem``.

    Takes adlfs's constructor arguments (``account_name``,
    ``account_key``, ``connection_string``, ``sas_token``, ``credential``,
    ``client_id``/``client_secret``/``tenant_id``, ``anon``,
    ``account_host``, ``version_aware``, ...) plus fsfast's tuning options.
    Listings are cached in ``dircache`` as in adlfs.
    """

    protocol = ("abfs", "az", "abfss")
    root_marker = ""
    _rm_skips_nonempty_dirs = True
    _rust_protocol = "abfs"

    def __init__(
        self,
        account_name: str | None = None,
        account_key: str | None = None,
        connection_string: str | None = None,
        credential: Any = None,
        sas_token: str | None = None,
        request_session: Any = None,
        socket_timeout: Any = None,
        blocksize: int = _DEFAULT_BLOCK_SIZE,
        client_id: str | None = None,
        client_secret: str | None = None,
        tenant_id: str | None = None,
        anon: bool | None = None,
        location_mode: str = "primary",
        loop: Any = None,
        asynchronous: bool = False,
        default_fill_cache: bool = True,
        default_cache_type: str = "bytes",
        version_aware: bool = False,
        assume_container_exists: bool | None = None,
        max_concurrency: int | None = None,
        timeout: int | None = None,
        connection_timeout: int | None = None,
        read_timeout: int | None = None,
        account_host: str | None = None,
        **kwargs: Any,
    ) -> None:
        if self._cached:
            return
        self.kwargs = kwargs.copy()
        self.account_name = account_name
        self.account_key = account_key
        self.connection_string = connection_string
        self.sas_token = sas_token
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        if anon is not None:
            self.anon = anon
        else:
            # adlfs resolves the attribute from $AZURE_STORAGE_ANON (as the
            # Rust backend does for the connection).
            self.anon = os.getenv("AZURE_STORAGE_ANON", "false").lower() not in ("false", "0", "f", "")
        self.location_mode = location_mode
        self.blocksize = blocksize
        self.default_fill_cache = default_fill_cache
        self.default_cache_type = default_cache_type
        self.version_aware = version_aware
        self.assume_container_exists = assume_container_exists
        self.max_concurrency = max_concurrency
        self.timeout = timeout
        self.connection_timeout = connection_timeout
        self.read_timeout = read_timeout
        self.account_host = account_host
        self.credential = credential
        opts: dict[str, Any] = dict(kwargs)
        opts.update(
            account_name=account_name,
            account_key=account_key,
            connection_string=connection_string,
            credential=_credential_option(credential),
            sas_token=sas_token,
            blocksize=blocksize if blocksize != _DEFAULT_BLOCK_SIZE else None,
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
            anon=anon,
            location_mode=location_mode,
            default_fill_cache=default_fill_cache,
            default_cache_type=default_cache_type,
            version_aware=version_aware,
            assume_container_exists=assume_container_exists,
            max_concurrency=max_concurrency,
            timeout=timeout,
            connection_timeout=connection_timeout,
            read_timeout=read_timeout,
            account_host=account_host,
        )
        opts = {k: v for k, v in opts.items() if v is not None}
        super().__init__(asynchronous=asynchronous, loop=loop, **opts)

    # ------------------------------------------------------------------
    # paths (adlfs)

    @classmethod
    def _strip_protocol(cls, path: Any) -> Any:
        if isinstance(path, list):
            return [cls._strip_protocol(p) for p in path]
        store_suffix = ".dfs.core.windows.net"
        if isinstance(cls.protocol, str):
            starts: tuple[str, ...] = (f"{cls.protocol}://",)
        else:
            starts = tuple(f"{proto}://" for proto in cls.protocol)
        if not path.startswith(starts):
            path = "abfs://" + path.lstrip("/")
        ops = infer_storage_options(path)
        if "username" in ops:
            if ops.get("username", None):
                ops["path"] = ops["username"] + ops["path"]
        elif ops.get("host", None):
            if ops["host"].count(store_suffix) == 0:
                ops["path"] = ops["host"] + ops["path"]
        url_query = ops.get("url_query")
        if url_query is not None:
            ops["path"] = f"{ops['path']}?{url_query}"
        return ops["path"].lstrip("/")

    @staticmethod
    def _get_kwargs_from_urls(urlpath: str) -> dict[str, Any]:
        ops = infer_storage_options(urlpath)
        out: dict[str, Any] = {}
        host = ops.get("host", None)
        if host:
            match = re.match(r"(?P<account_name>.+)\.(dfs|blob)\.core\.windows\.net", host)
            if match:
                out["account_name"] = match.groupdict()["account_name"]
        url_query = ops.get("url_query")
        if url_query is not None and "versionid" in parse_qs(url_query):
            out["version_aware"] = True
        return out

    def split_path(
        self, path: str, delimiter: str = "/", return_container: bool = False, **kwargs: Any
    ) -> tuple[str, str, str | None]:
        """``(container, blob, version_id)`` of a path (adlfs ``split_path``)."""
        if path in ["", delimiter]:
            return "", "", None
        path = self._strip_protocol(path).lstrip(delimiter)
        if "/" not in path:
            return path, "", None
        container, keypart = path.split(delimiter, 1)
        key, _, version_id = keypart.partition("?versionid=")
        return container, key, version_id if self.version_aware and version_id else None

    # ------------------------------------------------------------------
    # cache entries in adlfs's shapes

    def _listing_key(self, path: Any) -> str:
        return self._strip_protocol(path).strip("/")

    def _dir_entry(self, path: str) -> dict[str, Any]:
        return {"name": path, "size": None, "type": "directory"}

    def _fix(self, entry: dict[str, Any]) -> dict[str, Any]:
        # adlfs's content_settings is azure's ContentSettings (a dict in
        # this key order) with content_md5 as a bytearray.
        cs = entry.get("content_settings")
        if isinstance(cs, dict):
            md5 = cs.get("content_md5")
            entry["content_settings"] = _content_settings(
                content_type=cs.get("content_type"),
                content_encoding=cs.get("content_encoding"),
                content_language=cs.get("content_language"),
                content_md5=bytearray(md5) if isinstance(md5, bytes) else md5,
                content_disposition=cs.get("content_disposition"),
                cache_control=cs.get("cache_control"),
            )
        return entry

    def _named(self, path: Any, info: dict[str, Any]) -> dict[str, Any]:
        # adlfs names a directory after the path as given (a trailing "/"
        # is kept).
        container, key, _ = self.split_path(path)
        full = f"{container}/{key}" if key else container
        if info["type"] == "directory" and info["name"] != full and key.endswith("/"):
            info = {**info, "name": full}
        return info

    def find(
        self,
        path: Any,
        maxdepth: int | None = None,
        withdirs: bool = False,
        detail: bool = False,
        prefix: str = "",
        **kwargs: Any,
    ) -> Any:
        # adlfs's find: a file path gives ``[path]`` and the root is never
        # listed. adlfs ignores ``maxdepth`` (so ``cp``/``rm``/``get`` with
        # ``maxdepth`` act on the whole tree); fsfast honours it, as
        # fsspec's contract (and its abstract test suite) requires.
        _check_maxdepth(maxdepth)
        full = self._listing_key(path)
        found = self._fix_all(self._rfs.find(full, None, True, True))
        return self._adlfs_find(full, found, withdirs, detail, maxdepth, prefix)

    async def _find(
        self,
        path: Any,
        withdirs: bool = False,
        prefix: str = "",
        maxdepth: int | None = None,
        **kwargs: Any,
    ) -> Any:
        _check_maxdepth(maxdepth)
        detail = kwargs.pop("detail", False)
        full = self._listing_key(path)
        found = self._fix_all(await self._rfs.find_async(full, None, True, True))
        return self._adlfs_find(full, found, withdirs, detail, maxdepth, prefix)

    @staticmethod
    def _adlfs_find(
        full: str,
        found: dict[str, Any],
        withdirs: bool,
        detail: bool,
        maxdepth: int | None = None,
        prefix: str = "",
    ) -> Any:
        if len(found) == 1:
            (only,) = found.values()
            if only["type"] == "file" and only["name"] == full:
                return [full]
        # adlfs's ``prefix=`` keeps the names starting with
        # ``path/prefix``. fsfast filters the listing of ``path`` (adlfs
        # lists with ``name_starts_with``; the result is the same, adlfs
        # transfers less for a narrow prefix of a large tree).
        cut = len(full) + 1
        target = f"{full}/{prefix.strip('/')}" if prefix else f"{full}/"
        out = {
            k: v
            for k, v in sorted(found.items())
            if k.startswith(target)
            and (withdirs or v["type"] != "directory")
            and (maxdepth is None or k[cut:].rstrip("/").count("/") < maxdepth)
        }
        return out if detail else list(out)

    def invalidate_cache(self, path: Any = None) -> None:
        # adlfs drops only the given path's listing (callers invalidate
        # parents themselves); fsfast also drops the ancestors, which is
        # never less correct.
        super().invalidate_cache(path)

    def info(self, path: Any, refresh: bool = False, **kwargs: Any) -> dict[str, Any]:
        p = self._listing_key(path)
        if p == "":
            return {"name": "", "size": None, "type": "directory"}
        if "/" not in p:
            if not refresh and _ROOT_PATH in self.dircache:
                out = [o for o in self.dircache[_ROOT_PATH] if o["name"] == p]
                if out:
                    return out[0]
            return self._fix(self._rfs.info(p))
        return self._named(path, super().info(path, refresh=refresh))

    async def _info(self, path: Any, refresh: bool = False, **kwargs: Any) -> dict[str, Any]:
        p = self._listing_key(path)
        if p == "":
            return {"name": "", "size": None, "type": "directory"}
        if "/" not in p:
            if not refresh and _ROOT_PATH in self.dircache:
                out = [o for o in self.dircache[_ROOT_PATH] if o["name"] == p]
                if out:
                    return out[0]
            return self._fix(await self._rfs.info_async(p))
        return self._named(path, await super()._info(path, refresh=refresh))

    def ls(
        self,
        path: Any,
        detail: bool = False,
        invalidate_cache: bool = False,
        delimiter: str = "/",
        return_glob: bool = False,
        version_id: str | None = None,
        versions: bool = False,
        **kwargs: Any,
    ) -> list[Any]:
        if versions or version_id:
            raise NotImplementedError("fsfast.AzureBlobFileSystem.ls does not list versions")
        if invalidate_cache:
            self.dircache.clear()
        return super().ls(self._ls_target(path), detail=detail, refresh=return_glob)

    async def _ls(
        self,
        path: Any,
        detail: bool = False,
        invalidate_cache: bool = False,
        delimiter: str = "/",
        return_glob: bool = False,
        version_id: str | None = None,
        versions: bool = False,
        **kwargs: Any,
    ) -> list[Any]:
        if versions or version_id:
            raise NotImplementedError("fsfast.AzureBlobFileSystem.ls does not list versions")
        if invalidate_cache:
            self.dircache.clear()
        return await super()._ls(self._ls_target(path), detail=detail, refresh=return_glob)

    def _ls_target(self, path: Any) -> Any:
        """adlfs lists the containers for ``""``, ``"."``, ``"*"`` and
        ``"/"`` (each optionally followed by ``/``)."""
        container, key, _ = self.split_path(path)
        if container in ("", ".", "*", "/") and key in ("", "/"):
            return ""
        return path

    @staticmethod
    def _names(out: list[dict[str, Any]]) -> list[str]:
        return sorted({o["name"] for o in out})

    # ------------------------------------------------------------------
    # directories

    # -- containers (adlfs: mkdir creates only top-level containers; any
    # path below a container is a no-op)

    def _probe_failed(self, container: str, exc: Exception) -> bool:
        # adlfs ``_container_exists``: with ``assume_container_exists=None``
        # a failed probe (e.g. no permission to read the container's
        # properties) warns and assumes the container exists.
        if self.assume_container_exists is None:
            warnings.warn(
                f"Failed to fetch container properties for {container}. Assume it exists already",
                stacklevel=4,
            )
            return True
        raise ValueError(f"Failed to fetch container properties for {container} for {exc}") from exc

    def _container_exists(self, container: str) -> bool:
        if self.assume_container_exists:
            return True
        try:
            self._rfs.info(container)
        except FileNotFoundError:
            return False
        except Exception as e:
            return self._probe_failed(container, e)
        return True

    async def _container_exists_async(self, container: str) -> bool:
        if self.assume_container_exists:
            return True
        try:
            await self._rfs.info_async(container)
        except FileNotFoundError:
            return False
        except Exception as e:
            return self._probe_failed(container, e)
        return True

    @staticmethod
    def _mkdir_check(container: str, exists: bool, create_parents: bool, exist_ok: bool) -> bool:
        """adlfs ``_mkdir``'s checks; returns whether to create the
        container."""
        if not create_parents and not exists:
            raise PermissionError("Azure Container does not exist.  Set create_parents=True to create!!")
        if exists and not exist_ok:
            raise FileExistsError(
                f"Cannot overwrite existing Azure container -- {container} already exists."
            )
        return not exists

    def makedir(self, path: Any, exist_ok: bool = False) -> None:
        """Create a container (adlfs ``makedir``: an existing container
        raises ``FileExistsError`` unless ``exist_ok``)."""
        self.mkdir(path, create_parents=True, exist_ok=exist_ok)

    def mkdir(self, path: Any, create_parents: bool = True, delimiter: str = "/", **kwargs: Any) -> None:
        container = self.split_path(path)[0]
        try:
            exists = self._container_exists(container)
            if self._mkdir_check(container, exists, create_parents, kwargs.get("exist_ok", True)):
                self._rfs.mkdir(container, True)
        finally:
            # The container (and with it the root listing) and the path.
            self.invalidate_cache(container)
            self.invalidate_cache(path)

    async def _mkdir(self, path: Any, create_parents: bool = True, delimiter: str = "/", **kwargs: Any) -> None:
        container = self.split_path(path)[0]
        try:
            exists = await self._container_exists_async(container)
            if self._mkdir_check(container, exists, create_parents, kwargs.get("exist_ok", True)):
                await self._rfs.mkdir_async(container, True)
        finally:
            # The container (and with it the root listing) and the path.
            self.invalidate_cache(container)
            self.invalidate_cache(path)

    def rmdir(self, path: Any, delimiter: str = "/", **kwargs: Any) -> None:
        """adlfs semantics: a container path deletes the container (with
        everything in it, one request); any path below a container, or a
        missing container, is a silent no-op (blob "directories" are
        prefixes)."""
        container, key, _ = self.split_path(self._strip(path), delimiter=delimiter)
        if key or not container:
            return
        try:
            self._rfs.info(container)
        except FileNotFoundError:
            return
        try:
            self._rfs.call("delete_container", {"container": container})
        finally:
            self.invalidate_cache(container)

    async def _rmdir(self, path: Any, delimiter: str = "/", **kwargs: Any) -> None:
        container, key, _ = self.split_path(self._strip(path), delimiter=delimiter)
        if key or not container:
            return
        try:
            await self._rfs.info_async(container)
        except FileNotFoundError:
            return
        try:
            await self._rfs.call_async("delete_container", {"container": container})
        finally:
            self.invalidate_cache(container)

    # ------------------------------------------------------------------
    # adlfs extras

    def url(
        self,
        path: Any,
        expires: int = 3600,
        content_disposition: str | None = None,
        content_encoding: str | None = None,
        content_language: str | None = None,
        content_type: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Read-only SAS URL for ``path`` (needs an account key)."""
        if content_disposition or content_encoding or content_language or content_type:
            raise NotImplementedError(
                "fsfast.AzureBlobFileSystem.url does not support content_* response overrides"
            )
        return self._rfs.sign(self._strip(path), float(expires))

    async def _url(self, path: Any, expires: int = 3600, **kwargs: Any) -> str:
        if any(kwargs.get(k) for k in ("content_disposition", "content_encoding", "content_language", "content_type")):
            raise NotImplementedError(
                "fsfast.AzureBlobFileSystem.url does not support content_* response overrides"
            )
        return await self._rfs.sign_async(self._strip(path), float(expires))

    def sign(self, path: Any, expiration: int = 100, **kwargs: Any) -> str:
        return self.url(path, expires=expiration, **kwargs)

    async def _sign(self, path: Any, expiration: int = 100, **kwargs: Any) -> str:
        return await self._url(path, expires=expiration, **kwargs)

    def getxattr(self, path: Any, attr: str) -> Any:
        """One metadata value of a blob."""
        meta = self.info(path).get("metadata", {})
        return meta[attr]

    def setxattrs(self, rpath: Any, **kwargs: Any) -> None:
        """Replace a blob's metadata with ``kwargs``."""
        try:
            self._rfs.call("set_metadata", {"path": self._strip(rpath), "metadata": kwargs})
        except FileNotFoundError:
            raise
        except Exception as e:
            raise FileNotFoundError(rpath) from e
        finally:
            self.invalidate_cache(self._parent(rpath))

    async def _setxattrs(self, rpath: Any, **kwargs: Any) -> None:
        try:
            await self._rfs.call_async("set_metadata", {"path": self._strip(rpath), "metadata": kwargs})
        finally:
            self.invalidate_cache(self._parent(rpath))

    def modified(self, path: Any) -> Any:
        return self.info(path)["last_modified"]

    async def _modified(self, path: Any) -> Any:
        return (await self._info(path))["last_modified"]

    def created(self, path: Any) -> Any:
        return self.info(path)["creation_time"]

    async def _created(self, path: Any) -> Any:
        return (await self._info(path))["creation_time"]

    def _open(
        self,
        path: Any,
        mode: str = "rb",
        block_size: int | None = None,
        autocommit: bool = True,
        cache_options: dict[str, Any] | None = None,
        cache_type: str | None = None,
        metadata: dict[str, str] | None = None,
        version_id: str | None = None,
        **kwargs: Any,
    ) -> Any:
        from ._file import FsfastFile

        extra = None
        if mode != "rb":
            extra = _write_extra(kwargs.pop("content_settings", None), metadata)
        # An explicit size (here or on the filesystem) sets the Rust
        # handle's block size; otherwise the backend's tuned defaults apply
        # (8 MiB upload blocks and ranged reads), while ``f.blocksize``
        # reports adlfs's value.
        explicit = block_size or (self.blocksize if self.blocksize != _DEFAULT_BLOCK_SIZE else None)
        f = FsfastFile(
            self,
            self._strip(path),
            mode,
            block_size=explicit,
            autocommit=autocommit,
            cache_type="readahead" if cache_type is None else cache_type,
            cache_options=cache_options,
            version=version_id,
            extra=extra,
        )
        f.blocksize = block_size or self.blocksize
        return f

    # -- writes with adlfs's per-call ``content_settings=``

    @staticmethod
    def _pipe_mode(mode: str, overwrite: bool | None) -> str:
        # adlfs: ``overwrite=False`` (or fsspec's ``mode="create"``) fails
        # on an existing blob.
        return "create" if overwrite is False else mode

    def pipe_file(
        self, path: Any, value: Any, overwrite: bool = True, max_concurrency: int | None = None, **kwargs: Any
    ) -> None:
        mode = self._pipe_mode(kwargs.pop("mode", "overwrite"), overwrite)
        extra = _write_extra(kwargs.pop("content_settings", None))
        try:
            self._rfs.pipe_file(self._strip(path), self._payload(value), mode, extra)
        finally:
            self.invalidate_cache(path)

    async def _pipe_file(
        self, path: Any, value: Any, overwrite: bool = True, max_concurrency: int | None = None, **kwargs: Any
    ) -> None:
        mode = self._pipe_mode(kwargs.pop("mode", "overwrite"), overwrite)
        extra = _write_extra(kwargs.pop("content_settings", None))
        try:
            await self._rfs.pipe_file_async(self._strip(path), self._payload(value), mode, extra)
        finally:
            self.invalidate_cache(path)

    def put_file(
        self,
        lpath: Any,
        rpath: Any,
        callback: Any = None,
        mode: str = "overwrite",
        overwrite: bool = True,
        **kwargs: Any,
    ) -> None:
        callback = callback or DEFAULT_CALLBACK
        kwargs.pop("delimiter", None)
        kwargs.pop("max_concurrency", None)
        mode = self._pipe_mode(mode, overwrite)
        extra = _write_extra(kwargs.pop("content_settings", None))
        if extra is None:
            return super().put_file(lpath, rpath, callback=callback, mode=mode)
        lpath = os.fspath(lpath)
        size = os.path.getsize(lpath) if os.path.isfile(lpath) else 0
        callback.set_size(size)
        try:
            self._put_streamed(lpath, rpath, mode, extra)
        finally:
            self.invalidate_cache(rpath)
        callback.relative_update(size)

    def put(
        self,
        lpath: Any,
        rpath: Any,
        recursive: bool = False,
        callback: Any = None,
        maxdepth: int | None = None,
        **kwargs: Any,
    ) -> None:
        extra = _write_extra(kwargs.pop("content_settings", None))
        if extra is None:
            return super().put(lpath, rpath, recursive=recursive, callback=callback, maxdepth=maxdepth, **kwargs)
        mode = kwargs.get("mode", "overwrite")
        try:
            for lp, rp in self._put_pairs(lpath, rpath, recursive, maxdepth):
                self._put_streamed(lp, rp, mode, extra)
        finally:
            self._invalidate_paths(rpath, tree=True)
