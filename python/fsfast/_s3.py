"""fsfast's ``s3://`` / ``s3a://`` filesystem: a drop-in for ``s3fs.S3FileSystem``."""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import parse_qs, urlsplit

from fsspec.callbacks import DEFAULT_CALLBACK
from fsspec.utils import tokenize

from ._objstore import ObjectStoreFileSystem

__all__ = ["S3FileSystem"]

#: s3fs ``key_acls`` / ``buck_acls``.
KEY_ACLS = {
    "private",
    "public-read",
    "public-read-write",
    "authenticated-read",
    "aws-exec-read",
    "bucket-owner-read",
    "bucket-owner-full-control",
}
BUCKET_ACLS = {"private", "public-read", "public-read-write", "authenticated-read"}

_ARN_FORMATS = [
    re.compile(
        r"^(?P<bucket>arn:(aws).*:s3:[a-z\-0-9]*:[0-9]{12}:accesspoint[:/][^/]+)/?"
        r"(?P<key>.*)$"
    ),
    re.compile(
        r"^(?P<bucket>arn:(aws).*:s3-outposts:[a-z\-0-9]+:[0-9]{12}:outpost[/:]"
        r"[a-zA-Z0-9\-]{1,63}[/:](bucket|accesspoint)[/:][a-zA-Z0-9\-]{1,63})[/:]?(?P<key>.*)$"
    ),
    re.compile(
        r"^(?P<bucket>arn:(aws).*:s3-outposts:[a-z\-0-9]+:[0-9]{12}:outpost[/:]"
        r"[a-zA-Z0-9\-]{1,63}[/:]bucket[/:]"
        r"[a-zA-Z0-9\-]{1,63})[/:]?(?P<key>.*)$"
    ),
    re.compile(
        r"^(?P<bucket>arn:(aws).*:s3-object-lambda:[a-z\-0-9]+:[0-9]{12}:"
        r"accesspoint[/:][a-zA-Z0-9\-]{1,63})[/:]?(?P<key>.*)$"
    ),
]


def _botocore_to_options(value: Any) -> Any:
    """botocore objects s3fs accepts in ``config_kwargs``/``client_kwargs``
    as plain values: ``botocore.UNSIGNED`` becomes ``"unsigned"`` and a
    ``botocore.config.Config`` its user-provided options."""
    if value is None or isinstance(value, (str, bytes, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {k: _botocore_to_options(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_botocore_to_options(v) for v in value]
    cls = type(value)
    if cls.__module__.startswith("botocore") and cls.__name__ == "UNSIGNED":
        return "unsigned"
    provided = getattr(value, "_user_provided_options", None)
    if isinstance(provided, dict):  # botocore.config.Config
        return _botocore_to_options(provided)
    return value


class S3FileSystem(ObjectStoreFileSystem):
    """Drop-in replacement for ``s3fs.S3FileSystem``.

    Takes s3fs's constructor arguments (``key``/``secret``/``token``,
    ``anon``, ``endpoint_url``, ``client_kwargs``, ``config_kwargs``,
    ``s3_additional_kwargs``, ``requester_pays``, ``version_aware``, ...)
    and fsfast's tuning options (``max_concurrency``, ``request_size``,
    ``part_size``, ``connect_timeout``, ...; see fsfast-s3's docs) as
    keywords. Listings are cached in ``dircache`` as in s3fs.

    ``session`` (an aiobotocore session) cannot be used by the Rust client:
    pass the credentials instead.
    """

    protocol = ("s3", "s3a")
    root_marker = ""
    connect_timeout = 5
    retries = 5
    read_timeout = 15
    default_block_size = 50 * 2**20
    _rust_protocol = "s3"
    # s3fs's append files start at the existing object's size (tell()).
    _append_tell_from_end = True

    def __init__(
        self,
        anon: bool = False,
        endpoint_url: str | None = None,
        key: str | None = None,
        secret: str | None = None,
        token: str | None = None,
        use_ssl: bool = True,
        client_kwargs: dict[str, Any] | None = None,
        requester_pays: bool = False,
        default_block_size: int | None = None,
        default_fill_cache: bool = True,
        default_cache_type: str = "readahead",
        version_aware: bool = False,
        config_kwargs: dict[str, Any] | None = None,
        s3_additional_kwargs: dict[str, Any] | None = None,
        session: Any = None,
        username: str | None = None,
        password: str | None = None,
        cache_regions: bool = False,
        asynchronous: bool = False,
        loop: Any = None,
        max_concurrency: int = 10,
        fixed_upload_size: bool = False,
        local_expiry_check: bool = False,
        **kwargs: Any,
    ) -> None:
        if self._cached:
            return
        if key and username:
            raise KeyError("Supply either key or username, not both")
        if secret and password:
            raise KeyError("Supply secret or password, not both")
        if username:
            key = username
        if password:
            secret = password
        if session is not None:
            raise NotImplementedError(
                "fsfast.S3FileSystem cannot use an aiobotocore session; pass "
                "key/secret/token or profile instead"
            )
        self.endpoint_url = endpoint_url
        self.anon = anon
        self.key = key
        self.secret = secret
        self.token = token
        self.kwargs = kwargs
        self.default_block_size = default_block_size or self.default_block_size
        self.default_fill_cache = default_fill_cache
        self.default_cache_type = default_cache_type
        self.version_aware = version_aware
        self.client_kwargs = client_kwargs or {}
        self.config_kwargs = config_kwargs or {}
        self.requester_pays = requester_pays
        self.req_kw = {"RequestPayer": "requester"} if requester_pays else {}
        self.s3_additional_kwargs = s3_additional_kwargs or {}
        self.use_ssl = use_ssl
        self.cache_regions = cache_regions
        self.max_concurrency = max_concurrency
        self.fixed_upload_size = fixed_upload_size
        self.local_expiry_check = local_expiry_check
        self.session = None
        opts: dict[str, Any] = dict(kwargs)
        opts.update(
            anon=anon,
            endpoint_url=endpoint_url,
            key=key,
            secret=secret,
            token=token,
            use_ssl=use_ssl,
            client_kwargs=_botocore_to_options(self.client_kwargs),
            requester_pays=requester_pays,
            default_block_size=default_block_size,
            default_fill_cache=default_fill_cache,
            default_cache_type=default_cache_type,
            version_aware=version_aware,
            config_kwargs=_botocore_to_options(self.config_kwargs),
            s3_additional_kwargs=self.s3_additional_kwargs,
            cache_regions=cache_regions,
            max_concurrency=max_concurrency,
            fixed_upload_size=fixed_upload_size,
            local_expiry_check=local_expiry_check,
        )
        # s3fs deletes with DeleteObjects and never reports missing keys.
        opts.setdefault("strict_delete", False)
        opts = {k: v for k, v in opts.items() if v is not None}
        super().__init__(asynchronous=asynchronous, loop=loop, **opts)

    # ------------------------------------------------------------------
    # paths (s3fs)

    @staticmethod
    def _get_kwargs_from_urls(urlpath: str) -> dict[str, Any]:
        url_query = urlsplit(urlpath).query
        out: dict[str, Any] = {}
        if url_query is not None and "versionId" in parse_qs(url_query):
            out["version_aware"] = True
        return out

    @staticmethod
    def _find_bucket_key(s3_path: str) -> tuple[str, str]:
        for fmt in _ARN_FORMATS:
            match = fmt.match(s3_path)
            if match:
                return match.group("bucket"), match.group("key")
        bucket, _, key = s3_path.partition("/")
        return bucket, key

    def split_path(self, path: str) -> tuple[str, str, str | None]:
        """``(bucket, key, version_id)`` of an S3 path (s3fs ``split_path``)."""
        trail = path[len(path.rstrip("/")) :]
        path = self._strip_protocol(path).lstrip("/")
        if "/" not in path:
            return path, "", None
        bucket, keypart = self._find_bucket_key(path)
        key, _, version_id = keypart.partition("?versionId=")
        key += trail
        return bucket, key, version_id if self.version_aware and version_id else None

    # ------------------------------------------------------------------
    # cache entries in s3fs's shapes

    def _dir_entry(self, path: str) -> dict[str, Any]:
        return {"name": path, "size": 0, "type": "directory"}

    def info(
        self,
        path: Any,
        bucket: str | None = None,
        key: str | None = None,
        refresh: bool = False,
        version_id: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        if version_id is not None:
            if not self.version_aware:
                raise ValueError(
                    "version_id cannot be specified if the filesystem is not version aware"
                )
            return self._rfs.info(f"{self._listing_key(path)}?versionId={version_id}")
        p = self._strip(path)
        if p in ("", "/"):
            return {"name": p, "size": 0, "type": "directory"}
        return super().info(path, refresh=refresh)

    async def _info(
        self,
        path: Any,
        bucket: str | None = None,
        key: str | None = None,
        refresh: bool = False,
        version_id: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        if version_id is not None:
            if not self.version_aware:
                raise ValueError(
                    "version_id cannot be specified if the filesystem is not version aware"
                )
            return await self._rfs.info_async(f"{self._listing_key(path)}?versionId={version_id}")
        p = self._strip(path)
        if p in ("", "/"):
            return {"name": p, "size": 0, "type": "directory"}
        return await super()._info(path, refresh=refresh)

    def ls(
        self,
        path: Any,
        detail: bool = False,
        refresh: bool = False,
        versions: bool = False,
        **kwargs: Any,
    ) -> list[Any]:
        if versions:
            out = self._rfs.call("ls_versions", {"path": self._listing_key(path)})
            return out if detail else sorted(o["name"] for o in out)
        return super().ls(path, detail=detail, refresh=refresh)

    async def _ls(
        self,
        path: Any,
        detail: bool = False,
        refresh: bool = False,
        versions: bool = False,
        **kwargs: Any,
    ) -> list[Any]:
        if versions:
            out = await self._rfs.call_async("ls_versions", {"path": self._listing_key(path)})
            return out if detail else sorted(o["name"] for o in out)
        return await super()._ls(path, detail=detail, refresh=refresh)

    def exists(self, path: Any, **kwargs: Any) -> bool:
        if path in ("", "/"):
            return True  # the root always exists, even if anon
        return super().exists(path)

    async def _exists(self, path: Any, **kwargs: Any) -> bool:
        if path in ("", "/"):
            return True
        return await super()._exists(path)

    def isdir(self, path: Any) -> bool:
        if self._strip(path).strip("/") == "":
            return True
        return super().isdir(path)

    async def _isdir(self, path: Any) -> bool:
        if self._strip(path).strip("/") == "":
            return True
        return await super()._isdir(path)

    def find(
        self,
        path: Any,
        maxdepth: int | None = None,
        withdirs: bool | None = None,
        detail: bool = False,
        prefix: str = "",
        **kwargs: Any,
    ) -> Any:
        bucket, _, _ = self.split_path(self._strip(path))
        if not bucket:
            raise ValueError("Cannot traverse all of S3")
        if prefix:
            found = self._rfs.call(
                "find_prefix",
                {
                    "path": self._listing_key(path),
                    "prefix": prefix,
                    "maxdepth": maxdepth,
                    "withdirs": True,
                },
            )
            return self._find_result(
                self._listing_key(path),
                list(found),
                maxdepth,
                bool(withdirs),
                detail,
                False,
            )
        return super().find(path, maxdepth=maxdepth, withdirs=bool(withdirs), detail=detail)

    async def _find(
        self,
        path: Any,
        maxdepth: int | None = None,
        withdirs: bool | None = None,
        **kwargs: Any,
    ) -> Any:
        bucket, _, _ = self.split_path(self._strip(path))
        if not bucket:
            raise ValueError("Cannot traverse all of S3")
        prefix = kwargs.pop("prefix", "")
        detail = kwargs.pop("detail", False)
        if prefix:
            found = await self._rfs.call_async(
                "find_prefix",
                {
                    "path": self._listing_key(path),
                    "prefix": prefix,
                    "maxdepth": maxdepth,
                    "withdirs": True,
                },
            )
            return self._find_result(
                self._listing_key(path),
                list(found),
                maxdepth,
                bool(withdirs),
                detail,
                False,
            )
        return await super()._find(path, maxdepth=maxdepth, withdirs=bool(withdirs), detail=detail)

    def _find_result(
        self,
        root: str,
        found: list[dict[str, Any]],
        maxdepth: int | None,
        withdirs: bool,
        detail: bool,
        cache: bool,
    ) -> Any:
        # s3fs builds the directories of a flat listing itself, with its own
        # key order (they also land in the listings cache).
        for i, o in enumerate(found):
            if o["type"] == "directory" and "Key" in o and not maxdepth:
                found[i] = {
                    "Key": o["Key"],
                    "Size": o["Size"],
                    "name": o["name"],
                    "StorageClass": o["StorageClass"],
                    "type": o["type"],
                    "size": o["size"],
                }
        return super()._find_result(root, found, maxdepth, withdirs, detail, cache)

    def glob(self, path: Any, maxdepth: int | None = None, **kwargs: Any) -> Any:
        if isinstance(path, str) and path.startswith("*"):
            raise ValueError("Cannot traverse all of S3")
        return super().glob(path, maxdepth=maxdepth, **kwargs)

    def walk(self, path: Any, maxdepth: int | None = None, topdown: bool = True, on_error: Any = "omit", **kwargs: Any) -> Any:
        if path in ["", "*"] + [f"{p}://" for p in self.protocol]:
            raise ValueError("Cannot crawl all of S3")
        return super().walk(path, maxdepth=maxdepth, topdown=topdown, on_error=on_error, **kwargs)

    # ------------------------------------------------------------------
    # directories and buckets

    def mkdir(self, path: Any, acl: Any = False, create_parents: bool = True, **kwargs: Any) -> None:
        if acl:
            if acl not in BUCKET_ACLS:
                raise ValueError("ACL not in %s", BUCKET_ACLS)
            raise NotImplementedError("fsfast.S3FileSystem.mkdir does not support acl")
        path = self._strip(path).rstrip("/")
        if not path:
            raise ValueError
        try:
            self._rfs.mkdir(path, create_parents)
        finally:
            self.invalidate_cache(path)

    async def _mkdir(self, path: Any, acl: Any = False, create_parents: bool = True, **kwargs: Any) -> None:
        if acl:
            raise NotImplementedError("fsfast.S3FileSystem.mkdir does not support acl")
        path = self._strip(path).rstrip("/")
        if not path:
            raise ValueError
        try:
            await self._rfs.mkdir_async(path, create_parents)
        finally:
            self.invalidate_cache(path)

    def makedirs(self, path: Any, exist_ok: bool = False) -> None:
        try:
            self.mkdir(path, create_parents=True)
        except FileExistsError:
            if not exist_ok:
                raise

    async def _makedirs(self, path: Any, exist_ok: bool = False) -> None:
        try:
            await self._mkdir(path, create_parents=True)
        except FileExistsError:
            if not exist_ok:
                raise

    def _rm_expanded(self, paths: list[str]) -> list[str]:
        # s3fs: every path with a key goes to DeleteObjects (missing keys
        # and pseudo-directories are fine), then buckets are removed; the
        # deleted keys are returned.
        files = [p for p in paths if self.split_path(p)[1]]
        buckets = [p for p in paths if not self.split_path(p)[1]]
        if files:
            self._rfs.rm_files(files, on_error="raise")
        for b in buckets:
            self._rfs.rmdir(b)
        return files

    async def _rm_expanded_async(self, paths: list[str]) -> list[str]:
        files = [p for p in paths if self.split_path(p)[1]]
        buckets = [p for p in paths if not self.split_path(p)[1]]
        if files:
            await self._rfs.rm_files_async(files, on_error="raise")
        for b in buckets:
            await self._rfs.rmdir_async(b)
        return files

    def cat_file(
        self,
        path: Any,
        version_id: str | None = None,
        start: int | None = None,
        end: int | None = None,
        **kwargs: Any,
    ) -> bytes:
        return super().cat_file(self._versioned(path, version_id), start=start, end=end)

    async def _cat_file(
        self,
        path: Any,
        version_id: str | None = None,
        start: int | None = None,
        end: int | None = None,
        **kwargs: Any,
    ) -> bytes:
        return await super()._cat_file(self._versioned(path, version_id), start=start, end=end)

    def _versioned(self, path: Any, version_id: str | None) -> Any:
        """``path`` addressing ``version_id`` (s3fs's ``version_id``
        keyword, as a ``?versionId=`` suffix the Rust backend parses)."""
        if version_id is None:
            return path
        if not self.version_aware:
            raise ValueError(
                "version_id cannot be specified if the filesystem is not version aware"
            )
        return f"{self._strip(path)}?versionId={version_id}"

    # ------------------------------------------------------------------
    # files

    def touch(self, path: Any, truncate: bool = True, data: Any = None, **kwargs: Any) -> None:
        bucket, key, version_id = self.split_path(self._strip(path))
        if version_id:
            raise ValueError("S3 does not support touching existing versions of files")
        if not truncate and self.exists(path):
            raise ValueError("S3 does not support touching existent files")
        try:
            self._rfs.pipe_file(self._strip(path), data or b"", "overwrite", kwargs or None)
        finally:
            self.invalidate_cache(path)

    async def _touch(self, path: Any, truncate: bool = True, data: Any = None, **kwargs: Any) -> None:
        bucket, key, version_id = self.split_path(self._strip(path))
        if version_id:
            raise ValueError("S3 does not support touching existing versions of files")
        if not truncate and await self._exists(path):
            raise ValueError("S3 does not support touching existent files")
        try:
            await self._rfs.pipe_file_async(self._strip(path), data or b"", "overwrite", kwargs or None)
        finally:
            self.invalidate_cache(path)

    # -- put with per-call S3 parameters (s3fs forwards put/put_file
    # keywords such as ContentType= or Metadata= to PutObject and
    # CreateMultipartUpload). Without such keywords the Rust batch upload
    # is used; with them each file streams through a write handle that
    # carries the parameters.

    @staticmethod
    def _put_params(kwargs: dict[str, Any]) -> dict[str, Any]:
        for k in ("chunksize", "max_concurrency", "mode", "callback"):
            kwargs.pop(k, None)
        return kwargs

    def _put_one_with_params(self, lpath: str, rpath: str, mode: str, params: dict[str, Any]) -> None:
        self._put_streamed(lpath, rpath, mode, params)

    def put_file(self, lpath: Any, rpath: Any, callback: Any = DEFAULT_CALLBACK, mode: str = "overwrite", **kwargs: Any) -> None:
        params = self._put_params(dict(kwargs))
        if not params:
            return super().put_file(lpath, rpath, callback=callback, mode=mode)
        lpath = os.fspath(lpath)
        size = os.path.getsize(lpath) if os.path.isfile(lpath) else 0
        callback.set_size(size)
        try:
            self._put_one_with_params(lpath, rpath, mode, params)
        finally:
            self.invalidate_cache(rpath)
        callback.relative_update(size)

    def put(self, lpath: Any, rpath: Any, recursive: bool = False, callback: Any = None, maxdepth: int | None = None, **kwargs: Any) -> None:
        mode = kwargs.get("mode", "overwrite")
        params = self._put_params(dict(kwargs))
        if not params:
            return super().put(lpath, rpath, recursive=recursive, callback=callback, maxdepth=maxdepth, **kwargs)
        # Expand exactly as fsspec's put does, then upload each file with
        # the parameters.
        pairs = self._put_pairs(lpath, rpath, recursive, maxdepth)
        try:
            for lp, rp in pairs:
                self._put_one_with_params(lp, rp, mode, params)
        finally:
            self._invalidate_paths(rpath)

    def pipe_file(self, path: Any, value: Any, mode: str = "overwrite", **kwargs: Any) -> None:
        kwargs.pop("chunksize", None)
        kwargs.pop("max_concurrency", None)
        try:
            self._rfs.pipe_file(self._strip(path), self._payload(value), mode, kwargs or None)
        finally:
            self.invalidate_cache(path)

    async def _pipe_file(self, path: Any, value: Any, mode: str = "overwrite", **kwargs: Any) -> None:
        kwargs.pop("chunksize", None)
        kwargs.pop("max_concurrency", None)
        try:
            await self._rfs.pipe_file_async(self._strip(path), self._payload(value), mode, kwargs or None)
        finally:
            self.invalidate_cache(path)

    def _open(
        self,
        path: Any,
        mode: str = "rb",
        block_size: int | None = None,
        acl: Any = False,
        version_id: str | None = None,
        fill_cache: bool | None = None,
        cache_type: str | None = None,
        autocommit: bool = True,
        size: int | None = None,
        requester_pays: bool | None = None,
        cache_options: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        from ._file import FsfastFile

        if acl:
            if acl not in KEY_ACLS:
                raise ValueError("ACL not in %s", KEY_ACLS)
            kwargs["ACL"] = acl
        if version_id is not None and not self.version_aware:
            raise ValueError(
                "version_id cannot be specified if the filesystem is not version aware"
            )
        # s3fs passes only the keywords an S3 call accepts and drops the
        # rest; ``blocksize`` (a common misspelling of ``block_size``) is
        # dropped here likewise instead of being rejected as an unknown
        # S3 parameter.
        kwargs.pop("blocksize", None)
        p = self._strip(path)
        bucket, key, path_version = self.split_path(p)
        if not key:
            raise ValueError("Attempt to open non key-like path: %s" % path)
        if mode != "rb":
            block_size = block_size or self.default_block_size
            if block_size < 5 * 2**20:
                raise ValueError("Block size must be >=5MB")
        return FsfastFile(
            self,
            p,
            mode,
            block_size=block_size or self.default_block_size,
            autocommit=autocommit,
            cache_type=cache_type or self.default_cache_type,
            cache_options=cache_options,
            version=version_id,
            extra=kwargs or None,
        )

    # ------------------------------------------------------------------
    # s3fs extras

    def checksum(self, path: Any, refresh: bool = False) -> int:
        """Unique value for the current version of a file (from its ETag)."""
        info = self.info(path, refresh=refresh)
        if info["type"] != "directory":
            return int(info["ETag"].strip('"').split("-")[0], 16)
        return int(tokenize(info), 16)

    def modified(self, path: Any, version_id: str | None = None, refresh: bool = False) -> Any:
        """Last modified timestamp of the file at ``path`` as a datetime."""
        info = self.info(path=path, version_id=version_id, refresh=refresh)
        if "LastModified" not in info:
            raise IsADirectoryError
        return info["LastModified"]

    async def _modified(self, path: Any, version_id: str | None = None, refresh: bool = False) -> Any:
        info = await self._info(path, version_id=version_id, refresh=refresh)
        if "LastModified" not in info:
            raise IsADirectoryError
        return info["LastModified"]

    def created(self, path: Any) -> Any:
        raise NotImplementedError("S3 objects have no creation time (s3fs raises too)")

    def url(self, path: Any, expires: int = 3600, client_method: str = "get_object", **kwargs: Any) -> str:
        """Pre-signed URL (SigV4) to ``client_method`` the object; only
        ``get_object`` is supported."""
        if client_method != "get_object" or kwargs:
            raise NotImplementedError(
                "fsfast.S3FileSystem.url supports client_method='get_object' without extra parameters"
            )
        return self._rfs.sign(self._strip(path), float(expires))

    async def _url(self, path: Any, expires: int = 3600, client_method: str = "get_object", **kwargs: Any) -> str:
        if client_method != "get_object" or kwargs:
            raise NotImplementedError(
                "fsfast.S3FileSystem.url supports client_method='get_object' without extra parameters"
            )
        return await self._rfs.sign_async(self._strip(path), float(expires))

    def sign(self, path: Any, expiration: int = 100, **kwargs: Any) -> str:
        return self.url(path, expires=expiration, **kwargs)

    async def _sign(self, path: Any, expiration: int = 100, **kwargs: Any) -> str:
        return await self._url(path, expires=expiration, **kwargs)

    def get_tags(self, path: Any) -> dict[str, str]:
        """The object's tags."""
        return self._rfs.call("get_tags", {"path": self._strip(path)})

    def put_tags(self, path: Any, tags: dict[str, str], mode: str = "o") -> None:
        """Set tags: ``mode="o"`` replaces them, ``"m"`` merges."""
        if mode not in ("o", "m"):
            raise ValueError("Mode must be {'o', 'm'}, not %s" % mode)
        self._rfs.call("put_tags", {"path": self._strip(path), "tags": tags, "merge": mode == "m"})

    def metadata(self, path: Any, refresh: bool = False, **kwargs: Any) -> dict[str, str]:
        """The object's user metadata (``x-amz-meta-*``)."""
        return self._rfs.call("metadata", {"path": self._strip(path)})

    def getxattr(self, path: Any, attr_name: str, **kwargs: Any) -> str | None:
        """One user metadata value (``None`` if unset)."""
        return self._rfs.call("getxattr", {"path": self._strip(path), "name": attr_name})

    def setxattr(self, path: Any, copy_kwargs: dict[str, Any] | None = None, **kw_args: Any) -> None:
        """Set user metadata (``None`` values remove keys), in place."""
        try:
            self._rfs.call(
                "setxattr",
                {"path": self._strip(path), "attrs": kw_args, "copy_kwargs": copy_kwargs or {}},
            )
        finally:
            self.invalidate_cache(path)

    def chmod(self, path: Any, acl: str, recursive: bool = False, **kwargs: Any) -> None:
        """Apply a canned ACL to an object (or every object below a prefix)
        or a bucket."""
        self._rfs.call("chmod", {"path": self._strip(path), "acl": acl, "recursive": recursive})

    def object_version_info(self, path: Any, **kwargs: Any) -> list[dict[str, Any]]:
        """Every version of an object (``version_aware`` filesystems only)."""
        if not self.version_aware:
            raise ValueError(
                "version specific functionality is disabled for non-version aware filesystems"
            )
        return self._rfs.call("object_versions", {"path": self._strip(path)})

    def is_bucket_versioned(self, bucket: str) -> bool:
        return self._rfs.call("is_bucket_versioned", {"bucket": bucket})

    def make_bucket_versioned(self, bucket: str, versioned: bool = True) -> None:
        """Enable (or suspend) versioning on a bucket."""
        self._rfs.call("make_bucket_versioned", {"bucket": bucket, "versioned": versioned})

    def invalidate_region_cache(self) -> None:
        """s3fs drops its per-bucket clients; fsfast resolves bucket regions
        inside the Rust client and re-resolves them on redirects, so there
        is nothing to drop."""

    async def _invalidate_region_cache(self) -> None:
        self.invalidate_region_cache()

    def merge(self, path: Any, filelist: list[Any], **kwargs: Any) -> None:
        raise NotImplementedError("fsfast.S3FileSystem does not implement merge (multipart copy)")

    def get_delegated_s3pars(self, exp: int = 3600) -> dict[str, Any]:
        raise NotImplementedError("fsfast.S3FileSystem does not implement get_delegated_s3pars")

    def clear_multipart_uploads(self, bucket: str) -> None:
        raise NotImplementedError("fsfast.S3FileSystem does not implement clear_multipart_uploads")

    def list_multipart_uploads(self, bucket: str) -> list[Any]:
        raise NotImplementedError("fsfast.S3FileSystem does not implement list_multipart_uploads")
