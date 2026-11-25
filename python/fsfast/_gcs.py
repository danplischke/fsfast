"""fsfast's ``gs://`` / ``gcs://`` filesystem: a drop-in for ``gcsfs.GCSFileSystem``."""

from __future__ import annotations

import os
import warnings
from typing import Any
from urllib.parse import parse_qs, urlsplit

from fsspec.utils import stringify_path

from ._objstore import ObjectStoreFileSystem

__all__ = ["GCSFileSystem"]

#: gcsfs ``DEFAULT_PROJECT``.
DEFAULT_PROJECT = os.getenv("GCSFS_DEFAULT_PROJECT", "")


def _token_option(token: Any) -> Any:
    """gcsfs ``token`` values as fsfast-gcs options: strings, paths and
    dicts pass through; a ``google.oauth2.credentials.Credentials`` (user
    credentials) becomes its ``authorized_user`` dict, or its current access
    token when it cannot be refreshed."""
    if token is None or isinstance(token, (str, dict)):
        return token
    if isinstance(token, os.PathLike):
        return os.fspath(token)
    refresh = getattr(token, "refresh_token", None)
    client_id = getattr(token, "client_id", None)
    client_secret = getattr(token, "client_secret", None)
    if refresh and client_id and client_secret:
        return {
            "type": "authorized_user",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh,
        }
    raw = getattr(token, "token", None)
    if isinstance(raw, str) and raw:
        return raw
    raise NotImplementedError(
        f"fsfast.GCSFileSystem cannot use a {type(token).__name__} credentials object; "
        "pass a service-account file/dict, 'google_default', 'anon' or an access token"
    )


class GCSFileSystem(ObjectStoreFileSystem):
    """Drop-in replacement for ``gcsfs.GCSFileSystem``.

    Takes gcsfs's constructor arguments (``project``, ``access``,
    ``token``, ``consistency``, ``requester_pays``, ``endpoint_url``,
    ``version_aware``, ``session_kwargs``, ...) plus fsfast's tuning options
    (``request_size``, ``max_concurrency``, ``upload_chunk_size``, ...).
    Listings are cached in ``dircache`` as in gcsfs (``cache_timeout`` sets
    ``listings_expiry_time``).
    """

    scopes = {"read_only", "read_write", "full_control"}
    retries = 6
    default_block_size = 2**24
    protocol = ("gs", "gcs")
    root_marker = ""
    _rust_protocol = "gs"

    def __init__(
        self,
        project: str | None = DEFAULT_PROJECT,
        access: str = "full_control",
        token: Any = None,
        block_size: int | None = None,
        consistency: str = "none",
        cache_timeout: float | None = None,
        secure_serialize: bool = True,
        check_connection: Any = None,
        requests_timeout: float | None = None,
        requester_pays: bool | str = False,
        asynchronous: bool = False,
        session_kwargs: dict[str, Any] | None = None,
        loop: Any = None,
        timeout: float | None = None,
        endpoint_url: str | None = None,
        default_location: str | None = None,
        version_aware: bool = False,
        **kwargs: Any,
    ) -> None:
        if self._cached:
            return
        if cache_timeout is not None:
            kwargs["listings_expiry_time"] = cache_timeout
        if access not in self.scopes:
            raise ValueError(f"access must be one of {self.scopes}")
        if project is None:
            warnings.warn("GCS project not set - cannot list or create buckets", stacklevel=2)
        if check_connection:
            warnings.warn(
                "The `check_connection` argument is deprecated and will be removed in a future release.",
                DeprecationWarning,
                stacklevel=2,
            )
        if block_size is not None:
            self.default_block_size = block_size
        self.project = project
        self.access = access
        self.requester_pays = requester_pays
        self.consistency = consistency
        self.cache_timeout = cache_timeout or kwargs.get("listings_expiry_time")
        self.requests_timeout = requests_timeout
        self.timeout = timeout
        self.session_kwargs = session_kwargs or {}
        self.default_location = default_location
        self.version_aware = version_aware
        self._endpoint = endpoint_url
        opts: dict[str, Any] = dict(kwargs)
        opts.update(
            project=project or None,
            access=access,
            token=_token_option(token),
            block_size=block_size,
            consistency=consistency,
            requests_timeout=requests_timeout,
            requester_pays=requester_pays,
            session_kwargs=session_kwargs,
            endpoint_url=endpoint_url,
            default_location=default_location,
            version_aware=version_aware,
            timeout=timeout,
        )
        opts = {k: v for k, v in opts.items() if v is not None}
        super().__init__(asynchronous=asynchronous, loop=loop, **opts)

    # ------------------------------------------------------------------
    # paths (gcsfs)

    @classmethod
    def _strip_protocol(cls, path: Any) -> Any:
        if isinstance(path, list):
            return [cls._strip_protocol(p) for p in path]
        path = stringify_path(path)
        protos = (cls.protocol,) if isinstance(cls.protocol, str) else cls.protocol
        for protocol in protos:
            if path.startswith(protocol + "://"):
                path = path[len(protocol) + 3 :]
            elif path.startswith(protocol + "::"):
                path = path[len(protocol) + 2 :]
        return path or cls.root_marker

    @classmethod
    def _split_path(cls, path: str, version_aware: bool = False) -> tuple[str, str, str | None]:
        path = cls._strip_protocol(path).lstrip("/")
        if "/" not in path:
            return path, "", None
        bucket, keypart = path.split("/", 1)
        key = keypart
        generation = None
        if version_aware:
            parts = urlsplit(keypart)
            try:
                if parts.fragment:
                    generation = parts.fragment
                elif parts.query:
                    parsed = parse_qs(parts.query)
                    if "generation" in parsed:
                        generation = parsed["generation"][0]
                if generation is not None:
                    int(generation)
                    key = parts.path
            except ValueError:
                generation = None
        return bucket, key, generation

    def split_path(self, path: str) -> tuple[str, str, str | None]:
        """``(bucket, key, generation)`` of a GCS path (gcsfs ``split_path``)."""
        return self._split_path(path, version_aware=self.version_aware)

    @classmethod
    def _get_kwargs_from_urls(cls, path: str) -> dict[str, Any]:
        _, _, generation = cls._split_path(path, version_aware=True)
        if generation is not None:
            return {"version_aware": True}
        return {}

    # ------------------------------------------------------------------
    # cache entries in gcsfs's shapes

    def _dir_entry(self, path: str) -> dict[str, Any]:
        return {
            "bucket": self.split_path(path)[0],
            "name": path,
            "size": 0,
            "storageClass": "DIRECTORY",
            "type": "directory",
        }

    def info(self, path: Any, generation: str | None = None, **kwargs: Any) -> dict[str, Any]:
        if generation is not None:
            return self._rfs.info(f"{self._listing_key(path)}#{generation}")
        if "/" not in self._listing_key(path):
            # Buckets: gcsfs always GETs the bucket resource.
            return self._rfs.info(self._listing_key(path))
        return super().info(path, **kwargs)

    async def _info(self, path: Any, generation: str | None = None, **kwargs: Any) -> dict[str, Any]:
        if generation is not None:
            return await self._rfs.info_async(f"{self._listing_key(path)}#{generation}")
        if "/" not in self._listing_key(path):
            return await self._rfs.info_async(self._listing_key(path))
        return await super()._info(path, **kwargs)

    def ls(
        self,
        path: Any,
        detail: bool = False,
        prefix: str = "",
        versions: bool = False,
        refresh: bool = False,
        **kwargs: Any,
    ) -> list[Any]:
        if prefix or versions:
            raise NotImplementedError("fsfast.GCSFileSystem.ls does not support prefix= or versions=")
        if refresh:
            self.invalidate_cache(path)
        return super().ls(path, detail=detail, refresh=refresh)

    async def _ls(
        self,
        path: Any,
        detail: bool = False,
        prefix: str = "",
        versions: bool = False,
        refresh: bool = False,
        **kwargs: Any,
    ) -> list[Any]:
        if prefix or versions:
            raise NotImplementedError("fsfast.GCSFileSystem.ls does not support prefix= or versions=")
        if refresh:
            self.invalidate_cache(path)
        return await super()._ls(path, detail=detail, refresh=refresh)

    def find(
        self,
        path: Any,
        maxdepth: int | None = None,
        withdirs: bool = False,
        detail: bool = False,
        prefix: str = "",
        versions: bool = False,
        **kwargs: Any,
    ) -> Any:
        if prefix or versions:
            raise NotImplementedError("fsfast.GCSFileSystem.find does not support prefix= or versions=")
        return super().find(path, maxdepth=maxdepth, withdirs=withdirs, detail=detail)

    # ------------------------------------------------------------------
    # buckets

    def mkdir(
        self,
        path: Any,
        acl: str = "projectPrivate",
        default_acl: str = "bucketOwnerFullControl",
        location: str | None = None,
        create_parents: bool = True,
        enable_versioning: bool = False,
        **kwargs: Any,
    ) -> None:
        if location is not None or enable_versioning or kwargs:
            raise NotImplementedError(
                "fsfast.GCSFileSystem.mkdir does not support location, enable_versioning "
                "or other bucket settings (use default_location= on the filesystem)"
            )
        try:
            self._rfs.mkdir(self._strip(path), create_parents)
        finally:
            self.invalidate_cache(path)

    async def _mkdir(
        self,
        path: Any,
        acl: str = "projectPrivate",
        default_acl: str = "bucketOwnerFullControl",
        location: str | None = None,
        create_parents: bool = True,
        enable_versioning: bool = False,
        **kwargs: Any,
    ) -> None:
        if location is not None or enable_versioning or kwargs:
            raise NotImplementedError(
                "fsfast.GCSFileSystem.mkdir does not support location, enable_versioning "
                "or other bucket settings (use default_location= on the filesystem)"
            )
        try:
            await self._rfs.mkdir_async(self._strip(path), create_parents)
        finally:
            self.invalidate_cache(path)

    def makedirs(self, path: Any, exist_ok: bool = False) -> None:
        # gcsfs: buckets only; prefixes need no creation.
        bucket = self.split_path(self._strip(path))[0]
        if not self.exists(bucket):
            self.mkdir(bucket)
        elif not exist_ok and "/" not in self._listing_key(path):
            raise FileExistsError(path)

    # ------------------------------------------------------------------
    # gcsfs extras

    @property
    def buckets(self) -> list[str]:
        """Names of the project's buckets (``"name/"``, as gcsfs lists them)."""
        return [b["name"] for b in self.ls("", detail=True)]

    def url(self, path: Any, generation: str | None = None) -> str:
        """HTTP download URL of ``path``."""
        return self._rfs.call("url", {"path": self._strip(path), "generation": generation})

    def merge(self, path: Any, paths: list[Any], acl: Any = None) -> None:
        """Concatenate objects into one (``objects.compose``, up to 32
        sources)."""
        try:
            self._rfs.call(
                "merge", {"path": self._strip(path), "paths": [self._strip(p) for p in paths]}
            )
        finally:
            self.invalidate_cache(path)

    async def _merge(self, path: Any, paths: list[Any], acl: Any = None) -> None:
        try:
            await self._rfs.call_async(
                "merge", {"path": self._strip(path), "paths": [self._strip(p) for p in paths]}
            )
        finally:
            self.invalidate_cache(path)

    def getxattr(self, path: Any, attr: str) -> Any:
        """One user metadata value of an object."""
        return (self.info(path).get("metadata") or {})[attr]

    async def _getxattr(self, path: Any, attr: str) -> Any:
        return ((await self._info(path)).get("metadata") or {})[attr]

    def setxattrs(self, path: Any, content_type: Any = None, content_encoding: Any = None, fixed_key_metadata: Any = None, **kwargs: Any) -> Any:
        raise NotImplementedError("fsfast.GCSFileSystem does not implement setxattrs (object PATCH)")

    def modified(self, path: Any) -> Any:
        return self.info(path)["mtime"]

    async def _modified(self, path: Any) -> Any:
        return (await self._info(path))["mtime"]

    def created(self, path: Any) -> Any:
        return self.info(path)["ctime"]

    async def _created(self, path: Any) -> Any:
        return (await self._info(path))["ctime"]

    def _open(
        self,
        path: Any,
        mode: str = "rb",
        block_size: int | None = None,
        cache_options: dict[str, Any] | None = None,
        acl: Any = None,
        consistency: str | None = None,
        metadata: dict[str, Any] | None = None,
        autocommit: bool = True,
        fixed_key_metadata: dict[str, Any] | None = None,
        generation: str | None = None,
        **kwargs: Any,
    ) -> Any:
        from ._file import FsfastFile

        extra: dict[str, Any] = {}
        if metadata:
            extra["metadata"] = metadata
        if fixed_key_metadata:
            extra["fixed_key_metadata"] = fixed_key_metadata
        if consistency:
            extra["consistency"] = consistency
        if "content_type" in kwargs:
            extra["content_type"] = kwargs.pop("content_type")
        cache_type = kwargs.pop("cache_type", "readahead")
        if mode != "rb" and not extra:
            extra = {}
        return FsfastFile(
            self,
            self._strip(path),
            mode,
            block_size=block_size or self.default_block_size,
            autocommit=autocommit,
            cache_type=cache_type,
            cache_options=cache_options,
            version=generation,
            extra=(extra or None) if mode != "rb" else None,
        )
