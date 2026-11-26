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


def _gcp_universe_domain() -> str:
    """gcsfs ``_gcp_universe_domain``."""
    return os.getenv("GOOGLE_CLOUD_UNIVERSE_DOMAIN", "googleapis.com")


def _location() -> str:
    """gcsfs ``_location``: ``$STORAGE_EMULATOR_HOST`` (``http://`` added
    when it has no scheme) or ``https://storage.<universe domain>``. The
    Rust backend resolves its endpoint the same way."""
    emulator = os.getenv("STORAGE_EMULATOR_HOST", "")
    if emulator not in {"default", ""}:
        if not emulator.startswith(("http://", "https://")):
            emulator = f"http://{emulator}"
        return emulator
    return f"https://storage.{_gcp_universe_domain()}"


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
        # The Rust backend resolves its endpoint once, at construction
        # (gcsfs re-reads $STORAGE_EMULATOR_HOST on every request); report
        # the endpoint actually in use.
        self._resolved_location = endpoint_url or _location()
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
        if versions:
            raise NotImplementedError("fsfast.GCSFileSystem.ls does not support versions=")
        if refresh:
            self.invalidate_cache(path)
        if prefix:
            key = self._listing_key(path)
            listdir = self._prefix_dir(key, prefix)
            try:
                entries = self._ls_entries(listdir, refresh)
            except FileNotFoundError:
                entries = []
            out = self._prefix_entries(listdir, f"{key}/{prefix}", entries)
            if not out and "/" in key:
                out = [self._object_or_missing(key, self._rfs.info(key))]
            return out if detail else self._names(out)
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
        if versions:
            raise NotImplementedError("fsfast.GCSFileSystem.ls does not support versions=")
        if refresh:
            self.invalidate_cache(path)
        if prefix:
            key = self._listing_key(path)
            listdir = self._prefix_dir(key, prefix)
            try:
                entries = await self._ls_entries_async(listdir, refresh)
            except FileNotFoundError:
                entries = []
            out = self._prefix_entries(listdir, f"{key}/{prefix}", entries)
            if not out and "/" in key:
                out = [self._object_or_missing(key, await self._rfs.info_async(key))]
            return out if detail else self._names(out)
        return await super()._ls(path, detail=detail, refresh=refresh)

    # gcsfs's ``prefix=`` lists ``path`` with the object-name prefix
    # ``path/prefix``. fsfast filters the full listing (from the listings
    # cache when it is there) instead of a second, narrower request: the
    # result is the same and the full listing can be reused; for a huge
    # directory and a narrow prefix gcsfs transfers less.

    @staticmethod
    def _prefix_dir(key: str, prefix: str) -> str:
        """The directory whose one-level listing holds the matches of
        ``prefix`` (gcsfs lists with ``delimiter="/"``, so a prefix with a
        ``/`` lists below that directory)."""
        head = prefix.rpartition("/")[0]
        return f"{key}/{head}" if head else key

    def _prefix_entries(self, listdir: str, full: str, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not self._is_listing(listdir, entries):
            return []
        return [
            e
            for e in entries
            if (e["name"].rstrip("/") + ("/" if e["type"] == "directory" else "")).startswith(full)
        ]

    @staticmethod
    def _object_or_missing(key: str, info: dict[str, Any]) -> dict[str, Any]:
        # gcsfs falls back to GETting ``path`` as an object, which fails
        # for a prefix ("directory").
        if info["type"] == "directory":
            raise FileNotFoundError(key)
        return info

    def _find_prefix_result(
        self,
        root: str,
        prefix: str,
        found: list[dict[str, Any]],
        maxdepth: int | None,
        withdirs: bool,
        detail: bool,
    ) -> Any:
        """gcsfs ``_find`` with ``prefix=``: objects whose names start with
        ``root/prefix``, their parent directories below ``root`` when
        ``withdirs``; the listings cache is left alone (partial listing)."""
        full = f"{root}/{prefix}"
        objects = [o for o in found if o["type"] != "directory" and o["name"].startswith(full)]
        out = list(objects)
        if withdirs:
            # gcsfs ``_get_dirs_and_update_cache``: the parents that match
            # the prefix, in its find-directory shape.
            dirs: dict[str, dict[str, Any]] = {}
            for o in objects:
                parent = self._parent(o["name"])
                while len(parent) >= len(root) and parent.startswith(full) and parent not in dirs:
                    dir_key = self.split_path(parent)[1]
                    if dir_key:
                        dirs[parent] = {
                            "Key": dir_key,
                            "Size": 0,
                            "name": parent,
                            "StorageClass": "DIRECTORY",
                            "type": "directory",
                            "size": 0,
                        }
                    parent = self._parent(parent)
            out = sorted(out + list(dirs.values()), key=lambda x: x["name"])
        if maxdepth:
            depth = root.count("/") + maxdepth
            out = [o for o in out if o["name"].count("/") <= depth]
        if detail:
            return {o["name"]: o for o in out}
        return [o["name"] for o in out]

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
        if versions:
            raise NotImplementedError("fsfast.GCSFileSystem.find does not support versions=")
        if prefix:
            if maxdepth is not None and maxdepth < 1:
                raise ValueError("maxdepth must be at least 1")
            found = self._fix_all(self._rfs.find(self._strip(path), None, False, True, as_list=True))
            return self._find_prefix_result(self._listing_key(path), prefix, found, maxdepth, withdirs, detail)
        return super().find(path, maxdepth=maxdepth, withdirs=withdirs, detail=detail)

    async def _find(
        self,
        path: Any,
        maxdepth: int | None = None,
        withdirs: bool = False,
        **kwargs: Any,
    ) -> Any:
        prefix = kwargs.pop("prefix", "")
        if kwargs.pop("versions", False):
            raise NotImplementedError("fsfast.GCSFileSystem.find does not support versions=")
        if prefix:
            if maxdepth is not None and maxdepth < 1:
                raise ValueError("maxdepth must be at least 1")
            found = self._fix_all(
                await self._rfs.find_async(self._strip(path), None, False, True, as_list=True)
            )
            return self._find_prefix_result(
                self._listing_key(path), prefix, found, maxdepth, withdirs, kwargs.pop("detail", False)
            )
        return await super()._find(path, maxdepth=maxdepth, withdirs=withdirs, **kwargs)

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
    def _location(self) -> str:
        return self._resolved_location

    @property
    def batch_url_base(self) -> str:
        """Batch API base URL (gcsfs ``batch_url_base``)."""
        return f"{self._location}/batch/storage/v1"

    @property
    def base(self) -> str:
        """JSON API base URL (gcsfs ``base``)."""
        return f"{self._location}/storage/v1/"

    @property
    def on_google(self) -> bool:
        """Whether the endpoint is Google's (not an emulator), as gcsfs
        decides it."""
        return f"torage.{_gcp_universe_domain()}" in self._location

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

    async def _mv_file(self, path1: Any, path2: Any, **kwargs: Any) -> None:
        if self.split_path(self._strip(path2))[2]:
            raise ValueError("Cannot move to specific object generation")
        await super()._mv_file(path1, path2)

    def mv_file(self, path1: Any, path2: Any, **kwargs: Any) -> None:
        """Move one object (gcsfs ``mv_file``)."""
        if self.split_path(self._strip(path2))[2]:
            raise ValueError("Cannot move to specific object generation")
        try:
            self._rfs.mv_file(self._strip(path1), self._strip(path2))
        finally:
            self.invalidate_cache(path1)
            self.invalidate_cache(path2)

    def getxattr(self, path: Any, attr: str) -> Any:
        """One user metadata value of an object."""
        return (self.info(path).get("metadata") or {})[attr]

    async def _getxattr(self, path: Any, attr: str) -> Any:
        return ((await self._info(path)).get("metadata") or {})[attr]

    def setxattrs(self, path: Any, content_type: Any = None, content_encoding: Any = None, fixed_key_metadata: Any = None, **kwargs: Any) -> Any:
        """Not implemented (gcsfs patches the object's metadata); raises
        ``NotImplementedError``. Pass ``metadata=``/``content_type=`` to
        ``open()`` or ``pipe_file()`` instead."""
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
