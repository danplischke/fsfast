"""fsfast's ``sftp://`` / ``ssh://`` filesystem: a drop-in for
``fsspec.implementations.sftp.SFTPFileSystem``."""

from __future__ import annotations

import io
import os
import uuid
from typing import Any

from fsspec.utils import infer_storage_options

from ._base import FsfastFileSystem

__all__ = ["SFTPFileSystem"]

#: paramiko missing-host-key policy classes -> fsfast-sftp names.
_POLICY_NAMES = {
    "AutoAddPolicy": "auto_add",
    "RejectPolicy": "reject",
    "WarningPolicy": "warning",
}


def _policy_option(policy: Any) -> Any:
    """fsspec ``host_key_policy`` (a name, or a paramiko policy class or
    instance) as fsfast-sftp's name."""
    if policy is None or isinstance(policy, str):
        if isinstance(policy, str) and policy not in _POLICY_NAMES.values():
            raise ValueError(
                f"Unknown host_key_policy {policy!r}; expected one of "
                f"{sorted(_POLICY_NAMES.values())} or a paramiko.MissingHostKeyPolicy"
            )
        return policy
    cls = policy if isinstance(policy, type) else type(policy)
    for klass in cls.__mro__:
        if klass.__name__ in _POLICY_NAMES and klass.__module__.startswith("paramiko"):
            return _POLICY_NAMES[klass.__name__]
    # fsspec's message (fsfast maps paramiko's AutoAddPolicy, WarningPolicy
    # and RejectPolicy, and their subclasses).
    raise TypeError(
        f"host_key_policy must be one of {sorted(_POLICY_NAMES.values())}, a "
        f"paramiko.MissingHostKeyPolicy subclass or instance, not {type(policy).__name__}"
    )


def _pkey_option(pkey: Any) -> Any:
    """A paramiko ``PKey`` as private key text (strings pass through)."""
    if pkey is None or isinstance(pkey, str):
        return pkey
    write = getattr(pkey, "write_private_key", None)
    if callable(write):
        buf = io.StringIO()
        write(buf)
        return buf.getvalue()
    raise TypeError(f"pkey must be key text or a paramiko PKey, not {type(pkey).__name__}")


class SFTPFileSystem(FsfastFileSystem):
    """Drop-in replacement for ``fsspec.implementations.sftp.SFTPFileSystem``.

    ``SFTPFileSystem(host, **ssh_kwargs)`` with paramiko's ``connect``
    keywords (``port``, ``username``, ``password``, ``pkey``,
    ``key_filename``, ``passphrase``, ``allow_agent``, ``look_for_keys``,
    ``timeout``, ``banner_timeout``, ``auth_timeout``, ``channel_timeout``,
    ``compress``, ``disabled_algorithms``), ``temppath`` and
    ``host_key_policy``, plus fsfast's options (``known_hosts``,
    ``ssh_config``, ``connections``, ``max_inflight``, ...). Connects at
    construction, like fsspec's class. ``sock``/``transport_factory`` objects
    cannot be passed to the Rust client.
    """

    protocol = ("sftp", "ssh")
    root_marker = ""
    _put_makes_parents = True
    # fsspec's generic touch (open(path, "wb")) is deferred in a transaction.
    _touch_defers_in_transaction = True
    _rust_protocol = "sftp"

    def __init__(self, host: str, **ssh_kwargs: Any) -> None:
        if self._cached:
            return
        python_opts = {
            k: ssh_kwargs.pop(k)
            for k in ("skip_instance_cache", "use_listings_cache", "listings_expiry_time", "max_paths", "asynchronous", "loop")
            if k in ssh_kwargs
        }
        self.temppath = ssh_kwargs.pop("temppath", "/tmp")
        self.host_key_policy = ssh_kwargs.pop("host_key_policy", None)
        self.host = host
        self.ssh_kwargs = ssh_kwargs
        opts = dict(ssh_kwargs)
        if "pkey" in opts:
            opts["pkey"] = _pkey_option(opts["pkey"])
        policy = _policy_option(self.host_key_policy)
        if policy is not None:
            opts["host_key_policy"] = policy
        if isinstance(opts.get("key_filename"), os.PathLike):
            opts["key_filename"] = os.fspath(opts["key_filename"])
        opts = {k: v for k, v in opts.items() if v is not None}
        super().__init__(host=host, temppath=self.temppath, **opts, **python_opts)
        self._rfs.call("connect")

    @classmethod
    def _strip_protocol(cls, path: Any) -> str:
        return infer_storage_options(path)["path"]

    @staticmethod
    def _get_kwargs_from_urls(urlpath: str) -> dict[str, Any]:
        out = infer_storage_options(urlpath)
        out.pop("path", None)
        out.pop("protocol", None)
        return out

    # ------------------------------------------------------------------
    # fsspec sftp semantics

    def info(self, path: Any, **kwargs: Any) -> dict[str, Any]:
        p = self._strip(path)
        out = self._rfs.info(p)
        out["name"] = p  # fsspec names the entry after the path as given
        return out

    async def _info(self, path: Any, **kwargs: Any) -> dict[str, Any]:
        p = self._strip(path)
        out = await self._rfs.info_async(p)
        out["name"] = p
        return out

    def ls(self, path: Any, detail: bool = False, **kwargs: Any) -> list[Any]:
        p = self._strip(path)
        out = self._rfs.ls(p, detail=True)
        self._check_listing(p, out)
        return out if detail else sorted(o["name"] for o in out)

    async def _ls(self, path: Any, detail: bool = False, **kwargs: Any) -> list[Any]:
        p = self._strip(path)
        out = await self._rfs.ls_async(p, detail=True)
        self._check_listing(p, out)
        return out if detail else sorted(o["name"] for o in out)

    @staticmethod
    def _check_listing(path: str, out: list[dict[str, Any]]) -> None:
        if len(out) == 1 and out[0]["type"] != "directory" and out[0]["name"] == path:
            # The core contract's ls of a file; OpenSSH answers OPENDIR on a
            # file with NO_SUCH_FILE, which paramiko raises as ENOENT.
            raise FileNotFoundError(2, "No such file")

    def mkdir(self, path: Any, create_parents: bool = True, mode: int = 511) -> None:
        p = self._strip(path)
        if self.exists(p):
            raise FileExistsError(f"File exists: {p}")
        if create_parents:
            self.makedirs(p)
        else:
            self._rfs.mkdir(p, False)
        if mode != 511:
            self.chmod(p, mode)

    def makedirs(self, path: Any, exist_ok: bool = False, mode: int = 511) -> None:
        p = self._strip(path)
        if self.exists(p) and not exist_ok:
            raise FileExistsError(f"File exists: {p}")
        self._rfs.makedirs(p, True)

    def modified(self, path: Any) -> Any:
        """Last modification time as a datetime."""
        mtime = self.info(path).get("mtime", None)
        if mtime is not None:
            return mtime
        raise RuntimeError("Could not retrieve modification time.")

    async def _modified(self, path: Any) -> Any:
        mtime = (await self._info(path)).get("mtime", None)
        if mtime is not None:
            return mtime
        raise RuntimeError("Could not retrieve modification time.")

    def created(self, path: Any) -> Any:
        """SFTP has no creation time; fsspec returns the modification time."""
        mtime = self.info(path).get("mtime", None)
        if mtime is not None:
            return mtime
        raise RuntimeError("Could not retrieve creation time (modification time).")

    async def _created(self, path: Any) -> Any:
        return await self._modified(path)

    def put_file(self, lpath: Any, rpath: Any, callback: Any = None, **kwargs: Any) -> None:
        self.makedirs(self._parent(os.fspath(rpath)), exist_ok=True)
        from fsspec.callbacks import DEFAULT_CALLBACK

        super().put_file(lpath, rpath, callback=callback or DEFAULT_CALLBACK, **kwargs)

    def get_file(self, rpath: Any, lpath: Any, callback: Any = None, outfile: Any = None, **kwargs: Any) -> None:
        from fsspec.callbacks import DEFAULT_CALLBACK

        if outfile is None and isinstance(lpath, (str, os.PathLike)) and self.isdir(rpath):
            os.makedirs(lpath, exist_ok=True)
            return
        super().get_file(rpath, lpath, callback=callback or DEFAULT_CALLBACK, outfile=outfile, **kwargs)

    def mv(self, old: Any, new: Any, recursive: Any = None, maxdepth: Any = None, **kwargs: Any) -> None:
        """Rename (``posix-rename@openssh.com``; directories move whole)."""
        self._rfs.mv_file(self._strip(old), self._strip(new))

    def _transaction_temp_path(self, path: str) -> str:
        # fsspec writes deferred files to <temppath>/<uuid>.
        return "/".join([self.temppath, str(uuid.uuid4())])

    def _rekey_root(self, path: Any, found: Any, detail: bool) -> Any:
        # fsspec's generic find keys the root by the path as given.
        given = self._strip(path)
        bare = given.rstrip("/")
        if given == bare:
            return found
        items = found.items() if detail else ((n, None) for n in found)
        out = {given if n == bare else n: i for n, i in items}
        return out if detail else list(out)

    def find(
        self,
        path: Any,
        maxdepth: int | None = None,
        withdirs: bool = False,
        detail: bool = False,
        **kwargs: Any,
    ) -> Any:
        found = super().find(path, maxdepth=maxdepth, withdirs=withdirs, detail=detail)
        return self._rekey_root(path, found, detail)

    async def _find(
        self,
        path: Any,
        maxdepth: int | None = None,
        withdirs: bool = False,
        **kwargs: Any,
    ) -> Any:
        detail = kwargs.pop("detail", False)
        found = await super()._find(path, maxdepth=maxdepth, withdirs=withdirs, detail=detail)
        return self._rekey_root(path, found, detail)

    # ------------------------------------------------------------------
    # paramiko-style extras

    def chmod(self, path: Any, mode: int) -> None:
        """Change the permission bits of ``path``."""
        self._rfs.call("chmod", {"path": self._strip(path), "mode": int(mode)})

    def symlink(self, target: str, link: Any) -> None:
        """Create a symbolic link ``link`` pointing at ``target``."""
        self._rfs.call("symlink", {"target": target, "link": self._strip(link)})

    def readlink(self, path: Any) -> str:
        """The target of a symbolic link."""
        return self._rfs.call("readlink", {"path": self._strip(path)})

    def realpath(self, path: Any) -> str:
        """The server's canonical absolute form of ``path``."""
        return self._rfs.call("realpath", {"path": self._strip(path)})
