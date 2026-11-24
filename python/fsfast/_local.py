"""fsfast's ``file://`` / ``local://`` filesystem."""

from __future__ import annotations

import datetime
import os
import os.path as osp
import shutil
from typing import Any

from fsspec.implementations import local as _ref

from ._base import FsfastFileSystem

__all__ = ["LocalFileSystem"]


class LocalFileSystem(FsfastFileSystem, _ref.LocalFileSystem):
    """Drop-in replacement for ``fsspec.implementations.local.LocalFileSystem``.

    It is a subclass of fsspec's class (so ``isinstance`` checks in
    libraries keep working) whose methods all run in Rust: ``info``/``ls``
    with fsspec's exact keys and values, parallel ``find``, in-kernel copies
    (``copy_file_range``), positional parallel reads.

    Parameters
    ----------
    auto_mkdir: bool
        Create the parent directory of every write target, as fsspec does.
    """

    root_marker = "/"
    protocol = ("file", "local")
    local_file = True
    _rust_protocol = "file"
    # fsspec's generic cat_file seeks to ``start`` and returns
    # ``f.read(end - f.tell())`` from a Python file: a count of -1 reads to
    # EOF, anything below raises ValueError.
    _seek_read_ranges = True

    # Path semantics are fsspec's own.
    _strip_protocol = classmethod(_ref.LocalFileSystem._strip_protocol.__func__)  # type: ignore[assignment,var-annotated]
    _parent = classmethod(_ref.LocalFileSystem._parent.__func__)  # type: ignore[assignment,var-annotated]
    _get_kwargs_from_urls = staticmethod(_ref.LocalFileSystem._get_kwargs_from_urls)
    unstrip_protocol = _ref.LocalFileSystem.unstrip_protocol

    def __init__(self, auto_mkdir: bool = False, **kwargs: Any) -> None:
        if self._cached:
            return
        self.auto_mkdir = auto_mkdir
        super().__init__(**kwargs)

    def _rust_options(self, storage_options: dict[str, Any]) -> dict[str, Any]:
        opts = super()._rust_options(storage_options)
        opts["auto_mkdir"] = bool(self.auto_mkdir)
        return opts

    @property
    def fsid(self) -> str:
        return "local"

    def ls(self, path: Any, detail: bool = False, **kwargs: Any) -> list[Any]:
        return self._rfs.ls(self._strip(path), detail=detail)

    def lexists(self, path: Any, **kwargs: Any) -> bool:
        return osp.lexists(self._strip(path))

    def isdir(self, path: Any) -> bool:
        try:
            return self._rfs.info(self._strip(path))["type"] == "directory"
        except (OSError, ValueError):  # like os.path.isdir
            return False

    def modified(self, path: Any) -> datetime.datetime:
        info = self.info(path)
        return datetime.datetime.fromtimestamp(info["mtime"], tz=datetime.timezone.utc)

    def created(self, path: Any) -> datetime.datetime:
        info = self.info(path)
        return datetime.datetime.fromtimestamp(info["created"], tz=datetime.timezone.utc)

    async def _modified(self, path: Any) -> datetime.datetime:
        info = await self._info(path)
        return datetime.datetime.fromtimestamp(info["mtime"], tz=datetime.timezone.utc)

    async def _created(self, path: Any) -> datetime.datetime:
        info = await self._info(path)
        return datetime.datetime.fromtimestamp(info["created"], tz=datetime.timezone.utc)

    # ------------------------------------------------------------------
    # moving: shutil.move semantics (move *into* an existing directory)

    def _move_target(self, path1: str, path2: str) -> str:
        """``shutil.move``'s destination rule: an existing directory
        destination means "move inside it"; moving a directory into itself
        is a ``shutil.Error``."""
        real = path2
        if os.path.isdir(path2):
            if _samefile(path1, path2) and not os.path.islink(path1):
                return path2  # rename onto itself (e.g. case change)
            real = os.path.join(path2, os.path.basename(path1.rstrip("/")))
            if os.path.exists(real):
                raise shutil.Error(f"Destination path '{real}' already exists")
        if os.path.isdir(path1) and not os.path.islink(path1) and _destinsrc(path1, path2):
            raise shutil.Error(f"Cannot move a directory '{path1}' into itself '{path2}'.")
        return real

    def mv(self, path1: Any, path2: Any, recursive: bool = True, maxdepth: int | None = None, **kwargs: Any) -> None:
        """Move files or directories (always recursive, like fsspec's local
        ``mv``, which is ``shutil.move``)."""
        path1 = self._strip(path1)
        path2 = self._strip(path2)
        if self.auto_mkdir:
            self.makedirs(self._parent(path2), exist_ok=True)
        self._rfs.mv_file(path1, self._move_target(path1, path2))

    async def _mv(self, path1: Any, path2: Any, recursive: bool = True, maxdepth: int | None = None, **kwargs: Any) -> None:
        path1 = self._strip(path1)
        path2 = self._strip(path2)
        if self.auto_mkdir:
            await self._makedirs(self._parent(path2), exist_ok=True)
        await self._rfs.mv_file_async(path1, self._move_target(path1, path2))

    # ------------------------------------------------------------------
    # deleting: shutil.rmtree semantics for directories

    def _tree_steps(self, entries: dict[str, dict[str, Any]]) -> tuple[list[str], list[str]]:
        files = [n for n, i in entries.items() if i["type"] != "directory"]
        # Reverse lexicographic order puts children before their parents.
        dirs = sorted((n for n, i in entries.items() if i["type"] == "directory"), reverse=True)
        return files, dirs

    def _check_tree(self, p: str, recursive: bool) -> None:
        if not recursive:
            raise ValueError("Cannot delete directory, set recursive=True")
        if osp.abspath(p) == os.getcwd():
            raise ValueError("Cannot delete current working directory")

    def rm(self, path: Any, recursive: bool = False, maxdepth: int | None = None) -> None:
        """Delete files, or directory trees with ``recursive=True``
        (``maxdepth`` is ignored, as in fsspec's local ``rm``)."""
        if not isinstance(path, list):
            path = [path]
        pending: list[str] = []
        for p in path:
            p = self._strip(p)
            if osp.isdir(p) and not osp.islink(p):
                self._check_tree(p, recursive)
                if pending:
                    self._rfs.rm_files(pending, on_error="raise")
                    pending = []
                files, dirs = self._tree_steps(self._rfs.find(p, withdirs=True, detail=True))
                if files:
                    self._rfs.rm_files(files, on_error="raise")
                self._rfs.rmdir_many(dirs, on_error="raise")
            else:
                pending.append(p)
        if pending:
            self._rfs.rm_files(pending, on_error="raise")

    async def _rm(
        self,
        path: Any,
        recursive: bool = False,
        batch_size: int | None = None,
        maxdepth: int | None = None,
        **kwargs: Any,
    ) -> None:
        if not isinstance(path, list):
            path = [path]
        pending: list[str] = []
        for p in path:
            p = self._strip(p)
            if osp.isdir(p) and not osp.islink(p):
                self._check_tree(p, recursive)
                if pending:
                    await self._rfs.rm_files_async(pending, on_error="raise")
                    pending = []
                entries = await self._rfs.find_async(p, None, True, True)
                files, dirs = self._tree_steps(entries)
                if files:
                    await self._rfs.rm_files_async(files, on_error="raise")
                await self._rfs.rmdir_many_async(dirs, on_error="raise")
            else:
                pending.append(p)
        if pending:
            await self._rfs.rm_files_async(pending, on_error="raise")

    # ------------------------------------------------------------------
    # files

    def _open(
        self,
        path: Any,
        mode: str = "rb",
        block_size: int | str | None = None,
        autocommit: bool = True,
        cache_options: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        if mode not in ("rb", "wb", "ab", "xb"):
            # Modes such as "r+b" need a real OS file: use fsspec's opener.
            path = self._strip(path)
            if self.auto_mkdir and ("w" in mode or "x" in mode or "a" in mode):
                self.makedirs(self._parent(path), exist_ok=True)
            return _ref.LocalFileOpener(path, mode, fs=self, autocommit=autocommit, **kwargs)
        return super()._open(
            path,
            mode=mode,
            block_size=block_size,
            autocommit=autocommit,
            cache_options=cache_options,
            **kwargs,
        )


def _destinsrc(src: str, dst: str) -> bool:
    """Whether ``dst`` is inside ``src`` (``shutil._destinsrc``)."""
    src = os.path.join(os.path.abspath(src), "")
    dst = os.path.join(os.path.abspath(dst), "")
    return dst.startswith(src)


def _samefile(src: str, dst: str) -> bool:
    try:
        return os.path.samefile(src, dst)
    except OSError:
        return False
