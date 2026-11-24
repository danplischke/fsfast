"""fsfast's ``memory://`` filesystem."""

from __future__ import annotations

from typing import Any

from fsspec.implementations import memory as _ref
from fsspec.spec import AbstractFileSystem
from fsspec.utils import tokenize

from ._base import FsfastFileSystem, _is_exc

__all__ = ["MemoryFileSystem"]


class MemoryFileSystem(FsfastFileSystem):
    """Drop-in replacement for ``fsspec.implementations.memory.MemoryFileSystem``.

    Like fsspec's, every default instance shares one process-wide store;
    ``global_store=False`` (with ``skip_instance_cache=True``) gives an
    independent one. File contents live in Rust as immutable buffers: reads,
    ranges and copies never copy data, and ``pipe_file`` of a ``bytes``
    object stores it without copying.

    Unlike fsspec's class there are no ``store``/``pseudo_dirs`` attributes
    (the store is not a Python dict); use ``rm("", recursive=True)`` to empty
    it.
    """

    protocol = "memory"
    root_marker = "/"
    _rust_protocol = "memory"
    _pipe_none_is_empty = True

    _strip_protocol = classmethod(_ref.MemoryFileSystem._strip_protocol.__func__)  # type: ignore[assignment,var-annotated]
    _parent = classmethod(AbstractFileSystem._parent.__func__)  # type: ignore[assignment,var-annotated]
    _get_kwargs_from_urls = staticmethod(_ref.MemoryFileSystem._get_kwargs_from_urls)

    def __init__(self, *args: Any, global_store: bool = True, **kwargs: Any) -> None:
        if self._cached:
            return
        self.global_store = global_store
        super().__init__(*args, **kwargs)

    def _rust_options(self, storage_options: dict[str, Any]) -> dict[str, Any]:
        opts = super()._rust_options(storage_options)
        opts["global_store"] = bool(self.global_store)
        return opts

    @property
    def _fs_token(self) -> str:
        if self.global_store:
            return super()._fs_token
        return tokenize(super()._fs_token, id(self))

    # ------------------------------------------------------------------
    # pickling: an independent store travels with the instance

    def _dump_store(self) -> dict[str, Any]:
        entries = self._rfs.find("", None, True, True)
        dirs = [n for n, i in entries.items() if i["type"] == "directory"]
        files = [n for n, i in entries.items() if i["type"] == "file"]
        data = self._rfs.cat_many(files, on_error="raise") if files else []
        return {"dirs": dirs, "files": dict(zip(files, data))}

    def _load_store(self, state: dict[str, Any]) -> None:
        if state["dirs"]:
            self._rfs.makedirs_many(state["dirs"], exist_ok=True, on_error="raise")
        files = state["files"]
        if files:
            self._rfs.pipe_many(list(files), list(files.values()), on_error="raise")

    def __reduce__(self) -> Any:
        reduced = super().__reduce__()
        if self.global_store:
            return reduced
        factory, (cls, args, kwargs) = reduced
        # Restore into a new instance even when the source is cached.
        kwargs = {**kwargs, "skip_instance_cache": True}
        return factory, (cls, args, kwargs), {"_fsfast_store": self._dump_store()}

    def __setstate__(self, state: dict[str, Any]) -> None:
        store = state.pop("_fsfast_store", None)
        self.__dict__.update(state)
        if store is not None:
            self._load_store(store)

    # ------------------------------------------------------------------
    # "is a file" means "is in the store", as in fsspec. A path can be a
    # stored file and an implied directory at once (a file created after
    # ``mkdir("/x/a")`` at ``/x``); ``info()`` then reports the directory.

    def _stored(self, paths: list[str]) -> list[bool]:
        """Whether each path is a file in the store (an empty read)."""
        out = self._rfs.cat_ranges(paths, [0] * len(paths), [0] * len(paths), on_error="return")
        return [not _is_exc(x) for x in out]

    async def _stored_async(self, paths: list[str]) -> list[bool]:
        out = await self._rfs.cat_ranges_async(
            paths, [0] * len(paths), [0] * len(paths), on_error="return"
        )
        return [not _is_exc(x) for x in out]

    def isfile(self, path: Any) -> bool:
        try:
            return self._stored([self._strip(path)])[0]
        except Exception:
            return False

    async def _isfile(self, path: Any) -> bool:
        try:
            return (await self._stored_async([self._strip(path)]))[0]
        except Exception:
            return False

    # timestamps exist for stored files only (fsspec keeps them on MemoryFile)

    def modified(self, path: Any) -> Any:
        p = self._strip(path)
        if not self._stored([p])[0]:
            raise FileNotFoundError(p)
        return self._rfs.times(p)[0]

    def created(self, path: Any) -> Any:
        p = self._strip(path)
        if not self._stored([p])[0]:
            raise FileNotFoundError(p)
        return self._rfs.times(p)[1]

    async def _modified(self, path: Any) -> Any:
        p = self._strip(path)
        if not (await self._stored_async([p]))[0]:
            raise FileNotFoundError(p)
        return (await self._rfs.times_async(p))[0]

    async def _created(self, path: Any) -> Any:
        p = self._strip(path)
        if not (await self._stored_async([p]))[0]:
            raise FileNotFoundError(p)
        return (await self._rfs.times_async(p))[1]

    # ------------------------------------------------------------------
    # rm: fsspec MemoryFileSystem.rm semantics, batched

    def _rm_steps(
        self, paths: list[str], infos: list[Any], stored: list[bool]
    ) -> list[tuple[str, list[str]]]:
        existed = {p for p, i, f in zip(paths, infos, stored) if f or not _is_exc(i)}
        is_file = dict(zip(paths, stored))
        steps: list[tuple[str, list[str]]] = []
        for p in reversed(paths):
            if is_file[p]:
                if steps and steps[-1][0] == "files":
                    steps[-1][1].append(p)
                else:
                    steps.append(("files", [p]))
            elif p not in existed:
                steps.append(("missing", [p]))
            else:
                steps.append(("dir", [p]))
        return steps

    def rm(self, path: Any, recursive: bool = False, maxdepth: int | None = None) -> None:
        if isinstance(path, str):
            path = self._strip(path)
        else:
            path = self._strip_all(path)
        paths = self.expand_path(path, recursive=recursive, maxdepth=maxdepth)
        infos = self._rfs.info_many(paths, on_error="return")
        for step, items in self._rm_steps(paths, infos, self._stored(paths)):
            if step == "files":
                self._rfs.rm_files(items, on_error="raise")
            elif step == "missing":
                raise FileNotFoundError(items[0])
            elif self._rfs.exists(items[0]):
                # A directory that only existed implicitly vanishes with its
                # last file; a remaining one is removed like fsspec does.
                self._rfs.rmdir(items[0])

    async def _rm(
        self,
        path: Any,
        recursive: bool = False,
        batch_size: int | None = None,
        maxdepth: int | None = None,
        **kwargs: Any,
    ) -> None:
        if isinstance(path, str):
            path = self._strip(path)
        else:
            path = self._strip_all(path)
        paths = await self._expand_path(path, recursive=recursive, maxdepth=maxdepth)
        infos = await self._rfs.info_many_async(paths, on_error="return")
        stored = await self._stored_async(paths)
        for step, items in self._rm_steps(paths, infos, stored):
            if step == "files":
                await self._rfs.rm_files_async(items, on_error="raise")
            elif step == "missing":
                raise FileNotFoundError(items[0])
            elif await self._rfs.exists_async(items[0]):
                await self._rfs.rmdir_async(items[0])
