"""fsfast: Rust implementations of fsspec filesystems.

The classes are drop-in replacements for fsspec's: same protocols, the same
``storage_options``, ``info()`` keys, error types and path semantics, with
the whole data path (sync and async methods, file objects, caching, batching)
in Rust.

Use them directly::

    import fsfast
    fs = fsfast.LocalFileSystem()

or swap them into fsspec's registry so existing code picks them up::

    fsfast.install()                 # every protocol fsfast implements
    fsfast.install(["memory"])       # selected protocols

Setting ``FSFAST_OVERRIDE=file,memory`` (or ``all``) in the environment
installs them when ``fsfast`` is imported.
"""

from __future__ import annotations

import os
import warnings
from typing import Any

import fsspec

from . import _core
from ._base import FsfastFileSystem
from ._core import PreconditionFailed, available_protocols, runtime_info
from ._file import FsfastFile
from ._local import LocalFileSystem
from ._memory import MemoryFileSystem

__version__: str = _core.__version__

__all__ = [
    "FsfastFile",
    "FsfastFileSystem",
    "LocalFileSystem",
    "MemoryFileSystem",
    "PreconditionFailed",
    "__version__",
    "available_protocols",
    "install",
    "installed",
    "reset_stats",
    "runtime_info",
    "stats",
    "uninstall",
]

#: fsspec protocol name -> fsfast class.
CLASSES: dict[str, type[FsfastFileSystem]] = {
    "file": LocalFileSystem,
    "local": LocalFileSystem,
    "memory": MemoryFileSystem,
}

_previous: dict[str, Any] = {}


def _resolve(protocols: str | list[str] | tuple[str, ...] | None) -> list[str]:
    if protocols is None:
        return list(CLASSES)
    if isinstance(protocols, str):
        protocols = [protocols]
    out = []
    for p in protocols:
        p = p.strip().lower()
        if not p:
            continue
        if p not in CLASSES:
            raise ValueError(
                f"fsfast does not implement protocol {p!r} (available: {', '.join(CLASSES)})"
            )
        out.append(p)
    return out


def install(protocols: str | list[str] | tuple[str, ...] | None = None) -> list[str]:
    """Register fsfast's classes in fsspec's registry (``clobber=True``), so
    ``fsspec.filesystem(...)``, ``fsspec.open(...)``, pandas, xarray, dask,
    ... use them. ``None`` installs every protocol fsfast implements.

    Returns the protocols installed.
    """
    from fsspec.registry import _registry

    names = _resolve(protocols)
    for name in names:
        if name not in _previous:
            _previous[name] = _registry.get(name)
        fsspec.register_implementation(name, CLASSES[name], clobber=True)
    return names


def uninstall(protocols: str | list[str] | tuple[str, ...] | None = None) -> list[str]:
    """Undo :func:`install`: restore whatever fsspec had registered before
    (normally its own implementation). Returns the protocols restored."""
    from fsspec.registry import _registry

    names = [n for n in _resolve(protocols) if n in _previous]
    for name in names:
        prev = _previous.pop(name)
        if prev is None:
            _registry.pop(name, None)
        else:
            fsspec.register_implementation(name, prev, clobber=True)
    return names


def installed() -> list[str]:
    """Protocols whose fsspec registry entry is currently an fsfast class."""
    from fsspec.registry import _registry

    return [n for n, cls in CLASSES.items() if _registry.get(n) is cls]


def stats(fs: FsfastFileSystem) -> dict[str, Any]:
    """Request counters and latency quantiles of an fsfast filesystem."""
    return fs.stats()


def reset_stats(fs: FsfastFileSystem) -> None:
    """Zero the counters of an fsfast filesystem."""
    fs.reset_stats()


def _install_from_env() -> None:
    value = os.environ.get("FSFAST_OVERRIDE", "").strip()
    if not value or value.lower() in {"0", "false", "no", "off"}:
        return
    if value.lower() in {"1", "true", "yes", "on", "all", "*"}:
        install()
        return
    wanted = [p for p in value.replace(";", ",").split(",") if p.strip()]
    unknown = [p for p in wanted if p.strip().lower() not in CLASSES]
    if unknown:
        warnings.warn(
            f"FSFAST_OVERRIDE: ignoring protocols fsfast does not implement: {', '.join(unknown)}",
            RuntimeWarning,
            stacklevel=2,
        )
    install([p for p in wanted if p.strip().lower() in CLASSES])


_install_from_env()
