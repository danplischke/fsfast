"""Shared fixtures for fsfast's Python tests.

Run with ``pytest tests/python`` from the repository's virtualenv after
``maturin develop --release``.
"""

from __future__ import annotations

import os
import sys

import fsspec.asyn
import pytest

import fsfast

HERE = os.path.dirname(__file__)
if HERE not in sys.path:
    sys.path.insert(0, HERE)


# ---------------------------------------------------------------------------
# Guard: no fsfast call may go through fsspec's ``sync()`` event-loop bridge
# (a sync method wrapped by ``mirror_sync_methods``, or fsspec code calling
# ``sync`` on our behalf). The patched ``sync`` raises *and* records the call,
# because callers such as ``exists()`` swallow exceptions; every test fails
# if a call was recorded while it ran.

_SYNC_CALLS: list[str] = []
_original_sync = fsspec.asyn.sync


def _guarded_sync(loop, func, *args, timeout=None, **kwargs):
    owner = getattr(func, "__self__", None)
    if isinstance(owner, fsfast.FsfastFileSystem):
        name = f"{type(owner).__name__}.{getattr(func, '__name__', func)}"
        _SYNC_CALLS.append(name)
        raise AssertionError(f"fsspec.asyn.sync() bridge used for {name}")
    return _original_sync(loop, func, *args, timeout=timeout, **kwargs)


fsspec.asyn.sync = _guarded_sync


@pytest.fixture(autouse=True)
def _no_fsspec_sync_bridge():
    start = len(_SYNC_CALLS)
    yield
    used = _SYNC_CALLS[start:]
    assert not used, f"fsspec.asyn.sync() bridge used for {sorted(set(used))}"


def clear_memory(fs: fsfast.MemoryFileSystem) -> None:
    """Empty a memory filesystem's store."""
    fs.rm("", recursive=True)


@pytest.fixture
def local_fs() -> fsfast.LocalFileSystem:
    return fsfast.LocalFileSystem()


@pytest.fixture
def memory_fs():
    """The shared (global-store) memory filesystem, emptied around the test."""
    fs = fsfast.MemoryFileSystem()
    clear_memory(fs)
    yield fs
    clear_memory(fs)


@pytest.fixture
def isolated_memory_fs() -> fsfast.MemoryFileSystem:
    return fsfast.MemoryFileSystem(global_store=False, skip_instance_cache=True)


@pytest.fixture
def tmp(tmp_path) -> str:
    return str(tmp_path)
