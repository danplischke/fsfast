"""Registration, the fsspec integration surface, stats and misc API."""

from __future__ import annotations

import os
import subprocess
import sys

import fsspec
import pytest
from fsspec.asyn import AsyncFileSystem, async_methods, private
from fsspec.implementations.local import LocalFileSystem as RefLocal
from fsspec.spec import AbstractFileSystem

import fsfast


@pytest.mark.parametrize("cls", [fsfast.LocalFileSystem, fsfast.MemoryFileSystem])
def test_no_sync_method_goes_through_fsspec_sync_bridge(cls):
    """mirror_sync_methods replaces a sync method only when it is still
    AbstractFileSystem's default; fsfast overrides every one of them."""
    fs = cls(skip_instance_cache=True)
    for name in set(async_methods + dir(AsyncFileSystem)):
        if not private.match(name):
            continue
        sync = name[1:]
        default = getattr(AbstractFileSystem, sync, None)
        if default is None or not (
            inspect_coroutine(getattr(fs, name, None))
        ):
            continue
        bound = getattr(fs, sync)
        assert getattr(bound, "__func__", None) is not default, sync
        assert "sync_wrapper" not in getattr(bound, "__qualname__", ""), sync
        assert type(bound).__name__ == "method", (sync, bound)


def inspect_coroutine(obj) -> bool:
    import inspect

    return inspect.iscoroutinefunction(obj) or inspect.isasyncgenfunction(obj)


def test_local_is_a_drop_in_subclass():
    fs = fsfast.LocalFileSystem()
    assert isinstance(fs, RefLocal)
    assert isinstance(fs, AsyncFileSystem)
    assert fs.protocol == ("file", "local")
    assert fs.fsid == "local"
    assert fs.local_file is True
    assert fs._isfilestore()


def test_install_and_uninstall():
    before = fsspec.get_filesystem_class("memory")
    try:
        assert fsfast.install(["memory"]) == ["memory"]
        assert fsspec.get_filesystem_class("memory") is fsfast.MemoryFileSystem
        assert isinstance(fsspec.filesystem("memory"), fsfast.MemoryFileSystem)
        assert "memory" in fsfast.installed()
        with fsspec.open("memory://via-fsspec-open", "wb") as f:
            f.write(b"abc")
        with fsspec.open("memory://via-fsspec-open", "rb") as f:
            assert f.read() == b"abc"
        fs, path = fsspec.core.url_to_fs("memory://x/y")
        assert isinstance(fs, fsfast.MemoryFileSystem) and path == "/x/y"
        m = fsspec.get_mapper("memory://mapper")
        m["k"] = b"v"
        assert m["k"] == b"v" and list(m) == ["k"]
        del m["k"]
        with pytest.raises(ValueError):
            fsfast.install(["s3-not-implemented"])
    finally:
        fsfast.uninstall(["memory"])
    assert fsspec.get_filesystem_class("memory") is before


def test_fsfast_override_environment_variable():
    code = (
        "import fsspec, fsfast;"
        "print(fsspec.get_filesystem_class('file').__module__,"
        " fsspec.get_filesystem_class('memory').__module__)"
    )
    env = dict(os.environ, FSFAST_OVERRIDE="file")
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True)
    assert out.stdout.split() == ["fsfast._local", "fsspec.implementations.memory"]
    env["FSFAST_OVERRIDE"] = "all"
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True)
    assert out.stdout.split() == ["fsfast._local", "fsfast._memory"]
    env["FSFAST_OVERRIDE"] = "memory,bogus"
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True)
    assert out.stdout.split()[1] == "fsfast._memory"
    assert "bogus" in out.stderr


def test_stats_and_runtime_info(memory_fs):
    memory_fs.reset_stats()
    memory_fs.pipe_file("/s", b"12345")
    memory_fs.cat_file("/s")
    memory_fs.info("/s")
    s = fsfast.stats(memory_fs)
    assert s["requests"] >= 3
    assert s["bytes_written"] == 5 and s["bytes_read"] == 5
    assert {"read", "write", "info"} <= set(s["ops"])
    assert s["ops"]["read"]["count"] >= 1 and s["ops"]["read"]["p50_us"] >= 0
    fsfast.reset_stats(memory_fs)
    assert fsfast.stats(memory_fs)["requests"] == 0
    info = fsfast.runtime_info()
    assert info["pid"] == os.getpid() and info["workers"] >= 1
    assert set(fsfast.available_protocols()) == {
        "file", "local", "memory", "http", "https", "s3", "s3a", "smb",
        "sftp", "ssh", "gs", "gcs", "abfs", "az", "abfss",
    }
    assert set(fsfast.CLASSES) == set(fsfast.available_protocols())


def test_capabilities_and_hints():
    r = fsfast.LocalFileSystem().rust
    caps = r.capabilities()
    assert caps["hierarchical"] and caps["append"]
    hints = r.io_hints()
    assert hints["request_size"] > 0 and hints["max_concurrency"] > 0
    assert r.protocols == ("file", "local")


def test_instance_caching_and_tokens():
    a = fsfast.LocalFileSystem()
    b = fsfast.LocalFileSystem()
    assert a is b
    c = fsfast.LocalFileSystem(auto_mkdir=True)
    assert c is not a and c.auto_mkdir
    iso1 = fsfast.MemoryFileSystem(global_store=False)
    iso2 = fsfast.MemoryFileSystem(global_store=False)
    assert iso1 is iso2  # instance cache applies (like fsspec)
    iso3 = fsfast.MemoryFileSystem(global_store=False, skip_instance_cache=True)
    assert iso3 is not iso1 and iso3._fs_token != iso1._fs_token


def test_bulk_operations_use_paths_with_protocols(memory_fs, tmp):
    memory_fs.pipe({"memory://p/a": b"1", "memory://p/b": b"2"})
    assert memory_fs.cat(["memory://p/a", "memory://p/b"]) == {"/p/a": b"1", "/p/b": b"2"}
    local = fsfast.LocalFileSystem()
    local.pipe_file(f"file://{tmp}/x", b"local")
    assert local.cat_file(f"local://{tmp}/x") == b"local"
    assert local.exists(f"file://{tmp}/x")


def test_get_file_to_file_like(memory_fs):
    import io

    memory_fs.pipe_file("/gf", b"stream me" * 1000)
    buf = io.BytesIO()
    memory_fs.get_file("/gf", buf)
    assert buf.getvalue() == b"stream me" * 1000


def test_local_rm_semantics(tmp):
    fs = fsfast.LocalFileSystem()
    os.makedirs(f"{tmp}/tree/a/b")
    with open(f"{tmp}/tree/a/b/f", "w") as f:
        f.write("x")
    os.symlink(f"{tmp}/tree/a", f"{tmp}/tree/link")
    outside = f"{tmp}/outside"
    os.makedirs(outside)
    with open(f"{outside}/keep", "w") as f:
        f.write("k")
    os.symlink(outside, f"{tmp}/tree/a/escape")
    with pytest.raises(ValueError, match="recursive=True"):
        fs.rm(f"{tmp}/tree")
    fs.rm(f"{tmp}/tree", recursive=True)
    assert not os.path.lexists(f"{tmp}/tree")
    # symlinks inside the tree are removed, not followed
    assert os.path.exists(f"{outside}/keep")
    cwd = os.getcwd()
    try:
        os.chdir(outside)
        with pytest.raises(ValueError, match="current working directory"):
            fs.rm(outside, recursive=True)
    finally:
        os.chdir(cwd)


def test_local_mv_into_existing_directory(tmp):
    import shutil

    fs = fsfast.LocalFileSystem()
    os.makedirs(f"{tmp}/dst")
    fs.pipe_file(f"{tmp}/f", b"1")
    fs.mv(f"{tmp}/f", f"{tmp}/dst")
    assert fs.cat_file(f"{tmp}/dst/f") == b"1"
    fs.pipe_file(f"{tmp}/f", b"2")
    with pytest.raises(shutil.Error):
        fs.mv(f"{tmp}/f", f"{tmp}/dst")
    auto = fsfast.LocalFileSystem(auto_mkdir=True)
    auto.mv(f"{tmp}/f", f"{tmp}/new/parent/f")
    assert auto.cat_file(f"{tmp}/new/parent/f") == b"2"
    # A directory moved into itself: shutil.move's error (fsspec's local mv)
    os.makedirs(f"{tmp}/selfdir/sub")
    for target in (f"{tmp}/selfdir/inner", f"{tmp}/selfdir/sub"):
        with pytest.raises(shutil.Error, match="into itself"):
            fs.mv(f"{tmp}/selfdir", target)
        with pytest.raises(shutil.Error, match="into itself"):
            RefLocal().mv(f"{tmp}/selfdir", target)
    assert os.path.isdir(f"{tmp}/selfdir/sub")
    fs.mv(f"{tmp}/selfdir", f"{tmp}/selfdir")  # onto itself: a no-op
    fs.mv(f"{tmp}/selfdir", f"{tmp}/selfdir2")  # a prefix sibling is fine
    assert os.path.isdir(f"{tmp}/selfdir2/sub")


def test_memory_dual_file_and_directory_path(isolated_memory_fs):
    fs = isolated_memory_fs
    fs.mkdir("/x/a", create_parents=False)
    fs.pipe_file("/x", b"file too")
    assert fs.info("/x")["type"] == "directory"  # like fsspec
    assert fs.isfile("/x")  # "in the store", like fsspec
    assert fs.modified("/x") is not None
    fs.rm("/x")
    assert not fs.isfile("/x")


def test_sync_instance_does_not_start_fsspec_loop():
    fs = fsfast.MemoryFileSystem(skip_instance_cache=True)
    fs.pipe_file("/z", b"1")
    assert fs.cat_file("/z") == b"1"
    assert fs._loop is None  # the fsspec IO loop was never needed


def test_async_methods_need_a_running_loop(memory_fs, tmp):
    # Like any asyncio API, both the inline-resolved path (memory) and the
    # runtime path (local) require a running event loop.
    memory_fs.pipe_file("/needs-loop", b"x")
    with pytest.raises(RuntimeError):
        memory_fs.rust.info_async("/needs-loop")
    with pytest.raises(RuntimeError):
        fsfast.LocalFileSystem().rust.info_async(tmp)
    # A call that raised must not have done anything: the check comes before
    # the operation starts (memory would complete it inline, local in the
    # background).
    with pytest.raises(RuntimeError):
        memory_fs.rust.pipe_file_async("/not-written", b"x")
    with pytest.raises(RuntimeError):
        memory_fs.rust.rm_file_async("/needs-loop")
    with pytest.raises(RuntimeError):
        fsfast.LocalFileSystem().rust.pipe_file_async(f"{tmp}/not-written", b"x")
    import time

    time.sleep(0.2)
    assert not memory_fs.exists("/not-written")
    assert memory_fs.cat_file("/needs-loop") == b"x"
    assert not os.path.exists(f"{tmp}/not-written")


def test_sync_bridge_guard_catches_wrapped_methods(memory_fs):
    """The conftest guard really sees a method routed through fsspec's
    ``sync()``: wrap one the way ``mirror_sync_methods`` would."""
    import fsspec.asyn

    from conftest import _SYNC_CALLS

    fs = fsfast.MemoryFileSystem(skip_instance_cache=True)
    wrapped = fsspec.asyn.sync_wrapper(fs._info, obj=fs)
    start = len(_SYNC_CALLS)
    with pytest.raises(AssertionError, match="sync"):
        wrapped("/")
    assert _SYNC_CALLS[start:] == ["MemoryFileSystem._info"]
    del _SYNC_CALLS[start:]  # this test triggered it on purpose
