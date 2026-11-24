"""Exception mapping: Rust ``ErrorKind`` -> Python exception classes with
errno, strerror, filename and backend detail attributes."""

from __future__ import annotations

import errno
import os
import pickle

import pytest

import fsfast


def test_os_error_attributes(tmp):
    fs = fsfast.LocalFileSystem()
    missing = f"{tmp}/missing"
    with pytest.raises(FileNotFoundError) as ei:
        fs.info(missing)
    e = ei.value
    assert e.errno == errno.ENOENT
    assert e.filename == missing
    assert e.strerror == os.strerror(errno.ENOENT)
    # str() reads exactly like an OS error raised by Python itself
    try:
        os.stat(missing)
    except FileNotFoundError as native:
        assert str(e) == str(native)
    for attr in ("http_status", "ntstatus", "sftp_status", "code"):
        assert getattr(e, attr) is None


def test_error_classes(tmp, memory_fs):
    fs = fsfast.LocalFileSystem()
    os.makedirs(f"{tmp}/d/sub")
    with open(f"{tmp}/f", "wb") as f:
        f.write(b"x")
    cases = [
        (lambda: fs.cat_file(f"{tmp}/d"), IsADirectoryError, errno.EISDIR),
        (lambda: fs.ls(f"{tmp}/f/x"), NotADirectoryError, errno.ENOTDIR),
        (lambda: fs.mkdir(f"{tmp}/d"), FileExistsError, errno.EEXIST),
        (lambda: fs.pipe_file(f"{tmp}/f", b"y", mode="create"), FileExistsError, errno.EEXIST),
        (lambda: fs.rmdir(f"{tmp}/d"), OSError, errno.ENOTEMPTY),
        (lambda: fs.rm_file(f"{tmp}/nope"), FileNotFoundError, errno.ENOENT),
        (lambda: fs.open(f"{tmp}/d", "wb"), IsADirectoryError, errno.EISDIR),
        (lambda: memory_fs.rmdir("/"), None, None),
    ]
    for fn, cls, code in cases:
        if cls is None:
            fn()  # memory: rmdir of the root is silently ignored (fsspec)
            continue
        with pytest.raises(cls) as ei:
            fn()
        assert ei.value.errno == code, fn
        assert type(ei.value) is cls or cls is OSError
    # rmdir of a non-empty directory is a plain OSError(ENOTEMPTY)
    with pytest.raises(OSError) as ei:
        fs.rmdir(f"{tmp}/d")
    assert type(ei.value) is OSError
    memory_fs.mkdir("/m/x")
    with pytest.raises(OSError) as ei:
        memory_fs.rmdir("/m")
    assert ei.value.errno == errno.ENOTEMPTY


def test_value_and_not_implemented_errors(tmp, memory_fs):
    fs = fsfast.LocalFileSystem()
    with pytest.raises(NotImplementedError):
        fs.sign(f"{tmp}/x")
    memory_fs.pipe_file("/t", b"1")
    with pytest.raises(NotImplementedError):
        memory_fs.touch("/t", truncate=False)
    with pytest.raises(ValueError):
        fs.find(tmp, maxdepth=0)
    with pytest.raises(ValueError):
        fs.rust.cat_many([tmp], on_error="bogus")
    with pytest.raises(ValueError):
        fs.open(f"{tmp}/x", "rb", cache_type="nonsense")


def test_unknown_storage_options_fail_loudly():
    with pytest.raises(ValueError, match="unknown or unsupported option"):
        fsfast.LocalFileSystem(not_an_option=1, skip_instance_cache=True)
    with pytest.raises(ValueError, match="unknown or unsupported option"):
        fsfast.MemoryFileSystem(typo=True, skip_instance_cache=True)
    with pytest.raises(NotImplementedError, match="protocol"):
        fsfast._core.make_filesystem("nope", {})
    with pytest.raises(TypeError):
        fsfast._core.make_filesystem("memory", {"global_store": object()})
    # Python-layer options are accepted and not passed on.
    fsfast.MemoryFileSystem(
        use_listings_cache=False, listings_expiry_time=1, max_paths=3, skip_instance_cache=True
    )


def test_precondition_failed_is_an_oserror():
    assert issubclass(fsfast.PreconditionFailed, OSError)
    e = fsfast.PreconditionFailed(errno.EINVAL, "changed", "/p")
    assert e.filename == "/p"
    assert fsfast.PreconditionFailed.__module__ == "fsfast"
    assert isinstance(pickle.loads(pickle.dumps(e)), fsfast.PreconditionFailed)


def test_batch_errors_return_or_raise(tmp):
    fs = fsfast.LocalFileSystem()
    fs.pipe_file(f"{tmp}/a", b"aa")
    out = fs.rust.cat_many([f"{tmp}/a", f"{tmp}/b"], on_error="return")
    assert out[0] == b"aa"
    assert isinstance(out[1], FileNotFoundError)
    assert out[1].filename == f"{tmp}/b"
    with pytest.raises(FileNotFoundError):
        fs.rust.cat_many([f"{tmp}/a", f"{tmp}/b"], on_error="raise")
    res = fs.rust.rm_files([f"{tmp}/zz", f"{tmp}/a"], on_error="return")
    assert isinstance(res[0], FileNotFoundError) and res[1] is None
    assert not os.path.exists(f"{tmp}/a")


@pytest.mark.parametrize("backend", ["local", "memory"])
def test_failing_batch_item_never_leaves_partial_files(tmp, backend, isolated_memory_fs):
    """``pipe({...})`` with one failing item raises its error; every other
    target is either untouched or completely written - a write in flight
    is never abandoned half-way (which used to leave truncated files,
    destroying the previous content of existing targets)."""
    if backend == "local":
        fs = fsfast.LocalFileSystem()
        root = tmp
    else:
        fs = isolated_memory_fs
        root = "/r"
    old = b"previous content"
    big = os.urandom(24 << 20)
    for trial in range(3):
        targets = {f"{root}/missing-parent/x": b"1"} if backend == "local" else {}
        if backend == "memory":
            fs.pipe_file(f"{root}/afile", b"f")
            targets[f"{root}/afile/x"] = b"1"  # parent is a file
        names = [f"{root}/t{trial}_{i}" for i in range(6)]
        for n in names:
            fs.pipe_file(n, old)
        targets.update({n: big for n in names})
        with pytest.raises((FileNotFoundError, NotADirectoryError, FileExistsError)):
            fs.pipe(targets)
        for n in names:
            data = fs.cat_file(n)
            assert data in (old, big), (n, len(data))
