"""Parity of fsfast.SFTPFileSystem with fsspec's SFTPFileSystem (paramiko)
against OpenSSH.

Needs ``FSFAST_TEST_SFTP_HOST``/``_PORT``/``_USER``/``_PASSWORD``; otherwise
only the offline path tests run.
"""

from __future__ import annotations

import os

import pytest

import fsfast
import netparity as np_

pytest.importorskip("paramiko")
from fsspec.implementations.sftp import SFTPFileSystem as RefSFTP  # noqa: E402

HOST = os.environ.get("FSFAST_TEST_SFTP_HOST")
needs_service = pytest.mark.skipif(not HOST, reason="FSFAST_TEST_SFTP_HOST not set")


def opts() -> dict:
    return {
        "host": HOST,
        "port": int(os.environ.get("FSFAST_TEST_SFTP_PORT", "22")),
        "username": os.environ["FSFAST_TEST_SFTP_USER"],
        "password": os.environ["FSFAST_TEST_SFTP_PASSWORD"],
    }


def backend() -> np_.Backend:
    def new_root(fs):
        root = f"{fs.ftp.normalize('.')}/{np_.unique('fsfast-par')}"
        fs.mkdir(root)
        return root

    def cleanup(fs, root):
        try:
            fs.rm(root, recursive=True)
        except OSError:
            pass

    return np_.Backend(
        name="sftp",
        make_ref=lambda: RefSFTP(skip_instance_cache=True, **opts()),
        make_fast=lambda: fsfast.SFTPFileSystem(skip_instance_cache=True, **opts()),
        new_root=new_root,
        cleanup=cleanup,
        hierarchical=True,
        known={
            # fsspec's sftp cat_file fails (AttributeError) for a negative
            # start; fsfast reads the suffix.
            "cat_file suffix": "fsspec sftp raises AttributeError",
            "cat_file neg end": "fsspec sftp raises",
            # paramiko files have no ``size`` attribute.
            "read_block": "fsspec sftp raises AttributeError",
            "open read seek": "paramiko files have no .size",
            # fsspec's sftp has no cp_file (NotImplementedError); fsfast
            # copies with copy-data@openssh.com (or a pipelined stream).
            "cp_file": "fsspec sftp raises NotImplementedError",
            "copy recursive": "fsspec sftp raises NotImplementedError",
            # paramiko's file.write returns None; fsfast returns the count
            # like io objects.
            "open wb": "paramiko write() returns None",
            # fsspec's sftp put_file of a directory fails (IsADirectoryError)
            # so put(recursive=True) of a tree with subdirectories fails.
            "put recursive": "fsspec sftp raises IsADirectoryError",
            "copy missing": "fsspec sftp raises NotImplementedError (no cp_file)",
            # fsspec's sftp mv(old, new) takes no recursive keyword.
            "mv dir": "fsspec sftp raises TypeError for recursive=True",
        },
        ignore_tree=frozenset({"/put"}),
        volatile=frozenset({"time", "mtime"}),
        resync={
            "cp_file": lambda fs, root: _mirror(fs, f"{root}/src/one.txt", f"{root}/copy/one.txt"),
            "copy recursive": lambda fs, root: _mirror(fs, f"{root}/src", f"{root}/tree"),
            "mv dir": lambda fs, root: fs.mv(f"{root}/tree", f"{root}/tree2"),
        },
    )


def _mirror(fs, src: str, dst: str) -> None:
    """Copy a file or tree with the reference's working primitives."""
    if fs.isfile(src):
        fs.makedirs(fs._parent(dst), exist_ok=True)
        fs.pipe_file(dst, fs.cat_file(src))
        return
    for name, info in fs.find(src, withdirs=True, detail=True).items():
        target = dst + name.rstrip("/")[len(src) :]
        if info["type"] == "directory":
            fs.makedirs(target, exist_ok=True)
        else:
            fs.makedirs(fs._parent(target), exist_ok=True)
            fs.pipe_file(target, fs.cat_file(name))


@pytest.fixture(scope="module")
def env():
    if not HOST:
        pytest.skip("FSFAST_TEST_SFTP_HOST not set")
    b = backend()
    ref, fast = b.make_ref(), b.make_fast()
    roots = []
    yield b, ref, fast, roots
    for r in roots:
        b.cleanup(ref, r)


@pytest.mark.parametrize(
    "path",
    [
        "sftp://host/abs/path/file",
        "ssh://user:pw@host:2222/home/x",
        "sftp://host/dir/",
        "/abs/a/b",
        "rel/path",
        "sftp://host",
    ],
)
def test_paths(path):
    assert fsfast.SFTPFileSystem._strip_protocol(path) == RefSFTP._strip_protocol(path)
    assert fsfast.SFTPFileSystem._get_kwargs_from_urls(path) == RefSFTP._get_kwargs_from_urls(path)
    assert fsfast.SFTPFileSystem._parent(path) == RefSFTP._parent(path)
    assert fsfast.SFTPFileSystem.protocol == RefSFTP.protocol
    assert fsfast.SFTPFileSystem.root_marker == RefSFTP.root_marker


def test_host_key_policy_names():
    import paramiko

    from fsfast._sftp import _policy_option

    assert _policy_option(None) is None
    assert _policy_option("reject") == "reject"
    assert _policy_option(paramiko.RejectPolicy) == "reject"
    assert _policy_option(paramiko.AutoAddPolicy()) == "auto_add"
    assert _policy_option(paramiko.WarningPolicy()) == "warning"
    with pytest.raises(ValueError):
        _policy_option("bogus")


@needs_service
def test_eager_connect_fails_at_construction():
    o = opts()
    o["password"] = "wrong-password"
    with pytest.raises(PermissionError):
        fsfast.SFTPFileSystem(skip_instance_cache=True, **o)


@needs_service
def test_pkey_object(tmp_path):
    import paramiko

    key = paramiko.Ed25519Key.from_private_key_file  # noqa: F841 - API exists
    from fsfast._sftp import _pkey_option

    rsa = paramiko.RSAKey.generate(1024)
    text = _pkey_option(rsa)
    assert text.startswith("-----BEGIN RSA PRIVATE KEY-----")


@needs_service
def test_reads(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    np_.build_tree(ref, root, b.hierarchical)
    problems = np_.check_reads(b, ref, fast, root)
    assert not problems, "\n".join(problems)
    for label, op in [
        ("created", lambda fs: fs.created(f"{root}/a.txt")),
        ("modified", lambda fs: fs.modified(f"{root}/a.txt")),
        ("ls empty dir", lambda fs: fs.ls(f"{root}/empty")),
        ("info empty dir", lambda fs: fs.info(f"{root}/empty")),
        ("mkdir existing", lambda fs: fs.mkdir(f"{root}/d")),
        ("makedirs existing", lambda fs: fs.makedirs(f"{root}/d")),
        ("rmdir nonempty", lambda fs: fs.rmdir(f"{root}/d")),
    ]:
        msg = np_.compare(b, label, np_.run(lambda: op(ref)), np_.run(lambda: op(fast)))
        assert msg is None, msg


@needs_service
def test_writes(env):
    b, ref, fast, roots = env
    ref_root, fast_root = b.new_root(ref), b.new_root(ref)
    roots += [ref_root, fast_root]
    problems = np_.check_writes(b, ref, fast, ref_root, fast_root)
    assert not problems, "\n".join(problems)


@needs_service
def test_fsspec_integration(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    ref.pipe_file(f"{root}/x.bin", b"via fsspec")
    o = opts()
    for proto in ("sftp", "ssh"):
        url = f"{proto}://{o['username']}@{o['host']}:{o['port']}{root}/x.bin"
        np_.check_fsspec_integration(proto, o, url, b"via fsspec", fsfast.SFTPFileSystem)


@needs_service
def test_async_and_pickle(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    fast.mkdir(f"{root}/async")
    np_.check_async(lambda: fsfast.SFTPFileSystem(asynchronous=True, skip_instance_cache=True, **opts()), root)
    fast.pipe_file(f"{root}/p.bin", b"pickled")
    np_.check_pickle(fast, f"{root}/p.bin", b"pickled")


@needs_service
def test_extras(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    fast.pipe_file(f"{root}/f", b"x")
    fast.chmod(f"{root}/f", 0o600)
    assert ref.ftp.stat(f"{root}/f").st_mode & 0o777 == 0o600
    fast.symlink(f"{root}/f", f"{root}/link")
    assert fast.readlink(f"{root}/link") == ref.ftp.readlink(f"{root}/link")
    assert fast.realpath(".") == ref.ftp.normalize(".")
    with fast.transaction:
        with fast.open(f"{root}/tx", "wb") as f:
            f.write(b"later")
        assert not ref.exists(f"{root}/tx")
    assert ref.cat(f"{root}/tx") == b"later"


@needs_service
def test_fork_rebuilds_connections(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    fast.pipe_file(f"{root}/f.bin", b"before fork")
    pid = os.fork()
    if pid == 0:  # child: the parent's sockets are not used
        code = 0
        try:
            if fast.cat_file(f"{root}/f.bin") != b"before fork":
                code = 1
        except BaseException:
            code = 2
        os._exit(code)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert fast.cat_file(f"{root}/f.bin") == b"before fork"
