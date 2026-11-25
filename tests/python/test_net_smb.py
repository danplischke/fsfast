"""Parity of fsfast.SMBFileSystem with fsspec's SMBFileSystem against Samba
(the ``data`` share with mandatory signing and the ``enc`` share with
required encryption).

Needs ``FSFAST_TEST_SMB_HOST``/``_USER``/``_PASSWORD``; otherwise only the
offline path tests run.
"""

from __future__ import annotations

import os

import pytest

import fsfast
import netparity as np_

pytest.importorskip("smbprotocol")
from fsspec.implementations.smb import SMBFileSystem as RefSMB  # noqa: E402

HOST = os.environ.get("FSFAST_TEST_SMB_HOST")
needs_service = pytest.mark.skipif(not HOST, reason="FSFAST_TEST_SMB_HOST not set")
SHARES = [os.environ.get("FSFAST_TEST_SMB_SHARE", "data"), os.environ.get("FSFAST_TEST_SMB_ENC_SHARE", "enc")]


def opts() -> dict:
    return {
        "host": HOST,
        "port": int(os.environ.get("FSFAST_TEST_SMB_PORT", "445")),
        "username": os.environ["FSFAST_TEST_SMB_USER"],
        "password": os.environ["FSFAST_TEST_SMB_PASSWORD"],
    }


def backend(share: str) -> np_.Backend:
    def new_root(fs):
        root = f"/{share}/{np_.unique('fsfast-par')}"
        fs.mkdir(root)
        return root

    def cleanup(fs, root):
        try:
            fs.rm(root, recursive=True)
        except OSError:
            pass

    return np_.Backend(
        name=f"smb-{share}",
        make_ref=lambda: RefSMB(skip_instance_cache=True, **opts()),
        make_fast=lambda: fsfast.SMBFileSystem(skip_instance_cache=True, **opts()),
        new_root=new_root,
        cleanup=cleanup,
        hierarchical=True,
        # smbclient raises its own SMBOSError (an OSError) with the errno;
        # fsfast raises the matching OSError subclass with the same errno.
        errno_only=True,
        known={
            # fsspec's smb cat_file fails (AttributeError) for a negative
            # start; fsfast reads the suffix.
            "cat_file suffix": "fsspec smb raises AttributeError",
            "cat_file neg end": "fsspec smb raises",
            # smbclient's file objects have no ``size`` attribute, which
            # fsspec's read_block (and this test) use.
            "read_block": "fsspec smb raises AttributeError",
            "open read seek": "smbclient files have no .size",
            # fsspec rounds a float timestamp to the microsecond, fsfast
            # truncates the exact FILETIME: they can differ by 1 µs.
            "created": "up to 1 µs apart (rounding)",
            # fsspec's smb has no cp_file and its copy() fails for
            # recursive=True; fsfast copies server-side (FSCTL_SRV_COPYCHUNK).
            "cp_file": "fsspec smb raises NotImplementedError",
            "copy recursive": "fsspec smb raises TypeError",
            # fsspec's smb glob never matches a directory (its find keys
            # carry a trailing "/"); fsfast matches directories as fsspec's
            # glob does elsewhere and its abstract suite requires.
            "glob star": "fsspec smb omits directories",
            "glob doublestar": "fsspec smb names directories with a trailing /",
            "glob detail": "fsspec smb omits directories",
            # smbclient files reject 'xb' on an existing file with
            # SMBOSError(EEXIST)... and fsspec's generic mv of a directory
            # is a single server rename in both; see python-parity.md.
        },
        volatile=frozenset({"time", "mtime"}),
        resync={
            "cp_file": lambda fs, root: _mirror(fs, f"{root}/src/one.txt", f"{root}/copy/one.txt"),
            "copy recursive": lambda fs, root: _mirror(fs, f"{root}/src", f"{root}/tree"),
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


@pytest.fixture(scope="module", params=SHARES)
def env(request):
    if not HOST:
        pytest.skip("FSFAST_TEST_SMB_HOST not set")
    b = backend(request.param)
    ref, fast = b.make_ref(), b.make_fast()
    roots = []
    yield b, ref, fast, roots
    for r in roots:
        b.cleanup(ref, r)


@pytest.mark.parametrize(
    "path",
    [
        "smb://host/share/dir/file.csv",
        "smb://user:pw@host:139/share/x",
        "smb://workgroup;user:pw@host/share/folder/",
        "/share/a/b",
        "smb://host/share",
        "smb://host/share/file?q=1#frag",
    ],
)
def test_paths(path):
    assert fsfast.SMBFileSystem._strip_protocol(path) == RefSMB._strip_protocol(path)
    assert fsfast.SMBFileSystem._get_kwargs_from_urls(path) == RefSMB._get_kwargs_from_urls(path)
    assert fsfast.SMBFileSystem._parent(path) == RefSMB._parent(path)
    assert fsfast.SMBFileSystem.protocol == RefSMB.protocol
    assert fsfast.SMBFileSystem.root_marker == RefSMB.root_marker


def test_constructor_validation():
    with pytest.raises(ValueError):
        fsfast.SMBFileSystem("127.0.0.1", register_session_retry_wait=-1, skip_instance_cache=True)
    with pytest.raises(ValueError):
        fsfast.SMBFileSystem("127.0.0.1", register_session_retry_factor=0, skip_instance_cache=True)


@needs_service
def test_eager_connect_fails_at_construction():
    o = opts()
    o["password"] = "wrong-password"
    with pytest.raises(PermissionError):
        fsfast.SMBFileSystem(skip_instance_cache=True, register_session_retries=0, **o)


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
        ("ls share", lambda fs: sorted(x["name"] for x in fs.ls(root.rsplit("/", 1)[0]) if x["name"].startswith(root))),
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
    url = f"smb://{o['username']}:{o['password']}@{o['host']}:{o['port']}{root}/x.bin"
    np_.check_fsspec_integration("smb", o, url, b"via fsspec", fsfast.SMBFileSystem)


@needs_service
def test_async_and_pickle(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    fast.mkdir(f"{root}/async")
    np_.check_async(lambda: fsfast.SMBFileSystem(asynchronous=True, skip_instance_cache=True, **opts()), root)
    # share_access="r": the pickled file reopens the path while the original
    # handle is open (the default, like fsspec's, is an exclusive open).
    shared = fsfast.SMBFileSystem(share_access="r", skip_instance_cache=True, **opts())
    shared.pipe_file(f"{root}/p.bin", b"pickled")
    np_.check_pickle(shared, f"{root}/p.bin", b"pickled")


@needs_service
def test_connection_info(env):
    b, ref, fast, roots = env
    share = b.name.split("-", 1)[1]
    info = fast.connection_info(share)
    assert info["signing"] or info["share_encrypted"]
    if share == "enc":
        assert info["share_encrypted"] or info["encrypt_all"]


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
