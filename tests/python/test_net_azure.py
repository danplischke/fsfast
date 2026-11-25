"""Parity of fsfast.AzureBlobFileSystem with adlfs.AzureBlobFileSystem
against Azurite.

Needs ``FSFAST_TEST_AZURE_CONNECTION_STRING``; otherwise only the offline
path tests run.
"""

from __future__ import annotations

import os

import pytest

import fsfast  # noqa: E402
import netparity as np_  # noqa: E402

adlfs = pytest.importorskip("adlfs")

CONN = os.environ.get("FSFAST_TEST_AZURE_CONNECTION_STRING")
needs_service = pytest.mark.skipif(not CONN, reason="FSFAST_TEST_AZURE_CONNECTION_STRING not set")
ENDPOINT = CONN


def opts() -> dict:
    return {"connection_string": CONN}


def backend() -> np_.Backend:
    def new_root(fs):
        bucket = np_.unique("fsfast-par")
        fs.mkdir(bucket)
        return bucket

    def cleanup(fs, root):
        try:
            fs.rm(root, recursive=True)
        except FileNotFoundError:
            pass

    return np_.Backend(
        name="azure",
        make_ref=lambda: adlfs.AzureBlobFileSystem(skip_instance_cache=True, **opts()),
        make_fast=lambda: fsfast.AzureBlobFileSystem(skip_instance_cache=True, **opts()),
        new_root=new_root,
        cleanup=cleanup,
        known={
            # The Azure SDK rejects a negative offset (ValueError); fsfast
            # reads the suffix like other fsfast backends.
            "cat_file suffix": "fsfast reads the last 5 bytes",
            "cat_file neg end": "adlfs raises ValueError (malformed Content-Range)",
            # adlfs fails with TypeError opening a directory.
            "open dir": "fsfast raises IsADirectoryError",
            # adlfs appends only to append blobs; fsfast also appends to block
            # blobs (re-staging the existing blocks).
            "open ab": "adlfs raises ResourceExistsError (InvalidBlobType)",
            # adlfs uploads on close even inside a transaction; fsfast
            # defers the upload to the commit, as fsspec specifies.
            "transaction": "adlfs makes the file visible before commit",
            # As in s3fs: the generic mv copies the tree, then fails copying
            # the directory entry and leaves the source in place.
            "mv dir": "adlfs raises FileNotFoundError after copying",
        },
        resync={
            "mv dir": lambda fs, root: fs.rm(f"{root}/tree", recursive=True),
            "open ab": lambda fs, root: fs.pipe_file(
                f"{root}/w/written.bin", fs.cat_file(f"{root}/w/written.bin") + b"+more"
            )
        },
        volatile=frozenset({"etag", "last_modified", "creation_time", "content_settings", "deleted"}),
    )


@pytest.fixture(scope="module")
def env():
    if not ENDPOINT:
        pytest.skip("FSFAST_TEST_AZURE_CONNECTION_STRING not set")
    b = backend()
    ref, fast = b.make_ref(), b.make_fast()
    roots = []
    yield b, ref, fast, roots
    for r in roots:
        b.cleanup(ref, r)


@pytest.mark.parametrize(
    "path",
    [
        "abfs://container/blob",
        "az://container/dir/",
        "abfss://container@account.dfs.core.windows.net/dir/file",
        "container/a/b",
        "/container/x",
        "abfs://container",
        "abfs://container/blob?versionid=2024-01-01T00:00:00.0000000Z",
        "",
    ],
)
def test_paths(path):
    ref = adlfs.AzureBlobFileSystem(account_name="devstoreaccount1", anon=True, skip_instance_cache=True)
    fast = fsfast.AzureBlobFileSystem(account_name="devstoreaccount1", anon=True, skip_instance_cache=True)
    assert fast._strip_protocol(path) == ref._strip_protocol(path)
    assert fast._get_kwargs_from_urls(path) == ref._get_kwargs_from_urls(path)
    assert fast._parent(path) == ref._parent(path)
    assert fast.split_path(path) == ref.split_path(path)
    assert fast.unstrip_protocol(path) == ref.unstrip_protocol(path)
    assert fast.protocol == ref.protocol
    assert fast.root_marker == ref.root_marker


def test_credential_objects():
    from azure.core.credentials import AzureNamedKeyCredential, AzureSasCredential

    from fsfast._azure import _credential_option

    assert _credential_option(AzureNamedKeyCredential("acct", "a2V5")) == {
        "account_name": "acct",
        "account_key": "a2V5",
    }
    assert _credential_option(AzureSasCredential("sv=1&sig=x")) == {"sas_token": "sv=1&sig=x"}

    class Token:
        def get_token(self, *scopes):
            from azure.core.credentials import AccessToken

            assert scopes == ("https://storage.azure.com/.default",)
            return AccessToken("tok", 1_900_000_000)

    assert _credential_option(Token()) == {"token": "tok", "expires_on": 1_900_000_000}
    with pytest.raises(NotImplementedError):
        _credential_option(object())


@needs_service
def test_reads(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    np_.build_tree(ref, root, b.hierarchical)
    problems = np_.check_reads(b, ref, fast, root)
    assert not problems, "\n".join(problems)
    for label, op in [
        ("info container", lambda fs: {k: v for k, v in fs.info(root).items() if k not in ("etag", "last_modified")}),
        ("ls container", lambda fs: fs.ls(root)),
        ("exists container", lambda fs: fs.exists(root)),
        ("isdir container", lambda fs: fs.isdir(root)),
        ("info root", lambda fs: fs.info("")),
        ("containers", lambda fs: root in fs.ls("")),
        ("getxattr", lambda fs: fs.getxattr(f"{root}/a.txt", "is_directory")),
    ]:
        ref.invalidate_cache()
        fast.invalidate_cache()
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
def test_listings_cache_semantics(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    other = b.make_ref()
    ref.pipe_file(f"{root}/a", b"1")
    for fs in (ref, fast):
        fs.invalidate_cache()
        assert fs.ls(root) == [f"{root}/a"]
    other.pipe_file(f"{root}/b", b"2")
    assert fast.ls(root) == ref.ls(root) == [f"{root}/a"]
    assert fast.ls(root, invalidate_cache=True) == ref.ls(root, invalidate_cache=True) == [f"{root}/a", f"{root}/b"]


@needs_service
def test_fsspec_integration(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    ref.pipe_file(f"{root}/x.bin", b"via fsspec")
    for proto in ("abfs", "az", "abfss"):
        np_.check_fsspec_integration(proto, opts(), f"{proto}://{root}/x.bin", b"via fsspec", fsfast.AzureBlobFileSystem)


@needs_service
def test_async_and_pickle(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    np_.check_async(lambda: fsfast.AzureBlobFileSystem(asynchronous=True, skip_instance_cache=True, **opts()), root)
    fast.pipe_file(f"{root}/p.bin", b"pickled")
    np_.check_pickle(fast, f"{root}/p.bin", b"pickled")


@needs_service
def test_extras(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    p = f"{root}/m.txt"
    fast.pipe_file(p, b"meta")
    fast.setxattrs(p, color="blue", size="xl")
    assert ref.info(p, refresh=True)["metadata"] == {"color": "blue", "size": "xl"}
    assert fast.getxattr(p, "color") == ref.getxattr(p, "color") == "blue"
    assert fast.modified(p) == ref.modified(p)
    assert fast.created(p) == ref.created(p)
    url = fast.url(p, expires=60)
    assert "sig=" in url and "/m.txt" in url
    import urllib.request

    with urllib.request.urlopen(url) as resp:  # the SAS URL reads the blob
        assert resp.read() == b"meta"
    with pytest.raises(NotImplementedError):
        fast.url(p, content_type="text/plain")
    fast.makedir(f"{root}2", exist_ok=True)
    roots.append(f"{root}2")
    assert ref.exists(f"{root}2")
    with pytest.raises(FileExistsError):
        fast.makedir(f"{root}2")


@needs_service
def test_rmdir_semantics(env):
    """adlfs ``rmdir`` deletes a container (even a non-empty one: that is
    how adlfs users drop a container) and is a silent no-op below one."""
    b, ref, fast, roots = env
    outcomes = {}
    for name, fs in (("ref", ref), ("fast", fast)):
        root = b.new_root(ref)
        roots.append(root)
        ref.pipe({f"{root}/a/x": b"x", f"{root}/y": b"y"})
        steps = [
            ("prefix", lambda: fs.rmdir(f"{root}/a")),
            ("missing", lambda: fs.rmdir(f"{root}/nope")),
            ("file", lambda: fs.rmdir(f"{root}/y")),
            ("still there", lambda: [ref.exists(f"{root}/a/x"), ref.exists(f"{root}/y")]),
            ("ls before", lambda: [fs.ls(""), None][1]),  # fill the root cache
            ("container", lambda: fs.rmdir(root)),
            ("gone", lambda: [ref.exists(root, refresh=True), fs.exists(root), root in fs.ls("")]),
            ("missing container", lambda: fs.rmdir(root)),
        ]
        outcomes[name] = [(label, repr(np_.run(op))) for label, op in steps]
    assert outcomes["fast"] == outcomes["ref"]
