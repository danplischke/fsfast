"""Parity of fsfast.GCSFileSystem with gcsfs.GCSFileSystem against
fake-gcs-server.

Needs ``FSFAST_TEST_GCS_ENDPOINT``; otherwise only the offline path tests
run.
"""

from __future__ import annotations

import os

import pytest

# gcsfs >= 2026.8 probes every bucket over gRPC (60 s stalls on the emulator)
os.environ.setdefault("GCSFS_EXPERIMENTAL_ZB_HNS_SUPPORT", "false")

import fsfast  # noqa: E402
import netparity as np_  # noqa: E402

gcsfs = pytest.importorskip("gcsfs")

ENDPOINT = os.environ.get("FSFAST_TEST_GCS_ENDPOINT")
needs_service = pytest.mark.skipif(not ENDPOINT, reason="FSFAST_TEST_GCS_ENDPOINT not set")


def opts() -> dict:
    return {"endpoint_url": ENDPOINT, "token": "anon", "project": "test"}


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
        name="gcs",
        make_ref=lambda: gcsfs.GCSFileSystem(skip_instance_cache=True, **opts()),
        make_fast=lambda: fsfast.GCSFileSystem(skip_instance_cache=True, **opts()),
        new_root=new_root,
        cleanup=cleanup,
        # Object dicts carry the server's JSON fields in the server's order,
        # which fsfast cannot observe; it uses Google's documented order.
        check_order=False,
        known={
            # gcsfs opens a prefix as an empty object; fsfast raises.
            "open dir": "fsfast raises FileNotFoundError",
        },
        volatile=frozenset(
            {"generation", "etag", "md5Hash", "crc32c", "timeCreated", "updated", "timeStorageClassUpdated", "mtime", "ctime", "id", "selfLink", "mediaLink", "bucket", "acl"}
        ),
    )


@pytest.fixture(scope="module")
def env():
    if not ENDPOINT:
        pytest.skip("FSFAST_TEST_GCS_ENDPOINT not set")
    b = backend()
    ref, fast = b.make_ref(), b.make_fast()
    roots = []
    yield b, ref, fast, roots
    for r in roots:
        b.cleanup(ref, r)


@pytest.mark.parametrize(
    "path",
    [
        "gs://bucket/key",
        "gcs://bucket/dir/",
        "bucket/a/b",
        "gs://bucket",
        "gs://bucket/obj#12345",
        "gs://bucket/obj?generation=42",
        "gs://bucket/not#a-generation",
        "gcs::bucket/x",
        "",
    ],
)
def test_paths(path):
    ref = gcsfs.GCSFileSystem(token="anon", project="p", skip_instance_cache=True)
    fast = fsfast.GCSFileSystem(token="anon", project="p", skip_instance_cache=True)
    assert fast._strip_protocol(path) == ref._strip_protocol(path)
    assert fast._get_kwargs_from_urls(path) == ref._get_kwargs_from_urls(path)
    assert fast._parent(path) == ref._parent(path)
    assert fast.split_path(path) == ref.split_path(path)
    assert fast._split_path(path, version_aware=True) == ref._split_path(path, version_aware=True)
    assert fast.unstrip_protocol(path) == ref.unstrip_protocol(path)
    assert fast.protocol == ref.protocol
    assert fast.root_marker == ref.root_marker


def test_constructor():
    with pytest.raises(ValueError):
        fsfast.GCSFileSystem(access="bogus", token="anon", skip_instance_cache=True)
    fs = fsfast.GCSFileSystem(token="anon", cache_timeout=5, skip_instance_cache=True)
    assert fs.dircache.listings_expiry_time == 5
    with pytest.warns(UserWarning):
        fsfast.GCSFileSystem(project=None, token="anon", skip_instance_cache=True)


@needs_service
def test_reads(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    np_.build_tree(ref, root, b.hierarchical)
    problems = np_.check_reads(b, ref, fast, root)
    assert not problems, "\n".join(problems)
    for label, op in [
        ("info bucket", lambda fs: {k: v for k, v in fs.info(root).items() if k not in ("timeCreated", "updated")}),
        ("ls bucket", lambda fs: fs.ls(root)),
        ("exists bucket", lambda fs: fs.exists(root)),
        ("url", lambda fs: fs.url(f"{root}/a.txt")),
        ("buckets", lambda fs: f"{root}/" in fs.buckets),
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
    assert fast.ls(root, refresh=True) == ref.ls(root, refresh=True) == [f"{root}/a", f"{root}/b"]


@needs_service
def test_fsspec_integration(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    ref.pipe_file(f"{root}/x.bin", b"via fsspec")
    np_.check_fsspec_integration("gs", opts(), f"gs://{root}/x.bin", b"via fsspec", fsfast.GCSFileSystem)
    np_.check_fsspec_integration("gcs", opts(), f"gcs://{root}/x.bin", b"via fsspec", fsfast.GCSFileSystem)


@needs_service
def test_async_and_pickle(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    np_.check_async(lambda: fsfast.GCSFileSystem(asynchronous=True, skip_instance_cache=True, **opts()), root)
    fast.pipe_file(f"{root}/p.bin", b"pickled")
    np_.check_pickle(fast, f"{root}/p.bin", b"pickled")


@needs_service
def test_extras(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    fast.pipe({f"{root}/a": b"aa", f"{root}/b": b"bb"})
    fast.merge(f"{root}/ab", [f"{root}/a", f"{root}/b"])
    assert ref.cat(f"{root}/ab") == b"aabb"
    with fast.open(f"{root}/m", "wb", metadata={"k": "v"}) as f:
        f.write(b"x")
    assert fast.getxattr(f"{root}/m", "k") == ref.getxattr(f"{root}/m", "k") == "v"
    assert fast.modified(f"{root}/m") == ref.modified(f"{root}/m")
    assert fast.created(f"{root}/m") == ref.created(f"{root}/m")
    with pytest.raises(NotImplementedError):
        fast.setxattrs(f"{root}/m", content_type="text/plain")
