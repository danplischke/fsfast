"""Parity of fsfast.S3FileSystem with s3fs.S3FileSystem against RustFS.

Needs ``FSFAST_TEST_S3_ENDPOINT``/``_KEY``/``_SECRET`` (``eval "$(scripts/
test-services.sh env)"``); otherwise only the offline path tests run.
"""

from __future__ import annotations

import os

import pytest

import fsfast
import netparity as np_

s3fs = pytest.importorskip("s3fs")

ENDPOINT = os.environ.get("FSFAST_TEST_S3_ENDPOINT")
needs_service = pytest.mark.skipif(not ENDPOINT, reason="FSFAST_TEST_S3_ENDPOINT not set")


def opts() -> dict:
    return {
        "key": os.environ["FSFAST_TEST_S3_KEY"],
        "secret": os.environ["FSFAST_TEST_S3_SECRET"],
        "endpoint_url": ENDPOINT,
    }


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
        name="s3",
        make_ref=lambda: s3fs.S3FileSystem(skip_instance_cache=True, **opts()),
        make_fast=lambda: fsfast.S3FileSystem(skip_instance_cache=True, **opts()),
        new_root=new_root,
        cleanup=cleanup,
        known={
            # s3fs (botocore) raises OSError(EINVAL) for a range past EOF.
            "cat_file past eof": "fsfast returns b'' like other fsspec backends",
            # s3fs's mv(recursive=True) copies the tree, then fails copying
            # the directory entry itself (cp_file of a prefix) and leaves
            # the source in place; fsfast skips directory entries.
            "mv dir": "s3fs raises FileNotFoundError after copying",
            # s3fs "opens" a prefix as an empty file; fsfast: FileNotFoundError.
            "open dir": "fsfast raises FileNotFoundError",
        },
        volatile=frozenset({"LastModified", "ETag"}),
        resync={"mv dir": lambda fs, root: fs.rm(f"{root}/tree", recursive=True)},
    )


@pytest.fixture(scope="module")
def env():
    if not ENDPOINT:
        pytest.skip("FSFAST_TEST_S3_ENDPOINT not set")
    b = backend()
    ref, fast = b.make_ref(), b.make_fast()
    roots = []
    yield b, ref, fast, roots
    for r in roots:
        b.cleanup(ref, r)


# ---------------------------------------------------------------------------
# offline: path handling


@pytest.mark.parametrize(
    "path",
    [
        "s3://bucket/key",
        "s3a://bucket/dir/",
        "bucket/a/b",
        "s3://bucket",
        "s3://bucket/key?versionId=abc",
        "s3://arn:aws:s3:us-east-1:123456789012:accesspoint/ap/key",
        "",
        "/bucket/x",
    ],
)
def test_paths(path):
    ref = s3fs.S3FileSystem(anon=True, skip_instance_cache=True)
    fast = fsfast.S3FileSystem(anon=True, skip_instance_cache=True)
    assert fast._strip_protocol(path) == ref._strip_protocol(path)
    assert fast._get_kwargs_from_urls(path) == ref._get_kwargs_from_urls(path)
    assert fast._parent(path) == ref._parent(path)
    assert fast.split_path(path) == ref.split_path(path)
    assert fast.unstrip_protocol(path) == ref.unstrip_protocol(path)
    assert fast.protocol == ref.protocol
    assert fast.root_marker == ref.root_marker


def test_constructor_aliases():
    with pytest.raises(KeyError):
        fsfast.S3FileSystem(key="a", username="b", skip_instance_cache=True)
    with pytest.raises(KeyError):
        fsfast.S3FileSystem(secret="a", password="b", skip_instance_cache=True)
    fs = fsfast.S3FileSystem(username="u", password="p", skip_instance_cache=True)
    assert (fs.key, fs.secret) == ("u", "p")
    fs = fsfast.S3FileSystem(anon=True, version_aware=True, skip_instance_cache=True)
    assert fs.version_aware and fs.anon
    # unknown options are errors, like every fsfast backend
    with pytest.raises(ValueError):
        fsfast.S3FileSystem(not_an_option=1, skip_instance_cache=True)


def test_botocore_values_are_translated():
    botocore = pytest.importorskip("botocore")
    from botocore.config import Config

    fs = fsfast.S3FileSystem(
        config_kwargs={"signature_version": botocore.UNSIGNED},
        client_kwargs={"config": Config(connect_timeout=3, region_name="eu-west-1")},
        skip_instance_cache=True,
    )
    opts_ = fs.rust.options
    assert opts_["config_kwargs"]["signature_version"] == "unsigned"
    assert opts_["client_kwargs"]["config"]["connect_timeout"] == 3


def test_instance_cache():
    a = fsfast.S3FileSystem(anon=True, endpoint_url="http://127.0.0.1:1")
    b = fsfast.S3FileSystem(anon=True, endpoint_url="http://127.0.0.1:1")
    assert a is b


# ---------------------------------------------------------------------------
# live parity


@needs_service
def test_reads(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    np_.build_tree(ref, root, b.hierarchical)
    problems = np_.check_reads(b, ref, fast, root)
    assert not problems, "\n".join(problems)
    # the bucket itself and the root
    for label, op in [
        ("info bucket", lambda fs: fs.info(root)),
        ("ls bucket", lambda fs: fs.ls(root)),
        ("exists bucket", lambda fs: fs.exists(root)),
        ("isdir bucket", lambda fs: fs.isdir(root)),
        ("info root", lambda fs: fs.info("")),
        ("buckets in root", lambda fs: [e for e in fs.ls("", detail=True) if e["name"] == root]),
        ("find all", lambda fs: fs.find("")),
        ("checksum", lambda fs: fs.checksum(f"{root}/a.txt")),
        ("metadata", lambda fs: fs.metadata(f"{root}/a.txt")),
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
    for fs in (ref, fast):
        fs.invalidate_cache()
    ref.pipe_file(f"{root}/a", b"1")
    for fs in (ref, fast):
        assert fs.ls(root) == [f"{root}/a"]
    other.pipe_file(f"{root}/b", b"2")  # written behind both caches
    assert fast.ls(root) == ref.ls(root) == [f"{root}/a"]
    assert fast.exists(f"{root}/b") == ref.exists(f"{root}/b")
    assert fast.ls(root, refresh=True) == ref.ls(root, refresh=True) == [f"{root}/a", f"{root}/b"]
    fast.invalidate_cache(root)
    ref.invalidate_cache(root)
    assert fast.ls(root) == ref.ls(root)
    # disabled cache
    nocache = fsfast.S3FileSystem(use_listings_cache=False, skip_instance_cache=True, **opts())
    nocache.ls(root)
    other.pipe_file(f"{root}/c", b"3")
    assert f"{root}/c" in nocache.ls(root)
    assert not nocache.dircache


@needs_service
def test_fsspec_integration(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    ref.pipe_file(f"{root}/x.bin", b"via fsspec")
    np_.check_fsspec_integration("s3", opts(), f"s3://{root}/x.bin", b"via fsspec", fsfast.S3FileSystem)
    np_.check_fsspec_integration("s3a", opts(), f"s3a://{root}/x.bin", b"via fsspec", fsfast.S3FileSystem)


@needs_service
def test_async_and_pickle(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    np_.check_async(lambda: fsfast.S3FileSystem(asynchronous=True, skip_instance_cache=True, **opts()), root)
    fast.pipe_file(f"{root}/p.bin", b"pickled")
    np_.check_pickle(fast, f"{root}/p.bin", b"pickled")


@needs_service
def test_extras(env):
    b, ref, fast, roots = env
    root = b.new_root(ref)
    roots.append(root)
    p = f"{root}/x.txt"
    fast.pipe_file(p, b"data", Metadata={"mykey": "v1"}, ContentType="text/plain")
    assert fast.info(p, refresh=True)["ContentType"] == ref.info(p, refresh=True)["ContentType"] == "text/plain"
    assert fast.metadata(p) == ref.metadata(p) == {"mykey": "v1"}
    assert fast.getxattr(p, "mykey") == ref.getxattr(p, "mykey") == "v1"
    fast.setxattr(p, mykey="v2", other="o")
    assert ref.metadata(p) == {"mykey": "v2", "other": "o"}
    fast.put_tags(p, {"t1": "a"})
    assert fast.get_tags(p) == ref.get_tags(p) == {"t1": "a"}
    fast.put_tags(p, {"t2": "b"}, mode="m")
    assert ref.get_tags(p) == {"t1": "a", "t2": "b"}
    with pytest.raises(ValueError):
        fast.put_tags(p, {}, mode="x")
    url = fast.url(p, expires=60)
    assert url.startswith(ENDPOINT) and "X-Amz-Signature" in url
    import urllib.request

    with urllib.request.urlopen(url) as resp:  # presigned GET works
        assert resp.read() == b"data"
    assert fast.sign(p).startswith(ENDPOINT)
    fast.invalidate_region_cache()
    assert fast.is_bucket_versioned(root) == ref.is_bucket_versioned(root)
    with pytest.raises(ValueError):
        fast.object_version_info(p)
    with pytest.raises(NotImplementedError):
        fast.url(p, client_method="put_object")
    # open() keywords become request parameters
    with fast.open(f"{root}/typed.bin", "wb", ContentType="application/x-test") as f:
        f.write(b"typed")
    assert ref.info(f"{root}/typed.bin")["ContentType"] == "application/x-test"
    # modified raises IsADirectoryError for prefixes, like s3fs
    ref.pipe_file(f"{root}/d/f", b"")
    with pytest.raises(IsADirectoryError):
        fast.modified(f"{root}/d")
