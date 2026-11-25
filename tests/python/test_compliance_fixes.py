"""Regression tests for defects found by the compliance sweep
(docs/dev/compliance.md). Offline tests use the memory filesystem; the
service-backed ones skip when the test services are not configured."""

from __future__ import annotations

import os
import pickle
import uuid

import pytest
from fsspec.callbacks import Callback

import fsfast


def _unique() -> str:
    return f"fsfast-fix-{uuid.uuid4().hex[:10]}"


# ---------------------------------------------------------------------------
# offline (memory)


def test_get_creates_local_parent_directories(memory_fs, tmp):
    memory_fs.pipe("/src/a/f", b"1")
    target = f"{tmp}/new/deeper/f"
    memory_fs.get("/src/a/f", target)
    assert open(target, "rb").read() == b"1"
    memory_fs.get(["/src/a/f"], [f"{tmp}/other/x/f"])
    assert os.path.exists(f"{tmp}/other/x/f")
    memory_fs.get_file("/src/a/f", f"{tmp}/single/f")
    assert os.path.exists(f"{tmp}/single/f")


def test_get_file_reports_progress_to_callback(memory_fs, tmp):
    memory_fs.pipe("/f", b"x" * 133)
    cb = Callback()
    memory_fs.get_file("/f", f"{tmp}/f", callback=cb)
    assert cb.size == 133 and cb.value == 133


def test_commit_after_discard_raises(memory_fs):
    f = memory_fs.open("/deferred", "wb", autocommit=False)
    f.write(b"1")
    f.close()
    f.discard()
    with pytest.raises(ValueError):
        f.commit()
    assert not memory_fs.exists("/deferred")


def test_pipe_and_touch_are_deferred_in_a_transaction(memory_fs):
    with memory_fs.transaction:
        memory_fs.pipe("/p", b"1")
        memory_fs.pipe({"/q": b"2"})
        memory_fs.touch("/t")
        assert not memory_fs.exists("/p")
        assert not memory_fs.exists("/q")
        assert not memory_fs.exists("/t")
    assert memory_fs.cat("/p") == b"1" and memory_fs.cat("/q") == b"2"
    assert memory_fs.cat("/t") == b""
    with pytest.raises(RuntimeError), memory_fs.transaction:
        memory_fs.pipe("/gone", b"1")
        raise RuntimeError
    assert not memory_fs.exists("/gone")


def test_pickling_a_write_file_raises_value_and_runtime_error(memory_fs):
    with memory_fs.open("/w", "wb") as f:
        with pytest.raises(ValueError):
            pickle.dumps(f)
        with pytest.raises(RuntimeError):
            pickle.dumps(f)


def test_write_mode_seek_still_raises(memory_fs):
    # zipfile probes seek(tell()) to decide whether it may seek back later.
    import zipfile

    with memory_fs.open("/z.zip", "wb") as f:
        with zipfile.ZipFile(f, "w") as z:
            z.writestr("a", b"data")
    with memory_fs.open("/z.zip", "rb") as f, zipfile.ZipFile(f) as z:
        assert z.read("a") == b"data"


# ---------------------------------------------------------------------------
# services

S3 = os.environ.get("FSFAST_TEST_S3_ENDPOINT")
GCS = os.environ.get("FSFAST_TEST_GCS_ENDPOINT")
AZ = os.environ.get("FSFAST_TEST_AZURE_CONNECTION_STRING")
SMB = os.environ.get("FSFAST_TEST_SMB_HOST")


@pytest.fixture
def s3():
    if not S3:
        pytest.skip("FSFAST_TEST_S3_ENDPOINT not set")
    fs = fsfast.S3FileSystem(
        key=os.environ["FSFAST_TEST_S3_KEY"],
        secret=os.environ["FSFAST_TEST_S3_SECRET"],
        endpoint_url=S3,
        skip_instance_cache=True,
    )
    bucket = _unique()
    fs.mkdir(bucket)
    yield fs, bucket
    fs.rm(bucket, recursive=True)


def test_s3_open_xb_on_existing_object_fails_at_open(s3):
    fs, b = s3
    fs.pipe(f"{b}/x", b"1")
    with pytest.raises(FileExistsError):
        fs.open(f"{b}/x", "xb")
    with fs.open(f"{b}/new", "xb") as f:
        f.write(b"2")
    assert fs.cat(f"{b}/new") == b"2"


def test_s3_append_tell_starts_at_existing_size(s3):
    fs, b = s3
    fs.pipe(f"{b}/a", b"hello\n")
    with fs.open(f"{b}/a", "ab") as f:
        assert f.tell() == 6
        f.write(b"extra")
        assert f.tell() == 11
    assert fs.cat(f"{b}/a") == b"hello\nextra"


def test_s3_put_forwards_s3_parameters(s3, tmp):
    fs, b = s3
    src = f"{tmp}/t.json"
    with open(src, "w") as f:
        f.write("text")
    fs.put(src, f"{b}/t.json", ContentType="text/css")
    assert fs.info(f"{b}/t.json")["ContentType"] == "text/css"
    fs.put_file(src, f"{b}/u.json", ContentType="text/plain", Metadata={"k": "v"})
    assert fs.info(f"{b}/u.json")["ContentType"] == "text/plain"
    assert fs.metadata(f"{b}/u.json") == {"k": "v"}


def test_s3_recursive_put_creates_missing_bucket(s3, tmp):
    fs, _ = s3
    os.makedirs(f"{tmp}/outer/inner")
    for p in ("outer/afile", "outer/inner/bfile"):
        with open(f"{tmp}/{p}", "w") as f:
            f.write("hello")
    bucket = _unique()
    try:
        fs.put(f"{tmp}/outer", bucket, recursive=True)
        assert sorted(fs.find(bucket)) == [f"{bucket}/afile", f"{bucket}/inner/bfile"]
    finally:
        fs.rm(bucket, recursive=True)


def test_s3_find_fills_cache_with_file_and_prefix_of_the_same_name(s3):
    fs, b = s3
    fs.pipe({f"{b}/find/a/a": b"data", f"{b}/find/a": b"", f"{b}/find/b": b""})
    fs.invalidate_cache()
    direct = fs.ls(f"{b}/find", detail=True)
    fs.invalidate_cache()
    fs.find(f"{b}/find")
    assert fs.ls(f"{b}/find", detail=True) == direct
    assert [(o["name"].rsplit("/", 1)[-1], o["type"]) for o in direct] == [
        ("a", "file"),
        ("a", "directory"),
        ("b", "file"),
    ]


def test_gcs_open_xb_on_existing_object_fails_at_open():
    if not GCS:
        pytest.skip("FSFAST_TEST_GCS_ENDPOINT not set")
    fs = fsfast.GCSFileSystem(endpoint_url=GCS, token="anon", project="test", skip_instance_cache=True)
    b = _unique()
    fs.mkdir(b)
    try:
        fs.pipe(f"{b}/x", b"1")
        with pytest.raises(FileExistsError):
            fs.open(f"{b}/x", "xb")
    finally:
        fs.rm(b, recursive=True)


def test_azure_find_honours_maxdepth():
    if not AZ:
        pytest.skip("FSFAST_TEST_AZURE_CONNECTION_STRING not set")
    fs = fsfast.AzureBlobFileSystem(connection_string=AZ, skip_instance_cache=True)
    c = _unique()
    fs.mkdir(c)
    try:
        fs.pipe({f"{c}/s/f1": b"", f"{c}/s/sub/f2": b"", f"{c}/s/sub/deep/f3": b""})
        assert fs.find(f"{c}/s", maxdepth=1) == [f"{c}/s/f1"]
        assert fs.find(f"{c}/s", maxdepth=2, withdirs=True) == [f"{c}/s/f1", f"{c}/s/sub", f"{c}/s/sub/deep", f"{c}/s/sub/f2"]
        assert len(fs.find(f"{c}/s")) == 3
        with pytest.raises(ValueError):
            fs.find(f"{c}/s", maxdepth=0)
        fs.mkdir(f"{c}/t")
        fs.cp(f"{c}/s", f"{c}/t", recursive=True, maxdepth=1)
        assert fs.find(f"{c}/t") == [f"{c}/t/f1"]
    finally:
        fs.rm(c, recursive=True)


def test_smb_glob_matches_directories():
    if not SMB:
        pytest.skip("FSFAST_TEST_SMB_HOST not set")
    fs = fsfast.SMBFileSystem(
        host=SMB,
        port=int(os.environ.get("FSFAST_TEST_SMB_PORT", "445")),
        username=os.environ["FSFAST_TEST_SMB_USER"],
        password=os.environ["FSFAST_TEST_SMB_PASSWORD"],
        skip_instance_cache=True,
    )
    root = f"/{os.environ.get('FSFAST_TEST_SMB_SHARE', 'data')}/{_unique()}"
    try:
        fs.makedirs(f"{root}/sub/nest")
        fs.touch(f"{root}/sub/f1")
        fs.touch(f"{root}/sub/nest/f2")
        assert fs.glob(f"{root}/sub/*") == [f"{root}/sub/f1", f"{root}/sub/nest"]
        assert fs.glob(f"{root}/sub/*/") == [f"{root}/sub/nest"]
        fs.mkdir(f"{root}/copy")
        fs.cp(f"{root}/sub/*", f"{root}/copy", recursive=True)
        assert sorted(fs.find(f"{root}/copy")) == [f"{root}/copy/f1", f"{root}/copy/nest/f2"]
    finally:
        fs.rm(root, recursive=True)
