"""Regression tests for the defects the upstream test suites found
(docs/dev/compliance.md): each test runs the same calls against the
reference implementation and the fsfast class on the same service and
compares the outcomes.

Needs the GCS / Azure emulators (``eval "$(scripts/test-services.sh env)"``);
the offline tests always run.
"""

from __future__ import annotations

import os
import uuid
import warnings
from collections.abc import Callable, Iterator
from typing import Any

import pytest

import fsfast

GCS = os.environ.get("FSFAST_TEST_GCS_ENDPOINT")
AZURE = os.environ.get("FSFAST_TEST_AZURE_CONNECTION_STRING")
needs_gcs = pytest.mark.skipif(not GCS, reason="FSFAST_TEST_GCS_ENDPOINT not set")
needs_azure = pytest.mark.skipif(not AZURE, reason="FSFAST_TEST_AZURE_CONNECTION_STRING not set")

# gcsfs hangs in open() against fake-gcs-server while probing for zonal/HNS
# buckets unless this is off.
os.environ.setdefault("GCSFS_EXPERIMENTAL_ZB_HNS_SUPPORT", "false")


def _unique() -> str:
    return f"fsfast-fix-{uuid.uuid4().hex[:12]}"


def _outcome(fn: Callable[[], Any]) -> Any:
    try:
        return ("ok", fn())
    except Exception as e:  # compared by type
        return ("raise", type(e).__name__)


# ---------------------------------------------------------------------------
# GCS


def test_gcs_location_properties(monkeypatch: pytest.MonkeyPatch) -> None:
    gcsfs = pytest.importorskip("gcsfs")
    monkeypatch.delenv("STORAGE_EMULATOR_HOST", raising=False)
    for domain in (None, "s3nsapis.fr"):
        if domain is None:
            monkeypatch.delenv("GOOGLE_CLOUD_UNIVERSE_DOMAIN", raising=False)
        else:
            monkeypatch.setenv("GOOGLE_CLOUD_UNIVERSE_DOMAIN", domain)
        ref = gcsfs.GCSFileSystem(token="anon", skip_instance_cache=True)
        fast = fsfast.GCSFileSystem(token="anon", skip_instance_cache=True)
        for attr in ("base", "batch_url_base", "on_google"):
            assert getattr(fast, attr) == getattr(ref, attr), attr
        assert fast.url("/test/path") == ref.url("/test/path")
    emu = fsfast.GCSFileSystem(token="anon", endpoint_url="http://127.0.0.1:1", skip_instance_cache=True)
    assert emu.on_google is False
    assert emu.base == "http://127.0.0.1:1/storage/v1/"


@pytest.fixture
def gcs_pair() -> Iterator[tuple[Any, Any, str]]:
    if not GCS:
        pytest.skip("FSFAST_TEST_GCS_ENDPOINT not set")
    gcsfs = pytest.importorskip("gcsfs")
    opts = {"endpoint_url": GCS, "token": "anon", "project": "test"}
    ref = gcsfs.GCSFileSystem(skip_instance_cache=True, **opts)
    fast = fsfast.GCSFileSystem(skip_instance_cache=True, **opts)
    bucket = _unique()
    fast.mkdir(bucket)
    files = {
        "base/test_1": b"1",
        "base/test_2": b"2",
        "base/other": b"3",
        "base/folder_1/file1.txt": b"4",
        "base/folder_2/sub/file2.txt": b"5",
    }
    fast.pipe({f"{bucket}/{k}": v for k, v in files.items()})
    try:
        yield ref, fast, bucket
    finally:
        fast.rm(bucket, recursive=True)


@needs_gcs
def test_gcs_prefix_listings(gcs_pair: tuple[Any, Any, str]) -> None:
    ref, fast, bucket = gcs_pair
    base = f"{bucket}/base"
    calls: list[Callable[[Any], Any]] = [
        lambda fs: fs.ls(base, prefix="test_"),
        lambda fs: fs.ls(base + "/", prefix="folder"),
        lambda fs: fs.ls(base, prefix="folder_1/"),
        lambda fs: sorted(fs.ls(base, prefix="zzz")),
        lambda fs: fs.ls(base + "/test_1", prefix="x"),
        lambda fs: fs.find(base, prefix="test_"),
        lambda fs: fs.find(base, prefix="non_existent_"),
        lambda fs: fs.find(base, prefix="folder_", withdirs=True),
        lambda fs: fs.find(base, prefix="folder_2/s", withdirs=True),
        lambda fs: fs.find(base, prefix="folder", maxdepth=2),
        lambda fs: sorted(fs.find(base, prefix="test_", detail=True)),
        lambda fs: fs.find(base + "/missing", prefix="x"),
    ]
    for i, call in enumerate(calls):
        for fs in (ref, fast):
            fs.invalidate_cache()
        assert _outcome(lambda c=call: c(fast)) == _outcome(lambda c=call: c(ref)), i
    # A prefixed find leaves the listings cache alone (gcsfs).
    fast.invalidate_cache()
    fast.ls(base)
    before = dict(fast.dircache)
    fast.find(base, prefix="test_")
    assert dict(fast.dircache) == before


@needs_gcs
def test_gcs_mv_file(gcs_pair: tuple[Any, Any, str]) -> None:
    ref, fast, bucket = gcs_pair
    for fs in (ref, fast):
        fs.version_aware = True
        try:
            with pytest.raises(ValueError, match="Cannot move to specific object generation"):
                fs.mv_file(f"{bucket}/base/test_1", f"{bucket}/dest#123456")
        finally:
            fs.version_aware = False
    fast.ls(f"{bucket}/base")
    fast.mv_file(f"{bucket}/base/test_1", f"{bucket}/base/moved")
    assert fast.cat(f"{bucket}/base/moved") == b"1"
    assert not fast.exists(f"{bucket}/base/test_1")
    assert f"{bucket}/base/moved" in fast.ls(f"{bucket}/base")


# ---------------------------------------------------------------------------
# Azure


def test_azure_blocksize_and_anon(monkeypatch: pytest.MonkeyPatch) -> None:
    adlfs = pytest.importorskip("adlfs")
    conn = (
        "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;"
        "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
        "BlobEndpoint=http://127.0.0.1:1/devstoreaccount1;"
    )
    for env in (None, "true", "false", "1"):
        if env is None:
            monkeypatch.delenv("AZURE_STORAGE_ANON", raising=False)
        else:
            monkeypatch.setenv("AZURE_STORAGE_ANON", env)
        for anon in (None, True, False):
            kw = {"connection_string": conn, "skip_instance_cache": True}
            if anon is not None:
                kw["anon"] = anon
            ref, fast = adlfs.AzureBlobFileSystem(**kw), fsfast.AzureBlobFileSystem(**kw)
            assert fast.anon is ref.anon, (env, anon)
            assert fast.blocksize == ref.blocksize
    fast = fsfast.AzureBlobFileSystem(connection_string=conn, blocksize=7 * 2**20, skip_instance_cache=True)
    assert fast.blocksize == 7 * 2**20


@pytest.fixture
def azure_pair() -> Iterator[tuple[Any, Any, str]]:
    if not AZURE:
        pytest.skip("FSFAST_TEST_AZURE_CONNECTION_STRING not set")
    adlfs = pytest.importorskip("adlfs")
    ref = adlfs.AzureBlobFileSystem(connection_string=AZURE, skip_instance_cache=True)
    fast = fsfast.AzureBlobFileSystem(connection_string=AZURE, skip_instance_cache=True)
    container = _unique()
    fast.mkdir(container)
    created = [container]
    try:
        yield ref, fast, container
    finally:
        for c in created + [f"{container}-new", f"{container}-ref"]:
            try:
                fast.rm(c, recursive=True)
            except FileNotFoundError:
                pass


CS = {
    "content_type": "application/pdf",
    "content_disposition": 'attachment; filename="f.pdf"',
    "cache_control": "max-age=3600",
}


def _cs(fs: Any, path: str) -> dict[str, Any]:
    cs = fs.info(path, refresh=True)["content_settings"]
    return {k: cs[k] for k in CS}


@needs_azure
def test_azure_content_settings_and_metadata(azure_pair: tuple[Any, Any, str], tmp_path: Any) -> None:
    from azure.storage.blob import ContentSettings

    ref, fast, c = azure_pair
    src = tmp_path / "sample"
    src.write_bytes(b"data")
    for name, fs in (("ref", ref), ("fast", fast)):
        with fs.open(f"{c}/{name}/open.pdf", "wb", content_settings=CS, metadata={"k": "v"}) as f:
            f.write(b"0123456789")
        with fs.open(f"{c}/{name}/obj.pdf", "wb", content_settings=ContentSettings(**CS)) as f:
            f.write(b"x")
        fs.pipe_file(f"{c}/{name}/pipe.pdf", b"0123", content_settings=CS)
        fs.put_file(str(src), f"{c}/{name}/put_file.pdf", content_settings=ContentSettings(**CS))
        fs.put(str(src), f"{c}/{name}/put.pdf", content_settings=CS)
    for leaf in ("open.pdf", "obj.pdf", "pipe.pdf", "put_file.pdf", "put.pdf"):
        assert _cs(fast, f"{c}/fast/{leaf}") == _cs(ref, f"{c}/ref/{leaf}") == CS, leaf
    for name, fs in (("ref", ref), ("fast", fast)):
        assert fs.info(f"{c}/{name}/open.pdf", refresh=True)["metadata"] == {"k": "v"}
        # Without metadata adlfs marks the blob as a file.
        assert fs.info(f"{c}/{name}/pipe.pdf", refresh=True)["metadata"] == {"is_directory": "false"}
    assert fast.cat(f"{c}/fast/put.pdf") == b"data"
    # overwrite=False (adlfs) fails on an existing blob.
    for name, fs in (("ref", ref), ("fast", fast)):
        with pytest.raises(FileExistsError):
            fs.pipe_file(f"{c}/{name}/pipe.pdf", b"again", overwrite=False)


@needs_azure
def test_azure_rm_ls_find(azure_pair: tuple[Any, Any, str]) -> None:
    ref, fast, c = azure_pair
    fast.pipe({f"{c}/d/a": b"1", f"{c}/d/sub/x": b"2", f"{c}/p/test_1": b"3", f"{c}/p/test_10": b"4", f"{c}/p2": b"5"})
    calls: list[Callable[[Any], Any]] = [
        lambda fs: c in fs.ls("."),
        lambda fs: c in fs.ls("*") and c in fs.ls("./"),
        lambda fs: fs.find(c, prefix="p"),
        lambda fs: fs.find(f"{c}/p", prefix="test_1"),
        lambda fs: fs.find(f"{c}/p/", prefix="test_"),
        lambda fs: fs.find(c, prefix="d/s", withdirs=True),
        lambda fs: fs.find(f"{c}/p/test_1", prefix="zzz"),
        # Non-recursive rm of a non-empty directory leaves it in place.
        lambda fs: (fs.rm(f"{c}/d"), fs.find(f"{c}/d"))[1],
    ]
    for i, call in enumerate(calls):
        for fs in (ref, fast):
            fs.invalidate_cache()
        assert _outcome(lambda c=call: c(fast)) == _outcome(lambda c=call: c(ref)), i


@needs_azure
def test_azure_mkdir_makedir(azure_pair: tuple[Any, Any, str]) -> None:
    ref, fast, c = azure_pair

    def steps(fs: Any, new: str) -> list[Any]:
        out = []
        out.append(_outcome(lambda: fs.makedir(c, exist_ok=False)))
        out.append(_outcome(lambda: fs.makedir(c, exist_ok=True)))
        out.append(_outcome(lambda: fs.makedir(f"{c}/dir", exist_ok=False)))
        out.append(_outcome(lambda: fs.mkdir(f"{new}/dir", create_parents=False)))
        out.append(_outcome(lambda: fs.makedir(f"{new}/dir")))
        out.append(new in fs.ls(".") and f"{new}/dir" not in fs.ls(new))
        out.append(_outcome(lambda: fs.mkdir(new, exist_ok=False)))
        out.append(_outcome(lambda: fs.mkdir(new)))
        fs.rm(new, recursive=True)
        out.append(new in fs.ls(""))
        return out

    assert steps(fast, f"{c}-new") == steps(ref, f"{c}-ref")


def test_azure_mkdir_probe_failure_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = (
        "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;"
        "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
        "BlobEndpoint=http://127.0.0.1:1/devstoreaccount1;"
    )

    def failing_info(path: str) -> Any:
        raise PermissionError(path)

    for assume, expect in ((None, "warn"), (False, ValueError), (True, None)):
        fs = fsfast.AzureBlobFileSystem(
            connection_string=conn, assume_container_exists=assume, skip_instance_cache=True
        )
        monkeypatch.setattr(fs, "_rfs", _Proxy(fs._rfs, info=failing_info))
        if expect == "warn":
            with pytest.warns(UserWarning, match="Assume it exists already"):
                fs.mkdir("bad_container_name")
        elif expect is ValueError:
            with pytest.raises(ValueError):
                fs.mkdir("bad_container_name")
        else:
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                fs.mkdir("bad_container_name")


class _Proxy:
    """The Rust filesystem with some methods replaced."""

    def __init__(self, inner: Any, **overrides: Any) -> None:
        self._inner = inner
        self._overrides = overrides

    def __getattr__(self, name: str) -> Any:
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._inner, name)
