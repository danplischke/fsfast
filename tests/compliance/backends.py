"""Backend factories shared by the compliance suites.

Each backend can be built as the fsfast class (``impl="fsfast"``, the
default) or as the reference implementation (``impl="ref"``) so a suite can
be run against both on the same service and their results compared: a test
that fails for the reference too is a property of the suite or of the
emulator, not an fsfast defect.

Network backends read their settings from the environment exported by
``eval "$(scripts/test-services.sh env)"`` and are skipped when it is unset.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pytest

#: Which implementation the suites build: "fsfast" or "ref".
IMPL = os.environ.get("FSFAST_COMPLIANCE_IMPL", "fsfast")


def unique(prefix: str = "fsfast-cmp") -> str:
    """A bucket/directory name no other test run uses."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


@dataclass
class Backend:
    """How to build one filesystem and where a test may write."""

    name: str
    #: environment variable that must be set for the service to be used
    env: str | None
    make_fast: Callable[[], Any]
    make_ref: Callable[[], Any]
    #: create and return a fresh, empty root path (bucket or directory)
    new_root: Callable[[Any], str]
    supports_empty_directories: bool = True
    extra: dict = field(default_factory=dict)

    def available(self) -> bool:
        return self.env is None or bool(os.environ.get(self.env))

    def make(self) -> Any:
        if not self.available():
            pytest.skip(f"{self.env} not set (eval \"$(scripts/test-services.sh env)\")")
        return self.make_ref() if IMPL == "ref" else self.make_fast()


def _rm_quiet(fs: Any, path: str) -> None:
    try:
        fs.rm(path, recursive=True)
    except (FileNotFoundError, OSError):
        pass


# ---------------------------------------------------------------------------
# option sets


def s3_opts() -> dict:
    return {
        "key": os.environ["FSFAST_TEST_S3_KEY"],
        "secret": os.environ["FSFAST_TEST_S3_SECRET"],
        "endpoint_url": os.environ["FSFAST_TEST_S3_ENDPOINT"],
    }


def gcs_opts() -> dict:
    return {"endpoint_url": os.environ["FSFAST_TEST_GCS_ENDPOINT"], "token": "anon", "project": "test"}


def azure_opts() -> dict:
    return {"connection_string": os.environ["FSFAST_TEST_AZURE_CONNECTION_STRING"]}


def smb_opts() -> dict:
    return {
        "host": os.environ["FSFAST_TEST_SMB_HOST"],
        "port": int(os.environ.get("FSFAST_TEST_SMB_PORT", "445")),
        "username": os.environ["FSFAST_TEST_SMB_USER"],
        "password": os.environ["FSFAST_TEST_SMB_PASSWORD"],
    }


def sftp_opts() -> dict:
    return {
        "host": os.environ["FSFAST_TEST_SFTP_HOST"],
        "port": int(os.environ.get("FSFAST_TEST_SFTP_PORT", "22")),
        "username": os.environ["FSFAST_TEST_SFTP_USER"],
        "password": os.environ["FSFAST_TEST_SFTP_PASSWORD"],
    }


# ---------------------------------------------------------------------------
# factories (imports are lazy so a missing reference package only skips)


def _fast(name: str) -> Callable[..., Any]:
    def build(**kw: Any) -> Any:
        import fsfast

        return getattr(fsfast, name)(skip_instance_cache=True, **kw)

    return build


def _ref_s3(**kw: Any) -> Any:
    s3fs = pytest.importorskip("s3fs")
    return s3fs.S3FileSystem(skip_instance_cache=True, **kw)


def _ref_gcs(**kw: Any) -> Any:
    # gcsfs hangs in open() against fake-gcs-server while probing for
    # zonal/HNS buckets unless this is off.
    os.environ.setdefault("GCSFS_EXPERIMENTAL_ZB_HNS_SUPPORT", "false")
    gcsfs = pytest.importorskip("gcsfs")
    return gcsfs.GCSFileSystem(skip_instance_cache=True, **kw)


def _ref_azure(**kw: Any) -> Any:
    adlfs = pytest.importorskip("adlfs")
    return adlfs.AzureBlobFileSystem(skip_instance_cache=True, **kw)


def _ref_smb(**kw: Any) -> Any:
    pytest.importorskip("smbclient")
    from fsspec.implementations.smb import SMBFileSystem

    return SMBFileSystem(skip_instance_cache=True, **kw)


def _ref_sftp(**kw: Any) -> Any:
    pytest.importorskip("paramiko")
    from fsspec.implementations.sftp import SFTPFileSystem

    return SFTPFileSystem(skip_instance_cache=True, **kw)


def _bucket_root(fs: Any) -> str:
    bucket = unique()
    fs.mkdir(bucket)
    return bucket


def _smb_root(share: str) -> Callable[[Any], str]:
    def new_root(fs: Any) -> str:
        root = f"/{share}/{unique()}"
        fs.mkdir(root)
        return root

    return new_root


def _sftp_root(fs: Any) -> str:
    # The account's home directory: fsspec sftp exposes paramiko's
    # normalize, fsfast the realpath extension.
    home = fs.ftp.normalize(".") if hasattr(fs, "ftp") else fs.realpath(".")
    root = f"{home.rstrip('/')}/{unique()}"
    fs.mkdir(root)
    return root


def backends() -> dict[str, Backend]:
    """Every network backend the compliance suites run against."""
    return {
        "s3": Backend(
            "s3",
            "FSFAST_TEST_S3_ENDPOINT",
            lambda: _fast("S3FileSystem")(**s3_opts()),
            lambda: _ref_s3(**s3_opts()),
            _bucket_root,
            supports_empty_directories=False,
        ),
        "gcs": Backend(
            "gcs",
            "FSFAST_TEST_GCS_ENDPOINT",
            lambda: _fast("GCSFileSystem")(**gcs_opts()),
            lambda: _ref_gcs(**gcs_opts()),
            _bucket_root,
            supports_empty_directories=False,
        ),
        "azure": Backend(
            "azure",
            "FSFAST_TEST_AZURE_CONNECTION_STRING",
            lambda: _fast("AzureBlobFileSystem")(**azure_opts()),
            lambda: _ref_azure(**azure_opts()),
            _bucket_root,
            supports_empty_directories=False,
        ),
        "smb-data": Backend(
            "smb-data",
            "FSFAST_TEST_SMB_HOST",
            lambda: _fast("SMBFileSystem")(**smb_opts()),
            lambda: _ref_smb(**smb_opts()),
            _smb_root(os.environ.get("FSFAST_TEST_SMB_SHARE", "data")),
        ),
        "smb-enc": Backend(
            "smb-enc",
            "FSFAST_TEST_SMB_HOST",
            lambda: _fast("SMBFileSystem")(**smb_opts()),
            lambda: _ref_smb(**smb_opts()),
            _smb_root(os.environ.get("FSFAST_TEST_SMB_ENC_SHARE", "enc")),
        ),
        "sftp": Backend(
            "sftp",
            "FSFAST_TEST_SFTP_HOST",
            lambda: _fast("SFTPFileSystem")(**sftp_opts()),
            lambda: _ref_sftp(**sftp_opts()),
            _sftp_root,
        ),
    }


def cleanup(fs: Any, root: str) -> None:
    """Remove a root created by ``Backend.new_root``."""
    _rm_quiet(fs, root)
