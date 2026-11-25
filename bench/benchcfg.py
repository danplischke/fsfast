"""Shared configuration of the benchmark harness (``bench/run.py``).

Profiles fix the workload parameters used by *every* implementation (fsfast's
Python classes, the reference fsspec implementations, the ``fsf`` CLI and the
native tools), so their numbers are comparable. Targets describe how each
implementation reaches one local test service.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, replace
from typing import Any

KiB = 1 << 10
MiB = 1 << 20
GiB = 1 << 30


@dataclass(frozen=True)
class Params:
    """Workload parameters (see docs/BENCHMARKS.md for what each one times)."""

    #: W1/W2/W6: size of the large object.
    size: int
    #: W2: write() chunk size; W1 open-read: read() chunk size.
    chunk: int
    #: W3/W4: number and size of the small files.
    small_count: int
    small_size: int
    #: W5: info() on this many files of the 10k-entry directory.
    info_count: int
    #: W5: entries of the directory that is listed and found.
    ls_entries: int
    #: W6: random ranged reads (cat_ranges) of range_size bytes.
    ranges: int
    range_size: int
    #: W7: copy of copy_count files of copy_size bytes.
    copy_count: int
    copy_size: int
    #: W8: rm of delete_count files.
    delete_count: int
    #: measured iterations and untimed warm-up iterations per workload.
    repeat: int
    warmup: int
    #: operations in flight for fsf's multi-operation workloads (the Python
    #: implementations use their own defaults).
    concurrency: int = 32
    #: W1 seed of the W6 offsets.
    seed: int = 0x5EED

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> Params:
        return cls(**d)


PROFILES: dict[str, Params] = {
    # CI smoke test: proves every workload runs everywhere; numbers are noise.
    "tiny": Params(
        size=2 * MiB,
        chunk=1 * MiB,
        small_count=20,
        small_size=4 * KiB,
        info_count=20,
        ls_entries=50,
        ranges=16,
        range_size=16 * KiB,
        copy_count=4,
        copy_size=64 * KiB,
        delete_count=30,
        repeat=2,
        warmup=1,
        concurrency=8,
    ),
    # The task's workloads (docs/BENCHMARKS.md): 256 MiB objects, 1000 small
    # files, a 10k-entry directory, 64 x 4 MiB copies, 5000 deletes.
    "default": Params(
        size=256 * MiB,
        chunk=8 * MiB,
        small_count=1000,
        small_size=4 * KiB,
        info_count=1000,
        ls_entries=10_000,
        ranges=500,
        range_size=64 * KiB,
        copy_count=64,
        copy_size=4 * MiB,
        delete_count=5000,
        repeat=3,
        warmup=1,
    ),
    # Dedicated hardware: 1 GiB objects, more repetitions.
    "large": Params(
        size=1 * GiB,
        chunk=16 * MiB,
        small_count=1000,
        small_size=4 * KiB,
        info_count=1000,
        ls_entries=10_000,
        ranges=1000,
        range_size=64 * KiB,
        copy_count=64,
        copy_size=4 * MiB,
        delete_count=5000,
        repeat=5,
        warmup=1,
    ),
}


def profile(name: str, overrides: dict[str, int] | None = None) -> Params:
    p = PROFILES[name]
    return replace(p, **overrides) if overrides else p


#: Workload ids and names, shared with ``fsf bench`` (crates/fsfast-cli).
WORKLOADS: list[tuple[str, str, str]] = [
    ("W1", "seq-read", "read one large object (cat_file)"),
    (
        "W1",
        "seq-read-open",
        "read one large object through open() in chunk-sized read() calls",
    ),
    (
        "W2",
        "seq-write",
        "write one large object through open('wb') in chunk-sized write() calls",
    ),
    ("W3", "small-read", "cat() of small_count small files"),
    ("W4", "small-write", "pipe() of small_count small files"),
    ("W5", "metadata-info", "info() on info_count files, one call after another"),
    ("W5", "metadata-ls", "ls(detail=True) of a ls_entries-entry directory"),
    ("W5", "metadata-find", "find() of the same directory"),
    (
        "W6",
        "random-read",
        "cat_ranges() of `ranges` random range_size ranges of the large object",
    ),
    ("W7", "copy", "copy() of copy_count files of copy_size within the filesystem"),
    ("W8", "delete", "rm() of delete_count files"),
]

#: Every named target (``bench/run.py --targets``).
TARGETS = ["local", "memory", "s3", "gcs", "azure", "smb", "smb-enc", "sftp", "http"]

#: Environment variables a target needs (from ``scripts/test-services.sh env``).
TARGET_ENV: dict[str, list[str]] = {
    "local": [],
    "memory": [],
    "http": [],
    "s3": ["FSFAST_TEST_S3_ENDPOINT", "FSFAST_TEST_S3_KEY", "FSFAST_TEST_S3_SECRET"],
    "gcs": ["FSFAST_TEST_GCS_ENDPOINT"],
    "azure": ["FSFAST_TEST_AZURE_CONNECTION_STRING"],
    "smb": ["FSFAST_TEST_SMB_HOST", "FSFAST_TEST_SMB_USER", "FSFAST_TEST_SMB_PASSWORD"],
    "smb-enc": [
        "FSFAST_TEST_SMB_HOST",
        "FSFAST_TEST_SMB_USER",
        "FSFAST_TEST_SMB_PASSWORD",
    ],
    "sftp": [
        "FSFAST_TEST_SFTP_HOST",
        "FSFAST_TEST_SFTP_USER",
        "FSFAST_TEST_SFTP_PASSWORD",
    ],
}

#: Python implementations per target: impl name -> reference description.
#: ``fsfast`` is always available; the others are the reference
#: implementations fsfast replaces (sshfs is a second SFTP reference).
PY_IMPLS: dict[str, dict[str, str]] = {
    "local": {
        "fsfast": "fsfast.LocalFileSystem",
        "reference": "fsspec LocalFileSystem",
    },
    "memory": {
        "fsfast": "fsfast.MemoryFileSystem",
        "reference": "fsspec MemoryFileSystem",
    },
    "http": {
        "fsfast": "fsfast.HTTPFileSystem",
        "reference": "fsspec HTTPFileSystem (aiohttp)",
    },
    "s3": {"fsfast": "fsfast.S3FileSystem", "reference": "s3fs.S3FileSystem"},
    "gcs": {"fsfast": "fsfast.GCSFileSystem", "reference": "gcsfs.GCSFileSystem"},
    "azure": {
        "fsfast": "fsfast.AzureBlobFileSystem",
        "reference": "adlfs.AzureBlobFileSystem",
    },
    "smb": {
        "fsfast": "fsfast.SMBFileSystem",
        "reference": "fsspec SMBFileSystem (smbprotocol)",
    },
    "smb-enc": {
        "fsfast": "fsfast.SMBFileSystem",
        "reference": "fsspec SMBFileSystem (smbprotocol)",
    },
    "sftp": {
        "fsfast": "fsfast.SFTPFileSystem",
        "reference": "fsspec SFTPFileSystem (paramiko)",
        "sshfs": "sshfs.SSHFileSystem (asyncssh)",
    },
}


def smb_share(target: str) -> str:
    if target == "smb-enc":
        return os.environ.get("FSFAST_TEST_SMB_ENC_SHARE", "enc")
    return os.environ.get("FSFAST_TEST_SMB_SHARE", "data")


def storage_options(target: str) -> dict[str, Any]:
    """``storage_options`` for the target, identical for fsfast and the
    reference (option names match the reference implementations)."""
    e = os.environ
    if target == "s3":
        return {
            "key": e["FSFAST_TEST_S3_KEY"],
            "secret": e["FSFAST_TEST_S3_SECRET"],
            "endpoint_url": e["FSFAST_TEST_S3_ENDPOINT"],
        }
    if target == "gcs":
        return {
            "endpoint_url": e["FSFAST_TEST_GCS_ENDPOINT"],
            "token": "anon",
            "project": "test",
        }
    if target == "azure":
        return {"connection_string": e["FSFAST_TEST_AZURE_CONNECTION_STRING"]}
    if target in ("smb", "smb-enc"):
        return {
            "host": e["FSFAST_TEST_SMB_HOST"],
            "port": int(e.get("FSFAST_TEST_SMB_PORT", "445")),
            "username": e["FSFAST_TEST_SMB_USER"],
            "password": e["FSFAST_TEST_SMB_PASSWORD"],
        }
    if target == "sftp":
        return {
            "host": e["FSFAST_TEST_SFTP_HOST"],
            "port": int(e.get("FSFAST_TEST_SFTP_PORT", "22")),
            "username": e["FSFAST_TEST_SFTP_USER"],
            "password": e["FSFAST_TEST_SFTP_PASSWORD"],
        }
    return {}
