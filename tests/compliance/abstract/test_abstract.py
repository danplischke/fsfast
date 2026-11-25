"""fsspec's abstract test suite (``fsspec.tests.abstract``) against every
fsfast class.

The fixtures follow how the reference implementations wire the suite:

* local: fsspec's ``implementations/tests/local/local_fixtures.py``
  (``tmpdir``, ``auto_mkdir=True``, ``make_path_posix``);
* memory: fsspec's ``memory_fixtures.py`` (cleared store, root ``""``,
  ``/``-joined paths);
* s3/gcs/azure: s3fs's ``tests/derived/s3fs_fixtures.py`` (a bucket as
  ``fs_path``, ``supports_empty_directories=False``), with a fresh bucket per
  test class instead of s3fs's fixed ``test`` bucket so runs on the shared
  services never collide;
* smb (both shares) and sftp: a fresh directory per test class.

``FSFAST_COMPLIANCE_IMPL=ref`` runs the same classes against the reference
implementations, which is how the triage in ``docs/dev/compliance.md``
separates fsfast defects from properties of the suite or of an emulator.

HTTP is not run: the suite needs ``makedirs``/``rm``/``touch`` on the
remote side, which fsspec's HTTPFileSystem does not offer either (fsspec
does not run this suite for http).
"""

from __future__ import annotations

import posixpath

import pytest
from fsspec.implementations.local import make_path_posix
from fsspec.tests import abstract
from fsspec.tests.abstract import AbstractFixtures

from backends import IMPL, backends, cleanup

SUITES = {
    "Copy": abstract.AbstractCopyTests,
    "Get": abstract.AbstractGetTests,
    "Put": abstract.AbstractPutTests,
    "Open": abstract.AbstractOpenTests,
    "Pipe": abstract.AbstractPipeTests,
}

# ---------------------------------------------------------------------------
# local / memory


class LocalFixtures(AbstractFixtures):
    @pytest.fixture(scope="class")
    @classmethod
    def fs(cls):
        if IMPL == "ref":
            from fsspec.implementations.local import LocalFileSystem
        else:
            from fsfast import LocalFileSystem
        return LocalFileSystem(auto_mkdir=True)

    @pytest.fixture
    def fs_path(self, tmpdir):
        return str(tmpdir)

    @pytest.fixture
    def fs_sanitize_path(self):
        return make_path_posix


def _clear_memory(m) -> None:
    if IMPL == "ref":
        m.store.clear()
        m.pseudo_dirs.clear()
        m.pseudo_dirs.append("")
    else:
        m.rm("", recursive=True)


class MemoryFixtures(AbstractFixtures):
    @pytest.fixture(scope="class")
    @classmethod
    def fs(cls):
        if IMPL == "ref":
            from fsspec.implementations.memory import MemoryFileSystem
        else:
            from fsfast import MemoryFileSystem
        m = MemoryFileSystem()
        _clear_memory(m)
        try:
            yield m
        finally:
            _clear_memory(m)

    @pytest.fixture
    def fs_join(self):
        return lambda *args: "/".join(args)

    @pytest.fixture
    def fs_path(self):
        return ""


# ---------------------------------------------------------------------------
# network backends


def _network_fixtures(key: str) -> type:
    backend = backends()[key]

    class NetworkFixtures(AbstractFixtures):
        @pytest.fixture(scope="class")
        def _fs_and_root(self):
            fs = backend.make()
            root = backend.new_root(fs)
            try:
                yield fs, root
            finally:
                cleanup(fs, root)

        @pytest.fixture(scope="class")
        def fs(self, _fs_and_root):
            return _fs_and_root[0]

        @pytest.fixture
        def fs_path(self, _fs_and_root):
            return _fs_and_root[1]

        @pytest.fixture
        def fs_join(self):
            return posixpath.join

        @pytest.fixture
        def supports_empty_directories(self):
            return backend.supports_empty_directories

        # Two scenario builders touch ``source/<file>`` before creating
        # ``source``; that only works where writing a file creates its
        # parents (object stores, or local/smb with ``auto_mkdir=True``).
        # On smb/sftp with default options the directory is created first;
        # the scenario itself is unchanged.
        def _glob_edge_cases_files(self, some_fs, some_join, some_path):
            some_fs.makedirs(some_join(some_path, "source"), exist_ok=True)
            return super()._glob_edge_cases_files(some_fs, some_join, some_path)

        def _10_files_with_hashed_names(self, some_fs, some_join, some_path):
            some_fs.makedirs(some_join(some_path, "source"), exist_ok=True)
            return super()._10_files_with_hashed_names(some_fs, some_join, some_path)

    NetworkFixtures.__name__ = f"{key.title().replace('-', '')}Fixtures"
    return NetworkFixtures


FIXTURES: dict[str, type] = {"local": LocalFixtures, "memory": MemoryFixtures}
for _key in backends():
    FIXTURES[_key] = _network_fixtures(_key)

# One test class per (backend, suite), e.g. ``TestS3Copy``.
for _backend, _fixtures in FIXTURES.items():
    for _suite, _tests in SUITES.items():
        _name = f"Test{_backend.title().replace('-', '')}{_suite}"
        globals()[_name] = type(_name, (_tests, _fixtures), {"backend": _backend})
