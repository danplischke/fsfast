"""fsspec's own abstract test suite (``fsspec.tests.abstract``: copy, get,
put, open, pipe) against fsfast's Local and Memory classes.

The fixtures mirror how fsspec wires the suite for its own classes in its
source tree (``fsspec/implementations/tests/{local,memory}/*_fixtures.py``,
which are not installed with the wheel): local runs in a ``tmpdir`` with
``auto_mkdir=True`` and ``make_path_posix`` as path sanitizer; memory runs
at the root of a cleared store with ``/``-joined paths. The ``local_fs``
used as the other side of ``put``/``get`` is fsspec's reference
``LocalFileSystem`` (as in fsspec); a second set of classes uses fsfast's
local filesystem on that side too.
"""

from __future__ import annotations

import os

import pytest
from fsspec.implementations.local import make_path_posix
from fsspec.tests import abstract
from fsspec.tests.abstract import AbstractFixtures

import fsfast
from conftest import clear_memory


class LocalFixtures(AbstractFixtures):
    @pytest.fixture(scope="class")
    @classmethod
    def fs(cls):
        return fsfast.LocalFileSystem(auto_mkdir=True)

    @pytest.fixture
    def fs_path(self, tmpdir):
        return str(tmpdir)

    @pytest.fixture
    def fs_sanitize_path(self):
        return make_path_posix


class MemoryFixtures(AbstractFixtures):
    @pytest.fixture(scope="class")
    @classmethod
    def fs(cls):
        m = fsfast.MemoryFileSystem()
        clear_memory(m)
        try:
            yield m
        finally:
            clear_memory(m)

    @pytest.fixture
    def fs_join(self):
        return lambda *args: "/".join(args)

    @pytest.fixture
    def fs_path(self):
        return ""


class TestLocalCopy(abstract.AbstractCopyTests, LocalFixtures):
    pass


class TestLocalGet(abstract.AbstractGetTests, LocalFixtures):
    pass


class TestLocalPut(abstract.AbstractPutTests, LocalFixtures):
    pass


class TestLocalOpen(abstract.AbstractOpenTests, LocalFixtures):
    pass


class TestLocalPipe(abstract.AbstractPipeTests, LocalFixtures):
    pass


class TestMemoryCopy(abstract.AbstractCopyTests, MemoryFixtures):
    pass


class TestMemoryGet(abstract.AbstractGetTests, MemoryFixtures):
    pass


class TestMemoryPut(abstract.AbstractPutTests, MemoryFixtures):
    pass


class TestMemoryOpen(abstract.AbstractOpenTests, MemoryFixtures):
    pass


class TestMemoryPipe(abstract.AbstractPipeTests, MemoryFixtures):
    pass


class FsfastLocalSide:
    """Use fsfast's own local filesystem as the local side of put/get."""

    @pytest.fixture(scope="class")
    @classmethod
    def local_fs(cls):
        return fsfast.LocalFileSystem(auto_mkdir=True)


class TestMemoryGetFsfastLocal(FsfastLocalSide, abstract.AbstractGetTests, MemoryFixtures):
    pass


class TestMemoryPutFsfastLocal(FsfastLocalSide, abstract.AbstractPutTests, MemoryFixtures):
    pass


# fsspec.tests.abstract.mv holds module-level tests written against
# ``fsspec.filesystem("file")``; these are the same tests on fsfast's class.


def test_move_raises_error_with_tmpdir(tmpdir):
    source = tmpdir.join("source_file.txt")
    source.write("content")
    destination = tmpdir.join("non_existent_directory/destination_file.txt")
    fs = fsfast.LocalFileSystem()
    with pytest.raises(FileNotFoundError):
        fs.mv(str(source), str(destination))


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="needs non-root POSIX permissions")
@pytest.mark.parametrize("recursive", (True, False))
def test_move_raises_error_with_tmpdir_permission(recursive, tmpdir):
    source = tmpdir.join("source_file.txt")
    source.write("content")
    protected_dir = tmpdir.mkdir("protected_directory")
    os.chmod(str(protected_dir), 0o555)
    destination = protected_dir.join("destination_file.txt")
    fs = fsfast.LocalFileSystem()
    try:
        with pytest.raises(PermissionError):
            fs.mv(str(source), str(destination), recursive=recursive)
        assert not os.path.exists(destination)
    finally:
        os.chmod(str(protected_dir), 0o755)
