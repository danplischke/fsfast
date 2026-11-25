"""pytest plugin that runs an upstream test suite against fsfast's classes.

Loaded with ``-p fsfast_shim`` (``tests/compliance/upstream`` on
``PYTHONPATH``) by ``tests/compliance/run.sh``. Environment:

``FSFAST_SHIM``
    which suite: ``s3fs``, ``fsspec``, ``gcsfs`` or ``adlfs``.
``FSFAST_UPSTREAM_DIR``
    where ``upstream/fetch.sh`` put the sources.
``FSFAST_SHIM_IMPL``
    ``fsfast`` (default) or ``ref``: ``ref`` leaves the reference classes
    in place, giving the baseline the triage compares against.

The installed reference packages lack their ``tests`` packages, so the
fetched source trees are appended to the packages' ``__path__``
(``s3fs.tests``, ``fsspec.implementations.tests``, ``gcsfs.tests`` then
import from the matching upstream tag) while everything else keeps coming
from the installed, identical versions.

Then the reference class is replaced by the fsfast class everywhere a test
can reach it: the module attribute (``from s3fs.core import S3FileSystem``
in a test module resolves after this plugin runs), the package attribute
and fsspec's registry.

Tests that depend on reference internals or that fsfast deliberately does
differently are deselected or marked from ``triage.py`` (one entry per
test, each with its reason); everything else must pass.
"""

from __future__ import annotations

import importlib
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

SUITE = os.environ.get("FSFAST_SHIM", "")
IMPL = os.environ.get("FSFAST_SHIM_IMPL", "fsfast")
UPSTREAM = os.environ.get(
    "FSFAST_UPSTREAM_DIR", os.path.join(os.path.dirname(HERE), ".upstream")
)


def _version(dist: str) -> str:
    import importlib.metadata as md

    return md.version(dist)


def _extend(package: str, path: str) -> None:
    """Let ``package``'s missing subpackages (``tests``) import from ``path``."""
    mod = importlib.import_module(package)
    if not os.path.isdir(path):
        raise pytest.UsageError(f"{path} missing: run tests/compliance/upstream/fetch.sh")
    if path not in mod.__path__:
        mod.__path__.append(path)


def _swap(module: str, name: str, new: type) -> None:
    mod = importlib.import_module(module)
    setattr(mod, name, new)


def _clear_memory(m: object) -> None:
    m.rm("", recursive=True)  # type: ignore[attr-defined]


def _patch_fsspec_memory_fixtures() -> None:
    """fsspec's memory fixtures reset the global store through the
    reference's internals (``m.store.clear()``, ``m.pseudo_dirs``); the
    replacements reset it through the public API. Nothing else changes."""
    import fsspec

    @pytest.fixture()
    def m():
        fs = fsspec.filesystem("memory")
        _clear_memory(fs)
        try:
            yield fs
        finally:
            _clear_memory(fs)

    conftest = importlib.import_module("fsspec.conftest")
    conftest.m = m

    @pytest.fixture(scope="class")
    def fs(cls):
        fs = fsspec.filesystem("memory")
        _clear_memory(fs)
        try:
            yield fs
        finally:
            _clear_memory(fs)

    fixtures = importlib.import_module("fsspec.implementations.tests.memory.memory_fixtures")
    fixtures.MemoryFixtures.fs = fs


def _adlfs_container_names() -> set[str]:
    """Container names that appear as string literals in adlfs's tests
    (the suite creates fixed names such as ``data``, ``catdir``,
    ``putdir``)."""
    import ast

    tests = os.path.join(UPSTREAM, f"adlfs-{_version('adlfs')}", "adlfs", "tests")
    names: set[str] = set()
    for fn in os.listdir(tests):
        if not fn.endswith(".py"):
            continue
        with open(os.path.join(tests, fn)) as f:
            tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                head = node.value.split("/", 1)[0]
                if 3 <= len(head) <= 63 and all(c.islower() or c.isdigit() or c == "-" for c in head):
                    names.add(head)
    return names


def _patch_adlfs_conftest() -> None:
    """adlfs's conftest starts an Azurite docker container (session
    autouse fixture); the shared Azurite service is used instead.

    The suite uses fixed container names (``data``, ``catdir``, ...), so
    it refuses to run if any container named in its sources already exists
    (it could be someone else's), and at the end deletes the containers
    named in its sources that it created (tests that fail midway leave
    them behind)."""
    conftest = importlib.import_module("adlfs.tests.conftest")
    from adlfs.tests.constants import ACCOUNT_NAME, KEY, URL

    @pytest.fixture(scope="session", autouse=True)
    def spawn_azurite():
        from azure.storage.blob import BlobServiceClient

        conn = f"DefaultEndpointsProtocol=http;AccountName={ACCOUNT_NAME};AccountKey={KEY};BlobEndpoint={URL}/{ACCOUNT_NAME};"
        client = BlobServiceClient.from_connection_string(conn)
        ours = _adlfs_container_names()
        before = {c["name"] for c in client.list_containers()}
        clash = sorted(before & ours)
        if clash:
            pytest.exit(f"adlfs suite: Azurite already has containers {clash} (not ours); not running", 3)
        try:
            yield None
        finally:
            for c in client.list_containers():
                if c["name"] in ours and c["name"] not in before:
                    client.delete_container(c["name"])

    conftest.spawn_azurite = spawn_azurite


def _patch_gcsfs_conftest() -> None:
    """gcsfs's fixtures close the aiohttp session on teardown through
    ``GCSFileSystem.close_session(gcs.loop, gcs._session, ...)``, a gcsfs
    internal (fsfast has no aiohttp session; its connections live in the
    Rust backend and close with it). Only that teardown step is replaced."""
    conftest = importlib.import_module("gcsfs.tests.conftest")

    def _close_gcs(gcs: object) -> None:
        return None

    async def _close_gcs_async(gcs: object) -> None:
        return None

    conftest._close_gcs = _close_gcs
    conftest._close_gcs_async = _close_gcs_async


def _setup() -> None:
    import fsspec

    import fsfast

    if SUITE == "s3fs":
        _extend("s3fs", os.path.join(UPSTREAM, f"s3fs-{_version('s3fs')}", "s3fs"))
        if IMPL == "fsfast":
            for mod in ("s3fs", "s3fs.core"):
                _swap(mod, "S3FileSystem", fsfast.S3FileSystem)
            fsfast.install(["s3", "s3a"])
    elif SUITE == "fsspec":
        root = os.path.join(UPSTREAM, f"fsspec-git-{_version('fsspec')}", "fsspec")
        _extend("fsspec", root)
        _extend("fsspec.tests", os.path.join(root, "tests"))
        _extend("fsspec.implementations", os.path.join(root, "implementations"))
        if IMPL == "ref":
            # The installed sshfs package registers itself for sftp/ssh
            # through an entry point; fsspec's tests (and the baseline)
            # are about fsspec's own paramiko-based class.
            for proto in ("sftp", "ssh"):
                fsspec.register_implementation(
                    proto, "fsspec.implementations.sftp.SFTPFileSystem", clobber=True
                )
        if IMPL == "fsfast":
            swaps = {
                "fsspec.implementations.local": ("LocalFileSystem", fsfast.LocalFileSystem),
                "fsspec.implementations.memory": ("MemoryFileSystem", fsfast.MemoryFileSystem),
                "fsspec.implementations.http": ("HTTPFileSystem", fsfast.HTTPFileSystem),
                "fsspec.implementations.sftp": ("SFTPFileSystem", fsfast.SFTPFileSystem),
                "fsspec.implementations.smb": ("SMBFileSystem", fsfast.SMBFileSystem),
            }
            for module, (name, cls) in swaps.items():
                try:
                    _swap(module, name, cls)
                except ImportError:  # optional dependency of the reference missing
                    pass
            fsfast.install(["file", "local", "memory", "http", "https", "sftp", "ssh", "smb"])
            _patch_fsspec_memory_fixtures()
    elif SUITE == "gcsfs":
        # gcsfs probes for zonal/HNS buckets, which hangs against
        # fake-gcs-server.
        os.environ.setdefault("GCSFS_EXPERIMENTAL_ZB_HNS_SUPPORT", "false")
        _extend("gcsfs", os.path.join(UPSTREAM, f"gcsfs-git-{_version('gcsfs')}", "gcsfs"))
        if IMPL == "fsfast":
            for mod in ("gcsfs", "gcsfs.core"):
                _swap(mod, "GCSFileSystem", fsfast.GCSFileSystem)
            fsfast.install(["gs", "gcs"])
            _patch_gcsfs_conftest()
    elif SUITE == "adlfs":
        _patch_adlfs_conftest()
        if IMPL == "fsfast":
            for mod in ("adlfs", "adlfs.spec"):
                _swap(mod, "AzureBlobFileSystem", fsfast.AzureBlobFileSystem)
            fsfast.install(["abfs", "az", "abfss"])
    elif SUITE:
        raise pytest.UsageError(f"FSFAST_SHIM={SUITE!r}: expected s3fs, fsspec, gcsfs or adlfs")
    del fsspec


_setup()


def pytest_report_header(config: pytest.Config) -> str:
    return f"fsfast shim: suite={SUITE or '-'} impl={IMPL} upstream={UPSTREAM}"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Apply the triage table (skip/xfail with the recorded reason)."""
    if IMPL != "fsfast":
        return
    import triage

    table = triage.TABLE.get(SUITE, {})
    used: set[str] = set()
    for item in items:
        for key, (kind, reason) in table.items():
            if triage.matches(key, item.nodeid):
                used.add(key)
                if kind == "skip" or (kind == "skip-root" and os.geteuid() == 0):
                    item.add_marker(pytest.mark.skip(reason=f"[fsfast triage] {reason}"))
                elif kind == "skip-root":
                    pass
                else:
                    item.add_marker(pytest.mark.xfail(reason=f"[fsfast triage] {reason}", strict=False))
                break
    config._fsfast_triage_used = used  # type: ignore[attr-defined]


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter, config: pytest.Config) -> None:
    """List triage entries that matched no collected test (stale entries,
    or tests not selected in this run)."""
    used = getattr(config, "_fsfast_triage_used", None)
    if used is None:
        return
    import triage

    unused = sorted(set(triage.TABLE.get(SUITE, {})) - used)
    if unused:
        terminalreporter.write_sep("-", f"fsfast triage: {len(unused)} entries matched no collected test")
        for key in unused:
            terminalreporter.write_line(f"  {key}")


# ---------------------------------------------------------------------------
# fsspec's smb/sftp tests start docker containers (a Samba share ``home``,
# an sshd with root login) from module fixtures. run.sh runs copies of
# those modules whose ``/home/...`` paths were rewritten to a fresh
# directory on the shared test services (FSFAST_GEN_SMB_ROOT /
# FSFAST_GEN_SFTP_ROOT); here the docker fixtures are replaced by fixtures
# that return the services' connection settings and remove that directory
# afterwards. Test bodies are unchanged.


def _smb_settings() -> dict:
    return {
        "host": os.environ["FSFAST_TEST_SMB_HOST"],
        "port": int(os.environ.get("FSFAST_TEST_SMB_PORT", "445")),
        "username": os.environ["FSFAST_TEST_SMB_USER"],
        "password": os.environ["FSFAST_TEST_SMB_PASSWORD"],
    }


def _sftp_settings() -> dict:
    return {
        "host": os.environ["FSFAST_TEST_SFTP_HOST"],
        "port": int(os.environ.get("FSFAST_TEST_SFTP_PORT", "22")),
        "username": os.environ["FSFAST_TEST_SFTP_USER"],
        "password": os.environ["FSFAST_TEST_SFTP_PASSWORD"],
    }


def _service_fixture(settings, root_env: str, protocol: str):
    @pytest.fixture(scope="module")
    def fixture():
        root = os.environ.get(root_env)
        if not root:
            pytest.skip(f"{root_env} not set (run through tests/compliance/run.sh)")
        import fsspec

        opts = settings()
        fs = fsspec.filesystem(protocol, skip_instance_cache=True, **opts)
        fs.makedirs(root, exist_ok=True)
        try:
            yield opts
        finally:
            try:
                fs.rm(root, recursive=True)
            except OSError:
                pass

    return fixture


@pytest.hookimpl(tryfirst=True)
def pytest_collectstart(collector: pytest.Collector) -> None:
    if not isinstance(collector, pytest.Module):
        return
    name = collector.path.name
    if name == "test_smb.py" and os.environ.get("FSFAST_GEN_SMB_ROOT"):
        collector.obj.smb_params = _service_fixture(_smb_settings, "FSFAST_GEN_SMB_ROOT", "smb")
    elif name == "test_sftp.py" and os.environ.get("FSFAST_GEN_SFTP_ROOT"):
        mod = collector.obj
        mod.ssh = _service_fixture(_sftp_settings, "FSFAST_GEN_SFTP_ROOT", "sftp")
        root = os.environ["FSFAST_GEN_SFTP_ROOT"].rstrip("/") + "/someuser/"

        @pytest.fixture(scope="module")
        def root_path():
            return root

        mod.root_path = root_path
