"""Live parity harness for the network backends.

Each backend test module describes how to build the reference filesystem
(s3fs, gcsfs, adlfs, fsspec's smb/sftp/http) and fsfast's replacement against
the same local service, and where a scratch root lives. The harness then

* builds one tree with the reference and compares every read-only operation
  run through both implementations on that same tree: results must be equal,
  dicts must have the same keys in the same order, and errors must be of the
  same type (or a subclass of it with the same errno, see
  :func:`same_error`);
* runs the same sequence of mutating operations through each implementation
  in its own root and compares every outcome and the resulting trees
  (snapshotted with the reference, names mapped between the roots).

Intentional deviations are listed per backend in ``Backend.known`` (keyed by
operation label) and documented in docs/dev/python-parity.md.
"""

from __future__ import annotations

import asyncio
import os
import pickle
import tempfile
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import fsspec


def unique(prefix: str = "fsfast") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


@dataclass
class Outcome:
    ok: bool
    value: Any = None
    exc: BaseException | None = None

    def __repr__(self) -> str:
        if self.ok:
            return f"ok({self.value!r})"
        return f"err({type(self.exc).__name__}: {self.exc})"


def run(fn: Callable[[], Any]) -> Outcome:
    try:
        return Outcome(True, fn())
    except Exception as e:  # noqa: BLE001 - comparing exception types
        return Outcome(False, exc=e)


def same_error(ref: BaseException, fast: BaseException, errno_only: bool = False) -> bool:
    """Whether fsfast's exception stands in for the reference's: the same
    type, or a subclass of it (code catching the reference type still
    catches it), or - for references that raise a bare ``OSError`` subclass
    of their own (smbprotocol's ``SMBOSError``) - an ``OSError`` with the
    same errno."""
    if type(fast) is type(ref) or isinstance(fast, type(ref)):
        return True
    if isinstance(ref, OSError) and isinstance(fast, OSError):
        if ref.errno is not None and ref.errno == fast.errno:
            return True
        if errno_only:
            return False
        # the reference used a bare OSError/IOError without errno
        return type(ref) is OSError and ref.errno is None
    return False


def key_orders(a: Any, b: Any, path: str = "") -> list[str]:
    """Places where two nested results have dicts with different key
    orders."""
    out: list[str] = []
    if isinstance(a, dict) and isinstance(b, dict):
        if list(a) != list(b):
            out.append(f"{path}: {list(a)} != {list(b)}")
        for k in a:
            if k in b:
                out += key_orders(a[k], b[k], f"{path}.{k}")
    elif isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        for i, (x, y) in enumerate(zip(a, b)):
            out += key_orders(x, y, f"{path}[{i}]")
    return out


def type_diffs(a: Any, b: Any, path: str = "") -> list[str]:
    """Places where two equal nested results hold values of different
    types (``==`` treats ``1``, ``1.0`` and ``True`` as equal, and users
    observe the difference: ``json.dumps``, ``isinstance``, formatting)."""
    if type(a) is not type(b):
        return [f"{path}: {type(a).__name__} != {type(b).__name__}"]
    out: list[str] = []
    if isinstance(a, dict):
        for k in a:
            if k in b:
                out += type_diffs(a[k], b[k], f"{path}.{k}")
    elif isinstance(a, (list, tuple)):
        for i, (x, y) in enumerate(zip(a, b)):
            out += type_diffs(x, y, f"{path}[{i}]")
    return out


def normalize(v: Any) -> Any:
    """Make nested results comparable: objects behaving as mappings (azure
    ``ContentSettings``) become dicts."""
    if isinstance(v, dict):
        return {k: normalize(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return type(v)(normalize(x) for x in v)
    if hasattr(v, "keys") and hasattr(v, "__getitem__") and not isinstance(v, (bytes, str)):
        return {k: normalize(v[k]) for k in v.keys()}
    return v


@dataclass
class Backend:
    """How to reach one service with both implementations."""

    name: str
    make_ref: Callable[[], Any]
    make_fast: Callable[[], Any]
    #: A fresh, empty scratch root (created if the backend needs that).
    new_root: Callable[[Any], str]
    #: Remove a scratch root and everything below it.
    cleanup: Callable[[Any, str], None]
    #: Real directories (SMB, SFTP) rather than key prefixes.
    hierarchical: bool = False
    #: Compare dict key order (False where the reference's order comes from
    #: the server and fsfast cannot observe it).
    check_order: bool = True
    #: Exceptions: only compare errnos (the reference raises its own OSError
    #: subclass).
    errno_only: bool = False
    #: Operation labels whose outcome intentionally differs.
    known: dict[str, str] = field(default_factory=dict)
    #: Keys whose values legitimately differ between two roots written at
    #: different times (mutation checks only).
    volatile: frozenset[str] = frozenset()
    #: After a step listed in ``known`` that leaves the reference's tree in
    #: a broken state, bring the reference root back in line (called with
    #: the reference filesystem and its root).
    resync: dict[str, Callable[[Any, str], None]] = field(default_factory=dict)
    #: Subtrees (relative to the roots) left out of tree comparisons because
    #: a ``known`` step legitimately created them on one side only.
    ignore_tree: frozenset[str] = frozenset()
    #: Labels whose list results come in an arbitrary order in the
    #: reference (fsspec's http builds listings from a set): compared
    #: sorted, at every nesting level.
    unordered: frozenset[str] = frozenset()


class Mismatch(AssertionError):
    pass


def compare(b: Backend, label: str, ref: Outcome, fast: Outcome, mapper: Callable[[Any], Any] | None = None) -> str | None:
    """``None`` if the outcomes match, else a description."""
    if label in b.known:
        return None
    if ref.ok != fast.ok:
        return f"{label}: ref {ref!r} vs fast {fast!r}"
    if not ref.ok:
        assert ref.exc is not None and fast.exc is not None
        if same_error(ref.exc, fast.exc, b.errno_only):
            return None
        return f"{label}: ref raised {type(ref.exc).__name__}({ref.exc}), fast {type(fast.exc).__name__}({fast.exc})"
    rv = normalize(ref.value)
    fv = normalize(fast.value)
    if mapper is not None:
        fv = mapper(fv)
    if label in b.unordered:
        rv, fv = _sorted_deep(rv), _sorted_deep(fv)
    if b.volatile:
        rv, fv = strip_volatile(rv, b.volatile), strip_volatile(fv, b.volatile)
    if rv != fv:
        return f"{label}: values differ\n  ref : {rv!r}\n  fast: {fv!r}"
    types = type_diffs(rv, fv)
    if types:
        return f"{label}: value types differ: {types[:3]}"
    if b.check_order:
        orders = key_orders(rv, fv)
        if orders:
            return f"{label}: key order differs: {orders[:3]}"
    return None


def _sorted_deep(v: Any) -> Any:
    if isinstance(v, (list, tuple)):
        items = [_sorted_deep(x) for x in v]
        return sorted(items, key=repr)
    if isinstance(v, dict):
        return {k: _sorted_deep(x) for k, x in v.items()}
    return v


def strip_volatile(v: Any, keys: frozenset[str]) -> Any:
    if isinstance(v, dict):
        return {k: strip_volatile(x, keys) for k, x in v.items() if k not in keys}
    if isinstance(v, list):
        return [strip_volatile(x, keys) for x in v]
    return v


# ---------------------------------------------------------------------------
# read-only parity on one shared tree

ODD = "odd name +%ü&=.txt"


def build_tree(fs: Any, root: str, hierarchical: bool) -> None:
    if hierarchical:
        fs.makedirs(f"{root}/d/sub", exist_ok=True)
        fs.makedirs(f"{root}/empty", exist_ok=True)
    fs.pipe(
        {
            f"{root}/top.bin": bytes(range(256)) * 40,
            f"{root}/a.txt": b"line one\nline two\nthree\n",
            f"{root}/d/f.txt": b"hello",
            f"{root}/d/sub/g.csv": b"x,y\n1,2\n",
            f"{root}/dir.txt": b"prefix twin",
            f"{root}/{ODD}": b"odd",
            f"{root}/empty.bin": b"",
        }
    )


def _exc_id(x: Any) -> Any:
    """An exception returned in a result list, by errno (OSErrors) or type."""
    if isinstance(x, OSError):
        code = x.errno
        if code is None:  # e.g. FileNotFoundError(path): errno by class
            import errno as e

            code = {FileNotFoundError: e.ENOENT, PermissionError: e.EACCES, IsADirectoryError: e.EISDIR, NotADirectoryError: e.ENOTDIR, FileExistsError: e.EEXIST}.get(type(x))
        return ("OSError", code)
    if isinstance(x, Exception):
        return type(x).__name__
    return x


def read_ops(root: str) -> list[tuple[str, Callable[[Any], Any]]]:
    """``(label, op)`` pairs; labels containing ``"cached"`` keep each
    filesystem's listings cache from the previous step."""

    def opened(fs: Any) -> Any:
        with fs.open(f"{root}/top.bin", "rb") as f:
            a = f.read(10)
            f.seek(100)
            b = f.read(5)
            f.seek(-3, 2)
            c = f.read()
            return a, b, c, f.tell(), f.size

    def lines(fs: Any) -> Any:
        with fs.open(f"{root}/a.txt", "rb") as f:
            return [f.readline(), list(f)]

    def text(fs: Any) -> Any:
        with fs.open(f"{root}/a.txt", "r") as f:
            return f.read()

    return [
        ("info file", lambda fs: fs.info(f"{root}/top.bin")),
        ("info dir", lambda fs: fs.info(f"{root}/d")),
        ("info dir slash", lambda fs: fs.info(f"{root}/d/")),
        ("info nested", lambda fs: fs.info(f"{root}/d/sub/g.csv")),
        ("info odd", lambda fs: fs.info(f"{root}/{ODD}")),
        ("info empty file", lambda fs: fs.info(f"{root}/empty.bin")),
        ("ls detail", lambda fs: fs.ls(root, detail=True)),
        ("ls names", lambda fs: fs.ls(root, detail=False)),
        ("cached info after ls", lambda fs: fs.info(f"{root}/top.bin")),
        ("cached info dir after ls", lambda fs: fs.info(f"{root}/d")),
        ("cached exists after ls", lambda fs: [fs.exists(f"{root}/a.txt"), fs.exists(f"{root}/nope")]),
        ("ls subdir", lambda fs: fs.ls(f"{root}/d", detail=True)),
        ("ls file", lambda fs: fs.ls(f"{root}/top.bin", detail=True)),
        ("ls trailing slash", lambda fs: fs.ls(f"{root}/d/", detail=False)),
        ("find", lambda fs: fs.find(root)),
        ("find detail", lambda fs: fs.find(root, detail=True)),
        ("find withdirs", lambda fs: fs.find(root, withdirs=True)),
        ("find withdirs detail", lambda fs: fs.find(root, withdirs=True, detail=True)),
        ("find maxdepth", lambda fs: fs.find(root, maxdepth=1)),
        ("find maxdepth withdirs", lambda fs: fs.find(root, maxdepth=1, withdirs=True)),
        ("find subdir", lambda fs: fs.find(f"{root}/d")),
        ("find file", lambda fs: fs.find(f"{root}/a.txt")),
        ("find missing", lambda fs: fs.find(f"{root}/nope")),
        ("cached info after find", lambda fs: fs.info(f"{root}/d/f.txt")),
        ("walk", lambda fs: list(fs.walk(root))),
        ("glob star", lambda fs: fs.glob(f"{root}/*")),
        ("glob txt", lambda fs: fs.glob(f"{root}/*.txt")),
        ("glob recursive", lambda fs: fs.glob(f"{root}/**/*.csv")),
        ("glob doublestar", lambda fs: fs.glob(f"{root}/**")),
        ("glob detail", lambda fs: fs.glob(f"{root}/d/*", detail=True)),
        ("glob class", lambda fs: fs.glob(f"{root}/[ad]*.txt")),
        ("du", lambda fs: fs.du(root)),
        ("du detail", lambda fs: fs.du(root, total=False)),
        ("exists", lambda fs: [fs.exists(f"{root}/top.bin"), fs.exists(f"{root}/d"), fs.exists(f"{root}/nope"), fs.exists(f"{root}/d/nope")]),
        ("isdir", lambda fs: [fs.isdir(f"{root}/top.bin"), fs.isdir(f"{root}/d"), fs.isdir(f"{root}/nope")]),
        ("isfile", lambda fs: [fs.isfile(f"{root}/top.bin"), fs.isfile(f"{root}/d"), fs.isfile(f"{root}/nope")]),
        ("size", lambda fs: fs.size(f"{root}/top.bin")),
        ("sizes", lambda fs: fs.sizes([f"{root}/top.bin", f"{root}/a.txt"])),
        ("modified type", lambda fs: type(fs.modified(f"{root}/top.bin")).__name__),
        ("cat", lambda fs: fs.cat(f"{root}/a.txt")),
        ("cat odd", lambda fs: fs.cat(f"{root}/{ODD}")),
        ("cat empty", lambda fs: fs.cat(f"{root}/empty.bin")),
        ("cat list", lambda fs: fs.cat([f"{root}/a.txt", f"{root}/d/f.txt"])),
        ("cat recursive", lambda fs: fs.cat(f"{root}/d", recursive=True)),
        ("cat glob", lambda fs: fs.cat(f"{root}/*.txt")),
        ("cat_file range", lambda fs: fs.cat_file(f"{root}/top.bin", start=10, end=20)),
        ("cat_file open end", lambda fs: fs.cat_file(f"{root}/top.bin", start=10_000)),
        ("cat_file suffix", lambda fs: fs.cat_file(f"{root}/top.bin", start=-5)),
        ("cat_file neg end", lambda fs: fs.cat_file(f"{root}/top.bin", start=0, end=-10_000 + 5)),
        ("cat_file past eof", lambda fs: fs.cat_file(f"{root}/top.bin", start=10_000, end=20_000)),
        ("cat_ranges", lambda fs: fs.cat_ranges([f"{root}/top.bin", f"{root}/a.txt", f"{root}/top.bin"], [0, 5, 100], [4, 9, 200])),
        ("cat_ranges missing", lambda fs: [_exc_id(x) for x in fs.cat_ranges([f"{root}/nope", f"{root}/a.txt"], [0, 0], [1, 1])]),
        ("head", lambda fs: fs.head(f"{root}/a.txt", 4)),
        ("tail", lambda fs: fs.tail(f"{root}/a.txt", 4)),
        ("read_block", lambda fs: fs.read_block(f"{root}/a.txt", 3, 8, delimiter=b"\n")),
        ("open read seek", opened),
        ("open lines", lines),
        ("open text", text),
        ("info missing", lambda fs: fs.info(f"{root}/nope")),
        ("info missing nested", lambda fs: fs.info(f"{root}/nope/deeper")),
        ("cat missing", lambda fs: fs.cat(f"{root}/nope")),
        ("cat_file missing", lambda fs: fs.cat_file(f"{root}/nope")),
        ("ls missing", lambda fs: fs.ls(f"{root}/nope")),
        ("open missing", lambda fs: fs.open(f"{root}/nope", "rb")),
        ("size missing", lambda fs: fs.size(f"{root}/nope")),
        ("modified missing", lambda fs: fs.modified(f"{root}/nope")),
        ("open dir", lambda fs: fs.open(f"{root}/d", "rb").read()),
        ("cat dir", lambda fs: fs.cat_file(f"{root}/d")),
    ]


def check_reads(b: Backend, ref: Any, fast: Any, root: str) -> list[str]:
    problems = []
    for label, op in read_ops(root):
        if "cached" not in label:
            ref.invalidate_cache()
            fast.invalidate_cache()
        r = run(lambda: op(ref))
        f = run(lambda: op(fast))
        msg = compare(b, label, r, f)
        if msg:
            problems.append(msg)
    return problems


# ---------------------------------------------------------------------------
# mutations: same steps in two roots, compare outcomes and trees


def snapshot(fs: Any, root: str, hierarchical: bool) -> dict[str, Any]:
    fs.invalidate_cache()
    try:
        found = fs.find(root, withdirs=hierarchical, detail=True)
    except FileNotFoundError:
        return {}
    out: dict[str, Any] = {}
    for name, info in found.items():
        rel = name.rstrip("/")[len(root.rstrip("/")) :]
        if info["type"] == "directory":
            out[rel] = "<dir>"
        else:
            out[rel] = fs.cat_file(name)
    return out


def write_ops(root: str, local: str, hierarchical: bool) -> list[tuple[str, Callable[[Any], Any]]]:
    """Mutating steps; each runs on a fresh view of the tree built by the
    previous steps."""

    def write_file(fs: Any) -> Any:
        with fs.open(f"{root}/w/written.bin", "wb") as f:
            n = f.write(b"abc" * 1000)
            f.write(b"tail")
            pos = f.tell()
        return n, pos

    def write_text(fs: Any) -> Any:
        with fs.open(f"{root}/w/text.txt", "w") as f:
            f.write("héllo\nwörld\n")
        return fs.cat(f"{root}/w/text.txt")

    def append(fs: Any) -> Any:
        with fs.open(f"{root}/w/written.bin", "ab") as f:
            f.write(b"+more")
        return fs.cat(f"{root}/w/written.bin")[-10:]

    def exclusive(fs: Any) -> Any:
        with fs.open(f"{root}/w/written.bin", "xb") as f:
            f.write(b"no")

    def transaction(fs: Any) -> Any:
        with fs.transaction:
            with fs.open(f"{root}/w/tx.bin", "wb") as f:
                f.write(b"deferred")
            visible = fs.exists(f"{root}/w/tx.bin")
        return visible, fs.cat(f"{root}/w/tx.bin")

    def get(fs: Any) -> Any:
        dest = os.path.join(local, f"get-{uuid.uuid4().hex}")
        fs.get(f"{root}/src", dest, recursive=True)
        out = {}
        for dirpath, _, files in os.walk(dest):
            for n in files:
                p = os.path.join(dirpath, n)
                with open(p, "rb") as fh:
                    out[os.path.relpath(p, dest)] = fh.read()
        return out

    def get_file(fs: Any) -> Any:
        dest = os.path.join(local, f"one-{uuid.uuid4().hex}")
        fs.get_file(f"{root}/src/one.txt", dest)
        with open(dest, "rb") as fh:
            return fh.read()

    mk = [
        ("mkdir", lambda fs: fs.mkdir(f"{root}/made")),
        ("mkdir exists", lambda fs: fs.mkdir(f"{root}/made")),
        ("makedirs", lambda fs: fs.makedirs(f"{root}/made/x/y")),
        ("makedirs exist_ok", lambda fs: fs.makedirs(f"{root}/made/x/y", exist_ok=True)),
        ("makedirs exists", lambda fs: fs.makedirs(f"{root}/made/x/y")),
        ("makedirs w", lambda fs: fs.makedirs(f"{root}/w", exist_ok=True)),
        ("makedirs src", lambda fs: fs.makedirs(f"{root}/src/sub", exist_ok=True)),
        ("makedirs copy", lambda fs: fs.makedirs(f"{root}/copy", exist_ok=True)),
        ("rmdir", lambda fs: fs.rmdir(f"{root}/made/x/y")),
    ] if hierarchical else []
    return mk + [
        ("pipe_file", lambda fs: fs.pipe_file(f"{root}/src/one.txt", b"one")),
        ("pipe dict", lambda fs: fs.pipe({f"{root}/src/two.txt": b"two", f"{root}/src/sub/three.txt": b"3" * 3000})),
        ("pipe odd", lambda fs: fs.pipe_file(f"{root}/src/{ODD}", b"odd")),
        ("pipe overwrite", lambda fs: fs.pipe_file(f"{root}/src/two.txt", b"TWO")),
        ("write_bytes", lambda fs: fs.write_bytes(f"{root}/w/wb.bin", b"\x00\x01")),
        ("read_bytes", lambda fs: fs.read_bytes(f"{root}/w/wb.bin")),
        ("touch", lambda fs: fs.touch(f"{root}/w/touched")),
        ("touched size", lambda fs: fs.size(f"{root}/w/touched")),
        ("open wb", write_file),
        ("open w text", write_text),
        ("open ab", append),
        ("open xb existing", exclusive),
        ("transaction", transaction),
        ("put_file", lambda fs: fs.put_file(os.path.join(local, "up", "a.bin"), f"{root}/up/a.bin")),
        ("put recursive", lambda fs: fs.put(os.path.join(local, "up") + "/", f"{root}/put", recursive=True)),
        ("get recursive", get),
        ("get_file", get_file),
        ("cp_file", lambda fs: fs.cp_file(f"{root}/src/one.txt", f"{root}/copy/one.txt")),
        ("copy recursive", lambda fs: fs.copy(f"{root}/src", f"{root}/tree", recursive=True)),
        ("copy missing", lambda fs: fs.copy(f"{root}/nope", f"{root}/x")),
        ("mv file", lambda fs: fs.mv(f"{root}/copy/one.txt", f"{root}/moved.txt")),
        ("mv dir", lambda fs: fs.mv(f"{root}/tree", f"{root}/tree2", recursive=True)),
        ("mv missing", lambda fs: fs.mv(f"{root}/nope", f"{root}/x")),
        ("rm file", lambda fs: fs.rm(f"{root}/moved.txt")),
        ("rm_file", lambda fs: fs.rm_file(f"{root}/src/two.txt")),
        ("rm missing", lambda fs: fs.rm(f"{root}/nope")),
        ("rm recursive", lambda fs: fs.rm(f"{root}/tree2", recursive=True)),
        ("exists after rm", lambda fs: [fs.exists(f"{root}/tree2"), fs.exists(f"{root}/src/two.txt")]),
        ("ls after writes", lambda fs: fs.ls(f"{root}/src", detail=False)),
    ]


#: Steps whose return value is an implementation detail (s3fs returns boto
#: responses, fsspec's rm returns nothing, ...): only success or the error
#: type is compared.
STATUS_ONLY = frozenset(
    {
        "mkdir", "mkdir exists", "makedirs", "makedirs exist_ok", "makedirs exists",
        "makedirs w", "makedirs src", "makedirs copy", "rmdir", "pipe_file", "pipe dict", "pipe odd",
        "pipe overwrite", "write_bytes", "touch", "put_file", "put recursive",
        "cp_file", "copy recursive", "copy missing", "mv file", "mv dir", "mv missing",
        "rm file", "rm_file", "rm missing", "rm recursive",
    }
)


def check_writes(b: Backend, ref: Any, fast: Any, ref_root: str, fast_root: str) -> list[str]:
    problems = []
    with tempfile.TemporaryDirectory() as local:
        up = os.path.join(local, "up")
        os.makedirs(os.path.join(up, "nested"))
        for rel, data in {"a.bin": b"A" * 100, "b.txt": b"bee", "nested/c.txt": b"sea"}.items():
            with open(os.path.join(up, rel), "wb") as fh:
                fh.write(data)

        def mapper(v: Any) -> Any:
            if isinstance(v, str):
                return v.replace(fast_root, ref_root)
            if isinstance(v, dict):
                return {mapper(k): mapper(x) for k, x in v.items()}
            if isinstance(v, (list, tuple)):
                return type(v)(mapper(x) for x in v)
            return v

        ref_ops = write_ops(ref_root, local, b.hierarchical)
        fast_ops = write_ops(fast_root, local, b.hierarchical)
        for (label, rop), (_, fop) in zip(ref_ops, fast_ops):
            r = run(lambda: rop(ref))
            f = run(lambda: fop(fast))
            if label in STATUS_ONLY:
                r.value = f.value = None
            msg = compare(b, label, r, f, mapper)
            if msg:
                problems.append(msg)
            if label in b.resync:
                b.resync[label](ref, ref_root)
            rs = snapshot(ref, ref_root, b.hierarchical)
            fs_ = snapshot(ref, fast_root, b.hierarchical)
            for prefix in b.ignore_tree:
                rs = {k: v for k, v in rs.items() if not k.startswith(prefix)}
                fs_ = {k: v for k, v in fs_.items() if not k.startswith(prefix)}
            if rs != fs_ and f"tree after {label}" not in b.known:
                problems.append(f"tree after {label}: ref {sorted(rs)} vs fast {sorted(fs_)}")
                break
    return problems


# ---------------------------------------------------------------------------
# integration: fsspec registry, URLs, async, pickling


def check_fsspec_integration(proto: str, storage_options: dict[str, Any], url: str, expected: bytes, cls: type) -> None:
    import fsfast

    fsfast.install([proto])
    try:
        fs = fsspec.filesystem(proto, **storage_options)
        assert isinstance(fs, cls), type(fs)
        with fsspec.open(url, "rb", **storage_options) as f:
            assert f.read() == expected
        fs2, path = fsspec.core.url_to_fs(url, **storage_options)
        assert isinstance(fs2, cls)
        assert fs2.cat_file(path) == expected
    finally:
        fsfast.uninstall([proto])


def check_pickle(fs: Any, path: str, expected: bytes) -> None:
    clone = pickle.loads(pickle.dumps(fs))
    assert type(clone) is type(fs)
    assert clone.cat_file(path) == expected
    with fs.open(path, "rb") as f:
        f.read(1)
        g = pickle.loads(pickle.dumps(f))
        assert g.read() == expected[1:]


def check_async(make_async: Callable[[], Any], root: str) -> None:
    async def main() -> None:
        fs = make_async()
        assert fs.asynchronous
        p = f"{root}/async/x.bin"
        await fs._pipe_file(p, b"async data")
        assert await fs._cat_file(p) == b"async data"
        assert await fs._cat_file(p, start=1, end=4) == b"syn"
        info = await fs._info(p)
        assert info["size"] == 10
        assert await fs._exists(p)
        assert p in [n.rstrip("/") for n in await fs._find(f"{root}/async")]
        listing = await fs._ls(f"{root}/async", detail=True)
        assert [i["name"].rstrip("/") for i in listing] == [p]
        out = await fs._cat_ranges([p, p], [0, 6], [2, 10])
        assert out == [b"as", b"data"]
        await fs._rm_file(p)
        assert not await fs._exists(p)

    asyncio.run(main())
