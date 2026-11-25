"""Behaviour parity with fsspec's reference implementations.

The same operations run on fsspec's ``LocalFileSystem`` / ``MemoryFileSystem``
and on fsfast's classes; results (with paths mapped between the two trees),
exception types and the resulting trees must match. Trees are always
snapshotted with the *reference* implementation.
"""

from __future__ import annotations

import datetime
import os
import string

import pytest
from fsspec.implementations.local import LocalFileSystem as RefLocal
from fsspec.implementations.memory import MemoryFileSystem as RefMemory
from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule

import fsfast
from conftest import clear_memory

REF_LOCAL = RefLocal()


def outcome(fn, *args, **kwargs):
    """``("ok", value)`` or ``("err", exception type)``."""
    try:
        return ("ok", fn(*args, **kwargs))
    except Exception as e:  # noqa: BLE001 - comparing exception types
        return ("err", type(e))


def build_tree(root: str, broken_link: bool = True) -> None:
    """A tree with files, nested and empty directories, symlinks."""
    os.makedirs(f"{root}/dir/sub/deep")
    os.makedirs(f"{root}/empty")
    for rel, data in {
        "a.txt": b"hello world\n" * 3,
        "b.bin": bytes(range(256)) * 4,
        "dir/c.txt": b"c",
        "dir/sub/d.txt": b"dd\nee\n",
        "dir/sub/deep/e.txt": b"",
        "dir.txt": b"prefix twin",
    }.items():
        with open(f"{root}/{rel}", "wb") as f:
            f.write(data)
    os.symlink(f"{root}/a.txt", f"{root}/link")
    os.symlink(f"{root}/dir", f"{root}/dirlink")
    if broken_link:
        os.symlink(f"{root}/nowhere", f"{root}/broken")


def ref_snapshot(root: str) -> dict[str, tuple[str, bytes | None]]:
    out: dict[str, tuple[str, bytes | None]] = {}
    if not REF_LOCAL.exists(root):
        return out
    for name, info in REF_LOCAL.find(root, withdirs=True, detail=True).items():
        rel = name[len(root) :]
        if info["type"] == "file":
            out[rel] = ("file", REF_LOCAL.cat_file(name))
        else:
            out[rel] = (info["type"], None)
    return out


# ---------------------------------------------------------------------------
# local, read-only: one tree, results must be identical


@pytest.fixture
def tree(tmp_path):
    root = str(tmp_path / "t")
    build_tree(root)
    return root


@pytest.fixture
def pair():
    return REF_LOCAL, fsfast.LocalFileSystem()


def test_info_and_ls_identical(tree, pair):
    ref, ours = pair
    for rel in ["a.txt", "dir", "empty", "link", "dirlink", "dir/sub/deep/e.txt", ""]:
        p = f"{tree}/{rel}".rstrip("/")
        r, o = ref.info(p), ours.info(p)
        assert r == o, rel
        assert list(r) == list(o), f"key order differs for {rel}"
    for p in [tree, f"{tree}/dir", f"{tree}/a.txt", f"{tree}/empty"]:
        assert sorted(ref.ls(p)) == sorted(ours.ls(p))
        assert sorted(ref.ls(p, detail=True), key=lambda d: d["name"]) == sorted(
            ours.ls(p, detail=True), key=lambda d: d["name"]
        )
    # the default of ``detail`` is fsspec local's (False)
    assert isinstance(ours.ls(tree)[0], str)


def test_errors_identical(tree, pair):
    ref, ours = pair
    cases = [
        ("info", f"{tree}/missing"),
        ("info", f"{tree}/broken"),
        ("ls", f"{tree}/missing"),
        ("cat_file", f"{tree}/dir"),
        ("cat_file", f"{tree}/missing"),
        ("rm_file", f"{tree}/missing"),
        ("rmdir", f"{tree}/dir"),
        ("rmdir", f"{tree}/missing"),
        ("rmdir", f"{tree}/a.txt"),
        ("mkdir", f"{tree}/dir"),
        ("mkdir", f"{tree}/a.txt/x"),
        ("open", f"{tree}/missing"),
        ("open", f"{tree}/dir"),
        ("sign", f"{tree}/a.txt"),
    ]
    for op, p in cases:
        r = outcome(getattr(ref, op), p)
        o = outcome(getattr(ours, op), p)
        assert r[0] == o[0] == "err", (op, p, r, o)
        assert r[1] is o[1], (op, p, r, o)
    r = outcome(ref.makedirs, f"{tree}/dir", exist_ok=False)
    o = outcome(ours.makedirs, f"{tree}/dir", exist_ok=False)
    assert r == o
    r = outcome(ref.rm, f"{tree}/dir")
    o = outcome(ours.rm, f"{tree}/dir")
    assert r == o == ("err", ValueError)


def test_find_glob_walk_du_identical(tree, pair):
    ref, ours = pair
    for kw in [{}, {"withdirs": True}, {"maxdepth": 1}, {"maxdepth": 2, "withdirs": True}]:
        assert ref.find(tree, **kw) == ours.find(tree, **kw), kw
        assert ref.find(tree, detail=True, **kw) == ours.find(tree, detail=True, **kw), kw
    assert ref.find(f"{tree}/a.txt") == ours.find(f"{tree}/a.txt")
    assert ref.find(f"{tree}/missing") == ours.find(f"{tree}/missing") == []
    for pat in ["*", "*.txt", "**", "**/*.txt", "dir/*", "dir/**", "d?r*", "[ab].*", "**/", "dir*"]:
        assert ref.glob(f"{tree}/{pat}") == ours.glob(f"{tree}/{pat}"), pat
        assert ref.glob(f"{tree}/{pat}", maxdepth=2) == ours.glob(f"{tree}/{pat}", maxdepth=2), pat
    norm = lambda w: sorted((p, sorted(d), sorted(f)) for p, d, f in w)  # noqa: E731
    assert norm(ref.walk(tree)) == norm(ours.walk(tree))
    assert norm(ref.walk(tree, maxdepth=2)) == norm(ours.walk(tree, maxdepth=2))
    # The tree holds a broken symlink: fsspec's du re-stats every entry and
    # raises FileNotFoundError; so does fsfast's.
    assert outcome(ref.du, tree) == outcome(ours.du, tree) == ("err", FileNotFoundError)
    sub = f"{tree}/dir"
    assert ref.du(sub) == ours.du(sub)
    assert ref.du(sub, total=False) == ours.du(sub, total=False)
    assert ref.du(sub, total=False, withdirs=True) == ours.du(sub, total=False, withdirs=True)
    assert ref.du(sub, maxdepth=1, total=False) == ours.du(sub, maxdepth=1, total=False)
    for kw in [{}, {"recursive": True}, {"recursive": True, "maxdepth": 1}]:
        assert ref.expand_path(f"{tree}/dir", **kw) == ours.expand_path(f"{tree}/dir", **kw)
        assert ref.expand_path(f"{tree}/*.txt", **kw) == ours.expand_path(f"{tree}/*.txt", **kw)


def test_predicates_and_metadata_identical(tree, pair):
    ref, ours = pair
    for rel in ["a.txt", "dir", "link", "dirlink", "broken", "missing", ""]:
        p = f"{tree}/{rel}".rstrip("/")
        for op in ["exists", "isdir", "isfile", "lexists"]:
            assert getattr(ref, op)(p) == getattr(ours, op)(p), (op, rel)
    p = f"{tree}/a.txt"
    assert ref.size(p) == ours.size(p)
    assert ref.sizes([p, f"{tree}/b.bin"]) == ours.sizes([p, f"{tree}/b.bin"])
    assert ref.modified(p) == ours.modified(p)
    assert ref.created(p) == ours.created(p)
    assert ours.modified(p).tzinfo is datetime.timezone.utc
    assert ref.ukey(p) == ours.ukey(p)
    assert ref.checksum(p) == ours.checksum(p)
    assert ref.read_block(p, 3, 10, delimiter=b"\n") == ours.read_block(p, 3, 10, delimiter=b"\n")
    assert ref.head(p, 5) == ours.head(p, 5)
    assert ref.tail(p, 5) == ours.tail(p, 5)
    assert ref.head(p, -1) == ours.head(p, -1)
    assert ref.tail(p, 0) == ours.tail(p, 0)
    assert ref.unstrip_protocol(p) == ours.unstrip_protocol(p)
    for raw in ["file://" + p, "local://" + p, "./x", "~/y", "rel/z/", "/"]:
        assert ref._strip_protocol(raw) == ours._strip_protocol(raw), raw
        assert ref._parent(raw) == ours._parent(raw), raw


RANGES = [
    (None, None),
    (-1, -1),  # empty range on a directory must still fail like open()
    (-1, None),
    (0, 5),
    (5, None),
    (-5, None),
    (None, -3),
    (-10, -2),
    (2, 1),  # inverted: fsspec's generic cat_file reads to EOF
    (-2, -10),
    (100, 200),
    (-1000, 4),
    (0, -1000),
    (3, 3),
]


@pytest.mark.parametrize("start,end", RANGES)
def test_cat_file_ranges_identical(tree, pair, start, end):
    ref, ours = pair
    for rel in ["a.txt", "b.bin", "dir/sub/deep/e.txt", "missing", "dir"]:
        p = f"{tree}/{rel}"
        r = outcome(ref.cat_file, p, start, end)
        o = outcome(ours.cat_file, p, start, end)
        assert r == o, (rel, start, end, r, o)
    paths = [f"{tree}/a.txt", f"{tree}/b.bin", f"{tree}/missing", f"{tree}/dir", f"{tree}/empty"]
    r = ref.cat_ranges(paths, start, end)
    o = ours.cat_ranges(paths, start, end)
    norm = lambda xs: [type(x) if isinstance(x, Exception) else x for x in xs]  # noqa: E731
    assert norm(r) == norm(o), (start, end, r, o)


def test_cat_and_cat_ranges_identical(tree, pair):
    ref, ours = pair
    paths = [f"{tree}/a.txt", f"{tree}/b.bin", f"{tree}/a.txt", f"{tree}/missing"]
    starts = [s for s, _ in RANGES[:4]]
    ends = [e for _, e in RANGES[:4]]
    r = ref.cat_ranges(paths, starts, ends)
    o = ours.cat_ranges(paths, starts, ends)
    assert r[:3] == o[:3]
    assert type(r[3]) is type(o[3]) is FileNotFoundError
    with pytest.raises(FileNotFoundError):
        ours.cat_ranges(paths, starts, ends, on_error="raise")
    # scalar starts/ends are broadcast
    assert ref.cat_ranges(paths[:3], 1, 4) == ours.cat_ranges(paths[:3], 1, 4)
    # max_gap is accepted (ranges are always coalesced)
    assert ours.cat_ranges(paths[:2], 0, 3, max_gap=10) == ref.cat_ranges(paths[:2], 0, 3)
    with pytest.raises(ValueError):
        ours.cat_ranges(paths, [0], [1])
    with pytest.raises(TypeError):
        ours.cat_ranges(tuple(paths), 0, 1)

    assert ref.cat(f"{tree}/a.txt") == ours.cat(f"{tree}/a.txt")
    assert ref.cat([f"{tree}/a.txt", f"{tree}/b.bin"]) == ours.cat([f"{tree}/a.txt", f"{tree}/b.bin"])
    assert ref.cat(f"{tree}/*.txt") == ours.cat(f"{tree}/*.txt")
    r = ref.cat(f"{tree}/dir", recursive=True, on_error="omit")
    o = ours.cat(f"{tree}/dir", recursive=True, on_error="omit")
    assert r == o
    r = ref.cat(f"{tree}/dir", recursive=True, on_error="return")
    o = ours.cat(f"{tree}/dir", recursive=True, on_error="return")
    assert {k: (type(v) if isinstance(v, Exception) else v) for k, v in r.items()} == {
        k: (type(v) if isinstance(v, Exception) else v) for k, v in o.items()
    }
    assert outcome(ref.cat, f"{tree}/dir", recursive=True)[1] is outcome(
        ours.cat, f"{tree}/dir", recursive=True
    )[1]
    assert ref.cat(f"{tree}/*.txt", start=1, end=4) == ours.cat(f"{tree}/*.txt", start=1, end=4)


def test_file_reads_identical(tree, pair):
    ref, ours = pair
    p = f"{tree}/b.bin"
    with ref.open(p) as fr, ours.open(p) as fo:
        assert fr.size == fo.size
        for op, args in [
            ("read", (10,)),
            ("tell", ()),
            ("seek", (5, 1)),
            ("read", (3,)),
            ("seek", (-7, 2)),
            ("read", ()),
            ("read", (5,)),
            ("seek", (2000,)),
            ("read", (1,)),
            ("seek", (0,)),
            ("readline", ()),
        ]:
            assert getattr(fr, op)(*args) == getattr(fo, op)(*args), (op, args)
    q = f"{tree}/a.txt"
    with ref.open(q, "r") as fr, ours.open(q, "r") as fo:
        assert fr.readlines() == fo.readlines()
    with ref.open(q, "rb") as fr, ours.open(q, "rb") as fo:
        assert list(fr) == list(fo)


# ---------------------------------------------------------------------------
# local, mutating: two identical trees, same operations


@pytest.fixture
def trees(tmp_path):
    a, b = str(tmp_path / "ref"), str(tmp_path / "ours")
    build_tree(a)
    build_tree(b)
    return a, b


def both(trees, op, *rels, **kwargs):
    """Run ``op`` with tree-relative paths on both filesystems; compare."""
    a, b = trees
    ref, ours = REF_LOCAL, fsfast.LocalFileSystem()
    map_a = [f"{a}/{r}" if isinstance(r, str) else r for r in rels]
    map_b = [f"{b}/{r}" if isinstance(r, str) else r for r in rels]
    r = outcome(getattr(ref, op), *map_a, **kwargs)
    o = outcome(getattr(ours, op), *map_b, **kwargs)
    assert r[0] == o[0], (op, rels, kwargs, r, o)
    if r[0] == "err":
        assert issubclass(o[1], OSError) == issubclass(r[1], OSError), (op, rels, r, o)
        assert r[1] is o[1] or (issubclass(r[1], o[1]) or issubclass(o[1], r[1])), (op, rels, r, o)
    assert ref_snapshot(a) == ref_snapshot(b), (op, rels, kwargs)
    return r, o


MUTATIONS = [
    ("mkdir", ("new",), {}),
    ("mkdir", ("new/a/b",), {"create_parents": False}),
    ("mkdir", ("dir",), {}),
    ("makedirs", ("x/y/z",), {"exist_ok": True}),
    ("makedirs", ("dir",), {"exist_ok": True}),
    ("makedirs", ("a.txt",), {"exist_ok": True}),
    ("touch", ("a.txt",), {"truncate": False}),
    ("touch", ("t.txt",), {}),
    ("touch", ("a.txt",), {}),
    ("pipe_file", ("p.txt", b"pp"), {}),
    ("pipe_file", ("a.txt", b"over"), {}),
    ("pipe_file", ("a.txt", b"x"), {"mode": "create"}),
    ("pipe_file", ("nodir/x", b"x"), {}),
    ("pipe", ({"q1": b"1"},), {}),
    ("rm_file", ("a.txt",), {}),
    ("rm_file", ("dir",), {}),
    ("rm_file", ("link",), {}),
    ("rm", ("dir",), {"recursive": True}),
    ("rm", ("dirlink",), {}),
    ("rm", ("empty",), {"recursive": True}),
    ("rmdir", ("empty",), {}),
    ("cp_file", ("a.txt", "copy.txt"), {}),
    ("cp_file", ("dir", "dircopy"), {}),
    ("cp_file", ("missing", "x"), {}),
    ("cp_file", ("a.txt", "nodir/x"), {}),
    ("copy", ("dir", "dcopy"), {"recursive": True}),
    ("copy", ("dir/", "dcopy2"), {"recursive": True}),
    ("copy", ("dir", "empty"), {"recursive": True}),
    ("copy", ("dir/*", "empty"), {}),
    ("copy", ("dir", "empty/"), {"recursive": True, "maxdepth": 1}),
    ("copy", ("*.txt", "empty/"), {}),
    ("mv", ("a.txt", "moved.txt"), {}),
    ("mv", ("a.txt", "empty"), {}),
    ("mv", ("dir", "empty"), {}),
    ("mv", ("dir", "newdir"), {}),
    ("mv", ("a.txt", "dir.txt"), {}),
    ("mv", ("missing", "x"), {}),
    ("mv", ("a.txt", "nodir/x"), {}),
]


@pytest.mark.parametrize("op,args,kwargs", MUTATIONS, ids=[f"{m[0]}-{i}" for i, m in enumerate(MUTATIONS)])
def test_local_mutations_identical(trees, op, args, kwargs):
    if op == "pipe":
        a, b = trees
        d = args[0]
        r = outcome(REF_LOCAL.pipe, {f"{a}/{k}": v for k, v in d.items()})
        o = outcome(fsfast.LocalFileSystem().pipe, {f"{b}/{k}": v for k, v in d.items()})
        assert r == o
        assert ref_snapshot(a) == ref_snapshot(b)
        return
    rels = [x for x in args]
    both(trees, op, *rels, **kwargs)


def test_local_put_get_identical(tmp_path):
    src = str(tmp_path / "src")
    # Without the broken link: on a failing item fsspec's sync loop stops,
    # while fsfast's batch (like fsspec's async _put/_get) finishes the
    # other items; both raise (checked below).
    build_tree(src, broken_link=False)
    for i, (sub, kw) in enumerate(
        [("", {"recursive": True}), ("/", {"recursive": True}), ("/*.txt", {}), ("/dir", {"recursive": True, "maxdepth": 1})]
    ):
        for op in ("put", "get"):
            a, b = str(tmp_path / f"{op}{i}ref"), str(tmp_path / f"{op}{i}ours")
            os.makedirs(a)
            os.makedirs(b)
            r = outcome(getattr(REF_LOCAL, op), src + sub, a + "/", **kw)
            o = outcome(getattr(fsfast.LocalFileSystem(), op), src + sub, b + "/", **kw)
            assert r[0] == o[0], (op, sub, r, o)
            assert ref_snapshot(a) == ref_snapshot(b), (op, sub, kw)
    os.symlink(f"{src}/nowhere", f"{src}/broken")
    for op in ("put", "get"):
        dst = str(tmp_path / f"{op}-broken")
        os.makedirs(dst)
        r = outcome(getattr(REF_LOCAL, op), src, dst + "/ref/", recursive=True)
        o = outcome(getattr(fsfast.LocalFileSystem(), op), src, dst + "/ours/", recursive=True)
        assert r == o == ("err", FileNotFoundError), (op, r, o)


# ---------------------------------------------------------------------------
# memory: fsspec's MemoryFileSystem vs fsfast's, same paths (separate stores)


@pytest.fixture
def mems():
    ref = RefMemory()
    ref.store.clear()
    ref.pseudo_dirs.clear()
    ref.pseudo_dirs.append("")
    ours = fsfast.MemoryFileSystem()
    clear_memory(ours)
    yield ref, ours
    ref.store.clear()
    ref.pseudo_dirs.clear()
    ref.pseudo_dirs.append("")
    clear_memory(ours)


def mem_snapshot(fs) -> dict[str, tuple[str, bytes | None]]:
    out = {}
    for name, info in fs.find("", withdirs=True, detail=True).items():
        out[name] = (info["type"], fs.cat_file(name) if info["type"] == "file" else None)
    return out


def strip_times(info):
    return {k: v for k, v in info.items() if k != "created"}


def test_memory_metadata_identical(mems):
    ref, ours = mems
    for fs in mems:
        fs.pipe({"/a/b/c": b"123", "/a/d": b"", "/e": b"eee"})
        fs.mkdir("/empty")
        fs.mkdir("/a/pseudo")
    for p in ["/a", "/a/b/c", "/empty", "", "/a/pseudo"]:
        r, o = ref.info(p), ours.info(p)
        assert strip_times(r) == strip_times(o), p
        assert list(r) == list(o), p
        if r["type"] == "file":
            assert isinstance(o["created"], datetime.datetime)
    for p in ["/a", "", "/a/b/c", "/empty"]:
        assert sorted(ref.ls(p, detail=False)) == sorted(ours.ls(p, detail=False))
        key = lambda d: d["name"]  # noqa: E731
        r = sorted((strip_times(x) for x in ref.ls(p)), key=key)
        o = sorted((strip_times(x) for x in ours.ls(p)), key=key)
        assert r == o, p
        for x in ours.ls(p):
            if x["type"] == "file":
                assert isinstance(x["created"], float)
    for kw in [{}, {"withdirs": True}, {"maxdepth": 1}, {"maxdepth": 1, "withdirs": True}]:
        assert ref.find("/a", **kw) == ours.find("/a", **kw), kw
        assert ref.find("", **kw) == ours.find("", **kw), kw
    for pat in ["/a/*", "/**", "/a/**/c", "/?", "/a/[bd]"]:
        assert ref.glob(pat) == ours.glob(pat), pat
    assert ref.du("/a") == ours.du("/a")
    assert ref.cat("/a", recursive=True, on_error="omit") == ours.cat("/a", recursive=True, on_error="omit")
    for op in ["modified", "created"]:
        assert outcome(getattr(ref, op), "/a")[1] is outcome(getattr(ours, op), "/a")[1]
        assert isinstance(getattr(ours, op)("/e"), datetime.datetime)
    for start, end in RANGES:
        if start is not None and end is not None and start > end >= 0:
            continue  # slicing (memory) and seek+read (local) differ; memory slices
        assert ref.cat_file("/e", start, end) == ours.cat_file("/e", start, end), (start, end)
    assert ref.cat_file("/e", 2, 1) == ours.cat_file("/e", 2, 1) == b""
    for start, end in [(-1, -1), (0, 0), (-1, None), (None, -1)]:
        r = outcome(ref.cat_file, "/a", start, end)
        o = outcome(ours.cat_file, "/a", start, end)
        assert r == o, (start, end, r, o)
        r = outcome(ref.cat_ranges, ["/a", "/a"], [start, 0], [end, 0])
        o = outcome(ours.cat_ranges, ["/a", "/a"], [start, 0], [end, 0])
        norm = lambda x: [type(v) if isinstance(v, Exception) else v for v in x[1]] if x[0] == "ok" else x  # noqa: E731
        assert norm(r) == norm(o), (start, end, r, o)


MEM_MUTATIONS = [
    ("mkdir", ("/a",), {}),
    ("mkdir", ("/a/b/c",), {"create_parents": False}),
    ("mkdir", ("/new/x",), {}),
    ("mkdir", ("/a/f/sub",), {}),
    ("makedirs", ("/a",), {"exist_ok": False}),
    ("makedirs", ("/a",), {"exist_ok": True}),
    ("rmdir", ("/a",), {}),
    ("rmdir", ("/a/sub",), {}),
    ("rmdir", ("/empty",), {}),
    ("rmdir", ("/nope",), {}),
    ("rm_file", ("/a/f",), {}),
    ("rm_file", ("/a",), {}),
    ("rm", ("/a",), {}),
    ("rm", ("/a",), {"recursive": True}),
    ("rm", ("/a/*",), {}),
    ("rm", ("/nope",), {}),
    ("rm", (["/a/f", "/top"],), {}),
    ("touch", ("/a/f",), {"truncate": False}),
    ("touch", ("/n",), {}),
    ("pipe_file", ("/a/f", b"new"), {"mode": "create"}),
    ("pipe_file", ("/a/f/x", b"under file"), {}),
    ("pipe_file", ("/a/sub", b"onto dir"), {}),
    ("pipe_file", ("/nonedata", None), {}),  # fsspec memory: an empty file
    ("pipe", ("/nonedata2",), {}),
    ("pipe", ({"/nd/a": None, "/nd/b": b"b"},), {}),
    ("pipe_file", ("/strdata", "text"), {}),
    ("cp_file", ("/a/f", "/g"), {}),
    ("cp_file", ("/a/sub", "/subcopy"), {}),
    ("cp_file", ("/nope", "/g"), {}),
    ("copy", ("/a", "/b"), {"recursive": True}),
    ("copy", ("/a/", "/b"), {"recursive": True}),
    ("copy", ("/a", "/empty"), {"recursive": True}),
    ("copy", ("/a/*", "/empty/"), {}),
    ("copy", ("/a", "/empty"), {"recursive": True, "maxdepth": 1}),
    ("mv", ("/a/f", "/moved"), {}),
    ("mv", ("/a", "/b"), {"recursive": True}),
    ("mv", ("/a", "/empty"), {"recursive": True}),
    ("mv", ("/top", "/empty"), {}),
    ("mv", ("/nope", "/x"), {}),
]


def mem_setup(fs):
    fs.pipe({"/a/f": b"ff", "/a/sub/g": b"g", "/a/sub/deep/h": b"hh", "/top": b"t"})
    fs.mkdir("/empty")
    fs.mkdir("/a/sub/pd")


@pytest.mark.parametrize("op,args,kwargs", MEM_MUTATIONS, ids=[f"{m[0]}-{i}" for i, m in enumerate(MEM_MUTATIONS)])
def test_memory_mutations_identical(mems, op, args, kwargs):
    ref, ours = mems
    mem_setup(ref)
    mem_setup(ours)
    r = outcome(getattr(ref, op), *args, **kwargs)
    o = outcome(getattr(ours, op), *args, **kwargs)
    assert r[0] == o[0], (op, args, r, o)
    if r[0] == "err":
        assert r[1] is o[1], (op, args, r, o)
    assert mem_snapshot(ref) == mem_snapshot(ours), (op, args, kwargs)


# ---------------------------------------------------------------------------
# randomized differential test (hypothesis stateful) on the memory classes

NAMES = st.sampled_from(["a", "b", "c", "d.txt"])
PATHS = st.lists(NAMES, min_size=1, max_size=3).map(lambda parts: "/" + "/".join(parts))
DATA = st.binary(max_size=40)


class MemoryParity(RuleBasedStateMachine):
    """Random operation sequences on fsspec's memory FS and fsfast's must
    produce the same outcomes and the same store."""

    @initialize()
    def setup(self):
        self.ref = RefMemory(global_store=False, skip_instance_cache=True)
        self.ours = fsfast.MemoryFileSystem(global_store=False, skip_instance_cache=True)

    def same(self, op, *args, **kwargs):
        r = outcome(getattr(self.ref, op), *args, **kwargs)
        o = outcome(getattr(self.ours, op), *args, **kwargs)
        assert r[0] == o[0], (op, args, kwargs, r, o)
        if r[0] == "err":
            assert r[1] is o[1], (op, args, kwargs, r, o)
        return r, o

    @rule(path=PATHS, data=DATA, create=st.booleans())
    def pipe(self, path, data, create):
        self.same("pipe_file", path, data, mode="create" if create else "overwrite")

    @rule(path=PATHS, parents=st.booleans())
    def mkdir(self, path, parents):
        self.same("mkdir", path, create_parents=parents)

    @rule(path=PATHS, recursive=st.booleans())
    def rm(self, path, recursive):
        self.same("rm", path, recursive=recursive)

    @rule(path=PATHS)
    def rmdir(self, path):
        self.same("rmdir", path)

    @rule(src=PATHS, dst=PATHS, recursive=st.booleans())
    def copy(self, src, dst, recursive):
        if recursive and (dst == src or dst.startswith(src + "/")):
            # Copying a tree onto or into itself: fsspec expands the source
            # while writing into it, so its result depends on iteration
            # order (it can turn a copied directory into an empty file).
            # Undefined, like mv into itself below; see python-parity.md.
            return
        self.same("copy", src, dst, recursive=recursive)

    @rule(src=PATHS, dst=PATHS)
    def cp_file(self, src, dst):
        self.same("cp_file", src, dst)

    @rule(src=PATHS, dst=PATHS, recursive=st.booleans())
    def mv(self, src, dst, recursive):
        if src != dst and dst.startswith(src + "/"):
            return  # fsspec copies a tree into itself forever-ish; undefined
        self.same("mv", src, dst, recursive=recursive)

    @rule(path=PATHS)
    def read(self, path):
        r, o = self.same("cat_file", path)
        if r[0] == "ok":
            assert r[1] == o[1]
        r, o = self.same("ls", path, detail=False)
        if r[0] == "ok":
            assert sorted(r[1]) == sorted(o[1])
        self.same("info", path)

    @invariant()
    def stores_match(self):
        if hasattr(self, "ref"):
            assert mem_snapshot(self.ref) == mem_snapshot(self.ours)


TestMemoryParityStateful = MemoryParity.TestCase
TestMemoryParityStateful.settings = settings(
    max_examples=int(os.environ.get("FSFAST_HYPOTHESIS_EXAMPLES", "60")),
    stateful_step_count=25,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


class LocalParity(RuleBasedStateMachine):
    """Random operation sequences on two identical local trees."""

    @initialize()
    def setup(self):
        import tempfile

        self.base = tempfile.mkdtemp(prefix="fsfast-parity-")
        self.a = f"{self.base}/ref"
        self.b = f"{self.base}/ours"
        os.makedirs(self.a)
        os.makedirs(self.b)
        self.ours = fsfast.LocalFileSystem()

    def teardown(self):
        import shutil

        if hasattr(self, "base"):
            shutil.rmtree(self.base, ignore_errors=True)

    def same(self, op, *rels, **kwargs):
        ra = [self.a + r if isinstance(r, str) else r for r in rels]
        rb = [self.b + r if isinstance(r, str) else r for r in rels]
        r = outcome(getattr(REF_LOCAL, op), *ra, **kwargs)
        o = outcome(getattr(self.ours, op), *rb, **kwargs)
        assert r[0] == o[0], (op, rels, kwargs, r, o)
        if r[0] == "err":
            assert issubclass(r[1], OSError) == issubclass(o[1], OSError), (op, rels, r, o)
        return r, o

    @rule(path=PATHS, data=DATA)
    def pipe(self, path, data):
        self.same("pipe_file", path, data)

    @rule(path=PATHS)
    def makedirs(self, path):
        self.same("makedirs", path, exist_ok=True)

    @rule(path=PATHS)
    def touch(self, path):
        self.same("touch", path)

    @rule(path=PATHS, recursive=st.booleans())
    def rm(self, path, recursive):
        self.same("rm", path, recursive=recursive)

    @rule(src=PATHS, dst=PATHS, recursive=st.booleans())
    def copy(self, src, dst, recursive):
        self.same("copy", src, dst, recursive=recursive)

    @rule(src=PATHS, dst=PATHS)
    def mv(self, src, dst):
        if dst.startswith(src + "/") or src.startswith(dst + "/"):
            return
        self.same("mv", src, dst)

    @rule(path=PATHS, start=st.none() | st.integers(-50, 50), end=st.none() | st.integers(-50, 50))
    def read(self, path, start, end):
        r, o = self.same("cat_file", path, start, end)
        if r[0] == "ok":
            assert r[1] == o[1]

    @invariant()
    def trees_match(self):
        if hasattr(self, "a"):
            assert ref_snapshot(self.a) == ref_snapshot(self.b)


TestLocalParityStateful = LocalParity.TestCase
TestLocalParityStateful.settings = settings(
    max_examples=int(os.environ.get("FSFAST_HYPOTHESIS_EXAMPLES", "40")),
    stateful_step_count=20,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


def test_strip_protocol_parity_memory():
    for raw in ["memory://a/b/", "/a//b", "a", "", "memory://", "x::y", "s3://b/k/"]:
        assert RefMemory._strip_protocol(raw) == fsfast.MemoryFileSystem._strip_protocol(raw), raw
        assert RefMemory._parent(raw) == fsfast.MemoryFileSystem._parent(raw), raw


def test_names_with_odd_characters(tmp_path):
    ours = fsfast.LocalFileSystem()
    root = str(tmp_path)
    for name in ["sp ace", "uni-ćöde", "per%cent", "hash#x", "q?mark", string.punctuation.replace("/", "")[:10]]:
        p = f"{root}/{name}"
        ours.pipe_file(p, name.encode())
        assert REF_LOCAL.info(p) == ours.info(p)
        assert ours.cat_file(p) == name.encode()
    assert sorted(REF_LOCAL.ls(root)) == sorted(ours.ls(root))
