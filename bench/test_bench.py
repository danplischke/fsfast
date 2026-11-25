"""Tests of the benchmark harness (no services needed).

    .venv/bin/python -m pytest bench/test_bench.py -q

They run the Python workloads on the memory and local targets with tiny
parameters, check the document shape and the report, and check that
nothing is left behind.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import benchcfg
import run

TINY = replace(
    benchcfg.PROFILES["tiny"],
    size=256 << 10,
    chunk=64 << 10,
    small_count=5,
    info_count=4,
    ls_entries=6,
    ranges=4,
    range_size=4 << 10,
    copy_count=2,
    copy_size=8 << 10,
    delete_count=5,
    repeat=2,
    warmup=1,
)
NAMES = {(w, n) for w, n, _ in benchcfg.WORKLOADS}


def worker(target: str, impl: str, root: str) -> dict:
    out = subprocess.run(
        [
            sys.executable,
            str(HERE / "pyworker.py"),
            "--target",
            target,
            "--impl",
            impl,
            "--root",
            root,
            "--params",
            json.dumps(TINY.to_json()),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )
    return json.loads(out.stdout)


@pytest.mark.parametrize("impl", ["fsfast", "reference"])
def test_worker_memory(impl: str) -> None:
    pytest.importorskip("fsfast")
    root = f"/fsbench-test-{os.getpid()}-{impl}"
    doc = worker("memory", impl, root)
    assert not doc.get("error"), doc
    got = {(r["workload"], r["name"]) for r in doc["results"]}
    assert got == NAMES
    for r in doc["results"]:
        assert not r.get("error"), r
        assert r["iterations"] == TINY.repeat and len(r["times_s"]) == TINY.repeat
        assert r["best_s"] <= r["median_s"]
        assert r["ops_per_s"]["best"] >= r["ops_per_s"]["median"] > 0
        assert r["cpu_s"]["best"] >= 0
    w1 = next(r for r in doc["results"] if r["name"] == "seq-read")
    assert w1["bytes_per_iter"] == TINY.size and w1["mb_per_s"]["best"] > 0
    ls = next(r for r in doc["results"] if r["name"] == "metadata-ls")
    assert ls["items_per_iter"] == TINY.ls_entries


def test_worker_local_cleans_up(tmp_path: Path) -> None:
    pytest.importorskip("fsfast")
    root = tmp_path / "root"
    doc = worker("local", "fsfast", str(root))
    assert not doc.get("error"), doc
    assert all(not r.get("error") for r in doc["results"]), doc["results"]
    assert not root.exists()


def test_fsf_groups_cover_the_workloads() -> None:
    groups = run.fsf_groups(TINY, run.ALL_WORKLOADS)
    kept = set().union(*(names for _, _, names in groups))
    assert kept == {n for _, n in NAMES} - {"seq-read-open"}
    info = next(args for gid, args, _ in groups if gid == "info")
    assert info[info.index("-c") + 1] == "1"  # sequential like the Python loop
    assert info[info.index("--count") + 1] == str(TINY.info_count)
    only = run.fsf_groups(TINY, ["W3"])
    assert [g[0] for g in only] == ["small"] and only[0][1][:2] == ["-w", "W3"]


def result(
    wid: str, name: str, impl: str, med: float, best: float, unit: str = "mb_per_s"
) -> dict:
    return {
        "workload": wid,
        "name": name,
        "impl": impl,
        unit: {"median": med, "best": best},
        "ops_per_s": {"median": 1.0, "best": 1.0},
    }


def test_report_and_merge() -> None:
    a = {
        "meta": {},
        "params": {},
        "runs": [
            {
                "target": "s3",
                "impl": "fsfast",
                "results": [result("W1", "seq-read", "fsfast", 200.0, 250.0)],
            },
            {
                "target": "s3",
                "impl": "reference",
                "results": [result("W1", "seq-read", "reference", 100.0, 110.0)],
                "params_override": {"size": 1},
            },
        ],
    }
    b = {
        "runs": [
            {
                "target": "s3",
                "impl": "fsf",
                "results": [result("W1", "seq-read", "fsf", 400.0, 410.0)],
            }
        ]
    }
    text = run.report(run.merge_docs([a, b]))
    assert (
        "| W1 seq-read | MB/s | 200 (250) | 100 (110) | 400 (410) | 2.00x | 0.50x |"
        in text
    )
    assert "Note: reference: run with {'size': 1}" in text
    # a later document replaces the same (target, impl)
    c = {
        "runs": [
            {
                "target": "s3",
                "impl": "fsfast",
                "results": [result("W1", "seq-read", "fsfast", 300.0, 300.0)],
            }
        ]
    }
    assert "| 300 (300) |" in run.report(run.merge_docs([a, c]))
    unsupported = {
        "runs": [
            {
                "target": "http",
                "impl": "reference",
                "results": [
                    {
                        "workload": "W8",
                        "name": "delete",
                        "impl": "reference",
                        "unsupported": "no rm",
                    }
                ],
            }
        ]
    }
    assert "| W8 delete |  | n/a |" in run.report(unsupported)


def test_summarize_and_set() -> None:
    s = run.summarize([2.0, 1.0, 4.0], nbytes=4_000_000, ops=2, items=10)
    assert s["best_s"] == 1.0 and s["median_s"] == 2.0
    assert s["mb_per_s"] == {"best": 4.0, "median": 2.0}
    assert s["items_per_s"] == {"best": 10.0, "median": 5.0}
    assert run.summarize([1.0], nbytes=0, ops=1)["mb_per_s"] is None
    assert run.parse_set(["size=1G", "repeat=5", "range_size=64K"]) == {
        "size": 1 << 30,
        "repeat": 5,
        "range_size": 64 << 10,
    }
    with pytest.raises(SystemExit):
        run.parse_set(["nope=1"])


def test_speedups_table() -> None:
    doc = {
        "runs": [
            {
                "target": "s3",
                "impl": "fsfast",
                "results": [result("W1", "seq-read", "fsfast", 300.0, 300.0)],
            },
            {
                "target": "s3",
                "impl": "reference",
                "results": [result("W1", "seq-read", "reference", 100.0, 100.0)],
            },
            {
                "target": "http",
                "impl": "fsfast",
                "results": [
                    {
                        "workload": "W1",
                        "name": "seq-read",
                        "impl": "fsfast",
                        "mb_per_s": {"median": 5.0, "best": 5.0},
                    }
                ],
            },
            {
                "target": "http",
                "impl": "reference",
                "results": [
                    {
                        "workload": "W1",
                        "name": "seq-read",
                        "impl": "reference",
                        "unsupported": "x",
                    }
                ],
            },
        ]
    }
    assert run.speedups(doc).splitlines() == [
        "| workload | s3 | http |",
        "|---|---|---|",
        "| W1 seq-read | 3.00x | n/a |",
    ]
