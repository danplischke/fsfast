#!/usr/bin/env python3
"""Compare ``bench/run.py`` documents and flag throughput regressions.

    python bench/compare.py CURRENT.json --baseline OLD.json [--threshold 0.05]
    python bench/compare.py CURRENT.json --history DIR [--keep 20]

Every (target, workload result) pair is compared on its best throughput:
MB/s for workloads that move data, ops/s (entries/s for listings)
otherwise. With ``--history`` the reference is the median of the matching
values in every document in DIR (the "trailing median" of docs/PLAN.md
§8.3); ``--keep N`` then prunes DIR to its N newest documents after the
comparison. A result more than ``--threshold`` (default 5%) below the
reference is a regression and makes the exit status 1. Results missing on
either side are reported but are not regressions.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any

Key = tuple[str, str]


def metric(result: dict[str, Any]) -> tuple[str, float] | None:
    """(unit, value) used to compare one workload result."""
    for field, unit in (("mb_per_s", "MB/s"), ("items_per_s", "entries/s"), ("ops_per_s", "ops/s")):
        v = (result.get(field) or {}).get("best")
        if isinstance(v, (int, float)) and v > 0:
            return unit, float(v)
    return None


def values(doc: dict[str, Any]) -> dict[Key, tuple[str, float]]:
    out: dict[Key, tuple[str, float]] = {}
    for run in doc.get("runs", []):
        target = run.get("target") or run.get("protocol") or run.get("url", "?")
        for r in run.get("results", []):
            m = metric(r)
            if m is not None:
                out[(target, f"{r['workload']} {r['name']}")] = m
    return out


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("current", type=Path)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--baseline", type=Path, help="one earlier document")
    g.add_argument("--history", type=Path, help="directory of earlier documents (trailing median)")
    ap.add_argument("--threshold", type=float, default=0.05, help="allowed relative drop (0.05 = 5%%)")
    ap.add_argument("--keep", type=int, default=0, help="with --history: keep only the N newest documents")
    a = ap.parse_args(argv)

    cur = values(load(a.current))
    refs: dict[Key, list[float]] = {}
    units: dict[Key, str] = {}
    if a.baseline:
        docs = [a.baseline]
    else:
        docs = sorted(p for p in a.history.glob("*.json") if p.resolve() != a.current.resolve()) \
            if a.history.is_dir() else []
    for p in docs:
        try:
            for k, (unit, v) in values(load(p)).items():
                refs.setdefault(k, []).append(v)
                units[k] = unit
        except (OSError, json.JSONDecodeError) as e:
            print(f"ignoring {p}: {e}", file=sys.stderr)

    if not refs:
        print("no reference results: nothing to compare (first run?)")
        return 0

    regressions = 0
    print(f"{'target':<10} {'workload':<22} {'reference':>14} {'current':>14} {'change':>8}")
    for k in sorted(set(cur) | set(refs)):
        target, name = k
        if k not in cur:
            print(f"{target:<10} {name:<22} {'':>14} {'missing':>14}")
            continue
        unit, v = cur[k]
        if k not in refs:
            print(f"{target:<10} {name:<22} {'new':>14} {v:>9.1f} {unit}")
            continue
        ref = statistics.median(refs[k])
        change = v / ref - 1.0
        flag = ""
        if change < -a.threshold:
            flag = "  REGRESSION"
            regressions += 1
        print(f"{target:<10} {name:<22} {ref:>14.1f} {v:>14.1f} {change:>+7.1%} {unit}{flag}")

    if a.history and a.keep > 0 and a.history.is_dir():
        old = sorted(a.history.glob("*.json"))
        for p in old[: max(0, len(old) - a.keep)]:
            p.unlink()

    if regressions:
        print(f"{regressions} result(s) more than {a.threshold:.0%} below the reference")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
