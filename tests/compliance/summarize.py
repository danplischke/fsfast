r"""Summarize pytest JUnit XML reports from ``tests/compliance/run.sh``.

Usage::

    python tests/compliance/summarize.py REPORT.xml [...] [--group N | --by-report | --pattern RE] [--failures] [--clean]

Prints passed/failed/error/skipped/xfailed counts per test class (``--group``
picks how many ``::``-separated parts of the test id form the group key)
(``--pattern`` groups by the first regex group matched in the class name,
e.g. ``'Test(\w+?)(?:Copy|Get|Put|Open|Pipe)$'`` gives one row per
backend of the abstract suite) and, with ``--failures``, the first line of each failure message.
"""

from __future__ import annotations

import argparse
import collections
import os
import re
import sys
import xml.etree.ElementTree as ET


def outcome(case: ET.Element) -> tuple[str, str]:
    for tag in ("failure", "error", "skipped"):
        el = case.find(tag)
        if el is not None:
            msg = (el.get("message") or el.text or "").strip().splitlines()
            first = msg[0] if msg else ""
            if tag == "skipped" and el.get("type") == "pytest.xfail":
                return "xfailed", first
            if tag == "failure" and "[XPASS(strict)]" in first:
                return "failed", first
            return {"failure": "failed", "error": "error", "skipped": "skipped"}[tag], first
    return "passed", ""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("reports", nargs="+")
    ap.add_argument("--group", type=int, default=1, help="classname parts used as the group key")
    ap.add_argument("--failures", action="store_true")
    ap.add_argument("--by-report", action="store_true", help="one row per report file")
    ap.add_argument("--pattern", help="group by the first group of this regex on the class name")
    ap.add_argument("--clean", action="store_true", help="exit 1 if anything failed or errored")
    args = ap.parse_args()

    kinds = ("passed", "failed", "error", "skipped", "xfailed")
    counts: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    msgs: list[tuple[str, str, str, str]] = []
    for report in args.reports:
        for case in ET.parse(report).iter("testcase"):
            cls = case.get("classname", "")
            if args.by_report:
                group = os.path.splitext(os.path.basename(report))[0]
            elif args.pattern:
                m = re.search(args.pattern, cls)
                group = m.group(1) if m else cls
            else:
                group = ".".join(cls.split(".")[-args.group :]) if args.group else cls
            kind, msg = outcome(case)
            counts[group][kind] += 1
            if kind in ("failed", "error"):
                msgs.append((group, case.get("name", ""), kind, msg))

    print("| group | " + " | ".join(kinds) + " |")
    print("|---|" + "---:|" * len(kinds))
    total: collections.Counter = collections.Counter()
    for group in sorted(counts):
        total.update(counts[group])
        print(f"| {group} | " + " | ".join(str(counts[group][k]) for k in kinds) + " |")
    print("| **total** | " + " | ".join(f"**{total[k]}**" for k in kinds) + " |")
    if args.clean and (total["failed"] or total["error"]):
        sys.exit(1)
    if args.failures:
        print()
        for group, name, kind, msg in msgs:
            print(f"{kind.upper()} {group}::{name}: {msg[:300]}")


if __name__ == "__main__":
    main()
