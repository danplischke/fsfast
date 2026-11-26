"""Tests of the compliance runner itself (``tests/compliance/run.sh``).

Run with ``pytest tests/compliance/test_runner.py``; ``run.sh`` only
collects ``tests/compliance/abstract``, so this module never runs as part
of a compliance suite.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
RUN = HERE / "run.sh"

CLEAN_XML = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" errors="0" failures="0" skipped="0" tests="5">
<testcase classname="stale.TestOld" name="t1"/><testcase classname="stale.TestOld" name="t2"/>
<testcase classname="stale.TestOld" name="t3"/><testcase classname="stale.TestOld" name="t4"/>
<testcase classname="stale.TestOld" name="t5"/>
</testsuite></testsuites>
"""


def run(reports: pathlib.Path, **env: str) -> subprocess.CompletedProcess[str]:
    e = dict(os.environ)
    e.update(env)
    e["FSFAST_COMPLIANCE_REPORTS"] = str(reports)
    e.setdefault("PYTHON", sys.executable)
    return subprocess.run(
        ["bash", str(RUN), "abstract"],
        env=e,
        capture_output=True,
        text=True,
        timeout=600,
    )


def test_pytest_usage_error_is_not_judged_from_a_stale_report(tmp_path: pathlib.Path) -> None:
    # A clean report from an earlier run, then a run whose pytest exits on a
    # usage error before writing any report.
    (tmp_path / "abstract.xml").write_text(CLEAN_XML)
    r = run(tmp_path, FSFAST_COMPLIANCE_TIMEOUT="notanumber")
    out = r.stdout + r.stderr
    assert "--timeout" in out, out
    assert r.returncode != 0, out
    assert "wrote no report" in out, out
    # The stale report was removed, and the summary does not show it.
    assert not (tmp_path / "abstract.xml").exists()
    assert "| 5 |" not in out, out

