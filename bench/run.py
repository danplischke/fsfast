#!/usr/bin/env python3
"""Run ``fsf bench`` against one or more targets and collect the JSON reports.

Examples::

    # every local test service (scripts/test-services.sh), tiny smoke profile
    eval "$(scripts/test-services.sh env)"
    python bench/run.py --fsf target/release/fsf --profile tiny --targets all

    # explicit URLs, extra fsf arguments after "--"
    python bench/run.py --targets s3://my-bucket/bench /mnt/nvme/bench \\
        --profile large -- --opt s3:anon=false

Named targets map to the local test services and run in a fresh,
uniquely named bucket/directory that ``fsf bench --create`` creates and
removes again. Anything containing ``://`` or ``/`` is used as a URL as
given (it must already exist unless ``--create`` is passed through).

The combined document written to ``--out`` (default ``bench/results/raw``)
has the shape ``{"meta": {...}, "runs": [<fsf bench --json report>, ...]}``;
``bench/compare.py`` compares such documents.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

#: fsf bench arguments per profile.
PROFILES: dict[str, list[str]] = {
    # CI smoke test: proves every workload runs, numbers are not meaningful.
    "tiny": [
        "--size", "1MiB", "--file-size", "4KiB", "--count", "32", "--ranges", "32",
        "--range-size", "16KiB", "-n", "2", "--warmup", "1", "-c", "8",
    ],
    # Nightly default: small enough for a shared runner.
    "default": [
        "--size", "256MiB", "--file-size", "16KiB", "--count", "1000", "--ranges", "512",
        "--range-size", "256KiB", "-n", "3", "--warmup", "1", "-c", "32",
    ],
    # Dedicated hardware (PLAN.md §8: W1 at multi-GiB, W4 at 10k files).
    "large": [
        "--size", "4GiB", "--file-size", "16KiB", "--count", "10000", "--ranges", "2048",
        "--range-size", "4MiB", "-n", "5", "--warmup", "1", "-c", "64",
    ],
}

#: Named targets: (required environment variables, URL template).
#: ``{u}`` is a unique name; ``{VAR}`` an environment variable.
SERVICES: dict[str, tuple[list[str], str]] = {
    "memory": ([], "memory://{u}"),
    "local": ([], "local"),
    "s3": (["FSFAST_TEST_S3_ENDPOINT", "FSFAST_TEST_S3_KEY", "FSFAST_TEST_S3_SECRET"], "s3://{u}"),
    "gcs": (["FSFAST_TEST_GCS_ENDPOINT"], "gs://{u}"),
    "azure": (["FSFAST_TEST_AZURE_CONNECTION_STRING"], "abfs://{u}"),
    "smb": (
        ["FSFAST_TEST_SMB_HOST", "FSFAST_TEST_SMB_SHARE", "FSFAST_TEST_SMB_USER"],
        "smb://{FSFAST_TEST_SMB_HOST}/{FSFAST_TEST_SMB_SHARE}/{u}",
    ),
    "smb-enc": (
        ["FSFAST_TEST_SMB_HOST", "FSFAST_TEST_SMB_ENC_SHARE", "FSFAST_TEST_SMB_USER"],
        "smb://{FSFAST_TEST_SMB_HOST}/{FSFAST_TEST_SMB_ENC_SHARE}/{u}",
    ),
    "sftp": (["FSFAST_TEST_SFTP_HOST", "FSFAST_TEST_SFTP_USER"], "sftp://{FSFAST_TEST_SFTP_HOST}/tmp/{u}"),
}


def find_fsf(explicit: str | None) -> str:
    """The fsf binary: --fsf, $FSF, target/release/fsf, target/debug/fsf, $PATH."""
    candidates = [explicit, os.environ.get("FSF")]
    exe = ".exe" if os.name == "nt" else ""
    candidates += [str(ROOT / "target" / p / f"fsf{exe}") for p in ("release", "debug")]
    for c in candidates:
        if c and Path(c).is_file():
            return c
    found = shutil.which("fsf")
    if found:
        return found
    sys.exit("fsf not found: build it with `cargo build --release -p fsfast-cli` or pass --fsf")


def resolve_target(name: str, unique: str, tmp_root: Path) -> tuple[str, list[str]] | None:
    """URL and extra fsf arguments for a target, or None when unavailable."""
    if "://" in name or "/" in name or name.startswith("."):
        return name, []
    if name not in SERVICES:
        sys.exit(f"unknown target {name!r} (known: {', '.join(SERVICES)}, or a URL)")
    needed, template = SERVICES[name]
    missing = [v for v in needed if not os.environ.get(v)]
    if missing:
        print(f"skipping {name}: {', '.join(missing)} not set", file=sys.stderr)
        return None
    if name == "local":
        path = tmp_root / unique
        return str(path), ["--create"]
    url = template.format(u=unique, **os.environ)
    return url, ["--test-services", "--create"]


def run_one(fsf: str, url: str, args: list[str], timeout: float) -> dict[str, Any]:
    cmd = [fsf, "bench", url, "--json", "-q", *args]
    print("$ " + " ".join(cmd), file=sys.stderr)
    t0 = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        report = {"url": url, "error": f"fsf exited {proc.returncode} without a JSON report"}
    report["exit_code"] = proc.returncode
    report["wall_s"] = round(time.monotonic() - t0, 3)
    return report


def summary_line(report: dict[str, Any]) -> list[str]:
    lines = []
    proto = report.get("target") or report.get("protocol", "?")
    for r in report.get("results", []):
        mb = (r.get("mb_per_s") or {}).get("best")
        ops = (r.get("ops_per_s") or {}).get("best")
        p99 = (r.get("latency_ms") or {}).get("p99")
        reqs = (r.get("stats") or {}).get("requests")
        lines.append(
            f"{proto:<8} {r['workload']:<3} {r['name']:<15} "
            f"{'' if mb is None else f'{mb:10.1f} MB/s'}{'':>2}"
            f"{'' if ops is None else f'{ops:10.0f} ops/s'}{'':>2}"
            f"{'' if p99 is None else f'p99 {p99:8.2f} ms'}"
            f"{'' if reqs is None else f'  {reqs} req'}"
        )
    if report.get("error"):
        lines.append(f"{proto:<8} ERROR {report['error']}")
    return lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fsf", help="path to the fsf binary")
    ap.add_argument("--targets", nargs="+", default=["memory", "local"],
                    help="service names (memory local s3 gcs azure smb smb-enc sftp | all) or URLs")
    ap.add_argument("--profile", choices=sorted(PROFILES), default="tiny")
    ap.add_argument("--workloads", default="all", help="fsf --workloads value")
    ap.add_argument("--out", default=str(ROOT / "bench" / "results" / "raw"),
                    help="directory for the combined JSON document")
    ap.add_argument("--label", default="", help="free-form label stored in the document")
    ap.add_argument("--timeout", type=float, default=3600, help="seconds per target")
    ap.add_argument("extra", nargs=argparse.REMAINDER, help="arguments after -- go to fsf bench")
    a = ap.parse_args(argv)

    extra = a.extra[1:] if a.extra[:1] == ["--"] else a.extra
    fsf = find_fsf(a.fsf)
    targets = list(SERVICES) if a.targets == ["all"] else a.targets
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    unique = f"fsf-benchrun-{stamp.lower()}-{os.getpid()}"
    tmp_root = Path(os.environ.get("RUNNER_TEMP") or os.environ.get("TMPDIR") or "/tmp")

    version = subprocess.run([fsf, "--version"], capture_output=True, text=True).stdout.strip()
    doc: dict[str, Any] = {
        "meta": {
            "created_at": stamp,
            "label": a.label,
            "profile": a.profile,
            "fsf": version,
            "git_sha": os.environ.get("GITHUB_SHA") or _git_sha(),
            "host": platform.node(),
            "platform": platform.platform(),
            "cpus": os.cpu_count(),
            "extra_args": extra,
        },
        "runs": [],
    }
    failed = False
    for t in targets:
        resolved = resolve_target(t, unique, tmp_root)
        if resolved is None:
            continue
        url, targs = resolved
        args = [*PROFILES[a.profile], "--workloads", a.workloads, *targs, *extra]
        report = run_one(fsf, url, args, a.timeout)
        report["target"] = t
        doc["runs"].append(report)
        failed |= report["exit_code"] != 0 or bool(report.get("error"))
        for line in summary_line(report):
            print(line)

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"bench-{stamp}{'-' + a.label if a.label else ''}.json"
    path.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {path}", file=sys.stderr)
    return 1 if failed else 0


def _git_sha() -> str | None:
    try:
        return subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


if __name__ == "__main__":
    sys.exit(main())
