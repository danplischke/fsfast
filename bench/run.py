#!/usr/bin/env python3
"""Benchmark fsfast against the reference fsspec implementations.

For every target (a local test service, see ``scripts/test-services.sh``)
the same workloads (W1-W8, ``bench/benchcfg.py``) run through

* ``fsfast``    - fsfast's Python classes (``import fsfast``),
* ``reference`` - the fsspec implementation fsfast replaces (fsspec's
  local/memory/http/smb/sftp, s3fs, gcsfs, adlfs),
* ``sshfs``     - a second SFTP reference (asyncssh), sftp only,
* ``fsf``       - the ``fsf bench`` CLI: the Rust engine without Python,
* ``native``    - native tools where they exist (coreutils, smbclient,
  OpenSSH sftp, curl).

Every Python implementation runs in its own fresh interpreter
(``bench/pyworker.py``). Each workload does ``warmup`` untimed and
``repeat`` timed iterations; the document records every iteration time, the
best and the median, MB/s or ops/s, client CPU seconds, fsfast's request
counters, the machine, the load average around every run and the service
versions. Examples::

    eval "$(scripts/test-services.sh env)"
    cargo build --release -p fsfast-cli
    maturin develop --release -m crates/fsfast-py/Cargo.toml
    python bench/run.py --targets all --profile default --out bench/results --label baseline
    python bench/run.py --targets s3 smb --impls fsfast,reference -w W1,W3
    python bench/run.py --report bench/results/bench-...json    # tables only

The combined document has the shape ``{"meta": {...}, "params": {...},
"runs": [{"target", "impl", "results": [...]}, ...]}``; ``--out`` (default
``bench/results/raw``, git-ignored) receives it plus a Markdown summary.
``bench/compare.py`` compares documents (keyed by target, implementation and
workload). Anything containing ``://`` or ``/`` in ``--targets`` is a URL
run with ``fsf`` only (arguments after ``--`` go to ``fsf bench``).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import platform
import shlex
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from benchcfg import (
    PROFILES,
    PY_IMPLS,
    TARGET_ENV,
    TARGETS,
    Params,
    profile,
    smb_share,
)

IMPLS = ["fsfast", "reference", "sshfs", "fsf", "native"]

#: Python package each Python implementation needs, per target.
NEEDS: dict[str, dict[str, str]] = {
    "local": {"reference": "fsspec"},
    "memory": {"reference": "fsspec"},
    "http": {"reference": "aiohttp"},
    "s3": {"reference": "s3fs"},
    "gcs": {"reference": "gcsfs"},
    "azure": {"reference": "adlfs"},
    "smb": {"reference": "smbprotocol"},
    "smb-enc": {"reference": "smbprotocol"},
    "sftp": {"reference": "paramiko", "sshfs": "sshfs"},
}
ALL_WORKLOADS = ["W1", "W2", "W3", "W4", "W5", "W6", "W7", "W8"]


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# environment


def find_fsf(explicit: str | None) -> str | None:
    """The fsf binary: --fsf, $FSF, target/release/fsf, target/debug/fsf, $PATH."""
    exe = ".exe" if os.name == "nt" else ""
    for c in [
        explicit,
        os.environ.get("FSF"),
        *(str(ROOT / "target" / p / f"fsf{exe}") for p in ("release", "debug")),
    ]:
        if c and Path(c).is_file():
            return c
    return shutil.which("fsf")


def find_nginx(explicit: str | None) -> str | None:
    for c in [
        explicit,
        os.environ.get("FSFAST_BENCH_NGINX"),
        shutil.which("nginx"),
        "/usr/sbin/nginx",
    ]:
        if c and Path(c).is_file():
            return c
    return None


def out_of(cmd: list[str], timeout: float = 15) -> str | None:
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (p.stdout or p.stderr).strip()
    return text.splitlines()[0] if text else None


def git_info() -> dict[str, Any]:
    sha = out_of(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    dirty = out_of(
        ["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=no"]
    )
    return {"sha": os.environ.get("GITHUB_SHA") or sha, "dirty": bool(dirty)}


def cpu_model() -> str | None:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or None


def mem_total_gib() -> float | None:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return round(int(line.split()[1]) / 1024 / 1024, 1)
    except OSError:
        pass
    return None


def py_versions(python: str) -> dict[str, str | None]:
    code = (
        "import importlib.metadata as m, json\n"
        "out = {}\n"
        "for p in ['fsfast', 'fsspec', 's3fs', 'gcsfs', 'adlfs', 'smbprotocol', 'paramiko', 'sshfs',\n"
        "          'asyncssh', 'aiohttp', 'aiobotocore', 'botocore', 'azure-storage-blob', 'cryptography']:\n"
        "    try: out[p] = m.version(p)\n"
        "    except Exception: out[p] = None\n"
        "print(json.dumps(out))\n"
    )
    try:
        p = subprocess.run(
            [python, "-c", code],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return json.loads(p.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {}


def docker_image(
    container: str, version_cmd: list[str] | None
) -> dict[str, Any] | None:
    fmt = "{{.Config.Image}}|{{.Image}}|{{.Created}}"
    line = out_of(["docker", "inspect", "--format", fmt, container])
    if not line or "|" not in line:
        return None
    image, image_id, created = line.split("|", 2)
    info: dict[str, Any] = {
        "container": container,
        "image": image,
        "image_id": image_id[:19],
        "created": created,
    }
    labels = out_of(
        ["docker", "image", "inspect", "--format", "{{json .Config.Labels}}", image_id]
    )
    if labels and labels != "null":
        try:
            info["labels"] = {
                k: v for k, v in json.loads(labels).items() if "version" in k.lower()
            }
        except ValueError:
            pass
    if version_cmd:
        info["version"] = out_of(["docker", "exec", container, *version_cmd])
    return info


def service_versions(nginx: str | None) -> dict[str, Any]:
    return {
        "s3 (RustFS)": docker_image("fsfast-s3", ["rustfs", "--version"]),
        "gcs (fake-gcs-server)": docker_image("fsfast-gcs", None),
        "azure (Azurite)": docker_image("fsfast-azure", ["azurite", "--version"]),
        "smb (Samba smbd)": out_of(["smbd", "--version"]),
        "sftp (OpenSSH sshd)": out_of(["/usr/sbin/sshd", "-V"])
        or out_of(["ssh", "-V"]),
        "http (nginx)": out_of([nginx, "-v"]) if nginx else None,
        "smbclient": out_of(["smbclient", "--version"]),
        "ssh client": out_of(["ssh", "-V"]),
        "curl": out_of(["curl", "--version"]),
    }


def machine() -> dict[str, Any]:
    return {
        "host": platform.node(),
        "platform": platform.platform(),
        "cpu": cpu_model(),
        "cpus": os.cpu_count(),
        "mem_gib": mem_total_gib(),
        "python": sys.version.split()[0],
        "loadavg_start": list(os.getloadavg()),
    }


# ---------------------------------------------------------------------------
# HTTP server (nginx with WebDAV PUT/DELETE and autoindex listings)


class Nginx:
    """A private nginx serving ``docroot`` on a free loopback port; it is
    a plain process of ours (never a system service)."""

    def __init__(self, binary: str, docroot: Path) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="fsbench-nginx-"))
        self.docroot = docroot
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        user = "user root;" if os.geteuid() == 0 else ""
        conf = f"""
{user}
worker_processes 2;
pid {self.dir}/nginx.pid;
error_log {self.dir}/error.log warn;
events {{ worker_connections 4096; }}
http {{
  access_log off;
  default_type application/octet-stream;
  sendfile on; tcp_nopush on; tcp_nodelay on;
  keepalive_requests 1000000; keepalive_timeout 120s;
  client_max_body_size 0; client_body_buffer_size 1m;
  client_body_temp_path {self.dir}/body; proxy_temp_path {self.dir}/proxy;
  fastcgi_temp_path {self.dir}/fcgi; uwsgi_temp_path {self.dir}/uwsgi; scgi_temp_path {self.dir}/scgi;
  server {{
    listen 127.0.0.1:{self.port};
    root {docroot};
    location / {{
      autoindex on;
      dav_methods PUT DELETE MKCOL;
      create_full_put_path on;
      dav_access user:rw group:r all:r;
    }}
  }}
}}
"""
        (self.dir / "nginx.conf").write_text(conf)
        self.proc = subprocess.Popen(
            [
                binary,
                "-p",
                str(self.dir),
                "-c",
                str(self.dir / "nginx.conf"),
                "-g",
                "daemon off;",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    return
            except OSError:
                if self.proc.poll() is not None:
                    raise RuntimeError(
                        f"nginx failed: {self.proc.stderr.read().decode() if self.proc.stderr else ''}"
                    )
                time.sleep(0.05)
        raise RuntimeError("nginx did not start")

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        shutil.rmtree(self.dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# targets


class Target:
    """Where each implementation works for one named target."""

    def __init__(
        self, name: str, unique: str, local_dir: Path, nginx: Nginx | None
    ) -> None:
        self.name, self.unique, self.local_dir, self.nginx = (
            name,
            unique,
            local_dir,
            nginx,
        )

    def py_root(self, impl: str) -> tuple[str, str | None]:
        """(root path for the Python implementation, http disk root)."""
        u = f"{self.unique}-{impl}"
        n = self.name
        if n == "local":
            return str(self.local_dir / u), None
        if n == "memory":
            return f"/{u}", None
        if n in ("s3", "gcs", "azure"):
            return u, None
        if n in ("smb", "smb-enc"):
            return f"/{smb_share(n)}/{u}", None
        if n == "sftp":
            return f"/tmp/{u}", None
        if n == "http":
            assert self.nginx is not None
            return f"{self.nginx.base}/{u}", str(self.nginx.docroot / u)
        raise ValueError(n)

    def fsf_url(self, group: str) -> tuple[str, list[str]]:
        """(URL, extra fsf arguments) of one fsf group run."""
        u = f"{self.unique}-fsf-{group}"
        n, e = self.name, os.environ
        if n == "local":
            return str(self.local_dir / u), ["--create"]
        if n == "memory":
            return f"memory://{u}", ["--create"]
        if n == "http":
            assert self.nginx is not None
            (self.nginx.docroot / u).mkdir(parents=True, exist_ok=True)
            return f"{self.nginx.base}/{u}", []
        scheme = {"s3": "s3://", "gcs": "gs://", "azure": "abfs://"}
        if n in scheme:
            return f"{scheme[n]}{u}", ["--test-services", "--create"]
        if n in ("smb", "smb-enc"):
            return f"smb://{e['FSFAST_TEST_SMB_HOST']}/{smb_share(n)}/{u}", [
                "--test-services",
                "--create",
            ]
        if n == "sftp":
            return f"sftp://{e['FSFAST_TEST_SFTP_HOST']}/tmp/{u}", [
                "--test-services",
                "--create",
            ]
        raise ValueError(n)


def available(name: str) -> str | None:
    """None if the target can run, else why not."""
    missing = [v for v in TARGET_ENV[name] if not os.environ.get(v)]
    if missing:
        return f'{", ".join(missing)} not set (eval "$(scripts/test-services.sh env)")'
    return None


# ---------------------------------------------------------------------------
# result helpers


def summarize(
    times: list[float], nbytes: int, ops: int, items: int | None = None
) -> dict[str, Any]:
    best, med = min(times), statistics.median(times)
    out: dict[str, Any] = {
        "iterations": len(times),
        "times_s": [round(t, 6) for t in times],
        "best_s": round(best, 6),
        "median_s": round(med, 6),
        "bytes_per_iter": nbytes,
        "ops_per_iter": ops,
        "mb_per_s": {"best": nbytes / best / 1e6, "median": nbytes / med / 1e6}
        if nbytes
        else None,
        "ops_per_s": {"best": ops / best, "median": ops / med},
    }
    if items is not None:
        out["items_per_iter"] = items
        out["items_per_s"] = {"best": items / best, "median": items / med}
    return out


def run_json(
    cmd: list[str],
    timeout: float,
    env: dict[str, str] | None = None,
    stream: bool = False,
) -> tuple[dict[str, Any], str]:
    """Run a command that prints one JSON document; (document, stderr).
    With ``stream`` its stderr goes straight to ours (progress of long
    runs) and the returned stderr is empty."""
    log("$ " + " ".join(shlex.quote(c) for c in cmd))
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=None if stream else subprocess.PIPE,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        err = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        return {"error": f"timed out after {timeout:.0f} s"}, err
    try:
        doc = json.loads(p.stdout)
    except json.JSONDecodeError:
        doc = {
            "error": f"exit {p.returncode} without a JSON document: {p.stdout[-500:]}"
        }
    doc["exit_code"] = p.returncode
    return doc, p.stderr or ""


# ---------------------------------------------------------------------------
# Python implementations


#: Smaller objects for implementations too slow for the profile's sizes to
#: finish in reasonable time: paramiko (fsspec's sftp) writes at about
#: 1 MB/s (no pipelining), so a 256 MiB W2 would take four minutes per
#: iteration. MB/s stays comparable; the override is recorded in the run.
SLOW_OVERRIDES: dict[tuple[str, str], dict[str, int]] = {
    ("sftp", "reference"): {"size": 32 << 20, "copy_size": 1 << 20},
}


def run_python(
    python: str,
    target: Target,
    impl: str,
    p: Params,
    workloads: list[str],
    timeout: float,
    full: bool = False,
) -> dict[str, Any]:
    over = (
        {}
        if full
        else {
            k: v
            for k, v in SLOW_OVERRIDES.get((target.name, impl), {}).items()
            if v < getattr(p, k)
        }
    )
    if over:
        p = Params.from_json(
            {**p.to_json(), **over, "chunk": min(p.chunk, over.get("size", p.chunk))}
        )
        log(
            f"{target.name}/{impl}: smaller sizes {over} (too slow for the profile; --full-size disables this)"
        )
    root, disk = target.py_root(impl)
    cmd = [
        python,
        str(HERE / "pyworker.py"),
        "--target",
        target.name,
        "--impl",
        impl,
        "--root",
        root,
        "--params",
        json.dumps(p.to_json()),
        "--workloads",
        ",".join(workloads),
    ]
    if disk:
        cmd += ["--disk-root", disk]
    env = dict(os.environ)
    env.setdefault("GCSFS_EXPERIMENTAL_ZB_HNS_SUPPORT", "false")
    t0 = time.monotonic()
    doc, _ = run_json(cmd, timeout, env, stream=True)
    doc["wall_s"] = round(time.monotonic() - t0, 3)
    if over:
        doc["params_override"] = over
    if disk:
        shutil.rmtree(disk, ignore_errors=True)
    return doc


# ---------------------------------------------------------------------------
# fsf (Rust only)


def fsf_groups(
    p: Params, workloads: list[str]
) -> list[tuple[str, list[str], set[str]]]:
    """fsf bench invocations: (group id, arguments, result names kept).

    One invocation cannot use different file sizes and counts per
    workload, so the workloads are split into groups with the same
    parameters as the Python implementations. W5 runs twice: ``info`` on
    ``info_count`` files one call at a time (like the Python loop), and
    ``ls``/``find`` of one ``ls_entries``-entry directory."""
    c = str(p.concurrency)
    common = ["-n", str(p.repeat), "--warmup", str(p.warmup), "--seed", str(p.seed)]
    g: list[tuple[str, list[str], set[str]]] = []
    big = [w for w in ("W1", "W2", "W6") if w in workloads]
    if big:
        g.append(
            (
                "big",
                [
                    "-w",
                    ",".join(big),
                    "--size",
                    str(p.size),
                    "--range-size",
                    str(p.range_size),
                    "--ranges",
                    str(p.ranges),
                    "-c",
                    c,
                    *common,
                ],
                {"seq-read", "seq-write", "random-read"},
            )
        )
    small = [w for w in ("W3", "W4") if w in workloads]
    if small:
        g.append(
            (
                "small",
                [
                    "-w",
                    ",".join(small),
                    "--count",
                    str(p.small_count),
                    "--file-size",
                    str(p.small_size),
                    "-c",
                    c,
                    *common,
                ],
                {"small-read", "small-write"},
            )
        )
    if "W5" in workloads:
        g.append(
            (
                "info",
                [
                    "-w",
                    "W5",
                    "--count",
                    str(p.info_count),
                    "--dirs",
                    "1",
                    "--file-size",
                    "100",
                    "-c",
                    "1",
                    *common,
                ],
                {"metadata-info"},
            )
        )
        g.append(
            (
                "ls",
                [
                    "-w",
                    "W5",
                    "--count",
                    str(p.ls_entries),
                    "--dirs",
                    "1",
                    "--file-size",
                    "100",
                    "-c",
                    c,
                    *common,
                ],
                {"metadata-ls", "metadata-find"},
            )
        )
    if "W7" in workloads:
        g.append(
            (
                "copy",
                [
                    "-w",
                    "W7",
                    "--count",
                    str(p.copy_count),
                    "--file-size",
                    str(p.copy_size),
                    "-c",
                    c,
                    *common,
                ],
                {"copy"},
            )
        )
    if "W8" in workloads:
        g.append(
            (
                "delete",
                [
                    "-w",
                    "W8",
                    "--count",
                    str(p.delete_count),
                    "--file-size",
                    str(p.small_size),
                    "-c",
                    c,
                    *common,
                ],
                {"delete"},
            )
        )
    return g


def run_fsf(
    fsf: str,
    target: Target,
    p: Params,
    workloads: list[str],
    extra: list[str],
    timeout: float,
) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "impl": "fsf",
        "target": target.name,
        "results": [],
        "groups": [],
    }
    t0 = time.monotonic()
    for gid, args, keep in fsf_groups(p, workloads):
        url, targs = target.fsf_url(gid)
        rep, err = run_json(
            [fsf, "bench", url, "--json", "-q", *args, *targs, *extra], timeout
        )
        if err.strip():
            sys.stderr.write(err[-3000:])
        doc["groups"].append(
            {
                "group": gid,
                "url": url,
                "config": rep.get("config"),
                "cleanup": rep.get("cleanup"),
                "error": rep.get("error"),
                "exit_code": rep.get("exit_code"),
            }
        )
        doc.setdefault("version", rep.get("version"))
        for r in rep.get("results", []):
            if r.get("name") in keep:
                r["impl"] = "fsf"
                r["fsf_group"] = gid
                doc["results"].append(r)
        if rep.get("error"):
            doc.setdefault("errors", []).append(f"{gid}: {rep['error']}")
        if target.name == "http":
            shutil.rmtree(
                target.nginx.docroot / f"{target.unique}-fsf-{gid}", ignore_errors=True
            )  # type: ignore[union-attr]
    doc["wall_s"] = round(time.monotonic() - t0, 3)
    return doc


# ---------------------------------------------------------------------------
# native tools


def timed(
    cmd: str | list[str],
    *,
    shell: bool = False,
    env: dict[str, str] | None = None,
    stdin: str | None = None,
) -> float:
    t0 = time.perf_counter()
    p = subprocess.run(
        cmd,
        shell=shell,
        capture_output=True,
        text=True,
        env=env,
        input=stdin,
        timeout=3600,
        check=False,
    )
    t = time.perf_counter() - t0
    if p.returncode != 0:
        raise RuntimeError(
            f"{cmd if isinstance(cmd, str) else ' '.join(cmd)}: exit {p.returncode}: {(p.stderr or p.stdout)[-500:]}"
        )
    if (
        "NT_STATUS" in (p.stdout + p.stderr)
        and "NT_STATUS_OK" not in p.stdout + p.stderr
    ):
        raise RuntimeError(f"smbclient: {(p.stdout + p.stderr)[-500:]}")
    return t


class Native:
    """Native-tool runs: ``(workload, name, tool, setup, body, teardown,
    bytes, ops, items)`` per workload, all timed like the Python ones."""

    def __init__(
        self, target: Target, p: Params, scratch: Path, fsf: str | None
    ) -> None:
        self.t, self.p, self.scratch, self.fsf = target, p, scratch, fsf
        self.results: list[dict[str, Any]] = []
        self.src = scratch / "native-src.bin"
        self.dst = scratch / "native-dst.bin"
        if not self.src.exists():
            with open(self.src, "wb") as f:
                chunk = os.urandom(p.chunk)
                f.writelines(chunk for _ in range(p.size // p.chunk))
                f.write(chunk[: p.size % p.chunk])

    def measure(
        self,
        wid: str,
        name: str,
        tool: str,
        body: Callable[[int], float | None],
        nbytes: int,
        ops: int,
        items: int | None = None,
        prepare: Callable[[int], None] = lambda it: None,
        teardown: Callable[[int], None] = lambda it: None,
        note: str | None = None,
    ) -> None:
        res: dict[str, Any] = {
            "workload": wid,
            "name": name,
            "impl": "native",
            "tool": tool,
            "warmup": self.p.warmup,
        }
        if note:
            res["note"] = note
        times: list[float] = []
        try:
            for it in range(self.p.warmup + self.p.repeat):
                prepare(it)
                t = body(it)
                teardown(it)
                if it >= self.p.warmup and t is not None:
                    times.append(t)
            res.update(summarize(times, nbytes, ops, items))
            log(f"native {wid} {name} ({tool}): best {min(times):.4f}s")
        except Exception as e:  # noqa: BLE001
            res["error"] = f"{type(e).__name__}: {e}"[:2000]
            log(f"native {wid} {name}: ERROR {res['error']}")
        self.results.append(res)

    # -- per target ----------------------------------------------------------

    def run(self, workloads: list[str]) -> dict[str, Any]:
        n = self.t.name
        fn = {
            "local": self.local,
            "smb": self.smb,
            "smb-enc": self.smb,
            "sftp": self.sftp,
            "http": self.http,
        }.get(n)
        doc: dict[str, Any] = {"impl": "native", "target": n, "results": self.results}
        if fn is None:
            doc["unsupported"] = (
                "no native tool installed for this service (aws-cli/gcloud/azcopy are not used)"
            )
            return doc
        t0 = time.monotonic()
        try:
            fn(workloads)
        except Exception as e:  # noqa: BLE001
            doc["error"] = f"{type(e).__name__}: {e}"
            log(f"native {n}: ERROR {doc['error']}")
        doc["wall_s"] = round(time.monotonic() - t0, 3)
        return doc

    def local(self, workloads: list[str]) -> None:
        root = self.t.local_dir / f"{self.t.unique}-native"
        root.mkdir(parents=True)
        p = self.p
        big = root / "large.bin"
        try:
            if "W2" in workloads or "W1" in workloads or "W6" in workloads:
                self.measure(
                    "W2",
                    "seq-write",
                    "cp",
                    lambda it: timed(["cp", str(self.src), str(big)]),
                    p.size,
                    1,
                    teardown=lambda it: None,
                    note="cp from a tmpfs file",
                )
            if "W1" in workloads:
                self.measure(
                    "W1",
                    "seq-read",
                    "cat",
                    lambda it: timed(
                        f"cat {shlex.quote(str(big))} > /dev/null", shell=True
                    ),
                    p.size,
                    1,
                )
            if "W3" in workloads:
                sd = root / "small"
                sd.mkdir()
                data = os.urandom(p.small_size)
                for i in range(p.small_count):
                    (sd / f"f{i:06d}").write_bytes(data)
                self.measure(
                    "W3",
                    "small-read",
                    "cat",
                    lambda it: timed(
                        f"cat {shlex.quote(str(sd))}/* > /dev/null", shell=True
                    ),
                    p.small_count * p.small_size,
                    p.small_count,
                )
            if "W5" in workloads:
                md = root / "meta"
                md.mkdir()
                for i in range(p.ls_entries):
                    (md / f"f{i:06d}").write_bytes(b"x" * 100)
                self.measure(
                    "W5",
                    "metadata-ls",
                    "ls -l",
                    lambda it: timed(["ls", "-l", "--", str(md)]),
                    0,
                    1,
                    p.ls_entries,
                )
                self.measure(
                    "W5",
                    "metadata-find",
                    "find",
                    lambda it: timed(["find", str(md)]),
                    0,
                    1,
                    p.ls_entries,
                )
            if "W7" in workloads:
                cs = root / "copysrc"
                cs.mkdir()
                with open(self.src, "rb") as f:
                    blob = f.read(p.copy_size)
                for i in range(p.copy_count):
                    (cs / f"f{i:04d}").write_bytes(blob)

                def cp(it: int) -> float:
                    d = root / f"copy{it}"
                    d.mkdir()
                    return timed(
                        f"cp {shlex.quote(str(cs))}/* {shlex.quote(str(d))}/",
                        shell=True,
                    )

                self.measure(
                    "W7",
                    "copy",
                    "cp",
                    cp,
                    p.copy_count * p.copy_size,
                    p.copy_count,
                    teardown=lambda it: shutil.rmtree(root / f"copy{it}"),
                )
            if "W8" in workloads:

                def prep(it: int) -> None:
                    d = root / f"del{it}"
                    d.mkdir()
                    data = b"x" * p.small_size
                    for i in range(p.delete_count):
                        (d / f"f{i:06d}").write_bytes(data)

                self.measure(
                    "W8",
                    "delete",
                    "rm",
                    lambda it: timed(
                        f"rm -f {shlex.quote(str(root / f'del{it}'))}/*", shell=True
                    ),
                    0,
                    p.delete_count,
                    prepare=prep,
                    teardown=lambda it: (root / f"del{it}").rmdir(),
                )
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def smb(self, workloads: list[str]) -> None:
        e = os.environ
        share = smb_share(self.t.name)
        d = f"{self.t.unique}-native"
        base = [
            "smbclient",
            f"//{e['FSFAST_TEST_SMB_HOST']}/{share}",
            "-p",
            e.get("FSFAST_TEST_SMB_PORT", "445"),
            "-U",
            f"{e['FSFAST_TEST_SMB_USER']}%{e['FSFAST_TEST_SMB_PASSWORD']}",
            "-m",
            "SMB3",
        ]
        if self.t.name == "smb-enc":
            base.append("--client-protection=encrypt")
        tool = "smbclient" + (" (encrypted)" if self.t.name == "smb-enc" else "")

        def smbc(cmds: str) -> float:
            return timed([*base, "-c", cmds])

        smbc(f"mkdir {d}")
        try:
            connect = statistics.median(smbc("exit") for _ in range(3))
            note = f"includes process start, connect and session setup (~{connect * 1000:.0f} ms alone)"
            p = self.p
            if {"W1", "W2"} & set(workloads):
                self.measure(
                    "W2",
                    "seq-write",
                    tool,
                    lambda it: smbc(f"put {self.src} {d}\\large.bin"),
                    p.size,
                    1,
                    note=note,
                )
            if "W1" in workloads:
                self.measure(
                    "W1",
                    "seq-read",
                    tool,
                    lambda it: smbc(f"get {d}\\large.bin /dev/null"),
                    p.size,
                    1,
                    note=note,
                )
            if "W5" in workloads and self.fsf:
                self.upload_tree(
                    d, f"smb://{e['FSFAST_TEST_SMB_HOST']}/{share}/{d}/meta"
                )
                self.measure(
                    "W5",
                    "metadata-ls",
                    tool,
                    lambda it: smbc(f"ls {d}\\meta\\*"),
                    0,
                    1,
                    p.ls_entries,
                    note=note,
                )
        finally:
            if self.fsf:
                subprocess.run(
                    [
                        self.fsf,
                        "--test-services",
                        "rm",
                        "-r",
                        f"smb://{e['FSFAST_TEST_SMB_HOST']}/{share}/{d}",
                    ],
                    capture_output=True,
                    timeout=600,
                    check=False,
                )

    def upload_tree(self, rel: str, url: str) -> None:
        """Create the ls_entries-entry directory with fsf (untimed setup)."""
        assert self.fsf
        local = self.scratch / "native-meta"
        if not local.exists():
            local.mkdir()
            for i in range(self.p.ls_entries):
                (local / f"f{i:06d}").write_bytes(b"x" * 100)
        subprocess.run(
            [self.fsf, "--test-services", "cp", "-r", "-j", "32", str(local), url],
            check=True,
            capture_output=True,
            timeout=1800,
        )

    def sftp(self, workloads: list[str]) -> None:
        e = os.environ
        d = f"/tmp/{self.t.unique}-native"
        env = dict(e, SSHPASS=e["FSFAST_TEST_SFTP_PASSWORD"])
        base = [
            "sshpass",
            "-e",
            "sftp",
            "-q",
            "-P",
            e.get("FSFAST_TEST_SFTP_PORT", "22"),
            "-o",
            "BatchMode=no",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "PubkeyAuthentication=no",
            "-b",
            "-",
            f"{e['FSFAST_TEST_SFTP_USER']}@{e['FSFAST_TEST_SFTP_HOST']}",
        ]

        def sftp(cmds: str) -> float:
            return timed(base, env=env, stdin=cmds + "\n")

        sftp(f"mkdir {d}")
        try:
            connect = statistics.median(sftp("pwd") for _ in range(3))
            note = f"OpenSSH sftp defaults (-R 64 -B 32768); includes connect and auth (~{connect * 1000:.0f} ms alone)"
            p = self.p
            if {"W1", "W2"} & set(workloads):
                self.measure(
                    "W2",
                    "seq-write",
                    "sftp",
                    lambda it: sftp(f"put {self.src} {d}/large.bin"),
                    p.size,
                    1,
                    note=note,
                )
            if "W1" in workloads:
                self.measure(
                    "W1",
                    "seq-read",
                    "sftp",
                    lambda it: sftp(f"get {d}/large.bin /dev/null"),
                    p.size,
                    1,
                    note=note,
                )
            if "W5" in workloads and self.fsf:
                self.upload_tree(d, f"sftp://{e['FSFAST_TEST_SFTP_HOST']}{d}/meta")
                self.measure(
                    "W5",
                    "metadata-ls",
                    "sftp",
                    lambda it: sftp(f"ls -l {d}/meta"),
                    0,
                    1,
                    p.ls_entries,
                    note=note,
                )
        finally:
            if self.fsf:
                subprocess.run(
                    [
                        self.fsf,
                        "--test-services",
                        "rm",
                        "-r",
                        f"sftp://{e['FSFAST_TEST_SFTP_HOST']}{d}",
                    ],
                    capture_output=True,
                    timeout=600,
                    check=False,
                )

    def http(self, workloads: list[str]) -> None:
        assert self.t.nginx is not None
        u = f"{self.t.unique}-native"
        disk = self.t.nginx.docroot / u
        disk.mkdir(parents=True)
        url = f"{self.t.nginx.base}/{u}/large.bin"
        p = self.p
        try:
            if {"W1", "W2"} & set(workloads):
                self.measure(
                    "W2",
                    "seq-write",
                    "curl -T (PUT)",
                    lambda it: timed(["curl", "-sSf", "-T", str(self.src), url]),
                    p.size,
                    1,
                )
            if "W1" in workloads:
                self.measure(
                    "W1",
                    "seq-read",
                    "curl",
                    lambda it: timed(["curl", "-sSf", "-o", "/dev/null", url]),
                    p.size,
                    1,
                )
        finally:
            shutil.rmtree(disk, ignore_errors=True)


# ---------------------------------------------------------------------------
# leftovers


def sweep(fsf: str | None, target: Target, impls: list[str]) -> list[str]:
    """Remove scratch roots a crashed worker left behind (fsf rm -r)."""
    left = []
    if not fsf or target.name in ("memory", "http"):
        return left
    for impl in impls:
        if impl not in ("fsfast", "reference", "sshfs"):
            continue
        root, _ = target.py_root(impl)
        url = {
            "local": root,
            "s3": f"s3://{root}",
            "gcs": f"gs://{root}",
            "azure": f"abfs://{root}",
            "smb": f"smb://{os.environ.get('FSFAST_TEST_SMB_HOST')}{root}",
            "smb-enc": f"smb://{os.environ.get('FSFAST_TEST_SMB_HOST')}{root}",
            "sftp": f"sftp://{os.environ.get('FSFAST_TEST_SFTP_HOST')}{root}",
        }[target.name]
        args = [fsf] + ([] if target.name == "local" else ["--test-services"])
        info = subprocess.run(
            [*args, "info", url], capture_output=True, timeout=120, check=False
        )
        if info.returncode == 0:
            log(f"sweeping leftover {url}")
            subprocess.run(
                [*args, "rm", "-r", url], capture_output=True, timeout=1800, check=False
            )
            left.append(url)
    return left


# ---------------------------------------------------------------------------
# report


def metric(r: dict[str, Any]) -> tuple[str, dict[str, float]] | None:
    """(unit, {best, median}) shown for one result."""
    if r.get("workload") in ("W1", "W2", "W6", "W7") and r.get("mb_per_s"):
        return "MB/s", r["mb_per_s"]
    if r.get("items_per_s"):
        return "entries/s", r["items_per_s"]
    if r.get("ops_per_s"):
        return "ops/s", r["ops_per_s"]
    return None


def fmt_num(v: float) -> str:
    if v >= 100:
        return f"{v:,.0f}"
    if v >= 10:
        return f"{v:.1f}"
    return f"{v:.2f}"


ROWS = [
    ("W1", "seq-read"),
    ("W1", "seq-read-open"),
    ("W2", "seq-write"),
    ("W3", "small-read"),
    ("W4", "small-write"),
    ("W5", "metadata-info"),
    ("W5", "metadata-ls"),
    ("W5", "metadata-find"),
    ("W6", "random-read"),
    ("W7", "copy"),
    ("W8", "delete"),
]


def speedups(doc: dict[str, Any], other: str = "reference") -> str:
    """Markdown table: fsfast's median speedup over ``other`` per workload
    (rows) and target (columns)."""
    med: dict[tuple[str, str], dict[tuple[str, str], Any]] = {}
    targets: list[str] = []
    for run in doc.get("runs", []):
        t = run.get("target", "?")
        if t not in targets and run.get("results"):
            targets.append(t)
        for r in run.get("results", []):
            if r.get("unsupported"):
                v: Any = "n/a"
            elif r.get("error"):
                v = "error"
            else:
                m = metric(r)
                v = m[1]["median"] if m else None
            med.setdefault((t, run.get("impl", "fsf")), {})[
                (r["workload"], r["name"])
            ] = v
    cols = [t for t in targets if (t, "fsfast") in med and (t, other) in med]
    if not cols:
        return ""
    lines = ["| workload | " + " | ".join(cols) + " |", "|---|" + "---|" * len(cols)]
    for key in ROWS:
        cells = []
        for t in cols:
            a, b = med[(t, "fsfast")].get(key), med[(t, other)].get(key)
            if isinstance(a, float) and isinstance(b, float) and b > 0:
                cells.append(f"{a / b:.2f}x")
            elif "n/a" in (a, b):
                cells.append("n/a")
            elif "error" in (a, b):
                cells.append("error")
            else:
                cells.append("")
        if any(cells):
            lines.append(f"| {key[0]} {key[1]} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def report(doc: dict[str, Any]) -> str:
    """Markdown tables: one per target, cells "median (best)", speedups on
    medians."""
    by: dict[str, dict[str, dict[tuple[str, str], dict[str, Any]]]] = {}
    notes: dict[str, list[str]] = {}
    for run in doc.get("runs", []):
        t = by.setdefault(run.get("target", "?"), {})
        res = t.setdefault(run.get("impl", "fsf"), {})
        for r in run.get("results", []):
            res[(r["workload"], r["name"])] = r
        if run.get("params_override"):
            notes.setdefault(run.get("target", "?"), []).append(
                f"{run.get('impl')}: run with {run['params_override']} (too slow for the profile's sizes)"
            )
    lines: list[str] = []
    for target, impls in by.items():
        cols = [i for i in IMPLS if i in impls]
        lines.append(f"### {target}\n")
        head = ["workload", "unit", *cols]
        if "fsfast" in cols and "reference" in cols:
            head.append("fsfast / ref")
        if "fsfast" in cols and "sshfs" in cols:
            head.append("fsfast / sshfs")
        if "fsfast" in cols and "fsf" in cols:
            head.append("fsfast / fsf")
        lines.append("| " + " | ".join(head) + " |")
        lines.append("|" + "---|" * len(head))
        for key in ROWS:
            cells: dict[str, str] = {}
            med: dict[str, float] = {}
            unit = ""
            for c in cols:
                r = impls[c].get(key)
                if r is None:
                    cells[c] = ""
                    continue
                if r.get("unsupported"):
                    cells[c] = "n/a"
                    continue
                if r.get("error"):
                    cells[c] = "error"
                    continue
                m = metric(r)
                if m is None:
                    cells[c] = ""
                    continue
                unit = unit or m[0]
                if m[0] != unit:
                    cells[c] = f"{fmt_num(m[1]['median'])} {m[0]}"
                else:
                    cells[c] = f"{fmt_num(m[1]['median'])} ({fmt_num(m[1]['best'])})"
                med[c] = m[1]["median"]
            if not any(cells.values()):
                continue
            row = [f"{key[0]} {key[1]}", unit, *(cells[c] for c in cols)]
            for other in ("reference", "sshfs", "fsf"):
                if "fsfast" in cols and other in cols:
                    a, b = med.get("fsfast"), med.get(other)
                    row.append(f"{a / b:.2f}x" if a and b else "")
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")
        for n in notes.get(target, []):
            lines.append(f"Note: {n}.\n")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# main


def merge_docs(docs: list[dict[str, Any]]) -> dict[str, Any]:
    """One document from several: runs keyed by (target, impl), later
    documents win; ``meta`` and ``params`` of the first one."""
    runs: dict[tuple[str, str], dict[str, Any]] = {}
    for d in docs:
        for r in d.get("runs", []):
            if r.get("results") or (r.get("target"), r.get("impl")) not in runs:
                runs[(r.get("target", "?"), r.get("impl", "fsf"))] = r
    return {
        "meta": docs[0].get("meta", {}),
        "params": docs[0].get("params", {}),
        "runs": list(runs.values()),
    }


def parse_set(items: list[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for s in items:
        k, _, v = s.partition("=")
        if k not in Params.__dataclass_fields__:
            sys.exit(
                f"--set: unknown parameter {k!r} (known: {', '.join(Params.__dataclass_fields__)})"
            )
        mult = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}.get(v[-1:].upper(), 1)
        out[k] = int(v[:-1] if mult > 1 else v) * mult
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--targets",
        nargs="+",
        default=["memory", "local"],
        help=f"named targets ({' '.join(TARGETS)} | all) or fsf URLs",
    )
    ap.add_argument(
        "--impls",
        default="all",
        help=f"comma-separated subset of {','.join(IMPLS)} (default all)",
    )
    ap.add_argument("--profile", choices=sorted(PROFILES), default="tiny")
    ap.add_argument(
        "-w", "--workloads", default="all", help="comma-separated W1..W8 (default all)"
    )
    ap.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="PARAM=N",
        help="override a profile parameter, e.g. --set size=1G --set repeat=5",
    )
    ap.add_argument("--fsf", help="path to the fsf binary (default target/release/fsf)")
    ap.add_argument(
        "--python",
        default=sys.executable,
        help="interpreter for the Python implementations",
    )
    ap.add_argument("--nginx", help="nginx binary for the http target")
    ap.add_argument(
        "--local-dir",
        default=os.environ.get("FSFAST_BENCH_LOCAL_DIR") or tempfile.gettempdir(),
        help="directory for the local target (default: the temp directory)",
    )
    ap.add_argument(
        "--out",
        default=str(HERE / "results" / "raw"),
        help="directory for the JSON and Markdown output",
    )
    ap.add_argument(
        "--label",
        default="",
        help="free-form label stored in the document and the file name",
    )
    ap.add_argument(
        "--timeout",
        type=float,
        default=3600,
        help="seconds per (target, implementation)",
    )
    ap.add_argument(
        "--full-size",
        action="store_true",
        help="no smaller sizes for slow implementations (paramiko)",
    )
    ap.add_argument(
        "--report",
        type=Path,
        nargs="+",
        help="only print the tables of existing documents (later runs of the same target and "
        "implementation replace earlier ones)",
    )
    ap.add_argument(
        "extra", nargs=argparse.REMAINDER, help="arguments after -- go to fsf bench"
    )
    a = ap.parse_args(argv)

    if a.report:
        merged = merge_docs([json.loads(f.read_text()) for f in a.report])
        table = speedups(merged)
        if table:
            print("### fsfast / reference (medians)\n\n" + table)
        print(report(merged))
        return 0

    extra = a.extra[1:] if a.extra[:1] == ["--"] else a.extra
    impls = (
        IMPLS
        if a.impls == "all"
        else [i.strip() for i in a.impls.split(",") if i.strip()]
    )
    bad = [i for i in impls if i not in IMPLS]
    if bad:
        sys.exit(f"unknown implementation(s) {bad} (known: {IMPLS})")
    workloads = (
        ALL_WORKLOADS
        if a.workloads == "all"
        else [w.strip().upper() for w in a.workloads.split(",")]
    )
    p = profile(a.profile, parse_set(a.set))
    fsf = find_fsf(a.fsf)
    if "fsf" in impls and not fsf:
        log("fsf not found (cargo build --release -p fsfast-cli): skipping fsf runs")
    targets = TARGETS if a.targets == ["all"] else a.targets
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    unique = f"fsbench-{stamp.lower()}-{os.getpid()}"
    local_dir = Path(a.local_dir)
    scratch = Path(
        tempfile.mkdtemp(
            prefix="fsbench-", dir="/dev/shm" if os.path.isdir("/dev/shm") else None
        )
    )

    nginx_bin = find_nginx(a.nginx)
    pkgs = py_versions(a.python)
    nginx: Nginx | None = None
    doc: dict[str, Any] = {
        "meta": {
            "created_at": stamp,
            "label": a.label,
            "profile": a.profile,
            "impls": impls,
            "workloads": workloads,
            "fsf": out_of([fsf, "--version"]) if fsf else None,
            "fsf_path": fsf,
            "git": git_info(),
            "machine": machine(),
            "python_packages": pkgs,
            "services": service_versions(nginx_bin),
            "fsf_extra_args": extra,
            "local_dir": str(local_dir),
        },
        "params": p.to_json(),
        "runs": [],
    }
    failed = False
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"bench-{stamp}{'-' + a.label if a.label else ''}.json"
    partial = path.with_suffix(".partial.json")
    try:
        for name in targets:
            if "://" in name or "/" in name:
                if not fsf:
                    continue
                rep, _ = run_json(
                    [
                        fsf,
                        "bench",
                        name,
                        "--json",
                        "-q",
                        "-w",
                        ",".join(workloads),
                        *extra,
                    ],
                    a.timeout,
                )
                rep.update(target=name, impl="fsf")
                doc["runs"].append(rep)
                failed |= bool(rep.get("error"))
                continue
            if name not in TARGETS:
                sys.exit(
                    f"unknown target {name!r} (known: {', '.join(TARGETS)}, or a URL)"
                )
            why = available(name)
            if name == "http" and why is None:
                if not nginx_bin:
                    why = "nginx not found (apt-get download nginx && dpkg -x nginx_*.deb DIR; --nginx DIR/usr/sbin/nginx)"
                elif nginx is None:
                    docroot = Path(
                        tempfile.mkdtemp(prefix="fsbench-www-", dir=local_dir)
                    )
                    nginx = Nginx(nginx_bin, docroot)
            if why:
                log(f"skipping {name}: {why}")
                doc["runs"].append({"target": name, "skipped": why})
                continue
            target = Target(name, unique, local_dir, nginx)
            for impl in impls:
                if impl in ("fsfast", "reference", "sshfs"):
                    if impl not in PY_IMPLS[name]:
                        continue
                    pkg = "fsfast" if impl == "fsfast" else NEEDS[name][impl]
                    if not pkgs.get(pkg):
                        log(
                            f"skipping {name}/{impl}: {pkg} is not installed in {a.python}"
                        )
                        continue
                log(f"== {name} / {impl}")
                load0 = list(os.getloadavg())
                if impl in ("fsfast", "reference", "sshfs"):
                    run = run_python(
                        a.python, target, impl, p, workloads, a.timeout, a.full_size
                    )
                    failed |= impl == "fsfast" and bool(
                        run.get("error")
                        or any(r.get("error") for r in run.get("results", []))
                    )
                elif impl == "fsf":
                    if not fsf:
                        continue
                    if name == "http":
                        # fsf bench needs a directory it can write to and
                        # remove; fsspec's http has neither (info() of a
                        # URL is always a file, no rm).
                        doc["runs"].append(
                            {
                                "target": name,
                                "impl": impl,
                                "results": [],
                                "unsupported": "fsf bench needs a writable directory target (http has no directories or rm)",
                            }
                        )
                        continue
                    run = run_fsf(fsf, target, p, workloads, extra, a.timeout)
                    failed |= bool(run.get("errors"))
                else:
                    run = Native(target, p, scratch, fsf).run(workloads)
                run.update(
                    target=name,
                    impl=impl,
                    loadavg_before=load0,
                    loadavg_after=list(os.getloadavg()),
                )
                if impl in PY_IMPLS[name]:
                    run.setdefault("description", PY_IMPLS[name][impl])
                doc["runs"].append(run)
                # Long runs: keep what is done so far on disk.
                partial.write_text(json.dumps(doc, indent=1) + "\n")
            left = sweep(fsf, target, impls)
            if left:
                doc["runs"][-1].setdefault("swept", left)
    finally:
        if nginx is not None:
            nginx.stop()
            shutil.rmtree(nginx.docroot, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)
        doc["meta"]["loadavg_end"] = list(os.getloadavg())
        path.write_text(json.dumps(doc, indent=1) + "\n")
        table = report(doc)
        path.with_suffix(".md").write_text(table + "\n")
        partial.unlink(missing_ok=True)
        print(table)
        log(f"wrote {path} and {path.with_suffix('.md')}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
