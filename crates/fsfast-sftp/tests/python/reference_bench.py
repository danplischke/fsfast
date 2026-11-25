"""Reference benchmark: fsspec sftp (paramiko) and sshfs (asyncssh).

Mirrors tests/bench.rs on the same server so the numbers are comparable:
a large file written in 1 MiB chunks, read with cat_file, get_file and
put_file, then 1000 x 16 KiB files piped / read / info'd sequentially
(and, for sshfs, 32 at a time through its async API).

Usage (from the repository root):

    eval "$(scripts/test-services.sh env)"
    .venv/bin/python crates/fsfast-sftp/tests/python/reference_bench.py [paramiko|sshfs] [MiB] [files]
"""

import asyncio
import os
import sys
import tempfile
import time
import uuid

HOST = os.environ["FSFAST_TEST_SFTP_HOST"]
PORT = int(os.environ.get("FSFAST_TEST_SFTP_PORT", "22"))
USER = os.environ.get("FSFAST_TEST_SFTP_USER", "fsfast")
PASSWORD = os.environ.get("FSFAST_TEST_SFTP_PASSWORD", "fsfastpw")
STATE = os.environ.get("FSFAST_TEST_STATE", "/tmp/fsfast-test")
HOME = f"{STATE}/sftp/home"

which = sys.argv[1] if len(sys.argv) > 1 else "paramiko"
MIB = int(sys.argv[2]) if len(sys.argv) > 2 else 256
NFILES = int(sys.argv[3]) if len(sys.argv) > 3 else 1000


def connect():
    if which == "paramiko":
        from fsspec.implementations.sftp import SFTPFileSystem

        return SFTPFileSystem(HOST, port=PORT, username=USER, password=PASSWORD,
                              look_for_keys=False, allow_agent=False)
    from sshfs import SSHFileSystem

    return SSHFileSystem(HOST, port=PORT, username=USER, password=PASSWORD,
                         known_hosts=None, client_keys=[])


def rate(n, dt):
    return f"{n / dt / 1e6:8.1f} MB/s"


def main():
    fs = connect()
    d = f"{HOME}/fsfast-sftp-refbench-{which}-{uuid.uuid4().hex[:8]}"
    fs.mkdir(d)
    try:
        size = MIB << 20
        data = bytes((i * 31 % 251) for i in range(251)) * (size // 251 + 1)
        data = data[:size]
        p = f"{d}/big.bin"
        for rnd in range(2):
            t = time.perf_counter()
            with fs.open(p, "wb") as f:
                for off in range(0, size, 1 << 20):
                    f.write(data[off:off + (1 << 20)])
            dt = time.perf_counter() - t
            print(f"[{which}] round {rnd}: write {MIB} MiB: {rate(size, dt)} ({dt:.2f}s)", flush=True)

            t = time.perf_counter()
            got = fs.cat_file(p)
            dt = time.perf_counter() - t
            assert got == data
            del got
            print(f"[{which}] round {rnd}: cat   {MIB} MiB: {rate(size, dt)} ({dt:.2f}s)", flush=True)

            local = os.path.join(tempfile.gettempdir(), f"refbench-{uuid.uuid4().hex}.bin")
            t = time.perf_counter()
            fs.get_file(p, local)
            dt = time.perf_counter() - t
            print(f"[{which}] round {rnd}: get   {MIB} MiB: {rate(size, dt)} ({dt:.2f}s)", flush=True)
            t = time.perf_counter()
            fs.put_file(local, f"{d}/put.bin")
            dt = time.perf_counter() - t
            print(f"[{which}] round {rnd}: put   {MIB} MiB: {rate(size, dt)} ({dt:.2f}s)", flush=True)
            os.remove(local)

        payload = b"\x07" * (16 << 10)
        paths = [f"{d}/f{i:05}" for i in range(NFILES)]
        t = time.perf_counter()
        for q in paths:
            fs.pipe_file(q, payload)
        dt = time.perf_counter() - t
        print(f"[{which}] conc  1: pipe {NFILES} x 16 KiB: {NFILES / dt:8.0f} files/s", flush=True)
        t = time.perf_counter()
        for q in paths:
            assert len(fs.cat_file(q)) == len(payload)
        dt = time.perf_counter() - t
        print(f"[{which}] conc  1: cat  {NFILES} x 16 KiB: {NFILES / dt:8.0f} files/s", flush=True)
        t = time.perf_counter()
        for q in paths:
            fs.info(q)
        dt = time.perf_counter() - t
        print(f"[{which}] conc  1: info {NFILES}: {NFILES / dt:8.0f} ops/s", flush=True)

        if which == "sshfs":
            # sshfs is asyncio-native: measure its best case, 32 concurrent.
            async def conc(fn):
                sem = asyncio.Semaphore(32)

                async def one(q):
                    async with sem:
                        return await fn(q)

                t = time.perf_counter()
                await asyncio.gather(*(one(q) for q in paths))
                return time.perf_counter() - t

            from fsspec.asyn import sync

            dt = sync(fs.loop, conc, lambda q: fs._pipe_file(q, payload))
            print(f"[{which}] conc 32: pipe {NFILES} x 16 KiB: {NFILES / dt:8.0f} files/s", flush=True)
            dt = sync(fs.loop, conc, fs._cat_file)
            print(f"[{which}] conc 32: cat  {NFILES} x 16 KiB: {NFILES / dt:8.0f} files/s", flush=True)
            dt = sync(fs.loop, conc, fs._info)
            print(f"[{which}] conc 32: info {NFILES}: {NFILES / dt:8.0f} ops/s", flush=True)

        t = time.perf_counter()
        assert len(fs.ls(d)) >= NFILES
        print(f"[{which}] ls of {NFILES} entries: {(time.perf_counter() - t) * 1e3:.1f} ms", flush=True)
        t = time.perf_counter()
        for q in paths:
            fs.rm_file(q)
        dt = time.perf_counter() - t
        print(f"[{which}] rm {NFILES}: {NFILES / dt:8.0f} files/s", flush=True)
    finally:
        fs.rm(d, recursive=True)


main()
