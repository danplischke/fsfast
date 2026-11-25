"""The workloads of `examples/gcs_bench.rs`, through gcsfs on the same endpoint.

    eval "$(scripts/test-services.sh env)"
    GCSFS_EXPERIMENTAL_ZB_HNS_SUPPORT=false .venv/bin/python \
        crates/fsfast-gcs/tools/bench_gcsfs.py [size_mib] [repeats]

`GCSFS_EXPERIMENTAL_ZB_HNS_SUPPORT=false` selects gcsfs's core
`GCSFileSystem` (the default extended class probes bucket types over gRPC,
which the emulator does not serve). Each workload runs `repeats` times; the
best run is reported. Concurrency 64 uses gcsfs's own batching
(`cat`/`pipe` with lists, `asyncio.gather` for info).
"""

import asyncio
import os
import sys
import tempfile
import time

import gcsfs

size_mib = int(sys.argv[1]) if len(sys.argv) > 1 else 128
repeats = int(sys.argv[2]) if len(sys.argv) > 2 else 3
fs = gcsfs.GCSFileSystem(
    endpoint_url=os.environ["FSFAST_TEST_GCS_ENDPOINT"],
    token="anon",
    project="test-project",
    skip_instance_cache=True,
)
bucket = f"fsfast-bench-py-{os.getpid()}"
fs.mkdir(bucket)


def best(f):
    out = []
    for _ in range(repeats):
        t = time.perf_counter()
        f()
        out.append(time.perf_counter() - t)
    return min(out)


def mbps(n, s):
    return n / 1e6 / s


size = size_mib << 20
data = bytes((i * 7 % 251) for i in range(256)) * (size // 256)
big = f"{bucket}/big.bin"
put = best(lambda: fs.pipe_file(big, data))


def get():
    fs.invalidate_cache()
    assert len(fs.cat_file(big)) == size


g = best(get)
print(f"put {size_mib} MiB (pipe_file): {mbps(size, put):.0f} MB/s")
print(f"get {size_mib} MiB (cat_file):  {mbps(size, g):.0f} MB/s")
with tempfile.TemporaryDirectory() as d:
    local = os.path.join(d, "big.bin")
    out = os.path.join(d, "out.bin")
    with open(local, "wb") as f:
        f.write(data)
    pf = best(lambda: fs.put_file(local, big))

    def getf():
        fs.invalidate_cache()
        fs.get_file(big, out)

    gf = best(getf)
print(f"put_file {size_mib} MiB:        {mbps(size, pf):.0f} MB/s")
print(f"get_file {size_mib} MiB:        {mbps(size, gf):.0f} MB/s")


def stream_put():
    with fs.open(big, "wb") as f:
        for i in range(0, size, 1 << 20):
            f.write(data[i : i + (1 << 20)])


sp = best(stream_put)
print(f"open_write {size_mib} MiB:      {mbps(size, sp):.0f} MB/s")

n = 1000
small = [f"{bucket}/small/{i:05}" for i in range(n)]
payload = b"*" * 4096
for conc in (1, 64):
    if conc == 1:
        def pipe():
            for p in small:
                fs.pipe_file(p, payload)

        def cat():
            fs.invalidate_cache()
            for p in small:
                assert len(fs.cat_file(p)) == 4096

        def info():
            fs.invalidate_cache()
            for p in small:
                fs.info(p)
    else:
        def pipe():
            fs.pipe({p: payload for p in small}, batch_size=conc)

        def cat():
            fs.invalidate_cache()
            got = fs.cat(small, batch_size=conc)
            assert all(len(v) == 4096 for v in got.values())

        def info():
            fs.invalidate_cache()

            async def go():
                sem = asyncio.Semaphore(conc)

                async def one(p):
                    async with sem:
                        return await fs._info(p)

                return await asyncio.gather(*(one(p) for p in small))

            from fsspec.asyn import sync

            sync(fs.loop, go)

    tp, tc, ti = best(pipe), best(cat), best(info)
    print(
        f"1000 x 4 KiB (concurrency {conc:>2}): pipe {n / tp:.0f} files/s; "
        f"cat {n / tc:.0f} files/s; info {n / ti:.0f} ops/s"
    )


def ls():
    fs.invalidate_cache()
    assert len(fs.ls(f"{bucket}/small")) == n


def find():
    fs.invalidate_cache()
    assert len(fs.find(bucket)) == n + 1


tl, tf = best(ls), best(find)
print(f"ls 1000 entries: {tl * 1e3:.1f} ms; find 1001 entries: {tf * 1e3:.1f} ms")
t = time.perf_counter()
fs.rm(small)
print(f"rm 1000 objects: {n / (time.perf_counter() - t):.0f} objects/s")
fs.rm(bucket, recursive=True)
