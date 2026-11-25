#!/usr/bin/env python3
"""The workloads of examples/s3_bench.rs, run through s3fs (default
options) on the same endpoint.

    eval "$(scripts/test-services.sh env)"
    .venv/bin/python crates/fsfast-s3/tools/bench_s3fs.py [size_mib] [repeats]
"""
import asyncio
import os
import sys
import tempfile
import time

import s3fs

size_mib = int(sys.argv[1]) if len(sys.argv) > 1 else 256
repeats = int(sys.argv[2]) if len(sys.argv) > 2 else 3
fs = s3fs.S3FileSystem(
    key=os.environ["FSFAST_TEST_S3_KEY"],
    secret=os.environ["FSFAST_TEST_S3_SECRET"],
    endpoint_url=os.environ["FSFAST_TEST_S3_ENDPOINT"],
    use_listings_cache=False,
    skip_instance_cache=True,
)
bucket = f"s3fs-bench-{os.getpid()}"
fs.mkdir(bucket)


def best(f):
    times = []
    for _ in range(repeats):
        t = time.perf_counter()
        f()
        times.append(time.perf_counter() - t)
    return min(times)


size = size_mib << 20
data = bytes((i * 7 % 251) for i in range(256)) * (size // 256)
big = f"{bucket}/big.bin"
put = best(lambda: fs.pipe_file(big, data))
def get():
    assert len(fs.cat_file(big)) == size
g = best(get)
print(f"put {size_mib} MiB (pipe_file): {size / put / 1e6:.0f} MB/s ({put:.2f} s)")
print(f"get {size_mib} MiB (cat_file):  {size / g / 1e6:.0f} MB/s ({g:.2f} s)")

with tempfile.TemporaryDirectory() as d:
    local = os.path.join(d, "big.bin")
    with open(local, "wb") as f:
        f.write(data)
    out = os.path.join(d, "out.bin")
    pf = best(lambda: fs.put_file(local, big))
    gf = best(lambda: fs.get_file(big, out))
    print(f"put_file {size_mib} MiB:        {size / pf / 1e6:.0f} MB/s")
    print(f"get_file {size_mib} MiB:        {size / gf / 1e6:.0f} MB/s")

if os.environ.get("FSFAST_BENCH_ONLY") == "large":
    fs.rm(bucket, recursive=True)
    sys.exit(0)

n = 1000
small = [f"{bucket}/small/{i:05}" for i in range(n)]
fs.pipe({p: b"*" * 4096 for p in small})


def cat_seq():
    for p in small:
        assert len(fs.cat_file(p)) == 4096


def cat_batch():
    out = fs.cat(small)
    assert len(out) == n


def info_seq():
    for p in small:
        fs.info(p)


async def _info_gather():
    sem = asyncio.Semaphore(64)

    async def one(p):
        async with sem:
            return await fs._info(p)

    await asyncio.gather(*[one(p) for p in small])


def info_conc():
    from fsspec.asyn import sync
    sync(fs.loop, _info_gather)


c1, i1 = best(cat_seq), best(info_seq)
cb, ic = best(cat_batch), best(info_conc)
print(f"cat 1000 x 4 KiB (sequential cat_file): {n / c1:.0f} files/s; info 1000 sequential: {n / i1:.0f} ops/s")
print(f"cat 1000 x 4 KiB (fs.cat batch):        {n / cb:.0f} files/s; info 1000 (gather, 64): {n / ic:.0f} ops/s")

m = 5000
doomed = [f"{bucket}/rm/{i:05}" for i in range(m)]
times = []
for _ in range(repeats):
    fs.pipe({p: b"x" for p in doomed})
    t = time.perf_counter()
    fs.rm(doomed)
    times.append(time.perf_counter() - t)
rm = min(times)
print(f"rm 5000 keys: {rm:.2f} s ({m / rm:.0f} keys/s)")
fs.rm(bucket, recursive=True)
