"""The workload of `examples/bench.rs` through adlfs, on the same Azurite.

    eval "$(scripts/test-services.sh env)"
    .venv/bin/python crates/fsfast-azure/tools/bench_adlfs.py [large_mib] [small_count] [list_count]

Uses adlfs's batch APIs where it has them (pipe/cat/rm of many paths fan out
through fsspec's async gather), so the comparison is with adlfs at its best.
"""
import os
import sys
import time
import warnings

warnings.simplefilter("ignore")
from adlfs import AzureBlobFileSystem  # noqa: E402

large_mib = int(sys.argv[1]) if len(sys.argv) > 1 else 256
small_count = int(sys.argv[2]) if len(sys.argv) > 2 else 500
list_count = int(sys.argv[3]) if len(sys.argv) > 3 else 2000

fs = AzureBlobFileSystem(connection_string=os.environ["FSFAST_TEST_AZURE_CONNECTION_STRING"])
c = f"bench-py-{os.getpid()}"
fs.mkdir(c)

data = bytes(i % 251 for i in range(256)) * (large_mib << 12)
p = f"{c}/large.bin"
t = time.perf_counter()
fs.pipe_file(p, data)
put = time.perf_counter() - t
t = time.perf_counter()
got = fs.cat_file(p)
get = time.perf_counter() - t
assert len(got) == len(data)
print(f"large put  {large_mib} MiB: {put:.2f} s, {len(data) / put / 1e6:.1f} MB/s")
print(f"large get  {large_mib} MiB: {get:.2f} s, {len(data) / get / 1e6:.1f} MB/s")

small = b"\x07" * 4096
paths = [f"{c}/small/{i:05}" for i in range(small_count)]
t = time.perf_counter()
fs.pipe({q: small for q in paths})
el = time.perf_counter() - t
print(f"small put  {small_count} x 4 KiB: {el:.2f} s, {small_count / el:.0f} ops/s")
t = time.perf_counter()
out = fs.cat(paths)
el = time.perf_counter() - t
assert all(len(v) == 4096 for v in out.values())
print(f"small get  {small_count} x 4 KiB: {el:.2f} s, {small_count / el:.0f} ops/s")
fs.invalidate_cache()
t = time.perf_counter()
for q in paths:
    fs.info(q)
el = time.perf_counter() - t
print(f"small info {small_count} (sequential; adlfs has no batch info): {el:.2f} s, {small_count / el:.0f} ops/s")

lpaths = [f"{c}/list/d{i % 20:02}/{i:05}" for i in range(list_count)]
fs.pipe({q: b"" for q in lpaths})
fs.invalidate_cache()
t = time.perf_counter()
found = fs.find(f"{c}/list")
el = time.perf_counter() - t
assert len(found) == list_count, len(found)
print(f"find       {list_count} blobs: {el:.3f} s, {list_count / el:.0f} entries/s")
fs.invalidate_cache()
t = time.perf_counter()
n = sum(len(fs.ls(f"{c}/list/d{d:02}")) for d in range(20))
el = time.perf_counter() - t
assert n == list_count
print(f"ls x20     {list_count} blobs: {el:.3f} s, {list_count / el:.0f} entries/s")

allp = paths + lpaths + [p]
t = time.perf_counter()
fs.rm(allp)
el = time.perf_counter() - t
print(f"rm         {len(allp)} blobs: {el:.2f} s, {len(allp) / el:.0f} ops/s")
fs.rmdir(c)
