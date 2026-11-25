# bench/: fsfast against the reference implementations

`run.py` runs the same workloads against every local test service through
fsfast's Python classes, the reference fsspec implementations, the `fsf`
CLI (Rust only) and native tools, and writes one JSON document plus a
Markdown summary. Method, environment, results and caveats are in
[docs/BENCHMARKS.md](../docs/BENCHMARKS.md).

| file | purpose |
|---|---|
| `run.py` | the harness: targets × implementations × workloads, JSON + Markdown output, `--report` re-renders the tables of a document |
| `pyworker.py` | one Python implementation against one target, in a fresh interpreter (started by `run.py`) |
| `benchcfg.py` | profiles (workload parameters shared by every implementation), targets, storage options |
| `test_bench.py` | harness tests without services (`.venv/bin/python -m pytest bench/test_bench.py`) |
| `compare.py` | compare a document with a baseline document or with the trailing median of a history directory; exit 1 on a regression beyond the threshold (default 5%) |
| `results/` | documents kept with the repository (the ones docs/BENCHMARKS.md quotes); `results/raw/` (git-ignored) is the default output |

## Implementations (`--impls`)

| impl | what runs |
|---|---|
| `fsfast` | `fsfast.<Name>FileSystem` from Python |
| `reference` | the implementation fsfast replaces: fsspec's local/memory/http/smb/sftp, s3fs, gcsfs, adlfs |
| `sshfs` | sshfs (asyncssh), a second SFTP reference |
| `fsf` | `fsf bench --json` (crates/fsfast-cli), the Rust engine without Python |
| `native` | coreutils (local), `smbclient`, OpenSSH `sftp`, `curl` (http) |

## Workloads (`-w`)

| id | name | Python call that is timed | fsf |
|---|---|---|---|
| W1 | `seq-read` | `cat_file(path)` of a `size` object | parallel ranged reads |
| W1 | `seq-read-open` | `open(path, "rb")` + `read(chunk)` until EOF | (none) |
| W2 | `seq-write` | `open(path, "wb")` + `write(chunk)` (http: `put_file`) | write handle, chunked |
| W3 | `small-read` | `cat([small_count paths])` | `cat_file`, `-c` in flight |
| W4 | `small-write` | `pipe({path: data})` | `pipe_file`, `-c` in flight |
| W5 | `metadata-info` | `info()` on `info_count` files, one after another | `-c 1` |
| W5 | `metadata-ls` | `ls(dir, detail=True)` of an `ls_entries` directory | same |
| W5 | `metadata-find` | `find(dir)` of that directory | same |
| W6 | `random-read` | `cat_ranges([path]*ranges, starts, ends)`, `range_size` each | `read_at` on one handle |
| W7 | `copy` | `copy(srcs, dsts)` of `copy_count` × `copy_size` | server-side `cp_file` |
| W8 | `delete` | `rm([delete_count paths])` | `rm_files` |

Every workload runs `warmup` untimed and `repeat` timed iterations;
setup, verification and cleanup are untimed. Caches (`invalidate_cache`)
are cleared and the garbage collector runs before each iteration. Results
are verified (byte and entry counts). Profiles: `tiny` (smoke test, CI),
`default` (the documented numbers), `large` (1 GiB objects, 5 repeats);
`--set name=value` overrides any parameter (`--set size=1G`).

## Examples

```sh
eval "$(scripts/test-services.sh env)"
cargo build --release -p fsfast-cli
. .venv/bin/activate && maturin develop --release -m crates/fsfast-py/Cargo.toml

python bench/run.py --targets all --profile default --out bench/results --label baseline
python bench/run.py --targets s3 smb --impls fsfast,reference -w W1,W3 --profile default
python bench/run.py --report bench/results/bench-<stamp>-baseline.json
python bench/compare.py NEW.json --baseline OLD.json
```

The `http` target needs an `nginx` binary (WebDAV PUT, autoindex
listings); without root it can come from the distribution package:
`apt-get download nginx && dpkg -x nginx_*.deb DIR`, then
`--nginx DIR/usr/sbin/nginx`. `run.py` starts its own nginx on a free
loopback port and stops it afterwards.

Each run works under unique names (`fsbench-<stamp>-<pid>-<impl>`) and
removes them; a sweep with `fsf rm -r` removes what a crashed worker left.
`fsf bench` can also be run by hand (`fsf --test-services bench s3://bucket
--create -w W1,W6 --size 1GiB`); arguments after `--` on the `run.py`
command line are passed to it.
