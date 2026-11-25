# bench/: macro benchmarks with `fsf bench`

`fsf` (crate `crates/fsfast-cli`) runs the benchmark workloads against any
URL it can open; the scripts here run it over several targets, keep the JSON
reports and compare runs.

| file | purpose |
|---|---|
| `run.py` | run `fsf bench --json` against named services or URLs, write one combined document to `bench/results/raw/` (git-ignored) |
| `compare.py` | compare a document with a baseline document or with the trailing median of a history directory; exit 1 on a regression beyond the threshold (default 5%) |

## Workloads

| id | name | what is timed | latency samples |
|---|---|---|---|
| W1 | `seq-read` | read one `--size` file with parallel ranged reads (`--block-size`, `--io-concurrency`, default: backend I/O hints) | one per iteration |
| W2 | `seq-write` | write one `--size` file in `--block-size` chunks through a write handle | one per iteration |
| W3 | `small-read` | `cat_file` of `--count` files of `--file-size`, `--concurrency` in flight | one per file |
| W4 | `small-write` | `pipe_file` of `--count` files | one per file |
| W5 | `metadata-info`, `metadata-ls`, `metadata-find` | `info` on every file of a tree of `--dirs` directories, `ls` of every directory, one recursive `find` | one per call |
| W6 | `random-read` | `--ranges` reads of `--range-size` at random (seeded) offsets of one `--size` file over one handle | one per read |
| W7 | `copy` | copy `--count` files: server-side within the target, or to `--dest` on another filesystem (upload / download / streamed) | one per file |
| W8 | `delete` | one `rm_files` batch of `--count` files | one per batch |

Every workload runs `--warmup` untimed iterations and `--iterations`
measured ones. Reported per workload: best and median iteration time, MB/s
(decimal, 10^6 B/s) and ops/s (and entries/s for listings) for the best and
median iteration, p50/p90/p99/max/mean latency, and the engine counters
(requests, errors, retries, throttles, bytes on the wire, requests per
operation kind) summed over the timed sections of the measured iterations
only. Setup, warm-up and per-iteration preparation/cleanup are not counted.
In-process backends (`file`, `memory`) have no counters (`"stats": null`).

The W-numbering follows the task that introduced `fsf`; docs/PLAN.md §8.1
groups the same operations differently (PLAN's W2/W3 are W6 here with
`--range-size 4MiB` / `64KiB`, PLAN's W4 is W3/W4, W5/W6 are W5, W7 is W7).
PLAN's W8 (pandas/xarray/duckdb stacks) is not an `fsf` workload.

Each run works under a unique prefix `<URL>/fsf-bench-<ms>-<pid>-<rand>`
and deletes it at the end, also after an error or Ctrl-C (`--keep` keeps
it). `--create` creates a missing target directory/bucket first and removes
it again afterwards.

## Examples

```sh
cargo build --release -p fsfast-cli
eval "$(scripts/test-services.sh env)"

# one target by hand
target/release/fsf --test-services bench s3://my-bench --create -w W1,W6 --size 1GiB -c 64

# every local service, nightly profile, then compare with the last run
python bench/run.py --targets all --profile default
python bench/compare.py bench/results/raw/bench-NEW.json --baseline bench/results/raw/bench-OLD.json

# cross-backend copy: memory -> S3 (streamed)
target/release/fsf --test-services bench memory://src --create -w W7 --dest s3://my-bench
```

Profiles in `run.py`: `tiny` (CI smoke test, numbers meaningless),
`default` (nightly on a shared runner), `large` (dedicated hardware, GiB
objects, 10k files). Arguments after `--` are passed to `fsf bench`.

Loopback services hide network latency (docs/PLAN.md §8.2): for numbers
that mean something, shape the link with `tc netem` or run against real
endpoints, and build `fsf` in release mode.
