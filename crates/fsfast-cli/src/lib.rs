//! `fsf`, the fsfast command line.
//!
//! * Manual use: `ls`, `info`, `find`, `cat`, `cp` (local↔remote,
//!   remote↔remote, recursive, parallel), `rm`, `mkdir` on any compiled-in
//!   backend ([`backends::BACKENDS`]).
//! * `bench`: the W1–W8 workloads ([`bench::Workload`]) with warm-up,
//!   best/median times, p50/p90/p99 latencies, MB/s, ops/s, engine counters
//!   and JSON output for the benchmark harness (`bench/` in the repository).
//!
//! Locations and options are parsed in [`target`] and [`options`]; see
//! `fsf --help` and docs/dev/ci.md.

pub mod backends;
pub mod bench;
pub mod cli;
pub mod commands;
pub mod ops;
pub mod options;
pub mod target;
pub mod units;

pub use cli::main_with_args;
