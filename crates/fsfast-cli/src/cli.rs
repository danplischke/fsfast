//! Command-line definition and dispatch.

use std::ffi::OsString;
use std::io::Write;

use clap::{Arg, ArgAction, ArgMatches, Command};
use fsfast_core::{Error, ErrorKind, Result};

use crate::bench::{BenchConfig, Workload};
use crate::options::{OptSpec, OptionSet, parse_opt};
use crate::target::Session;
use crate::units::parse_size;
use crate::{backends, bench, commands, ops};

/// Parsed command line.
#[derive(Debug, Clone)]
pub struct Cli {
    /// `--opt` values.
    pub opts: Vec<OptSpec>,
    /// `--test-services`.
    pub test_services: bool,
    /// `--json`.
    pub json: bool,
    /// `--stats`.
    pub stats: bool,
    /// `-q`.
    pub quiet: bool,
    /// `-v` count.
    pub verbose: u8,
    /// The command.
    pub command: Cmd,
}

/// A subcommand.
#[derive(Debug, Clone)]
pub enum Cmd {
    /// List a directory.
    Ls { url: String, long: bool },
    /// Metadata of one path.
    Info { url: String },
    /// Recursive listing.
    Find {
        url: String,
        maxdepth: Option<usize>,
        withdirs: bool,
        long: bool,
    },
    /// Print a file (or a byte range).
    Cat {
        url: String,
        start: Option<u64>,
        end: Option<u64>,
    },
    /// Copy files.
    Cp {
        src: String,
        dst: String,
        recursive: bool,
        jobs: usize,
    },
    /// Delete files or trees.
    Rm { urls: Vec<String>, recursive: bool },
    /// Create directories.
    Mkdir { urls: Vec<String>, parents: bool },
    /// Run benchmark workloads.
    Bench { url: String, config: BenchConfig },
    /// List compiled-in protocols.
    Protocols,
}

const ABOUT: &str = "fsf: fsfast's command line (manual file operations and benchmarks)";

const AFTER_HELP: &str = "\
LOCATIONS are URLs such as s3://bucket/key, gs://bucket/key, abfs://container/blob,
smb://user:pw@host/share/path, sftp://user@host/path, https://host/file, memory://path,
or local paths. Paths follow each backend's fsspec rules.

OPTIONS for backends (fsspec storage_options names) come from, lowest precedence first:
  --test-services          the scripts/test-services.sh env settings (FSFAST_TEST_*)
  FSF_OPTS='{...}'         JSON object applied like unscoped --opt values
  FSF_OPTS_<PROTO>='{...}' JSON object for one protocol (FSF_OPTS_S3, FSF_OPTS_GS, ...)
  the URL itself           e.g. host/username/password of smb:// and sftp:// URLs
  --opt [PROTO:]KEY=VALUE  VALUE is JSON when it is a number, bool, null, object or array
  --opt [PROTO:]KEY:=JSON  VALUE must be JSON (use :='\"123\"' for numeric-looking strings)
Unscoped options apply to the network backends of the command (not file/memory).

EXAMPLES:
  fsf --test-services ls -l s3://bucket/dir
  fsf --opt endpoint_url=http://127.0.0.1:9000 --opt key=K --opt secret=S cat s3://b/k
  fsf cp -r -j 32 ./data s3://bucket/data/
  fsf --test-services bench s3://bucket --workloads W1,W3,W6 --size 256MiB --json";

fn url_arg(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name).required(true).help(help)
}

fn flag(name: &'static str, short: Option<char>, help: &'static str) -> Arg {
    let a = Arg::new(name)
        .long(name)
        .action(ArgAction::SetTrue)
        .overrides_with(name)
        .help(help);
    match short {
        Some(c) => a.short(c),
        None => a,
    }
}

/// `--opt`: accepted before and after the subcommand. It is defined on
/// every command instead of being a clap `global` argument, because clap
/// replaces (rather than merges) global values given at both levels.
fn opt_arg() -> Arg {
    Arg::new("opt")
        .short('o')
        .long("opt")
        .value_name("[PROTO:]KEY=VALUE")
        .action(ArgAction::Append)
        .help("Backend option (repeatable); see `fsf --help`")
}

fn value(name: &'static str, help: &'static str) -> Arg {
    // Later occurrences override earlier ones, so wrappers such as
    // bench/run.py can append overrides to a preset argument list.
    Arg::new(name)
        .long(name)
        .value_name("N")
        .overrides_with(name)
        .help(help)
}

/// The clap command tree.
pub fn command() -> Command {
    let bench = Command::new("bench")
        .about("Run benchmark workloads against a location (everything is created under a unique prefix and removed afterwards)")
        .arg(opt_arg())
        .arg(url_arg("url", "Directory, bucket or container to benchmark in"))
        .arg(
            Arg::new("workloads")
                .short('w')
                .long("workloads")
                .value_name("LIST")
                .default_value("all")
                .overrides_with("workloads")
                .help("Comma-separated workloads: W1 seq-read, W2 seq-write, W3 small-read, W4 small-write, W5 metadata, W6 random-read, W7 copy, W8 delete, or all"),
        )
        .arg(value("size", "Large file size for W1/W2/W6 [default: 64MiB]").value_name("SIZE"))
        .arg(value("file-size", "Small file size for W3/W4/W5/W7/W8 [default: 16KiB]").value_name("SIZE"))
        .arg(value("count", "Number of small files [default: 256]"))
        .arg(value("concurrency", "Operations in flight [default: 16]").short('c'))
        .arg(value("io-concurrency", "Requests in flight within one large read (W1) [default: backend hint]"))
        .arg(value("block-size", "W1 read request size and W2 write chunk size [default: backend hint]").value_name("SIZE"))
        .arg(value("range-size", "Length of each W6 random read [default: 256KiB]").value_name("SIZE"))
        .arg(value("ranges", "Random reads per W6 iteration [default: 256]"))
        .arg(value("dirs", "Directories of the W5 tree [default: count/64]"))
        .arg(value("iterations", "Measured iterations per workload [default: 3]").short('n'))
        .arg(value("warmup", "Untimed warm-up iterations [default: 1]"))
        .arg(value("seed", "Seed for random offsets and payload"))
        .arg(Arg::new("dest").long("dest").value_name("URL").overrides_with("dest").help("W7: copy to this location (another filesystem) instead of within the target"))
        .arg(flag("keep", None, "Do not delete the benchmark prefix"))
        .arg(flag("create", None, "Create the target directory/bucket when missing (and remove it afterwards)"));
    Command::new("fsf")
        .version(env!("CARGO_PKG_VERSION"))
        .about(ABOUT)
        .after_help(AFTER_HELP)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(opt_arg())
        .arg(flag("test-services", None, "Use the FSFAST_TEST_* settings of scripts/test-services.sh as option defaults").global(true))
        .arg(flag("json", None, "Machine-readable JSON output").global(true))
        .arg(flag("stats", None, "Print engine request counters to stderr when done").global(true))
        .arg(flag("quiet", Some('q'), "Suppress progress and summary lines on stderr").global(true))
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::Count)
                .global(true)
                .help("More log output on stderr (-v info, -vv debug, -vvv trace; RUST_LOG overrides)"),
        )
        .subcommand(
            Command::new("ls")
                .about("List a directory (or a file)")
                .arg(opt_arg())
                .arg(url_arg("url", "Location"))
                .arg(flag("long", Some('l'), "Type, size, modification time and name")),
        )
        .subcommand(
            Command::new("info")
                .about("Print the fsspec info() dict of a path as JSON")
                .arg(opt_arg())
                .arg(url_arg("url", "Location")),
        )
        .subcommand(
            Command::new("find")
                .about("Recursive listing")
                .arg(opt_arg())
                .arg(url_arg("url", "Location"))
                .arg(value("maxdepth", "Maximum depth"))
                .arg(flag("withdirs", None, "Include directories"))
                .arg(flag("long", Some('l'), "Type, size, modification time and name")),
        )
        .subcommand(
            Command::new("cat")
                .about("Write a file (or a byte range of it) to stdout")
                .arg(opt_arg())
                .arg(url_arg("url", "Location"))
                .arg(value("start", "First byte (inclusive)"))
                .arg(value("end", "End byte (exclusive)")),
        )
        .subcommand(
            Command::new("cp")
                .about("Copy files: local<->remote, remote<->remote (server-side within one filesystem)")
                .arg(opt_arg())
                .arg(url_arg("src", "Source location"))
                .arg(url_arg("dst", "Destination (an existing directory or a trailing / copies into it)"))
                .arg(flag("recursive", Some('r'), "Copy directories recursively"))
                .arg(value("jobs", "Files copied in parallel [default: 8]").short('j')),
        )
        .subcommand(
            Command::new("rm")
                .about("Delete files (and trees with -r)")
                .arg(opt_arg())
                .arg(Arg::new("urls").required(true).num_args(1..).help("Locations"))
                .arg(flag("recursive", Some('r'), "Delete directories recursively")),
        )
        .subcommand(
            Command::new("mkdir")
                .about("Create directories (buckets/containers at the top level of object stores)")
                .arg(opt_arg())
                .arg(Arg::new("urls").required(true).num_args(1..).help("Locations"))
                .arg(flag("parents", Some('p'), "Create parents; no error if it exists")),
        )
        .subcommand(Command::new("protocols")
                .about("List the compiled-in protocols")
                .arg(opt_arg()))
        .subcommand(bench)
}

fn usage(cmd: &str, m: impl std::fmt::Display) -> Error {
    Error::invalid_input(format!("{cmd}: {m}"))
}

fn get_num<T: std::str::FromStr>(m: &ArgMatches, name: &str) -> Result<Option<T>> {
    match m.get_one::<String>(name) {
        None => Ok(None),
        Some(s) => s
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| usage(&format!("--{name}"), format!("invalid number {s:?}"))),
    }
}

fn get_size(m: &ArgMatches, name: &str) -> Result<Option<u64>> {
    m.get_one::<String>(name)
        .map(|s| parse_size(s).map_err(|e| usage(&format!("--{name}"), e.message())))
        .transpose()
}

fn get_str(m: &ArgMatches, name: &str) -> String {
    m.get_one::<String>(name).cloned().unwrap_or_default()
}

fn get_strs(m: &ArgMatches, name: &str) -> Vec<String> {
    m.get_many::<String>(name)
        .map(|v| v.cloned().collect())
        .unwrap_or_default()
}

fn bench_config(m: &ArgMatches) -> Result<BenchConfig> {
    let d = BenchConfig::default();
    let cfg = BenchConfig {
        workloads: Workload::parse_list(&get_str(m, "workloads"))?,
        size: get_size(m, "size")?.unwrap_or(d.size),
        file_size: get_size(m, "file-size")?.unwrap_or(d.file_size),
        count: get_num(m, "count")?.unwrap_or(d.count),
        concurrency: get_num(m, "concurrency")?.unwrap_or(d.concurrency),
        io_concurrency: get_num(m, "io-concurrency")?,
        block_size: get_size(m, "block-size")?
            .map(|b| usize::try_from(b).map_err(|_| usage("--block-size", "too large")))
            .transpose()?,
        range_size: get_size(m, "range-size")?.unwrap_or(d.range_size),
        ranges: get_num(m, "ranges")?.unwrap_or(d.ranges),
        dirs: get_num(m, "dirs")?,
        iterations: get_num(m, "iterations")?.unwrap_or(d.iterations),
        warmup: get_num(m, "warmup")?.unwrap_or(d.warmup),
        seed: get_num(m, "seed")?.unwrap_or(d.seed),
        keep: m.get_flag("keep"),
        create: m.get_flag("create"),
        dest: m.get_one::<String>("dest").cloned(),
    };
    cfg.validate()?;
    Ok(cfg)
}

/// Parse a command line. `Err(Ok(clap error))` is a usage/help/version
/// outcome for clap to print; `Err(Err(..))` an invalid value.
pub fn parse_args<I, T>(
    args: I,
) -> std::result::Result<Cli, std::result::Result<clap::Error, Error>>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let m = command().try_get_matches_from(args).map_err(Ok)?;
    from_matches(&m).map_err(Err)
}

fn from_matches(m: &ArgMatches) -> Result<Cli> {
    let (name, sm) = m.subcommand().expect("subcommand_required");
    // Options before the subcommand first, so later ones win.
    let mut raw = get_strs(m, "opt");
    raw.extend(get_strs(sm, "opt"));
    let opts = raw
        .iter()
        .map(|s| parse_opt(s))
        .collect::<Result<Vec<_>>>()?;
    let command = match name {
        "ls" => Cmd::Ls {
            url: get_str(sm, "url"),
            long: sm.get_flag("long"),
        },
        "info" => Cmd::Info {
            url: get_str(sm, "url"),
        },
        "find" => Cmd::Find {
            url: get_str(sm, "url"),
            maxdepth: get_num(sm, "maxdepth")?,
            withdirs: sm.get_flag("withdirs"),
            long: sm.get_flag("long"),
        },
        "cat" => {
            let start = get_num(sm, "start")?;
            let end = get_num(sm, "end")?;
            if let (Some(s), Some(e)) = (start, end)
                && e < s
            {
                return Err(usage("cat", "--end must not be before --start"));
            }
            Cmd::Cat {
                url: get_str(sm, "url"),
                start,
                end,
            }
        }
        "cp" => {
            let jobs = get_num(sm, "jobs")?.unwrap_or(8);
            if jobs == 0 {
                return Err(usage("cp", "--jobs must be at least 1"));
            }
            Cmd::Cp {
                src: get_str(sm, "src"),
                dst: get_str(sm, "dst"),
                recursive: sm.get_flag("recursive"),
                jobs,
            }
        }
        "rm" => Cmd::Rm {
            urls: get_strs(sm, "urls"),
            recursive: sm.get_flag("recursive"),
        },
        "mkdir" => Cmd::Mkdir {
            urls: get_strs(sm, "urls"),
            parents: sm.get_flag("parents"),
        },
        "protocols" => Cmd::Protocols,
        "bench" => Cmd::Bench {
            url: get_str(sm, "url"),
            config: bench_config(sm)?,
        },
        other => return Err(usage(other, "unknown command")),
    };
    Ok(Cli {
        opts,
        test_services: m.get_flag("test-services"),
        json: m.get_flag("json"),
        stats: m.get_flag("stats"),
        quiet: m.get_flag("quiet"),
        verbose: m.get_count("verbose"),
        command,
    })
}

fn init_logging(verbose: u8) {
    use tracing_subscriber::EnvFilter;
    let default = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// Run a parsed command. Returns the process exit code.
pub async fn run(cli: Cli) -> Result<i32> {
    let env = |k: &str| std::env::var(k).ok();
    let session = Session::new(OptionSet::new(cli.opts.clone(), cli.test_services, &env)?);
    let res = dispatch(&cli, &session).await;
    if cli.stats {
        let mut err = std::io::stderr().lock();
        for (proto, b) in session.built() {
            if let Some(s) = &b.stats {
                let c = ops::Counters::of(&s.snapshot());
                let _ = writeln!(err, "stats[{proto}]: {}", c.line());
            }
        }
    }
    session.close().await;
    res
}

async fn dispatch(cli: &Cli, session: &Session) -> Result<i32> {
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr();
    let quiet = cli.quiet;
    match &cli.command {
        Cmd::Ls { url, long } => commands::ls(session, url, *long, cli.json, &mut out).await?,
        Cmd::Info { url } => commands::info(session, url, &mut out).await?,
        Cmd::Find {
            url,
            maxdepth,
            withdirs,
            long,
        } => {
            commands::find(
                session, url, *maxdepth, *withdirs, *long, cli.json, &mut out,
            )
            .await?
        }
        Cmd::Cat { url, start, end } => commands::cat(session, url, *start, *end, &mut out).await?,
        Cmd::Cp {
            src,
            dst,
            recursive,
            jobs,
        } => commands::cp(session, src, dst, *recursive, *jobs, quiet, &mut err).await?,
        Cmd::Rm { urls, recursive } => {
            let u: Vec<&str> = urls.iter().map(String::as_str).collect();
            commands::rm(session, &u, *recursive, quiet, &mut err).await?
        }
        Cmd::Mkdir { urls, parents } => {
            let u: Vec<&str> = urls.iter().map(String::as_str).collect();
            commands::mkdir(session, &u, *parents).await?
        }
        Cmd::Protocols => {
            for b in backends::BACKENDS {
                writeln!(out, "{}", b.protocols.join(" ")).map_err(commands::out_err)?;
            }
        }
        Cmd::Bench { url, config } => {
            drop(out);
            return run_bench(session, url, config, cli.json, quiet).await;
        }
    }
    Ok(0)
}

async fn run_bench(
    session: &Session,
    url: &str,
    config: &BenchConfig,
    json: bool,
    quiet: bool,
) -> Result<i32> {
    let progress = |s: &str| {
        if !quiet {
            eprintln!("fsf: {s}");
        }
    };
    let on_result = |r: &bench::WorkloadResult| {
        if !json {
            let mut o = std::io::stdout().lock();
            let _ = writeln!(o, "{}", r.human());
            let _ = o.flush();
        }
    };
    // Poll the Ctrl-C future once right away: that installs the handler
    // before the benchmark creates anything, so an early interrupt is
    // handled (with cleanup) instead of killing the process.
    let mut sigint = Box::pin(tokio::signal::ctrl_c());
    let early = futures::FutureExt::now_or_never(&mut sigint);
    let cancel = async move {
        let res = match early {
            Some(r) => r,
            None => sigint.await,
        };
        if res.is_err() {
            // No signal handling available: never cancel.
            std::future::pending::<()>().await;
        }
    };
    let report = bench::run_bench(session, url, config, &progress, &on_result, cancel).await?;
    let mut out = std::io::stdout().lock();
    if json {
        serde_json::to_writer_pretty(&mut out, &report.to_json())
            .map_err(|e| Error::new(ErrorKind::Io, e.to_string()))?;
        writeln!(out).map_err(commands::out_err)?;
    } else {
        let c = &report.cleanup;
        if c.ran {
            writeln!(
                out,
                "cleanup: removed {} file(s), {} director(y/ies) under {}",
                c.files, c.dirs, report.prefix
            )
            .map_err(commands::out_err)?;
        } else {
            writeln!(out, "kept {}", report.prefix).map_err(commands::out_err)?;
        }
    }
    for e in &report.cleanup.errors {
        eprintln!("fsf: cleanup failed: {e}");
    }
    if let Some(e) = &report.error {
        eprintln!("fsf: error: {e}");
        // 128 + SIGINT, as shells report an interrupted command.
        return Ok(if report.interrupted { 130 } else { 1 });
    }
    Ok(if report.cleanup.errors.is_empty() {
        0
    } else {
        1
    })
}

/// The `fsf` entry point: parse `args`, run, return the exit code
/// (0 success, 1 failure, 2 usage error, 130 benchmark interrupted).
pub fn main_with_args<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match parse_args(args) {
        Ok(c) => c,
        Err(Ok(e)) => {
            let code = e.exit_code();
            let _ = e.print();
            return code;
        }
        Err(Err(e)) => {
            eprintln!("fsf: error: {e}");
            return 2;
        }
    };
    init_logging(cli.verbose);
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("fsf")
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fsf: error: cannot start the runtime: {e}");
            return 1;
        }
    };
    let code = match rt.block_on(run(cli)) {
        Ok(code) => code,
        Err(e) if commands::is_broken_pipe(&e) => 0,
        Err(e) => {
            eprintln!("fsf: error: {e}");
            1
        }
    };
    // Do not wait for lingering background tasks (pool reapers, ...).
    rt.shutdown_timeout(std::time::Duration::from_secs(2));
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        let mut v = vec!["fsf"];
        v.extend_from_slice(args);
        match parse_args(v) {
            Ok(c) => c,
            Err(Ok(e)) => panic!("clap: {e}"),
            Err(Err(e)) => panic!("{e}"),
        }
    }

    fn parse_err(args: &[&str]) -> bool {
        let mut v = vec!["fsf"];
        v.extend_from_slice(args);
        parse_args(v).is_err()
    }

    #[test]
    fn clap_definition_is_consistent() {
        command().debug_assert();
    }

    #[test]
    fn global_options_anywhere() {
        let c = parse(&[
            "--opt",
            "key=a",
            "ls",
            "-l",
            "memory://x",
            "-o",
            "s3:secret=b",
            "--json",
        ]);
        assert_eq!(c.opts.len(), 2);
        assert!(c.json);
        assert!(matches!(c.command, Cmd::Ls { long: true, ref url } if url == "memory://x"));
        let c = parse(&["--test-services", "-vv", "--stats", "info", "/tmp"]);
        assert!(c.test_services && c.stats);
        assert_eq!(c.verbose, 2);
    }

    #[test]
    fn subcommands() {
        let c = parse(&["cp", "-r", "-j", "4", "a", "s3://b/c/"]);
        assert!(matches!(
            c.command,
            Cmd::Cp {
                recursive: true,
                jobs: 4,
                ..
            }
        ));
        let c = parse(&["cp", "a", "b"]);
        assert!(matches!(
            c.command,
            Cmd::Cp {
                recursive: false,
                jobs: 8,
                ..
            }
        ));
        let c = parse(&["rm", "-r", "a", "b"]);
        assert!(matches!(c.command, Cmd::Rm { recursive: true, ref urls } if urls.len() == 2));
        let c = parse(&["mkdir", "-p", "x"]);
        assert!(matches!(c.command, Cmd::Mkdir { parents: true, .. }));
        let c = parse(&["cat", "--start", "5", "--end", "10", "x"]);
        assert!(matches!(
            c.command,
            Cmd::Cat {
                start: Some(5),
                end: Some(10),
                ..
            }
        ));
        let c = parse(&["find", "--maxdepth", "2", "--withdirs", "x"]);
        assert!(matches!(
            c.command,
            Cmd::Find {
                maxdepth: Some(2),
                withdirs: true,
                ..
            }
        ));
        assert!(matches!(parse(&["protocols"]).command, Cmd::Protocols));
    }

    #[test]
    fn invalid_command_lines() {
        assert!(parse_err(&[]));
        assert!(parse_err(&["ls"]));
        assert!(parse_err(&["cp", "a"]));
        assert!(parse_err(&["cp", "-j", "0", "a", "b"]));
        assert!(parse_err(&["cat", "--start", "9", "--end", "1", "x"]));
        assert!(parse_err(&["cat", "--start", "x", "y"]));
        assert!(parse_err(&["--opt", "novalue", "ls", "x"]));
        assert!(parse_err(&["bench", "x", "--size", "12Q"]));
        assert!(parse_err(&["bench", "x", "-w", "W9"]));
        assert!(parse_err(&["bench", "x", "-n", "0"]));
        assert!(parse_err(&["frobnicate"]));
    }

    #[test]
    fn bench_flags() {
        let c = parse(&[
            "bench",
            "memory://b",
            "-w",
            "W1,W6",
            "--size",
            "1MiB",
            "--file-size",
            "1k",
            "--count",
            "10",
            "-c",
            "4",
            "--io-concurrency",
            "2",
            "--block-size",
            "64KiB",
            "--range-size",
            "4k",
            "--ranges",
            "20",
            "--dirs",
            "3",
            "-n",
            "2",
            "--warmup",
            "0",
            "--seed",
            "7",
            "--keep",
            "--create",
            "--dest",
            "/tmp/x",
        ]);
        let Cmd::Bench { url, config } = c.command else {
            panic!("not bench")
        };
        assert_eq!(url, "memory://b");
        assert_eq!(config.workloads, vec![Workload::W1, Workload::W6]);
        assert_eq!(config.size, 1 << 20);
        assert_eq!(config.file_size, 1024);
        assert_eq!(config.count, 10);
        assert_eq!(config.concurrency, 4);
        assert_eq!(config.io_concurrency, Some(2));
        assert_eq!(config.block_size, Some(64 << 10));
        assert_eq!(config.range_size, 4096);
        assert_eq!(config.ranges, 20);
        assert_eq!(config.dirs, Some(3));
        assert_eq!(config.iterations, 2);
        assert_eq!(config.warmup, 0);
        assert_eq!(config.seed, 7);
        assert!(config.keep && config.create);
        assert_eq!(config.dest.as_deref(), Some("/tmp/x"));
        // Repeated value flags: the last one wins.
        let Cmd::Bench { config, .. } = parse(&[
            "bench", "x", "--size", "1MiB", "--size", "2MiB", "--keep", "--keep",
        ])
        .command
        else {
            panic!()
        };
        assert_eq!(config.size, 2 << 20);
        let Cmd::Bench { config, .. } = parse(&["bench", "x"]).command else {
            panic!()
        };
        assert_eq!(config.workloads.len(), 8);
        assert_eq!(config.iterations, 3);
    }
}
