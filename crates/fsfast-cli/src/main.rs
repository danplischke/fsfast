//! The `fsf` binary (see the `fsfast_cli` library for the implementation).

fn main() {
    std::process::exit(fsfast_cli::main_with_args(std::env::args_os()));
}
