//! The individual conformance checks.
//!
//! Each check is an `async fn(&Ctx) -> CheckResult` running in its own
//! directory `ctx.dir`. Checks must only touch paths below `ctx.dir`.

mod data;
mod dirs;
mod meta;
mod mutate;
mod write;

use futures::future::BoxFuture;

use crate::ctx::{CheckResult, Ctx};

/// Type-erased check entry point.
pub(crate) type CheckFn = for<'a> fn(&'a Ctx) -> BoxFuture<'a, CheckResult>;

macro_rules! registry {
    ($($name:ident => $f:path),* $(,)?) => {
        /// All checks, in execution order.
        pub(crate) static REGISTRY: &[(&str, CheckFn)] = &[
            $((stringify!($name), {
                fn wrapper(c: &Ctx) -> BoxFuture<'_, CheckResult> {
                    Box::pin($f(c))
                }
                wrapper as CheckFn
            })),*
        ];
    };
}

registry! {
    pipe_cat_roundtrip => data::pipe_cat_roundtrip,
    cat_file_ranges => data::cat_file_ranges,
    cat_ranges => data::cat_ranges,
    info => meta::info,
    ls => meta::ls,
    find => meta::find,
    exists => meta::exists,
    mkdir_rmdir => dirs::mkdir_rmdir,
    makedirs => dirs::makedirs,
    rm_file => mutate::rm_file,
    rm_files_batch => mutate::rm_files_batch,
    cp_file => mutate::cp_file,
    mv_file => mutate::mv_file,
    touch => mutate::touch,
    open_write_stream => write::open_write_stream,
    open_write_create_new => write::open_write_create_new,
    open_write_append => write::open_write_append,
    open_write_abort => write::open_write_abort,
    put_get_large => write::put_get_large,
    open_read_errors => data::open_read_errors,
    read_at_eof => data::read_at_eof,
    concurrent_read_at => data::concurrent_read_at,
    read_ranges_large => data::read_ranges_large,
    special_names => meta::special_names,
}
