//! The process-wide tokio runtime and the bridges from Python into Rust
//! futures (docs/PLAN.md §4.4).
//!
//! * **One runtime per process**, a multi-thread tokio runtime built lazily
//!   on first use ([`runtime`]). Worker threads default to the CPU count;
//!   `FSFAST_WORKER_THREADS` and `FSFAST_MAX_BLOCKING_THREADS` override the
//!   worker and blocking-pool sizes.
//! * **Fork safety.** A forked child inherits the parent's runtime object but
//!   none of its threads. Using it would hang and dropping it would join
//!   threads that do not exist, so the child leaks it (`mem::forget`) and
//!   builds a new one: eagerly from `os.register_at_fork(after_in_child=...)`
//!   ([`after_fork_child`]) and, for forks that bypass Python's hooks, on
//!   first use, because a `pthread_atfork` handler counts every fork
//!   ([`fork_generation`]; an atomic load per call instead of a `getpid`
//!   system call).
//!   The runtime slot is an [`ArcSwapOption`], so no lock can be held across
//!   a fork. Locks inside backends are kept out of the child by the fork
//!   gate ([`crate::gate`]): the `before` hook ([`before_fork`]) waits until
//!   no backend future is being polled.
//! * **Sync calls** ([`block_on`]) detach from the interpreter (release the
//!   GIL), drive the future on the calling thread with a minimal executor —
//!   no thread hop, no asyncio, no per-call timer — and wake every
//!   [`SIGNAL_CHECK_INTERVAL`] to run `PyErr_CheckSignals`, so Ctrl-C
//!   interrupts a long operation (the future is then dropped, i.e.
//!   cancelled, and the `KeyboardInterrupt` propagates).
//! * **Async calls** ([`future_into_py`]) return asyncio futures through
//!   `pyo3-async-runtimes`; its generic runtime traits are implemented on top
//!   of the same fork-aware runtime ([`FsfastRuntime`]).

use std::future::Future;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use pyo3::prelude::*;
use pyo3_async_runtimes::TaskLocals;
use pyo3_async_runtimes::generic::{ContextExt, Runtime as AsyncRuntime};
use tokio::runtime::{Handle, Runtime};

use crate::gate;

/// How often a blocked sync call re-attaches to the interpreter to check for
/// pending signals (Ctrl-C).
pub(crate) const SIGNAL_CHECK_INTERVAL: Duration = Duration::from_millis(100);

/// The runtime together with the process (and fork generation) that built it.
pub(crate) struct RuntimeSlot {
    pid: u32,
    generation: u64,
    rt: Runtime,
}

impl RuntimeSlot {
    /// The runtime's handle.
    pub(crate) fn handle(&self) -> &Handle {
        self.rt.handle()
    }

    /// PID of the process that built this runtime.
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }
}

static RUNTIME: ArcSwapOption<RuntimeSlot> = ArcSwapOption::const_empty();

/// Incremented in every forked child, by a `pthread_atfork` child handler
/// ([`watch_forks`]) that sees each `fork()` made through the C library,
/// including forks that bypass Python's `os.register_at_fork` hooks. State
/// tied to a process's runtime (the runtime itself, backend instances, open
/// files with background work) records it and, when it changed, is rebuilt
/// or abandoned instead of touching the parent's runtime, which has no
/// threads here. Checking it is one atomic load: no `getpid` system call on
/// every operation.
static FORK_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Whether the `pthread_atfork` handler is installed. If registering it
/// failed, the Python `after_in_child` hook counts forks instead.
static ATFORK_INSTALLED: AtomicBool = AtomicBool::new(false);

/// The current fork generation (see [`FORK_GENERATION`]); one atomic load.
pub(crate) fn fork_generation() -> u64 {
    FORK_GENERATION.load(Ordering::Acquire)
}

fn note_fork() {
    FORK_GENERATION.fetch_add(1, Ordering::AcqRel);
}

/// `pthread_atfork` child handler. Runs in the child inside `fork()`, where
/// only async-signal-safe operations are allowed: a lock-free atomic
/// increment is one.
#[cfg(unix)]
extern "C" fn on_fork_child() {
    note_fork();
}

/// Install the fork watcher (once per process; cheap after the first call).
/// Called before anything records a fork generation: when the module is
/// imported, before building a runtime and when creating a filesystem.
pub(crate) fn watch_forks() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        #[cfg(unix)]
        {
            // SAFETY: registers a `'static` handler that performs a single
            // atomic increment, which is async-signal-safe as required for
            // code running in a child between `fork()` and its return.
            let rc = unsafe {
                libc::pthread_atfork(None, None, Some(on_fork_child as unsafe extern "C" fn()))
            };
            if rc == 0 {
                ATFORK_INSTALLED.store(true, Ordering::Release);
            } else {
                tracing::warn!(
                    rc,
                    "fsfast: pthread_atfork failed; forks are only detected through os.fork()"
                );
            }
        }
    });
}

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok()?.trim().parse().ok()
}

fn build_runtime() -> Runtime {
    watch_forks();
    let mut b = tokio::runtime::Builder::new_multi_thread();
    b.enable_all().thread_name("fsfast-rt");
    if let Some(n) = env_usize("FSFAST_WORKER_THREADS") {
        b.worker_threads(n.max(1));
    }
    if let Some(n) = env_usize("FSFAST_MAX_BLOCKING_THREADS") {
        b.max_blocking_threads(n.max(1));
    }
    // Failing to start threads leaves nothing sensible to do; PyO3 turns the
    // panic into a Python `PanicException`.
    b.build()
        .unwrap_or_else(|e| panic!("fsfast: cannot start the tokio runtime: {e}"))
}

/// The current process's runtime, building it on first use (or after a
/// fork). Cheap: two atomic loads on the fast path.
pub(crate) fn runtime() -> Arc<RuntimeSlot> {
    loop {
        let generation = fork_generation();
        let current = RUNTIME.load_full();
        if let Some(slot) = &current
            && slot.generation == generation
        {
            return slot.clone();
        }
        let fresh = Arc::new(RuntimeSlot {
            pid: std::process::id(),
            rt: build_runtime(),
            // Read after `build_runtime` installed the fork watcher.
            generation: fork_generation(),
        });
        let prev = RUNTIME.compare_and_swap(&current, Some(fresh.clone()));
        let won = match (&*prev, &current) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        drop(prev);
        if won {
            if let Some(inherited) = current {
                // Built by the parent before the fork (the Python hook did
                // not run, or has not run yet).
                abandon(inherited);
            }
            return fresh;
        }
        // Another thread installed a runtime first: discard ours and retry.
        if let Ok(slot) = Arc::try_unwrap(fresh) {
            slot.rt.shutdown_background();
        }
    }
}

/// Leak a runtime inherited from the parent process: its threads do not
/// exist in this process, so it must never be dropped (dropping joins them).
/// Leaking one strong reference keeps the count above zero forever.
fn abandon(slot: Arc<RuntimeSlot>) {
    tracing::debug!(
        parent_pid = slot.pid,
        "fsfast: abandoning runtime inherited across fork"
    );
    std::mem::forget(slot);
}

/// `os.register_at_fork(before=...)` hook: wait, with the interpreter
/// released, until no backend code driven by fsfast runs, and keep new
/// operations from starting until the fork is done (see [`crate::gate`]).
pub(crate) fn before_fork(py: Python<'_>) {
    py.detach(gate::close_for_fork);
}

/// `os.register_at_fork(after_in_parent=...)` hook: let operations resume.
pub(crate) fn after_fork_parent() {
    gate::reopen_after_fork();
}

/// `os.register_at_fork(after_in_child=...)` hook: reset the fork gate and
/// forget the parent's runtime; the next call builds a fresh one.
pub(crate) fn after_fork_child() {
    let child = gate::reset_in_child();
    if child && !ATFORK_INSTALLED.load(Ordering::Acquire) {
        // The `pthread_atfork` handler is missing: count the fork here.
        note_fork();
    }
    if let Some(old) = RUNTIME.swap(None) {
        if old.generation != fork_generation() {
            abandon(old);
        } else {
            // Not actually inherited (hook called by hand): keep it.
            RUNTIME.store(Some(old));
        }
    }
}

/// Run `fut` to completion from synchronous Python code: the interpreter is
/// released while the future runs on the calling thread, and pending signals
/// are checked every [`SIGNAL_CHECK_INTERVAL`] (a signal handler raising, e.g.
/// `KeyboardInterrupt`, cancels the future and is returned as the error).
pub(crate) fn block_on<F>(py: Python<'_>, fut: F) -> PyResult<F::Output>
where
    F: Future + Send,
    F::Output: Send,
{
    let slot = runtime();
    py.detach(move || drive(&slot, fut))
}

/// Drive `fut` on the current (detached) thread.
pub(crate) fn drive<F>(slot: &RuntimeSlot, fut: F) -> PyResult<F::Output>
where
    F: Future + Send,
    F::Output: Send,
{
    if Handle::try_current().is_ok() {
        // A runtime context is active on this thread: Python code reached
        // from a finalizer running on a runtime worker (or inside a poll).
        // Blocking a worker could starve the very tasks the future waits
        // for, so drive it from a helper thread instead (rare; correctness
        // over speed). The helper works for this thread's poll, so it shares
        // its fork-gate entries (see `gate::with_inherited_depth`).
        let depth = gate::depth();
        return std::thread::scope(|s| {
            s.spawn(move || gate::with_inherited_depth(depth, || run_until_complete(slot, fut)))
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
        });
    }
    run_until_complete(slot, fut)
}

/// Spin this long for a wake-up before parking the thread. Operations that
/// hand work to another thread (e.g. a backend's blocking pool) typically
/// complete within a few microseconds; catching that without a futex sleep
/// and wake-up saves a context switch per call.
const SPIN: Duration = Duration::from_micros(30);

/// Wakes the thread driving a sync call.
struct ThreadWaker {
    woken: AtomicBool,
    thread: std::thread::Thread,
}

impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // `swap` so concurrent wakes unpark at most once.
        if !self.woken.swap(true, Ordering::Release) {
            self.thread.unpark();
        }
    }
}

/// A minimal executor for sync calls: polls `fut` on this thread inside the
/// runtime context (tokio's I/O and timer drivers run on its workers; the
/// blocking pool and spawned tasks are reached through the context), spins
/// briefly and then parks between wake-ups, and runs the interpreter's
/// signal handlers every [`SIGNAL_CHECK_INTERVAL`] (a handler that raises
/// cancels the call). Compared with `Runtime::block_on` this needs no timer
/// registration per call and avoids a futex round trip when the result
/// arrives quickly.
fn run_until_complete<F: Future>(slot: &RuntimeSlot, fut: F) -> PyResult<F::Output> {
    run_with_signal_checks(slot, fut, SIGNAL_CHECK_INTERVAL, || {
        Python::attach(|py| py.check_signals())
    })
}

/// [`run_until_complete`] with the signal check and its interval as
/// parameters (tests count the checks).
///
/// The deadline is checked after every poll, not only before parking: a
/// future that is woken again within the spin window each time (a long
/// stream of quickly completing sub-operations) never parks, and must still
/// see Ctrl-C.
fn run_with_signal_checks<F: Future>(
    slot: &RuntimeSlot,
    fut: F,
    interval: Duration,
    mut check_signals: impl FnMut() -> PyResult<()>,
) -> PyResult<F::Output> {
    let _ctx = slot.rt.enter();
    let waker_state = Arc::new(ThreadWaker {
        woken: AtomicBool::new(false),
        thread: std::thread::current(),
    });
    let waker = Waker::from(waker_state.clone());
    let mut cx = Context::from_waker(&waker);
    let mut fut = pin!(fut);
    // Set on the first poll that does not complete, so calls finishing at
    // once never read the clock.
    let mut next_check: Option<Instant> = None;
    loop {
        // Each poll runs inside the fork gate (see `crate::gate`); this
        // thread is detached from the interpreter, so it may wait there.
        let polled = {
            let _gate = gate::enter();
            fut.as_mut().poll(&mut cx)
        };
        if let Poll::Ready(v) = polled {
            return Ok(v);
        }
        let now = Instant::now();
        let deadline = *next_check.get_or_insert(now + interval);
        if now >= deadline {
            check_signals()?;
            next_check = Some(now + interval);
        }
        let spin_until = now + SPIN;
        while !waker_state.woken.swap(false, Ordering::Acquire) {
            let now = Instant::now();
            if now < spin_until {
                std::hint::spin_loop();
                continue;
            }
            let deadline = next_check.unwrap_or(now);
            if now >= deadline {
                // Re-poll after every interval as well: a spurious poll is
                // harmless, and a lost wake-up cannot hang the call. The
                // signal check runs at the top of the loop.
                break;
            }
            std::thread::park_timeout(deadline - now);
        }
    }
}

tokio::task_local! {
    /// asyncio event loop and contextvars of the Python task awaiting a
    /// Rust future (what `pyo3-async-runtimes` needs to resolve it).
    static TASK_LOCALS: TaskLocals;
}

/// `pyo3-async-runtimes` runtime adapter over [`runtime`].
pub(crate) struct FsfastRuntime;

impl AsyncRuntime for FsfastRuntime {
    type JoinError = tokio::task::JoinError;
    type JoinHandle = tokio::task::JoinHandle<()>;

    fn spawn<F>(fut: F) -> Self::JoinHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        runtime().handle().spawn(fut)
    }

    fn spawn_blocking<F>(f: F) -> Self::JoinHandle
    where
        F: FnOnce() + Send + 'static,
    {
        runtime().handle().spawn_blocking(f)
    }
}

impl ContextExt for FsfastRuntime {
    fn scope<F, R>(locals: TaskLocals, fut: F) -> Pin<Box<dyn Future<Output = R> + Send>>
    where
        F: Future<Output = R> + Send + 'static,
    {
        Box::pin(TASK_LOCALS.scope(locals, fut))
    }

    fn get_task_locals() -> Option<TaskLocals> {
        TASK_LOCALS.try_with(Clone::clone).ok()
    }
}

/// Wrap `fut` in an asyncio future bound to `event_loop` (the running loop,
/// looked up by the caller), with the caller's contextvars. The result is
/// converted to Python (with the interpreter attached) when the future
/// completes; cancelling the asyncio future drops `fut`.
pub(crate) fn future_into_py<'py, F, T>(
    py: Python<'py>,
    event_loop: Bound<'py, PyAny>,
    fut: F,
) -> PyResult<Bound<'py, PyAny>>
where
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: for<'a> IntoPyObject<'a> + Send + 'static,
{
    let locals = TaskLocals::new(event_loop).copy_context(py)?;
    // Only `fut` runs inside the fork gate: the wrapper around it attaches
    // to the interpreter to resolve the asyncio future, which must never
    // happen while holding a gate entry (the forking thread waits for gate
    // entries and then needs the interpreter back).
    pyo3_async_runtimes::generic::future_into_py_with_locals::<FsfastRuntime, _, T>(
        py,
        locals,
        gate::Gated(Box::pin(fut)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_is_shared_and_pid_tagged() {
        let a = runtime();
        let b = runtime();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(a.pid(), std::process::id());
        assert_eq!(a.handle().block_on(async { 1 + 1 }), 2);
    }

    #[cfg(unix)]
    #[test]
    fn every_fork_is_counted_in_the_child_only() {
        watch_forks();
        let before = fork_generation();
        // SAFETY: the child only performs async-signal-safe operations (an
        // atomic load and `_exit`), as required after forking a
        // multi-threaded process.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let counted = fork_generation() == before + 1;
            // SAFETY: `_exit` is async-signal-safe and ends the child.
            unsafe { libc::_exit(if counted { 0 } else { 1 }) };
        }
        let mut status = 0;
        // SAFETY: waits for the child created above; `status` is valid.
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "the fork was not counted in the child (status {status})"
        );
        assert_eq!(fork_generation(), before, "the parent's generation changed");
    }

    #[test]
    fn manual_fork_hook_in_same_process_keeps_runtime() {
        let a = runtime();
        let generation = fork_generation();
        after_fork_child();
        let b = runtime();
        assert!(Arc::ptr_eq(&a, &b));
        // Not a fork: objects tied to the runtime must keep their state.
        assert_eq!(fork_generation(), generation);
    }

    #[test]
    fn signal_checks_run_while_the_future_keeps_waking_itself() {
        // A future woken again at once on every poll never parks; the old
        // executor only checked signals before parking, so Ctrl-C was
        // ignored for as long as such an operation ran.
        let slot = runtime();
        let start = Instant::now();
        let fut = std::future::poll_fn(|cx| {
            if start.elapsed() >= Duration::from_millis(250) {
                return Poll::Ready(7);
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        });
        let mut checks = 0;
        let out = run_with_signal_checks(&slot, fut, Duration::from_millis(40), || {
            checks += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(out, 7);
        assert!(checks >= 3, "only {checks} signal checks in 250 ms");
    }

    #[test]
    fn a_raising_signal_check_cancels_a_parked_call() {
        struct SetOnDrop(Arc<AtomicBool>);
        impl Drop for SetOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let slot = runtime();
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = SetOnDrop(dropped.clone());
        let fut = async move {
            let _guard = guard;
            std::future::pending::<()>().await
        };
        let mut checks = 0;
        let start = Instant::now();
        let err = run_with_signal_checks(&slot, fut, Duration::from_millis(20), || {
            checks += 1;
            if checks == 3 {
                Err(pyo3::exceptions::PyKeyboardInterrupt::new_err(()))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(dropped.load(Ordering::SeqCst), "the future was not dropped");
        Python::attach(|py| {
            assert!(err.is_instance_of::<pyo3::exceptions::PyKeyboardInterrupt>(py))
        });
    }

    #[test]
    fn drive_works_inside_a_runtime_context() {
        let slot = runtime();
        let out = slot
            .handle()
            .block_on(async {
                // Simulates Python code reached from a runtime worker.
                drive(&runtime(), async { 7 })
            })
            .unwrap();
        assert_eq!(out, 7);
    }

    #[test]
    fn executor_drives_ready_timer_blocking_and_spawned_work() {
        let slot = runtime();
        assert_eq!(drive(&slot, async { 3 }).unwrap(), 3);
        // tokio timers (driven by the runtime's workers) wake us.
        let v = drive(&slot, async {
            tokio::time::sleep(Duration::from_millis(5)).await;
            4
        })
        .unwrap();
        assert_eq!(v, 4);
        // Blocking-pool and spawned tasks are reachable through the context.
        let v = drive(&slot, async {
            let a = tokio::task::spawn_blocking(|| 5).await.unwrap();
            let b = tokio::spawn(async { 6 }).await.unwrap();
            a + b
        })
        .unwrap();
        assert_eq!(v, 11);
        // Many wake-ups in a row (spin and park paths).
        let v = drive(&slot, async {
            let mut n = 0;
            for i in 0..200u64 {
                if i % 50 == 0 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                n += tokio::task::spawn_blocking(move || i).await.unwrap();
            }
            n
        })
        .unwrap();
        assert_eq!(v, (0..200).sum::<u64>());
    }
}
