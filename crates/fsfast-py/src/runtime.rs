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
//! * **Sync calls** ([`block_on`], [`block_on_inline`]) detach from the
//!   interpreter (release the GIL), drive the future on the calling thread
//!   with a minimal executor —
//!   no thread hop, no asyncio, no per-call timer — and wake every
//!   [`SIGNAL_CHECK_INTERVAL`] to run `PyErr_CheckSignals`, so Ctrl-C
//!   interrupts a long operation (the future is then dropped, i.e.
//!   cancelled, and the `KeyboardInterrupt` propagates). For single
//!   operations the executor also lets backends run short blocking steps
//!   (local `stat`/`open`/small reads and writes) inline on the calling
//!   thread through `fsfast_core::blocking`, so a local `info()` costs no
//!   thread hop at all.
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
    py.detach(move || drive_with(&slot, fut, false))
}

/// [`block_on`] for a future that is *one* operation: while it is polled,
/// backends may run short blocking steps inline on this thread
/// (`fsfast_core::blocking`), saving a blocking-pool hand-off and a
/// cross-thread wake-up per step. Safe because this thread is not a runtime
/// worker (see [`drive_with`]) and waits for this result anyway. Not for
/// batches: their items' blocking steps would run one after another.
pub(crate) fn block_on_inline<F>(py: Python<'_>, fut: F) -> PyResult<F::Output>
where
    F: Future + Send,
    F::Output: Send,
{
    let slot = runtime();
    py.detach(move || drive_with(&slot, fut, true))
}

/// Drive `fut` on the current (detached) thread; backends' blocking steps
/// go to the blocking pool.
pub(crate) fn drive<F>(slot: &RuntimeSlot, fut: F) -> PyResult<F::Output>
where
    F: Future + Send,
    F::Output: Send,
{
    drive_with(slot, fut, false)
}

/// Drive `fut` on the current (detached) thread, letting backends run short
/// blocking steps inline when `inline` is set.
///
/// The future is never polled on a runtime worker thread: when called from
/// one (or from inside a poll), a helper thread drives it. So inline
/// blocking only ever occupies a thread that waits for this call.
pub(crate) fn drive_with<F>(slot: &RuntimeSlot, fut: F, inline: bool) -> PyResult<F::Output>
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
            s.spawn(move || {
                gate::with_inherited_depth(depth, || run_until_complete(slot, fut, inline))
            })
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
        });
    }
    run_until_complete(slot, fut, inline)
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
fn run_until_complete<F: Future>(slot: &RuntimeSlot, fut: F, inline: bool) -> PyResult<F::Output> {
    run_with_signal_checks(slot, fut, SIGNAL_CHECK_INTERVAL, inline, || {
        Python::attach(|py| py.check_signals())
    })
}

/// [`run_until_complete`] with the signal check and its interval as
/// parameters (tests count the checks).
///
/// With `inline`, every poll runs under
/// `fsfast_core::blocking::allow_inline(true, ..)`: backend blocking steps
/// reached from that poll run on this thread. Inline steps are short by
/// contract (long or parallel work still goes to the pool), so signal
/// checks stay timely.
///
/// The deadline is checked after every poll, not only before parking: a
/// future that is woken again within the spin window each time (a long
/// stream of quickly completing sub-operations) never parks, and must still
/// see Ctrl-C.
fn run_with_signal_checks<F: Future>(
    slot: &RuntimeSlot,
    fut: F,
    interval: Duration,
    inline: bool,
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
            fsfast_core::blocking::allow_inline(inline, || fut.as_mut().poll(&mut cx))
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

// ---------------------------------------------------------------------------
// Async calls: completion through the event loop's own selector.
//
// `pyo3-async-runtimes` resolves an asyncio future in three hops after the
// Rust future is ready: a tokio worker polls it, a blocking-pool thread takes
// the interpreter to convert the result, and `call_soon_threadsafe` wakes the
// event loop. With a backend that itself waits on the blocking pool (local
// files) that is ~150 µs per call. Here, instead:
//
// * The operation is polled once on the calling (event-loop) thread with a
//   real waker. Ready at once (memory, caches): an already-resolved future
//   is returned.
// * Otherwise the waker belongs to a [`Task`]: waking it pushes the task on
//   its loop's [`Completer`] queue and signals an eventfd (a pipe on other
//   Unixes) that the loop watches with `add_reader`. No thread hop, no
//   interpreter needed on the waking thread.
// * The loop thread drains the queue in one callback ([`CompletionReader`]),
//   batching every completion that arrived since the last wake-up. A woken
//   task is polled once more right there (detached from the interpreter):
//   one blocking step (a `stat`, a small read) is then complete and the
//   asyncio future is resolved directly, on its own thread.
// * A task still pending after that poll is long-running (network I/O,
//   several steps): it moves to a tokio task, so the loop thread never
//   drives I/O, and its result comes back through the same queue.
//
// Cancelling the asyncio future drops the Rust future (or aborts its tokio
// task). Loops without `add_reader` (Windows' proactor loop) fall back to
// `pyo3-async-runtimes`.
// ---------------------------------------------------------------------------

/// The future of an async operation, with its result converted to Python
/// on the event-loop thread.
pub(crate) type OpFuture = Pin<Box<dyn Future<Output = crate::out::Converted> + Send>>;

/// Return an asyncio awaitable for `fut`, bound to the running event loop
/// (`RuntimeError` without one, before anything is polled).
///
/// The future is first polled on the calling thread with the interpreter
/// released; if that completes it, the result is returned as an
/// already-resolved asyncio future.
pub(crate) fn spawn_async<'py>(py: Python<'py>, fut: OpFuture) -> PyResult<Bound<'py, PyAny>> {
    let event_loop = pyo3_async_runtimes::get_running_loop(py)?;
    let slot = runtime();
    let Some(completer) = completer_for(py, &event_loop)? else {
        return spawn_async_fallback(py, event_loop, &slot, fut);
    };
    let task = Arc::new(Task {
        fut: parking_lot::Mutex::new(Stage::Loop(fut)),
        py_future: std::sync::OnceLock::new(),
        completer,
        scheduled: AtomicBool::new(false),
    });
    match py.detach(|| task.poll_on_this_thread(&slot)) {
        Polled::Ready(out) => resolved_future(py, &event_loop, out.into_pyobject(py)),
        Polled::Pending => {
            // Wakes that already happened are queued and only processed by
            // the loop, i.e. after this returns and the future is set.
            let py_future = event_loop.call_method0(pyo3::intern!(py, "create_future"))?;
            let _ = task.py_future.set(py_future.clone().unbind());
            let on_done = Bound::new(py, CancelOnDone(task))?;
            py_future.call_method1(pyo3::intern!(py, "add_done_callback"), (on_done,))?;
            Ok(py_future)
        }
        Polled::Gone => unreachable!("a new task holds its future"),
    }
}

/// `spawn_async` for loops without `add_reader`: first poll here (no-op
/// waker), then `pyo3-async-runtimes`.
fn spawn_async_fallback<'py>(
    py: Python<'py>,
    event_loop: Bound<'py, PyAny>,
    slot: &RuntimeSlot,
    mut fut: OpFuture,
) -> PyResult<Bound<'py, PyAny>> {
    let first = py.detach(|| {
        let _gate = gate::enter();
        let _ctx = slot.handle().enter();
        fut.as_mut().poll(&mut Context::from_waker(Waker::noop()))
    });
    match first {
        Poll::Ready(out) => resolved_future(py, &event_loop, out.into_pyobject(py)),
        Poll::Pending => future_into_py(py, event_loop, async move { Ok(fut.await) }),
    }
}

/// An asyncio future of `event_loop` already holding `result` (or its
/// exception), so awaiting it returns or raises immediately.
fn resolved_future<'py>(
    py: Python<'py>,
    event_loop: &Bound<'py, PyAny>,
    result: PyResult<Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    let fut = event_loop.call_method0(pyo3::intern!(py, "create_future"))?;
    set_outcome(py, &fut, result)?;
    Ok(fut)
}

fn set_outcome<'py>(
    py: Python<'py>,
    fut: &Bound<'py, PyAny>,
    result: PyResult<Bound<'py, PyAny>>,
) -> PyResult<()> {
    match result {
        Ok(v) => fut.call_method1(pyo3::intern!(py, "set_result"), (v,))?,
        Err(e) => fut.call_method1(pyo3::intern!(py, "set_exception"), (e.into_value(py),))?,
    };
    Ok(())
}

/// Where a task's future is.
enum Stage {
    /// Polled on the event-loop thread (first and second poll).
    Loop(OpFuture),
    /// Moved to a tokio task (still pending after the second poll).
    Spawned(tokio::task::AbortHandle),
    /// Completed, or dropped because the asyncio future was cancelled.
    Gone,
}

enum Polled {
    Ready(crate::out::Converted),
    Pending,
    Gone,
}

/// One awaited operation.
struct Task {
    fut: parking_lot::Mutex<Stage>,
    /// The asyncio future awaiting it (set right after the first poll).
    py_future: std::sync::OnceLock<Py<PyAny>>,
    completer: Arc<Completer>,
    /// Queued for a poll on the loop thread (coalesces repeated wakes).
    scheduled: AtomicBool,
}

impl Wake for Task {
    fn wake(self: Arc<Self>) {
        if !self.scheduled.swap(true, Ordering::AcqRel) {
            self.completer.push(Completion::Poll(self.clone()));
        }
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if !self.scheduled.swap(true, Ordering::AcqRel) {
            self.completer.push(Completion::Poll(self.clone()));
        }
    }
}

impl Task {
    /// Poll the future on this (detached, non-worker) thread with the task
    /// as waker. Inline blocking is not allowed here: this is the event
    /// loop's thread, which must not wait for syscalls.
    fn poll_on_this_thread(self: &Arc<Self>, slot: &RuntimeSlot) -> Polled {
        let mut stage = self.fut.lock();
        let Stage::Loop(fut) = &mut *stage else {
            return Polled::Gone; // a stale wake-up
        };
        let waker = Waker::from(self.clone());
        let polled = {
            let _gate = gate::enter();
            let _ctx = slot.handle().enter();
            fut.as_mut().poll(&mut Context::from_waker(&waker))
        };
        match polled {
            Poll::Ready(out) => {
                *stage = Stage::Gone;
                Polled::Ready(out)
            }
            Poll::Pending => Polled::Pending,
        }
    }

    /// Second poll, on the loop thread (from the completion callback).
    /// Still pending: continue on a tokio task.
    fn poll_or_spawn(self: &Arc<Self>, slot: &RuntimeSlot) -> Option<crate::out::Converted> {
        match self.poll_on_this_thread(slot) {
            Polled::Ready(out) => Some(out),
            Polled::Gone => None,
            Polled::Pending => {
                let mut stage = self.fut.lock();
                if let Stage::Loop(_) = &*stage {
                    let Stage::Loop(mut fut) = std::mem::replace(&mut *stage, Stage::Gone) else {
                        unreachable!()
                    };
                    let task = self.clone();
                    let handle = slot.handle().spawn(async move {
                        // Every poll inside the fork gate (as `gate::Gated`,
                        // without boxing the boxed future again).
                        let out = std::future::poll_fn(|cx| {
                            let _gate = gate::enter();
                            fut.as_mut().poll(cx)
                        })
                        .await;
                        let completer = task.completer.clone();
                        completer.push(Completion::Done(task, out));
                    });
                    *stage = Stage::Spawned(handle.abort_handle());
                }
                None
            }
        }
    }

    /// Resolve the asyncio future with `out` (on the loop thread), unless
    /// it was cancelled meanwhile.
    fn resolve(&self, py: Python<'_>, out: crate::out::Converted) -> PyResult<()> {
        let Some(fut) = self.py_future.get() else {
            return Ok(());
        };
        let fut = fut.bind(py);
        if fut.call_method0(pyo3::intern!(py, "done"))?.is_truthy()? {
            return Ok(());
        }
        set_outcome(py, fut, out.into_pyobject(py))
    }

    /// The asyncio future was cancelled: drop the Rust future (cancelling
    /// the operation) or abort the tokio task driving it.
    fn cancel(&self, py: Python<'_>) {
        let stage = std::mem::replace(&mut *self.fut.lock(), Stage::Gone);
        match stage {
            Stage::Loop(fut) => {
                // Drop handlers may wait (locks) or need the runtime context.
                let slot = runtime();
                py.detach(move || {
                    let _gate = gate::enter();
                    let _ctx = slot.handle().enter();
                    drop(fut);
                });
            }
            Stage::Spawned(abort) => abort.abort(),
            Stage::Gone => {}
        }
    }
}

/// `add_done_callback` hook: cancels the Rust side when the asyncio future
/// is cancelled.
#[pyclass(frozen)]
struct CancelOnDone(Arc<Task>);

#[pymethods]
impl CancelOnDone {
    fn __call__(&self, py: Python<'_>, fut: &Bound<'_, PyAny>) -> PyResult<()> {
        if fut
            .call_method0(pyo3::intern!(py, "cancelled"))?
            .is_truthy()?
        {
            self.0.cancel(py);
        }
        Ok(())
    }
}

/// Work for the event-loop thread.
enum Completion {
    /// The task was woken: poll it again.
    Poll(Arc<Task>),
    /// The task's tokio side finished: resolve its asyncio future.
    Done(Arc<Task>, crate::out::Converted),
}

/// The completion queue of one event loop, with the file descriptor the
/// loop watches (`add_reader`) to learn that the queue is not empty.
struct Completer {
    queue: parking_lot::Mutex<Vec<Completion>>,
    /// Whether the descriptor has been signalled since the loop last
    /// drained the queue: one `write` per batch of completions.
    signaled: AtomicBool,
    notify: Notifier,
    /// Fork generation that created it (the descriptor is shared with the
    /// parent after a fork).
    generation: u64,
}

impl Completer {
    fn push(&self, c: Completion) {
        self.queue.lock().push(c);
        // AcqRel RMW on both sides (see `CompletionReader::__call__`): if
        // this sees `true`, the loop's later swap to `false` synchronises
        // with it and its drain sees the item just pushed.
        if !self.signaled.swap(true, Ordering::AcqRel) {
            self.notify.signal();
        }
    }
}

/// The loop's `add_reader` callback: drains the queue on the loop thread.
#[pyclass(frozen)]
struct CompletionReader(Arc<Completer>);

#[pymethods]
impl CompletionReader {
    fn __call__(&self, py: Python<'_>) -> PyResult<()> {
        let completer = &self.0;
        completer.notify.drain();
        completer.signaled.swap(false, Ordering::AcqRel);
        let items = std::mem::take(&mut *completer.queue.lock());
        if items.is_empty() {
            return Ok(());
        }
        let slot = runtime();
        let mut first_err = None;
        for item in items {
            let r = match item {
                Completion::Poll(task) => {
                    task.scheduled.store(false, Ordering::Release);
                    match py.detach(|| task.poll_or_spawn(&slot)) {
                        Some(out) => task.resolve(py, out),
                        None => Ok(()),
                    }
                }
                Completion::Done(task, out) => task.resolve(py, out),
            };
            // Keep resolving the others; report the first failure to the
            // loop's exception handler.
            if let Err(e) = r {
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    }
}

/// A non-blocking, close-on-exec descriptor pair to wake the event loop.
#[cfg(unix)]
struct Notifier {
    read_fd: std::os::fd::OwnedFd,
    /// `None` for an eventfd (read and write on the same descriptor).
    write_fd: Option<std::os::fd::OwnedFd>,
}

#[cfg(unix)]
impl Notifier {
    fn new() -> std::io::Result<Self> {
        use std::os::fd::FromRawFd;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // SAFETY: plain syscall; the result is checked before use.
            let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: `fd` is a new descriptor owned by nothing else.
            let read_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
            Ok(Notifier {
                read_fd,
                write_fd: None,
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let mut fds = [0 as libc::c_int; 2];
            // SAFETY: `fds` has room for the two descriptors `pipe` writes.
            if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: both descriptors are new and owned by nothing else.
            let (r, w) = unsafe {
                (
                    std::os::fd::OwnedFd::from_raw_fd(fds[0]),
                    std::os::fd::OwnedFd::from_raw_fd(fds[1]),
                )
            };
            for fd in [fds[0], fds[1]] {
                // SAFETY: fcntl on descriptors owned above.
                unsafe {
                    let fl = libc::fcntl(fd, libc::F_GETFL);
                    libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
                    libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                }
            }
            Ok(Notifier {
                read_fd: r,
                write_fd: Some(w),
            })
        }
    }

    fn raw_read_fd(&self) -> i32 {
        use std::os::fd::AsRawFd;
        self.read_fd.as_raw_fd()
    }

    /// Make the descriptor readable (from any thread).
    fn signal(&self) {
        use std::os::fd::AsRawFd;
        let fd = self.write_fd.as_ref().unwrap_or(&self.read_fd).as_raw_fd();
        let one: u64 = 1;
        // An eventfd takes an 8-byte counter increment; for a pipe any byte
        // will do (the first of `one`). EAGAIN (pipe full, counter at max)
        // means it is readable already.
        let len = if self.write_fd.is_some() { 1 } else { 8 };
        // SAFETY: writes `len <= 8` bytes from a live local `u64`.
        let _ = unsafe { libc::write(fd, (&raw const one).cast(), len) };
    }

    /// Consume the readiness (on the loop thread).
    fn drain(&self) {
        let mut buf = [0u8; 64];
        loop {
            // SAFETY: reads at most `buf.len()` bytes into a live buffer.
            let n = unsafe { libc::read(self.raw_read_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            // An eventfd is reset by one read; a pipe is read until empty.
            if n <= 0 || self.write_fd.is_none() {
                break;
            }
        }
    }
}

/// Never constructed off Unix ([`register_completer`] returns `None`).
#[cfg(not(unix))]
struct Notifier;

#[cfg(not(unix))]
impl Notifier {
    fn raw_read_fd(&self) -> i32 {
        -1
    }
    fn signal(&self) {}
    fn drain(&self) {}
}

/// A loop with its completer (`None`: the loop has no `add_reader`).
type LoopEntry = (Py<PyAny>, Option<Arc<Completer>>);

thread_local! {
    /// The event loops this thread ran async calls on, with their
    /// completers; normally one. Holding each loop keeps its identity unique
    /// while listed. Entries are pruned when their loop is closed.
    static LOOPS: std::cell::RefCell<Vec<LoopEntry>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// The completer registered with `event_loop` (the running loop of this
/// thread), creating and registering one on first use; `None` when the loop
/// cannot watch file descriptors.
///
/// A loop keeps its completer while it is open, even when the thread runs
/// another loop meanwhile: futures pending on it still complete when it
/// runs again.
fn completer_for(
    py: Python<'_>,
    event_loop: &Bound<'_, PyAny>,
) -> PyResult<Option<Arc<Completer>>> {
    let generation = fork_generation();
    let hit = LOOPS.with(|l| {
        let l = l.borrow();
        let (_, comp) = l.iter().find(|(lp, _)| lp.bind(py).is(event_loop))?;
        comp.as_ref()
            .is_none_or(|c| c.generation == generation)
            .then(|| comp.clone())
    });
    if let Some(c) = hit {
        return Ok(c);
    }
    // Miss (rare): drop entries of closed loops and of a parent process,
    // then register with this loop.
    let stale: Vec<LoopEntry> = LOOPS.with(|l| {
        let mut l = l.borrow_mut();
        let mut stale = Vec::new();
        let mut i = 0;
        while i < l.len() {
            let (lp, comp) = &l[i];
            let inherited = comp.as_ref().is_some_and(|c| c.generation != generation);
            let closed = lp
                .bind(py)
                .call_method0(pyo3::intern!(py, "is_closed"))
                .and_then(|v| v.is_truthy())
                .unwrap_or(true);
            if inherited || closed {
                stale.push(l.swap_remove(i));
            } else {
                i += 1;
            }
        }
        stale
    });
    for (_, comp) in stale {
        let Some(comp) = comp else { continue };
        if comp.generation != generation {
            // Inherited across a fork: the parent may still use the
            // descriptor and the loop's selector; touch neither.
            std::mem::forget(comp);
            continue;
        }
        // Completions that a closed loop will never process: dropping them
        // breaks the task <-> completer reference cycle.
        let orphans = std::mem::take(&mut *comp.queue.lock());
        drop(orphans);
    }
    let completer = register_completer(event_loop, generation)?;
    LOOPS.with(|l| {
        l.borrow_mut()
            .push((event_loop.clone().unbind(), completer.clone()))
    });
    Ok(completer)
}

#[cfg(unix)]
fn register_completer(
    event_loop: &Bound<'_, PyAny>,
    generation: u64,
) -> PyResult<Option<Arc<Completer>>> {
    let py = event_loop.py();
    let notify = Notifier::new()?;
    let fd = notify.raw_read_fd();
    let completer = Arc::new(Completer {
        queue: parking_lot::Mutex::new(Vec::new()),
        signaled: AtomicBool::new(false),
        notify,
        generation,
    });
    let reader = Bound::new(py, CompletionReader(completer.clone()))?;
    match event_loop.call_method1(pyo3::intern!(py, "add_reader"), (fd, reader)) {
        Ok(_) => Ok(Some(completer)),
        Err(e) if e.is_instance_of::<pyo3::exceptions::PyNotImplementedError>(py) => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(not(unix))]
fn register_completer(
    _event_loop: &Bound<'_, PyAny>,
    _generation: u64,
) -> PyResult<Option<Arc<Completer>>> {
    Ok(None)
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
        let out = run_with_signal_checks(&slot, fut, Duration::from_millis(40), false, || {
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
        let err = run_with_signal_checks(&slot, fut, Duration::from_millis(20), false, || {
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

    /// Cost of the thread hops an awaited local call makes, printed (run
    /// with `cargo test -p fsfast-py --release -- --ignored --nocapture
    /// hop_costs`): a blocking-pool round trip from a plain thread, and an
    /// eventfd wake-up of a thread sleeping in `epoll_wait` (what waking the
    /// event loop costs).
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "timing printout, not a test"]
    fn hop_costs() {
        let slot = runtime();
        let n = 20_000u32;
        let t = Instant::now();
        for _ in 0..n {
            let h = slot.handle().spawn_blocking(|| ());
            slot.handle().block_on(h).unwrap();
        }
        let pool = t.elapsed() / n;

        let notify = Arc::new(Notifier::new().unwrap());
        let back = Arc::new(Notifier::new().unwrap());
        let wait = |fd: i32| {
            // SAFETY: epoll on descriptors owned by the notifiers above.
            unsafe {
                let ep = libc::epoll_create1(libc::EPOLL_CLOEXEC);
                let mut ev = libc::epoll_event {
                    events: libc::EPOLLIN as u32,
                    u64: 0,
                };
                libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev);
                ep
            }
        };
        let (n2, b2) = (notify.clone(), back.clone());
        let peer = std::thread::spawn(move || {
            let ep = wait(n2.raw_read_fd());
            let mut ev = libc::epoll_event { events: 0, u64: 0 };
            for _ in 0..n {
                // SAFETY: waits on the epoll instance created above.
                unsafe { libc::epoll_wait(ep, &mut ev, 1, -1) };
                n2.drain();
                b2.signal();
            }
        });
        let ep = wait(back.raw_read_fd());
        let mut ev = libc::epoll_event { events: 0, u64: 0 };
        let t = Instant::now();
        for _ in 0..n {
            notify.signal();
            // SAFETY: waits on the epoll instance created above.
            unsafe { libc::epoll_wait(ep, &mut ev, 1, -1) };
            back.drain();
        }
        let eventfd_rtt = t.elapsed() / n;
        peer.join().unwrap();
        eprintln!(
            "blocking-pool round trip: {pool:?}; eventfd+epoll ping-pong: {eventfd_rtt:?} \
             (one wake-up is about half)"
        );
    }

    #[test]
    fn sync_executor_inlines_blocking_steps_only_when_asked() {
        let slot = runtime();
        let me = std::thread::current().id();
        fn step() -> impl Future<Output = fsfast_core::Result<std::thread::ThreadId>> + Send {
            fsfast_core::blocking(|| Ok(std::thread::current().id()))
        }
        // Single operation: the step runs on this (the calling) thread.
        assert_eq!(drive_with(&slot, step(), true).unwrap().unwrap(), me);
        // Batch / default: the blocking pool.
        assert_ne!(drive_with(&slot, step(), false).unwrap().unwrap(), me);
        assert_ne!(drive(&slot, step()).unwrap().unwrap(), me);
        // The flag does not outlive the call.
        assert!(!fsfast_core::blocking::inline_allowed());
        // From inside a runtime context the helper thread drives the
        // future; inline steps run there, never on a runtime worker.
        let on_worker = slot.handle().block_on(async {
            tokio::spawn(async move {
                let worker = std::thread::current().id();
                let ran = drive_with(&runtime(), step(), true).unwrap().unwrap();
                (worker, ran)
            })
            .await
            .unwrap()
        });
        assert_ne!(on_worker.0, on_worker.1);
    }

    // ---- async completion (spawn_async) -----------------------------------

    use std::collections::HashSet;
    use std::sync::Mutex;

    use crate::out::{Converted, PyOut};

    /// Ids of test futures that were dropped before completing.
    static DROPPED: Mutex<Option<HashSet<u64>>> = Mutex::new(None);

    struct DropMark(u64, bool);

    impl Drop for DropMark {
        fn drop(&mut self) {
            if !self.1 {
                DROPPED
                    .lock()
                    .unwrap()
                    .get_or_insert_with(HashSet::new)
                    .insert(self.0);
            }
        }
    }

    fn converted(out: fsfast_core::Result<PyOut>) -> Converted {
        Converted {
            out,
            backend: crate::registry::lookup("memory").unwrap(),
        }
    }

    /// A test operation awaited from Python: `kind` selects its shape.
    #[pyfunction]
    fn op<'py>(py: Python<'py>, kind: String, id: u64) -> PyResult<Bound<'py, PyAny>> {
        let fut: OpFuture = Box::pin(async move {
            let mut mark = DropMark(id, false);
            let out = match kind.as_str() {
                // Completes in the first poll.
                "ready" => Ok(PyOut::Str(format!("ready{id}"))),
                // One blocking-pool step: resolved by the loop-thread poll.
                "hop" => {
                    let v = tokio::task::spawn_blocking(move || id * 2).await.unwrap();
                    Ok(PyOut::Str(format!("hop{v}")))
                }
                // Several steps: handed over to a tokio task.
                "steps" => {
                    for _ in 0..3 {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    Ok(PyOut::Str(format!("steps{id}")))
                }
                "error" => {
                    tokio::task::spawn_blocking(|| ()).await.unwrap();
                    Err(fsfast_core::Error::not_found(format!("/missing/{id}")))
                }
                // Never wakes: cancelled while on the loop thread.
                "never" => std::future::pending().await,
                // Wakes once, then never: cancelled while on tokio.
                "wake_then_never" => {
                    tokio::task::yield_now().await;
                    tokio::task::yield_now().await;
                    std::future::pending().await
                }
                other => panic!("unknown kind {other}"),
            };
            mark.1 = true;
            converted(out)
        });
        spawn_async(py, fut)
    }

    #[pyfunction]
    fn dropped(id: u64) -> bool {
        DROPPED
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|s| s.contains(&id))
    }

    #[pyfunction]
    fn loops_known() -> usize {
        LOOPS.with(|l| l.borrow().len())
    }

    /// Run `code` with `op`, `dropped` and `loops_known` in its globals.
    fn run_py(code: &std::ffi::CStr) {
        Python::attach(|py| {
            let g = pyo3::types::PyDict::new(py);
            g.set_item("op", wrap_pyfunction!(op, py).unwrap()).unwrap();
            g.set_item("dropped", wrap_pyfunction!(dropped, py).unwrap())
                .unwrap();
            g.set_item("loops_known", wrap_pyfunction!(loops_known, py).unwrap())
                .unwrap();
            if let Err(e) = py.run(code, Some(&g), None) {
                e.display(py);
                panic!("python failed: {e}");
            }
        });
    }

    #[test]
    fn async_results_errors_and_hand_off() {
        run_py(
            c"
import asyncio
async def main():
    assert await op('ready', 1) == 'ready1'
    assert await op('hop', 2) == 'hop4'
    assert await op('steps', 3) == 'steps3'
    try:
        await op('error', 4)
    except FileNotFoundError as e:
        assert '/missing/4' in str(e)
    else:
        raise AssertionError('no error')
    kinds = ['ready', 'hop', 'steps']
    got = await asyncio.gather(*(op(kinds[i % 3], i) for i in range(3000)))
    want = [('ready%d', 'hop%d', 'steps%d')[i % 3] % (i * 2 if i % 3 == 1 else i)
            for i in range(3000)]
    assert got == want
asyncio.run(main())
",
        );
    }

    #[test]
    fn async_without_a_running_loop_raises_before_polling() {
        run_py(
            c"
try:
    op('never', 900)
except RuntimeError:
    pass
else:
    raise AssertionError('no RuntimeError')
assert not dropped(900)
",
        );
    }

    #[test]
    fn cancelling_drops_the_rust_future_in_both_stages() {
        run_py(
            c"
import asyncio, time
async def main():
    for kind, i in (('never', 101), ('wake_then_never', 102)):
        try:
            await asyncio.wait_for(op(kind, i), 0.05)
        except asyncio.TimeoutError:
            pass
        else:
            raise AssertionError('completed')
        deadline = time.monotonic() + 5
        while not dropped(i):
            assert time.monotonic() < deadline, f'{kind} future not dropped'
            await asyncio.sleep(0.01)
    # A cancelled task does not disturb others completing in the same batch.
    t = asyncio.ensure_future(op('hop', 103))
    t.cancel()
    assert await op('hop', 104) == 'hop208'
asyncio.run(main())
",
        );
    }

    #[test]
    fn loops_alternating_on_one_thread_keep_their_completions() {
        run_py(
            c"
import asyncio
async def call(kind, i):
    return await op(kind, i)
a = asyncio.new_event_loop()
b = asyncio.new_event_loop()
try:
    # A background operation on loop a, still pending when b runs.
    ta = a.create_task(call('steps', 201))
    a.run_until_complete(asyncio.sleep(0))
    assert not ta.done()
    assert b.run_until_complete(call('hop', 202)) == 'hop404'
    assert a.run_until_complete(ta) == 'steps201'
    assert a.run_until_complete(call('hop', 203)) == 'hop406'
finally:
    a.close()
    b.close()
# Closed loops are forgotten on the next new loop; repeated asyncio.run
# calls do not accumulate.
for i in range(50):
    assert asyncio.run(call('hop', 300 + i)) == 'hop%d' % (2 * (300 + i))
assert loops_known() <= 2, loops_known()
",
        );
    }

    #[test]
    fn event_loops_on_several_threads() {
        run_py(
            c"
import asyncio, threading
errors = []
def worker(k):
    try:
        async def main():
            r = await asyncio.gather(*(op('hop', k * 1000 + i) for i in range(300)))
            assert r == ['hop%d' % (2 * (k * 1000 + i)) for i in range(300)]
        asyncio.run(main())
    except BaseException as e:
        errors.append(e)
ts = [threading.Thread(target=worker, args=(k,)) for k in range(4)]
for t in ts: t.start()
for t in ts: t.join()
assert not errors, errors
",
        );
    }
}
