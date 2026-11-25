//! The local backend driven the way the Python bindings drive synchronous
//! calls: polled on a plain (non-worker) thread that allows inline blocking
//! (`fsfast_core::blocking::allow_inline`). Short operations must then
//! complete in their first poll, on the calling thread, and everything else
//! (fan-out, large transfers) must still work through the blocking pool.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use bytes::Bytes;
use fsfast_core::blocking::allow_inline;
use fsfast_core::{ByteRange, FileSystem, FindOptions, WriteOptions};
use fsfast_local::LocalFileSystem;
use fsfast_testkit::{SuiteConfig, assert_suite, check_names};

struct Unpark(std::thread::Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// A minimal sync executor like the bindings' one: polls on this thread with
/// inline blocking allowed, parks between wake-ups.
fn block_on_inline<F: Future>(rt: &tokio::runtime::Runtime, fut: F) -> F::Output {
    let _ctx = rt.enter();
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut fut = pin!(fut);
    loop {
        if let Poll::Ready(v) = allow_inline(true, || fut.as_mut().poll(&mut cx)) {
            return v;
        }
        std::thread::park_timeout(Duration::from_millis(50));
    }
}

/// Poll `fut` once with inline blocking allowed and a no-op waker.
fn first_poll<F: Future>(rt: &tokio::runtime::Runtime, fut: F) -> Poll<F::Output> {
    let _ctx = rt.enter();
    let mut cx = Context::from_waker(Waker::noop());
    let mut fut = pin!(fut);
    allow_inline(true, || fut.as_mut().poll(&mut cx))
}

/// A runtime whose blocking pool has a single thread, so that a test can
/// occupy it ([`occupy_pool`]): work sent to the pool then cannot finish,
/// while inline work still can.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap()
}

/// Occupy the pool's only thread until the returned guard is dropped.
fn occupy_pool(rt: &tokio::runtime::Runtime) -> impl Drop {
    struct Release(Option<std::sync::mpsc::Sender<()>>);
    impl Drop for Release {
        fn drop(&mut self) {
            let _ = self.0.take().unwrap().send(());
        }
    }
    let (busy_tx, busy_rx) = std::sync::mpsc::channel::<()>();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    rt.spawn_blocking(move || {
        busy_tx.send(()).unwrap();
        let _ = rx.recv();
    });
    busy_rx.recv().unwrap();
    Release(Some(tx))
}

fn root_of(dir: &tempfile::TempDir) -> String {
    let p = dir.path().to_str().expect("UTF-8 temp dir").to_owned();
    fsfast_local::strip_protocol(&p).into_owned()
}

#[test]
fn local_passes_the_suite_under_an_inline_executor() {
    let rt = runtime();
    let dir = tempfile::tempdir().unwrap();
    let root = root_of(&dir);
    let fs = LocalFileSystem::new();
    let cfg = SuiteConfig::default().large_file_bytes(12 << 20);
    let report = block_on_inline(&rt, assert_suite(Arc::new(fs), &root, cfg));
    assert_eq!(report.skipped().count(), 0, "{report}");
    assert_eq!(report.passed().count(), check_names().len());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn short_operations_complete_inline_in_the_first_poll() {
    let rt = runtime();
    let dir = tempfile::tempdir().unwrap();
    let root = root_of(&dir);
    let fs = LocalFileSystem::new();
    let f = format!("{root}/a.bin");
    let d = format!("{root}/sub");
    let wo = WriteOptions::default();
    // Nothing could complete through the pool: Ready means inline.
    let _busy = occupy_pool(&rt);

    let ready = |p: Poll<fsfast_core::Result<()>>, what: &str| match p {
        Poll::Ready(r) => r.unwrap_or_else(|e| panic!("{what}: {e}")),
        Poll::Pending => panic!("{what} did not complete inline"),
    };
    ready(
        first_poll(&rt, fs.pipe_file(&f, Bytes::from_static(b"hello"), &wo)),
        "pipe_file",
    );
    match first_poll(&rt, fs.info(&f)) {
        Poll::Ready(Ok(i)) => assert_eq!(i.size, 5),
        other => panic!("info: {other:?}"),
    }
    match first_poll(&rt, fs.cat_file(&f, ByteRange::Full)) {
        Poll::Ready(Ok(b)) => assert_eq!(&b[..], b"hello"),
        other => panic!("cat_file: {other:?}"),
    }
    match first_poll(&rt, fs.exists(&f)) {
        Poll::Ready(Ok(true)) => {}
        other => panic!("exists: {other:?}"),
    }
    ready(first_poll(&rt, fs.mkdir(&d, false)), "mkdir");
    match first_poll(&rt, fs.ls(&root)) {
        Poll::Ready(Ok(v)) => assert_eq!(v.len(), 2),
        other => panic!("ls: {other:?}"),
    }
    ready(first_poll(&rt, fs.rmdir(&d)), "rmdir");
    ready(first_poll(&rt, fs.touch(&f, false)), "touch");
    ready(first_poll(&rt, fs.rm_file(&f)), "rm_file");
    // Errors come back inline too.
    match first_poll(&rt, fs.info(&f)) {
        Poll::Ready(Err(e)) => assert_eq!(e.kind(), fsfast_core::ErrorKind::NotFound),
        other => panic!("info of a missing file: {other:?}"),
    }
}

#[test]
fn long_or_parallel_work_still_uses_the_pool() {
    let rt = runtime();
    let dir = tempfile::tempdir().unwrap();
    let root = root_of(&dir);
    let fs = LocalFileSystem::new();
    let wo = WriteOptions::default();

    // A payload above the inline limit is written on the pool.
    let big = Bytes::from(vec![7u8; 5 << 20]);
    let f = format!("{root}/big.bin");
    let g = format!("{root}/copy.bin");
    std::fs::write(dir.path().join("big.bin"), b"seed").unwrap();
    {
        // While the pool is busy, work sent to it stays pending (the
        // first polls below queue it; it runs once the pool is released).
        let _busy = occupy_pool(&rt);
        assert!(first_poll(&rt, fs.pipe_file(&f, big.clone(), &wo)).is_pending());
        // Copies of unknown size run on the pool.
        assert!(first_poll(&rt, fs.cp_file(&f, &g)).is_pending());
    }
    block_on_inline(&rt, fs.pipe_file(&f, big.clone(), &wo)).unwrap();
    block_on_inline(&rt, fs.cp_file(&f, &g)).unwrap();
    assert_eq!(std::fs::read(dir.path().join("copy.bin")).unwrap(), big);
    // A large cat_file opens inline, then reads its pieces in parallel.
    let big_read = Bytes::from(vec![9u8; 20 << 20]);
    block_on_inline(&rt, fs.pipe_file(&f, big_read.clone(), &wo)).unwrap();
    let got = block_on_inline(&rt, fs.cat_file(&f, ByteRange::Full)).unwrap();
    assert_eq!(got, big_read);

    // find lists sub-directories on the pool, in parallel.
    for i in 0..5 {
        std::fs::create_dir_all(dir.path().join(format!("d{i}/e"))).unwrap();
        std::fs::write(dir.path().join(format!("d{i}/e/f")), b"x").unwrap();
    }
    let opts = FindOptions {
        maxdepth: None,
        withdirs: false,
    };
    let found = block_on_inline(&rt, fs.find(&root, &opts)).unwrap();
    assert_eq!(found.len(), 2 + 5);
    // Several rm_files batches run on the pool; one batch runs inline.
    let make = |prefix: &str, n: usize| -> Vec<String> {
        (0..n)
            .map(|i| {
                let p = format!("{root}/{prefix}{i}");
                std::fs::write(&p, b"").unwrap();
                p
            })
            .collect()
    };
    {
        // (The pending first poll queues its batches on the pool; they
        // finish in the background once it is released.)
        let p = make("p", 100);
        let _busy = occupy_pool(&rt);
        assert!(first_poll(&rt, fs.rm_files(&p)).is_pending());
    }
    let r = block_on_inline(&rt, fs.rm_files(&make("m", 100)));
    assert!(r.iter().all(|r| r.is_ok()), "{r:?}");
    let s = make("s", 30);
    let _busy = occupy_pool(&rt);
    match first_poll(&rt, fs.rm_files(&s)) {
        Poll::Ready(v) => assert!(v.iter().all(|r| r.is_ok()), "{v:?}"),
        Poll::Pending => panic!("a single rm_files batch did not run inline"),
    }
}
