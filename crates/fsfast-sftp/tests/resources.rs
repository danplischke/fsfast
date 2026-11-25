//! Resource-leak checks against the local OpenSSH server: server file
//! handles of dropped/cancelled operations are released and TCP connections
//! go away after `close()`. Gated on `FSFAST_TEST_SFTP_HOST`.
//!
//! Server-side handles are observed through `/proc/<pid>/fd` of the
//! `sftp-server` processes (the test server runs on this machine), which
//! needs permission to read other processes' fd tables (root, or the same
//! user); the checks are skipped with a message otherwise.

mod common;

use std::collections::HashSet;
use std::path::Path;
use std::time::{Duration, Instant};

use bytes::Bytes;
use fsfast_core::{ByteRange, FileSystem, ReadOptions, WriteOptions};

/// Number of open fds of any SFTP server process that point at `file`, or
/// `None` when the fd tables cannot be read.
fn server_fds_on(file: &Path) -> Option<usize> {
    let mut n = 0;
    let mut saw_server = false;
    for e in std::fs::read_dir("/proc").ok()?.flatten() {
        let pid = e.file_name();
        let Some(pid) = pid
            .to_str()
            .filter(|p| p.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        let cmd = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        let cmd = String::from_utf8_lossy(&cmd);
        // `sftp-server`, or the per-session sshd process with
        // `Subsystem sftp internal-sftp` ("sshd: user@internal-sftp").
        if !(cmd.contains("sftp-server") || cmd.contains("@internal-sftp")) {
            continue;
        }
        saw_server = true;
        let fds = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path()).ok().as_deref() == Some(file) {
                n += 1;
            }
        }
    }
    saw_server.then_some(n)
}

/// Socket inodes of this process.
fn own_socket_inodes() -> HashSet<String> {
    let mut v = HashSet::new();
    if let Ok(rd) = std::fs::read_dir("/proc/self/fd") {
        for fd in rd.flatten() {
            if let Ok(t) = std::fs::read_link(fd.path()) {
                let t = t.to_string_lossy().into_owned();
                if let Some(i) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                    v.insert(i.to_owned());
                }
            }
        }
    }
    v
}

/// Established TCP connections of this process to `port`.
fn own_connections_to(port: u16) -> usize {
    let mine = own_socket_inodes();
    let mut n = 0;
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(table) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                continue;
            }
            let rport = f[2].rsplit(':').next().unwrap_or("");
            // 01 = ESTABLISHED.
            if u16::from_str_radix(rport, 16).ok() == Some(port)
                && f[3] == "01"
                && mine.contains(f[9])
            {
                n += 1;
            }
        }
    }
    n
}

/// The tests count this process's connections, so they must not overlap.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropped_and_cancelled_operations_release_server_handles() {
    let Some(env) = common::env() else { return };
    let _serial = SERIAL.lock().await;
    let fs = env.fs(&[]);
    let dir = env.dir("res");
    fs.mkdir(&dir, false).await.unwrap();
    let file = format!("{dir}/data.bin");
    fs.pipe_file(
        &file,
        Bytes::from(vec![7u8; 8 << 20]),
        &WriteOptions::default(),
    )
    .await
    .unwrap();
    let local = std::fs::canonicalize(&file).unwrap_or_else(|_| file.clone().into());
    let Some(base) = server_fds_on(&local) else {
        eprintln!("skipping handle checks: cannot read the sftp-server fd tables");
        common::rm_tree(&fs, &dir).await;
        return;
    };
    assert_eq!(base, 0);
    // The probe sees an open handle (so the checks below can fail).
    let held = fs.open_read(&file, &ReadOptions::default()).await.unwrap();
    assert_eq!(server_fds_on(&local), Some(1));
    held.close().await.unwrap();
    assert_eq!(server_fds_on(&local), Some(0));

    // Read handles dropped without close().
    for _ in 0..20 {
        let h = fs.open_read(&file, &ReadOptions::default()).await.unwrap();
        assert_eq!(h.read_at(1 << 20, 10).await.unwrap().len(), 10);
        drop(h);
    }
    // cat_file / open_read cancelled at many points of their round trips.
    for i in 0..40u64 {
        let d = Duration::from_micros(50 + i * 97);
        let _ = tokio::time::timeout(d, fs.cat_file(&file, ByteRange::Full)).await;
        let _ = tokio::time::timeout(d, fs.open_read(&file, &ReadOptions::default())).await;
    }
    // ls and cp_file cancelled while their directory/destination handle is
    // open on the server.
    let subdir = format!("{dir}/sub");
    fs.mkdir(&subdir, false).await.unwrap();
    for i in 0..300 {
        fs.pipe_file(
            &format!("{subdir}/entry-with-a-longish-name-{i:04}"),
            Bytes::new(),
            &WriteOptions::default(),
        )
        .await
        .unwrap();
    }
    let copy = format!("{dir}/copy.bin");
    for i in 0..40u64 {
        let d = Duration::from_micros(100 + i * 151);
        let _ = tokio::time::timeout(d, fs.ls(&subdir)).await;
        let _ = tokio::time::timeout(d * 4, fs.cp_file(&file, &copy)).await;
    }
    let subdir_local = std::fs::canonicalize(&subdir).unwrap();
    eventually(
        "the server closed every handle of the listed directory",
        || server_fds_on(&subdir_local) == Some(0),
    )
    .await;
    if let Ok(c) = std::fs::canonicalize(&copy) {
        eventually("the server closed every handle of the copy", || {
            server_fds_on(&c) == Some(0)
        })
        .await;
    }
    // Write handles dropped without close/abort.
    for i in 0..10 {
        let mut w = fs
            .open_write(&format!("{dir}/w{i}"), &WriteOptions::default())
            .await
            .unwrap();
        w.write(Bytes::from_static(b"partial")).await.unwrap();
        drop(w);
    }
    eventually("the server closed every handle of data.bin", || {
        server_fds_on(&local) == Some(0)
    })
    .await;
    for i in 0..10 {
        let w = std::fs::canonicalize(format!("{dir}/w{i}")).unwrap();
        eventually("the server closed the dropped write handles", || {
            server_fds_on(&w) == Some(0)
        })
        .await;
    }
    common::rm_tree(&fs, &dir).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_releases_tcp_connections() {
    let Some(env) = common::env() else { return };
    let _serial = SERIAL.lock().await;
    let before = own_connections_to(env.port);
    {
        let fs = env.fs(&[("connections", 3.into())]);
        // Concurrency grows the pool.
        let infos = futures::future::join_all((0..64).map(|_| fs.info(&env.home))).await;
        assert!(infos.iter().all(Result::is_ok));
        let h = fs.open_read(&env.home, &ReadOptions::default()).await;
        assert!(h.is_err(), "reading a directory must fail");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(own_connections_to(env.port) > before);
        fs.close().await.unwrap();
        assert_eq!(fs.connections(), 0);
        eventually("close() released every TCP connection", || {
            own_connections_to(env.port) == before
        })
        .await;
        // The filesystem reconnects lazily...
        assert!(fs.info(&env.home).await.unwrap().is_dir());
        assert_eq!(own_connections_to(env.port), before + 1);
    }
    // ...and dropping it releases the connection too.
    eventually("dropping the filesystem released its connection", || {
        own_connections_to(env.port) == before
    })
    .await;
}
