//! Scenarios the shared test server cannot show, against a private OpenSSH
//! server this test starts on a free port (and stops again):
//!
//! * keyboard-interactive only (`PasswordAuthentication no`): the client
//!   answers PAM's prompt with the password, as paramiko's fallback does;
//! * a host key that changes between connections: `auto_add` remembers the
//!   first key, and the second server key is rejected as a mismatch.
//!
//! Gated on `FSFAST_TEST_SFTP_HOST` (it uses the same test user); skipped
//! unless running as root with `/usr/sbin/sshd` and `ssh-keygen` available.

mod common;

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use fsfast_core::{Detail, ErrorKind, FileSystem, Value};

struct Sshd {
    child: Child,
    port: u16,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn hostkey(dir: &Path, name: &str) -> Option<PathBuf> {
    let p = dir.join(name);
    Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&p)
        .status()
        .ok()?
        .success()
        .then_some(p)
}

fn start(dir: &Path, port: u16, key: &Path) -> Option<Sshd> {
    let cfg = dir.join(format!("sshd_config_{port}"));
    std::fs::write(
        &cfg,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}/sshd_{port}.pid\n\
             PasswordAuthentication no\nKbdInteractiveAuthentication yes\nPubkeyAuthentication no\n\
             UsePAM yes\nStrictModes no\nSubsystem sftp internal-sftp\nLogLevel ERROR\n",
            key.display(),
            dir.display()
        ),
    )
    .ok()?;
    let child = Command::new("/usr/sbin/sshd")
        .args(["-D", "-e", "-f"])
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let sshd = Sshd { child, port };
    for _ in 0..200 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(sshd);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    None
}

fn code(e: &fsfast_core::Error) -> Option<String> {
    e.details().iter().find_map(|d| match d {
        Detail::Code(c) => Some(c.clone()),
        _ => None,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keyboard_interactive_and_changed_host_key() {
    let Some(env) = common::env() else { return };
    if !is_root() || !Path::new("/usr/sbin/sshd").exists() {
        eprintln!("skipping private sshd test: needs root and /usr/sbin/sshd");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (Some(key_a), Some(key_b)) = (hostkey(dir.path(), "a"), hostkey(dir.path(), "b")) else {
        eprintln!("skipping private sshd test: ssh-keygen failed");
        return;
    };
    let port = free_port();
    let Some(sshd) = start(dir.path(), port, &key_a) else {
        eprintln!("skipping private sshd test: sshd did not start");
        return;
    };
    let opts = |password: &str| {
        env.options(&[
            ("port", Value::Int(i64::from(port))),
            ("password", Value::Str(password.into())),
            ("known_hosts", Value::Bool(false)),
            ("host_key_policy", "auto_add".into()),
        ])
    };

    // Only keyboard-interactive is offered; the password answers it.
    let fs = fsfast_sftp::SftpFileSystem::from_options(opts(&env.password)).unwrap();
    assert!(fs.info(&env.home).await.unwrap().is_dir());
    fs.close().await.unwrap();
    let fs = fsfast_sftp::SftpFileSystem::from_options(opts("wrong")).unwrap();
    let e = fs.info(&env.home).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
    assert!(e.to_string().contains("keyboard-interactive"), "{e}");

    // The same address now presents another host key: auto_add learned the
    // first one, so this is a mismatch, not a new key.
    drop(sshd);
    let Some(_sshd) = start(dir.path(), port, &key_b) else {
        eprintln!("skipping the host key part: sshd did not restart");
        return;
    };
    let fs = fsfast_sftp::SftpFileSystem::from_options(opts(&env.password)).unwrap();
    let e = fs.info(&env.home).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ConnectionFailed, "{e}");
    assert_eq!(code(&e).as_deref(), Some("HostKeyMismatch"), "{e}");
}

fn is_root() -> bool {
    // Avoid a libc dependency: root's uid shows in /proc/self/status.
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(|u| u == "0"))
        })
        .unwrap_or(false)
}
