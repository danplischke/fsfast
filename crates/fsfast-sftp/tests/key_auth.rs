//! Public key authentication against the local OpenSSH server: OpenSSH,
//! PEM (PKCS#1/SEC1) and PKCS#8 keys, plain and encrypted, given as files
//! (`key_filename`, ssh_config `IdentityFile`), as text (`pkey`) or held by
//! an ssh-agent.
//!
//! Gated on `FSFAST_TEST_SFTP_HOST`. The test appends its own public keys
//! (tagged with a unique comment) to the test user's
//! `$FSFAST_TEST_STATE/sftp/home/.ssh/authorized_keys` and removes exactly
//! those lines afterwards; password authentication keeps working for
//! everyone else. It is skipped when that file cannot be written (needs to
//! run as root or as the test user) or `ssh-keygen` is missing.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use fsfast_core::{ErrorKind, FileSystem, Value};

const PASSPHRASE: &str = "correct horse battery";

/// Removes our lines from authorized_keys on drop (also on panic).
struct Installed {
    file: PathBuf,
    tag: String,
}

impl Drop for Installed {
    fn drop(&mut self) {
        if let Ok(text) = std::fs::read_to_string(&self.file) {
            let kept: String = text
                .lines()
                .filter(|l| !l.contains(&self.tag))
                .map(|l| format!("{l}\n"))
                .collect();
            let _ = std::fs::write(&self.file, kept);
        }
    }
}

fn keygen(dir: &Path, name: &str, args: &[&str], passphrase: &str, tag: &str) -> Option<PathBuf> {
    let path = dir.join(name);
    let ok = Command::new("ssh-keygen")
        .args(["-q", "-N", passphrase, "-C", tag, "-f"])
        .arg(&path)
        .args(args)
        .stdin(Stdio::null())
        .status()
        .ok()?
        .success();
    ok.then_some(path)
}

fn chown_to(path: &Path, like: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(like)?;
    std::os::unix::fs::chown(path, Some(m.uid()), Some(m.gid()))
}

/// Install `pubs` for the test user. `None` (skip) when not possible.
fn install(env: &common::Env, pubs: &[PathBuf], tag: &str) -> Option<Installed> {
    let home = PathBuf::from(&env.home);
    let ssh = home.join(".ssh");
    if !ssh.exists() {
        std::fs::create_dir(&ssh).ok()?;
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).ok()?;
        chown_to(&ssh, &home).ok()?;
    }
    let file = ssh.join("authorized_keys");
    let mut text = std::fs::read_to_string(&file).unwrap_or_default();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    for p in pubs {
        let mut pp = p.as_os_str().to_owned();
        pp.push(".pub");
        text.push_str(std::fs::read_to_string(PathBuf::from(pp)).ok()?.trim_end());
        text.push('\n');
    }
    std::fs::write(&file, text).ok()?;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).ok()?;
    chown_to(&file, &home).ok()?;
    Some(Installed {
        file,
        tag: tag.to_owned(),
    })
}

/// Options without a usable password: success proves key authentication.
fn key_opts<'a>(extra: &[(&'a str, Value)]) -> Vec<(&'a str, Value)> {
    let mut v = vec![
        ("password", Value::Null),
        ("allow_agent", Value::Bool(false)),
        ("look_for_keys", Value::Bool(false)),
    ];
    v.extend_from_slice(extra);
    v
}

async fn connect(env: &common::Env, extra: &[(&str, Value)]) -> fsfast_core::Result<()> {
    let mut o = env.options(extra);
    o.retain(|_, v| !v.is_null());
    let fs = fsfast_sftp::SftpFileSystem::from_options(o)?;
    let r = fs.info(&env.home).await.map(|_| ());
    fs.close().await.unwrap();
    r
}

struct Agent(Child, PathBuf);

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_file(&self.1);
    }
}

fn start_agent(dir: &Path) -> Option<Agent> {
    let sock = dir.join("agent.sock");
    let child = Command::new("ssh-agent")
        .arg("-D")
        .arg("-a")
        .arg(&sock)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let agent = Agent(child, sock.clone());
    for _ in 0..100 {
        if sock.exists() {
            return Some(agent);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_key_authentication() {
    let Some(env) = common::env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let tag = format!("fsfast-sftp-test-{}", common::unique("key"));
    let keys = [
        ("ed25519", vec!["-t", "ed25519"], ""),
        ("ed25519_enc", vec!["-t", "ed25519"], PASSPHRASE),
        ("rsa_openssh", vec!["-t", "rsa", "-b", "2048"], ""),
        ("rsa_pem", vec!["-t", "rsa", "-b", "2048", "-m", "PEM"], ""),
        (
            "rsa_pem_enc",
            vec!["-t", "rsa", "-b", "2048", "-m", "PEM"],
            PASSPHRASE,
        ),
        (
            "ecdsa_pkcs8",
            vec!["-t", "ecdsa", "-b", "256", "-m", "PKCS8"],
            "",
        ),
        (
            "ecdsa_pkcs8_enc",
            vec!["-t", "ecdsa", "-b", "256", "-m", "PKCS8"],
            PASSPHRASE,
        ),
        ("not_installed", vec!["-t", "ed25519"], ""),
    ];
    let mut paths = Vec::new();
    for (name, args, pass) in &keys {
        let Some(p) = keygen(d, name, args, pass, &tag) else {
            eprintln!("skipping key auth test: ssh-keygen failed or is missing");
            return;
        };
        paths.push((name.to_string(), p, !pass.is_empty()));
    }
    let installed: Vec<PathBuf> = paths
        .iter()
        .filter(|(n, _, _)| n != "not_installed")
        .map(|(_, p, _)| p.clone())
        .collect();
    let Some(_guard) = install(&env, &installed, &tag) else {
        eprintln!("skipping key auth test: cannot write the test user's authorized_keys");
        return;
    };

    for (name, path, encrypted) in &paths {
        if name == "not_installed" {
            continue;
        }
        let kf = Value::Str(path.display().to_string());
        let pass = if *encrypted {
            Value::Str(PASSPHRASE.into())
        } else {
            Value::Null
        };
        connect(
            &env,
            &key_opts(&[("key_filename", kf.clone()), ("passphrase", pass.clone())]),
        )
        .await
        .unwrap_or_else(|e| panic!("key_filename {name}: {e}"));
        // The same key given as text.
        let text = std::fs::read_to_string(path).unwrap();
        connect(
            &env,
            &key_opts(&[("pkey", Value::Str(text)), ("passphrase", pass)]),
        )
        .await
        .unwrap_or_else(|e| panic!("pkey {name}: {e}"));
        if *encrypted {
            // paramiko falls back to the password as passphrase.
            connect(
                &env,
                &key_opts(&[
                    ("key_filename", kf.clone()),
                    ("password", Value::Str(PASSPHRASE.into())),
                ]),
            )
            .await
            .unwrap_or_else(|e| panic!("{name} unlocked with the password: {e}"));
            // No passphrase: the key is skipped and nothing else works.
            let e = connect(&env, &key_opts(&[("key_filename", kf.clone())]))
                .await
                .unwrap_err();
            assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{name}: {e}");
            assert!(e.to_string().contains("encrypted"), "{name}: {e}");
            let e = connect(
                &env,
                &key_opts(&[("key_filename", kf), ("passphrase", "wrong".into())]),
            )
            .await
            .unwrap_err();
            assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{name}: {e}");
        }
    }

    let by_name = |n: &str| {
        paths
            .iter()
            .find(|(name, _, _)| name == n)
            .map(|(_, p, _)| p.clone())
            .unwrap()
    };
    // An unknown key is rejected; the next candidate (a list of files)
    // still gets its turn.
    let e = connect(
        &env,
        &key_opts(&[(
            "key_filename",
            by_name("not_installed").display().to_string().into(),
        )]),
    )
    .await
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    connect(
        &env,
        &key_opts(&[(
            "key_filename",
            Value::List(vec![
                by_name("not_installed").display().to_string().into(),
                d.join("missing-key").display().to_string().into(),
                by_name("ed25519").display().to_string().into(),
            ]),
        )]),
    )
    .await
    .unwrap();

    // RSA signature algorithm selection honours disabled_algorithms.
    let rsa = by_name("rsa_pem").display().to_string();
    let disable = |names: &[&str]| {
        Value::Map(
            [(
                "pubkeys".to_owned(),
                Value::List(names.iter().map(|n| Value::Str((*n).into())).collect()),
            )]
            .into_iter()
            .collect(),
        )
    };
    connect(
        &env,
        &key_opts(&[
            ("key_filename", rsa.clone().into()),
            ("disabled_algorithms", disable(&["rsa-sha2-512"])),
        ]),
    )
    .await
    .unwrap();
    let e = connect(
        &env,
        &key_opts(&[
            ("key_filename", rsa.into()),
            (
                "disabled_algorithms",
                disable(&["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]),
            ),
        ]),
    )
    .await
    .unwrap_err();
    assert!(e.to_string().contains("disabled"), "{e}");

    // ssh_config IdentityFile.
    let cfg = d.join("config");
    std::fs::write(
        &cfg,
        format!(
            "Host *\n  IdentityFile {}\n",
            by_name("ecdsa_pkcs8").display()
        ),
    )
    .unwrap();
    connect(
        &env,
        &key_opts(&[("ssh_config", cfg.display().to_string().into())]),
    )
    .await
    .unwrap();

    // ssh-agent (socket from ssh_config IdentityAgent, so the test does not
    // touch the process environment).
    let Some(agent) = start_agent(d) else {
        eprintln!("ssh-agent not available: skipping the agent part");
        return;
    };
    let added = Command::new("ssh-add")
        .arg(by_name("rsa_openssh"))
        .env("SSH_AUTH_SOCK", &agent.1)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(added, "ssh-add failed");
    std::fs::write(
        &cfg,
        format!("Host *\n  IdentityAgent {}\n", agent.1.display()),
    )
    .unwrap();
    connect(
        &env,
        &[
            ("password", Value::Null),
            ("allow_agent", Value::Bool(true)),
            ("look_for_keys", Value::Bool(false)),
            ("ssh_config", cfg.display().to_string().into()),
        ],
    )
    .await
    .unwrap();
    // allow_agent=False ignores it.
    let e = connect(
        &env,
        &key_opts(&[("ssh_config", cfg.display().to_string().into())]),
    )
    .await
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    // IdentitiesOnly: agent keys that match no IdentityFile are not used.
    std::fs::write(
        &cfg,
        format!(
            "Host *\n  IdentityAgent {}\n  IdentitiesOnly yes\n  IdentityFile {}\n",
            agent.1.display(),
            by_name("not_installed").display()
        ),
    )
    .unwrap();
    let e = connect(
        &env,
        &[
            ("password", Value::Null),
            ("allow_agent", Value::Bool(true)),
            ("look_for_keys", Value::Bool(false)),
            ("ssh_config", cfg.display().to_string().into()),
        ],
    )
    .await
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
    drop(agent);
}
