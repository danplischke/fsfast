//! Host key policy against the real server key: known_hosts with the right
//! key (plain, hashed, wildcard, HostKeyAlias), a wrong key, a revoked key,
//! only other key types, and an empty file, under each `host_key_policy`.
//! Gated on `FSFAST_TEST_SFTP_HOST`; needs the server's public host key at
//! `$FSFAST_TEST_STATE/sftp/hostkey.pub`.
//!
//! Every scenario runs in one test, sequentially, because keys accepted by
//! `auto_add` are remembered process-wide.

mod common;

use std::path::Path;

use base64::Engine as _;
use fsfast_core::{Detail, ErrorKind, FileSystem, Value};
use fsfast_sftp::ssh::known_hosts::forget_learned_keys;
use hmac::{Hmac, KeyInit, Mac};

/// Some other ed25519 key and an ecdsa key (public halves).
const OTHER_ED25519: &str = "AAAAC3NzaC1lZDI1NTE5AAAAILRE8DSyFxEgdZMM4miMVjqM5YgT1bwkzz5XRrp95Nyg";
const OTHER_ECDSA: &str = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFKcB7s+J+rjvBRb2Mld/UCy1ftO9/9jAZYod3XRAoYsQfCvu0xWBC+W5jfOwpfzFDKaZJCcRQuyhoMqftIA7oY=";

fn hashed(name: &str) -> String {
    let salt = b"fsfast-known-hosts-salt!";
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(salt).unwrap();
    mac.update(name.as_bytes());
    let b64 = base64::engine::general_purpose::STANDARD;
    format!(
        "|1|{}|{}",
        b64.encode(salt),
        b64.encode(mac.finalize().into_bytes())
    )
}

fn code(e: &fsfast_core::Error) -> Option<String> {
    e.details().iter().find_map(|d| match d {
        Detail::Code(c) => Some(c.clone()),
        _ => None,
    })
}

async fn try_connect(
    env: &common::Env,
    kh: &Path,
    policy: &str,
    extra: &[(&str, Value)],
) -> fsfast_core::Result<()> {
    let mut opts = vec![
        ("known_hosts", Value::Str(kh.display().to_string())),
        ("host_key_policy", Value::Str(policy.into())),
    ];
    opts.extend_from_slice(extra);
    let fs = env.fs(&opts);
    fs.info(&env.home).await.map(|_| ())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_key_policies() {
    let Some(env) = common::env() else { return };
    let pubfile = env.state.join("sftp/hostkey.pub");
    let Ok(line) = std::fs::read_to_string(&pubfile) else {
        eprintln!("skipping host key test: cannot read {}", pubfile.display());
        return;
    };
    let mut parts = line.split_whitespace();
    let (ktype, key) = (parts.next().unwrap(), parts.next().unwrap());
    let name = if env.port == 22 {
        env.host.clone()
    } else {
        format!("[{}]:{}", env.host, env.port)
    };
    let dir = tempfile::tempdir().unwrap();
    let kh = dir.path().join("known_hosts");
    let write = |text: String| std::fs::write(&kh, text).unwrap();

    let ok_cases = [
        ("plain entry", format!("{name} {ktype} {key}\n")),
        ("hashed entry", format!("{} {ktype} {key}\n", hashed(&name))),
        (
            "wildcard entry among others",
            format!(
                "# comment\nother.example {ktype} {OTHER_ED25519}\n[127.0.0.*]:{} {ktype} {key} trailing comment\n",
                env.port
            ),
        ),
        (
            "right key next to another key type",
            format!("{name} ecdsa-sha2-nistp256 {OTHER_ECDSA}\n{name} {ktype} {key}\n"),
        ),
    ];
    for (what, text) in ok_cases {
        write(text);
        for policy in ["auto_add", "warning", "reject"] {
            forget_learned_keys();
            try_connect(&env, &kh, policy, &[])
                .await
                .unwrap_or_else(|e| panic!("{what} with {policy}: {e}"));
        }
    }

    // A conflicting key for the host is rejected in every mode.
    for text in [
        format!("{name} {ktype} {OTHER_ED25519}\n"),
        format!("{} {ktype} {OTHER_ED25519}\n", hashed(&name)),
    ] {
        write(text);
        for policy in ["auto_add", "warning", "reject"] {
            forget_learned_keys();
            let e = try_connect(&env, &kh, policy, &[]).await.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::ConnectionFailed, "{policy}: {e}");
            assert_eq!(
                code(&e).as_deref(),
                Some("HostKeyMismatch"),
                "{policy}: {e}"
            );
            assert!(!e.is_retryable());
        }
    }

    // A revoked key is rejected even when also listed as known.
    write(format!("@revoked * {ktype} {key}\n{name} {ktype} {key}\n"));
    for policy in ["auto_add", "reject"] {
        forget_learned_keys();
        let e = try_connect(&env, &kh, policy, &[]).await.unwrap_err();
        assert_eq!(code(&e).as_deref(), Some("HostKeyRevoked"), "{policy}: {e}");
    }

    // Unknown host (empty file, or only another key type, or the entry is
    // for the default port): reject refuses, warning and auto_add accept.
    for text in [
        String::new(),
        format!("{name} ecdsa-sha2-nistp256 {OTHER_ECDSA}\n"),
        format!("{} {ktype} {key}\n", env.host),
    ] {
        write(text);
        forget_learned_keys();
        let e = try_connect(&env, &kh, "reject", &[]).await.unwrap_err();
        assert_eq!(code(&e).as_deref(), Some("HostKeyUnknown"), "{e}");
        try_connect(&env, &kh, "warning", &[]).await.unwrap();
        // warning did not remember the key...
        let e = try_connect(&env, &kh, "reject", &[]).await.unwrap_err();
        assert_eq!(code(&e).as_deref(), Some("HostKeyUnknown"), "{e}");
        // ...auto_add does, for the rest of the process, but a key it
        // accepted unverified never satisfies `reject`, which trusts only
        // the known-hosts files.
        try_connect(&env, &kh, "auto_add", &[]).await.unwrap();
        let e = try_connect(&env, &kh, "reject", &[]).await.unwrap_err();
        assert_eq!(code(&e).as_deref(), Some("HostKeyUnknown"), "{e}");
    }
    forget_learned_keys();

    // The default policy (no host_key_policy) is fsspec's auto_add.
    write(String::new());
    let fs = env.fs(&[("known_hosts", Value::Str(kh.display().to_string()))]);
    fs.info(&env.home).await.unwrap();
    forget_learned_keys();

    // known_hosts=False loads nothing: only auto_add/warning connect.
    let fs = env.fs(&[
        ("known_hosts", Value::Bool(false)),
        ("host_key_policy", "reject".into()),
    ]);
    assert_eq!(
        code(&fs.info("/").await.unwrap_err()).as_deref(),
        Some("HostKeyUnknown")
    );

    // HostKeyAlias from ssh_config: the key is looked up under the alias.
    let cfg = dir.path().join("config");
    std::fs::write(
        &cfg,
        format!(
            "Host *\n  HostKeyAlias fsfast-alias\n  UserKnownHostsFile {}\n",
            kh.display()
        ),
    )
    .unwrap();
    let alias_name = if env.port == 22 {
        "fsfast-alias".to_owned()
    } else {
        format!("[fsfast-alias]:{}", env.port)
    };
    write(format!(
        "{alias_name} {ktype} {key}\n{name} {ktype} {OTHER_ED25519}\n"
    ));
    let fs = env.fs(&[
        ("ssh_config", Value::Str(cfg.display().to_string())),
        ("host_key_policy", "reject".into()),
    ]);
    fs.info(&env.home).await.unwrap();
    // StrictHostKeyChecking=yes in ssh_config means reject when the option
    // is not given.
    std::fs::write(
        &cfg,
        format!(
            "Host *\n  StrictHostKeyChecking yes\n  UserKnownHostsFile {}\n  GlobalKnownHostsFile none\n",
            kh.display()
        ),
    )
    .unwrap();
    write(String::new());
    let fs = env.fs(&[("ssh_config", Value::Str(cfg.display().to_string()))]);
    assert_eq!(
        code(&fs.info("/").await.unwrap_err()).as_deref(),
        Some("HostKeyUnknown")
    );
    fs.close().await.unwrap();
}
