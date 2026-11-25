//! The SSH side: configuration files, host keys, authentication and the
//! russh connection that carries the SFTP subsystem.

pub mod auth;
pub mod config;
pub mod connect;
pub mod known_hosts;

use std::path::PathBuf;

/// Home directory of the local user: `$HOME`, else the passwd entry.
pub fn home_dir() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        return Some(PathBuf::from(h));
    }
    passwd_entry().map(|(_, home)| PathBuf::from(home))
}

/// Name of the local user, as Python's `getpass.getuser()` finds it (which
/// paramiko uses as the default `username`): `LOGNAME`, `USER`, `LNAME`,
/// `USERNAME`, then the passwd entry of the current uid.
pub fn local_user() -> Option<String> {
    for var in ["LOGNAME", "USER", "LNAME", "USERNAME"] {
        if let Ok(v) = std::env::var(var)
            && !v.is_empty()
        {
            return Some(v);
        }
    }
    passwd_entry().map(|(name, _)| name)
}

/// `(name, home)` of the current uid from `/etc/passwd`.
#[cfg(unix)]
fn passwd_entry() -> Option<(String, String)> {
    let uid = rustix::process::getuid().as_raw();
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 6 && f[2].parse::<u32>().ok() == Some(uid))
            .then(|| (f[0].to_owned(), f[5].to_owned()))
    })
}

#[cfg(not(unix))]
fn passwd_entry() -> Option<(String, String)> {
    None
}
