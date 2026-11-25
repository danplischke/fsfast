//! fsspec-compatible SFTP filesystem for fsfast.
//!
//! [`SftpFileSystem`] (alias [`SFTPFileSystem`]) replaces fsspec's
//! `fsspec.implementations.sftp.SFTPFileSystem` (paramiko): the same
//! `storage_options`, the same paths, the same `info()` keys and the same
//! directory semantics, on a native client built for throughput:
//!
//! * **SSH transport: russh** (client only), AEAD ciphers preferred
//!   (`aes128-gcm@openssh.com`, `aes256-gcm@openssh.com`,
//!   `chacha20-poly1305@openssh.com`, all through aws-lc), a 64 MiB channel
//!   window and 64 KiB packets so the window never throttles a pipelined
//!   transfer.
//! * **SFTP v3 codec written here** ([`proto`]), as OpenSSH implements it,
//!   with the `limits@openssh.com`, `posix-rename@openssh.com`,
//!   `statvfs@openssh.com`, `fsync@openssh.com`, `hardlink@openssh.com`,
//!   `lsetstat@openssh.com`, `copy-data`, `expand-path@openssh.com` and
//!   `home-directory` extensions. Decoders are total (property-tested).
//! * **Pipelining everywhere** ([`session`]): a request-id completion map
//!   with any number of requests in flight; a writer task that coalesces
//!   small requests into one SSH packet; a reader task that never copies
//!   READ data. Reads keep an adaptive window of up to `max_inflight`
//!   (default 64) READs of the server's maximum size (255 KiB on OpenSSH)
//!   in flight and reassemble out-of-order and short replies; writes keep
//!   up to 64 WRITEs in flight; CLOSE goes out behind the last WRITE.
//!   Metadata operations are batched: `open_read`/`cat_file` send STAT and
//!   OPEN together, `ls` pipelines READDIRs and does not wait for CLOSE,
//!   `mkdir(create_parents=True)` sends all MKDIRs at once, `rm_files`
//!   pipelines its REMOVEs, `touch` sends OPEN, FSETSTAT and CLOSE in two
//!   round trips.
//! * **A pool of SSH connections** ([`pool`]), one SFTP channel each,
//!   growing in the background under concurrent load (up to `connections`,
//!   default 4), so parallel many-file operations use several server
//!   processes and cores.
//!
//! # Options
//!
//! fsspec/paramiko names: `host` (required), `port`, `username`,
//! `password`, `pkey` (private key text), `key_filename`, `passphrase`,
//! `timeout`, `allow_agent`, `look_for_keys`, `compress`,
//! `banner_timeout`, `auth_timeout`, `channel_timeout`,
//! `disabled_algorithms`, `host_key_policy`, `temppath`, plus
//! `AbstractFileSystem`'s cache options (ignored). `sock`,
//! `transport_factory` and `auth_strategy` (Python objects) are rejected
//! when set. fsfast extensions: `known_hosts`, `ssh_config`,
//! `connections`, `max_inflight`, `read_chunk_size`, `write_chunk_size`,
//! `request_timeout`, `keepalive_interval`, `fsync_on_close`. See
//! [`SftpConfig`].
//!
//! Authentication follows paramiko's order (key, key files, agent,
//! `~/.ssh/id_*`, password, keyboard-interactive with the password); see
//! [`ssh::auth`]. `~/.ssh/config` and `/etc/ssh/ssh_config` are read
//! (`Host`/`Match`, `HostName`, `Port`, `User`, `IdentityFile`,
//! `IdentitiesOnly`, `IdentityAgent`, `UserKnownHostsFile`, `HostKeyAlias`,
//! `StrictHostKeyChecking`, `ConnectTimeout`, `Compression`,
//! `ServerAliveInterval`, `Include`); explicit options win. A configured
//! `ProxyJump`/`ProxyCommand` makes the connection fail with
//! `Unsupported` rather than bypass the jump host.
//!
//! # Host keys
//!
//! `host_key_policy` keeps fsspec's values and default (`auto_add`), but
//! unlike paramiko (which fsspec gives no known hosts at all) the
//! known-hosts files are consulted, and a key that conflicts with a
//! recorded one, or is `@revoked`, is rejected in every mode. See
//! [`ssh::known_hosts`].
//!
//! # `info()` records
//!
//! `{"name", "size", "type", "uid", "gid", "time", "mtime"}` exactly as
//! fsspec's `_decode_stat`: `type` is `"directory"`, `"file"` or (in `ls`
//! only, which shows `lstat` attributes) `"link"`; `time`/`mtime` are UTC
//! datetimes of the access and modification times. `info()` follows
//! symlinks (STAT), like fsspec. See [`info`].
//!
//! # Differences from fsspec's implementation
//!
//! * `info(name).name` is canonical (no trailing slash), as the fsfast core
//!   contract requires; fsspec echoes the path as given.
//! * `ls` of a file returns `[info(file)]` (the fsfast contract and fsspec's
//!   generic behaviour) instead of raising `FileNotFoundError`.
//! * Errors are more precise where OpenSSH's codes are vague, always as a
//!   subclass of the exception fsspec raises: `rmdir` of a non-empty
//!   directory raises `OSError(ENOTEMPTY)` (fsspec: `OSError` "Failure");
//!   `rm_file` of a directory and reading a directory raise
//!   `IsADirectoryError` (fsspec: `OSError` "Failure");
//!   `open(..., "xb")` of an existing file raises `FileExistsError`
//!   (fsspec: `OSError`). Where OpenSSH reports ENOTDIR (`rmdir` of a file,
//!   `mkdir`/`makedirs` below a regular file) the kind stays fsspec's
//!   `FileNotFoundError` and the message names the component that is not a
//!   directory. `makedirs(file, exist_ok=True)` raises `FileExistsError`
//!   (the fsfast core contract; fsspec silently returns).
//! * `cp_file` works (server-side with `copy-data`, else streamed); fsspec
//!   raises `NotImplementedError`. `touch(path, truncate=False)` of an
//!   existing file updates its times (fsspec: `NotImplementedError`).
//! * `mv_file` replaces an existing destination (posix-rename), as fsspec
//!   does on OpenSSH; without the extension the replacement is emulated
//!   (not atomic).
//! * `put_file` creates missing parent directories, as fsspec does, but
//!   only after the upload found them missing (no extra round trip).

#![warn(missing_docs)]

pub mod error;
mod fs;
pub mod handle;
pub mod info;
pub mod options;
pub mod pool;
pub mod proto;
pub mod session;
pub mod ssh;

pub use fs::{ConnectionInfo, SFTPFileSystem, SftpFileSystem};
pub use handle::{SftpReadHandle, SftpWriteHandle};
pub use info::INFO_KEYS;
pub use options::{SftpConfig, SshConfigSource, get_kwargs_from_urls, parent, strip_protocol};
pub use ssh::known_hosts::HostKeyPolicy;
