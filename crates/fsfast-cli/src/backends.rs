//! The compiled-in backends: protocol names, constructors, URL handling and
//! access to each backend's engine [`Stats`].
//!
//! [`BACKENDS`] is the one table that knows every backend crate; each entry
//! is gated by the cargo feature of the same name (all on by default).

use std::sync::Arc;

use fsfast_core::{DynFileSystem, Error, Options, Result};
use fsfast_engine::Stats;

/// A built filesystem plus its request counters, when the backend has them
/// (the in-process `file` and `memory` backends make no wire requests).
#[derive(Debug, Clone)]
pub struct Built {
    /// The filesystem.
    pub fs: DynFileSystem,
    /// Engine counters (`requests`, `retries`, `bytes_read`, ...).
    pub stats: Option<Arc<Stats>>,
}

/// Static description of one backend.
pub struct Backend {
    /// fsspec protocol names; the first is canonical.
    pub protocols: &'static [&'static str],
    /// The backend's strict `from_options`.
    pub build: fn(Options) -> Result<Built>,
    /// fsspec `_strip_protocol` of the backend.
    pub strip_protocol: fn(&str) -> String,
    /// fsspec `_get_kwargs_from_urls` of the backend (options inferred from
    /// the URL, e.g. SMB/SFTP `host`/`port`/`username`/`password`).
    pub url_options: fn(&str) -> Options,
    /// Whether the backend runs in-process without a network service (local
    /// disk, memory). Unscoped `--opt` values are not applied to these.
    pub in_process: bool,
}

impl Backend {
    /// Canonical protocol name.
    pub fn name(&self) -> &'static str {
        self.protocols[0]
    }
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backend")
            .field("protocols", &self.protocols)
            .finish_non_exhaustive()
    }
}

// Unused only in builds without the backends that infer nothing from URLs.
#[allow(dead_code)]
fn no_url_options(_: &str) -> Options {
    Options::new()
}

#[cfg(feature = "local")]
static LOCAL: Backend = Backend {
    protocols: &["file", "local"],
    build: |o| {
        Ok(Built {
            fs: Arc::new(fsfast_local::LocalFileSystem::from_options(o)?),
            stats: None,
        })
    },
    strip_protocol: |p| fsfast_local::strip_protocol(p).into_owned(),
    url_options: no_url_options,
    in_process: true,
};

#[cfg(feature = "memory")]
static MEMORY: Backend = Backend {
    protocols: &["memory"],
    build: |o| {
        Ok(Built {
            fs: Arc::new(fsfast_memory::MemoryFileSystem::from_options(o)?),
            stats: None,
        })
    },
    strip_protocol: |p| fsfast_memory::strip_protocol(p).into_owned(),
    url_options: no_url_options,
    in_process: true,
};

#[cfg(feature = "http")]
static HTTP: Backend = Backend {
    protocols: &["http", "https"],
    build: |o| {
        let fs = fsfast_http::HttpFileSystem::from_options(o)?;
        let stats = fs.client().stats().clone();
        Ok(Built {
            fs: Arc::new(fs),
            stats: Some(stats),
        })
    },
    // fsspec's HTTPFileSystem keeps the whole URL as the path.
    strip_protocol: |p| p.to_owned(),
    url_options: no_url_options,
    in_process: false,
};

#[cfg(feature = "s3")]
static S3: Backend = Backend {
    protocols: fsfast_s3::path::PROTOCOLS,
    build: |o| {
        let fs = fsfast_s3::S3FileSystem::from_options(o)?;
        let stats = fs.stats().clone();
        Ok(Built {
            fs: Arc::new(fs),
            stats: Some(stats),
        })
    },
    strip_protocol: fsfast_s3::path::strip_protocol,
    url_options: no_url_options,
    in_process: false,
};

#[cfg(feature = "smb")]
static SMB: Backend = Backend {
    protocols: &["smb"],
    build: |o| {
        let fs = fsfast_smb::SmbFileSystem::from_options(o)?;
        let stats = fs.stats().clone();
        Ok(Built {
            fs: Arc::new(fs),
            stats: Some(stats),
        })
    },
    strip_protocol: fsfast_smb::strip_protocol,
    url_options: fsfast_smb::get_kwargs_from_urls,
    in_process: false,
};

#[cfg(feature = "sftp")]
static SFTP: Backend = Backend {
    protocols: &["sftp", "ssh"],
    build: |o| {
        let fs = fsfast_sftp::SftpFileSystem::from_options(o)?;
        let stats = fs.stats().clone();
        Ok(Built {
            fs: Arc::new(fs),
            stats: Some(stats),
        })
    },
    strip_protocol: fsfast_sftp::strip_protocol,
    url_options: fsfast_sftp::get_kwargs_from_urls,
    in_process: false,
};

#[cfg(feature = "gcs")]
static GCS: Backend = Backend {
    protocols: fsfast_gcs::path::PROTOCOLS,
    build: |o| {
        let fs = fsfast_gcs::GCSFileSystem::from_options(o)?;
        let stats = fs.stats().clone();
        Ok(Built {
            fs: Arc::new(fs),
            stats: Some(stats),
        })
    },
    strip_protocol: |p| fsfast_gcs::path::strip_protocol(p).to_owned(),
    url_options: no_url_options,
    in_process: false,
};

#[cfg(feature = "azure")]
static AZURE: Backend = Backend {
    protocols: fsfast_azure::PROTOCOLS,
    build: |o| {
        let fs = fsfast_azure::AzureBlobFileSystem::from_options(o)?;
        let stats = fs.stats().clone();
        Ok(Built {
            fs: Arc::new(fs),
            stats: Some(stats),
        })
    },
    strip_protocol: fsfast_azure::path::strip_protocol,
    url_options: |url| {
        // adlfs `_get_kwargs_from_urls`.
        let mut o = Options::new();
        let (account, versioned) = fsfast_azure::path::kwargs_from_url(url);
        if let Some(a) = account {
            o.insert("account_name".into(), fsfast_core::Value::Str(a));
        }
        if versioned {
            o.insert("version_aware".into(), fsfast_core::Value::Bool(true));
        }
        o
    },
    in_process: false,
};

/// Every compiled-in backend.
pub static BACKENDS: &[&Backend] = &[
    #[cfg(feature = "local")]
    &LOCAL,
    #[cfg(feature = "memory")]
    &MEMORY,
    #[cfg(feature = "http")]
    &HTTP,
    #[cfg(feature = "s3")]
    &S3,
    #[cfg(feature = "smb")]
    &SMB,
    #[cfg(feature = "sftp")]
    &SFTP,
    #[cfg(feature = "gcs")]
    &GCS,
    #[cfg(feature = "azure")]
    &AZURE,
];

/// The backend serving `protocol` (any alias, case-insensitive like URL
/// schemes).
pub fn lookup(protocol: &str) -> Result<&'static Backend> {
    let p = protocol.to_ascii_lowercase();
    BACKENDS
        .iter()
        .copied()
        .find(|b| b.protocols.contains(&p.as_str()))
        .ok_or_else(|| {
            Error::unsupported(format!(
                "protocol {protocol:?} (compiled-in protocols: {})",
                available().join(", ")
            ))
        })
}

/// Every protocol name served by a compiled-in backend.
pub fn available() -> Vec<&'static str> {
    BACKENDS
        .iter()
        .flat_map(|b| b.protocols.iter().copied())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_aliases_and_unknown() {
        #[cfg(feature = "local")]
        assert_eq!(lookup("local").unwrap().name(), "file");
        #[cfg(feature = "s3")]
        assert_eq!(lookup("S3A").unwrap().name(), "s3");
        #[cfg(feature = "gcs")]
        assert_eq!(lookup("gcs").unwrap().name(), "gs");
        #[cfg(feature = "azure")]
        assert_eq!(lookup("az").unwrap().name(), "abfs");
        #[cfg(feature = "sftp")]
        assert_eq!(lookup("ssh").unwrap().name(), "sftp");
        let e = lookup("nope").unwrap_err();
        assert_eq!(e.kind(), fsfast_core::ErrorKind::Unsupported);
    }

    #[test]
    fn builders_are_strict() {
        for b in BACKENDS {
            let mut o = Options::new();
            o.insert("definitely_not_an_option".into(), 1i64.into());
            assert!(
                (b.build)(o).is_err(),
                "{} accepted a bogus option",
                b.name()
            );
        }
    }
}
