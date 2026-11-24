//! The compiled-in backends and the `make_filesystem` factory.
//!
//! [`BACKENDS`] is the one place that knows every backend. Each entry is
//! gated by a cargo feature of the same name (all on by default), so wiring
//! a new backend crate (http, s3, smb, ...) is one feature line in
//! `Cargo.toml` plus one table entry here.

use fsfast_core::{DynFileSystem, Error, Options, Result};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::PyString;

/// Static description of a backend.
pub(crate) struct Backend {
    /// fsspec protocol names; the first is canonical.
    pub protocols: &'static [&'static str],
    /// Build an instance from `storage_options` (the backend's strict
    /// `from_options`).
    pub build: fn(Options) -> Result<DynFileSystem>,
    /// Whether a forked child must build a fresh instance instead of reusing
    /// the parent's (backends holding sockets or connection pools bound to
    /// the parent's runtime). Backends without such state keep theirs, which
    /// also preserves state like an isolated memory store.
    pub rebuild_after_fork: bool,
    /// The reference implementation's `info()` key order for
    /// `FileInfo::extra` (keys not listed follow, sorted).
    pub info_keys: &'static [&'static str],
    /// Interned Python strings for `info_keys` (built on first use).
    keys_cache: PyOnceLock<Vec<Py<PyString>>>,
}

impl Backend {
    // Unused only in a build without any backend feature.
    #[allow(dead_code)]
    const fn new(
        protocols: &'static [&'static str],
        build: fn(Options) -> Result<DynFileSystem>,
        rebuild_after_fork: bool,
        info_keys: &'static [&'static str],
    ) -> Self {
        Backend {
            protocols,
            build,
            rebuild_after_fork,
            info_keys,
            keys_cache: PyOnceLock::new(),
        }
    }

    /// Canonical protocol name.
    pub(crate) fn name(&self) -> &'static str {
        self.protocols[0]
    }

    /// `info_keys` as interned Python strings.
    pub(crate) fn interned_keys(&self, py: Python<'_>) -> &[Py<PyString>] {
        self.keys_cache.get_or_init(py, || {
            self.info_keys
                .iter()
                .map(|k| PyString::intern(py, k).unbind())
                .collect()
        })
    }
}

#[cfg(feature = "local")]
fn build_local(opts: Options) -> Result<DynFileSystem> {
    Ok(std::sync::Arc::new(
        fsfast_local::LocalFileSystem::from_options(opts)?,
    ))
}

#[cfg(feature = "memory")]
fn build_memory(opts: Options) -> Result<DynFileSystem> {
    Ok(std::sync::Arc::new(
        fsfast_memory::MemoryFileSystem::from_options(opts)?,
    ))
}

#[cfg(feature = "local")]
static LOCAL: Backend = Backend::new(
    &["file", "local"],
    build_local,
    false,
    // fsspec LocalFileSystem.info()
    &[
        "created",
        "islink",
        "mode",
        "uid",
        "gid",
        "mtime",
        "ino",
        "nlink",
        "destination",
    ],
);

#[cfg(feature = "memory")]
static MEMORY: Backend = Backend::new(&["memory"], build_memory, false, &["created"]);

/// Every compiled-in backend (add new backends here).
pub(crate) static BACKENDS: &[&Backend] = &[
    #[cfg(feature = "local")]
    &LOCAL,
    #[cfg(feature = "memory")]
    &MEMORY,
];

/// The backend serving `protocol`.
pub(crate) fn lookup(protocol: &str) -> Result<&'static Backend> {
    BACKENDS
        .iter()
        .copied()
        .find(|b| b.protocols.contains(&protocol))
        .ok_or_else(|| {
            Error::unsupported(format!(
                "protocol {protocol:?} (compiled-in protocols: {})",
                available().join(", ")
            ))
        })
}

/// Every protocol name served by a compiled-in backend.
pub(crate) fn available() -> Vec<&'static str> {
    BACKENDS
        .iter()
        .flat_map(|b| b.protocols.iter().copied())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_by_any_alias() {
        #[cfg(feature = "local")]
        {
            assert_eq!(lookup("local").unwrap().name(), "file");
            assert_eq!(lookup("file").unwrap().name(), "file");
        }
        #[cfg(feature = "memory")]
        assert_eq!(lookup("memory").unwrap().name(), "memory");
        let e = lookup("nope").err().unwrap();
        assert_eq!(e.kind(), fsfast_core::ErrorKind::Unsupported);
        assert!(e.to_string().contains("nope"));
    }

    #[test]
    fn builders_are_strict() {
        #[cfg(feature = "memory")]
        {
            let b = lookup("memory").unwrap();
            assert!((b.build)(Options::new()).is_ok());
            let mut o = Options::new();
            o.insert("bogus".into(), fsfast_core::Value::Int(1));
            assert!((b.build)(o).is_err());
        }
    }
}
