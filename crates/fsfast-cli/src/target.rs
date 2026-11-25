//! URL parsing and the per-command filesystem cache.
//!
//! A command-line location is either a URL `PROTOCOL://...` naming a
//! compiled-in protocol, or a local path (relative paths resolve against the
//! current directory, `~` against the home directory, exactly as fsspec's
//! `LocalFileSystem` does). The path handed to the backend is the backend's
//! own fsspec `_strip_protocol` of the URL, and URL-borne options (SMB/SFTP
//! host and credentials, the Azure account) come from its
//! `_get_kwargs_from_urls`, so a location means the same thing to `fsf` as
//! to `fsspec.url_to_fs`.

use std::collections::HashMap;
use std::sync::Arc;

use fsfast_core::{Error, Options, Result, path as fspath};
use parking_lot::Mutex;

use crate::backends::{self, Backend, Built};
use crate::options::OptionSet;

/// A parsed location (no filesystem built yet).
#[derive(Debug, Clone)]
pub struct Location {
    /// The original argument.
    pub url: String,
    /// The serving backend.
    pub backend: &'static Backend,
    /// The protocol-stripped path in the backend's form.
    pub path: String,
    /// Options inferred from the URL.
    pub url_options: Options,
    /// Whether the argument ended with `/` (a directory destination for
    /// `cp`).
    pub trailing_slash: bool,
}

/// The URL scheme of `s`, following fsspec's `split_protocol`: text before
/// `://` made of URL scheme characters and longer than one character (so a
/// Windows drive `C://x` is not a scheme). `file:`/`local:` without `//`
/// also name the local filesystem.
pub fn scheme(s: &str) -> Option<&str> {
    if let Some(i) = s.find("://") {
        let p = &s[..i];
        if p.len() > 1
            && p.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'.' | b'-'))
            && p.as_bytes()[0].is_ascii_alphabetic()
        {
            return Some(p);
        }
    }
    for local in ["file:", "local:"] {
        if s.len() > local.len() && s[..local.len()].eq_ignore_ascii_case(local) {
            return Some(&s[..local.len() - 1]);
        }
    }
    None
}

/// Parse a command-line location.
pub fn parse_location(url: &str) -> Result<Location> {
    if url.is_empty() {
        return Err(Error::invalid_input("empty location"));
    }
    // fsspec URL chaining (`simplecache::s3://...`) is a Python-layer
    // feature; reject it clearly instead of passing it to a backend.
    if let Some((head, _)) = url.split_once("::")
        && !head.is_empty()
        && !head.contains(['/', '\\'])
    {
        return Err(Error::unsupported(format!(
            "chained URLs ({url:?}); give the inner URL directly (use ./{url} for a local name)"
        )));
    }
    let backend = match scheme(url) {
        Some(p) => backends::lookup(p)?,
        None => backends::lookup("file").map_err(|_| {
            Error::invalid_input(format!(
                "{url:?} has no protocol and the local backend is not compiled in"
            ))
        })?,
    };
    let path = (backend.strip_protocol)(url);
    let url_options = (backend.url_options)(url);
    Ok(Location {
        url: url.to_owned(),
        backend,
        path,
        url_options,
        trailing_slash: url.ends_with('/') || (cfg!(windows) && url.ends_with('\\')),
    })
}

/// `child` of directory `dir` in the backend's path form.
pub fn child_path(backend: &Backend, dir: &str, child: &str) -> String {
    (backend.strip_protocol)(&fspath::join(dir, child))
}

/// A resolved location: the location plus its (shared) filesystem.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// The parsed location.
    pub loc: Location,
    /// The filesystem serving it.
    pub built: Built,
    /// Cache key of the filesystem; equal keys mean the same instance.
    pub fs_key: String,
}

impl Resolved {
    /// The backend path.
    pub fn path(&self) -> &str {
        &self.loc.path
    }

    /// Whether two locations are served by the same filesystem instance
    /// (same protocol and options), so `cp` can copy server-side.
    pub fn same_fs(&self, other: &Resolved) -> bool {
        self.fs_key == other.fs_key
    }

    /// Whether this is the local filesystem.
    pub fn is_local(&self) -> bool {
        self.loc.backend.name() == "file"
    }
}

/// Builds filesystems for locations, reusing one instance per protocol and
/// option set (connections and pools are shared across the command).
#[derive(Debug)]
pub struct Session {
    opts: OptionSet,
    cache: Mutex<HashMap<String, Built>>,
}

impl Session {
    /// A session using `opts`.
    pub fn new(opts: OptionSet) -> Self {
        Session {
            opts,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Parse every location of one command, checking option scoping.
    pub fn parse_all(&self, urls: &[&str]) -> Result<Vec<Location>> {
        let locs = urls
            .iter()
            .map(|u| parse_location(u))
            .collect::<Result<Vec<_>>>()?;
        let used: Vec<&'static Backend> = locs.iter().map(|l| l.backend).collect();
        self.opts.check_unscoped(&used)?;
        Ok(locs)
    }

    /// Build (or reuse) the filesystem for `loc`.
    pub fn resolve(&self, loc: Location) -> Result<Resolved> {
        let opts = self
            .opts
            .options_for(loc.backend, loc.url_options.clone())?;
        // `Options` is a BTreeMap, so its Debug form is deterministic.
        let fs_key = format!("{}\0{opts:?}", loc.backend.name());
        let mut cache = self.cache.lock();
        let built = match cache.get(&fs_key) {
            Some(b) => b.clone(),
            None => {
                let b = (loc.backend.build)(opts)?;
                cache.insert(fs_key.clone(), b.clone());
                b
            }
        };
        Ok(Resolved { loc, built, fs_key })
    }

    /// Parse and resolve several locations of one command.
    pub fn resolve_all(&self, urls: &[&str]) -> Result<Vec<Resolved>> {
        self.parse_all(urls)?
            .into_iter()
            .map(|l| self.resolve(l))
            .collect()
    }

    /// Every filesystem built so far.
    pub fn built(&self) -> Vec<(String, Built)> {
        let mut v: Vec<_> = self
            .cache
            .lock()
            .iter()
            .map(|(k, b)| (k.split('\0').next().unwrap_or("").to_owned(), b.clone()))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// Release pooled connections of every filesystem (errors ignored:
    /// the command's own result matters more).
    pub async fn close(&self) {
        let fss: Vec<Arc<dyn fsfast_core::FileSystem>> =
            self.cache.lock().values().map(|b| b.fs.clone()).collect();
        for fs in fss {
            if let Err(e) = fs.close().await {
                tracing::debug!(error = %e, "closing filesystem failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schemes() {
        assert_eq!(scheme("s3://b/k"), Some("s3"));
        assert_eq!(scheme("git+ssh://x"), Some("git+ssh"));
        assert_eq!(scheme("/tmp/x"), None);
        assert_eq!(scheme("rel/a://b"), None);
        assert_eq!(scheme("C://x"), None);
        assert_eq!(scheme("C:\\x"), None);
        assert_eq!(scheme("file:/tmp/x"), Some("file"));
        assert_eq!(scheme("FILE:/tmp/x"), Some("FILE"));
        assert_eq!(scheme("local:x"), Some("local"));
        assert_eq!(scheme("://x"), None);
        assert_eq!(scheme("1x://y"), None);
    }

    #[test]
    #[cfg(feature = "local")]
    fn local_paths() {
        let l = parse_location("/tmp/a/b/").unwrap();
        assert_eq!(l.backend.name(), "file");
        assert_eq!(l.path, "/tmp/a/b");
        assert!(l.trailing_slash);
        let l = parse_location("file:///tmp/x").unwrap();
        assert_eq!(l.path, "/tmp/x");
        let l = parse_location("local:///tmp/x").unwrap();
        assert_eq!(l.path, "/tmp/x");
        let l = parse_location("rel/x").unwrap();
        assert!(
            l.path.starts_with('/') && l.path.ends_with("/rel/x"),
            "{}",
            l.path
        );
        assert!(!l.trailing_slash);
    }

    #[test]
    #[cfg(feature = "memory")]
    fn memory_paths() {
        assert_eq!(parse_location("memory://a/b/").unwrap().path, "/a/b");
        assert_eq!(parse_location("memory://").unwrap().path, "");
    }

    #[test]
    #[cfg(feature = "s3")]
    fn object_store_paths() {
        let l = parse_location("s3://bucket/dir/key/").unwrap();
        assert_eq!(l.backend.name(), "s3");
        assert_eq!(l.path, "bucket/dir/key");
        assert!(l.url_options.is_empty());
        assert_eq!(parse_location("s3a://bucket").unwrap().path, "bucket");
        assert_eq!(
            parse_location("S3://bucket/k").unwrap().backend.name(),
            "s3"
        );
    }

    #[test]
    #[cfg(feature = "gcs")]
    fn gcs_paths() {
        assert_eq!(parse_location("gs://b/k").unwrap().path, "b/k");
        assert_eq!(parse_location("gcs://b/k").unwrap().path, "b/k");
    }

    #[test]
    #[cfg(feature = "azure")]
    fn azure_paths() {
        let l = parse_location("abfs://container/a/b").unwrap();
        assert_eq!(l.path, "container/a/b");
        assert!(l.url_options.is_empty());
        let l = parse_location("az://container@acct.dfs.core.windows.net/a").unwrap();
        assert_eq!(l.path, "container/a");
        assert_eq!(
            l.url_options["account_name"],
            fsfast_core::Value::Str("acct".into())
        );
    }

    #[test]
    #[cfg(feature = "smb")]
    fn smb_urls_carry_connection_options() {
        let l = parse_location("smb://user:pw@server:4445/share/dir/f").unwrap();
        assert_eq!(l.backend.name(), "smb");
        assert_eq!(l.path, "/share/dir/f");
        let o = &l.url_options;
        assert_eq!(o["host"], fsfast_core::Value::Str("server".into()));
        assert_eq!(o["port"], fsfast_core::Value::Int(4445));
        assert_eq!(o["username"], fsfast_core::Value::Str("user".into()));
        assert_eq!(o["password"], fsfast_core::Value::Str("pw".into()));
    }

    #[test]
    #[cfg(feature = "sftp")]
    fn sftp_urls_carry_connection_options() {
        let l = parse_location("ssh://me@host/home/me/x").unwrap();
        assert_eq!(l.backend.name(), "sftp");
        assert_eq!(l.path, "/home/me/x");
        assert_eq!(
            l.url_options["host"],
            fsfast_core::Value::Str("host".into())
        );
        assert_eq!(
            l.url_options["username"],
            fsfast_core::Value::Str("me".into())
        );
        assert!(!l.url_options.contains_key("port"));
    }

    #[test]
    #[cfg(feature = "http")]
    fn http_keeps_the_url() {
        let l = parse_location("https://example.com/a/b?x=1").unwrap();
        assert_eq!(l.backend.name(), "http");
        assert_eq!(l.path, "https://example.com/a/b?x=1");
    }

    #[test]
    fn errors() {
        assert!(parse_location("").is_err());
        let e = parse_location("nope://x").unwrap_err();
        assert_eq!(e.kind(), fsfast_core::ErrorKind::Unsupported);
        assert!(parse_location("simplecache::s3://b/k").is_err());
    }

    #[test]
    #[cfg(all(feature = "memory", feature = "local"))]
    fn session_reuses_instances() {
        let s = Session::new(OptionSet::default());
        let r = s
            .resolve_all(&["memory://a", "memory://b", "/tmp"])
            .unwrap();
        assert!(r[0].same_fs(&r[1]));
        assert!(!r[0].same_fs(&r[2]));
        assert!(r[2].is_local());
        assert_eq!(s.built().len(), 2);
    }

    #[test]
    #[cfg(feature = "memory")]
    fn child_paths() {
        let m = backends::lookup("memory").unwrap();
        assert_eq!(child_path(m, "", "x"), "/x");
        assert_eq!(child_path(m, "/a", "x/y"), "/a/x/y");
    }
}
