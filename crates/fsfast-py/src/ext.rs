//! Backend-specific methods, reached from Python through
//! `RustFileSystem.call(method, **kwargs)` (see
//! [`crate::registry::Backend::ext`]).
//!
//! Each dispatcher downcasts the backend object, reads the keyword
//! arguments strictly (unknown names are `InvalidInput`) and returns a
//! [`PyOut`]. They exist for the reference classes' extras that users call
//! directly: s3fs `get_tags`/`put_tags`/`getxattr`/`setxattr`/
//! `object_version_info`/..., gcsfs `url`/`merge`, adlfs `setxattrs`, and
//! SMB's eager `connect` (fsspec's `register_session` at construction).

#![allow(dead_code)] // helpers unused in builds without some backends

use std::collections::BTreeMap;
use std::sync::Arc;

use fsfast_core::{Error, Options, Result, Value};
use futures::future::BoxFuture;

use crate::out::PyOut;
use crate::registry::AnyFs;

/// Keyword arguments of one call, consumed by name.
struct Args {
    method: String,
    opts: Options,
}

impl Args {
    fn new(method: &str, opts: Options) -> Self {
        Args {
            method: method.to_owned(),
            opts,
        }
    }

    fn take(&mut self, name: &str) -> Option<Value> {
        self.opts.remove(name).filter(|v| !matches!(v, Value::Null))
    }

    fn str(&mut self, name: &str) -> Result<String> {
        self.opt_str(name)?.ok_or_else(|| {
            Error::invalid_input(format!("{}: missing argument {name:?}", self.method))
        })
    }

    fn opt_str(&mut self, name: &str) -> Result<Option<String>> {
        match self.take(name) {
            None => Ok(None),
            Some(Value::Str(s)) => Ok(Some(s)),
            Some(other) => Err(self.bad(name, "a str", &other)),
        }
    }

    fn bool(&mut self, name: &str, default: bool) -> Result<bool> {
        match self.take(name) {
            None => Ok(default),
            Some(Value::Bool(b)) => Ok(b),
            Some(other) => Err(self.bad(name, "a bool", &other)),
        }
    }

    fn opt_usize(&mut self, name: &str) -> Result<Option<usize>> {
        match self.take(name) {
            None => Ok(None),
            Some(Value::Int(i)) if i >= 0 => Ok(Some(i as usize)),
            Some(other) => Err(self.bad(name, "a non-negative int", &other)),
        }
    }

    fn strings(&mut self, name: &str) -> Result<Vec<String>> {
        match self.take(name) {
            Some(Value::List(items)) => items
                .into_iter()
                .map(|v| match v {
                    Value::Str(s) => Ok(s),
                    other => Err(self.bad(name, "a list of str", &other)),
                })
                .collect(),
            Some(other) => Err(self.bad(name, "a list of str", &other)),
            None => Err(Error::invalid_input(format!(
                "{}: missing argument {name:?}",
                self.method
            ))),
        }
    }

    fn map(&mut self, name: &str) -> Result<BTreeMap<String, Value>> {
        match self.take(name) {
            None => Ok(BTreeMap::new()),
            Some(Value::Map(m)) => Ok(m),
            Some(other) => Err(self.bad(name, "a dict", &other)),
        }
    }

    /// A `{str: str}` dict (values converted with `str()` semantics for
    /// numbers and bools, as boto/azure accept them).
    fn str_map(&mut self, name: &str) -> Result<BTreeMap<String, String>> {
        let m = self.map(name)?;
        m.into_iter()
            .map(|(k, v)| Ok((k.clone(), self.scalar_str(name, v)?)))
            .collect()
    }

    fn scalar_str(&self, name: &str, v: Value) -> Result<String> {
        Ok(match v {
            Value::Str(s) => s,
            Value::Int(i) => i.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Bool(b) => if b { "True" } else { "False" }.to_owned(),
            other => return Err(self.bad(name, "str values", &other)),
        })
    }

    fn bad(&self, name: &str, want: &str, got: &Value) -> Error {
        Error::invalid_input(format!(
            "{}: argument {name:?} must be {want}, got {}",
            self.method,
            got.type_name()
        ))
    }

    /// Fail on arguments nobody consumed.
    fn finish(self) -> Result<()> {
        match self.opts.keys().next() {
            None => Ok(()),
            Some(k) => Err(Error::invalid_input(format!(
                "{}: unexpected argument {k:?}",
                self.method
            ))),
        }
    }
}

fn unknown(backend: &str, method: &str) -> Error {
    Error::unsupported(format!("{backend} has no method {method:?}"))
}

fn downcast<T: Send + Sync + 'static>(any: AnyFs) -> Result<Arc<T>> {
    any.downcast::<T>()
        .map_err(|_| Error::new(fsfast_core::ErrorKind::Other, "backend type mismatch"))
}

fn string_map(m: BTreeMap<String, String>) -> PyOut {
    PyOut::Value(Value::Map(
        m.into_iter().map(|(k, v)| (k, Value::Str(v))).collect(),
    ))
}

// ---------------------------------------------------------------------------
// SMB

/// SMB methods: `connect()` (fsspec's eager `register_session`) and
/// `connection_info(share)`.
#[cfg(feature = "smb")]
pub(crate) fn smb(any: AnyFs, method: String, opts: Options) -> BoxFuture<'static, Result<PyOut>> {
    Box::pin(async move {
        let fs = downcast::<fsfast_smb::SmbFileSystem>(any)?;
        let mut a = Args::new(&method, opts);
        match method.as_str() {
            "connect" => {
                a.finish()?;
                fs.connect().await?;
                Ok(PyOut::None)
            }
            "connection_info" => {
                let share = a.str("share")?;
                a.finish()?;
                let c = fs.connection_info(&share).await?;
                let mut m = BTreeMap::new();
                m.insert("dialect".into(), Value::Str(c.dialect));
                m.insert(
                    "signing_algorithm".into(),
                    c.signing_algorithm.map_or(Value::Null, Value::Str),
                );
                m.insert("signing".into(), Value::Bool(c.signing));
                m.insert("cipher".into(), c.cipher.map_or(Value::Null, Value::Str));
                m.insert("encrypt_all".into(), Value::Bool(c.encrypt_all));
                m.insert("share_encrypted".into(), Value::Bool(c.share_encrypted));
                m.insert("max_read_size".into(), Value::Int(c.max_read_size.into()));
                m.insert("max_write_size".into(), Value::Int(c.max_write_size.into()));
                Ok(PyOut::Value(Value::Map(m)))
            }
            other => Err(unknown("smb", other)),
        }
    })
}

// ---------------------------------------------------------------------------
// SFTP

/// SFTP methods: `connect()` (fsspec connects at construction),
/// `realpath(path)`, `readlink(path)`, `symlink(target, link)`,
/// `chmod(path, mode)`.
#[cfg(feature = "sftp")]
pub(crate) fn sftp(any: AnyFs, method: String, opts: Options) -> BoxFuture<'static, Result<PyOut>> {
    Box::pin(async move {
        let fs = downcast::<fsfast_sftp::SftpFileSystem>(any)?;
        let mut a = Args::new(&method, opts);
        match method.as_str() {
            "connect" => {
                a.finish()?;
                fs.connection_info().await?;
                Ok(PyOut::None)
            }
            "realpath" => {
                let path = a.str("path")?;
                a.finish()?;
                Ok(PyOut::Str(fs.realpath(&path).await?))
            }
            "readlink" => {
                let path = a.str("path")?;
                a.finish()?;
                Ok(PyOut::Str(fs.readlink(&path).await?))
            }
            "symlink" => {
                let target = a.str("target")?;
                let link = a.str("link")?;
                a.finish()?;
                fs.symlink(&target, &link).await?;
                Ok(PyOut::None)
            }
            "chmod" => {
                let path = a.str("path")?;
                let mode = a
                    .opt_usize("mode")?
                    .ok_or_else(|| Error::invalid_input("chmod: missing argument \"mode\""))?;
                a.finish()?;
                let mode = u32::try_from(mode)
                    .map_err(|_| Error::invalid_input("chmod: mode out of range"))?;
                fs.chmod(&path, mode).await?;
                Ok(PyOut::None)
            }
            other => Err(unknown("sftp", other)),
        }
    })
}

// ---------------------------------------------------------------------------
// S3

/// s3fs extras.
#[cfg(feature = "s3")]
pub(crate) fn s3(any: AnyFs, method: String, opts: Options) -> BoxFuture<'static, Result<PyOut>> {
    use fsfast_core::FindOptions;
    Box::pin(async move {
        let fs = downcast::<fsfast_s3::S3FileSystem>(any)?;
        let mut a = Args::new(&method, opts);
        match method.as_str() {
            "get_tags" => {
                let path = a.str("path")?;
                a.finish()?;
                Ok(string_map(fs.get_tags(&path).await?))
            }
            "put_tags" => {
                let path = a.str("path")?;
                let tags = a.str_map("tags")?;
                let merge = a.bool("merge", false)?;
                a.finish()?;
                fs.put_tags(&path, &tags, merge).await?;
                Ok(PyOut::None)
            }
            "metadata" => {
                let path = a.str("path")?;
                a.finish()?;
                Ok(string_map(fs.metadata(&path).await?))
            }
            "getxattr" => {
                let path = a.str("path")?;
                let name = a.str("name")?;
                a.finish()?;
                Ok(PyOut::Value(
                    fs.getxattr(&path, &name)
                        .await?
                        .map_or(Value::Null, Value::Str),
                ))
            }
            "setxattr" => {
                let path = a.str("path")?;
                let attrs = a.map("attrs")?;
                let copy = a.map("copy_kwargs")?;
                a.finish()?;
                let attrs = attrs
                    .into_iter()
                    .map(|(k, v)| match v {
                        Value::Null => Ok((k, None)),
                        v => Ok((k, Some(a_scalar(&method, v)?))),
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?;
                let params = if copy.is_empty() {
                    None
                } else {
                    Some(fsfast_s3::params::Params::from_map(&copy, "copy_kwargs")?)
                };
                fs.setxattr(&path, &attrs, params.as_ref()).await?;
                Ok(PyOut::None)
            }
            "chmod" => {
                let path = a.str("path")?;
                let acl = a.str("acl")?;
                let recursive = a.bool("recursive", false)?;
                a.finish()?;
                fs.chmod(&path, &acl, recursive).await?;
                Ok(PyOut::None)
            }
            "object_versions" => {
                let path = a.str("path")?;
                a.finish()?;
                Ok(PyOut::InfoList(fs.object_versions(&path).await?))
            }
            "ls_versions" => {
                let path = a.str("path")?;
                a.finish()?;
                Ok(PyOut::InfoList(fs.ls_versions(&path).await?))
            }
            "find_prefix" => {
                let path = a.str("path")?;
                let prefix = a.opt_str("prefix")?.unwrap_or_default();
                let maxdepth = a.opt_usize("maxdepth")?;
                let withdirs = a.bool("withdirs", false)?;
                a.finish()?;
                let opts = FindOptions { maxdepth, withdirs };
                Ok(PyOut::InfoList(
                    fs.find_prefix(&path, &prefix, &opts).await?,
                ))
            }
            "is_bucket_versioned" => {
                let bucket = a.str("bucket")?;
                a.finish()?;
                Ok(PyOut::Bool(fs.is_bucket_versioned(&bucket).await?))
            }
            "make_bucket_versioned" => {
                let bucket = a.str("bucket")?;
                let versioned = a.bool("versioned", true)?;
                a.finish()?;
                fs.make_bucket_versioned(&bucket, versioned).await?;
                Ok(PyOut::None)
            }
            "bucket_region" => {
                let bucket = a.str("bucket")?;
                a.finish()?;
                Ok(PyOut::Str(fs.bucket_region(&bucket).await?))
            }
            other => Err(unknown("s3", other)),
        }
    })
}

#[cfg(feature = "s3")]
fn a_scalar(method: &str, v: Value) -> Result<String> {
    Args::new(method, Options::new()).scalar_str("attrs", v)
}

// ---------------------------------------------------------------------------
// GCS

/// gcsfs extras: `url(path, generation=None)`, `merge(path, paths)`,
/// `buckets()`, `project()`.
#[cfg(feature = "gcs")]
pub(crate) fn gcs(any: AnyFs, method: String, opts: Options) -> BoxFuture<'static, Result<PyOut>> {
    Box::pin(async move {
        let fs = downcast::<fsfast_gcs::GCSFileSystem>(any)?;
        let mut a = Args::new(&method, opts);
        match method.as_str() {
            "url" => {
                let path = a.str("path")?;
                let generation = a.opt_str("generation")?;
                a.finish()?;
                Ok(PyOut::Str(fs.url(&path, generation.as_deref())?))
            }
            "merge" => {
                let path = a.str("path")?;
                let paths = a.strings("paths")?;
                a.finish()?;
                fs.merge(&path, &paths).await?;
                Ok(PyOut::None)
            }
            "buckets" => {
                a.finish()?;
                Ok(PyOut::Names(fs.buckets().await?))
            }
            "project" => {
                a.finish()?;
                Ok(PyOut::Value(
                    fs.project().await?.map_or(Value::Null, Value::Str),
                ))
            }
            other => Err(unknown("gcs", other)),
        }
    })
}

// ---------------------------------------------------------------------------
// Azure

/// adlfs extras: `set_metadata(path, metadata)` (adlfs `setxattrs`),
/// `create_container(container, public_access=None)` and
/// `delete_container(container)` (adlfs `rmdir` of a container: Azure
/// deletes the container with every blob in it, in one request).
#[cfg(feature = "azure")]
pub(crate) fn azure(
    any: AnyFs,
    method: String,
    opts: Options,
) -> BoxFuture<'static, Result<PyOut>> {
    Box::pin(async move {
        let fs = downcast::<fsfast_azure::AzureBlobFileSystem>(any)?;
        let mut a = Args::new(&method, opts);
        match method.as_str() {
            "set_metadata" => {
                let path = a.str("path")?;
                let metadata = a.str_map("metadata")?;
                a.finish()?;
                fs.set_metadata(&path, &metadata).await?;
                Ok(PyOut::None)
            }
            "create_container" => {
                let container = a.str("container")?;
                let public = a.opt_str("public_access")?;
                a.finish()?;
                fs.create_container_with_access(&container, public.as_deref())
                    .await?;
                Ok(PyOut::None)
            }
            "delete_container" => {
                let container = a.str("container")?;
                a.finish()?;
                fs.delete_container_raw(&container).await?;
                Ok(PyOut::None)
            }
            other => Err(unknown("abfs", other)),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_are_strict() {
        let mut o = Options::new();
        o.insert("path".into(), Value::Str("b/k".into()));
        o.insert("extra".into(), Value::Int(1));
        let mut a = Args::new("m", o);
        assert_eq!(a.str("path").unwrap(), "b/k");
        assert!(a.str("missing").is_err());
        assert!(!a.bool("flag", false).unwrap());
        let e = a.finish().unwrap_err();
        assert!(e.to_string().contains("extra"), "{e}");
    }

    #[test]
    fn args_type_checks() {
        let mut o = Options::new();
        o.insert("n".into(), Value::Str("x".into()));
        o.insert("tags".into(), {
            let mut m = BTreeMap::new();
            m.insert("a".into(), Value::Int(1));
            m.insert("b".into(), Value::Bool(true));
            Value::Map(m)
        });
        o.insert("none".into(), Value::Null);
        let mut a = Args::new("m", o);
        assert!(a.opt_usize("n").is_err());
        let tags = a.str_map("tags").unwrap();
        assert_eq!(tags["a"], "1");
        assert_eq!(tags["b"], "True");
        assert_eq!(a.opt_str("none").unwrap(), None);
        a.finish().unwrap();
    }
}
