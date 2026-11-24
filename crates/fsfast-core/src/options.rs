//! Strict `storage_options` parsing.
//!
//! Every backend constructor takes an [`Options`] map (built from Python
//! keyword arguments) and reads it through an [`OptionReader`]. Unknown keys
//! are an error: silently ignoring a typo'd credential or endpoint option is a
//! classic source of "why is it talking to the wrong bucket" bugs.
//! Options that exist in the reference implementation but have no effect in
//! fsfast must be consumed explicitly with [`OptionReader::accept_ignored`].

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::{Error, Result, Value};

/// Raw option map.
pub type Options = BTreeMap<String, Value>;

/// Typed, consumption-tracking reader over an [`Options`] map.
#[derive(Debug)]
pub struct OptionReader {
    protocol: &'static str,
    opts: Options,
    consumed: BTreeSet<String>,
}

impl OptionReader {
    pub fn new(protocol: &'static str, opts: Options) -> Self {
        OptionReader {
            protocol,
            opts,
            consumed: BTreeSet::new(),
        }
    }

    fn take(&mut self, key: &str) -> Option<&Value> {
        let v = self.opts.get(key)?;
        self.consumed.insert(key.to_owned());
        if v.is_null() { None } else { Some(v) }
    }

    fn type_err(&self, key: &str, want: &str, got: &Value) -> Error {
        Error::invalid_input(format!(
            "{}: option '{key}' must be {want}, got {}",
            self.protocol,
            got.type_name()
        ))
    }

    /// Raw value (any type). `None` if absent or `None` in Python.
    pub fn value(&mut self, key: &str) -> Option<Value> {
        self.take(key).cloned()
    }

    pub fn string(&mut self, key: &str) -> Result<Option<String>> {
        match self.take(key).cloned() {
            None => Ok(None),
            Some(Value::Str(s)) => Ok(Some(s)),
            Some(v) => Err(self.type_err(key, "a string", &v)),
        }
    }

    /// First present key among aliases (all aliases are marked consumed).
    pub fn string_any(&mut self, keys: &[&str]) -> Result<Option<String>> {
        let mut found = None;
        for k in keys {
            let v = self.string(k)?;
            if found.is_none() {
                found = v;
            }
        }
        Ok(found)
    }

    pub fn bool(&mut self, key: &str) -> Result<Option<bool>> {
        match self.take(key).cloned() {
            None => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(b)),
            Some(Value::Int(i)) if i == 0 || i == 1 => Ok(Some(i == 1)),
            Some(Value::Str(s)) => match s.to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" | "on" => Ok(Some(true)),
                "false" | "0" | "no" | "off" => Ok(Some(false)),
                _ => Err(Error::invalid_input(format!(
                    "{}: option '{key}' must be a boolean, got {s:?}",
                    self.protocol
                ))),
            },
            Some(v) => Err(self.type_err(key, "a boolean", &v)),
        }
    }

    pub fn i64(&mut self, key: &str) -> Result<Option<i64>> {
        match self.take(key).cloned() {
            None => Ok(None),
            Some(v) => match v.as_i64() {
                Some(i) => Ok(Some(i)),
                None => match &v {
                    Value::Str(s) => s
                        .parse()
                        .map(Some)
                        .map_err(|_| self.type_err(key, "an integer", &v)),
                    _ => Err(self.type_err(key, "an integer", &v)),
                },
            },
        }
    }

    pub fn u64(&mut self, key: &str) -> Result<Option<u64>> {
        match self.i64(key)? {
            None => Ok(None),
            Some(i) if i >= 0 => Ok(Some(i as u64)),
            Some(i) => Err(Error::invalid_input(format!(
                "{}: option '{key}' must be non-negative, got {i}",
                self.protocol
            ))),
        }
    }

    pub fn usize(&mut self, key: &str) -> Result<Option<usize>> {
        Ok(self.u64(key)?.map(|v| v as usize))
    }

    pub fn f64(&mut self, key: &str) -> Result<Option<f64>> {
        match self.take(key).cloned() {
            None => Ok(None),
            Some(v) => v
                .as_f64()
                .map(Some)
                .ok_or_else(|| self.type_err(key, "a number", &v)),
        }
    }

    /// Seconds as int/float → Duration.
    pub fn duration_secs(&mut self, key: &str) -> Result<Option<Duration>> {
        match self.f64(key)? {
            None => Ok(None),
            Some(s) if s >= 0.0 && s.is_finite() => Ok(Some(Duration::from_secs_f64(s))),
            Some(s) => Err(Error::invalid_input(format!(
                "{}: option '{key}' must be a non-negative number of seconds, got {s}",
                self.protocol
            ))),
        }
    }

    pub fn map(&mut self, key: &str) -> Result<Option<BTreeMap<String, Value>>> {
        match self.take(key).cloned() {
            None => Ok(None),
            Some(Value::Map(m)) => Ok(Some(m)),
            Some(v) => Err(self.type_err(key, "a dict", &v)),
        }
    }

    /// A nested option map read with its own strict reader (e.g. s3fs
    /// `client_kwargs`). The nested reader's protocol label is the parent's.
    pub fn nested(&mut self, key: &str) -> Result<Option<OptionReader>> {
        Ok(self.map(key)?.map(|m| OptionReader::new(self.protocol, m)))
    }

    pub fn string_map(&mut self, key: &str) -> Result<Option<BTreeMap<String, String>>> {
        match self.map(key)? {
            None => Ok(None),
            Some(m) => m
                .into_iter()
                .map(|(k, v)| match v {
                    Value::Str(s) => Ok((k, s)),
                    other => Err(self.type_err(key, "a dict of strings", &other)),
                })
                .collect::<Result<_>>()
                .map(Some),
        }
    }

    pub fn string_list(&mut self, key: &str) -> Result<Option<Vec<String>>> {
        match self.take(key).cloned() {
            None => Ok(None),
            Some(Value::Str(s)) => Ok(Some(vec![s])),
            Some(Value::List(l)) => l
                .into_iter()
                .map(|v| match v {
                    Value::Str(s) => Ok(s),
                    other => Err(self.type_err(key, "a list of strings", &other)),
                })
                .collect::<Result<_>>()
                .map(Some),
            Some(v) => Err(self.type_err(key, "a list of strings", &v)),
        }
    }

    /// Mark keys accepted for compatibility with the reference implementation
    /// that intentionally have no effect in fsfast.
    pub fn accept_ignored(&mut self, keys: &[&str]) {
        for k in keys {
            if self.opts.contains_key(*k) {
                self.consumed.insert((*k).to_owned());
            }
        }
    }

    /// Keys present but not yet consumed.
    pub fn remaining(&self) -> Vec<String> {
        self.opts
            .keys()
            .filter(|k| !self.consumed.contains(*k))
            .cloned()
            .collect()
    }

    /// Error if any key was not consumed.
    pub fn finish(self) -> Result<()> {
        let rest = self.remaining();
        if rest.is_empty() {
            Ok(())
        } else {
            Err(Error::invalid_input(format!(
                "{}: unknown or unsupported option(s): {}",
                self.protocol,
                rest.join(", ")
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(pairs: &[(&str, Value)]) -> Options {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    #[test]
    fn typed_reads_and_strictness() {
        let mut r = OptionReader::new(
            "s3",
            opts(&[
                ("key", "AK".into()),
                ("anon", Value::Str("true".into())),
                ("max_concurrency", Value::Int(8)),
                ("timeout", Value::Float(1.5)),
                ("typo", Value::Int(1)),
                ("secret", Value::Null),
            ]),
        );
        assert_eq!(r.string("key").unwrap().as_deref(), Some("AK"));
        assert_eq!(r.bool("anon").unwrap(), Some(true));
        assert_eq!(r.usize("max_concurrency").unwrap(), Some(8));
        assert_eq!(
            r.duration_secs("timeout").unwrap(),
            Some(Duration::from_millis(1500))
        );
        assert_eq!(r.string("secret").unwrap(), None);
        let err = r.finish().unwrap_err();
        assert!(err.to_string().contains("typo"), "{err}");
    }

    #[test]
    fn type_errors() {
        let mut r = OptionReader::new("smb", opts(&[("port", "abc".into())]));
        assert!(r.u64("port").is_err());
    }
}
