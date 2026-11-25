//! `s3_additional_kwargs`: botocore parameter names → HTTP headers or query
//! parameters, filtered per operation exactly like s3fs.
//!
//! s3fs merges `s3_additional_kwargs` (plus `RequestPayer` for
//! `requester_pays`) into *every* call and keeps the parameters the
//! operation's botocore input shape declares (`ParamKwargsHelper`). The
//! generated table in `params_table.rs` (from botocore's S3 model, see
//! `tools/gen_params.py`) lists where each parameter goes on the wire and
//! which operations accept it. Values are rendered the way botocore
//! serializes them (booleans as `true`/`false`, timestamps as RFC 1123 or
//! ISO 8601, `Metadata` as `x-amz-meta-*` headers), and SSE-C keys get
//! botocore's `sse_md5` treatment: the raw key is base64-encoded and its
//! MD5 digest sent alongside.

use std::collections::BTreeMap;
use std::time::{Duration, UNIX_EPOCH};

use fsfast_core::{Error, Result, Value};
use fsfast_http_transport::header::{HeaderMap, HeaderName, HeaderValue};
use md5::{Digest, Md5};

use crate::encode::{b64, http_date, iso8601};

#[path = "params_table.rs"]
#[allow(dead_code)]
mod table;

#[cfg(test)]
use table::OPERATIONS;
pub(crate) use table::PARAMS;

/// An S3 API operation fsfast issues.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    ListBuckets,
    HeadBucket,
    GetBucketLocation,
    CreateBucket,
    DeleteBucket,
    ListObjectsV2,
    ListObjectVersions,
    HeadObject,
    GetObject,
    PutObject,
    DeleteObject,
    DeleteObjects,
    CopyObject,
    CreateMultipartUpload,
    UploadPart,
    UploadPartCopy,
    CompleteMultipartUpload,
    AbortMultipartUpload,
    GetBucketVersioning,
    PutBucketVersioning,
    GetObjectTagging,
    PutObjectTagging,
    PutObjectAcl,
    PutBucketAcl,
}

/// Where a parameter goes on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Loc {
    /// A header.
    Header(&'static str),
    /// One header per map entry, named prefix + key (`x-amz-meta-`).
    HeaderPrefix(&'static str),
    /// A query-string parameter.
    Query(&'static str),
}

/// The botocore type of a parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamKind {
    /// A string.
    String,
    /// A boolean (`true`/`false`).
    Boolean,
    /// An integer.
    Integer,
    /// A map of strings.
    Map,
    /// A timestamp; `true` for ISO 8601, `false` for RFC 1123.
    Timestamp(bool),
}

/// One forwardable parameter.
#[derive(Debug)]
pub struct ParamSpec {
    /// botocore name (`ServerSideEncryption`).
    pub name: &'static str,
    /// Wire location.
    pub loc: Loc,
    /// Value type.
    pub kind: ParamKind,
    /// Operations whose input shape declares it.
    pub ops: &'static [Op],
}

/// The table entry for `name`.
pub fn spec(name: &str) -> Option<&'static ParamSpec> {
    PARAMS
        .binary_search_by(|p| p.name.cmp(name))
        .ok()
        .map(|i| &PARAMS[i])
}

#[derive(Debug, Clone)]
enum Rendered {
    Headers(Vec<(HeaderName, HeaderValue)>),
    Query(&'static str, String),
}

/// A validated set of botocore parameters, ready to be applied to requests.
#[derive(Debug, Clone, Default)]
pub struct Params {
    items: Vec<(&'static ParamSpec, Rendered, Option<String>)>,
}

fn header_name(name: &str) -> Result<HeaderName> {
    HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes())
        .map_err(|_| Error::invalid_input(format!("invalid header name {name:?}")))
}

fn header_value(param: &str, v: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(v).map_err(|_| {
        Error::invalid_input(format!(
            "s3_additional_kwargs: value of {param} is not a valid HTTP header value: {v:?}"
        ))
    })
}

fn scalar(param: &str, v: &Value) -> Result<String> {
    Ok(match v {
        Value::Str(s) => s.clone(),
        Value::Int(i) => i.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Bool(b) => if *b { "true" } else { "false" }.to_owned(),
        Value::Bytes(b) => String::from_utf8(b.clone()).map_err(|_| {
            Error::invalid_input(format!("s3_additional_kwargs: {param} is not valid UTF-8"))
        })?,
        other => {
            return Err(Error::invalid_input(format!(
                "s3_additional_kwargs: {param} must be a scalar, got {}",
                other.type_name()
            )));
        }
    })
}

impl Params {
    /// Validate a botocore-style parameter map (`s3_additional_kwargs`, or
    /// per-call extras). `what` names the source in error messages.
    pub fn from_map(map: &BTreeMap<String, Value>, what: &str) -> Result<Params> {
        let mut p = Params::default();
        for (k, v) in map {
            p.set(k, v)
                .map_err(|e| Error::invalid_input(format!("{what}: {}", e.message())))?;
        }
        Ok(p)
    }

    /// Set (or replace) parameter `name`. A `None` value removes it.
    pub fn set(&mut self, name: &str, value: &Value) -> Result<()> {
        let spec = spec(name).ok_or_else(|| {
            Error::invalid_input(format!(
                "unknown or unsupported S3 parameter {name:?} (accepted: {})",
                PARAMS.iter().map(|p| p.name).collect::<Vec<_>>().join(", ")
            ))
        })?;
        self.items.retain(|(s, _, _)| s.name != spec.name);
        if value.is_null() {
            return Ok(());
        }
        let (rendered, raw) = match (spec.loc, spec.kind) {
            (Loc::HeaderPrefix(prefix), ParamKind::Map) => {
                let Value::Map(m) = value else {
                    return Err(Error::invalid_input(format!(
                        "{name} must be a dict of strings, got {}",
                        value.type_name()
                    )));
                };
                let mut hs = Vec::with_capacity(m.len());
                for (k, v) in m {
                    let v = scalar(name, v)?;
                    hs.push((
                        header_name(&format!("{prefix}{k}"))?,
                        header_value(name, &v)?,
                    ));
                }
                (Rendered::Headers(hs), None)
            }
            (loc, kind) => {
                let text = match (kind, value) {
                    (ParamKind::Timestamp(iso), Value::Time(t)) => {
                        if iso {
                            iso8601(*t)
                        } else {
                            http_date(*t)
                        }
                    }
                    (ParamKind::Timestamp(iso), Value::Int(_) | Value::Float(_)) => {
                        let secs = value.as_f64().unwrap_or(0.0).max(0.0);
                        let t = UNIX_EPOCH + Duration::from_secs_f64(secs);
                        if iso { iso8601(t) } else { http_date(t) }
                    }
                    (ParamKind::Boolean, Value::Bool(b)) => b.to_string(),
                    (ParamKind::Boolean, Value::Str(s))
                        if matches!(s.to_ascii_lowercase().as_str(), "true" | "false") =>
                    {
                        s.to_ascii_lowercase()
                    }
                    (ParamKind::Boolean, other) => {
                        return Err(Error::invalid_input(format!(
                            "{name} must be a boolean, got {}",
                            other.type_name()
                        )));
                    }
                    (ParamKind::Integer, v) => match v.as_i64() {
                        Some(i) => i.to_string(),
                        None => {
                            return Err(Error::invalid_input(format!(
                                "{name} must be an integer, got {}",
                                v.type_name()
                            )));
                        }
                    },
                    (ParamKind::Map, other) => {
                        return Err(Error::invalid_input(format!(
                            "{name} must be a dict, got {}",
                            other.type_name()
                        )));
                    }
                    (_, v) => {
                        if (name == "SSECustomerKey" || name == "CopySourceSSECustomerKey")
                            && let Value::Bytes(b) = v
                        {
                            // Raw key bytes (often not UTF-8).
                            return self.push_sse_key(spec, b);
                        }
                        scalar(name, v)?
                    }
                };
                if name == "SSECustomerKey" || name == "CopySourceSSECustomerKey" {
                    return self.push_sse_key(spec, text.as_bytes());
                }
                let rendered = match loc {
                    Loc::Header(h) => {
                        Rendered::Headers(vec![(header_name(h)?, header_value(name, &text)?)])
                    }
                    Loc::Query(q) => Rendered::Query(q, text.clone()),
                    Loc::HeaderPrefix(_) => unreachable!("prefix headers are maps"),
                };
                (rendered, Some(text))
            }
        };
        self.items.push((spec, rendered, raw));
        Ok(())
    }

    /// botocore `sse_md5`: send the base64 key and the base64 MD5 of the raw
    /// key bytes.
    fn push_sse_key(&mut self, spec: &'static ParamSpec, key: &[u8]) -> Result<()> {
        let Loc::Header(h) = spec.loc else {
            return Err(Error::invalid_input("SSE-C key must be a header parameter"));
        };
        let md5_header = format!("{h}-MD5");
        let mut key_value = header_value(spec.name, &b64(key))?;
        key_value.set_sensitive(true);
        let headers = vec![
            (header_name(h)?, key_value),
            (
                header_name(&md5_header)?,
                header_value(spec.name, &b64(&Md5::digest(key)))?,
            ),
        ];
        self.items.push((spec, Rendered::Headers(headers), None));
        Ok(())
    }

    /// `self` with `other`'s parameters added or replacing.
    pub fn merged(&self, other: &Params) -> Params {
        let mut out = self.clone();
        for item in &other.items {
            out.items.retain(|(s, _, _)| s.name != item.0.name);
            out.items.push(item.clone());
        }
        out
    }

    /// Whether parameter `name` is set.
    pub fn contains(&self, name: &str) -> bool {
        self.items.iter().any(|(s, _, _)| s.name == name)
    }

    /// The textual value of a scalar parameter.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.items
            .iter()
            .find(|(s, _, _)| s.name == name)
            .and_then(|(_, _, raw)| raw.as_deref())
    }

    /// Whether no parameter is set.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The headers the SSE-C key parameter renders to (for deriving the
    /// copy-source variant).
    pub(crate) fn sse_c_headers(&self) -> Option<Vec<(HeaderName, HeaderValue)>> {
        self.items.iter().find_map(|(s, r, _)| match (s.name, r) {
            ("SSECustomerKey", Rendered::Headers(h)) => Some(h.clone()),
            _ => None,
        })
    }

    /// Add the parameters `op` accepts to `headers` and `query`.
    pub fn apply(&self, op: Op, headers: &mut HeaderMap, query: &mut Vec<(String, String)>) {
        for (spec, rendered, _) in &self.items {
            if !spec.ops.contains(&op) {
                continue;
            }
            match rendered {
                Rendered::Headers(hs) => {
                    for (n, v) in hs {
                        headers.insert(n.clone(), v.clone());
                    }
                }
                Rendered::Query(q, v) => {
                    query.retain(|(k, _)| k != q);
                    query.push(((*q).to_owned(), v.clone()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    #[test]
    fn table_is_sorted_and_covers_operations() {
        assert!(PARAMS.windows(2).all(|w| w[0].name < w[1].name));
        assert_eq!(OPERATIONS.len(), 24);
        let sse = spec("ServerSideEncryption").unwrap();
        assert!(sse.ops.contains(&Op::PutObject));
        assert!(!sse.ops.contains(&Op::GetObject));
        let rp = spec("RequestPayer").unwrap();
        assert!(rp.ops.contains(&Op::GetObject) && rp.ops.contains(&Op::ListObjectsV2));
    }

    #[test]
    fn renders_like_botocore() {
        let p = Params::from_map(
            &map(&[
                ("ServerSideEncryption", "aws:kms".into()),
                ("SSEKMSKeyId", "key-1".into()),
                ("BucketKeyEnabled", true.into()),
                ("ACL", "private".into()),
                (
                    "Metadata",
                    Value::Map(map(&[("Owner", "me".into()), ("x", "y".into())])),
                ),
                ("RequestPayer", "requester".into()),
                ("ResponseContentType", "text/plain".into()),
            ]),
            "s3_additional_kwargs",
        )
        .unwrap();
        let mut h = HeaderMap::new();
        let mut q = Vec::new();
        p.apply(Op::PutObject, &mut h, &mut q);
        assert_eq!(h["x-amz-server-side-encryption"], "aws:kms");
        assert_eq!(h["x-amz-server-side-encryption-aws-kms-key-id"], "key-1");
        assert_eq!(h["x-amz-server-side-encryption-bucket-key-enabled"], "true");
        assert_eq!(h["x-amz-acl"], "private");
        assert_eq!(h["x-amz-meta-owner"], "me");
        assert_eq!(h["x-amz-request-payer"], "requester");
        assert!(q.is_empty());
        let mut h = HeaderMap::new();
        p.apply(Op::GetObject, &mut h, &mut q);
        assert!(!h.contains_key("x-amz-server-side-encryption"));
        assert_eq!(h["x-amz-request-payer"], "requester");
        assert_eq!(
            q,
            vec![("response-content-type".to_owned(), "text/plain".to_owned())]
        );
        assert_eq!(p.get("ACL"), Some("private"));
    }

    #[test]
    fn sse_c_key_gets_md5() {
        let key = "0123456789abcdef0123456789abcdef";
        let p = Params::from_map(
            &map(&[
                ("SSECustomerAlgorithm", "AES256".into()),
                ("SSECustomerKey", key.into()),
            ]),
            "x",
        )
        .unwrap();
        let mut h = HeaderMap::new();
        p.apply(Op::HeadObject, &mut h, &mut Vec::new());
        assert_eq!(
            h["x-amz-server-side-encryption-customer-key"],
            "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
        );
        assert_eq!(
            h["x-amz-server-side-encryption-customer-key-md5"],
            "hRasmdxgYDKV3nvbahU1MA=="
        );
        let raw = Params::from_map(
            &map(&[("SSECustomerKey", Value::Bytes(vec![0xff; 32]))]),
            "x",
        )
        .unwrap();
        assert!(raw.sse_c_headers().is_some());
    }

    #[test]
    fn rejects_unknown_and_mistyped() {
        assert!(Params::from_map(&map(&[("Bogus", "x".into())]), "x").is_err());
        assert!(Params::from_map(&map(&[("BucketKeyEnabled", "maybe".into())]), "x").is_err());
        assert!(Params::from_map(&map(&[("Metadata", "notamap".into())]), "x").is_err());
        let p = Params::from_map(&map(&[("ACL", Value::Null)]), "x").unwrap();
        assert!(p.is_empty());
    }

    #[test]
    fn merge_overrides() {
        let a = Params::from_map(&map(&[("ACL", "private".into())]), "x").unwrap();
        let b = Params::from_map(&map(&[("ACL", "public-read".into())]), "x").unwrap();
        assert_eq!(a.merged(&b).get("ACL"), Some("public-read"));
    }
}
