//! Request URLs: AWS regional endpoints or a custom `endpoint_url`, with
//! path-style or virtual-hosted addressing (botocore's defaults: virtual
//! hosting on AWS for DNS-compatible bucket names, path style for custom
//! endpoints unless `addressing_style` says otherwise).

use fsfast_core::{Error, Result};
use fsfast_http_transport::Url;

use crate::encode::uri_encode;
use crate::path::is_virtual_hostable;

/// `config_kwargs={"s3": {"addressing_style": ...}}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Addressing {
    /// Virtual-hosted on AWS when the bucket name allows it, else path style.
    #[default]
    Auto,
    /// `https://endpoint/bucket/key`.
    Path,
    /// `https://bucket.endpoint/key`.
    Virtual,
}

impl Addressing {
    /// Parse botocore's names (`auto`, `path`, `virtual`).
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "auto" => Ok(Addressing::Auto),
            "path" => Ok(Addressing::Path),
            "virtual" => Ok(Addressing::Virtual),
            other => Err(Error::invalid_input(format!(
                "addressing_style must be 'auto', 'path' or 'virtual', got {other:?}"
            ))),
        }
    }
}

/// Where requests go.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// `Some(url)`: a custom endpoint; `None`: AWS.
    pub custom: Option<Url>,
    /// Addressing style.
    pub addressing: Addressing,
    /// HTTPS for AWS endpoints (`use_ssl`).
    pub use_ssl: bool,
    /// Dual-stack (IPv4+IPv6) AWS endpoints.
    pub dualstack: bool,
    /// FIPS AWS endpoints.
    pub fips: bool,
    /// Transfer Acceleration endpoints.
    pub accelerate: bool,
    /// `us-east-1` uses `s3.us-east-1.amazonaws.com` instead of the legacy
    /// global `s3.amazonaws.com`.
    pub us_east_1_regional: bool,
}

impl Endpoint {
    /// AWS endpoints with default settings.
    pub fn aws() -> Self {
        Endpoint {
            custom: None,
            addressing: Addressing::Auto,
            use_ssl: true,
            dualstack: false,
            fips: false,
            accelerate: false,
            us_east_1_regional: false,
        }
    }

    /// A custom endpoint (`endpoint_url`).
    pub fn custom(url: &str) -> Result<Self> {
        let mut u = Url::parse(url)
            .map_err(|e| Error::invalid_input(format!("invalid endpoint_url {url:?}: {e}")))?;
        if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
            return Err(Error::invalid_input(format!(
                "endpoint_url must be an http(s) URL with a host, got {url:?}"
            )));
        }
        u.set_query(None);
        u.set_fragment(None);
        Ok(Endpoint {
            custom: Some(u),
            ..Endpoint::aws()
        })
    }

    /// Whether requests go to AWS (not a custom endpoint).
    pub fn is_aws(&self) -> bool {
        self.custom.is_none()
    }

    fn aws_host(&self, region: &str) -> String {
        let suffix = if region.starts_with("cn-") {
            "amazonaws.com.cn"
        } else {
            "amazonaws.com"
        };
        if self.accelerate {
            let ds = if self.dualstack { ".dualstack" } else { "" };
            return format!("s3-accelerate{ds}.{suffix}");
        }
        match (self.fips, self.dualstack) {
            (true, true) => format!("s3-fips.dualstack.{region}.{suffix}"),
            (true, false) => format!("s3-fips.{region}.{suffix}"),
            (false, true) => format!("s3.dualstack.{region}.{suffix}"),
            (false, false) if region == "us-east-1" && !self.us_east_1_regional => {
                format!("s3.{suffix}")
            }
            (false, false) => format!("s3.{region}.{suffix}"),
        }
    }

    /// The URL of a request: `bucket` (none for `ListBuckets`), `key` (none
    /// for bucket operations; encoded once, `/` kept), and the query
    /// parameters (unencoded; an empty value renders as a bare name like
    /// `?uploads`).
    pub fn url(
        &self,
        bucket: Option<&str>,
        key: Option<&str>,
        query: &[(String, String)],
        region: &str,
    ) -> Result<Url> {
        if let Some(k) = key
            && k.split('/').any(|seg| seg == "." || seg == "..")
        {
            // URL parsers (WHATWG, and so reqwest) resolve dot segments, so
            // such a key would silently address a different object.
            return Err(Error::invalid_input(format!(
                "object keys with '.' or '..' path segments are not supported: {k:?}"
            ))
            .with_path(format!("{}/{k}", bucket.unwrap_or(""))));
        }
        let (scheme, host, base_path) = match &self.custom {
            Some(u) => {
                let host = match u.port() {
                    Some(p) => format!("{}:{p}", u.host_str().unwrap_or("")),
                    None => u.host_str().unwrap_or("").to_owned(),
                };
                (u.scheme(), host, u.path().trim_end_matches('/').to_owned())
            }
            None => (
                if self.use_ssl { "https" } else { "http" },
                self.aws_host(region),
                String::new(),
            ),
        };
        let virtual_host = match bucket {
            None => false,
            Some(b) => match self.addressing {
                Addressing::Path => false,
                Addressing::Virtual => true,
                Addressing::Auto => {
                    (self.is_aws() || self.accelerate) && is_virtual_hostable(b, scheme == "http")
                }
            },
        };
        let mut s = String::with_capacity(64 + key.map_or(0, str::len));
        s.push_str(scheme);
        s.push_str("://");
        if virtual_host && let Some(b) = bucket {
            s.push_str(b);
            s.push('.');
        }
        s.push_str(&host);
        s.push_str(&base_path);
        s.push('/');
        if !virtual_host && let Some(b) = bucket {
            s.push_str(&uri_encode(b, false));
            if key.is_some() {
                s.push('/');
            }
        }
        if let Some(k) = key {
            s.push_str(&uri_encode(k, true));
        }
        if !query.is_empty() {
            s.push('?');
            for (i, (k, v)) in query.iter().enumerate() {
                if i > 0 {
                    s.push('&');
                }
                s.push_str(&uri_encode(k, false));
                if !v.is_empty() {
                    s.push('=');
                    s.push_str(&uri_encode(v, false));
                }
            }
        }
        Url::parse(&s).map_err(|e| Error::invalid_input(format!("cannot build request URL {s:?}: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(a, b)| ((*a).into(), (*b).into())).collect()
    }

    #[test]
    fn aws_urls() {
        let e = Endpoint::aws();
        let u = e.url(Some("my-bucket"), Some("a b/c"), &[], "eu-west-1").unwrap();
        assert_eq!(u.as_str(), "https://my-bucket.s3.eu-west-1.amazonaws.com/a%20b/c");
        let u = e.url(Some("my-bucket"), Some("k"), &[], "us-east-1").unwrap();
        assert_eq!(u.as_str(), "https://my-bucket.s3.amazonaws.com/k");
        let u = e.url(Some("my.bucket"), Some("k"), &[], "eu-west-1").unwrap();
        assert_eq!(u.as_str(), "https://s3.eu-west-1.amazonaws.com/my.bucket/k");
        let u = e.url(None, None, &[], "eu-west-1").unwrap();
        assert_eq!(u.as_str(), "https://s3.eu-west-1.amazonaws.com/");
        let u = e
            .url(Some("b-b-b"), None, &q(&[("list-type", "2"), ("prefix", "a/b c")]), "cn-north-1")
            .unwrap();
        assert_eq!(
            u.as_str(),
            "https://b-b-b.s3.cn-north-1.amazonaws.com.cn/?list-type=2&prefix=a%2Fb%20c"
        );
        let u = e.url(Some("bbb"), Some("k"), &q(&[("uploads", "")]), "us-west-2").unwrap();
        assert_eq!(u.as_str(), "https://bbb.s3.us-west-2.amazonaws.com/k?uploads");
    }

    #[test]
    fn custom_urls() {
        let e = Endpoint::custom("http://127.0.0.1:9000").unwrap();
        let u = e.url(Some("bucket"), Some("//double"), &[], "us-east-1").unwrap();
        assert_eq!(u.as_str(), "http://127.0.0.1:9000/bucket///double");
        let u = e.url(Some("bucket"), None, &[], "us-east-1").unwrap();
        assert_eq!(u.as_str(), "http://127.0.0.1:9000/bucket");
        let e = Endpoint::custom("http://example.com:9000/base/").unwrap();
        let u = e.url(Some("b"), Some("k/l"), &[], "x").unwrap();
        assert_eq!(u.as_str(), "http://example.com:9000/base/b/k/l");
        let mut e = Endpoint::custom("http://example.com:9000").unwrap();
        e.addressing = Addressing::Virtual;
        let u = e.url(Some("my-bucket"), Some("k"), &[], "x").unwrap();
        assert_eq!(u.as_str(), "http://my-bucket.example.com:9000/k");
    }

    #[test]
    fn dot_segments_are_rejected() {
        let e = Endpoint::custom("http://h").unwrap();
        assert!(e.url(Some("b"), Some("a/../b"), &[], "r").is_err());
        assert!(e.url(Some("b"), Some("."), &[], "r").is_err());
        assert!(e.url(Some("b"), Some("a/.hidden/..x"), &[], "r").is_ok());
    }
}
