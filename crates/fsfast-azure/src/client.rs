//! Request plumbing: endpoint URLs, query strings, authorization, the
//! server-side `timeout`, and one retry with a fresh token after a 401.

use std::future::Future;

use fsfast_core::{Error, Result};
use fsfast_http_transport::{HttpClient, Method, Request, Response, Url};

use crate::auth::Credential;
use crate::path::quote;

/// A query string built from pairs; names and values are percent-encoded
/// (everything but unreserved characters), so the Shared Key canonical form
/// (decoded values) is unambiguous.
#[derive(Debug, Default, Clone)]
pub struct Query(String);

impl Query {
    /// An empty query.
    pub fn new() -> Self {
        Query(String::new())
    }

    /// Append `name=value`.
    pub fn push(&mut self, name: &str, value: &str) -> &mut Self {
        if !self.0.is_empty() {
            self.0.push('&');
        }
        self.0.push_str(&quote(name, false));
        self.0.push('=');
        self.0.push_str(&quote(value, false));
        self
    }

    /// Builder form of [`Query::push`].
    pub fn with(mut self, name: &str, value: &str) -> Self {
        self.push(name, value);
        self
    }

    /// Append `name=value` when `value` is set.
    pub fn with_opt(mut self, name: &str, value: Option<&str>) -> Self {
        if let Some(v) = value {
            self.push(name, v);
        }
        self
    }

    /// The encoded string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The Blob service endpoint and credentials.
#[derive(Debug)]
pub struct Client {
    /// The shared HTTP client.
    pub http: HttpClient,
    /// Blob endpoint (`https://acct.blob.core.windows.net`, or a path-style
    /// emulator URL), without trailing slash.
    pub endpoint: String,
    /// How requests are authorized.
    pub cred: Credential,
    /// Server-side operation timeout (adlfs `timeout`), seconds.
    pub server_timeout: Option<u64>,
}

impl Client {
    /// `{endpoint}/{container}`.
    pub fn container_url(&self, container: &str) -> String {
        format!("{}/{}", self.endpoint, quote(container, false))
    }

    /// `{endpoint}/{container}/{blob}` (blob name quoted with `/` kept,
    /// like the SDK).
    pub fn blob_url(&self, container: &str, blob: &str) -> String {
        format!(
            "{}/{}/{}",
            self.endpoint,
            quote(container, false),
            quote(blob, true)
        )
    }

    /// A request for `url` + `query` (plus the server-side `timeout`).
    pub fn request(&self, method: Method, url: &str, query: &Query) -> Result<Request> {
        let mut q = query.as_str().to_owned();
        if let Some(t) = self.server_timeout {
            if !q.is_empty() {
                q.push('&');
            }
            q.push_str(&format!("timeout={t}"));
        }
        let full = if q.is_empty() {
            url.to_owned()
        } else {
            format!("{url}?{q}")
        };
        let parsed = Url::parse(&full)
            .map_err(|e| Error::invalid_input(format!("invalid URL {full:?}: {e}")))?;
        check_url_path(url, &parsed).map_err(|e| {
            let rel = url.strip_prefix(self.endpoint.as_str()).unwrap_or(url);
            e.with_path(crate::path::unquote(rel.trim_start_matches('/')).into_owned())
        })?;
        Request::from_url(method, parsed)
    }

    /// Authorize and send `req` (retried by the transport on transient
    /// failures) and process the response with `f`. A 401 with a bearer
    /// token drops the token and sends the request once more.
    pub async fn execute<T, F, Fut>(&self, req: Request, f: F) -> Result<T>
    where
        F: Fn(Response) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let len = req.body_ref().len().unwrap_or(0);
        let unsigned = matches!(self.cred, Credential::Bearer(_)).then(|| req.clone());
        let mut req = req;
        let used = self.cred.authorize(&mut req, len).await?;
        match self.http.send_with(req, &f).await {
            Err(e) if e.http_status() == Some(401) => {
                let Some(mut retry) = unsigned else {
                    return Err(e);
                };
                if !self.cred.on_unauthorized(&used).await {
                    return Err(e);
                }
                tracing::debug!("Blob service returned 401; retrying with a fresh token");
                self.cred.authorize(&mut retry, len).await?;
                self.http.send_with(retry, &f).await
            }
            other => other,
        }
    }

    /// Send `req`, drain the body, and return the response headers.
    pub async fn send_headers(&self, req: Request) -> Result<ResponseHead> {
        self.execute(req, |r| async move {
            let head = ResponseHead {
                status: r.status().as_u16(),
                headers: r.headers().clone(),
            };
            r.bytes().await?;
            Ok(head)
        })
        .await
    }

    /// Send `req` and return status, headers and body.
    pub async fn send_body(&self, req: Request) -> Result<(ResponseHead, bytes::Bytes)> {
        self.execute(req, |r| async move {
            let head = ResponseHead {
                status: r.status().as_u16(),
                headers: r.headers().clone(),
            };
            let body = r.bytes().await?;
            Ok((head, body))
        })
        .await
    }
}

/// The path part of an absolute URL string (between the authority and the
/// query), as written.
fn raw_path(url: &str) -> &str {
    let rest = url.find("://").map_or(url, |i| &url[i + 3..]);
    let rest = rest.find('/').map_or("", |i| &rest[i..]);
    rest.find(['?', '#']).map_or(rest, |i| &rest[..i])
}

/// Fail when URL parsing changed the path of `url`: a container or blob
/// name with `.` or `..` segments (`a/../b`, `d/.`) is resolved away by the
/// URL parser (and by the service), so the request would address a
/// *different* blob. Such names cannot be used through the Blob REST API.
pub(crate) fn check_url_path(url: &str, parsed: &Url) -> Result<()> {
    let raw = raw_path(url);
    let raw = if raw.is_empty() { "/" } else { raw };
    if parsed.path() == raw {
        return Ok(());
    }
    Err(Error::invalid_input(format!(
        "blob or container name with '.' or '..' path segments cannot be addressed: {}",
        crate::path::unquote(raw)
    )))
}

/// [`check_url_path`] for a URL that is not sent as the request target
/// (a copy source).
pub(crate) fn check_url(url: &str) -> Result<()> {
    let parsed =
        Url::parse(url).map_err(|e| Error::invalid_input(format!("invalid URL {url:?}: {e}")))?;
    check_url_path(url, &parsed)
}

/// Status and headers of a response whose body was consumed.
#[derive(Debug, Clone)]
pub struct ResponseHead {
    /// HTTP status.
    pub status: u16,
    /// Response headers.
    pub headers: fsfast_http_transport::header::HeaderMap,
}

impl ResponseHead {
    /// A header as a string.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries() {
        let q = Query::new()
            .with("restype", "container")
            .with("prefix", "a b/c+d")
            .with_opt("marker", None);
        assert_eq!(q.as_str(), "restype=container&prefix=a%20b%2Fc%2Bd");
    }

    #[test]
    fn dot_segments_are_detected() {
        for ok in [
            "http://h:1/acct/c/a",
            "http://h/acct/c/dots..",
            "http://h/acct/c/..x/.y/...",
            "http://h",
            "https://h/c/a%2F..",
            "http://h/acct/c//double",
        ] {
            check_url(ok).unwrap();
        }
        for bad in [
            "http://h/acct/c/a/../b",
            "http://h/acct/c/./b",
            "http://h/acct/c/d/.",
            "http://h/acct/c/e/..",
            "http://h/acct/c/a/%2E%2E/b",
        ] {
            let e = check_url(bad).unwrap_err();
            assert_eq!(e.kind(), fsfast_core::ErrorKind::InvalidInput, "{bad}");
        }
    }
}
