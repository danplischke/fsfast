//! Request plumbing: endpoint URLs, query strings, authentication headers,
//! requester-pays, and the one retry after a 401.

use std::future::Future;
use std::sync::Arc;

use fsfast_core::{Error, ErrorKind, Result};
use fsfast_http_transport::header::{AUTHORIZATION, HeaderName, HeaderValue};
use fsfast_http_transport::{HttpClient, Method, Request, Response, Url};

use crate::auth::Credentials;
use crate::options::RequesterPays;
use crate::path::quote;

/// A query string built from pairs; names and values are percent-encoded
/// like gcsfs's `quote` (so `+` and spaces are unambiguous).
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
        self.0.push_str(&quote(name));
        self.0.push('=');
        self.0.push_str(&quote(value));
        self
    }

    /// Append `name=value` when `value` is set.
    pub fn opt(&mut self, name: &str, value: Option<&str>) -> &mut Self {
        if let Some(v) = value {
            self.push(name, v);
        }
        self
    }

    /// Builder form of [`Query::push`].
    pub fn with(mut self, name: &str, value: &str) -> Self {
        self.push(name, value);
        self
    }

    /// Builder form of [`Query::opt`].
    pub fn with_opt(mut self, name: &str, value: Option<&str>) -> Self {
        self.opt(name, value);
        self
    }

    /// The encoded string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The GCS endpoints and credentials.
#[derive(Debug)]
pub struct Client {
    /// The shared HTTP client.
    pub http: HttpClient,
    /// `scheme://host[:port]`.
    pub location: String,
    /// Credentials (resolved on first use).
    pub creds: Arc<Credentials>,
    requester_pays: RequesterPays,
}

impl Client {
    /// A client for `location`.
    pub fn new(http: HttpClient, location: String, creds: Arc<Credentials>, requester_pays: RequesterPays) -> Self {
        Client {
            http,
            location,
            creds,
            requester_pays,
        }
    }

    /// `{location}/storage/v1/b/{bucket}`.
    pub fn bucket_url(&self, bucket: &str) -> String {
        format!("{}/storage/v1/b/{}", self.location, quote(bucket))
    }

    /// `{location}/storage/v1/b/{bucket}/o/{key}`.
    pub fn object_url(&self, bucket: &str, key: &str) -> String {
        format!("{}/storage/v1/b/{}/o/{}", self.location, quote(bucket), quote(key))
    }

    /// `{location}/download/storage/v1/b/{bucket}/o/{key}` (media).
    pub fn download_url(&self, bucket: &str, key: &str) -> String {
        format!(
            "{}/download/storage/v1/b/{}/o/{}",
            self.location,
            quote(bucket),
            quote(key)
        )
    }

    /// `{location}/upload/storage/v1/b/{bucket}/o`.
    pub fn upload_url(&self, bucket: &str) -> String {
        format!("{}/upload/storage/v1/b/{}/o", self.location, quote(bucket))
    }

    /// `{location}/storage/v1/b`.
    pub fn buckets_url(&self) -> String {
        format!("{}/storage/v1/b", self.location)
    }

    /// A request for `url` with `query` appended.
    pub fn request(&self, method: Method, url: &str, query: &Query) -> Result<Request> {
        let full = if query.as_str().is_empty() {
            url.to_owned()
        } else if url.contains('?') {
            format!("{url}&{}", query.as_str())
        } else {
            format!("{url}?{}", query.as_str())
        };
        let parsed = Url::parse(&full).map_err(|e| Error::invalid_input(format!("invalid URL {full:?}: {e}")))?;
        Request::from_url(method, parsed)
    }

    /// The project billed for requester-pays requests, if enabled.
    async fn user_project(&self) -> Result<Option<String>> {
        Ok(match &self.requester_pays {
            RequesterPays::Off => None,
            RequesterPays::Explicit(p) => Some(p.clone()),
            RequesterPays::Project => Some(
                self.creds
                    .resolve(&self.http)
                    .await?
                    .project
                    .clone()
                    .unwrap_or_default(),
            ),
        })
    }

    /// Add `userProject` for requester-pays buckets.
    async fn add_user_project(&self, req: &mut Request) -> Result<()> {
        if let Some(p) = self.user_project().await? {
            let u = req.url_mut();
            let q = match u.query() {
                Some(q) if !q.is_empty() => format!("{q}&userProject={}", quote(&p)),
                _ => format!("userProject={}", quote(&p)),
            };
            u.set_query(Some(&q));
        }
        Ok(())
    }

    /// Set `Authorization` (and `x-goog-user-project` for credentials with
    /// a quota project); returns the authorization header used.
    async fn add_auth(&self, req: &mut Request) -> Result<Option<HeaderValue>> {
        if self.creds.is_anonymous() {
            return Ok(None);
        }
        let resolved = self.creds.resolve(&self.http).await?;
        let Some(tokens) = &resolved.tokens else {
            return Ok(None);
        };
        let h = tokens.header(&self.http, self.creds.scope()).await?;
        req.headers_mut().insert(AUTHORIZATION, h.clone());
        if let Some(qp) = tokens.quota_project()
            && let Ok(v) = HeaderValue::try_from(qp)
        {
            req.headers_mut()
                .insert(HeaderName::from_static("x-goog-user-project"), v);
        }
        Ok(Some(h))
    }

    /// Send `req` (retried by the transport on transient failures) and
    /// process the response with `f`. A 401 drops the cached access token
    /// and the request is sent once more with a fresh one.
    pub async fn execute<T, F, Fut>(&self, req: Request, f: F) -> Result<T>
    where
        F: Fn(Response) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let mut req = req;
        self.add_user_project(&mut req).await?;
        let used = self.add_auth(&mut req).await?;
        let Some(used) = used else {
            return self.http.send_with(req, &f).await;
        };
        let retry = req.clone();
        match self.http.send_with(req, &f).await {
            Err(e) if e.http_status() == Some(401) => {
                let resolved = self.creds.resolve(&self.http).await?;
                let refreshable = resolved.tokens.as_ref().is_some_and(|t| t.invalidate(&used));
                if !refreshable {
                    return Err(e);
                }
                tracing::debug!("GCS returned 401; retrying with a fresh access token");
                let mut req = retry;
                self.add_auth(&mut req).await?;
                self.http.send_with(req, &f).await
            }
            other => other,
        }
    }

    /// Send `req` and read (discard) the body, so the connection is
    /// reused.
    pub async fn send_ok(&self, req: Request) -> Result<()> {
        self.execute(req, |r| async move { r.bytes().await.map(|_| ()) }).await
    }

    /// Send `req` and parse a JSON object from the body.
    pub async fn json(&self, req: Request) -> Result<serde_json::Map<String, serde_json::Value>> {
        self.execute(req, |r| async move {
            let path = r.path().to_owned();
            let body = r.bytes().await?;
            parse_json_object(&body).map_err(|e| e.with_path(path))
        })
        .await
    }

    /// The effective project (gcsfs `fs.project`).
    pub async fn project(&self) -> Result<Option<String>> {
        Ok(self.creds.resolve(&self.http).await?.project.clone())
    }
}

/// Parse a JSON object (an empty body is an empty object).
pub fn parse_json_object(body: &[u8]) -> Result<serde_json::Map<String, serde_json::Value>> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(serde_json::Map::new());
    }
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(m)) => Ok(m),
        Ok(_) => Err(Error::protocol("expected a JSON object in the response")),
        Err(e) => Err(Error::new(ErrorKind::Protocol, format!("invalid JSON response: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries() {
        let q = Query::new()
            .with("prefix", "a b/c+d")
            .with_opt("pageToken", None)
            .with("delimiter", "/");
        assert_eq!(q.as_str(), "prefix=a%20b%2Fc%2Bd&delimiter=%2F");
        assert_eq!(Query::new().as_str(), "");
    }

    #[test]
    fn json_bodies() {
        assert!(parse_json_object(b"").unwrap().is_empty());
        assert_eq!(parse_json_object(br#"{"a":1}"#).unwrap()["a"], 1);
        assert!(parse_json_object(b"[1]").is_err());
        assert!(parse_json_object(b"{").is_err());
    }
}
