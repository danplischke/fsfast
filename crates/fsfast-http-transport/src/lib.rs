//! The HTTP client shared by fsfast's HTTP-based backends (http, s3, gcs,
//! azure, webdav). See docs/adr/0002-http-client.md for why it is built on
//! reqwest.
//!
//! * [`HttpConfig`]: timeouts, pool size, HTTP/2, TLS verification and extra
//!   roots, default headers, Basic auth, cookies, proxy, retries, redirects,
//!   DNS rotation; with option parsers for the aiohttp/fsspec names
//!   ([`HttpConfig::apply_client_kwargs`], [`HttpConfig::apply_request_kwargs`])
//!   and fsfast's own tuning names ([`HttpConfig::apply_fsfast_options`]).
//! * [`HttpClient`]: cheap to clone. [`HttpClient::send`] retries retry-safe
//!   requests (idempotent methods with replayable bodies, or requests marked
//!   safe) through [`fsfast_engine::retry`](mod@fsfast_engine::retry), limits concurrency per host with
//!   an [`fsfast_engine::aimd::AimdLimiter`], and records
//!   [`fsfast_engine::stats::Stats`].
//! * Errors: statuses map onto precise [`fsfast_core::ErrorKind`]s with
//!   [`fsfast_core::Detail::Http`]; an [`ErrorParser`] decodes service error
//!   bodies into [`fsfast_core::Detail::Code`] (see [`error`]).
//! * Bodies: requests from [`bytes::Bytes`] without copying
//!   ([`RequestBody`]); responses collected into one pre-sized buffer
//!   ([`Response::bytes`]) or streamed ([`Response::into_stream`]).
//! * Ranges: [`Response::range_bytes`] returns exactly the requested bytes
//!   whether the server answered 206, 200 or 416 ([`range`]).
//!
//! Proxies: by default `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and
//! `NO_PROXY` are honoured (see [`ProxyConfig`]).
//!
//! ```no_run
//! # async fn demo() -> fsfast_core::Result<()> {
//! use fsfast_core::ByteRange;
//! use fsfast_http_transport::{HttpClient, HttpConfig, Request};
//!
//! let client = HttpClient::new(HttpConfig::default())?;
//! let req = Request::get("https://example.com/data.bin")?
//!     .range(ByteRange::Bounded { start: 0, end: 4096 });
//! // Retries the request *and* the body transfer on transient failures.
//! let head = client
//!     .send_with(req, |resp| async move { resp.range_bytes(ByteRange::Bounded { start: 0, end: 4096 }).await })
//!     .await?;
//! assert!(head.data.len() <= 4096);
//! # Ok(()) }
//! ```

#![warn(missing_docs)]

mod client;
pub mod config;
pub mod error;
mod idle;
pub mod range;
pub mod request;
pub mod resolver;
pub mod response;

pub use client::{HttpClient, HttpClientBuilder};
pub use config::{AuthEncoding, BasicAuth, HttpConfig, ProxyConfig};
pub use error::{
    ErrorParser, ServiceError, log_display, parse_retry_after, status_kind, status_retryable,
};
pub use range::{ContentRange, RangeReply, classify_range_response, parse_content_range};
pub use request::{BodyLengthMismatch, Request, RequestBody, redact_url};
pub use resolver::RotatingResolver;
pub use response::{BodyStream, RangeBody, Response};

/// Re-exported HTTP types (from the `http` crate via reqwest).
pub use reqwest::{Method, StatusCode, Url, Version, header};
