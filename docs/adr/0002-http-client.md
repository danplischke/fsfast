# ADR-0002: Build the shared HTTP transport on reqwest

- Status: accepted
- Date: 2026-11-24

## Context

Five backends speak HTTP: http(s), S3, GCS, Azure Blob/ADLS and WebDAV.
They all need the same client machinery, which lives in
`crates/fsfast-http-transport`:

- **Proxies.** `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY` must be
  honoured: in many deployments (and in our own development environment)
  direct outbound connections are blocked, while local services have to
  bypass the proxy. This means HTTPS through `CONNECT` tunnels, proxy
  authentication, and `NO_PROXY` matching on domains, IPs and CIDR blocks.
- **Connections.** Pooling and keep-alive, HTTP/2 negotiated through ALPN
  (GCS benefits), HTTP/1.1 otherwise.
- **TLS.** rustls, the OS trust store, extra CA bundles, and an explicit
  "do not verify" switch (aiohttp's `ssl=False`).
- **DNS.** A pluggable resolver. Object-store endpoints resolve to many
  addresses, and AWS CRT gets much of its S3 throughput from spreading
  connections over all of them.
- **Bodies.** Streaming in both directions, with no copies of request bodies.
- **Redirects.** Following them, and dropping credentials on cross-origin
  hops.

PLAN §4.8 suggested hyper 1.x plus hyper-util with our own connector and
pool, for maximum control.

## Options considered

1. **Raw hyper + hyper-util, own connector and pool.** Full control, but we
   would have to rebuild what reqwest already does correctly: proxy
   tunnelling and authentication, `NO_PROXY` semantics, redirect policy
   with sensitive-header stripping, ALPN-driven HTTP/2 selection, and
   connect timeouts. Each is a known source of
   subtle bugs, and proxy handling is mandatory here, not optional.
2. **reqwest**, built on the same hyper/hyper-util stack. It covers every
   requirement above and still lets us plug in a resolver
   (`ClientBuilder::dns_resolver`) and connector layers.
3. **libcurl bindings / isahc** (a C dependency and a different async
   model) or **ureq** (blocking). Both rejected.

## Decision

Use **reqwest 0.13** with `default-features = false` and only these
features:

- `rustls`: aws-lc-rs as the crypto provider, plus
  `rustls-platform-verifier`, which uses the OS trust store and also honours
  `SSL_CERT_FILE`.
- `http2`: offered through ALPN; HTTP/2 without TLS (h2c) is available with
  prior knowledge.
- `stream`: streaming request and response bodies.

Native TLS is not compiled in. Automatic decompression is deliberately off:
sizes and byte ranges must refer to the stored bytes, so the http backend
also sends `Accept-Encoding: identity`.

fsfast's own policy layer sits on top of reqwest:

- **Retries.** `HttpClient::send` retries through `fsfast_engine::retry`
  (full jitter, `Retry-After` honoured), but only for retry-safe requests:
  idempotent methods with a replayable body, or requests marked safe by the
  caller. `send_with` retries the body transfer too. TLS certificate
  failures and request bodies of the wrong length are classified as not
  retryable.
- **Concurrency.** Each host has an `fsfast_engine::aimd::AimdLimiter`.
  reqwest's pool caps only *idle* connections, so this limiter is what
  bounds concurrent requests per host. A response holds its permit until
  its body has been collected; a stream releases the permit straight away,
  so that a long-lived stream cannot starve other requests.
- **Timeouts.** reqwest provides the connect timeout. The read timeout is
  fsfast's own *idle* timeout (`crate::idle`): a request fails only after
  `read_timeout` (default 120 s) without progress in either direction, so
  a multi-GiB upload or download that keeps moving is never cut off.
  reqwest's `read_timeout` is not used for this, because it is a fixed
  deadline up to the response head and would kill long uploads. aiohttp's
  300 s *total* timeout is deliberately not copied.
- **Redirects of request bodies.** reqwest can resend a body on 307/308
  only when it holds the whole body in memory. fsfast keeps in-memory bodies
  up to 16 MiB resendable. Larger bodies and streams are sent in slices so
  that the idle timeout sees progress, and a 307/308 for them fails with an
  error instead of silently not resending the body.
- **Statistics.** `fsfast_engine::stats::Stats` counts requests, errors,
  bytes, retries and throttles, and keeps latency histograms per operation.
- **Error mapping.** Status codes map to `ErrorKind`s, with
  `Detail::Http` attached. An `ErrorParser` hook lets each service turn its
  error body into `Detail::Code`, and a request can override the kind
  chosen for a given status.
- **Bodies and ranges.**
  - A body sent as one chunk is returned with no copy at all. Otherwise,
    when the length is known, it is collected into a single pre-sized
    buffer; when it is not, the chunks are gathered and concatenated once.
  - Range replies are classified as 206, 200 or 416, so callers always get
    exactly the bytes they asked for, even from servers that ignore
    `Range`.
- **DNS rotation.** `RotatingResolver` returns all A and AAAA records,
  rotated within each address family on every lookup. It is enabled with
  `HttpConfig::rotate_dns`. The S3/GCS backends are expected to turn it on;
  it is off by default.
- **Option parsing** is shared across backends, using the aiohttp/fsspec
  names (`client_kwargs` and per-request keywords) plus fsfast tuning
  options.

## Consequences

- **Proxy defaults.** Environment proxies are honoured by default. This
  deliberately differs from aiohttp, whose `trust_env` defaults to `False`.
  `client_kwargs={"trust_env": False}` restores direct connections, and
  `proxy=` forces a proxy and ignores the environment.
- **Pool control.** We do not control which pooled connection carries a
  request, or exactly how many connections are opened per IP. If S3 at
  very high bandwidth needs CRT-style connection placement, a custom
  connector can be plugged in through reqwest's `connector_layer`, or this
  decision can be revisited for that backend alone.
- **Build requirements.** aws-lc-sys needs a C toolchain and cmake at build
  time, both of which CI must provide. Using ring instead would mean
  installing a process-wide default rustls provider before building clients.
- **Cookies.** Only static cookies are sent (the `cookies` option). A
  persistent cookie jar like aiohttp's `CookieJar`, which stores
  `Set-Cookie` headers across requests, is not enabled: it pulls in the
  `cookie_store` dependency, and no target workload needs it yet.
- **Revisit** if profiling shows reqwest's per-request overhead mattering
  next to I/O, if we need HTTP/3, or if the pool model gets in the way of
  the throughput targets in PLAN §8.4.
