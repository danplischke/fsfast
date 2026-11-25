"""Regenerate tests/vectors.rs from azure-storage-blob's own signing code.

    .venv/bin/python crates/fsfast-azure/tools/gen_vectors.py > crates/fsfast-azure/tests/vectors.rs

Shared Key: SharedKeyCredentialPolicy.on_request on fixed requests with a
fixed x-ms-date; SAS: generate_blob_sas with a fixed expiry (sts_hook gives
the string-to-sign).
"""
import json

from azure.core.pipeline import PipelineRequest, PipelineContext
from azure.core.rest import HttpRequest
from azure.storage.blob._shared.authentication import SharedKeyCredentialPolicy
from azure.storage.blob import generate_blob_sas, BlobSasPermissions
from datetime import datetime, timezone
KEY = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
ACCT = "devstoreaccount1"
cases = [
  ("GET", "http://127.0.0.1:10000/devstoreaccount1/cont?restype=container&comp=list&prefix=a%20b%2F&delimiter=%2F&include=metadata", {}, b""),
  ("PUT", "https://acct.blob.core.windows.net/cont/dir/f%C3%BC%20x.bin?comp=block&blockid=QUFBQQ%3D%3D", {"Content-Type": "application/octet-stream"}, b"hello world"),
  ("PUT", "https://acct.blob.core.windows.net/cont/x", {"x-ms-blob-type": "BlockBlob", "x-ms-meta-is_directory": "false", "x-ms-blob-content-type": "text/plain", "If-None-Match": "*"}, b""),
  ("HEAD", "https://acct.blob.core.windows.net/cont/x?versionid=2026-01-01T00%3A00%3A00.0000000Z", {"If-Match": "\"0x1\"", "x-ms-range": "bytes=0-9"}, b""),
  ("DELETE", "https://acct.blob.core.windows.net/cont?restype=container&timeout=30", {}, b""),
]
out = []
for method, url, hdrs, body in cases:
    acct = ACCT if "127.0.0.1" in url else "acct"
    h = {"x-ms-version": "2024-11-04", "x-ms-date": "Wed, 25 Nov 2026 06:30:34 GMT"}
    h.update(hdrs)
    if body: h["Content-Length"] = str(len(body))
    req = HttpRequest(method, url, headers=h, content=body or None)
    preq = PipelineRequest(req, PipelineContext(None))
    pol = SharedKeyCredentialPolicy(acct, KEY)
    captured = {}
    orig = pol._add_authorization_header
    def cap(request, sts, _o=orig, _c=captured):
        _c["sts"] = sts; _o(request, sts)
    pol._add_authorization_header = cap
    pol.on_request(preq)
    out.append({"method": method, "url": url, "account": acct, "headers": {k:v for k,v in hdrs.items()}, "body_len": len(body), "sts": captured["sts"], "auth": req.headers["Authorization"]})
sas = []
exp = datetime(2026, 11, 25, 6, 30, 34, tzinfo=timezone.utc)
for blob, vid, extra in [("a b/ü.txt", None, {}), ("x", "2026-01-01T00:00:00.0000000Z", {}), ("dir/y", None, {"content_type": "text/plain", "content_disposition": "attachment", "start": datetime(2026,11,24,0,0,0,tzinfo=timezone.utc), "protocol": "https", "ip": "1.2.3.4"})]:
    captured = {}
    t = generate_blob_sas(ACCT, "cont", blob, account_key=KEY, permission=BlobSasPermissions(read=True), expiry=exp, version_id=vid, sts_hook=lambda s, c=captured: c.__setitem__("sts", s), **extra)
    sas.append({"blob": blob, "version_id": vid, "extra": {k:(v.strftime("%Y-%m-%dT%H:%M:%SZ") if isinstance(v, datetime) else v) for k,v in extra.items()}, "token": t, "sts": captured["sts"]})
import azure.storage.blob._serialize as s
VECTORS = json.loads(json.dumps({"shared_key": out, "sas": sas, "sdk_version": s._SUPPORTED_API_VERSIONS[-1]}, indent=1, ensure_ascii=False))

d = VECTORS
def r(s): return json.dumps(s, ensure_ascii=False)  # JSON string literal is a valid Rust literal for our content
out = []
out.append('''//! Signature vectors produced with azure-storage-blob 12.31.1's own code
//! (`SharedKeyCredentialPolicy.on_request` and `generate_blob_sas`, fixed
//! request and fixed date; regenerate with `tools/gen_vectors.py`), checked
//! against fsfast's implementation.

use std::time::{Duration, UNIX_EPOCH};

use fsfast_azure::auth::SharedKey;
use fsfast_azure::auth::sas::BlobSas;
use fsfast_azure::connstr::DEVSTORE_ACCOUNT_KEY;
use fsfast_http_transport::header::{HeaderName, HeaderValue};
use fsfast_http_transport::{Method, Request};

struct SkCase {
    method: &'static str,
    url: &'static str,
    account: &'static str,
    headers: &'static [(&'static str, &'static str)],
    body_len: u64,
    sts: &'static str,
    auth: &'static str,
}

const SHARED_KEY: &[SkCase] = &[''')
for c in d["shared_key"]:
    hs = ", ".join(f"({r(k.lower())}, {r(v)})" for k, v in c["headers"].items())
    out.append(f'''    SkCase {{
        method: {r(c["method"])},
        url: {r(c["url"])},
        account: {r(c["account"])},
        headers: &[{hs}],
        body_len: {c["body_len"]},
        sts: {r(c["sts"])},
        auth: {r(c["auth"])},
    }},''')
out.append('''];

#[test]
fn shared_key_matches_azure_sdk() {
    for c in SHARED_KEY {
        let method = Method::from_bytes(c.method.as_bytes()).unwrap();
        let mut req = Request::new(method, c.url).unwrap();
        let h = req.headers_mut();
        h.insert("x-ms-version", HeaderValue::from_static("2024-11-04"));
        h.insert("x-ms-date", HeaderValue::from_static("Wed, 25 Nov 2026 06:30:34 GMT"));
        for (k, v) in c.headers {
            h.insert(HeaderName::from_static(k), HeaderValue::from_static(v));
        }
        let key = SharedKey::new(c.account, DEVSTORE_ACCOUNT_KEY).unwrap();
        let sts = key.string_to_sign(c.method, req.url(), req.headers(), c.body_len);
        assert_eq!(sts, c.sts, "{} {}", c.method, c.url);
        assert_eq!(key.authorization(&sts), c.auth, "{} {}", c.method, c.url);
    }
}

struct SasCase {
    blob: &'static str,
    version_id: Option<&'static str>,
    start: Option<u64>,
    ip: Option<&'static str>,
    protocol: Option<&'static str>,
    content_type: Option<&'static str>,
    content_disposition: Option<&'static str>,
    sts: &'static str,
    token: &'static str,
}

const SAS: &[SasCase] = &[''')
import calendar, time
for c in d["sas"]:
    e = c["extra"]
    def o(k): return f"Some({r(e[k])})" if k in e else "None"
    start = "None"
    if "start" in e:
        start = f"Some({calendar.timegm(time.strptime(e['start'], '%Y-%m-%dT%H:%M:%SZ'))})"
    vid = f"Some({r(c['version_id'])})" if c["version_id"] else "None"
    out.append(f'''    SasCase {{
        blob: {r(c["blob"])},
        version_id: {vid},
        start: {start},
        ip: {o("ip")},
        protocol: {o("protocol")},
        content_type: {o("content_type")},
        content_disposition: {o("content_disposition")},
        sts: {r(c["sts"])},
        token: {r(c["token"])},
    }},''')
out.append(f'''];

#[test]
fn blob_sas_matches_generate_blob_sas() {{
    let key = SharedKey::new("devstoreaccount1", DEVSTORE_ACCOUNT_KEY).unwrap();
    let expiry = UNIX_EPOCH + Duration::from_secs({calendar.timegm((2026,11,25,6,30,34,0,0,0))});
    for c in SAS {{
        let sas = BlobSas {{
            container: "cont",
            blob: c.blob,
            permission: "r",
            expiry: Some(expiry),
            start: c.start.map(|s| UNIX_EPOCH + Duration::from_secs(s)),
            version: {r(d["sdk_version"])},
            version_id: c.version_id,
            ip: c.ip,
            protocol: c.protocol,
            content_type: c.content_type,
            content_disposition: c.content_disposition,
            ..BlobSas::default()
        }};
        let (sts, token) = sas.sign(&key);
        assert_eq!(sts, c.sts, "{{}}", c.blob);
        assert_eq!(token, c.token, "{{}}", c.blob);
    }}
}}
''')
print("\n".join(out))
