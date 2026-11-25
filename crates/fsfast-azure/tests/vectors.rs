//! Signature vectors produced with azure-storage-blob 12.31.1's own code
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

const SHARED_KEY: &[SkCase] = &[
    SkCase {
        method: "GET",
        url: "http://127.0.0.1:10000/devstoreaccount1/cont?restype=container&comp=list&prefix=a%20b%2F&delimiter=%2F&include=metadata",
        account: "devstoreaccount1",
        headers: &[],
        body_len: 0,
        sts: "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:Wed, 25 Nov 2026 06:30:34 GMT\nx-ms-version:2024-11-04\n/devstoreaccount1/devstoreaccount1/cont\ncomp:list\ndelimiter:/\ninclude:metadata\nprefix:a b/\nrestype:container",
        auth: "SharedKey devstoreaccount1:FgBV+ZKcFQ9UasxKLsUcY5ojgdR9B8qCbM8Jo5avA2w=",
    },
    SkCase {
        method: "PUT",
        url: "https://acct.blob.core.windows.net/cont/dir/f%C3%BC%20x.bin?comp=block&blockid=QUFBQQ%3D%3D",
        account: "acct",
        headers: &[("content-type", "application/octet-stream")],
        body_len: 11,
        sts: "PUT\n\n\n11\n\napplication/octet-stream\n\n\n\n\n\n\nx-ms-date:Wed, 25 Nov 2026 06:30:34 GMT\nx-ms-version:2024-11-04\n/acct/cont/dir/f%C3%BC%20x.bin\nblockid:QUFBQQ==\ncomp:block",
        auth: "SharedKey acct:/mMJyKl4P65XgMUiL9cM3ADYCIAj3fcfjPiXjmol3mU=",
    },
    SkCase {
        method: "PUT",
        url: "https://acct.blob.core.windows.net/cont/x",
        account: "acct",
        headers: &[
            ("x-ms-blob-type", "BlockBlob"),
            ("x-ms-meta-is_directory", "false"),
            ("x-ms-blob-content-type", "text/plain"),
            ("if-none-match", "*"),
        ],
        body_len: 0,
        sts: "PUT\n\n\n\n\n\n\n\n\n*\n\n\nx-ms-blob-content-type:text/plain\nx-ms-blob-type:BlockBlob\nx-ms-date:Wed, 25 Nov 2026 06:30:34 GMT\nx-ms-meta-is_directory:false\nx-ms-version:2024-11-04\n/acct/cont/x",
        auth: "SharedKey acct:JuyFyEuq5/KoVj1XAcAelko11So0o091J8A9drcu8PM=",
    },
    SkCase {
        method: "HEAD",
        url: "https://acct.blob.core.windows.net/cont/x?versionid=2026-01-01T00%3A00%3A00.0000000Z",
        account: "acct",
        headers: &[("if-match", "\"0x1\""), ("x-ms-range", "bytes=0-9")],
        body_len: 0,
        sts: "HEAD\n\n\n\n\n\n\n\n\"0x1\"\n\n\n\nx-ms-date:Wed, 25 Nov 2026 06:30:34 GMT\nx-ms-range:bytes=0-9\nx-ms-version:2024-11-04\n/acct/cont/x\nversionid:2026-01-01T00:00:00.0000000Z",
        auth: "SharedKey acct:0tWWw4guGq/AnrhWyifjnjUR8AOJ0b34X4hpQVjhmFA=",
    },
    SkCase {
        method: "DELETE",
        url: "https://acct.blob.core.windows.net/cont?restype=container&timeout=30",
        account: "acct",
        headers: &[],
        body_len: 0,
        sts: "DELETE\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:Wed, 25 Nov 2026 06:30:34 GMT\nx-ms-version:2024-11-04\n/acct/cont\nrestype:container\ntimeout:30",
        auth: "SharedKey acct:BC0NTOMNZtKi7PQoOnr/1nG/dgGrA5gSI+QUgBmk0pk=",
    },
];

#[test]
fn shared_key_matches_azure_sdk() {
    for c in SHARED_KEY {
        let method = Method::from_bytes(c.method.as_bytes()).unwrap();
        let mut req = Request::new(method, c.url).unwrap();
        let h = req.headers_mut();
        h.insert("x-ms-version", HeaderValue::from_static("2024-11-04"));
        h.insert(
            "x-ms-date",
            HeaderValue::from_static("Wed, 25 Nov 2026 06:30:34 GMT"),
        );
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

const SAS: &[SasCase] = &[
    SasCase {
        blob: "a b/ü.txt",
        version_id: None,
        start: None,
        ip: None,
        protocol: None,
        content_type: None,
        content_disposition: None,
        sts: "r\n\n2026-11-25T06:30:34Z\n/blob/devstoreaccount1/cont/a b/ü.txt\n\n\n\n2026-10-06\nb\n\n\n\n\n\n\n",
        token: "se=2026-11-25T06%3A30%3A34Z&sp=r&sv=2026-10-06&sr=b&sig=cOrfl4qwLveXe%2BMzSiMrbgmzI7XgYpZRCz%2BC4F22cvc%3D",
    },
    SasCase {
        blob: "x",
        version_id: Some("2026-01-01T00:00:00.0000000Z"),
        start: None,
        ip: None,
        protocol: None,
        content_type: None,
        content_disposition: None,
        sts: "r\n\n2026-11-25T06:30:34Z\n/blob/devstoreaccount1/cont/x\n\n\n\n2026-10-06\nbv\n2026-01-01T00:00:00.0000000Z\n\n\n\n\n\n",
        token: "se=2026-11-25T06%3A30%3A34Z&sp=r&sv=2026-10-06&sr=bv&sig=O%2B2wcRAjNMl70gDbWoIO7iZSK3SgPB%2Bi5EmwFxg5j7A%3D",
    },
    SasCase {
        blob: "dir/y",
        version_id: None,
        start: Some(1795478400),
        ip: Some("1.2.3.4"),
        protocol: Some("https"),
        content_type: Some("text/plain"),
        content_disposition: Some("attachment"),
        sts: "r\n2026-11-24T00:00:00Z\n2026-11-25T06:30:34Z\n/blob/devstoreaccount1/cont/dir/y\n\n1.2.3.4\nhttps\n2026-10-06\nb\n\n\n\nattachment\n\n\ntext/plain",
        token: "st=2026-11-24T00%3A00%3A00Z&se=2026-11-25T06%3A30%3A34Z&sp=r&sip=1.2.3.4&spr=https&sv=2026-10-06&sr=b&rscd=attachment&rsct=text/plain&sig=cZmwPjSFmsQQu/wsSNjxHLrK1wGplLMb%2BclfvFEtzzI%3D",
    },
];

#[test]
fn blob_sas_matches_generate_blob_sas() {
    let key = SharedKey::new("devstoreaccount1", DEVSTORE_ACCOUNT_KEY).unwrap();
    let expiry = UNIX_EPOCH + Duration::from_secs(1795588234);
    for c in SAS {
        let sas = BlobSas {
            container: "cont",
            blob: c.blob,
            permission: "r",
            expiry: Some(expiry),
            start: c.start.map(|s| UNIX_EPOCH + Duration::from_secs(s)),
            version: "2026-10-06",
            version_id: c.version_id,
            ip: c.ip,
            protocol: c.protocol,
            content_type: c.content_type,
            content_disposition: c.content_disposition,
            ..BlobSas::default()
        };
        let (sts, token) = sas.sign(&key);
        assert_eq!(sts, c.sts, "{}", c.blob);
        assert_eq!(token, c.token, "{}", c.blob);
    }
}
