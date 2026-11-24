#!/usr/bin/env python3
"""Generate SigV4 test vectors for fsfast-s3 with botocore.

Run from the repository root:

    .venv/bin/python crates/fsfast-s3/tools/gen_sigv4_vectors.py \
        > crates/fsfast-s3/tests/data/sigv4_vectors.json

Three kinds of vectors are produced, all with fixed credentials and a fixed
clock so the output is deterministic:

* ``sign``: ``botocore.auth.S3SigV4Auth`` applied to an ``AWSRequest`` with
  explicit headers and body. Pins the canonical request, the string to sign
  and the Authorization header (header signing).
* ``url``: the URL a real botocore S3 client sends for an operation
  (captured in ``before-send``), pinning key/bucket/query encoding and
  addressing (path-style vs virtual-hosted).
* ``presign``: ``generate_presigned_url`` (SigV4 query auth), pinning the
  query parameters and the signature of pre-signed URLs.
"""

import datetime
import hashlib
import json
import sys
from urllib.parse import parse_qsl, urlsplit

import botocore.auth
import botocore.compat
import botocore.config
import botocore.session
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.utils import percent_encode

FIXED = datetime.datetime(2026, 11, 24, 12, 34, 56)
botocore.auth.get_current_datetime = lambda *a, **k: FIXED
botocore.compat.get_current_datetime = lambda *a, **k: FIXED

AK = "AKIDEXAMPLE"
SK = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
TOKEN = "IQoJb3JpZ2luX2VjEXAMPLE//+/token=="

KEYS = [
    "simple.txt",
    "a b.txt",
    "dir/sub dir/file name.csv",
    "unicode/ünïcödé/файл.txt",
    "emoji😀/x",
    "plus+equals=amp&semi;comma,",
    "tilde~under_score-dash.dot",
    "100%done %41",
    "double//slash",
    "trailing/",
    "/leading",
    "q?hash#pct%",
    "star*paren()quote'dq\"bang!dollar$at@colon:",
    "back\\slash^caret`tick{brace}|pipe<lt>gt[br]",
    "  spaces  ",
    "tab\tnew",
]


def sha(b):
    return hashlib.sha256(b).hexdigest()


def sign_case(name, method, url, headers, body=b"", payload="sha256", token=None,
              region="us-east-1"):
    creds = Credentials(AK, SK, token)
    req = AWSRequest(method=method, url=url, headers=dict(headers), data=body)
    # S3SigV4Auth decides the payload hash itself; steer it like a client
    # configured with s3={"payload_signing_enabled": ...} would.
    req.context["client_config"] = botocore.config.Config(
        s3={"payload_signing_enabled": payload == "sha256"})
    signer = botocore.auth.S3SigV4Auth(creds, "s3", region)
    # add_auth computes these from the request; recompute them for the record.
    signer.add_auth(req)
    authorization = req.headers["Authorization"]
    # Recompute the intermediate strings without the Authorization header
    # add_auth inserted (it is not part of what was signed).
    del req.headers["Authorization"]
    req.context["timestamp"] = FIXED.strftime("%Y%m%dT%H%M%SZ")
    cr = signer.canonical_request(req)
    sts = signer.string_to_sign(req, cr)
    return {
        "kind": "sign",
        "name": name,
        "method": method,
        "url": url,
        "region": region,
        "token": token,
        "headers": [[k, v] for k, v in headers],
        "body_hex": body.hex(),
        "payload": payload,
        "canonical_request": cr,
        "string_to_sign": sts,
        "authorization": authorization,
        "x_amz_date": req.headers["X-Amz-Date"],
        "x_amz_content_sha256": req.headers["X-Amz-Content-SHA256"],
    }


class Stop(Exception):
    pass


def client(endpoint=None, region="us-east-1", **cfg):
    s = botocore.session.get_session()
    return s.create_client(
        "s3",
        endpoint_url=endpoint,
        region_name=region,
        aws_access_key_id=AK,
        aws_secret_access_key=SK,
        config=botocore.config.Config(signature_version="s3v4", **cfg),
    )


def capture_url(c, op, **params):
    out = {}

    def hook(request, **kw):
        out["url"] = request.url
        raise Stop()

    c.meta.events.register("before-send.s3", hook)
    try:
        getattr(c, op)(**params)
    except Stop:
        pass
    finally:
        c.meta.events.unregister("before-send.s3", hook)
    return out["url"]


def url_case(name, endpoint, region, addressing, op, bucket, key=None, query=None, **cfg):
    s3cfg = dict(cfg.pop("s3", {}))
    if addressing:
        s3cfg["addressing_style"] = addressing
    c = client(endpoint, region, s3=s3cfg, **cfg)
    params = {"Bucket": bucket}
    if key is not None:
        params["Key"] = key
    params.update(query or {})
    url = capture_url(c, op, **params)
    parts = urlsplit(url)
    return {
        "kind": "url",
        "name": name,
        "endpoint": endpoint,
        "region": region,
        "addressing": addressing or "auto",
        "op": op,
        "bucket": bucket,
        "key": key,
        "params": {k: v for k, v in (query or {}).items() if not isinstance(v, bytes)},
        "scheme": parts.scheme,
        "netloc": parts.netloc,
        "path": parts.path,
        # Encoded pairs, as sent.
        "query": [p.split("=", 1) if "=" in p else [p, ""] for p in parts.query.split("&")]
        if parts.query else [],
    }


def presign_case(name, endpoint, region, bucket, key, expires, token=None, version_id=None,
                 addressing=None):
    s = botocore.session.get_session()
    s3cfg = {"addressing_style": addressing} if addressing else {}
    c = s.create_client(
        "s3", endpoint_url=endpoint, region_name=region,
        aws_access_key_id=AK, aws_secret_access_key=SK, aws_session_token=token,
        config=botocore.config.Config(signature_version="s3v4", s3=s3cfg),
    )
    params = {"Bucket": bucket, "Key": key}
    if version_id:
        params["VersionId"] = version_id
    url = c.generate_presigned_url("get_object", Params=params, ExpiresIn=expires)
    parts = urlsplit(url)
    return {
        "kind": "presign",
        "name": name,
        "endpoint": endpoint,
        "region": region,
        "addressing": addressing or "auto",
        "bucket": bucket,
        "key": key,
        "expires": expires,
        "token": token,
        "version_id": version_id,
        "scheme": parts.scheme,
        "netloc": parts.netloc,
        "path": parts.path,
        "query": [p.split("=", 1) for p in parts.query.split("&")],
    }


def main():
    cases = []
    ep = "http://127.0.0.1:9000"
    # Header signing.
    for i, key in enumerate(KEYS):
        path = "/bucket/" + percent_encode(key, safe="/~")
        cases.append(sign_case(f"get-key-{i}", "GET", ep + path, [], payload="sha256"))
    cases.append(sign_case(
        "head-token-virtual", "HEAD",
        "https://my-bucket.s3.eu-west-1.amazonaws.com/" + percent_encode("a b/ü.txt", safe="/~"),
        [], payload="sha256", token=TOKEN, region="eu-west-1"))
    cases.append(sign_case(
        "list-v2-query", "GET",
        ep + "/bucket?list-type=2&prefix=" + percent_encode("dir a/ü/") + "&delimiter=%2F"
        + "&continuation-token=" + percent_encode("1/ab+cd==") + "&max-keys=1000"
        + "&encoding-type=url",
        [], payload="sha256"))
    cases.append(sign_case(
        "list-v2-unsorted-dup", "GET",
        ep + "/bucket?prefix=b&list-type=2&a=2&a=1&start-after=" + percent_encode("x y"),
        [], payload="sha256"))
    cases.append(sign_case("create-mpu", "POST", ep + "/bucket/big%20file?uploads",
                           [("Content-Type", "application/octet-stream")], payload="sha256"))
    body = b"part data \x00\xff" * 100
    cases.append(sign_case(
        "upload-part-sha256", "PUT", ep + "/bucket/k?partNumber=3&uploadId=" + percent_encode("abc/def+=="),
        [("Content-Length", str(len(body)))], body=body, payload="sha256"))
    cases.append(sign_case(
        "put-unsigned-https", "PUT", "https://bucket.s3.amazonaws.com/k%20k",
        [("Content-Type", "text/plain"), ("x-amz-meta-note", "  multiple   spaces  here "),
         ("x-amz-server-side-encryption", "AES256"), ("x-amz-acl", "private"),
         ("Content-Length", "5"), ("If-None-Match", "*")],
        body=b"hello", payload="unsigned", token=TOKEN))
    xml = (b'<?xml version="1.0" encoding="UTF-8"?><Delete><Quiet>true</Quiet>'
           b'<Object><Key>a&amp;b</Key></Object></Delete>')
    import base64
    md5 = base64.b64encode(hashlib.md5(xml).digest()).decode()
    cases.append(sign_case(
        "delete-objects", "POST", ep + "/bucket?delete",
        [("Content-MD5", md5), ("Content-Type", "application/xml")], body=xml, payload="sha256"))
    cases.append(sign_case(
        "copy-object", "PUT", ep + "/dst/" + percent_encode("to ü", safe="/~"),
        [("x-amz-copy-source", "src/" + percent_encode("from ü+=", safe="/~")),
         ("x-amz-metadata-directive", "COPY")], payload="sha256"))
    cases.append(sign_case(
        "get-range-ifmatch", "GET", ep + "/bucket/obj?versionId=" + percent_encode("3/L4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY"),
        [("Range", "bytes=0-99"), ("If-Match", '"d41d8cd98f00b204e9800998ecf8427e"')],
        payload="sha256"))
    cases.append(sign_case(
        "sse-c", "GET", ep + "/bucket/obj",
        [("x-amz-server-side-encryption-customer-algorithm", "AES256"),
         ("x-amz-server-side-encryption-customer-key", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="),
         ("x-amz-server-side-encryption-customer-key-MD5", "zZ5FnqcIqUjVwvWmyog4zw=="),
         ("x-amz-request-payer", "requester")],
        payload="sha256"))
    cases.append(sign_case("list-buckets-root", "GET", ep + "/", [], payload="sha256"))
    cases.append(sign_case("ipv6-host", "GET", "http://[::1]:9000/bucket/k", [], payload="sha256"))
    cases.append(sign_case("default-port-https", "GET", "https://example.com/bucket/k", [], payload="sha256"))

    # URL construction by a real client.
    aws = None
    for i, key in enumerate(KEYS):
        cases.append(url_case(f"url-path-{i}", ep, "us-east-1", None, "head_object", "bucket", key))
        cases.append(url_case(f"url-aws-{i}", aws, "eu-west-1", None, "head_object", "my-bucket", key))
    cases.append(url_case("url-aws-us-east-1", aws, "us-east-1", None, "head_object", "my-bucket", "k"))
    cases.append(url_case("url-aws-dotted", aws, "eu-west-1", None, "head_object", "my.dotted.bucket", "k"))
    cases.append(url_case("url-aws-upper", aws, "eu-west-1", None, "head_object", "MyBucket", "k"))
    cases.append(url_case("url-aws-path-style", aws, "eu-west-1", "path", "head_object", "my-bucket", "k"))
    cases.append(url_case("url-custom-virtual", "http://example.com:9000", "eu-west-1", "virtual",
                          "head_object", "my-bucket", "k"))
    cases.append(url_case("url-custom-prefix", "http://example.com:9000/base/", "eu-west-1", None,
                          "head_object", "my-bucket", "k/l"))
    cases.append(url_case("url-cn", aws, "cn-north-1", None, "head_object", "my-bucket", "k"))
    cases.append(url_case("url-dualstack", aws, "eu-west-1", None, "head_object", "my-bucket", "k",
                          s3={"use_dualstack_endpoint": True}))
    cases.append(url_case("url-list", ep, "us-east-1", None, "list_objects_v2", "bucket", None,
                          {"Prefix": "a b/ü&=+", "Delimiter": "/", "MaxKeys": 1,
                           "ContinuationToken": "tok/+=", "StartAfter": "x~y"}))
    cases.append(url_case("url-versions", ep, "us-east-1", None, "list_object_versions", "bucket", None,
                          {"Prefix": "p", "KeyMarker": "k m", "VersionIdMarker": "v+1"}))
    cases.append(url_case("url-upload-part", ep, "us-east-1", None, "upload_part", "bucket", "a b",
                          {"PartNumber": 7, "UploadId": "u/+=id", "Body": b""}))
    cases.append(url_case("url-get-version", ep, "us-east-1", None, "get_object", "bucket", "k",
                          {"VersionId": "v 1+/"}))

    # Pre-signed URLs.
    for i, key in enumerate(["simple.txt", "a b/ü+=.txt", "trailing/", "double//slash"]):
        cases.append(presign_case(f"presign-path-{i}", ep, "us-east-1", "bucket", key, 3600))
    cases.append(presign_case("presign-token", ep, "eu-central-1", "bucket", "k", 100, token=TOKEN))
    cases.append(presign_case("presign-version", ep, "us-east-1", "bucket", "k", 604800,
                              version_id="3/L4kq+tJ"))
    cases.append(presign_case("presign-aws", None, "eu-west-1", "my-bucket", "dir/a b", 900))
    json.dump(cases, sys.stdout, indent=1, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
