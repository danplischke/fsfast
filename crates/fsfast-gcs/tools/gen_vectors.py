# Generates tests/data/vectors.json: a throwaway RSA test key, the JWT
# assertion google-auth builds for it at a fixed time, and V4 signed URLs
# from google-cloud-storage. Run: .venv/bin/python -I crates/fsfast-gcs/tools/gen_vectors.py
# (writes vectors.json in the current directory).
import json, datetime
from unittest import mock
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from google.oauth2 import service_account
import google.auth._helpers as h
from google.cloud.storage import _signing
from google.cloud.storage.blob import _quote

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
pkcs1 = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode()
info = {
  "type": "service_account",
  "project_id": "fsfast-test",
  "private_key_id": "0123456789abcdef0123456789abcdef01234567",
  "private_key": pem,
  "client_email": "tester@fsfast-test.iam.gserviceaccount.com",
  "client_id": "123456789012345678901",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
}
scope = "https://www.googleapis.com/auth/devstorage.full_control"
creds = service_account.Credentials.from_service_account_info(info, scopes=[scope])
fixed = datetime.datetime(2026, 11, 24, 19, 16, 54)
with mock.patch.object(h, "utcnow", return_value=fixed):
    assertion = creds._make_authorization_grant_assertion()
iat = int((fixed - datetime.datetime(1970,1,1)).total_seconds())
name = "dir/odd name+%&~ü.bin"
resource = f"/bucket-1/{_quote(name, safe=b'/~')}"
url = _signing.generate_signed_url_v4(creds, resource, 3600, api_access_endpoint="https://storage.googleapis.com", _request_timestamp="20261124T191654Z")
url_gen = _signing.generate_signed_url_v4(creds, resource, 900, api_access_endpoint="http://127.0.0.1:4443", generation="1795547814877753", _request_timestamp="20261124T191654Z")
json.dump({"info": info, "pkcs1": pkcs1, "scope": scope, "iat": iat, "assertion": assertion.decode() if isinstance(assertion, bytes) else assertion,
  "object": name, "signed_url": url, "signed_url_gen": url_gen}, open("vectors.json", "w"), indent=1)
print(iat, url[:120])
