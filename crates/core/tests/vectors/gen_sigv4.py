"""Generate tests/vectors/sigv4.json with botocore, AWS's own signer.

    python -m venv venv && venv/bin/pip install botocore
    venv/bin/python crates/core/tests/vectors/gen_sigv4.py > crates/core/tests/vectors/sigv4.json

Each vector records the request as it goes on the wire, the headers botocore
signed, and the canonical request and signature botocore produced. The Rust
test feeds the same inputs to `broker::sigv4::sign` and compares both.
"""
import json
import sys
from urllib.parse import urlsplit

import botocore
from botocore.auth import S3SigV4Auth, SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

AKID = "AKIDEXAMPLE"
SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
TOKEN = "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA=="


def vector(name, service, region, ts, method, url, headers=None, body=b"", token=None):
    creds = Credentials(AKID, SECRET, token)
    s3 = service == "s3"
    auth = (S3SigV4Auth if s3 else SigV4Auth)(creds, service, region)
    req = AWSRequest(method=method, url=url, data=body, headers=dict(headers or {}))
    req.context["timestamp"] = ts
    if s3:
        req.context["payload_signing_enabled"] = True
    auth._modify_request_before_signing(req)
    canonical = auth.canonical_request(req)
    string_to_sign = auth.string_to_sign(req, canonical)
    signature = auth.signature(string_to_sign, req)
    parts = urlsplit(url)
    signed_names = auth.signed_headers(auth.headers_to_sign(req)).split(";")
    signed = []
    for n in signed_names:
        if n == "host":
            signed.append(["host", parts.netloc])
            continue
        for k, v in req.headers.items():
            if k.lower() == n:
                signed.append([n, v.decode() if isinstance(v, bytes) else v])
    return {
        "name": name,
        "service": service,
        "region": region,
        "amz_date": ts,
        "access_key_id": AKID,
        "secret_access_key": SECRET,
        "session_token": token,
        "method": method,
        "path": parts.path,
        "query": parts.query or None,
        "headers": signed,
        "payload_hash": canonical.rsplit("\n", 1)[1],
        "body_utf8": body.decode(),
        "canonical_request": canonical,
        "signature": signature,
    }


TS = "20150830T123600Z"
vectors = [
    vector("iam-list-users (the AWS General Reference example)", "iam", "us-east-1", TS, "GET",
           "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
           {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}),
    vector("get-vanilla", "service", "us-east-1", TS, "GET", "https://example.amazonaws.com/"),
    vector("query-order-and-encoding", "sqs", "eu-west-1", TS, "GET",
           "https://sqs.eu-west-1.amazonaws.com/123456789012/my-queue?b=2&a=2&a=1&Param=value%20with%20spaces&unreserved=-._~&slash=a%2Fb&plus=x%2By&empty="),
    vector("dynamodb-json-target", "dynamodb", "us-west-2", "20261007T101112Z", "POST",
           "https://dynamodb.us-west-2.amazonaws.com/",
           {"Content-Type": "application/x-amz-json-1.0", "X-Amz-Target": "DynamoDB_20120810.GetItem"},
           b'{"TableName":"users","Key":{"id":{"S":"42"}}}'),
    vector("session-token", "sts", "ap-south-1", "20261007T101112Z", "POST",
           "https://sts.ap-south-1.amazonaws.com/",
           {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
           b"Action=GetCallerIdentity&Version=2011-06-15", token=TOKEN),
    vector("execute-api-path-is-encoded-twice", "execute-api", "us-east-1", TS, "GET",
           "https://abc123.execute-api.us-east-1.amazonaws.com/prod/items/a%20b/caf%C3%A9?q=1"),
    vector("non-s3-path-normalised", "lambda", "us-east-1", TS, "GET",
           "https://lambda.us-east-1.amazonaws.com/2015-03-31/./functions/../functions//my-fn/"),
    vector("header-whitespace-collapsed", "service", "us-east-1", TS, "GET",
           "https://example.amazonaws.com/",
           {"X-Amz-Meta-Note": "  a   b    c  "}),
    vector("s3-get-object-special-characters", "s3", "us-east-1", "20130524T000000Z", "GET",
           "http://s3.us-east-1.amazonaws.com/examplebucket/photos/2026/a%20b%2Bc%3Dd.jpg",
           {"Range": "bytes=0-9"}),
    vector("s3-path-not-normalised", "s3", "eu-central-1", "20130524T000000Z", "GET",
           "http://s3.eu-central-1.amazonaws.com/examplebucket/a/./b/../c//d"),
    vector("s3-put-object", "s3", "us-east-1", "20130524T000000Z", "PUT",
           "http://s3.us-east-1.amazonaws.com/examplebucket/test%24file.text",
           {"x-amz-storage-class": "REDUCED_REDUNDANCY", "Content-Type": "text/plain"},
           b"Welcome to Amazon S3."),
    vector("s3-list-objects-v2", "s3", "us-east-1", "20130524T000000Z", "GET",
           "http://s3.us-east-1.amazonaws.com/examplebucket?list-type=2&max-keys=2&prefix=J%2F"),
    vector("s3-session-token", "s3", "us-east-1", "20261007T101112Z", "HEAD",
           "http://s3.us-east-1.amazonaws.com/examplebucket/key", token=TOKEN),
]

json.dump({"generator": f"botocore {botocore.__version__}", "vectors": vectors}, sys.stdout, indent=1)
sys.stdout.write("\n")
