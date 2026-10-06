"""A stand-in for AWS that checks every request's SigV4 signature with botocore.

    python verify_server.py <access key id> <secret access key> <host> [<host> ...]

One listener per logical AWS host (the broker is told to connect to them
instead of the real endpoints). On start it prints one line of JSON mapping
each host to its port, then serves until stdin closes.

For every request it recomputes the signature with botocore, AWS's own signer,
from exactly what arrived: the method, the raw path and query, the headers the
client declared as signed, and the body. A mismatch is answered the way AWS
answers it (403 SignatureDoesNotMatch), so the SDK on the other side of the
broker fails loudly. Matching requests get a small canned response in the
service's own format.

`GET /__stats` on any listener reports what was seen.
"""
import hashlib
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from botocore.auth import S3SigV4Auth, SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

AKID, SECRET = sys.argv[1], sys.argv[2]
HOSTS = sys.argv[3:]
STATS = {"ok": 0, "failed": [], "requests": []}
LOCK = threading.Lock()


def check(host, method, raw_path, headers, body):
    """Return None when the signature verifies, else a description of what is wrong."""
    authz = headers.get("authorization", "")
    if not authz.startswith("AWS4-HMAC-SHA256 "):
        return f"not SigV4: {authz[:40]!r}"
    parts = dict(p.strip().split("=", 1) for p in authz[len("AWS4-HMAC-SHA256 "):].split(","))
    akid, date, region, service, term = parts["Credential"].split("/")
    if akid != AKID:
        return f"signed with access key {akid!r}, expected the real one"
    if term != "aws4_request":
        return "bad credential scope"
    amz_date = headers.get("x-amz-date", "")
    if not amz_date.startswith(date):
        return "x-amz-date does not match the credential scope date"
    declared = headers.get("x-amz-content-sha256")
    if declared != hashlib.sha256(body).hexdigest():
        return f"x-amz-content-sha256 {declared!r} is not the hash of the {len(body)}-byte body"
    signed_names = parts["SignedHeaders"].split(";")
    for must in ("host", "x-amz-date"):
        if must not in signed_names:
            return f"{must} is not signed"
    unsigned_amz = [h for h in headers if h.startswith("x-amz-") and h not in signed_names]
    if unsigned_amz:
        return f"x-amz headers sent but not signed: {unsigned_amz}"
    # Rebuild the request the way the service would see it: only the headers
    # the client said it signed, for the host this listener stands in for.
    req = AWSRequest(
        method=method,
        url=f"https://{host}{raw_path}",
        data=body,
        headers={n: headers[n] for n in signed_names if n != "host"},
    )
    req.context["timestamp"] = amz_date
    auth = (S3SigV4Auth if service == "s3" else SigV4Auth)(Credentials(AKID, SECRET), service, region)
    canonical = auth.canonical_request(req)
    expected = auth.signature(auth.string_to_sign(req, canonical), req)
    if expected != parts["Signature"]:
        return "SignatureDoesNotMatch\n--- canonical request the verifier built ---\n" + canonical
    return None


def canned(service, method, path, query, headers, body):
    """A plausible success response for the few operations the test client performs."""
    if service == "s3":
        if method == "PUT":
            return 200, {"ETag": '"' + hashlib.md5(body).hexdigest() + '"'}, b""
        if method == "DELETE":
            # As S3 does. (botocore treats a 200 with a non-XML body as a 500.)
            return 204, {}, b""
        if "list-type=2" in query:
            xml = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                "<Name>demo-bucket</Name><KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>"
                "<Contents><Key>reports/q3 summary.txt</Key><Size>21</Size><StorageClass>STANDARD</StorageClass></Contents>"
                "</ListBucketResult>"
            )
            return 200, {"Content-Type": "application/xml"}, xml.encode()
        return 200, {"Content-Type": "text/plain", "ETag": '"abc"'}, b"contents of " + path.encode()
    if service == "dynamodb":
        target = headers.get("x-amz-target", "")
        out = {"Item": {"id": {"S": "42"}, "name": {"S": "Ada"}}} if target.endswith("GetItem") else {}
        return 200, {"Content-Type": "application/x-amz-json-1.0"}, json.dumps(out).encode()
    if service == "sts":
        xml = (
            '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>'
            "<Arn>arn:aws:iam::123456789012:user/demo</Arn><UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account>"
            "</GetCallerIdentityResult><ResponseMetadata><RequestId>r-1</RequestId></ResponseMetadata></GetCallerIdentityResponse>"
        )
        return 200, {"Content-Type": "text/xml"}, xml.encode()
    return 200, {"Content-Type": "application/json"}, b"{}"


def handler_for(host):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _serve(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            headers = {k.lower(): v for k, v in self.headers.items()}
            path, _, query = self.path.partition("?")
            if path == "/__stats":
                with LOCK:
                    out = json.dumps(STATS).encode()
                return self._reply(200, {"Content-Type": "application/json"}, out)
            problem = check(host, self.command, self.path, headers, body)
            service = "?"
            try:
                service = headers["authorization"].split("Credential=")[1].split(",")[0].split("/")[3]
            except Exception:
                pass
            with LOCK:
                STATS["requests"].append({"host": host, "method": self.command, "path": self.path, "service": service,
                                          "body_len": len(body), "problem": problem})
                if problem:
                    STATS["failed"].append(f"{self.command} {host}{self.path}: {problem}")
                else:
                    STATS["ok"] += 1
            if problem:
                err = ("<Error><Code>SignatureDoesNotMatch</Code><Message>" + problem.split("\n")[0] +
                       "</Message></Error>").encode()
                return self._reply(403, {"Content-Type": "application/xml"}, err)
            status, extra, out = canned(service, self.command, path, query, headers, body)
            self._reply(status, extra, out if self.command != "HEAD" else b"")

        def _reply(self, status, headers, body):
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("x-amz-request-id", "TESTREQUEST")
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_PUT = do_POST = do_DELETE = do_HEAD = _serve

    return Handler


ports = {}
for h in HOSTS:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(h))
    ports[h] = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
print(json.dumps(ports), flush=True)
sys.stdin.read()  # run until the parent closes our stdin
