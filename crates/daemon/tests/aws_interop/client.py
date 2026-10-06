"""Real AWS SDK calls through the Unseenkey broker.

Configured the way `usk env aws` tells a user to configure it: three
environment variables and nothing else. The access key id is a handle, the
secret is a placeholder, and the endpoint is the local broker.

    AWS_ENDPOINT_URL        http://127.0.0.1:<port>/p/aws
    AWS_ACCESS_KEY_ID       usk_h_…
    AWS_SECRET_ACCESS_KEY   handled-by-unseenkey

Prints one JSON object with what each call returned. Any failure, including
a signature AWS would reject, raises and exits non-zero.
"""
import json
import os

import boto3
from botocore.config import Config

assert os.environ["AWS_ACCESS_KEY_ID"].startswith("usk_h_"), "expected a handle, not a key"
cfg = Config(retries={"max_attempts": 1, "mode": "standard"}, connect_timeout=5, read_timeout=20)
out = {"boto3": boto3.__version__}

s3 = boto3.client("s3", region_name="us-east-1", config=cfg)
listing = s3.list_objects_v2(Bucket="demo-bucket", Prefix="reports/")
out["s3_list"] = [o["Key"] for o in listing.get("Contents", [])]
# Recent SDKs upload with aws-chunked framing and a trailing checksum.
put = s3.put_object(Bucket="demo-bucket", Key="uploads/héllo wörld (1).txt", Body=b"hello from boto3\n" * 50,
                    ContentType="text/plain", Metadata={"origin": "interop test"})
out["s3_put_etag"] = put["ETag"]
got = s3.get_object(Bucket="demo-bucket", Key="reports/q3 summary+final=1.txt")
out["s3_get"] = got["Body"].read().decode()
s3.head_object(Bucket="demo-bucket", Key="reports/q3.txt")
s3.delete_object(Bucket="demo-bucket", Key="tmp/old.txt")

ddb = boto3.client("dynamodb", region_name="eu-west-1", config=cfg)
item = ddb.get_item(TableName="users", Key={"id": {"S": "42"}})
out["dynamodb_item"] = item["Item"]["name"]["S"]

sts = boto3.client("sts", region_name="ap-south-1", config=cfg)
out["sts_account"] = sts.get_caller_identity()["Account"]

print(json.dumps(out))
