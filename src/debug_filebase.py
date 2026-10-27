import boto3
import os

client = boto3.client(
    "s3",
    endpoint_url="https://s3.filebase.io",
    aws_access_key_id=os.environ["FILEBASE_ACCESS_KEY"],
    aws_secret_access_key=os.environ["FILEBASE_SECRET_KEY"],
    region_name="auto",
)

response = client.head_object(Bucket=os.environ["FILEBASE_BUCKET"], Key="timestamp.json")
import json
print(json.dumps(response, indent=2, default=str))