import boto3
import uuid
import os

AWS_REGION = os.environ.get("AWS_REGION", "us-east-2")
S3_BUCKET = os.environ["S3_BUCKET_NAME"]

s3 = boto3.client(
    "s3",
    aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
    aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
    region_name=AWS_REGION
)

def upload_file_to_s3(file_obj, filename, content_type):
    unique_name = f"{uuid.uuid4()}_{filename}"
    s3.upload_fileobj(
        file_obj,
        S3_BUCKET,
        unique_name,
        ExtraArgs={"ContentType": content_type}
    )
    file_url = f"https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{unique_name}"
    return file_url
