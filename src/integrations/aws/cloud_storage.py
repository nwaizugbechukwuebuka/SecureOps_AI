
"""
Async AWS S3 client for SecureOps.
"""
import aioboto3
import aiofiles
from config.settings import settings
from typing import Any, Dict

class S3Client:
    """
    Async S3 client for file upload and download.
    """
    def __init__(self):
        self.bucket = settings.s3_bucket
        self.region = settings.aws_region

    async def upload_file(self, file_path: str, key: str) -> Dict[str, Any]:
        """Upload a file to S3 asynchronously."""
        try:
            async with aioboto3.client(
                "s3",
                region_name=self.region,
                aws_secret_access_key=settings.aws_secret_access_key,
                aws_access_key_id=settings.aws_access_key_id,
            ) as s3:
                async with aiofiles.open(file_path, "rb") as f:
                    await s3.upload_fileobj(f, self.bucket, key)
            return {"status": "uploaded", "key": key}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def download_file(self, key: str, dest_path: str) -> Dict[str, Any]:
        """Download a file from S3 asynchronously."""
        try:
            async with aioboto3.client(
                "s3",
                region_name=self.region,
                aws_secret_access_key=settings.aws_secret_access_key,
                aws_access_key_id=settings.aws_access_key_id,
            ) as s3:
                async with aiofiles.open(dest_path, "wb") as f:
                    await s3.download_fileobj(self.bucket, key, f)
            return {"status": "downloaded", "key": key}
        except Exception as e:
            return {"status": "error", "error": str(e)}
