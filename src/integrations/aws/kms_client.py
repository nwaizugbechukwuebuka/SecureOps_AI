"""
Async AWS KMS client for SecureOps.
"""

from typing import Any, Dict

import aiobotocore.session

from config.settings import settings


class KMSClient:
    """
    Async AWS KMS client for encryption and decryption.
    """

    def __init__(self):
        self.session = aiobotocore.session.get_session()
        self.region = settings.aws_region
        self.key_id = settings.kms_key_id

    async def encrypt(self, plaintext: bytes) -> Dict[str, Any]:
        """Encrypt plaintext using AWS KMS asynchronously."""
        try:
            async with self.session.create_client(
                "kms",
                region_name=self.region,
                aws_secret_access_key=settings.aws_secret_access_key,
                aws_access_key_id=settings.aws_access_key_id,
            ) as client:
                response = await client.encrypt(KeyId=self.key_id, Plaintext=plaintext)
                return response
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def decrypt(self, ciphertext: bytes) -> Dict[str, Any]:
        """Decrypt ciphertext using AWS KMS asynchronously."""
        try:
            async with self.session.create_client(
                "kms",
                region_name=self.region,
                aws_secret_access_key=settings.aws_secret_access_key,
                aws_access_key_id=settings.aws_access_key_id,
            ) as client:
                response = await client.decrypt(CiphertextBlob=ciphertext)
                return response
        except Exception as e:
            return {"status": "error", "error": str(e)}
