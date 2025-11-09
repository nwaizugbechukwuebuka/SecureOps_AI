"""
Async AWS SSM Parameter Store client for SecureOps.
"""

from typing import Any, Dict

import aiobotocore.session

from config.settings import settings


class SSMClient:
    """
    Async AWS SSM Parameter Store client for retrieving parameters.
    """

    def __init__(self):
        self.session = aiobotocore.session.get_session()
        self.region = settings.aws_region

    async def get_parameter(self, name: str, with_decryption: bool = True) -> Dict[str, Any]:
        """Get a parameter from SSM Parameter Store asynchronously."""
        try:
            async with self.session.create_client(
                "ssm",
                region_name=self.region,
                aws_secret_access_key=settings.aws_secret_access_key,
                aws_access_key_id=settings.aws_access_key_id,
            ) as client:
                response = await client.get_parameter(Name=name, WithDecryption=with_decryption)
                return response
        except Exception as e:
            return {"status": "error", "error": str(e)}
