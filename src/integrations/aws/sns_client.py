"""
Async AWS SNS client for SecureOps.
"""

from typing import Any, Dict, Optional

import aiobotocore.session

from config.settings import settings


class SNSClient:
    """
    Async AWS SNS client for publishing messages.
    """

    def __init__(self):
        self.session = aiobotocore.session.get_session()
        self.region = settings.aws_region

    async def publish(
        self, topic_arn: str, message: str, subject: Optional[str] = None
    ) -> Dict[str, Any]:
        """Publish a message to an SNS topic asynchronously."""
        try:
            async with self.session.create_client(
                "sns",
                region_name=self.region,
                aws_secret_access_key=settings.aws_secret_access_key,
                aws_access_key_id=settings.aws_access_key_id,
            ) as client:
                params = {"TopicArn": topic_arn, "Message": message}
                if subject:
                    params["Subject"] = subject
                response = await client.publish(**params)
                return response
        except Exception as e:
            return {"status": "error", "error": str(e)}
