import asyncio
from typing import Dict, List

"""
AWS CloudTrail log parser stub.
Mocked CloudTrail parser returning fake events.
"""


class CloudTrailParser:
    async def fetch(self) -> List[Dict]:
        await asyncio.sleep(0)
        return [
            {"id": "ct-1", "source": "cloudtrail", "event": "CreateUser: admin-user"},
            {"id": "ct-2", "source": "cloudtrail", "event": "ConsoleLogin: Success"},
        ]


__all__ = ["CloudTrailParser"]
