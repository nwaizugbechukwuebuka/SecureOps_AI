
"""AWS CloudTrail log parser stub."""
from typing import List, Dict

class CloudTrailParser:
    async def fetch(self) -> List[Dict]:
        # Replace with real AWS integration
        return [{"id": "ct-1", "source": "cloudtrail", "event": "User login"}]


"""
AWS CloudTrail log parser stub.

Mocked CloudTrail parser returning fake events.
"""
import asyncio
from typing import List, Dict

class CloudTrailParser:
    async def fetch(self) -> List[Dict]:
        await asyncio.sleep(0)
        return [
            {"id": "ct-1", "source": "cloudtrail", "event": "CreateUser: admin-user"},
            {"id": "ct-2", "source": "cloudtrail", "event": "ConsoleLogin: Success"},
        ]

__all__ = ["CloudTrailParser"]

