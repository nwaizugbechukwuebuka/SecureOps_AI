import asyncio
from typing import Any, Dict, List


class SiemConnector:
    """
    Mock SIEM connector that asynchronously returns example log events.
    """

    async def fetch(self) -> List[Dict[str, Any]]:
        await asyncio.sleep(0)  # ensures this is a real async coroutine
        return [
            {
                "id": "siem-1",
                "source": "siem",
                "message": "Failed login from 10.0.0.5",
            },
            {
                "id": "siem-2",
                "source": "siem",
                "message": "Malware detected on host srv-3",
            },
        ]


__all__ = ["SiemConnector"]
