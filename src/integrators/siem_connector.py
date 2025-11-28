
from __future__ import annotations
"""SIEM connector stub."""
from typing import List, Dict

class SiemConnector:
    async def fetch(self) -> List[Dict]:
        return [
            {"id": "siem-1", "source": "siem", "message": "Failed login"},
            {"id": "siem-2", "source": "siem", "message": "Malware detected"},
        ]

__all__ = ["SiemConnector"]
"""Mocked SIEM connector that returns example log events.
"""

import asyncio
from typing import List, Dict, Any, Sequence


class SiemConnector:
    async def fetch(self) -> List[dict[str, Any][str, Any]]:
        await asyncio.sleep(0)
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

