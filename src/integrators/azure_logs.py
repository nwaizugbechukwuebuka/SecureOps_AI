
"""Azure logs provider stub."""
from typing import List, Dict

class AzureLogs:
    async def fetch(self) -> List[Dict]:
        return [{"id": "az-1", "source": "azure", "message": "Suspicious process execution"}]

__all__ = ["AzureLogs"]
"""Mocked Azure logs provider."""

import asyncio
from typing import List, Any

class AzureLogs:
    async def fetch(self) -> List[Dict]:
        await asyncio.sleep(0)
        return [
            {
                "id": "az-1",
                "source": "azure",
                "message": "Suspicious process execution on vm-12",
            },
        ]

__all__ = ["AzureLogs"]
"""Mocked Azure logs provider."""

import asyncio
from typing import List, Any


class AzureLogs:
    async def fetch(self) -> List[Dict[str, Any]]:
        await asyncio.sleep(0)
        return [
            {
                "id": "az-1",
                "source": "azure",
                "message": "Suspicious process execution on vm-12",
            },
        ]


__all__ = ["AzureLogs"]

