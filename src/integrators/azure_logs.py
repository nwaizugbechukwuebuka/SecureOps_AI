import asyncio
from typing import Any, Dict, List

"""Mocked Azure logs provider."""


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
