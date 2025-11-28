"""Ingest pipeline: fetch logs from cloud/SIEM sources."""
from typing import AsyncIterator, List, Dict, Any

async def run_ingest(connectors: List[Any] = None) -> AsyncIterator[Dict[str, Any]]:
    connectors = connectors or []
    for connector in connectors:
        async for event in connector.fetch():
            yield event

__all__ = ["run_ingest"]


"""Ingest pipeline: collect logs/events from integrators and yield normalized records.
"""

import asyncio
import logging
from typing import AsyncIterator, Dict, Any, List

from integrators.siem_connector import SiemConnector
from integrators.cloudtrail_parser import CloudTrailParser
from integrators.azure_logs import AzureLogs

LOG = logging.getLogger("secureops.pipelines.ingest")

async def run_ingest(connectors: List[object] | None = None) -> AsyncIterator[Dict[str, Any]]:
    connectors = connectors or [SiemConnector(), CloudTrailParser(), AzureLogs()]
    for c in connectors:
        try:
            items = await c.fetch()
            for it in items:
                LOG.debug("Ingesting item: %s", it)
                yield it
        except Exception:
            LOG.exception("Connector failed: %s", c)
        await asyncio.sleep(0)

__all__ = ["run_ingest"]

