import asyncio
import logging
from typing import Any, AsyncIterator, Dict, List

from integrators.azure_logs import AzureLogs
from integrators.cloudtrail_parser import CloudTrailParser
from integrators.siem_connector import SiemConnector

"""
Ingest pipeline: collect logs/events from integrators and yield normalized records.
"""


LOG = logging.getLogger("secureops.pipelines.ingest")


async def run_ingest(
    connectors: List[object] | None = None,
) -> AsyncIterator[Dict[str, Any]]:
    """
    Ingest records from all configured connectors.
    Each connector must implement `.fetch()` returning a list of events.
    """
    connectors = connectors or [SiemConnector(), CloudTrailParser(), AzureLogs()]

    for c in connectors:
        try:
            items = await c.fetch()
            for it in items:
                LOG.debug("Ingesting item: %s", it)
                yield it
        except Exception:
            LOG.exception("Connector failed: %s", c)

        await asyncio.sleep(0)  # allow cooperative async scheduling


__all__ = ["run_ingest"]
