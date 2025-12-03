import asyncio
import logging

from fastapi import APIRouter, BackgroundTasks, Depends

from integrators.slack_notifier import SlackNotifier
from pipelines.detection_pipeline import run_detection
from pipelines.ingest_pipeline import run_ingest
from pipelines.response_pipeline import run_response
from security.auth import require_token

router = APIRouter()
LOG = logging.getLogger("secureops.api.scan")


@router.post("/run", dependencies=[Depends(require_token)])
async def run_scan(background: BackgroundTasks, dry_run: bool = True) -> dict:
    LOG.info("Starting scan (dry_run=%s)", dry_run)
    records = []
    async for rec in run_ingest():
        records.append(rec)
    detections = []
    async for det in run_detection(records):
        detections.append(det)

    async def _bg_run() -> None:
        await run_response(detections, notifier=SlackNotifier(dry_run=dry_run), dry_run=dry_run)

    background.add_task(lambda: asyncio.run(_bg_run()))
    return {
        "processed": len(records),
        "detections": len(detections),
        "dry_run": dry_run,
    }
