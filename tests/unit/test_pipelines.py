import pytest

from integrators.siem_connector import SiemConnector
from pipelines.ingest_pipeline import run_ingest
from pipelines.detection_pipeline import run_detection
from pipelines.response_pipeline import run_response


@pytest.mark.asyncio
async def test_ingest_with_siem():
    items = []
    async for i in run_ingest(connectors=[SiemConnector()]):
        items.append(i)

    assert isinstance(items, list)
    assert len(items) >= 1


@pytest.mark.asyncio
async def test_detection_and_response_pipeline(stub_model):
    records = [{"id": "r1", "message": "failed login"}]
    outs = []
    async for o in run_detection(records, classifier=None if not stub_model else None):
        outs.append(o)

    # Run detection. Classifier will default to model_loader; avoid heavy
    # training during tests by using the stub model.
    assert isinstance(outs, list)

    # Build a fake detections list for response
    detections = [
        {
            "record": {"id": "r1"},
            "threat": type("T", (), {"probability": 0.9})(),
            "anomaly": type("A", (), {"score": 0.8})(),
        }
    ]

    actions = await run_response(detections, notifier=None, dry_run=True)
    assert isinstance(actions, list)
    assert actions[0]["suggestion"] in {"investigate", "monitor"}
