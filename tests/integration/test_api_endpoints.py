import sys
from pathlib import Path

# Ensure src is importable when running tests from repository root
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from src.security.crypto import generate_hmac_token


def test_health_endpoint(client):
    r = client.get("/health/")
    assert r.status_code == 200
    assert r.json().get("status") == "ok"


def test_ai_analyze_protection(client):
    # Missing token -> 401
    r = client.post("/ai/analyze", json={"prompt": "hello"})
    assert r.status_code == 401

    # Invalid token -> 403
    r = client.post(
        "/ai/analyze",
        json={"prompt": "hello"},
        headers={"X-API-Token": "bad"},
    )
    assert r.status_code == 403

    # Valid token -> 200
    token = generate_hmac_token("test-secret", "secureops-client")
    r = client.post(
        "/ai/analyze",
        json={"prompt": "hello"},
        headers={"X-API-Token": token},
    )
    assert r.status_code == 200
    data = r.json()
    assert "suggestion" in data


def test_scan_run_endpoint_client_side(monkeypatch, client):
    # Stub pipelines to avoid real connectors and heavy work
    async def fake_ingest(connectors=None):
        for rec in [{"id": "r1", "message": "msg"}]:
            yield rec

    async def fake_detection(records):
        for r in records:
            yield {
                "record": r,
                "threat": type("T", (), {"probability": 0.1})(),
                "anomaly": type("A", (), {"score": 0.0})(),
            }

    async def fake_response(detections, notifier=None, dry_run=True):
        out = []
        for d in detections:
            out.append({"id": d.get("record", {}).get("id", "local"), "score": 0.1})
        return out

    from src.pipelines import ingest_pipeline as ingest
    from src.pipelines import detection_pipeline as detection
    from src.pipelines import response_pipeline as response

    monkeypatch.setattr(ingest, "run_ingest", fake_ingest)
    monkeypatch.setattr(detection, "run_detection", fake_detection)
    monkeypatch.setattr(response, "run_response", fake_response)

    # run_scan requires a valid token
    token = generate_hmac_token("test-secret", "secureops-client")
    r = client.post("/scan/run", headers={"X-API-Token": token})
    assert r.status_code == 200
    data = r.json()
    assert "processed" in data and "detections" in data
