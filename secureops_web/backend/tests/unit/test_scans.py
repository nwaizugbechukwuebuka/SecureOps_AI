from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_scan():
    response = client.post("/scan", json={"target": "localhost", "scan_type": "basic"})
    assert response.status_code == 200
    assert response.json()["status"] == "completed"
