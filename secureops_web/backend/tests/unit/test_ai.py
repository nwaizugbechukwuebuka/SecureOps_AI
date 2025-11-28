from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_ai_analysis():
    response = client.post("/ai/analyze", json={"data": "test"})
    assert response.status_code == 200
    assert "result" in response.json()
