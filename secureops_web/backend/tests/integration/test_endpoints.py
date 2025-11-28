from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_endpoints():
    assert client.get("/health").status_code == 200
    assert client.post("/login").status_code == 200
