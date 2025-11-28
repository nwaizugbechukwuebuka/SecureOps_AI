from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_auth_me():
    response = client.get("/me")
    assert response.status_code == 200
    assert "user" in response.json()
