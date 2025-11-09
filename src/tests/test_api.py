"""
Pytest suite for SecureOps API endpoints.
"""

import pytest
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_rbac_enforcement():
    """Test that protected endpoints require authentication/authorization."""
    # Example: /api/v1/pipelines/ (should require auth)
    response = client.get("/api/v1/pipelines/")
    assert response.status_code in (401, 403)


def test_audit_log_on_login(monkeypatch):
    """Test that login attempts are logged for audit trail."""
    from api.utils.logger import AuditLogger

    logs = []

    class DummyLogger:
        def info(self, *args, **kwargs):
            logs.append((args, kwargs))

        def warning(self, *args, **kwargs):
            logs.append((args, kwargs))

    audit_logger = AuditLogger()
    audit_logger.logger = DummyLogger()
    audit_logger.login_attempt(
        username="alice",
        success=False,
        ip_address="1.2.3.4",
        failure_reason="bad password",
    )
    assert any("login_attempt" in arg for args, _ in logs for arg in args)


def test_compliance_error_response():
    """Test that compliance errors are handled gracefully."""
    # Simulate a compliance error endpoint (example, adjust as needed)
    response = client.get("/api/v1/compliance/nonexistent")
    assert response.status_code in (400, 404)
