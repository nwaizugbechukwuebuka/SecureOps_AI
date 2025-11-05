"""
Pytest suite for Reporting utilities.
"""
from secureops_ai.src.utils.reporting import Reporting

def test_to_json():
    data = {"a": 1}
    json_str = Reporting.to_json(data)
    assert '"a": 1' in json_str

def test_to_csv():
    data = [{"a": 1, "b": 2}, {"a": 3, "b": 4}]
    csv_str = Reporting.to_csv(data)
    assert "a,b" in csv_str
    assert "1,2" in csv_str
    assert "3,4" in csv_str

def test_to_txt():
    data = {"a": 1}
    txt = Reporting.to_txt(data)
    assert "a" in txt


def test_audit_log_generation(monkeypatch):
    """Test that audit logs are generated for reporting actions."""
    from secureops_ai.src.api.utils.logger import AuditLogger
    logs = []
    class DummyLogger:
        def info(self, *args, **kwargs):
            logs.append((args, kwargs))
    audit_logger = AuditLogger()
    audit_logger.logger = DummyLogger()
    audit_logger.user_action(user_id=1, username="alice", action="generate_report", resource_type="report", resource_id="r1", ip_address="127.0.0.1")
    assert any("user_action" in args for args, _ in logs)


def test_compliance_report_formatting():
    """Test that compliance reports include required frameworks."""
    from secureops_ai.src.api.utils.config import Settings
    settings = Settings()
    frameworks = settings.compliance_frameworks
    assert "OWASP" in frameworks
    assert "NIST" in frameworks
