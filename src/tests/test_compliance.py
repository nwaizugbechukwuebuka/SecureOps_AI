import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import status
from httpx import AsyncClient

from src.api.main import app
from src.api.models.user import User


@pytest.fixture
def test_client():
    """Create test client for FastAPI app"""
    return AsyncClient(app=app, base_url="http://test")


@pytest.fixture
def mock_db():
    """Mock database session"""
    return Mock()


@pytest.fixture
def mock_user():
    """Mock authenticated user"""
    user = Mock(spec=User)
    user.id = 1
    user.email = "test@example.com"
    user.is_active = True
    return user


@pytest.fixture
def auth_headers():
    """Authentication headers for requests"""
    return {"Authorization": "Bearer test_token"}


@pytest.fixture
def sample_compliance_data():
    """Sample compliance framework data"""
    return {
        "owasp_top_10": {
            "score": 85.5,
            "passed": 8,
            "failed": 2,
            "controls": [
                {
                    "id": "A01",
                    "name": "Broken Access Control",
                    "status": "passed",
                    "last_check": "2023-01-15T10:00:00Z",
                },
                {
                    "id": "A02",
                    "name": "Cryptographic Failures",
                    "status": "failed",
                    "last_check": "2023-01-15T10:00:00Z",
                },
            ],
        },
        "nist_csf": {
            "score": 78.0,
            "passed": 15,
            "failed": 4,
            "controls": [
                {
                    "id": "ID.AM-1",
                    "name": "Physical devices and systems",
                    "status": "passed",
                    "last_check": "2023-01-15T10:00:00Z",
                }
            ],
        },
    }


class TestComplianceFrameworks:
    """Test compliance framework management"""

    @pytest.mark.asyncio
    async def test_get_frameworks_success(self, test_client, auth_headers):
        """Test successful frameworks retrieval"""
        with patch(
            "src.api.routes.compliance.get_current_user"
        ) as mock_get_user, patch(
            "src.api.routes.compliance.get_db"
        ) as mock_get_db, patch(
            "src.api.services.compliance_service.get_available_frameworks"
        ) as mock_get_frameworks:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_frameworks = {
                "owasp_top_10": {
                    "name": "OWASP Top 10",
                    "description": "Top 10 Web Application Security Risks",
                    "version": "2021",
                    "controls_count": 10,
                },
                "nist_csf": {
                    "name": "NIST Cybersecurity Framework",
                    "description": "Comprehensive cybersecurity guidelines",
                    "version": "1.1",
                    "controls_count": 108,
                },
                "soc2": {
                    "name": "SOC 2",
                    "description": "Service Organization Control 2",
                    "version": "2017",
                    "controls_count": 64,
                },
            }

            mock_get_frameworks.return_value = mock_frameworks

            response = await test_client.get(
                "/api/v1/compliance/frameworks", headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert "owasp_top_10" in data
            assert "nist_csf" in data
            assert "soc2" in data
            assert data["owasp_top_10"]["controls_count"] == 10

    @pytest.mark.asyncio
    async def test_get_framework_details(self, test_client, auth_headers):
        """Test framework details retrieval"""
        with patch(
            "src.api.routes.compliance.get_current_user"
        ) as mock_get_user, patch(
            "src.api.routes.compliance.get_db"
        ) as mock_get_db, patch(
            "src.api.services.compliance_service.get_framework_details"
        ) as mock_get_details:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_details = {
                "id": "owasp_top_10",
                "name": "OWASP Top 10",
                "version": "2021",
                "controls": [
                    {
                        "id": "A01",
                        "name": "Broken Access Control",
                        "description": "Control access to resources",
                        "category": "access_control",
                        "status": "passed",
                    },
                    {
                        "id": "A02",
                        "name": "Cryptographic Failures",
                        "description": "Protect data with cryptography",
                        "category": "cryptography",
                        "status": "failed",
                    },
                ],
            }

            mock_get_details.return_value = mock_details

            response = await test_client.get(
                "/api/v1/compliance/frameworks/owasp_top_10", headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["id"] == "owasp_top_10"
            assert len(data["controls"]) == 2


class TestComplianceAssessment:
    """Test compliance assessment functionality"""

    @pytest.mark.asyncio
    async def test_get_compliance_overview(
        self, test_client, sample_compliance_data, auth_headers
    ):
        """Test compliance overview retrieval"""
        with patch(
            "src.api.routes.compliance.get_current_user"
        ) as mock_get_user, patch(
            "src.api.routes.compliance.get_db"
        ) as mock_get_db, patch(
            "src.api.services.compliance_service.get_compliance_overview"
        ) as mock_get_overview:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_overview = {
                "overall_score": 82.5,
                "trend": 3.2,
                "frameworks": sample_compliance_data,
                "controls": {
                    "passed": 23,
                    "failed": 6,
                    "warnings": 3,
                    "not_applicable": 2,
                },
                "categories": {
                    "access_control": {"score": 85, "passed": 8, "total": 10},
                    "cryptography": {"score": 75, "passed": 6, "total": 8},
                    "logging": {"score": 90, "passed": 9, "total": 10},
                },
                "recent_issues": [
                    {
                        "control_id": "A02",
                        "framework": "owasp_top_10",
                        "description": "Weak cryptographic implementation",
                        "severity": "high",
                        "status": "failed",
                    }
                ],
            }

            mock_get_overview.return_value = mock_overview

            response = await test_client.get("/api/v1/compliance", headers=auth_headers)

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["overall_score"] == 82.5
            assert data["trend"] == 3.2
            assert "frameworks" in data
            assert "controls" in data

    @pytest.mark.asyncio
    async def test_get_compliance_by_framework(self, test_client, auth_headers):
        """Test compliance data for specific framework"""
        with patch(
            "src.api.routes.compliance.get_current_user"
        ) as mock_get_user, patch(
            "src.api.routes.compliance.get_db"
        ) as mock_get_db, patch(
            "src.api.services.compliance_service.get_framework_compliance"
        ) as mock_get_compliance:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_compliance = {
                "framework": "owasp_top_10",
                "score": 85.5,
                "passed": 8,
                "failed": 2,
                "last_assessment": "2023-01-15T10:00:00Z",
                "controls": [
                    {
                        "id": "A01",
                        "name": "Broken Access Control",
                        "status": "passed",
                        "last_check": "2023-01-15T10:00:00Z",
                        "findings": [],
                    },
                    {
                        "id": "A02",
                        "name": "Cryptographic Failures",
                        "status": "failed",
                        "last_check": "2023-01-15T10:00:00Z",
                        "findings": [
                            {
                                "type": "vulnerability",
                                "severity": "high",
                                "description": "Weak encryption algorithm used",
                            }
                        ],
                    },
                ],
            }

            mock_get_compliance.return_value = mock_compliance

            params = {"framework": "owasp_top_10"}
            response = await test_client.get(
                "/api/v1/compliance", params=params, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["framework"] == "owasp_top_10"
            assert data["score"] == 85.5

    @pytest.mark.asyncio
    async def test_run_compliance_assessment(self, test_client, auth_headers):
        """Test running compliance assessment"""
        with patch(
            "src.api.routes.compliance.get_current_user"
        ) as mock_get_user, patch(
            "src.api.routes.compliance.get_db"
        ) as mock_get_db, patch(
            "src.api.services.compliance_service.run_assessment"
        ) as mock_run_assessment:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            assessment_id = "assessment_123"
            mock_run_assessment.return_value = {
                "assessment_id": assessment_id,
                "status": "running",
                "framework": "owasp_top_10",
                "started_at": datetime.now().isoformat(),
                "estimated_duration": 300,
            }

            assessment_data = {"framework": "owasp_top_10", "scope": "full"}

            response = await test_client.post(
                "/api/v1/compliance/assess", json=assessment_data, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["assessment_id"] == assessment_id
            assert data["status"] == "running"


class TestComplianceControls:
    """Test compliance control management"""

    @pytest.mark.asyncio
    async def test_update_control_status(self, test_client, auth_headers):
        """Test updating control status"""
        with patch(
            "src.api.routes.compliance.get_current_user"
        ) as mock_get_user, patch(
            "src.api.routes.compliance.get_db"
        ) as mock_get_db, patch(
            "src.api.services.compliance_service.update_control_status"
        ) as mock_update:

            mock_user = Mock()
            mock_user.id = 1
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            updated_control = {
                "id": "A01",
                "framework": "owasp_top_10",
                "status": "acknowledged",
                "updated_at": datetime.now().isoformat(),
                "updated_by": 1,
                "note": "Control acknowledged for review",
            }

            mock_update.return_value = updated_control

            update_data = {
                "status": "acknowledged",
                "note": "Control acknowledged for review",
            }

            response = await test_client.patch(
                "/api/v1/compliance/controls/A01",
                json=update_data,
                headers=auth_headers,
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["status"] == "acknowledged"
            assert data["note"] == "Control acknowledged for review"

    @pytest.mark.asyncio
    async def test_get_control_details(self, test_client, auth_headers):
        """Test getting control details"""
        with patch(
            "src.api.routes.compliance.get_current_user"
        ) as mock_get_user, patch(
            "src.api.routes.compliance.get_db"
        ) as mock_get_db, patch(
            "src.api.services.compliance_service.get_control_details"
        ) as mock_get_control:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_control = {
                "id": "A01",
                "framework": "owasp_top_10",
                "name": "Broken Access Control",
                "description": "Control access to resources and functions",
                "category": "access_control",
                "status": "passed",
                "last_check": "2023-01-15T10:00:00Z",
                "findings": [],
                "remediation": [
                    "Implement proper access controls",
                    "Use principle of least privilege",
                    "Regular access reviews",
                ],
                "references": [
                    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
                ],
            }

            mock_get_control.return_value = mock_control

            response = await test_client.get(
                "/api/v1/compliance/controls/A01", headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["id"] == "A01"
            assert data["name"] == "Broken Access Control"
            assert len(data["remediation"]) == 3


class TestComplianceReporting:
    """Test compliance reporting functionality"""

    @pytest.mark.asyncio
    async def test_generate_compliance_report(self, test_client, auth_headers):
        """Test compliance report generation"""
        with patch(
            "src.api.routes.compliance.get_current_user"
        ) as mock_get_user, patch(
            "src.api.routes.compliance.get_db"
        ) as mock_get_db, patch(
            "src.api.services.compliance_service.generate_report"
        ) as mock_generate:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            report_id = "report_123"
            mock_generate.return_value = {
                "report_id": report_id,
                "status": "generating",
                "format": "pdf",
                "framework": "owasp_top_10",
                "created_at": datetime.now().isoformat(),
            }

            report_data = {
                "framework": "owasp_top_10",
                "format": "pdf",
                "include_remediation": True,
                "include_trends": True,
            }

            response = await test_client.post(
                "/api/v1/compliance/report", json=report_data, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["report_id"] == report_id
            assert data["status"] == "generating"

    @pytest.mark.asyncio
    async def test_download_compliance_report(self, test_client, auth_headers):
        """Test compliance report download"""
        with patch(
            "src.api.routes.compliance.get_current_user"
        ) as mock_get_user, patch(
            "src.api.routes.compliance.get_db"
        ) as mock_get_db, patch(
            "src.api.services.compliance_service.get_report_file"
        ) as mock_get_file:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            # Mock PDF content
            mock_file_content = b"PDF content here"
            mock_get_file.return_value = {
                "content": mock_file_content,
                "filename": "compliance_report_owasp_top_10_2023-01-15.pdf",
                "content_type": "application/pdf",
            }

            response = await test_client.get(
                "/api/v1/compliance/report/report_123", headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            assert response.headers["content-type"] == "application/pdf"

    @pytest.mark.asyncio
    async def test_get_compliance_trends(self, test_client, auth_headers):
        """Test compliance trends retrieval"""
        with patch(
            "src.api.routes.compliance.get_current_user"
        ) as mock_get_user, patch(
            "src.api.routes.compliance.get_db"
        ) as mock_get_db, patch(
            "src.api.services.compliance_service.get_compliance_trends"
        ) as mock_get_trends:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_trends = {
                "period": "30d",
                "framework": "owasp_top_10",
                "data": [
                    {"date": "2023-01-01", "score": 80.0, "passed": 8, "failed": 2},
                    {"date": "2023-01-15", "score": 85.5, "passed": 8, "failed": 2},
                ],
                "summary": {"improvement": 5.5, "trend": "improving"},
            }

            mock_get_trends.return_value = mock_trends

            params = {"framework": "owasp_top_10", "period": "30d"}

            response = await test_client.get(
                "/api/v1/compliance/trends", params=params, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["period"] == "30d"
            assert data["summary"]["improvement"] == 5.5


class TestComplianceAutomation:
    """Test compliance automation features"""

    @pytest.mark.asyncio
    async def test_configure_automated_assessment(self, test_client, auth_headers):
        """Test configuring automated compliance assessment"""
        with patch(
            "src.api.routes.compliance.get_current_user"
        ) as mock_get_user, patch(
            "src.api.routes.compliance.get_db"
        ) as mock_get_db, patch(
            "src.api.services.compliance_service.configure_automation"
        ) as mock_configure:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            config_id = "config_123"
            mock_configure.return_value = {
                "config_id": config_id,
                "framework": "owasp_top_10",
                "schedule": "weekly",
                "enabled": True,
                "next_run": "2023-01-22T10:00:00Z",
            }

            automation_config = {
                "framework": "owasp_top_10",
                "schedule": "weekly",
                "day_of_week": "monday",
                "time": "10:00",
                "enabled": True,
                "notify_on_failure": True,
            }

            response = await test_client.post(
                "/api/v1/compliance/automation",
                json=automation_config,
                headers=auth_headers,
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["config_id"] == config_id
            assert data["schedule"] == "weekly"

    @pytest.mark.asyncio
    async def test_get_automation_status(self, test_client, auth_headers):
        """Test getting automation status"""
        with patch(
            "src.api.routes.compliance.get_current_user"
        ) as mock_get_user, patch(
            "src.api.routes.compliance.get_db"
        ) as mock_get_db, patch(
            "src.api.services.compliance_service.get_automation_status"
        ) as mock_get_status:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_status = {
                "configurations": [
                    {
                        "config_id": "config_123",
                        "framework": "owasp_top_10",
                        "schedule": "weekly",
                        "enabled": True,
                        "last_run": "2023-01-15T10:00:00Z",
                        "next_run": "2023-01-22T10:00:00Z",
                        "status": "success",
                    }
                ],
                "recent_runs": [
                    {
                        "run_id": "run_456",
                        "framework": "owasp_top_10",
                        "started_at": "2023-01-15T10:00:00Z",
                        "completed_at": "2023-01-15T10:05:00Z",
                        "status": "success",
                        "score": 85.5,
                    }
                ],
            }

            mock_get_status.return_value = mock_status

            response = await test_client.get(
                "/api/v1/compliance/automation", headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert len(data["configurations"]) == 1
            assert len(data["recent_runs"]) == 1


class TestComplianceIntegrations:
    """Test compliance integrations"""

    @pytest.mark.asyncio
    async def test_sync_with_external_tools(self, test_client, auth_headers):
        """Test syncing compliance data with external tools"""
        with patch(
            "src.api.routes.compliance.get_current_user"
        ) as mock_get_user, patch(
            "src.api.routes.compliance.get_db"
        ) as mock_get_db, patch(
            "src.api.services.compliance_service.sync_external_tools"
        ) as mock_sync:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_sync.return_value = {
                "sync_id": "sync_789",
                "status": "completed",
                "tools_synced": ["trivy", "safety", "bandit"],
                "controls_updated": 15,
                "new_findings": 3,
            }

            sync_data = {
                "tools": ["trivy", "safety", "bandit"],
                "framework": "owasp_top_10",
            }

            response = await test_client.post(
                "/api/v1/compliance/sync", json=sync_data, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["status"] == "completed"
            assert data["controls_updated"] == 15

    @pytest.mark.asyncio
    async def test_export_compliance_data(self, test_client, auth_headers):
        """Test exporting compliance data"""
        with patch(
            "src.api.routes.compliance.get_current_user"
        ) as mock_get_user, patch(
            "src.api.routes.compliance.get_db"
        ) as mock_get_db, patch(
            "src.api.services.compliance_service.export_compliance_data"
        ) as mock_export:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            # Mock JSON export
            mock_export_data = {
                "framework": "owasp_top_10",
                "export_date": "2023-01-15T10:00:00Z",
                "controls": [
                    {
                        "id": "A01",
                        "status": "passed",
                        "last_check": "2023-01-15T10:00:00Z",
                    }
                ],
            }

            mock_export.return_value = mock_export_data

            params = {"framework": "owasp_top_10", "format": "json"}

            response = await test_client.get(
                "/api/v1/compliance/export", params=params, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["framework"] == "owasp_top_10"
            assert len(data["controls"]) == 1


class TestComplianceValidation:
    """Test compliance data validation"""

    @pytest.mark.asyncio
    async def test_validate_framework_config(self, test_client, auth_headers):
        """Test framework configuration validation"""
        with patch(
            "src.api.routes.compliance.get_current_user"
        ) as mock_get_user, patch(
            "src.api.services.compliance_service.validate_framework_config"
        ) as mock_validate:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_validate.return_value = {
                "valid": True,
                "errors": [],
                "warnings": ["Some controls may not be applicable to your environment"],
            }

            config_data = {
                "framework": "owasp_top_10",
                "controls": ["A01", "A02", "A03"],
                "scope": "web_application",
            }

            response = await test_client.post(
                "/api/v1/compliance/validate", json=config_data, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["valid"] is True
            assert len(data["warnings"]) == 1

    @pytest.mark.asyncio
    async def test_validate_control_mapping(self, test_client, auth_headers):
        """Test control mapping validation"""
        with patch(
            "src.api.routes.compliance.get_current_user"
        ) as mock_get_user, patch(
            "src.api.services.compliance_service.validate_control_mapping"
        ) as mock_validate:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_validate.return_value = {
                "valid": False,
                "errors": ["Control A99 does not exist in OWASP Top 10"],
                "suggestions": [
                    "Did you mean A09 (Security Logging and Monitoring Failures)?"
                ],
            }

            mapping_data = {
                "framework": "owasp_top_10",
                "mappings": [
                    {"control_id": "A01", "scanner": "trivy"},
                    {"control_id": "A99", "scanner": "bandit"},  # Invalid
                ],
            }

            response = await test_client.post(
                "/api/v1/compliance/validate-mapping",
                json=mapping_data,
                headers=auth_headers,
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["valid"] is False
            assert len(data["errors"]) == 1


if __name__ == "__main__":
    pytest.main([__file__])
