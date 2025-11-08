import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

import pytest
from fastapi import status
from httpx import AsyncClient

from src.api.main import app
from src.api.models.alert import Alert, AlertSeverity, AlertStatus
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
def sample_alert_data():
    """Sample alert data for testing"""
    return {
        "title": "Test Security Alert",
        "description": "This is a test security alert",
        "severity": "high",
        "source": "test_scanner",
        "pipeline_id": 1,
        "vulnerability_id": "CVE-2023-1234",
        "metadata": {
            "scanner": "trivy",
            "component": "test-component",
            "version": "1.0.0",
        },
    }


@pytest.fixture
def mock_alert():
    """Mock alert object"""
    alert = Mock(spec=Alert)
    alert.id = 1
    alert.title = "Test Security Alert"
    alert.description = "This is a test security alert"
    alert.severity = AlertSeverity.HIGH
    alert.status = AlertStatus.OPEN
    alert.source = "test_scanner"
    alert.pipeline_id = 1
    alert.vulnerability_id = "CVE-2023-1234"
    alert.created_at = datetime.now()
    alert.updated_at = datetime.now()
    alert.acknowledged_at = None
    alert.resolved_at = None
    alert.acknowledged_by = None
    alert.resolved_by = None
    alert.metadata = {"scanner": "trivy"}
    return alert


@pytest.fixture
def auth_headers():
    """Authentication headers for requests"""
    return {"Authorization": "Bearer test_token"}


class TestAlertCreation:
    """Test alert creation functionality"""

    @pytest.mark.asyncio
    async def test_create_alert_success(
        self, test_client, sample_alert_data, auth_headers
    ):
        """Test successful alert creation"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.alerts.create_alert"
        ) as mock_create_alert:

            mock_user = Mock()
            mock_user.id = 1
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_alert = Mock()
            mock_alert.id = 1
            mock_alert.title = sample_alert_data["title"]
            mock_alert.severity = sample_alert_data["severity"]
            mock_alert.status = "open"
            mock_alert.created_at = datetime.now()

            mock_create_alert.return_value = mock_alert

            response = await test_client.post(
                "/api/v1/alerts", json=sample_alert_data, headers=auth_headers
            )

            assert response.status_code == status.HTTP_201_CREATED
            data = response.json()
            assert data["title"] == sample_alert_data["title"]
            assert data["severity"] == sample_alert_data["severity"]
            assert data["status"] == "open"
            assert "id" in data

    @pytest.mark.asyncio
    async def test_create_alert_invalid_severity(
        self, test_client, sample_alert_data, auth_headers
    ):
        """Test alert creation with invalid severity"""
        sample_alert_data["severity"] = "invalid_severity"

        response = await test_client.post(
            "/api/v1/alerts", json=sample_alert_data, headers=auth_headers
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_create_alert_missing_title(
        self, test_client, sample_alert_data, auth_headers
    ):
        """Test alert creation without required title"""
        del sample_alert_data["title"]

        response = await test_client.post(
            "/api/v1/alerts", json=sample_alert_data, headers=auth_headers
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_create_alert_unauthorized(self, test_client, sample_alert_data):
        """Test alert creation without authentication"""
        response = await test_client.post("/api/v1/alerts", json=sample_alert_data)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestAlertRetrieval:
    """Test alert retrieval functionality"""

    @pytest.mark.asyncio
    async def test_get_alerts_success(self, test_client, auth_headers):
        """Test successful alerts retrieval"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch("src.api.routes.alerts.get_alerts") as mock_get_alerts:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            # Mock alert list
            mock_alert1 = Mock()
            mock_alert1.id = 1
            mock_alert1.title = "Alert 1"
            mock_alert1.severity = "high"
            mock_alert1.status = "open"

            mock_alert2 = Mock()
            mock_alert2.id = 2
            mock_alert2.title = "Alert 2"
            mock_alert2.severity = "medium"
            mock_alert2.status = "acknowledged"

            mock_get_alerts.return_value = ([mock_alert1, mock_alert2], 2)

            response = await test_client.get("/api/v1/alerts", headers=auth_headers)

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert len(data["items"]) == 2
            assert data["total"] == 2
            assert data["items"][0]["title"] == "Alert 1"
            assert data["items"][1]["title"] == "Alert 2"

    @pytest.mark.asyncio
    async def test_get_alerts_with_filters(self, test_client, auth_headers):
        """Test alerts retrieval with filters"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch("src.api.routes.alerts.get_alerts") as mock_get_alerts:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_alerts.return_value = ([], 0)

            params = {
                "severity": "high",
                "status": "open",
                "source": "trivy",
                "limit": 10,
                "offset": 0,
            }

            response = await test_client.get(
                "/api/v1/alerts", params=params, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            mock_get_alerts.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_alert_by_id_success(self, test_client, mock_alert, auth_headers):
        """Test successful alert retrieval by ID"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.alerts.get_alert_by_id"
        ) as mock_get_alert:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_alert.return_value = mock_alert

            response = await test_client.get("/api/v1/alerts/1", headers=auth_headers)

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["id"] == mock_alert.id
            assert data["title"] == mock_alert.title

    @pytest.mark.asyncio
    async def test_get_alert_by_id_not_found(self, test_client, auth_headers):
        """Test alert retrieval with non-existent ID"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.alerts.get_alert_by_id"
        ) as mock_get_alert:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_alert.return_value = None

            response = await test_client.get("/api/v1/alerts/999", headers=auth_headers)

            assert response.status_code == status.HTTP_404_NOT_FOUND


class TestAlertUpdate:
    """Test alert update functionality"""

    @pytest.mark.asyncio
    async def test_update_alert_success(self, test_client, mock_alert, auth_headers):
        """Test successful alert update"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.alerts.get_alert_by_id"
        ) as mock_get_alert, patch(
            "src.api.routes.alerts.update_alert"
        ) as mock_update_alert:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_alert.return_value = mock_alert

            updated_alert = Mock()
            updated_alert.id = mock_alert.id
            updated_alert.title = "Updated Alert Title"
            updated_alert.description = mock_alert.description
            updated_alert.severity = mock_alert.severity

            mock_update_alert.return_value = updated_alert

            update_data = {"title": "Updated Alert Title"}
            response = await test_client.patch(
                "/api/v1/alerts/1", json=update_data, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["title"] == "Updated Alert Title"

    @pytest.mark.asyncio
    async def test_acknowledge_alert_success(
        self, test_client, mock_alert, auth_headers
    ):
        """Test successful alert acknowledgment"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.alerts.get_alert_by_id"
        ) as mock_get_alert, patch(
            "src.api.routes.alerts.acknowledge_alert"
        ) as mock_acknowledge:

            mock_user = Mock()
            mock_user.id = 1
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_alert.return_value = mock_alert

            acknowledged_alert = Mock()
            acknowledged_alert.id = mock_alert.id
            acknowledged_alert.status = AlertStatus.ACKNOWLEDGED
            acknowledged_alert.acknowledged_at = datetime.now()
            acknowledged_alert.acknowledged_by = 1

            mock_acknowledge.return_value = acknowledged_alert

            response = await test_client.post(
                "/api/v1/alerts/1/acknowledge", headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["status"] == "acknowledged"

    @pytest.mark.asyncio
    async def test_resolve_alert_success(self, test_client, mock_alert, auth_headers):
        """Test successful alert resolution"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.alerts.get_alert_by_id"
        ) as mock_get_alert, patch(
            "src.api.routes.alerts.resolve_alert"
        ) as mock_resolve:

            mock_user = Mock()
            mock_user.id = 1
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_alert.return_value = mock_alert

            resolved_alert = Mock()
            resolved_alert.id = mock_alert.id
            resolved_alert.status = AlertStatus.RESOLVED
            resolved_alert.resolved_at = datetime.now()
            resolved_alert.resolved_by = 1

            mock_resolve.return_value = resolved_alert

            resolution_data = {"resolution_note": "Fixed vulnerability"}
            response = await test_client.post(
                "/api/v1/alerts/1/resolve", json=resolution_data, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["status"] == "resolved"


class TestAlertDeletion:
    """Test alert deletion functionality"""

    @pytest.mark.asyncio
    async def test_delete_alert_success(self, test_client, mock_alert, auth_headers):
        """Test successful alert deletion"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.alerts.get_alert_by_id"
        ) as mock_get_alert, patch(
            "src.api.routes.alerts.delete_alert"
        ) as mock_delete:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_alert.return_value = mock_alert
            mock_delete.return_value = True

            response = await test_client.delete(
                "/api/v1/alerts/1", headers=auth_headers
            )

            assert response.status_code == status.HTTP_204_NO_CONTENT

    @pytest.mark.asyncio
    async def test_delete_alert_not_found(self, test_client, auth_headers):
        """Test deletion of non-existent alert"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.alerts.get_alert_by_id"
        ) as mock_get_alert:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_alert.return_value = None

            response = await test_client.delete(
                "/api/v1/alerts/999", headers=auth_headers
            )

            assert response.status_code == status.HTTP_404_NOT_FOUND


class TestAlertBulkOperations:
    """Test bulk alert operations"""

    @pytest.mark.asyncio
    async def test_bulk_acknowledge_success(self, test_client, auth_headers):
        """Test successful bulk alert acknowledgment"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.alerts.bulk_acknowledge_alerts"
        ) as mock_bulk_ack:

            mock_user = Mock()
            mock_user.id = 1
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_bulk_ack.return_value = 3  # 3 alerts acknowledged

            bulk_data = {"alert_ids": [1, 2, 3], "action": "acknowledge"}

            response = await test_client.post(
                "/api/v1/alerts/bulk-action", json=bulk_data, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["affected_count"] == 3
            assert data["action"] == "acknowledge"

    @pytest.mark.asyncio
    async def test_bulk_resolve_success(self, test_client, auth_headers):
        """Test successful bulk alert resolution"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.alerts.bulk_resolve_alerts"
        ) as mock_bulk_resolve:

            mock_user = Mock()
            mock_user.id = 1
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_bulk_resolve.return_value = 2  # 2 alerts resolved

            bulk_data = {
                "alert_ids": [1, 2],
                "action": "resolve",
                "resolution_note": "Bulk resolution",
            }

            response = await test_client.post(
                "/api/v1/alerts/bulk-action", json=bulk_data, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["affected_count"] == 2
            assert data["action"] == "resolve"

    @pytest.mark.asyncio
    async def test_bulk_delete_success(self, test_client, auth_headers):
        """Test successful bulk alert deletion"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.alerts.bulk_delete_alerts"
        ) as mock_bulk_delete:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_bulk_delete.return_value = 5  # 5 alerts deleted

            bulk_data = {"alert_ids": [1, 2, 3, 4, 5], "action": "delete"}

            response = await test_client.post(
                "/api/v1/alerts/bulk-action", json=bulk_data, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["affected_count"] == 5
            assert data["action"] == "delete"


class TestAlertStatistics:
    """Test alert statistics functionality"""

    @pytest.mark.asyncio
    async def test_get_alert_stats_success(self, test_client, auth_headers):
        """Test successful alert statistics retrieval"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.alerts.get_alert_statistics"
        ) as mock_get_stats:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_stats = {
                "total": 100,
                "open": 30,
                "acknowledged": 45,
                "resolved": 25,
                "by_severity": {"critical": 10, "high": 25, "medium": 40, "low": 25},
                "by_source": {"trivy": 50, "safety": 30, "bandit": 20},
                "trend": {"daily": [5, 8, 12, 3, 7], "weekly": [25, 30, 22, 18]},
            }

            mock_get_stats.return_value = mock_stats

            response = await test_client.get(
                "/api/v1/alerts/stats", headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["total"] == 100
            assert data["open"] == 30
            assert "by_severity" in data
            assert "by_source" in data
            assert "trend" in data

    @pytest.mark.asyncio
    async def test_get_alert_trends_success(self, test_client, auth_headers):
        """Test successful alert trends retrieval"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.alerts.get_alert_trends"
        ) as mock_get_trends:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_trends = {
                "period": "30d",
                "data": [
                    {
                        "date": "2023-01-01",
                        "count": 5,
                        "severity_breakdown": {"high": 2, "medium": 3},
                    },
                    {
                        "date": "2023-01-02",
                        "count": 8,
                        "severity_breakdown": {"high": 3, "medium": 4, "low": 1},
                    },
                ],
            }

            mock_get_trends.return_value = mock_trends

            params = {"period": "30d", "severity": "high"}
            response = await test_client.get(
                "/api/v1/alerts/trends", params=params, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["period"] == "30d"
            assert len(data["data"]) == 2


class TestAlertNotifications:
    """Test alert notification functionality"""

    @pytest.mark.asyncio
    async def test_alert_webhook_trigger(
        self, test_client, sample_alert_data, auth_headers
    ):
        """Test alert webhook trigger on creation"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.alerts.create_alert"
        ) as mock_create_alert, patch(
            "src.api.services.alert_service.trigger_alert_webhook"
        ) as mock_webhook:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_alert = Mock()
            mock_alert.id = 1
            mock_alert.severity = "high"
            mock_create_alert.return_value = mock_alert

            mock_webhook.return_value = True

            response = await test_client.post(
                "/api/v1/alerts", json=sample_alert_data, headers=auth_headers
            )

            assert response.status_code == status.HTTP_201_CREATED
            # Webhook should be triggered for high severity alerts
            mock_webhook.assert_called_once()

    @pytest.mark.asyncio
    async def test_alert_email_notification(
        self, test_client, sample_alert_data, auth_headers
    ):
        """Test alert email notification on creation"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.alerts.create_alert"
        ) as mock_create_alert, patch(
            "src.api.services.alert_service.send_alert_email"
        ) as mock_email:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_alert = Mock()
            mock_alert.id = 1
            mock_alert.severity = "critical"
            mock_create_alert.return_value = mock_alert

            mock_email.return_value = True

            sample_alert_data["severity"] = "critical"
            response = await test_client.post(
                "/api/v1/alerts", json=sample_alert_data, headers=auth_headers
            )

            assert response.status_code == status.HTTP_201_CREATED
            # Email should be sent for critical alerts
            mock_email.assert_called_once()


class TestAlertFiltering:
    """Test alert filtering and search functionality"""

    @pytest.mark.asyncio
    async def test_filter_alerts_by_date_range(self, test_client, auth_headers):
        """Test filtering alerts by date range"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch("src.api.routes.alerts.get_alerts") as mock_get_alerts:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_alerts.return_value = ([], 0)

            params = {
                "start_date": "2023-01-01",
                "end_date": "2023-01-31",
                "severity": "high",
            }

            response = await test_client.get(
                "/api/v1/alerts", params=params, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            mock_get_alerts.assert_called_once()

    @pytest.mark.asyncio
    async def test_search_alerts_by_text(self, test_client, auth_headers):
        """Test searching alerts by text content"""
        with patch("src.api.routes.alerts.get_current_user") as mock_get_user, patch(
            "src.api.routes.alerts.get_db"
        ) as mock_get_db, patch("src.api.routes.alerts.search_alerts") as mock_search:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_search.return_value = ([], 0)

            params = {"search": "CVE-2023"}
            response = await test_client.get(
                "/api/v1/alerts/search", params=params, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            mock_search.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__])
