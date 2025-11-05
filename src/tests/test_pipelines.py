import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

import pytest
from fastapi import status
from httpx import AsyncClient

from secureops_ai.src.api.main import app
from secureops_ai.src.api.models.pipeline import Pipeline, PipelineStatus, PlatformType
from secureops_ai.src.api.models.user import User


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
def sample_pipeline_data():
    """Sample pipeline data for testing"""
    return {
        "name": "Test Pipeline",
        "description": "A test CI/CD pipeline",
        "platform": "github",
        "repository_url": "https://github.com/test/repo",
        "branch": "main",
        "config": {
            "triggers": ["push", "pull_request"],
            "environment": "production",
            "notifications": True,
        },
        "webhook_url": "https://api.github.com/repos/test/repo/hooks",
        "webhook_secret": "secret123",
    }


@pytest.fixture
def mock_pipeline():
    """Mock pipeline object"""
    pipeline = Mock(spec=Pipeline)
    pipeline.id = 1
    pipeline.name = "Test Pipeline"
    pipeline.description = "A test CI/CD pipeline"
    pipeline.platform = PlatformType.GITHUB
    pipeline.status = PipelineStatus.ACTIVE
    pipeline.repository_url = "https://github.com/test/repo"
    pipeline.branch = "main"
    pipeline.webhook_url = "https://api.github.com/repos/test/repo/hooks"
    pipeline.created_at = datetime.now()
    pipeline.updated_at = datetime.now()
    pipeline.last_run = None
    pipeline.next_run = None
    pipeline.config = {"triggers": ["push"]}
    pipeline.user_id = 1
    return pipeline


@pytest.fixture
def auth_headers():
    """Authentication headers for requests"""
    return {"Authorization": "Bearer test_token"}


class TestPipelineCreation:
    """Test pipeline creation functionality"""

    @pytest.mark.asyncio
    async def test_create_pipeline_success(
        self, test_client, sample_pipeline_data, auth_headers
    ):
        """Test successful pipeline creation"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.pipelines.create_pipeline"
        ) as mock_create_pipeline, patch(
            "src.api.services.pipeline_services.setup_webhook"
        ) as mock_setup_webhook:

            mock_user = Mock()
            mock_user.id = 1
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_pipeline = Mock()
            mock_pipeline.id = 1
            mock_pipeline.name = sample_pipeline_data["name"]
            mock_pipeline.platform = sample_pipeline_data["platform"]
            mock_pipeline.status = "active"
            mock_pipeline.created_at = datetime.now()

            mock_create_pipeline.return_value = mock_pipeline
            mock_setup_webhook.return_value = True

            response = await test_client.post(
                "/api/v1/pipelines", json=sample_pipeline_data, headers=auth_headers
            )

            assert response.status_code == status.HTTP_201_CREATED
            data = response.json()
            assert data["name"] == sample_pipeline_data["name"]
            assert data["platform"] == sample_pipeline_data["platform"]
            assert data["status"] == "active"
            assert "id" in data

    @pytest.mark.asyncio
    async def test_create_pipeline_invalid_platform(
        self, test_client, sample_pipeline_data, auth_headers
    ):
        """Test pipeline creation with invalid platform"""
        sample_pipeline_data["platform"] = "invalid_platform"

        response = await test_client.post(
            "/api/v1/pipelines", json=sample_pipeline_data, headers=auth_headers
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_create_pipeline_missing_repository(
        self, test_client, sample_pipeline_data, auth_headers
    ):
        """Test pipeline creation without required repository URL"""
        del sample_pipeline_data["repository_url"]

        response = await test_client.post(
            "/api/v1/pipelines", json=sample_pipeline_data, headers=auth_headers
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_create_pipeline_webhook_setup_failure(
        self, test_client, sample_pipeline_data, auth_headers
    ):
        """Test pipeline creation with webhook setup failure"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.pipelines.create_pipeline"
        ) as mock_create_pipeline, patch(
            "src.api.services.pipeline_services.setup_webhook"
        ) as mock_setup_webhook:

            mock_user = Mock()
            mock_user.id = 1
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_pipeline = Mock()
            mock_pipeline.id = 1
            mock_create_pipeline.return_value = mock_pipeline

            # Webhook setup fails
            mock_setup_webhook.side_effect = Exception("Webhook setup failed")

            response = await test_client.post(
                "/api/v1/pipelines", json=sample_pipeline_data, headers=auth_headers
            )

            # Pipeline created but webhook warning should be included
            assert response.status_code == status.HTTP_201_CREATED
            data = response.json()
            assert "webhook_warning" in data or "warnings" in data


class TestPipelineRetrieval:
    """Test pipeline retrieval functionality"""

    @pytest.mark.asyncio
    async def test_get_pipelines_success(self, test_client, auth_headers):
        """Test successful pipelines retrieval"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.pipelines.get_pipelines"
        ) as mock_get_pipelines:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            # Mock pipeline list
            mock_pipeline1 = Mock()
            mock_pipeline1.id = 1
            mock_pipeline1.name = "Pipeline 1"
            mock_pipeline1.platform = "github"
            mock_pipeline1.status = "active"

            mock_pipeline2 = Mock()
            mock_pipeline2.id = 2
            mock_pipeline2.name = "Pipeline 2"
            mock_pipeline2.platform = "gitlab"
            mock_pipeline2.status = "paused"

            mock_get_pipelines.return_value = ([mock_pipeline1, mock_pipeline2], 2)

            response = await test_client.get("/api/v1/pipelines", headers=auth_headers)

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert len(data["items"]) == 2
            assert data["total"] == 2
            assert data["items"][0]["name"] == "Pipeline 1"
            assert data["items"][1]["name"] == "Pipeline 2"

    @pytest.mark.asyncio
    async def test_get_pipelines_with_filters(self, test_client, auth_headers):
        """Test pipelines retrieval with filters"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.pipelines.get_pipelines"
        ) as mock_get_pipelines:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_pipelines.return_value = ([], 0)

            params = {
                "platform": "github",
                "status": "active",
                "limit": 10,
                "offset": 0,
            }

            response = await test_client.get(
                "/api/v1/pipelines", params=params, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            mock_get_pipelines.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_pipeline_by_id_success(
        self, test_client, mock_pipeline, auth_headers
    ):
        """Test successful pipeline retrieval by ID"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.pipelines.get_pipeline_by_id"
        ) as mock_get_pipeline:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_pipeline.return_value = mock_pipeline

            response = await test_client.get(
                "/api/v1/pipelines/1", headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["id"] == mock_pipeline.id
            assert data["name"] == mock_pipeline.name

    @pytest.mark.asyncio
    async def test_get_pipeline_by_id_not_found(self, test_client, auth_headers):
        """Test pipeline retrieval with non-existent ID"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.pipelines.get_pipeline_by_id"
        ) as mock_get_pipeline:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_pipeline.return_value = None

            response = await test_client.get(
                "/api/v1/pipelines/999", headers=auth_headers
            )

            assert response.status_code == status.HTTP_404_NOT_FOUND


class TestPipelineUpdate:
    """Test pipeline update functionality"""

    @pytest.mark.asyncio
    async def test_update_pipeline_success(
        self, test_client, mock_pipeline, auth_headers
    ):
        """Test successful pipeline update"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.pipelines.get_pipeline_by_id"
        ) as mock_get_pipeline, patch(
            "src.api.routes.pipelines.update_pipeline"
        ) as mock_update_pipeline:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_pipeline.return_value = mock_pipeline

            updated_pipeline = Mock()
            updated_pipeline.id = mock_pipeline.id
            updated_pipeline.name = "Updated Pipeline Name"
            updated_pipeline.description = mock_pipeline.description
            updated_pipeline.platform = mock_pipeline.platform

            mock_update_pipeline.return_value = updated_pipeline

            update_data = {"name": "Updated Pipeline Name"}
            response = await test_client.patch(
                "/api/v1/pipelines/1", json=update_data, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["name"] == "Updated Pipeline Name"

    @pytest.mark.asyncio
    async def test_pause_pipeline_success(
        self, test_client, mock_pipeline, auth_headers
    ):
        """Test successful pipeline pause"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.pipelines.get_pipeline_by_id"
        ) as mock_get_pipeline, patch(
            "src.api.routes.pipelines.pause_pipeline"
        ) as mock_pause:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_pipeline.return_value = mock_pipeline

            paused_pipeline = Mock()
            paused_pipeline.id = mock_pipeline.id
            paused_pipeline.status = PipelineStatus.PAUSED

            mock_pause.return_value = paused_pipeline

            response = await test_client.post(
                "/api/v1/pipelines/1/pause", headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["status"] == "paused"

    @pytest.mark.asyncio
    async def test_resume_pipeline_success(
        self, test_client, mock_pipeline, auth_headers
    ):
        """Test successful pipeline resume"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.pipelines.get_pipeline_by_id"
        ) as mock_get_pipeline, patch(
            "src.api.routes.pipelines.resume_pipeline"
        ) as mock_resume:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            # Pipeline is currently paused
            mock_pipeline.status = PipelineStatus.PAUSED
            mock_get_pipeline.return_value = mock_pipeline

            resumed_pipeline = Mock()
            resumed_pipeline.id = mock_pipeline.id
            resumed_pipeline.status = PipelineStatus.ACTIVE

            mock_resume.return_value = resumed_pipeline

            response = await test_client.post(
                "/api/v1/pipelines/1/resume", headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["status"] == "active"


class TestPipelineExecution:
    """Test pipeline execution functionality"""

    @pytest.mark.asyncio
    async def test_trigger_pipeline_success(
        self, test_client, mock_pipeline, auth_headers
    ):
        """Test successful pipeline trigger"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.pipelines.get_pipeline_by_id"
        ) as mock_get_pipeline, patch(
            "src.api.services.pipeline_services.trigger_pipeline"
        ) as mock_trigger:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_pipeline.return_value = mock_pipeline

            execution_id = str(uuid4())
            mock_trigger.return_value = {
                "execution_id": execution_id,
                "status": "running",
                "started_at": datetime.now().isoformat(),
            }

            response = await test_client.post(
                "/api/v1/pipelines/1/trigger", headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["execution_id"] == execution_id
            assert data["status"] == "running"

    @pytest.mark.asyncio
    async def test_trigger_pipeline_already_running(
        self, test_client, mock_pipeline, auth_headers
    ):
        """Test triggering pipeline that's already running"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.pipelines.get_pipeline_by_id"
        ) as mock_get_pipeline, patch(
            "src.api.services.pipeline_services.trigger_pipeline"
        ) as mock_trigger:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            # Pipeline is currently running
            mock_pipeline.status = PipelineStatus.RUNNING
            mock_get_pipeline.return_value = mock_pipeline

            mock_trigger.side_effect = Exception("Pipeline already running")

            response = await test_client.post(
                "/api/v1/pipelines/1/trigger", headers=auth_headers
            )

            assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.asyncio
    async def test_get_pipeline_logs_success(
        self, test_client, mock_pipeline, auth_headers
    ):
        """Test successful pipeline logs retrieval"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.pipelines.get_pipeline_by_id"
        ) as mock_get_pipeline, patch(
            "src.api.services.pipeline_services.get_pipeline_logs"
        ) as mock_get_logs:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_pipeline.return_value = mock_pipeline

            mock_logs = {
                "execution_id": str(uuid4()),
                "logs": [
                    {
                        "timestamp": "2023-01-01T10:00:00Z",
                        "level": "INFO",
                        "message": "Pipeline started",
                    },
                    {
                        "timestamp": "2023-01-01T10:01:00Z",
                        "level": "INFO",
                        "message": "Running security scan",
                    },
                    {
                        "timestamp": "2023-01-01T10:02:00Z",
                        "level": "WARN",
                        "message": "Vulnerability found",
                    },
                ],
                "total_lines": 3,
            }

            mock_get_logs.return_value = mock_logs

            response = await test_client.get(
                "/api/v1/pipelines/1/logs", headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert len(data["logs"]) == 3
            assert data["total_lines"] == 3


class TestPipelineDeletion:
    """Test pipeline deletion functionality"""

    @pytest.mark.asyncio
    async def test_delete_pipeline_success(
        self, test_client, mock_pipeline, auth_headers
    ):
        """Test successful pipeline deletion"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.pipelines.get_pipeline_by_id"
        ) as mock_get_pipeline, patch(
            "src.api.routes.pipelines.delete_pipeline"
        ) as mock_delete, patch(
            "src.api.services.pipeline_services.cleanup_webhook"
        ) as mock_cleanup:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_pipeline.return_value = mock_pipeline
            mock_delete.return_value = True
            mock_cleanup.return_value = True

            response = await test_client.delete(
                "/api/v1/pipelines/1", headers=auth_headers
            )

            assert response.status_code == status.HTTP_204_NO_CONTENT

    @pytest.mark.asyncio
    async def test_delete_pipeline_with_active_runs(
        self, test_client, mock_pipeline, auth_headers
    ):
        """Test deletion of pipeline with active runs"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.pipelines.get_pipeline_by_id"
        ) as mock_get_pipeline, patch(
            "src.api.services.pipeline_services.has_active_runs"
        ) as mock_has_runs:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_pipeline.return_value = mock_pipeline
            mock_has_runs.return_value = True

            response = await test_client.delete(
                "/api/v1/pipelines/1", headers=auth_headers
            )

            assert response.status_code == status.HTTP_400_BAD_REQUEST
            data = response.json()
            assert "active runs" in data["detail"].lower()


class TestPipelineStatistics:
    """Test pipeline statistics functionality"""

    @pytest.mark.asyncio
    async def test_get_pipeline_stats_success(self, test_client, auth_headers):
        """Test successful pipeline statistics retrieval"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.pipelines.get_pipeline_statistics"
        ) as mock_get_stats:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_stats = {
                "total": 25,
                "active": 20,
                "paused": 3,
                "failed": 2,
                "by_platform": {"github": 15, "gitlab": 7, "jenkins": 3},
                "success_rate": 85.5,
                "avg_execution_time": 420,  # seconds
                "recent_executions": [
                    {"date": "2023-01-01", "count": 12, "success": 10},
                    {"date": "2023-01-02", "count": 15, "success": 13},
                ],
            }

            mock_get_stats.return_value = mock_stats

            response = await test_client.get(
                "/api/v1/pipelines/stats", headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["total"] == 25
            assert data["active"] == 20
            assert "by_platform" in data
            assert "success_rate" in data


class TestPipelineWebhooks:
    """Test pipeline webhook functionality"""

    @pytest.mark.asyncio
    async def test_handle_webhook_github_success(self, test_client):
        """Test successful GitHub webhook handling"""
        with patch("src.api.routes.pipelines.get_db") as mock_get_db, patch(
            "src.api.routes.pipelines.verify_webhook_signature"
        ) as mock_verify, patch(
            "src.api.routes.pipelines.get_pipeline_by_webhook_url"
        ) as mock_get_pipeline, patch(
            "src.api.services.pipeline_services.process_webhook"
        ) as mock_process:

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_verify.return_value = True

            mock_pipeline = Mock()
            mock_pipeline.id = 1
            mock_pipeline.platform = "github"
            mock_get_pipeline.return_value = mock_pipeline

            mock_process.return_value = {"status": "processed"}

            webhook_payload = {
                "action": "opened",
                "pull_request": {"head": {"sha": "abc123"}, "base": {"ref": "main"}},
                "repository": {
                    "full_name": "test/repo",
                    "clone_url": "https://github.com/test/repo.git",
                },
            }

            headers = {
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": "sha256=test_signature",
            }

            response = await test_client.post(
                "/api/v1/pipelines/webhook/github",
                json=webhook_payload,
                headers=headers,
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["status"] == "processed"

    @pytest.mark.asyncio
    async def test_handle_webhook_invalid_signature(self, test_client):
        """Test webhook handling with invalid signature"""
        with patch("src.api.routes.pipelines.verify_webhook_signature") as mock_verify:

            mock_verify.return_value = False

            webhook_payload = {"test": "data"}
            headers = {"X-GitHub-Event": "push", "X-Hub-Signature-256": "invalid"}

            response = await test_client.post(
                "/api/v1/pipelines/webhook/github",
                json=webhook_payload,
                headers=headers,
            )

            assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestPipelineIntegrations:
    """Test pipeline platform integrations"""

    @pytest.mark.asyncio
    async def test_sync_github_pipelines(self, test_client, auth_headers):
        """Test GitHub pipelines synchronization"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_db"
        ) as mock_get_db, patch(
            "src.api.integrations.github_actions.sync_repositories"
        ) as mock_sync:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_sync.return_value = {
                "synced": 5,
                "created": 2,
                "updated": 3,
                "errors": 0,
            }

            response = await test_client.post(
                "/api/v1/pipelines/sync/github", headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["synced"] == 5
            assert data["created"] == 2

    @pytest.mark.asyncio
    async def test_test_integration_connection(self, test_client, auth_headers):
        """Test integration connection testing"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.test_platform_connection"
        ) as mock_test:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_test.return_value = {
                "status": "success",
                "connection_time": 0.25,
                "api_version": "v3",
                "permissions": ["read", "write"],
            }

            test_data = {
                "platform": "github",
                "token": "test_token",
                "base_url": "https://api.github.com",
            }

            response = await test_client.post(
                "/api/v1/pipelines/test-connection",
                json=test_data,
                headers=auth_headers,
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["status"] == "success"
            assert "connection_time" in data


class TestPipelineSecurity:
    """Test pipeline security scanning"""

    @pytest.mark.asyncio
    async def test_get_pipeline_security_scan(
        self, test_client, mock_pipeline, auth_headers
    ):
        """Test pipeline security scan results retrieval"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.pipelines.get_pipeline_by_id"
        ) as mock_get_pipeline, patch(
            "src.api.services.pipeline_services.get_security_scan_results"
        ) as mock_get_scan:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_pipeline.return_value = mock_pipeline

            mock_scan_results = {
                "scan_id": str(uuid4()),
                "pipeline_id": 1,
                "status": "completed",
                "vulnerabilities": [
                    {
                        "id": "CVE-2023-1234",
                        "severity": "high",
                        "package": "example-package",
                        "version": "1.0.0",
                    }
                ],
                "summary": {"critical": 0, "high": 1, "medium": 3, "low": 5},
            }

            mock_get_scan.return_value = mock_scan_results

            response = await test_client.get(
                "/api/v1/pipelines/1/security-scan", headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["status"] == "completed"
            assert len(data["vulnerabilities"]) == 1
            assert "summary" in data

    @pytest.mark.asyncio
    async def test_trigger_security_scan(
        self, test_client, mock_pipeline, auth_headers
    ):
        """Test triggering security scan for pipeline"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_db"
        ) as mock_get_db, patch(
            "src.api.routes.pipelines.get_pipeline_by_id"
        ) as mock_get_pipeline, patch(
            "src.api.services.pipeline_services.trigger_security_scan"
        ) as mock_trigger_scan:

            mock_user = Mock()
            mock_get_user.return_value = mock_user

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            mock_get_pipeline.return_value = mock_pipeline

            scan_id = str(uuid4())
            mock_trigger_scan.return_value = {
                "scan_id": scan_id,
                "status": "started",
                "estimated_duration": 300,
            }

            response = await test_client.post(
                "/api/v1/pipelines/1/security-scan", headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["scan_id"] == scan_id
            assert data["status"] == "started"


if __name__ == "__main__":
    pytest.main([__file__])
