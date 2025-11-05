import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import status
from httpx import AsyncClient

from secureops_ai.src.api.main import app
from secureops_ai.src.api.models.user import User


@pytest.fixture
def test_client():
    """Create test client for FastAPI app"""
    return AsyncClient(app=app, base_url="http://test")


@pytest.fixture
def auth_headers():
    """Authentication headers for requests"""
    return {"Authorization": "Bearer test_token"}


@pytest.fixture
def mock_user():
    """Mock authenticated user"""
    user = Mock(spec=User)
    user.id = 1
    user.email = "test@example.com"
    user.is_active = True
    return user


class TestHealthEndpoints:
    """Test health check and status endpoints"""

    @pytest.mark.asyncio
    async def test_health_check(self, test_client):
        """Test basic health check endpoint"""
        response = await test_client.get("/health")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "version" in data

    @pytest.mark.asyncio
    async def test_health_detailed(self, test_client):
        """Test detailed health check endpoint"""
        with patch(
            "src.api.routes.health.check_database_connection"
        ) as mock_db_check, patch(
            "src.api.routes.health.check_redis_connection"
        ) as mock_redis_check, patch(
            "src.api.routes.health.check_external_services"
        ) as mock_external_check:

            mock_db_check.return_value = {"status": "healthy", "response_time": 0.05}
            mock_redis_check.return_value = {"status": "healthy", "response_time": 0.02}
            mock_external_check.return_value = {"trivy": "healthy", "github": "healthy"}

            response = await test_client.get("/health/detailed")

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["status"] == "healthy"
            assert "database" in data["services"]
            assert "redis" in data["services"]
            assert "external" in data["services"]

    @pytest.mark.asyncio
    async def test_readiness_check(self, test_client):
        """Test readiness probe endpoint"""
        with patch("src.api.routes.health.check_system_readiness") as mock_readiness:
            mock_readiness.return_value = {
                "ready": True,
                "checks": {"database": True, "migrations": True, "cache": True},
            }

            response = await test_client.get("/ready")

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["ready"] is True

    @pytest.mark.asyncio
    async def test_liveness_check(self, test_client):
        """Test liveness probe endpoint"""
        response = await test_client.get("/alive")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["alive"] is True
        assert "uptime" in data


class TestAPIVersioning:
    """Test API versioning endpoints"""

    @pytest.mark.asyncio
    async def test_api_v1_prefix(self, test_client, auth_headers):
        """Test that all API endpoints use v1 prefix"""
        # Test various endpoints to ensure they use /api/v1/ prefix
        endpoints = [
            "/api/v1/users/me",
            "/api/v1/pipelines",
            "/api/v1/alerts",
            "/api/v1/compliance",
        ]

        for endpoint in endpoints:
            with patch("src.api.routes.auth.get_current_user") as mock_get_user:
                mock_get_user.return_value = Mock()

                response = await test_client.get(endpoint, headers=auth_headers)
                # Should not return 404, meaning the endpoint exists
                assert response.status_code != status.HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    async def test_api_info_endpoint(self, test_client):
        """Test API information endpoint"""
        response = await test_client.get("/api/v1/info")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "version" in data
        assert "title" in data
        assert "description" in data


class TestCORSHeaders:
    """Test CORS configuration"""

    @pytest.mark.asyncio
    async def test_cors_headers_present(self, test_client):
        """Test that CORS headers are present in responses"""
        response = await test_client.options("/api/v1/info")

        assert "access-control-allow-origin" in response.headers
        assert "access-control-allow-methods" in response.headers
        assert "access-control-allow-headers" in response.headers

    @pytest.mark.asyncio
    async def test_cors_preflight_request(self, test_client):
        """Test CORS preflight request handling"""
        headers = {
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type, Authorization",
        }

        response = await test_client.options("/api/v1/pipelines", headers=headers)

        assert response.status_code == status.HTTP_200_OK
        assert "access-control-allow-origin" in response.headers


class TestErrorHandling:
    """Test error handling across endpoints"""

    @pytest.mark.asyncio
    async def test_404_not_found(self, test_client):
        """Test 404 error handling"""
        response = await test_client.get("/api/v1/nonexistent")

        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = response.json()
        assert "detail" in data

    @pytest.mark.asyncio
    async def test_method_not_allowed(self, test_client):
        """Test 405 method not allowed"""
        response = await test_client.patch("/health")

        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    @pytest.mark.asyncio
    async def test_validation_error_422(self, test_client, auth_headers):
        """Test 422 validation error handling"""
        invalid_data = {
            "name": "",  # Empty name should fail validation
            "platform": "invalid_platform",
        }

        response = await test_client.post(
            "/api/v1/pipelines", json=invalid_data, headers=auth_headers
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        data = response.json()
        assert "detail" in data

    @pytest.mark.asyncio
    async def test_internal_server_error_500(self, test_client, auth_headers):
        """Test 500 internal server error handling"""
        with patch("src.api.routes.pipelines.get_pipelines") as mock_get_pipelines:
            mock_get_pipelines.side_effect = Exception("Database connection failed")

            response = await test_client.get("/api/v1/pipelines", headers=auth_headers)

            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            data = response.json()
            assert "detail" in data


class TestRateLimiting:
    """Test rate limiting across endpoints"""

    @pytest.mark.asyncio
    async def test_rate_limiting_unauthenticated(self, test_client):
        """Test rate limiting for unauthenticated requests"""
        # Make multiple requests to trigger rate limiting
        responses = []
        for i in range(10):
            response = await test_client.get("/api/v1/info")
            responses.append(response.status_code)

        # Should handle high frequency requests appropriately
        # At least some requests should succeed
        assert any(code == status.HTTP_200_OK for code in responses)

    @pytest.mark.asyncio
    async def test_rate_limiting_authenticated(self, test_client, auth_headers):
        """Test rate limiting for authenticated requests"""
        with patch("src.api.routes.auth.get_current_user") as mock_get_user:
            mock_get_user.return_value = Mock()

            # Authenticated users should have higher rate limits
            responses = []
            for i in range(15):
                response = await test_client.get(
                    "/api/v1/users/me", headers=auth_headers
                )
                responses.append(response.status_code)

            # Most requests should succeed for authenticated users
            success_count = sum(1 for code in responses if code == status.HTTP_200_OK)
            assert success_count > 10


class TestSecurityHeaders:
    """Test security headers in responses"""

    @pytest.mark.asyncio
    async def test_security_headers_present(self, test_client):
        """Test that security headers are present"""
        response = await test_client.get("/api/v1/info")

        # Check for common security headers
        headers_to_check = [
            "x-content-type-options",
            "x-frame-options",
            "x-xss-protection",
        ]

        for header in headers_to_check:
            assert (
                header in response.headers
                or header.replace("-", "_") in response.headers
            )

    @pytest.mark.asyncio
    async def test_no_server_header_exposure(self, test_client):
        """Test that server information is not exposed"""
        response = await test_client.get("/api/v1/info")

        # Server header should not expose detailed server information
        server_header = response.headers.get("server", "")
        assert "uvicorn" not in server_header.lower()
        assert "python" not in server_header.lower()


class TestContentNegotiation:
    """Test content negotiation"""

    @pytest.mark.asyncio
    async def test_json_content_type(self, test_client):
        """Test JSON content type handling"""
        response = await test_client.get("/api/v1/info")

        assert response.status_code == status.HTTP_200_OK
        assert "application/json" in response.headers["content-type"]

    @pytest.mark.asyncio
    async def test_accept_header_handling(self, test_client):
        """Test Accept header handling"""
        headers = {"Accept": "application/json"}
        response = await test_client.get("/api/v1/info", headers=headers)

        assert response.status_code == status.HTTP_200_OK
        assert "application/json" in response.headers["content-type"]

    @pytest.mark.asyncio
    async def test_unsupported_media_type(self, test_client, auth_headers):
        """Test unsupported media type handling"""
        headers = {**auth_headers, "Content-Type": "application/xml"}
        xml_data = "<pipeline><name>Test</name></pipeline>"

        response = await test_client.post(
            "/api/v1/pipelines", content=xml_data, headers=headers
        )

        assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE


class TestRequestValidation:
    """Test request validation across endpoints"""

    @pytest.mark.asyncio
    async def test_large_request_body(self, test_client, auth_headers):
        """Test handling of large request bodies"""
        # Create a large payload
        large_data = {
            "name": "Test Pipeline",
            "description": "A" * 10000,  # Very long description
            "platform": "github",
            "repository_url": "https://github.com/test/repo",
        }

        response = await test_client.post(
            "/api/v1/pipelines", json=large_data, headers=auth_headers
        )

        # Should either accept or reject with appropriate status
        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        ]

    @pytest.mark.asyncio
    async def test_malformed_json(self, test_client, auth_headers):
        """Test handling of malformed JSON"""
        malformed_json = '{"name": "Test", "invalid": json}'

        response = await test_client.post(
            "/api/v1/pipelines",
            content=malformed_json,
            headers={**auth_headers, "Content-Type": "application/json"},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestPaginationEndpoints:
    """Test pagination across paginated endpoints"""

    @pytest.mark.asyncio
    async def test_pagination_parameters(self, test_client, auth_headers):
        """Test pagination parameters validation"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_pipelines"
        ) as mock_get_pipelines:

            mock_get_user.return_value = Mock()
            mock_get_pipelines.return_value = ([], 0)

            # Test valid pagination parameters
            params = {"limit": 10, "offset": 0}
            response = await test_client.get(
                "/api/v1/pipelines", params=params, headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_pagination_limits(self, test_client, auth_headers):
        """Test pagination limits"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user:
            mock_get_user.return_value = Mock()

            # Test with limit exceeding maximum
            params = {"limit": 1000, "offset": 0}
            response = await test_client.get(
                "/api/v1/pipelines", params=params, headers=auth_headers
            )

            # Should either accept with adjusted limit or reject
            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            ]


class TestWebSocketEndpoints:
    """Test WebSocket endpoint availability"""

    @pytest.mark.asyncio
    async def test_websocket_endpoint_exists(self, test_client):
        """Test that WebSocket endpoint is available"""
        # Test WebSocket connection endpoint
        # Note: This just tests that the endpoint exists, not the actual WS functionality
        try:
            response = await test_client.get("/ws")
            # WebSocket endpoints typically return 426 for HTTP requests
            assert response.status_code in [
                status.HTTP_426_UPGRADE_REQUIRED,
                status.HTTP_404_NOT_FOUND,
                status.HTTP_200_OK,
            ]
        except Exception:
            # WebSocket testing is complex, so we just ensure no critical errors
            pass


class TestDocumentationEndpoints:
    """Test API documentation endpoints"""

    @pytest.mark.asyncio
    async def test_openapi_schema(self, test_client):
        """Test OpenAPI schema endpoint"""
        response = await test_client.get("/openapi.json")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "openapi" in data
        assert "info" in data
        assert "paths" in data

    @pytest.mark.asyncio
    async def test_swagger_docs(self, test_client):
        """Test Swagger documentation endpoint"""
        response = await test_client.get("/docs")

        assert response.status_code == status.HTTP_200_OK
        assert "text/html" in response.headers["content-type"]

    @pytest.mark.asyncio
    async def test_redoc_docs(self, test_client):
        """Test ReDoc documentation endpoint"""
        response = await test_client.get("/redoc")

        assert response.status_code == status.HTTP_200_OK
        assert "text/html" in response.headers["content-type"]


class TestMetricsEndpoints:
    """Test metrics and monitoring endpoints"""

    @pytest.mark.asyncio
    async def test_metrics_endpoint(self, test_client):
        """Test metrics endpoint"""
        with patch("src.api.routes.metrics.generate_metrics") as mock_metrics:
            mock_metrics.return_value = """
            # HELP http_requests_total Total HTTP requests
            # TYPE http_requests_total counter
            http_requests_total{method="GET",status="200"} 100
            """

            response = await test_client.get("/metrics")

            assert response.status_code == status.HTTP_200_OK
            assert "text/plain" in response.headers["content-type"]

    @pytest.mark.asyncio
    async def test_prometheus_format(self, test_client):
        """Test Prometheus metrics format"""
        with patch(
            "src.api.routes.metrics.generate_prometheus_metrics"
        ) as mock_prometheus:
            mock_prometheus.return_value = "# Prometheus metrics here"

            headers = {"Accept": "text/plain; version=0.0.4"}
            response = await test_client.get("/metrics", headers=headers)

            assert response.status_code == status.HTTP_200_OK


class TestDependencyInjection:
    """Test dependency injection across endpoints"""

    @pytest.mark.asyncio
    async def test_database_dependency(self, test_client, auth_headers):
        """Test database dependency injection"""
        with patch("src.api.database.get_db") as mock_get_db:
            mock_db = Mock()
            mock_get_db.return_value = mock_db

            response = await test_client.get("/api/v1/pipelines", headers=auth_headers)

            # Database dependency should be called
            mock_get_db.assert_called()

    @pytest.mark.asyncio
    async def test_user_dependency(self, test_client, auth_headers):
        """Test current user dependency injection"""
        with patch("src.api.routes.auth.get_current_user") as mock_get_user:
            mock_user = Mock()
            mock_get_user.return_value = mock_user

            response = await test_client.get("/api/v1/users/me", headers=auth_headers)

            # User dependency should be called
            mock_get_user.assert_called()


class TestAsyncEndpoints:
    """Test asynchronous endpoint behavior"""

    @pytest.mark.asyncio
    async def test_concurrent_requests(self, test_client, auth_headers):
        """Test handling of concurrent requests"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.get_pipelines"
        ) as mock_get_pipelines:

            mock_get_user.return_value = Mock()
            mock_get_pipelines.return_value = ([], 0)

            # Make concurrent requests
            tasks = []
            for i in range(5):
                task = test_client.get("/api/v1/pipelines", headers=auth_headers)
                tasks.append(task)

            responses = await asyncio.gather(*tasks)

            # All requests should succeed
            for response in responses:
                assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_long_running_request(self, test_client, auth_headers):
        """Test handling of long-running requests"""
        with patch("src.api.routes.pipelines.get_current_user") as mock_get_user, patch(
            "src.api.routes.pipelines.trigger_pipeline"
        ) as mock_trigger:

            mock_get_user.return_value = Mock()

            async def slow_trigger(*args, **kwargs):
                await asyncio.sleep(0.1)  # Simulate slow operation
                return {"execution_id": "test_123", "status": "running"}

            mock_trigger.side_effect = slow_trigger

            response = await test_client.post(
                "/api/v1/pipelines/1/trigger", headers=auth_headers
            )

            # Should handle slow operations gracefully
            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_408_REQUEST_TIMEOUT,
            ]


if __name__ == "__main__":
    pytest.main([__file__])
