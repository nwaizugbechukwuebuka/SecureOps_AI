"""Shared test configuration and fixtures."""

from unittest.mock import Mock

import pytest
from httpx import AsyncClient

from api.models.user import User
from main import app


@pytest.fixture
async def test_client():
    """Create test client for FastAPI app"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


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
    """Mock authentication headers"""
    return {"Authorization": "Bearer test-token"}
