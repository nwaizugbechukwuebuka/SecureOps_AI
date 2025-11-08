import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch

import jwt
import pytest
from fastapi import status
from httpx import AsyncClient

from src.api.main import app
from src.api.models.user import User
from src.api.utils.config import get_settings

settings = get_settings()


@pytest.fixture
def test_client():
    """Create test client for FastAPI app"""
    return AsyncClient(app=app, base_url="http://test")


@pytest.fixture
def sample_user_data():
    """Sample user data for testing"""
    return {
        "email": "test@example.com",
        "password": "TestPassword123!",
        "first_name": "Test",
        "last_name": "User",
        "is_active": True,
    }


@pytest.fixture
def mock_db():
    """Mock database session"""
    return Mock()


@pytest.fixture
def mock_user():
    """Mock user object"""
    user = Mock(spec=User)
    user.id = 1
    user.email = "test@example.com"
    user.first_name = "Test"
    user.last_name = "User"
    user.is_active = True
    user.is_verified = True
    user.created_at = datetime.now()
    user.last_login = None
    return user


@pytest.fixture
def valid_token():
    """Generate a valid JWT token for testing"""
    payload = {
        "sub": "test@example.com",
        "user_id": 1,
        "exp": datetime.utcnow() + timedelta(minutes=30),
        "iat": datetime.utcnow(),
        "type": "access",
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


@pytest.fixture
def expired_token():
    """Generate an expired JWT token for testing"""
    payload = {
        "sub": "test@example.com",
        "user_id": 1,
        "exp": datetime.utcnow() - timedelta(minutes=30),
        "iat": datetime.utcnow() - timedelta(hours=1),
        "type": "access",
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


class TestUserRegistration:
    """Test user registration functionality"""

    @pytest.mark.asyncio
    async def test_register_user_success(self, test_client, sample_user_data):
        """Test successful user registration"""
        with patch("src.api.routes.auth.get_db") as mock_get_db, patch(
            "src.api.routes.auth.create_user"
        ) as mock_create_user, patch(
            "src.api.routes.auth.send_verification_email"
        ) as mock_send_email:

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            # Mock user creation
            mock_user = Mock()
            mock_user.id = 1
            mock_user.email = sample_user_data["email"]
            mock_user.first_name = sample_user_data["first_name"]
            mock_user.last_name = sample_user_data["last_name"]
            mock_user.is_active = True
            mock_user.is_verified = False

            mock_create_user.return_value = mock_user
            mock_send_email.return_value = True

            response = await test_client.post(
                "/api/v1/auth/register", json=sample_user_data
            )

            assert response.status_code == status.HTTP_201_CREATED
            data = response.json()
            assert data["email"] == sample_user_data["email"]
            assert data["first_name"] == sample_user_data["first_name"]
            assert "id" in data
            assert "password" not in data  # Password should not be returned

    @pytest.mark.asyncio
    async def test_register_user_duplicate_email(self, test_client, sample_user_data):
        """Test registration with duplicate email"""
        with patch("src.api.routes.auth.get_db") as mock_get_db, patch(
            "src.api.routes.auth.get_user_by_email"
        ) as mock_get_user:

            mock_db = Mock()
            mock_get_db.return_value = mock_db

            # Mock existing user
            mock_get_user.return_value = Mock()

            response = await test_client.post(
                "/api/v1/auth/register", json=sample_user_data
            )

            assert response.status_code == status.HTTP_400_BAD_REQUEST
            data = response.json()
            assert "already registered" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_register_user_invalid_email(self, test_client, sample_user_data):
        """Test registration with invalid email format"""
        sample_user_data["email"] = "invalid-email"

        response = await test_client.post(
            "/api/v1/auth/register", json=sample_user_data
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_register_user_weak_password(self, test_client, sample_user_data):
        """Test registration with weak password"""
        sample_user_data["password"] = "123"

        response = await test_client.post(
            "/api/v1/auth/register", json=sample_user_data
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestUserLogin:
    """Test user login functionality"""

    @pytest.mark.asyncio
    async def test_login_success(self, test_client, sample_user_data, mock_user):
        """Test successful user login"""
        with patch("src.api.routes.auth.authenticate_user") as mock_auth, patch(
            "src.api.routes.auth.create_access_token"
        ) as mock_create_token, patch(
            "src.api.routes.auth.create_refresh_token"
        ) as mock_create_refresh, patch(
            "src.api.routes.auth.update_last_login"
        ) as mock_update_login:

            mock_auth.return_value = mock_user
            mock_create_token.return_value = "access_token"
            mock_create_refresh.return_value = "refresh_token"
            mock_update_login.return_value = None

            login_data = {
                "username": sample_user_data["email"],
                "password": sample_user_data["password"],
            }

            response = await test_client.post("/api/v1/auth/login", data=login_data)

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["access_token"] == "access_token"
            assert data["refresh_token"] == "refresh_token"
            assert data["token_type"] == "bearer"
            assert "user" in data

    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, test_client, sample_user_data):
        """Test login with invalid credentials"""
        with patch("src.api.routes.auth.authenticate_user") as mock_auth:
            mock_auth.return_value = None

            login_data = {
                "username": sample_user_data["email"],
                "password": "wrong_password",
            }

            response = await test_client.post("/api/v1/auth/login", data=login_data)

            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            data = response.json()
            assert "incorrect" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_login_inactive_user(self, test_client, sample_user_data, mock_user):
        """Test login with inactive user"""
        mock_user.is_active = False

        with patch("src.api.routes.auth.authenticate_user") as mock_auth:
            mock_auth.return_value = mock_user

            login_data = {
                "username": sample_user_data["email"],
                "password": sample_user_data["password"],
            }

            response = await test_client.post("/api/v1/auth/login", data=login_data)

            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            data = response.json()
            assert "inactive" in data["detail"].lower()


class TestTokenManagement:
    """Test JWT token management"""

    @pytest.mark.asyncio
    async def test_refresh_token_success(self, test_client):
        """Test successful token refresh"""
        with patch("src.api.routes.auth.verify_refresh_token") as mock_verify, patch(
            "src.api.routes.auth.get_user_by_email"
        ) as mock_get_user, patch(
            "src.api.routes.auth.create_access_token"
        ) as mock_create_token:

            mock_user = Mock()
            mock_user.email = "test@example.com"
            mock_user.is_active = True

            mock_verify.return_value = "test@example.com"
            mock_get_user.return_value = mock_user
            mock_create_token.return_value = "new_access_token"

            refresh_data = {"refresh_token": "valid_refresh_token"}
            response = await test_client.post("/api/v1/auth/refresh", json=refresh_data)

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["access_token"] == "new_access_token"
            assert data["token_type"] == "bearer"

    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, test_client):
        """Test refresh with invalid token"""
        with patch("src.api.routes.auth.verify_refresh_token") as mock_verify:
            mock_verify.side_effect = Exception("Invalid token")

            refresh_data = {"refresh_token": "invalid_refresh_token"}
            response = await test_client.post("/api/v1/auth/refresh", json=refresh_data)

            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_logout_success(self, test_client, valid_token):
        """Test successful user logout"""
        with patch("src.api.routes.auth.get_current_user") as mock_get_user, patch(
            "src.api.routes.auth.invalidate_token"
        ) as mock_invalidate:

            mock_user = Mock()
            mock_get_user.return_value = mock_user
            mock_invalidate.return_value = True

            headers = {"Authorization": f"Bearer {valid_token}"}
            response = await test_client.post("/api/v1/auth/logout", headers=headers)

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["message"] == "Successfully logged out"


class TestPasswordManagement:
    """Test password management functionality"""

    @pytest.mark.asyncio
    async def test_change_password_success(self, test_client, valid_token, mock_user):
        """Test successful password change"""
        with patch("src.api.routes.auth.get_current_user") as mock_get_user, patch(
            "src.api.routes.auth.verify_password"
        ) as mock_verify, patch("src.api.routes.auth.update_password") as mock_update:

            mock_get_user.return_value = mock_user
            mock_verify.return_value = True
            mock_update.return_value = True

            password_data = {
                "current_password": "OldPassword123!",
                "new_password": "NewPassword123!",
            }

            headers = {"Authorization": f"Bearer {valid_token}"}
            response = await test_client.post(
                "/api/v1/auth/change-password", json=password_data, headers=headers
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["message"] == "Password updated successfully"

    @pytest.mark.asyncio
    async def test_change_password_wrong_current(
        self, test_client, valid_token, mock_user
    ):
        """Test password change with wrong current password"""
        with patch("src.api.routes.auth.get_current_user") as mock_get_user, patch(
            "src.api.routes.auth.verify_password"
        ) as mock_verify:

            mock_get_user.return_value = mock_user
            mock_verify.return_value = False

            password_data = {
                "current_password": "WrongPassword",
                "new_password": "NewPassword123!",
            }

            headers = {"Authorization": f"Bearer {valid_token}"}
            response = await test_client.post(
                "/api/v1/auth/change-password", json=password_data, headers=headers
            )

            assert response.status_code == status.HTTP_400_BAD_REQUEST
            data = response.json()
            assert "current password" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_reset_password_request(self, test_client):
        """Test password reset request"""
        with patch("src.api.routes.auth.get_user_by_email") as mock_get_user, patch(
            "src.api.routes.auth.create_reset_token"
        ) as mock_create_token, patch(
            "src.api.routes.auth.send_reset_email"
        ) as mock_send_email:

            mock_user = Mock()
            mock_get_user.return_value = mock_user
            mock_create_token.return_value = "reset_token"
            mock_send_email.return_value = True

            reset_data = {"email": "test@example.com"}
            response = await test_client.post(
                "/api/v1/auth/reset-password", json=reset_data
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert "reset link sent" in data["message"].lower()

    @pytest.mark.asyncio
    async def test_reset_password_confirm(self, test_client):
        """Test password reset confirmation"""
        with patch("src.api.routes.auth.verify_reset_token") as mock_verify, patch(
            "src.api.routes.auth.get_user_by_email"
        ) as mock_get_user, patch("src.api.routes.auth.update_password") as mock_update:

            mock_verify.return_value = "test@example.com"
            mock_user = Mock()
            mock_get_user.return_value = mock_user
            mock_update.return_value = True

            confirm_data = {
                "token": "valid_reset_token",
                "new_password": "NewPassword123!",
            }
            response = await test_client.post(
                "/api/v1/auth/reset-password/confirm", json=confirm_data
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert "password reset successfully" in data["message"].lower()


class TestEmailVerification:
    """Test email verification functionality"""

    @pytest.mark.asyncio
    async def test_verify_email_success(self, test_client):
        """Test successful email verification"""
        with patch("src.api.routes.auth.verify_email_token") as mock_verify, patch(
            "src.api.routes.auth.get_user_by_email"
        ) as mock_get_user, patch("src.api.routes.auth.activate_user") as mock_activate:

            mock_verify.return_value = "test@example.com"
            mock_user = Mock()
            mock_user.is_verified = False
            mock_get_user.return_value = mock_user
            mock_activate.return_value = True

            verify_data = {"token": "valid_verification_token"}
            response = await test_client.post(
                "/api/v1/auth/verify-email", json=verify_data
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert "email verified successfully" in data["message"].lower()

    @pytest.mark.asyncio
    async def test_verify_email_invalid_token(self, test_client):
        """Test email verification with invalid token"""
        with patch("src.api.routes.auth.verify_email_token") as mock_verify:
            mock_verify.side_effect = Exception("Invalid token")

            verify_data = {"token": "invalid_verification_token"}
            response = await test_client.post(
                "/api/v1/auth/verify-email", json=verify_data
            )

            assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.asyncio
    async def test_resend_verification_email(self, test_client):
        """Test resending verification email"""
        with patch("src.api.routes.auth.get_user_by_email") as mock_get_user, patch(
            "src.api.routes.auth.send_verification_email"
        ) as mock_send_email:

            mock_user = Mock()
            mock_user.is_verified = False
            mock_get_user.return_value = mock_user
            mock_send_email.return_value = True

            resend_data = {"email": "test@example.com"}
            response = await test_client.post(
                "/api/v1/auth/resend-verification", json=resend_data
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert "verification email sent" in data["message"].lower()


class TestTokenValidation:
    """Test token validation and security"""

    @pytest.mark.asyncio
    async def test_access_protected_route_valid_token(
        self, test_client, valid_token, mock_user
    ):
        """Test accessing protected route with valid token"""
        with patch("src.api.routes.auth.get_current_user") as mock_get_user:
            mock_get_user.return_value = mock_user

            headers = {"Authorization": f"Bearer {valid_token}"}
            response = await test_client.get("/api/v1/users/me", headers=headers)

            assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_access_protected_route_no_token(self, test_client):
        """Test accessing protected route without token"""
        response = await test_client.get("/api/v1/users/me")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_access_protected_route_invalid_token(self, test_client):
        """Test accessing protected route with invalid token"""
        headers = {"Authorization": "Bearer invalid_token"}
        response = await test_client.get("/api/v1/users/me", headers=headers)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_access_protected_route_expired_token(
        self, test_client, expired_token
    ):
        """Test accessing protected route with expired token"""
        headers = {"Authorization": f"Bearer {expired_token}"}
        response = await test_client.get("/api/v1/users/me", headers=headers)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestRateLimiting:
    """Test rate limiting for authentication endpoints"""

    @pytest.mark.asyncio
    async def test_login_rate_limiting(self, test_client, sample_user_data):
        """Test rate limiting on login attempts"""
        login_data = {
            "username": sample_user_data["email"],
            "password": "wrong_password",
        }

        # Simulate multiple failed login attempts
        responses = []
        for i in range(6):  # Assuming rate limit is 5 attempts
            response = await test_client.post("/api/v1/auth/login", data=login_data)
            responses.append(response.status_code)

        # Last request should be rate limited
        assert responses[-1] == status.HTTP_429_TOO_MANY_REQUESTS

    @pytest.mark.asyncio
    async def test_registration_rate_limiting(self, test_client, sample_user_data):
        """Test rate limiting on registration attempts"""
        # Simulate multiple registration attempts
        responses = []
        for i in range(6):  # Assuming rate limit is 5 attempts
            sample_user_data["email"] = f"test{i}@example.com"
            response = await test_client.post(
                "/api/v1/auth/register", json=sample_user_data
            )
            responses.append(response.status_code)

        # Should handle high frequency requests appropriately
        assert any(
            status_code in [status.HTTP_201_CREATED, status.HTTP_429_TOO_MANY_REQUESTS]
            for status_code in responses
        )


if __name__ == "__main__":
    pytest.main([__file__])
