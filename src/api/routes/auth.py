"""Authentication routes for SecureOps API."""

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models.user import User
from ..utils.config import get_settings
from ..utils.logger import get_logger

router = APIRouter()
logger = get_logger(__name__)
security = HTTPBearer()
settings = get_settings()


# Pydantic models
class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str]
    is_active: bool
    role: str

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None


# Dependency to get current user from token
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Get current user from JWT token."""
    # For now, return a mock user to enable testing
    # In production, this would verify the JWT token and fetch the user
    mock_user = User()
    mock_user.id = 1
    mock_user.username = "admin"
    mock_user.email = "admin@secureops.com"
    mock_user.role = "admin"
    mock_user.is_active = True
    mock_user.is_superuser = True
    return mock_user


# Optional dependency for endpoints that can work without authentication
async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """Get current user from JWT token, returns None if not authenticated."""
    if not credentials:
        return None
    return await get_current_user(credentials, db)


@router.post("/login", response_model=TokenResponse)
async def login(
    login_data: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """Login endpoint."""
    logger.info(f"Login attempt for username: {login_data.username}")
    
    # For now, return a mock successful login
    # In production, this would verify credentials against the database
    mock_user = UserResponse(
        id=1,
        username=login_data.username,
        email="admin@secureops.com",
        full_name="Admin User",
        is_active=True,
        role="admin"
    )
    
    return TokenResponse(
        access_token="mock_jwt_token_placeholder",
        expires_in=1800,  # 30 minutes
        user=mock_user
    )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    register_data: RegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    """User registration endpoint."""
    logger.info(f"Registration attempt for username: {register_data.username}")
    
    # For now, return a mock registration success
    # In production, this would create a new user in the database
    return UserResponse(
        id=2,
        username=register_data.username,
        email=register_data.email,
        full_name=register_data.full_name,
        is_active=True,
        role="user"
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """Get current user information."""
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        is_active=current_user.is_active,
        role=current_user.role
    )


@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user)
):
    """Logout endpoint."""
    logger.info(f"User {current_user.username} logged out")
    return {"message": "Successfully logged out"}


@router.post("/refresh")
async def refresh_token(
    current_user: User = Depends(get_current_user)
):
    """Refresh JWT token."""
    return TokenResponse(
        access_token="refreshed_mock_jwt_token",
        expires_in=1800,
        user=UserResponse(
            id=current_user.id,
            username=current_user.username,
            email=current_user.email,
            full_name=current_user.full_name,
            is_active=current_user.is_active,
            role=current_user.role
        )
    )
