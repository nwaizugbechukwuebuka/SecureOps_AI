"""
User management models for authentication and authorization.
"""

from datetime import datetime
from typing import List, Optional

from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field, validator
from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String, Text
from sqlalchemy.orm import relationship

from .base import Base, BaseResponse, IDMixin, TimestampMixin

# Password hashing context - use pbkdf2 for development to avoid bcrypt issues
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256", "bcrypt"], 
    deprecated="auto",
    pbkdf2_sha256__rounds=29000,
)


class User(Base, IDMixin, TimestampMixin):
    """User model for authentication and profile management."""

    __tablename__ = "users"

    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)

    # Profile information
    company = Column(String(255), nullable=True)
    department = Column(String(100), nullable=True)
    role = Column(String(100), nullable=True)
    timezone = Column(String(50), default="UTC", nullable=False)

    # Security settings
    last_login = Column(DateTime(timezone=True), nullable=True)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    password_changed_at = Column(DateTime(timezone=True), nullable=True)

    # Notification preferences
    notification_preferences = Column(JSON, nullable=True)

    # API access
    api_key = Column(String(255), unique=True, nullable=True, index=True)
    api_key_created_at = Column(DateTime(timezone=True), nullable=True)

    def verify_password(self, password: str) -> bool:
        """Verify a password against the stored hash."""
        return pwd_context.verify(password, self.hashed_password)

    def set_password(self, password: str) -> None:
        """Hash and set a new password."""
        # Truncate password to 72 bytes for bcrypt compatibility
        password_bytes = password.encode('utf-8')[:72]
        password_truncated = password_bytes.decode('utf-8', errors='ignore')
        self.hashed_password = pwd_context.hash(password_truncated)
        self.password_changed_at = datetime.utcnow()

    def is_locked(self) -> bool:
        """Check if account is currently locked."""
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until

    def increment_failed_login(self) -> None:
        """Increment failed login attempts and lock if threshold exceeded."""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:  # Lock after 5 failed attempts
            self.locked_until = datetime.utcnow().replace(
                hour=datetime.utcnow().hour + 1
            )

    def reset_failed_login(self) -> None:
        """Reset failed login attempts after successful login."""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.utcnow()


# Pydantic models for API serialization
class UserBase(BaseModel):
    """Base user model with common fields."""

    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: Optional[str] = Field(None, max_length=255)
    company: Optional[str] = Field(None, max_length=255)
    department: Optional[str] = Field(None, max_length=100)
    role: Optional[str] = Field(None, max_length=100)
    timezone: str = Field(default="UTC", max_length=50)

    @validator("username")
    def validate_username(cls, v):
        if not v.isalnum() and "_" not in v and "-" not in v:
            raise ValueError(
                "Username must contain only alphanumeric characters, underscores, or hyphens"
            )
        return v.lower()


class UserCreate(UserBase):
    """Model for user creation."""

    password: str = Field(..., min_length=8, max_length=100)
    confirm_password: str = Field(..., min_length=8, max_length=100)

    @validator("confirm_password")
    def passwords_match(cls, v, values):
        if "password" in values and v != values["password"]:
            raise ValueError("Passwords do not match")
        return v

    @validator("password")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v):
            raise ValueError("Password must contain at least one special character")
        return v


class UserUpdate(BaseModel):
    """Model for user updates."""

    full_name: Optional[str] = Field(None, max_length=255)
    email: Optional[EmailStr] = None
    company: Optional[str] = Field(None, max_length=255)
    department: Optional[str] = Field(None, max_length=100)
    role: Optional[str] = Field(None, max_length=100)
    timezone: Optional[str] = Field(None, max_length=50)
    notification_preferences: Optional[dict] = None


class UserResponse(UserBase, BaseResponse):
    """Model for user API responses."""

    is_active: bool
    is_verified: bool
    last_login: Optional[datetime] = None
    notification_preferences: Optional[dict] = None

    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    """Model for user login."""

    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=1, max_length=100)
    remember_me: bool = Field(default=False)


class UserPasswordChange(BaseModel):
    """Model for password changes."""

    current_password: str = Field(..., min_length=1, max_length=100)
    new_password: str = Field(..., min_length=8, max_length=100)
    confirm_password: str = Field(..., min_length=8, max_length=100)

    @validator("confirm_password")
    def passwords_match(cls, v, values):
        if "new_password" in values and v != values["new_password"]:
            raise ValueError("New passwords do not match")
        return v

    @validator("new_password")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v):
            raise ValueError("Password must contain at least one special character")
        return v


class Token(BaseModel):
    """JWT token response model."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class TokenData(BaseModel):
    """Token payload data model."""

    user_id: Optional[int] = None
    username: Optional[str] = None
    scopes: List[str] = []


class APIKeyCreate(BaseModel):
    """Model for API key creation."""

    name: str = Field(..., min_length=1, max_length=100)
    expires_in_days: Optional[int] = Field(default=90, ge=1, le=365)


class APIKeyResponse(BaseModel):
    """Model for API key response."""

    key: str
    name: str
    created_at: datetime
    expires_at: Optional[datetime] = None

    class Config:
        from_attributes = True
