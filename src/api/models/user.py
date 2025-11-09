"""User model for authentication and authorization."""

from datetime import datetime
from typing import Optional

from passlib.context import CryptContext
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from sqlalchemy.orm import relationship

from .base import Base, IDMixin, TimestampMixin

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class User(Base, IDMixin, TimestampMixin):
    """User model for authentication and profile management."""

    __tablename__ = "users"

    # Basic Information
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=True)
    hashed_password = Column(String(255), nullable=False)

    # Account Status
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)

    # Role and Permissions
    role = Column(String(50), default="user", nullable=False)  # user, admin, security_admin, etc.

    # Account Security
    password_changed_at = Column(DateTime, nullable=True)
    last_login = Column(DateTime, nullable=True)
    failed_login_count = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)

    # Profile Information
    avatar_url = Column(String(500), nullable=True)
    bio = Column(Text, nullable=True)
    timezone = Column(String(50), default="UTC", nullable=False)

    # Notification Preferences
    email_notifications = Column(Boolean, default=True, nullable=False)
    slack_user_id = Column(String(100), nullable=True)

    # API Access
    api_key = Column(String(255), nullable=True, index=True)
    api_key_created_at = Column(DateTime, nullable=True)

    def set_password(self, password: str) -> None:
        """Hash and set password."""
        self.hashed_password = pwd_context.hash(password)
        self.password_changed_at = datetime.utcnow()

    def verify_password(self, password: str) -> bool:
        """Verify password against hash."""
        return pwd_context.verify(password, self.hashed_password)

    def is_locked(self) -> bool:
        """Check if account is locked due to failed logins."""
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until

    def increment_failed_login(self) -> None:
        """Increment failed login count."""
        self.failed_login_count += 1
        # Lock account after 5 failed attempts for 30 minutes
        if self.failed_login_count >= 5:
            from datetime import timedelta

            self.locked_until = datetime.utcnow() + timedelta(minutes=30)

    def reset_failed_login(self) -> None:
        """Reset failed login count and unlock account."""
        self.failed_login_count = 0
        self.locked_until = None
        self.last_login = datetime.utcnow()

    def has_role(self, role: str) -> bool:
        """Check if user has specified role."""
        return self.role == role or self.is_superuser

    def can_access_resource(self, resource: str, action: str = "read") -> bool:
        """Check if user can access a resource with specific action."""
        if self.is_superuser:
            return True

        # Basic role-based access control
        role_permissions = {
            "admin": ["read", "write", "delete", "manage"],
            "security_admin": ["read", "write", "delete"],
            "analyst": ["read", "write"],
            "viewer": ["read"],
            "user": ["read"],
        }

        allowed_actions = role_permissions.get(self.role, ["read"])
        return action in allowed_actions

    def to_dict(self, include_sensitive: bool = False) -> dict:
        """Convert user to dictionary."""
        data = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "is_active": self.is_active,
            "is_verified": self.is_verified,
            "is_superuser": self.is_superuser,
            "role": self.role,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "avatar_url": self.avatar_url,
            "bio": self.bio,
            "timezone": self.timezone,
            "email_notifications": self.email_notifications,
        }

        if include_sensitive:
            data.update(
                {
                    "failed_login_count": self.failed_login_count,
                    "locked_until": (self.locked_until.isoformat() if self.locked_until else None),
                    "password_changed_at": (self.password_changed_at.isoformat() if self.password_changed_at else None),
                    "api_key": self.api_key,
                    "api_key_created_at": (self.api_key_created_at.isoformat() if self.api_key_created_at else None),
                }
            )

        return data

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"


class UserSession(Base, IDMixin, TimestampMixin):
    """User session model for tracking active sessions."""

    __tablename__ = "user_sessions"

    user_id = Column(Integer, nullable=False, index=True)
    session_token = Column(String(255), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(Text, nullable=True)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    last_activity = Column(DateTime, nullable=True)

    def is_expired(self) -> bool:
        """Check if session is expired."""
        return datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        """Check if session is valid and active."""
        return self.is_active and not self.is_expired()

    def refresh(self, extend_minutes: int = 30) -> None:
        """Refresh session expiration."""
        from datetime import timedelta

        self.expires_at = datetime.utcnow() + timedelta(minutes=extend_minutes)
        self.last_activity = datetime.utcnow()


class UserLoginHistory(Base, IDMixin, TimestampMixin):
    """Track user login history for security monitoring."""

    __tablename__ = "user_login_history"

    user_id = Column(Integer, nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    login_successful = Column(Boolean, nullable=False)
    failure_reason = Column(String(255), nullable=True)
    location = Column(String(255), nullable=True)  # Geolocation if available

    def __repr__(self) -> str:
        status = "SUCCESS" if self.login_successful else "FAILED"
        return f"<UserLoginHistory(user_id={self.user_id}, status={status}, ip={self.ip_address})>"
