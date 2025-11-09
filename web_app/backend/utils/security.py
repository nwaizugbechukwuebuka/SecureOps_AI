"""
Security utilities for SecureOps AI
JWT tokens, password hashing, and authentication helpers
"""

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from fastapi import HTTPException, status
from config import settings


class SecurityManager:
    """Security utilities for authentication and authorization"""

    def __init__(self):
        self.secret_key = settings.secret_key
        self.algorithm = settings.algorithm
        self.access_token_expire_minutes = settings.access_token_expire_minutes

    def hash_password(self, password: str) -> str:
        """Hash password using SHA256 (simple demo implementation)"""
        return hashlib.sha256(password.encode()).hexdigest()

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return self.hash_password(plain_password) == hashed_password

    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)

        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def decode_access_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Decode and verify JWT access token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except JWTError:
            return None

    def generate_api_key(self) -> str:
        """Generate secure API key"""
        return secrets.token_urlsafe(32)

    def hash_api_key(self, api_key: str) -> str:
        """Hash API key for storage"""
        return hashlib.sha256(api_key.encode()).hexdigest()

    def verify_api_key(self, api_key: str, hashed_key: str) -> bool:
        """Verify API key against hash"""
        return self.hash_api_key(api_key) == hashed_key


# Global security manager instance
security_manager = SecurityManager()

# Authentication exceptions
credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

inactive_user_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Inactive user account",
    headers={"WWW-Authenticate": "Bearer"},
)

insufficient_permissions_exception = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions to access this resource"
)

# Helper functions


def create_token_for_user(user_data: Dict[str, Any]) -> str:
    """Create access token for user"""
    token_data = {
        "sub": user_data["username"],
        "user_id": user_data["id"],
        "is_admin": user_data.get("is_admin", False),
        "role": user_data.get("role", "user"),
    }
    return security_manager.create_access_token(token_data)


def extract_user_from_token(token: str) -> Optional[Dict[str, Any]]:
    """Extract user information from token"""
    payload = security_manager.decode_access_token(token)
    if payload is None:
        return None

    return {
        "username": payload.get("sub"),
        "user_id": payload.get("user_id"),
        "is_admin": payload.get("is_admin", False),
        "role": payload.get("role", "user"),
    }


def validate_password_strength(password: str) -> bool:
    """Validate password meets minimum requirements"""
    if len(password) < settings.password_min_length:
        return False

    # Add more password strength checks as needed
    # - Must contain uppercase letter
    # - Must contain lowercase letter
    # - Must contain digit
    # - Must contain special character

    return True


def generate_secure_filename(filename: str) -> str:
    """Generate secure filename for uploads"""
    # Extract extension
    parts = filename.rsplit(".", 1)
    if len(parts) == 2:
        extension = parts[1].lower()
        # Generate secure random name
        secure_name = secrets.token_hex(16)
        return f"{secure_name}.{extension}"
    else:
        return secrets.token_hex(16)


def sanitize_input(input_string: str) -> str:
    """Sanitize input string to prevent injection attacks"""
    # Remove potentially dangerous characters
    dangerous_chars = ["<", ">", '"', "'", "&", ";", "`", "|", "$"]
    sanitized = input_string

    for char in dangerous_chars:
        sanitized = sanitized.replace(char, "")

    return sanitized.strip()


def is_safe_redirect_url(url: str, allowed_hosts: list = None) -> bool:
    """Check if URL is safe for redirects"""
    if not url:
        return False

    # Don't allow absolute URLs unless they're to allowed hosts
    if url.startswith(("http://", "https://")):
        if allowed_hosts:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            return parsed.netloc in allowed_hosts
        return False

    # Allow relative URLs that don't start with //
    if url.startswith("//"):
        return False

    return True


def log_security_event(event_type: str, details: Dict[str, Any], user_id: Optional[int] = None):
    """Log security-related events for audit trail"""
    # This would integrate with your logging system
    import logging

    logger = logging.getLogger("secureops.security")
    logger.info(
        f"Security Event: {event_type}",
        extra={
            "event_type": event_type,
            "details": details,
            "user_id": user_id,
            "timestamp": datetime.utcnow().isoformat(),
        },
    )
