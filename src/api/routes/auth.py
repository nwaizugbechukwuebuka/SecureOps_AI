"""
Authentication API Routes

This module contains FastAPI routes for user authentication, authorization,
token management, and security features like MFA and session management.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

<<<<<<< HEAD

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
import redis.asyncio as aioredis
=======
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models.user import User
from ..utils.config import settings
<<<<<<< HEAD
from ..utils.rbac import require_role, require_superuser
from ..utils.logger import get_logger
=======
from ..utils.logger import get_logger, log_api_request, log_security_event
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
from ..utils.validators import validate_email, validate_password

router = APIRouter()
logger = get_logger(__name__)
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

<<<<<<< HEAD
# Placeholder logging functions 
def log_api_request(method: str, path: str, user_id: int):
    logger.info(f"API Request: {method} {path} by user {user_id}")

def log_security_event(event_type: str, description: str, user_id: int, additional_data=None):
    logger.warning(f"Security Event: {event_type} - {description} by user {user_id}")
=======
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

# Pydantic models
class UserRegistration(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern="^[a-zA-Z0-9_-]+$")
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str = Field(..., min_length=2, max_length=100)
    company: Optional[str] = Field(None, max_length=100)


class UserLogin(BaseModel):
    username: str
    password: str
    remember_me: bool = False


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: int
    username: str
    email: str
    is_admin: bool


class PasswordReset(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class MFASetupResponse(BaseModel):
    qr_code: str
    secret_key: str
    backup_codes: list[str]


class MFAVerification(BaseModel):
    code: str


<<<<<<< HEAD

# Redis-based login rate limiting
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

async def get_redis():
    return aioredis.from_url(settings.redis_url, encoding="utf-8", decode_responses=True)

=======
# Rate limiting storage (in production, use Redis)
login_attempts: dict[str, tuple[int, datetime]] = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

def get_client_ip(request: Request) -> str:
    """Safely get client IP address from request."""
    return request.client.host if request.client else "unknown"


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.security.access_token_expire_minutes
        )

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, settings.security.secret_key, algorithm=settings.security.algorithm
    )

    return encoded_jwt


def create_refresh_token(user_id: int) -> str:
    """Create refresh token for user."""
    data = {
        "user_id": user_id,
        "type": "refresh",
        "exp": datetime.utcnow()
        + timedelta(days=settings.security.refresh_token_expire_days),
    }

    return jwt.encode(
        data, settings.security.secret_key, algorithm=settings.security.algorithm
    )


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash password."""
    return pwd_context.hash(password)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Get current authenticated user from JWT token.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Decode JWT token
        payload = jwt.decode(
            credentials.credentials,
            settings.security.secret_key,
            algorithms=[settings.security.algorithm],
        )

        user_id: int = payload.get("user_id")
        if user_id is None:
            raise credentials_exception

        # Get user from database
        query = select(User).where(User.id == user_id)
        result = await db.execute(query)
        user = result.scalar_one_or_none()

        if user is None:
            raise credentials_exception

        # Check if user is active
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is disabled",
            )

        # Update last seen
        user.last_login = datetime.now(timezone.utc)
        await db.commit()

        return user

    except JWTError:
        raise credentials_exception


<<<<<<< HEAD

async def check_rate_limit(request: Request, username: str) -> bool:
    """Check if user is rate limited for login attempts using Redis."""
    client_ip = get_client_ip(request)
    key = f"login_attempts:{client_ip}:{username}"
    redis_conn = await get_redis()
    attempts = await redis_conn.get(key)
    if attempts is not None and int(attempts) >= MAX_LOGIN_ATTEMPTS:
        return False
    return True



async def record_login_attempt(request: Request, username: str, success: bool):
    """Record login attempt for rate limiting using Redis."""
    client_ip = get_client_ip(request)
    key = f"login_attempts:{client_ip}:{username}"
    redis_conn = await get_redis()
    if success:
        await redis_conn.delete(key)
    else:
        attempts = await redis_conn.incr(key)
        if attempts == 1:
            await redis_conn.expire(key, int(LOCKOUT_DURATION.total_seconds()))
=======
def check_rate_limit(request: Request, username: str) -> bool:
    """Check if user is rate limited for login attempts."""
    client_ip = get_client_ip(request)
    key = f"{client_ip}:{username}"

    now = datetime.now(timezone.utc)

    if key in login_attempts:
        attempts, last_attempt = login_attempts[key]

        # Reset attempts if lockout period has passed
        if now - last_attempt > LOCKOUT_DURATION:
            del login_attempts[key]
            return True

        # Check if max attempts reached
        if attempts >= MAX_LOGIN_ATTEMPTS:
            return False

    return True


def record_login_attempt(request: Request, username: str, success: bool):
    """Record login attempt for rate limiting."""
    client_ip = get_client_ip(request)
    key = f"{client_ip}:{username}"
    now = datetime.now(timezone.utc)

    if success:
        # Clear attempts on successful login
        if key in login_attempts:
            del login_attempts[key]
    else:
        # Increment failed attempts
        if key in login_attempts:
            attempts, _ = login_attempts[key]
            login_attempts[key] = (attempts + 1, now)
        else:
            login_attempts[key] = (1, now)
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3


@router.post("/register", response_model=TokenResponse)
async def register_user(
    user_data: UserRegistration,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Register new user account.

    Creates new user with validation, password hashing,
    and automatic login upon successful registration.
    """
    log_api_request("POST", "/auth/register", None)

    try:
        # Validate email format
        email_validation = validate_email(user_data.email)
        if not email_validation.is_valid:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid email: {', '.join(email_validation.errors)}",
            )

        # Validate password strength
        password_validation = validate_password(user_data.password)
        if not password_validation.is_valid:
            raise HTTPException(
                status_code=400,
                detail=f"Weak password: {', '.join(password_validation.errors)}",
            )

        # Check if username already exists
        username_query = select(User).where(User.username == user_data.username)
        username_result = await db.execute(username_query)
        if username_result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Username already registered")

        # Check if email already exists
        email_query = select(User).where(User.email == user_data.email)
        email_result = await db.execute(email_query)
        if email_result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Email already registered")

        # Create new user
        hashed_password = get_password_hash(user_data.password)

        new_user = User(
            username=user_data.username,
            email=user_data.email,
            hashed_password=hashed_password,
            full_name=user_data.full_name,
            company=user_data.company,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )

        db.add(new_user)
        await db.flush()  # Get the ID
        await db.commit()

        # Create tokens
        access_token = create_access_token(
            data={"user_id": new_user.id, "username": new_user.username}
        )
        refresh_token = create_refresh_token(new_user.id)

        # Log security event
        log_security_event(
            f"New user registered: {user_data.username}",
            severity="info",
            user_id=new_user.id,
            client_ip=get_client_ip(request),
        )

        logger.info(f"User registered successfully: {user_data.username}")

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.security.access_token_expire_minutes * 60,
            user_id=new_user.id,
            username=new_user.username,
            email=new_user.email,
            is_admin=new_user.is_admin,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(status_code=500, detail="Registration failed")


@router.post("/login", response_model=TokenResponse)
async def login_user(
    user_credentials: UserLogin, request: Request, db: AsyncSession = Depends(get_db)
):
    """
    Authenticate user and return access tokens.

    Validates credentials, handles rate limiting,
    and returns JWT tokens for API access.
    """
    log_api_request("POST", "/auth/login", None)

    try:
        # Check rate limiting
<<<<<<< HEAD
        if not await check_rate_limit(request, user_credentials.username):
=======
        if not check_rate_limit(request, user_credentials.username):
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
            log_security_event(
                f"Rate limit exceeded for user: {user_credentials.username}",
                severity="warning",
                client_ip=get_client_ip(request),
            )
            raise HTTPException(
                status_code=429,
                detail="Too many login attempts. Please try again later.",
            )

        # Get user from database
        query = select(User).where(User.username == user_credentials.username)
        result = await db.execute(query)
        user = result.scalar_one_or_none()

        # Verify credentials
        if not user or not verify_password(
            user_credentials.password, user.hashed_password
        ):
<<<<<<< HEAD
            await record_login_attempt(request, user_credentials.username, False)
=======
            record_login_attempt(request, user_credentials.username, False)

>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
            log_security_event(
                f"Failed login attempt for user: {user_credentials.username}",
                severity="warning",
                client_ip=get_client_ip(request),
            )
<<<<<<< HEAD
=======

>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
            raise HTTPException(
                status_code=401, detail="Incorrect username or password"
            )

        # Check if user is active
        if not user.is_active:
<<<<<<< HEAD
            await record_login_attempt(request, user_credentials.username, False)
=======
            record_login_attempt(request, user_credentials.username, False)

>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
            log_security_event(
                f"Login attempt for disabled user: {user_credentials.username}",
                severity="warning",
                user_id=user.id,
                client_ip=get_client_ip(request),
            )
<<<<<<< HEAD
            raise HTTPException(status_code=401, detail="User account is disabled")

        # Successful authentication
        await record_login_attempt(request, user_credentials.username, True)
=======

            raise HTTPException(status_code=401, detail="User account is disabled")

        # Successful authentication
        record_login_attempt(request, user_credentials.username, True)
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

        # Update user last login
        user.last_login = datetime.now(timezone.utc)
        await db.commit()

        # Create tokens
        token_expires = timedelta(minutes=settings.security.access_token_expire_minutes)
        if user_credentials.remember_me:
            token_expires = timedelta(days=30)  # Extended session

        access_token = create_access_token(
            data={"user_id": user.id, "username": user.username},
            expires_delta=token_expires,
        )
        refresh_token = create_refresh_token(user.id)

        log_security_event(
            f"User logged in successfully: {user.username}",
            severity="info",
            user_id=user.id,
            client_ip=get_client_ip(request),
        )

        logger.info(f"User logged in: {user.username}")

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=int(token_expires.total_seconds()),
            user_id=user.id,
            username=user.username,
            email=user.email,
            is_admin=user.is_admin,
        )
<<<<<<< HEAD
=======

>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail="Login failed")


@router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(
    refresh_request: RefreshTokenRequest, db: AsyncSession = Depends(get_db)
):
    """
    Refresh access token using refresh token.

    Validates refresh token and issues new access token
    for continued API access without re-authentication.
    """
    log_api_request("POST", "/auth/refresh", None)

    try:
        # Decode refresh token
        payload = jwt.decode(
            refresh_request.refresh_token,
            settings.security.secret_key,
            algorithms=[settings.security.algorithm],
        )

        user_id: int = payload.get("user_id")
        token_type: str = payload.get("type")

        if user_id is None or token_type != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        # Get user from database
        user = await db.get(User, user_id)
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")

        # Create new access token
        access_token = create_access_token(
            data={"user_id": user.id, "username": user.username}
        )

        logger.info(f"Access token refreshed for user: {user.username}")

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_request.refresh_token,  # Keep same refresh token
            expires_in=settings.security.access_token_expire_minutes * 60,
            user_id=user.id,
            username=user.username,
            email=user.email,
            is_admin=user.is_admin,
        )

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        raise HTTPException(status_code=500, detail="Token refresh failed")


@router.post("/logout")
async def logout_user(request: Request, current_user: User = Depends(get_current_user)):
    """
    Logout current user.

    Invalidates tokens and logs security event.
    In production, would add token to blacklist.
    """
    log_api_request("POST", "/auth/logout", current_user.id)

    try:
        # In production, add token to blacklist/revocation list
        # For now, just log the logout event

        log_security_event(
            f"User logged out: {current_user.username}",
            severity="info",
            user_id=current_user.id,
            client_ip=get_client_ip(request),
        )

        logger.info(f"User logged out: {current_user.username}")

        return {"message": "Successfully logged out"}

    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        raise HTTPException(status_code=500, detail="Logout failed")


@router.get("/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """
    Get current user information.

    Returns user profile data for the authenticated user.
    """
    log_api_request("GET", "/auth/me", current_user.id)

    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "company": current_user.company,
        "is_admin": current_user.is_admin,
        "is_active": current_user.is_active,
        "created_at": current_user.created_at,
        "last_login": current_user.last_login,
    }


@router.post("/password-reset")
async def request_password_reset(
    reset_request: PasswordReset,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Request password reset email.

    Generates secure reset token and sends email
    with reset instructions to user.
    """
    log_api_request("POST", "/auth/password-reset", None)

    try:
        # Find user by email
        query = select(User).where(User.email == reset_request.email)
        result = await db.execute(query)
        user = result.scalar_one_or_none()

        if not user:
            # Don't reveal if email exists or not
            return {"message": "If the email exists, a reset link has been sent"}

        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        reset_expires = datetime.now(timezone.utc) + timedelta(hours=1)

        # Store reset token (in production, use proper storage)
        user.reset_token = reset_token
        user.reset_token_expires = reset_expires
        await db.commit()

        # Queue email sending
        background_tasks.add_task(
            send_password_reset_email, user.email, user.full_name, reset_token
        )

        log_security_event(
            f"Password reset requested for user: {user.username}",
            severity="info",
            user_id=user.id,
        )

        return {"message": "If the email exists, a reset link has been sent"}

    except Exception as e:
        logger.error(f"Password reset request error: {str(e)}")
        raise HTTPException(status_code=500, detail="Password reset request failed")


@router.post("/password-reset/confirm")
async def confirm_password_reset(
    reset_data: PasswordResetConfirm, db: AsyncSession = Depends(get_db)
):
    """
    Confirm password reset with new password.

    Validates reset token and updates user password
    with the new secure password.
    """
    log_api_request("POST", "/auth/password-reset/confirm", None)

    try:
        # Find user by reset token
        query = select(User).where(
            User.reset_token == reset_data.token,
            User.reset_token_expires > datetime.now(timezone.utc),
        )
        result = await db.execute(query)
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(
                status_code=400, detail="Invalid or expired reset token"
            )

        # Validate new password
        password_validation = validate_password(reset_data.new_password)
        if not password_validation.is_valid:
            raise HTTPException(
                status_code=400,
                detail=f"Weak password: {', '.join(password_validation.errors)}",
            )

        # Update password and clear reset token
        user.hashed_password = get_password_hash(reset_data.new_password)
        user.reset_token = None
        user.reset_token_expires = None
        await db.commit()

        log_security_event(
            f"Password reset completed for user: {user.username}",
            severity="info",
            user_id=user.id,
        )

        logger.info(f"Password reset completed for user: {user.username}")

        return {"message": "Password reset successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password reset confirm error: {str(e)}")
        raise HTTPException(status_code=500, detail="Password reset failed")


@router.post("/password/change")
async def change_password(
    password_change: PasswordChange,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Change user password.

    Allows authenticated user to change their password
    after verifying current password.
    """
    log_api_request("POST", "/auth/password/change", current_user.id)

    try:
        # Verify current password
        if not verify_password(
            password_change.current_password, current_user.hashed_password
        ):
            raise HTTPException(status_code=400, detail="Current password is incorrect")

        # Validate new password
        password_validation = validate_password(password_change.new_password)
        if not password_validation.is_valid:
            raise HTTPException(
                status_code=400,
                detail=f"Weak password: {', '.join(password_validation.errors)}",
            )

        # Check if new password is different
        if verify_password(password_change.new_password, current_user.hashed_password):
            raise HTTPException(
                status_code=400,
                detail="New password must be different from current password",
            )

        # Update password
        current_user.hashed_password = get_password_hash(password_change.new_password)
        await db.commit()

        log_security_event(
            f"Password changed for user: {current_user.username}",
            severity="info",
            user_id=current_user.id,
        )

        logger.info(f"Password changed for user: {current_user.username}")

        return {"message": "Password changed successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change error: {str(e)}")
        raise HTTPException(status_code=500, detail="Password change failed")


# Helper functions


async def send_password_reset_email(email: str, name: str, token: str):
    """Send password reset email (placeholder)."""
    # In production, implement actual email sending
    logger.info(f"Password reset email would be sent to {email} with token {token}")


async def send_welcome_email(email: str, name: str):
    """Send welcome email to new user (placeholder)."""
    # In production, implement actual email sending
    logger.info(f"Welcome email would be sent to {email}")


# Export the get_current_user function for use in other modules
__all__ = ["get_current_user"]
