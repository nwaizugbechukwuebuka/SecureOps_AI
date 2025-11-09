"""
Enhanced Authentication Router for SecureOps AI
JWT-based authentication with MFA, rate limiting, and comprehensive security
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr

from database import get_db
from models_enhanced import User, UserSession, UserRole
from utils.security_enhanced import (
    TokenManager,
    MFAService,
    PasswordValidator,
    RateLimiter,
    get_current_user,
    get_client_ip,
    get_user_agent,
    hash_password,
    verify_password,
)
from utils.audit_logger import security_logger
from config import settings

router = APIRouter(prefix="/auth", tags=["authentication"])

# Pydantic schemas


class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    user: Dict[str, Any]
    requires_mfa: bool = False


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class MFASetupResponse(BaseModel):
    secret: str
    qr_code: str
    backup_codes: list[str]


class MFAVerifyRequest(BaseModel):
    code: str


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirmRequest(BaseModel):
    token: str
    new_password: str


@router.post("/login", response_model=LoginResponse)
async def login(request: Request, response: Response, login_data: LoginRequest, db: Session = Depends(get_db)):
    """
    Enhanced login with MFA support and security monitoring
    """
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)

    # Rate limiting
    if not RateLimiter.check_rate_limit(db, client_ip, "login"):
        security_logger.log_security_alert(
            db=db,
            alert_type="RATE_LIMIT_EXCEEDED",
            description=f"Rate limit exceeded for login attempts from IP: {client_ip}",
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many login attempts. Please try again later."
        )

    # Find user
    user = db.query(User).filter((User.username == login_data.username) | (User.email == login_data.username)).first()

    if not user:
        security_logger.log_login_attempt(
            db=db,
            username=login_data.username,
            success=False,
            ip_address=client_ip,
            user_agent=user_agent,
            failure_reason="User not found",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    # Check if account is locked
    if user.is_locked():
        security_logger.log_login_attempt(
            db=db,
            username=login_data.username,
            success=False,
            ip_address=client_ip,
            user_agent=user_agent,
            user_id=user.id,
            failure_reason="Account locked",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is temporarily locked due to multiple failed login attempts",
        )

    # Verify password
    if not verify_password(login_data.password, user.hashed_password):
        user.failed_login_attempts += 1

        # Lock account after max attempts
        if user.failed_login_attempts >= 5:  # SecurityConfig.MAX_LOGIN_ATTEMPTS
            user.lock_account()
            security_logger.log_security_alert(
                db=db,
                alert_type="ACCOUNT_LOCKED",
                description=f"Account locked for user {user.username} after {user.failed_login_attempts} failed attempts",
                user_id=user.id,
                ip_address=client_ip,
            )

        db.commit()

        security_logger.log_login_attempt(
            db=db,
            username=login_data.username,
            success=False,
            ip_address=client_ip,
            user_agent=user_agent,
            user_id=user.id,
            failure_reason="Invalid password",
        )

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    # Check if user is active
    if not user.is_active:
        security_logger.log_login_attempt(
            db=db,
            username=login_data.username,
            success=False,
            ip_address=client_ip,
            user_agent=user_agent,
            user_id=user.id,
            failure_reason="Account inactive",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is inactive")

    # Check MFA if enabled
    if user.mfa_enabled:
        if not login_data.mfa_code:
            # Return partial success, client needs to provide MFA code
            return LoginResponse(access_token="", refresh_token="", user={}, requires_mfa=True)

        # Verify MFA code
        mfa_valid = False
        if user.mfa_secret:
            mfa_valid = MFAService.verify_totp(user.mfa_secret, login_data.mfa_code)

        # Try backup codes if TOTP fails
        if not mfa_valid and user.backup_codes:
            mfa_valid = user.verify_backup_code(login_data.mfa_code)
            if mfa_valid:
                db.commit()  # Save updated backup codes

        if not mfa_valid:
            security_logger.log_login_attempt(
                db=db,
                username=login_data.username,
                success=False,
                ip_address=client_ip,
                user_agent=user_agent,
                user_id=user.id,
                failure_reason="Invalid MFA code",
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")

    # Successful login - reset failed attempts
    user.failed_login_attempts = 0
    user.last_login = datetime.utcnow()
    user.unlock_account()

    # Create session
    jti = secrets.token_urlsafe(32)
    session = UserSession(
        user_id=user.id,
        token_jti=jti,
        ip_address=client_ip,
        user_agent=user_agent,
        expires_at=datetime.utcnow() + timedelta(days=7),  # Refresh token expiry
    )
    db.add(session)
    db.commit()

    # Create tokens
    access_token = TokenManager.create_access_token(user.id, user.role, jti)
    refresh_token = TokenManager.create_refresh_token(user.id, jti)

    # Set secure cookies
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=not settings.debug,  # Use secure cookies in production
        samesite="lax",
        max_age=1800,  # 30 minutes
    )

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=not settings.debug,
        samesite="lax",
        max_age=604800,  # 7 days
    )

    # Log successful login
    security_logger.log_login_attempt(
        db=db, username=login_data.username, success=True, ip_address=client_ip, user_agent=user_agent, user_id=user.id
    )

    return LoginResponse(
        access_token=access_token, refresh_token=refresh_token, user=user.to_dict(), requires_mfa=False
    )


@router.post("/logout")
async def logout(
    request: Request, response: Response, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Logout user and revoke session"""
    client_ip = get_client_ip(request)

    # Get authorization header to extract JTI
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        payload = TokenManager.verify_token(token)
        if payload:
            jti = payload.get("jti")
            # Revoke session
            session = (
                db.query(UserSession)
                .filter(UserSession.token_jti == jti, UserSession.user_id == current_user.id)
                .first()
            )
            if session:
                session.revoke()
                db.commit()

    # Clear cookies
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")

    # Log logout
    security_logger.log_logout(db, current_user, client_ip)

    return {"message": "Successfully logged out"}


@router.post("/refresh", response_model=LoginResponse)
async def refresh_token(
    request: Request, response: Response, refresh_data: RefreshTokenRequest, db: Session = Depends(get_db)
):
    """Refresh access token"""
    payload = TokenManager.verify_token(refresh_data.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    user_id = int(payload.get("sub"))
    jti = payload.get("jti")

    # Verify session
    session = db.query(UserSession).filter(UserSession.token_jti == jti, UserSession.user_id == user_id).first()

    if not session or not session.is_valid():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")

    # Get user
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    # Create new access token
    new_access_token = TokenManager.create_access_token(user.id, user.role, jti)

    # Update session last used
    session.last_used = datetime.utcnow()
    db.commit()

    # Set new access token cookie
    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=not settings.debug,
        samesite="lax",
        max_age=1800,
    )

    return LoginResponse(
        access_token=new_access_token, refresh_token=refresh_data.refresh_token, user=user.to_dict(), requires_mfa=False
    )


@router.get("/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return current_user.to_dict()


@router.post("/change-password")
async def change_password(
    request: Request,
    password_data: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Change user password"""
    client_ip = get_client_ip(request)

    # Verify current password
    if not verify_password(password_data.current_password, current_user.hashed_password):
        security_logger.log_security_event(
            db=db,
            event_type="PASSWORD_CHANGE_FAILED",
            description=f"Failed password change attempt for user {current_user.username}",
            user_id=current_user.id,
            ip_address=client_ip,
            risk_level="MEDIUM",
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    # Validate new password
    is_valid, errors = PasswordValidator.validate_password(password_data.new_password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Password does not meet requirements", "errors": errors},
        )

    # Update password
    current_user.hashed_password = hash_password(password_data.new_password)
    current_user.last_password_change = datetime.utcnow()
    db.commit()

    # Log password change
    security_logger.log_password_change(db, current_user, client_ip)

    return {"message": "Password changed successfully"}


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Setup MFA for user account"""
    if current_user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is already enabled")

    # Generate MFA secret
    secret = MFAService.generate_secret()
    uri = MFAService.get_totp_uri(secret, current_user.email)
    qr_code = MFAService.generate_qr_code(uri)
    backup_codes = current_user.generate_backup_codes()

    # Store secret (not enabled yet until verified)
    current_user.mfa_secret = secret
    db.commit()

    return MFASetupResponse(secret=secret, qr_code=qr_code, backup_codes=backup_codes)


@router.post("/mfa/verify")
async def verify_mfa_setup(
    request: Request,
    verify_data: MFAVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Verify MFA setup and enable it"""
    client_ip = get_client_ip(request)

    if not current_user.mfa_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA setup not initiated")

    # Verify TOTP code
    if not MFAService.verify_totp(current_user.mfa_secret, verify_data.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid MFA code")

    # Enable MFA
    current_user.mfa_enabled = True
    db.commit()

    # Log MFA enabled
    security_logger.log_mfa_event(db, current_user, True, client_ip)

    return {"message": "MFA enabled successfully"}


@router.post("/mfa/disable")
async def disable_mfa(
    request: Request,
    verify_data: MFAVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Disable MFA for user account"""
    client_ip = get_client_ip(request)

    if not current_user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not enabled")

    # Verify current MFA code or backup code
    mfa_valid = False
    if current_user.mfa_secret:
        mfa_valid = MFAService.verify_totp(current_user.mfa_secret, verify_data.code)

    if not mfa_valid and current_user.backup_codes:
        mfa_valid = current_user.verify_backup_code(verify_data.code)

    if not mfa_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid MFA code")

    # Disable MFA
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    current_user.backup_codes = None
    db.commit()

    # Log MFA disabled
    security_logger.log_mfa_event(db, current_user, False, client_ip)

    return {"message": "MFA disabled successfully"}


@router.post("/request-password-reset")
async def request_password_reset(request: Request, reset_data: PasswordResetRequest, db: Session = Depends(get_db)):
    """Request password reset token"""
    client_ip = get_client_ip(request)

    # Rate limiting for password reset requests
    if not RateLimiter.check_rate_limit(db, client_ip, "password_reset"):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many password reset requests")

    user = db.query(User).filter(User.email == reset_data.email).first()

    # Always return success to prevent email enumeration
    if user and user.is_active:
        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        user.password_reset_token = reset_token
        user.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
        db.commit()

        # Log password reset request
        security_logger.log_security_event(
            db=db,
            event_type="PASSWORD_RESET_REQUESTED",
            description=f"Password reset requested for user {user.username}",
            user_id=user.id,
            ip_address=client_ip,
            risk_level="MEDIUM",
        )

        # TODO: Send email with reset token
        # In production, send email here
        # For demo, we'll just log it
        print(f"Password reset token for {user.email}: {reset_token}")

    return {"message": "If the email exists, a password reset link has been sent"}


@router.post("/reset-password")
async def reset_password(request: Request, reset_data: PasswordResetConfirmRequest, db: Session = Depends(get_db)):
    """Reset password with token"""
    client_ip = get_client_ip(request)

    # Find user with valid reset token
    user = (
        db.query(User)
        .filter(User.password_reset_token == reset_data.token, User.password_reset_expires > datetime.utcnow())
        .first()
    )

    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")

    # Validate new password
    is_valid, errors = PasswordValidator.validate_password(reset_data.new_password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Password does not meet requirements", "errors": errors},
        )

    # Update password
    user.hashed_password = hash_password(reset_data.new_password)
    user.last_password_change = datetime.utcnow()
    user.password_reset_token = None
    user.password_reset_expires = None
    user.failed_login_attempts = 0
    user.unlock_account()

    # Revoke all existing sessions
    db.query(UserSession).filter(UserSession.user_id == user.id).update({"is_revoked": True})

    db.commit()

    # Log password reset
    security_logger.log_security_event(
        db=db,
        event_type="PASSWORD_RESET_COMPLETED",
        description=f"Password reset completed for user {user.username}",
        user_id=user.id,
        ip_address=client_ip,
        risk_level="HIGH",
    )

    return {"message": "Password reset successfully"}


@router.get("/sessions")
async def get_user_sessions(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get user's active sessions"""
    sessions = (
        db.query(UserSession)
        .filter(
            UserSession.user_id == current_user.id, ~UserSession.is_revoked, UserSession.expires_at > datetime.utcnow()
        )
        .order_by(UserSession.last_used.desc())
        .all()
    )

    return [
        {
            "id": session.id,
            "ip_address": session.ip_address,
            "user_agent": session.user_agent,
            "created_at": session.created_at.isoformat(),
            "last_used": session.last_used.isoformat(),
            "expires_at": session.expires_at.isoformat(),
        }
        for session in sessions
    ]


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Revoke a specific user session"""
    session = db.query(UserSession).filter(UserSession.id == session_id, UserSession.user_id == current_user.id).first()

    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    session.revoke()
    db.commit()

    return {"message": "Session revoked successfully"}
