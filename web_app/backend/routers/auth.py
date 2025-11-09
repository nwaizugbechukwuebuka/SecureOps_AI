"""
Authentication routes for SecureOps AI
Login, logout, user profile, and token management
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from database import get_db, User
from schemas import UserLogin, LoginResponse, UserResponse, UserUpdate
from config import settings
from utils.security import (
    security_manager,
    create_token_for_user,
    credentials_exception,
    inactive_user_exception,
    log_security_event,
    extract_user_from_token,
    validate_password_strength,
)
from datetime import datetime

router = APIRouter(prefix="/auth", tags=["authentication"])

# Security scheme for JWT tokens
security = HTTPBearer(auto_error=False)

# Dependency to get current user from token


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)
) -> dict:
    """Get current authenticated user from token"""

    if not credentials:
        raise credentials_exception

    # Extract user info from token
    user_info = extract_user_from_token(credentials.credentials)

    if not user_info:
        raise credentials_exception

    # Verify user still exists and is active
    user = db.query(User).filter(User.id == user_info["user_id"]).first()

    if not user:
        raise credentials_exception

    if not user.is_active:
        raise inactive_user_exception

    return user_info


# Optional: Admin-only dependency


async def get_current_admin_user(current_user: dict = Depends(get_current_user)) -> dict:
    """Get current user and verify admin privileges"""

    if not current_user.get("is_admin"):
        from utils.security import insufficient_permissions_exception

        raise insufficient_permissions_exception

    return current_user


@router.post("/login", response_model=LoginResponse)
async def login(credentials: UserLogin, db: Session = Depends(get_db)):
    """Authenticate user and return access token"""

    # Find user by username
    user = db.query(User).filter(User.username == credentials.username).first()

    if not user:
        # Log failed login attempt
        log_security_event("failed_login_attempt", {"username": credentials.username, "reason": "user_not_found"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    # Verify password
    if not user.verify_password(credentials.password):
        # Log failed login attempt
        log_security_event(
            "failed_login_attempt", {"username": credentials.username, "reason": "invalid_password"}, user_id=user.id
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    # Check if user is active
    if not user.is_active:
        log_security_event(
            "failed_login_attempt", {"username": credentials.username, "reason": "account_inactive"}, user_id=user.id
        )
        raise inactive_user_exception

    # Update last login timestamp
    user.last_login = datetime.utcnow()
    db.add(user)
    db.commit()

    # Create access token
    user_dict = user.to_dict()
    access_token = create_token_for_user(user_dict)

    # Log successful login
    log_security_event("successful_login", {"username": user.username}, user_id=user.id)

    return LoginResponse(access_token=access_token, token_type="bearer", user=UserResponse(**user_dict))


@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """Logout user (client-side token invalidation)"""

    # Log logout event
    log_security_event("user_logout", {"username": current_user.get("username")}, user_id=current_user.get("user_id"))

    return {"message": f"User {current_user.get('username')} successfully logged out"}


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get current authenticated user information"""

    # Fetch fresh user data from database
    user = db.query(User).filter(User.id == current_user["user_id"]).first()

    if not user:
        raise credentials_exception

    if not user.is_active:
        raise inactive_user_exception

    return UserResponse(**user.to_dict())


@router.put("/me", response_model=UserResponse)
async def update_current_user(
    user_update: UserUpdate, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Update current user profile"""

    # Fetch user from database
    user = db.query(User).filter(User.id == current_user["user_id"]).first()

    if not user:
        raise credentials_exception

    if not user.is_active:
        raise inactive_user_exception

    # Update user fields
    update_data = user_update.dict(exclude_unset=True)

    for field, value in update_data.items():
        if hasattr(user, field):
            setattr(user, field, value)

    db.add(user)
    db.commit()
    db.refresh(user)

    # Log profile update
    log_security_event("profile_updated", {"updated_fields": list(update_data.keys())}, user_id=user.id)

    return UserResponse(**user.to_dict())


@router.post("/change-password")
async def change_password(
    current_password: str,
    new_password: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Change user password"""

    # Fetch user from database
    user = db.query(User).filter(User.id == current_user["user_id"]).first()

    if not user:
        raise credentials_exception

    if not user.is_active:
        raise inactive_user_exception

    # Verify current password
    if not user.verify_password(current_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    # Validate new password strength
    if not validate_password_strength(new_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password must be at least {settings.password_min_length} characters long",
        )

    # Update password
    user.hashed_password = user.hash_password(new_password)
    db.add(user)
    db.commit()

    # Log password change
    log_security_event("password_changed", {"username": user.username}, user_id=user.id)

    return {"message": "Password changed successfully"}
