"""
User management routes for SecureOps AI
Admin operations for managing users, roles, and permissions
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from typing import List
from database import get_db, User
from schemas import UserCreate, UserUpdate, UserResponse, PaginatedResponse, UserSearchFilters
from routers.auth import get_current_user, get_current_admin_user
from utils.security import log_security_event
from datetime import datetime

router = APIRouter(prefix="/users", tags=["user-management"])


@router.get("/", response_model=PaginatedResponse[UserResponse])
async def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    search: str = Query(None, description="Search in username, email, or full name"),
    role: str = Query(None, description="Filter by role"),
    is_active: bool = Query(None, description="Filter by active status"),
    current_user: dict = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    """List all users with pagination and filtering (Admin only)"""

    query = db.query(User)

    # Apply search filter
    if search:
        search_filter = or_(
            User.username.ilike(f"%{search}%"), User.email.ilike(f"%{search}%"), User.full_name.ilike(f"%{search}%")
        )
        query = query.filter(search_filter)

    # Apply role filter
    if role:
        query = query.filter(User.role == role)

    # Apply active status filter
    if is_active is not None:
        query = query.filter(User.is_active == is_active)

    # Get total count before pagination
    total = query.count()

    # Apply pagination
    users = query.offset(skip).limit(limit).all()

    # Convert to response models
    user_responses = [UserResponse(**user.to_dict()) for user in users]

    return PaginatedResponse(
        items=user_responses,
        total=total,
        page=skip // limit + 1,
        per_page=limit,
        total_pages=(total + limit - 1) // limit,
    )


@router.post("/", response_model=UserResponse)
async def create_user(
    user_data: UserCreate, current_user: dict = Depends(get_current_admin_user), db: Session = Depends(get_db)
):
    """Create a new user (Admin only)"""

    # Check if username or email already exists
    existing_user = (
        db.query(User).filter(or_(User.username == user_data.username, User.email == user_data.email)).first()
    )

    if existing_user:
        if existing_user.username == user_data.username:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    # Validate password strength
    from utils.security import validate_password_strength

    if not validate_password_strength(user_data.password):
        from config import settings

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password must be at least {settings.password_min_length} characters long",
        )

    # Create new user
    user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        role=user_data.role or "user",
        is_admin=user_data.is_admin or False,
        is_active=True,
    )

    # Hash password
    user.hashed_password = user.hash_password(user_data.password)

    db.add(user)
    db.commit()
    db.refresh(user)

    # Log user creation
    log_security_event(
        "user_created",
        {"created_username": user.username, "created_by": current_user.get("username"), "role": user.role},
        user_id=current_user.get("user_id"),
    )

    return UserResponse(**user.to_dict())


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(user_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get user by ID (Admin or own profile)"""

    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Check permissions: admin can view any user, users can only view their own profile
    if not current_user.get("is_admin") and current_user.get("user_id") != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")

    return UserResponse(**user.to_dict())


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int, user_update: UserUpdate, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Update user (Admin or own profile with restrictions)"""

    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Check permissions
    is_admin = current_user.get("is_admin")
    is_own_profile = current_user.get("user_id") == user_id

    if not is_admin and not is_own_profile:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")

    # Prepare update data
    update_data = user_update.dict(exclude_unset=True)

    # Non-admin users cannot change role, admin status, or active status
    if not is_admin:
        restricted_fields = ["role", "is_admin", "is_active"]
        for field in restricted_fields:
            if field in update_data:
                del update_data[field]

    # Check for username/email uniqueness if being changed
    if "username" in update_data and update_data["username"] != user.username:
        existing_user = (
            db.query(User).filter(and_(User.username == update_data["username"], User.id != user_id)).first()
        )
        if existing_user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")

    if "email" in update_data and update_data["email"] != user.email:
        existing_user = db.query(User).filter(and_(User.email == update_data["email"], User.id != user_id)).first()
        if existing_user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already taken")

    # Apply updates
    for field, value in update_data.items():
        if hasattr(user, field):
            setattr(user, field, value)

    db.add(user)
    db.commit()
    db.refresh(user)

    # Log user update
    log_security_event(
        "user_updated",
        {
            "updated_user": user.username,
            "updated_by": current_user.get("username"),
            "updated_fields": list(update_data.keys()),
        },
        user_id=current_user.get("user_id"),
    )

    return UserResponse(**user.to_dict())


@router.delete("/{user_id}")
async def delete_user(
    user_id: int, current_user: dict = Depends(get_current_admin_user), db: Session = Depends(get_db)
):
    """Delete user (Admin only)"""

    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Prevent admin from deleting themselves
    if current_user.get("user_id") == user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete your own account")

    username = user.username

    db.delete(user)
    db.commit()

    # Log user deletion
    log_security_event(
        "user_deleted",
        {"deleted_username": username, "deleted_by": current_user.get("username")},
        user_id=current_user.get("user_id"),
    )

    return {"message": f"User {username} has been deleted successfully"}


@router.post("/{user_id}/activate")
async def activate_user(
    user_id: int, current_user: dict = Depends(get_current_admin_user), db: Session = Depends(get_db)
):
    """Activate user account (Admin only)"""

    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user.is_active:
        return {"message": f"User {user.username} is already active"}

    user.is_active = True
    db.add(user)
    db.commit()

    # Log account activation
    log_security_event(
        "user_activated",
        {"activated_username": user.username, "activated_by": current_user.get("username")},
        user_id=current_user.get("user_id"),
    )

    return {"message": f"User {user.username} has been activated"}


@router.post("/{user_id}/deactivate")
async def deactivate_user(
    user_id: int, current_user: dict = Depends(get_current_admin_user), db: Session = Depends(get_db)
):
    """Deactivate user account (Admin only)"""

    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Prevent admin from deactivating themselves
    if current_user.get("user_id") == user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot deactivate your own account")

    if not user.is_active:
        return {"message": f"User {user.username} is already inactive"}

    user.is_active = False
    db.add(user)
    db.commit()

    # Log account deactivation
    log_security_event(
        "user_deactivated",
        {"deactivated_username": user.username, "deactivated_by": current_user.get("username")},
        user_id=current_user.get("user_id"),
    )

    return {"message": f"User {user.username} has been deactivated"}


@router.get("/{user_id}/activity")
async def get_user_activity(
    user_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Get user activity log (Admin or own activity)"""

    # Check permissions
    if not current_user.get("is_admin") and current_user.get("user_id") != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")

    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Get security events for this user
    from database import SecurityEvent

    events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.user_id == user_id)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(100)
        .all()
    )

    activity_log = []
    for event in events:
        activity_log.append(
            {
                "id": event.id,
                "event_type": event.event_type,
                "severity": event.severity,
                "description": event.description,
                "timestamp": event.timestamp,
                "details": event.details,
            }
        )

    return {"user": UserResponse(**user.to_dict()), "activity": activity_log, "last_login": user.last_login}
