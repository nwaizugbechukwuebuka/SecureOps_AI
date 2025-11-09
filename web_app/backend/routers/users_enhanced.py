"""
Enhanced Users Router for SecureOps AI
User management with Role-Based Access Control (RBAC)
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session, joinedload
from pydantic import BaseModel, EmailStr

from database import get_db
from models_enhanced import User, UserRole
from utils.security_enhanced import (
    get_current_user,
    require_admin,
    require_analyst,
    PasswordValidator,
    hash_password,
    get_client_ip,
)
from utils.audit_logger import security_logger

router = APIRouter(prefix="/users", tags=["user_management"])

# Pydantic schemas


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    full_name: str
    password: str
    role: str = UserRole.VIEWER.value


class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class UserResponse(BaseModel):
    id: int
    uuid: str
    username: str
    email: str
    full_name: str
    role: str
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    created_at: str
    last_login: Optional[str] = None
    last_password_change: str


class UsersListResponse(BaseModel):
    users: List[UserResponse]
    total: int
    page: int
    per_page: int


@router.get("/", response_model=UsersListResponse)
async def get_users(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    role: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    """
    Get list of users with filtering and pagination
    Requires analyst role or higher
    """
    client_ip = get_client_ip(request)

    # Build query
    query = db.query(User)

    # Apply filters
    if role:
        query = query.filter(User.role == role)

    if search:
        query = query.filter(
            (User.username.ilike(f"%{search}%"))
            | (User.email.ilike(f"%{search}%"))
            | (User.full_name.ilike(f"%{search}%"))
        )

    if is_active is not None:
        query = query.filter(User.is_active == is_active)

    # Get total count
    total = query.count()

    # Apply pagination
    offset = (page - 1) * per_page
    users = query.order_by(User.created_at.desc()).offset(offset).limit(per_page).all()

    # Log data access
    security_logger.log_data_access(
        db=db,
        user=current_user,
        resource="users_list",
        ip_address=client_ip,
        details=f"Page {page}, filters: role={role}, search={search}, active={is_active}",
    )

    return UsersListResponse(
        users=[UserResponse(**user.to_dict()) for user in users], total=total, page=page, per_page=per_page
    )


@router.get("/roles")
async def get_available_roles(current_user: User = Depends(require_analyst)):
    """Get available user roles"""
    return {
        "roles": [
            {
                "value": UserRole.VIEWER.value,
                "label": "Viewer",
                "description": "Read-only access to dashboards and alerts",
            },
            {
                "value": UserRole.ANALYST.value,
                "label": "Analyst",
                "description": "Can view and analyze security data, manage alerts",
            },
            {
                "value": UserRole.ADMIN.value,
                "label": "Administrator",
                "description": "Full system access including user management",
            },
        ]
    }


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int, request: Request, current_user: User = Depends(require_analyst), db: Session = Depends(get_db)
):
    """
    Get user by ID
    Users can view their own profile, analysts+ can view any user
    """
    client_ip = get_client_ip(request)

    # Check if user is accessing their own profile or has analyst+ permissions
    if user_id != current_user.id and not current_user.has_permission(UserRole.ANALYST):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions to view this user")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Log data access
    security_logger.log_data_access(db=db, user=current_user, resource=f"user:{user_id}", ip_address=client_ip)

    return UserResponse(**user.to_dict())


@router.post("/", response_model=UserResponse)
async def create_user(
    request: Request, user_data: UserCreate, current_user: User = Depends(require_admin), db: Session = Depends(get_db)
):
    """
    Create new user
    Requires admin role
    """
    client_ip = get_client_ip(request)

    # Validate role
    valid_roles = [role.value for role in UserRole]
    if user_data.role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid role. Must be one of: {valid_roles}"
        )

    # Check if username or email already exists
    existing_user = (
        db.query(User).filter((User.username == user_data.username) | (User.email == user_data.email)).first()
    )

    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username or email already exists")

    # Validate password
    is_valid, errors = PasswordValidator.validate_password(user_data.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Password does not meet requirements", "errors": errors},
        )

    # Create user
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=hash_password(user_data.password),
        role=user_data.role,
        is_verified=True,  # Admin-created users are auto-verified
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Log user creation
    security_logger.log_user_creation(db, new_user, current_user.id, client_ip)

    return UserResponse(**new_user.to_dict())


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    request: Request,
    user_data: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Update user
    Users can update their own basic info, admins can update any user
    """
    client_ip = get_client_ip(request)

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Permission checks
    is_self_update = user_id == current_user.id
    is_admin = current_user.has_permission(UserRole.ADMIN)

    if not is_self_update and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions to update this user"
        )

    # Role changes require admin permissions
    if user_data.role is not None and not is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only administrators can change user roles")

    # is_active changes require admin permissions
    if user_data.is_active is not None and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Only administrators can activate/deactivate users"
        )

    # Store old values for audit log
    old_values = user.to_dict()

    # Update fields
    if user_data.username is not None:
        # Check if username already exists
        existing = db.query(User).filter(User.username == user_data.username, User.id != user_id).first()
        if existing:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")
        user.username = user_data.username

    if user_data.email is not None:
        # Check if email already exists
        existing = db.query(User).filter(User.email == user_data.email, User.id != user_id).first()
        if existing:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists")
        user.email = user_data.email

    if user_data.full_name is not None:
        user.full_name = user_data.full_name

    if user_data.role is not None:
        # Validate role
        valid_roles = [role.value for role in UserRole]
        if user_data.role not in valid_roles:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid role. Must be one of: {valid_roles}"
            )

        # Log role change separately
        if user.role != user_data.role:
            security_logger.log_role_change(
                db=db,
                target_user=user,
                old_role=user.role,
                new_role=user_data.role,
                changed_by_user_id=current_user.id,
                ip_address=client_ip,
            )

        user.role = user_data.role

    if user_data.is_active is not None:
        user.is_active = user_data.is_active

    db.commit()
    db.refresh(user)

    # Log user update
    new_values = user.to_dict()
    security_logger.log_user_update(
        db=db,
        updated_user=user,
        old_values=old_values,
        new_values=new_values,
        updated_by_user_id=current_user.id,
        ip_address=client_ip,
    )

    return UserResponse(**new_values)


@router.delete("/{user_id}")
async def delete_user(
    user_id: int, request: Request, current_user: User = Depends(require_admin), db: Session = Depends(get_db)
):
    """
    Delete user (soft delete by deactivating)
    Requires admin role
    """
    client_ip = get_client_ip(request)

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Prevent deleting self
    if user_id == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete your own account")

    # Soft delete (deactivate)
    user.is_active = False
    db.commit()

    # Log user deletion
    security_logger.log_user_deletion(db, user, current_user.id, client_ip)

    return {"message": "User deactivated successfully"}


@router.get("/{user_id}/audit-logs")
async def get_user_audit_logs(
    user_id: int,
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    """
    Get audit logs for a specific user
    Requires analyst role or higher
    """
    client_ip = get_client_ip(request)

    # Check if user exists
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Get audit logs for user
    from models_enhanced import AuditLog

    query = db.query(AuditLog).filter(AuditLog.user_id == user_id)

    total = query.count()
    offset = (page - 1) * per_page
    logs = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(per_page).all()

    # Log data access
    security_logger.log_data_access(
        db=db, user=current_user, resource=f"audit_logs:user:{user_id}", ip_address=client_ip
    )

    return {
        "logs": [log.to_dict() for log in logs],
        "total": total,
        "page": page,
        "per_page": per_page,
        "user": user.to_dict(),
    }


@router.post("/{user_id}/unlock")
async def unlock_user_account(
    user_id: int, request: Request, current_user: User = Depends(require_admin), db: Session = Depends(get_db)
):
    """
    Unlock a user account that has been locked due to failed login attempts
    Requires admin role
    """
    client_ip = get_client_ip(request)

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Unlock account
    user.unlock_account()
    db.commit()

    # Log account unlock
    security_logger.log_security_event(
        db=db,
        event_type="ACCOUNT_UNLOCKED",
        description=f"Account unlocked for user {user.username} by admin {current_user.username}",
        user_id=current_user.id,
        ip_address=client_ip,
        resource=f"user:{user_id}",
        risk_level="MEDIUM",
    )

    return {"message": f"Account unlocked for user {user.username}"}


@router.post("/{user_id}/reset-mfa")
async def reset_user_mfa(
    user_id: int, request: Request, current_user: User = Depends(require_admin), db: Session = Depends(get_db)
):
    """
    Reset MFA for a user (emergency admin action)
    Requires admin role
    """
    client_ip = get_client_ip(request)

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Reset MFA
    old_mfa_status = user.mfa_enabled
    user.mfa_enabled = False
    user.mfa_secret = None
    user.backup_codes = None
    db.commit()

    # Log MFA reset
    security_logger.log_security_event(
        db=db,
        event_type="MFA_RESET_BY_ADMIN",
        description=f"MFA reset for user {user.username} by admin {current_user.username}",
        user_id=current_user.id,
        ip_address=client_ip,
        resource=f"user:{user_id}",
        old_values={"mfa_enabled": old_mfa_status},
        new_values={"mfa_enabled": False},
        risk_level="HIGH",
    )

    return {"message": f"MFA reset for user {user.username}"}


@router.get("/statistics/dashboard")
async def get_user_statistics(current_user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    """
    Get user statistics for dashboard
    Requires analyst role or higher
    """
    from sqlalchemy import func
    from datetime import datetime, timedelta

    # Total users
    total_users = db.query(User).count()

    # Active users
    active_users = db.query(User).filter(User.is_active).count()

    # Users by role
    role_distribution = db.query(User.role, func.count(User.id).label("count")).group_by(User.role).all()

    # MFA adoption
    mfa_enabled_count = db.query(User).filter(User.mfa_enabled, User.is_active).count()

    # Recent user activity (last 24 hours)
    from models_enhanced import AuditLog, AuditEventType

    last_24h = datetime.utcnow() - timedelta(hours=24)

    recent_logins = (
        db.query(func.count(func.distinct(AuditLog.user_id)))
        .filter(AuditLog.event_type == AuditEventType.LOGIN_SUCCESS.value, AuditLog.created_at >= last_24h)
        .scalar()
        or 0
    )

    # Locked accounts
    locked_accounts = db.query(User).filter(User.locked_until > datetime.utcnow()).count()

    return {
        "total_users": total_users,
        "active_users": active_users,
        "inactive_users": total_users - active_users,
        "role_distribution": dict(role_distribution),
        "mfa_adoption": {
            "enabled": mfa_enabled_count,
            "total_active": active_users,
            "percentage": round((mfa_enabled_count / active_users * 100) if active_users > 0 else 0, 1),
        },
        "recent_activity": {"unique_logins_24h": recent_logins, "locked_accounts": locked_accounts},
    }
