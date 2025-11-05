"""
RBAC utilities for SecureOps API.
"""
from fastapi import Depends, HTTPException, status
from typing import List, Optional
from ..models.user import User

def require_role(*roles: str):
    def role_checker(current_user: User = Depends()):
        if not current_user.is_active:
            raise HTTPException(status_code=403, detail="Inactive user.")
        if current_user.is_superuser:
            return current_user
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {roles}, found: {current_user.role}",
            )
        return current_user
    return role_checker

def require_superuser(current_user: User = Depends()):
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser privileges required.")
    return current_user
