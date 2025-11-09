"""
Enhanced Audit Logger for SecureOps AI
Comprehensive logging system for security events and user actions
"""

import logging
import json
from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from fastapi import Request

from models_enhanced import AuditLog, User, AuditEventType
from database import get_db


class SecurityLogger:
    """Centralized security event logging"""

    def __init__(self):
        # Configure file logging
        self.setup_file_logging()

    def setup_file_logging(self):
        """Setup file-based logging"""
        # Security events logger
        self.security_logger = logging.getLogger("security")
        self.security_logger.setLevel(logging.INFO)

        # Create file handler for security events
        security_handler = logging.FileHandler("logs/security.log")
        security_handler.setLevel(logging.INFO)

        # Create formatter
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        security_handler.setFormatter(formatter)

        # Add handler to logger
        if not self.security_logger.handlers:
            self.security_logger.addHandler(security_handler)

        # Access logger
        self.access_logger = logging.getLogger("access")
        self.access_logger.setLevel(logging.INFO)

        access_handler = logging.FileHandler("logs/access.log")
        access_handler.setFormatter(formatter)

        if not self.access_logger.handlers:
            self.access_logger.addHandler(access_handler)

        # Error logger
        self.error_logger = logging.getLogger("error")
        self.error_logger.setLevel(logging.ERROR)

        error_handler = logging.FileHandler("logs/error.log")
        error_handler.setFormatter(formatter)

        if not self.error_logger.handlers:
            self.error_logger.addHandler(error_handler)

    def log_security_event(
        self,
        db: Session,
        event_type: AuditEventType,
        description: str,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        resource: Optional[str] = None,
        old_values: Optional[Dict] = None,
        new_values: Optional[Dict] = None,
        risk_level: str = "LOW",
        request: Optional[Request] = None,
    ) -> AuditLog:
        """Log a security event to database and files"""

        # Extract request info if provided
        if request:
            if not ip_address:
                ip_address = self._get_client_ip(request)
            if not user_agent:
                user_agent = request.headers.get("User-Agent", "Unknown")

        # Create audit log entry
        audit_log = AuditLog(
            user_id=user_id,
            event_type=event_type.value,
            event_description=description,
            ip_address=ip_address,
            user_agent=user_agent,
            resource=resource,
            old_values=old_values,
            new_values=new_values,
            risk_level=risk_level,
        )

        db.add(audit_log)
        db.commit()

        # Log to file based on risk level
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type.value,
            "description": description,
            "user_id": user_id,
            "ip_address": ip_address,
            "resource": resource,
            "risk_level": risk_level,
        }

        log_message = json.dumps(log_data)

        if risk_level in ["HIGH", "CRITICAL"]:
            self.security_logger.critical(log_message)
        elif risk_level == "MEDIUM":
            self.security_logger.warning(log_message)
        else:
            self.security_logger.info(log_message)

        return audit_log

    def log_login_attempt(
        self,
        db: Session,
        username: str,
        success: bool,
        ip_address: str,
        user_agent: str,
        user_id: Optional[int] = None,
        failure_reason: Optional[str] = None,
    ):
        """Log login attempt"""
        if success:
            self.log_security_event(
                db=db,
                event_type=AuditEventType.LOGIN_SUCCESS,
                description=f"Successful login for user: {username}",
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                risk_level="LOW",
            )
        else:
            risk_level = "MEDIUM" if failure_reason else "LOW"
            description = f"Failed login attempt for user: {username}"
            if failure_reason:
                description += f" - Reason: {failure_reason}"

            self.log_security_event(
                db=db,
                event_type=AuditEventType.LOGIN_FAILURE,
                description=description,
                ip_address=ip_address,
                user_agent=user_agent,
                risk_level=risk_level,
            )

    def log_logout(self, db: Session, user: User, ip_address: str):
        """Log user logout"""
        self.log_security_event(
            db=db,
            event_type=AuditEventType.LOGOUT,
            description=f"User logout: {user.username}",
            user_id=user.id,
            ip_address=ip_address,
            risk_level="LOW",
        )

    def log_password_change(self, db: Session, user: User, ip_address: str):
        """Log password change"""
        self.log_security_event(
            db=db,
            event_type=AuditEventType.PASSWORD_CHANGE,
            description=f"Password changed for user: {user.username}",
            user_id=user.id,
            ip_address=ip_address,
            risk_level="MEDIUM",
        )

    def log_mfa_event(self, db: Session, user: User, enabled: bool, ip_address: str):
        """Log MFA enable/disable"""
        event_type = AuditEventType.MFA_ENABLED if enabled else AuditEventType.MFA_DISABLED
        action = "enabled" if enabled else "disabled"

        self.log_security_event(
            db=db,
            event_type=event_type,
            description=f"MFA {action} for user: {user.username}",
            user_id=user.id,
            ip_address=ip_address,
            risk_level="HIGH" if not enabled else "MEDIUM",
        )

    def log_role_change(
        self, db: Session, target_user: User, old_role: str, new_role: str, changed_by_user_id: int, ip_address: str
    ):
        """Log role changes"""
        self.log_security_event(
            db=db,
            event_type=AuditEventType.ROLE_CHANGE,
            description=f"Role changed for user {target_user.username} from {old_role} to {new_role}",
            user_id=changed_by_user_id,
            ip_address=ip_address,
            resource=f"user:{target_user.id}",
            old_values={"role": old_role},
            new_values={"role": new_role},
            risk_level="HIGH",
        )

    def log_user_creation(self, db: Session, new_user: User, created_by_user_id: int, ip_address: str):
        """Log new user creation"""
        self.log_security_event(
            db=db,
            event_type=AuditEventType.USER_CREATED,
            description=f"New user created: {new_user.username} ({new_user.email})",
            user_id=created_by_user_id,
            ip_address=ip_address,
            resource=f"user:{new_user.id}",
            new_values=new_user.to_dict(),
            risk_level="MEDIUM",
        )

    def log_user_update(
        self,
        db: Session,
        updated_user: User,
        old_values: Dict,
        new_values: Dict,
        updated_by_user_id: int,
        ip_address: str,
    ):
        """Log user profile updates"""
        self.log_security_event(
            db=db,
            event_type=AuditEventType.USER_UPDATED,
            description=f"User profile updated: {updated_user.username}",
            user_id=updated_by_user_id,
            ip_address=ip_address,
            resource=f"user:{updated_user.id}",
            old_values=old_values,
            new_values=new_values,
            risk_level="LOW",
        )

    def log_user_deletion(self, db: Session, deleted_user: User, deleted_by_user_id: int, ip_address: str):
        """Log user deletion"""
        self.log_security_event(
            db=db,
            event_type=AuditEventType.USER_DELETED,
            description=f"User deleted: {deleted_user.username}",
            user_id=deleted_by_user_id,
            ip_address=ip_address,
            resource=f"user:{deleted_user.id}",
            old_values=deleted_user.to_dict(),
            risk_level="HIGH",
        )

    def log_data_access(self, db: Session, user: User, resource: str, ip_address: str, details: Optional[str] = None):
        """Log data access events"""
        description = f"Data accessed: {resource}"
        if details:
            description += f" - {details}"

        self.log_security_event(
            db=db,
            event_type=AuditEventType.DATA_ACCESS,
            description=description,
            user_id=user.id,
            ip_address=ip_address,
            resource=resource,
            risk_level="LOW",
        )

    def log_data_modification(
        self, db: Session, user: User, resource: str, old_values: Dict, new_values: Dict, ip_address: str
    ):
        """Log data modification events"""
        self.log_security_event(
            db=db,
            event_type=AuditEventType.DATA_MODIFICATION,
            description=f"Data modified: {resource}",
            user_id=user.id,
            ip_address=ip_address,
            resource=resource,
            old_values=old_values,
            new_values=new_values,
            risk_level="MEDIUM",
        )

    def log_security_alert(
        self,
        db: Session,
        alert_type: str,
        description: str,
        ip_address: Optional[str] = None,
        user_id: Optional[int] = None,
        metadata: Optional[Dict] = None,
    ):
        """Log security alerts"""
        self.log_security_event(
            db=db,
            event_type=AuditEventType.SECURITY_ALERT,
            description=f"Security Alert - {alert_type}: {description}",
            user_id=user_id,
            ip_address=ip_address,
            resource=alert_type,
            new_values=metadata,
            risk_level="HIGH",
        )

    def log_access_attempt(self, request: Request, user: Optional[User] = None):
        """Log API access attempts"""
        ip_address = self._get_client_ip(request)
        user_agent = request.headers.get("User-Agent", "Unknown")

        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "method": request.method,
            "path": str(request.url.path),
            "ip_address": ip_address,
            "user_agent": user_agent,
            "user_id": user.id if user else None,
            "username": user.username if user else "anonymous",
        }

        self.access_logger.info(json.dumps(log_data))

    def log_error(self, error: Exception, request: Optional[Request] = None, user: Optional[User] = None):
        """Log application errors"""
        error_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "error_type": type(error).__name__,
            "error_message": str(error),
            "user_id": user.id if user else None,
        }

        if request:
            error_data.update(
                {
                    "method": request.method,
                    "path": str(request.url.path),
                    "ip_address": self._get_client_ip(request),
                }
            )

        self.error_logger.error(json.dumps(error_data))

    def get_audit_summary(self, db: Session, hours: int = 24) -> Dict[str, Any]:
        """Get audit summary for dashboard"""
        from sqlalchemy import func
        from datetime import datetime, timedelta

        since = datetime.utcnow() - timedelta(hours=hours)

        # Event counts by type
        event_counts = (
            db.query(AuditLog.event_type, func.count(AuditLog.id).label("count"))
            .filter(AuditLog.created_at >= since)
            .group_by(AuditLog.event_type)
            .all()
        )

        # Risk level distribution
        risk_counts = (
            db.query(AuditLog.risk_level, func.count(AuditLog.id).label("count"))
            .filter(AuditLog.created_at >= since)
            .group_by(AuditLog.risk_level)
            .all()
        )

        # Recent high-risk events
        high_risk_events = (
            db.query(AuditLog)
            .filter(AuditLog.risk_level.in_(["HIGH", "CRITICAL"]), AuditLog.created_at >= since)
            .order_by(AuditLog.created_at.desc())
            .limit(10)
            .all()
        )

        # Failed login attempts
        failed_logins = (
            db.query(AuditLog)
            .filter(AuditLog.event_type == AuditEventType.LOGIN_FAILURE.value, AuditLog.created_at >= since)
            .count()
        )

        # Unique active users
        active_users = (
            db.query(func.count(func.distinct(AuditLog.user_id)))
            .filter(AuditLog.event_type == AuditEventType.LOGIN_SUCCESS.value, AuditLog.created_at >= since)
            .scalar()
            or 0
        )

        return {
            "period_hours": hours,
            "total_events": sum(count for _, count in event_counts),
            "event_types": dict(event_counts),
            "risk_levels": dict(risk_counts),
            "high_risk_events": [event.to_dict() for event in high_risk_events],
            "failed_login_attempts": failed_logins,
            "active_users": active_users,
        }

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
        x_forwarded_for = request.headers.get("X-Forwarded-For")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        x_real_ip = request.headers.get("X-Real-IP")
        if x_real_ip:
            return x_real_ip
        return request.client.host if request.client else "unknown"


# Global instance
security_logger = SecurityLogger()
