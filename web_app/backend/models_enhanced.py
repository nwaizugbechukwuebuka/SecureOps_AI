"""
Enhanced Database models for SecureOps AI with Enterprise Security
SQLAlchemy models with RBAC, MFA, Audit Logging, and Rate Limiting
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Float, JSON, Index, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
from enum import Enum
import bcrypt
import secrets
import uuid

# Create declarative base
Base = declarative_base()

class UserRole(Enum):
    """User roles for RBAC"""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

class AuditEventType(Enum):
    """Types of audit events"""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    ROLE_CHANGE = "role_change"
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    SECURITY_ALERT = "security_alert"

class User(Base):
    """Enhanced User model with MFA and security features"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()), index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    
    # Role-based access control
    role = Column(String(20), default=UserRole.VIEWER.value, nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    
    # Multi-Factor Authentication
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(32), nullable=True)  # TOTP secret
    backup_codes = Column(JSON, nullable=True)  # Recovery codes
    
    # Security tracking
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    last_password_change = Column(DateTime, default=datetime.utcnow)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    password_reset_token = Column(String(255), nullable=True)
    password_reset_expires = Column(DateTime, nullable=True)
    
    # Relationships
    audit_logs = relationship("AuditLog", back_populates="user")
    sessions = relationship("UserSession", back_populates="user")
    
    def verify_password(self, password: str) -> bool:
        """Verify password using bcrypt"""
        return bcrypt.checkpw(password.encode('utf-8'), self.hashed_password.encode('utf-8'))
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt with salt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def is_locked(self) -> bool:
        """Check if account is locked due to failed login attempts"""
        if self.locked_until:
            return datetime.utcnow() < self.locked_until
        return False
    
    def lock_account(self, duration_minutes: int = 30):
        """Lock account for specified duration"""
        self.locked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
    
    def unlock_account(self):
        """Unlock account"""
        self.failed_login_attempts = 0
        self.locked_until = None
    
    def generate_backup_codes(self) -> list:
        """Generate MFA backup codes"""
        codes = [secrets.token_hex(4).upper() for _ in range(10)]
        self.backup_codes = codes
        return codes
    
    def verify_backup_code(self, code: str) -> bool:
        """Verify and consume backup code"""
        if self.backup_codes and code.upper() in self.backup_codes:
            self.backup_codes.remove(code.upper())
            return True
        return False
    
    def has_permission(self, required_role: UserRole) -> bool:
        """Check if user has required permission level"""
        role_hierarchy = {
            UserRole.VIEWER.value: 1,
            UserRole.ANALYST.value: 2,
            UserRole.ADMIN.value: 3
        }
        return role_hierarchy.get(self.role, 0) >= role_hierarchy.get(required_role.value, 0)
    
    def to_dict(self, include_sensitive=False):
        """Convert to dictionary for API responses"""
        data = {
            'id': self.id,
            'uuid': self.uuid,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'mfa_enabled': self.mfa_enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'last_password_change': self.last_password_change.isoformat() if self.last_password_change else None,
        }
        
        if include_sensitive:
            data.update({
                'failed_login_attempts': self.failed_login_attempts,
                'is_locked': self.is_locked(),
                'locked_until': self.locked_until.isoformat() if self.locked_until else None,
            })
        
        return data

class UserSession(Base):
    """User sessions for token management"""
    __tablename__ = 'user_sessions'
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    token_jti = Column(String(36), unique=True, index=True, nullable=False)  # JWT ID
    ip_address = Column(String(45), nullable=True)  # IPv4/IPv6
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_used = Column(DateTime, default=datetime.utcnow)
    is_revoked = Column(Boolean, default=False)
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    def is_valid(self) -> bool:
        """Check if session is still valid"""
        return not self.is_revoked and datetime.utcnow() < self.expires_at
    
    def revoke(self):
        """Revoke session"""
        self.is_revoked = True

class AuditLog(Base):
    """Comprehensive audit logging"""
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    event_type = Column(String(50), nullable=False, index=True)
    event_description = Column(Text, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    resource = Column(String(100), nullable=True)  # What was accessed/modified
    old_values = Column(JSON, nullable=True)  # Before change
    new_values = Column(JSON, nullable=True)  # After change
    risk_level = Column(String(20), default='LOW')  # LOW, MEDIUM, HIGH, CRITICAL
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else 'System',
            'event_type': self.event_type,
            'event_description': self.event_description,
            'ip_address': self.ip_address,
            'resource': self.resource,
            'risk_level': self.risk_level,
            'created_at': self.created_at.isoformat(),
        }

class RateLimit(Base):
    """Rate limiting for brute force protection"""
    __tablename__ = 'rate_limits'
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    endpoint = Column(String(100), nullable=False)
    attempts = Column(Integer, default=1)
    window_start = Column(DateTime, default=datetime.utcnow)
    blocked_until = Column(DateTime, nullable=True)
    
    __table_args__ = (
        Index('idx_ip_endpoint', 'ip_address', 'endpoint'),
    )
    
    def is_blocked(self) -> bool:
        """Check if IP is currently blocked"""
        if self.blocked_until:
            return datetime.utcnow() < self.blocked_until
        return False
    
    def block(self, duration_minutes: int = 15):
        """Block IP for specified duration"""
        self.blocked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)

class SecurityAlert(Base):
    """Security alerts and threat notifications"""
    __tablename__ = 'security_alerts'
    
    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(50), nullable=False, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), default='MEDIUM')  # LOW, MEDIUM, HIGH, CRITICAL
    source_ip = Column(String(45), nullable=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    status = Column(String(20), default='OPEN')  # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    
    # Metadata
    metadata = Column(JSON, nullable=True)  # Additional context
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(Integer, ForeignKey('users.id'), nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'user_id': self.user_id,
            'status': self.status,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
        }

class SystemConfiguration(Base):
    """System configuration and security policies"""
    __tablename__ = 'system_config'
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False)
    value = Column(Text, nullable=False)
    category = Column(String(50), nullable=False, index=True)
    description = Column(Text, nullable=True)
    is_sensitive = Column(Boolean, default=False)  # Mask in logs
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(Integer, ForeignKey('users.id'), nullable=True)

# Dashboard analytics models (existing)
class DashboardMetric(Base):
    """Dashboard metrics and statistics"""
    __tablename__ = 'dashboard_metrics'
    
    id = Column(Integer, primary_key=True, index=True)
    metric_name = Column(String(100), nullable=False, index=True)
    metric_value = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    category = Column(String(50), nullable=False)
    
class ThreatIntelligence(Base):
    """Threat intelligence data"""
    __tablename__ = 'threat_intelligence'
    
    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String(255), nullable=False, index=True)
    indicator_type = Column(String(50), nullable=False)  # IP, DOMAIN, HASH, etc.
    threat_type = Column(String(100), nullable=False)
    severity = Column(String(20), default='MEDIUM')
    confidence = Column(Integer, default=50)  # 0-100
    source = Column(String(100), nullable=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'indicator': self.indicator,
            'indicator_type': self.indicator_type,
            'threat_type': self.threat_type,
            'severity': self.severity,
            'confidence': self.confidence,
            'source': self.source,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'is_active': self.is_active,
        }