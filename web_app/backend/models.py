"""
Database models for SecureOps AI
SQLAlchemy models for all entities
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Float, JSON
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import hashlib

# Create declarative base
Base = declarative_base()

class User(Base):
    """User model for authentication and user management"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    role = Column(String(20), default='user')
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    def verify_password(self, password: str) -> bool:
        """Verify password against stored hash"""
        # Simple hash verification for demo
        return hashlib.sha256(password.encode()).hexdigest() == self.hashed_password
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password for storage"""
        # Simple hash for demo
        return hashlib.sha256(password.encode()).hexdigest()
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'is_admin': self.is_admin,
            'is_active': self.is_active,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class SecurityEvent(Base):
    """Security events and incidents model"""
    __tablename__ = 'security_events'
    
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    source_ip = Column(String(45), nullable=False)
    target_ip = Column(String(45), nullable=False)
    description = Column(Text, nullable=False)
    status = Column(String(20), default='active')  # active, resolved, investigating
    affected_services = Column(JSON, default=list)
    event_metadata = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(Integer, ForeignKey('users.id'), nullable=True)
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'event_type': self.event_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'target_ip': self.target_ip,
            'description': self.description,
            'status': self.status,
            'affected_services': self.affected_services,
            'metadata': self.event_metadata,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'created_by': self.created_by
        }

class AutomationTask(Base):
    """Automation tasks and AI operations model"""
    __tablename__ = 'automation_tasks'
    
    id = Column(Integer, primary_key=True, index=True)
    task_name = Column(String(100), nullable=False)
    task_type = Column(String(50), nullable=False)  # scan, analysis, report, etc.
    status = Column(String(20), default='pending')  # pending, running, completed, failed
    progress = Column(Float, default=0.0)
    parameters = Column(JSON, default=dict)
    result = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'task_name': self.task_name,
            'task_type': self.task_type,
            'status': self.status,
            'progress': self.progress,
            'parameters': self.parameters,
            'result': self.result,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'created_by': self.created_by
        }

class Notification(Base):
    """System notifications model"""
    __tablename__ = 'notifications'
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(100), nullable=False)
    message = Column(Text, nullable=False)
    type = Column(String(20), default='info')  # info, warning, error, success
    priority = Column(String(10), default='medium')  # low, medium, high
    is_read = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)  # null = broadcast
    created_at = Column(DateTime, default=datetime.utcnow)
    read_at = Column(DateTime, nullable=True)
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'title': self.title,
            'message': self.message,
            'type': self.type,
            'priority': self.priority,
            'is_read': self.is_read,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'read_at': self.read_at.isoformat() if self.read_at else None
        }

class SystemLog(Base):
    """System logs and events model"""
    __tablename__ = 'system_logs'
    
    id = Column(Integer, primary_key=True, index=True)
    level = Column(String(10), nullable=False)  # INFO, WARNING, ERROR, DEBUG
    source = Column(String(50), nullable=False)  # module or component name
    message = Column(Text, nullable=False)
    category = Column(String(30), nullable=False)  # security, authentication, automation
    log_metadata = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'level': self.level,
            'source': self.source,
            'message': self.message,
            'category': self.category,
            'metadata': self.log_metadata,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }