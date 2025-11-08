"""Pipeline models for CI/CD pipeline tracking."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, String, Integer, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship

from .base import Base, IDMixin, TimestampMixin


class Pipeline(Base, IDMixin, TimestampMixin):
    """CI/CD Pipeline model."""

    __tablename__ = "pipelines"

    # Basic Information
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    repository_url = Column(String(500), nullable=True)
    branch = Column(String(100), default="main", nullable=False)
    
    # Configuration
    pipeline_type = Column(String(50), nullable=False)  # github_actions, gitlab_ci, jenkins, etc.
    configuration = Column(JSON, nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    last_run_at = Column(DateTime, nullable=True)
    last_run_status = Column(String(20), nullable=True)  # success, failed, running, cancelled
    
    # Associations
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "repository_url": self.repository_url,
            "branch": self.branch,
            "pipeline_type": self.pipeline_type,
            "is_active": self.is_active,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
            "last_run_status": self.last_run_status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class PipelineRun(Base, IDMixin, TimestampMixin):
    """Pipeline run/execution model."""

    __tablename__ = "pipeline_runs"

    # Basic Information
    pipeline_id = Column(Integer, ForeignKey("pipelines.id"), nullable=False, index=True)
    run_number = Column(Integer, nullable=False)
    status = Column(String(20), default="running", nullable=False)
    
    # Execution Details
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    
    # Results
    exit_code = Column(Integer, nullable=True)
    logs = Column(Text, nullable=True)
    artifacts = Column(JSON, nullable=True)
    
    # Trigger Information
    trigger_type = Column(String(50), nullable=True)  # push, pull_request, manual, scheduled
    triggered_by = Column(String(255), nullable=True)
    commit_hash = Column(String(40), nullable=True)
    commit_message = Column(Text, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "pipeline_id": self.pipeline_id,
            "run_number": self.run_number,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "trigger_type": self.trigger_type,
            "triggered_by": self.triggered_by,
            "commit_hash": self.commit_hash,
            "commit_message": self.commit_message
        }


class ScanJob(Base, IDMixin, TimestampMixin):
    """Security scan job model."""

    __tablename__ = "scan_jobs"

    # Basic Information
    pipeline_run_id = Column(Integer, ForeignKey("pipeline_runs.id"), nullable=False, index=True)
    scan_type = Column(String(50), nullable=False, index=True)  # dependency, secret, docker, compliance
    scanner_name = Column(String(100), nullable=False)
    
    # Execution
    status = Column(String(20), default="pending", nullable=False)  # pending, running, completed, failed
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Results
    findings_count = Column(Integer, default=0, nullable=False)
    vulnerabilities_found = Column(Integer, default=0, nullable=False)
    scan_results = Column(JSON, nullable=True)
    
    # Configuration
    scan_config = Column(JSON, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "pipeline_run_id": self.pipeline_run_id,
            "scan_type": self.scan_type,
            "scanner_name": self.scanner_name,
            "status": self.status,
            "findings_count": self.findings_count,
            "vulnerabilities_found": self.vulnerabilities_found,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None
        }
