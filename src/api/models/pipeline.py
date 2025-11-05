"""
Pipeline models for CI/CD pipeline monitoring and management.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl, validator
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from .base import (
    Base,
    BaseResponse,
    IDMixin,
    PipelineStatus,
    ScanStatus,
    TimestampMixin,
)
from .user import User


class Pipeline(Base, IDMixin, TimestampMixin):
    """Pipeline model for tracking CI/CD pipelines across different platforms."""

    __tablename__ = "pipelines"

    # Pipeline identification
    name = Column(String(255), nullable=False, index=True)
    platform = Column(
        String(50), nullable=False, index=True
    )  # github, gitlab, jenkins, azure
    external_id = Column(
        String(255), nullable=False, index=True
    )  # Platform-specific ID
    repository_url = Column(Text, nullable=True)
    repository_name = Column(String(255), nullable=True, index=True)
    branch = Column(String(255), nullable=True, index=True)

    # Pipeline configuration
    config_file_path = Column(String(500), nullable=True)  # Path to CI config file
    description = Column(Text, nullable=True)
    tags = Column(JSON, nullable=True)  # List of tags for categorization

    # Status and execution
    status = Column(
        String(50), default=PipelineStatus.RUNNING, nullable=False, index=True
    )
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    last_success_at = Column(DateTime(timezone=True), nullable=True)
    last_failure_at = Column(DateTime(timezone=True), nullable=True)

    # Metrics
    success_rate = Column(Float, default=0.0, nullable=False)  # Percentage
    average_duration = Column(Integer, default=0, nullable=False)  # Seconds
    total_runs = Column(Integer, default=0, nullable=False)
    failed_runs = Column(Integer, default=0, nullable=False)

    # Security and compliance
    security_score = Column(Float, nullable=True)  # 0-100 security score
    compliance_score = Column(Float, nullable=True)  # 0-100 compliance score
    last_scanned_at = Column(DateTime(timezone=True), nullable=True)

    # Configuration and webhook
    webhook_url = Column(Text, nullable=True)
    webhook_secret = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    monitoring_enabled = Column(Boolean, default=True, nullable=False)

    # User association
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    owner = relationship("User", backref="pipelines")

    # Relationships
    pipeline_runs = relationship(
        "PipelineRun", back_populates="pipeline", cascade="all, delete-orphan"
    )
    vulnerabilities = relationship("Vulnerability", back_populates="pipeline")
    alerts = relationship("Alert", back_populates="pipeline")


class PipelineRun(Base, IDMixin, TimestampMixin):
    """Individual pipeline execution/run tracking."""

    __tablename__ = "pipeline_runs"

    # Run identification
    pipeline_id = Column(
        Integer, ForeignKey("pipelines.id"), nullable=False, index=True
    )
    external_run_id = Column(String(255), nullable=False, index=True)
    run_number = Column(Integer, nullable=True)

    # Execution details
    status = Column(
        String(50), default=PipelineStatus.RUNNING, nullable=False, index=True
    )
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    duration = Column(Integer, nullable=True)  # Duration in seconds

    # Git information
    commit_sha = Column(String(255), nullable=True, index=True)
    commit_message = Column(Text, nullable=True)
    author_name = Column(String(255), nullable=True)
    author_email = Column(String(255), nullable=True)

    # Trigger information
    trigger_event = Column(
        String(100), nullable=True
    )  # push, pull_request, schedule, manual
    triggered_by = Column(String(255), nullable=True)

    # Results and artifacts
    logs_url = Column(Text, nullable=True)
    artifacts_url = Column(Text, nullable=True)
    test_results = Column(JSON, nullable=True)

    # Security scan results
    security_scan_status = Column(
        String(50), default=ScanStatus.PENDING, nullable=False
    )
    vulnerabilities_found = Column(Integer, default=0, nullable=False)
    critical_vulnerabilities = Column(Integer, default=0, nullable=False)
    high_vulnerabilities = Column(Integer, default=0, nullable=False)
    medium_vulnerabilities = Column(Integer, default=0, nullable=False)
    low_vulnerabilities = Column(Integer, default=0, nullable=False)

    # Compliance results
    compliance_checks = Column(JSON, nullable=True)
    compliance_passed = Column(Integer, default=0, nullable=False)
    compliance_failed = Column(Integer, default=0, nullable=False)

    # Raw webhook data
    webhook_payload = Column(JSON, nullable=True)

    # Relationships
    pipeline = relationship("Pipeline", back_populates="pipeline_runs")
    vulnerabilities = relationship("Vulnerability", back_populates="pipeline_run")


<<<<<<< HEAD
class ScanJob(Base, IDMixin, TimestampMixin):
    """Security scan job tracking - placeholder model"""

    __tablename__ = "scan_jobs"

    # Basic fields
    pipeline_id = Column(Integer, ForeignKey("pipelines.id"), nullable=False, index=True)
    status = Column(String(50), default="pending", nullable=False)
    scan_type = Column(String(100), nullable=True)
    
    # Relationships
    pipeline = relationship("Pipeline")


=======
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
# Pydantic models for API serialization
class PipelineBase(BaseModel):
    """Base pipeline model with common fields."""

    name: str = Field(..., min_length=1, max_length=255)
<<<<<<< HEAD
    platform: str = Field(..., pattern="^(github|gitlab|jenkins|azure)$")
=======
    platform: str = Field(..., regex="^(github|gitlab|jenkins|azure)$")
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    repository_url: Optional[HttpUrl] = None
    repository_name: Optional[str] = Field(None, max_length=255)
    branch: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    monitoring_enabled: bool = Field(default=True)


class PipelineCreate(PipelineBase):
    """Model for pipeline creation."""

    external_id: str = Field(..., min_length=1, max_length=255)
    config_file_path: Optional[str] = Field(None, max_length=500)
    webhook_url: Optional[HttpUrl] = None


class PipelineUpdate(BaseModel):
    """Model for pipeline updates."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    monitoring_enabled: Optional[bool] = None
    is_active: Optional[bool] = None


class PipelineResponse(PipelineBase, BaseResponse):
    """Model for pipeline API responses."""

    external_id: str
    status: str
    last_run_at: Optional[datetime] = None
    last_success_at: Optional[datetime] = None
    last_failure_at: Optional[datetime] = None
    success_rate: float
    average_duration: int
    total_runs: int
    failed_runs: int
    security_score: Optional[float] = None
    compliance_score: Optional[float] = None
    last_scanned_at: Optional[datetime] = None
    is_active: bool
    vulnerabilities_count: Optional[int] = None
    alerts_count: Optional[int] = None

    class Config:
        from_attributes = True


class PipelineRunBase(BaseModel):
    """Base pipeline run model."""

    run_number: Optional[int] = None
    commit_sha: Optional[str] = Field(None, max_length=255)
    commit_message: Optional[str] = None
    author_name: Optional[str] = Field(None, max_length=255)
    author_email: Optional[str] = Field(None, max_length=255)
    trigger_event: Optional[str] = Field(None, max_length=100)
    triggered_by: Optional[str] = Field(None, max_length=255)


class PipelineRunCreate(PipelineRunBase):
    """Model for pipeline run creation."""

    external_run_id: str = Field(..., min_length=1, max_length=255)
    status: str = Field(default=PipelineStatus.RUNNING)
    started_at: Optional[datetime] = None
    webhook_payload: Optional[Dict[str, Any]] = None


class PipelineRunUpdate(BaseModel):
    """Model for pipeline run updates."""

    status: Optional[str] = None
    completed_at: Optional[datetime] = None
    duration: Optional[int] = Field(None, ge=0)
    logs_url: Optional[HttpUrl] = None
    artifacts_url: Optional[HttpUrl] = None
    test_results: Optional[Dict[str, Any]] = None


class PipelineRunResponse(PipelineRunBase, BaseResponse):
    """Model for pipeline run API responses."""

    external_run_id: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration: Optional[int] = None
    security_scan_status: str
    vulnerabilities_found: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    compliance_passed: int
    compliance_failed: int
    pipeline_id: int

    class Config:
        from_attributes = True


class PipelineMetrics(BaseModel):
    """Pipeline metrics and statistics."""

    total_pipelines: int
    active_pipelines: int
    running_pipelines: int
    successful_runs_today: int
    failed_runs_today: int
    average_success_rate: float
    total_vulnerabilities: int
    critical_vulnerabilities: int
    compliance_score_avg: float


class PipelineWebhookEvent(BaseModel):
    """Webhook event data structure."""

    event_type: str = Field(..., max_length=100)
<<<<<<< HEAD
    platform: str = Field(..., pattern="^(github|gitlab|jenkins|azure)$")
    __table_args__ = {'extend_existing': True}
=======
    platform: str = Field(..., regex="^(github|gitlab|jenkins|azure)$")
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    pipeline_id: str = Field(..., max_length=255)
    run_id: str = Field(..., max_length=255)
    status: str
    repository_url: Optional[str] = None
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    commit_message: Optional[str] = None
    author: Optional[str] = None
    timestamp: datetime
    raw_payload: Dict[str, Any]

    class Config:
        schema_extra = {
            "example": {
                "event_type": "pipeline.completed",
                "platform": "github",
                "pipeline_id": "123456",
                "run_id": "run-789",
                "status": "success",
                "repository_url": "https://github.com/user/repo",
                "branch": "main",
                "commit_sha": "abc123def456",
                "commit_message": "Fix security vulnerability",
                "author": "john.doe",
                "timestamp": "2023-10-17T12:00:00Z",
                "raw_payload": {},
            }
        }
