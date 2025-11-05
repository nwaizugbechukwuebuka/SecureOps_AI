"""
Base database model with common fields and configurations.
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict
from sqlalchemy import Column, DateTime, Integer, String, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import declarative_mixin

Base = declarative_base()


@declarative_mixin
class TimestampMixin:
    """Mixin to add created_at and updated_at timestamps to models."""

    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


@declarative_mixin
class IDMixin:
    """Mixin to add primary key ID field."""

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)


class BaseResponse(BaseModel):
    """Base Pydantic model for API responses."""

    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class PaginationParams(BaseModel):
    """Standard pagination parameters."""

    skip: int = 0
    limit: int = 100

    class Config:
        schema_extra = {"example": {"skip": 0, "limit": 20}}


class PaginatedResponse(BaseModel):
    """Standard paginated response wrapper."""

    items: list[Any]
    total: int
    skip: int
    limit: int
    has_next: bool
    has_prev: bool

    @classmethod
    def create(
        cls, items: list, total: int, skip: int, limit: int
    ) -> "PaginatedResponse":
        """Create a paginated response."""
        return cls(
            items=items,
            total=total,
            skip=skip,
            limit=limit,
            has_next=skip + limit < total,
            has_prev=skip > 0,
        )


class APIResponse(BaseModel):
    """Standard API response wrapper."""

    success: bool
    message: str
    data: Optional[Any] = None
    errors: Optional[list[str]] = None

    @classmethod
    def success_response(
        cls, data: Any = None, message: str = "Success"
    ) -> "APIResponse":
        """Create a success response."""
        return cls(success=True, message=message, data=data)

    @classmethod
    def error_response(
        cls, message: str, errors: Optional[list[str]] = None
    ) -> "APIResponse":
        """Create an error response."""
        return cls(success=False, message=message, errors=errors or [])


# Enums for consistent status values
class SeverityLevel:
    """Security vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus:
    """Scan execution status values."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PipelineStatus:
    """CI/CD pipeline status values."""

    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


class AlertStatus:
    """Alert management status values."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    SUPPRESSED = "suppressed"


class ComplianceStatus:
    """Compliance check status values."""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"
