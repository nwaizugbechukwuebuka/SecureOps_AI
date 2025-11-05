"""
Alert models for security incident management and notifications.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field, validator
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
    AlertStatus,
    Base,
    BaseResponse,
    IDMixin,
    SeverityLevel,
    TimestampMixin,
)
from .pipeline import Pipeline
from .user import User
from .vulnerability import Vulnerability


class Alert(Base, IDMixin, TimestampMixin):
    """Alert model for security incidents and notifications."""

    __tablename__ = "alerts"

    # Alert identification and classification
    title = Column(String(500), nullable=False, index=True)
    description = Column(Text, nullable=True)
    alert_type = Column(
        String(100), nullable=False, index=True
    )  # vulnerability, compliance, policy, threshold
    severity = Column(String(20), nullable=False, index=True)
    category = Column(
        String(100), nullable=True, index=True
    )  # security, performance, availability

    # Status and management
    status = Column(String(50), default=AlertStatus.OPEN, nullable=False, index=True)
    priority = Column(
        String(20), default="medium", nullable=False
    )  # critical, high, medium, low

    # Source and context
    source = Column(
        String(100), nullable=False, index=True
    )  # scanner name, monitor, manual
    source_reference = Column(String(255), nullable=True)  # Reference to source entity

    # Timeline
    triggered_at = Column(DateTime(timezone=True), nullable=False, index=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    # Assignment and ownership
    assigned_to_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Resolution details
    resolution_notes = Column(Text, nullable=True)
    resolution_time = Column(Integer, nullable=True)  # Minutes to resolve

    # Escalation
    escalated = Column(Boolean, default=False, nullable=False)
    escalated_at = Column(DateTime(timezone=True), nullable=True)
    escalation_level = Column(Integer, default=0, nullable=False)

    # Notification settings
    notification_sent = Column(Boolean, default=False, nullable=False)
    notification_channels = Column(
        JSON, nullable=True
    )  # List of channels (email, slack, etc.)
    notification_recipients = Column(JSON, nullable=True)  # List of recipient emails

    # Metrics and scoring
    impact_score = Column(Float, nullable=True)  # Business impact score
    confidence_score = Column(Float, nullable=True)  # Alert confidence level
    false_positive_likelihood = Column(Float, nullable=True)

    # Relationships
    pipeline_id = Column(Integer, ForeignKey("pipelines.id"), nullable=True, index=True)
    vulnerability_id = Column(
        Integer, ForeignKey("vulnerabilities.id"), nullable=True, index=True
    )

    pipeline = relationship("Pipeline", back_populates="alerts")
    vulnerability = relationship("Vulnerability", back_populates="alerts")
    assigned_to = relationship(
        "User", foreign_keys=[assigned_to_id], backref="assigned_alerts"
    )
    created_by = relationship(
        "User", foreign_keys=[created_by_id], backref="created_alerts"
    )

    # Additional context and metadata
    context = Column(JSON, nullable=True)  # Additional alert context
    tags = Column(JSON, nullable=True)  # Alert tags for categorization

    # Suppression and filtering
    suppressed = Column(Boolean, default=False, nullable=False)
    suppression_reason = Column(Text, nullable=True)
    suppression_expires_at = Column(DateTime(timezone=True), nullable=True)

    def calculate_impact_score(self) -> float:
        """Calculate alert impact score based on severity, pipeline importance, etc."""
        severity_weights = {
            SeverityLevel.CRITICAL: 10.0,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5.0,
            SeverityLevel.LOW: 2.5,
            SeverityLevel.INFO: 1.0,
        }

        base_score = severity_weights.get(self.severity, 5.0)

        # Factor in vulnerability CVSS score if available
        vuln_factor = 1.0
        if self.vulnerability and self.vulnerability.cvss_base_score:
            vuln_factor = self.vulnerability.cvss_base_score / 10.0

        # Factor in pipeline importance (based on activity)
        pipeline_factor = 1.0
        if self.pipeline:
            # Higher activity = higher importance
            if self.pipeline.total_runs > 100:
                pipeline_factor = 1.5
            elif self.pipeline.total_runs > 50:
                pipeline_factor = 1.2

        impact_score = base_score * vuln_factor * pipeline_factor
        return min(impact_score, 100.0)  # Cap at 100

    def should_escalate(self) -> bool:
        """Determine if alert should be escalated based on time and severity."""
        if self.status in [AlertStatus.RESOLVED, AlertStatus.CLOSED]:
            return False

        if self.escalated:
            return False

        # Time since alert was triggered
        time_since_triggered = (
            datetime.utcnow() - self.triggered_at
        ).total_seconds() / 3600  # hours

        # Escalation thresholds based on severity
        escalation_thresholds = {
            SeverityLevel.CRITICAL: 1,  # 1 hour
            SeverityLevel.HIGH: 4,  # 4 hours
            SeverityLevel.MEDIUM: 24,  # 24 hours
            SeverityLevel.LOW: 72,  # 72 hours
        }

        threshold = escalation_thresholds.get(self.severity, 24)
        return time_since_triggered >= threshold


class AlertRule(Base, IDMixin, TimestampMixin):
    """Alert rule configuration for automated alert generation."""

    __tablename__ = "alert_rules"

    # Rule identification
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    # Trigger conditions
    trigger_type = Column(
        String(100), nullable=False
    )  # vulnerability_threshold, scan_failure, etc.
    trigger_conditions = Column(JSON, nullable=False)  # Condition parameters

    # Alert configuration
    alert_severity = Column(String(20), nullable=False)
    alert_category = Column(String(100), nullable=True)
    alert_title_template = Column(String(500), nullable=False)
    alert_description_template = Column(Text, nullable=True)

    # Scope and filtering
    pipeline_filters = Column(
        JSON, nullable=True
    )  # Pipeline inclusion/exclusion criteria
    vulnerability_filters = Column(JSON, nullable=True)  # Vulnerability criteria

    # Notification settings
    notification_enabled = Column(Boolean, default=True, nullable=False)
    notification_channels = Column(JSON, nullable=True)
    notification_recipients = Column(JSON, nullable=True)

    # Rate limiting
    cooldown_minutes = Column(Integer, default=60, nullable=False)
    max_alerts_per_hour = Column(Integer, default=10, nullable=False)

    # Assignment
    auto_assign_to_id = Column(Integer, ForeignKey("users.id"), nullable=True)
<<<<<<< HEAD
    auto_assign_to = relationship("User", foreign_keys=[auto_assign_to_id], backref="alert_rules")
=======
    auto_assign_to = relationship("User", backref="alert_rules")
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

    # Metadata
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_by = relationship(
        "User", foreign_keys=[created_by_id], backref="created_alert_rules"
    )


# Pydantic models for API serialization
class AlertBase(BaseModel):
    """Base alert model with common fields."""

    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    alert_type: str = Field(..., max_length=100)
<<<<<<< HEAD
    severity: str = Field(..., pattern="^(critical|high|medium|low|info)$")
    category: Optional[str] = Field(None, max_length=100)
    priority: str = Field(default="medium", pattern="^(critical|high|medium|low)$")
=======
    severity: str = Field(..., regex="^(critical|high|medium|low|info)$")
    category: Optional[str] = Field(None, max_length=100)
    priority: str = Field(default="medium", regex="^(critical|high|medium|low)$")
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    source: str = Field(..., max_length=100)


class AlertCreate(AlertBase):
    """Model for alert creation."""

    source_reference: Optional[str] = Field(None, max_length=255)
    triggered_at: Optional[datetime] = None
    pipeline_id: Optional[int] = None
    vulnerability_id: Optional[int] = None
    assigned_to_id: Optional[int] = None
    context: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None

    @validator("triggered_at", pre=True, always=True)
    def set_triggered_at(cls, v):
        return v or datetime.utcnow()


class AlertUpdate(BaseModel):
    """Model for alert updates."""

    status: Optional[str] = Field(
<<<<<<< HEAD
    None, pattern="^(open|in_progress|resolved|closed|suppressed)$"
    )
    priority: Optional[str] = Field(None, pattern="^(critical|high|medium|low)$")
=======
        None, regex="^(open|in_progress|resolved|closed|suppressed)$"
    )
    priority: Optional[str] = Field(None, regex="^(critical|high|medium|low)$")
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    assigned_to_id: Optional[int] = None
    resolution_notes: Optional[str] = None
    suppressed: Optional[bool] = None
    suppression_reason: Optional[str] = None
    tags: Optional[List[str]] = None


class AlertResponse(AlertBase, BaseResponse):
    """Model for alert API responses."""

    status: str
    triggered_at: datetime
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    assigned_to_id: Optional[int] = None
    created_by_id: Optional[int] = None

    resolution_notes: Optional[str] = None
    resolution_time: Optional[int] = None
    escalated: bool
    escalation_level: int

    impact_score: Optional[float] = None
    confidence_score: Optional[float] = None

    pipeline_id: Optional[int] = None
    vulnerability_id: Optional[int] = None

    suppressed: bool
    suppression_reason: Optional[str] = None

    tags: Optional[List[str]] = None

    class Config:
        from_attributes = True


class AlertRuleBase(BaseModel):
    """Base alert rule model."""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    trigger_type: str = Field(..., max_length=100)
    trigger_conditions: Dict[str, Any] = Field(...)
<<<<<<< HEAD
    alert_severity: str = Field(..., pattern="^(critical|high|medium|low|info)$")
=======
    alert_severity: str = Field(..., regex="^(critical|high|medium|low|info)$")
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    alert_title_template: str = Field(..., min_length=1, max_length=500)


class AlertRuleCreate(AlertRuleBase):
    """Model for alert rule creation."""

    alert_category: Optional[str] = Field(None, max_length=100)
    alert_description_template: Optional[str] = None
    pipeline_filters: Optional[Dict[str, Any]] = None
    vulnerability_filters: Optional[Dict[str, Any]] = None
    notification_enabled: bool = Field(default=True)
    notification_channels: Optional[List[str]] = None
    notification_recipients: Optional[List[str]] = None
    cooldown_minutes: int = Field(default=60, ge=1, le=1440)
    max_alerts_per_hour: int = Field(default=10, ge=1, le=100)
    auto_assign_to_id: Optional[int] = None


class AlertRuleUpdate(BaseModel):
    """Model for alert rule updates."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    is_active: Optional[bool] = None
    trigger_conditions: Optional[Dict[str, Any]] = None
    alert_severity: Optional[str] = Field(
<<<<<<< HEAD
    None, pattern="^(critical|high|medium|low|info)$"
=======
        None, regex="^(critical|high|medium|low|info)$"
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    )
    notification_enabled: Optional[bool] = None
    cooldown_minutes: Optional[int] = Field(None, ge=1, le=1440)
    max_alerts_per_hour: Optional[int] = Field(None, ge=1, le=100)


class AlertRuleResponse(AlertRuleBase, BaseResponse):
    """Model for alert rule API responses."""

    is_active: bool
    notification_enabled: bool
    cooldown_minutes: int
    max_alerts_per_hour: int
    auto_assign_to_id: Optional[int] = None
    created_by_id: int

    class Config:
        from_attributes = True


class AlertStats(BaseModel):
    """Alert statistics and metrics."""

    total_alerts: int
    open_alerts: int
    in_progress_alerts: int
    resolved_alerts: int
    suppressed_alerts: int

    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int

    alerts_today: int
    alerts_this_week: int
    alerts_this_month: int

    average_resolution_time: Optional[float] = None  # Hours
    escalated_alerts: int

    by_category: Dict[str, int]
    by_source: Dict[str, int]
    by_pipeline: Dict[str, int]

    alert_trend: List[Dict[str, Any]]  # Time series data


class AlertNotification(BaseModel):
    """Alert notification configuration."""

    alert_id: int
<<<<<<< HEAD
    channel: str = Field(..., pattern="^(email|slack|webhook|sms)$")
=======
    channel: str = Field(..., regex="^(email|slack|webhook|sms)$")
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    recipient: str = Field(..., max_length=255)
    template: Optional[str] = None
    sent_at: Optional[datetime] = None
    delivery_status: str = Field(
<<<<<<< HEAD
    default="pending", pattern="^(pending|sent|failed|retry)$"
=======
        default="pending", regex="^(pending|sent|failed|retry)$"
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    )
    error_message: Optional[str] = None

    class Config:
        schema_extra = {
            "example": {
                "alert_id": 123,
                "channel": "email",
                "recipient": "security@company.com",
                "template": "critical_vulnerability",
                "sent_at": "2023-10-17T12:00:00Z",
                "delivery_status": "sent",
            }
        }


<<<<<<< HEAD
class NotificationChannel(Base, IDMixin, TimestampMixin):
    """Notification channel for alert delivery (email, slack, webhook, etc.)."""

    __tablename__ = "notification_channels"

    name = Column(String(255), nullable=False, index=True)
    channel_type = Column(String(50), nullable=False, index=True)  # email, slack, webhook, etc.
    endpoint = Column(String(500), nullable=False)  # Email address, webhook URL, etc.
    configuration = Column(JSON, nullable=True)  # Channel-specific config (auth, templates, etc.)
    pipeline_id = Column(Integer, ForeignKey("pipelines.id"), nullable=True, index=True)
    enabled = Column(Boolean, default=True, nullable=False)

    pipeline = relationship("Pipeline", backref="notification_channels")

    def __repr__(self):
        return f"<NotificationChannel(name={self.name}, type={self.channel_type}, endpoint={self.endpoint})>"


class NotificationChannelSchema(BaseModel):
    id: Optional[int]
    name: str
    channel_type: str
    endpoint: str
    configuration: Optional[dict] = None
    pipeline_id: Optional[int] = None
    enabled: bool = True

    class Config:
        orm_mode = True

=======
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
class AlertEscalation(BaseModel):
    """Alert escalation configuration."""

    level: int = Field(..., ge=1, le=5)
    time_threshold_hours: int = Field(..., ge=1, le=168)  # Max 1 week
    escalate_to_users: List[int] = Field(..., min_items=1)
    notification_channels: List[str] = Field(..., min_items=1)
    escalation_message: Optional[str] = None

    class Config:
        schema_extra = {
            "example": {
                "level": 1,
                "time_threshold_hours": 4,
                "escalate_to_users": [1, 2, 3],
                "notification_channels": ["email", "slack"],
                "escalation_message": "Critical security alert requires immediate attention",
            }
        }
