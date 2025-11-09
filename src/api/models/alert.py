"""Alert model for security notifications and incidents."""

import json
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import (JSON, Boolean, Column, DateTime, ForeignKey, Integer,
                        String, Text)
from sqlalchemy.orm import relationship

from .base import Base, IDMixin, TimestampMixin


class Alert(Base, IDMixin, TimestampMixin):
    """Alert model for security incidents and notifications."""

    __tablename__ = "alerts"

    # Basic Information
    title = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    severity = Column(
        String(20), nullable=False, index=True
    )  # low, medium, high, critical
    status = Column(
        String(20), default="open", nullable=False, index=True
    )  # open, acknowledged, investigating, resolved, closed
    alert_type = Column(
        String(50), nullable=False, index=True
    )  # security, compliance, performance, availability
    source = Column(
        String(100), nullable=False, index=True
    )  # scanner name, integration, etc.

    # Relationships
    pipeline_id = Column(Integer, ForeignKey("pipelines.id"), nullable=True, index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    resolved_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Timestamps
    resolved_at = Column(DateTime, nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Metadata and Context
    alert_metadata = Column(
        JSON, nullable=True
    )  # Additional context data (renamed from metadata)
    tags = Column(String(500), nullable=True)  # Comma-separated tags
    priority = Column(Integer, default=3, nullable=False)  # 1=highest, 5=lowest

    # External References
    external_id = Column(
        String(255), nullable=True, index=True
    )  # ID from external system
    external_url = Column(String(500), nullable=True)  # Link to external system

    # Notification Status
    notification_sent = Column(Boolean, default=False, nullable=False)
    notification_channels = Column(
        String(200), nullable=True
    )  # JSON array of channel IDs

    def acknowledge(self, user_id: int, note: str = None) -> None:
        """Acknowledge the alert."""
        self.status = "acknowledged"
        self.acknowledged_at = datetime.utcnow()
        self.acknowledged_by = user_id
        if note and self.alert_metadata:
            self.alert_metadata["acknowledgment_note"] = note
        elif note:
            self.alert_metadata = {"acknowledgment_note": note}

    def resolve(self, user_id: int, resolution_note: str = None) -> None:
        """Resolve the alert."""
        self.status = "resolved"
        self.resolved_at = datetime.utcnow()
        self.resolved_by = user_id
        if resolution_note and self.alert_metadata:
            self.alert_metadata["resolution_note"] = resolution_note
        elif resolution_note:
            self.alert_metadata = {"resolution_note": resolution_note}

    def reopen(self, user_id: int, reason: str = None) -> None:
        """Reopen a resolved alert."""
        self.status = "open"
        self.resolved_at = None
        self.resolved_by = None
        if reason and self.alert_metadata:
            self.alert_metadata["reopen_reason"] = reason
            self.alert_metadata["reopened_by"] = user_id
            self.alert_metadata["reopened_at"] = datetime.utcnow().isoformat()
        elif reason:
            self.alert_metadata = {
                "reopen_reason": reason,
                "reopened_by": user_id,
                "reopened_at": datetime.utcnow().isoformat(),
            }

    def get_tags_list(self) -> list:
        """Get tags as a list."""
        if not self.tags:
            return []
        return [tag.strip() for tag in self.tags.split(",") if tag.strip()]

    def set_tags(self, tags: list) -> None:
        """Set tags from a list."""
        self.tags = ",".join(str(tag).strip() for tag in tags if tag)

    def add_tag(self, tag: str) -> None:
        """Add a single tag."""
        current_tags = self.get_tags_list()
        if tag not in current_tags:
            current_tags.append(tag)
            self.set_tags(current_tags)

    def remove_tag(self, tag: str) -> None:
        """Remove a single tag."""
        current_tags = self.get_tags_list()
        if tag in current_tags:
            current_tags.remove(tag)
            self.set_tags(current_tags)

    def to_dict(self, include_metadata: bool = True) -> dict:
        """Convert alert to dictionary."""
        data = {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "alert_type": self.alert_type,
            "source": self.source,
            "pipeline_id": self.pipeline_id,
            "priority": self.priority,
            "tags": self.get_tags_list(),
            "external_id": self.external_id,
            "external_url": self.external_url,
            "notification_sent": self.notification_sent,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "acknowledged_at": (
                self.acknowledged_at.isoformat() if self.acknowledged_at else None
            ),
            "created_by": self.created_by,
            "resolved_by": self.resolved_by,
            "acknowledged_by": self.acknowledged_by,
        }

        if include_metadata and self.alert_metadata:
            data["metadata"] = self.alert_metadata

        return data

    def __repr__(self) -> str:
        return f"<Alert(id={self.id}, title='{self.title}', severity='{self.severity}', status='{self.status}')>"


class AlertRule(Base, IDMixin, TimestampMixin):
    """Alert rule configuration for automated alert generation."""

    __tablename__ = "alert_rules"

    # Basic Information
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)

    # Rule Configuration
    condition = Column(JSON, nullable=False)  # Rule condition in JSON format
    severity_threshold = Column(String(20), default="medium", nullable=False)
    alert_type = Column(String(50), nullable=False)

    # Associations
    pipeline_id = Column(Integer, ForeignKey("pipelines.id"), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Notification Configuration
    notification_channels = Column(JSON, nullable=True)  # Array of channel IDs

    # Rate Limiting
    cooldown_minutes = Column(
        Integer, default=60, nullable=False
    )  # Minimum time between alerts
    last_triggered = Column(DateTime, nullable=True)

    def can_trigger(self) -> bool:
        """Check if rule can trigger based on cooldown."""
        if not self.enabled:
            return False

        if self.last_triggered is None:
            return True

        from datetime import timedelta

        cooldown_end = self.last_triggered + timedelta(minutes=self.cooldown_minutes)
        return datetime.utcnow() > cooldown_end

    def trigger(self) -> None:
        """Mark rule as triggered."""
        self.last_triggered = datetime.utcnow()

    def to_dict(self) -> dict:
        """Convert rule to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "condition": self.condition,
            "severity_threshold": self.severity_threshold,
            "alert_type": self.alert_type,
            "pipeline_id": self.pipeline_id,
            "notification_channels": self.notification_channels,
            "cooldown_minutes": self.cooldown_minutes,
            "last_triggered": (
                self.last_triggered.isoformat() if self.last_triggered else None
            ),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class NotificationChannel(Base, IDMixin, TimestampMixin):
    """Notification channel configuration for alerts."""

    __tablename__ = "notification_channels"

    # Basic Information
    name = Column(String(255), nullable=False, index=True)
    channel_type = Column(
        String(50), nullable=False, index=True
    )  # email, slack, webhook, msteams, sms
    enabled = Column(Boolean, default=True, nullable=False)

    # Configuration
    configuration = Column(JSON, nullable=False)  # Channel-specific configuration

    # Settings
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    def to_dict(self, include_config: bool = True) -> dict:
        """Convert channel to dictionary."""
        data = {
            "id": self.id,
            "name": self.name,
            "channel_type": self.channel_type,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

        if include_config:
            data["configuration"] = self.configuration

        return data

    def __repr__(self) -> str:
        return f"<NotificationChannel(id={self.id}, name='{self.name}', type='{self.channel_type}')>"
