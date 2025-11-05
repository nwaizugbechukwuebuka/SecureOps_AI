"""
Alert Service Layer

This module provides business logic for managing security alerts,
notifications, and escalation workflows in the SecureOps platform.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, delete, desc, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..models.alert import Alert
from ..models.pipeline import Pipeline
from ..models.user import User
from ..models.vulnerability import Vulnerability
from ..utils.config import settings
from ..utils.logger import get_logger

logger = get_logger(__name__)


class NotificationChannel(Enum):
    """Supported notification channels."""

    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    SMS = "sms"
    TEAMS = "teams"


class AlertService:
    """Service for managing security alerts and notifications."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_user_alerts(
        self,
        user_id: int,
        skip: int = 0,
        limit: int = 100,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        alert_type: Optional[str] = None,
        pipeline_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get paginated list of user's alerts with filtering.

        Args:
            user_id: User ID to filter alerts
            skip: Number of records to skip
            limit: Maximum number of records to return
            severity: Filter by alert severity
            status: Filter by alert status
            alert_type: Filter by alert type
            pipeline_id: Filter by pipeline ID

        Returns:
            List of alert data with related information
        """
        try:
            # Build base query with joins
            query = (
                select(Alert)
                .options(
                    selectinload(Alert.pipeline), selectinload(Alert.vulnerability)
                )
                .join(Pipeline)
                .where(Pipeline.owner_id == user_id)
            )

            # Apply filters
            if severity:
                query = query.where(Alert.severity == severity)
            if status:
                query = query.where(Alert.status == status)
            if alert_type:
                query = query.where(Alert.alert_type == alert_type)
            if pipeline_id:
                query = query.where(Alert.pipeline_id == pipeline_id)

            # Add ordering and pagination
            query = query.order_by(desc(Alert.created_at)).offset(skip).limit(limit)

            # Execute query
            result = await self.db.execute(query)
            alerts = result.scalars().all()

            # Build response data
            alert_data = []
            for alert in alerts:
                alert_dict = {
                    "id": alert.id,
                    "title": alert.title,
                    "message": alert.message,
                    "alert_type": alert.alert_type,
                    "severity": alert.severity,
                    "status": alert.status,
                    "pipeline_id": alert.pipeline_id,
                    "pipeline_name": alert.pipeline.name if alert.pipeline else None,
                    "vulnerability_id": alert.vulnerability_id,
                    "source": alert.source,
                    "metadata": alert.metadata or {},
                    "acknowledged_at": alert.acknowledged_at,
                    "acknowledged_by": alert.acknowledged_by,
                    "resolved_at": alert.resolved_at,
                    "resolved_by": alert.resolved_by,
                    "notification_sent": alert.notification_sent,
                    "escalation_level": alert.escalation_level,
                    "created_at": alert.created_at,
                    "updated_at": alert.updated_at,
                }

                # Add vulnerability details if available
                if alert.vulnerability:
                    alert_dict["vulnerability_details"] = {
                        "title": alert.vulnerability.title,
                        "severity": alert.vulnerability.severity,
                        "cve_id": alert.vulnerability.cve_id,
                        "cvss_score": alert.vulnerability.cvss_score,
                    }

                alert_data.append(alert_dict)

            return alert_data

        except Exception as e:
            logger.error(f"Error getting user alerts: {str(e)}")
            raise

    async def get_alert_by_id(
        self, alert_id: int, user_id: int
    ) -> Optional[Dict[str, Any]]:
        """
        Get specific alert by ID with detailed information.

        Args:
            alert_id: Alert ID
            user_id: User ID for ownership verification

        Returns:
            Alert data with related information or None if not found
        """
        try:
            query = (
                select(Alert)
                .options(
                    selectinload(Alert.pipeline), selectinload(Alert.vulnerability)
                )
                .join(Pipeline)
                .where(and_(Alert.id == alert_id, Pipeline.owner_id == user_id))
            )

            result = await self.db.execute(query)
            alert = result.scalar_one_or_none()

            if not alert:
                return None

            alert_data = {
                "id": alert.id,
                "title": alert.title,
                "message": alert.message,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "status": alert.status,
                "pipeline_id": alert.pipeline_id,
                "pipeline_name": alert.pipeline.name if alert.pipeline else None,
                "vulnerability_id": alert.vulnerability_id,
                "source": alert.source,
                "metadata": alert.metadata or {},
                "acknowledged_at": alert.acknowledged_at,
                "acknowledged_by": alert.acknowledged_by,
                "resolved_at": alert.resolved_at,
                "resolved_by": alert.resolved_by,
                "notification_sent": alert.notification_sent,
                "escalation_level": alert.escalation_level,
                "created_at": alert.created_at,
                "updated_at": alert.updated_at,
            }

            # Add related data
            if alert.pipeline:
                alert_data["pipeline_details"] = {
                    "name": alert.pipeline.name,
                    "repository_url": alert.pipeline.repository_url,
                    "ci_cd_platform": alert.pipeline.ci_cd_platform,
                }

            if alert.vulnerability:
                alert_data["vulnerability_details"] = {
                    "title": alert.vulnerability.title,
                    "description": alert.vulnerability.description,
                    "severity": alert.vulnerability.severity,
                    "cve_id": alert.vulnerability.cve_id,
                    "cvss_score": alert.vulnerability.cvss_score,
                    "file_path": alert.vulnerability.file_path,
                    "remediation": alert.vulnerability.remediation,
                }

            return alert_data

        except Exception as e:
            logger.error(f"Error getting alert {alert_id}: {str(e)}")
            raise

    async def create_alert(
        self,
        title: str,
        message: str,
        alert_type: str,
        severity: str,
        pipeline_id: int,
        vulnerability_id: Optional[int] = None,
        source: str = "system",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Alert:
        """
        Create new security alert.

        Args:
            title: Alert title
            message: Alert description
            alert_type: Type of alert
            severity: Alert severity level
            pipeline_id: Associated pipeline ID
            vulnerability_id: Associated vulnerability ID (optional)
            source: Alert source system
            metadata: Additional alert metadata

        Returns:
            Created alert object
        """
        try:
            alert = Alert(
                title=title,
                message=message,
                alert_type=alert_type,
                severity=severity,
                status="open",
                pipeline_id=pipeline_id,
                vulnerability_id=vulnerability_id,
                source=source,
                metadata=metadata or {},
                escalation_level=0,
                notification_sent=False,
                created_at=datetime.now(timezone.utc),
            )

            self.db.add(alert)
            await self.db.commit()
            await self.db.refresh(alert)

            # Trigger notification processing
            await self._process_alert_notifications(alert)

            logger.info(f"Created alert {alert.id} for pipeline {pipeline_id}")
            return alert

        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error creating alert: {str(e)}")
            raise

    async def acknowledge_alert(
        self, alert_id: int, user_id: int, notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Acknowledge an alert.

        Args:
            alert_id: Alert ID to acknowledge
            user_id: User ID acknowledging the alert
            notes: Optional acknowledgment notes

        Returns:
            Updated alert data
        """
        try:
            # Update alert
            update_data = {
                "status": "acknowledged",
                "acknowledged_at": datetime.now(timezone.utc),
                "acknowledged_by": user_id,
                "updated_at": datetime.now(timezone.utc),
            }

            if notes:
                metadata = {"acknowledgment_notes": notes}
                update_data["metadata"] = metadata

            query = update(Alert).where(Alert.id == alert_id).values(update_data)
            await self.db.execute(query)
            await self.db.commit()

            logger.info(f"Acknowledged alert {alert_id} by user {user_id}")

            # Return updated alert (simplified for ownership check)
            return await self.get_alert_by_id(alert_id, user_id)

        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error acknowledging alert {alert_id}: {str(e)}")
            raise

    async def resolve_alert(
        self, alert_id: int, user_id: int, resolution_notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Resolve an alert.

        Args:
            alert_id: Alert ID to resolve
            user_id: User ID resolving the alert
            resolution_notes: Optional resolution notes

        Returns:
            Updated alert data
        """
        try:
            # Update alert
            update_data = {
                "status": "resolved",
                "resolved_at": datetime.now(timezone.utc),
                "resolved_by": user_id,
                "updated_at": datetime.now(timezone.utc),
            }

            if resolution_notes:
                metadata = {"resolution_notes": resolution_notes}
                update_data["metadata"] = metadata

            query = update(Alert).where(Alert.id == alert_id).values(update_data)
            await self.db.execute(query)
            await self.db.commit()

            logger.info(f"Resolved alert {alert_id} by user {user_id}")

            # Return updated alert
            return await self.get_alert_by_id(alert_id, user_id)

        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error resolving alert {alert_id}: {str(e)}")
            raise

    async def delete_alert(self, alert_id: int) -> None:
        """
        Delete an alert.

        Args:
            alert_id: Alert ID to delete
        """
        try:
            query = delete(Alert).where(Alert.id == alert_id)
            await self.db.execute(query)
            await self.db.commit()

            logger.info(f"Deleted alert {alert_id}")

        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error deleting alert {alert_id}: {str(e)}")
            raise

    async def get_alert_statistics(
        self, user_id: int, days_back: int = 30
    ) -> Dict[str, Any]:
        """
        Get alert statistics for user's pipelines.

        Args:
            user_id: User ID
            days_back: Number of days to include in statistics

        Returns:
            Dictionary containing alert metrics
        """
        try:
            start_date = datetime.now(timezone.utc) - timedelta(days=days_back)

            # Get alert counts by status
            status_query = (
                select(func.count(Alert.id).label("count"), Alert.status)
                .join(Pipeline)
                .where(
                    and_(Pipeline.owner_id == user_id, Alert.created_at >= start_date)
                )
                .group_by(Alert.status)
            )

            status_result = await self.db.execute(status_query)
            status_counts = {
                status: count for count, status in status_result.fetchall()
            }

            # Get alert counts by severity
            severity_query = (
                select(func.count(Alert.id).label("count"), Alert.severity)
                .join(Pipeline)
                .where(
                    and_(Pipeline.owner_id == user_id, Alert.created_at >= start_date)
                )
                .group_by(Alert.severity)
            )

            severity_result = await self.db.execute(severity_query)
            severity_counts = {
                severity: count for count, severity in severity_result.fetchall()
            }

            # Get daily trends
            daily_query = (
                select(
                    func.count(Alert.id).label("count"),
                    func.date_trunc("day", Alert.created_at).label("date"),
                )
                .join(Pipeline)
                .where(
                    and_(Pipeline.owner_id == user_id, Alert.created_at >= start_date)
                )
                .group_by(func.date_trunc("day", Alert.created_at))
                .order_by("date")
            )

            daily_result = await self.db.execute(daily_query)
            daily_counts = {
                date.strftime("%Y-%m-%d"): count
                for count, date in daily_result.fetchall()
            }

            # Calculate response times
            response_time_query = (
                select(
                    func.avg(
                        func.extract("epoch", Alert.acknowledged_at - Alert.created_at)
                    ).label("avg_response_time")
                )
                .join(Pipeline)
                .where(
                    and_(
                        Pipeline.owner_id == user_id,
                        Alert.acknowledged_at.isnot(None),
                        Alert.created_at >= start_date,
                    )
                )
            )

            response_result = await self.db.execute(response_time_query)
            avg_response_time = response_result.scalar() or 0

            return {
                "period_days": days_back,
                "total_alerts": sum(status_counts.values()),
                "status_breakdown": status_counts,
                "severity_breakdown": severity_counts,
                "daily_trends": daily_counts,
                "avg_response_time_seconds": round(avg_response_time, 2),
                "open_alerts": status_counts.get("open", 0),
                "critical_alerts": severity_counts.get("critical", 0),
            }

        except Exception as e:
            logger.error(f"Error getting alert statistics: {str(e)}")
            raise

    async def get_notification_channels(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Get user's configured notification channels.

        Args:
            user_id: User ID

        Returns:
            List of notification channel configurations
        """
        try:
            # Get user's notification preferences
            user_query = select(User).where(User.id == user_id)
            result = await self.db.execute(user_query)
            user = result.scalar_one_or_none()

            if not user:
                return []

            # Extract notification channels from user preferences
            preferences = user.preferences or {}
            notifications = preferences.get("notifications", {})

            channels = []

            # Email channel
            if notifications.get("email", {}).get("enabled", True):
                channels.append(
                    {
                        "type": "email",
                        "name": "Email Notifications",
                        "enabled": True,
                        "config": {
                            "email": user.email,
                            "severity_filter": notifications.get("email", {}).get(
                                "severity_filter", ["critical", "high"]
                            ),
                        },
                    }
                )

            # Slack channel
            if notifications.get("slack", {}).get("enabled", False):
                slack_config = notifications.get("slack", {})
                channels.append(
                    {
                        "type": "slack",
                        "name": "Slack Notifications",
                        "enabled": True,
                        "config": {
                            "webhook_url": slack_config.get("webhook_url"),
                            "channel": slack_config.get("channel", "#security"),
                            "severity_filter": slack_config.get(
                                "severity_filter", ["critical", "high"]
                            ),
                        },
                    }
                )

            # Webhook channel
            if notifications.get("webhook", {}).get("enabled", False):
                webhook_config = notifications.get("webhook", {})
                channels.append(
                    {
                        "type": "webhook",
                        "name": "Custom Webhook",
                        "enabled": True,
                        "config": {
                            "url": webhook_config.get("url"),
                            "headers": webhook_config.get("headers", {}),
                            "severity_filter": webhook_config.get(
                                "severity_filter", ["critical", "high"]
                            ),
                        },
                    }
                )

            return channels

        except Exception as e:
            logger.error(f"Error getting notification channels: {str(e)}")
            raise

    async def update_notification_channels(
        self, user_id: int, channels: List[Dict[str, Any]]
    ) -> None:
        """
        Update user's notification channel configurations.

        Args:
            user_id: User ID
            channels: List of channel configurations to update
        """
        try:
            # Get current user
            user_query = select(User).where(User.id == user_id)
            result = await self.db.execute(user_query)
            user = result.scalar_one_or_none()

            if not user:
                raise ValueError("User not found")

            # Update preferences
            preferences = user.preferences or {}
            notifications = preferences.get("notifications", {})

            for channel in channels:
                channel_type = channel.get("type")
                if channel_type in ["email", "slack", "webhook", "teams", "sms"]:
                    notifications[channel_type] = {
                        "enabled": channel.get("enabled", False),
                        **channel.get("config", {}),
                    }

            preferences["notifications"] = notifications

            # Update user preferences
            update_query = (
                update(User)
                .where(User.id == user_id)
                .values(
                    {
                        "preferences": preferences,
                        "updated_at": datetime.now(timezone.utc),
                    }
                )
            )
            await self.db.execute(update_query)
            await self.db.commit()

            logger.info(f"Updated notification channels for user {user_id}")

        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error updating notification channels: {str(e)}")
            raise

    async def test_notification_channel(
        self, user_id: int, channel_type: str, config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Test notification channel configuration.

        Args:
            user_id: User ID
            channel_type: Type of notification channel
            config: Channel configuration

        Returns:
            Test result with success status and details
        """
        try:
            test_message = {
                "title": "SecureOps Test Alert",
                "message": "This is a test notification from SecureOps platform.",
                "severity": "info",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            success = False
            error_message = None

            try:
                if channel_type == "email":
                    success = await self._send_email_notification(
                        config.get("email"), test_message
                    )
                elif channel_type == "slack":
                    success = await self._send_slack_notification(
                        config.get("webhook_url"),
                        config.get("channel", "#security"),
                        test_message,
                    )
                elif channel_type == "webhook":
                    success = await self._send_webhook_notification(
                        config.get("url"), config.get("headers", {}), test_message
                    )
                else:
                    error_message = f"Unsupported channel type: {channel_type}"

            except Exception as e:
                error_message = str(e)
                success = False

            return {
                "success": success,
                "channel_type": channel_type,
                "message": (
                    "Test notification sent successfully" if success else error_message
                ),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            logger.error(f"Error testing notification channel: {str(e)}")
            raise

    async def create_vulnerability_alert(
        self, vulnerability_id: int, pipeline_id: int
    ) -> Alert:
        """
        Create alert for new vulnerability detection.

        Args:
            vulnerability_id: Vulnerability ID
            pipeline_id: Pipeline ID

        Returns:
            Created alert object
        """
        try:
            # Get vulnerability details
            vuln_query = select(Vulnerability).where(
                Vulnerability.id == vulnerability_id
            )
            result = await self.db.execute(vuln_query)
            vulnerability = result.scalar_one_or_none()

            if not vulnerability:
                raise ValueError("Vulnerability not found")

            # Create alert
            alert = await self.create_alert(
                title=f"New {vulnerability.severity.upper()} vulnerability detected",
                message=f"Vulnerability '{vulnerability.title}' found in {vulnerability.file_path}",
                alert_type="vulnerability",
                severity=vulnerability.severity,
                pipeline_id=pipeline_id,
                vulnerability_id=vulnerability_id,
                source="scanner",
                metadata={
                    "cve_id": vulnerability.cve_id,
                    "cvss_score": vulnerability.cvss_score,
                    "scanner_type": vulnerability.scanner_type,
                    "file_path": vulnerability.file_path,
                },
            )

            return alert

        except Exception as e:
            logger.error(f"Error creating vulnerability alert: {str(e)}")
            raise

    # Private helper methods
    async def _process_alert_notifications(self, alert: Alert) -> None:
        """Process notifications for new alert."""
        try:
            # Get pipeline owner for notification preferences
            pipeline_query = (
                select(Pipeline)
                .options(selectinload(Pipeline.owner))
                .where(Pipeline.id == alert.pipeline_id)
            )

            result = await self.db.execute(pipeline_query)
            pipeline = result.scalar_one_or_none()

            if not pipeline or not pipeline.owner:
                return

            # Get notification channels
            channels = await self.get_notification_channels(pipeline.owner.id)

            # Send notifications based on severity and channel configuration
            notification_tasks = []
            for channel in channels:
                if self._should_notify_channel(alert.severity, channel):
                    task = self._send_alert_notification(alert, channel)
                    notification_tasks.append(task)

            # Execute all notifications concurrently
            if notification_tasks:
                await asyncio.gather(*notification_tasks, return_exceptions=True)

                # Mark alert as notified
                update_query = (
                    update(Alert)
                    .where(Alert.id == alert.id)
                    .values(
                        {
                            "notification_sent": True,
                            "updated_at": datetime.now(timezone.utc),
                        }
                    )
                )
                await self.db.execute(update_query)
                await self.db.commit()

        except Exception as e:
            logger.error(f"Error processing alert notifications: {str(e)}")

    def _should_notify_channel(
        self, alert_severity: str, channel: Dict[str, Any]
    ) -> bool:
        """Check if channel should receive notification based on severity filter."""
        severity_filter = channel.get("config", {}).get(
            "severity_filter", ["critical", "high"]
        )
        return alert_severity in severity_filter

    async def _send_alert_notification(
        self, alert: Alert, channel: Dict[str, Any]
    ) -> None:
        """Send alert notification to specific channel."""
        try:
            channel_type = channel.get("type")
            config = channel.get("config", {})

            message = {
                "title": alert.title,
                "message": alert.message,
                "severity": alert.severity,
                "alert_type": alert.alert_type,
                "pipeline_id": alert.pipeline_id,
                "timestamp": alert.created_at.isoformat(),
                "metadata": alert.metadata,
            }

            if channel_type == "email":
                await self._send_email_notification(config.get("email"), message)
            elif channel_type == "slack":
                await self._send_slack_notification(
                    config.get("webhook_url"),
                    config.get("channel", "#security"),
                    message,
                )
            elif channel_type == "webhook":
                await self._send_webhook_notification(
                    config.get("url"), config.get("headers", {}), message
                )

        except Exception as e:
            logger.error(
                f"Error sending notification to {channel.get('type')}: {str(e)}"
            )

    async def _send_email_notification(
        self, email: str, message: Dict[str, Any]
    ) -> bool:
        """Send email notification (placeholder implementation)."""
        # In production, this would integrate with an email service
        logger.info(f"Sending email notification to {email}: {message.get('title')}")
        return True

    async def _send_slack_notification(
        self, webhook_url: str, channel: str, message: Dict[str, Any]
    ) -> bool:
        """Send Slack notification (placeholder implementation)."""
        # In production, this would make HTTP request to Slack webhook
        logger.info(f"Sending Slack notification to {channel}: {message.get('title')}")
        return True

    async def _send_webhook_notification(
        self, url: str, headers: Dict[str, str], message: Dict[str, Any]
    ) -> bool:
        """Send webhook notification (placeholder implementation)."""
        # In production, this would make HTTP request to webhook URL
        logger.info(f"Sending webhook notification to {url}: {message.get('title')}")
        return True
