
# === STUBS FOR UNDEFINED HELPERS (placed before usage) ===
import warnings

async def _generate_digest_content(*args, **kwargs):
    warnings.warn("_generate_digest_content is a stub and must be implemented.")
    return None

async def _get_digest_recipients(*args, **kwargs):
    warnings.warn("_get_digest_recipients is a stub and must be implemented.")
    return []

async def _get_escalation_channels(*args, **kwargs):
    warnings.warn("_get_escalation_channels is a stub and must be implemented.")
    return []

async def _generate_escalation_content(*args, **kwargs):
    warnings.warn("_generate_escalation_content is a stub and must be implemented.")
    return {"subject": "[ESCALATION]", "message": "Escalation content not implemented.", "meta_data": {}}

def _is_within_notification_hours(*args, **kwargs):
    warnings.warn("_is_within_notification_hours is a stub and must be implemented.")
    return True
"""
Alert Processing Background Tasks

This module contains Celery tasks for processing security alerts, sending notifications,
and managing alert workflows asynchronously.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import json
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from celery import Celery
from celery.utils.log import get_task_logger
from jinja2 import Template

from src.api.database import AsyncSessionLocal
from src.api.models.alert import Alert, AlertRule, NotificationChannel
from src.api.models.pipeline import Pipeline
from src.api.models.user import User
from src.api.utils.config import settings
from src.api.utils.logger import get_logger

# Import the main Celery app
from src.tasks.celery_app import app as celery_app

logger = get_task_logger(__name__)


@celery_app.task(bind=True, name="secureops.tasks.alert_tasks.process_alert")
def process_alert(self, alert_id: int):
    """
    Process a security alert, determine recipients, and send notifications.

    Args:
        alert_id: ID of the alert to process
    """
    logger.info(f"Processing alert {alert_id}")

    try:
        import asyncio

        # Process the alert asynchronously
        result = asyncio.run(_process_alert_async(alert_id))

        logger.info(f"Alert {alert_id} processed successfully")
        return result

    except Exception as e:
        logger.error(f"Failed to process alert {alert_id}: {str(e)}")
        raise


@celery_app.task(bind=True, name="secureops.tasks.alert_tasks.send_notification")
def send_notification(
    self,
    notification_id: str,
    channel_type: str,
    recipient: str,
    subject: str,
    message: str,
    meta_data: Dict[str, Any] = None,
):
    """
    Send a notification through specified channel.

    Args:
        notification_id: Unique identifier for the notification
        channel_type: Type of notification channel (email, slack, webhook, etc.)
        recipient: Recipient address or endpoint
        subject: Notification subject
        message: Notification message/content
    meta_data: Additional meta data for the notification
    """
    logger.info(f"Sending {channel_type} notification {notification_id} to {recipient}")

    try:
        import asyncio

        result = asyncio.run(
            _send_notification_async(
                notification_id=notification_id,
                channel_type=channel_type,
                recipient=recipient,
                subject=subject,
                message=message,
                meta_data=meta_data or {},
            )
        )

        logger.info(f"Notification {notification_id} sent successfully")
        return result

    except Exception as e:
        logger.error(f"Failed to send notification {notification_id}: {str(e)}")
        raise


@celery_app.task(bind=True, name="secureops.tasks.alert_tasks.escalate_alert")
def escalate_alert(self, alert_id: int, escalation_level: int):
    """
    Escalate an alert to higher severity or different recipients.

    Args:
        alert_id: ID of the alert to escalate
        escalation_level: Level of escalation (1, 2, 3, etc.)
    """
    logger.info(f"Escalating alert {alert_id} to level {escalation_level}")

    try:
        import asyncio

        result = asyncio.run(_escalate_alert_async(alert_id, escalation_level))

        logger.info(f"Alert {alert_id} escalated to level {escalation_level}")
        return result

    except Exception as e:
        logger.error(f"Failed to escalate alert {alert_id}: {str(e)}")
        raise


@celery_app.task(bind=True, name="secureops.tasks.alert_tasks.digest_alerts")
def digest_alerts(self, pipeline_id: Optional[int] = None, time_range: str = "24h"):
    """
    Create and send alert digest for specified time range.

    Args:
        pipeline_id: Optional pipeline ID to filter alerts
        time_range: Time range for digest (1h, 4h, 24h, 7d)
    """
    logger.info(f"Creating alert digest for time range {time_range}")

    try:
        import asyncio

        result = asyncio.run(_create_alert_digest_async(pipeline_id, time_range))

        logger.info(f"Alert digest created and sent for {time_range}")
        return result

    except Exception as e:
        logger.error(f"Failed to create alert digest: {str(e)}")
        raise


@celery_app.task(bind=True, name="secureops.tasks.alert_tasks.cleanup_old_alerts")
def cleanup_old_alerts(self, retention_days: int = 90):
    """
    Clean up old resolved alerts based on retention policy.

    Args:
        retention_days: Number of days to retain resolved alerts
    """
    logger.info(f"Cleaning up alerts older than {retention_days} days")

    try:
        import asyncio

        result = asyncio.run(_cleanup_old_alerts_async(retention_days))

        logger.info(f"Cleaned up {result['cleaned_count']} old alerts")
        return result

    except Exception as e:
        logger.error(f"Failed to cleanup old alerts: {str(e)}")
        raise


# Async implementation functions


async def _process_alert_async(alert_id: int) -> Dict[str, Any]:
    """Process alert and determine notification actions."""
    try:
        async with AsyncSessionLocal() as db:
            # Get alert with related data
            from sqlalchemy import select
            from sqlalchemy.orm import selectinload

            query = (
                select(Alert)
                .options(selectinload(Alert.pipeline), selectinload(Alert.rule))
                .where(Alert.id == alert_id)
            )

            result = await db.execute(query)
            alert = result.scalar_one_or_none()

            if not alert:
                raise ValueError(f"Alert {alert_id} not found")

            # Update alert status to processing
            alert.status = "processing"
            alert.processed_at = datetime.now(timezone.utc)
            await db.commit()

            # Determine notification recipients and channels
            notifications = await _determine_notifications(alert)

            # Send notifications
            notification_results = []
            for notification in notifications:
                try:
                    # Send notification asynchronously
                    send_notification.delay(
                        notification_id=f"{alert_id}_{notification['channel_id']}",
                        channel_type=notification["channel_type"],
                        recipient=notification["recipient"],
                        subject=notification["subject"],
                        message=notification["message"],
                        metadata=notification["metadata"],
                    )

                    notification_results.append(
                        {
                            "channel_type": notification["channel_type"],
                            "recipient": notification["recipient"],
                            "status": "queued",
                        }
                    )

                except Exception as e:
                    logger.error(f"Failed to queue notification: {str(e)}")
                    notification_results.append(
                        {
                            "channel_type": notification["channel_type"],
                            "recipient": notification["recipient"],
                            "status": "failed",
                            "error": str(e),
                        }
                    )

            # Update alert status
            alert.status = "notified"
            alert.notification_sent = True
            await db.commit()

            # Schedule escalation if needed
            escalation_delay = _get_escalation_delay(alert.severity)
            if escalation_delay:
                escalate_alert.apply_async(
                    args=[alert_id, 1], countdown=escalation_delay
                )

            return {
                "alert_id": alert_id,
                "status": "processed",
                "notifications_sent": len(notification_results),
                "notifications": notification_results,
            }

    except Exception as e:
        # Update alert status to failed
        async with AsyncSessionLocal() as db:
            alert = await db.get(Alert, alert_id)
            if alert:
                alert.status = "failed"
                alert.error_message = str(e)
                await db.commit()
        raise


async def _send_notification_async(
    notification_id: str,
    channel_type: str,
    recipient: str,
    subject: str,
    message: str,
    metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """Send notification through specified channel."""
    try:
        if channel_type == "email":
            return await _send_email_notification(recipient, subject, message, metadata)
        elif channel_type == "slack":
            return await _send_slack_notification(recipient, subject, message, metadata)
        elif channel_type == "webhook":
            return await _send_webhook_notification(
                recipient, subject, message, metadata
            )
        elif channel_type == "msteams":
            return await _send_msteams_notification(
                recipient, subject, message, metadata
            )
        else:
            raise ValueError(f"Unsupported channel type: {channel_type}")

    except Exception as e:
        logger.error(f"Failed to send {channel_type} notification: {str(e)}")
        return {"notification_id": notification_id, "status": "failed", "error": str(e)}


async def _escalate_alert_async(alert_id: int, escalation_level: int) -> Dict[str, Any]:
    """Escalate alert to higher level."""
    try:
        async with AsyncSessionLocal() as db:
            alert = await db.get(Alert, alert_id)
            if not alert:
                raise ValueError(f"Alert {alert_id} not found")

            # Check if alert is still active
            if alert.status in ["resolved", "acknowledged"]:
                logger.info(
                    f"Alert {alert_id} already resolved/acknowledged, skipping escalation"
                )
                return {"status": "skipped", "reason": "alert_resolved"}

            # Update alert escalation level
            alert.escalation_level = escalation_level
            alert.last_escalated_at = datetime.now(timezone.utc)

            # Determine escalation recipients
            escalation_notifications = await _determine_escalation_notifications(
                alert, escalation_level
            )

            # Send escalation notifications
            for notification in escalation_notifications:
                send_notification.delay(
                    notification_id=f"{alert_id}_escalation_{escalation_level}_{notification['channel_id']}",
                    channel_type=notification["channel_type"],
                    recipient=notification["recipient"],
                    subject=notification["subject"],
                    message=notification["message"],
                    metadata=notification["metadata"],
                )

            await db.commit()

            # Schedule next escalation if needed
            next_escalation_delay = _get_escalation_delay(
                alert.severity, escalation_level + 1
            )
            if (
                next_escalation_delay and escalation_level < 3
            ):  # Max 3 escalation levels
                escalate_alert.apply_async(
                    args=[alert_id, escalation_level + 1],
                    countdown=next_escalation_delay,
                )

            return {
                "alert_id": alert_id,
                "escalation_level": escalation_level,
                "notifications_sent": len(escalation_notifications),
            }

    except Exception as e:
        logger.error(f"Failed to escalate alert {alert_id}: {str(e)}")
        raise


async def _create_alert_digest_async(
    pipeline_id: Optional[int], time_range: str
) -> Dict[str, Any]:
    """Create and send alert digest."""
    try:
        # Parse time range
        time_delta = _parse_time_range(time_range)
        start_time = datetime.now(timezone.utc) - time_delta

        async with AsyncSessionLocal() as db:
            from sqlalchemy import and_, select

            # Build query for alerts in time range
            query = select(Alert).where(
                and_(
                    Alert.created_at >= start_time,
                    Alert.created_at <= datetime.now(timezone.utc),
                )
            )

            if pipeline_id:
                query = query.where(Alert.pipeline_id == pipeline_id)

            result = await db.execute(query)
            alerts = result.scalars().all()

            if not alerts:
                logger.info(f"No alerts found for digest in time range {time_range}")
                return {"status": "no_alerts", "time_range": time_range}

            # Generate digest content
            digest_content = await _generate_digest_content(
                alerts, time_range, pipeline_id
            )

            # Determine digest recipients
            digest_recipients = await _get_digest_recipients(pipeline_id)

            # Send digest notifications
            notifications_sent = 0
            for recipient in digest_recipients:
                try:
                    send_notification.delay(
                        notification_id=f"digest_{time_range}_{pipeline_id or 'all'}_{datetime.now().timestamp()}",
                        channel_type=recipient["channel_type"],
                        recipient=recipient["address"],
                        subject=f"Security Alert Digest - {time_range}",
                        message=digest_content,
                        metadata={
                            "digest_type": "alert_digest",
                            "time_range": time_range,
                            "pipeline_id": pipeline_id,
                            "alert_count": len(alerts),
                        },
                    )
                    notifications_sent += 1
                except Exception as e:
                    logger.error(
                        f"Failed to send digest to {recipient['address']}: {str(e)}"
                    )

            return {
                "status": "sent",
                "time_range": time_range,
                "alert_count": len(alerts),
                "recipients": notifications_sent,
            }

    except Exception as e:
        logger.error(f"Failed to create alert digest: {str(e)}")
        raise


async def _cleanup_old_alerts_async(retention_days: int) -> Dict[str, Any]:
    """Clean up old resolved alerts."""
    try:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)

        async with AsyncSessionLocal() as db:
            from sqlalchemy import and_, delete, select

            # Count alerts to be deleted
            count_query = select(Alert).where(
                and_(
                    Alert.status.in_(["resolved", "closed"]),
                    Alert.resolved_at < cutoff_date,
                )
            )

            result = await db.execute(count_query)
            alerts_to_delete = len(result.scalars().all())

            # Delete old alerts
            delete_query = delete(Alert).where(
                and_(
                    Alert.status.in_(["resolved", "closed"]),
                    Alert.resolved_at < cutoff_date,
                )
            )

            await db.execute(delete_query)
            await db.commit()

            logger.info(f"Cleaned up {alerts_to_delete} old alerts")

            return {
                "status": "completed",
                "cleaned_count": alerts_to_delete,
                "cutoff_date": cutoff_date.isoformat(),
            }

    except Exception as e:
        logger.error(f"Failed to cleanup old alerts: {str(e)}")
        raise


# Notification channel implementations


async def _send_email_notification(
    recipient: str, subject: str, message: str, metadata: Dict[str, Any]
) -> Dict[str, Any]:
    """Send email notification."""
    try:
        # Create email message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.EMAIL_FROM
        msg["To"] = recipient

        # Create HTML and text versions
        html_content = await _render_email_template(message, metadata)
        text_content = _html_to_text(html_content)

        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        # Send email
        with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as server:
            if settings.EMAIL_USE_TLS:
                server.starttls()
            if settings.EMAIL_USERNAME:
                server.login(settings.EMAIL_USERNAME, settings.EMAIL_PASSWORD)

            server.send_message(msg)

        return {"status": "sent", "channel_type": "email", "recipient": recipient}

    except Exception as e:
        logger.error(f"Failed to send email to {recipient}: {str(e)}")
        raise


async def _send_slack_notification(
    webhook_url: str, subject: str, message: str, metadata: Dict[str, Any]
) -> Dict[str, Any]:
    """Send Slack notification."""
    try:
        # Format message for Slack
        slack_message = {
            "text": subject,
            "attachments": [
                {
                    "color": _get_slack_color(metadata.get("severity", "medium")),
                    "fields": [
                        {"title": "Alert Details", "value": message, "short": False}
                    ],
                    "footer": "SecureOps Security Platform",
                    "ts": int(datetime.now().timestamp()),
                }
            ],
        }

        # Add additional fields if available
        if metadata.get("pipeline_name"):
            slack_message["attachments"][0]["fields"].append(
                {"title": "Pipeline", "value": metadata["pipeline_name"], "short": True}
            )

        if metadata.get("severity"):
            slack_message["attachments"][0]["fields"].append(
                {
                    "title": "Severity",
                    "value": metadata["severity"].upper(),
                    "short": True,
                }
            )

        # Send to Slack
        response = requests.post(webhook_url, json=slack_message)
        response.raise_for_status()

        return {"status": "sent", "channel_type": "slack", "recipient": webhook_url}

    except Exception as e:
        logger.error(f"Failed to send Slack notification: {str(e)}")
        raise


async def _send_webhook_notification(
    webhook_url: str, subject: str, message: str, metadata: Dict[str, Any]
) -> Dict[str, Any]:
    """Send webhook notification."""
    try:
        payload = {
            "subject": subject,
            "message": message,
            "metadata": metadata,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        response = requests.post(
            webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        response.raise_for_status()

        return {
            "status": "sent",
            "channel_type": "webhook",
            "recipient": webhook_url,
            "response_status": response.status_code,
        }

    except Exception as e:
        logger.error(f"Failed to send webhook notification: {str(e)}")
        raise


async def _send_msteams_notification(
    webhook_url: str, subject: str, message: str, metadata: Dict[str, Any]
) -> Dict[str, Any]:
    """Send Microsoft Teams notification."""
    try:
        # Format message for Teams
        teams_message = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": _get_teams_color(metadata.get("severity", "medium")),
            "summary": subject,
            "sections": [
                {
                    "activityTitle": subject,
                    "activitySubtitle": f"SecureOps Alert - {metadata.get('severity', 'Unknown').upper()}",
                    "facts": [{"name": "Message", "value": message}],
                    "markdown": True,
                }
            ],
        }

        # Add additional facts if available
        if metadata.get("pipeline_name"):
            teams_message["sections"][0]["facts"].append(
                {"name": "Pipeline", "value": metadata["pipeline_name"]}
            )

        if metadata.get("alert_id"):
            teams_message["sections"][0]["facts"].append(
                {"name": "Alert ID", "value": str(metadata["alert_id"])}
            )

        # Send to Teams
        response = requests.post(webhook_url, json=teams_message)
        response.raise_for_status()

        return {"status": "sent", "channel_type": "msteams", "recipient": webhook_url}

    except Exception as e:
        logger.error(f"Failed to send Teams notification: {str(e)}")
        raise


# Utility functions


async def _determine_notifications(alert: Alert) -> List[Dict[str, Any]]:
    """Determine notification recipients and channels for alert."""
    notifications = []

    try:
        async with AsyncSessionLocal() as db:
            # Get notification channels for the alert's pipeline
            from sqlalchemy import select

            query = select(NotificationChannel).where(
                NotificationChannel.pipeline_id == alert.pipeline_id
            )

            result = await db.execute(query)
            channels = result.scalars().all()

            for channel in channels:
                # Check if channel should receive this alert
                if _should_notify_channel(channel, alert):
                    notification_content = await _generate_notification_content(
                        alert, channel
                    )

                    notifications.append(
                        {
                            "channel_id": channel.id,
                            "channel_type": channel.channel_type,
                            "recipient": channel.endpoint,
                            "subject": notification_content["subject"],
                            "message": notification_content["message"],
                            "metadata": notification_content["metadata"],
                        }
                    )

        return notifications

    except Exception as e:
        logger.error(f"Failed to determine notifications: {str(e)}")
        return []


async def _determine_escalation_notifications(
    alert: Alert, escalation_level: int
) -> List[Dict[str, Any]]:
    """Determine escalation notification recipients."""
    notifications = []

    try:
        # Get escalation channels (typically different from regular notifications)
        escalation_channels = await _get_escalation_channels(
            alert.pipeline_id, escalation_level
        )

        for channel in escalation_channels:
            content = await _generate_escalation_content(
                alert, escalation_level, channel
            )

            notifications.append(
                {
                    "channel_id": f"escalation_{channel['id']}",
                    "channel_type": channel["channel_type"],
                    "recipient": channel["endpoint"],
                    "subject": content["subject"],
                    "message": content["message"],
                    "metadata": content["metadata"],
                }
            )

        return notifications

    except Exception as e:
        logger.error(f"Failed to determine escalation notifications: {str(e)}")
        return []


def _should_notify_channel(channel: NotificationChannel, alert: Alert) -> bool:
    """Check if a notification channel should receive this alert."""
    try:
        # Check severity threshold
        severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        alert_severity = severity_levels.get(alert.severity, 0)
        min_severity = severity_levels.get(
            channel.configuration.get("min_severity", "low"), 0
        )

        if alert_severity < min_severity:
            return False

        # Check time restrictions
        if not _is_within_notification_hours(channel.configuration):
            return False

        # Check alert type filters
        allowed_types = channel.configuration.get("alert_types", [])
        if allowed_types and alert.alert_type not in allowed_types:
            return False

        return True

    except Exception as e:
        logger.error(f"Error checking notification channel: {str(e)}")
        return False


def _get_escalation_delay(severity: str, level: int = 1) -> Optional[int]:
    """Get escalation delay in seconds based on severity and level."""
    delays = {
        "critical": {1: 300, 2: 600, 3: 1800},  # 5min, 10min, 30min
        "high": {1: 900, 2: 1800, 3: 3600},  # 15min, 30min, 1hour
        "medium": {1: 3600, 2: 7200, 3: 14400},  # 1hour, 2hours, 4hours
        "low": {},  # No escalation for low severity
    }

    return delays.get(severity, {}).get(level)


def _parse_time_range(time_range: str) -> timedelta:
    """Parse time range string to timedelta."""
    if time_range.endswith("h"):
        hours = int(time_range[:-1])
        return timedelta(hours=hours)
    elif time_range.endswith("d"):
        days = int(time_range[:-1])
        return timedelta(days=days)
    else:
        raise ValueError(f"Invalid time range format: {time_range}")


def _get_slack_color(severity: str) -> str:
    """Get Slack color for severity level."""
    colors = {
        "critical": "#FF0000",
        "high": "#FF8C00",
        "medium": "#FFD700",
        "low": "#90EE90",
    }
    return colors.get(severity, "#808080")


def _get_teams_color(severity: str) -> str:
    """Get Teams color for severity level."""
    colors = {
        "critical": "FF0000",
        "high": "FF8C00",
        "medium": "FFD700",
        "low": "90EE90",
    }
    return colors.get(severity, "808080")


async def _render_email_template(message: str, metadata: Dict[str, Any]) -> str:
    """Render email template with alert data."""
    template_str = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .header { background-color: #f4f4f4; padding: 20px; border-radius: 5px; }
            .severity-{{ severity }} { border-left: 5px solid {{ severity_color }}; padding-left: 15px; }
            .details { margin: 20px 0; }
            .footer { margin-top: 30px; font-size: 12px; color: #666; }
        </style>
    </head>
    <body>
        <div class="header severity-{{ severity }}">
            <h2>Security Alert: {{ title }}</h2>
            <p><strong>Severity:</strong> {{ severity|upper }}</p>
            {% if pipeline_name %}
            <p><strong>Pipeline:</strong> {{ pipeline_name }}</p>
            {% endif %}
        </div>
        
        <div class="details">
            <p>{{ message }}</p>
            
            {% if metadata.scan_results_summary %}
            <h3>Scan Results Summary:</h3>
            <ul>
                <li>Critical Issues: {{ metadata.scan_results_summary.critical }}</li>
                <li>High Issues: {{ metadata.scan_results_summary.high }}</li>
                <li>Total Issues: {{ metadata.scan_results_summary.total }}</li>
            </ul>
            {% endif %}
        </div>
        
        <div class="footer">
            <p>This alert was generated by SecureOps Security Platform</p>
            <p>Alert ID: {{ alert_id }}</p>
            <p>Timestamp: {{ timestamp }}</p>
        </div>
    </body>
    </html>
    """

    template = Template(template_str)

    severity_colors = {
        "critical": "#FF0000",
        "high": "#FF8C00",
        "medium": "#FFD700",
        "low": "#90EE90",
    }

    return template.render(
        message=message,
        severity=metadata.get("severity", "medium"),
        severity_color=severity_colors.get(
            metadata.get("severity", "medium"), "#808080"
        ),
        title=metadata.get("title", "Security Alert"),
        pipeline_name=metadata.get("pipeline_name"),
        alert_id=metadata.get("alert_id"),
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        metadata=metadata,
    )


def _html_to_text(html: str) -> str:
    """Convert HTML to plain text."""
    import re

    # Remove HTML tags
    text = re.sub("<[^<]+?>", "", html)

    # Decode HTML entities
    import html as html_lib

    text = html_lib.unescape(text)

    # Clean up whitespace
    text = re.sub(r"\s+", " ", text)
    text = text.strip()

    return text


async def _generate_notification_content(
    alert: Alert, channel: NotificationChannel
) -> Dict[str, Any]:
    """Generate notification content for alert and channel."""
    # This would typically use templates based on channel type
    subject = f"[{alert.severity.upper()}] {alert.title}"

    message = f"""
    Security Alert: {alert.title}
    
    Severity: {alert.severity.upper()}
    Pipeline: {alert.pipeline.name if alert.pipeline else 'Unknown'}
    
    Description:
    {alert.description}
    
    Time: {alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
    """

    metadata = {
        "alert_id": alert.id,
        "severity": alert.severity,
        "alert_type": alert.alert_type,
        "pipeline_name": alert.pipeline.name if alert.pipeline else None,
        "pipeline_id": alert.pipeline_id,
    }

    return {"subject": subject, "message": message, "metadata": metadata}


# Additional utility functions would be implemented here...
# _generate_escalation_content, _get_escalation_channels, etc.
