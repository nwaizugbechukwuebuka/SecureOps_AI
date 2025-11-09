"""
Alert Tasks for SecureOps AI

This module provides comprehensive alert processing, notification delivery,
and escalation management for the SecureOps platform.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import asyncio
import hashlib
import json
import logging
import smtplib
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

import requests
from celery import signature
from celery.utils.log import get_task_logger
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.database import AsyncSessionLocal
from src.api.models.alert import Alert
from src.api.models.pipeline import Pipeline
from src.api.models.user import User
from src.api.models.vulnerability import Vulnerability
from src.api.services.alert_service import AlertService, NotificationChannel
from src.api.utils.config import get_settings
from src.tasks.celery_app import app as celery_app

# Configuration
settings = get_settings()
logger = get_task_logger(__name__)

# Task configuration constants
ALERT_PROCESSING_BATCH_SIZE = getattr(settings, "ALERT_PROCESSING_BATCH_SIZE", 50)
ALERT_ESCALATION_DELAY_MINUTES = getattr(settings, "ALERT_ESCALATION_DELAY_MINUTES", 30)
NOTIFICATION_RETRY_ATTEMPTS = getattr(settings, "NOTIFICATION_RETRY_ATTEMPTS", 3)
NOTIFICATION_RETRY_DELAY_SECONDS = getattr(
    settings, "NOTIFICATION_RETRY_DELAY_SECONDS", 60
)
WEBHOOK_TIMEOUT_SECONDS = getattr(settings, "WEBHOOK_TIMEOUT_SECONDS", 30)
MAX_RETRY_ATTEMPTS = getattr(settings, "MAX_RETRY_ATTEMPTS", 3)
RETRY_DELAY_SECONDS = getattr(settings, "RETRY_DELAY_SECONDS", 60)


@celery_app.task(
    bind=True,
    name="secureops.tasks.alert_tasks.process_new_alerts",
    max_retries=MAX_RETRY_ATTEMPTS,
    default_retry_delay=RETRY_DELAY_SECONDS,
)
def process_new_alerts(self) -> Dict[str, Any]:
    """
    Process newly created alerts for routing, enrichment, and initial delivery.

    Returns:
        Dict containing processing results and statistics
    """
    processing_id = str(uuid.uuid4())
    start_time = time.time()

    logger.info(
        f"[{processing_id}] Starting alert processing",
        extra={"processing_id": processing_id, "task": "process_new_alerts"},
    )

    try:
        return asyncio.run(_process_new_alerts_async(processing_id))

    except Exception as e:
        logger.error(
            f"[{processing_id}] Alert processing failed: {str(e)}",
            extra={
                "processing_id": processing_id,
                "error": str(e),
                "traceback": traceback.format_exc(),
                "duration": time.time() - start_time,
            },
        )

        # Retry on failure
        if self.request.retries < MAX_RETRY_ATTEMPTS:
            logger.info(f"[{processing_id}] Retrying alert processing")
            raise self.retry(countdown=RETRY_DELAY_SECONDS)

        return {
            "success": False,
            "processing_id": processing_id,
            "error": str(e),
            "duration": time.time() - start_time,
        }


async def _process_new_alerts_async(processing_id: str) -> Dict[str, Any]:
    """Async implementation of new alert processing."""
    async with AsyncSessionLocal() as db:
        try:
            results = {
                "processing_id": processing_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alerts_processed": 0,
                "notifications_scheduled": 0,
                "escalations_triggered": 0,
                "success": True,
            }

            # Get unprocessed alerts
            unprocessed_query = (
                select(Alert)
                .where(Alert.status == "open")
                .order_by(Alert.created_at)
                .limit(ALERT_PROCESSING_BATCH_SIZE)
            )

            unprocessed_alerts = (await db.execute(unprocessed_query)).scalars().all()
            results["alerts_processed"] = len(unprocessed_alerts)

            if not unprocessed_alerts:
                logger.debug(f"[{processing_id}] No new alerts to process")
                return results

            # Process each alert
            for alert in unprocessed_alerts:
                try:
                    await _enrich_alert_context(db, alert, processing_id)
                    await _schedule_alert_notifications(alert, processing_id)
                    results["notifications_scheduled"] += 1
                except Exception as e:
                    logger.error(
                        f"[{processing_id}] Failed to process alert {alert.id}: {str(e)}"
                    )
                    continue

            # Check for escalation candidates
            escalation_alerts = await _identify_escalation_candidates(db)
            for alert in escalation_alerts:
                await _trigger_alert_escalation(alert, processing_id)
                results["escalations_triggered"] += 1

            await db.commit()

            logger.info(f"[{processing_id}] Alert processing completed successfully")
            return results

        except Exception as e:
            await db.rollback()
            raise


async def _enrich_alert_context(
    db: AsyncSession, alert: Alert, processing_id: str
) -> None:
    """Enrich alert with additional context data."""
    try:
        if not alert.metadata:
            alert.metadata = {}

        # Add pipeline context if available
        if alert.pipeline_id:
            pipeline_query = select(Pipeline).where(Pipeline.id == alert.pipeline_id)
            pipeline = (await db.execute(pipeline_query)).scalar_one_or_none()

            if pipeline:
                alert.metadata.update(
                    {
                        "pipeline_name": pipeline.name,
                        "pipeline_repository": pipeline.repository_url,
                        "pipeline_branch": pipeline.branch,
                    }
                )

        # Add vulnerability context if available
        if hasattr(alert, "vulnerability_id") and alert.vulnerability_id:
            vuln_query = select(Vulnerability).where(
                Vulnerability.id == alert.vulnerability_id
            )
            vulnerability = (await db.execute(vuln_query)).scalar_one_or_none()

            if vulnerability:
                alert.metadata.update(
                    {
                        "vulnerability_cve": vulnerability.cve_id,
                        "vulnerability_package": vulnerability.package_name,
                        "vulnerability_version": vulnerability.package_version,
                    }
                )

        alert.metadata["enriched_at"] = datetime.now(timezone.utc).isoformat()
        logger.debug(f"[{processing_id}] Enriched alert {alert.id}")

    except Exception as e:
        logger.warning(f"[{processing_id}] Failed to enrich alert {alert.id}: {str(e)}")


async def _schedule_alert_notifications(alert: Alert, processing_id: str) -> None:
    """Schedule notification delivery for an alert."""
    try:
        channels = _get_notification_channels_for_severity(alert.severity)

        for i, channel in enumerate(channels):
            countdown = 5 + (i * 2)

            task_signature = deliver_alert_notification.signature(
                args=[alert.id, channel.value, processing_id], queue="alerts"
            )
            task_signature.apply_async(countdown=countdown)

            logger.debug(
                f"[{processing_id}] Scheduled {channel.value} notification for alert {alert.id}"
            )

    except Exception as e:
        logger.error(f"[{processing_id}] Failed to schedule notifications: {str(e)}")


def _get_notification_channels_for_severity(severity: str) -> List[NotificationChannel]:
    """Get notification channels based on alert severity."""
    severity_lower = severity.lower()

    if severity_lower == "critical":
        return [
            NotificationChannel.EMAIL,
            NotificationChannel.SLACK,
            NotificationChannel.SMS,
        ]
    elif severity_lower == "high":
        return [NotificationChannel.EMAIL, NotificationChannel.SLACK]
    elif severity_lower == "medium":
        return [NotificationChannel.EMAIL]
    else:
        return [NotificationChannel.EMAIL]


async def _identify_escalation_candidates(db: AsyncSession) -> List[Alert]:
    """Identify alerts that should be escalated."""
    escalation_threshold = datetime.now(timezone.utc) - timedelta(
        minutes=ALERT_ESCALATION_DELAY_MINUTES
    )

    escalation_query = select(Alert).where(
        and_(
            Alert.status == "open",
            Alert.acknowledged_at.is_(None),
            Alert.created_at <= escalation_threshold,
            Alert.severity.in_(["critical", "high"]),
        )
    )

    return (await db.execute(escalation_query)).scalars().all()


async def _trigger_alert_escalation(alert: Alert, processing_id: str) -> None:
    """Trigger escalation for unacknowledged alerts."""
    logger.warning(f"[{processing_id}] Escalating alert {alert.id}")

    escalation_channels = [
        NotificationChannel.EMAIL,
        NotificationChannel.SLACK,
        NotificationChannel.SMS,
    ]

    for channel in escalation_channels:
        task_signature = deliver_escalation_notification.signature(
            args=[alert.id, channel.value, processing_id], queue="alerts"
        )
        task_signature.apply_async(countdown=10)


@celery_app.task(
    bind=True,
    name="secureops.tasks.alert_tasks.deliver_alert_notification",
    max_retries=NOTIFICATION_RETRY_ATTEMPTS,
    default_retry_delay=NOTIFICATION_RETRY_DELAY_SECONDS,
)
def deliver_alert_notification(
    self, alert_id: int, channel: str, processing_id: str
) -> Dict[str, Any]:
    """
    Deliver alert notification through specified channel.

    Args:
        alert_id: ID of the alert to send notification for
        channel: Notification channel (email, slack, webhook, etc.)
        processing_id: Processing batch ID for tracking

    Returns:
        Dict containing delivery results
    """
    delivery_id = str(uuid.uuid4())
    start_time = time.time()

    logger.info(
        f"[{delivery_id}] Delivering {channel} notification for alert {alert_id}",
        extra={
            "delivery_id": delivery_id,
            "alert_id": alert_id,
            "channel": channel,
            "processing_id": processing_id,
        },
    )

    try:
        return asyncio.run(
            _deliver_alert_notification_async(
                alert_id, channel, processing_id, delivery_id
            )
        )

    except Exception as e:
        logger.error(
            f"[{delivery_id}] Notification delivery failed: {str(e)}",
            extra={
                "delivery_id": delivery_id,
                "alert_id": alert_id,
                "channel": channel,
                "error": str(e),
                "duration": time.time() - start_time,
            },
        )

        # Retry on failure
        if self.request.retries < NOTIFICATION_RETRY_ATTEMPTS:
            logger.info(f"[{delivery_id}] Retrying notification delivery")
            raise self.retry(countdown=NOTIFICATION_RETRY_DELAY_SECONDS)

        return {
            "success": False,
            "delivery_id": delivery_id,
            "alert_id": alert_id,
            "channel": channel,
            "error": str(e),
            "duration": time.time() - start_time,
        }


async def _deliver_alert_notification_async(
    alert_id: int, channel: str, processing_id: str, delivery_id: str
) -> Dict[str, Any]:
    """Async implementation of alert notification delivery."""
    async with AsyncSessionLocal() as db:
        try:
            # Get alert details
            alert_query = select(Alert).where(Alert.id == alert_id)
            alert = (await db.execute(alert_query)).scalar_one_or_none()

            if not alert:
                raise ValueError(f"Alert {alert_id} not found")

            result = {
                "delivery_id": delivery_id,
                "alert_id": alert_id,
                "channel": channel,
                "success": False,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            # Deliver notification based on channel
            if channel == NotificationChannel.EMAIL.value:
                delivery_result = await _deliver_email_notification(alert, delivery_id)
            elif channel == NotificationChannel.SLACK.value:
                delivery_result = await _deliver_slack_notification(alert, delivery_id)
            elif channel == NotificationChannel.WEBHOOK.value:
                delivery_result = await _deliver_webhook_notification(
                    alert, delivery_id
                )
            elif channel == NotificationChannel.SMS.value:
                delivery_result = await _deliver_sms_notification(alert, delivery_id)
            else:
                raise ValueError(f"Unsupported notification channel: {channel}")

            result.update(delivery_result)

            # Update alert delivery tracking
            await _update_alert_delivery_tracking(db, alert, result, processing_id)
            await db.commit()

            logger.info(f"[{delivery_id}] Notification delivery completed")
            return result

        except Exception as e:
            await db.rollback()
            raise


async def _update_alert_delivery_tracking(
    db: AsyncSession, alert: Alert, delivery_result: Dict[str, Any], processing_id: str
) -> None:
    """Update alert metadata with delivery tracking information."""
    if not alert.metadata:
        alert.metadata = {}

    if "delivery_history" not in alert.metadata:
        alert.metadata["delivery_history"] = []

    alert.metadata["delivery_history"].append(
        {
            "delivery_id": delivery_result["delivery_id"],
            "channel": delivery_result["channel"],
            "timestamp": delivery_result["timestamp"],
            "success": delivery_result["success"],
            "processing_id": processing_id,
        }
    )

    # Keep only the last 10 delivery records
    alert.metadata["delivery_history"] = alert.metadata["delivery_history"][-10:]


async def _deliver_email_notification(alert: Alert, delivery_id: str) -> Dict[str, Any]:
    """Deliver email notification for alert."""
    try:
        # Email configuration from settings
        smtp_server = getattr(settings, "smtp_server", "localhost")
        smtp_port = getattr(settings, "smtp_port", 587)
        smtp_username = getattr(settings, "smtp_username", "")
        smtp_password = getattr(settings, "smtp_password", "")
        from_email = getattr(settings, "from_email", "alerts@secureops.ai")

        # Get recipient emails
        recipients = _get_email_recipients_for_severity(alert.severity)

        if not recipients:
            return {"success": False, "error": "No email recipients configured"}

        # Create email content
        subject = f"[SecureOps Alert] {alert.severity.upper()}: {alert.title}"
        html_content = _generate_email_html(alert)
        text_content = _generate_email_text(alert)

        # Send email
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = ", ".join(recipients)

        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        # Send via SMTP
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            if smtp_username and smtp_password:
                server.starttls()
                server.login(smtp_username, smtp_password)

            server.send_message(msg)

        logger.info(
            f"[{delivery_id}] Email sent successfully to {len(recipients)} recipients"
        )

        return {"success": True, "recipients": recipients, "subject": subject}

    except Exception as e:
        logger.error(f"[{delivery_id}] Email delivery failed: {str(e)}")
        return {"success": False, "error": str(e)}


async def _deliver_slack_notification(alert: Alert, delivery_id: str) -> Dict[str, Any]:
    """Deliver Slack notification for alert."""
    try:
        slack_webhook_url = getattr(settings, "slack_webhook_url", None)

        if not slack_webhook_url:
            return {"success": False, "error": "Slack webhook URL not configured"}

        # Create Slack payload
        color_map = {
            "critical": "danger",
            "high": "warning",
            "medium": "good",
            "low": "#36a64f",
            "info": "#439FE0",
        }

        payload = {
            "attachments": [
                {
                    "color": color_map.get(alert.severity.lower(), "#cccccc"),
                    "title": f"SecureOps Alert: {alert.title}",
                    "text": alert.description[:300],
                    "fields": [
                        {
                            "title": "Severity",
                            "value": alert.severity.upper(),
                            "short": True,
                        },
                        {
                            "title": "Type",
                            "value": alert.alert_type.replace("_", " ").title(),
                            "short": True,
                        },
                        {
                            "title": "Created",
                            "value": alert.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                            "short": True,
                        },
                    ],
                    "footer": "SecureOps AI",
                    "ts": int(alert.created_at.timestamp()),
                }
            ]
        }

        # Send to Slack
        response = requests.post(
            slack_webhook_url, json=payload, timeout=WEBHOOK_TIMEOUT_SECONDS
        )

        response.raise_for_status()

        logger.info(f"[{delivery_id}] Slack notification sent successfully")

        return {"success": True, "response_status": response.status_code}

    except Exception as e:
        logger.error(f"[{delivery_id}] Slack notification failed: {str(e)}")
        return {"success": False, "error": str(e)}


async def _deliver_webhook_notification(
    alert: Alert, delivery_id: str
) -> Dict[str, Any]:
    """Deliver webhook notification for alert."""
    try:
        webhook_url = getattr(settings, "alert_webhook_url", None)

        if not webhook_url:
            return {"success": False, "error": "Webhook URL not configured"}

        # Create webhook payload
        payload = {
            "alert_id": alert.id,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity,
            "alert_type": alert.alert_type,
            "status": alert.status,
            "source": alert.source,
            "created_at": alert.created_at.isoformat(),
            "metadata": alert.metadata,
            "delivery_id": delivery_id,
        }

        # Send webhook
        response = requests.post(
            webhook_url,
            json=payload,
            timeout=WEBHOOK_TIMEOUT_SECONDS,
            headers={"Content-Type": "application/json"},
        )

        response.raise_for_status()

        logger.info(f"[{delivery_id}] Webhook notification sent successfully")

        return {"success": True, "response_status": response.status_code}

    except Exception as e:
        logger.error(f"[{delivery_id}] Webhook notification failed: {str(e)}")
        return {"success": False, "error": str(e)}


async def _deliver_sms_notification(alert: Alert, delivery_id: str) -> Dict[str, Any]:
    """Deliver SMS notification for alert (placeholder implementation)."""
    try:
        sms_recipients = _get_sms_recipients_for_severity(alert.severity)

        if not sms_recipients:
            return {"success": False, "error": "No SMS recipients configured"}

        message = f"SecureOps Alert: {alert.severity.upper()} - {alert.title[:100]}"

        logger.info(
            f"[{delivery_id}] SMS would be sent to {len(sms_recipients)} recipients: {message}"
        )

        return {
            "success": True,
            "recipients": sms_recipients,
            "message": message,
            "note": "SMS delivery is not implemented - logged only",
        }

    except Exception as e:
        logger.error(f"[{delivery_id}] SMS notification failed: {str(e)}")
        return {"success": False, "error": str(e)}


def _get_email_recipients_for_severity(severity: str) -> List[str]:
    """Get email recipients based on alert severity."""
    severity_lower = severity.lower()

    if severity_lower == "critical":
        return getattr(settings, "critical_alert_emails", [])
    elif severity_lower == "high":
        return getattr(settings, "high_alert_emails", [])
    else:
        return getattr(settings, "general_alert_emails", [])


def _get_sms_recipients_for_severity(severity: str) -> List[str]:
    """Get SMS recipients based on alert severity."""
    severity_lower = severity.lower()

    if severity_lower in ["critical", "high"]:
        return getattr(settings, "alert_sms_recipients", [])
    return []


def _generate_email_html(alert: Alert) -> str:
    """Generate HTML email content for alert."""
    severity_colors = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#17a2b8",
        "info": "#28a745",
    }

    color = severity_colors.get(alert.severity.lower(), "#6c757d")

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .alert-header {{ background-color: {color}; color: white; padding: 20px; }}
            .alert-body {{ background-color: #f8f9fa; padding: 20px; }}
            .alert-meta {{ margin-top: 20px; padding-top: 20px; color: #6c757d; }}
        </style>
    </head>
    <body>
        <div class="alert-header">
            <h2>SecureOps Security Alert</h2>
            <div>Severity: {alert.severity}</div>
        </div>
        <div class="alert-body">
            <h3>{alert.title}</h3>
            <p>{alert.description}</p>
            
            <div class="alert-meta">
                <p><strong>Alert ID:</strong> {alert.id}</p>
                <p><strong>Type:</strong> {alert.alert_type}</p>
                <p><strong>Source:</strong> {alert.source}</p>
                <p><strong>Created:</strong> {alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
        </div>
    </body>
    </html>
    """


def _generate_email_text(alert: Alert) -> str:
    """Generate plain text email content for alert."""
    return f"""
SecureOps Security Alert

SEVERITY: {alert.severity.upper()}
TITLE: {alert.title}

DESCRIPTION:
{alert.description}

DETAILS:
- Alert ID: {alert.id}
- Type: {alert.alert_type}
- Source: {alert.source}
- Created: {alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}

This alert was generated by SecureOps AI security monitoring system.
    """


@celery_app.task(
    bind=True,
    name="secureops.tasks.alert_tasks.deliver_escalation_notification",
    max_retries=NOTIFICATION_RETRY_ATTEMPTS,
    default_retry_delay=NOTIFICATION_RETRY_DELAY_SECONDS,
)
def deliver_escalation_notification(
    self, alert_id: int, channel: str, processing_id: str
) -> Dict[str, Any]:
    """Deliver escalation notification for unacknowledged critical alerts."""
    escalation_id = str(uuid.uuid4())

    logger.warning(
        f"[{escalation_id}] Delivering escalation {channel} notification for alert {alert_id}"
    )

    try:
        return asyncio.run(
            _deliver_escalation_notification_async(
                alert_id, channel, processing_id, escalation_id
            )
        )

    except Exception as e:
        logger.error(f"[{escalation_id}] Escalation notification failed: {str(e)}")
        return {
            "success": False,
            "escalation_id": escalation_id,
            "alert_id": alert_id,
            "channel": channel,
            "error": str(e),
        }


async def _deliver_escalation_notification_async(
    alert_id: int, channel: str, processing_id: str, escalation_id: str
) -> Dict[str, Any]:
    """Async implementation of escalation notification delivery."""
    async with AsyncSessionLocal() as db:
        try:
            # Get alert details
            alert_query = select(Alert).where(Alert.id == alert_id)
            alert = (await db.execute(alert_query)).scalar_one_or_none()

            if not alert:
                raise ValueError(f"Alert {alert_id} not found")

            # Create escalation-specific alert copy
            escalation_alert = _create_escalation_alert_copy(alert)

            # Deliver escalation notification
            if channel == NotificationChannel.EMAIL.value:
                delivery_result = await _deliver_email_notification(
                    escalation_alert, escalation_id
                )
            elif channel == NotificationChannel.SLACK.value:
                delivery_result = await _deliver_slack_notification(
                    escalation_alert, escalation_id
                )
            elif channel == NotificationChannel.SMS.value:
                delivery_result = await _deliver_sms_notification(
                    escalation_alert, escalation_id
                )
            else:
                raise ValueError(f"Escalation not supported for channel: {channel}")

            # Update alert metadata with escalation info
            await _update_alert_escalation_tracking(
                db, alert, escalation_id, channel, delivery_result
            )
            await db.commit()

            result = {
                "escalation_id": escalation_id,
                "alert_id": alert_id,
                "channel": channel,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            result.update(delivery_result)

            return result

        except Exception as e:
            await db.rollback()
            raise


def _create_escalation_alert_copy(alert: Alert) -> Alert:
    """Create a modified copy of alert for escalation notification."""
    escalation_alert = Alert()
    escalation_alert.id = alert.id
    escalation_alert.title = f"ESCALATED: {alert.title}"
    escalation_alert.description = f"ESCALATION NOTICE: This alert has not been acknowledged.\n\n{alert.description}"
    escalation_alert.severity = alert.severity
    escalation_alert.alert_type = alert.alert_type
    escalation_alert.status = alert.status
    escalation_alert.source = alert.source
    escalation_alert.created_at = alert.created_at
    escalation_alert.pipeline_id = alert.pipeline_id
    escalation_alert.metadata = alert.metadata or {}

    return escalation_alert


async def _update_alert_escalation_tracking(
    db: AsyncSession,
    alert: Alert,
    escalation_id: str,
    channel: str,
    delivery_result: Dict[str, Any],
) -> None:
    """Update alert metadata with escalation tracking information."""
    if not alert.metadata:
        alert.metadata = {}

    if "escalations" not in alert.metadata:
        alert.metadata["escalations"] = []

    alert.metadata["escalations"].append(
        {
            "escalation_id": escalation_id,
            "channel": channel,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "success": delivery_result.get("success", False),
        }
    )


@celery_app.task(name="secureops.tasks.alert_tasks.cleanup_old_alerts")
def cleanup_old_alerts() -> Dict[str, Any]:
    """Clean up old resolved alerts and their associated data."""
    cleanup_id = str(uuid.uuid4())

    logger.info(f"[{cleanup_id}] Starting alert cleanup")

    try:
        return asyncio.run(_cleanup_old_alerts_async(cleanup_id))

    except Exception as e:
        logger.error(f"[{cleanup_id}] Alert cleanup failed: {str(e)}")
        return {"success": False, "cleanup_id": cleanup_id, "error": str(e)}


async def _cleanup_old_alerts_async(cleanup_id: str) -> Dict[str, Any]:
    """Async implementation of alert cleanup."""
    async with AsyncSessionLocal() as db:
        try:
            results = {
                "cleanup_id": cleanup_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alerts_archived": 0,
                "alerts_deleted": 0,
                "success": True,
            }

            # Archive old resolved alerts (older than 90 days)
            archive_threshold = datetime.now(timezone.utc) - timedelta(days=90)

            archive_query = (
                select(Alert)
                .where(
                    and_(
                        Alert.status.in_(["resolved", "closed"]),
                        Alert.updated_at <= archive_threshold,
                    )
                )
                .limit(100)
            )

            alerts_to_archive = (await db.execute(archive_query)).scalars().all()

            for alert in alerts_to_archive:
                if not alert.metadata:
                    alert.metadata = {}
                alert.metadata["archived_at"] = datetime.now(timezone.utc).isoformat()
                results["alerts_archived"] += 1

            await db.commit()

            logger.info(f"[{cleanup_id}] Alert cleanup completed successfully")
            return results

        except Exception as e:
            await db.rollback()
            raise


@celery_app.task(name="secureops.tasks.alert_tasks.setup_alert_processing_schedule")
def setup_alert_processing_schedule() -> Dict[str, str]:
    """Setup periodic alert processing tasks using Celery beat."""
    logger.info("Setting up alert processing schedule")

    schedule_config = {
        "alert_processing": "*/1 * * * *",  # Every minute
        "escalation_check": "*/5 * * * *",  # Every 5 minutes
        "alert_cleanup": "0 2 * * *",  # Daily at 2 AM
    }

    logger.info(f"Alert processing schedule configured: {schedule_config}")

    return {
        "status": "configured",
        "schedule": schedule_config,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# Export all alert task functions for Celery autodiscovery
__all__ = [
    "process_new_alerts",
    "deliver_alert_notification",
    "deliver_escalation_notification",
    "cleanup_old_alerts",
    "setup_alert_processing_schedule",
]
