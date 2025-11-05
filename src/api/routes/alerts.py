"""
Alerts API Routes

This module contains FastAPI routes for managing security alerts, notifications,
alert rules, and escalation workflows in the SecureOps platform.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..database import get_db
from ..models.alert import Alert, AlertRule, NotificationChannel
from ..models.pipeline import Pipeline
from ..models.user import User
from ..services.alert_service import AlertService
from ..utils.config import settings
<<<<<<< HEAD
from ..utils.logger import get_logger
# from ..main import emit_dashboard_event  # Avoiding circular import
from .auth import get_current_user
from ..utils.rbac import require_role, require_superuser
=======
from ..utils.logger import get_logger, log_api_request, log_security_event
from .auth import get_current_user
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

router = APIRouter()
logger = get_logger(__name__)

<<<<<<< HEAD
# Placeholder logging functions until we implement proper logging
def log_api_request(method: str, path: str, user_id: int):
    logger.info(f"API Request: {method} {path} by user {user_id}")

def log_security_event(event_type: str, description: str, user_id: int, additional_data=None):
    logger.warning(f"Security Event: {event_type} - {description} by user {user_id}")

async def emit_dashboard_event(event_type: str, data: dict):
    """Placeholder for dashboard event emission"""
    logger.info(f"Dashboard Event: {event_type} - {data}")
=======
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

# Pydantic models for request/response
class AlertResponse(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    alert_type: str
    status: str
    pipeline_id: Optional[int]
    pipeline_name: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]
    resolved_at: Optional[datetime]
    resolved_by: Optional[str]
    escalation_level: int
    metadata: Dict[str, Any]


class CreateAlertRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    description: str = Field(..., min_length=1)
<<<<<<< HEAD
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")
    alert_type: str = Field(..., pattern="^(scan|monitoring|system|security)$")
=======
    severity: str = Field(..., regex="^(low|medium|high|critical)$")
    alert_type: str = Field(..., regex="^(scan|monitoring|system|security)$")
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    pipeline_id: Optional[int] = None
    metadata: Dict[str, Any] = {}


class UpdateAlertRequest(BaseModel):
    status: Optional[str] = Field(
<<<<<<< HEAD
    None, pattern="^(open|acknowledged|resolved|closed|false_positive)$"
=======
        None, regex="^(open|acknowledged|resolved|closed|false_positive)$"
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    )
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    resolution_notes: Optional[str] = None


class AlertRuleRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str
    conditions: Dict[str, Any]
<<<<<<< HEAD
    severity_threshold: str = Field("medium", pattern="^(low|medium|high|critical)$")
=======
    severity_threshold: str = Field("medium", regex="^(low|medium|high|critical)$")
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    pipeline_id: Optional[int] = None
    enabled: bool = True
    notification_channels: List[int] = []


class NotificationChannelRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
<<<<<<< HEAD
    channel_type: str = Field(..., pattern="^(email|slack|webhook|msteams|sms)$")
=======
    channel_type: str = Field(..., regex="^(email|slack|webhook|msteams|sms)$")
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    endpoint: str = Field(..., min_length=1)
    configuration: Dict[str, Any] = {}
    pipeline_id: Optional[int] = None
    enabled: bool = True


@router.get("/", response_model=List[AlertResponse])
async def get_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
<<<<<<< HEAD
    severity: Optional[str] = Query(None, pattern="^(low|medium|high|critical)$"),
    status: Optional[str] = Query(
    None, pattern="^(open|acknowledged|resolved|closed|false_positive)$"
    ),
    alert_type: Optional[str] = Query(
    None, pattern="^(scan|monitoring|system|security)$"
    ),
    pipeline_id: Optional[int] = Query(None),
    days_back: Optional[int] = Query(None, ge=1, le=365),
    current_user: User = Depends(require_role("admin", "security", "devops")),
=======
    severity: Optional[str] = Query(None, regex="^(low|medium|high|critical)$"),
    status: Optional[str] = Query(
        None, regex="^(open|acknowledged|resolved|closed|false_positive)$"
    ),
    alert_type: Optional[str] = Query(
        None, regex="^(scan|monitoring|system|security)$"
    ),
    pipeline_id: Optional[int] = Query(None),
    days_back: Optional[int] = Query(None, ge=1, le=365),
    current_user: User = Depends(get_current_user),
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve alerts with filtering and pagination.

    Returns list of alerts matching the specified criteria,
    with optional filtering by severity, status, type, and time range.
    """
    log_api_request("GET", "/alerts/", current_user.id)

    try:
        # Build query with user access control
        query = (
            select(Alert)
            .options(selectinload(Alert.pipeline))
            .join(Pipeline, Alert.pipeline_id == Pipeline.id, isouter=True)
        )

        # Filter by user's accessible pipelines
        if not current_user.is_admin:
            query = query.where(
                or_(
                    Pipeline.owner_id == current_user.id,
                    Alert.pipeline_id.is_(None),  # System alerts
                )
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

        if days_back:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_back)
            query = query.where(Alert.created_at >= cutoff_date)

        # Order by created_at descending and apply pagination
        query = query.order_by(desc(Alert.created_at)).offset(skip).limit(limit)

        result = await db.execute(query)
        alerts = result.scalars().all()

        # Convert to response format
        alert_responses = []
        for alert in alerts:
            alert_response = AlertResponse(
                id=alert.id,
                title=alert.title,
                description=alert.description,
                severity=alert.severity,
                alert_type=alert.alert_type,
                status=alert.status,
                pipeline_id=alert.pipeline_id,
                pipeline_name=alert.pipeline.name if alert.pipeline else None,
                created_at=alert.created_at,
                updated_at=alert.updated_at,
                resolved_at=alert.resolved_at,
                resolved_by=alert.resolved_by,
                escalation_level=alert.escalation_level,
                metadata=alert.metadata or {},
            )
            alert_responses.append(alert_response)

        logger.info(
            f"Retrieved {len(alert_responses)} alerts for user {current_user.id}"
        )
        return alert_responses

    except Exception as e:
        logger.error(f"Error retrieving alerts: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alerts")


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
<<<<<<< HEAD
    current_user: User = Depends(require_role("admin", "security", "devops")),
=======
    current_user: User = Depends(get_current_user),
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    db: AsyncSession = Depends(get_db),
):
    """
    Get specific alert by ID with full details.

    Returns complete alert information including metadata,
    escalation history, and associated pipeline data.
    """
    log_api_request("GET", f"/alerts/{alert_id}", current_user.id)

    try:
        # Query alert with pipeline data
        query = (
            select(Alert)
            .options(selectinload(Alert.pipeline))
            .where(Alert.id == alert_id)
        )

        result = await db.execute(query)
        alert = result.scalar_one_or_none()

        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        # Check access permissions
        if not current_user.is_admin and alert.pipeline:
            if alert.pipeline.owner_id != current_user.id:
                raise HTTPException(
                    status_code=403, detail="Access denied to this alert"
                )

        alert_response = AlertResponse(
            id=alert.id,
            title=alert.title,
            description=alert.description,
            severity=alert.severity,
            alert_type=alert.alert_type,
            status=alert.status,
            pipeline_id=alert.pipeline_id,
            pipeline_name=alert.pipeline.name if alert.pipeline else None,
            created_at=alert.created_at,
            updated_at=alert.updated_at,
            resolved_at=alert.resolved_at,
            resolved_by=alert.resolved_by,
            escalation_level=alert.escalation_level,
            metadata=alert.metadata or {},
        )

        logger.info(f"Retrieved alert {alert_id} for user {current_user.id}")
        return alert_response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving alert {alert_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alert")


@router.post("/", response_model=AlertResponse)
async def create_alert(
    alert_request: CreateAlertRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new security alert.

    Creates alert and triggers notification workflows
    based on severity and configured alert rules.
    """
    log_api_request("POST", "/alerts/", current_user.id)

    try:
        # Validate pipeline access if specified
        if alert_request.pipeline_id:
            pipeline_query = select(Pipeline).where(
                Pipeline.id == alert_request.pipeline_id
            )
            pipeline_result = await db.execute(pipeline_query)
            pipeline = pipeline_result.scalar_one_or_none()

            if not pipeline:
                raise HTTPException(status_code=404, detail="Pipeline not found")

            if not current_user.is_admin and pipeline.owner_id != current_user.id:
                raise HTTPException(
                    status_code=403, detail="Access denied to this pipeline"
                )

        # Create alert using service
        alert_service = AlertService(db)

        alert = await alert_service.create_alert(
            title=alert_request.title,
            description=alert_request.description,
            severity=alert_request.severity,
            alert_type=alert_request.alert_type,
            pipeline_id=alert_request.pipeline_id,
            metadata=alert_request.metadata,
            created_by=current_user.id,
        )

        # Queue alert processing in background
        background_tasks.add_task(alert_service.process_alert_notifications, alert.id)

        # Log security event
        log_security_event(
            f"Alert created: {alert_request.title}",
            severity=alert_request.severity,
            user_id=current_user.id,
            pipeline_id=alert_request.pipeline_id,
            alert_id=alert.id,
        )

        alert_response = AlertResponse(
            id=alert.id,
            title=alert.title,
            description=alert.description,
            severity=alert.severity,
            alert_type=alert.alert_type,
            status=alert.status,
            pipeline_id=alert.pipeline_id,
            pipeline_name=None,  # Will be loaded if needed
            created_at=alert.created_at,
            updated_at=alert.updated_at,
            resolved_at=alert.resolved_at,
            resolved_by=alert.resolved_by,
            escalation_level=alert.escalation_level,
            metadata=alert.metadata or {},
        )

<<<<<<< HEAD

        # Emit real-time event to dashboard WebSocket
        try:
            await emit_dashboard_event(
                event_type="alert_created",
                payload={
                    "id": alert.id,
                    "title": alert.title,
                    "description": alert.description,
                    "severity": alert.severity,
                    "alert_type": alert.alert_type,
                    "status": alert.status,
                    "pipeline_id": alert.pipeline_id,
                    "created_at": alert.created_at.isoformat(),
                    "metadata": alert.metadata or {},
                },
                channel="alerts"
            )
        except Exception as emit_err:
            logger.warning(f"Failed to emit real-time alert event: {emit_err}")

=======
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
        logger.info(f"Created alert {alert.id} for user {current_user.id}")
        return alert_response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating alert: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create alert")


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: int,
    update_request: UpdateAlertRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Update alert status, assignment, or resolution.

    Allows updating alert status, assigning to users,
    adding notes, and marking as resolved.
    """
    log_api_request("PATCH", f"/alerts/{alert_id}", current_user.id)

    try:
        # Get existing alert
        query = (
            select(Alert)
            .options(selectinload(Alert.pipeline))
            .where(Alert.id == alert_id)
        )

        result = await db.execute(query)
        alert = result.scalar_one_or_none()

        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        # Check access permissions
        if not current_user.is_admin and alert.pipeline:
            if alert.pipeline.owner_id != current_user.id:
                raise HTTPException(
                    status_code=403, detail="Access denied to this alert"
                )

        alert_service = AlertService(db)

        # Update alert
        updated_alert = await alert_service.update_alert(
            alert_id=alert_id,
            status=update_request.status,
            assigned_to=update_request.assigned_to,
            notes=update_request.notes,
            resolution_notes=update_request.resolution_notes,
            updated_by=current_user.id,
        )

        # Log status changes
        if update_request.status and update_request.status != alert.status:
            log_security_event(
                f"Alert status changed from {alert.status} to {update_request.status}",
                severity="info",
                user_id=current_user.id,
                alert_id=alert_id,
            )

        # Queue notification for status changes
        if update_request.status in ["resolved", "closed"]:
            background_tasks.add_task(
                alert_service.send_resolution_notification, alert_id, current_user.id
            )

        alert_response = AlertResponse(
            id=updated_alert.id,
            title=updated_alert.title,
            description=updated_alert.description,
            severity=updated_alert.severity,
            alert_type=updated_alert.alert_type,
            status=updated_alert.status,
            pipeline_id=updated_alert.pipeline_id,
            pipeline_name=(
                updated_alert.pipeline.name if updated_alert.pipeline else None
            ),
            created_at=updated_alert.created_at,
            updated_at=updated_alert.updated_at,
            resolved_at=updated_alert.resolved_at,
            resolved_by=updated_alert.resolved_by,
            escalation_level=updated_alert.escalation_level,
            metadata=updated_alert.metadata or {},
        )

        logger.info(f"Updated alert {alert_id} for user {current_user.id}")
        return alert_response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating alert {alert_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update alert")


@router.delete("/{alert_id}")
async def delete_alert(
    alert_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Delete an alert (admin only).

    Permanently removes alert from the system.
    Only available to administrators.
    """
    log_api_request("DELETE", f"/alerts/{alert_id}", current_user.id)

    try:
        if not current_user.is_admin:
            raise HTTPException(
                status_code=403, detail="Only administrators can delete alerts"
            )

        # Get alert
        alert = await db.get(Alert, alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        # Log security event
        log_security_event(
            f"Alert deleted: {alert.title}",
            severity="warning",
            user_id=current_user.id,
            alert_id=alert_id,
        )

        # Delete alert
        await db.delete(alert)
        await db.commit()

        logger.info(f"Deleted alert {alert_id} by admin {current_user.id}")
        return {"message": "Alert deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting alert {alert_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete alert")


@router.get("/statistics/summary")
async def get_alert_statistics(
    days_back: int = Query(30, ge=1, le=365),
    pipeline_id: Optional[int] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get alert statistics and metrics.

    Returns aggregated alert data including counts by severity,
    status distribution, and trends over time.
    """
    log_api_request("GET", "/alerts/statistics/summary", current_user.id)

    try:
        alert_service = AlertService(db)

        statistics = await alert_service.get_alert_statistics(
            user_id=current_user.id, days_back=days_back, pipeline_id=pipeline_id
        )

        logger.info(f"Retrieved alert statistics for user {current_user.id}")
        return statistics

    except Exception as e:
        logger.error(f"Error retrieving alert statistics: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Failed to retrieve alert statistics"
        )


# Alert Rules Management


@router.get("/rules/")
async def get_alert_rules(
    pipeline_id: Optional[int] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get configured alert rules.

    Returns list of alert rules with their conditions
    and notification configurations.
    """
    log_api_request("GET", "/alerts/rules/", current_user.id)

    try:
        query = select(AlertRule)

        # Filter by user's pipelines
        if pipeline_id:
            query = query.where(AlertRule.pipeline_id == pipeline_id)
        elif not current_user.is_admin:
            # Get user's pipelines
            pipeline_query = select(Pipeline.id).where(
                Pipeline.owner_id == current_user.id
            )
            pipeline_result = await db.execute(pipeline_query)
            user_pipeline_ids = [row[0] for row in pipeline_result.fetchall()]

            query = query.where(
                or_(
                    AlertRule.pipeline_id.in_(user_pipeline_ids),
                    AlertRule.pipeline_id.is_(None),  # Global rules
                )
            )

        result = await db.execute(query)
        rules = result.scalars().all()

        logger.info(f"Retrieved {len(rules)} alert rules for user {current_user.id}")
        return [
            {
                "id": rule.id,
                "name": rule.name,
                "description": rule.description,
                "conditions": rule.conditions,
                "severity_threshold": rule.severity_threshold,
                "pipeline_id": rule.pipeline_id,
                "enabled": rule.enabled,
                "created_at": rule.created_at,
                "updated_at": rule.updated_at,
            }
            for rule in rules
        ]

    except Exception as e:
        logger.error(f"Error retrieving alert rules: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alert rules")


@router.post("/rules/")
async def create_alert_rule(
    rule_request: AlertRuleRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create new alert rule.

    Creates alert rule with conditions and notification channels
    for automated alert generation.
    """
    log_api_request("POST", "/alerts/rules/", current_user.id)

    try:
        # Validate pipeline access if specified
        if rule_request.pipeline_id:
            pipeline = await db.get(Pipeline, rule_request.pipeline_id)
            if not pipeline:
                raise HTTPException(status_code=404, detail="Pipeline not found")

            if not current_user.is_admin and pipeline.owner_id != current_user.id:
                raise HTTPException(
                    status_code=403, detail="Access denied to this pipeline"
                )

        alert_service = AlertService(db)

        rule = await alert_service.create_alert_rule(
            name=rule_request.name,
            description=rule_request.description,
            conditions=rule_request.conditions,
            severity_threshold=rule_request.severity_threshold,
            pipeline_id=rule_request.pipeline_id,
            notification_channels=rule_request.notification_channels,
            created_by=current_user.id,
        )

        logger.info(f"Created alert rule {rule.id} for user {current_user.id}")

        return {
            "id": rule.id,
            "name": rule.name,
            "description": rule.description,
            "conditions": rule.conditions,
            "severity_threshold": rule.severity_threshold,
            "pipeline_id": rule.pipeline_id,
            "enabled": rule.enabled,
            "created_at": rule.created_at,
            "message": "Alert rule created successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating alert rule: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create alert rule")


# Notification Channels Management


@router.get("/channels/")
async def get_notification_channels(
    pipeline_id: Optional[int] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get configured notification channels.

    Returns list of notification channels for alerts
    with their configuration and status.
    """
    log_api_request("GET", "/alerts/channels/", current_user.id)

    try:
        query = select(NotificationChannel)

        # Filter by user's pipelines
        if pipeline_id:
            query = query.where(NotificationChannel.pipeline_id == pipeline_id)
        elif not current_user.is_admin:
            # Get user's pipelines
            pipeline_query = select(Pipeline.id).where(
                Pipeline.owner_id == current_user.id
            )
            pipeline_result = await db.execute(pipeline_query)
            user_pipeline_ids = [row[0] for row in pipeline_result.fetchall()]

            query = query.where(
                or_(
                    NotificationChannel.pipeline_id.in_(user_pipeline_ids),
                    NotificationChannel.pipeline_id.is_(None),  # Global channels
                )
            )

        result = await db.execute(query)
        channels = result.scalars().all()

        logger.info(
            f"Retrieved {len(channels)} notification channels for user {current_user.id}"
        )

        return [
            {
                "id": channel.id,
                "name": channel.name,
                "channel_type": channel.channel_type,
                "endpoint": channel.endpoint,
                "configuration": channel.configuration,
                "pipeline_id": channel.pipeline_id,
                "enabled": channel.enabled,
                "created_at": channel.created_at,
                "last_used": channel.last_used,
            }
            for channel in channels
        ]

    except Exception as e:
        logger.error(f"Error retrieving notification channels: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Failed to retrieve notification channels"
        )


@router.post("/channels/")
async def create_notification_channel(
    channel_request: NotificationChannelRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create new notification channel.

    Creates notification channel for alert delivery
    via email, Slack, webhooks, or other services.
    """
    log_api_request("POST", "/alerts/channels/", current_user.id)

    try:
        # Validate pipeline access if specified
        if channel_request.pipeline_id:
            pipeline = await db.get(Pipeline, channel_request.pipeline_id)
            if not pipeline:
                raise HTTPException(status_code=404, detail="Pipeline not found")

            if not current_user.is_admin and pipeline.owner_id != current_user.id:
                raise HTTPException(
                    status_code=403, detail="Access denied to this pipeline"
                )

        alert_service = AlertService(db)

        channel = await alert_service.create_notification_channel(
            name=channel_request.name,
            channel_type=channel_request.channel_type,
            endpoint=channel_request.endpoint,
            configuration=channel_request.configuration,
            pipeline_id=channel_request.pipeline_id,
            created_by=current_user.id,
        )

        logger.info(
            f"Created notification channel {channel.id} for user {current_user.id}"
        )

        return {
            "id": channel.id,
            "name": channel.name,
            "channel_type": channel.channel_type,
            "endpoint": channel.endpoint,
            "configuration": channel.configuration,
            "pipeline_id": channel.pipeline_id,
            "enabled": channel.enabled,
            "created_at": channel.created_at,
            "message": "Notification channel created successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating notification channel: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Failed to create notification channel"
        )


@router.post("/test/{alert_id}")
async def test_alert_notifications(
    alert_id: int,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Test alert notifications for a specific alert.

    Sends test notifications through all configured channels
    to verify notification delivery works correctly.
    """
    log_api_request("POST", f"/alerts/test/{alert_id}", current_user.id)

    try:
        # Get alert
        query = (
            select(Alert)
            .options(selectinload(Alert.pipeline))
            .where(Alert.id == alert_id)
        )

        result = await db.execute(query)
        alert = result.scalar_one_or_none()

        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        # Check access permissions
        if not current_user.is_admin and alert.pipeline:
            if alert.pipeline.owner_id != current_user.id:
                raise HTTPException(
                    status_code=403, detail="Access denied to this alert"
                )

        alert_service = AlertService(db)

        # Queue test notifications
        background_tasks.add_task(
            alert_service.send_test_notifications, alert_id, current_user.id
        )

        logger.info(f"Test notifications queued for alert {alert_id}")

        return {
            "message": "Test notifications queued successfully",
            "alert_id": alert_id,
            "status": "Test notifications will be sent shortly",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error testing alert notifications: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Failed to test alert notifications"
        )
