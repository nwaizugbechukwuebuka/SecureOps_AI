"""
Dashboard and system monitoring routes for SecureOps AI
System metrics, security events, automation tasks, and notifications
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, and_
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from database import get_db, SecurityEvent
from models import AutomationTask, Notification, SystemLog
from schemas import (
    SecurityEventResponse, AutomationTaskResponse, NotificationResponse,
    SystemMetricsResponse, DashboardStatsResponse, PaginatedResponse
)
from routers.auth import get_current_user
from utils.security import log_security_event

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

@router.get("/stats", response_model=DashboardStatsResponse)
async def get_dashboard_stats(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get overall dashboard statistics"""
    
    # Get date range for recent activities (last 24 hours)
    since_yesterday = datetime.utcnow() - timedelta(hours=24)
    
    # Count security events by severity (last 24h)
    security_events_today = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.timestamp >= since_yesterday
    ).scalar() or 0
    
    critical_events_today = db.query(func.count(SecurityEvent.id)).filter(
        and_(
            SecurityEvent.timestamp >= since_yesterday,
            SecurityEvent.severity == "critical"
        )
    ).scalar() or 0
    
    # Count automation tasks by status
    automation_tasks_running = db.query(func.count(AutomationTask.id)).filter(
        AutomationTask.status == "running"
    ).scalar() or 0
    
    automation_tasks_total = db.query(func.count(AutomationTask.id)).scalar() or 0
    
    # Count unread notifications for current user
    unread_notifications = db.query(func.count(Notification.id)).filter(
        and_(
            Notification.user_id == current_user.get("user_id"),
            Notification.read == False
        )
    ).scalar() or 0
    
    # System health metrics (simulated for now)
    system_uptime = "99.8%"
    cpu_usage = 45.2
    memory_usage = 62.1
    disk_usage = 34.7
    
    return DashboardStatsResponse(
        security_events_today=security_events_today,
        critical_events_today=critical_events_today,
        automation_tasks_running=automation_tasks_running,
        automation_tasks_total=automation_tasks_total,
        unread_notifications=unread_notifications,
        system_uptime=system_uptime,
        cpu_usage=cpu_usage,
        memory_usage=memory_usage,
        disk_usage=disk_usage
    )

@router.get("/security-events", response_model=PaginatedResponse[SecurityEventResponse])
async def get_security_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    hours: int = Query(24, description="Hours to look back"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get security events with filtering and pagination"""
    
    # Calculate time range
    since_time = datetime.utcnow() - timedelta(hours=hours)
    
    query = db.query(SecurityEvent).filter(SecurityEvent.timestamp >= since_time)
    
    # Apply filters
    if severity:
        query = query.filter(SecurityEvent.severity == severity)
    
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    
    # Get total count
    total = query.count()
    
    # Apply pagination and ordering
    events = query.order_by(desc(SecurityEvent.timestamp)).offset(skip).limit(limit).all()
    
    # Convert to response models
    event_responses = []
    for event in events:
        event_responses.append(SecurityEventResponse(
            id=event.id,
            event_type=event.event_type,
            severity=event.severity,
            description=event.description,
            source_ip=event.source_ip,
            user_id=event.user_id,
            timestamp=event.timestamp,
            details=event.details or {}
        ))
    
    return PaginatedResponse(
        items=event_responses,
        total=total,
        page=skip // limit + 1,
        per_page=limit,
        total_pages=(total + limit - 1) // limit
    )

@router.get("/automation-tasks", response_model=PaginatedResponse[AutomationTaskResponse])
async def get_automation_tasks(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    status: Optional[str] = Query(None, description="Filter by status"),
    task_type: Optional[str] = Query(None, description="Filter by task type"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get automation tasks with filtering and pagination"""
    
    query = db.query(AutomationTask)
    
    # Apply filters
    if status:
        query = query.filter(AutomationTask.status == status)
    
    if task_type:
        query = query.filter(AutomationTask.task_type == task_type)
    
    # Non-admin users can only see their own tasks
    if not current_user.get("is_admin"):
        query = query.filter(AutomationTask.user_id == current_user.get("user_id"))
    
    # Get total count
    total = query.count()
    
    # Apply pagination and ordering
    tasks = query.order_by(desc(AutomationTask.created_at)).offset(skip).limit(limit).all()
    
    # Convert to response models
    task_responses = []
    for task in tasks:
        task_responses.append(AutomationTaskResponse(
            id=task.id,
            task_name=task.task_name,
            task_type=task.task_type,
            status=task.status,
            user_id=task.user_id,
            created_at=task.created_at,
            scheduled_time=task.scheduled_time,
            completed_at=task.completed_at,
            configuration=task.configuration or {},
            result=task.result or {}
        ))
    
    return PaginatedResponse(
        items=task_responses,
        total=total,
        page=skip // limit + 1,
        per_page=limit,
        total_pages=(total + limit - 1) // limit
    )

@router.get("/notifications", response_model=PaginatedResponse[NotificationResponse])
async def get_notifications(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    unread_only: bool = Query(False, description="Show only unread notifications"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get notifications for current user"""
    
    query = db.query(Notification).filter(
        Notification.user_id == current_user.get("user_id")
    )
    
    # Filter by read status
    if unread_only:
        query = query.filter(Notification.read == False)
    
    # Get total count
    total = query.count()
    
    # Apply pagination and ordering
    notifications = query.order_by(desc(Notification.created_at)).offset(skip).limit(limit).all()
    
    # Convert to response models
    notification_responses = []
    for notification in notifications:
        notification_responses.append(NotificationResponse(
            id=notification.id,
            title=notification.title,
            message=notification.message,
            notification_type=notification.notification_type,
            priority=notification.priority,
            read=notification.read,
            user_id=notification.user_id,
            created_at=notification.created_at
        ))
    
    return PaginatedResponse(
        items=notification_responses,
        total=total,
        page=skip // limit + 1,
        per_page=limit,
        total_pages=(total + limit - 1) // limit
    )

@router.put("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Mark notification as read"""
    
    notification = db.query(Notification).filter(
        and_(
            Notification.id == notification_id,
            Notification.user_id == current_user.get("user_id")
        )
    ).first()
    
    if not notification:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found"
        )
    
    notification.read = True
    db.add(notification)
    db.commit()
    
    return {"message": "Notification marked as read"}

@router.put("/notifications/mark-all-read")
async def mark_all_notifications_read(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Mark all notifications as read for current user"""
    
    db.query(Notification).filter(
        and_(
            Notification.user_id == current_user.get("user_id"),
            Notification.read == False
        )
    ).update({Notification.read: True})
    
    db.commit()
    
    return {"message": "All notifications marked as read"}

@router.get("/system-metrics", response_model=SystemMetricsResponse)
async def get_system_metrics(
    current_user: dict = Depends(get_current_user)
):
    """Get real-time system metrics"""
    
    # In a real implementation, these would come from system monitoring
    # For now, we'll simulate the metrics
    import random
    
    metrics = SystemMetricsResponse(
        timestamp=datetime.utcnow(),
        cpu_usage=round(random.uniform(20, 80), 1),
        memory_usage=round(random.uniform(40, 85), 1),
        disk_usage=round(random.uniform(25, 60), 1),
        network_in=round(random.uniform(100, 1000), 2),
        network_out=round(random.uniform(50, 500), 2),
        active_connections=random.randint(50, 200),
        uptime_seconds=86400 * 30,  # 30 days uptime
        load_average=[
            round(random.uniform(0.5, 2.0), 2),
            round(random.uniform(0.8, 2.5), 2),
            round(random.uniform(1.0, 3.0), 2)
        ]
    )
    
    return metrics

@router.get("/recent-activity")
async def get_recent_activity(
    limit: int = Query(10, ge=1, le=50),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get recent system activity summary"""
    
    # Get recent security events
    recent_events = db.query(SecurityEvent).order_by(
        desc(SecurityEvent.timestamp)
    ).limit(limit).all()
    
    # Get recent automation tasks
    recent_tasks = db.query(AutomationTask).order_by(
        desc(AutomationTask.created_at)
    ).limit(limit).all()
    
    # Combine and sort by timestamp
    activity_items = []
    
    for event in recent_events:
        activity_items.append({
            "type": "security_event",
            "id": event.id,
            "title": f"Security Event: {event.event_type}",
            "description": event.description,
            "timestamp": event.timestamp,
            "severity": event.severity
        })
    
    for task in recent_tasks:
        activity_items.append({
            "type": "automation_task",
            "id": task.id,
            "title": f"Task: {task.task_name}",
            "description": f"Status: {task.status}",
            "timestamp": task.created_at,
            "status": task.status
        })
    
    # Sort by timestamp (most recent first)
    activity_items.sort(key=lambda x: x["timestamp"], reverse=True)
    
    return {
        "activities": activity_items[:limit],
        "total_items": len(activity_items)
    }

@router.post("/test-notification")
async def create_test_notification(
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a test notification (for testing purposes)"""
    
    notification = Notification(
        title="Test Notification",
        message=f"This is a test notification created by {current_user.get('username')}",
        notification_type="info",
        priority="medium",
        user_id=current_user.get("user_id"),
        read=False
    )
    
    db.add(notification)
    db.commit()
    
    # Log the test notification creation
    log_security_event(
        "test_notification_created",
        {"username": current_user.get("username")},
        user_id=current_user.get("user_id")
    )
    
    return {"message": "Test notification created successfully", "id": notification.id}