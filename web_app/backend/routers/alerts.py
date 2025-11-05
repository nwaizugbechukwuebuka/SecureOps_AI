from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta

from ..database import get_db
from ..models import Alert, User
from ..schemas import AlertCreate, AlertUpdate, AlertResponse
from ..utils.security import get_current_active_user
from ..services.analytics_service import AnalyticsService

router = APIRouter(prefix="/alerts", tags=["alerts"])

@router.get("/", response_model=List[AlertResponse])
async def get_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get alerts with optional filtering by severity and status
    """
    query = db.query(Alert)
    
    # Apply filters
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    
    # Order by creation date (newest first)
    query = query.order_by(Alert.created_at.desc())
    
    # Apply pagination
    alerts = query.offset(skip).limit(limit).all()
    
    return alerts

@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get a specific alert by ID
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    return alert

@router.post("/", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
async def create_alert(
    alert: AlertCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Create a new security alert
    """
    db_alert = Alert(
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        source=alert.source,
        ip_address=alert.ip_address,
        details=alert.details,
        created_by_id=current_user.id
    )
    
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    
    # Trigger real-time notification
    # TODO: Implement WebSocket notification
    
    return db_alert

@router.put("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: int,
    alert_update: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Update an existing alert
    """
    db_alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not db_alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    # Update fields
    for field, value in alert_update.dict(exclude_unset=True).items():
        setattr(db_alert, field, value)
    
    db_alert.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(db_alert)
    
    return db_alert

@router.post("/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Acknowledge an alert
    """
    db_alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not db_alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    db_alert.status = "acknowledged"
    db_alert.acknowledged_at = datetime.utcnow()
    db_alert.acknowledged_by_id = current_user.id
    db_alert.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(db_alert)
    
    return db_alert

@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Delete an alert (admin only)
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can delete alerts"
        )
    
    db_alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not db_alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    db.delete(db_alert)
    db.commit()

@router.get("/stats/summary")
async def get_alerts_summary(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get alerts summary statistics
    """
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    # Get alerts within date range
    alerts = db.query(Alert).filter(
        Alert.created_at >= start_date,
        Alert.created_at <= end_date
    ).all()
    
    # Calculate statistics
    total_alerts = len(alerts)
    severity_counts = {}
    status_counts = {}
    
    for alert in alerts:
        # Count by severity
        severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
        # Count by status
        status_counts[alert.status] = status_counts.get(alert.status, 0) + 1
    
    return {
        "total_alerts": total_alerts,
        "severity_breakdown": severity_counts,
        "status_breakdown": status_counts,
        "period_days": days,
        "start_date": start_date,
        "end_date": end_date
    }

@router.get("/trends/daily")
async def get_daily_alert_trends(
    days: int = Query(30, ge=1, le=90),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get daily alert trends for charts
    """
    analytics_service = AnalyticsService(db)
    trends = analytics_service.get_daily_alert_trends(days)
    
    return trends