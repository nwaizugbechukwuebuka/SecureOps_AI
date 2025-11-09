"""
Enhanced Dashboard Router for SecureOps AI
Security analytics dashboard with audit logs and metrics
"""

from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_, or_

from database import get_db
from models_enhanced import User, AuditLog, SecurityAlert, AuditEventType, UserRole
from utils.security_enhanced import get_current_user, require_analyst, get_client_ip
from utils.audit_logger import security_logger

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats")
async def get_dashboard_stats(
    request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """
    Get dashboard statistics and metrics
    """
    client_ip = get_client_ip(request)

    # Log data access
    security_logger.log_data_access(db=db, user=current_user, resource="dashboard_stats", ip_address=client_ip)

    # Time periods
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    last_30d = now - timedelta(days=30)

    # Basic system stats
    total_users = db.query(User).count()
    active_users = db.query(User).filter(User.is_active).count()

    # Security alerts in last 24h
    recent_alerts = db.query(SecurityAlert).filter(SecurityAlert.created_at >= last_24h).count()

    critical_alerts = (
        db.query(SecurityAlert).filter(SecurityAlert.severity == "CRITICAL", SecurityAlert.status == "OPEN").count()
    )

    # Login statistics
    successful_logins_24h = (
        db.query(AuditLog)
        .filter(AuditLog.event_type == AuditEventType.LOGIN_SUCCESS.value, AuditLog.created_at >= last_24h)
        .count()
    )

    failed_logins_24h = (
        db.query(AuditLog)
        .filter(AuditLog.event_type == AuditEventType.LOGIN_FAILURE.value, AuditLog.created_at >= last_24h)
        .count()
    )

    # MFA adoption rate
    mfa_users = db.query(User).filter(User.mfa_enabled, User.is_active).count()

    mfa_adoption_rate = (mfa_users / active_users * 100) if active_users > 0 else 0

    # Risk score calculation
    risk_factors = {
        "failed_logins": min(failed_logins_24h / 10, 10),  # Max 10 points
        "critical_alerts": min(critical_alerts * 2, 20),  # Max 20 points
        "low_mfa_adoption": max(0, (50 - mfa_adoption_rate) / 5),  # Max 10 points if <50%
    }

    total_risk_score = sum(risk_factors.values())
    risk_level = "LOW"
    if total_risk_score > 25:
        risk_level = "CRITICAL"
    elif total_risk_score > 15:
        risk_level = "HIGH"
    elif total_risk_score > 8:
        risk_level = "MEDIUM"

    return {
        "system_overview": {
            "total_users": total_users,
            "active_users": active_users,
            "mfa_adoption_rate": round(mfa_adoption_rate, 1),
            "system_health": "HEALTHY",  # Could be calculated based on various factors
        },
        "security_metrics": {
            "alerts_24h": recent_alerts,
            "critical_alerts": critical_alerts,
            "successful_logins_24h": successful_logins_24h,
            "failed_logins_24h": failed_logins_24h,
            "risk_score": round(total_risk_score, 1),
            "risk_level": risk_level,
        },
        "risk_factors": risk_factors,
        "last_updated": now.isoformat(),
    }


@router.get("/audit-logs")
async def get_audit_logs(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    event_type: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    user_id: Optional[int] = Query(None),
    hours: int = Query(24, ge=1, le=168),  # Last 1-168 hours (7 days max)
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    """
    Get audit logs for dashboard
    Requires analyst role or higher
    """
    client_ip = get_client_ip(request)

    # Time filter
    since = datetime.utcnow() - timedelta(hours=hours)

    # Build query
    query = db.query(AuditLog).filter(AuditLog.created_at >= since)

    # Apply filters
    if event_type:
        query = query.filter(AuditLog.event_type == event_type)

    if risk_level:
        query = query.filter(AuditLog.risk_level == risk_level)

    if user_id:
        query = query.filter(AuditLog.user_id == user_id)

    # Get total count
    total = query.count()

    # Apply pagination
    offset = (page - 1) * per_page
    logs = query.order_by(desc(AuditLog.created_at)).offset(offset).limit(per_page).all()

    # Enrich logs with user information
    enriched_logs = []
    for log in logs:
        log_dict = log.to_dict()
        if log.user_id:
            user = db.query(User).filter(User.id == log.user_id).first()
            if user:
                log_dict["username"] = user.username
                log_dict["user_role"] = user.role
        enriched_logs.append(log_dict)

    # Log access
    security_logger.log_data_access(
        db=db,
        user=current_user,
        resource="audit_logs",
        ip_address=client_ip,
        details=f"Page {page}, filters: event_type={event_type}, risk_level={risk_level}, user_id={user_id}, hours={hours}",
    )

    return {
        "logs": enriched_logs,
        "pagination": {"total": total, "page": page, "per_page": per_page, "pages": (total + per_page - 1) // per_page},
        "filters": {"event_type": event_type, "risk_level": risk_level, "user_id": user_id, "hours": hours},
    }


@router.get("/security-alerts")
async def get_security_alerts(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    alert_type: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get security alerts
    """
    client_ip = get_client_ip(request)

    # Build query
    query = db.query(SecurityAlert)

    # Apply filters
    if severity:
        query = query.filter(SecurityAlert.severity == severity)

    if status:
        query = query.filter(SecurityAlert.status == status)

    if alert_type:
        query = query.filter(SecurityAlert.alert_type == alert_type)

    # Get total count
    total = query.count()

    # Apply pagination and ordering
    offset = (page - 1) * per_page
    alerts = query.order_by(desc(SecurityAlert.created_at)).offset(offset).limit(per_page).all()

    # Log access
    security_logger.log_data_access(db=db, user=current_user, resource="security_alerts", ip_address=client_ip)

    return {
        "alerts": [alert.to_dict() for alert in alerts],
        "pagination": {"total": total, "page": page, "per_page": per_page, "pages": (total + per_page - 1) // per_page},
    }


@router.get("/login-activity")
async def get_login_activity(
    request: Request,
    hours: int = Query(24, ge=1, le=168),
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    """
    Get login activity analytics
    Requires analyst role or higher
    """
    client_ip = get_client_ip(request)

    since = datetime.utcnow() - timedelta(hours=hours)

    # Successful logins over time (hourly buckets)
    successful_logins = (
        db.query(func.date_trunc("hour", AuditLog.created_at).label("hour"), func.count(AuditLog.id).label("count"))
        .filter(AuditLog.event_type == AuditEventType.LOGIN_SUCCESS.value, AuditLog.created_at >= since)
        .group_by("hour")
        .order_by("hour")
        .all()
    )

    # Failed logins over time
    failed_logins = (
        db.query(func.date_trunc("hour", AuditLog.created_at).label("hour"), func.count(AuditLog.id).label("count"))
        .filter(AuditLog.event_type == AuditEventType.LOGIN_FAILURE.value, AuditLog.created_at >= since)
        .group_by("hour")
        .order_by("hour")
        .all()
    )

    # Top source IPs for failed logins
    top_failed_ips = (
        db.query(AuditLog.ip_address, func.count(AuditLog.id).label("count"))
        .filter(
            AuditLog.event_type == AuditEventType.LOGIN_FAILURE.value,
            AuditLog.created_at >= since,
            AuditLog.ip_address.isnot(None),
        )
        .group_by(AuditLog.ip_address)
        .order_by(desc("count"))
        .limit(10)
        .all()
    )

    # Geographic distribution (would need IP geolocation service)
    # For now, just return IP addresses
    unique_login_ips = (
        db.query(func.distinct(AuditLog.ip_address))
        .filter(
            AuditLog.event_type == AuditEventType.LOGIN_SUCCESS.value,
            AuditLog.created_at >= since,
            AuditLog.ip_address.isnot(None),
        )
        .count()
    )

    # Log access
    security_logger.log_data_access(db=db, user=current_user, resource="login_activity", ip_address=client_ip)

    return {
        "period_hours": hours,
        "successful_logins_timeline": [
            {"hour": item.hour.isoformat(), "count": item.count} for item in successful_logins
        ],
        "failed_logins_timeline": [{"hour": item.hour.isoformat(), "count": item.count} for item in failed_logins],
        "top_failed_login_ips": [{"ip_address": item.ip_address, "attempts": item.count} for item in top_failed_ips],
        "unique_login_locations": unique_login_ips,
    }


@router.get("/user-activity")
async def get_user_activity(
    request: Request,
    hours: int = Query(24, ge=1, le=168),
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    """
    Get user activity statistics
    Requires analyst role or higher
    """
    client_ip = get_client_ip(request)

    since = datetime.utcnow() - timedelta(hours=hours)

    # Most active users
    most_active_users = (
        db.query(AuditLog.user_id, func.count(AuditLog.id).label("activity_count"))
        .filter(AuditLog.created_at >= since, AuditLog.user_id.isnot(None))
        .group_by(AuditLog.user_id)
        .order_by(desc("activity_count"))
        .limit(10)
        .all()
    )

    # Enrich with user details
    active_users_data = []
    for activity in most_active_users:
        user = db.query(User).filter(User.id == activity.user_id).first()
        if user:
            active_users_data.append(
                {
                    "user_id": user.id,
                    "username": user.username,
                    "role": user.role,
                    "activity_count": activity.activity_count,
                }
            )

    # Activity by type
    activity_by_type = (
        db.query(AuditLog.event_type, func.count(AuditLog.id).label("count"))
        .filter(AuditLog.created_at >= since)
        .group_by(AuditLog.event_type)
        .order_by(desc("count"))
        .all()
    )

    # Risk events
    high_risk_events = (
        db.query(AuditLog)
        .filter(AuditLog.risk_level.in_(["HIGH", "CRITICAL"]), AuditLog.created_at >= since)
        .order_by(desc(AuditLog.created_at))
        .limit(10)
        .all()
    )

    # Log access
    security_logger.log_data_access(db=db, user=current_user, resource="user_activity", ip_address=client_ip)

    return {
        "period_hours": hours,
        "most_active_users": active_users_data,
        "activity_by_type": [{"event_type": item.event_type, "count": item.count} for item in activity_by_type],
        "high_risk_events": [event.to_dict() for event in high_risk_events],
    }


@router.get("/security-overview")
async def get_security_overview(
    request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """
    Get security overview for dashboard widgets
    """
    client_ip = get_client_ip(request)

    # Time periods
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    # Account security metrics
    locked_accounts = db.query(User).filter(User.locked_until > now).count()

    mfa_enabled = db.query(User).filter(User.mfa_enabled, User.is_active).count()

    total_active = db.query(User).filter(User.is_active).count()

    # Recent security events
    recent_password_changes = (
        db.query(AuditLog)
        .filter(AuditLog.event_type == AuditEventType.PASSWORD_CHANGE.value, AuditLog.created_at >= last_7d)
        .count()
    )

    recent_role_changes = (
        db.query(AuditLog)
        .filter(AuditLog.event_type == AuditEventType.ROLE_CHANGE.value, AuditLog.created_at >= last_7d)
        .count()
    )

    # Critical events in last 24h
    critical_events_24h = (
        db.query(AuditLog).filter(AuditLog.risk_level == "CRITICAL", AuditLog.created_at >= last_24h).count()
    )

    # Failed login attempts by IP
    failed_login_ips = (
        db.query(AuditLog.ip_address, func.count(AuditLog.id).label("attempts"))
        .filter(
            AuditLog.event_type == AuditEventType.LOGIN_FAILURE.value,
            AuditLog.created_at >= last_24h,
            AuditLog.ip_address.isnot(None),
        )
        .group_by(AuditLog.ip_address)
        .having(func.count(AuditLog.id) >= 5)
        .all()
    )

    # Calculate security score
    security_factors = {
        "mfa_adoption": (mfa_enabled / total_active * 100) if total_active > 0 else 0,
        "locked_accounts": locked_accounts,
        "critical_events": critical_events_24h,
        "suspicious_ips": len(failed_login_ips),
    }

    # Security score calculation (0-100)
    base_score = 100
    base_score -= max(0, (50 - security_factors["mfa_adoption"]) / 2)  # Penalty for low MFA
    base_score -= security_factors["locked_accounts"] * 5  # -5 per locked account
    base_score -= security_factors["critical_events"] * 10  # -10 per critical event
    base_score -= security_factors["suspicious_ips"] * 3  # -3 per suspicious IP

    security_score = max(0, min(100, base_score))

    # Log access
    security_logger.log_data_access(db=db, user=current_user, resource="security_overview", ip_address=client_ip)

    return {
        "account_security": {
            "locked_accounts": locked_accounts,
            "mfa_adoption_rate": round(security_factors["mfa_adoption"], 1),
            "recent_password_changes": recent_password_changes,
            "recent_role_changes": recent_role_changes,
        },
        "threat_indicators": {
            "critical_events_24h": critical_events_24h,
            "suspicious_ips": len(failed_login_ips),
            "failed_login_ips": [{"ip": ip.ip_address, "attempts": ip.attempts} for ip in failed_login_ips],
        },
        "security_score": {
            "score": round(security_score, 1),
            "level": (
                "EXCELLENT"
                if security_score >= 90
                else "GOOD" if security_score >= 75 else "FAIR" if security_score >= 60 else "POOR"
            ),
            "factors": security_factors,
        },
        "recommendations": _generate_security_recommendations(security_factors),
    }


@router.get("/system-health")
async def get_system_health(
    request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """
    Get system health metrics
    """
    client_ip = get_client_ip(request)

    # Database health
    try:
        user_count = db.query(User).count()
        db_healthy = True
    except Exception:
        user_count = 0
        db_healthy = False

    # Recent activity (last hour)
    last_hour = datetime.utcnow() - timedelta(hours=1)
    recent_activity = db.query(AuditLog).filter(AuditLog.created_at >= last_hour).count()

    # Error rate (approximate)
    error_logs = db.query(AuditLog).filter(AuditLog.risk_level == "CRITICAL", AuditLog.created_at >= last_hour).count()

    error_rate = (error_logs / max(recent_activity, 1)) * 100

    # Log access
    security_logger.log_data_access(db=db, user=current_user, resource="system_health", ip_address=client_ip)

    return {
        "database": {"status": "HEALTHY" if db_healthy else "ERROR", "user_count": user_count},
        "activity": {"requests_last_hour": recent_activity, "error_rate_percentage": round(error_rate, 2)},
        "overall_status": "HEALTHY" if db_healthy and error_rate < 5 else "WARNING",
    }


def _generate_security_recommendations(factors: dict) -> list:
    """Generate security recommendations based on current metrics"""
    recommendations = []

    if factors["mfa_adoption"] < 80:
        recommendations.append(
            {
                "type": "MFA_ADOPTION",
                "priority": "HIGH",
                "message": f"MFA adoption is only {factors['mfa_adoption']:.1f}%. Encourage users to enable MFA.",
                "action": "Implement MFA enforcement policy",
            }
        )

    if factors["locked_accounts"] > 0:
        recommendations.append(
            {
                "type": "LOCKED_ACCOUNTS",
                "priority": "MEDIUM",
                "message": f"{factors['locked_accounts']} accounts are currently locked.",
                "action": "Review and unlock legitimate accounts",
            }
        )

    if factors["critical_events"] > 0:
        recommendations.append(
            {
                "type": "CRITICAL_EVENTS",
                "priority": "CRITICAL",
                "message": f"{factors['critical_events']} critical security events in last 24h.",
                "action": "Investigate critical events immediately",
            }
        )

    if factors["suspicious_ips"] > 0:
        recommendations.append(
            {
                "type": "SUSPICIOUS_IPS",
                "priority": "HIGH",
                "message": f"{factors['suspicious_ips']} IPs with multiple failed login attempts.",
                "action": "Consider IP blocking or additional monitoring",
            }
        )

    if not recommendations:
        recommendations.append(
            {
                "type": "ALL_GOOD",
                "priority": "INFO",
                "message": "Security posture is good. Continue monitoring.",
                "action": "Maintain current security practices",
            }
        )

    return recommendations
