"""Reports and analytics routes for SecureOps API."""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models.user import User
from ..utils.logger import get_logger
from .auth import get_current_user

router = APIRouter()
logger = get_logger(__name__)


# Pydantic models
class SecurityMetrics(BaseModel):
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    resolved_vulnerabilities: int
    open_vulnerabilities: int


class PipelineMetrics(BaseModel):
    total_pipelines: int
    active_pipelines: int
    successful_runs: int
    failed_runs: int
    average_duration: float


class AlertMetrics(BaseModel):
    total_alerts: int
    open_alerts: int
    resolved_alerts: int
    alerts_by_severity: Dict[str, int]
    recent_alerts: int


class DashboardSummary(BaseModel):
    security_metrics: SecurityMetrics
    pipeline_metrics: PipelineMetrics
    alert_metrics: AlertMetrics
    last_updated: datetime


class VulnerabilityReport(BaseModel):
    id: int
    title: str
    severity: str
    cve_id: Optional[str]
    package_name: Optional[str]
    pipeline_name: Optional[str]
    discovered_at: datetime
    status: str


@router.get("/dashboard", response_model=DashboardSummary)
async def get_dashboard_summary(
    days: int = Query(30, ge=1, le=365, description="Number of days to include"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get dashboard summary with key metrics."""
    try:
        # Mock dashboard data
        dashboard_data = DashboardSummary(
            security_metrics=SecurityMetrics(
                total_vulnerabilities=47,
                critical_vulnerabilities=3,
                high_vulnerabilities=12,
                medium_vulnerabilities=18,
                low_vulnerabilities=14,
                resolved_vulnerabilities=35,
                open_vulnerabilities=12
            ),
            pipeline_metrics=PipelineMetrics(
                total_pipelines=8,
                active_pipelines=6,
                successful_runs=156,
                failed_runs=23,
                average_duration=180.5
            ),
            alert_metrics=AlertMetrics(
                total_alerts=89,
                open_alerts=15,
                resolved_alerts=74,
                alerts_by_severity={
                    "critical": 5,
                    "high": 18,
                    "medium": 31,
                    "low": 35
                },
                recent_alerts=12
            ),
            last_updated=datetime.now()
        )
        
        logger.info(f"Dashboard summary retrieved for user {current_user.id}")
        return dashboard_data
        
    except Exception as e:
        logger.error(f"Error retrieving dashboard summary: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dashboard summary"
        )


@router.get("/vulnerabilities", response_model=List[VulnerabilityReport])
async def get_vulnerability_report(
    severity: Optional[str] = Query(None, pattern="^(low|medium|high|critical)$"),
    status_filter: Optional[str] = Query(None, alias="status", pattern="^(open|triaged|fixed|accepted_risk)$"),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get vulnerability report with filtering options."""
    try:
        # Mock vulnerability data
        mock_vulnerabilities = [
            VulnerabilityReport(
                id=1,
                title="Critical SQL Injection in user authentication",
                severity="critical",
                cve_id="CVE-2023-12345",
                package_name="auth-service",
                pipeline_name="SecureOps CI/CD",
                discovered_at=datetime.now() - timedelta(days=2),
                status="open"
            ),
            VulnerabilityReport(
                id=2,
                title="Outdated dependency with known vulnerabilities",
                severity="high",
                cve_id="CVE-2023-54321",
                package_name="express",
                pipeline_name="Frontend Pipeline",
                discovered_at=datetime.now() - timedelta(days=5),
                status="triaged"
            ),
            VulnerabilityReport(
                id=3,
                title="Weak encryption algorithm detected",
                severity="medium",
                cve_id=None,
                package_name="crypto-utils",
                pipeline_name="API Pipeline",
                discovered_at=datetime.now() - timedelta(days=7),
                status="fixed"
            )
        ]
        
        # Apply filters
        filtered_vulnerabilities = mock_vulnerabilities
        if severity:
            filtered_vulnerabilities = [v for v in filtered_vulnerabilities if v.severity == severity]
        if status_filter:
            filtered_vulnerabilities = [v for v in filtered_vulnerabilities if v.status == status_filter]
        
        # Apply limit
        filtered_vulnerabilities = filtered_vulnerabilities[:limit]
        
        logger.info(f"Vulnerability report retrieved for user {current_user.id}, returned {len(filtered_vulnerabilities)} items")
        return filtered_vulnerabilities
        
    except Exception as e:
        logger.error(f"Error retrieving vulnerability report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve vulnerability report"
        )


@router.get("/compliance")
async def get_compliance_report(
    framework: str = Query("cis", description="Compliance framework (cis, nist, pci)"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get compliance report for specified framework."""
    try:
        # Mock compliance data
        compliance_data = {
            "framework": framework.upper(),
            "overall_score": 78.5,
            "total_controls": 156,
            "passed_controls": 122,
            "failed_controls": 28,
            "not_applicable": 6,
            "categories": {
                "Access Control": {
                    "score": 85,
                    "passed": 17,
                    "failed": 3,
                    "total": 20
                },
                "Data Protection": {
                    "score": 72,
                    "passed": 13,
                    "failed": 5,
                    "total": 18
                },
                "Network Security": {
                    "score": 80,
                    "passed": 24,
                    "failed": 6,
                    "total": 30
                },
                "Incident Response": {
                    "score": 90,
                    "passed": 9,
                    "failed": 1,
                    "total": 10
                }
            },
            "recent_improvements": [
                "Implemented multi-factor authentication",
                "Updated encryption standards",
                "Enhanced logging and monitoring"
            ],
            "priority_actions": [
                "Address weak password policies",
                "Implement data loss prevention",
                "Update incident response procedures"
            ],
            "last_assessment": datetime.now() - timedelta(days=1)
        }
        
        logger.info(f"Compliance report ({framework}) retrieved for user {current_user.id}")
        return compliance_data
        
    except Exception as e:
        logger.error(f"Error retrieving compliance report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve compliance report"
        )


@router.get("/export/{report_type}")
async def export_report(
    report_type: str,
    format: str = Query("json", pattern="^(json|csv|pdf)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Export report in specified format."""
    try:
        if report_type not in ["vulnerabilities", "compliance", "dashboard"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid report type"
            )
        
        # Mock export response
        export_data = {
            "message": f"Report export initiated",
            "report_type": report_type,
            "format": format,
            "download_url": f"/api/v1/reports/download/{report_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}",
            "expires_at": datetime.now() + timedelta(hours=24)
        }
        
        logger.info(f"Report export ({report_type}/{format}) initiated by user {current_user.id}")
        return export_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export report"
        )
