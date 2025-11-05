"""
Reports API Routes

This module contains FastAPI routes for generating and managing security reports,
compliance reports, vulnerability summaries, and dashboard analytics.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..database import get_db
from ..models.alert import Alert
from ..models.pipeline import Pipeline, ScanJob
from ..models.user import User
from ..models.vulnerability import Vulnerability
from ..services.report_service import ReportService
from ..utils.config import settings
<<<<<<< HEAD
from ..utils.logger import get_logger

# Placeholder logging function
def log_api_request(method: str, path: str, user_id: int):
    logger = get_logger(__name__)
    logger.info(f"API Request: {method} {path} by user {user_id}")
from .auth import get_current_user
from ..utils.rbac import require_role, require_superuser
=======
from ..utils.logger import get_logger, log_api_request
from .auth import get_current_user
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

router = APIRouter()
logger = get_logger(__name__)


@router.get("/dashboard/summary")
async def get_dashboard_summary(
<<<<<<< HEAD
    current_user: User = Depends(require_role("admin", "security", "devops")), db: AsyncSession = Depends(get_db)
=======
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
):
    """
    Get comprehensive dashboard summary with key metrics.

    Returns overview statistics, recent activity, and trend data
    for the security dashboard.
    """
    log_api_request("GET", "/reports/dashboard/summary", current_user.id)

    try:
        report_service = ReportService(db)
        summary = await report_service.get_dashboard_summary(current_user.id)

        logger.info(f"Dashboard summary generated for user {current_user.id}")
        return summary

    except Exception as e:
        logger.error(f"Error generating dashboard summary: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Failed to generate dashboard summary"
        )


@router.get("/vulnerabilities/summary")
async def get_vulnerability_summary(
    pipeline_id: Optional[int] = Query(None, description="Filter by pipeline ID"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    status: Optional[str] = Query(None, description="Filter by vulnerability status"),
    days_back: int = Query(30, description="Number of days to look back"),
<<<<<<< HEAD
    current_user: User = Depends(require_role("admin", "security", "devops")),
=======
    current_user: User = Depends(get_current_user),
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    db: AsyncSession = Depends(get_db),
):
    """
    Get vulnerability summary with filtering and aggregation.

    Provides vulnerability counts by severity, status, scanner type,
    and time-based trends.
    """
    log_api_request("GET", "/reports/vulnerabilities/summary", current_user.id)

    try:
        report_service = ReportService(db)

        filters = {
            "pipeline_id": pipeline_id,
            "severity": severity,
            "status": status,
            "days_back": days_back,
            "user_id": current_user.id,
        }

        summary = await report_service.get_vulnerability_summary(**filters)

        logger.info(f"Vulnerability summary generated for user {current_user.id}")
        return summary

    except Exception as e:
        logger.error(f"Error generating vulnerability summary: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Failed to generate vulnerability summary"
        )


@router.get("/pipelines/performance")
async def get_pipeline_performance(
    pipeline_id: Optional[int] = Query(None, description="Specific pipeline ID"),
    days_back: int = Query(30, description="Number of days to analyze"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get pipeline performance metrics and scan statistics.

    Includes scan frequency, success rates, average duration,
    and trend analysis.
    """
    log_api_request("GET", "/reports/pipelines/performance", current_user.id)

    try:
        report_service = ReportService(db)

        performance = await report_service.get_pipeline_performance(
            user_id=current_user.id, pipeline_id=pipeline_id, days_back=days_back
        )

        logger.info(f"Pipeline performance report generated for user {current_user.id}")
        return performance

    except Exception as e:
        logger.error(f"Error generating pipeline performance report: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Failed to generate pipeline performance report"
        )


@router.get("/compliance/status")
async def get_compliance_status(
    framework: Optional[str] = Query(
        None, description="Compliance framework (OWASP, NIST, SOC2, GDPR)"
    ),
    pipeline_id: Optional[int] = Query(None, description="Filter by pipeline ID"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get compliance status across different frameworks.

    Provides compliance scores, failed controls, and recommendations
    for security frameworks.
    """
    log_api_request("GET", "/reports/compliance/status", current_user.id)

    try:
        report_service = ReportService(db)

        compliance_status = await report_service.get_compliance_status(
            user_id=current_user.id, framework=framework, pipeline_id=pipeline_id
        )

        logger.info(f"Compliance status report generated for user {current_user.id}")
        return compliance_status

    except Exception as e:
        logger.error(f"Error generating compliance status: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Failed to generate compliance status report"
        )


@router.get("/security/trends")
async def get_security_trends(
    metric: str = Query(
        "vulnerabilities",
        description="Metric to analyze (vulnerabilities, scans, alerts)",
    ),
    period: str = Query("7d", description="Time period (7d, 30d, 90d, 1y)"),
    group_by: str = Query("day", description="Grouping (day, week, month)"),
    pipeline_id: Optional[int] = Query(None, description="Filter by pipeline ID"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get security trend analysis over time.

    Provides time-series data for vulnerabilities, scans, alerts,
    and other security metrics.
    """
    log_api_request("GET", "/reports/security/trends", current_user.id)

    try:
        report_service = ReportService(db)

        trends = await report_service.get_security_trends(
            user_id=current_user.id,
            metric=metric,
            period=period,
            group_by=group_by,
            pipeline_id=pipeline_id,
        )

        logger.info(f"Security trends report generated for user {current_user.id}")
        return trends

    except Exception as e:
        logger.error(f"Error generating security trends: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Failed to generate security trends report"
        )


@router.get("/alerts/analytics")
async def get_alert_analytics(
    days_back: int = Query(30, description="Number of days to analyze"),
    pipeline_id: Optional[int] = Query(None, description="Filter by pipeline ID"),
    severity: Optional[str] = Query(None, description="Filter by alert severity"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get alert analytics and statistics.

    Provides alert volume, response times, escalation patterns,
    and resolution statistics.
    """
    log_api_request("GET", "/reports/alerts/analytics", current_user.id)

    try:
        report_service = ReportService(db)

        analytics = await report_service.get_alert_analytics(
            user_id=current_user.id,
            days_back=days_back,
            pipeline_id=pipeline_id,
            severity=severity,
        )

        logger.info(f"Alert analytics generated for user {current_user.id}")
        return analytics

    except Exception as e:
        logger.error(f"Error generating alert analytics: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Failed to generate alert analytics"
        )


@router.post("/generate")
async def generate_custom_report(
    report_config: Dict[str, Any],
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Generate custom security report based on configuration.

    Accepts flexible report configuration and generates comprehensive
    reports asynchronously.
    """
    log_api_request("POST", "/reports/generate", current_user.id)

    try:
        # Validate report configuration
        required_fields = ["report_type", "format", "filters"]
        for field in required_fields:
            if field not in report_config:
                raise HTTPException(
                    status_code=400, detail=f"Missing required field: {field}"
                )

        # Supported report types
        valid_report_types = [
            "vulnerability_assessment",
            "compliance_audit",
            "security_posture",
            "risk_analysis",
            "executive_summary",
        ]

        if report_config["report_type"] not in valid_report_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid report type. Must be one of: {', '.join(valid_report_types)}",
            )

        # Supported formats
        valid_formats = ["pdf", "json", "csv", "html"]
        if report_config["format"] not in valid_formats:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid format. Must be one of: {', '.join(valid_formats)}",
            )

        report_service = ReportService(db)

        # Queue report generation as background task
        task_id = await report_service.queue_custom_report(
            user_id=current_user.id, report_config=report_config
        )

        # Add to background tasks for immediate processing
        background_tasks.add_task(
            report_service.generate_custom_report_async,
            task_id,
            current_user.id,
            report_config,
        )

        logger.info(
            f"Custom report queued for user {current_user.id}, task_id: {task_id}"
        )

        return {
            "message": "Report generation started",
            "task_id": task_id,
            "estimated_completion": "2-5 minutes",
            "status_url": f"/api/v1/reports/status/{task_id}",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error queuing custom report: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to start report generation")


@router.get("/status/{task_id}")
async def get_report_status(
    task_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get status of report generation task.

    Returns current status, progress, and download URL when complete.
    """
    log_api_request("GET", f"/reports/status/{task_id}", current_user.id)

    try:
        report_service = ReportService(db)

        status = await report_service.get_report_status(
            task_id=task_id, user_id=current_user.id
        )

        if not status:
            raise HTTPException(status_code=404, detail="Report task not found")

        logger.info(f"Report status checked for task {task_id}")
        return status

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking report status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to check report status")


@router.get("/download/{task_id}")
async def download_report(
    task_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Download generated report file.

    Returns the report file with appropriate content type based on format.
    """
    log_api_request("GET", f"/reports/download/{task_id}", current_user.id)

    try:
        report_service = ReportService(db)

        report_file = await report_service.get_report_file(
            task_id=task_id, user_id=current_user.id
        )

        if not report_file:
            raise HTTPException(
                status_code=404, detail="Report file not found or not ready"
            )

        from fastapi.responses import FileResponse

        # Determine content type based on format
        content_types = {
            "pdf": "application/pdf",
            "json": "application/json",
            "csv": "text/csv",
            "html": "text/html",
        }

        content_type = content_types.get(
            report_file["format"], "application/octet-stream"
        )

        logger.info(f"Report downloaded for task {task_id}")

        return FileResponse(
            path=report_file["file_path"],
            media_type=content_type,
            filename=report_file["filename"],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading report: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to download report")


@router.get("/export/vulnerabilities")
async def export_vulnerabilities(
    format: str = Query("csv", description="Export format (csv, json, xlsx)"),
    pipeline_id: Optional[int] = Query(None, description="Filter by pipeline ID"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
    days_back: int = Query(30, description="Number of days to include"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Export vulnerability data in various formats.

    Provides detailed vulnerability export with flexible filtering
    and multiple output formats.
    """
    log_api_request("GET", "/reports/export/vulnerabilities", current_user.id)

    try:
        # Validate format
        valid_formats = ["csv", "json", "xlsx"]
        if format not in valid_formats:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid format. Must be one of: {', '.join(valid_formats)}",
            )

        report_service = ReportService(db)

        export_file = await report_service.export_vulnerabilities(
            user_id=current_user.id,
            format=format,
            pipeline_id=pipeline_id,
            severity=severity,
            status=status,
            days_back=days_back,
        )

        from fastapi.responses import FileResponse

        # Determine content type
        content_types = {
            "csv": "text/csv",
            "json": "application/json",
            "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        }

        logger.info(f"Vulnerability export generated for user {current_user.id}")

        return FileResponse(
            path=export_file["file_path"],
            media_type=content_types[format],
            filename=export_file["filename"],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting vulnerabilities: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Failed to export vulnerability data"
        )


@router.get("/metrics/scanner")
async def get_scanner_metrics(
    scanner_type: Optional[str] = Query(None, description="Filter by scanner type"),
    days_back: int = Query(30, description="Number of days to analyze"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get scanner performance and effectiveness metrics.

    Provides statistics on scan execution times, success rates,
    and vulnerability detection patterns by scanner type.
    """
    log_api_request("GET", "/reports/metrics/scanner", current_user.id)

    try:
        report_service = ReportService(db)

        metrics = await report_service.get_scanner_metrics(
            user_id=current_user.id, scanner_type=scanner_type, days_back=days_back
        )

        logger.info(f"Scanner metrics generated for user {current_user.id}")
        return metrics

    except Exception as e:
        logger.error(f"Error generating scanner metrics: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Failed to generate scanner metrics"
        )


@router.get("/risk/assessment")
async def get_risk_assessment(
    pipeline_id: Optional[int] = Query(None, description="Filter by pipeline ID"),
    include_trends: bool = Query(True, description="Include risk trend analysis"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get comprehensive risk assessment report.

    Provides risk scoring, threat analysis, and security posture
    assessment based on vulnerabilities and compliance status.
    """
    log_api_request("GET", "/reports/risk/assessment", current_user.id)

    try:
        report_service = ReportService(db)

        risk_assessment = await report_service.get_risk_assessment(
            user_id=current_user.id,
            pipeline_id=pipeline_id,
            include_trends=include_trends,
        )

        logger.info(f"Risk assessment generated for user {current_user.id}")
        return risk_assessment

    except Exception as e:
        logger.error(f"Error generating risk assessment: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Failed to generate risk assessment"
        )


@router.post("/schedule")
async def schedule_report(
    report_schedule: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Schedule periodic report generation.

    Allows users to set up automated report generation
    on daily, weekly, or monthly schedules.
    """
    log_api_request("POST", "/reports/schedule", current_user.id)

    try:
        # Validate schedule configuration
        required_fields = ["report_type", "frequency", "recipients"]
        for field in required_fields:
            if field not in report_schedule:
                raise HTTPException(
                    status_code=400, detail=f"Missing required field: {field}"
                )

        # Validate frequency
        valid_frequencies = ["daily", "weekly", "monthly"]
        if report_schedule["frequency"] not in valid_frequencies:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid frequency. Must be one of: {', '.join(valid_frequencies)}",
            )

        report_service = ReportService(db)

        schedule_id = await report_service.create_report_schedule(
            user_id=current_user.id, schedule_config=report_schedule
        )

        logger.info(
            f"Report schedule created for user {current_user.id}, schedule_id: {schedule_id}"
        )

        return {
            "message": "Report schedule created successfully",
            "schedule_id": schedule_id,
            "next_execution": report_schedule.get("next_execution"),
            "status": "active",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating report schedule: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create report schedule")
