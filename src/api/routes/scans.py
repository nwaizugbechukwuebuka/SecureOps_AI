"""
Comprehensive Scanning Routes for SecureOps AI Platform
Integrates all security scanners through the orchestration layer.

This module provides API endpoints for:
- Security scan orchestration
- Scanner management
- Scan result retrieval
- Real-time scan status monitoring

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks, status
from pydantic import BaseModel, Field, validator
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models.pipeline import ScanJob, Pipeline
from ..models.vulnerability import Vulnerability
from ..models.user import User
from ..utils.logger import get_logger
from .auth import get_current_user

# Import scanner components
import sys
import os

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from scanners.common import enhanced_orchestrator, ScannerType, SeverityLevel
from tasks.scan_tasks import orchestrate_security_scan, get_scan_status

router = APIRouter()
logger = get_logger(__name__)


# Pydantic models for API requests/responses
class ScanRequest(BaseModel):
    """Request model for initiating security scans."""

    repository_url: str = Field(..., description="Git repository URL to scan")
    branch: str = Field(default="main", description="Branch to scan")
    scan_types: List[str] = Field(
        default=["dependency", "docker", "secret", "threat", "compliance"],
        description="Types of scans to perform",
    )
    scan_config: Optional[Dict[str, Any]] = Field(
        default=None, description="Additional scan configuration options"
    )
    notify_on_completion: bool = Field(
        default=True, description="Whether to send notifications when scan completes"
    )

    @validator("repository_url")
    def validate_repository_url(cls, v):
        if not v or not v.strip():
            raise ValueError("Repository URL is required")
        if not (v.startswith("https://") or v.startswith("git@")):
            raise ValueError("Invalid repository URL format")
        return v.strip()

    @validator("scan_types")
    def validate_scan_types(cls, v):
        valid_types = ["dependency", "docker", "secret", "threat", "compliance"]
        for scan_type in v:
            if scan_type not in valid_types:
                raise ValueError(
                    f"Invalid scan type: {scan_type}. Valid types: {valid_types}"
                )
        return v


class ScanResponse(BaseModel):
    """Response model for scan initiation."""

    scan_id: str
    task_id: str
    status: str
    repository_url: str
    branch: str
    scan_types: List[str]
    initiated_at: datetime
    estimated_completion: Optional[datetime] = None


class ScanStatusResponse(BaseModel):
    """Response model for scan status."""

    scan_id: str
    task_id: str
    status: str
    progress: float = Field(ge=0, le=100)
    current_step: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    results_available: bool = False


class ScanResultsResponse(BaseModel):
    """Response model for scan results."""

    scan_id: str
    repository_url: str
    branch: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    overall_risk_score: float
    risk_level: str
    compliance_status: Dict[str, str]
    scan_summary: Dict[str, Any]
    detailed_findings: Dict[str, Any]


class ScannerHealthResponse(BaseModel):
    """Response model for scanner health status."""

    scanner_count: int
    available_scanners: int
    unavailable_scanners: int
    scanner_details: Dict[str, Any]
    last_updated: datetime


class FindingResponse(BaseModel):
    """Response model for individual findings."""

    id: str
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: float
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    scanner_name: str
    found_at: datetime


# API Endpoints


@router.post("/scans/initiate", response_model=ScanResponse, tags=["Scanning"])
async def initiate_security_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Initiate a comprehensive security scan for a repository.

    This endpoint triggers the complete security scanning workflow including:
    - Repository cloning and analysis
    - Multi-scanner security analysis
    - Result processing and aggregation
    - Report generation
    - Alert notification (if configured)
    """
    try:
        logger.info(
            f"Initiating security scan for {scan_request.repository_url}#{scan_request.branch} by user {current_user.id}"
        )

        # Trigger the comprehensive scan via Celery task
        task = orchestrate_security_scan.delay(
            repository_url=scan_request.repository_url,
            branch=scan_request.branch,
            scan_types=scan_request.scan_types,
            user_id=current_user.id,
            scan_config=scan_request.scan_config or {},
        )

        scan_initiated = datetime.utcnow()

        # Store scan job in database
        scan_job = ScanJob(
            task_id=task.id,
            repository_url=scan_request.repository_url,
            branch=scan_request.branch,
            scan_types=scan_request.scan_types,
            user_id=current_user.id,
            status="initiated",
            initiated_at=scan_initiated,
        )

        db.add(scan_job)
        await db.commit()
        await db.refresh(scan_job)

        logger.info(f"Security scan {scan_job.id} initiated with task {task.id}")

        return ScanResponse(
            scan_id=str(scan_job.id),
            task_id=task.id,
            status="initiated",
            repository_url=scan_request.repository_url,
            branch=scan_request.branch,
            scan_types=scan_request.scan_types,
            initiated_at=scan_initiated,
        )

    except Exception as e:
        logger.error(f"Failed to initiate security scan: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate security scan: {str(e)}",
        )


@router.get(
    "/scans/{scan_id}/status", response_model=ScanStatusResponse, tags=["Scanning"]
)
async def get_scan_status(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get the current status of a security scan.

    Returns real-time status information including:
    - Current execution phase
    - Progress percentage
    - Estimated completion time
    - Any error messages
    """
    try:
        # Get scan job from database
        scan_job = await db.get(ScanJob, scan_id)
        if not scan_job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
            )

        # Check authorization
        if scan_job.user_id != current_user.id and not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Access denied"
            )

        # Get task status from Celery
        task_status = get_scan_status(scan_job.task_id)

        # Update scan job status if needed
        if task_status.get("status") != scan_job.status:
            scan_job.status = task_status.get("status", scan_job.status)
            if task_status.get("status") == "completed":
                scan_job.completed_at = datetime.utcnow()
            await db.commit()

        return ScanStatusResponse(
            scan_id=scan_id,
            task_id=scan_job.task_id,
            status=scan_job.status,
            progress=task_status.get("progress", 0),
            current_step=task_status.get("current_step"),
            started_at=scan_job.initiated_at,
            completed_at=scan_job.completed_at,
            error_message=task_status.get("error_message"),
            results_available=scan_job.status == "completed",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan status for {scan_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scan status",
        )


@router.get(
    "/scans/{scan_id}/results", response_model=ScanResultsResponse, tags=["Scanning"]
)
async def get_scan_results(
    scan_id: str,
    include_details: bool = Query(
        default=True, description="Include detailed findings"
    ),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get comprehensive results from a completed security scan.

    Returns:
    - Executive summary with risk scores
    - Detailed findings by severity
    - Compliance status assessment
    - Remediation recommendations
    """
    try:
        # Get scan job
        scan_job = await db.get(ScanJob, scan_id)
        if not scan_job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
            )

        # Check authorization
        if scan_job.user_id != current_user.id and not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Access denied"
            )

        if scan_job.status != "completed":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Scan not completed yet"
            )

        # Get scan results from task
        task_result = orchestrate_security_scan.AsyncResult(scan_job.task_id)

        if not task_result or not task_result.successful():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan results not available",
            )

        scan_data = task_result.result
        results = scan_data.get("results", {})

        # Extract summary information
        executive_summary = results.get("executive_summary", {})

        response_data = {
            "scan_id": scan_id,
            "repository_url": scan_job.repository_url,
            "branch": scan_job.branch,
            "total_findings": executive_summary.get("total_findings", 0),
            "critical_count": executive_summary.get("critical_issues", 0),
            "high_count": executive_summary.get("high_issues", 0),
            "medium_count": 0,  # Extract from detailed results
            "low_count": 0,  # Extract from detailed results
            "info_count": 0,  # Extract from detailed results
            "overall_risk_score": executive_summary.get("overall_risk_score", 0),
            "risk_level": executive_summary.get("risk_level", "UNKNOWN"),
            "compliance_status": results.get("compliance_status", {}),
            "scan_summary": results.get("scan_metadata", {}),
            "detailed_findings": (
                results.get("detailed_findings", {}) if include_details else {}
            ),
        }

        return ScanResultsResponse(**response_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan results for {scan_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scan results",
        )


@router.get("/scans", tags=["Scanning"])
async def list_scans(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    status_filter: Optional[str] = Query(
        default=None, description="Filter by scan status"
    ),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    List security scans for the current user.

    Supports filtering by status and pagination.
    """
    try:
        from sqlalchemy import select

        # Build query
        query = select(ScanJob).where(ScanJob.user_id == current_user.id)

        if status_filter:
            query = query.where(ScanJob.status == status_filter)

        query = query.order_by(ScanJob.initiated_at.desc()).offset(skip).limit(limit)

        # Execute query
        result = await db.execute(query)
        scans = result.scalars().all()

        # Format response
        scan_list = []
        for scan in scans:
            scan_list.append(
                {
                    "scan_id": str(scan.id),
                    "repository_url": scan.repository_url,
                    "branch": scan.branch,
                    "status": scan.status,
                    "scan_types": scan.scan_types,
                    "initiated_at": scan.initiated_at,
                    "completed_at": scan.completed_at,
                }
            )

        return {
            "scans": scan_list,
            "total": len(scan_list),
            "skip": skip,
            "limit": limit,
        }

    except Exception as e:
        logger.error(f"Failed to list scans: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scans",
        )


@router.get(
    "/scanners/health",
    response_model=ScannerHealthResponse,
    tags=["Scanner Management"],
)
async def get_scanners_health(current_user: User = Depends(get_current_user)):
    """
    Get health status of all registered security scanners.

    Returns information about scanner availability and capabilities.
    """
    try:
        health_status = await enhanced_orchestrator.get_health_status()

        return ScannerHealthResponse(
            scanner_count=health_status["scanner_count"],
            available_scanners=health_status["available_scanners"],
            unavailable_scanners=health_status["unavailable_scanners"],
            scanner_details=health_status["scanner_details"],
            last_updated=datetime.utcnow(),
        )

    except Exception as e:
        logger.error(f"Failed to get scanner health: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scanner health status",
        )


@router.get("/scanners/capabilities", tags=["Scanner Management"])
async def get_scanner_capabilities(current_user: User = Depends(get_current_user)):
    """
    Get capabilities and configuration options for all scanners.
    """
    try:
        capabilities = {
            "supported_scan_types": [
                scanner_type.value for scanner_type in ScannerType
            ],
            "severity_levels": [level.value for level in SeverityLevel],
            "scanner_details": {},
        }

        # Get detailed capabilities from orchestrator
        health_status = await enhanced_orchestrator.get_health_status()

        for scanner_name, details in health_status["scanner_details"].items():
            capabilities["scanner_details"][scanner_name] = {
                "type": details.get("type"),
                "available": details.get("available"),
                "version": details.get("version"),
                "capabilities": details.get("capabilities", []),
            }

        return capabilities

    except Exception as e:
        logger.error(f"Failed to get scanner capabilities: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scanner capabilities",
        )


@router.delete("/scans/{scan_id}", tags=["Scanning"])
async def cancel_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Cancel a running security scan.
    """
    try:
        # Get scan job
        scan_job = await db.get(ScanJob, scan_id)
        if not scan_job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
            )

        # Check authorization
        if scan_job.user_id != current_user.id and not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Access denied"
            )

        if scan_job.status in ["completed", "failed", "cancelled"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot cancel completed scan",
            )

        # Revoke Celery task
        from celery import current_app

        current_app.control.revoke(scan_job.task_id, terminate=True)

        # Update status
        scan_job.status = "cancelled"
        scan_job.completed_at = datetime.utcnow()
        await db.commit()

        logger.info(f"Scan {scan_id} cancelled by user {current_user.id}")

        return {"message": "Scan cancelled successfully", "scan_id": scan_id}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel scan {scan_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cancel scan",
        )


@router.post("/scans/{scan_id}/retry", tags=["Scanning"])
async def retry_failed_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Retry a failed security scan with the same configuration.
    """
    try:
        # Get original scan job
        original_scan = await db.get(ScanJob, scan_id)
        if not original_scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Original scan not found"
            )

        # Check authorization
        if original_scan.user_id != current_user.id and not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Access denied"
            )

        if original_scan.status != "failed":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Can only retry failed scans",
            )

        # Create new scan task with same parameters
        task = orchestrate_security_scan.delay(
            repository_url=original_scan.repository_url,
            branch=original_scan.branch,
            scan_types=original_scan.scan_types,
            user_id=current_user.id,
            scan_config={},
        )

        # Create new scan job
        new_scan = ScanJob(
            task_id=task.id,
            repository_url=original_scan.repository_url,
            branch=original_scan.branch,
            scan_types=original_scan.scan_types,
            user_id=current_user.id,
            status="initiated",
            initiated_at=datetime.utcnow(),
            parent_scan_id=original_scan.id,
        )

        db.add(new_scan)
        await db.commit()
        await db.refresh(new_scan)

        logger.info(f"Retry scan {new_scan.id} created for failed scan {scan_id}")

        return {
            "message": "Scan retry initiated",
            "new_scan_id": str(new_scan.id),
            "task_id": task.id,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retry scan {scan_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retry scan",
        )
