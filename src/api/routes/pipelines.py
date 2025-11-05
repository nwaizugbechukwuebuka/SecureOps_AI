"""
Pipelines API Routes

This module contains FastAPI routes for managing CI/CD pipelines, security scans,
vulnerability tracking, and pipeline monitoring in the SecureOps platform.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..database import get_db
from ..models.pipeline import Pipeline, ScanJob
from ..models.user import User
from ..models.vulnerability import Vulnerability
from ..services.pipeline_services import PipelineService
from ..utils.config import settings
from ..utils.logger import get_logger

# Placeholder logging function
def log_api_request(method: str, path: str, user_id: int):
    logger = get_logger(__name__)
    logger.info(f"API Request: {method} {path} by user {user_id}")

# Placeholder validation function
def validate_pipeline_config(config):
    """Placeholder pipeline configuration validator"""
    return {"valid": True, "errors": []}
from ..utils.validators import validate_url
from .auth import get_current_user
from ..utils.rbac import require_role, require_superuser

router = APIRouter()
logger = get_logger(__name__)


# Pydantic models for request/response
class PipelineResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    repository_url: str
    branch: str
    ci_cd_platform: str
    status: str
    is_active: bool
    last_scan_at: Optional[datetime]
    next_scan_at: Optional[datetime]
    vulnerability_count: int
    critical_count: int
    high_count: int
    created_at: datetime
    updated_at: Optional[datetime]
    configuration: Dict[str, Any]


class CreatePipelineRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    repository_url: str = Field(..., min_length=1)
    branch: str = Field(default="main", min_length=1, max_length=100)
    ci_cd_platform: str = Field(
    ..., pattern="^(github|gitlab|azure_devops|jenkins|bitbucket)$"
    )
    configuration: Dict[str, Any] = {}
    webhook_secret: Optional[str] = None
    scan_schedule: Optional[str] = None  # Cron expression


class UpdatePipelineRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    repository_url: Optional[str] = None
    branch: Optional[str] = Field(None, min_length=1, max_length=100)
    configuration: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None
    scan_schedule: Optional[str] = None


class ScanRequest(BaseModel):
    scanner_types: List[str] = Field(
        default=["dependency", "secret", "container", "policy"]
    )
    target_branch: Optional[str] = None
    scan_config: Dict[str, Any] = {}
    priority: str = Field(default="normal", pattern="^(low|normal|high|urgent)$")


class ScanJobResponse(BaseModel):
    id: int
    pipeline_id: int
    job_type: str
    status: str
    scanner_types: List[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_seconds: Optional[int]
    vulnerabilities_found: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    scan_config: Dict[str, Any]
    error_message: Optional[str]
    results_summary: Dict[str, Any]


class WebhookPayload(BaseModel):
    event_type: str
    repository: Dict[str, Any]
    branch: Optional[str] = None
    commit: Optional[Dict[str, Any]] = None
    pull_request: Optional[Dict[str, Any]] = None
    workflow: Optional[Dict[str, Any]] = None


@router.get("/", response_model=List[PipelineResponse])
async def get_pipelines(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[str] = Query(None, pattern="^(active|inactive|error|scanning)$"),
    ci_cd_platform: Optional[str] = Query(
    None, pattern="^(github|gitlab|azure_devops|jenkins|bitbucket)$"
    ),
    search: Optional[str] = Query(None, min_length=1),
    current_user: User = Depends(require_role("admin", "devops")),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve user's pipelines with filtering and pagination.

    Returns list of pipelines owned by the current user
    with vulnerability counts and scan status.
    """
    log_api_request("GET", "/pipelines/", current_user.id)

    try:
        pipeline_service = PipelineService(db)

        pipelines = await pipeline_service.get_user_pipelines(
            user_id=current_user.id,
            skip=skip,
            limit=limit,
            status=status,
            ci_cd_platform=ci_cd_platform,
            search=search,
        )

        logger.info(f"Retrieved {len(pipelines)} pipelines for user {current_user.id}")
        return pipelines

    except Exception as e:
        logger.error(f"Error retrieving pipelines: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve pipelines")


@router.get("/{pipeline_id}", response_model=PipelineResponse)
async def get_pipeline(
    pipeline_id: int,
    current_user: User = Depends(require_role("admin", "devops")),
    db: AsyncSession = Depends(get_db),
):
    """
    Get specific pipeline by ID with detailed information.

    Returns complete pipeline data including configuration,
    recent scan history, and vulnerability statistics.
    """
    log_api_request("GET", f"/pipelines/{pipeline_id}", current_user.id)

    try:
        pipeline_service = PipelineService(db)

        pipeline = await pipeline_service.get_pipeline_by_id(
            pipeline_id=pipeline_id, user_id=current_user.id
        )

        if not pipeline:
            raise HTTPException(status_code=404, detail="Pipeline not found")

        logger.info(f"Retrieved pipeline {pipeline_id} for user {current_user.id}")
        return pipeline

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving pipeline {pipeline_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve pipeline")


@router.post("/", response_model=PipelineResponse)
async def create_pipeline(
    pipeline_request: CreatePipelineRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_role("admin", "devops")),
    db: AsyncSession = Depends(get_db),
):
    """
    Create new CI/CD pipeline for security monitoring.

    Creates pipeline configuration, validates repository access,
    and optionally triggers initial security scan.
    """
    log_api_request("POST", "/pipelines/", current_user.id)

    from ..utils.logger import AuditLogger
    audit_logger = AuditLogger()
    try:
        # Validate repository URL
        url_validation = validate_url(
            pipeline_request.repository_url, ["http", "https", "git", "ssh"]
        )
        if not url_validation.is_valid:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid repository URL: {', '.join(url_validation.errors)}",
            )

        # Validate pipeline configuration if provided
        if pipeline_request.configuration:
            config_validation = validate_pipeline_config(pipeline_request.configuration)
            if not config_validation.is_valid:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid configuration: {', '.join(config_validation.errors)}",
                )

        pipeline_service = PipelineService(db)

        # Check if pipeline with same repository already exists for user
        existing_pipeline = await pipeline_service.get_pipeline_by_repo(
            repository_url=pipeline_request.repository_url, user_id=current_user.id
        )

        if existing_pipeline:
            raise HTTPException(
                status_code=400, detail="Pipeline for this repository already exists"
            )

        # Create pipeline

        pipeline = await pipeline_service.create_pipeline(
            name=pipeline_request.name,
            description=pipeline_request.description,
            repository_url=pipeline_request.repository_url,
            branch=pipeline_request.branch,
            ci_cd_platform=pipeline_request.ci_cd_platform,
            configuration=pipeline_request.configuration,
            webhook_secret=pipeline_request.webhook_secret,
            scan_schedule=pipeline_request.scan_schedule,
            owner_id=current_user.id,
        )

        # Audit log pipeline creation
        audit_logger.user_action(
            user_id=current_user.id,
            username=getattr(current_user, 'username', None),
            action="create_pipeline",
            resource_type="pipeline",
            resource_id=str(pipeline.id),
            ip_address=None,  # Optionally extract from request context
            user_agent=None,  # Optionally extract from request context
            success=True,
            details={
                "name": pipeline.name,
                "repository_url": pipeline.repository_url,
                "ci_cd_platform": pipeline.ci_cd_platform
            }
        )

        # Queue initial scan if configured
        if pipeline_request.configuration.get("auto_scan_on_create", False):
            background_tasks.add_task(
                pipeline_service.trigger_initial_scan, pipeline.id
            )

        logger.info(f"Created pipeline {pipeline.id} for user {current_user.id}")

        # Return pipeline response
        return PipelineResponse(
            id=pipeline.id,
            name=pipeline.name,
            description=pipeline.description,
            repository_url=pipeline.repository_url,
            branch=pipeline.branch,
            ci_cd_platform=pipeline.ci_cd_platform,
            status=pipeline.status,
            is_active=pipeline.is_active,
            last_scan_at=pipeline.last_scan_at,
            next_scan_at=pipeline.next_scan_at,
            vulnerability_count=0,  # New pipeline
            critical_count=0,
            high_count=0,
            created_at=pipeline.created_at,
            updated_at=pipeline.updated_at,
            configuration=pipeline.configuration or {},
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating pipeline: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create pipeline")


@router.patch("/{pipeline_id}", response_model=PipelineResponse)
async def update_pipeline(
    pipeline_id: int,
    update_request: UpdatePipelineRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Update existing pipeline configuration.

    Allows modifying pipeline settings, repository information,
    and scan configuration.
    """
    log_api_request("PATCH", f"/pipelines/{pipeline_id}", current_user.id)

    try:
        pipeline_service = PipelineService(db)

        # Verify pipeline ownership
        existing_pipeline = await pipeline_service.get_pipeline_by_id(
            pipeline_id=pipeline_id, user_id=current_user.id
        )

        if not existing_pipeline:
            raise HTTPException(status_code=404, detail="Pipeline not found")

        # Validate repository URL if being updated
        if update_request.repository_url:
            url_validation = validate_url(
                update_request.repository_url, ["http", "https", "git", "ssh"]
            )
            if not url_validation.is_valid:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid repository URL: {', '.join(url_validation.errors)}",
                )

        # Validate configuration if being updated
        if update_request.configuration:
            config_validation = validate_pipeline_config(update_request.configuration)
            if not config_validation.is_valid:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid configuration: {', '.join(config_validation.errors)}",
                )

        # Update pipeline
        updated_pipeline = await pipeline_service.update_pipeline(
            pipeline_id=pipeline_id,
            name=update_request.name,
            description=update_request.description,
            repository_url=update_request.repository_url,
            branch=update_request.branch,
            configuration=update_request.configuration,
            is_active=update_request.is_active,
            scan_schedule=update_request.scan_schedule,
        )

        logger.info(f"Updated pipeline {pipeline_id} for user {current_user.id}")
        return updated_pipeline

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating pipeline {pipeline_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update pipeline")


@router.delete("/{pipeline_id}")
async def delete_pipeline(
    pipeline_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Delete pipeline and all associated data.

    Permanently removes pipeline, scan history,
    and vulnerability records.
    """
    log_api_request("DELETE", f"/pipelines/{pipeline_id}", current_user.id)

    try:
        pipeline_service = PipelineService(db)

        # Verify pipeline ownership
        pipeline = await pipeline_service.get_pipeline_by_id(
            pipeline_id=pipeline_id, user_id=current_user.id
        )

        if not pipeline:
            raise HTTPException(status_code=404, detail="Pipeline not found")

        # Delete pipeline and associated data
        await pipeline_service.delete_pipeline(pipeline_id)

        logger.info(f"Deleted pipeline {pipeline_id} for user {current_user.id}")
        return {"message": "Pipeline deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting pipeline {pipeline_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete pipeline")


@router.post("/{pipeline_id}/scan", response_model=ScanJobResponse)
async def trigger_scan(
    pipeline_id: int,
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Trigger security scan for pipeline.

    Starts comprehensive security scan using configured
    scanners and returns scan job information.
    """
    log_api_request("POST", f"/pipelines/{pipeline_id}/scan", current_user.id)

    try:
        pipeline_service = PipelineService(db)

        # Verify pipeline ownership and status
        pipeline = await pipeline_service.get_pipeline_by_id(
            pipeline_id=pipeline_id, user_id=current_user.id
        )

        if not pipeline:
            raise HTTPException(status_code=404, detail="Pipeline not found")

        if not pipeline.is_active:
            raise HTTPException(status_code=400, detail="Cannot scan inactive pipeline")

        # Validate scanner types
        valid_scanners = ["dependency", "secret", "container", "policy"]
        invalid_scanners = [
            s for s in scan_request.scanner_types if s not in valid_scanners
        ]
        if invalid_scanners:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid scanner types: {', '.join(invalid_scanners)}",
            )

        # Create scan job
        scan_job = await pipeline_service.create_scan_job(
            pipeline_id=pipeline_id,
            scanner_types=scan_request.scanner_types,
            target_branch=scan_request.target_branch or pipeline.branch,
            scan_config=scan_request.scan_config,
            priority=scan_request.priority,
            triggered_by=current_user.id,
        )

        # Queue scan execution
        background_tasks.add_task(pipeline_service.execute_scan_job, scan_job.id)

        logger.info(f"Triggered scan {scan_job.id} for pipeline {pipeline_id}")

        return ScanJobResponse(
            id=scan_job.id,
            pipeline_id=scan_job.pipeline_id,
            job_type=scan_job.job_type,
            status=scan_job.status,
            scanner_types=scan_job.scanner_types or [],
            started_at=scan_job.started_at,
            completed_at=scan_job.completed_at,
            duration_seconds=None,
            vulnerabilities_found=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            scan_config=scan_job.configuration or {},
            error_message=scan_job.error_message,
            results_summary=scan_job.results_summary or {},
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error triggering scan for pipeline {pipeline_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to trigger scan")


@router.get("/{pipeline_id}/scans", response_model=List[ScanJobResponse])
async def get_scan_history(
    pipeline_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    status: Optional[str] = Query(
        None, pattern="^(pending|running|completed|failed|cancelled)$"
    ),
    current_user: User = Depends(require_role("admin", "devops", "security")),
    db: AsyncSession = Depends(get_db),
):
    """
    Get scan history for pipeline.

    Returns list of scan jobs with results and statistics
    for the specified pipeline.
    """
    log_api_request("GET", f"/pipelines/{pipeline_id}/scans", current_user.id)

    try:
        pipeline_service = PipelineService(db)

        # Verify pipeline ownership
        pipeline = await pipeline_service.get_pipeline_by_id(
            pipeline_id=pipeline_id, user_id=current_user.id
        )

        if not pipeline:
            raise HTTPException(status_code=404, detail="Pipeline not found")

        # Get scan history
        scan_jobs = await pipeline_service.get_scan_history(
            pipeline_id=pipeline_id, skip=skip, limit=limit, status=status
        )

        logger.info(f"Retrieved {len(scan_jobs)} scan jobs for pipeline {pipeline_id}")
        return scan_jobs

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Error retrieving scan history for pipeline {pipeline_id}: {str(e)}"
        )
        raise HTTPException(status_code=500, detail="Failed to retrieve scan history")


@router.get("/{pipeline_id}/vulnerabilities")
async def get_pipeline_vulnerabilities(
    pipeline_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None, pattern="^(low|medium|high|critical)$"),
    status: Optional[str] = Query(
        None, pattern="^(open|acknowledged|resolved|false_positive)$"
    ),
    scanner_type: Optional[str] = Query(None),
    current_user: User = Depends(require_role("admin", "devops", "security")),
    db: AsyncSession = Depends(get_db),
):
    """
    Get vulnerabilities for specific pipeline.

    Returns filtered list of vulnerabilities found
    in the pipeline's security scans.
    """
    log_api_request("GET", f"/pipelines/{pipeline_id}/vulnerabilities", current_user.id)

    try:
        pipeline_service = PipelineService(db)

        # Verify pipeline ownership
        pipeline = await pipeline_service.get_pipeline_by_id(
            pipeline_id=pipeline_id, user_id=current_user.id
        )

        if not pipeline:
            raise HTTPException(status_code=404, detail="Pipeline not found")

        # Get vulnerabilities
        vulnerabilities = await pipeline_service.get_pipeline_vulnerabilities(
            pipeline_id=pipeline_id,
            skip=skip,
            limit=limit,
            severity=severity,
            status=status,
            scanner_type=scanner_type,
        )

        logger.info(
            f"Retrieved {len(vulnerabilities)} vulnerabilities for pipeline {pipeline_id}"
        )
        return vulnerabilities

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Error retrieving vulnerabilities for pipeline {pipeline_id}: {str(e)}"
        )
        raise HTTPException(
            status_code=500, detail="Failed to retrieve vulnerabilities"
        )


@router.post("/{pipeline_id}/webhook")
async def handle_webhook(
    pipeline_id: int,
    webhook_payload: WebhookPayload,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Handle CI/CD webhook events.

    Processes webhook events from CI/CD platforms
    and triggers appropriate security scans.
    """
    log_api_request("POST", f"/pipelines/{pipeline_id}/webhook", current_user.id)

    try:
        pipeline_service = PipelineService(db)

        # Get pipeline (webhooks might not have user context)
        pipeline_query = select(Pipeline).where(Pipeline.id == pipeline_id)
        result = await db.execute(pipeline_query)
        pipeline = result.scalar_one_or_none()

        if not pipeline:
            raise HTTPException(status_code=404, detail="Pipeline not found")

        # Process webhook event
        scan_triggered = await pipeline_service.process_webhook_event(
            pipeline_id=pipeline_id,
            event_type=webhook_payload.event_type,
            event_data={
                "repository": webhook_payload.repository,
                "branch": webhook_payload.branch,
                "commit": webhook_payload.commit,
                "pull_request": webhook_payload.pull_request,
                "workflow": webhook_payload.workflow,
            },
        )

        logger.info(
            f"Processed webhook for pipeline {pipeline_id}, scan_triggered: {scan_triggered}"
        )

        return {
            "message": "Webhook processed successfully",
            "scan_triggered": scan_triggered,
            "pipeline_id": pipeline_id,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing webhook for pipeline {pipeline_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to process webhook")


@router.get("/{pipeline_id}/statistics")
async def get_pipeline_statistics(
    pipeline_id: int,
    days_back: int = Query(30, ge=1, le=365),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get pipeline statistics and metrics.

    Returns comprehensive statistics including scan frequency,
    vulnerability trends, and security posture metrics.
    """
    log_api_request("GET", f"/pipelines/{pipeline_id}/statistics", current_user.id)

    try:
        pipeline_service = PipelineService(db)

        # Verify pipeline ownership
        pipeline = await pipeline_service.get_pipeline_by_id(
            pipeline_id=pipeline_id, user_id=current_user.id
        )

        if not pipeline:
            raise HTTPException(status_code=404, detail="Pipeline not found")

        # Get statistics
        statistics = await pipeline_service.get_pipeline_statistics(
            pipeline_id=pipeline_id, days_back=days_back
        )

        logger.info(f"Retrieved statistics for pipeline {pipeline_id}")
        return statistics

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Error retrieving statistics for pipeline {pipeline_id}: {str(e)}"
        )
        raise HTTPException(
            status_code=500, detail="Failed to retrieve pipeline statistics"
        )


@router.post("/{pipeline_id}/enable")
async def enable_pipeline(
    pipeline_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Enable pipeline for monitoring and scanning.

    Activates pipeline and resumes scheduled scans
    and webhook processing.
    """
    log_api_request("POST", f"/pipelines/{pipeline_id}/enable", current_user.id)

    try:
        pipeline_service = PipelineService(db)

        # Verify pipeline ownership
        pipeline = await pipeline_service.get_pipeline_by_id(
            pipeline_id=pipeline_id, user_id=current_user.id
        )

        if not pipeline:
            raise HTTPException(status_code=404, detail="Pipeline not found")

        # Enable pipeline
        await pipeline_service.enable_pipeline(pipeline_id)

        logger.info(f"Enabled pipeline {pipeline_id}")
        return {"message": "Pipeline enabled successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error enabling pipeline {pipeline_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to enable pipeline")


@router.post("/{pipeline_id}/disable")
async def disable_pipeline(
    pipeline_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Disable pipeline monitoring and scanning.

    Deactivates pipeline and stops scheduled scans
    and webhook processing.
    """
    log_api_request("POST", f"/pipelines/{pipeline_id}/disable", current_user.id)

    try:
        pipeline_service = PipelineService(db)

        # Verify pipeline ownership
        pipeline = await pipeline_service.get_pipeline_by_id(
            pipeline_id=pipeline_id, user_id=current_user.id
        )

        if not pipeline:
            raise HTTPException(status_code=404, detail="Pipeline not found")

        # Disable pipeline
        await pipeline_service.disable_pipeline(pipeline_id)

        logger.info(f"Disabled pipeline {pipeline_id}")
        return {"message": "Pipeline disabled successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error disabling pipeline {pipeline_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to disable pipeline")
