"""Pipeline management routes for SecureOps API."""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models.pipeline import Pipeline, PipelineRun
from ..models.user import User
from ..utils.logger import get_logger
from .auth import get_current_user

router = APIRouter()
logger = get_logger(__name__)


# Pydantic models
class PipelineResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    repository_url: Optional[str]
    branch: str
    pipeline_type: str
    is_active: bool
    last_run_at: Optional[datetime]
    last_run_status: Optional[str]

    class Config:
        from_attributes = True


class CreatePipelineRequest(BaseModel):
    name: str = Field(..., max_length=255)
    description: Optional[str] = None
    repository_url: Optional[str] = None
    branch: str = Field(default="main", max_length=100)
    pipeline_type: str = Field(..., max_length=50)


class PipelineRunResponse(BaseModel):
    id: int
    pipeline_id: int
    run_number: int
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_seconds: Optional[int]
    trigger_type: Optional[str]
    commit_hash: Optional[str]

    class Config:
        from_attributes = True


@router.get("/", response_model=List[PipelineResponse])
@router.get("", response_model=List[PipelineResponse])
async def get_pipelines(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    active_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve pipelines with pagination."""
    try:
        # Mock pipeline data for testing
        mock_pipelines = [
            PipelineResponse(
                id=1,
                name="SecureOps CI/CD",
                description="Main application pipeline",
                repository_url="https://github.com/nwaizugbechukwuebuka/SecureOps",
                branch="main",
                pipeline_type="github_actions",
                is_active=True,
                last_run_at=datetime.now(),
                last_run_status="success",
            )
        ]

        logger.info(
            f"Retrieved {len(mock_pipelines)} pipelines for user {current_user.id}"
        )
        return mock_pipelines

    except Exception as e:
        logger.error(f"Error retrieving pipelines: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve pipelines",
        )


@router.get("/{pipeline_id}", response_model=PipelineResponse)
async def get_pipeline(
    pipeline_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve a specific pipeline by ID."""
    try:
        # Mock pipeline data
        if pipeline_id == 1:
            return PipelineResponse(
                id=1,
                name="SecureOps CI/CD",
                description="Main application pipeline",
                repository_url="https://github.com/nwaizugbechukwuebuka/SecureOps",
                branch="main",
                pipeline_type="github_actions",
                is_active=True,
                last_run_at=datetime.now(),
                last_run_status="success",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Pipeline not found"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving pipeline {pipeline_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve pipeline",
        )


@router.post("/", response_model=PipelineResponse, status_code=status.HTTP_201_CREATED)
@router.post("", response_model=PipelineResponse, status_code=status.HTTP_201_CREATED)
async def create_pipeline(
    pipeline_data: CreatePipelineRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new pipeline."""
    try:
        logger.info(f"Pipeline creation attempted by user {current_user.id}")

        # Mock pipeline creation
        return PipelineResponse(
            id=2,
            name=pipeline_data.name,
            description=pipeline_data.description,
            repository_url=pipeline_data.repository_url,
            branch=pipeline_data.branch,
            pipeline_type=pipeline_data.pipeline_type,
            is_active=True,
            last_run_at=None,
            last_run_status=None,
        )

    except Exception as e:
        logger.error(f"Error creating pipeline: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create pipeline",
        )


@router.get("/{pipeline_id}/runs", response_model=List[PipelineRunResponse])
async def get_pipeline_runs(
    pipeline_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get runs for a specific pipeline."""
    try:
        # Mock pipeline runs
        mock_runs = [
            PipelineRunResponse(
                id=1,
                pipeline_id=pipeline_id,
                run_number=1,
                status="completed",
                started_at=datetime.now(),
                completed_at=datetime.now(),
                duration_seconds=120,
                trigger_type="push",
                commit_hash="abc123def456",
            )
        ]

        logger.info(f"Retrieved {len(mock_runs)} runs for pipeline {pipeline_id}")
        return mock_runs

    except Exception as e:
        logger.error(f"Error retrieving pipeline runs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve pipeline runs",
        )


@router.post("/{pipeline_id}/trigger")
async def trigger_pipeline(
    pipeline_id: int,
    trigger_reason: Optional[str] = "Manual trigger",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Trigger a pipeline run."""
    try:
        logger.info(f"Pipeline {pipeline_id} triggered by user {current_user.id}")

        return {
            "message": "Pipeline triggered successfully",
            "pipeline_id": pipeline_id,
            "run_id": 123,  # Mock run ID
            "status": "queued",
        }

    except Exception as e:
        logger.error(f"Error triggering pipeline {pipeline_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to trigger pipeline",
        )
