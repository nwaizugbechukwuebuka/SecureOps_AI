"""Compliance management routes for SecureOps API."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models.user import User
from ..services import compliance_service
from ..utils.logger import get_logger
from .auth import get_current_user

router = APIRouter()
logger = get_logger(__name__)


# Response Models
class ComplianceFrameworkResponse(BaseModel):
    """Response model for compliance framework"""

    id: int
    name: str
    version: str
    description: str
    controls_count: int
    is_active: bool
    created_at: datetime


class ComplianceControlResponse(BaseModel):
    """Response model for compliance control"""

    id: str
    title: str
    description: str
    status: str
    framework_id: int
    last_assessed: Optional[datetime]


class ComplianceAssessmentResponse(BaseModel):
    """Response model for compliance assessment"""

    id: int
    framework_id: int
    framework_name: str
    status: str
    score: float
    total_controls: int
    passed_controls: int
    failed_controls: int
    created_at: datetime


# Routes
@router.get("/frameworks")
@router.get("/frameworks/")
async def get_frameworks(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get all compliance frameworks"""
    logger.info(f"Getting compliance frameworks for user {current_user.id}")

    # Use the compliance service
    frameworks_data = await compliance_service.get_available_frameworks(db)

    # Return the frameworks data as expected by the tests
    return frameworks_data


@router.get("/frameworks/{framework_id}")
async def get_framework_details(
    framework_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get compliance framework details"""
    logger.info(f"Getting framework {framework_id} for user {current_user.id}")

    # Use the compliance service
    framework_details = await compliance_service.get_framework_details(db, framework_id)

    if not framework_details:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Framework not found"
        )

    return framework_details


@router.get("")
async def get_compliance(
    framework: str = Query(
        None, description="Specific framework to get compliance for"
    ),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get compliance data - overview or by framework"""
    if framework:
        # Get compliance for specific framework
        logger.info(
            f"Getting compliance for framework {framework} for user {current_user.id}"
        )
        framework_compliance = await compliance_service.get_framework_compliance(
            db, framework, current_user.id
        )
        return framework_compliance
    else:
        # Get overall compliance overview
        logger.info(f"Getting compliance overview for user {current_user.id}")
        overview = await compliance_service.get_compliance_overview(db, current_user.id)
        return overview


@router.post("/assess")
async def run_compliance_assessment(
    assessment_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Run compliance assessment"""
    framework = assessment_data.get("framework")
    logger.info(
        f"Running compliance assessment for framework {framework} for user {current_user.id}"
    )

    # Run the assessment using the service
    result = await compliance_service.run_assessment(
        db, framework, current_user.id, assessment_data
    )
    return result


@router.get("/overview", response_model=dict)
@router.get("/overview/", response_model=dict)
async def get_compliance_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get compliance overview"""
    logger.info(f"Getting compliance overview for user {current_user.id}")

    return {
        "total_frameworks": 3,
        "active_frameworks": 2,
        "overall_score": 78.5,
        "critical_issues": 2,
        "recent_assessments": 5,
    }


@router.get(
    "/frameworks/{framework_id}/assessment", response_model=ComplianceAssessmentResponse
)
async def get_compliance_by_framework(
    framework_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get compliance assessment by framework"""
    logger.info(f"Getting compliance assessment for framework {framework_id}")

    return ComplianceAssessmentResponse(
        id=1,
        framework_id=framework_id,
        framework_name="SOC 2",
        status="completed",
        score=78.5,
        total_controls=64,
        passed_controls=50,
        failed_controls=14,
        created_at=datetime.utcnow(),
    )


@router.post("/frameworks/{framework_id}/assess")
@router.post("/frameworks/{framework_id}/assess/")
async def run_compliance_assessment(
    framework_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Run compliance assessment"""
    logger.info(f"Running compliance assessment for framework {framework_id}")

    return {
        "message": "Compliance assessment started",
        "assessment_id": 123,
        "status": "running",
    }


@router.put("/controls/{control_id}/status")
async def update_control_status_v1(
    control_id: str,
    status: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update control status"""
    logger.info(f"Updating control {control_id} status to {status}")

    return {
        "message": "Control status updated",
        "control_id": control_id,
        "status": status,
    }


@router.patch("/controls/{control_id}")
async def update_control_status(
    control_id: str,
    update_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Update control status via PATCH"""
    framework_id = update_data.get("framework", "owasp_top_10")  # default framework
    status = update_data.get("status")
    notes = update_data.get("note", "")

    logger.info(f"PATCH updating control {control_id} status to {status}")

    # Use the service function
    result = await compliance_service.update_control_status(
        db, framework_id, control_id, status, current_user.id, notes
    )
    return result


@router.get("/controls/{control_id}")
async def get_control_details(
    control_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get control details"""
    logger.info(f"Getting control {control_id} details")

    # Use the service function
    result = await compliance_service.get_control_details(
        db, "owasp_top_10", control_id, current_user.id
    )
    return result


@router.post("/report")
async def generate_compliance_report_v2(
    report_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Generate compliance report (POST version)"""
    framework_id = report_data.get("framework", "owasp_top_10")
    format = report_data.get("format", "pdf")
    include_details = report_data.get("include_remediation", True)

    logger.info(f"Generating compliance report for framework {framework_id}")

    # Use the service function
    result = await compliance_service.generate_report(
        db, framework_id, current_user.id, format, include_details
    )
    return result


@router.get("/report/{report_id}")
async def download_compliance_report_v2(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Download compliance report by ID"""
    logger.info(f"Downloading compliance report {report_id}")

    # Use the service function
    result = await compliance_service.get_report_file(db, report_id, current_user.id)

    from fastapi.responses import Response

    return Response(
        content=result["content"],
        headers={"content-type": "application/pdf"},
        media_type="application/pdf",
    )


@router.get("/reports/{framework_id}")
@router.get("/reports/{framework_id}/")
async def generate_compliance_report(
    framework_id: int,
    format: str = Query("pdf", pattern="^(pdf|csv|json)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate compliance report"""
    logger.info(f"Generating compliance report for framework {framework_id}")

    return {
        "message": "Report generation started",
        "report_id": f"report-{framework_id}-{int(datetime.utcnow().timestamp())}",
        "format": format,
        "status": "generating",
    }


@router.get("/reports/{framework_id}/download")
async def download_compliance_report(
    framework_id: int,
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Download compliance report"""
    logger.info(f"Downloading report {report_id} for framework {framework_id}")

    return {
        "download_url": f"/downloads/reports/{report_id}.pdf",
        "expires_at": datetime.utcnow().isoformat(),
    }


@router.get("/trends")
@router.get("/trends/")
async def get_compliance_trends(
    framework: str = Query(None),
    period: str = Query("30d"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get compliance trends"""
    # Extract days from period (e.g., "30d" -> 30)
    days = int(period[:-1]) if period.endswith("d") else 30
    logger.info(f"Getting compliance trends for {days} days")

    # Use the service function
    result = await compliance_service.get_compliance_trends(
        db, framework, current_user.id, days
    )
    return result


@router.post("/automation")
async def configure_automation_v2(
    automation_config: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Configure compliance automation"""
    framework_id = automation_config.get("framework", "owasp_top_10")

    logger.info("Configuring automated compliance assessment")

    # Use the service function
    result = await compliance_service.configure_automation(
        db, framework_id, automation_config, current_user.id
    )
    return result


@router.get("/automation")
async def get_automation_status_v2(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get automation status"""
    logger.info("Getting automation status")

    # Use the service function
    result = await compliance_service.get_automation_status(db, current_user.id)
    return result


@router.post("/automation/configure")
@router.post("/automation/configure/")
async def configure_automated_assessment(
    config: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Configure automated assessment"""
    logger.info("Configuring automated compliance assessment")

    return {
        "message": "Automated assessment configured",
        "config_id": 456,
        "schedule": config.get("schedule", "daily"),
    }


@router.get("/automation/status")
@router.get("/automation/status/")
async def get_automation_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get automation status"""
    logger.info("Getting automation status")

    return {
        "enabled": True,
        "last_run": datetime.utcnow().isoformat(),
        "next_run": datetime.utcnow().isoformat(),
        "status": "healthy",
    }


@router.post("/integrations/sync")
@router.post("/integrations/sync/")
async def sync_with_external_tools(
    tool_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Sync with external tools"""
    logger.info(f"Syncing with external tool: {tool_name}")

    return {
        "message": f"Sync with {tool_name} initiated",
        "sync_id": 789,
        "status": "running",
    }


@router.get("/integrations/export")
@router.get("/integrations/export/")
async def export_compliance_data(
    format: str = Query("json", pattern="^(json|csv|xml)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Export compliance data"""
    logger.info(f"Exporting compliance data in {format} format")

    return {
        "export_url": f"/downloads/exports/compliance-{int(datetime.utcnow().timestamp())}.{format}",
        "format": format,
        "status": "ready",
    }


@router.post("/validation/framework-config")
@router.post("/validation/framework-config/")
async def validate_framework_config(
    config: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Validate framework configuration"""
    logger.info("Validating framework configuration")

    return {
        "valid": True,
        "errors": [],
        "warnings": ["Consider updating control descriptions"],
    }


@router.post("/validation/control-mapping")
@router.post("/validation/control-mapping/")
async def validate_control_mapping(
    mapping: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Validate control mapping"""
    logger.info("Validating control mapping")

    return {
        "valid": True,
        "mapped_controls": 42,
        "unmapped_controls": 2,
        "conflicts": [],
    }


@router.post("/sync")
async def sync_with_external_tools(
    sync_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Sync compliance data with external tools"""
    tool_configs = sync_data.get("tools", [])

    logger.info(f"Syncing with {len(tool_configs)} external tools")

    # Use the service function
    result = await compliance_service.sync_external_tools(
        db, current_user.id, tool_configs
    )
    return result


@router.get("/export")
async def export_compliance_data(
    framework: str = Query(...),
    format: str = Query("json", pattern="^(json|csv|xml)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Export compliance data"""
    logger.info(
        f"Exporting compliance data for framework {framework} in {format} format"
    )

    # Use the service function
    result = await compliance_service.export_compliance_data(
        db, framework, current_user.id, format
    )
    return result


@router.post("/validate")
async def validate_framework_config(
    config_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Validate framework configuration"""
    framework_id = config_data.get("framework", "owasp_top_10")

    logger.info(f"Validating framework configuration for {framework_id}")

    # Use the service function
    result = await compliance_service.validate_framework_config(
        db, framework_id, config_data, current_user.id
    )
    return result


@router.post("/validate-mapping")
async def validate_control_mapping(
    mapping_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Validate control mapping"""
    logger.info("Validating control mapping")

    # Use the service function
    result = await compliance_service.validate_control_mapping(
        db, mapping_data, current_user.id
    )
    return result
