"""
Pipeline Service Layer

This module provides business logic for managing CI/CD pipelines,
security scans, and vulnerability tracking in the SecureOps platform.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from celery import current_app as celery_app
from sqlalchemy import and_, delete, desc, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..models.alert import Alert
from ..models.pipeline import Pipeline, ScanJob
from ..models.user import User
from ..models.vulnerability import Vulnerability
from ..utils.config import settings
from ..utils.logger import get_logger

logger = get_logger(__name__)


class PipelineService:
    """Service for managing CI/CD pipelines and security scans."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_user_pipelines(
        self,
        user_id: int,
        skip: int = 0,
        limit: int = 100,
        status: Optional[str] = None,
        ci_cd_platform: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get paginated list of user's pipelines with filtering.

        Args:
            user_id: User ID to filter pipelines
            skip: Number of records to skip
            limit: Maximum number of records to return
            status: Filter by pipeline status
            ci_cd_platform: Filter by CI/CD platform
            search: Search term for pipeline name or repository

        Returns:
            List of pipeline data with vulnerability counts
        """
        try:
            # Build base query
            query = select(Pipeline).where(Pipeline.owner_id == user_id)

            # Apply filters
            if status:
                query = query.where(Pipeline.status == status)

            if ci_cd_platform:
                query = query.where(Pipeline.ci_cd_platform == ci_cd_platform)

            if search:
                search_term = f"%{search.lower()}%"
                query = query.where(
                    or_(
                        func.lower(Pipeline.name).like(search_term),
                        func.lower(Pipeline.repository_url).like(search_term),
                        func.lower(Pipeline.description).like(search_term),
                    )
                )

            # Add ordering and pagination
            query = query.order_by(desc(Pipeline.updated_at)).offset(skip).limit(limit)

            # Execute query
            result = await self.db.execute(query)
            pipelines = result.scalars().all()

            # Get vulnerability counts for each pipeline
            pipeline_data = []
            for pipeline in pipelines:
                vuln_counts = await self._get_vulnerability_counts(pipeline.id)

                pipeline_data.append(
                    {
                        "id": pipeline.id,
                        "name": pipeline.name,
                        "description": pipeline.description,
                        "repository_url": pipeline.repository_url,
                        "branch": pipeline.branch,
                        "ci_cd_platform": pipeline.ci_cd_platform,
                        "status": pipeline.status,
                        "is_active": pipeline.is_active,
                        "last_scan_at": pipeline.last_scan_at,
                        "next_scan_at": pipeline.next_scan_at,
                        "vulnerability_count": vuln_counts["total"],
                        "critical_count": vuln_counts["critical"],
                        "high_count": vuln_counts["high"],
                        "created_at": pipeline.created_at,
                        "updated_at": pipeline.updated_at,
                        "configuration": pipeline.configuration or {},
                    }
                )

            return pipeline_data

        except Exception as e:
            logger.error(f"Error getting user pipelines: {str(e)}")
            raise

    async def get_pipeline_by_id(self, pipeline_id: int, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Get specific pipeline by ID with detailed information.

        Args:
            pipeline_id: Pipeline ID
            user_id: User ID for ownership verification

        Returns:
            Pipeline data with vulnerability counts or None if not found
        """
        try:
            query = select(Pipeline).where(and_(Pipeline.id == pipeline_id, Pipeline.owner_id == user_id))

            result = await self.db.execute(query)
            pipeline = result.scalar_one_or_none()

            if not pipeline:
                return None

            # Get vulnerability counts
            vuln_counts = await self._get_vulnerability_counts(pipeline.id)

            return {
                "id": pipeline.id,
                "name": pipeline.name,
                "description": pipeline.description,
                "repository_url": pipeline.repository_url,
                "branch": pipeline.branch,
                "ci_cd_platform": pipeline.ci_cd_platform,
                "status": pipeline.status,
                "is_active": pipeline.is_active,
                "last_scan_at": pipeline.last_scan_at,
                "next_scan_at": pipeline.next_scan_at,
                "vulnerability_count": vuln_counts["total"],
                "critical_count": vuln_counts["critical"],
                "high_count": vuln_counts["high"],
                "created_at": pipeline.created_at,
                "updated_at": pipeline.updated_at,
                "configuration": pipeline.configuration or {},
            }

        except Exception as e:
            logger.error(f"Error getting pipeline {pipeline_id}: {str(e)}")
            raise

    async def get_pipeline_by_repo(self, repository_url: str, user_id: int) -> Optional[Pipeline]:
        """
        Get pipeline by repository URL for duplicate checking.

        Args:
            repository_url: Repository URL to search
            user_id: User ID for ownership verification

        Returns:
            Pipeline object or None if not found
        """
        try:
            query = select(Pipeline).where(
                and_(
                    Pipeline.repository_url == repository_url,
                    Pipeline.owner_id == user_id,
                )
            )

            result = await self.db.execute(query)
            return result.scalar_one_or_none()

        except Exception as e:
            logger.error(f"Error getting pipeline by repo: {str(e)}")
            raise

    async def create_pipeline(
        self,
        name: str,
        repository_url: str,
        branch: str,
        ci_cd_platform: str,
        owner_id: int,
        description: Optional[str] = None,
        configuration: Optional[Dict[str, Any]] = None,
        webhook_secret: Optional[str] = None,
        scan_schedule: Optional[str] = None,
    ) -> Pipeline:
        """
        Create new pipeline with configuration.

        Args:
            name: Pipeline name
            repository_url: Git repository URL
            branch: Target branch
            ci_cd_platform: CI/CD platform type
            owner_id: User ID of pipeline owner
            description: Optional description
            configuration: Pipeline configuration
            webhook_secret: Webhook authentication secret
            scan_schedule: Cron expression for scheduled scans

        Returns:
            Created pipeline object
        """
        try:
            # Generate webhook URL
            webhook_url = f"{settings.BASE_URL}/api/pipelines/webhook/{owner_id}"

            # Create pipeline
            pipeline = Pipeline(
                name=name,
                description=description,
                repository_url=repository_url,
                branch=branch,
                ci_cd_platform=ci_cd_platform,
                status="active",
                is_active=True,
                configuration=configuration or {},
                webhook_url=webhook_url,
                webhook_secret=webhook_secret,
                scan_schedule=scan_schedule,
                owner_id=owner_id,
                created_at=datetime.now(timezone.utc),
            )

            self.db.add(pipeline)
            await self.db.commit()
            await self.db.refresh(pipeline)

            logger.info(f"Created pipeline {pipeline.id} for user {owner_id}")
            return pipeline

        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error creating pipeline: {str(e)}")
            raise

    async def update_pipeline(
        self,
        pipeline_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        repository_url: Optional[str] = None,
        branch: Optional[str] = None,
        configuration: Optional[Dict[str, Any]] = None,
        is_active: Optional[bool] = None,
        scan_schedule: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Update existing pipeline configuration.

        Args:
            pipeline_id: Pipeline ID to update
            **kwargs: Fields to update

        Returns:
            Updated pipeline data
        """
        try:
            update_data = {"updated_at": datetime.now(timezone.utc)}

            if name is not None:
                update_data["name"] = name
            if description is not None:
                update_data["description"] = description
            if repository_url is not None:
                update_data["repository_url"] = repository_url
            if branch is not None:
                update_data["branch"] = branch
            if configuration is not None:
                update_data["configuration"] = configuration
            if is_active is not None:
                update_data["is_active"] = is_active
                update_data["status"] = "active" if is_active else "inactive"
            if scan_schedule is not None:
                update_data["scan_schedule"] = scan_schedule

            # Audit log: configuration change
            logger.info(
                f"Pipeline config update: pipeline_id={pipeline_id}, changes={list(update_data.keys())}",
                extra={
                    "event_type": "audit.configuration_changed",
                    "pipeline_id": pipeline_id,
                    "fields_changed": list(update_data.keys()),
                },
            )

            # Update pipeline
            query = update(Pipeline).where(Pipeline.id == pipeline_id).values(update_data)
            await self.db.execute(query)
            await self.db.commit()

            # Return updated pipeline
            return await self.get_pipeline_by_id(pipeline_id, None)  # Skip user check for internal use

        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error updating pipeline {pipeline_id}: {str(e)}")
            raise

    async def delete_pipeline(self, pipeline_id: int) -> None:
        """
        Delete pipeline and all associated data.

        Args:
            pipeline_id: Pipeline ID to delete
        """
        try:
            # Delete associated vulnerabilities
            vuln_query = delete(Vulnerability).where(Vulnerability.pipeline_id == pipeline_id)
            await self.db.execute(vuln_query)

            # Delete associated scan jobs
            scan_query = delete(ScanJob).where(ScanJob.pipeline_id == pipeline_id)
            await self.db.execute(scan_query)

            # Delete associated alerts
            alert_query = delete(Alert).where(Alert.pipeline_id == pipeline_id)
            await self.db.execute(alert_query)

            # Delete pipeline
            pipeline_query = delete(Pipeline).where(Pipeline.id == pipeline_id)
            await self.db.execute(pipeline_query)

            await self.db.commit()
            logger.info(f"Deleted pipeline {pipeline_id} and associated data")
            # Audit log: pipeline deletion
            logger.info(
                f"Pipeline deleted: pipeline_id={pipeline_id}",
                extra={
                    "event_type": "audit.pipeline_deleted",
                    "pipeline_id": pipeline_id,
                },
            )

        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error deleting pipeline {pipeline_id}: {str(e)}")
            raise

    async def create_scan_job(
        self,
        pipeline_id: int,
        scanner_types: List[str],
        target_branch: str,
        scan_config: Dict[str, Any],
        priority: str = "normal",
        triggered_by: Optional[int] = None,
    ) -> ScanJob:
        """
        Create new scan job for pipeline.

        Args:
            pipeline_id: Target pipeline ID
            scanner_types: List of scanners to run
            target_branch: Branch to scan
            scan_config: Scanner configuration
            priority: Scan priority level
            triggered_by: User ID who triggered scan

        Returns:
            Created scan job object
        """
        try:
            scan_job = ScanJob(
                pipeline_id=pipeline_id,
                job_type="security_scan",
                status="pending",
                scanner_types=scanner_types,
                target_branch=target_branch,
                configuration=scan_config,
                priority=priority,
                triggered_by=triggered_by,
                created_at=datetime.now(timezone.utc),
            )

            self.db.add(scan_job)
            await self.db.commit()
            await self.db.refresh(scan_job)

            logger.info(f"Created scan job {scan_job.id} for pipeline {pipeline_id}")
            return scan_job

        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error creating scan job: {str(e)}")
            raise

    async def get_scan_history(
        self,
        pipeline_id: int,
        skip: int = 0,
        limit: int = 50,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get scan job history for pipeline.

        Args:
            pipeline_id: Pipeline ID
            skip: Number of records to skip
            limit: Maximum number of records
            status: Filter by scan status

        Returns:
            List of scan job data with results
        """
        try:
            query = select(ScanJob).where(ScanJob.pipeline_id == pipeline_id)

            if status:
                query = query.where(ScanJob.status == status)

            query = query.order_by(desc(ScanJob.created_at)).offset(skip).limit(limit)

            result = await self.db.execute(query)
            scan_jobs = result.scalars().all()

            # Build response data
            scan_data = []
            for job in scan_jobs:
                duration_seconds = None
                if job.started_at and job.completed_at:
                    duration_seconds = int((job.completed_at - job.started_at).total_seconds())

                # Get vulnerability counts for this scan
                vuln_counts = await self._get_scan_vulnerability_counts(job.id)

                # Summarize AI-detected threats from results_summary if present
                results_summary = job.results_summary or {}
                ai_threats = []
                ai_threat_count = 0
                ai_critical_count = 0
                ai_high_count = 0
                ai_medium_count = 0
                ai_low_count = 0
                if "ai_threats" in results_summary:
                    ai_threats = results_summary["ai_threats"]
                    ai_threat_count = len(ai_threats)
                    for t in ai_threats:
                        level = t.get("threat_level", "high")
                        if level == "critical":
                            ai_critical_count += 1
                        elif level == "high":
                            ai_high_count += 1
                        elif level == "medium":
                            ai_medium_count += 1
                        elif level == "low":
                            ai_low_count += 1

                scan_data.append(
                    {
                        "id": job.id,
                        "pipeline_id": job.pipeline_id,
                        "job_type": job.job_type,
                        "status": job.status,
                        "scanner_types": job.scanner_types or [],
                        "started_at": job.started_at,
                        "completed_at": job.completed_at,
                        "duration_seconds": duration_seconds,
                        "vulnerabilities_found": vuln_counts["total"],
                        "critical_count": vuln_counts["critical"],
                        "high_count": vuln_counts["high"],
                        "medium_count": vuln_counts["medium"],
                        "low_count": vuln_counts["low"],
                        "scan_config": job.configuration or {},
                        "error_message": job.error_message,
                        "results_summary": {
                            **results_summary,
                            "ai_threat_summary": (
                                {
                                    "count": ai_threat_count,
                                    "critical": ai_critical_count,
                                    "high": ai_high_count,
                                    "medium": ai_medium_count,
                                    "low": ai_low_count,
                                }
                                if ai_threat_count > 0
                                else {}
                            ),
                        },
                    }
                )

            return scan_data

        except Exception as e:
            logger.error(f"Error getting scan history: {str(e)}")
            raise

    async def get_pipeline_vulnerabilities(
        self,
        pipeline_id: int,
        skip: int = 0,
        limit: int = 100,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        scanner_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities for specific pipeline.

        Args:
            pipeline_id: Pipeline ID
            skip: Number of records to skip
            limit: Maximum number of records
            severity: Filter by severity level
            status: Filter by vulnerability status
            scanner_type: Filter by scanner type

        Returns:
            List of vulnerability data
        """
        try:
            query = select(Vulnerability).where(Vulnerability.pipeline_id == pipeline_id)

            if severity:
                query = query.where(Vulnerability.severity == severity)
            if status:
                query = query.where(Vulnerability.status == status)
            if scanner_type:
                query = query.where(Vulnerability.scanner_type == scanner_type)

            query = query.order_by(desc(Vulnerability.created_at)).offset(skip).limit(limit)

            result = await self.db.execute(query)
            vulnerabilities = result.scalars().all()

            # Convert to dict format
            vuln_data = []
            for vuln in vulnerabilities:
                vuln_data.append(
                    {
                        "id": vuln.id,
                        "title": vuln.title,
                        "description": vuln.description,
                        "severity": vuln.severity,
                        "status": vuln.status,
                        "scanner_type": vuln.scanner_type,
                        "vulnerability_id": vuln.vulnerability_id,
                        "cve_id": vuln.cve_id,
                        "cvss_score": vuln.cvss_score,
                        "file_path": vuln.file_path,
                        "line_number": vuln.line_number,
                        "remediation": vuln.remediation,
                        "references": vuln.references,
                        "first_detected": vuln.first_detected,
                        "last_detected": vuln.last_detected,
                        "created_at": vuln.created_at,
                        "updated_at": vuln.updated_at,
                    }
                )

            return vuln_data

        except Exception as e:
            logger.error(f"Error getting pipeline vulnerabilities: {str(e)}")
            raise

    async def process_webhook_event(self, pipeline_id: int, event_type: str, event_data: Dict[str, Any]) -> bool:
        """
        Process CI/CD webhook event and trigger scan if needed.

        Args:
            pipeline_id: Pipeline ID
            event_type: Type of webhook event
            event_data: Event payload data

        Returns:
            True if scan was triggered, False otherwise
        """
        try:
            # Get pipeline configuration
            query = select(Pipeline).where(Pipeline.id == pipeline_id)
            result = await self.db.execute(query)
            pipeline = result.scalar_one_or_none()

            if not pipeline or not pipeline.is_active:
                return False

            # Check if event should trigger scan
            config = pipeline.configuration or {}
            webhook_config = config.get("webhook", {})

            # Default trigger events
            trigger_events = webhook_config.get("trigger_events", ["push", "pull_request", "merge"])

            if event_type not in trigger_events:
                return False

            # Check branch filter if configured
            target_branch = event_data.get("branch", pipeline.branch)
            branch_filter = webhook_config.get("branch_filter", [pipeline.branch])

            if branch_filter and target_branch not in branch_filter:
                return False

            # Create and queue scan job
            scanner_types = webhook_config.get("scanners", ["dependency", "secret", "container"])

            scan_job = await self.create_scan_job(
                pipeline_id=pipeline_id,
                scanner_types=scanner_types,
                target_branch=target_branch,
                scan_config={"webhook_triggered": True, "event_type": event_type},
                priority="normal",
            )

            # Queue scan execution (would be handled by Celery in production)
            logger.info(f"Queued scan job {scan_job.id} from webhook event {event_type}")

            return True

        except Exception as e:
            logger.error(f"Error processing webhook event: {str(e)}")
            raise

    async def get_pipeline_statistics(self, pipeline_id: int, days_back: int = 30) -> Dict[str, Any]:
        """
        Get comprehensive pipeline statistics and metrics.

        Args:
            pipeline_id: Pipeline ID
            days_back: Number of days to include in statistics

        Returns:
            Dictionary containing various pipeline metrics
        """
        try:
            start_date = datetime.now(timezone.utc) - timedelta(days=days_back)

            # Get scan statistics
            scan_query = (
                select(func.count(ScanJob.id), ScanJob.status)
                .where(
                    and_(
                        ScanJob.pipeline_id == pipeline_id,
                        ScanJob.created_at >= start_date,
                    )
                )
                .group_by(ScanJob.status)
            )

            scan_result = await self.db.execute(scan_query)
            scan_stats = {status: count for count, status in scan_result.fetchall()}

            # Get vulnerability trends
            vuln_query = (
                select(
                    func.count(Vulnerability.id),
                    Vulnerability.severity,
                    func.date_trunc("day", Vulnerability.created_at).label("date"),
                )
                .where(
                    and_(
                        Vulnerability.pipeline_id == pipeline_id,
                        Vulnerability.created_at >= start_date,
                    )
                )
                .group_by(
                    Vulnerability.severity,
                    func.date_trunc("day", Vulnerability.created_at),
                )
            )

            vuln_result = await self.db.execute(vuln_query)
            vuln_trends = {}
            for count, severity, date in vuln_result.fetchall():
                date_str = date.strftime("%Y-%m-%d")
                if date_str not in vuln_trends:
                    vuln_trends[date_str] = {}
                vuln_trends[date_str][severity] = count

            # Get current vulnerability counts
            current_vulns = await self._get_vulnerability_counts(pipeline_id)

            # Calculate scan frequency
            total_scans = sum(scan_stats.values())
            avg_scans_per_day = total_scans / days_back if days_back > 0 else 0

            # Get latest scan info
            latest_scan_query = (
                select(ScanJob).where(ScanJob.pipeline_id == pipeline_id).order_by(desc(ScanJob.created_at)).limit(1)
            )

            latest_scan_result = await self.db.execute(latest_scan_query)
            latest_scan = latest_scan_result.scalar_one_or_none()

            return {
                "pipeline_id": pipeline_id,
                "period_days": days_back,
                "scan_statistics": {
                    "total_scans": total_scans,
                    "scans_by_status": scan_stats,
                    "avg_scans_per_day": round(avg_scans_per_day, 2),
                    "success_rate": ((scan_stats.get("completed", 0) / total_scans * 100) if total_scans > 0 else 0),
                },
                "vulnerability_statistics": {
                    "current_counts": current_vulns,
                    "trends_by_day": vuln_trends,
                    "total_found_period": sum(sum(day_data.values()) for day_data in vuln_trends.values()),
                },
                "latest_scan": {
                    "id": latest_scan.id if latest_scan else None,
                    "status": latest_scan.status if latest_scan else None,
                    "created_at": latest_scan.created_at if latest_scan else None,
                    "completed_at": latest_scan.completed_at if latest_scan else None,
                },
            }

        except Exception as e:
            logger.error(f"Error getting pipeline statistics: {str(e)}")
            raise

    async def enable_pipeline(self, pipeline_id: int) -> None:
        """Enable pipeline for monitoring and scanning."""
        try:
            query = (
                update(Pipeline)
                .where(Pipeline.id == pipeline_id)
                .values(
                    {
                        "is_active": True,
                        "status": "active",
                        "updated_at": datetime.now(timezone.utc),
                    }
                )
            )
            await self.db.execute(query)
            await self.db.commit()

            logger.info(f"Enabled pipeline {pipeline_id}")

        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error enabling pipeline {pipeline_id}: {str(e)}")
            raise

    async def disable_pipeline(self, pipeline_id: int) -> None:
        """Disable pipeline monitoring and scanning."""
        try:
            query = (
                update(Pipeline)
                .where(Pipeline.id == pipeline_id)
                .values(
                    {
                        "is_active": False,
                        "status": "inactive",
                        "updated_at": datetime.now(timezone.utc),
                    }
                )
            )
            await self.db.execute(query)
            await self.db.commit()

            logger.info(f"Disabled pipeline {pipeline_id}")

        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error disabling pipeline {pipeline_id}: {str(e)}")
            raise

    async def trigger_initial_scan(self, pipeline_id: int) -> None:
        """Trigger initial scan for newly created pipeline."""
        try:
            # This would typically queue a Celery task
            logger.info(f"Triggering initial scan for pipeline {pipeline_id}")

            # Create initial scan job
            await self.create_scan_job(
                pipeline_id=pipeline_id,
                scanner_types=["dependency", "secret", "container", "policy"],
                target_branch="main",  # Default branch
                scan_config={"initial_scan": True},
                priority="normal",
            )

        except Exception as e:
            logger.error(f"Error triggering initial scan: {str(e)}")
            raise

    async def execute_scan_job(self, scan_job_id: int) -> None:
        """Execute scan job (placeholder for Celery task)."""
        try:
            # This would be implemented as a Celery task in production
            logger.info(f"Executing scan job {scan_job_id}")

            # Update job status to running
            query = (
                update(ScanJob)
                .where(ScanJob.id == scan_job_id)
                .values({"status": "running", "started_at": datetime.now(timezone.utc)})
            )
            await self.db.execute(query)
            await self.db.commit()

        except Exception as e:
            logger.error(f"Error executing scan job {scan_job_id}: {str(e)}")
            raise

    # Helper methods
    async def _get_vulnerability_counts(self, pipeline_id: int) -> Dict[str, int]:
        """Get vulnerability counts by severity for pipeline."""
        try:
            query = (
                select(func.count(Vulnerability.id).label("count"), Vulnerability.severity)
                .where(
                    and_(
                        Vulnerability.pipeline_id == pipeline_id,
                        Vulnerability.status.in_(["open", "acknowledged"]),
                    )
                )
                .group_by(Vulnerability.severity)
            )

            result = await self.db.execute(query)
            counts = {severity: count for count, severity in result.fetchall()}

            return {
                "total": sum(counts.values()),
                "critical": counts.get("critical", 0),
                "high": counts.get("high", 0),
                "medium": counts.get("medium", 0),
                "low": counts.get("low", 0),
            }

        except Exception as e:
            logger.error(f"Error getting vulnerability counts: {str(e)}")
            return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    async def _get_scan_vulnerability_counts(self, scan_job_id: int) -> Dict[str, int]:
        """Get vulnerability counts for specific scan job."""
        try:
            query = (
                select(func.count(Vulnerability.id).label("count"), Vulnerability.severity)
                .where(Vulnerability.scan_job_id == scan_job_id)
                .group_by(Vulnerability.severity)
            )

            result = await self.db.execute(query)
            counts = {severity: count for count, severity in result.fetchall()}

            return {
                "total": sum(counts.values()),
                "critical": counts.get("critical", 0),
                "high": counts.get("high", 0),
                "medium": counts.get("medium", 0),
                "low": counts.get("low", 0),
            }

        except Exception as e:
            logger.error(f"Error getting scan vulnerability counts: {str(e)}")
            return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
