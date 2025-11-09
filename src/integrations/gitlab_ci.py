"""
GitLab CI Integration Service

This module provides comprehensive integration with GitLab CI/CD,
including webhook processing, pipeline monitoring, and security analysis.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.database import AsyncSessionLocal
from src.api.models.alert import Alert, AlertSeverity, AlertType
from src.api.models.pipeline import (Pipeline, PipelineRun, PipelineStatus,
                                     PlatformType)
from src.api.models.vulnerability import (SeverityLevel, Vulnerability,
                                          VulnerabilityStatus)
from src.api.utils.config import get_settings
from src.api.utils.logger import get_logger

settings = get_settings()

logger = get_logger(__name__)


class GitLabCIIntegration:
    """GitLab CI integration service for webhook processing and API interactions."""

    def __init__(self):
        self.base_url = settings.GITLAB_URL or "https://gitlab.com"
        self.api_base = f"{self.base_url}/api/v4"
        self.access_token = settings.GITLAB_ACCESS_TOKEN
        self.webhook_token = settings.GITLAB_WEBHOOK_TOKEN
        self.session_timeout = 30

    async def verify_webhook_token(self, request_token: str) -> bool:
        """Verify GitLab webhook token for security."""
        try:
            return request_token == self.webhook_token
        except Exception as e:
            logger.error(f"Failed to verify webhook token: {e}")
            return False

    async def process_pipeline_webhook(self, payload: Dict[str, Any]) -> None:
        """Process GitLab CI pipeline webhook."""
        try:
            object_kind = payload.get("object_kind")

            if object_kind == "pipeline":
                await self._handle_pipeline_event(payload)
            elif object_kind == "job":
                await self._handle_job_event(payload)
            elif object_kind == "merge_request":
                await self._handle_merge_request_event(payload)
            else:
                logger.info(f"Unhandled webhook type: {object_kind}")

        except Exception as e:
            logger.error(f"Failed to process GitLab webhook: {e}")
            raise

    async def _handle_pipeline_event(self, payload: Dict[str, Any]) -> None:
        """Handle GitLab pipeline events."""
        try:
            object_attributes = payload.get("object_attributes", {})
            project = payload.get("project", {})

            if not object_attributes or not project:
                logger.warning("Invalid pipeline webhook payload")
                return

            async with AsyncSessionLocal() as db:
                await self._process_pipeline_event(
                    db, object_attributes, project, payload
                )

        except Exception as e:
            logger.error(f"Failed to handle pipeline event: {e}")
            raise

    async def _process_pipeline_event(
        self,
        db: AsyncSession,
        pipeline_data: Dict[str, Any],
        project: Dict[str, Any],
        full_payload: Dict[str, Any],
    ) -> None:
        """Process individual pipeline event."""
        try:
            # Extract pipeline information
            pipeline_id = pipeline_data.get("id")
            status = pipeline_data.get("status", "unknown")
            ref = pipeline_data.get("ref", "main")
            sha = pipeline_data.get("sha")

            project_path = project.get("path_with_namespace")
            project_url = project.get("web_url")

            # Map GitLab status to our pipeline status
            pipeline_status = self._map_gitlab_status(status)

            # Create or update pipeline
            pipeline = await self._create_or_update_pipeline(
                db, project_path, project_url, ref, project
            )

            # Create pipeline run
            pipeline_run = await self._create_pipeline_run(
                db, pipeline.id, pipeline_id, pipeline_status, sha, pipeline_data
            )

            # Trigger security analysis if pipeline completed
            if status == "success":
                await self._trigger_security_analysis(
                    pipeline_run, project, pipeline_data
                )
            elif status == "failed":
                await self._analyze_pipeline_failure(
                    pipeline_run, project, pipeline_data
                )

            await db.commit()
            logger.info(f"Processed pipeline {pipeline_id} for {project_path}")

        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to process pipeline event: {e}")
            raise

    def _map_gitlab_status(self, status: str) -> PipelineStatus:
        """Map GitLab pipeline status to our pipeline status."""
        status_mapping = {
            "created": PipelineStatus.PENDING,
            "waiting_for_resource": PipelineStatus.PENDING,
            "preparing": PipelineStatus.PENDING,
            "pending": PipelineStatus.PENDING,
            "running": PipelineStatus.RUNNING,
            "success": PipelineStatus.SUCCESS,
            "failed": PipelineStatus.FAILURE,
            "canceled": PipelineStatus.FAILURE,
            "skipped": PipelineStatus.FAILURE,
            "manual": PipelineStatus.PENDING,
            "scheduled": PipelineStatus.PENDING,
        }
        return status_mapping.get(status, PipelineStatus.UNKNOWN)

    async def _create_or_update_pipeline(
        self,
        db: AsyncSession,
        project_path: str,
        project_url: str,
        ref: str,
        project: Dict[str, Any],
    ) -> Pipeline:
        """Create or update pipeline record."""
        from sqlalchemy import select

        # Check if pipeline exists
        stmt = select(Pipeline).where(
            Pipeline.repository_url == project_url,
            Pipeline.branch == ref,
            Pipeline.platform == PlatformType.GITLAB_CI,
        )
        result = await db.execute(stmt)
        pipeline = result.scalars().first()

        if pipeline:
            pipeline.last_scan = datetime.now(timezone.utc)
            pipeline.is_active = True
        else:
            pipeline = Pipeline(
                name=f"{project_path}/{ref}",
                repository_url=project_url,
                branch=ref,
                platform=PlatformType.GITLAB_CI,
                configuration={
                    "project_id": project.get("id"),
                    "project_path": project_path,
                    "default_branch": project.get("default_branch", "main"),
                    "visibility": project.get("visibility", "private"),
                    "namespace": project.get("namespace", {}).get("name"),
                    "webhook_enabled": True,
                },
                is_active=True,
            )
            db.add(pipeline)
            await db.flush()

        return pipeline

    async def _create_pipeline_run(
        self,
        db: AsyncSession,
        pipeline_id: int,
        gitlab_pipeline_id: int,
        status: PipelineStatus,
        sha: str,
        pipeline_data: Dict[str, Any],
    ) -> PipelineRun:
        """Create pipeline run record."""
        from sqlalchemy import select

        # Check if run already exists
        stmt = select(PipelineRun).where(
            PipelineRun.pipeline_id == pipeline_id,
            PipelineRun.external_id == str(gitlab_pipeline_id),
        )
        result = await db.execute(stmt)
        existing_run = result.scalars().first()

        if existing_run:
            existing_run.status = status
            existing_run.finished_at = (
                datetime.now(timezone.utc)
                if status in [PipelineStatus.SUCCESS, PipelineStatus.FAILURE]
                else None
            )
            return existing_run

        # Create new run
        started_at = pipeline_data.get("created_at")
        finished_at = pipeline_data.get("finished_at")

        pipeline_run = PipelineRun(
            pipeline_id=pipeline_id,
            external_id=str(gitlab_pipeline_id),
            status=status,
            commit_hash=sha,
            started_at=(
                datetime.fromisoformat(started_at.replace("Z", "+00:00"))
                if started_at
                else datetime.now(timezone.utc)
            ),
            finished_at=(
                datetime.fromisoformat(finished_at.replace("Z", "+00:00"))
                if finished_at
                else None
            ),
            metadata={
                "pipeline_url": pipeline_data.get("url"),
                "source": pipeline_data.get("source"),
                "ref": pipeline_data.get("ref"),
                "tag": pipeline_data.get("tag"),
                "user": pipeline_data.get("user", {}).get("name"),
                "duration": pipeline_data.get("duration"),
                "queued_duration": pipeline_data.get("queued_duration"),
            },
        )

        db.add(pipeline_run)
        await db.flush()
        return pipeline_run

    async def _handle_job_event(self, payload: Dict[str, Any]) -> None:
        """Handle GitLab CI job events."""
        try:
            build_data = payload.get("build", {})
            project = payload.get("project", {})

            if not build_data or not project:
                logger.warning("Invalid job webhook payload")
                return

            # Log job status for monitoring
            job_name = build_data.get("name")
            job_status = build_data.get("status")
            stage = build_data.get("stage")

            logger.info(f"Job {job_name} in stage {stage}: {job_status}")

            # If this is a security-related job, handle specially
            if "security" in job_name.lower() or "scan" in job_name.lower():
                await self._handle_security_job(build_data, project)

        except Exception as e:
            logger.error(f"Failed to handle job event: {e}")

    async def _handle_security_job(
        self, job_data: Dict[str, Any], project: Dict[str, Any]
    ) -> None:
        """Handle security-related job completion."""
        try:
            job_status = job_data.get("status")
            if job_status == "success":
                # Try to fetch security artifacts
                await self._fetch_security_artifacts(job_data, project)
            elif job_status == "failed":
                # Create alert for failed security job
                await self._create_security_job_alert(job_data, project)

        except Exception as e:
            logger.error(f"Failed to handle security job: {e}")

    async def _handle_merge_request_event(self, payload: Dict[str, Any]) -> None:
        """Handle GitLab merge request events."""
        try:
            object_attributes = payload.get("object_attributes", {})
            project = payload.get("project", {})

            if not object_attributes or not project:
                logger.warning("Invalid merge request webhook payload")
                return

            action = object_attributes.get("action")
            if action in ["open", "update", "reopen"]:
                # Trigger security scan for merge request
                await self._trigger_mr_security_scan(object_attributes, project)

        except Exception as e:
            logger.error(f"Failed to handle merge request event: {e}")

    async def _trigger_mr_security_scan(
        self, mr_data: Dict[str, Any], project: Dict[str, Any]
    ) -> None:
        """Trigger security scan for merge request."""
        try:
            mr_iid = mr_data.get("iid")
            source_branch = mr_data.get("source_branch")
            target_branch = mr_data.get("target_branch")

            logger.info(f"Triggering MR security scan for !{mr_iid}")

            # Schedule security analysis
            from src.tasks.scan_tasks import schedule_merge_request_scan

            await schedule_merge_request_scan.apply_async(
                args=[
                    project.get("id"),
                    mr_iid,
                    source_branch,
                    target_branch,
                    mr_data.get("last_commit", {}).get("id"),
                ]
            )

        except Exception as e:
            logger.error(f"Failed to trigger MR security scan: {e}")

    async def _trigger_security_analysis(
        self,
        pipeline_run: PipelineRun,
        project: Dict[str, Any],
        pipeline_data: Dict[str, Any],
    ) -> None:
        """Trigger security analysis for completed pipeline."""
        try:
            from src.tasks.scan_tasks import schedule_repository_scan

            # Schedule security scans
            await schedule_repository_scan.apply_async(
                args=[
                    pipeline_run.id,
                    project.get("path_with_namespace"),
                    project.get("ssh_url_to_repo"),
                    pipeline_data.get("sha"),
                    pipeline_data.get("ref"),
                ]
            )

            logger.info(f"Scheduled security analysis for run {pipeline_run.id}")

        except Exception as e:
            logger.error(f"Failed to trigger security analysis: {e}")

    async def _analyze_pipeline_failure(
        self,
        pipeline_run: PipelineRun,
        project: Dict[str, Any],
        pipeline_data: Dict[str, Any],
    ) -> None:
        """Analyze failed pipeline for security implications."""
        try:
            # Fetch pipeline jobs to understand failure
            jobs = await self.get_pipeline_jobs(
                project.get("id"), pipeline_data.get("id")
            )

            security_failures = []
            for job in jobs:
                if job.get("status") == "failed":
                    job_name = job.get("name", "").lower()
                    if any(
                        keyword in job_name
                        for keyword in ["security", "scan", "test", "lint"]
                    ):
                        security_failures.append(job)

            if security_failures:
                await self._create_pipeline_failure_alert(
                    pipeline_run, project, security_failures
                )

        except Exception as e:
            logger.error(f"Failed to analyze pipeline failure: {e}")

    async def get_pipeline_jobs(
        self, project_id: int, pipeline_id: int
    ) -> List[Dict[str, Any]]:
        """Get jobs for a specific pipeline."""
        try:
            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.get(
                    f"{self.api_base}/projects/{project_id}/pipelines/{pipeline_id}/jobs",
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                        "Content-Type": "application/json",
                    },
                )

                if response.status_code == 200:
                    return response.json()
                else:
                    logger.warning(
                        f"Failed to fetch pipeline jobs: {response.status_code}"
                    )
                    return []

        except Exception as e:
            logger.error(f"Failed to get pipeline jobs: {e}")
            return []

    async def get_job_artifacts(self, project_id: int, job_id: int) -> Optional[bytes]:
        """Download job artifacts."""
        try:
            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.get(
                    f"{self.api_base}/projects/{project_id}/jobs/{job_id}/artifacts",
                    headers={"Authorization": f"Bearer {self.access_token}"},
                )

                if response.status_code == 200:
                    return response.content
                else:
                    return None

        except Exception as e:
            logger.error(f"Failed to get job artifacts: {e}")
            return None

    async def create_merge_request_note(
        self, project_id: int, merge_request_iid: int, note_body: str
    ) -> bool:
        """Create a note on a merge request."""
        try:
            payload = {"body": note_body}

            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.post(
                    f"{self.api_base}/projects/{project_id}/merge_requests/{merge_request_iid}/notes",
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )

                return response.status_code == 201

        except Exception as e:
            logger.error(f"Failed to create merge request note: {e}")
            return False

    async def get_project_variables(self, project_id: int) -> List[Dict[str, Any]]:
        """Get project CI/CD variables (for security analysis)."""
        try:
            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.get(
                    f"{self.api_base}/projects/{project_id}/variables",
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                        "Content-Type": "application/json",
                    },
                )

                if response.status_code == 200:
                    return response.json()
                else:
                    logger.warning(
                        f"Failed to fetch project variables: {response.status_code}"
                    )
                    return []

        except Exception as e:
            logger.error(f"Failed to get project variables: {e}")
            return []

    async def analyze_gitlab_ci_security(self, project_id: int) -> List[Dict[str, Any]]:
        """Analyze GitLab CI configuration for security issues."""
        security_issues = []

        try:
            # Get .gitlab-ci.yml content
            ci_config = await self.get_file_content(project_id, ".gitlab-ci.yml")
            if not ci_config:
                return security_issues

            import yaml

            try:
                ci_data = yaml.safe_load(ci_config)
            except yaml.YAMLError as e:
                security_issues.append(
                    {
                        "file": ".gitlab-ci.yml",
                        "issue": "Invalid YAML syntax",
                        "severity": "high",
                        "description": f"YAML parsing error: {e}",
                    }
                )
                return security_issues

            # Analyze CI configuration
            issues = []
            issues.extend(self._check_image_security(ci_data))
            issues.extend(self._check_script_security(ci_data))
            issues.extend(self._check_variable_security(ci_data))
            issues.extend(self._check_artifact_security(ci_data))

            security_issues.extend(issues)

        except Exception as e:
            logger.error(f"Failed to analyze GitLab CI security: {e}")

        return security_issues

    async def get_file_content(
        self, project_id: int, file_path: str, ref: str = "main"
    ) -> Optional[str]:
        """Get file content from GitLab repository."""
        try:
            import urllib.parse

            encoded_path = urllib.parse.quote(file_path, safe="")

            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.get(
                    f"{self.api_base}/projects/{project_id}/repository/files/{encoded_path}",
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                        "Content-Type": "application/json",
                    },
                    params={"ref": ref},
                )

                if response.status_code == 200:
                    data = response.json()
                    import base64

                    return base64.b64decode(data["content"]).decode("utf-8")
                else:
                    return None

        except Exception as e:
            logger.error(f"Failed to get file content: {e}")
            return None

    def _check_image_security(self, ci_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for insecure Docker images in CI configuration."""
        issues = []

        # Check global image
        global_image = ci_data.get("image")
        if global_image and self._is_insecure_image(global_image):
            issues.append(
                {
                    "file": ".gitlab-ci.yml",
                    "issue": f"Potentially insecure global image: {global_image}",
                    "severity": "medium",
                    "description": "Consider using specific tags instead of 'latest'",
                }
            )

        # Check job images
        for job_name, job_config in ci_data.items():
            if isinstance(job_config, dict) and "image" in job_config:
                image = job_config["image"]
                if self._is_insecure_image(image):
                    issues.append(
                        {
                            "file": ".gitlab-ci.yml",
                            "issue": f"Potentially insecure image in job '{job_name}': {image}",
                            "severity": "medium",
                            "description": "Consider using specific tags instead of 'latest'",
                        }
                    )

        return issues

    def _is_insecure_image(self, image: str) -> bool:
        """Check if Docker image uses insecure tags."""
        if isinstance(image, str):
            return ":latest" in image or not ":" in image
        return False

    def _check_script_security(self, ci_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for potentially insecure scripts."""
        issues = []

        dangerous_patterns = [
            "curl.*|.*sh",  # Piping curl to shell
            "wget.*|.*sh",  # Piping wget to shell
            "sudo.*rm.*-rf",  # Dangerous rm commands
            "chmod.*777",  # Overly permissive permissions
        ]

        import re

        for job_name, job_config in ci_data.items():
            if isinstance(job_config, dict) and "script" in job_config:
                scripts = job_config["script"]
                if isinstance(scripts, list):
                    scripts = " ".join(scripts)

                for pattern in dangerous_patterns:
                    if re.search(pattern, scripts, re.IGNORECASE):
                        issues.append(
                            {
                                "file": ".gitlab-ci.yml",
                                "issue": f"Potentially dangerous script in job '{job_name}'",
                                "severity": "high",
                                "description": f"Found pattern: {pattern}",
                            }
                        )

        return issues

    def _check_variable_security(self, ci_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for hardcoded variables and secrets."""
        issues = []

        # Check global variables
        variables = ci_data.get("variables", {})
        for var_name, var_value in variables.items():
            if self._is_potential_secret(var_name, str(var_value)):
                issues.append(
                    {
                        "file": ".gitlab-ci.yml",
                        "issue": f"Potential hardcoded secret: {var_name}",
                        "severity": "high",
                        "description": "Consider using GitLab CI/CD variables instead",
                    }
                )

        return issues

    def _is_potential_secret(self, name: str, value: str) -> bool:
        """Check if a variable might contain a secret."""
        secret_indicators = ["password", "secret", "key", "token", "api"]
        name_lower = name.lower()

        # Check if name suggests it's a secret
        is_secret_name = any(indicator in name_lower for indicator in secret_indicators)

        # Check if value looks like a secret (long alphanumeric string)
        is_secret_value = len(value) > 16 and value.isalnum()

        return is_secret_name and is_secret_value

    def _check_artifact_security(self, ci_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for insecure artifact configurations."""
        issues = []

        for job_name, job_config in ci_data.items():
            if isinstance(job_config, dict) and "artifacts" in job_config:
                artifacts = job_config["artifacts"]

                # Check for artifacts without expiration
                if isinstance(artifacts, dict) and "expire_in" not in artifacts:
                    issues.append(
                        {
                            "file": ".gitlab-ci.yml",
                            "issue": f"Job '{job_name}' has artifacts without expiration",
                            "severity": "low",
                            "description": "Consider setting artifact expiration to save storage",
                        }
                    )

                # Check for overly broad artifact paths
                paths = (
                    artifacts.get("paths", []) if isinstance(artifacts, dict) else []
                )
                for path in paths:
                    if path in ["*", "**/*", "."]:
                        issues.append(
                            {
                                "file": ".gitlab-ci.yml",
                                "issue": f"Job '{job_name}' has overly broad artifact path: {path}",
                                "severity": "medium",
                                "description": "Consider specifying exact paths to avoid exposing sensitive files",
                            }
                        )

        return issues

    async def _fetch_security_artifacts(
        self, job_data: Dict[str, Any], project: Dict[str, Any]
    ) -> None:
        """Fetch and process security scan artifacts."""
        try:
            job_id = job_data.get("id")
            project_id = project.get("id")

            artifacts = await self.get_job_artifacts(project_id, job_id)
            if artifacts:
                # Process security artifacts
                await self._process_security_artifacts(artifacts, job_data, project)

        except Exception as e:
            logger.error(f"Failed to fetch security artifacts: {e}")

    async def _process_security_artifacts(
        self, artifacts: bytes, job_data: Dict[str, Any], project: Dict[str, Any]
    ) -> None:
        """Process security scan artifacts."""
        try:
            # This would typically parse SAST/DAST reports
            # For now, we'll log the processing
            logger.info(
                f"Processing security artifacts from job {job_data.get('name')}"
            )

            # TODO: Implement actual artifact parsing for common formats:
            # - GitLab SAST reports (JSON)
            # - Container scanning reports
            # - Dependency scanning reports
            # - DAST reports
            raise NotImplementedError(
                "Artifact parsing for common formats is not yet implemented."
            )

        except Exception as e:
            logger.error(f"Failed to process security artifacts: {e}")

    async def _create_security_job_alert(
        self, job_data: Dict[str, Any], project: Dict[str, Any]
    ) -> None:
        """Create alert for failed security job."""
        try:
            async with AsyncSessionLocal() as db:
                alert = Alert(
                    type=AlertType.PIPELINE_FAILURE,
                    severity=AlertSeverity.HIGH,
                    title=f"Security job failed: {job_data.get('name')}",
                    description=f"Security job {job_data.get('name')} failed in project {project.get('path_with_namespace')}",
                    source_type="gitlab_ci",
                    source_id=str(job_data.get("id")),
                    metadata={
                        "job_name": job_data.get("name"),
                        "project_path": project.get("path_with_namespace"),
                        "job_url": job_data.get("url"),
                        "stage": job_data.get("stage"),
                        "failure_reason": job_data.get("failure_reason"),
                    },
                )

                db.add(alert)
                await db.commit()

                logger.info(
                    f"Created alert for failed security job {job_data.get('id')}"
                )

        except Exception as e:
            logger.error(f"Failed to create security job alert: {e}")

    async def _create_pipeline_failure_alert(
        self,
        pipeline_run: PipelineRun,
        project: Dict[str, Any],
        failed_jobs: List[Dict[str, Any]],
    ) -> None:
        """Create alert for pipeline failure with security implications."""
        try:
            async with AsyncSessionLocal() as db:
                failed_job_names = [job.get("name") for job in failed_jobs]

                alert = Alert(
                    type=AlertType.PIPELINE_FAILURE,
                    severity=AlertSeverity.MEDIUM,
                    title=f"Security-related pipeline failures in {project.get('path_with_namespace')}",
                    description=f"Pipeline {pipeline_run.external_id} failed with security-related job failures: {', '.join(failed_job_names)}",
                    source_type="gitlab_ci",
                    source_id=pipeline_run.external_id,
                    metadata={
                        "pipeline_run_id": pipeline_run.id,
                        "project_path": project.get("path_with_namespace"),
                        "failed_jobs": failed_job_names,
                        "commit_sha": pipeline_run.commit_hash,
                    },
                )

                db.add(alert)
                await db.commit()

                logger.info(f"Created pipeline failure alert for run {pipeline_run.id}")

        except Exception as e:
            logger.error(f"Failed to create pipeline failure alert: {e}")


# Global instance
gitlab_integration = GitLabCIIntegration()
