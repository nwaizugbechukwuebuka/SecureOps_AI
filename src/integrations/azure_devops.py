"""
Azure DevOps Integration Service

This module provides comprehensive integration with Azure DevOps,
including webhook processing, pipeline monitoring, and security analysis.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import asyncio
import base64
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.database import AsyncSessionLocal
from src.api.models.alert import Alert, AlertSeverity, AlertType
from src.api.models.pipeline import Pipeline, PipelineRun, PipelineStatus, PlatformType
from src.api.models.vulnerability import (
    SeverityLevel,
    Vulnerability,
    VulnerabilityStatus,
)
from src.api.utils.config import get_settings
from src.api.utils.logger import get_logger

settings = get_settings()
settings = get_settings()

logger = get_logger(__name__)


class AzureDevOpsIntegration:
    """Azure DevOps integration service for webhook processing and API interactions."""

    def __init__(self):
        self.organization = settings.AZURE_ORGANIZATION
        self.personal_access_token = settings.AZURE_PAT
        self.webhook_secret = settings.AZURE_WEBHOOK_SECRET
        self.base_url = f"https://dev.azure.com/{self.organization}"
        self.api_version = "7.0"
        self.session_timeout = 30

        # Create basic auth header for PAT
        if self.personal_access_token:
            credentials = f":{self.personal_access_token}"
            self.auth_header = base64.b64encode(credentials.encode()).decode()
        else:
            self.auth_header = None

    async def verify_webhook_signature(self, payload: bytes, signature: str) -> bool:
        """Verify Azure DevOps webhook signature for security."""
        try:
            import hashlib
            import hmac

            if not self.webhook_secret:
                logger.warning("Webhook secret not configured")
                return True  # Allow if not configured (development mode)

            expected_signature = hmac.new(
                self.webhook_secret.encode("utf-8"), payload, hashlib.sha256
            ).hexdigest()

            return hmac.compare_digest(expected_signature, signature)

        except Exception as e:
            logger.error(f"Failed to verify webhook signature: {e}")
            return False

    async def process_webhook(self, payload: Dict[str, Any]) -> None:
        """Process Azure DevOps webhook based on event type."""
        try:
            event_type = payload.get("eventType")

            if event_type == "build.complete":
                await self._handle_build_complete(payload)
            elif event_type == "ms.vss-pipelines.run-state-changed-event":
                await self._handle_pipeline_run_state_changed(payload)
            elif event_type == "git.pullrequest.created":
                await self._handle_pull_request_created(payload)
            elif event_type == "git.pullrequest.updated":
                await self._handle_pull_request_updated(payload)
            else:
                logger.info(f"Unhandled Azure DevOps event type: {event_type}")

        except Exception as e:
            logger.error(f"Failed to process Azure DevOps webhook: {e}")
            raise

    async def _handle_build_complete(self, payload: Dict[str, Any]) -> None:
        """Handle Azure DevOps build completion events."""
        try:
            resource = payload.get("resource", {})

            if not resource:
                logger.warning("No resource data in build complete event")
                return

            async with AsyncSessionLocal() as db:
                await self._process_build_resource(db, resource, payload)

        except Exception as e:
            logger.error(f"Failed to handle build complete event: {e}")
            raise

    async def _handle_pipeline_run_state_changed(self, payload: Dict[str, Any]) -> None:
        """Handle Azure DevOps pipeline run state changes."""
        try:
            resource = payload.get("resource", {})

            if not resource:
                logger.warning("No resource data in pipeline run event")
                return

            async with AsyncSessionLocal() as db:
                await self._process_pipeline_run_resource(db, resource, payload)

        except Exception as e:
            logger.error(f"Failed to handle pipeline run state changed event: {e}")
            raise

    async def _process_build_resource(
        self, db: AsyncSession, resource: Dict[str, Any], full_payload: Dict[str, Any]
    ) -> None:
        """Process Azure DevOps build resource."""
        try:
            # Extract build information
            build_id = resource.get("id")
            build_number = resource.get("buildNumber")
            status = resource.get("status")
            result = resource.get("result")

            # Extract definition information
            definition = resource.get("definition", {})
            project = resource.get("project", {})
            repository = resource.get("repository", {})

            # Map Azure DevOps status to our pipeline status
            pipeline_status = self._map_azure_status(status, result)

            # Create or update pipeline
            pipeline = await self._create_or_update_pipeline(
                db, definition, project, repository
            )

            # Create pipeline run
            pipeline_run = await self._create_pipeline_run(
                db, pipeline.id, build_id, build_number, pipeline_status, resource
            )

            # Trigger security analysis if build succeeded
            if pipeline_status == PipelineStatus.SUCCESS:
                await self._trigger_security_analysis(pipeline_run, resource, project)
            elif pipeline_status == PipelineStatus.FAILURE:
                await self._analyze_build_failure(pipeline_run, resource, project)

            await db.commit()
            logger.info(
                f"Processed build {build_number} ({build_id}) for {definition.get('name')}"
            )

        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to process build resource: {e}")
            raise

    async def _process_pipeline_run_resource(
        self, db: AsyncSession, resource: Dict[str, Any], full_payload: Dict[str, Any]
    ) -> None:
        """Process Azure DevOps pipeline run resource."""
        try:
            # Extract pipeline run information
            run_id = resource.get("id")
            run_name = resource.get("name")
            state = resource.get("state")
            result = resource.get("result")

            # Extract pipeline and project information
            pipeline_info = resource.get("pipeline", {})
            project = full_payload.get("resourceContainers", {}).get("project", {})

            # Map Azure DevOps state to our pipeline status
            pipeline_status = self._map_azure_pipeline_state(state, result)

            # Create or update pipeline
            pipeline = await self._create_or_update_pipeline_from_run(
                db, pipeline_info, project, resource
            )

            # Create pipeline run
            pipeline_run = await self._create_pipeline_run_from_run(
                db, pipeline.id, run_id, run_name, pipeline_status, resource
            )

            # Handle completed runs
            if state == "completed":
                if pipeline_status == PipelineStatus.SUCCESS:
                    await self._trigger_security_analysis_for_run(
                        pipeline_run, resource, project
                    )
                elif pipeline_status == PipelineStatus.FAILURE:
                    await self._analyze_pipeline_run_failure(
                        pipeline_run, resource, project
                    )

            await db.commit()
            logger.info(f"Processed pipeline run {run_name} ({run_id})")

        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to process pipeline run resource: {e}")
            raise

    def _map_azure_status(self, status: str, result: Optional[str]) -> PipelineStatus:
        """Map Azure DevOps build status to pipeline status."""
        if status == "completed":
            if result == "succeeded":
                return PipelineStatus.SUCCESS
            elif result in ["failed", "canceled", "abandoning", "abandoned"]:
                return PipelineStatus.FAILURE
            elif result == "partiallySucceeded":
                return PipelineStatus.FAILURE  # Treat as failure for security analysis
            else:
                return PipelineStatus.UNKNOWN
        elif status in ["inProgress", "notStarted"]:
            return PipelineStatus.RUNNING
        elif status == "postponed":
            return PipelineStatus.PENDING
        else:
            return PipelineStatus.UNKNOWN

    def _map_azure_pipeline_state(
        self, state: str, result: Optional[str]
    ) -> PipelineStatus:
        """Map Azure DevOps pipeline run state to pipeline status."""
        if state == "completed":
            if result == "succeeded":
                return PipelineStatus.SUCCESS
            elif result in ["failed", "canceled"]:
                return PipelineStatus.FAILURE
            else:
                return PipelineStatus.UNKNOWN
        elif state == "running":
            return PipelineStatus.RUNNING
        elif state == "pending":
            return PipelineStatus.PENDING
        else:
            return PipelineStatus.UNKNOWN

    async def _create_or_update_pipeline(
        self,
        db: AsyncSession,
        definition: Dict[str, Any],
        project: Dict[str, Any],
        repository: Dict[str, Any],
    ) -> Pipeline:
        """Create or update pipeline record from build definition."""
        from sqlalchemy import select

        definition_name = definition.get("name", "Unknown Pipeline")
        project_name = project.get("name", "Unknown Project")
        repo_url = repository.get("url", "")

        # Use project + definition as unique identifier
        pipeline_name = f"{project_name}/{definition_name}"

        # Check if pipeline exists
        stmt = select(Pipeline).where(
            Pipeline.name == pipeline_name,
            Pipeline.platform == PlatformType.AZURE_DEVOPS,
        )

        result = await db.execute(stmt)
        pipeline = result.scalars().first()

        if pipeline:
            pipeline.last_scan = datetime.now(timezone.utc)
            pipeline.is_active = True
        else:
            pipeline = Pipeline(
                name=pipeline_name,
                repository_url=repo_url,
                branch=repository.get("defaultBranch", "main"),
                platform=PlatformType.AZURE_DEVOPS,
                configuration={
                    "definition_id": definition.get("id"),
                    "definition_name": definition_name,
                    "project_id": project.get("id"),
                    "project_name": project_name,
                    "repository_id": repository.get("id"),
                    "organization": self.organization,
                    "webhook_enabled": True,
                },
                is_active=True,
            )
            db.add(pipeline)
            await db.flush()

        return pipeline

    async def _create_or_update_pipeline_from_run(
        self,
        db: AsyncSession,
        pipeline_info: Dict[str, Any],
        project: Dict[str, Any],
        run_resource: Dict[str, Any],
    ) -> Pipeline:
        """Create or update pipeline record from pipeline run."""
        from sqlalchemy import select

        pipeline_name_from_info = pipeline_info.get("name", "Unknown Pipeline")
        project_name = project.get("name", "Unknown Project")

        # Use project + pipeline as unique identifier
        pipeline_name = f"{project_name}/{pipeline_name_from_info}"

        # Check if pipeline exists
        stmt = select(Pipeline).where(
            Pipeline.name == pipeline_name,
            Pipeline.platform == PlatformType.AZURE_DEVOPS,
        )

        result = await db.execute(stmt)
        pipeline = result.scalars().first()

        if pipeline:
            pipeline.last_scan = datetime.now(timezone.utc)
            pipeline.is_active = True
        else:
            pipeline = Pipeline(
                name=pipeline_name,
                repository_url="",  # May not be available in run resource
                branch="main",  # Default branch
                platform=PlatformType.AZURE_DEVOPS,
                configuration={
                    "pipeline_id": pipeline_info.get("id"),
                    "pipeline_name": pipeline_name_from_info,
                    "project_id": project.get("id"),
                    "project_name": project_name,
                    "organization": self.organization,
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
        build_id: int,
        build_number: str,
        status: PipelineStatus,
        resource: Dict[str, Any],
    ) -> PipelineRun:
        """Create pipeline run record from build."""
        from sqlalchemy import select

        # Check if run already exists
        stmt = select(PipelineRun).where(
            PipelineRun.pipeline_id == pipeline_id,
            PipelineRun.external_id == str(build_id),
        )
        result = await db.execute(stmt)
        existing_run = result.scalars().first()

        if existing_run:
            existing_run.status = status
            existing_run.finished_at = (
                self._parse_azure_timestamp(resource.get("finishTime"))
                if status in [PipelineStatus.SUCCESS, PipelineStatus.FAILURE]
                else None
            )
            return existing_run

        # Extract timing information
        started_at = self._parse_azure_timestamp(resource.get("startTime"))
        finished_at = self._parse_azure_timestamp(resource.get("finishTime"))

        # Create new run
        pipeline_run = PipelineRun(
            pipeline_id=pipeline_id,
            external_id=str(build_id),
            status=status,
            commit_hash=resource.get("sourceVersion", ""),
            started_at=started_at or datetime.now(timezone.utc),
            finished_at=finished_at,
            metadata={
                "build_number": build_number,
                "build_id": build_id,
                "build_url": resource.get("url"),
                "source_branch": resource.get("sourceBranch"),
                "requested_by": resource.get("requestedBy", {}).get("displayName"),
                "reason": resource.get("reason"),
                "queue": resource.get("queue", {}).get("name"),
                "priority": resource.get("priority"),
            },
        )

        db.add(pipeline_run)
        await db.flush()
        return pipeline_run

    async def _create_pipeline_run_from_run(
        self,
        db: AsyncSession,
        pipeline_id: int,
        run_id: int,
        run_name: str,
        status: PipelineStatus,
        resource: Dict[str, Any],
    ) -> PipelineRun:
        """Create pipeline run record from pipeline run."""
        from sqlalchemy import select

        # Check if run already exists
        stmt = select(PipelineRun).where(
            PipelineRun.pipeline_id == pipeline_id,
            PipelineRun.external_id == str(run_id),
        )
        result = await db.execute(stmt)
        existing_run = result.scalars().first()

        if existing_run:
            existing_run.status = status
            existing_run.finished_at = (
                self._parse_azure_timestamp(resource.get("finishedDate"))
                if status in [PipelineStatus.SUCCESS, PipelineStatus.FAILURE]
                else None
            )
            return existing_run

        # Extract timing information
        started_at = self._parse_azure_timestamp(resource.get("createdDate"))
        finished_at = self._parse_azure_timestamp(resource.get("finishedDate"))

        # Create new run
        pipeline_run = PipelineRun(
            pipeline_id=pipeline_id,
            external_id=str(run_id),
            status=status,
            commit_hash="",  # May not be available in run resource
            started_at=started_at or datetime.now(timezone.utc),
            finished_at=finished_at,
            metadata={
                "run_name": run_name,
                "run_id": run_id,
                "state": resource.get("state"),
                "result": resource.get("result"),
                "pipeline_id": resource.get("pipeline", {}).get("id"),
                "pipeline_name": resource.get("pipeline", {}).get("name"),
            },
        )

        db.add(pipeline_run)
        await db.flush()
        return pipeline_run

    def _parse_azure_timestamp(self, timestamp: Optional[str]) -> Optional[datetime]:
        """Parse Azure DevOps timestamp to datetime."""
        if not timestamp:
            return None

        try:
            # Azure DevOps uses ISO format with 'Z' suffix
            return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except Exception as e:
            logger.warning(f"Failed to parse timestamp {timestamp}: {e}")
            return None

    async def _handle_pull_request_created(self, payload: Dict[str, Any]) -> None:
        """Handle pull request creation for security analysis."""
        try:
            resource = payload.get("resource", {})
            if not resource:
                return

            await self._trigger_pr_security_analysis(resource, payload)

        except Exception as e:
            logger.error(f"Failed to handle pull request created: {e}")

    async def _handle_pull_request_updated(self, payload: Dict[str, Any]) -> None:
        """Handle pull request updates for security analysis."""
        try:
            resource = payload.get("resource", {})
            if not resource:
                return

            # Only trigger analysis for certain updates (new commits)
            if resource.get("status") == "active":
                await self._trigger_pr_security_analysis(resource, payload)

        except Exception as e:
            logger.error(f"Failed to handle pull request updated: {e}")

    async def _trigger_pr_security_analysis(
        self, pr_resource: Dict[str, Any], full_payload: Dict[str, Any]
    ) -> None:
        """Trigger security analysis for pull request."""
        try:
            pr_id = pr_resource.get("pullRequestId")
            source_branch = pr_resource.get("sourceRefName", "").replace(
                "refs/heads/", ""
            )
            target_branch = pr_resource.get("targetRefName", "").replace(
                "refs/heads/", ""
            )

            repository = pr_resource.get("repository", {})
            project = repository.get("project", {})

            logger.info(f"Triggering PR security analysis for PR #{pr_id}")

            # Schedule security analysis
            from src.tasks.scan_tasks import schedule_pull_request_scan

            await schedule_pull_request_scan.apply_async(
                args=[
                    project.get("id"),
                    repository.get("id"),
                    pr_id,
                    source_branch,
                    target_branch,
                    pr_resource.get("lastMergeSourceCommit", {}).get("commitId"),
                ]
            )

        except Exception as e:
            logger.error(f"Failed to trigger PR security analysis: {e}")

    async def _trigger_security_analysis(
        self,
        pipeline_run: PipelineRun,
        resource: Dict[str, Any],
        project: Dict[str, Any],
    ) -> None:
        """Trigger security analysis for completed build."""
        try:
            from src.tasks.scan_tasks import schedule_azure_build_scan

            # Schedule security scans
            await schedule_azure_build_scan.apply_async(
                args=[
                    pipeline_run.id,
                    project.get("id"),
                    resource.get("id"),
                    resource.get("repository", {}).get("url"),
                    resource.get("sourceVersion"),
                    resource.get("sourceBranch"),
                ]
            )

            logger.info(
                f"Scheduled security analysis for build {resource.get('buildNumber')}"
            )

        except Exception as e:
            logger.error(f"Failed to trigger security analysis: {e}")

    async def _trigger_security_analysis_for_run(
        self,
        pipeline_run: PipelineRun,
        resource: Dict[str, Any],
        project: Dict[str, Any],
    ) -> None:
        """Trigger security analysis for completed pipeline run."""
        try:
            from src.tasks.scan_tasks import schedule_azure_pipeline_run_scan

            # Schedule security scans
            await schedule_azure_pipeline_run_scan.apply_async(
                args=[
                    pipeline_run.id,
                    project.get("id"),
                    resource.get("pipeline", {}).get("id"),
                    resource.get("id"),
                ]
            )

            logger.info(
                f"Scheduled security analysis for pipeline run {resource.get('name')}"
            )

        except Exception as e:
            logger.error(f"Failed to trigger security analysis for run: {e}")

    async def get_build_logs(self, project_id: str, build_id: int) -> Optional[str]:
        """Get build logs from Azure DevOps."""
        if not self.auth_header:
            logger.warning("Azure DevOps authentication not configured")
            return None

        try:
            url = f"{self.base_url}/{project_id}/_apis/build/builds/{build_id}/logs"

            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                # First, get the list of log files
                response = await client.get(
                    url,
                    headers={
                        "Authorization": f"Basic {self.auth_header}",
                        "Content-Type": "application/json",
                    },
                    params={"api-version": self.api_version},
                )

                if response.status_code != 200:
                    return None

                logs_data = response.json()
                logs = []

                # Download each log file
                for log_info in logs_data.get("value", []):
                    log_id = log_info.get("id")
                    if log_id:
                        log_response = await client.get(
                            f"{url}/{log_id}",
                            headers={
                                "Authorization": f"Basic {self.auth_header}",
                                "Content-Type": "text/plain",
                            },
                            params={"api-version": self.api_version},
                        )

                        if log_response.status_code == 200:
                            logs.append(f"=== Log {log_id} ===\n{log_response.text}\n")

                return "\n".join(logs)

        except Exception as e:
            logger.error(f"Failed to get build logs: {e}")
            return None

    async def get_build_artifacts(
        self, project_id: str, build_id: int
    ) -> List[Dict[str, Any]]:
        """Get build artifacts from Azure DevOps."""
        if not self.auth_header:
            logger.warning("Azure DevOps authentication not configured")
            return []

        try:
            url = (
                f"{self.base_url}/{project_id}/_apis/build/builds/{build_id}/artifacts"
            )

            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.get(
                    url,
                    headers={
                        "Authorization": f"Basic {self.auth_header}",
                        "Content-Type": "application/json",
                    },
                    params={"api-version": self.api_version},
                )

                if response.status_code == 200:
                    data = response.json()
                    return data.get("value", [])
                else:
                    return []

        except Exception as e:
            logger.error(f"Failed to get build artifacts: {e}")
            return []

    async def create_pull_request_comment(
        self,
        project_id: str,
        repository_id: str,
        pull_request_id: int,
        comment_content: str,
    ) -> bool:
        """Create a comment on a pull request."""
        if not self.auth_header:
            logger.warning("Azure DevOps authentication not configured")
            return False

        try:
            url = f"{self.base_url}/{project_id}/_apis/git/repositories/{repository_id}/pullRequests/{pull_request_id}/threads"

            payload = {
                "comments": [
                    {"parentCommentId": 0, "content": comment_content, "commentType": 1}
                ],
                "status": 1,
            }

            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.post(
                    url,
                    headers={
                        "Authorization": f"Basic {self.auth_header}",
                        "Content-Type": "application/json",
                    },
                    params={"api-version": self.api_version},
                    json=payload,
                )

                return response.status_code == 200

        except Exception as e:
            logger.error(f"Failed to create pull request comment: {e}")
            return False

    async def analyze_azure_pipeline_security(
        self, project_id: str, pipeline_id: int
    ) -> List[Dict[str, Any]]:
        """Analyze Azure Pipeline for security issues."""
        security_issues = []

        try:
            # Get pipeline definition
            pipeline_def = await self.get_pipeline_definition(project_id, pipeline_id)
            if not pipeline_def:
                return security_issues

            # Analyze YAML content
            yaml_content = pipeline_def.get("process", {}).get("yamlFilename")
            if yaml_content:
                repo_id = pipeline_def.get("repository", {}).get("id")
                if repo_id:
                    yaml_file_content = await self.get_file_content(
                        project_id, repo_id, yaml_content
                    )
                    if yaml_file_content:
                        issues = self._analyze_yaml_security(
                            yaml_file_content, yaml_content
                        )
                        security_issues.extend(issues)

        except Exception as e:
            logger.error(f"Failed to analyze Azure Pipeline security: {e}")

        return security_issues

    async def get_pipeline_definition(
        self, project_id: str, pipeline_id: int
    ) -> Optional[Dict[str, Any]]:
        """Get Azure Pipeline definition."""
        if not self.auth_header:
            return None

        try:
            url = f"{self.base_url}/{project_id}/_apis/pipelines/{pipeline_id}"

            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.get(
                    url,
                    headers={
                        "Authorization": f"Basic {self.auth_header}",
                        "Content-Type": "application/json",
                    },
                    params={"api-version": self.api_version},
                )

                if response.status_code == 200:
                    return response.json()
                else:
                    return None

        except Exception as e:
            logger.error(f"Failed to get pipeline definition: {e}")
            return None

    async def get_file_content(
        self,
        project_id: str,
        repository_id: str,
        file_path: str,
        version_type: str = "branch",
        version: str = "main",
    ) -> Optional[str]:
        """Get file content from Azure Repos."""
        if not self.auth_header:
            return None

        try:
            url = f"{self.base_url}/{project_id}/_apis/git/repositories/{repository_id}/items"

            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.get(
                    url,
                    headers={
                        "Authorization": f"Basic {self.auth_header}",
                        "Content-Type": "text/plain",
                    },
                    params={
                        "path": file_path,
                        "versionType": version_type,
                        "version": version,
                        "api-version": self.api_version,
                    },
                )

                if response.status_code == 200:
                    return response.text
                else:
                    return None

        except Exception as e:
            logger.error(f"Failed to get file content: {e}")
            return None

    def _analyze_yaml_security(
        self, yaml_content: str, file_name: str
    ) -> List[Dict[str, Any]]:
        """Analyze Azure Pipeline YAML for security issues."""
        issues = []

        try:
            import yaml

            try:
                pipeline_data = yaml.safe_load(yaml_content)
            except yaml.YAMLError as e:
                issues.append(
                    {
                        "file": file_name,
                        "issue": "Invalid YAML syntax",
                        "severity": "high",
                        "description": f"YAML parsing error: {e}",
                    }
                )
                return issues

            # Check various security aspects
            issues.extend(self._check_variable_security_azure(pipeline_data, file_name))
            issues.extend(self._check_script_security_azure(pipeline_data, file_name))
            issues.extend(self._check_resource_security_azure(pipeline_data, file_name))
            issues.extend(self._check_trigger_security_azure(pipeline_data, file_name))

        except Exception as e:
            logger.error(f"Failed to analyze YAML security: {e}")

        return issues

    def _check_variable_security_azure(
        self, pipeline_data: Dict[str, Any], file_name: str
    ) -> List[Dict[str, Any]]:
        """Check for variable-related security issues."""
        issues = []

        variables = pipeline_data.get("variables", {})
        if isinstance(variables, list):
            # Handle variable groups
            for var_group in variables:
                if isinstance(var_group, dict) and "group" in var_group:
                    # Variable groups are external, generally okay
                    continue
                elif isinstance(var_group, dict):
                    # Individual variables
                    for var_name, var_value in var_group.items():
                        if self._is_potential_secret_azure(var_name, str(var_value)):
                            issues.append(
                                {
                                    "file": file_name,
                                    "issue": f"Potential hardcoded secret: {var_name}",
                                    "severity": "high",
                                    "description": "Consider using Azure Key Vault or variable groups",
                                }
                            )
        elif isinstance(variables, dict):
            for var_name, var_value in variables.items():
                if self._is_potential_secret_azure(var_name, str(var_value)):
                    issues.append(
                        {
                            "file": file_name,
                            "issue": f"Potential hardcoded secret: {var_name}",
                            "severity": "high",
                            "description": "Consider using Azure Key Vault or variable groups",
                        }
                    )

        return issues

    def _is_potential_secret_azure(self, name: str, value: str) -> bool:
        """Check if a variable might contain a secret."""
        secret_indicators = ["password", "secret", "key", "token", "connectionstring"]
        name_lower = name.lower()

        # Check if name suggests it's a secret
        is_secret_name = any(indicator in name_lower for indicator in secret_indicators)

        # Check if value looks like a secret (not a variable reference)
        is_not_variable_ref = not any(
            pattern in value for pattern in ["$(", "$[", "${"]
        )
        is_secret_value = len(value) > 16 and is_not_variable_ref

        return is_secret_name and is_secret_value

    def _check_script_security_azure(
        self, pipeline_data: Dict[str, Any], file_name: str
    ) -> List[Dict[str, Any]]:
        """Check for script-related security issues."""
        issues = []

        jobs = pipeline_data.get("jobs", [])
        stages = pipeline_data.get("stages", [])

        # Check jobs directly
        for job in jobs:
            if isinstance(job, dict):
                issues.extend(self._check_job_scripts_azure(job, file_name))

        # Check stages
        for stage in stages:
            if isinstance(stage, dict):
                stage_jobs = stage.get("jobs", [])
                for job in stage_jobs:
                    if isinstance(job, dict):
                        issues.extend(self._check_job_scripts_azure(job, file_name))

        return issues

    def _check_job_scripts_azure(
        self, job: Dict[str, Any], file_name: str
    ) -> List[Dict[str, Any]]:
        """Check individual job for script security issues."""
        issues = []

        steps = job.get("steps", [])
        for step in steps:
            if isinstance(step, dict):
                # Check script tasks
                if "script" in step:
                    script_content = step["script"]
                    if self._has_dangerous_commands_azure(script_content):
                        issues.append(
                            {
                                "file": file_name,
                                "issue": f"Potentially dangerous script in job '{job.get('job', 'unknown')}'",
                                "severity": "high",
                                "description": "Script contains potentially dangerous commands",
                            }
                        )

                # Check PowerShell tasks
                if step.get("task") == "PowerShell@2":
                    script_content = (
                        step.get("inputs", {}).get("targetType") == "inline"
                    )
                    if script_content:
                        inline_script = step.get("inputs", {}).get("script", "")
                        if self._has_dangerous_commands_azure(inline_script):
                            issues.append(
                                {
                                    "file": file_name,
                                    "issue": f"Potentially dangerous PowerShell script",
                                    "severity": "high",
                                    "description": "PowerShell script contains potentially dangerous commands",
                                }
                            )

        return issues

    def _has_dangerous_commands_azure(self, script_content: str) -> bool:
        """Check if script content has dangerous commands."""
        dangerous_patterns = [
            "curl.*|.*sh",  # Piping to shell
            "wget.*|.*sh",
            "Invoke-Expression.*\\$",  # PowerShell dynamic execution
            "rm.*-rf",  # Dangerous rm
            "Remove-Item.*-Recurse.*-Force",  # PowerShell dangerous removal
        ]

        import re

        return any(
            re.search(pattern, script_content, re.IGNORECASE)
            for pattern in dangerous_patterns
        )

    def _check_resource_security_azure(
        self, pipeline_data: Dict[str, Any], file_name: str
    ) -> List[Dict[str, Any]]:
        """Check for resource-related security issues."""
        issues = []

        resources = pipeline_data.get("resources", {})

        # Check container resources
        containers = resources.get("containers", [])
        for container in containers:
            if isinstance(container, dict):
                image = container.get("image", "")
                if ":latest" in image or not ":" in image:
                    issues.append(
                        {
                            "file": file_name,
                            "issue": f"Container image uses 'latest' tag: {image}",
                            "severity": "medium",
                            "description": "Consider using specific version tags for better security",
                        }
                    )

        return issues

    def _check_trigger_security_azure(
        self, pipeline_data: Dict[str, Any], file_name: str
    ) -> List[Dict[str, Any]]:
        """Check for trigger-related security issues."""
        issues = []

        trigger = pipeline_data.get("trigger", {})
        pr_trigger = pipeline_data.get("pr", {})

        # Check if pipeline can be triggered from any branch
        if trigger == "*" or (isinstance(trigger, list) and "*" in trigger):
            issues.append(
                {
                    "file": file_name,
                    "issue": "Pipeline can be triggered from any branch",
                    "severity": "medium",
                    "description": "Consider restricting triggers to specific branches",
                }
            )

        # Similar check for PR triggers
        if pr_trigger == "*" or (isinstance(pr_trigger, list) and "*" in pr_trigger):
            issues.append(
                {
                    "file": file_name,
                    "issue": "Pipeline can be triggered by PRs to any branch",
                    "severity": "low",
                    "description": "Consider restricting PR triggers to specific branches",
                }
            )

        return issues

    async def _analyze_build_failure(
        self,
        pipeline_run: PipelineRun,
        resource: Dict[str, Any],
        project: Dict[str, Any],
    ) -> None:
        """Analyze failed build for security implications."""
        try:
            build_id = resource.get("id")
            project_id = project.get("id")

            # Get build logs
            logs = await self.get_build_logs(project_id, build_id)

            if logs:
                security_issues = self._analyze_logs_for_security_azure(logs)
                if security_issues:
                    await self._create_build_failure_alert_azure(
                        pipeline_run, resource, security_issues
                    )

        except Exception as e:
            logger.error(f"Failed to analyze build failure: {e}")

    async def _analyze_pipeline_run_failure(
        self,
        pipeline_run: PipelineRun,
        resource: Dict[str, Any],
        project: Dict[str, Any],
    ) -> None:
        """Analyze failed pipeline run for security implications."""
        try:
            # For pipeline runs, we might need to get additional information
            # This is a placeholder for more sophisticated analysis
            logger.info(
                f"Analyzing pipeline run failure for run {pipeline_run.external_id}"
            )

            # Could fetch pipeline run details, logs, etc.

        except Exception as e:
            logger.error(f"Failed to analyze pipeline run failure: {e}")

    def _analyze_logs_for_security_azure(self, logs: str) -> List[str]:
        """Analyze build logs for security-related issues."""
        if not logs:
            return []

        security_keywords = [
            "vulnerability",
            "cve",
            "security",
            "exploit",
            "authentication failed",
            "access denied",
            "unauthorized",
            "certificate",
            "ssl",
            "tls error",
        ]

        security_issues = []
        lines = logs.lower().split("\n")

        for i, line in enumerate(lines):
            if any(keyword in line for keyword in security_keywords):
                if any(
                    error_word in line for error_word in ["error", "fail", "warning"]
                ):
                    # Get context around the security-related issue
                    start = max(0, i - 2)
                    end = min(len(lines), i + 3)
                    context = "\n".join(lines[start:end])
                    security_issues.append(context)

        return security_issues

    async def _create_build_failure_alert_azure(
        self,
        pipeline_run: PipelineRun,
        resource: Dict[str, Any],
        security_issues: List[str],
    ) -> None:
        """Create alert for build failure with security implications."""
        try:
            async with AsyncSessionLocal() as db:
                alert = Alert(
                    type=AlertType.PIPELINE_FAILURE,
                    severity=AlertSeverity.MEDIUM,
                    title=f"Azure DevOps build failure with security implications",
                    description=f"Build {resource.get('buildNumber')} failed with security-related errors",
                    source_type="azure_devops",
                    source_id=pipeline_run.external_id,
                    metadata={
                        "pipeline_run_id": pipeline_run.id,
                        "build_number": resource.get("buildNumber"),
                        "build_url": resource.get("url"),
                        "definition_name": resource.get("definition", {}).get("name"),
                        "security_issues": security_issues[
                            :3
                        ],  # Limit to first 3 issues
                        "total_issues": len(security_issues),
                    },
                )

                db.add(alert)
                await db.commit()

                logger.info(f"Created build failure alert for run {pipeline_run.id}")

        except Exception as e:
            logger.error(f"Failed to create build failure alert: {e}")


# Global instance
azure_devops_integration = AzureDevOpsIntegration()
