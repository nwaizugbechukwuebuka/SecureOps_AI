"""
GitHub Actions Integration Service

This module provides comprehensive integration with GitHub Actions,
including webhook processing, workflow monitoring, and security analysis.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
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


class GitHubActionsIntegration:
    """GitHub Actions integration service for webhook processing and API interactions."""

    def __init__(self):
        self.app_id = settings.GITHUB_APP_ID
        self.private_key = settings.GITHUB_PRIVATE_KEY
        self.webhook_secret = settings.GITHUB_WEBHOOK_SECRET
        self.base_url = "https://api.github.com"
        self.session_timeout = 30

    async def verify_webhook_signature(self, payload: bytes, signature: str) -> bool:
        """Verify GitHub webhook signature for security."""
        try:
            import hashlib
            import hmac

            expected_signature = hmac.new(
                self.webhook_secret.encode("utf-8"), payload, hashlib.sha256
            ).hexdigest()

            signature_header = signature.replace("sha256=", "")
            return hmac.compare_digest(expected_signature, signature_header)

        except Exception as e:
            logger.error(f"Failed to verify webhook signature: {e}")
            return False

    def generate_jwt_token(self, installation_id: Optional[int] = None) -> str:
        """Generate JWT token for GitHub App authentication."""
        try:
            private_key_obj = serialization.load_pem_private_key(
                self.private_key.encode(), password=None
            )

            now = datetime.now(timezone.utc)
            payload = {
                "iat": now,
                "exp": now.replace(minute=now.minute + 10),  # 10 minutes expiry
                "iss": self.app_id,
            }

            if installation_id:
                payload["installation_id"] = installation_id

            return jwt.encode(payload, private_key_obj, algorithm="RS256")

        except Exception as e:
            logger.error(f"Failed to generate JWT token: {e}")
            raise

    async def get_installation_access_token(self, installation_id: int) -> str:
        """Get installation access token for API requests."""
        try:
            jwt_token = self.generate_jwt_token()

            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.post(
                    f"{self.base_url}/app/installations/{installation_id}/access_tokens",
                    headers={
                        "Authorization": f"Bearer {jwt_token}",
                        "Accept": "application/vnd.github.v3+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                )

                response.raise_for_status()
                data = response.json()
                return data["token"]

        except Exception as e:
            logger.error(f"Failed to get installation access token: {e}")
            raise

    async def process_workflow_run_webhook(self, payload: Dict[str, Any]) -> None:
        """Process GitHub Actions workflow run webhook."""
        try:
            action = payload.get("action")
            workflow_run = payload.get("workflow_run", {})
            repository = payload.get("repository", {})

            if not workflow_run or not repository:
                logger.warning("Invalid workflow run webhook payload")
                return

            async with AsyncSessionLocal() as db:
                await self._handle_workflow_run_event(
                    db, action, workflow_run, repository
                )

        except Exception as e:
            logger.error(f"Failed to process workflow run webhook: {e}")
            raise

    async def _handle_workflow_run_event(
        self,
        db: AsyncSession,
        action: str,
        workflow_run: Dict[str, Any],
        repository: Dict[str, Any],
    ) -> None:
        """Handle individual workflow run event."""
        try:
            # Extract workflow information
            workflow_id = workflow_run.get("id")
            workflow_name = workflow_run.get("name", "Unknown Workflow")
            status = workflow_run.get("status", "unknown")
            conclusion = workflow_run.get("conclusion")
            branch = workflow_run.get("head_branch", "main")
            commit_sha = workflow_run.get("head_sha")

            repo_full_name = repository.get("full_name")
            repo_url = repository.get("html_url")

            # Map GitHub status to our pipeline status
            pipeline_status = self._map_github_status(status, conclusion)

            # Create or update pipeline
            pipeline = await self._create_or_update_pipeline(
                db, repo_full_name, repo_url, branch
            )

            # Create pipeline run
            pipeline_run = await self._create_pipeline_run(
                db,
                pipeline.id,
                workflow_id,
                workflow_name,
                pipeline_status,
                commit_sha,
                workflow_run,
            )

            # Trigger security analysis if workflow completed
            if action == "completed" and pipeline_status in [
                PipelineStatus.SUCCESS,
                PipelineStatus.FAILURE,
            ]:
                await self._trigger_security_analysis(
                    pipeline_run, repository, workflow_run
                )

            await db.commit()
            logger.info(f"Processed workflow run {workflow_id} for {repo_full_name}")

        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to handle workflow run event: {e}")
            raise

    def _map_github_status(
        self, status: str, conclusion: Optional[str]
    ) -> PipelineStatus:
        """Map GitHub workflow status to pipeline status."""
        if status == "completed":
            if conclusion == "success":
                return PipelineStatus.SUCCESS
            elif conclusion in ["failure", "cancelled", "timed_out"]:
                return PipelineStatus.FAILURE
            else:
                return PipelineStatus.FAILURE
        elif status in ["queued", "in_progress"]:
            return PipelineStatus.RUNNING
        else:
            return PipelineStatus.PENDING

    async def _create_or_update_pipeline(
        self, db: AsyncSession, repo_name: str, repo_url: str, branch: str
    ) -> Pipeline:
        """Create or update pipeline record."""
        from sqlalchemy import select

        # Check if pipeline exists
        stmt = select(Pipeline).where(
            Pipeline.repository_url == repo_url,
            Pipeline.branch == branch,
            Pipeline.platform == PlatformType.GITHUB_ACTIONS,
        )
        result = await db.execute(stmt)
        pipeline = result.scalars().first()

        if pipeline:
            pipeline.last_scan = datetime.now(timezone.utc)
            pipeline.is_active = True
        else:
            pipeline = Pipeline(
                name=f"{repo_name}/{branch}",
                repository_url=repo_url,
                branch=branch,
                platform=PlatformType.GITHUB_ACTIONS,
                configuration={
                    "repository": repo_name,
                    "default_branch": branch,
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
        workflow_id: int,
        workflow_name: str,
        status: PipelineStatus,
        commit_sha: str,
        workflow_run: Dict[str, Any],
    ) -> PipelineRun:
        """Create pipeline run record."""
        from sqlalchemy import select

        # Check if run already exists
        stmt = select(PipelineRun).where(
            PipelineRun.pipeline_id == pipeline_id,
            PipelineRun.external_id == str(workflow_id),
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
        pipeline_run = PipelineRun(
            pipeline_id=pipeline_id,
            external_id=str(workflow_id),
            status=status,
            commit_hash=commit_sha,
            started_at=(
                datetime.fromisoformat(
                    workflow_run.get("created_at", "").replace("Z", "+00:00")
                )
                if workflow_run.get("created_at")
                else datetime.now(timezone.utc)
            ),
            finished_at=(
                datetime.fromisoformat(
                    workflow_run.get("updated_at", "").replace("Z", "+00:00")
                )
                if status in [PipelineStatus.SUCCESS, PipelineStatus.FAILURE]
                and workflow_run.get("updated_at")
                else None
            ),
            metadata={
                "workflow_name": workflow_name,
                "workflow_url": workflow_run.get("html_url"),
                "actor": workflow_run.get("actor", {}).get("login"),
                "event": workflow_run.get("event"),
                "jobs_count": (
                    workflow_run.get("jobs_url", "").count("/jobs/")
                    if workflow_run.get("jobs_url")
                    else 0
                ),
            },
        )

        db.add(pipeline_run)
        await db.flush()
        return pipeline_run

    async def _trigger_security_analysis(
        self,
        pipeline_run: PipelineRun,
        repository: Dict[str, Any],
        workflow_run: Dict[str, Any],
    ) -> None:
        """Trigger security analysis for completed workflow."""
        try:
            from src.tasks.scan_tasks import schedule_repository_scan

            # Schedule security scans
            await schedule_repository_scan.apply_async(
                args=[
                    pipeline_run.id,
                    repository.get("full_name"),
                    repository.get("clone_url"),
                    workflow_run.get("head_sha"),
                    workflow_run.get("head_branch", "main"),
                ]
            )

            logger.info(f"Scheduled security analysis for run {pipeline_run.id}")

        except Exception as e:
            logger.error(f"Failed to trigger security analysis: {e}")

    async def get_workflow_logs(
        self, repo_owner: str, repo_name: str, run_id: int, installation_id: int
    ) -> Optional[str]:
        """Fetch workflow run logs from GitHub API."""
        try:
            access_token = await self.get_installation_access_token(installation_id)

            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.get(
                    f"{self.base_url}/repos/{repo_owner}/{repo_name}/actions/runs/{run_id}/logs",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                )

                if response.status_code == 200:
                    return response.text
                else:
                    logger.warning(f"Failed to fetch logs: {response.status_code}")
                    return None

        except Exception as e:
            logger.error(f"Failed to get workflow logs: {e}")
            return None

    async def create_check_run(
        self,
        repo_owner: str,
        repo_name: str,
        commit_sha: str,
        installation_id: int,
        name: str = "SecureOps Security Scan",
        status: str = "in_progress",
        conclusion: Optional[str] = None,
        output: Optional[Dict[str, Any]] = None,
    ) -> Optional[int]:
        """Create a check run on GitHub for security scan results."""
        try:
            access_token = await self.get_installation_access_token(installation_id)

            payload = {"name": name, "head_sha": commit_sha, "status": status}

            if conclusion:
                payload["conclusion"] = conclusion

            if output:
                payload["output"] = output

            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.post(
                    f"{self.base_url}/repos/{repo_owner}/{repo_name}/check-runs",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                    json=payload,
                )

                if response.status_code == 201:
                    data = response.json()
                    return data.get("id")
                else:
                    logger.warning(
                        f"Failed to create check run: {response.status_code}"
                    )
                    return None

        except Exception as e:
            logger.error(f"Failed to create check run: {e}")
            return None

    async def update_check_run(
        self,
        repo_owner: str,
        repo_name: str,
        check_run_id: int,
        installation_id: int,
        status: str = "completed",
        conclusion: str = "success",
        output: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Update an existing check run with scan results."""
        try:
            access_token = await self.get_installation_access_token(installation_id)

            payload = {"status": status, "conclusion": conclusion}

            if output:
                payload["output"] = output

            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.patch(
                    f"{self.base_url}/repos/{repo_owner}/{repo_name}/check-runs/{check_run_id}",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                    json=payload,
                )

                return response.status_code == 200

        except Exception as e:
            logger.error(f"Failed to update check run: {e}")
            return False

    async def get_repository_secrets(
        self, repo_owner: str, repo_name: str, installation_id: int
    ) -> List[Dict[str, Any]]:
        """Get repository secrets (names only, not values)."""
        try:
            access_token = await self.get_installation_access_token(installation_id)

            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.get(
                    f"{self.base_url}/repos/{repo_owner}/{repo_name}/actions/secrets",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                )

                if response.status_code == 200:
                    data = response.json()
                    return data.get("secrets", [])
                else:
                    logger.warning(f"Failed to fetch secrets: {response.status_code}")
                    return []

        except Exception as e:
            logger.error(f"Failed to get repository secrets: {e}")
            return []

    async def analyze_workflow_security(
        self, repo_owner: str, repo_name: str, installation_id: int
    ) -> List[Dict[str, Any]]:
        """Analyze workflow files for security issues."""
        security_issues = []

        try:
            access_token = await self.get_installation_access_token(installation_id)

            # Get workflow files
            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.get(
                    f"{self.base_url}/repos/{repo_owner}/{repo_name}/contents/.github/workflows",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                )

                if response.status_code != 200:
                    return security_issues

                workflows = response.json()
                if not isinstance(workflows, list):
                    return security_issues

                for workflow_file in workflows:
                    if workflow_file.get("name", "").endswith((".yml", ".yaml")):
                        issues = await self._analyze_workflow_file(
                            client, access_token, workflow_file
                        )
                        security_issues.extend(issues)

            return security_issues

        except Exception as e:
            logger.error(f"Failed to analyze workflow security: {e}")
            return security_issues

    async def _analyze_workflow_file(
        self,
        client: httpx.AsyncClient,
        access_token: str,
        workflow_file: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Analyze individual workflow file for security issues."""
        issues = []

        try:
            # Get workflow file content
            response = await client.get(
                workflow_file.get("download_url", ""),
                headers={"Authorization": f"Bearer {access_token}"},
            )

            if response.status_code != 200:
                return issues

            content = response.text

            # Check for common security issues
            import yaml

            try:
                workflow_data = yaml.safe_load(content)
            except yaml.YAMLError:
                issues.append(
                    {
                        "file": workflow_file.get("name"),
                        "issue": "Invalid YAML syntax",
                        "severity": "high",
                        "line": 1,
                    }
                )
                return issues

            # Check for security issues
            issues.extend(
                self._check_workflow_permissions(workflow_file, workflow_data)
            )
            issues.extend(self._check_hardcoded_secrets(workflow_file, content))
            issues.extend(self._check_unsafe_actions(workflow_file, workflow_data))
            issues.extend(
                self._check_pull_request_security(workflow_file, workflow_data)
            )

        except Exception as e:
            logger.error(
                f"Failed to analyze workflow file {workflow_file.get('name')}: {e}"
            )

        return issues

    def _check_workflow_permissions(
        self, workflow_file: Dict[str, Any], workflow_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Check for overly permissive workflow permissions."""
        issues = []

        permissions = workflow_data.get("permissions")
        if permissions == "write-all":
            issues.append(
                {
                    "file": workflow_file.get("name"),
                    "issue": "Workflow has write-all permissions",
                    "severity": "high",
                    "description": "Consider using minimal required permissions",
                }
            )

        jobs = workflow_data.get("jobs", {})
        for job_name, job_data in jobs.items():
            if job_data.get("permissions") == "write-all":
                issues.append(
                    {
                        "file": workflow_file.get("name"),
                        "issue": f"Job '{job_name}' has write-all permissions",
                        "severity": "medium",
                        "description": "Consider using minimal required permissions for this job",
                    }
                )

        return issues

    def _check_hardcoded_secrets(
        self, workflow_file: Dict[str, Any], content: str
    ) -> List[Dict[str, Any]]:
        """Check for hardcoded secrets in workflow files."""
        issues = []

        # Common patterns for secrets
        secret_patterns = [
            r'password\s*[:=]\s*["\']?[a-zA-Z0-9]{8,}["\']?',
            r'api[_-]?key\s*[:=]\s*["\']?[a-zA-Z0-9]{16,}["\']?',
            r'secret\s*[:=]\s*["\']?[a-zA-Z0-9]{16,}["\']?',
            r'token\s*[:=]\s*["\']?[a-zA-Z0-9]{16,}["\']?',
        ]

        import re

        for i, line in enumerate(content.split("\n"), 1):
            for pattern in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Skip if it's using secrets context
                    if "${{ secrets." not in line:
                        issues.append(
                            {
                                "file": workflow_file.get("name"),
                                "issue": "Potential hardcoded secret",
                                "severity": "high",
                                "line": i,
                                "description": f"Line {i} may contain hardcoded credentials",
                            }
                        )

        return issues

    def _check_unsafe_actions(
        self, workflow_file: Dict[str, Any], workflow_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Check for potentially unsafe GitHub Actions."""
        issues = []

        # Known potentially unsafe actions
        unsafe_patterns = [
            r"actions/checkout@v[12]",  # Older versions
            r".*@master$",  # Using master instead of pinned version
            r".*@main$",  # Using main instead of pinned version
        ]

        import re

        jobs = workflow_data.get("jobs", {})
        for job_name, job_data in jobs.items():
            steps = job_data.get("steps", [])
            for step in steps:
                uses = step.get("uses", "")
                if uses:
                    for pattern in unsafe_patterns:
                        if re.match(pattern, uses):
                            issues.append(
                                {
                                    "file": workflow_file.get("name"),
                                    "issue": f"Potentially unsafe action: {uses}",
                                    "severity": "medium",
                                    "description": "Consider pinning to specific version or using latest stable version",
                                }
                            )

        return issues

    def _check_pull_request_security(
        self, workflow_file: Dict[str, Any], workflow_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Check for pull request security issues."""
        issues = []

        on_events = workflow_data.get("on", {})
        if isinstance(on_events, dict):
            pr_events = on_events.get("pull_request_target")
            if pr_events:
                # Check if workflow runs on pull_request_target with write permissions
                permissions = workflow_data.get("permissions", {})
                if permissions and any(
                    perm == "write" for perm in permissions.values()
                ):
                    issues.append(
                        {
                            "file": workflow_file.get("name"),
                            "issue": "pull_request_target with write permissions",
                            "severity": "high",
                            "description": "This combination can be dangerous for security",
                        }
                    )

        return issues


# Global instance
github_integration = GitHubActionsIntegration()
