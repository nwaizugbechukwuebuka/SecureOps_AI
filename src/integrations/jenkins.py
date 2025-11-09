"""
Jenkins Integration Service

This module provides comprehensive integration with Jenkins CI/CD,
including webhook processing, build monitoring, and security analysis.

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
from src.api.models.pipeline import (Pipeline, PipelineRun, PipelineStatus,
                                     PlatformType)
from src.api.models.vulnerability import (SeverityLevel, Vulnerability,
                                          VulnerabilityStatus)
from src.api.utils.config import get_settings
from src.api.utils.logger import get_logger

settings = get_settings()
settings = get_settings()

logger = get_logger(__name__)


class JenkinsIntegration:
    """Jenkins integration service for webhook processing and API interactions."""

    def __init__(self):
        self.base_url = settings.JENKINS_URL
        self.username = settings.JENKINS_USERNAME
        self.api_token = settings.JENKINS_API_TOKEN
        self.webhook_token = settings.JENKINS_WEBHOOK_TOKEN
        self.session_timeout = 30

        # Create basic auth header
        if self.username and self.api_token:
            credentials = f"{self.username}:{self.api_token}"
            self.auth_header = base64.b64encode(credentials.encode()).decode()
        else:
            self.auth_header = None

    async def verify_webhook_token(self, request_token: str) -> bool:
        """Verify Jenkins webhook token for security."""
        try:
            return request_token == self.webhook_token
        except Exception as e:
            logger.error(f"Failed to verify webhook token: {e}")
            return False

    async def process_build_webhook(self, payload: Dict[str, Any]) -> None:
        """Process Jenkins build webhook."""
        try:
            # Jenkins webhook structure can vary, handle common formats
            if "build" in payload:
                await self._handle_build_event(payload["build"])
            elif "job" in payload and "build" in payload:
                await self._handle_job_build_event(payload)
            else:
                # Direct build notification
                await self._handle_build_event(payload)

        except Exception as e:
            logger.error(f"Failed to process Jenkins webhook: {e}")
            raise

    async def _handle_build_event(self, build_data: Dict[str, Any]) -> None:
        """Handle Jenkins build events."""
        try:
            if not build_data:
                logger.warning("Empty build data received")
                return

            async with AsyncSessionLocal() as db:
                await self._process_build_event(db, build_data)

        except Exception as e:
            logger.error(f"Failed to handle build event: {e}")
            raise

    async def _handle_job_build_event(self, payload: Dict[str, Any]) -> None:
        """Handle Jenkins job build events."""
        try:
            job_data = payload.get("job", {})
            build_data = payload.get("build", {})

            if not job_data or not build_data:
                logger.warning("Invalid job build webhook payload")
                return

            # Enhance build data with job information
            enhanced_build_data = {
                **build_data,
                "job_name": job_data.get("name"),
                "job_url": job_data.get("url"),
                "job_display_name": job_data.get("displayName"),
            }

            async with AsyncSessionLocal() as db:
                await self._process_build_event(db, enhanced_build_data)

        except Exception as e:
            logger.error(f"Failed to handle job build event: {e}")
            raise

    async def _process_build_event(
        self, db: AsyncSession, build_data: Dict[str, Any]
    ) -> None:
        """Process individual build event."""
        try:
            # Extract build information
            build_number = build_data.get("number")
            build_url = build_data.get("url")
            status = build_data.get("status", "UNKNOWN")
            result = build_data.get("result")

            # Try to extract job information
            job_name = build_data.get("job_name") or build_data.get(
                "displayName", "Unknown Job"
            )
            job_url = build_data.get("job_url") or self._extract_job_url_from_build(
                build_url
            )

            # Extract SCM information if available
            scm_info = self._extract_scm_info(build_data)

            # Map Jenkins status to our pipeline status
            pipeline_status = self._map_jenkins_status(status, result)

            # Create or update pipeline
            pipeline = await self._create_or_update_pipeline(
                db, job_name, job_url, scm_info
            )

            # Create pipeline run
            pipeline_run = await self._create_pipeline_run(
                db, pipeline.id, build_number, pipeline_status, build_data
            )

            # Trigger security analysis if build completed successfully
            if pipeline_status == PipelineStatus.SUCCESS:
                await self._trigger_security_analysis(
                    pipeline_run, build_data, scm_info
                )
            elif pipeline_status == PipelineStatus.FAILURE:
                await self._analyze_build_failure(pipeline_run, build_data)

            await db.commit()
            logger.info(f"Processed build {build_number} for job {job_name}")

        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to process build event: {e}")
            raise

    def _extract_job_url_from_build(self, build_url: str) -> str:
        """Extract job URL from build URL."""
        if not build_url:
            return ""

        try:
            # Remove build number from URL
            # e.g., http://jenkins.example.com/job/my-job/123/ -> http://jenkins.example.com/job/my-job/
            parts = build_url.rstrip("/").split("/")
            if parts and parts[-1].isdigit():
                return "/".join(parts[:-1]) + "/"
            return build_url
        except Exception:
            return build_url

    def _extract_scm_info(self, build_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract SCM information from build data."""
        scm_info = {"repository_url": "", "branch": "main", "commit_hash": ""}

        try:
            # Try various SCM fields that Jenkins might provide
            scm = build_data.get("scm", {})

            # Git information
            if isinstance(scm, dict):
                scm_info["repository_url"] = scm.get("url", "")
                scm_info["branch"] = scm.get("branch", "main")
                scm_info["commit_hash"] = scm.get("commit", "")

            # Alternative locations for SCM info
            if not scm_info["repository_url"]:
                scm_info["repository_url"] = build_data.get("repository_url", "")

            if not scm_info["branch"]:
                scm_info["branch"] = build_data.get("branch", "main")

            if not scm_info["commit_hash"]:
                scm_info["commit_hash"] = build_data.get(
                    "commit", build_data.get("revision", "")
                )

        except Exception as e:
            logger.warning(f"Failed to extract SCM info: {e}")

        return scm_info

    def _map_jenkins_status(self, status: str, result: Optional[str]) -> PipelineStatus:
        """Map Jenkins build status to pipeline status."""
        # Jenkins uses both 'status' and 'result' fields
        if result:
            result_mapping = {
                "SUCCESS": PipelineStatus.SUCCESS,
                "FAILURE": PipelineStatus.FAILURE,
                "UNSTABLE": PipelineStatus.FAILURE,
                "ABORTED": PipelineStatus.FAILURE,
                "NOT_BUILT": PipelineStatus.FAILURE,
            }
            return result_mapping.get(result, PipelineStatus.UNKNOWN)

        status_mapping = {
            "SUCCESS": PipelineStatus.SUCCESS,
            "FAILURE": PipelineStatus.FAILURE,
            "UNSTABLE": PipelineStatus.FAILURE,
            "ABORTED": PipelineStatus.FAILURE,
            "IN_PROGRESS": PipelineStatus.RUNNING,
            "BUILDING": PipelineStatus.RUNNING,
            "STARTED": PipelineStatus.RUNNING,
            "PENDING": PipelineStatus.PENDING,
            "QUEUED": PipelineStatus.PENDING,
        }
        return status_mapping.get(status, PipelineStatus.UNKNOWN)

    async def _create_or_update_pipeline(
        self, db: AsyncSession, job_name: str, job_url: str, scm_info: Dict[str, Any]
    ) -> Pipeline:
        """Create or update pipeline record."""
        from sqlalchemy import select

        # Use job_url as unique identifier, fallback to job_name
        pipeline_key = job_url or job_name
        repository_url = scm_info.get("repository_url", job_url)
        branch = scm_info.get("branch", "main")

        # Check if pipeline exists
        stmt = select(Pipeline).where(
            Pipeline.name == job_name, Pipeline.platform == PlatformType.JENKINS
        )

        # If we have repository info, match on that too
        if repository_url:
            stmt = stmt.where(Pipeline.repository_url == repository_url)

        result = await db.execute(stmt)
        pipeline = result.scalars().first()

        if pipeline:
            pipeline.last_scan = datetime.now(timezone.utc)
            pipeline.is_active = True
            # Update repository URL if we have new info
            if repository_url and not pipeline.repository_url:
                pipeline.repository_url = repository_url
        else:
            pipeline = Pipeline(
                name=job_name,
                repository_url=repository_url,
                branch=branch,
                platform=PlatformType.JENKINS,
                configuration={
                    "job_name": job_name,
                    "job_url": job_url,
                    "jenkins_url": self.base_url,
                    "webhook_enabled": True,
                    "scm_type": "git" if repository_url else "unknown",
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
        build_number: int,
        status: PipelineStatus,
        build_data: Dict[str, Any],
    ) -> PipelineRun:
        """Create pipeline run record."""
        from sqlalchemy import select

        # Check if run already exists
        stmt = select(PipelineRun).where(
            PipelineRun.pipeline_id == pipeline_id,
            PipelineRun.external_id == str(build_number),
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

        # Extract timing information
        started_at = self._parse_jenkins_timestamp(build_data.get("timestamp"))
        duration = build_data.get("duration", 0)  # Duration in milliseconds
        finished_at = None

        if started_at and duration > 0:
            from datetime import timedelta

            finished_at = started_at + timedelta(milliseconds=duration)

        # Create new run
        pipeline_run = PipelineRun(
            pipeline_id=pipeline_id,
            external_id=str(build_number),
            status=status,
            commit_hash=build_data.get("scm", {}).get(
                "commit", build_data.get("commit", "")
            ),
            started_at=started_at or datetime.now(timezone.utc),
            finished_at=finished_at,
            metadata={
                "build_number": build_number,
                "build_url": build_data.get("url"),
                "display_name": build_data.get("displayName"),
                "duration_ms": duration,
                "executor": build_data.get("executor"),
                "node": build_data.get("builtOn"),
                "cause": build_data.get("cause"),
                "parameters": build_data.get("parameters", []),
            },
        )

        db.add(pipeline_run)
        await db.flush()
        return pipeline_run

    def _parse_jenkins_timestamp(self, timestamp: Any) -> Optional[datetime]:
        """Parse Jenkins timestamp to datetime."""
        if not timestamp:
            return None

        try:
            # Jenkins timestamps are usually in milliseconds since epoch
            if isinstance(timestamp, (int, float)):
                return datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc)
            elif isinstance(timestamp, str):
                # Try parsing as ISO format
                return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except Exception as e:
            logger.warning(f"Failed to parse timestamp {timestamp}: {e}")

        return None

    async def _trigger_security_analysis(
        self,
        pipeline_run: PipelineRun,
        build_data: Dict[str, Any],
        scm_info: Dict[str, Any],
    ) -> None:
        """Trigger security analysis for completed build."""
        try:
            from src.tasks.scan_tasks import schedule_jenkins_build_scan

            # Schedule security scans
            await schedule_jenkins_build_scan.apply_async(
                args=[
                    pipeline_run.id,
                    build_data.get("url"),
                    scm_info.get("repository_url"),
                    scm_info.get("commit_hash"),
                    scm_info.get("branch"),
                ]
            )

            logger.info(
                f"Scheduled security analysis for build {pipeline_run.external_id}"
            )

        except Exception as e:
            logger.error(f"Failed to trigger security analysis: {e}")

    async def _analyze_build_failure(
        self, pipeline_run: PipelineRun, build_data: Dict[str, Any]
    ) -> None:
        """Analyze failed build for security implications."""
        try:
            build_number = build_data.get("number")
            job_name = build_data.get("job_name", "Unknown Job")

            # Get build console log for analysis
            console_log = await self.get_build_console_log(job_name, build_number)

            # Analyze log for security-related failures
            security_issues = self._analyze_console_log_for_security(console_log)

            if security_issues:
                await self._create_build_failure_alert(
                    pipeline_run, build_data, security_issues
                )

        except Exception as e:
            logger.error(f"Failed to analyze build failure: {e}")

    def _analyze_console_log_for_security(self, console_log: str) -> List[str]:
        """Analyze console log for security-related failures."""
        if not console_log:
            return []

        security_keywords = [
            "security",
            "vulnerability",
            "cve",
            "exploit",
            "authentication",
            "authorization",
            "permission",
            "ssl",
            "tls",
            "certificate",
            "crypto",
            "injection",
            "xss",
            "csrf",
            "sql injection",
        ]

        security_issues = []
        lines = console_log.lower().split("\n")

        for i, line in enumerate(lines):
            if any(keyword in line for keyword in security_keywords):
                if any(
                    error_word in line for error_word in ["error", "fail", "exception"]
                ):
                    # Context around the security-related error
                    start = max(0, i - 2)
                    end = min(len(lines), i + 3)
                    context = "\n".join(lines[start:end])
                    security_issues.append(context)

        return security_issues

    async def get_build_console_log(
        self, job_name: str, build_number: int
    ) -> Optional[str]:
        """Get console log for a specific build."""
        if not self.auth_header:
            logger.warning("Jenkins authentication not configured")
            return None

        try:
            url = f"{self.base_url}/job/{job_name}/{build_number}/consoleText"

            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.get(
                    url,
                    headers={
                        "Authorization": f"Basic {self.auth_header}",
                        "Content-Type": "application/json",
                    },
                )

                if response.status_code == 200:
                    return response.text
                else:
                    logger.warning(
                        f"Failed to fetch console log: {response.status_code}"
                    )
                    return None

        except Exception as e:
            logger.error(f"Failed to get build console log: {e}")
            return None

    async def get_build_info(
        self, job_name: str, build_number: int
    ) -> Optional[Dict[str, Any]]:
        """Get detailed build information from Jenkins API."""
        if not self.auth_header:
            logger.warning("Jenkins authentication not configured")
            return None

        try:
            url = f"{self.base_url}/job/{job_name}/{build_number}/api/json"

            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.get(
                    url,
                    headers={
                        "Authorization": f"Basic {self.auth_header}",
                        "Content-Type": "application/json",
                    },
                )

                if response.status_code == 200:
                    return response.json()
                else:
                    logger.warning(
                        f"Failed to fetch build info: {response.status_code}"
                    )
                    return None

        except Exception as e:
            logger.error(f"Failed to get build info: {e}")
            return None

    async def get_job_config(self, job_name: str) -> Optional[str]:
        """Get Jenkins job configuration XML."""
        if not self.auth_header:
            logger.warning("Jenkins authentication not configured")
            return None

        try:
            url = f"{self.base_url}/job/{job_name}/config.xml"

            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.get(
                    url,
                    headers={
                        "Authorization": f"Basic {self.auth_header}",
                        "Content-Type": "application/xml",
                    },
                )

                if response.status_code == 200:
                    return response.text
                else:
                    logger.warning(
                        f"Failed to fetch job config: {response.status_code}"
                    )
                    return None

        except Exception as e:
            logger.error(f"Failed to get job config: {e}")
            return None

    async def analyze_jenkins_job_security(self, job_name: str) -> List[Dict[str, Any]]:
        """Analyze Jenkins job configuration for security issues."""
        security_issues = []

        try:
            config_xml = await self.get_job_config(job_name)
            if not config_xml:
                return security_issues

            import xml.etree.ElementTree as ET

            try:
                root = ET.fromstring(config_xml)
            except ET.ParseError as e:
                security_issues.append(
                    {
                        "job": job_name,
                        "issue": "Invalid XML configuration",
                        "severity": "high",
                        "description": f"XML parsing error: {e}",
                    }
                )
                return security_issues

            # Analyze job configuration
            issues = []
            issues.extend(self._check_script_security(root, job_name))
            issues.extend(self._check_credential_usage(root, job_name))
            issues.extend(self._check_plugin_security(root, job_name))
            issues.extend(self._check_build_triggers(root, job_name))

            security_issues.extend(issues)

        except Exception as e:
            logger.error(f"Failed to analyze Jenkins job security: {e}")

        return security_issues

    def _check_script_security(self, root, job_name: str) -> List[Dict[str, Any]]:
        """Check for potentially dangerous scripts in job configuration."""
        issues = []

        # Find all script elements
        for script_elem in root.iter():
            if (
                "script" in script_elem.tag.lower()
                or "command" in script_elem.tag.lower()
            ):
                script_content = script_elem.text or ""

                dangerous_patterns = [
                    "curl.*|.*sh",  # Piping to shell
                    "wget.*|.*sh",
                    "sudo.*rm.*-rf",  # Dangerous rm
                    "chmod.*777",  # Overly permissive permissions
                    "eval.*\\$",  # Dynamic evaluation
                ]

                import re

                for pattern in dangerous_patterns:
                    if re.search(pattern, script_content, re.IGNORECASE):
                        issues.append(
                            {
                                "job": job_name,
                                "issue": f"Potentially dangerous script command",
                                "severity": "high",
                                "description": f"Found pattern: {pattern}",
                            }
                        )

        return issues

    def _check_credential_usage(self, root, job_name: str) -> List[Dict[str, Any]]:
        """Check for credential-related security issues."""
        issues = []

        # Check for hardcoded credentials
        for elem in root.iter():
            if elem.text:
                text = elem.text.lower()
                if any(
                    keyword in text
                    for keyword in ["password", "secret", "key", "token"]
                ):
                    # Check if it looks like a hardcoded value (not a variable reference)
                    if not any(
                        var_pattern in elem.text
                        for var_pattern in ["${", "$", "{", "}"]
                    ):
                        issues.append(
                            {
                                "job": job_name,
                                "issue": "Potential hardcoded credential",
                                "severity": "high",
                                "description": f"Found in element: {elem.tag}",
                            }
                        )

        return issues

    def _check_plugin_security(self, root, job_name: str) -> List[Dict[str, Any]]:
        """Check for security issues with Jenkins plugins."""
        issues = []

        # Known problematic plugin patterns
        risky_plugins = [
            "script-security",  # If disabled
            "build-token-root",  # Token-based access
            "publish-over-ssh",  # SSH publishing
        ]

        # This is a simplified check - in practice, you'd check plugin versions
        # against known vulnerabilities
        for elem in root.iter():
            class_name = elem.get("class", "")
            if any(risky in class_name.lower() for risky in risky_plugins):
                issues.append(
                    {
                        "job": job_name,
                        "issue": f"Usage of potentially risky plugin",
                        "severity": "medium",
                        "description": f"Plugin class: {class_name}",
                    }
                )

        return issues

    def _check_build_triggers(self, root, job_name: str) -> List[Dict[str, Any]]:
        """Check for insecure build triggers."""
        issues = []

        # Find trigger elements
        for trigger_elem in root.iter():
            if "trigger" in trigger_elem.tag.lower():
                # Check for anonymous trigger access
                if "anonymous" in str(trigger_elem.attrib).lower():
                    issues.append(
                        {
                            "job": job_name,
                            "issue": "Anonymous build trigger enabled",
                            "severity": "high",
                            "description": "Job can be triggered without authentication",
                        }
                    )

                # Check for remote trigger tokens
                if "token" in str(trigger_elem.attrib).lower():
                    issues.append(
                        {
                            "job": job_name,
                            "issue": "Remote trigger token configured",
                            "severity": "medium",
                            "description": "Ensure token is properly secured",
                        }
                    )

        return issues

    async def get_build_artifacts(
        self, job_name: str, build_number: int
    ) -> List[Dict[str, Any]]:
        """Get build artifacts from Jenkins."""
        if not self.auth_header:
            logger.warning("Jenkins authentication not configured")
            return []

        try:
            url = f"{self.base_url}/job/{job_name}/{build_number}/api/json?tree=artifacts[*]"

            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.get(
                    url,
                    headers={
                        "Authorization": f"Basic {self.auth_header}",
                        "Content-Type": "application/json",
                    },
                )

                if response.status_code == 200:
                    data = response.json()
                    return data.get("artifacts", [])
                else:
                    logger.warning(
                        f"Failed to fetch build artifacts: {response.status_code}"
                    )
                    return []

        except Exception as e:
            logger.error(f"Failed to get build artifacts: {e}")
            return []

    async def download_artifact(
        self, job_name: str, build_number: int, artifact_path: str
    ) -> Optional[bytes]:
        """Download a specific build artifact."""
        if not self.auth_header:
            logger.warning("Jenkins authentication not configured")
            return None

        try:
            url = f"{self.base_url}/job/{job_name}/{build_number}/artifact/{artifact_path}"

            async with httpx.AsyncClient(timeout=self.session_timeout) as client:
                response = await client.get(
                    url, headers={"Authorization": f"Basic {self.auth_header}"}
                )

                if response.status_code == 200:
                    return response.content
                else:
                    logger.warning(
                        f"Failed to download artifact: {response.status_code}"
                    )
                    return None

        except Exception as e:
            logger.error(f"Failed to download artifact: {e}")
            return None

    async def _create_build_failure_alert(
        self,
        pipeline_run: PipelineRun,
        build_data: Dict[str, Any],
        security_issues: List[str],
    ) -> None:
        """Create alert for build failure with security implications."""
        try:
            async with AsyncSessionLocal() as db:
                alert = Alert(
                    type=AlertType.PIPELINE_FAILURE,
                    severity=AlertSeverity.MEDIUM,
                    title=f"Jenkins build failure with security implications",
                    description=f"Build {build_data.get('number')} failed with security-related errors",
                    source_type="jenkins",
                    source_id=pipeline_run.external_id,
                    metadata={
                        "pipeline_run_id": pipeline_run.id,
                        "job_name": build_data.get("job_name"),
                        "build_url": build_data.get("url"),
                        "security_issues": security_issues[
                            :5
                        ],  # Limit to first 5 issues
                        "total_issues": len(security_issues),
                    },
                )

                db.add(alert)
                await db.commit()

                logger.info(f"Created build failure alert for run {pipeline_run.id}")

        except Exception as e:
            logger.error(f"Failed to create build failure alert: {e}")


# Global instance
jenkins_integration = JenkinsIntegration()
