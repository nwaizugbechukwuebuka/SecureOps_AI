"""
Docker Container Security Scanner

This module provides comprehensive container security scanning using Trivy
and other container security tools. Includes image vulnerability scanning,
configuration analysis, and best practice checks.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..utils.config import settings
from ..utils.logger import get_logger
from .common import (
    BaseScanner,
    ScannerType,
    ScanResult,
    ScanSummary,
    SeverityLevel,
    orchestrator,
)

logger = get_logger(__name__)


class TrivyScanner(BaseScanner):
    """Trivy scanner for container vulnerabilities and misconfigurations."""

    def __init__(self):
        super().__init__("trivy", "0.46.0", ScannerType.CONTAINER)
        self.cache_dir = settings.TRIVY_CACHE_DIR or "/tmp/trivy-cache"

    def is_available(self) -> bool:
        """Check if Trivy is available."""
        try:
            result = subprocess.run(
                ["trivy", "--version"], capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    async def scan(self, target: str, **kwargs) -> Tuple[ScanSummary, List[ScanResult]]:
        """Scan container image or filesystem for vulnerabilities."""
        started_at = datetime.now(timezone.utc)
        results = []

        try:
            scan_type = kwargs.get("scan_type", "auto")

            if scan_type == "auto":
                scan_type = self._detect_scan_type(target)

            if scan_type == "image":
                results = await self._scan_container_image(target, **kwargs)
            elif scan_type == "filesystem":
                results = await self._scan_filesystem(target, **kwargs)
            elif scan_type == "config":
                results = await self._scan_config(target, **kwargs)
            else:
                raise ValueError(f"Unsupported scan type: {scan_type}")

            summary = self._create_summary(target, started_at, success=True)

            # Update summary with results
            for result in results:
                summary.add_result(result)

            self.logger.info(f"Trivy scan completed: {len(results)} findings")
            return summary, results

        except Exception as e:
            error_msg = f"Trivy scan failed: {e}"
            self.logger.error(error_msg)
            summary = self._create_summary(
                target, started_at, success=False, error_message=error_msg
            )
            return summary, []

    def _detect_scan_type(self, target: str) -> str:
        """Detect appropriate scan type for target."""
        if os.path.isdir(target):
            # Check if it contains Dockerfiles or container-related files
            dockerfile_patterns = [
                "Dockerfile",
                "Containerfile",
                "docker-compose.yml",
                "docker-compose.yaml",
            ]
            for pattern in dockerfile_patterns:
                if any(Path(target).rglob(pattern)):
                    return "config"
            return "filesystem"
        elif os.path.isfile(target):
            if target.lower().endswith(("dockerfile", "containerfile")):
                return "config"
            return "filesystem"
        else:
            # Assume it's a container image reference
            return "image"

    async def _scan_container_image(self, image: str, **kwargs) -> List[ScanResult]:
        """Scan container image for vulnerabilities."""
        results = []

        try:
            # Build Trivy command for image scanning
            command = [
                "trivy",
                "image",
                "--format",
                "json",
                "--cache-dir",
                self.cache_dir,
                image,
            ]

            # Add security checks
            security_checks = kwargs.get(
                "security_checks", ["vuln", "config", "secret"]
            )
            if security_checks:
                command.extend(["--security-checks", ",".join(security_checks)])

            # Add severity filter
            severity_filter = kwargs.get("severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
            command.extend(["--severity", severity_filter])

            # Run Trivy scan
            return_code, stdout, stderr = await self._run_command(
                command, timeout=600
            )  # 10 minutes timeout

            if stdout.strip():
                try:
                    trivy_data = json.loads(stdout)
                    results = self._parse_trivy_output(trivy_data, image)
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse Trivy JSON output: {e}")

            if stderr:
                self.logger.warning(f"Trivy stderr: {stderr}")

        except Exception as e:
            self.logger.error(f"Failed to scan container image {image}: {e}")

        return results

    async def _scan_filesystem(self, target: str, **kwargs) -> List[ScanResult]:
        """Scan filesystem for vulnerabilities."""
        results = []

        try:
            # Build Trivy command for filesystem scanning
            command = [
                "trivy",
                "fs",
                "--format",
                "json",
                "--cache-dir",
                self.cache_dir,
                target,
            ]

            # Add security checks
            security_checks = kwargs.get(
                "security_checks", ["vuln", "secret", "config"]
            )
            if security_checks:
                command.extend(["--security-checks", ",".join(security_checks)])

            # Add severity filter
            severity_filter = kwargs.get("severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
            command.extend(["--severity", severity_filter])

            # Run Trivy scan
            return_code, stdout, stderr = await self._run_command(command, timeout=300)

            if stdout.strip():
                try:
                    trivy_data = json.loads(stdout)
                    results = self._parse_trivy_output(trivy_data, target)
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse Trivy JSON output: {e}")

        except Exception as e:
            self.logger.error(f"Failed to scan filesystem {target}: {e}")

        return results

    async def _scan_config(self, target: str, **kwargs) -> List[ScanResult]:
        """Scan configuration files for misconfigurations."""
        results = []

        try:
            # Build Trivy command for config scanning
            command = [
                "trivy",
                "config",
                "--format",
                "json",
                "--cache-dir",
                self.cache_dir,
                target,
            ]

            # Add severity filter
            severity_filter = kwargs.get("severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
            command.extend(["--severity", severity_filter])

            # Run Trivy scan
            return_code, stdout, stderr = await self._run_command(command)

            if stdout.strip():
                try:
                    trivy_data = json.loads(stdout)
                    results = self._parse_trivy_output(trivy_data, target)
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse Trivy JSON output: {e}")

        except Exception as e:
            self.logger.error(f"Failed to scan config {target}: {e}")

        return results

    def _parse_trivy_output(
        self, trivy_data: Dict[str, Any], target: str
    ) -> List[ScanResult]:
        """Parse Trivy JSON output into ScanResult objects."""
        results = []

        try:
            # Handle Trivy output format
            scan_results = trivy_data.get("Results", [])

            for result in scan_results:
                target_name = result.get("Target", target)
                result_type = result.get("Type", "unknown")

                # Process vulnerabilities
                vulnerabilities = result.get("Vulnerabilities", [])
                for vuln in vulnerabilities:
                    results.append(
                        self._create_vulnerability_result(
                            vuln, target_name, result_type
                        )
                    )

                # Process misconfigurations
                misconfigurations = result.get("Misconfigurations", [])
                for misconf in misconfigurations:
                    results.append(
                        self._create_misconfiguration_result(
                            misconf, target_name, result_type
                        )
                    )

                # Process secrets
                secrets = result.get("Secrets", [])
                for secret in secrets:
                    results.append(
                        self._create_secret_result(secret, target_name, result_type)
                    )

        except Exception as e:
            self.logger.error(f"Failed to parse Trivy output: {e}")

        return results

    def _create_vulnerability_result(
        self, vuln: Dict[str, Any], target: str, result_type: str
    ) -> ScanResult:
        """Create ScanResult for vulnerability."""
        vuln_id = vuln.get("VulnerabilityID", "")
        pkg_name = vuln.get("PkgName", "")
        installed_version = vuln.get("InstalledVersion", "")
        fixed_version = vuln.get("FixedVersion", "")
        severity = vuln.get("Severity", "UNKNOWN")
        title = vuln.get("Title", "")
        description = vuln.get("Description", "")

        # Get CVE and CWE information
        cve_id = vuln_id if vuln_id.startswith("CVE-") else None
        cvss = vuln.get("CVSS", {})
        cvss_score = None

        # Extract CVSS score
        for cvss_version, cvss_data in cvss.items():
            if isinstance(cvss_data, dict) and "V3Score" in cvss_data:
                cvss_score = cvss_data["V3Score"]
                break
            elif isinstance(cvss_data, dict) and "V2Score" in cvss_data:
                cvss_score = cvss_data["V2Score"]
                break

        # Build remediation
        remediation = f"Update {pkg_name} from {installed_version}"
        if fixed_version:
            remediation += f" to {fixed_version} or later"

        # Get references
        references = []
        primary_url = vuln.get("PrimaryURL", "")
        if primary_url:
            references.append(primary_url)

        ref_urls = vuln.get("References", [])
        references.extend(ref_urls[:5])  # Limit to 5 references

        return ScanResult(
            scanner_type=ScannerType.CONTAINER,
            rule_id=f"trivy-vuln-{vuln_id}",
            title=f"Vulnerable package: {pkg_name} ({vuln_id})",
            description=f"{title}\n\n{description}",
            severity=self._map_trivy_severity(severity),
            confidence=0.9,
            file_path=target,
            cve_id=cve_id,
            cvss_score=cvss_score,
            remediation=remediation,
            references=references,
            metadata={
                "vulnerability_id": vuln_id,
                "package_name": pkg_name,
                "installed_version": installed_version,
                "fixed_version": fixed_version,
                "target_type": result_type,
                "trivy_severity": severity,
                "cvss_details": cvss,
            },
        )

    def _create_misconfiguration_result(
        self, misconf: Dict[str, Any], target: str, result_type: str
    ) -> ScanResult:
        """Create ScanResult for misconfiguration."""
        rule_id = misconf.get("ID", "")
        title = misconf.get("Title", "")
        description = misconf.get("Description", "")
        message = misconf.get("Message", "")
        severity = misconf.get("Severity", "UNKNOWN")

        # Get file location information
        cause_metadata = misconf.get("CauseMetadata", {})
        file_path = target
        line_number = None
        code_snippet = None

        if cause_metadata:
            provider = cause_metadata.get("Provider", "")
            resource = cause_metadata.get("Resource", "")
            start_line = cause_metadata.get("StartLine")
            end_line = cause_metadata.get("EndLine")
            code = cause_metadata.get("Code", {})

            if start_line:
                line_number = start_line

            if code and "Lines" in code:
                lines = code["Lines"]
                if lines:
                    code_snippet = "\n".join(
                        [line.get("Content", "") for line in lines[:10]]
                    )  # Limit to 10 lines

        # Get remediation
        resolution = misconf.get("Resolution", "")
        remediation = resolution if resolution else f"Fix misconfiguration: {rule_id}"

        # Get references
        references = []
        primary_url = misconf.get("PrimaryURL", "")
        if primary_url:
            references.append(primary_url)

        ref_urls = misconf.get("References", [])
        references.extend(ref_urls[:3])  # Limit to 3 references

        return ScanResult(
            scanner_type=ScannerType.CONTAINER,
            rule_id=f"trivy-config-{rule_id}",
            title=f"Configuration issue: {title}",
            description=f"{description}\n\n{message}",
            severity=self._map_trivy_severity(severity),
            confidence=0.8,
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            remediation=remediation,
            references=references,
            metadata={
                "rule_id": rule_id,
                "target_type": result_type,
                "trivy_severity": severity,
                "cause_metadata": cause_metadata,
            },
        )

    def _create_secret_result(
        self, secret: Dict[str, Any], target: str, result_type: str
    ) -> ScanResult:
        """Create ScanResult for exposed secret."""
        rule_id = secret.get("RuleID", "")
        category = secret.get("Category", "")
        severity = secret.get("Severity", "HIGH")  # Default to HIGH for secrets
        title = secret.get("Title", "")

        # Get file location
        start_line = secret.get("StartLine", 0)
        end_line = secret.get("EndLine", 0)
        code = secret.get("Code", {})

        code_snippet = None
        if code and "Lines" in code:
            lines = code["Lines"]
            if lines:
                # Mask sensitive content in code snippet
                masked_lines = []
                for line in lines[:5]:  # Limit to 5 lines
                    content = line.get("Content", "")
                    # Simple masking - replace potential secrets with asterisks
                    masked_content = self._mask_secret_content(content)
                    masked_lines.append(masked_content)
                code_snippet = "\n".join(masked_lines)

        return ScanResult(
            scanner_type=ScannerType.SECRET,
            rule_id=f"trivy-secret-{rule_id}",
            title=f"Exposed secret: {title or category}",
            description=f"Potential {category} secret detected in {target}",
            severity=SeverityLevel.HIGH,  # Secrets are always high severity
            confidence=0.8,
            file_path=target,
            line_number=start_line,
            code_snippet=code_snippet,
            remediation="Remove the exposed secret and use secure secret management instead",
            metadata={
                "rule_id": rule_id,
                "category": category,
                "start_line": start_line,
                "end_line": end_line,
                "target_type": result_type,
                "trivy_severity": severity,
            },
        )

    def _mask_secret_content(self, content: str) -> str:
        """Mask sensitive content in code snippets."""
        import re

        # Patterns for common secrets
        patterns = [
            (
                r'(["\']?)([a-zA-Z0-9+/=]{20,})(["\']?)',
                r"\1***MASKED***\3",
            ),  # Base64-like
            (r'(["\']?)([a-fA-F0-9]{32,})(["\']?)', r"\1***MASKED***\3"),  # Hex strings
            (
                r'(password\s*[:=]\s*["\']?)([^"\'\\s]+)(["\']?)',
                r"\1***MASKED***\3",
            ),  # Passwords
            (
                r'(api[_-]?key\s*[:=]\s*["\']?)([^"\'\\s]+)(["\']?)',
                r"\1***MASKED***\3",
            ),  # API keys
            (
                r'(token\s*[:=]\s*["\']?)([^"\'\\s]+)(["\']?)',
                r"\1***MASKED***\3",
            ),  # Tokens
        ]

        masked_content = content
        for pattern, replacement in patterns:
            masked_content = re.sub(
                pattern, replacement, masked_content, flags=re.IGNORECASE
            )

        return masked_content

    def _map_trivy_severity(self, severity: str) -> SeverityLevel:
        """Map Trivy severity to our severity levels."""
        severity_mapping = {
            "CRITICAL": SeverityLevel.CRITICAL,
            "HIGH": SeverityLevel.HIGH,
            "MEDIUM": SeverityLevel.MEDIUM,
            "LOW": SeverityLevel.LOW,
            "UNKNOWN": SeverityLevel.INFO,
        }
        return severity_mapping.get(severity.upper(), SeverityLevel.INFO)


class DockerBenchScanner(BaseScanner):
    """Docker Bench Security scanner for Docker host configuration."""

    def __init__(self):
        super().__init__("docker-bench", "1.5.0", ScannerType.CONTAINER)

    def is_available(self) -> bool:
        """Check if Docker Bench Security is available."""
        try:
            # Check if docker-bench-security script exists
            result = subprocess.run(
                ["which", "docker-bench-security"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except Exception:
            return False

    async def scan(self, target: str, **kwargs) -> Tuple[ScanSummary, List[ScanResult]]:
        """Run Docker Bench Security scan."""
        started_at = datetime.now(timezone.utc)
        results = []

        try:
            # Docker Bench Security doesn't take a target, it scans the Docker host
            results = await self._run_docker_bench()

            summary = self._create_summary("docker-host", started_at, success=True)

            # Update summary with results
            for result in results:
                summary.add_result(result)

            self.logger.info(f"Docker Bench scan completed: {len(results)} findings")
            return summary, results

        except Exception as e:
            error_msg = f"Docker Bench scan failed: {e}"
            self.logger.error(error_msg)
            summary = self._create_summary(
                "docker-host", started_at, success=False, error_message=error_msg
            )
            return summary, []

    async def _run_docker_bench(self) -> List[ScanResult]:
        """Run Docker Bench Security and parse results."""
        results = []

        try:
            # Run docker-bench-security
            command = ["docker-bench-security", "-j"]  # JSON output

            return_code, stdout, stderr = await self._run_command(command, timeout=300)

            if stdout.strip():
                try:
                    # Docker Bench output format may vary, handle different formats
                    lines = stdout.strip().split("\n")
                    for line in lines:
                        if line.strip().startswith("{"):
                            try:
                                bench_data = json.loads(line)
                                result = self._parse_docker_bench_result(bench_data)
                                if result:
                                    results.append(result)
                            except json.JSONDecodeError:
                                continue
                except Exception as e:
                    self.logger.error(f"Failed to parse Docker Bench output: {e}")

        except Exception as e:
            self.logger.error(f"Failed to run Docker Bench: {e}")

        return results

    def _parse_docker_bench_result(
        self, bench_data: Dict[str, Any]
    ) -> Optional[ScanResult]:
        """Parse Docker Bench result into ScanResult."""
        try:
            test_id = bench_data.get("id", "")
            description = bench_data.get("desc", "")
            result_status = bench_data.get("result", "")

            # Only create results for WARN and FAIL
            if result_status not in ["WARN", "FAIL"]:
                return None

            severity = (
                SeverityLevel.MEDIUM if result_status == "WARN" else SeverityLevel.HIGH
            )

            return ScanResult(
                scanner_type=ScannerType.CONTAINER,
                rule_id=f"docker-bench-{test_id}",
                title=f"Docker security issue: {test_id}",
                description=description,
                severity=severity,
                confidence=0.9,
                remediation=f"Follow Docker security best practices for test {test_id}",
                references=["https://github.com/docker/docker-bench-security"],
                metadata={
                    "test_id": test_id,
                    "result_status": result_status,
                    "docker_bench_version": "1.5.0",
                },
            )

        except Exception as e:
            self.logger.error(f"Failed to parse Docker Bench result: {e}")
            return None


class HadolintScanner(BaseScanner):
    """Hadolint scanner for Dockerfile best practices."""

    def __init__(self):
        super().__init__("hadolint", "2.12.0", ScannerType.CONTAINER)

    def is_available(self) -> bool:
        """Check if Hadolint is available."""
        try:
            result = subprocess.run(
                ["hadolint", "--version"], capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    async def scan(self, target: str, **kwargs) -> Tuple[ScanSummary, List[ScanResult]]:
        """Scan Dockerfile with Hadolint."""
        started_at = datetime.now(timezone.utc)
        results = []

        try:
            # Find Dockerfile(s) to scan
            dockerfiles = self._find_dockerfiles(target)

            if not dockerfiles:
                self.logger.info(f"No Dockerfiles found in {target}")
                summary = self._create_summary(target, started_at, success=True)
                return summary, []

            # Scan each Dockerfile
            for dockerfile in dockerfiles:
                file_results = await self._scan_dockerfile(dockerfile)
                results.extend(file_results)

            summary = self._create_summary(target, started_at, success=True)

            # Update summary with results
            for result in results:
                summary.add_result(result)

            self.logger.info(f"Hadolint scan completed: {len(results)} findings")
            return summary, results

        except Exception as e:
            error_msg = f"Hadolint scan failed: {e}"
            self.logger.error(error_msg)
            summary = self._create_summary(
                target, started_at, success=False, error_message=error_msg
            )
            return summary, []

    def _find_dockerfiles(self, target: str) -> List[str]:
        """Find Dockerfile(s) in target."""
        if os.path.isfile(target):
            if target.lower().endswith(("dockerfile", "containerfile")):
                return [target]
            return []

        dockerfiles = []
        for root, dirs, files in os.walk(target):
            for file in files:
                if file.lower() in ["dockerfile", "containerfile"] or file.startswith(
                    "Dockerfile."
                ):
                    dockerfiles.append(os.path.join(root, file))

        return dockerfiles

    async def _scan_dockerfile(self, dockerfile: str) -> List[ScanResult]:
        """Scan individual Dockerfile."""
        results = []

        try:
            command = ["hadolint", "--format", "json", dockerfile]

            return_code, stdout, stderr = await self._run_command(command)

            if stdout.strip():
                try:
                    hadolint_results = json.loads(stdout)
                    for issue in hadolint_results:
                        result = self._parse_hadolint_issue(issue, dockerfile)
                        if result:
                            results.append(result)
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse Hadolint JSON: {e}")

        except Exception as e:
            self.logger.error(f"Failed to scan Dockerfile {dockerfile}: {e}")

        return results

    def _parse_hadolint_issue(
        self, issue: Dict[str, Any], dockerfile: str
    ) -> Optional[ScanResult]:
        """Parse Hadolint issue into ScanResult."""
        try:
            rule_code = issue.get("code", "")
            level = issue.get("level", "info")
            message = issue.get("message", "")
            line = issue.get("line", 0)
            column = issue.get("column", 0)
            file_path = issue.get("file", dockerfile)

            # Map Hadolint levels to our severity
            severity_mapping = {
                "error": SeverityLevel.HIGH,
                "warning": SeverityLevel.MEDIUM,
                "info": SeverityLevel.LOW,
                "style": SeverityLevel.INFO,
            }

            severity = severity_mapping.get(level.lower(), SeverityLevel.INFO)

            return ScanResult(
                scanner_type=ScannerType.CONTAINER,
                rule_id=f"hadolint-{rule_code}",
                title=f"Dockerfile issue: {rule_code}",
                description=message,
                severity=severity,
                confidence=0.8,
                file_path=file_path,
                line_number=line if line > 0 else None,
                column_number=column if column > 0 else None,
                remediation=f"Fix Dockerfile issue according to rule {rule_code}",
                references=[f"https://github.com/hadolint/hadolint/wiki/{rule_code}"],
                metadata={
                    "rule_code": rule_code,
                    "level": level,
                    "hadolint_file": file_path,
                },
            )

        except Exception as e:
            self.logger.error(f"Failed to parse Hadolint issue: {e}")
            return None


# Register scanners with orchestrator
def register_container_scanners():
    """Register all container scanners with the orchestrator."""
    trivy_scanner = TrivyScanner()
    docker_bench_scanner = DockerBenchScanner()
    hadolint_scanner = HadolintScanner()

    orchestrator.register_scanner(trivy_scanner)
    orchestrator.register_scanner(docker_bench_scanner)
    orchestrator.register_scanner(hadolint_scanner)

    logger.info("Registered container scanners: Trivy, Docker Bench, Hadolint")


# Auto-register scanners when module is imported
register_container_scanners()
