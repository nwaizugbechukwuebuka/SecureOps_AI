"""
Dependency Security Scanner

This module provides comprehensive dependency scanning using Safety (for vulnerabilities)
and Bandit (for Python security issues). Includes package analysis and license checking.

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
    FileTypeDetector,
    ScannerType,
    ScanResult,
    ScanSummary,
    SeverityLevel,
    orchestrator,
)

logger = get_logger(__name__)


class SafetyScanner(BaseScanner):
    """Safety scanner for Python dependency vulnerabilities."""

    def __init__(self):
        super().__init__("safety", "3.0.0", ScannerType.DEPENDENCY)
        self.api_key = settings.SAFETY_API_KEY

    def is_available(self) -> bool:
        """Check if Safety is available."""
        try:
            result = subprocess.run(
                ["safety", "--version"], capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    async def scan(self, target: str, **kwargs) -> Tuple[ScanSummary, List[ScanResult]]:
        """Scan Python dependencies for known vulnerabilities."""
        started_at = datetime.now(timezone.utc)
        results = []

        try:
            # Find requirements files or use pipdeptree
            req_files = self._find_requirements_files(target)

            if req_files:
                for req_file in req_files:
                    file_results = await self._scan_requirements_file(req_file)
                    results.extend(file_results)
            else:
                # Scan installed packages if no requirements files found
                results = await self._scan_installed_packages(target)

            summary = self._create_summary(target, started_at, success=True)

            # Update summary with results
            for result in results:
                summary.add_result(result)

            self.logger.info(f"Safety scan completed: {len(results)} findings")
            return summary, results

        except Exception as e:
            error_msg = f"Safety scan failed: {e}"
            self.logger.error(error_msg)
            summary = self._create_summary(
                target, started_at, success=False, error_message=error_msg
            )
            return summary, []

    def _find_requirements_files(self, target: str) -> List[str]:
        """Find Python requirements files in target directory."""
        req_files = []

        if os.path.isfile(target):
            if target.endswith(
                ("requirements.txt", "Pipfile", "pyproject.toml", "setup.py")
            ):
                return [target]
            return []

        # Common requirements file patterns
        patterns = [
            "requirements.txt",
            "requirements/*.txt",
            "Pipfile",
            "Pipfile.lock",
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "poetry.lock",
        ]

        for root, dirs, files in os.walk(target):
            # Skip virtual environments and build directories
            dirs[:] = [
                d
                for d in dirs
                if d
                not in {"venv", ".venv", "__pycache__", "node_modules", "build", "dist"}
            ]

            for file in files:
                if any(file.endswith(pattern.split("/")[-1]) for pattern in patterns):
                    req_files.append(os.path.join(root, file))

        return req_files

    async def _scan_requirements_file(self, req_file: str) -> List[ScanResult]:
        """Scan specific requirements file."""
        results = []

        try:
            # Build Safety command
            command = ["safety", "check", "--file", req_file, "--json"]

            if self.api_key:
                command.extend(["--key", self.api_key])

            # Run Safety scan
            return_code, stdout, stderr = await self._run_command(command)

            if return_code != 0 and not stdout:
                self.logger.warning(
                    f"Safety scan of {req_file} returned code {return_code}: {stderr}"
                )
                return results

            # Parse JSON output
            if stdout.strip():
                try:
                    safety_data = json.loads(stdout)
                    results = self._parse_safety_output(safety_data, req_file)
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse Safety JSON output: {e}")

        except Exception as e:
            self.logger.error(f"Failed to scan requirements file {req_file}: {e}")

        return results

    async def _scan_installed_packages(self, target: str) -> List[ScanResult]:
        """Scan installed packages in environment."""
        results = []

        try:
            # Use Safety to check installed packages
            command = ["safety", "check", "--json"]

            if self.api_key:
                command.extend(["--key", self.api_key])

            # Run Safety scan
            return_code, stdout, stderr = await self._run_command(command, cwd=target)

            if return_code != 0 and not stdout:
                self.logger.warning(
                    f"Safety scan returned code {return_code}: {stderr}"
                )
                return results

            # Parse JSON output
            if stdout.strip():
                try:
                    safety_data = json.loads(stdout)
                    results = self._parse_safety_output(safety_data, target)
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse Safety JSON output: {e}")

        except Exception as e:
            self.logger.error(f"Failed to scan installed packages: {e}")

        return results

    def _parse_safety_output(self, safety_data: Any, source: str) -> List[ScanResult]:
        """Parse Safety JSON output into ScanResult objects."""
        results = []

        try:
            # Handle different Safety output formats
            vulnerabilities = []

            if isinstance(safety_data, list):
                vulnerabilities = safety_data
            elif isinstance(safety_data, dict):
                vulnerabilities = safety_data.get("vulnerabilities", [])

            for vuln in vulnerabilities:
                # Extract vulnerability information
                package_name = vuln.get("package_name", "Unknown")
                affected_versions = vuln.get("affected_versions", [])
                installed_version = vuln.get("installed_version", "Unknown")
                vulnerability_id = vuln.get("vulnerability_id", "")
                advisory = vuln.get("advisory", "")
                cve = vuln.get("cve", "")

                # Determine severity based on CVE/advisory content
                severity = self._determine_severity(advisory, cve)

                # Create scan result
                result = ScanResult(
                    scanner_type=ScannerType.DEPENDENCY,
                    rule_id=f"safety-{vulnerability_id}",
                    title=f"Vulnerable dependency: {package_name}",
                    description=f"{advisory}\nInstalled version: {installed_version}\nAffected versions: {', '.join(affected_versions) if affected_versions else 'Unknown'}",
                    severity=severity,
                    confidence=0.9,  # Safety has high confidence
                    file_path=source,
                    cve_id=cve if cve else None,
                    remediation=f"Update {package_name} to a version not in: {', '.join(affected_versions) if affected_versions else 'latest version'}",
                    references=(
                        [f"https://osv.dev/vulnerability/{vulnerability_id}"]
                        if vulnerability_id
                        else []
                    ),
                    metadata={
                        "package_name": package_name,
                        "installed_version": installed_version,
                        "affected_versions": affected_versions,
                        "vulnerability_id": vulnerability_id,
                        "cve": cve,
                        "source_file": source,
                    },
                )

                results.append(result)

        except Exception as e:
            self.logger.error(f"Failed to parse Safety output: {e}")

        return results

    def _determine_severity(self, advisory: str, cve: str) -> SeverityLevel:
        """Determine severity level from advisory text."""
        advisory_lower = advisory.lower()
        cve_lower = cve.lower()

        # Keywords that indicate different severity levels
        critical_keywords = [
            "critical",
            "remote code execution",
            "rce",
            "arbitrary code",
        ]
        high_keywords = [
            "high",
            "sql injection",
            "xss",
            "csrf",
            "authentication bypass",
        ]
        medium_keywords = [
            "medium",
            "denial of service",
            "dos",
            "information disclosure",
        ]

        combined_text = f"{advisory_lower} {cve_lower}"

        if any(keyword in combined_text for keyword in critical_keywords):
            return SeverityLevel.CRITICAL
        elif any(keyword in combined_text for keyword in high_keywords):
            return SeverityLevel.HIGH
        elif any(keyword in combined_text for keyword in medium_keywords):
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW


class BanditScanner(BaseScanner):
    """Bandit scanner for Python security issues (SAST)."""

    def __init__(self):
        super().__init__("bandit", "1.7.5", ScannerType.SAST)

    def is_available(self) -> bool:
        """Check if Bandit is available."""
        try:
            result = subprocess.run(
                ["bandit", "--version"], capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    async def scan(self, target: str, **kwargs) -> Tuple[ScanSummary, List[ScanResult]]:
        """Scan Python code for security issues."""
        started_at = datetime.now(timezone.utc)
        results = []

        try:
            # Configure Bandit options
            confidence_level = kwargs.get("confidence", "medium")
            severity_level = kwargs.get("severity", "low")

            # Find Python files to scan
            python_files = self._find_python_files(target)

            if not python_files:
                self.logger.info(f"No Python files found in {target}")
                summary = self._create_summary(target, started_at, success=True)
                return summary, []

            # Run Bandit scan
            results = await self._run_bandit_scan(
                target, confidence_level, severity_level
            )

            summary = self._create_summary(target, started_at, success=True)

            # Update summary with results
            for result in results:
                summary.add_result(result)

            self.logger.info(f"Bandit scan completed: {len(results)} findings")
            return summary, results

        except Exception as e:
            error_msg = f"Bandit scan failed: {e}"
            self.logger.error(error_msg)
            summary = self._create_summary(
                target, started_at, success=False, error_message=error_msg
            )
            return summary, []

    def _find_python_files(self, target: str) -> List[str]:
        """Find Python files in target."""
        if os.path.isfile(target) and target.endswith(".py"):
            return [target]

        return [
            file_path
            for file_path in FileTypeDetector.get_scannable_files(target)
            if FileTypeDetector.get_file_language(file_path) == "python"
        ]

    async def _run_bandit_scan(
        self, target: str, confidence: str, severity: str
    ) -> List[ScanResult]:
        """Run Bandit scan and parse results."""
        results = []

        try:
            # Build Bandit command
            command = [
                "bandit",
                "-r",
                target,  # Recursive
                "-f",
                "json",  # JSON format
                "-l",
                confidence,  # Confidence level
                "-s",
                severity,  # Severity level
            ]

            # Run Bandit
            return_code, stdout, stderr = await self._run_command(command)

            # Bandit returns non-zero when issues are found, which is expected
            if stdout.strip():
                try:
                    bandit_data = json.loads(stdout)
                    results = self._parse_bandit_output(bandit_data)
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse Bandit JSON output: {e}")

            if stderr and "No issues identified" not in stderr:
                self.logger.warning(f"Bandit stderr: {stderr}")

        except Exception as e:
            self.logger.error(f"Failed to run Bandit scan: {e}")

        return results

    def _parse_bandit_output(self, bandit_data: Dict[str, Any]) -> List[ScanResult]:
        """Parse Bandit JSON output into ScanResult objects."""
        results = []

        try:
            bandit_results = bandit_data.get("results", [])

            for issue in bandit_results:
                # Extract issue information
                test_id = issue.get("test_id", "")
                test_name = issue.get("test_name", "")
                issue_text = issue.get("issue_text", "")
                issue_confidence = issue.get("issue_confidence", "UNDEFINED")
                issue_severity = issue.get("issue_severity", "UNDEFINED")

                filename = issue.get("filename", "")
                line_number = issue.get("line_number", 0)
                line_range = issue.get("line_range", [])
                code = issue.get("code", "")

                # Map Bandit confidence to our confidence scale
                confidence = self._map_bandit_confidence(issue_confidence)

                # Map Bandit severity to our severity scale
                severity = self._map_bandit_severity(issue_severity)

                # Get CWE information if available
                cwe_id = self._get_cwe_for_test(test_id)

                # Create scan result
                result = ScanResult(
                    scanner_type=ScannerType.SAST,
                    rule_id=f"bandit-{test_id}",
                    title=f"Bandit: {test_name}",
                    description=issue_text,
                    severity=severity,
                    confidence=confidence,
                    file_path=filename,
                    line_number=line_number,
                    code_snippet=code,
                    cwe_id=cwe_id,
                    remediation=self._get_remediation_for_test(test_id),
                    references=[
                        f"https://bandit.readthedocs.io/en/latest/plugins/{test_id.lower()}.html"
                    ],
                    metadata={
                        "test_id": test_id,
                        "test_name": test_name,
                        "line_range": line_range,
                        "bandit_confidence": issue_confidence,
                        "bandit_severity": issue_severity,
                    },
                )

                results.append(result)

        except Exception as e:
            self.logger.error(f"Failed to parse Bandit output: {e}")

        return results

    def _map_bandit_confidence(self, bandit_confidence: str) -> float:
        """Map Bandit confidence level to float."""
        confidence_mapping = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5, "UNDEFINED": 0.3}
        return confidence_mapping.get(bandit_confidence.upper(), 0.5)

    def _map_bandit_severity(self, bandit_severity: str) -> SeverityLevel:
        """Map Bandit severity to our severity levels."""
        severity_mapping = {
            "HIGH": SeverityLevel.HIGH,
            "MEDIUM": SeverityLevel.MEDIUM,
            "LOW": SeverityLevel.LOW,
            "UNDEFINED": SeverityLevel.INFO,
        }
        return severity_mapping.get(bandit_severity.upper(), SeverityLevel.INFO)

    def _get_cwe_for_test(self, test_id: str) -> Optional[str]:
        """Get CWE ID for Bandit test."""
        # Mapping of common Bandit tests to CWE IDs
        cwe_mapping = {
            "B101": "CWE-95",  # Use of assert
            "B102": "CWE-78",  # Exec used
            "B103": "CWE-377",  # Set bad file permissions
            "B104": "CWE-259",  # Hardcoded bind to all interfaces
            "B105": "CWE-259",  # Hardcoded password string
            "B106": "CWE-259",  # Hardcoded password funcarg
            "B107": "CWE-259",  # Hardcoded password default
            "B108": "CWE-377",  # Hardcoded tmp directory
            "B110": "CWE-703",  # Try except pass
            "B112": "CWE-703",  # Try except continue
            "B201": "CWE-94",  # Flask debug true
            "B301": "CWE-502",  # Pickle
            "B302": "CWE-327",  # Insecure hash
            "B303": "CWE-327",  # Insecure hash MD5
            "B304": "CWE-327",  # Insecure hash MD4
            "B305": "CWE-327",  # Insecure hash SHA1
            "B306": "CWE-327",  # Insecure hash mktemp
            "B307": "CWE-78",  # Eval
            "B308": "CWE-327",  # Mark safe
            "B309": "CWE-326",  # HTTPSConnection
            "B310": "CWE-330",  # URLopen
            "B311": "CWE-330",  # Random
            "B312": "CWE-614",  # Telnet
            "B313": "CWE-94",  # XML bad cElementTree
            "B314": "CWE-94",  # XML bad ElementTree
            "B315": "CWE-94",  # XML bad Expat
            "B316": "CWE-94",  # XML bad minidom
            "B317": "CWE-94",  # XML bad pulldom
            "B318": "CWE-94",  # XML bad XMLParser
            "B319": "CWE-94",  # XML bad XMLParse columns
            "B320": "CWE-94",  # XML bad XMLParser
            "B321": "CWE-614",  # FTP related
            "B322": "CWE-322",  # Input
            "B323": "CWE-330",  # Unverified context
            "B324": "CWE-327",  # Hashlib new insecure
            "B325": "CWE-377",  # Tempnam
            "B401": "CWE-78",  # Import telnet
            "B402": "CWE-78",  # Import ftplib
            "B403": "CWE-502",  # Import pickle
            "B404": "CWE-78",  # Import subprocess
            "B405": "CWE-94",  # Import xml etree
            "B406": "CWE-94",  # Import xml sax
            "B407": "CWE-94",  # Import xml dom
            "B408": "CWE-94",  # Import xml minidom
            "B409": "CWE-94",  # Import xml pulldom
            "B410": "CWE-94",  # Import lxml
            "B411": "CWE-94",  # Import xmlrpclib
            "B412": "CWE-327",  # Import pyghmi
            "B413": "CWE-502",  # Import pycrypto
            "B501": "CWE-295",  # Request with verify false
            "B502": "CWE-295",  # SSL with bad version
            "B503": "CWE-295",  # SSL with bad defaults
            "B504": "CWE-295",  # SSL with no version
            "B505": "CWE-326",  # Weak cryptographic key
            "B506": "CWE-522",  # YAML load
            "B507": "CWE-614",  # SSH no host key verification
            "B601": "CWE-78",  # Shell injection
            "B602": "CWE-78",  # Subprocess popen shell
            "B603": "CWE-78",  # Subprocess without shell equals true
            "B604": "CWE-78",  # Any other function with shell equals true
            "B605": "CWE-78",  # Start process with a shell
            "B606": "CWE-78",  # Start process with no shell
            "B607": "CWE-78",  # Start process with partial path
            "B608": "CWE-89",  # Possible SQL injection
            "B609": "CWE-78",  # Linux commands wildcard injection
            "B610": "CWE-943",  # Django extra used
            "B611": "CWE-943",  # Django raw SQL used
            "B701": "CWE-215",  # Jinja2 autoescape false
            "B702": "CWE-117",  # Use of mako templates
            "B703": "CWE-117",  # Django mark safe
        }

        return cwe_mapping.get(test_id)

    def _get_remediation_for_test(self, test_id: str) -> Optional[str]:
        """Get remediation advice for Bandit test."""
        # Common remediation advice for Bandit tests
        remediation_mapping = {
            "B101": "Remove assert statements in production code or use proper error handling",
            "B102": "Avoid using exec(). Consider safer alternatives like importlib",
            "B105": "Remove hardcoded passwords. Use environment variables or secure key management",
            "B106": "Remove hardcoded passwords from function arguments",
            "B107": "Remove hardcoded passwords from default values",
            "B201": "Set Flask debug=False in production",
            "B301": "Avoid using pickle with untrusted data. Consider JSON or other safe formats",
            "B302": "Use secure hash algorithms like SHA-256 instead of MD5",
            "B311": "Use secrets module for cryptographically secure random numbers",
            "B501": "Enable SSL certificate verification in requests",
            "B601": "Avoid shell injection by using subprocess with shell=False",
            "B602": "Use subprocess without shell=True to prevent injection",
            "B608": "Use parameterized queries to prevent SQL injection",
        }

        return remediation_mapping.get(
            test_id, "Refer to Bandit documentation for specific remediation steps"
        )


class PipAuditScanner(BaseScanner):
    """Pip-audit scanner for Python dependency vulnerabilities (alternative to Safety)."""

    def __init__(self):
        super().__init__("pip-audit", "2.6.0", ScannerType.DEPENDENCY)

    def is_available(self) -> bool:
        """Check if pip-audit is available."""
        try:
            result = subprocess.run(
                ["pip-audit", "--version"], capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    async def scan(self, target: str, **kwargs) -> Tuple[ScanSummary, List[ScanResult]]:
        """Scan Python dependencies for vulnerabilities using pip-audit."""
        started_at = datetime.now(timezone.utc)
        results = []

        try:
            # Find requirements files
            req_files = SafetyScanner()._find_requirements_files(target)

            if req_files:
                for req_file in req_files:
                    file_results = await self._scan_requirements_with_pip_audit(
                        req_file
                    )
                    results.extend(file_results)
            else:
                # Scan installed packages
                results = await self._scan_installed_with_pip_audit(target)

            summary = self._create_summary(target, started_at, success=True)

            # Update summary with results
            for result in results:
                summary.add_result(result)

            self.logger.info(f"pip-audit scan completed: {len(results)} findings")
            return summary, results

        except Exception as e:
            error_msg = f"pip-audit scan failed: {e}"
            self.logger.error(error_msg)
            summary = self._create_summary(
                target, started_at, success=False, error_message=error_msg
            )
            return summary, []

    async def _scan_requirements_with_pip_audit(
        self, req_file: str
    ) -> List[ScanResult]:
        """Scan requirements file with pip-audit."""
        results = []

        try:
            command = ["pip-audit", "--requirement", req_file, "--format", "json"]

            return_code, stdout, stderr = await self._run_command(command)

            if stdout.strip():
                try:
                    audit_data = json.loads(stdout)
                    results = self._parse_pip_audit_output(audit_data, req_file)
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse pip-audit JSON output: {e}")

        except Exception as e:
            self.logger.error(f"Failed to scan requirements file with pip-audit: {e}")

        return results

    async def _scan_installed_with_pip_audit(self, target: str) -> List[ScanResult]:
        """Scan installed packages with pip-audit."""
        results = []

        try:
            command = ["pip-audit", "--format", "json"]

            return_code, stdout, stderr = await self._run_command(command, cwd=target)

            if stdout.strip():
                try:
                    audit_data = json.loads(stdout)
                    results = self._parse_pip_audit_output(audit_data, target)
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse pip-audit JSON output: {e}")

        except Exception as e:
            self.logger.error(f"Failed to scan installed packages with pip-audit: {e}")

        return results

    def _parse_pip_audit_output(
        self, audit_data: Dict[str, Any], source: str
    ) -> List[ScanResult]:
        """Parse pip-audit JSON output into ScanResult objects."""
        results = []

        try:
            vulnerabilities = audit_data.get("vulnerabilities", [])

            for vuln in vulnerabilities:
                package = vuln.get("package", {})
                package_name = package.get("name", "Unknown")
                package_version = package.get("version", "Unknown")

                vulns = vuln.get("vulnerabilities", [])

                for v in vulns:
                    vuln_id = v.get("id", "")
                    description = v.get("description", "")
                    fix_versions = v.get("fix_versions", [])

                    # Create scan result
                    result = ScanResult(
                        scanner_type=ScannerType.DEPENDENCY,
                        rule_id=f"pip-audit-{vuln_id}",
                        title=f"Vulnerable dependency: {package_name}",
                        description=f"{description}\nInstalled version: {package_version}",
                        severity=SeverityLevel.HIGH,  # pip-audit doesn't provide severity, assume high
                        confidence=0.9,
                        file_path=source,
                        remediation=f"Update {package_name} to version: {', '.join(fix_versions) if fix_versions else 'latest'}",
                        references=(
                            [f"https://osv.dev/vulnerability/{vuln_id}"]
                            if vuln_id
                            else []
                        ),
                        metadata={
                            "package_name": package_name,
                            "installed_version": package_version,
                            "vulnerability_id": vuln_id,
                            "fix_versions": fix_versions,
                            "source_file": source,
                        },
                    )

                    results.append(result)

        except Exception as e:
            self.logger.error(f"Failed to parse pip-audit output: {e}")

        return results


# Register scanners with orchestrator
def register_dependency_scanners():
    """Register all dependency scanners with the orchestrator."""
    safety_scanner = SafetyScanner()
    bandit_scanner = BanditScanner()
    pip_audit_scanner = PipAuditScanner()

    orchestrator.register_scanner(safety_scanner)
    orchestrator.register_scanner(bandit_scanner)
    orchestrator.register_scanner(pip_audit_scanner)

    logger.info("Registered dependency scanners: Safety, Bandit, pip-audit")


# Auto-register scanners when module is imported
register_dependency_scanners()
