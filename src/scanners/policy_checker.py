"""
Security Policy Checker

This module provides comprehensive security policy checking across various
configuration files, infrastructure as code, and security frameworks.
Supports OWASP, NIST, SOC2, GDPR, and custom policy compliance.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

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


class PolicyFramework(Enum):
    """Supported security policy frameworks."""

    OWASP = "owasp"
    NIST = "nist"
    SOC2 = "soc2"
    GDPR = "gdpr"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    ISO27001 = "iso27001"
    CUSTOM = "custom"


@dataclass
class PolicyRule:
    """Represents a security policy rule."""

    id: str
    framework: PolicyFramework
    title: str
    description: str
    severity: SeverityLevel
    category: str
    check_function: str
    remediation: str
    references: List[str]
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []


class PolicyChecker(BaseScanner):
    """Comprehensive security policy checker."""

    def __init__(self):
        super().__init__("policy-checker", "1.0.0", ScannerType.POLICY)
        self.rules = self._initialize_policy_rules()

    def is_available(self) -> bool:
        """Policy checker is always available."""
        return True

    def _initialize_policy_rules(self) -> List[PolicyRule]:
        """Initialize security policy rules."""
        rules = []

        # OWASP Security Rules
        rules.extend(self._get_owasp_rules())

        # NIST Cybersecurity Framework Rules
        rules.extend(self._get_nist_rules())

        # SOC2 Compliance Rules
        rules.extend(self._get_soc2_rules())

        # GDPR Privacy Rules
        rules.extend(self._get_gdpr_rules())

        # Infrastructure Security Rules
        rules.extend(self._get_infrastructure_rules())

        # CI/CD Security Rules
        rules.extend(self._get_cicd_rules())

        # Application Security Rules
        rules.extend(self._get_application_rules())

        return rules

    async def scan(self, target: str, **kwargs) -> Tuple[ScanSummary, List[ScanResult]]:
        """Scan target for policy compliance issues."""
        started_at = datetime.now(timezone.utc)
        results = []

        try:
            # Configuration options
            frameworks = kwargs.get(
                "frameworks", [PolicyFramework.OWASP, PolicyFramework.NIST]
            )
            if isinstance(frameworks, str):
                frameworks = [PolicyFramework(frameworks)]
            elif (
                isinstance(frameworks, list)
                and frameworks
                and isinstance(frameworks[0], str)
            ):
                frameworks = [PolicyFramework(f) for f in frameworks]

            # Filter rules by requested frameworks
            applicable_rules = [
                rule for rule in self.rules if rule.framework in frameworks
            ]

            self.logger.info(
                f"Checking {len(applicable_rules)} policy rules across {len(frameworks)} frameworks"
            )

            # Get files to analyze
            config_files = self._find_configuration_files(target)

            # Run policy checks
            for rule in applicable_rules:
                try:
                    rule_results = await self._check_policy_rule(
                        rule, target, config_files
                    )
                    results.extend(rule_results)
                except Exception as e:
                    self.logger.warning(f"Failed to check rule {rule.id}: {e}")

            # Remove duplicates
            results = self._deduplicate_results(results)

            summary = self._create_summary(target, started_at, success=True)

            # Update summary with results
            for result in results:
                summary.add_result(result)

            self.logger.info(f"Policy check completed: {len(results)} findings")
            return summary, results

        except Exception as e:
            error_msg = f"Policy check failed: {e}"
            self.logger.error(error_msg)
            summary = self._create_summary(
                target, started_at, success=False, error_message=error_msg
            )
            return summary, []

    def _find_configuration_files(self, target: str) -> Dict[str, List[str]]:
        """Find configuration files by type."""
        config_files = {
            "docker": [],
            "k8s": [],
            "terraform": [],
            "ansible": [],
            "ci_cd": [],
            "web_config": [],
            "app_config": [],
            "security_config": [],
        }

        if os.path.isfile(target):
            file_type = self._classify_config_file(target)
            if file_type:
                config_files[file_type].append(target)
            return config_files

        for root, dirs, files in os.walk(target):
            # Skip hidden directories and common non-config directories
            dirs[:] = [
                d
                for d in dirs
                if not d.startswith(".")
                and d
                not in {"node_modules", "__pycache__", "venv", ".venv", "build", "dist"}
            ]

            for file in files:
                file_path = os.path.join(root, file)
                file_type = self._classify_config_file(file_path)
                if file_type:
                    config_files[file_type].append(file_path)

        return config_files

    def _classify_config_file(self, file_path: str) -> Optional[str]:
        """Classify configuration file by type."""
        filename = os.path.basename(file_path).lower()

        # Docker files
        if filename in ["dockerfile", "containerfile"] or filename.startswith(
            "dockerfile."
        ):
            return "docker"
        if filename in ["docker-compose.yml", "docker-compose.yaml"]:
            return "docker"

        # Kubernetes files
        if any(
            pattern in filename for pattern in ["k8s", "kubernetes", "kustomization"]
        ):
            return "k8s"
        if filename.endswith((".yml", ".yaml")) and any(
            keyword
            in open(file_path, "r", encoding="utf-8", errors="ignore").read(500).lower()
            for keyword in ["apiversion:", "kind:", "metadata:", "spec:"]
        ):
            return "k8s"

        # Terraform files
        if filename.endswith(".tf") or filename.endswith(".tfvars"):
            return "terraform"

        # Ansible files
        if filename in ["ansible.cfg", "hosts", "inventory"]:
            return "ansible"
        if filename.endswith(".yml") and "playbook" in filename:
            return "ansible"

        # CI/CD files
        ci_cd_patterns = [
            ".gitlab-ci.yml",
            ".github/workflows",
            "azure-pipelines",
            "jenkinsfile",
            "buildspec.yml",
            ".travis.yml",
            ".circleci",
        ]
        if any(pattern in file_path.lower() for pattern in ci_cd_patterns):
            return "ci_cd"

        # Web server configs
        web_patterns = [
            "nginx.conf",
            "apache",
            "httpd.conf",
            ".htaccess",
            "web.config",
            "server.xml",
        ]
        if any(pattern in filename for pattern in web_patterns):
            return "web_config"

        # Application configs
        app_patterns = [
            "config.json",
            "settings.json",
            "app.config",
            "application.yml",
            "application.properties",
        ]
        if any(pattern in filename for pattern in app_patterns):
            return "app_config"

        # Security configs
        security_patterns = [
            "security.yml",
            "auth.config",
            "oauth",
            "jwt",
            "tls.conf",
            "ssl.conf",
            "certificates",
        ]
        if any(pattern in filename for pattern in security_patterns):
            return "security_config"

        return None

    async def _check_policy_rule(
        self, rule: PolicyRule, target: str, config_files: Dict[str, List[str]]
    ) -> List[ScanResult]:
        """Check a specific policy rule."""
        results = []

        try:
            # Get the check function
            check_method = getattr(self, rule.check_function, None)
            if not check_method:
                self.logger.warning(
                    f"Check function {rule.check_function} not found for rule {rule.id}"
                )
                return results

            # Execute the check
            violations = await check_method(target, config_files)

            # Convert violations to ScanResult objects
            for violation in violations:
                result = ScanResult(
                    scanner_type=ScannerType.POLICY,
                    rule_id=rule.id,
                    title=rule.title,
                    description=f"{rule.description}\n\nViolation: {violation.get('message', '')}",
                    severity=rule.severity,
                    confidence=violation.get("confidence", 0.8),
                    file_path=violation.get("file_path"),
                    line_number=violation.get("line_number"),
                    code_snippet=violation.get("code_snippet"),
                    remediation=rule.remediation,
                    references=rule.references,
                    metadata={
                        "policy_framework": rule.framework.value,
                        "policy_category": rule.category,
                        "policy_tags": rule.tags,
                        "violation_details": violation,
                    },
                )
                results.append(result)

        except Exception as e:
            self.logger.error(f"Error checking rule {rule.id}: {e}")

        return results

    def _get_owasp_rules(self) -> List[PolicyRule]:
        """Get OWASP security policy rules."""
        return [
            PolicyRule(
                id="OWASP-A01-2021",
                framework=PolicyFramework.OWASP,
                title="Broken Access Control",
                description="Check for proper access control implementation",
                severity=SeverityLevel.HIGH,
                category="Access Control",
                check_function="_check_access_control",
                remediation="Implement proper access control mechanisms",
                references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
                tags=["access-control", "authorization"],
            ),
            PolicyRule(
                id="OWASP-A02-2021",
                framework=PolicyFramework.OWASP,
                title="Cryptographic Failures",
                description="Check for cryptographic implementation issues",
                severity=SeverityLevel.HIGH,
                category="Cryptography",
                check_function="_check_cryptographic_failures",
                remediation="Use strong cryptographic algorithms and proper key management",
                references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
                tags=["cryptography", "encryption"],
            ),
            PolicyRule(
                id="OWASP-A03-2021",
                framework=PolicyFramework.OWASP,
                title="Injection",
                description="Check for injection vulnerabilities",
                severity=SeverityLevel.HIGH,
                category="Injection",
                check_function="_check_injection_vulnerabilities",
                remediation="Use parameterized queries and input validation",
                references=["https://owasp.org/Top10/A03_2021-Injection/"],
                tags=["injection", "sql-injection", "xss"],
            ),
            PolicyRule(
                id="OWASP-A05-2021",
                framework=PolicyFramework.OWASP,
                title="Security Misconfiguration",
                description="Check for security misconfigurations",
                severity=SeverityLevel.MEDIUM,
                category="Configuration",
                check_function="_check_security_misconfiguration",
                remediation="Follow security configuration best practices",
                references=[
                    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
                ],
                tags=["configuration", "hardening"],
            ),
            PolicyRule(
                id="OWASP-A09-2021",
                framework=PolicyFramework.OWASP,
                title="Security Logging and Monitoring Failures",
                description="Check for proper logging and monitoring",
                severity=SeverityLevel.MEDIUM,
                category="Logging",
                check_function="_check_logging_monitoring",
                remediation="Implement comprehensive logging and monitoring",
                references=[
                    "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"
                ],
                tags=["logging", "monitoring", "alerting"],
            ),
        ]

    def _get_nist_rules(self) -> List[PolicyRule]:
        """Get NIST Cybersecurity Framework rules."""
        return [
            PolicyRule(
                id="NIST-ID-AM-1",
                framework=PolicyFramework.NIST,
                title="Asset Management",
                description="Check for proper asset inventory and management",
                severity=SeverityLevel.MEDIUM,
                category="Identify",
                check_function="_check_asset_management",
                remediation="Implement comprehensive asset inventory",
                references=["https://www.nist.gov/cyberframework"],
                tags=["asset-management", "inventory"],
            ),
            PolicyRule(
                id="NIST-PR-AC-1",
                framework=PolicyFramework.NIST,
                title="Access Control Policy",
                description="Check for access control policies and procedures",
                severity=SeverityLevel.HIGH,
                category="Protect",
                check_function="_check_access_control_policy",
                remediation="Establish formal access control policies",
                references=["https://www.nist.gov/cyberframework"],
                tags=["access-control", "policy"],
            ),
            PolicyRule(
                id="NIST-PR-DS-1",
                framework=PolicyFramework.NIST,
                title="Data Security",
                description="Check for data protection at rest",
                severity=SeverityLevel.HIGH,
                category="Protect",
                check_function="_check_data_protection_at_rest",
                remediation="Implement encryption for data at rest",
                references=["https://www.nist.gov/cyberframework"],
                tags=["data-protection", "encryption"],
            ),
        ]

    def _get_soc2_rules(self) -> List[PolicyRule]:
        """Get SOC 2 compliance rules."""
        return [
            PolicyRule(
                id="SOC2-CC6.1",
                framework=PolicyFramework.SOC2,
                title="Logical Access Controls",
                description="Check for logical and physical access controls",
                severity=SeverityLevel.HIGH,
                category="Security",
                check_function="_check_logical_access_controls",
                remediation="Implement strong access controls and authentication",
                references=[
                    "https://us.aicpa.org/interestareas/frc/assuranceadvisoryservices/sorhome"
                ],
                tags=["access-control", "authentication"],
            ),
            PolicyRule(
                id="SOC2-CC6.7",
                framework=PolicyFramework.SOC2,
                title="Data Transmission",
                description="Check for secure data transmission",
                severity=SeverityLevel.HIGH,
                category="Security",
                check_function="_check_data_transmission_security",
                remediation="Use encrypted communication channels",
                references=[
                    "https://us.aicpa.org/interestareas/frc/assuranceadvisoryservices/sorhome"
                ],
                tags=["data-transmission", "encryption", "tls"],
            ),
        ]

    def _get_gdpr_rules(self) -> List[PolicyRule]:
        """Get GDPR privacy compliance rules."""
        return [
            PolicyRule(
                id="GDPR-ART-25",
                framework=PolicyFramework.GDPR,
                title="Data Protection by Design",
                description="Check for privacy by design implementation",
                severity=SeverityLevel.MEDIUM,
                category="Privacy",
                check_function="_check_privacy_by_design",
                remediation="Implement privacy by design principles",
                references=["https://gdpr.eu/article-25-data-protection-by-design/"],
                tags=["privacy", "data-protection"],
            ),
            PolicyRule(
                id="GDPR-ART-32",
                framework=PolicyFramework.GDPR,
                title="Security of Processing",
                description="Check for appropriate technical and organizational measures",
                severity=SeverityLevel.HIGH,
                category="Security",
                check_function="_check_security_of_processing",
                remediation="Implement appropriate security measures for personal data",
                references=["https://gdpr.eu/article-32-security-of-processing/"],
                tags=["security", "personal-data"],
            ),
        ]

    def _get_infrastructure_rules(self) -> List[PolicyRule]:
        """Get infrastructure security rules."""
        return [
            PolicyRule(
                id="INFRA-NET-1",
                framework=PolicyFramework.CUSTOM,
                title="Network Security",
                description="Check for proper network segmentation and security",
                severity=SeverityLevel.MEDIUM,
                category="Network",
                check_function="_check_network_security",
                remediation="Implement network segmentation and firewall rules",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Network_Segmentation_Cheat_Sheet.html"
                ],
                tags=["network", "firewall", "segmentation"],
            ),
        ]

    def _get_cicd_rules(self) -> List[PolicyRule]:
        """Get CI/CD security rules."""
        return [
            PolicyRule(
                id="CICD-SEC-1",
                framework=PolicyFramework.CUSTOM,
                title="CI/CD Pipeline Security",
                description="Check for secure CI/CD pipeline configuration",
                severity=SeverityLevel.MEDIUM,
                category="CI/CD",
                check_function="_check_cicd_security",
                remediation="Secure CI/CD pipelines with proper access controls",
                references=["https://owasp.org/www-project-devsecops-guideline/"],
                tags=["ci-cd", "pipeline", "devsecops"],
            ),
        ]

    def _get_application_rules(self) -> List[PolicyRule]:
        """Get application security rules."""
        return [
            PolicyRule(
                id="APP-SEC-1",
                framework=PolicyFramework.CUSTOM,
                title="Application Security Headers",
                description="Check for security headers configuration",
                severity=SeverityLevel.MEDIUM,
                category="Application",
                check_function="_check_security_headers",
                remediation="Configure appropriate security headers",
                references=["https://owasp.org/www-project-secure-headers/"],
                tags=["headers", "web-security"],
            ),
        ]

    # Policy check implementation methods

    async def _check_access_control(
        self, target: str, config_files: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """Check for access control issues."""
        violations = []

        # Check Kubernetes RBAC
        for k8s_file in config_files.get("k8s", []):
            try:
                with open(k8s_file, "r") as f:
                    content = yaml.safe_load(f)
                    if (
                        isinstance(content, dict)
                        and content.get("kind") == "RoleBinding"
                    ):
                        subjects = content.get("subjects", [])
                        for subject in subjects:
                            if subject.get("name") == "system:anonymous":
                                violations.append(
                                    {
                                        "message": "Anonymous access granted in RoleBinding",
                                        "file_path": k8s_file,
                                        "confidence": 0.9,
                                    }
                                )
            except Exception:
                continue

        return violations

    async def _check_cryptographic_failures(
        self, target: str, config_files: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """Check for cryptographic implementation issues."""
        violations = []

        # Check for weak SSL/TLS configurations
        for config_file in config_files.get("web_config", []):
            try:
                with open(config_file, "r") as f:
                    content = f.read().lower()

                    # Check for weak SSL protocols
                    weak_protocols = ["sslv2", "sslv3", "tlsv1", "tlsv1.1"]
                    for protocol in weak_protocols:
                        if protocol in content:
                            violations.append(
                                {
                                    "message": f"Weak SSL/TLS protocol {protocol} detected",
                                    "file_path": config_file,
                                    "confidence": 0.8,
                                }
                            )

                    # Check for weak ciphers
                    weak_ciphers = ["rc4", "des", "3des", "md5"]
                    for cipher in weak_ciphers:
                        if cipher in content:
                            violations.append(
                                {
                                    "message": f"Weak cipher {cipher} detected",
                                    "file_path": config_file,
                                    "confidence": 0.8,
                                }
                            )

            except Exception:
                continue

        return violations

    async def _check_injection_vulnerabilities(
        self, target: str, config_files: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """Check for injection vulnerability patterns."""
        violations = []

        # This would typically integrate with SAST tools
        # For now, check configuration patterns that might indicate issues

        for config_file in config_files.get("app_config", []):
            try:
                with open(config_file, "r") as f:
                    content = f.read()

                    # Check for SQL injection patterns in config
                    sql_patterns = [
                        r'SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*["\']?\$',
                        r"INSERT\s+INTO\s+\w+.*VALUES\s*\([^)]*\$[^)]*\)",
                    ]

                    for pattern in sql_patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            violations.append(
                                {
                                    "message": "Potential SQL injection pattern in configuration",
                                    "file_path": config_file,
                                    "confidence": 0.6,
                                    "code_snippet": match.group(0),
                                }
                            )

            except Exception:
                continue

        return violations

    async def _check_security_misconfiguration(
        self, target: str, config_files: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """Check for security misconfigurations."""
        violations = []

        # Check Docker configurations
        for docker_file in config_files.get("docker", []):
            try:
                with open(docker_file, "r") as f:
                    content = f.read().lower()

                    # Check for running as root
                    if "user root" in content or (
                        "user" not in content and "from" in content
                    ):
                        violations.append(
                            {
                                "message": "Container may be running as root user",
                                "file_path": docker_file,
                                "confidence": 0.7,
                            }
                        )

                    # Check for privileged mode
                    if "privileged" in content:
                        violations.append(
                            {
                                "message": "Container running in privileged mode",
                                "file_path": docker_file,
                                "confidence": 0.9,
                            }
                        )

            except Exception:
                continue

        return violations

    async def _check_logging_monitoring(
        self, target: str, config_files: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """Check for logging and monitoring configuration."""
        violations = []

        # Check if logging is configured
        has_logging_config = False

        for config_file in config_files.get("app_config", []):
            try:
                with open(config_file, "r") as f:
                    content = f.read().lower()
                    if any(
                        keyword in content for keyword in ["log", "audit", "monitor"]
                    ):
                        has_logging_config = True
                        break
            except Exception:
                continue

        if not has_logging_config:
            violations.append(
                {
                    "message": "No logging configuration found",
                    "file_path": target,
                    "confidence": 0.6,
                }
            )

        return violations

    async def _check_asset_management(
        self, target: str, config_files: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """Check for asset management practices."""
        violations = []

        # Check if there's any inventory or documentation
        inventory_files = [
            "inventory.yml",
            "assets.json",
            "components.yml",
            "services.yml",
            "infrastructure.md",
        ]

        has_inventory = any(
            os.path.exists(os.path.join(target, inv_file))
            for inv_file in inventory_files
        )

        if not has_inventory:
            violations.append(
                {
                    "message": "No asset inventory documentation found",
                    "file_path": target,
                    "confidence": 0.5,
                }
            )

        return violations

    async def _check_access_control_policy(
        self, target: str, config_files: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """Check for access control policy documentation."""
        violations = []

        policy_files = [
            "access-policy.md",
            "security-policy.yml",
            "rbac.yml",
            "permissions.json",
        ]

        has_policy = any(
            os.path.exists(os.path.join(target, policy_file))
            for policy_file in policy_files
        )

        if not has_policy:
            violations.append(
                {
                    "message": "No access control policy documentation found",
                    "file_path": target,
                    "confidence": 0.5,
                }
            )

        return violations

    async def _check_data_protection_at_rest(
        self, target: str, config_files: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """Check for data protection at rest."""
        violations = []

        # Check database configurations for encryption
        for config_file in config_files.get("app_config", []):
            try:
                with open(config_file, "r") as f:
                    content = f.read().lower()

                    # Check for database encryption settings
                    if "database" in content and "encrypt" not in content:
                        violations.append(
                            {
                                "message": "Database configuration may lack encryption at rest",
                                "file_path": config_file,
                                "confidence": 0.6,
                            }
                        )

            except Exception:
                continue

        return violations

    # Placeholder implementations for remaining check methods
    async def _check_logical_access_controls(
        self, target: str, config_files: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        return []

    async def _check_data_transmission_security(
        self, target: str, config_files: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        return []

    async def _check_privacy_by_design(
        self, target: str, config_files: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        return []

    async def _check_security_of_processing(
        self, target: str, config_files: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        return []

    async def _check_network_security(
        self, target: str, config_files: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        return []

    async def _check_cicd_security(
        self, target: str, config_files: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        return []

    async def _check_security_headers(
        self, target: str, config_files: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        return []

    def _deduplicate_results(self, results: List[ScanResult]) -> List[ScanResult]:
        """Remove duplicate policy violation results."""
        seen = set()
        deduplicated = []

        for result in results:
            key = (result.rule_id, result.file_path, result.line_number)
            if key not in seen:
                seen.add(key)
                deduplicated.append(result)

        return deduplicated


# Register scanner with orchestrator
def register_policy_checker():
    """Register policy checker with the orchestrator."""
    policy_checker = PolicyChecker()
    orchestrator.register_scanner(policy_checker)

    logger.info("Registered policy checker")


# Auto-register scanner when module is imported
register_policy_checker()
