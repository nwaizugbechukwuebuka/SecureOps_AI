"""
Common Scanner Utilities

This module provides shared utilities and base classes for security scanners.
Includes result processing, output parsing, and scanner orchestration.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from utils.config import settings
from utils.logger import get_logger

logger = get_logger(__name__)


class ScannerType(Enum):
    """Types of security scanners."""

    DEPENDENCY = "dependency"
    CONTAINER = "container"
    SECRET = "secret"
    SAST = "sast"
    POLICY = "policy"
    LICENSE = "license"
    INFRASTRUCTURE = "infrastructure"


class SeverityLevel(Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Vulnerability:
    """Represents a vulnerability finding."""

    id: str
    package: str
    version: str
    severity: str
    description: str


@dataclass
class ScanResult:
    """Represents the result of a security scan."""

    success: bool
    vulnerabilities: Optional[List[Vulnerability]] = None
    error: Optional[str] = None


@dataclass
class DetailedScanResult:
    """Represents a single detailed security scan finding."""

    scanner_type: ScannerType
    rule_id: str
    title: str
    description: str
    severity: SeverityLevel
    confidence: float  # 0.0 to 1.0
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    references: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "scanner_type": self.scanner_type.value,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column_number": self.column_number,
            "code_snippet": self.code_snippet,
            "cwe_id": self.cwe_id,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "remediation": self.remediation,
            "references": self.references or [],
            "metadata": self.metadata or {},
        }


@dataclass
class ScanSummary:
    """Summary of a security scan execution."""

    scanner_type: ScannerType
    scanner_name: str
    scanner_version: str
    target: str
    started_at: datetime
    finished_at: datetime
    success: bool
    error_message: Optional[str] = None
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    @property
    def duration(self) -> float:
        """Get scan duration in seconds."""
        return (self.finished_at - self.started_at).total_seconds()

    def add_result(self, result: ScanResult) -> None:
        """Add a scan result to the summary."""
        self.total_findings += 1

        if result.severity == SeverityLevel.CRITICAL:
            self.critical_count += 1
        elif result.severity == SeverityLevel.HIGH:
            self.high_count += 1
        elif result.severity == SeverityLevel.MEDIUM:
            self.medium_count += 1
        elif result.severity == SeverityLevel.LOW:
            self.low_count += 1
        elif result.severity == SeverityLevel.INFO:
            self.info_count += 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan summary to dictionary."""
        return {
            "scanner_type": self.scanner_type.value,
            "scanner_name": self.scanner_name,
            "scanner_version": self.scanner_version,
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration": self.duration,
            "success": self.success,
            "error_message": self.error_message,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
        }


class BaseScanner(ABC):
    """Base class for all security scanners."""

    def __init__(self, name: str, version: str, scanner_type: ScannerType):
        self.name = name
        self.version = version
        self.scanner_type = scanner_type
        self.logger = get_logger(f"scanner.{name}")

    @abstractmethod
    async def scan(self, target: str, **kwargs) -> Tuple[ScanSummary, List[ScanResult]]:
        """
        Perform security scan on target.

        Args:
            target: Target to scan (file, directory, image, etc.)
            **kwargs: Scanner-specific options

        Returns:
            Tuple of scan summary and list of scan results
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if scanner is available and properly configured."""
        pass

    def _create_summary(
        self,
        target: str,
        started_at: datetime,
        success: bool = True,
        error_message: Optional[str] = None,
    ) -> ScanSummary:
        """Create scan summary."""
        return ScanSummary(
            scanner_type=self.scanner_type,
            scanner_name=self.name,
            scanner_version=self.version,
            target=target,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc),
            success=success,
            error_message=error_message,
        )

    async def _run_command(
        self, command: List[str], cwd: Optional[str] = None, timeout: int = 300
    ) -> Tuple[int, str, str]:
        """
        Run command asynchronously.

        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                return_code = process.returncode

                return (
                    return_code,
                    stdout.decode("utf-8", errors="ignore"),
                    stderr.decode("utf-8", errors="ignore"),
                )

            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise TimeoutError(f"Command timeout after {timeout} seconds")

        except Exception as e:
            self.logger.error(f"Failed to run command {' '.join(command)}: {e}")
            raise


class ScannerOrchestrator:
    """Orchestrates multiple security scanners."""

    def __init__(self):
        self.scanners: Dict[str, BaseScanner] = {}
        self.logger = get_logger("scanner.orchestrator")

    def register_scanner(self, scanner: BaseScanner) -> None:
        """Register a scanner."""
        self.scanners[scanner.name] = scanner
        self.logger.info(f"Registered scanner: {scanner.name}")

    def get_scanner(self, name: str) -> Optional[BaseScanner]:
        """Get scanner by name."""
        return self.scanners.get(name)

    def get_available_scanners(self) -> List[BaseScanner]:
        """Get all available scanners."""
        return [scanner for scanner in self.scanners.values() if scanner.is_available()]

    def get_scanners_by_type(self, scanner_type: ScannerType) -> List[BaseScanner]:
        """Get scanners by type."""
        return [
            scanner
            for scanner in self.scanners.values()
            if scanner.scanner_type == scanner_type and scanner.is_available()
        ]

    async def scan_with_scanner(self, scanner_name: str, target: str, **kwargs) -> Tuple[ScanSummary, List[ScanResult]]:
        """Run scan with specific scanner."""
        scanner = self.get_scanner(scanner_name)
        if not scanner:
            raise ValueError(f"Scanner '{scanner_name}' not found")

        if not scanner.is_available():
            raise RuntimeError(f"Scanner '{scanner_name}' is not available")

        return await scanner.scan(target, **kwargs)

    async def scan_with_type(
        self, scanner_type: ScannerType, target: str, **kwargs
    ) -> List[Tuple[ScanSummary, List[ScanResult]]]:
        """Run scan with all scanners of given type."""
        scanners = self.get_scanners_by_type(scanner_type)

        if not scanners:
            self.logger.warning(f"No available scanners for type: {scanner_type.value}")
            return []

        results = []
        for scanner in scanners:
            try:
                result = await scanner.scan(target, **kwargs)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Scanner '{scanner.name}' failed: {e}")
                # Create failed summary
                started_at = datetime.now(timezone.utc)
                failed_summary = ScanSummary(
                    scanner_type=scanner.scanner_type,
                    scanner_name=scanner.name,
                    scanner_version=scanner.version,
                    target=target,
                    started_at=started_at,
                    finished_at=datetime.now(timezone.utc),
                    success=False,
                    error_message=str(e),
                )
                results.append((failed_summary, []))

        return results

    async def comprehensive_scan(
        self, target: str, scanner_types: Optional[List[ScannerType]] = None, **kwargs
    ) -> Dict[str, List[Tuple[ScanSummary, List[ScanResult]]]]:
        """Run comprehensive security scan with multiple scanner types."""
        if scanner_types is None:
            scanner_types = list(ScannerType)

        results = {}

        for scanner_type in scanner_types:
            self.logger.info(f"Running {scanner_type.value} scans on {target}")
            type_results = await self.scan_with_type(scanner_type, target, **kwargs)
            results[scanner_type.value] = type_results

        return results


class ResultProcessor:
    """Processes and filters scan results."""

    @staticmethod
    def filter_by_severity(results: List[ScanResult], min_severity: SeverityLevel) -> List[ScanResult]:
        """Filter results by minimum severity level."""
        severity_order = {
            SeverityLevel.INFO: 0,
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4,
        }

        min_level = severity_order[min_severity]
        return [result for result in results if severity_order[result.severity] >= min_level]

    @staticmethod
    def filter_by_confidence(results: List[ScanResult], min_confidence: float) -> List[ScanResult]:
        """Filter results by minimum confidence level."""
        return [result for result in results if result.confidence >= min_confidence]

    @staticmethod
    def deduplicate_results(results: List[ScanResult]) -> List[ScanResult]:
        """Remove duplicate scan results."""
        seen = set()
        unique_results = []

        for result in results:
            # Create a unique key based on important attributes
            key = (result.rule_id, result.file_path, result.line_number, result.title)

            if key not in seen:
                seen.add(key)
                unique_results.append(result)

        return unique_results

    @staticmethod
    def group_by_file(results: List[ScanResult]) -> Dict[str, List[ScanResult]]:
        """Group results by file path."""
        groups = {}

        for result in results:
            file_path = result.file_path or "unknown"
            if file_path not in groups:
                groups[file_path] = []
            groups[file_path].append(result)

        return groups

    @staticmethod
    def group_by_severity(results: List[ScanResult]) -> Dict[str, List[ScanResult]]:
        """Group results by severity level."""
        groups = {}

        for result in results:
            severity = result.severity.value
            if severity not in groups:
                groups[severity] = []
            groups[severity].append(result)

        return groups

    @staticmethod
    def calculate_risk_score(results: List[ScanResult]) -> float:
        """Calculate overall risk score from results."""
        if not results:
            return 0.0

        severity_weights = {
            SeverityLevel.CRITICAL: 10.0,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5.0,
            SeverityLevel.LOW: 2.5,
            SeverityLevel.INFO: 1.0,
        }

        total_score = 0.0
        for result in results:
            weight = severity_weights.get(result.severity, 1.0)
            confidence_factor = result.confidence
            total_score += weight * confidence_factor

        # Normalize to 0-100 scale
        max_possible_score = len(results) * 10.0
        if max_possible_score > 0:
            return min(100.0, (total_score / max_possible_score) * 100.0)

        return 0.0


class FileTypeDetector:
    """Detects file types for appropriate scanner selection."""

    PYTHON_EXTENSIONS = {".py", ".pyw"}
    JAVASCRIPT_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".vue"}
    JAVA_EXTENSIONS = {".java", ".class", ".jar"}
    C_CPP_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}
    GO_EXTENSIONS = {".go"}
    RUST_EXTENSIONS = {".rs"}
    PHP_EXTENSIONS = {".php", ".phtml"}
    RUBY_EXTENSIONS = {".rb", ".ruby"}
    SHELL_EXTENSIONS = {".sh", ".bash", ".zsh", ".fish"}

    CONFIG_FILES = {
        "dockerfile",
        "containerfile",
        ".dockerignore",
        "docker-compose.yml",
        "docker-compose.yaml",
        "kubernetes.yml",
        "kubernetes.yaml",
        "k8s.yml",
        "k8s.yaml",
        ".gitlab-ci.yml",
        ".github/workflows",
        "azure-pipelines.yml",
        "jenkinsfile",
        "makefile",
        "cmake",
        "build.gradle",
        "pom.xml",
        "package.json",
        "requirements.txt",
        "pipfile",
        "cargo.toml",
        "go.mod",
        "composer.json",
    }

    @classmethod
    def get_file_language(cls, file_path: str) -> Optional[str]:
        """Detect programming language from file path."""
        file_path_lower = file_path.lower()
        extension = Path(file_path).suffix.lower()
        filename = Path(file_path).name.lower()

        if extension in cls.PYTHON_EXTENSIONS:
            return "python"
        elif extension in cls.JAVASCRIPT_EXTENSIONS:
            return "javascript"
        elif extension in cls.JAVA_EXTENSIONS:
            return "java"
        elif extension in cls.C_CPP_EXTENSIONS:
            return "c/cpp"
        elif extension in cls.GO_EXTENSIONS:
            return "go"
        elif extension in cls.RUST_EXTENSIONS:
            return "rust"
        elif extension in cls.PHP_EXTENSIONS:
            return "php"
        elif extension in cls.RUBY_EXTENSIONS:
            return "ruby"
        elif extension in cls.SHELL_EXTENSIONS:
            return "shell"
        elif filename in cls.CONFIG_FILES or any(cf in filename for cf in cls.CONFIG_FILES):
            return "config"

        return None

    @classmethod
    def should_scan_file(cls, file_path: str) -> bool:
        """Check if file should be scanned."""
        # Skip binary files, build artifacts, dependencies
        skip_patterns = [
            ".git/",
            "__pycache__/",
            "node_modules/",
            ".venv/",
            "venv/",
            ".env/",
            "build/",
            "dist/",
            "target/",
            ".class",
            ".jar",
            ".war",
            ".exe",
            ".dll",
            ".so",
            ".pyc",
            ".pyo",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".pdf",
            ".doc",
            ".docx",
            ".zip",
            ".tar",
            ".gz",
        ]

        file_path_lower = file_path.lower()
        return not any(pattern in file_path_lower for pattern in skip_patterns)

    @classmethod
    def get_scannable_files(cls, directory: str) -> List[str]:
        """Get list of files that should be scanned."""
        scannable_files = []

        for root, dirs, files in os.walk(directory):
            # Skip certain directories
            dirs[:] = [
                d
                for d in dirs
                if not d.startswith(".")
                and d
                not in {
                    "__pycache__",
                    "node_modules",
                    "venv",
                    ".venv",
                    "build",
                    "dist",
                    "target",
                }
            ]

            for file in files:
                file_path = os.path.join(root, file)
                if cls.should_scan_file(file_path):
                    scannable_files.append(file_path)

        return scannable_files


class EnhancedScannerOrchestrator(ScannerOrchestrator):
    """Enhanced scanner orchestrator with task system integration and advanced features."""

    def __init__(self):
        super().__init__()
        self.scan_cache = {}
        self.scan_history = []
        self.performance_metrics = {}

    async def register_scanner(self, scanner_type: str, scanner: BaseScanner) -> None:
        """Register scanner with type validation and health checks."""
        if not scanner.is_available():
            logger.warning(f"Scanner {scanner.name} is not available, skipping registration")
            return

        await super().register_scanner(scanner)

        # Perform health check
        try:
            health_status = await scanner.health_check() if hasattr(scanner, "health_check") else {"status": "unknown"}
            logger.info(f"Scanner {scanner.name} health status: {health_status}")
        except Exception as e:
            logger.warning(f"Health check failed for {scanner.name}: {e}")

    async def orchestrate_comprehensive_scan(
        self,
        repository_url: str,
        branch: str = "main",
        scan_types: List[str] = None,
        user_id: int = None,
        scan_config: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Orchestrate a comprehensive security scan with task integration.
        This is the main entry point for scan orchestration.
        """
        scan_id = f"scan_{int(datetime.now(timezone.utc).timestamp())}"
        start_time = datetime.now(timezone.utc)

        logger.info(f"[{scan_id}] Starting comprehensive scan for {repository_url}#{branch}")

        if scan_types is None:
            scan_types = ["dependency", "docker", "secret", "threat", "compliance"]

        scan_context = {
            "scan_id": scan_id,
            "repository_url": repository_url,
            "branch": branch,
            "scan_types": scan_types,
            "user_id": user_id,
            "started_at": start_time,
            "config": scan_config or {},
        }

        try:
            # Clone repository to temporary directory
            temp_dir = await self._prepare_repository(repository_url, branch, scan_id)
            scan_context["temp_dir"] = temp_dir

            # Analyze repository structure
            repo_analysis = await self._analyze_repository(temp_dir)
            scan_context["repository_analysis"] = repo_analysis

            # Execute scans based on repository content
            scan_results = await self._execute_targeted_scans(temp_dir, scan_types, repo_analysis, scan_context)

            # Process and aggregate results
            processed_results = await self._process_scan_results(scan_results, scan_context)

            # Generate comprehensive report
            final_report = await self._generate_comprehensive_report(processed_results, scan_context)

            # Store results in database (if enabled)
            await self._store_scan_results(final_report, scan_context)

            # Trigger alerts if critical issues found
            await self._trigger_alerts_if_needed(final_report, scan_context)

            end_time = datetime.now(timezone.utc)
            execution_time = (end_time - start_time).total_seconds()

            logger.info(f"[{scan_id}] Comprehensive scan completed in {execution_time:.2f}s")

            return {
                "scan_id": scan_id,
                "status": "completed",
                "repository_url": repository_url,
                "branch": branch,
                "execution_time": execution_time,
                "started_at": start_time.isoformat(),
                "finished_at": end_time.isoformat(),
                "results": final_report,
                "summary": {
                    "total_scanners": len(scan_results),
                    "total_findings": sum(len(results[1]) for results in scan_results.values()),
                    "critical_issues": processed_results.get("critical_count", 0),
                    "high_issues": processed_results.get("high_count", 0),
                    "risk_score": processed_results.get("overall_risk_score", 0),
                },
            }

        except Exception as e:
            end_time = datetime.now(timezone.utc)
            execution_time = (end_time - start_time).total_seconds()

            logger.error(f"[{scan_id}] Comprehensive scan failed: {str(e)}")

            return {
                "scan_id": scan_id,
                "status": "failed",
                "repository_url": repository_url,
                "branch": branch,
                "execution_time": execution_time,
                "started_at": start_time.isoformat(),
                "finished_at": end_time.isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
            }

        finally:
            # Clean up temporary directory
            if "temp_dir" in locals():
                await self._cleanup_temp_directory(temp_dir, scan_id)

    async def _prepare_repository(self, repository_url: str, branch: str, scan_id: str) -> str:
        """Prepare repository for scanning by cloning to temporary directory."""
        temp_dir = tempfile.mkdtemp(prefix=f"secureops_scan_{scan_id}_")

        try:
            # Clone repository
            clone_cmd = [
                "git",
                "clone",
                "--depth",
                "1",
                "--branch",
                branch,
                repository_url,
                temp_dir,
            ]

            process = await asyncio.create_subprocess_exec(
                *clone_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                raise RuntimeError(f"Failed to clone repository: {stderr.decode()}")

            logger.info(f"[{scan_id}] Repository cloned to {temp_dir}")
            return temp_dir

        except Exception as e:
            # Clean up on failure
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            raise e

    async def _analyze_repository(self, repo_path: str) -> Dict[str, Any]:
        """Analyze repository structure to determine optimal scanning strategy."""
        analysis = {
            "languages": set(),
            "package_managers": set(),
            "has_dockerfile": False,
            "has_docker_compose": False,
            "has_kubernetes": False,
            "ci_cd_configs": [],
            "security_configs": [],
            "total_files": 0,
            "scannable_files": 0,
        }

        for root, dirs, files in os.walk(repo_path):
            # Skip hidden directories and common non-source directories
            dirs[:] = [
                d
                for d in dirs
                if not d.startswith(".")
                and d
                not in {
                    "__pycache__",
                    "node_modules",
                    "venv",
                    ".venv",
                    "build",
                    "dist",
                    "target",
                }
            ]

            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repo_path)
                filename = file.lower()

                analysis["total_files"] += 1

                # Detect programming languages
                language = FileTypeDetector.get_file_language(file_path)
                if language:
                    analysis["languages"].add(language)

                # Detect package managers
                if filename in ["package.json", "package-lock.json", "yarn.lock"]:
                    analysis["package_managers"].add("npm")
                elif filename in ["requirements.txt", "pipfile", "pyproject.toml"]:
                    analysis["package_managers"].add("pip")
                elif filename in ["pom.xml", "build.gradle", "gradle.properties"]:
                    analysis["package_managers"].add("maven/gradle")
                elif filename in ["composer.json", "composer.lock"]:
                    analysis["package_managers"].add("composer")
                elif filename in ["gemfile", "gemfile.lock"]:
                    analysis["package_managers"].add("bundler")
                elif filename in ["go.mod", "go.sum"]:
                    analysis["package_managers"].add("go")
                elif filename in ["cargo.toml", "cargo.lock"]:
                    analysis["package_managers"].add("cargo")

                # Detect containerization
                if filename in ["dockerfile", "containerfile"]:
                    analysis["has_dockerfile"] = True
                elif filename in ["docker-compose.yml", "docker-compose.yaml"]:
                    analysis["has_docker_compose"] = True

                # Detect Kubernetes
                if any(k in filename for k in ["kubernetes", "k8s"]) and filename.endswith((".yml", ".yaml")):
                    analysis["has_kubernetes"] = True

                # Detect CI/CD configurations
                if ".github/workflows" in relative_path and filename.endswith((".yml", ".yaml")):
                    analysis["ci_cd_configs"].append(f"GitHub Actions: {relative_path}")
                elif filename == ".gitlab-ci.yml":
                    analysis["ci_cd_configs"].append("GitLab CI")
                elif filename in ["azure-pipelines.yml", "azure-pipelines.yaml"]:
                    analysis["ci_cd_configs"].append("Azure Pipelines")
                elif filename.lower() == "jenkinsfile":
                    analysis["ci_cd_configs"].append("Jenkins")

                # Detect security configurations
                if filename in [
                    ".securityignore",
                    ".bandit",
                    "sonar-project.properties",
                ]:
                    analysis["security_configs"].append(filename)

                # Count scannable files
                if FileTypeDetector.should_scan_file(file_path):
                    analysis["scannable_files"] += 1

        # Convert sets to lists for JSON serialization
        analysis["languages"] = list(analysis["languages"])
        analysis["package_managers"] = list(analysis["package_managers"])

        return analysis

    async def _execute_targeted_scans(
        self,
        repo_path: str,
        requested_scan_types: List[str],
        repo_analysis: Dict[str, Any],
        scan_context: Dict[str, Any],
    ) -> Dict[str, Tuple[ScanSummary, List[ScanResult]]]:
        """Execute scans tailored to the repository content."""
        scan_results = {}
        scan_id = scan_context["scan_id"]

        # Map scan type names to ScannerType enums
        scanner_type_mapping = {
            "dependency": ScannerType.DEPENDENCY,
            "docker": ScannerType.CONTAINER,
            "secret": ScannerType.SECRET,
            "threat": ScannerType.SAST,
            "compliance": ScannerType.POLICY,
        }

        # Execute scans based on repository analysis
        for scan_type_name in requested_scan_types:
            scanner_type = scanner_type_mapping.get(scan_type_name)
            if not scanner_type:
                logger.warning(f"[{scan_id}] Unknown scan type: {scan_type_name}")
                continue

            # Check if scan type is applicable to this repository
            if not self._is_scan_applicable(scanner_type, repo_analysis):
                logger.info(f"[{scan_id}] Skipping {scan_type_name} scan - not applicable to repository")
                continue

            try:
                logger.info(f"[{scan_id}] Starting {scan_type_name} scan")

                # Get scanners for this type
                scanners = self.get_scanners_by_type(scanner_type)

                if not scanners:
                    logger.warning(f"[{scan_id}] No available scanners for {scan_type_name}")
                    continue

                # Execute scans with the available scanners
                for scanner in scanners:
                    try:
                        summary, results = await scanner.scan(repo_path)
                        scan_results[f"{scan_type_name}_{scanner.name}"] = (
                            summary,
                            results,
                        )

                        logger.info(f"[{scan_id}] {scanner.name} scan completed - {len(results)} findings")

                    except Exception as e:
                        logger.error(f"[{scan_id}] {scanner.name} scan failed: {str(e)}")

                        # Create failed summary
                        failed_summary = ScanSummary(
                            scanner_type=scanner.scanner_type,
                            scanner_name=scanner.name,
                            scanner_version=getattr(scanner, "version", "unknown"),
                            target=repo_path,
                            started_at=datetime.now(timezone.utc),
                            finished_at=datetime.now(timezone.utc),
                            success=False,
                            error_message=str(e),
                        )
                        scan_results[f"{scan_type_name}_{scanner.name}"] = (
                            failed_summary,
                            [],
                        )

            except Exception as e:
                logger.error(f"[{scan_id}] {scan_type_name} scan execution failed: {str(e)}")

        return scan_results

    def _is_scan_applicable(self, scanner_type: ScannerType, repo_analysis: Dict[str, Any]) -> bool:
        """Determine if a scan type is applicable based on repository analysis."""
        if scanner_type == ScannerType.DEPENDENCY:
            return bool(repo_analysis.get("package_managers"))
        elif scanner_type == ScannerType.CONTAINER:
            return repo_analysis.get("has_dockerfile") or repo_analysis.get("has_docker_compose")
        elif scanner_type == ScannerType.SECRET:
            return repo_analysis.get("scannable_files", 0) > 0
        elif scanner_type == ScannerType.SAST:
            return bool(repo_analysis.get("languages"))
        elif scanner_type == ScannerType.POLICY:
            return True  # Policy scans are always applicable

        return True  # Default to applicable

    async def _process_scan_results(
        self,
        scan_results: Dict[str, Tuple[ScanSummary, List[ScanResult]]],
        scan_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Process and aggregate scan results."""
        all_results = []
        scanner_summaries = []

        for scanner_key, (summary, results) in scan_results.items():
            all_results.extend(results)
            scanner_summaries.append(summary)

        # Deduplicate results
        deduplicated_results = ResultProcessor.deduplicate_results(all_results)

        # Calculate aggregated metrics
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for result in deduplicated_results:
            severity_counts[result.severity.value] += 1

        # Calculate risk score
        overall_risk_score = ResultProcessor.calculate_risk_score(deduplicated_results)

        # Group results by various criteria
        results_by_file = ResultProcessor.group_by_file(deduplicated_results)
        results_by_severity = ResultProcessor.group_by_severity(deduplicated_results)

        return {
            "total_findings": len(deduplicated_results),
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
            "medium_count": severity_counts["medium"],
            "low_count": severity_counts["low"],
            "info_count": severity_counts["info"],
            "overall_risk_score": overall_risk_score,
            "results_by_file": results_by_file,
            "results_by_severity": results_by_severity,
            "scanner_summaries": scanner_summaries,
            "all_results": deduplicated_results,
        }

    async def _generate_comprehensive_report(
        self, processed_results: Dict[str, Any], scan_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate comprehensive security scan report."""
        return {
            "scan_metadata": {
                "scan_id": scan_context["scan_id"],
                "repository_url": scan_context["repository_url"],
                "branch": scan_context["branch"],
                "scan_types": scan_context["scan_types"],
                "started_at": scan_context["started_at"].isoformat(),
                "repository_analysis": scan_context["repository_analysis"],
            },
            "executive_summary": {
                "total_findings": processed_results["total_findings"],
                "critical_issues": processed_results["critical_count"],
                "high_issues": processed_results["high_count"],
                "overall_risk_score": processed_results["overall_risk_score"],
                "risk_level": self._determine_risk_level(processed_results["overall_risk_score"]),
                "recommendation": self._generate_recommendation(processed_results),
            },
            "detailed_findings": {
                "by_severity": processed_results["results_by_severity"],
                "by_file": processed_results["results_by_file"],
                "scanner_summaries": [summary.to_dict() for summary in processed_results["scanner_summaries"]],
            },
            "remediation_guidance": self._generate_remediation_guidance(processed_results),
            "compliance_status": self._assess_compliance_status(processed_results),
        }

    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on score."""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 20:
            return "LOW"
        else:
            return "MINIMAL"

    def _generate_recommendation(self, processed_results: Dict[str, Any]) -> str:
        """Generate high-level recommendations based on results."""
        critical_count = processed_results["critical_count"]
        high_count = processed_results["high_count"]

        if critical_count > 0:
            return "IMMEDIATE ACTION REQUIRED: Critical security issues found that require immediate attention."
        elif high_count > 0:
            return "ACTION RECOMMENDED: High severity issues found that should be addressed promptly."
        elif processed_results["total_findings"] > 0:
            return "REVIEW RECOMMENDED: Security findings identified that should be reviewed and addressed."
        else:
            return "NO ISSUES FOUND: No security issues identified in this scan."

    def _generate_remediation_guidance(self, processed_results: Dict[str, Any]) -> Dict[str, List[str]]:
        """Generate remediation guidance for different issue types."""
        guidance = {
            "immediate_actions": [],
            "medium_term_actions": [],
            "long_term_actions": [],
        }

        if processed_results["critical_count"] > 0:
            guidance["immediate_actions"].extend(
                [
                    "Address all critical security vulnerabilities immediately",
                    "Review and update dependency versions",
                    "Implement emergency security patches",
                ]
            )

        if processed_results["high_count"] > 0:
            guidance["medium_term_actions"].extend(
                [
                    "Create remediation plan for high severity issues",
                    "Implement additional security controls",
                    "Enhance code review processes",
                ]
            )

        if processed_results["total_findings"] > 0:
            guidance["long_term_actions"].extend(
                [
                    "Integrate security scanning into CI/CD pipeline",
                    "Implement security training for development team",
                    "Establish regular security review cycles",
                ]
            )

        return guidance

    def _assess_compliance_status(self, processed_results: Dict[str, Any]) -> Dict[str, str]:
        """Assess compliance status based on scan results."""
        compliance_status = {}

        # Basic compliance assessment
        if processed_results["critical_count"] == 0 and processed_results["high_count"] == 0:
            compliance_status["overall"] = "COMPLIANT"
        elif processed_results["critical_count"] == 0:
            compliance_status["overall"] = "PARTIALLY_COMPLIANT"
        else:
            compliance_status["overall"] = "NON_COMPLIANT"

        return compliance_status

    async def _store_scan_results(self, report: Dict[str, Any], scan_context: Dict[str, Any]) -> None:
        """Store scan results in database."""
        try:
            # This would integrate with the database layer
            # For now, we'll just log that we would store the results
            logger.info(f"[{scan_context['scan_id']}] Storing scan results in database")

        except Exception as e:
            logger.error(f"Failed to store scan results: {str(e)}")

    async def _trigger_alerts_if_needed(self, report: Dict[str, Any], scan_context: Dict[str, Any]) -> None:
        """Trigger alerts for critical findings."""
        try:
            executive_summary = report.get("executive_summary", {})
            critical_issues = executive_summary.get("critical_issues", 0)
            high_issues = executive_summary.get("high_issues", 0)

            if critical_issues > 0 or high_issues > 5:  # Alert threshold
                # This would integrate with the alert system
                logger.warning(
                    f"[{scan_context['scan_id']}] Triggering security alerts for {critical_issues} critical and {high_issues} high severity issues"
                )

        except Exception as e:
            logger.error(f"Failed to trigger alerts: {str(e)}")

    async def _cleanup_temp_directory(self, temp_dir: str, scan_id: str) -> None:
        """Clean up temporary directory."""
        try:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                logger.info(f"[{scan_id}] Cleaned up temporary directory: {temp_dir}")
        except Exception as e:
            logger.warning(f"[{scan_id}] Failed to cleanup temp directory {temp_dir}: {str(e)}")

    async def get_health_status(self) -> Dict[str, Any]:
        """Get health status of all registered scanners."""
        health_status = {
            "scanner_count": len(self.scanners),
            "available_scanners": 0,
            "unavailable_scanners": 0,
            "scanner_details": {},
        }

        for name, scanner in self.scanners.items():
            try:
                is_available = scanner.is_available()
                scanner_health = {
                    "available": is_available,
                    "version": getattr(scanner, "version", "unknown"),
                    "type": scanner.scanner_type.value,
                }

                if hasattr(scanner, "health_check"):
                    detailed_health = await scanner.health_check()
                    scanner_health.update(detailed_health)

                health_status["scanner_details"][name] = scanner_health

                if is_available:
                    health_status["available_scanners"] += 1
                else:
                    health_status["unavailable_scanners"] += 1

            except Exception as e:
                health_status["scanner_details"][name] = {
                    "available": False,
                    "error": str(e),
                }
                health_status["unavailable_scanners"] += 1

        return health_status


# Global enhanced orchestrator instance
enhanced_orchestrator = EnhancedScannerOrchestrator()

# Legacy compatibility
orchestrator = enhanced_orchestrator
