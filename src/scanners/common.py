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

from ..utils.config import settings
from ..utils.logger import get_logger

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
class ScanResult:
    """Represents a single security scan finding."""

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
    meta_data: Optional[Dict[str, Any]] = None

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
            "meta_data": self.meta_data or {},
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
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
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

    async def scan_with_scanner(
        self, scanner_name: str, target: str, **kwargs
    ) -> Tuple[ScanSummary, List[ScanResult]]:
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
    def filter_by_severity(
        results: List[ScanResult], min_severity: SeverityLevel
    ) -> List[ScanResult]:
        """Filter results by minimum severity level."""
        severity_order = {
            SeverityLevel.INFO: 0,
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4,
        }

        min_level = severity_order[min_severity]
        return [
            result for result in results if severity_order[result.severity] >= min_level
        ]

    @staticmethod
    def filter_by_confidence(
        results: List[ScanResult], min_confidence: float
    ) -> List[ScanResult]:
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
        elif filename in cls.CONFIG_FILES or any(
            cf in filename for cf in cls.CONFIG_FILES
        ):
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


# Global orchestrator instance
orchestrator = ScannerOrchestrator()
