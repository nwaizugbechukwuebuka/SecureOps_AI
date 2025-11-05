"""
Validation utilities for SecureOps API.
"""

import ipaddress
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from pydantic import Field, validator
<<<<<<< HEAD
=======
from pydantic.validators import str_validator
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3


class ValidationError(ValueError):
    """Custom validation error with detailed information."""

    def __init__(self, message: str, field: Optional[str] = None, value: Any = None):
        self.message = message
        self.field = field
        self.value = value
        super().__init__(message)


def validate_email(email: str) -> str:
    """
    Validate email address format.

    Args:
        email: Email address to validate

    Returns:
        str: Validated email address

    Raises:
        ValidationError: If email format is invalid
    """
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    if not email or not isinstance(email, str):
        raise ValidationError("Email is required", "email", email)

    email = email.strip().lower()

    if not re.match(email_pattern, email):
        raise ValidationError("Invalid email format", "email", email)

    if len(email) > 255:
        raise ValidationError("Email too long (max 255 characters)", "email", email)

    return email


def validate_username(username: str) -> str:
    """
    Validate username format and constraints.

    Args:
        username: Username to validate

    Returns:
        str: Validated username

    Raises:
        ValidationError: If username is invalid
    """
    if not username or not isinstance(username, str):
        raise ValidationError("Username is required", "username", username)

    username = username.strip().lower()

    # Length constraints
    if len(username) < 3:
        raise ValidationError(
            "Username must be at least 3 characters", "username", username
        )

    if len(username) > 50:
        raise ValidationError(
            "Username must be at most 50 characters", "username", username
        )

    # Character constraints
    if not re.match(r"^[a-z0-9_-]+$", username):
        raise ValidationError(
            "Username can only contain lowercase letters, numbers, underscores, and hyphens",
            "username",
            username,
        )

    # Must start with letter or number
    if not re.match(r"^[a-z0-9]", username):
        raise ValidationError(
            "Username must start with a letter or number", "username", username
        )

    # Reserved usernames
    reserved = {
        "admin",
        "root",
        "system",
        "api",
        "www",
        "mail",
        "ftp",
        "security",
        "test",
        "demo",
    }
    if username in reserved:
        raise ValidationError(
            f"Username '{username}' is reserved", "username", username
        )

    return username


def validate_password(password: str) -> str:
    """
    Validate password strength and format.

    Args:
        password: Password to validate

    Returns:
        str: Validated password

    Raises:
        ValidationError: If password doesn't meet requirements
    """
    if not password or not isinstance(password, str):
        raise ValidationError("Password is required", "password")

    # Length requirements
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long", "password")

    if len(password) > 128:
        raise ValidationError(
            "Password must be at most 128 characters long", "password"
        )

    # Complexity requirements
    checks = [
        (r"[A-Z]", "Password must contain at least one uppercase letter"),
        (r"[a-z]", "Password must contain at least one lowercase letter"),
        (r"[0-9]", "Password must contain at least one digit"),
        (
            r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]",
            "Password must contain at least one special character",
        ),
    ]

    for pattern, message in checks:
        if not re.search(pattern, password):
            raise ValidationError(message, "password")

    # Common password patterns to avoid
    common_patterns = [
        r"123456",
        r"password",
        r"qwerty",
        r"admin",
        r"letmein",
        r"welcome",
    ]

    password_lower = password.lower()
    for pattern in common_patterns:
        if pattern in password_lower:
            raise ValidationError("Password contains common patterns", "password")

    return password


def validate_url(url: str, schemes: Optional[List[str]] = None) -> str:
    """
    Validate URL format and scheme.

    Args:
        url: URL to validate
        schemes: Allowed URL schemes (defaults to ['http', 'https'])

    Returns:
        str: Validated URL

    Raises:
        ValidationError: If URL is invalid
    """
    if not url or not isinstance(url, str):
        raise ValidationError("URL is required", "url", url)

    url = url.strip()

    if schemes is None:
        schemes = ["http", "https"]

    # Basic URL pattern
    url_pattern = r"^https?://[^\s/$.?#].[^\s]*$"

    if not re.match(url_pattern, url, re.IGNORECASE):
        raise ValidationError("Invalid URL format", "url", url)

    # Check scheme
    scheme = url.split("://", 1)[0].lower()
    if scheme not in schemes:
        raise ValidationError(f"URL scheme must be one of {schemes}", "url", url)

    # Length check
    if len(url) > 2048:
        raise ValidationError("URL too long (max 2048 characters)", "url", url)

    return url


def validate_ip_address(ip: str) -> str:
    """
    Validate IP address (IPv4 or IPv6).

    Args:
        ip: IP address to validate

    Returns:
        str: Validated IP address

    Raises:
        ValidationError: If IP address is invalid
    """
    if not ip or not isinstance(ip, str):
        raise ValidationError("IP address is required", "ip", ip)

    ip = ip.strip()

    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise ValidationError("Invalid IP address format", "ip", ip)


def validate_severity(severity: str) -> str:
    """
    Validate security severity level.

    Args:
        severity: Severity level to validate

    Returns:
        str: Validated severity level

    Raises:
        ValidationError: If severity is invalid
    """
    if not severity or not isinstance(severity, str):
        raise ValidationError("Severity is required", "severity", severity)

    severity = severity.lower().strip()
    valid_severities = ["critical", "high", "medium", "low", "info"]

    if severity not in valid_severities:
        raise ValidationError(
            f"Severity must be one of {valid_severities}", "severity", severity
        )

    return severity


def validate_cve_id(cve_id: str) -> str:
    """
    Validate CVE ID format.

    Args:
        cve_id: CVE ID to validate

    Returns:
        str: Validated CVE ID

    Raises:
        ValidationError: If CVE ID is invalid
    """
    if not cve_id or not isinstance(cve_id, str):
        raise ValidationError("CVE ID is required", "cve_id", cve_id)

    cve_id = cve_id.strip().upper()

    # CVE format: CVE-YYYY-NNNN (where YYYY is year and NNNN is sequence number)
    cve_pattern = r"^CVE-\d{4}-\d{4,}$"

    if not re.match(cve_pattern, cve_id):
        raise ValidationError(
            "Invalid CVE ID format (expected CVE-YYYY-NNNN)", "cve_id", cve_id
        )

    return cve_id


def validate_cwe_id(cwe_id: str) -> str:
    """
    Validate CWE ID format.

    Args:
        cwe_id: CWE ID to validate

    Returns:
        str: Validated CWE ID

    Raises:
        ValidationError: If CWE ID is invalid
    """
    if not cwe_id or not isinstance(cwe_id, str):
        raise ValidationError("CWE ID is required", "cwe_id", cwe_id)

    cwe_id = cwe_id.strip().upper()

    # Add CWE- prefix if not present
    if not cwe_id.startswith("CWE-"):
        if cwe_id.isdigit():
            cwe_id = f"CWE-{cwe_id}"
        else:
            raise ValidationError("Invalid CWE ID format", "cwe_id", cwe_id)

    # CWE format: CWE-NNN
    cwe_pattern = r"^CWE-\d{1,5}$"

    if not re.match(cwe_pattern, cwe_id):
        raise ValidationError(
            "Invalid CWE ID format (expected CWE-NNN)", "cwe_id", cwe_id
        )

    return cwe_id


def validate_cvss_score(score: float) -> float:
    """
    Validate CVSS score range.

    Args:
        score: CVSS score to validate

    Returns:
        float: Validated CVSS score

    Raises:
        ValidationError: If CVSS score is invalid
    """
    if score is None:
        raise ValidationError("CVSS score is required", "cvss_score", score)

    if not isinstance(score, (int, float)):
        raise ValidationError("CVSS score must be a number", "cvss_score", score)

    if not (0.0 <= score <= 10.0):
        raise ValidationError(
            "CVSS score must be between 0.0 and 10.0", "cvss_score", score
        )

    return float(score)


def validate_cvss_vector(vector: str) -> str:
    """
    Validate CVSS vector string format.

    Args:
        vector: CVSS vector to validate

    Returns:
        str: Validated CVSS vector

    Raises:
        ValidationError: If CVSS vector is invalid
    """
    if not vector or not isinstance(vector, str):
        raise ValidationError("CVSS vector is required", "cvss_vector", vector)

    vector = vector.strip()

    # Basic CVSS vector format check (simplified)
    # Full validation would be quite complex
    if not vector.startswith("CVSS:"):
        raise ValidationError(
            "CVSS vector must start with 'CVSS:'", "cvss_vector", vector
        )

    # Check for basic components
    required_components = ["AV:", "AC:", "Au:", "C:", "I:", "A:"]  # CVSS v2 example
    if "3.1" in vector or "3.0" in vector:
        required_components = [
            "AV:",
            "AC:",
            "PR:",
            "UI:",
            "S:",
            "C:",
            "I:",
            "A:",
        ]  # CVSS v3

    for component in required_components:
        if component not in vector:
            raise ValidationError(
                f"CVSS vector missing component: {component}", "cvss_vector", vector
            )

    return vector


def validate_file_path(file_path: str, max_length: int = 1000) -> str:
    """
    Validate file path format and constraints.

    Args:
        file_path: File path to validate
        max_length: Maximum allowed path length

    Returns:
        str: Validated file path

    Raises:
        ValidationError: If file path is invalid
    """
    if not file_path or not isinstance(file_path, str):
        raise ValidationError("File path is required", "file_path", file_path)

    file_path = file_path.strip()

    # Length check
    if len(file_path) > max_length:
        raise ValidationError(
            f"File path too long (max {max_length} characters)", "file_path", file_path
        )

    # Security checks - prevent path traversal
    dangerous_patterns = ["../", "..\\", "/../", "\\..\\"]
    for pattern in dangerous_patterns:
        if pattern in file_path:
            raise ValidationError(
                "File path contains dangerous patterns", "file_path", file_path
            )

    # Forbidden characters (basic check)
    forbidden_chars = ["<", ">", "|", "*", "?", '"']
    for char in forbidden_chars:
        if char in file_path:
            raise ValidationError(
                f"File path contains forbidden character: {char}",
                "file_path",
                file_path,
            )

    return file_path


def validate_package_name(package_name: str) -> str:
    """
    Validate package name format.

    Args:
        package_name: Package name to validate

    Returns:
        str: Validated package name

    Raises:
        ValidationError: If package name is invalid
    """
    if not package_name or not isinstance(package_name, str):
        raise ValidationError("Package name is required", "package_name", package_name)

    package_name = package_name.strip()

    # Length check
    if len(package_name) > 255:
        raise ValidationError(
            "Package name too long (max 255 characters)", "package_name", package_name
        )

    # Basic package name pattern (letters, numbers, hyphens, underscores, dots)
    if not re.match(r"^[a-zA-Z0-9._-]+$", package_name):
        raise ValidationError(
            "Package name can only contain letters, numbers, dots, hyphens, and underscores",
            "package_name",
            package_name,
        )

    return package_name


def validate_version_string(version: str) -> str:
    """
    Validate version string format (semantic versioning).

    Args:
        version: Version string to validate

    Returns:
        str: Validated version string

    Raises:
        ValidationError: If version is invalid
    """
    if not version or not isinstance(version, str):
        raise ValidationError("Version is required", "version", version)

    version = version.strip()

    # Basic semantic versioning pattern
    semver_pattern = r"^v?\d+\.\d+\.\d+(?:-[a-zA-Z0-9-]+)?(?:\+[a-zA-Z0-9-]+)?$"

    # Also allow simpler versions like "1.0", "2", etc.
    simple_pattern = r"^v?\d+(?:\.\d+)*(?:-[a-zA-Z0-9-]+)?$"

    if not (re.match(semver_pattern, version) or re.match(simple_pattern, version)):
        raise ValidationError("Invalid version format", "version", version)

    if len(version) > 50:
        raise ValidationError(
            "Version string too long (max 50 characters)", "version", version
        )

    return version


def validate_json_data(data: Any, max_size: int = 1024 * 1024) -> Dict[str, Any]:
    """
    Validate JSON data constraints.

    Args:
        data: JSON data to validate
        max_size: Maximum JSON string size in bytes

    Returns:
        Dict[str, Any]: Validated JSON data

    Raises:
        ValidationError: If JSON data is invalid
    """
    if data is None:
        return {}

    if not isinstance(data, dict):
        raise ValidationError("JSON data must be an object", "json_data", data)

    # Check serialized size
    try:
        import json

        json_str = json.dumps(data)
        if len(json_str.encode("utf-8")) > max_size:
            raise ValidationError(
                f"JSON data too large (max {max_size} bytes)", "json_data"
            )
    except (TypeError, ValueError) as e:
        raise ValidationError(f"Invalid JSON data: {e}", "json_data", data)

    # Check nesting depth (prevent deeply nested objects)
    def check_depth(obj, current_depth=0, max_depth=10):
        if current_depth > max_depth:
            raise ValidationError(
                f"JSON data too deeply nested (max {max_depth} levels)", "json_data"
            )

        if isinstance(obj, dict):
            for value in obj.values():
                check_depth(value, current_depth + 1, max_depth)
        elif isinstance(obj, list):
            for item in obj:
                check_depth(item, current_depth + 1, max_depth)

    check_depth(data)

    return data


def validate_tag_list(tags: List[str], max_tags: int = 50) -> List[str]:
    """
    Validate list of tags.

    Args:
        tags: List of tags to validate
        max_tags: Maximum number of tags allowed

    Returns:
        List[str]: Validated list of tags

    Raises:
        ValidationError: If tags are invalid
    """
    if not tags:
        return []

    if not isinstance(tags, list):
        raise ValidationError("Tags must be a list", "tags", tags)

    if len(tags) > max_tags:
        raise ValidationError(f"Too many tags (max {max_tags})", "tags", tags)

    validated_tags = []
    for i, tag in enumerate(tags):
        if not isinstance(tag, str):
            raise ValidationError(f"Tag at index {i} must be a string", "tags", tag)

        tag = tag.strip().lower()

        if not tag:
            continue  # Skip empty tags

        if len(tag) > 50:
            raise ValidationError(
                f"Tag too long (max 50 characters): {tag}", "tags", tag
            )

        if not re.match(r"^[a-z0-9_-]+$", tag):
            raise ValidationError(
                f"Tag contains invalid characters: {tag}", "tags", tag
            )

        if tag not in validated_tags:  # Remove duplicates
            validated_tags.append(tag)

    return validated_tags


def validate_datetime_range(
    start_date: Optional[datetime],
    end_date: Optional[datetime],
    max_range_days: int = 365,
) -> tuple[Optional[datetime], Optional[datetime]]:
    """
    Validate datetime range constraints.

    Args:
        start_date: Start datetime
        end_date: End datetime
        max_range_days: Maximum allowed range in days

    Returns:
        tuple: Validated (start_date, end_date)

    Raises:
        ValidationError: If datetime range is invalid
    """
    if start_date and end_date:
        if start_date >= end_date:
            raise ValidationError("Start date must be before end date", "date_range")

        range_days = (end_date - start_date).days
        if range_days > max_range_days:
            raise ValidationError(
                f"Date range too large (max {max_range_days} days)", "date_range"
            )

    return start_date, end_date


class SecureOpsValidator:
    """Centralized validator for SecureOps-specific validation logic."""

    @staticmethod
    def validate_pipeline_name(name: str) -> str:
        """Validate pipeline name format."""
        if not name or not isinstance(name, str):
            raise ValidationError("Pipeline name is required", "name", name)

        name = name.strip()

        if len(name) < 1:
            raise ValidationError("Pipeline name cannot be empty", "name", name)

        if len(name) > 255:
            raise ValidationError(
                "Pipeline name too long (max 255 characters)", "name", name
            )

        return name

    @staticmethod
    def validate_scanner_name(scanner: str) -> str:
        """Validate security scanner name."""
        if not scanner or not isinstance(scanner, str):
            raise ValidationError("Scanner name is required", "scanner", scanner)

        scanner = scanner.strip().lower()

        valid_scanners = [
            "bandit",
            "safety",
            "semgrep",
            "trivy",
            "docker-bench",
            "clair",
            "grype",
            "snyk",
            "whitesource",
            "sonarqube",
        ]

        if scanner not in valid_scanners:
            raise ValidationError(
                f"Scanner must be one of {valid_scanners}", "scanner", scanner
            )

        return scanner

    @staticmethod
    def validate_platform_type(platform: str) -> str:
        """Validate CI/CD platform type."""
        if not platform or not isinstance(platform, str):
            raise ValidationError("Platform is required", "platform", platform)

        platform = platform.strip().lower()

        valid_platforms = ["github", "gitlab", "jenkins", "azure"]

        if platform not in valid_platforms:
            raise ValidationError(
                f"Platform must be one of {valid_platforms}", "platform", platform
            )

        return platform
