"""
Validation Utilities Module

This module provides comprehensive validation functions for the SecureOps platform.
Includes validation for user input, configuration, file formats, and security constraints.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

import email_validator
import yaml

from .config import settings
from .logger import get_logger

logger = get_logger(__name__)


class ValidationError(Exception):
    """Custom validation error exception."""

    def __init__(
        self, message: str, field: Optional[str] = None, code: Optional[str] = None
    ):
        self.message = message
        self.field = field
        self.code = code
        super().__init__(message)


class ValidationResult:
    """Represents the result of a validation operation."""

    def __init__(
        self,
        is_valid: bool = True,
        errors: List[str] = None,
        warnings: List[str] = None,
    ):
        self.is_valid = is_valid
        self.errors = errors or []
        self.warnings = warnings or []

    def add_error(self, error: str):
        """Add an error to the result."""
        self.errors.append(error)
        self.is_valid = False

    def add_warning(self, warning: str):
        """Add a warning to the result."""
        self.warnings.append(warning)

    def merge(self, other: "ValidationResult"):
        """Merge another validation result into this one."""
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        if not other.is_valid:
            self.is_valid = False


# Basic data type validators


def validate_email(email: str) -> ValidationResult:
    """
    Validate email address format.

    Args:
        email: Email address to validate

    Returns:
        ValidationResult indicating if email is valid
    """
    result = ValidationResult()

    try:
        if not email or not isinstance(email, str):
            result.add_error("Email address is required")
            return result

        # Use email-validator library for comprehensive validation
        validated_email = email_validator.validate_email(email)

        # Additional checks
        if len(email) > 254:  # RFC 5321 limit
            result.add_error("Email address is too long")

        # Check for suspicious patterns
        suspicious_patterns = [
            r"\.{2,}",  # Multiple consecutive dots
            r"^\.|\.$",  # Starting or ending with dot
            r'[<>"]',  # Angle brackets or quotes
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, email):
                result.add_warning("Email address contains suspicious characters")
                break

    except email_validator.EmailNotValidError as e:
        result.add_error(f"Invalid email address: {str(e)}")
    except Exception as e:
        result.add_error(f"Email validation error: {str(e)}")

    return result


def validate_url(url: str, allowed_schemes: List[str] = None) -> ValidationResult:
    """
    Validate URL format and scheme.

    Args:
        url: URL to validate
        allowed_schemes: List of allowed URL schemes (default: ['http', 'https'])

    Returns:
        ValidationResult indicating if URL is valid
    """
    result = ValidationResult()

    if allowed_schemes is None:
        allowed_schemes = ["http", "https"]

    try:
        if not url or not isinstance(url, str):
            result.add_error("URL is required")
            return result

        parsed = urlparse(url)

        # Check scheme
        if not parsed.scheme:
            result.add_error("URL must include a scheme (http/https)")
        elif parsed.scheme.lower() not in allowed_schemes:
            result.add_error(f"URL scheme must be one of: {', '.join(allowed_schemes)}")

        # Check hostname
        if not parsed.netloc:
            result.add_error("URL must include a hostname")

        # Check for suspicious patterns
        if any(char in url for char in ["<", ">", '"', "'"]):
            result.add_warning("URL contains potentially dangerous characters")

        # Length check
        if len(url) > 2048:
            result.add_error("URL is too long")

    except Exception as e:
        result.add_error(f"URL validation error: {str(e)}")

    return result


def validate_ip_address(ip: str) -> ValidationResult:
    """
    Validate IP address (IPv4 or IPv6).

    Args:
        ip: IP address to validate

    Returns:
        ValidationResult indicating if IP address is valid
    """
    result = ValidationResult()

    try:
        if not ip or not isinstance(ip, str):
            result.add_error("IP address is required")
            return result

        # Try to parse as IP address
        ip_obj = ipaddress.ip_address(ip.strip())

        # Check for private/reserved addresses in certain contexts
        if ip_obj.is_private:
            result.add_warning("IP address is in private range")

        if ip_obj.is_reserved:
            result.add_warning("IP address is in reserved range")

        if ip_obj.is_loopback:
            result.add_warning("IP address is a loopback address")

    except ValueError as e:
        result.add_error(f"Invalid IP address: {str(e)}")
    except Exception as e:
        result.add_error(f"IP address validation error: {str(e)}")

    return result


def validate_password(password: str) -> ValidationResult:
    """
    Validate password strength based on security requirements.

    Args:
        password: Password to validate

    Returns:
        ValidationResult indicating password strength
    """
    result = ValidationResult()

    if not password or not isinstance(password, str):
        result.add_error("Password is required")
        return result

    min_length = settings.security.password_min_length

    # Length check
    if len(password) < min_length:
        result.add_error(f"Password must be at least {min_length} characters long")

    # Character requirements
    checks = [
        (r"[a-z]", "Password must contain at least one lowercase letter"),
        (r"[A-Z]", "Password must contain at least one uppercase letter"),
        (r"[0-9]", "Password must contain at least one digit"),
        (
            r'[!@#$%^&*(),.?":{}|<>]',
            "Password must contain at least one special character",
        ),
    ]

    for pattern, message in checks:
        if not re.search(pattern, password):
            result.add_error(message)

    # Common password patterns
    common_patterns = [
        (r"(.)\1{3,}", "Password contains too many repeated characters"),
        (
            r"(012|123|234|345|456|567|678|789|890)",
            "Password contains sequential numbers",
        ),
        (
            r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)",
            "Password contains sequential letters",
        ),
    ]

    for pattern, message in common_patterns:
        if re.search(pattern, password.lower()):
            result.add_warning(message)

    # Check against common passwords (simplified check)
    common_passwords = ["password", "123456", "admin", "root", "user", "test"]
    if password.lower() in common_passwords:
        result.add_error("Password is too common")

    return result


# Input sanitization validators


def validate_alphanumeric(value: str, field_name: str = "field") -> ValidationResult:
    """
    Validate that value contains only alphanumeric characters.

    Args:
        value: Value to validate
        field_name: Name of the field for error messages

    Returns:
        ValidationResult indicating if value is valid
    """
    result = ValidationResult()

    if not isinstance(value, str):
        result.add_error(f"{field_name} must be a string")
        return result

    if not value.isalnum():
        result.add_error(f"{field_name} must contain only letters and numbers")

    return result


def validate_filename(filename: str) -> ValidationResult:
    """
    Validate filename for security and filesystem compatibility.

    Args:
        filename: Filename to validate

    Returns:
        ValidationResult indicating if filename is safe
    """
    result = ValidationResult()

    if not filename or not isinstance(filename, str):
        result.add_error("Filename is required")
        return result

    # Check for path traversal attempts
    if ".." in filename or "/" in filename or "\\" in filename:
        result.add_error("Filename contains invalid path characters")

    # Check for reserved names (Windows)
    reserved_names = (
        ["CON", "PRN", "AUX", "NUL"]
        + [f"COM{i}" for i in range(1, 10)]
        + [f"LPT{i}" for i in range(1, 10)]
    )
    if filename.upper() in reserved_names:
        result.add_error("Filename is a reserved name")

    # Check for invalid characters
    invalid_chars = '<>:"|?*'
    if any(char in filename for char in invalid_chars):
        result.add_error("Filename contains invalid characters")

    # Length check
    if len(filename) > 255:
        result.add_error("Filename is too long")

    # Check for hidden files (optional warning)
    if filename.startswith("."):
        result.add_warning("Filename starts with dot (hidden file)")

    return result


def validate_json(json_string: str) -> ValidationResult:
    """
    Validate JSON format.

    Args:
        json_string: JSON string to validate

    Returns:
        ValidationResult indicating if JSON is valid
    """
    result = ValidationResult()

    try:
        if not json_string or not isinstance(json_string, str):
            result.add_error("JSON string is required")
            return result

        # Parse JSON
        json.loads(json_string)

        # Size check
        if len(json_string) > 1024 * 1024:  # 1MB limit
            result.add_warning("JSON string is very large")

    except json.JSONDecodeError as e:
        result.add_error(f"Invalid JSON format: {str(e)}")
    except Exception as e:
        result.add_error(f"JSON validation error: {str(e)}")

    return result


def validate_yaml(yaml_string: str) -> ValidationResult:
    """
    Validate YAML format.

    Args:
        yaml_string: YAML string to validate

    Returns:
        ValidationResult indicating if YAML is valid
    """
    result = ValidationResult()

    try:
        if not yaml_string or not isinstance(yaml_string, str):
            result.add_error("YAML string is required")
            return result

        # Parse YAML
        yaml.safe_load(yaml_string)

        # Size check
        if len(yaml_string) > 1024 * 1024:  # 1MB limit
            result.add_warning("YAML string is very large")

    except yaml.YAMLError as e:
        result.add_error(f"Invalid YAML format: {str(e)}")
    except Exception as e:
        result.add_error(f"YAML validation error: {str(e)}")

    return result


# Security-specific validators


def validate_sql_injection(value: str) -> ValidationResult:
    """
    Check for potential SQL injection patterns.

    Args:
        value: Value to check

    Returns:
        ValidationResult with warnings for suspicious patterns
    """
    result = ValidationResult()

    if not isinstance(value, str):
        return result

    # SQL injection patterns
    sql_patterns = [
        r"('|(\\'))+.*(;|--|#)",  # SQL comment patterns
        r"(union|select|insert|update|delete|drop|create|alter)\s+",  # SQL keywords
        r"(exec|execute|xp_|sp_)\s*\(",  # Stored procedure calls
        r"(script|javascript|vbscript|onload|onerror)",  # Script injection
    ]

    for pattern in sql_patterns:
        if re.search(pattern, value.lower()):
            result.add_warning("Input contains potentially dangerous SQL patterns")
            break

    return result


def validate_xss_injection(value: str) -> ValidationResult:
    """
    Check for potential XSS injection patterns.

    Args:
        value: Value to check

    Returns:
        ValidationResult with warnings for suspicious patterns
    """
    result = ValidationResult()

    if not isinstance(value, str):
        return result

    # XSS patterns
    xss_patterns = [
        r"<script[^>]*>.*?</script>",  # Script tags
        r"javascript:",  # JavaScript protocol
        r"on\w+\s*=",  # Event handlers
        r"<iframe[^>]*>",  # Iframe tags
        r"<object[^>]*>",  # Object tags
        r"<embed[^>]*>",  # Embed tags
    ]

    for pattern in xss_patterns:
        if re.search(pattern, value.lower()):
            result.add_warning("Input contains potentially dangerous script patterns")
            break

    return result


def validate_command_injection(value: str) -> ValidationResult:
    """
    Check for potential command injection patterns.

    Args:
        value: Value to check

    Returns:
        ValidationResult with warnings for suspicious patterns
    """
    result = ValidationResult()

    if not isinstance(value, str):
        return result

    # Command injection patterns
    command_patterns = [
        r"[;&|`$(){}[\]\\]",  # Shell metacharacters
        r"(rm|del|format|fdisk)\s+",  # Dangerous commands
        r"(wget|curl|nc|telnet)\s+",  # Network commands
        r"(cat|type|more|less)\s+/",  # File reading commands
    ]

    for pattern in command_patterns:
        if re.search(pattern, value.lower()):
            result.add_warning("Input contains potentially dangerous command patterns")
            break

    return result


# File validation


def validate_file_type(
    file_path: str, allowed_extensions: List[str]
) -> ValidationResult:
    """
    Validate file type based on extension.

    Args:
        file_path: Path to the file
        allowed_extensions: List of allowed file extensions (with or without dots)

    Returns:
        ValidationResult indicating if file type is allowed
    """
    result = ValidationResult()

    if not file_path or not isinstance(file_path, str):
        result.add_error("File path is required")
        return result

    # Normalize extensions (ensure they start with dot)
    normalized_extensions = []
    for ext in allowed_extensions:
        if not ext.startswith("."):
            ext = "." + ext
        normalized_extensions.append(ext.lower())

    # Get file extension
    file_ext = Path(file_path).suffix.lower()

    if file_ext not in normalized_extensions:
        result.add_error(
            f"File type '{file_ext}' not allowed. Allowed types: {', '.join(normalized_extensions)}"
        )

    return result


def validate_file_size(file_path: str, max_size_mb: int = 10) -> ValidationResult:
    """
    Validate file size.

    Args:
        file_path: Path to the file
        max_size_mb: Maximum allowed file size in MB

    Returns:
        ValidationResult indicating if file size is acceptable
    """
    result = ValidationResult()

    try:
        if not os.path.exists(file_path):
            result.add_error("File does not exist")
            return result

        file_size = os.path.getsize(file_path)
        max_size_bytes = max_size_mb * 1024 * 1024

        if file_size > max_size_bytes:
            result.add_error(
                f"File size ({file_size / 1024 / 1024:.2f} MB) exceeds limit ({max_size_mb} MB)"
            )

        # Warning for large files
        if file_size > max_size_bytes * 0.8:
            result.add_warning(f"File is large ({file_size / 1024 / 1024:.2f} MB)")

    except Exception as e:
        result.add_error(f"Error checking file size: {str(e)}")

    return result


# Configuration validators


def validate_pipeline_config(config: Dict[str, Any]) -> ValidationResult:
    """
    Validate pipeline configuration.

    Args:
        config: Pipeline configuration dictionary

    Returns:
        ValidationResult indicating if configuration is valid
    """
    result = ValidationResult()

    if not isinstance(config, dict):
        result.add_error("Configuration must be a dictionary")
        return result

    # Required fields
    required_fields = ["name", "repository_url"]
    for field in required_fields:
        if field not in config:
            result.add_error(f"Missing required field: {field}")

    # Validate repository URL if present
    if "repository_url" in config:
        url_result = validate_url(
            config["repository_url"], ["http", "https", "git", "ssh"]
        )
        result.merge(url_result)

    # Validate scanner configuration
    if "scanners" in config:
        if not isinstance(config["scanners"], list):
            result.add_error("Scanners configuration must be a list")
        else:
            valid_scanners = ["dependency", "secret", "container", "policy"]
            for scanner in config["scanners"]:
                if scanner not in valid_scanners:
                    result.add_error(f"Invalid scanner type: {scanner}")

    # Validate notification configuration
    if "notifications" in config:
        notification_result = validate_notification_config(config["notifications"])
        result.merge(notification_result)

    return result


def validate_notification_config(config: Dict[str, Any]) -> ValidationResult:
    """
    Validate notification configuration.

    Args:
        config: Notification configuration dictionary

    Returns:
        ValidationResult indicating if configuration is valid
    """
    result = ValidationResult()

    if not isinstance(config, dict):
        result.add_error("Notification configuration must be a dictionary")
        return result

    # Validate email configuration
    if "email" in config:
        email_config = config["email"]
        if "recipients" in email_config:
            if not isinstance(email_config["recipients"], list):
                result.add_error("Email recipients must be a list")
            else:
                for email in email_config["recipients"]:
                    email_result = validate_email(email)
                    if not email_result.is_valid:
                        result.add_error(f"Invalid email recipient: {email}")

    # Validate webhook configuration
    if "webhooks" in config:
        webhook_config = config["webhooks"]
        if not isinstance(webhook_config, list):
            result.add_error("Webhook configuration must be a list")
        else:
            for webhook in webhook_config:
                if "url" not in webhook:
                    result.add_error("Webhook missing URL")
                else:
                    url_result = validate_url(webhook["url"])
                    result.merge(url_result)

    return result


# Comprehensive validator function


def validate_input(value: Any, validation_type: str, **kwargs) -> ValidationResult:
    """
    Comprehensive input validation function.

    Args:
        value: Value to validate
        validation_type: Type of validation to perform
        **kwargs: Additional validation parameters

    Returns:
        ValidationResult indicating validation outcome
    """
    validators = {
        "email": lambda v: validate_email(v),
        "url": lambda v: validate_url(v, kwargs.get("allowed_schemes")),
        "ip": lambda v: validate_ip_address(v),
        "password": lambda v: validate_password(v),
        "alphanumeric": lambda v: validate_alphanumeric(
            v, kwargs.get("field_name", "field")
        ),
        "filename": lambda v: validate_filename(v),
        "json": lambda v: validate_json(v),
        "yaml": lambda v: validate_yaml(v),
    }

    validator = validators.get(validation_type)
    if not validator:
        result = ValidationResult()
        result.add_error(f"Unknown validation type: {validation_type}")
        return result

    try:
        result = validator(value)

        # Add security checks for string inputs
        if isinstance(value, str) and validation_type not in ["password"]:
            sql_result = validate_sql_injection(value)
            xss_result = validate_xss_injection(value)
            cmd_result = validate_command_injection(value)

            result.merge(sql_result)
            result.merge(xss_result)
            result.merge(cmd_result)

        return result

    except Exception as e:
        result = ValidationResult()
        result.add_error(f"Validation error: {str(e)}")
        return result


# Batch validation functions


def validate_multiple(
    validations: List[Tuple[Any, str, Dict[str, Any]]],
) -> ValidationResult:
    """
    Perform multiple validations and combine results.

    Args:
        validations: List of tuples (value, validation_type, kwargs)

    Returns:
        Combined ValidationResult
    """
    combined_result = ValidationResult()

    for value, validation_type, kwargs in validations:
        result = validate_input(value, validation_type, **kwargs)
        combined_result.merge(result)

    return combined_result
