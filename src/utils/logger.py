"""
Logging Utilities Module

This module provides centralized logging configuration and utilities
for the SecureOps platform. Supports structured logging, different formats,
and multiple output destinations.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import functools
import json
import logging
import logging.handlers
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union

from .config import settings


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            "timestamp": datetime.fromtimestamp(
                record.created, timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add extra fields if present
        if hasattr(record, "user_id"):
            log_entry["user_id"] = record.user_id

        if hasattr(record, "request_id"):
            log_entry["request_id"] = record.request_id

        if hasattr(record, "pipeline_id"):
            log_entry["pipeline_id"] = record.pipeline_id

        if hasattr(record, "scan_job_id"):
            log_entry["scan_job_id"] = record.scan_job_id

        # Add exception information if present
        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info),
            }

        # Add extra context if available
        if hasattr(record, "extra_data"):
            log_entry["extra"] = record.extra_data

        return json.dumps(log_entry, ensure_ascii=False)


class ContextFilter(logging.Filter):
    """Filter to add context information to log records."""

    def __init__(self):
        super().__init__()
        self.context = {}

    def filter(self, record: logging.LogRecord) -> bool:
        """Add context information to the log record."""
        # Add context fields to the record
        for key, value in self.context.items():
            setattr(record, key, value)

        return True

    def set_context(self, **kwargs):
        """Set context information."""
        self.context.update(kwargs)

    def clear_context(self):
        """Clear all context information."""
        self.context.clear()

    def remove_context(self, key: str):
        """Remove specific context key."""
        self.context.pop(key, None)


class SecurityAwareFormatter(logging.Formatter):
    """Formatter that sanitizes sensitive information from logs."""

    SENSITIVE_PATTERNS = [
        "password",
        "token",
        "key",
        "secret",
        "credential",
        "authorization",
        "auth",
        "jwt",
        "api_key",
    ]

    def format(self, record: logging.LogRecord) -> str:
        """Format record while sanitizing sensitive information."""
        # Create a copy of the record to avoid modifying the original
        record_copy = logging.makeLogRecord(record.__dict__)

        # Sanitize the message
        record_copy.msg = self._sanitize_message(str(record_copy.msg))

        # Sanitize arguments
        if record_copy.args:
            record_copy.args = tuple(
                self._sanitize_value(arg) for arg in record_copy.args
            )

        return super().format(record_copy)

    def _sanitize_message(self, message: str) -> str:
        """Sanitize sensitive information from log message."""
        import re

        # Pattern to match key=value or "key": "value" patterns
        for pattern in self.SENSITIVE_PATTERNS:
            # Match key=value
            message = re.sub(
                f"{pattern}=\\S+",
                f"{pattern}=***REDACTED***",
                message,
                flags=re.IGNORECASE,
            )

            # Match "key": "value"
            message = re.sub(
                f'"{pattern}":\\s*"[^"]*"',
                f'"{pattern}": "***REDACTED***"',
                message,
                flags=re.IGNORECASE,
            )

            # Match 'key': 'value'
            message = re.sub(
                f"'{pattern}':\s*'[^']*'",
                f"'{pattern}': '***REDACTED***'",
                message,
                flags=re.IGNORECASE,
            )

        return message

    def _sanitize_value(self, value: Any) -> Any:
        """Sanitize individual values."""
        if isinstance(value, str):
            return self._sanitize_message(value)
        elif isinstance(value, dict):
            return {
                k: (
                    "***REDACTED***"
                    if any(pattern in k.lower() for pattern in self.SENSITIVE_PATTERNS)
                    else v
                )
                for k, v in value.items()
            }
        return value


class LoggerManager:
    """Manages logger configuration and provides logging utilities."""

    def __init__(self):
        self._loggers = {}
        self._context_filter = ContextFilter()
        self._configured = False

    def configure_logging(self):
        """Configure logging based on settings."""
        if self._configured:
            return

        # Get root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, settings.logging.level.upper()))

        # Remove existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        # Configure console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, settings.logging.level.upper()))

        if settings.logging.enable_json_logging:
            console_formatter = JSONFormatter()
        else:
            console_formatter = SecurityAwareFormatter(
                fmt=settings.logging.format, datefmt="%Y-%m-%d %H:%M:%S"
            )

        console_handler.setFormatter(console_formatter)
        console_handler.addFilter(self._context_filter)
        root_logger.addHandler(console_handler)

        # Configure file handler if specified
        if settings.logging.file_path:
            self._configure_file_handler(root_logger)

        # Set specific logger levels
        self._configure_specific_loggers()

        self._configured = True

    def _configure_file_handler(self, root_logger: logging.Logger):
        """Configure file handler with rotation."""
        try:
            # Ensure log directory exists
            log_file_path = Path(settings.logging.file_path)
            log_file_path.parent.mkdir(parents=True, exist_ok=True)

            # Create rotating file handler
            file_handler = logging.handlers.RotatingFileHandler(
                filename=settings.logging.file_path,
                maxBytes=settings.logging.max_bytes,
                backupCount=settings.logging.backup_count,
                encoding="utf-8",
            )

            file_handler.setLevel(getattr(logging, settings.logging.level.upper()))

            if settings.logging.enable_json_logging:
                file_formatter = JSONFormatter()
            else:
                file_formatter = SecurityAwareFormatter(
                    fmt=settings.logging.format, datefmt="%Y-%m-%d %H:%M:%S"
                )

            file_handler.setFormatter(file_formatter)
            file_handler.addFilter(self._context_filter)
            root_logger.addHandler(file_handler)

        except Exception as e:
            # Fall back to console logging if file logging fails
            print(f"Warning: Could not configure file logging: {e}")

    def _configure_specific_loggers(self):
        """Configure specific loggers with appropriate levels."""
        # Set levels for third-party libraries
        logging.getLogger("uvicorn").setLevel(logging.WARNING)
        logging.getLogger("fastapi").setLevel(logging.INFO)
        logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
        logging.getLogger("celery").setLevel(logging.INFO)
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)

        # Configure application loggers
        logging.getLogger("secureops").setLevel(
            getattr(logging, settings.logging.level.upper())
        )
        logging.getLogger("secureops.scanners").setLevel(logging.INFO)
        logging.getLogger("secureops.tasks").setLevel(logging.INFO)
        logging.getLogger("secureops.api").setLevel(logging.INFO)

    def get_logger(self, name: str) -> logging.Logger:
        """Get a logger instance with proper configuration."""
        if not self._configured:
            self.configure_logging()

        if name not in self._loggers:
            logger = logging.getLogger(name)
            self._loggers[name] = logger

        return self._loggers[name]

    def set_context(self, **kwargs):
        """Set context information for all loggers."""
        self._context_filter.set_context(**kwargs)

    def clear_context(self):
        """Clear all context information."""
        self._context_filter.clear_context()

    def remove_context(self, key: str):
        """Remove specific context key."""
        self._context_filter.remove_context(key)


# Global logger manager instance
_logger_manager = LoggerManager()


def get_logger(name: str = None) -> logging.Logger:
    """
    Get a logger instance.

    Args:
        name: Logger name. If None, uses the calling module's name.

    Returns:
        Configured logger instance
    """
    if name is None:
        # Get the calling module's name
        frame = sys._getframe(1)
        name = frame.f_globals.get("__name__", "secureops")

    return _logger_manager.get_logger(name)


def configure_logging():
    """Configure logging system."""
    _logger_manager.configure_logging()


def set_log_context(**kwargs):
    """
    Set context information that will be included in all log messages.

    Args:
        **kwargs: Context key-value pairs
    """
    _logger_manager.set_context(**kwargs)


def clear_log_context():
    """Clear all context information."""
    _logger_manager.clear_context()


def remove_log_context(key: str):
    """
    Remove specific context key.

    Args:
        key: Context key to remove
    """
    _logger_manager.remove_context(key)


def log_function_call(func):
    """
    Decorator to log function calls with parameters and results.

    Args:
        func: Function to decorate

    Returns:
        Decorated function
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)

        # Log function entry
        logger.debug(
            f"Calling function {func.__name__}",
            extra={
                "extra_data": {
                    "function": func.__name__,
                    "args_count": len(args),
                    "kwargs_keys": list(kwargs.keys()),
                }
            },
        )

        try:
            # Call the function
            result = func(*args, **kwargs)

            # Log successful completion
            logger.debug(
                f"Function {func.__name__} completed successfully",
                extra={
                    "extra_data": {
                        "function": func.__name__,
                        "result_type": type(result).__name__,
                    }
                },
            )

            return result

        except Exception as e:
            # Log exception
            logger.error(
                f"Function {func.__name__} failed with exception: {str(e)}",
                exc_info=True,
                extra={
                    "extra_data": {
                        "function": func.__name__,
                        "exception_type": type(e).__name__,
                    }
                },
            )
            raise

    return wrapper


def log_async_function_call(func):
    """
    Decorator to log async function calls with parameters and results.

    Args:
        func: Async function to decorate

    Returns:
        Decorated async function
    """

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)

        # Log function entry
        logger.debug(
            f"Calling async function {func.__name__}",
            extra={
                "extra_data": {
                    "function": func.__name__,
                    "args_count": len(args),
                    "kwargs_keys": list(kwargs.keys()),
                }
            },
        )

        try:
            # Call the async function
            result = await func(*args, **kwargs)

            # Log successful completion
            logger.debug(
                f"Async function {func.__name__} completed successfully",
                extra={
                    "extra_data": {
                        "function": func.__name__,
                        "result_type": type(result).__name__,
                    }
                },
            )

            return result

        except Exception as e:
            # Log exception
            logger.error(
                f"Async function {func.__name__} failed with exception: {str(e)}",
                exc_info=True,
                extra={
                    "extra_data": {
                        "function": func.__name__,
                        "exception_type": type(e).__name__,
                    }
                },
            )
            raise

    return wrapper


class LogContext:
    """Context manager for temporary log context."""

    def __init__(self, **kwargs):
        """
        Initialize log context.

        Args:
            **kwargs: Context key-value pairs
        """
        self.context = kwargs
        self.previous_context = {}

    def __enter__(self):
        """Enter the context and set log context."""
        # Save current context
        self.previous_context = _logger_manager._context_filter.context.copy()

        # Set new context
        _logger_manager.set_context(**self.context)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the context and restore previous log context."""
        # Restore previous context
        _logger_manager._context_filter.context = self.previous_context


# Utility functions for common logging patterns


def log_api_request(method: str, path: str, user_id: Optional[str] = None, **kwargs):
    """
    Log API request with standard format.

    Args:
        method: HTTP method
        path: Request path
        user_id: Optional user ID
        **kwargs: Additional context
    """
    logger = get_logger("secureops.api")

    context = {"method": method, "path": path, "user_id": user_id, **kwargs}

    logger.info(f"{method} {path}", extra={"extra_data": context})


def log_scan_event(
    event: str, pipeline_id: int, scan_job_id: Optional[int] = None, **kwargs
):
    """
    Log scan-related event with standard format.

    Args:
        event: Event description
        pipeline_id: Pipeline ID
        scan_job_id: Optional scan job ID
        **kwargs: Additional context
    """
    logger = get_logger("secureops.scanners")

    context = {
        "event": event,
        "pipeline_id": pipeline_id,
        "scan_job_id": scan_job_id,
        **kwargs,
    }

    logger.info(
        event,
        extra={
            "extra_data": context,
            "pipeline_id": pipeline_id,
            "scan_job_id": scan_job_id,
        },
    )


def log_security_event(event: str, severity: str = "info", **kwargs):
    """
    Log security-related event with high visibility.

    Args:
        event: Security event description
        severity: Event severity (info, warning, error, critical)
        **kwargs: Additional context
    """
    logger = get_logger("secureops.security")

    context = {"event_type": "security", "severity": severity, **kwargs}

    log_method = getattr(logger, severity.lower(), logger.info)
    log_method(f"SECURITY EVENT: {event}", extra={"extra_data": context})


def log_performance_metric(
    metric_name: str, value: Union[int, float], unit: str = None, **kwargs
):
    """
    Log performance metric.

    Args:
        metric_name: Name of the metric
        value: Metric value
        unit: Optional unit of measurement
        **kwargs: Additional context
    """
    logger = get_logger("secureops.performance")

    context = {"metric_name": metric_name, "value": value, "unit": unit, **kwargs}

    logger.info(
        f"METRIC: {metric_name}={value}{f' {unit}' if unit else ''}",
        extra={"extra_data": context},
    )


# Initialize logging on module import
configure_logging()
