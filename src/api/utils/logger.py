"""Simplified logging configuration for SecureOps."""

import logging
import sys
from typing import Optional

from .config import get_settings

settings = get_settings()


def configure_logging():
    """Configure basic logging for the application."""
    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )


def get_logger(name: str) -> logging.Logger:
    """Get a configured logger instance."""
    return logging.getLogger(name)


class AuditLogger:
    """Simple audit logger for tracking security events."""

    def __init__(self):
        self.logger = get_logger("audit")

    def info(self, *args, **kwargs):
        self.logger.info(*args, **kwargs)

    def warning(self, *args, **kwargs):
        self.logger.warning(*args, **kwargs)

    def login_attempt(
        self,
        username: str,
        success: bool,
        ip_address: Optional[str] = None,
        failure_reason: Optional[str] = None,
    ):
        """Log a login attempt."""
        result = "SUCCESS" if success else "FAILED"
        message = (
            f"Login attempt for {username}: {result} from {ip_address or 'unknown IP'}"
        )
        if not success and failure_reason:
            message += f" - Reason: {failure_reason}"
        self.logger.info(f"login_attempt: {message}")


def setup_correlation_id_middleware(app):
    """Placeholder for correlation ID middleware."""
    pass


def setup_request_logging_middleware(app):
    """Placeholder for request logging middleware."""
    pass


def setup_security_logging_middleware(app):
    """Placeholder for security logging middleware."""
    pass


# Configure logging when module is imported
configure_logging()
