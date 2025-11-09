import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict
import json

# Configure logging


def setup_logging(
    log_level: str = "INFO", log_file: str = None, max_bytes: int = 10485760, backup_count: int = 5  # 10MB
) -> logging.Logger:
    """
    Set up centralized logging for the application
    """
    logger = logging.getLogger("secureops_ai")
    logger.setLevel(getattr(logging, log_level.upper()))

    # Clear any existing handlers
    logger.handlers.clear()

    # Create formatter
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler (if log file specified)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        from logging.handlers import RotatingFileHandler

        file_handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


# Get the default logger
logger = setup_logging()


class SecurityLogger:
    """Specialized logger for security events"""

    def __init__(self, name: str = "secureops_security"):
        self.logger = logging.getLogger(name)
        self._setup_security_logging()

    def _setup_security_logging(self):
        """Setup security-specific logging configuration"""
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter("%(asctime)s - SECURITY - %(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def log_auth_attempt(self, username: str, success: bool, ip_address: str = None):
        """Log authentication attempts"""
        status = "SUCCESS" if success else "FAILED"
        message = f"Authentication {status} - User: {username}"
        if ip_address:
            message += f" - IP: {ip_address}"

        if success:
            self.logger.info(message)
        else:
            self.logger.warning(message)

    def log_access_attempt(self, user: str, resource: str, action: str, success: bool):
        """Log access control events"""
        status = "ALLOWED" if success else "DENIED"
        message = f"Access {status} - User: {user} - Resource: {resource} - Action: {action}"

        if success:
            self.logger.info(message)
        else:
            self.logger.warning(message)

    def log_security_event(self, event_type: str, severity: str, description: str, details: Dict[str, Any] = None):
        """Log security events"""
        message = f"Security Event - Type: {event_type} - Severity: {severity} - {description}"

        if details:
            message += f" - Details: {json.dumps(details)}"

        if severity.lower() in ["critical", "high"]:
            self.logger.error(message)
        elif severity.lower() == "medium":
            self.logger.warning(message)
        else:
            self.logger.info(message)

    def log_data_access(self, user: str, table: str, action: str, record_count: int = None):
        """Log database access events"""
        message = f"Data Access - User: {user} - Table: {table} - Action: {action}"
        if record_count is not None:
            message += f" - Records: {record_count}"

        self.logger.info(message)

    def log_admin_action(self, admin_user: str, action: str, target: str = None):
        """Log administrative actions"""
        message = f"Admin Action - User: {admin_user} - Action: {action}"
        if target:
            message += f" - Target: {target}"

        self.logger.warning(message)


class AuditLogger:
    """Audit trail logger for compliance"""

    def __init__(self, name: str = "secureops_audit"):
        self.logger = logging.getLogger(name)
        self._setup_audit_logging()

    def _setup_audit_logging(self):
        """Setup audit-specific logging configuration"""
        if not self.logger.handlers:
            # Audit logs should always go to file for compliance
            from logging.handlers import RotatingFileHandler

            handler = RotatingFileHandler("logs/audit.log", maxBytes=50 * 1024 * 1024, backupCount=10)  # 50MB

            formatter = logging.Formatter("%(asctime)s - AUDIT - %(message)s", datefmt="%Y-%m-%d %H:%M:%S UTC")
            handler.setFormatter(formatter)

            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

            # Ensure logs directory exists
            Path("logs").mkdir(exist_ok=True)

    def log_user_action(self, user_id: int, username: str, action: str, details: Dict[str, Any] = None):
        """Log user actions for audit trail"""
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "username": username,
            "action": action,
            "details": details or {},
        }

        self.logger.info(json.dumps(audit_entry))

    def log_system_event(self, event_type: str, component: str, details: Dict[str, Any] = None):
        """Log system events for audit trail"""
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "component": component,
            "details": details or {},
        }

        self.logger.info(json.dumps(audit_entry))

    def log_configuration_change(self, user: str, component: str, old_value: Any, new_value: Any):
        """Log configuration changes"""
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user": user,
            "action": "configuration_change",
            "component": component,
            "old_value": str(old_value),
            "new_value": str(new_value),
        }

        self.logger.info(json.dumps(audit_entry))


# Create default loggers
security_logger = SecurityLogger()
audit_logger = AuditLogger()

# Utility functions


def log_request(method: str, path: str, user: str = None, status_code: int = None):
    """Log HTTP requests"""
    message = f"Request - {method} {path}"
    if user:
        message += f" - User: {user}"
    if status_code:
        message += f" - Status: {status_code}"

    if status_code and status_code >= 400:
        logger.warning(message)
    else:
        logger.info(message)


def log_performance(operation: str, duration: float, details: Dict[str, Any] = None):
    """Log performance metrics"""
    message = f"Performance - Operation: {operation} - Duration: {duration:.3f}s"
    if details:
        message += f" - Details: {json.dumps(details)}"

    logger.info(message)


def log_error(error: Exception, context: Dict[str, Any] = None):
    """Log errors with context"""
    message = f"Error - {type(error).__name__}: {str(error)}"
    if context:
        message += f" - Context: {json.dumps(context, default=str)}"

    logger.error(message, exc_info=True)
