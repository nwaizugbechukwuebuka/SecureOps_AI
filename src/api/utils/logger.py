"""
Logging configuration and utilities for SecureOps.
"""

import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import structlog

from .config import get_settings

# Get settings
settings = get_settings()


def configure_logging():
    """Configure structured logging with structlog and standard library."""

    # Create logs directory if it doesn't exist
    if settings.log_file:
        log_path = Path(settings.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

<<<<<<< HEAD

    # Prepare base handlers
    handlers = [logging.StreamHandler(sys.stdout)]
    if settings.log_file:
        handlers.append(logging.FileHandler(settings.log_file))

    # --- SIEM/External Log Forwarding Handlers ---
    # ELK/Elasticsearch
    if getattr(settings, "log_forward_elk_enabled", False):
        try:
            # Import ELK logging handler only when needed
            import elasticsearch_logging
            from elasticsearch import Elasticsearch
            
            # Create Elasticsearch client and handler
            es_client = Elasticsearch([{'host': settings.log_forward_elk_host or 'localhost', 'port': settings.log_forward_elk_port or 9200}])
            
            class ElasticsearchHandler(logging.Handler):
                def __init__(self, es_client):
                    super().__init__()
                    self.es_client = es_client
                    
                def emit(self, record):
                    try:
                        log_entry = {
                            'timestamp': record.created,
                            'level': record.levelname,
                            'message': self.format(record),
                            'logger': record.name,
                            'module': record.module,
                            'function': record.funcName,
                            'line': record.lineno
                        }
                        self.es_client.index(index="secureops-logs", body=log_entry)
                    except Exception:
                        pass
            
            elk_handler = ElasticsearchHandler(es_client)
            handlers.append(elk_handler)
            logging.getLogger().info("ELK/Elasticsearch log forwarding enabled.")
        except ImportError:
            logging.getLogger().warning("ELK log forwarding requested but elasticsearch-logging package not installed. Install with: pip install elasticsearch-logging")
        except Exception as e:
            logging.getLogger().error(f"Failed to enable ELK log forwarding: {e}")

    # Datadog
    if getattr(settings, "log_forward_datadog_enabled", False):
        try:
            # Import datadog only when needed
            from datadog_api_client.v1 import ApiClient, Configuration
            from datadog_api_client.v1.api.logs_api import LogsApi
            
            # Initialize Datadog API client
            configuration = Configuration()
            configuration.api_key['apiKeyAuth'] = settings.log_forward_datadog_api_key
            
            # Create a custom handler that sends logs to Datadog via HTTP
            class DatadogHandler(logging.Handler):
                def __init__(self, api_client):
                    super().__init__()
                    self.logs_api = LogsApi(api_client)
                    
                def emit(self, record):
                    try:
                        log_entry = {
                            'ddsource': 'secureops',
                            'ddtags': f'level:{record.levelname.lower()},source:secureops',
                            'message': self.format(record),
                            'level': record.levelname,
                            'timestamp': record.created * 1000  # Convert to milliseconds
                        }
                        # Send log to Datadog Logs API (this would need proper implementation)
                        pass  # Placeholder for actual Datadog logs submission
                    except Exception:
                        # Silently fail to avoid log loops
                        pass
            
            with ApiClient(configuration) as api_client:
                dd_handler = DatadogHandler(api_client)
                handlers.append(dd_handler)
            logging.getLogger().info("Datadog log forwarding enabled.")
        except ImportError:
            logging.getLogger().warning("Datadog log forwarding requested but datadog package not installed. Install with: pip install datadog")
        except Exception as e:
            logging.getLogger().error(f"Failed to enable Datadog log forwarding: {e}")

    # Syslog
    if getattr(settings, "log_forward_syslog_enabled", False):
        try:
            from logging.handlers import SysLogHandler
            syslog_address = (settings.log_forward_syslog_host or 'localhost', settings.log_forward_syslog_port or 514)
            syslog_handler = SysLogHandler(address=syslog_address)
            handlers.append(syslog_handler)
            logging.getLogger().info("Syslog log forwarding enabled.")
        except Exception as e:
            logging.getLogger().error(f"Failed to enable syslog log forwarding: {e}")

=======
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    # Configure standard library logging
    logging.basicConfig(
        level=getattr(logging, settings.log_level),
        format="%(message)s",
<<<<<<< HEAD
        handlers=handlers,
=======
        handlers=[
            logging.StreamHandler(sys.stdout),
            *([logging.FileHandler(settings.log_file)] if settings.log_file else []),
        ],
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    )

    # Configure structlog processors
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
<<<<<<< HEAD
=======
        structlog.processors.add_logger_name,
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    # Add appropriate renderer based on format preference
    if settings.log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))

    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.log_level)
        ),
        logger_factory=structlog.WriteLoggerFactory(),
        context_class=dict,
        cache_logger_on_first_use=True,
    )


def get_logger(name: Optional[str] = None) -> structlog.BoundLogger:
    """
    Get a configured logger instance.

    Args:
        name: Logger name (defaults to caller's module)

    Returns:
        structlog.BoundLogger: Configured logger instance
    """
    if name is None:
        # Get caller's module name
        frame = sys._getframe(1)
        name = frame.f_globals.get("__name__", "secureops")

    return structlog.get_logger(name)


class SecurityLogger:
    """Specialized logger for security events and audit trails."""

    def __init__(self):
        self.logger = get_logger("security")

    def vulnerability_detected(
        self,
        vulnerability_id: str,
        severity: str,
        pipeline_id: Optional[int] = None,
        scanner: Optional[str] = None,
        **kwargs
    ):
        """Log vulnerability detection event."""
        self.logger.warning(
            "vulnerability_detected",
            vulnerability_id=vulnerability_id,
            severity=severity,
            pipeline_id=pipeline_id,
            scanner=scanner,
            event_type="security.vulnerability_detected",
            **kwargs
        )

    def vulnerability_resolved(
        self,
        vulnerability_id: str,
        resolution_method: str,
        resolved_by: Optional[str] = None,
        **kwargs
    ):
        """Log vulnerability resolution event."""
        self.logger.info(
            "vulnerability_resolved",
            vulnerability_id=vulnerability_id,
            resolution_method=resolution_method,
            resolved_by=resolved_by,
            event_type="security.vulnerability_resolved",
            **kwargs
        )

    def alert_created(
        self,
        alert_id: int,
        alert_type: str,
        severity: str,
        pipeline_id: Optional[int] = None,
        **kwargs
    ):
        """Log alert creation event."""
        self.logger.warning(
            "alert_created",
            alert_id=alert_id,
            alert_type=alert_type,
            severity=severity,
            pipeline_id=pipeline_id,
            event_type="security.alert_created",
            **kwargs
        )

    def scan_completed(
        self,
        scan_id: str,
        scanner: str,
        vulnerabilities_found: int,
        scan_duration: float,
        pipeline_id: Optional[int] = None,
        **kwargs
    ):
        """Log scan completion event."""
        self.logger.info(
            "scan_completed",
            scan_id=scan_id,
            scanner=scanner,
            vulnerabilities_found=vulnerabilities_found,
            scan_duration=scan_duration,
            pipeline_id=pipeline_id,
            event_type="security.scan_completed",
            **kwargs
        )

    def scan_failed(
        self,
        scan_id: str,
        scanner: str,
        error: str,
        pipeline_id: Optional[int] = None,
        **kwargs
    ):
        """Log scan failure event."""
        self.logger.error(
            "scan_failed",
            scan_id=scan_id,
            scanner=scanner,
            error=error,
            pipeline_id=pipeline_id,
            event_type="security.scan_failed",
            **kwargs
        )

    def compliance_violation(
        self,
        rule_id: str,
        framework: str,
        severity: str,
        pipeline_id: Optional[int] = None,
        **kwargs
    ):
        """Log compliance violation event."""
        self.logger.warning(
            "compliance_violation",
            rule_id=rule_id,
            framework=framework,
            severity=severity,
            pipeline_id=pipeline_id,
            event_type="security.compliance_violation",
            **kwargs
        )

    def policy_violation(
        self,
        policy_id: str,
        policy_type: str,
        violation_details: str,
        pipeline_id: Optional[int] = None,
        **kwargs
    ):
        """Log policy violation event."""
        self.logger.warning(
            "policy_violation",
            policy_id=policy_id,
            policy_type=policy_type,
            violation_details=violation_details,
            pipeline_id=pipeline_id,
            event_type="security.policy_violation",
            **kwargs
        )


class AuditLogger:
    """Specialized logger for user actions and system events."""

    def __init__(self):
        self.logger = get_logger("audit")

    def user_action(
        self,
        user_id: Optional[int],
        username: Optional[str],
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Log user action for audit trail."""
        self.logger.info(
            "user_action",
            user_id=user_id,
            username=username,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            details=details or {},
            event_type="audit.user_action",
        )

    def login_attempt(
        self,
        username: str,
        success: bool,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        failure_reason: Optional[str] = None,
    ):
        """Log login attempt."""
        log_level = "info" if success else "warning"
        getattr(self.logger, log_level)(
            "login_attempt",
            username=username,
            success=success,
            ip_address=ip_address,
            user_agent=user_agent,
            failure_reason=failure_reason,
            event_type="audit.login_attempt",
        )

    def permission_denied(
        self,
        user_id: Optional[int],
        username: Optional[str],
        resource_type: str,
        resource_id: Optional[str],
        required_permission: str,
        ip_address: Optional[str] = None,
    ):
        """Log permission denied event."""
        self.logger.warning(
            "permission_denied",
            user_id=user_id,
            username=username,
            resource_type=resource_type,
            resource_id=resource_id,
            required_permission=required_permission,
            ip_address=ip_address,
            event_type="audit.permission_denied",
        )

    def configuration_changed(
        self,
        user_id: int,
        username: str,
        config_section: str,
        old_value: Any,
        new_value: Any,
        ip_address: Optional[str] = None,
    ):
        """Log configuration change."""
        self.logger.info(
            "configuration_changed",
            user_id=user_id,
            username=username,
            config_section=config_section,
            old_value=old_value,
            new_value=new_value,
            ip_address=ip_address,
            event_type="audit.configuration_changed",
        )


class PerformanceLogger:
    """Specialized logger for performance monitoring."""

    def __init__(self):
        self.logger = get_logger("performance")

    def request_duration(
        self,
        method: str,
        path: str,
        status_code: int,
        duration_ms: float,
        user_id: Optional[int] = None,
    ):
        """Log API request performance."""
        log_level = "warning" if duration_ms > 5000 else "info"  # Warn if > 5s
        getattr(self.logger, log_level)(
            "request_duration",
            method=method,
            path=path,
            status_code=status_code,
            duration_ms=duration_ms,
            user_id=user_id,
            event_type="performance.request_duration",
        )

    def database_query_duration(
        self,
        query_type: str,
        table_name: str,
        duration_ms: float,
        row_count: Optional[int] = None,
    ):
        """Log database query performance."""
        log_level = "warning" if duration_ms > 1000 else "debug"  # Warn if > 1s
        getattr(self.logger, log_level)(
            "database_query_duration",
            query_type=query_type,
            table_name=table_name,
            duration_ms=duration_ms,
            row_count=row_count,
            event_type="performance.database_query",
        )

    def scan_performance(
        self,
        scanner: str,
        scan_type: str,
        duration_seconds: float,
        files_scanned: int,
        vulnerabilities_found: int,
    ):
        """Log scan performance metrics."""
        self.logger.info(
            "scan_performance",
            scanner=scanner,
            scan_type=scan_type,
            duration_seconds=duration_seconds,
            files_scanned=files_scanned,
            vulnerabilities_found=vulnerabilities_found,
            scan_rate_files_per_second=files_scanned / max(duration_seconds, 0.1),
            event_type="performance.scan_metrics",
        )


class LoggerMiddleware:
    """Middleware for automatic request logging."""

    def __init__(self, app):
        self.app = app
        self.audit_logger = AuditLogger()
        self.performance_logger = PerformanceLogger()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start_time = datetime.utcnow()

        # Extract request information
        method = scope["method"]
        path = scope["path"]
        headers = dict(scope["headers"])
        client_ip = None
        user_agent = None

        if b"x-forwarded-for" in headers:
            client_ip = headers[b"x-forwarded-for"].decode()
        elif scope.get("client"):
            client_ip = scope["client"][0]

        if b"user-agent" in headers:
            user_agent = headers[b"user-agent"].decode()

        # Wrap send to capture response
        status_code = None

        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        # Process request
        await self.app(scope, receive, send_wrapper)

        # Calculate duration
        end_time = datetime.utcnow()
        duration_ms = (end_time - start_time).total_seconds() * 1000

        # Log performance
        if status_code:
            self.performance_logger.request_duration(
                method=method,
                path=path,
                status_code=status_code,
                duration_ms=duration_ms,
            )


# Global logger instances
security_logger = SecurityLogger()
audit_logger = AuditLogger()
performance_logger = PerformanceLogger()

# Main application logger
logger = get_logger("secureops")


<<<<<<< HEAD
=======
def setup_sentry():
    """Setup Sentry error tracking if configured."""
    if settings.sentry_dsn:
        try:
            import sentry_sdk
            from sentry_sdk.integrations.fastapi import FastApiIntegration
            from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
            from sentry_sdk.integrations.starlette import StarletteIntegration

            sentry_sdk.init(
                dsn=settings.sentry_dsn,
                environment=settings.sentry_environment,
                traces_sample_rate=0.1 if settings.is_production() else 1.0,
                integrations=[
                    FastApiIntegration(auto_enable=True),
                    StarletteIntegration(auto_enable=True),
                    SqlalchemyIntegration(),
                ],
                before_send=filter_sensitive_data,
            )
            logger.info("Sentry error tracking initialized")
        except ImportError:
            logger.warning("Sentry SDK not available, error tracking disabled")
        except Exception as e:
            logger.error("Failed to initialize Sentry", error=str(e))


>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
def filter_sensitive_data(event, hint):
    """Filter sensitive data from Sentry events."""
    # Remove sensitive headers
    if "request" in event and "headers" in event["request"]:
        sensitive_headers = ["authorization", "cookie", "x-api-key"]
        headers = event["request"]["headers"]
        for header in sensitive_headers:
            if header in headers:
                headers[header] = "[FILTERED]"

    # Remove sensitive form data
    if "request" in event and "data" in event["request"]:
        sensitive_fields = ["password", "token", "secret", "key"]
        data = event["request"]["data"]
        if isinstance(data, dict):
            for field in sensitive_fields:
                if field in data:
                    data[field] = "[FILTERED]"

    return event


<<<<<<< HEAD
def setup_sentry():
    """Setup Sentry error tracking if configured."""
    if settings.sentry_dsn:
        import sentry_sdk
        from sentry_sdk.integrations.starlette import StarletteIntegration
        from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
        from sentry_sdk.integrations.redis import RedisIntegration

        integrations = [
            StarletteIntegration(auto_enable=True),
            SqlalchemyIntegration(),
            RedisIntegration(),
        ]

        sentry_sdk.init(
            dsn=settings.sentry_dsn,
            environment=settings.sentry_environment,
            release=getattr(settings, "app_version", "unknown"),
            traces_sample_rate=0.1 if settings.is_production() else 1.0,
            profiles_sample_rate=0.1 if settings.is_production() else 1.0,
            integrations=integrations,
            before_send=filter_sensitive_data,
            send_default_pii=False,  # Security: Don't send PII by default
            attach_stacktrace=True,
            max_breadcrumbs=50,
            debug=settings.debug if not settings.is_production() else False,
        )
        logger.info("Sentry error tracking initialized")


def log_startup_info():
    """Log application startup information."""
    logger = get_logger(__name__)
    logger.info(
        "SecureOps application starting",
        app_name=settings.app_name,
        app_version=getattr(settings, "app_version", "unknown"),
=======
def log_startup_info():
    """Log application startup information."""
    logger.info(
        "SecureOps application starting",
        app_name=settings.app_name,
        app_version=settings.app_version,
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
        environment=settings.environment,
        debug=settings.debug,
        api_host=settings.api_host,
        api_port=settings.api_port,
    )


def log_shutdown_info():
    """Log application shutdown information."""
    logger.info(
        "SecureOps application shutting down",
        app_name=settings.app_name,
        environment=settings.environment,
    )


# Context managers for logging
class LogContext:
    """Context manager for adding structured logging context."""

    def __init__(self, **kwargs):
        self.context = kwargs
        self.token = None

    def __enter__(self):
        self.token = structlog.contextvars.bind_contextvars(**self.context)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.token:
            structlog.contextvars.unbind_contextvars(self.token)


# Decorators for automatic logging
def log_function_call(logger_instance=None):
    """Decorator to automatically log function calls."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            log = logger_instance or get_logger(func.__module__)

            try:
                log.debug(
                    "function_call_start",
                    function=func.__name__,
                    args_count=len(args),
                    kwargs_keys=list(kwargs.keys()),
                )

                result = func(*args, **kwargs)

                log.debug(
                    "function_call_success",
                    function=func.__name__,
                )

                return result

            except Exception as e:
                log.error(
                    "function_call_error",
                    function=func.__name__,
                    error=str(e),
                    error_type=type(e).__name__,
                )
                raise

        return wrapper

    return decorator


def log_async_function_call(logger_instance=None):
    """Decorator to automatically log async function calls."""

    def decorator(func):
        async def wrapper(*args, **kwargs):
            log = logger_instance or get_logger(func.__module__)

            try:
                log.debug(
                    "async_function_call_start",
                    function=func.__name__,
                    args_count=len(args),
                    kwargs_keys=list(kwargs.keys()),
                )

                result = await func(*args, **kwargs)

                log.debug(
                    "async_function_call_success",
                    function=func.__name__,
                )

                return result

            except Exception as e:
                log.error(
                    "async_function_call_error",
                    function=func.__name__,
                    error=str(e),
                    error_type=type(e).__name__,
                )
                raise

        return wrapper

    return decorator


# Initialize logging on import
configure_logging()
