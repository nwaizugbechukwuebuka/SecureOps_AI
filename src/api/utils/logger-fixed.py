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
    """Configure logging for the application with optional SIEM forwarding."""
    # Ensure log directory exists
    if settings.log_file:
        log_path = Path(settings.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

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
            logging.getLogger().warning("Datadog log forwarding requested but datadog-api-client package not installed. Install with: pip install datadog-api-client")
        except Exception as e:
            logging.getLogger().error(f"Failed to enable Datadog log forwarding: {e}")

    # Splunk
    if getattr(settings, "log_forward_splunk_enabled", False):
        try:
            import splunk_handler
            
            splunk_handler_instance = splunk_handler.SplunkHandler(
                host=settings.log_forward_splunk_host or 'localhost',
                port=settings.log_forward_splunk_port or 8088,
                token=settings.log_forward_splunk_token,
                index=settings.log_forward_splunk_index or 'secureops'
            )
            handlers.append(splunk_handler_instance)
            logging.getLogger().info("Splunk log forwarding enabled.")
        except ImportError:
            logging.getLogger().warning("Splunk log forwarding requested but splunk-handler package not installed. Install with: pip install splunk-handler")
        except Exception as e:
            logging.getLogger().error(f"Failed to enable Splunk log forwarding: {e}")

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

    # Configure standard library logging
    logging.basicConfig(
        level=getattr(logging, settings.log_level),
        format="%(message)s",
        handlers=handlers,
    )

    # Configure structlog processors
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.add_logger_name,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="ISO"),
    ]

    # Add JSON formatting for production
    if settings.log_format.lower() == "json":
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
        cache_logger_on_first_use=True,
    )

    # Set up Sentry for error tracking if configured
    setup_sentry()


def setup_sentry():
    """Set up Sentry error tracking if configured."""
    if hasattr(settings, 'sentry_dsn') and settings.sentry_dsn:
        try:
            import sentry_sdk
            from sentry_sdk.integrations.logging import LoggingIntegration
            
            sentry_logging = LoggingIntegration(
                level=logging.INFO,
                event_level=logging.ERROR
            )
            
            sentry_sdk.init(
                dsn=settings.sentry_dsn,
                integrations=[sentry_logging],
                traces_sample_rate=0.1,
                release=getattr(settings, 'app_version', 'unknown'),
                environment=settings.environment,
            )
            
            logging.getLogger().info("Sentry error tracking initialized.")
        except ImportError:
            logging.getLogger().warning("Sentry DSN configured but sentry-sdk not installed. Install with: pip install sentry-sdk")
        except Exception as e:
            logging.getLogger().error(f"Failed to initialize Sentry: {e}")


def get_logger(name: str = __name__) -> structlog.BoundLogger:
    """Get a structlog logger instance."""
    return structlog.get_logger(name)


def log_performance(func_name: str, execution_time: float, **kwargs):
    """Log performance metrics."""
    logger = get_logger("performance")
    logger.info(
        "Performance metric recorded",
        function=func_name,
        execution_time_ms=round(execution_time * 1000, 2),
        **kwargs
    )


def log_security_event(event_type: str, severity: str, details: Dict[str, Any]):
    """Log security-related events with consistent structure."""
    logger = get_logger("security")
    logger.warning(
        f"Security event: {event_type}",
        event_type=event_type,
        severity=severity,
        timestamp=datetime.utcnow().isoformat(),
        **details
    )


def log_audit_trail(action: str, user_id: Optional[str], resource: str, **kwargs):
    """Log audit trail events."""
    logger = get_logger("audit")
    logger.info(
        f"Audit: {action}",
        action=action,
        user_id=user_id,
        resource=resource,
        timestamp=datetime.utcnow().isoformat(),
        **kwargs
    )


def log_api_request(method: str, path: str, status_code: int, response_time: float, **kwargs):
    """Log API requests with consistent format."""
    logger = get_logger("api")
    logger.info(
        "API request",
        method=method,
        path=path,
        status_code=status_code,
        response_time_ms=round(response_time * 1000, 2),
        **kwargs
    )


class SecurityFilter(logging.Filter):
    """Filter to prevent logging of sensitive information."""
    
    SENSITIVE_PATTERNS = [
        "password",
        "token",
        "secret",
        "key",
        "authorization",
        "x-api-key",
    ]
    
    def filter(self, record):
        if hasattr(record, 'getMessage'):
            message = record.getMessage()
            for pattern in self.SENSITIVE_PATTERNS:
                if pattern.lower() in message.lower():
                    # Replace sensitive data with placeholder
                    record.msg = record.msg.replace(
                        record.args[0] if record.args else "",
                        "[REDACTED]"
                    )
                    break
        return True


# Initialize logging when module is imported
configure_logging()