"""
Celery application configuration for SecureOps AI.
Orchestrates all background tasks including scanning, alerts, cleanup, and monitoring.

This configuration integrates with:
- Security scanners for automated vulnerability analysis
- CI/CD platforms for pipeline integration
- Alert system for notifications
- Cleanup system for maintenance
- Monitoring system for health checks

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import os
import logging
from celery import Celery
from celery.signals import after_setup_logger, worker_ready, worker_shutdown
from kombu import Queue

# Get configuration settings
from src.api.utils.config import get_settings

settings = get_settings()

# Setup logging
logger = logging.getLogger(__name__)

# Create Celery app with comprehensive configuration
app = Celery(
    'secureops_ai',
    broker=getattr(settings, 'celery_broker_url', 'redis://localhost:6379/0'),
    backend=getattr(settings, 'celery_result_backend', 'redis://localhost:6379/0'),
    include=[
        'src.tasks.alert_tasks',
        'src.tasks.background_tasks', 
        'src.tasks.cleanup_tasks',
        'src.tasks.monitor_tasks',
        'src.tasks.scan_tasks',
        'src.tasks.workflow_executor',
    ]
)

# Configure Celery with production-ready settings
app.conf.update(
    # Serialization
    task_serializer=getattr(settings, 'celery_task_serializer', 'json'),
    result_serializer=getattr(settings, 'celery_result_serializer', 'json'),
    accept_content=['json'],
    
    # Timing
    result_expires=getattr(settings, 'celery_result_expires', 7200),  # 2 hours
    task_time_limit=getattr(settings, 'celery_task_time_limit', 3600),  # 1 hour
    task_soft_time_limit=getattr(settings, 'celery_task_soft_time_limit', 3300),  # 55 minutes
    
    # Timezone
    timezone='UTC',
    enable_utc=True,
    
    # Task routing with dedicated queues
    task_routes={
        'secureops.tasks.scan_tasks.*': {'queue': 'scans'},
        'secureops.tasks.alert_tasks.*': {'queue': 'alerts'},
        'secureops.tasks.monitor_tasks.*': {'queue': 'monitoring'},
        'secureops.tasks.cleanup_tasks.*': {'queue': 'cleanup'},
        'secureops.tasks.background_tasks.*': {'queue': 'background'},
        'secureops.tasks.workflow_executor.*': {'queue': 'workflows'},
    },
    
    # Queue configuration with priorities
    task_queues=(
        Queue('alerts', priority=9),      # High priority for alerts
        Queue('scans', priority=7),       # High priority for scans
        Queue('monitoring', priority=6),  # Medium-high for monitoring
        Queue('workflows', priority=5),   # Medium for workflows
        Queue('background', priority=3),  # Lower for background tasks
        Queue('cleanup', priority=2),     # Low priority for cleanup
        Queue('default', priority=4),     # Default queue
    ),
    
    # Worker configuration
    task_default_queue='default',
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_max_tasks_per_child=getattr(settings, 'celery_max_tasks_per_child', 1000),
    worker_disable_rate_limits=False,
    
    # Error handling
    task_reject_on_worker_lost=True,
    task_ignore_result=False,
    task_store_errors_even_if_ignored=True,
    
    # Retry configuration
    task_default_retry_delay=60,  # 1 minute
    task_max_retries=3,
    
    # Monitoring
    worker_send_task_events=True,
    task_send_sent_event=True,
    
    # Security
    task_always_eager=getattr(settings, 'celery_always_eager', False),
    task_eager_propagates=True,
    
    # Performance optimization
    broker_connection_retry_on_startup=True,
    broker_connection_retry=True,
    broker_connection_max_retries=10,
    
    # Result backend configuration
    result_backend_transport_options={
        'master_name': 'mymaster',
        'visibility_timeout': 3600,
        'retry_policy': {
            'timeout': 5.0
        }
    }
)

# Custom task base class for enhanced functionality
class SecureOpsTask(app.Task):
    """Base task class with enhanced error handling and logging."""
    
    autoretry_for = (Exception,)
    retry_kwargs = {'max_retries': 3, 'countdown': 60}
    retry_backoff = True
    retry_backoff_max = 700
    retry_jitter = False
    
    def on_success(self, retval, task_id, args, kwargs):
        """Log successful task completion."""
        logger.info(f"Task {self.name} [{task_id}] completed successfully")
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Log task failure with detailed information."""
        logger.error(f"Task {self.name} [{task_id}] failed: {str(exc)}")
        logger.debug(f"Task failure traceback: {einfo.traceback}")
    
    def on_retry(self, exc, task_id, args, kwargs, einfo):
        """Log task retry."""
        logger.warning(f"Task {self.name} [{task_id}] retrying due to: {str(exc)}")

# Set the custom task base class
app.Task = SecureOpsTask

# Signal handlers for enhanced monitoring
@after_setup_logger.connect
def setup_loggers(logger, *args, **kwargs):
    """Configure logging for Celery."""
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Add handler for file logging if configured
    if hasattr(settings, 'celery_log_file'):
        file_handler = logging.FileHandler(settings.celery_log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)


@worker_ready.connect
def worker_ready_handler(sender=None, **kwargs):
    """Handle worker ready event."""
    logger.info(f"Celery worker {sender.hostname} is ready and connected")


@worker_shutdown.connect  
def worker_shutdown_handler(sender=None, **kwargs):
    """Handle worker shutdown event."""
    logger.info(f"Celery worker {sender.hostname} is shutting down")


# Task discovery and registration
def autodiscover_tasks():
    """Auto-discover tasks from all modules."""
    try:
        # Import all task modules to register them
        from . import scan_tasks
        from . import cleanup_tasks  
        from . import alert_tasks
        from . import monitor_tasks
        from . import background_tasks
        from . import workflow_executor
        
        logger.info("All task modules imported successfully")
        
    except ImportError as e:
        logger.warning(f"Could not import some task modules: {e}")


# Beat schedule for periodic tasks
app.conf.beat_schedule = {
    # System health monitoring every 5 minutes
    'health-monitor': {
        'task': 'secureops.tasks.monitor_tasks.system_health_monitor',
        'schedule': 300.0,  # 5 minutes
    },
    
    # Cleanup old data every day at 2 AM
    'daily-cleanup': {
        'task': 'secureops.tasks.cleanup_tasks.comprehensive_system_cleanup',
        'schedule': 86400.0,  # 24 hours
        'options': {'queue': 'cleanup'}
    },
    
    # Alert digest every hour
    'hourly-alert-digest': {
        'task': 'secureops.tasks.alert_tasks.generate_alert_digest',
        'schedule': 3600.0,  # 1 hour
        'options': {'queue': 'alerts'}
    },
    
    # Database maintenance weekly
    'weekly-db-maintenance': {
        'task': 'secureops.tasks.cleanup_tasks.database_maintenance', 
        'schedule': 604800.0,  # 1 week
        'options': {'queue': 'cleanup'}
    },
    
    # Security scan health check every 15 minutes
    'scan-health-check': {
        'task': 'secureops.tasks.scan_tasks.scan_health_check',
        'schedule': 900.0,  # 15 minutes
        'options': {'queue': 'monitoring'}
    }
}

# Initialize task discovery
autodiscover_tasks()

if __name__ == '__main__':
    app.start()

if __name__ == '__main__':
    app.start()