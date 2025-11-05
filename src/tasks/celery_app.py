"""
Celery application configuration for SecureOps AI.
"""

import os
from celery import Celery

# Get configuration settings
from src.api.utils.config import get_settings

settings = get_settings()

# Create Celery app
app = Celery(
    'secureops',
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=[
        'src.tasks.alert_tasks',
        'src.tasks.background_tasks',
        'src.tasks.cleanup_tasks',
        'src.tasks.monitor_tasks',
        'src.tasks.scan_tasks',
        'src.tasks.workflow_executor',
    ]
)

# Configure Celery
app.conf.update(
    task_serializer=settings.celery_task_serializer,
    result_serializer=settings.celery_result_serializer,
    accept_content=['json'],
    result_expires=3600,
    timezone='UTC',
    enable_utc=True,
    task_routes={
        'src.tasks.scan_tasks.*': {'queue': 'scans'},
        'src.tasks.alert_tasks.*': {'queue': 'alerts'},
        'src.tasks.monitor_tasks.*': {'queue': 'monitoring'},
        'src.tasks.cleanup_tasks.*': {'queue': 'cleanup'},
    },
    task_default_queue='default',
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_max_tasks_per_child=1000,
)

# Auto-discover tasks from Django apps (if any)
# app.autodiscover_tasks()

if __name__ == '__main__':
    app.start()