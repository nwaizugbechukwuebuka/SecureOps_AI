"""
Background task scheduler for SecureOps using Celery.
"""

import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from celery import Celery
from celery.schedules import crontab
from kombu import Queue

from .config import get_settings
from .logger import get_logger

# Get application settings
settings = get_settings()
logger = get_logger(__name__)

# Create Celery app
celery_app = Celery(
    "secureops",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=[
        "src.tasks.scan_tasks",
        "src.tasks.alert_tasks",
        "src.tasks.monitor_tasks",
        "src.tasks.cleanup_tasks",
    ],
)

# Celery configuration
celery_app.conf.update(
    task_serializer=settings.celery_task_serializer,
    result_serializer=settings.celery_result_serializer,
    accept_content=["json"],
    result_expires=3600,  # Results expire after 1 hour
    timezone="UTC",
    enable_utc=True,
    # Task routing
    task_routes={
        "scan_tasks.*": {"queue": "scans"},
        "alert_tasks.*": {"queue": "alerts"},
        "monitor_tasks.*": {"queue": "monitoring"},
        "cleanup_tasks.*": {"queue": "maintenance"},
    },
    # Queue definitions
    task_default_queue="default",
    task_queues=(
        Queue("default", routing_key="default"),
        Queue("scans", routing_key="scans"),
        Queue("alerts", routing_key="alerts"),
        Queue("monitoring", routing_key="monitoring"),
        Queue("maintenance", routing_key="maintenance"),
        Queue("high_priority", routing_key="high_priority"),
    ),
    # Worker configuration
    worker_concurrency=4,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_max_tasks_per_child=1000,
    # Task execution
    task_soft_time_limit=1800,  # 30 minutes
    task_time_limit=2400,  # 40 minutes
    task_reject_on_worker_lost=True,
    # Retry configuration
    task_default_retry_delay=60,
    task_max_retries=3,
)

# Periodic task schedule
celery_app.conf.beat_schedule = {
    # Vulnerability scanning
    "schedule-vulnerability-scans": {
        "task": "scan_tasks.schedule_vulnerability_scans",
        "schedule": crontab(minute=0, hour="*/2"),  # Every 2 hours
    },
    # Monitor pipeline runs
    "monitor-pipeline-runs": {
        "task": "monitor_tasks.monitor_pipeline_runs",
        "schedule": crontab(minute="*/5"),  # Every 5 minutes
    },
    # Process alerts
    "process-pending-alerts": {
        "task": "alert_tasks.process_pending_alerts",
        "schedule": crontab(minute="*/2"),  # Every 2 minutes
    },
    # Check for alert escalations
    "check-alert-escalations": {
        "task": "alert_tasks.check_alert_escalations",
        "schedule": crontab(minute="*/10"),  # Every 10 minutes
    },
    # Send notification batches
    "send-notification-batches": {
        "task": "alert_tasks.send_notification_batches",
        "schedule": crontab(minute="*/1"),  # Every minute
    },
    # Cleanup old data
    "cleanup-old-pipeline-runs": {
        "task": "cleanup_tasks.cleanup_old_pipeline_runs",
        "schedule": crontab(minute=0, hour=2),  # Daily at 2 AM
    },
    "cleanup-resolved-vulnerabilities": {
        "task": "cleanup_tasks.cleanup_resolved_vulnerabilities",
        "schedule": crontab(
            minute=0, hour=3, day_of_week=0
        ),  # Weekly on Sunday at 3 AM
    },
    # Generate reports
    "generate-daily-security-report": {
        "task": "monitor_tasks.generate_daily_security_report",
        "schedule": crontab(minute=0, hour=8),  # Daily at 8 AM
    },
    "generate-weekly-compliance-report": {
        "task": "monitor_tasks.generate_weekly_compliance_report",
        "schedule": crontab(
            minute=0, hour=9, day_of_week=1
        ),  # Weekly on Monday at 9 AM
    },
    # Health checks
    "database-health-check": {
        "task": "monitor_tasks.database_health_check",
        "schedule": crontab(minute="*/15"),  # Every 15 minutes
    },
    "scanner-health-check": {
        "task": "monitor_tasks.scanner_health_check",
        "schedule": crontab(minute=0, hour="*/1"),  # Every hour
    },
    # Metrics collection
    "collect-pipeline-metrics": {
        "task": "monitor_tasks.collect_pipeline_metrics",
        "schedule": crontab(minute="*/30"),  # Every 30 minutes
    },
    "update-vulnerability-statistics": {
        "task": "monitor_tasks.update_vulnerability_statistics",
        "schedule": crontab(minute=15, hour="*/1"),  # Every hour at 15 minutes past
    },
}


class TaskScheduler:
    """Centralized task scheduling and management."""

    def __init__(self):
        self.celery = celery_app
        self.logger = logger

    def schedule_vulnerability_scan(
        self,
        pipeline_id: int,
        scan_type: str = "full",
        priority: str = "normal",
        delay: Optional[int] = None,
        **kwargs,
    ) -> str:
        """
        Schedule a vulnerability scan for a pipeline.

        Args:
            pipeline_id: ID of the pipeline to scan
            scan_type: Type of scan (full, incremental, targeted)
            priority: Task priority (low, normal, high)
            delay: Delay in seconds before starting scan
            **kwargs: Additional scan parameters

        Returns:
            str: Task ID
        """
        from src.tasks.scan_tasks import run_vulnerability_scan

        queue = "high_priority" if priority == "high" else "scans"

        task_kwargs = {"pipeline_id": pipeline_id, "scan_type": scan_type, **kwargs}

        if delay:
            result = run_vulnerability_scan.apply_async(
                kwargs=task_kwargs, queue=queue, countdown=delay
            )
        else:
            result = run_vulnerability_scan.apply_async(kwargs=task_kwargs, queue=queue)

        self.logger.info(
            "Vulnerability scan scheduled",
            task_id=result.id,
            pipeline_id=pipeline_id,
            scan_type=scan_type,
            priority=priority,
            delay=delay,
        )

        return result.id

    def schedule_compliance_check(
        self, pipeline_id: int, framework: str, priority: str = "normal", **kwargs
    ) -> str:
        """
        Schedule a compliance check for a pipeline.

        Args:
            pipeline_id: ID of the pipeline to check
            framework: Compliance framework (OWASP, NIST, etc.)
            priority: Task priority
            **kwargs: Additional check parameters

        Returns:
            str: Task ID
        """
        from src.tasks.scan_tasks import run_compliance_check

        queue = "high_priority" if priority == "high" else "scans"

        result = run_compliance_check.apply_async(
            kwargs={"pipeline_id": pipeline_id, "framework": framework, **kwargs},
            queue=queue,
        )

        self.logger.info(
            "Compliance check scheduled",
            task_id=result.id,
            pipeline_id=pipeline_id,
            framework=framework,
            priority=priority,
        )

        return result.id

    def schedule_alert_processing(
        self, alert_id: int, action: str = "process", priority: str = "high", **kwargs
    ) -> str:
        """
        Schedule alert processing task.

        Args:
            alert_id: ID of the alert to process
            action: Action to perform (process, escalate, notify)
            priority: Task priority
            **kwargs: Additional processing parameters

        Returns:
            str: Task ID
        """
        from src.tasks.alert_tasks import process_alert

        result = process_alert.apply_async(
            kwargs={"alert_id": alert_id, "action": action, **kwargs},
            queue="alerts",
            priority=9 if priority == "high" else 5,
        )

        self.logger.info(
            "Alert processing scheduled",
            task_id=result.id,
            alert_id=alert_id,
            action=action,
            priority=priority,
        )

        return result.id

    def schedule_notification(
        self,
        notification_type: str,
        recipients: List[str],
        message: Dict[str, Any],
        channel: str = "email",
        priority: str = "normal",
        delay: Optional[int] = None,
    ) -> str:
        """
        Schedule notification delivery.

        Args:
            notification_type: Type of notification
            recipients: List of recipient addresses
            message: Notification message content
            channel: Delivery channel (email, slack, webhook)
            priority: Task priority
            delay: Delay in seconds

        Returns:
            str: Task ID
        """
        from src.tasks.alert_tasks import send_notification

        task_kwargs = {
            "notification_type": notification_type,
            "recipients": recipients,
            "message": message,
            "channel": channel,
        }

        if delay:
            result = send_notification.apply_async(
                kwargs=task_kwargs, queue="alerts", countdown=delay
            )
        else:
            result = send_notification.apply_async(kwargs=task_kwargs, queue="alerts")

        self.logger.info(
            "Notification scheduled",
            task_id=result.id,
            notification_type=notification_type,
            channel=channel,
            recipients_count=len(recipients),
            priority=priority,
            delay=delay,
        )

        return result.id

    def schedule_pipeline_monitoring(
        self, pipeline_id: Optional[int] = None, check_type: str = "status", **kwargs
    ) -> str:
        """
        Schedule pipeline monitoring task.

        Args:
            pipeline_id: ID of specific pipeline (None for all)
            check_type: Type of monitoring check
            **kwargs: Additional monitoring parameters

        Returns:
            str: Task ID
        """
        from src.tasks.monitor_tasks import monitor_pipeline

        result = monitor_pipeline.apply_async(
            kwargs={"pipeline_id": pipeline_id, "check_type": check_type, **kwargs},
            queue="monitoring",
        )

        self.logger.info(
            "Pipeline monitoring scheduled",
            task_id=result.id,
            pipeline_id=pipeline_id,
            check_type=check_type,
        )

        return result.id

    def schedule_report_generation(
        self,
        report_type: str,
        parameters: Dict[str, Any],
        recipients: Optional[List[str]] = None,
        format: str = "pdf",
        **kwargs,
    ) -> str:
        """
        Schedule report generation task.

        Args:
            report_type: Type of report to generate
            parameters: Report parameters
            recipients: Report recipients
            format: Report format (pdf, html, json)
            **kwargs: Additional parameters

        Returns:
            str: Task ID
        """
        from src.tasks.monitor_tasks import generate_report

        result = generate_report.apply_async(
            kwargs={
                "report_type": report_type,
                "parameters": parameters,
                "recipients": recipients,
                "format": format,
                **kwargs,
            },
            queue="monitoring",
        )

        self.logger.info(
            "Report generation scheduled",
            task_id=result.id,
            report_type=report_type,
            format=format,
            recipients_count=len(recipients) if recipients else 0,
        )

        return result.id

    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """
        Get status of a scheduled task.

        Args:
            task_id: Task ID to check

        Returns:
            Dict containing task status information
        """
        result = self.celery.AsyncResult(task_id)

        status_info = {
            "task_id": task_id,
            "status": result.status,
            "ready": result.ready(),
            "successful": result.successful() if result.ready() else None,
            "failed": result.failed() if result.ready() else None,
        }

        if result.ready():
            if result.successful():
                status_info["result"] = result.result
            elif result.failed():
                status_info["error"] = str(result.info)
        else:
            status_info["info"] = result.info

        return status_info

    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a scheduled task.

        Args:
            task_id: Task ID to cancel

        Returns:
            bool: True if task was cancelled successfully
        """
        try:
            self.celery.control.revoke(task_id, terminate=True)
            self.logger.info("Task cancelled", task_id=task_id)
            return True
        except Exception as e:
            self.logger.error("Failed to cancel task", task_id=task_id, error=str(e))
            return False

    def get_active_tasks(self) -> List[Dict[str, Any]]:
        """
        Get list of currently active tasks.

        Returns:
            List of active task information
        """
        try:
            active_tasks = self.celery.control.inspect().active()

            tasks = []
            for worker, task_list in (active_tasks or {}).items():
                for task in task_list:
                    tasks.append(
                        {
                            "worker": worker,
                            "task_id": task["id"],
                            "task_name": task["name"],
                            "args": task.get("args", []),
                            "kwargs": task.get("kwargs", {}),
                            "time_start": task.get("time_start"),
                        }
                    )

            return tasks
        except Exception as e:
            self.logger.error("Failed to get active tasks", error=str(e))
            return []

    def get_worker_stats(self) -> Dict[str, Any]:
        """
        Get Celery worker statistics.

        Returns:
            Dict containing worker statistics
        """
        try:
            stats = self.celery.control.inspect().stats()

            if not stats:
                return {}

            # Aggregate stats from all workers
            total_stats = {
                "workers": len(stats),
                "total_tasks": 0,
                "active_tasks": 0,
                "processed_tasks": 0,
            }

            worker_details = []
            for worker, worker_stats in stats.items():
                worker_info = {
                    "worker": worker,
                    "status": "online",
                    "processed": worker_stats.get("total", {}).get("tasks.total", 0),
                    "active": len(worker_stats.get("active", [])),
                    "load": worker_stats.get("rusage", {}).get("utime", 0),
                }
                worker_details.append(worker_info)

                total_stats["processed_tasks"] += worker_info["processed"]
                total_stats["active_tasks"] += worker_info["active"]

            total_stats["workers_detail"] = worker_details

            return total_stats
        except Exception as e:
            self.logger.error("Failed to get worker stats", error=str(e))
            return {}

    def purge_queue(self, queue_name: str) -> int:
        """
        Purge all tasks from a queue.

        Args:
            queue_name: Name of queue to purge

        Returns:
            int: Number of tasks purged
        """
        try:
            purged = self.celery.control.purge()
            self.logger.info("Queue purged", queue=queue_name, tasks_purged=purged)
            return purged or 0
        except Exception as e:
            self.logger.error("Failed to purge queue", queue=queue_name, error=str(e))
            return 0


# Global scheduler instance
scheduler = TaskScheduler()


def init_celery_app(app):
    """
    Initialize Celery app with Flask/FastAPI application.

    Args:
        app: FastAPI or Flask application instance
    """

    class ContextTask(celery_app.Task):
        """Make celery tasks work with application context."""

        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery_app.Task = ContextTask
    return celery_app


def get_celery_app():
    """Get the Celery application instance."""
    return celery_app


def setup_periodic_tasks():
    """Setup periodic tasks for the scheduler."""
    logger.info("Setting up periodic tasks")

    # The periodic tasks are already configured in celery_app.conf.beat_schedule
    # This function can be used for any additional dynamic setup

    logger.info(
        "Periodic tasks configured", scheduled_tasks=len(celery_app.conf.beat_schedule)
    )


# Health check for Celery
def celery_health_check() -> Dict[str, Any]:
    """
    Perform health check on Celery workers and broker.

    Returns:
        Dict containing health status
    """
    health = {
        "status": "unhealthy",
        "broker_connected": False,
        "workers_online": 0,
        "queues_available": [],
        "errors": [],
    }

    try:
        # Check broker connection
        with celery_app.connection() as conn:
            conn.ensure_connection(max_retries=3, interval_start=1)
            health["broker_connected"] = True

        # Check workers
        stats = celery_app.control.inspect().stats()
        if stats:
            health["workers_online"] = len(stats)

        # Check queues
        with celery_app.connection() as conn:
            for queue_name in ["default", "scans", "alerts", "monitoring"]:
                try:
                    queue = conn.SimpleQueue(queue_name)
                    queue.qsize()  # Test queue access
                    health["queues_available"].append(queue_name)
                    queue.close()
                except Exception as e:
                    health["errors"].append(f"Queue {queue_name} error: {e}")

        # Determine overall status
        if (
            health["broker_connected"]
            and health["workers_online"] > 0
            and len(health["queues_available"]) > 0
        ):
            health["status"] = "healthy"

    except Exception as e:
        health["errors"].append(f"Health check error: {e}")

    return health
