"""
Task Scheduling Utilities Module

This module provides utilities for scheduling and managing periodic tasks
using Celery Beat and custom scheduling logic for the SecureOps platform.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import asyncio
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union

from celery import Celery
from celery.beat import ScheduleEntry
from celery.schedules import crontab, schedule

from .config import settings
from .logger import get_logger

logger = get_logger(__name__)


class ScheduleType(Enum):
    """Types of schedules available."""

    INTERVAL = "interval"
    CRONTAB = "crontab"
    SOLAR = "solar"
    CLOCKED = "clocked"


class TaskPriority(Enum):
    """Task priority levels."""

    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class ScheduledTask:
    """Represents a scheduled task configuration."""

    name: str
    task: str
    schedule: Union[dict, str]
    schedule_type: ScheduleType
    args: List[Any] = None
    kwargs: Dict[str, Any] = None
    priority: TaskPriority = TaskPriority.NORMAL
    enabled: bool = True
    description: str = ""
    max_retries: int = 3
    retry_delay: int = 60
    timeout: int = 3600
    expires: Optional[datetime] = None
    routing_key: Optional[str] = None
    queue: Optional[str] = None
    options: Dict[str, Any] = None


class TaskScheduler:
    """Manages task scheduling and periodic execution."""

    def __init__(self, celery_app: Celery = None):
        """
        Initialize task scheduler.

        Args:
            celery_app: Celery application instance
        """
        self.celery_app = celery_app
        self.scheduled_tasks: Dict[str, ScheduledTask] = {}
        self._beat_schedule: Dict[str, Dict[str, Any]] = {}

        # Initialize default scheduled tasks
        self._initialize_default_tasks()

    def _initialize_default_tasks(self):
        """Initialize default scheduled tasks for SecureOps."""
        default_tasks = [
            # System health monitoring
            ScheduledTask(
                name="system_health_check",
                task="secureops.tasks.monitor_tasks.system_health_check",
                schedule={"minutes": 5},
                schedule_type=ScheduleType.INTERVAL,
                description="Monitor system health every 5 minutes",
                priority=TaskPriority.HIGH,
                queue="monitoring",
            ),
            # Pipeline health monitoring
            ScheduledTask(
                name="pipeline_health_monitor",
                task="secureops.tasks.monitor_tasks.pipeline_health_monitor",
                schedule={"minutes": 15},
                schedule_type=ScheduleType.INTERVAL,
                description="Monitor pipeline health every 15 minutes",
                priority=TaskPriority.NORMAL,
                queue="monitoring",
            ),
            # Scanner availability check
            ScheduledTask(
                name="scanner_availability_check",
                task="secureops.tasks.monitor_tasks.scanner_availability_check",
                schedule={"minutes": 30},
                schedule_type=ScheduleType.INTERVAL,
                description="Check scanner availability every 30 minutes",
                priority=TaskPriority.NORMAL,
                queue="monitoring",
            ),
            # Performance metrics collection
            ScheduledTask(
                name="performance_metrics_collection",
                task="secureops.tasks.monitor_tasks.performance_metrics_collection",
                schedule={"minutes": 10},
                schedule_type=ScheduleType.INTERVAL,
                description="Collect performance metrics every 10 minutes",
                priority=TaskPriority.LOW,
                queue="monitoring",
            ),
            # Daily cleanup tasks
            ScheduledTask(
                name="daily_cleanup",
                task="secureops.tasks.cleanup_tasks.cleanup_temporary_files",
                schedule="0 2 * * *",  # 2 AM daily
                schedule_type=ScheduleType.CRONTAB,
                description="Clean up temporary files daily at 2 AM",
                priority=TaskPriority.LOW,
                queue="cleanup",
            ),
            # Weekly log cleanup
            ScheduledTask(
                name="weekly_log_cleanup",
                task="secureops.tasks.cleanup_tasks.cleanup_log_files",
                schedule="0 3 * * 0",  # 3 AM on Sundays
                schedule_type=ScheduleType.CRONTAB,
                description="Clean up old log files weekly",
                priority=TaskPriority.LOW,
                queue="cleanup",
            ),
            # Monthly database maintenance
            ScheduledTask(
                name="monthly_db_maintenance",
                task="secureops.tasks.cleanup_tasks.database_maintenance",
                schedule="0 4 1 * *",  # 4 AM on 1st of every month
                schedule_type=ScheduleType.CRONTAB,
                description="Perform database maintenance monthly",
                priority=TaskPriority.NORMAL,
                queue="maintenance",
            ),
            # Docker resource cleanup
            ScheduledTask(
                name="docker_cleanup",
                task="secureops.tasks.cleanup_tasks.cleanup_docker_resources",
                schedule="0 5 * * *",  # 5 AM daily
                schedule_type=ScheduleType.CRONTAB,
                description="Clean up Docker resources daily",
                priority=TaskPriority.LOW,
                queue="cleanup",
            ),
            # Daily alert digest
            ScheduledTask(
                name="daily_alert_digest",
                task="secureops.tasks.alert_tasks.digest_alerts",
                schedule="0 8 * * *",  # 8 AM daily
                schedule_type=ScheduleType.CRONTAB,
                args=["24h"],
                description="Send daily alert digest",
                priority=TaskPriority.NORMAL,
                queue="alerts",
            ),
            # Weekly alert cleanup
            ScheduledTask(
                name="weekly_alert_cleanup",
                task="secureops.tasks.alert_tasks.cleanup_old_alerts",
                schedule="0 6 * * 1",  # 6 AM on Mondays
                schedule_type=ScheduleType.CRONTAB,
                description="Clean up old resolved alerts weekly",
                priority=TaskPriority.LOW,
                queue="cleanup",
            ),
            # Dependency freshness check
            ScheduledTask(
                name="dependency_freshness_check",
                task="secureops.tasks.monitor_tasks.dependency_freshness_check",
                schedule="0 9 * * 1",  # 9 AM on Mondays
                schedule_type=ScheduleType.CRONTAB,
                description="Check for outdated dependencies weekly",
                priority=TaskPriority.NORMAL,
                queue="monitoring",
            ),
            # Integration health check
            ScheduledTask(
                name="integration_health_check",
                task="secureops.tasks.monitor_tasks.integration_health_check",
                schedule={"hours": 4},
                schedule_type=ScheduleType.INTERVAL,
                description="Check integration health every 4 hours",
                priority=TaskPriority.NORMAL,
                queue="monitoring",
            ),
            # Cache cleanup
            ScheduledTask(
                name="cache_cleanup",
                task="secureops.tasks.cleanup_tasks.cleanup_cache_data",
                schedule={"hours": 12},
                schedule_type=ScheduleType.INTERVAL,
                description="Clean up old cache data every 12 hours",
                priority=TaskPriority.LOW,
                queue="cleanup",
            ),
        ]

        for task in default_tasks:
            self.add_scheduled_task(task)

    def add_scheduled_task(self, task: ScheduledTask):
        """
        Add a scheduled task.

        Args:
            task: ScheduledTask instance to add
        """
        self.scheduled_tasks[task.name] = task

        # Convert to Celery beat schedule format
        beat_entry = self._create_beat_schedule_entry(task)
        self._beat_schedule[task.name] = beat_entry

        logger.info(f"Added scheduled task: {task.name}")

    def remove_scheduled_task(self, task_name: str):
        """
        Remove a scheduled task.

        Args:
            task_name: Name of the task to remove
        """
        if task_name in self.scheduled_tasks:
            del self.scheduled_tasks[task_name]

        if task_name in self._beat_schedule:
            del self._beat_schedule[task_name]

        logger.info(f"Removed scheduled task: {task_name}")

    def enable_task(self, task_name: str):
        """Enable a scheduled task."""
        if task_name in self.scheduled_tasks:
            self.scheduled_tasks[task_name].enabled = True
            self._beat_schedule[task_name]["enabled"] = True
            logger.info(f"Enabled scheduled task: {task_name}")

    def disable_task(self, task_name: str):
        """Disable a scheduled task."""
        if task_name in self.scheduled_tasks:
            self.scheduled_tasks[task_name].enabled = False
            self._beat_schedule[task_name]["enabled"] = False
            logger.info(f"Disabled scheduled task: {task_name}")

    def _create_beat_schedule_entry(self, task: ScheduledTask) -> Dict[str, Any]:
        """
        Create Celery beat schedule entry from ScheduledTask.

        Args:
            task: ScheduledTask instance

        Returns:
            Dictionary representing Celery beat schedule entry
        """
        entry = {
            "task": task.task,
            "enabled": task.enabled,
        }

        # Convert schedule based on type
        if task.schedule_type == ScheduleType.INTERVAL:
            if isinstance(task.schedule, dict):
                entry["schedule"] = schedule(**task.schedule)
            else:
                # Parse interval string (e.g., "5m", "1h", "30s")
                entry["schedule"] = self._parse_interval_string(task.schedule)

        elif task.schedule_type == ScheduleType.CRONTAB:
            if isinstance(task.schedule, str):
                # Parse crontab string
                entry["schedule"] = self._parse_crontab_string(task.schedule)
            else:
                entry["schedule"] = crontab(**task.schedule)

        # Add arguments
        if task.args:
            entry["args"] = task.args

        if task.kwargs:
            entry["kwargs"] = task.kwargs

        # Add options
        options = task.options or {}

        if task.priority != TaskPriority.NORMAL:
            options["priority"] = task.priority.value

        if task.routing_key:
            options["routing_key"] = task.routing_key

        if task.queue:
            options["queue"] = task.queue

        if task.expires:
            options["expires"] = task.expires

        if task.timeout != 3600:  # Default timeout
            options["time_limit"] = task.timeout

        if options:
            entry["options"] = options

        return entry

    def _parse_interval_string(self, interval_str: str) -> schedule:
        """
        Parse interval string to schedule object.

        Args:
            interval_str: Interval string (e.g., "5m", "1h", "30s")

        Returns:
            schedule object
        """
        import re

        pattern = r"^(\d+)([smhd])$"
        match = re.match(pattern, interval_str.lower())

        if not match:
            raise ValueError(f"Invalid interval format: {interval_str}")

        value, unit = match.groups()
        value = int(value)

        if unit == "s":
            return schedule(seconds=value)
        elif unit == "m":
            return schedule(minutes=value)
        elif unit == "h":
            return schedule(hours=value)
        elif unit == "d":
            return schedule(days=value)
        else:
            raise ValueError(f"Unsupported time unit: {unit}")

    def _parse_crontab_string(self, crontab_str: str) -> crontab:
        """
        Parse crontab string to crontab object.

        Args:
            crontab_str: Crontab string (e.g., "0 2 * * *")

        Returns:
            crontab object
        """
        parts = crontab_str.split()

        if len(parts) != 5:
            raise ValueError(f"Invalid crontab format: {crontab_str}")

        minute, hour, day_of_month, month_of_year, day_of_week = parts

        return crontab(
            minute=minute,
            hour=hour,
            day_of_month=day_of_month,
            month_of_year=month_of_year,
            day_of_week=day_of_week,
        )

    def get_beat_schedule(self) -> Dict[str, Dict[str, Any]]:
        """
        Get Celery beat schedule configuration.

        Returns:
            Dictionary of beat schedule entries
        """
        return {
            name: entry
            for name, entry in self._beat_schedule.items()
            if self.scheduled_tasks.get(name, ScheduledTask(name="", task="")).enabled
        }

    def list_scheduled_tasks(self) -> List[Dict[str, Any]]:
        """
        List all scheduled tasks with their details.

        Returns:
            List of task information dictionaries
        """
        task_list = []

        for name, task in self.scheduled_tasks.items():
            task_info = {
                "name": name,
                "task": task.task,
                "schedule": task.schedule,
                "schedule_type": task.schedule_type.value,
                "enabled": task.enabled,
                "description": task.description,
                "priority": task.priority.value,
                "queue": task.queue,
                "args": task.args,
                "kwargs": task.kwargs,
            }
            task_list.append(task_info)

        return task_list

    def schedule_one_time_task(
        self,
        task_name: str,
        eta: datetime,
        args: List[Any] = None,
        kwargs: Dict[str, Any] = None,
        **options,
    ):
        """
        Schedule a one-time task for execution at specific time.

        Args:
            task_name: Name of the task to schedule
            eta: When to execute the task
            args: Task arguments
            kwargs: Task keyword arguments
            **options: Additional Celery options
        """
        if not self.celery_app:
            raise ValueError("Celery app not configured")

        task = self.celery_app.send_task(
            task_name, args=args or [], kwargs=kwargs or {}, eta=eta, **options
        )

        logger.info(f"Scheduled one-time task {task_name} for {eta}")
        return task

    def schedule_delayed_task(
        self,
        task_name: str,
        countdown: int,
        args: List[Any] = None,
        kwargs: Dict[str, Any] = None,
        **options,
    ):
        """
        Schedule a task for execution after a delay.

        Args:
            task_name: Name of the task to schedule
            countdown: Delay in seconds
            args: Task arguments
            kwargs: Task keyword arguments
            **options: Additional Celery options
        """
        if not self.celery_app:
            raise ValueError("Celery app not configured")

        task = self.celery_app.send_task(
            task_name,
            args=args or [],
            kwargs=kwargs or {},
            countdown=countdown,
            **options,
        )

        logger.info(f"Scheduled delayed task {task_name} with {countdown}s delay")
        return task

    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """
        Get status of a scheduled task.

        Args:
            task_id: Task ID

        Returns:
            Task status information
        """
        if not self.celery_app:
            raise ValueError("Celery app not configured")

        result = self.celery_app.AsyncResult(task_id)

        return {
            "task_id": task_id,
            "status": result.status,
            "result": result.result,
            "traceback": result.traceback,
            "date_done": result.date_done,
        }

    def cancel_task(self, task_id: str):
        """
        Cancel a scheduled task.

        Args:
            task_id: Task ID to cancel
        """
        if not self.celery_app:
            raise ValueError("Celery app not configured")

        self.celery_app.control.revoke(task_id, terminate=True)
        logger.info(f"Cancelled task {task_id}")

    def export_schedule(self, file_path: str):
        """
        Export schedule configuration to file.

        Args:
            file_path: Path to export file
        """
        schedule_data = {
            "tasks": [
                {
                    "name": name,
                    "task": task.task,
                    "schedule": task.schedule,
                    "schedule_type": task.schedule_type.value,
                    "args": task.args,
                    "kwargs": task.kwargs,
                    "enabled": task.enabled,
                    "description": task.description,
                    "priority": task.priority.value,
                    "queue": task.queue,
                    "max_retries": task.max_retries,
                    "retry_delay": task.retry_delay,
                    "timeout": task.timeout,
                }
                for name, task in self.scheduled_tasks.items()
            ],
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }

        with open(file_path, "w") as f:
            json.dump(schedule_data, f, indent=2, default=str)

        logger.info(f"Exported schedule to {file_path}")

    def import_schedule(self, file_path: str):
        """
        Import schedule configuration from file.

        Args:
            file_path: Path to import file
        """
        with open(file_path, "r") as f:
            schedule_data = json.load(f)

        for task_data in schedule_data.get("tasks", []):
            task = ScheduledTask(
                name=task_data["name"],
                task=task_data["task"],
                schedule=task_data["schedule"],
                schedule_type=ScheduleType(task_data["schedule_type"]),
                args=task_data.get("args"),
                kwargs=task_data.get("kwargs"),
                enabled=task_data.get("enabled", True),
                description=task_data.get("description", ""),
                priority=TaskPriority(
                    task_data.get("priority", TaskPriority.NORMAL.value)
                ),
                queue=task_data.get("queue"),
                max_retries=task_data.get("max_retries", 3),
                retry_delay=task_data.get("retry_delay", 60),
                timeout=task_data.get("timeout", 3600),
            )

            self.add_scheduled_task(task)

        logger.info(f"Imported schedule from {file_path}")


# Global scheduler instance
_scheduler = TaskScheduler()


def get_scheduler() -> TaskScheduler:
    """Get the global task scheduler instance."""
    return _scheduler


def configure_scheduler(celery_app: Celery):
    """Configure the scheduler with Celery app."""
    _scheduler.celery_app = celery_app


def get_beat_schedule() -> Dict[str, Dict[str, Any]]:
    """Get Celery beat schedule configuration."""
    return _scheduler.get_beat_schedule()


# Convenience functions for common scheduling patterns


def schedule_pipeline_scan(
    pipeline_id: int, delay_minutes: int = 0, scanner_types: List[str] = None
):
    """
    Schedule a pipeline scan.

    Args:
        pipeline_id: ID of the pipeline to scan
        delay_minutes: Delay before starting scan
        scanner_types: List of scanner types to use
    """
    kwargs = {
        "pipeline_id": pipeline_id,
        "scanner_types": scanner_types
        or ["dependency", "secret", "container", "policy"],
    }

    if delay_minutes > 0:
        _scheduler.schedule_delayed_task(
            "secureops.tasks.scan_tasks.run_security_scan",
            countdown=delay_minutes * 60,
            kwargs=kwargs,
            queue="scan_queue",
        )
    else:
        _scheduler.celery_app.send_task(
            "secureops.tasks.scan_tasks.run_security_scan",
            kwargs=kwargs,
            queue="scan_queue",
        )


def schedule_continuous_monitoring(pipeline_id: int, interval_hours: int = 24):
    """
    Schedule continuous monitoring for a pipeline.

    Args:
        pipeline_id: ID of the pipeline to monitor
        interval_hours: Monitoring interval in hours
    """
    task_name = f"continuous_monitoring_pipeline_{pipeline_id}"

    monitoring_task = ScheduledTask(
        name=task_name,
        task="secureops.tasks.scan_tasks.continuous_monitoring_scan",
        schedule={"hours": interval_hours},
        schedule_type=ScheduleType.INTERVAL,
        args=[pipeline_id],
        description=f"Continuous monitoring for pipeline {pipeline_id}",
        priority=TaskPriority.NORMAL,
        queue="monitoring",
    )

    _scheduler.add_scheduled_task(monitoring_task)


def stop_continuous_monitoring(pipeline_id: int):
    """
    Stop continuous monitoring for a pipeline.

    Args:
        pipeline_id: ID of the pipeline
    """
    task_name = f"continuous_monitoring_pipeline_{pipeline_id}"
    _scheduler.remove_scheduled_task(task_name)


def schedule_alert_escalation(alert_id: int, escalation_level: int, delay_minutes: int):
    """
    Schedule alert escalation.

    Args:
        alert_id: ID of the alert
        escalation_level: Escalation level
        delay_minutes: Delay before escalation
    """
    _scheduler.schedule_delayed_task(
        "secureops.tasks.alert_tasks.escalate_alert",
        countdown=delay_minutes * 60,
        args=[alert_id, escalation_level],
        queue="alert_queue",
    )


# Task execution utilities


def execute_task_now(task_name: str, *args, **kwargs):
    """Execute a task immediately."""
    if _scheduler.celery_app:
        return _scheduler.celery_app.send_task(task_name, args=args, kwargs=kwargs)
    else:
        raise ValueError("Celery app not configured")
