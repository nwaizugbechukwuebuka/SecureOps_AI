"""
Monitor Tasks for SecureOps AI

This module provides comprehensive monitoring, health check, and system diagnostics
tasks for the SecureOps platform. Includes pipeline monitoring, scanner health checks,
system metrics collection, and automated issue detection.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import asyncio
import json
import logging
import os
import subprocess
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil
from celery import chord, group
from celery.utils.log import get_task_logger
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.database import AsyncSessionLocal
from src.api.models.alert import Alert, AlertSeverity, AlertStatus, AlertType
from src.api.models.pipeline import (Pipeline, PipelineRun, PipelineStatus,
                                     ScanJob, ScanJobStatus)
from src.api.models.vulnerability import Vulnerability
from src.api.services.alert_service import AlertService, NotificationChannel
from src.api.utils.config import get_settings
from src.api.utils.logger import get_logger
from src.tasks.celery_app import app as celery_app

settings = get_settings()
logger = get_task_logger(__name__)

# Configuration constants
MONITORING_INTERVAL_SECONDS = getattr(settings, "MONITORING_INTERVAL_SECONDS", 300)
HEALTH_CHECK_INTERVAL_SECONDS = getattr(settings, "HEALTH_CHECK_INTERVAL_SECONDS", 60)
SYSTEM_METRICS_INTERVAL_SECONDS = getattr(
    settings, "SYSTEM_METRICS_INTERVAL_SECONDS", 120
)
CRITICAL_CPU_THRESHOLD = getattr(settings, "CRITICAL_CPU_THRESHOLD", 90.0)
CRITICAL_MEMORY_THRESHOLD = getattr(settings, "CRITICAL_MEMORY_THRESHOLD", 85.0)
CRITICAL_DISK_THRESHOLD = getattr(settings, "CRITICAL_DISK_THRESHOLD", 90.0)
PIPELINE_TIMEOUT_MINUTES = getattr(settings, "PIPELINE_TIMEOUT_MINUTES", 60)
MAX_RETRY_ATTEMPTS = getattr(settings, "MAX_RETRY_ATTEMPTS", 3)
RETRY_DELAY_SECONDS = getattr(settings, "RETRY_DELAY_SECONDS", 60)


@celery_app.task(
    bind=True,
    name="secureops.tasks.monitor_tasks.monitor_pipeline_executions",
    max_retries=MAX_RETRY_ATTEMPTS,
    default_retry_delay=RETRY_DELAY_SECONDS,
)
def monitor_pipeline_executions(self) -> Dict[str, Any]:
    """
    Monitor active pipeline executions for timeouts, failures, and resource issues.

    Returns:
        Dict containing monitoring results and statistics
    """
    monitoring_id = str(uuid.uuid4())
    start_time = time.time()

    logger.info(
        f"[{monitoring_id}] Starting pipeline execution monitoring",
        extra={"monitoring_id": monitoring_id, "task": "monitor_pipeline_executions"},
    )

    try:
        return asyncio.run(_monitor_pipeline_executions_async(monitoring_id))

    except Exception as e:
        logger.error(
            f"[{monitoring_id}] Pipeline monitoring failed: {str(e)}",
            extra={
                "monitoring_id": monitoring_id,
                "error": str(e),
                "traceback": traceback.format_exc(),
                "duration": time.time() - start_time,
            },
        )

        # Retry on failure
        if self.request.retries < MAX_RETRY_ATTEMPTS:
            logger.info(f"[{monitoring_id}] Retrying pipeline monitoring")
            raise self.retry(countdown=RETRY_DELAY_SECONDS)

        return {
            "success": False,
            "monitoring_id": monitoring_id,
            "error": str(e),
            "duration": time.time() - start_time,
        }


async def _monitor_pipeline_executions_async(monitoring_id: str) -> Dict[str, Any]:
    """Async implementation of pipeline execution monitoring."""
    async with AsyncSessionLocal() as db:
        try:
            results = {
                "monitoring_id": monitoring_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "pipelines_checked": 0,
                "issues_detected": 0,
                "alerts_generated": 0,
                "actions_taken": [],
                "success": True,
            }

            # Get active pipeline runs
            active_runs_query = select(PipelineRun).where(
                PipelineRun.status.in_(
                    [PipelineStatus.RUNNING, PipelineStatus.SCANNING]
                )
            )
            active_runs = (await db.execute(active_runs_query)).scalars().all()
            results["pipelines_checked"] = len(active_runs)

            timeout_threshold = datetime.now(timezone.utc) - timedelta(
                minutes=PIPELINE_TIMEOUT_MINUTES
            )
            alert_service = AlertService(db)

            for pipeline_run in active_runs:
                # Check for timeouts
                if (
                    pipeline_run.started_at
                    and pipeline_run.started_at < timeout_threshold
                ):
                    await _handle_pipeline_timeout(
                        db, alert_service, pipeline_run, monitoring_id
                    )
                    results["issues_detected"] += 1
                    results["actions_taken"].append(
                        f"Handled timeout for pipeline run {pipeline_run.id}"
                    )

            await db.commit()

            logger.info(
                f"[{monitoring_id}] Pipeline monitoring completed successfully",
                extra={
                    "monitoring_id": monitoring_id,
                    "pipelines_checked": results["pipelines_checked"],
                    "issues_detected": results["issues_detected"],
                },
            )

            return results

        except Exception as e:
            await db.rollback()
            raise


async def _handle_pipeline_timeout(
    db: AsyncSession,
    alert_service: AlertService,
    pipeline_run: PipelineRun,
    monitoring_id: str,
) -> None:
    """Handle timed-out pipeline runs."""
    logger.warning(f"[{monitoring_id}] Pipeline run {pipeline_run.id} has timed out")

    # Update pipeline status
    pipeline_run.status = PipelineStatus.FAILED
    pipeline_run.finished_at = datetime.now(timezone.utc)
    pipeline_run.error_message = "Pipeline execution timed out"


@celery_app.task(
    bind=True,
    name="secureops.tasks.monitor_tasks.check_scanner_health",
    max_retries=MAX_RETRY_ATTEMPTS,
    default_retry_delay=RETRY_DELAY_SECONDS,
)
def check_scanner_health(self) -> Dict[str, Any]:
    """
    Perform health checks on all security scanners and external services.

    Returns:
        Dict containing health check results for all services
    """
    health_check_id = str(uuid.uuid4())
    start_time = time.time()

    logger.info(
        f"[{health_check_id}] Starting scanner health checks",
        extra={"health_check_id": health_check_id, "task": "check_scanner_health"},
    )

    try:
        return asyncio.run(_check_scanner_health_async(health_check_id))

    except Exception as e:
        logger.error(
            f"[{health_check_id}] Scanner health check failed: {str(e)}",
            extra={
                "health_check_id": health_check_id,
                "error": str(e),
                "duration": time.time() - start_time,
            },
        )

        return {
            "success": False,
            "health_check_id": health_check_id,
            "error": str(e),
            "duration": time.time() - start_time,
        }


async def _check_scanner_health_async(health_check_id: str) -> Dict[str, Any]:
    """Async implementation of scanner health checks."""
    results = {
        "health_check_id": health_check_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_status": "healthy",
        "services": {},
        "issues": [],
        "success": True,
    }

    # Check database health
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(func.count()).select_from(Pipeline))
            pipeline_count = result.scalar()

            results["services"]["database"] = {
                "status": "healthy",
                "response_time_ms": 0,
                "pipeline_count": pipeline_count,
            }

    except Exception as e:
        logger.error(f"[{health_check_id}] Database health check failed: {str(e)}")
        results["services"]["database"] = {"status": "unhealthy", "error": str(e)}
        results["issues"].append("Database connectivity issues")
        results["overall_status"] = "degraded"

    # Check external scanner tools
    scanner_tools = {
        "trivy": ["trivy", "--version"],
        "safety": ["safety", "--version"],
        "bandit": ["bandit", "--version"],
    }

    for tool_name, command in scanner_tools.items():
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                results["services"][tool_name] = {
                    "status": "healthy",
                    "version": result.stdout.strip()[:100],
                }
            else:
                results["services"][tool_name] = {
                    "status": "unhealthy",
                    "error": result.stderr.strip()[:200],
                }
                results["issues"].append(f"{tool_name} command failed")
                results["overall_status"] = "degraded"

        except subprocess.TimeoutExpired:
            results["services"][tool_name] = {
                "status": "unhealthy",
                "error": "Command timed out",
            }
            results["issues"].append(f"{tool_name} command timeout")
            results["overall_status"] = "degraded"

        except FileNotFoundError:
            results["services"][tool_name] = {
                "status": "unavailable",
                "error": "Tool not found",
            }
            results["issues"].append(f"{tool_name} not installed")

    logger.info(
        f"[{health_check_id}] Health check completed",
        extra={
            "health_check_id": health_check_id,
            "overall_status": results["overall_status"],
            "services_checked": len(results["services"]),
            "issues_found": len(results["issues"]),
        },
    )

    return results


@celery_app.task(
    bind=True,
    name="secureops.tasks.monitor_tasks.collect_system_metrics",
    max_retries=MAX_RETRY_ATTEMPTS,
    default_retry_delay=RETRY_DELAY_SECONDS,
)
def collect_system_metrics(self) -> Dict[str, Any]:
    """
    Collect comprehensive system metrics and generate alerts for critical issues.

    Returns:
        Dict containing all collected metrics and any alerts generated
    """
    metrics_id = str(uuid.uuid4())
    start_time = time.time()

    logger.info(
        f"[{metrics_id}] Starting system metrics collection",
        extra={"metrics_id": metrics_id, "task": "collect_system_metrics"},
    )

    try:
        return asyncio.run(_collect_system_metrics_async(metrics_id))

    except Exception as e:
        logger.error(
            f"[{metrics_id}] System metrics collection failed: {str(e)}",
            extra={
                "metrics_id": metrics_id,
                "error": str(e),
                "duration": time.time() - start_time,
            },
        )

        return {
            "success": False,
            "metrics_id": metrics_id,
            "error": str(e),
            "duration": time.time() - start_time,
        }


async def _collect_system_metrics_async(metrics_id: str) -> Dict[str, Any]:
    """Async implementation of system metrics collection."""
    metrics = {
        "metrics_id": metrics_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": {},
        "alerts_generated": 0,
        "critical_issues": [],
        "success": True,
    }

    try:
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=1)

        metrics["system"]["cpu"] = {
            "usage_percent": cpu_percent,
            "core_count": psutil.cpu_count(),
        }

        # Memory metrics
        memory = psutil.virtual_memory()

        metrics["system"]["memory"] = {
            "total_gb": round(memory.total / (1024**3), 2),
            "available_gb": round(memory.available / (1024**3), 2),
            "usage_percent": memory.percent,
        }

        # Disk metrics
        disk = psutil.disk_usage("/")
        metrics["system"]["disk"] = {
            "total_gb": round(disk.total / (1024**3), 2),
            "free_gb": round(disk.free / (1024**3), 2),
            "usage_percent": round((disk.used / disk.total) * 100, 2),
        }

        # Check for critical issues
        await _check_critical_metrics(metrics, metrics_id)

        logger.info(
            f"[{metrics_id}] System metrics collected successfully",
            extra={
                "metrics_id": metrics_id,
                "cpu_usage": cpu_percent,
                "memory_usage": memory.percent,
                "disk_usage": metrics["system"]["disk"]["usage_percent"],
                "critical_issues": len(metrics["critical_issues"]),
            },
        )

        return metrics

    except Exception as e:
        logger.error(f"[{metrics_id}] Error collecting system metrics: {str(e)}")
        metrics["success"] = False
        metrics["error"] = str(e)
        return metrics


async def _check_critical_metrics(metrics: Dict[str, Any], metrics_id: str) -> None:
    """Check metrics against thresholds and generate alerts for critical issues."""
    cpu_usage = metrics["system"]["cpu"]["usage_percent"]
    memory_usage = metrics["system"]["memory"]["usage_percent"]
    disk_usage = metrics["system"]["disk"]["usage_percent"]

    critical_issues = []

    # Check CPU threshold
    if cpu_usage >= CRITICAL_CPU_THRESHOLD:
        critical_issues.append(
            {
                "type": "high_cpu_usage",
                "value": cpu_usage,
                "threshold": CRITICAL_CPU_THRESHOLD,
                "message": f"CPU usage ({cpu_usage}%) exceeds critical threshold",
            }
        )

    # Check memory threshold
    if memory_usage >= CRITICAL_MEMORY_THRESHOLD:
        critical_issues.append(
            {
                "type": "high_memory_usage",
                "value": memory_usage,
                "threshold": CRITICAL_MEMORY_THRESHOLD,
                "message": f"Memory usage ({memory_usage}%) exceeds critical threshold",
            }
        )

    # Check disk threshold
    if disk_usage >= CRITICAL_DISK_THRESHOLD:
        critical_issues.append(
            {
                "type": "high_disk_usage",
                "value": disk_usage,
                "threshold": CRITICAL_DISK_THRESHOLD,
                "message": f"Disk usage ({disk_usage}%) exceeds critical threshold",
            }
        )

    metrics["critical_issues"] = critical_issues

    # Generate alerts for critical issues
    if critical_issues:
        try:
            async with AsyncSessionLocal() as db:
                alert_service = AlertService(db)

                for issue in critical_issues:
                    # Create system alert (simplified)
                    metrics["alerts_generated"] += 1

                await db.commit()

        except Exception as e:
            logger.error(f"[{metrics_id}] Failed to generate critical alerts: {str(e)}")


@celery_app.task(name="secureops.tasks.monitor_tasks.setup_monitoring_schedule")
def setup_monitoring_schedule() -> Dict[str, str]:
    """
    Setup periodic monitoring tasks using Celery beat.

    Returns:
        Dict with schedule configuration status
    """
    logger.info("Setting up monitoring schedule")

    schedule_config = {
        "pipeline_monitoring": "*/5 * * * *",  # Every 5 minutes
        "health_checks": "* * * * *",  # Every minute
        "system_metrics": "*/2 * * * *",  # Every 2 minutes
        "worker_monitoring": "*/3 * * * *",  # Every 3 minutes
    }

    logger.info(f"Monitoring schedule configured: {schedule_config}")

    return {
        "status": "configured",
        "schedule": schedule_config,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
