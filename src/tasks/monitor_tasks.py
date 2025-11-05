<<<<<<< HEAD
# === STUBS FOR UNDEFINED HELPERS ===
import warnings

async def _process_health_alerts(*args, **kwargs):
    warnings.warn("_process_health_alerts is a stub and must be implemented.")

async def _process_scanner_alerts(*args, **kwargs):
    warnings.warn("_process_scanner_alerts is a stub and must be implemented.")

async def _handle_repository_changes(*args, **kwargs):
    warnings.warn("_handle_repository_changes is a stub and must be implemented.")

async def _store_performance_metrics(*args, **kwargs):
    warnings.warn("_store_performance_metrics is a stub and must be implemented.")

async def _process_dependency_alerts(*args, **kwargs):
    warnings.warn("_process_dependency_alerts is a stub and must be implemented.")

async def _process_integration_alerts(*args, **kwargs):
    warnings.warn("_process_integration_alerts is a stub and must be implemented.")

async def _check_single_pipeline_health(*args, **kwargs):
    warnings.warn("_check_single_pipeline_health is a stub and must be implemented.")
    return None

async def _scanner_health_check(*args, **kwargs):
    warnings.warn("_scanner_health_check is a stub and must be implemented.")
    return None

async def _get_repository_info(*args, **kwargs):
    warnings.warn("_get_repository_info is a stub and must be implemented.")
    return None

async def _get_last_scan_time(*args, **kwargs):
    warnings.warn("_get_last_scan_time is a stub and must be implemented.")
    return None

async def _get_commits_since(*args, **kwargs):
    warnings.warn("_get_commits_since is a stub and must be implemented.")
    return []

async def _check_critical_file_changes(*args, **kwargs):
    warnings.warn("_check_critical_file_changes is a stub and must be implemented.")
    return []

async def _collect_application_metrics(*args, **kwargs):
    warnings.warn("_collect_application_metrics is a stub and must be implemented.")
    return {}

async def _check_python_dependencies(*args, **kwargs):
    warnings.warn("_check_python_dependencies is a stub and must be implemented.")
    return {}

async def _check_node_dependencies(*args, **kwargs):
    warnings.warn("_check_node_dependencies is a stub and must be implemented.")
    return {}

async def _check_system_dependencies(*args, **kwargs):
    warnings.warn("_check_system_dependencies is a stub and must be implemented.")
    return {}

async def _check_single_integration_health(*args, **kwargs):
    warnings.warn("_check_single_integration_health is a stub and must be implemented.")
    return None
=======
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
"""
System Monitoring Background Tasks

This module contains Celery tasks for continuous system monitoring,
health checks, and performance metric collection.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import asyncio
import json
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil
import requests
<<<<<<< HEAD
from celery.utils.log import get_task_logger

from src.api.database import AsyncSessionLocal
from src.api.models.alert import Alert
from src.api.models.pipeline import Pipeline, ScanJob
from src.scanners.common import orchestrator
from src.api.utils.config import settings
from src.api.utils.logger import get_logger

# Use the centralized Celery app
from src.tasks.celery_app import app as celery_app
=======
from celery import Celery
from celery.utils.log import get_task_logger

from ..api.database import async_session
from ..api.models.alert import Alert
from ..api.models.pipeline import Pipeline, ScanJob
from ..scanners.common import orchestrator
from ..utils.config import settings
from ..utils.logger import get_logger

# Use the same Celery app from scan_tasks
from .scan_tasks import celery_app
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

logger = get_task_logger(__name__)


@celery_app.task(bind=True, name="secureops.tasks.monitor_tasks.system_health_check")
def system_health_check(self):
    """
    Perform comprehensive system health check.
    Monitors CPU, memory, disk usage, and service availability.
    """
    logger.info("Starting system health check")

    try:
        import asyncio

        health_status = asyncio.run(_perform_health_check())

        # Check if any alerts need to be raised
        asyncio.run(_process_health_alerts(health_status))

        logger.info(
            f"System health check completed - Status: {health_status['overall_status']}"
        )
        return health_status

    except Exception as e:
        logger.error(f"System health check failed: {str(e)}")
        raise


@celery_app.task(
    bind=True, name="secureops.tasks.monitor_tasks.pipeline_health_monitor"
)
def pipeline_health_monitor(self, pipeline_id: Optional[int] = None):
    """
    Monitor pipeline health and performance metrics.

    Args:
        pipeline_id: Optional specific pipeline to monitor, otherwise monitors all
    """
    logger.info(
        f"Starting pipeline health monitoring for pipeline {pipeline_id or 'all'}"
    )

    try:
        import asyncio

        results = asyncio.run(_monitor_pipeline_health(pipeline_id))

        logger.info(
            f"Pipeline health monitoring completed - Monitored {results['pipelines_checked']} pipelines"
        )
        return results

    except Exception as e:
        logger.error(f"Pipeline health monitoring failed: {str(e)}")
        raise


@celery_app.task(
    bind=True, name="secureops.tasks.monitor_tasks.scanner_availability_check"
)
def scanner_availability_check(self):
    """
    Check availability and health of all security scanners.
    """
    logger.info("Starting scanner availability check")

    try:
        import asyncio

        scanner_status = asyncio.run(_check_scanner_availability())

        # Process any scanner alerts
        asyncio.run(_process_scanner_alerts(scanner_status))

        logger.info(
            f"Scanner availability check completed - {scanner_status['available_count']}/{scanner_status['total_count']} scanners available"
        )
        return scanner_status

    except Exception as e:
        logger.error(f"Scanner availability check failed: {str(e)}")
        raise


@celery_app.task(bind=True, name="secureops.tasks.monitor_tasks.repository_monitor")
def repository_monitor(self, pipeline_id: int):
    """
    Monitor repository for changes that might trigger new scans.

    Args:
        pipeline_id: Pipeline ID to monitor
    """
    logger.info(f"Starting repository monitoring for pipeline {pipeline_id}")

    try:
        import asyncio

        changes = asyncio.run(_monitor_repository_changes(pipeline_id))

        if changes["has_changes"]:
            logger.info(f"Repository changes detected for pipeline {pipeline_id}")
            # Trigger new scan if significant changes detected
            asyncio.run(_handle_repository_changes(pipeline_id, changes))

        return changes

    except Exception as e:
        logger.error(
            f"Repository monitoring failed for pipeline {pipeline_id}: {str(e)}"
        )
        raise


@celery_app.task(
    bind=True, name="secureops.tasks.monitor_tasks.performance_metrics_collection"
)
def performance_metrics_collection(self):
    """
    Collect and store system performance metrics.
    """
    logger.info("Starting performance metrics collection")

    try:
        import asyncio

        metrics = asyncio.run(_collect_performance_metrics())

        # Store metrics in database or monitoring system
        asyncio.run(_store_performance_metrics(metrics))

        logger.info("Performance metrics collection completed")
        return {
            "status": "completed",
            "metrics_collected": len(metrics),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Performance metrics collection failed: {str(e)}")
        raise


@celery_app.task(
    bind=True, name="secureops.tasks.monitor_tasks.dependency_freshness_check"
)
def dependency_freshness_check(self):
    """
    Check for outdated dependencies and security updates.
    """
    logger.info("Starting dependency freshness check")

    try:
        import asyncio

        results = asyncio.run(_check_dependency_freshness())

        # Process alerts for critical updates
        asyncio.run(_process_dependency_alerts(results))

        logger.info(
            f"Dependency freshness check completed - {results['outdated_count']} outdated dependencies found"
        )
        return results

    except Exception as e:
        logger.error(f"Dependency freshness check failed: {str(e)}")
        raise


@celery_app.task(
    bind=True, name="secureops.tasks.monitor_tasks.integration_health_check"
)
def integration_health_check(self):
    """
    Check health of external integrations (CI/CD systems, notification services).
    """
    logger.info("Starting integration health check")

    try:
        import asyncio

        integration_status = asyncio.run(_check_integration_health())

        # Process integration alerts
        asyncio.run(_process_integration_alerts(integration_status))

        logger.info(
            f"Integration health check completed - {integration_status['healthy_count']}/{integration_status['total_count']} integrations healthy"
        )
        return integration_status

    except Exception as e:
        logger.error(f"Integration health check failed: {str(e)}")
        raise


# Implementation functions


async def _perform_health_check() -> Dict[str, Any]:
    """Perform comprehensive system health check."""
    health_status = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_status": "healthy",
        "components": {},
    }

    try:
        # Check system resources
        health_status["components"]["system"] = await _check_system_resources()

        # Check database connectivity
        health_status["components"]["database"] = await _check_database_health()

        # Check Redis/Celery broker
        health_status["components"]["broker"] = await _check_broker_health()

        # Check disk space
        health_status["components"]["storage"] = await _check_storage_health()

        # Check external services
        health_status["components"][
            "external_services"
        ] = await _check_external_services()

        # Determine overall status
        component_statuses = [
            comp["status"] for comp in health_status["components"].values()
        ]
        if "critical" in component_statuses:
            health_status["overall_status"] = "critical"
        elif "warning" in component_statuses:
            health_status["overall_status"] = "warning"
        else:
            health_status["overall_status"] = "healthy"

        return health_status

    except Exception as e:
        health_status["overall_status"] = "critical"
        health_status["error"] = str(e)
        return health_status


async def _monitor_pipeline_health(pipeline_id: Optional[int]) -> Dict[str, Any]:
    """Monitor health of pipelines."""
    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pipelines_checked": 0,
        "healthy_pipelines": 0,
        "unhealthy_pipelines": 0,
        "pipeline_details": [],
    }

    try:
<<<<<<< HEAD
        async with AsyncSessionLocal() as db:
=======
        async with async_session() as db:
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
            from sqlalchemy import select

            # Get pipelines to check
            if pipeline_id:
                query = select(Pipeline).where(Pipeline.id == pipeline_id)
            else:
                query = select(Pipeline).where(Pipeline.is_active == True)

            result = await db.execute(query)
            pipelines = result.scalars().all()

            results["pipelines_checked"] = len(pipelines)

            for pipeline in pipelines:
                pipeline_health = await _check_single_pipeline_health(pipeline)
                results["pipeline_details"].append(pipeline_health)

                if pipeline_health["status"] == "healthy":
                    results["healthy_pipelines"] += 1
                else:
                    results["unhealthy_pipelines"] += 1

        return results

    except Exception as e:
        results["error"] = str(e)
        return results


async def _check_scanner_availability() -> Dict[str, Any]:
    """Check availability of all security scanners."""
    scanner_status = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_count": 0,
        "available_count": 0,
        "unavailable_count": 0,
        "scanner_details": [],
    }

    try:
        # Get all available scanners from orchestrator
        available_scanners = orchestrator.get_available_scanners()
        scanner_status["total_count"] = len(available_scanners)

        for scanner_type in available_scanners:
            scanner = orchestrator.get_scanner(scanner_type)

            scanner_health = {
                "type": scanner_type.value,
                "status": "unknown",
                "response_time": None,
                "error": None,
            }

            try:
                start_time = datetime.now()

                # Try to perform a simple health check on the scanner
                health_check_result = await _scanner_health_check(scanner)

                end_time = datetime.now()
                scanner_health["response_time"] = (
                    end_time - start_time
                ).total_seconds()

                if health_check_result:
                    scanner_health["status"] = "available"
                    scanner_status["available_count"] += 1
                else:
                    scanner_health["status"] = "unavailable"
                    scanner_status["unavailable_count"] += 1

            except Exception as e:
                scanner_health["status"] = "unavailable"
                scanner_health["error"] = str(e)
                scanner_status["unavailable_count"] += 1

            scanner_status["scanner_details"].append(scanner_health)

        return scanner_status

    except Exception as e:
        scanner_status["error"] = str(e)
        return scanner_status


async def _monitor_repository_changes(pipeline_id: int) -> Dict[str, Any]:
    """Monitor repository for changes."""
    changes = {
        "pipeline_id": pipeline_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "has_changes": False,
        "changes_detected": [],
        "last_commit": None,
        "files_changed": 0,
    }

    try:
<<<<<<< HEAD
        async with AsyncSessionLocal() as db:
=======
        async with async_session() as db:
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
            pipeline = await db.get(Pipeline, pipeline_id)
            if not pipeline or not pipeline.repository_url:
                return changes

            # Get repository information
            repo_info = await _get_repository_info(pipeline.repository_url)

            # Check if there are new commits since last scan
            last_scan_time = await _get_last_scan_time(pipeline_id)
            new_commits = await _get_commits_since(
                pipeline.repository_url, last_scan_time
            )

            if new_commits:
                changes["has_changes"] = True
                changes["changes_detected"] = new_commits
                changes["last_commit"] = new_commits[0] if new_commits else None
                changes["files_changed"] = sum(
                    commit.get("files_changed", 0) for commit in new_commits
                )

            # Check for critical file changes (security configs, dependencies)
            critical_changes = await _check_critical_file_changes(new_commits)
            changes["critical_changes"] = critical_changes

        return changes

    except Exception as e:
        changes["error"] = str(e)
        return changes


async def _collect_performance_metrics() -> List[Dict[str, Any]]:
    """Collect system performance metrics."""
    metrics = []
    timestamp = datetime.now(timezone.utc)

    try:
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()

        metrics.append(
            {
                "metric": "cpu_usage_percent",
                "value": cpu_percent,
                "timestamp": timestamp,
                "metadata": {"cpu_count": cpu_count},
            }
        )

        # Memory metrics
        memory = psutil.virtual_memory()
        metrics.append(
            {
                "metric": "memory_usage_percent",
                "value": memory.percent,
                "timestamp": timestamp,
                "metadata": {
                    "total": memory.total,
                    "available": memory.available,
                    "used": memory.used,
                },
            }
        )

        # Disk metrics
        disk = psutil.disk_usage("/")
        metrics.append(
            {
                "metric": "disk_usage_percent",
                "value": (disk.used / disk.total) * 100,
                "timestamp": timestamp,
                "metadata": {"total": disk.total, "used": disk.used, "free": disk.free},
            }
        )

        # Network metrics
        network = psutil.net_io_counters()
        metrics.append(
            {
                "metric": "network_bytes_sent",
                "value": network.bytes_sent,
                "timestamp": timestamp,
            }
        )

        metrics.append(
            {
                "metric": "network_bytes_recv",
                "value": network.bytes_recv,
                "timestamp": timestamp,
            }
        )

        # Process metrics
        process_count = len(psutil.pids())
        metrics.append(
            {"metric": "process_count", "value": process_count, "timestamp": timestamp}
        )

        # Application-specific metrics
        app_metrics = await _collect_application_metrics()
        metrics.extend(app_metrics)

        return metrics

    except Exception as e:
        logger.error(f"Error collecting performance metrics: {str(e)}")
        return metrics


async def _check_dependency_freshness() -> Dict[str, Any]:
    """Check for outdated dependencies."""
    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_dependencies": 0,
        "outdated_count": 0,
        "critical_updates": 0,
        "outdated_dependencies": [],
    }

    try:
        # Check Python dependencies
        python_deps = await _check_python_dependencies()

        # Check Node.js dependencies (if applicable)
        node_deps = await _check_node_dependencies()

        # Check system dependencies
        system_deps = await _check_system_dependencies()

        all_deps = python_deps + node_deps + system_deps

        results["total_dependencies"] = len(all_deps)
        results["outdated_dependencies"] = [
            dep for dep in all_deps if dep["is_outdated"]
        ]
        results["outdated_count"] = len(results["outdated_dependencies"])
        results["critical_updates"] = len(
            [
                dep
                for dep in results["outdated_dependencies"]
                if dep.get("has_security_update")
            ]
        )

        return results

    except Exception as e:
        results["error"] = str(e)
        return results


async def _check_integration_health() -> Dict[str, Any]:
    """Check health of external integrations."""
    integration_status = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_count": 0,
        "healthy_count": 0,
        "unhealthy_count": 0,
        "integration_details": [],
    }

    try:
        # Define integrations to check
        integrations_to_check = [
            {
                "name": "GitHub API",
                "endpoint": "https://api.github.com/user",
                "type": "github",
            },
            {
                "name": "GitLab API",
                "endpoint": "https://gitlab.com/api/v4/user",
                "type": "gitlab",
            },
            {
                "name": "Azure DevOps",
                "endpoint": settings.AZURE_DEVOPS_URL,
                "type": "azure",
            },
            {"name": "Jenkins", "endpoint": settings.JENKINS_URL, "type": "jenkins"},
            {
                "name": "Slack Webhook",
                "endpoint": settings.SLACK_WEBHOOK_URL,
                "type": "slack",
            },
        ]

        integration_status["total_count"] = len(integrations_to_check)

        for integration in integrations_to_check:
            if not integration["endpoint"]:
                continue

            health = await _check_single_integration_health(integration)
            integration_status["integration_details"].append(health)

            if health["status"] == "healthy":
                integration_status["healthy_count"] += 1
            else:
                integration_status["unhealthy_count"] += 1

        return integration_status

    except Exception as e:
        integration_status["error"] = str(e)
        return integration_status


# Helper functions


async def _check_system_resources() -> Dict[str, Any]:
    """Check system resource usage."""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()

        status = "healthy"
        if cpu_percent > 90 or memory.percent > 95:
            status = "critical"
        elif cpu_percent > 80 or memory.percent > 85:
            status = "warning"

        return {
            "status": status,
            "cpu_usage": cpu_percent,
            "memory_usage": memory.percent,
            "details": f"CPU: {cpu_percent}%, Memory: {memory.percent}%",
        }

    except Exception as e:
        return {"status": "critical", "error": str(e)}


async def _check_database_health() -> Dict[str, Any]:
    """Check database connectivity and health."""
    try:
<<<<<<< HEAD
        async with AsyncSessionLocal() as db:
=======
        async with async_session() as db:
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
            # Simple query to test connectivity
            from sqlalchemy import text

            result = await db.execute(text("SELECT 1"))

            return {"status": "healthy", "details": "Database connection successful"}

    except Exception as e:
        return {
            "status": "critical",
            "error": str(e),
            "details": "Database connection failed",
        }


async def _check_broker_health() -> Dict[str, Any]:
    """Check Redis/Celery broker health."""
    try:
        # Try to inspect Celery workers
        inspect = celery_app.control.inspect()
        stats = inspect.stats()

        if stats:
            worker_count = len(stats)
            return {
                "status": "healthy",
                "details": f"{worker_count} workers active",
                "worker_count": worker_count,
            }
        else:
            return {"status": "warning", "details": "No active workers found"}

    except Exception as e:
        return {
            "status": "critical",
            "error": str(e),
            "details": "Broker connection failed",
        }


async def _check_storage_health() -> Dict[str, Any]:
    """Check storage/disk space health."""
    try:
        disk = psutil.disk_usage("/")
        usage_percent = (disk.used / disk.total) * 100

        status = "healthy"
        if usage_percent > 95:
            status = "critical"
        elif usage_percent > 85:
            status = "warning"

        return {
            "status": status,
            "usage_percent": usage_percent,
            "free_space_gb": disk.free / (1024**3),
            "details": f"Disk usage: {usage_percent:.1f}%",
        }

    except Exception as e:
        return {"status": "critical", "error": str(e)}


async def _check_external_services() -> Dict[str, Any]:
    """Check connectivity to external services."""
    services = [
        {"name": "Internet connectivity", "url": "https://8.8.8.8", "timeout": 5},
        {"name": "Package repositories", "url": "https://pypi.org", "timeout": 10},
    ]

    healthy_count = 0
    total_count = len(services)

    for service in services:
        try:
            response = requests.get(service["url"], timeout=service["timeout"])
            if response.status_code < 400:
                healthy_count += 1
        except Exception:
            pass

    status = (
        "healthy"
        if healthy_count == total_count
        else "warning" if healthy_count > 0 else "critical"
    )

    return {
        "status": status,
        "healthy_services": healthy_count,
        "total_services": total_count,
        "details": f"{healthy_count}/{total_count} external services reachable",
    }


# Additional utility functions would be implemented here...
# _process_health_alerts, _scanner_health_check, etc.
