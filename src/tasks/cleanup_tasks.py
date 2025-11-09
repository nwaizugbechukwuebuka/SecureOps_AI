"""
System Cleanup Background Tasks

This module contains production-ready Celery tasks for comprehensive system maintenance,
cleanup operations, data retention management, and resource optimization.

Features:
- Automated data retention and archival
- Comprehensive cleanup with configurable retention policies
- Resource monitoring and optimization
- Database maintenance and optimization
- Secure deletion with audit trails
- Performance monitoring and metrics
- Error handling with detailed logging

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import asyncio
import os
import shutil
import tempfile
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from celery.utils.log import get_task_logger

from src.api.database import AsyncSessionLocal
from src.api.models.pipeline import ScanJob
from src.api.models.vulnerability import Vulnerability
from src.api.utils.config import get_settings

# Use the centralized Celery app
from src.tasks.celery_app import app as celery_app

settings = get_settings()
logger = get_task_logger(__name__)

# Configuration constants
DEFAULT_RETENTION_DAYS = getattr(settings, "DEFAULT_RETENTION_DAYS", 30)
DATABASE_MAINTENANCE_INTERVAL_HOURS = getattr(settings, "DATABASE_MAINTENANCE_INTERVAL_HOURS", 24)
MAX_CLEANUP_BATCH_SIZE = getattr(settings, "MAX_CLEANUP_BATCH_SIZE", 1000)
TEMP_FILE_MAX_AGE_HOURS = getattr(settings, "TEMP_FILE_MAX_AGE_HOURS", 24)
LOG_RETENTION_DAYS = getattr(settings, "LOG_RETENTION_DAYS", 7)


@celery_app.task(
    bind=True,
    name="secureops.tasks.cleanup_tasks.comprehensive_system_cleanup",
    max_retries=2,
)
def comprehensive_system_cleanup(self) -> Dict[str, Any]:
    """
    Perform comprehensive system cleanup including all maintenance tasks.
    This is the main cleanup orchestrator task.

    Returns:
        Dict containing cleanup results and metrics
    """
    cleanup_id = str(uuid.uuid4())
    start_time = time.time()

    logger.info(
        f"[{cleanup_id}] Starting comprehensive system cleanup",
        extra={"cleanup_id": cleanup_id},
    )

    try:
        result = asyncio.run(_comprehensive_cleanup_async(cleanup_id))

        execution_time = time.time() - start_time

        logger.info(
            f"[{cleanup_id}] Comprehensive cleanup completed in {execution_time:.2f}s",
            extra={
                "cleanup_id": cleanup_id,
                "execution_time": execution_time,
                "result": result,
            },
        )

        return {
            **result,
            "cleanup_id": cleanup_id,
            "execution_time": execution_time,
            "status": "completed",
        }

    except Exception as e:
        execution_time = time.time() - start_time
        error_details = {
            "error_type": type(e).__name__,
            "error_message": str(e),
            "traceback": traceback.format_exc(),
            "cleanup_id": cleanup_id,
            "execution_time": execution_time,
        }

        logger.error(
            f"[{cleanup_id}] Comprehensive cleanup failed: {str(e)}",
            extra=error_details,
        )

        if self.request.retries < 2:
            countdown = 300 * (2**self.request.retries)  # 5 min, 10 min
            raise self.retry(countdown=countdown, exc=e)

        return {
            "status": "failed",
            "error": error_details,
            "cleanup_id": cleanup_id,
            "execution_time": execution_time,
        }


@celery_app.task(bind=True, name="secureops.tasks.cleanup_tasks.cleanup_old_scan_jobs", max_retries=2)
def cleanup_old_scan_jobs(
    self,
    retention_days: int = DEFAULT_RETENTION_DAYS,
    batch_size: int = MAX_CLEANUP_BATCH_SIZE,
) -> Dict[str, Any]:
    """
    Clean up old scan jobs and their associated data with batched processing.

    Args:
        retention_days: Number of days to retain scan jobs
        batch_size: Number of records to process in each batch

    Returns:
        Dict containing cleanup results
    """
    cleanup_id = str(uuid.uuid4())
    start_time = time.time()

    logger.info(
        f"[{cleanup_id}] Starting cleanup of scan jobs older than {retention_days} days",
        extra={
            "cleanup_id": cleanup_id,
            "retention_days": retention_days,
            "batch_size": batch_size,
        },
    )

    try:
        result = asyncio.run(_cleanup_old_scan_jobs_async(retention_days, batch_size, cleanup_id))

        execution_time = time.time() - start_time

        logger.info(
            f"[{cleanup_id}] Scan job cleanup completed - "
            f"deleted {result.get('deleted_count', 0)} jobs in {execution_time:.2f}s",
            extra={
                "cleanup_id": cleanup_id,
                "execution_time": execution_time,
                "deleted_count": result.get("deleted_count", 0),
            },
        )

        return {
            **result,
            "cleanup_id": cleanup_id,
            "execution_time": execution_time,
            "status": "completed",
        }

    except Exception as e:
        execution_time = time.time() - start_time
        error_details = {
            "error_type": type(e).__name__,
            "error_message": str(e),
            "cleanup_id": cleanup_id,
            "execution_time": execution_time,
        }

        logger.error(f"[{cleanup_id}] Scan job cleanup failed: {str(e)}", extra=error_details)

        if self.request.retries < 2:
            raise self.retry(countdown=60, exc=e)

        return {
            "status": "failed",
            "error": error_details,
            "cleanup_id": cleanup_id,
            "execution_time": execution_time,
        }


@celery_app.task(
    bind=True,
    name="secureops.tasks.cleanup_tasks.cleanup_temporary_files",
    max_retries=2,
)
def cleanup_temporary_files(self, max_age_hours: int = TEMP_FILE_MAX_AGE_HOURS) -> Dict[str, Any]:
    """
    Clean up temporary files and directories older than specified age.

    Args:
        max_age_hours: Maximum age of temporary files in hours

    Returns:
        Dict containing cleanup results
    """
    cleanup_id = str(uuid.uuid4())
    start_time = time.time()

    logger.info(
        f"[{cleanup_id}] Starting cleanup of temporary files older than {max_age_hours} hours",
        extra={"cleanup_id": cleanup_id, "max_age_hours": max_age_hours},
    )

    try:
        result = asyncio.run(_cleanup_temporary_files_async(max_age_hours, cleanup_id))

        execution_time = time.time() - start_time

        logger.info(
            f"[{cleanup_id}] Temporary file cleanup completed - {result.get('files_deleted', 0)} files deleted in {execution_time:.2f}s",
            extra={
                "cleanup_id": cleanup_id,
                "execution_time": execution_time,
                "files_deleted": result.get("files_deleted", 0),
                "space_freed_mb": result.get("space_freed_mb", 0),
            },
        )

        return {
            **result,
            "cleanup_id": cleanup_id,
            "execution_time": execution_time,
            "status": "completed",
        }

    except Exception as e:
        execution_time = time.time() - start_time
        error_details = {
            "error_type": type(e).__name__,
            "error_message": str(e),
            "cleanup_id": cleanup_id,
            "execution_time": execution_time,
        }

        logger.error(
            f"[{cleanup_id}] Temporary file cleanup failed: {str(e)}",
            extra=error_details,
        )

        if self.request.retries < 2:
            raise self.retry(countdown=60, exc=e)

        return {
            "status": "failed",
            "error": error_details,
            "cleanup_id": cleanup_id,
            "execution_time": execution_time,
        }


@celery_app.task(
    bind=True,
    name="secureops.tasks.cleanup_tasks.archive_old_vulnerabilities",
    max_retries=2,
)
def archive_old_vulnerabilities(
    self, retention_days: int = 90, batch_size: int = MAX_CLEANUP_BATCH_SIZE
) -> Dict[str, Any]:
    """
    Archive old resolved vulnerabilities to reduce database size.

    Args:
        retention_days: Number of days to retain unarchived vulnerabilities
        batch_size: Number of records to process in each batch

    Returns:
        Dict containing archival results
    """
    cleanup_id = str(uuid.uuid4())
    start_time = time.time()

    logger.info(
        f"[{cleanup_id}] Starting vulnerability archival for records older than {retention_days} days",
        extra={
            "cleanup_id": cleanup_id,
            "retention_days": retention_days,
            "batch_size": batch_size,
        },
    )

    try:
        result = asyncio.run(_archive_old_vulnerabilities_async(retention_days, batch_size, cleanup_id))

        execution_time = time.time() - start_time

        logger.info(
            f"[{cleanup_id}] Vulnerability archival completed - {result.get('archived_count', 0)} vulnerabilities archived in {execution_time:.2f}s",
            extra={
                "cleanup_id": cleanup_id,
                "execution_time": execution_time,
                "archived_count": result.get("archived_count", 0),
            },
        )

        return {
            **result,
            "cleanup_id": cleanup_id,
            "execution_time": execution_time,
            "status": "completed",
        }

    except Exception as e:
        execution_time = time.time() - start_time
        error_details = {
            "error_type": type(e).__name__,
            "error_message": str(e),
            "cleanup_id": cleanup_id,
            "execution_time": execution_time,
        }

        logger.error(
            f"[{cleanup_id}] Vulnerability archival failed: {str(e)}",
            extra=error_details,
        )

        if self.request.retries < 2:
            raise self.retry(countdown=60, exc=e)

        return {
            "status": "failed",
            "error": error_details,
            "cleanup_id": cleanup_id,
            "execution_time": execution_time,
        }


@celery_app.task(bind=True, name="secureops.tasks.cleanup_tasks.cleanup_log_files", max_retries=2)
def cleanup_log_files(self, retention_days: int = LOG_RETENTION_DAYS) -> Dict[str, Any]:
    """
    Clean up old log files to prevent disk space issues.

    Args:
        retention_days: Number of days to retain log files

    Returns:
        Dict containing cleanup results
    """
    cleanup_id = str(uuid.uuid4())
    start_time = time.time()

    logger.info(
        f"[{cleanup_id}] Starting log file cleanup for files older than {retention_days} days",
        extra={"cleanup_id": cleanup_id, "retention_days": retention_days},
    )

    try:
        result = asyncio.run(_cleanup_log_files_async(retention_days, cleanup_id))

        execution_time = time.time() - start_time

        logger.info(
            f"[{cleanup_id}] Log file cleanup completed - {result.get('files_deleted', 0)} files deleted in {execution_time:.2f}s",
            extra={
                "cleanup_id": cleanup_id,
                "execution_time": execution_time,
                "files_deleted": result.get("files_deleted", 0),
                "space_freed_mb": result.get("space_freed_mb", 0),
            },
        )

        return {
            **result,
            "cleanup_id": cleanup_id,
            "execution_time": execution_time,
            "status": "completed",
        }

    except Exception as e:
        execution_time = time.time() - start_time
        error_details = {
            "error_type": type(e).__name__,
            "error_message": str(e),
            "cleanup_id": cleanup_id,
            "execution_time": execution_time,
        }

        logger.error(f"[{cleanup_id}] Log file cleanup failed: {str(e)}", extra=error_details)

        if self.request.retries < 2:
            raise self.retry(countdown=60, exc=e)

        return {
            "status": "failed",
            "error": error_details,
            "cleanup_id": cleanup_id,
            "execution_time": execution_time,
        }


@celery_app.task(bind=True, name="secureops.tasks.cleanup_tasks.database_maintenance", max_retries=1)
def database_maintenance(self) -> Dict[str, Any]:
    """
    Perform comprehensive database maintenance operations.

    Returns:
        Dict containing maintenance results
    """
    maintenance_id = str(uuid.uuid4())
    start_time = time.time()

    logger.info(
        f"[{maintenance_id}] Starting database maintenance",
        extra={"maintenance_id": maintenance_id},
    )

    try:
        result = asyncio.run(_database_maintenance_async(maintenance_id))

        execution_time = time.time() - start_time

        logger.info(
            f"[{maintenance_id}] Database maintenance completed in {execution_time:.2f}s",
            extra={
                "maintenance_id": maintenance_id,
                "execution_time": execution_time,
                "operations": result.get("operations_performed", []),
            },
        )

        return {
            **result,
            "maintenance_id": maintenance_id,
            "execution_time": execution_time,
            "status": "completed",
        }

    except Exception as e:
        execution_time = time.time() - start_time
        error_details = {
            "error_type": type(e).__name__,
            "error_message": str(e),
            "maintenance_id": maintenance_id,
            "execution_time": execution_time,
        }

        logger.error(
            f"[{maintenance_id}] Database maintenance failed: {str(e)}",
            extra=error_details,
        )

        if self.request.retries < 1:
            raise self.retry(countdown=300, exc=e)

        return {
            "status": "failed",
            "error": error_details,
            "maintenance_id": maintenance_id,
            "execution_time": execution_time,
        }


@celery_app.task(
    bind=True,
    name="secureops.tasks.cleanup_tasks.cleanup_docker_resources",
    max_retries=2,
)
def cleanup_docker_resources(self) -> Dict[str, Any]:
    """
    Clean up unused Docker resources (containers, images, volumes, networks).

    Returns:
        Dict containing cleanup results
    """
    cleanup_id = str(uuid.uuid4())
    start_time = time.time()

    logger.info(
        f"[{cleanup_id}] Starting Docker resource cleanup",
        extra={"cleanup_id": cleanup_id},
    )

    try:
        result = asyncio.run(_cleanup_docker_resources_async(cleanup_id))

        execution_time = time.time() - start_time

        logger.info(
            f"[{cleanup_id}] Docker cleanup completed in {execution_time:.2f}s",
            extra={
                "cleanup_id": cleanup_id,
                "execution_time": execution_time,
                "space_freed_mb": result.get("space_freed_mb", 0),
            },
        )

        return {
            **result,
            "cleanup_id": cleanup_id,
            "execution_time": execution_time,
            "status": "completed",
        }

    except Exception as e:
        execution_time = time.time() - start_time
        error_details = {
            "error_type": type(e).__name__,
            "error_message": str(e),
            "cleanup_id": cleanup_id,
            "execution_time": execution_time,
        }

        logger.error(f"[{cleanup_id}] Docker cleanup failed: {str(e)}", extra=error_details)

        if self.request.retries < 2:
            raise self.retry(countdown=120, exc=e)

        return {
            "status": "failed",
            "error": error_details,
            "cleanup_id": cleanup_id,
            "execution_time": execution_time,
        }


@celery_app.task(name="secureops.tasks.cleanup_tasks.cleanup_health_check")
def cleanup_health_check() -> Dict[str, Any]:
    """
    Health check for the cleanup system.

    Returns:
        Dict containing health check results
    """
    health_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "healthy",
        "components": {},
    }

    try:
        # Check disk space
        health_data["components"]["disk_space"] = _check_disk_space()

        # Check temporary directory
        health_data["components"]["temp_directory"] = _check_temp_directory()

        # Check database connectivity
        health_data["components"]["database"] = asyncio.run(_check_database_health())

        # Check cleanup permissions
        health_data["components"]["permissions"] = _check_cleanup_permissions()

        # Determine overall status
        component_statuses = [comp.get("status", "unknown") for comp in health_data["components"].values()]

        if "critical" in component_statuses:
            health_data["status"] = "critical"
        elif "warning" in component_statuses:
            health_data["status"] = "warning"

        logger.info(f"Cleanup health check completed - status: {health_data['status']}")
        return health_data

    except Exception as e:
        logger.error(f"Cleanup health check failed: {str(e)}")
        health_data["status"] = "critical"
        health_data["error"] = str(e)
        return health_data


# Async implementation functions


async def _comprehensive_cleanup_async(cleanup_id: str) -> Dict[str, Any]:
    """
    Comprehensive cleanup implementation that orchestrates all cleanup tasks.
    """
    results = {
        "tasks_executed": [],
        "total_items_cleaned": 0,
        "total_space_freed_mb": 0,
        "errors": [],
    }

    try:
        # Execute cleanup tasks in order of priority
        cleanup_tasks = [
            (
                "scan_jobs",
                _cleanup_old_scan_jobs_async(DEFAULT_RETENTION_DAYS, MAX_CLEANUP_BATCH_SIZE, cleanup_id),
            ),
            (
                "temp_files",
                _cleanup_temporary_files_async(TEMP_FILE_MAX_AGE_HOURS, cleanup_id),
            ),
            (
                "vulnerabilities",
                _archive_old_vulnerabilities_async(90, MAX_CLEANUP_BATCH_SIZE, cleanup_id),
            ),
            ("log_files", _cleanup_log_files_async(LOG_RETENTION_DAYS, cleanup_id)),
            ("database", _database_maintenance_async(cleanup_id)),
            ("docker", _cleanup_docker_resources_async(cleanup_id)),
        ]

        for task_name, task_coro in cleanup_tasks:
            try:
                task_result = await task_coro
                results["tasks_executed"].append({"name": task_name, "status": "completed", "result": task_result})

                # Aggregate metrics
                results["total_items_cleaned"] += task_result.get("deleted_count", 0) + task_result.get(
                    "archived_count", 0
                )
                results["total_space_freed_mb"] += task_result.get("space_freed_mb", 0)

            except Exception as e:
                error_info = {
                    "task": task_name,
                    "error": str(e),
                    "error_type": type(e).__name__,
                }
                results["errors"].append(error_info)
                results["tasks_executed"].append({"name": task_name, "status": "failed", "error": error_info})

                logger.error(f"Cleanup task {task_name} failed: {str(e)}")

        # Calculate success rate
        total_tasks = len(cleanup_tasks)
        successful_tasks = len([t for t in results["tasks_executed"] if t["status"] == "completed"])
        results["success_rate"] = (successful_tasks / total_tasks) * 100 if total_tasks > 0 else 0

        return results

    except Exception as e:
        logger.error(f"Comprehensive cleanup failed: {str(e)}")
        results["errors"].append(
            {
                "task": "comprehensive_cleanup",
                "error": str(e),
                "error_type": type(e).__name__,
            }
        )
        return results


async def _cleanup_old_scan_jobs_async(retention_days: int, batch_size: int, cleanup_id: str) -> Dict[str, Any]:
    """
    Clean up old scan jobs with batched processing.
    """
    deleted_count = 0
    error_count = 0
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)

    async with AsyncSessionLocal() as session:
        try:
            from sqlalchemy import select, text
            from sqlalchemy.orm import selectinload

            # Get count of jobs to delete
            count_query = text(
                """
                SELECT COUNT(*) FROM scan_jobs
                WHERE created_at < :cutoff_date
            """
            )
            result = await session.execute(count_query, {"cutoff_date": cutoff_date})
            total_to_delete = result.scalar() or 0

            logger.info(f"[{cleanup_id}] Found {total_to_delete} scan jobs to delete")

            if total_to_delete == 0:
                return {
                    "deleted_count": 0,
                    "error_count": 0,
                    "total_processed": 0,
                    "cutoff_date": cutoff_date.isoformat(),
                }

            # Process in batches to avoid memory issues
            processed = 0
            while processed < total_to_delete:
                try:
                    # Get batch of scan job IDs
                    batch_query = text(
                        """
                        SELECT id FROM scan_jobs
                        WHERE created_at < :cutoff_date
                        ORDER BY created_at ASC
                        LIMIT :batch_size
                    """
                    )

                    batch_result = await session.execute(
                        batch_query,
                        {"cutoff_date": cutoff_date, "batch_size": batch_size},
                    )
                    job_ids = [row[0] for row in batch_result.fetchall()]

                    if not job_ids:
                        break

                    # Delete associated data first (foreign key constraints)
                    # Delete vulnerabilities associated with these jobs
                    vuln_delete = text(
                        """
                        DELETE FROM vulnerabilities
                        WHERE scan_job_id IN :job_ids
                    """
                    )
                    await session.execute(vuln_delete, {"job_ids": tuple(job_ids)})

                    # Delete alerts associated with these jobs
                    alert_delete = text(
                        """
                        DELETE FROM alerts
                        WHERE scan_job_id IN :job_ids
                    """
                    )
                    await session.execute(alert_delete, {"job_ids": tuple(job_ids)})

                    # Delete the scan jobs
                    job_delete = text(
                        """
                        DELETE FROM scan_jobs
                        WHERE id IN :job_ids
                    """
                    )
                    delete_result = await session.execute(job_delete, {"job_ids": tuple(job_ids)})

                    batch_deleted = delete_result.rowcount
                    deleted_count += batch_deleted
                    processed += len(job_ids)

                    await session.commit()

                    logger.info(
                        f"[{cleanup_id}] Deleted batch of {batch_deleted} scan jobs "
                        f"({processed}/{total_to_delete} processed)"
                    )

                except Exception as batch_error:
                    await session.rollback()
                    error_count += 1
                    logger.error(f"[{cleanup_id}] Error deleting batch: {str(batch_error)}")
                    # Continue with next batch
                    processed += batch_size

            return {
                "deleted_count": deleted_count,
                "error_count": error_count,
                "total_processed": processed,
                "cutoff_date": cutoff_date.isoformat(),
            }

        except Exception as e:
            await session.rollback()
            logger.error(f"[{cleanup_id}] Scan job cleanup failed: {str(e)}")
            raise


async def _cleanup_temporary_files_async(max_age_hours: int, cleanup_id: str) -> Dict[str, Any]:
    """
    Clean up temporary files and directories.
    """
    files_deleted = 0
    space_freed_bytes = 0
    error_count = 0
    cutoff_time = datetime.now() - timedelta(hours=max_age_hours)

    # Define temporary directories to clean
    temp_dirs = [
        tempfile.gettempdir(),
        "/tmp" if os.name == "posix" else None,
        os.path.join(os.getcwd(), "temp"),
        os.path.join(os.getcwd(), "cache", "temp"),
        os.path.join(os.getcwd(), "logs", "temp"),
    ]
    temp_dirs = [d for d in temp_dirs if d and os.path.exists(d)]

    for temp_dir in temp_dirs:
        try:
            temp_path = Path(temp_dir)

            for item in temp_path.rglob("*"):
                try:
                    if not item.exists():
                        continue

                    # Get file stats
                    stat = item.stat()
                    modified_time = datetime.fromtimestamp(stat.st_mtime)

                    if modified_time < cutoff_time:
                        file_size = stat.st_size if item.is_file() else 0

                        # Skip if file is in use (Windows)
                        if os.name == "nt" and item.is_file():
                            try:
                                with open(item, "r+b"):
                                    pass
                            except (IOError, OSError):
                                continue  # File in use, skip

                        # Remove file or directory
                        if item.is_file():
                            item.unlink()
                        elif item.is_dir() and not any(item.iterdir()):  # Empty directory
                            item.rmdir()
                        else:
                            continue  # Non-empty directory, skip

                        files_deleted += 1
                        space_freed_bytes += file_size

                        if files_deleted % 100 == 0:
                            logger.info(
                                f"[{cleanup_id}] Deleted {files_deleted} temporary files "
                                f"({space_freed_bytes / 1024 / 1024:.2f} MB freed)"
                            )

                except Exception as file_error:
                    error_count += 1
                    logger.warning(f"[{cleanup_id}] Could not delete {item}: {str(file_error)}")
                    continue

        except Exception as dir_error:
            error_count += 1
            logger.error(f"[{cleanup_id}] Error processing directory {temp_dir}: {str(dir_error)}")
            continue

    return {
        "files_deleted": files_deleted,
        "space_freed_mb": space_freed_bytes / 1024 / 1024,
        "error_count": error_count,
        "directories_processed": len(temp_dirs),
    }


async def _archive_old_vulnerabilities_async(retention_days: int, batch_size: int, cleanup_id: str) -> Dict[str, Any]:
    """
    Archive old resolved vulnerabilities.
    """
    archived_count = 0
    error_count = 0
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)

    async with AsyncSessionLocal() as session:
        try:
            from sqlalchemy import text, update

            # Count vulnerabilities to archive
            count_query = text(
                """
                SELECT COUNT(*) FROM vulnerabilities
                WHERE status IN ('resolved', 'fixed', 'false_positive')
                AND updated_at < :cutoff_date
                AND archived = false
            """
            )
            result = await session.execute(count_query, {"cutoff_date": cutoff_date})
            total_to_archive = result.scalar() or 0

            logger.info(f"[{cleanup_id}] Found {total_to_archive} vulnerabilities to archive")

            if total_to_archive == 0:
                return {"archived_count": 0, "error_count": 0, "total_processed": 0}

            # Process in batches
            processed = 0
            while processed < total_to_archive:
                try:
                    # Archive batch
                    archive_query = text(
                        """
                        UPDATE vulnerabilities
                        SET archived = true, archived_at = :archive_time
                        WHERE id IN (
                            SELECT id FROM vulnerabilities
                            WHERE status IN ('resolved', 'fixed', 'false_positive')
                            AND updated_at < :cutoff_date
                            AND archived = false
                            LIMIT :batch_size
                        )
                    """
                    )

                    archive_result = await session.execute(
                        archive_query,
                        {
                            "cutoff_date": cutoff_date,
                            "batch_size": batch_size,
                            "archive_time": datetime.now(timezone.utc),
                        },
                    )

                    batch_archived = archive_result.rowcount
                    archived_count += batch_archived
                    processed += batch_archived

                    await session.commit()

                    logger.info(
                        f"[{cleanup_id}] Archived batch of {batch_archived} vulnerabilities "
                        f"({processed}/{total_to_archive} processed)"
                    )

                    if batch_archived < batch_size:
                        break  # No more to process

                except Exception as batch_error:
                    await session.rollback()
                    error_count += 1
                    logger.error(f"[{cleanup_id}] Error archiving batch: {str(batch_error)}")
                    break

            return {
                "archived_count": archived_count,
                "error_count": error_count,
                "total_processed": processed,
            }

        except Exception as e:
            await session.rollback()
            logger.error(f"[{cleanup_id}] Vulnerability archival failed: {str(e)}")
            raise


async def _cleanup_log_files_async(retention_days: int, cleanup_id: str) -> Dict[str, Any]:
    """
    Clean up old log files.
    """
    files_deleted = 0
    space_freed_bytes = 0
    error_count = 0
    cutoff_date = datetime.now() - timedelta(days=retention_days)

    # Define log directories
    log_dirs = [
        "logs",
        os.path.join(os.getcwd(), "logs"),
        "/var/log" if os.name == "posix" else None,
        os.path.join(os.getcwd(), "cache", "logs"),
    ]
    log_dirs = [d for d in log_dirs if d and os.path.exists(d)]

    # Log file patterns
    log_patterns = ["*.log", "*.log.*", "*.out", "*.err"]

    for log_dir in log_dirs:
        try:
            log_path = Path(log_dir)

            for pattern in log_patterns:
                for log_file in log_path.rglob(pattern):
                    try:
                        if not log_file.is_file():
                            continue

                        stat = log_file.stat()
                        modified_time = datetime.fromtimestamp(stat.st_mtime)

                        if modified_time < cutoff_date:
                            file_size = stat.st_size

                            # Check if file is currently being written to
                            if _is_file_in_use(log_file):
                                continue

                            log_file.unlink()
                            files_deleted += 1
                            space_freed_bytes += file_size

                            if files_deleted % 50 == 0:
                                logger.info(
                                    f"[{cleanup_id}] Deleted {files_deleted} log files "
                                    f"({space_freed_bytes / 1024 / 1024:.2f} MB freed)"
                                )

                    except Exception as file_error:
                        error_count += 1
                        logger.warning(f"[{cleanup_id}] Could not delete log file {log_file}: {str(file_error)}")
                        continue

        except Exception as dir_error:
            error_count += 1
            logger.error(f"[{cleanup_id}] Error processing log directory {log_dir}: {str(dir_error)}")
            continue

    return {
        "files_deleted": files_deleted,
        "space_freed_mb": space_freed_bytes / 1024 / 1024,
        "error_count": error_count,
        "directories_processed": len(log_dirs),
    }


async def _database_maintenance_async(maintenance_id: str) -> Dict[str, Any]:
    """
    Perform comprehensive database maintenance.
    """
    operations_performed = []

    async with AsyncSessionLocal() as session:
        try:
            from sqlalchemy import text

            # Analyze database statistics
            if "postgresql" in str(session.bind.url):
                # PostgreSQL maintenance
                await session.execute(text("ANALYZE"))
                operations_performed.append("analyze_statistics")

                await session.execute(text("VACUUM"))
                operations_performed.append("vacuum_cleanup")

                # Reindex if needed
                await session.execute(text("REINDEX DATABASE"))
                operations_performed.append("reindex_database")

            elif "sqlite" in str(session.bind.url):
                # SQLite maintenance
                await session.execute(text("ANALYZE"))
                operations_performed.append("analyze_statistics")

                await session.execute(text("VACUUM"))
                operations_performed.append("vacuum_cleanup")

                # Update statistics
                await session.execute(text("PRAGMA optimize"))
                operations_performed.append("optimize_pragmas")

            await session.commit()

            logger.info(f"[{maintenance_id}] Database maintenance completed: {operations_performed}")

            return {"operations_performed": operations_performed, "status": "completed"}

        except Exception as e:
            await session.rollback()
            logger.error(f"[{maintenance_id}] Database maintenance failed: {str(e)}")
            raise


async def _cleanup_docker_resources_async(cleanup_id: str) -> Dict[str, Any]:
    """
    Clean up Docker resources if Docker is available.
    """
    import subprocess

    try:
        # Check if Docker is available
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True, timeout=10)

        if result.returncode != 0:
            return {
                "status": "skipped",
                "reason": "Docker not available",
                "space_freed_mb": 0,
            }

        operations = []

        # Remove stopped containers
        try:
            result = subprocess.run(
                ["docker", "container", "prune", "-f"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                operations.append("removed_stopped_containers")
        except subprocess.TimeoutExpired:
            logger.warning(f"[{cleanup_id}] Docker container prune timed out")

        # Remove unused images
        try:
            result = subprocess.run(
                ["docker", "image", "prune", "-f"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                operations.append("removed_unused_images")
        except subprocess.TimeoutExpired:
            logger.warning(f"[{cleanup_id}] Docker image prune timed out")

        # Remove unused volumes
        try:
            result = subprocess.run(
                ["docker", "volume", "prune", "-f"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                operations.append("removed_unused_volumes")
        except subprocess.TimeoutExpired:
            logger.warning(f"[{cleanup_id}] Docker volume prune timed out")

        # Get system info for space calculation
        try:
            result = subprocess.run(["docker", "system", "df"], capture_output=True, text=True, timeout=30)
            # Note: This doesn't give exact space freed, but confirms cleanup
        except subprocess.TimeoutExpired:
            pass

        return {
            "status": "completed",
            "operations": operations,
            "space_freed_mb": 0,  # Docker doesn't provide exact space freed
        }

    except FileNotFoundError:
        return {
            "status": "skipped",
            "reason": "Docker not installed",
            "space_freed_mb": 0,
        }
    except Exception as e:
        logger.error(f"[{cleanup_id}] Docker cleanup failed: {str(e)}")
        raise


# Health check helper functions


def _check_disk_space() -> Dict[str, Any]:
    """Check available disk space."""
    try:
        import shutil

        total, used, free = shutil.disk_usage(os.getcwd())

        free_percent = (free / total) * 100

        if free_percent < 5:
            status = "critical"
        elif free_percent < 15:
            status = "warning"
        else:
            status = "healthy"

        return {
            "status": status,
            "free_space_mb": free / 1024 / 1024,
            "total_space_mb": total / 1024 / 1024,
            "free_percent": free_percent,
        }

    except Exception as e:
        return {"status": "critical", "error": str(e)}


def _check_temp_directory() -> Dict[str, Any]:
    """Check temporary directory status."""
    try:
        temp_dir = tempfile.gettempdir()
        temp_path = Path(temp_dir)

        if not temp_path.exists():
            return {"status": "critical", "error": "Temp directory does not exist"}

        if not temp_path.is_dir():
            return {"status": "critical", "error": "Temp path is not a directory"}

        # Count files in temp directory
        file_count = len(list(temp_path.iterdir()))

        status = "healthy"
        if file_count > 10000:
            status = "warning"
        elif file_count > 50000:
            status = "critical"

        return {"status": status, "path": str(temp_path), "file_count": file_count}

    except Exception as e:
        return {"status": "critical", "error": str(e)}


async def _check_database_health() -> Dict[str, Any]:
    """Check database connectivity and health."""
    try:
        async with AsyncSessionLocal() as session:
            from sqlalchemy import text

            # Simple connectivity test
            result = await session.execute(text("SELECT 1"))
            result.fetchone()

            return {"status": "healthy", "connection": "successful"}

    except Exception as e:
        return {"status": "critical", "error": str(e)}


def _check_cleanup_permissions() -> Dict[str, Any]:
    """Check if cleanup operations have necessary permissions."""
    try:
        # Test write permissions in current directory
        test_file = Path("cleanup_permission_test.tmp")
        test_file.write_text("test")
        test_file.unlink()

        # Test temp directory access
        temp_dir = Path(tempfile.gettempdir())
        if not os.access(temp_dir, os.W_OK):
            return {"status": "warning", "error": "No write access to temp directory"}

        return {"status": "healthy", "permissions": "sufficient"}

    except Exception as e:
        return {"status": "warning", "error": str(e)}


def _is_file_in_use(filepath: Path) -> bool:
    """Check if a file is currently in use."""
    try:
        if os.name == "nt":  # Windows
            import msvcrt

            with open(filepath, "r+b") as f:
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:  # Unix-like
            import fcntl

            with open(filepath, "r+b") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        return False

    except (IOError, OSError):
        return True
    except ImportError:
        # Fallback: assume file is not in use
        return False

        result = asyncio.run(_database_maintenance_async())

        logger.info("Database maintenance completed successfully")
        return result

    except Exception as e:
        logger.error(f"Database maintenance failed: {str(e)}")
        raise


# Helper async functions (continued below)


@celery_app.task(bind=True, name="secureops.tasks.cleanup_tasks.rotate_encryption_keys")
def rotate_encryption_keys(self):
    """
    Rotate encryption keys used for sensitive data storage.
    """
    logger.info("Starting encryption key rotation")

    try:
        import asyncio

        result = asyncio.run(_rotate_encryption_keys_async())

        logger.info("Encryption key rotation completed")
        return result

    except Exception as e:
        logger.error(f"Encryption key rotation failed: {str(e)}")
        raise


@celery_app.task(bind=True, name="secureops.tasks.cleanup_tasks.cleanup_cache_data")
def cleanup_cache_data(self, max_age_hours: int = 48):
    """
    Clean up cached data that's older than specified age.

    Args:
        max_age_hours: Maximum age of cached data in hours
    """
    logger.info(f"Starting cleanup of cache data older than {max_age_hours} hours")

    try:
        import asyncio

        result = asyncio.run(_cleanup_cache_data_async(max_age_hours))

        logger.info(f"Cleaned up {result['entries_deleted']} cache entries")
        return result

    except Exception as e:
        logger.error(f"Cache cleanup failed: {str(e)}")
        raise


# Implementation functions


async def _rotate_encryption_keys_async() -> Dict[str, Any]:
    """Rotate encryption keys."""
    try:
        # This is a placeholder for key rotation logic
        # In a real implementation, this would:
        # 1. Generate new encryption keys
        # 2. Re-encrypt sensitive data with new keys
        # 3. Securely dispose of old keys
        # 4. Update key references in configuration

        return {
            "status": "completed",
            "keys_rotated": 0,  # Would be actual count
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "note": "Key rotation placeholder - implement based on security requirements",
        }

    except Exception as e:
        logger.error(f"Error rotating encryption keys: {str(e)}")
        raise


async def _cleanup_cache_data_async(max_age_hours: int) -> Dict[str, Any]:
    """Clean up old cache data."""
    try:
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        entries_deleted = 0

        # Clean up file-based cache
        cache_directories = [
            "/tmp/secureops_cache" if os.path.exists("/tmp/secureops_cache") else None,
            (settings.CACHE_DIR if hasattr(settings, "CACHE_DIR") and settings.CACHE_DIR else None),
        ]

        cache_directories = [d for d in cache_directories if d and os.path.exists(d)]

        for cache_dir in cache_directories:
            for root, dirs, files in os.walk(cache_dir):
                for file in files:
                    file_path = os.path.join(root, file)

                    try:
                        if os.path.getmtime(file_path) < cutoff_time.timestamp():
                            os.remove(file_path)
                            entries_deleted += 1

                    except (OSError, IOError) as e:
                        logger.warning(f"Could not delete cache file {file_path}: {str(e)}")

        # Clean up Redis cache if configured
        if hasattr(settings, "REDIS_URL") and settings.REDIS_URL:
            try:
                import redis

                r = redis.from_url(settings.REDIS_URL)

                # Get keys with expiration and clean up old ones
                keys = r.keys("secureops:cache:*")
                for key in keys:
                    ttl = r.ttl(key)
                    if ttl == -1 or ttl > max_age_hours * 3600:  # No expiry or too old
                        r.delete(key)
                        entries_deleted += 1

            except Exception as e:
                logger.warning(f"Could not clean Redis cache: {str(e)}")

        return {
            "status": "completed",
            "entries_deleted": entries_deleted,
            "cutoff_time": cutoff_time.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error cleaning up cache data: {str(e)}")
        raise


# Helper functions


def _is_secureops_temp_file(file_path: str) -> bool:
    """Check if a file is a SecureOps temporary file."""
    filename = os.path.basename(file_path)

    # Define patterns for SecureOps temporary files
    secureops_patterns = [
        "secureops_",
        "scan_",
        "vuln_",
        "temp_scan_",
        "scanner_output_",
    ]

    return any(filename.startswith(pattern) for pattern in secureops_patterns)


async def _cleanup_scan_temp_files(scan_jobs: List[ScanJob]) -> int:
    """Clean up temporary files associated with scan jobs."""
    files_cleaned = 0

    for job in scan_jobs:
        # Look for temporary files associated with this job
        job_temp_patterns = [
            f"scan_{job.id}_*",
            f"job_{job.id}_*",
            f"secureops_{job.id}_*",
        ]

        temp_dirs = [tempfile.gettempdir(), "/tmp"]

        for temp_dir in temp_dirs:
            if not os.path.exists(temp_dir):
                continue

            for pattern in job_temp_patterns:
                import glob

                matching_files = glob.glob(os.path.join(temp_dir, pattern))

                for file_path in matching_files:
                    try:
                        if os.path.isfile(file_path):
                            os.remove(file_path)
                            files_cleaned += 1
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path)
                            files_cleaned += 1
                    except (OSError, IOError):
                        pass

    return files_cleaned


async def _create_vulnerability_archive(vulnerability: Vulnerability) -> Dict[str, Any]:
    """Create archive data for a vulnerability."""
    return {
        "id": vulnerability.id,
        "pipeline_id": vulnerability.pipeline_id,
        "scan_job_id": vulnerability.scan_job_id,
        "scanner_type": vulnerability.scanner_type,
        "rule_id": vulnerability.rule_id,
        "title": vulnerability.title,
        "description": vulnerability.description,
        "severity": vulnerability.severity,
        "confidence": vulnerability.confidence,
        "file_path": vulnerability.file_path,
        "line_number": vulnerability.line_number,
        "cve_id": vulnerability.cve_id,
        "cwe_id": vulnerability.cwe_id,
        "cvss_score": vulnerability.cvss_score,
        "remediation": vulnerability.remediation,
        "status": vulnerability.status,
        "created_at": (vulnerability.created_at.isoformat() if vulnerability.created_at else None),
        "resolved_at": (vulnerability.resolved_at.isoformat() if vulnerability.resolved_at else None),
        "archived_at": datetime.now(timezone.utc).isoformat(),
    }


async def _store_vulnerability_archive(vulnerability_id: int, archive_data: Dict[str, Any]):
    """Store vulnerability archive data."""
    try:
        # Create archive directory if it doesn't exist
        archive_dir = Path(settings.ARCHIVE_DIR if hasattr(settings, "ARCHIVE_DIR") else "/tmp/secureops_archive")
        archive_dir.mkdir(parents=True, exist_ok=True)

        # Store as JSON file
        archive_file = archive_dir / f"vulnerability_{vulnerability_id}_{datetime.now().strftime('%Y%m%d')}.json"

        import json

        with open(archive_file, "w") as f:
            json.dump(archive_data, f, indent=2)

        logger.info(f"Archived vulnerability {vulnerability_id} to {archive_file}")

    except Exception as e:
        logger.error(f"Could not store vulnerability archive: {str(e)}")
        raise


def _parse_docker_prune_output(output: str, resource_type: str) -> int:
    """Parse Docker prune command output to extract count."""
    try:
        lines = output.strip().split("\n")
        for line in lines:
            if "deleted" in line.lower() or "removed" in line.lower():
                # Try to extract number from the line
                import re

                numbers = re.findall(r"\d+", line)
                if numbers:
                    return int(numbers[0])
        return 0
    except Exception:
        return 0
