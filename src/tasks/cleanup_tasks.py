"""
System Cleanup Background Tasks

This module contains Celery tasks for system maintenance, cleanup operations,
and data retention management.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import asyncio
import os
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

<<<<<<< HEAD
from celery.utils.log import get_task_logger

from src.api.database import AsyncSessionLocal
from src.api.models.alert import Alert
from src.api.models.pipeline import Pipeline, ScanJob
from src.api.models.vulnerability import Vulnerability
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
from ..api.models.vulnerability import Vulnerability
from ..utils.config import settings
from ..utils.logger import get_logger

# Use the same Celery app from scan_tasks
from .scan_tasks import celery_app
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

logger = get_task_logger(__name__)


@celery_app.task(bind=True, name="secureops.tasks.cleanup_tasks.cleanup_old_scan_jobs")
def cleanup_old_scan_jobs(self, retention_days: int = 30):
    """
    Clean up old scan jobs and their associated data.

    Args:
        retention_days: Number of days to retain scan jobs
    """
    logger.info(f"Starting cleanup of scan jobs older than {retention_days} days")

    try:
        import asyncio

        result = asyncio.run(_cleanup_old_scan_jobs_async(retention_days))

        logger.info(f"Cleaned up {result['deleted_jobs']} old scan jobs")
        return result

    except Exception as e:
        logger.error(f"Scan job cleanup failed: {str(e)}")
        raise


@celery_app.task(
    bind=True, name="secureops.tasks.cleanup_tasks.cleanup_temporary_files"
)
def cleanup_temporary_files(self, max_age_hours: int = 24):
    """
    Clean up temporary files created during scans.

    Args:
        max_age_hours: Maximum age of temporary files in hours
    """
    logger.info(f"Starting cleanup of temporary files older than {max_age_hours} hours")

    try:
        import asyncio

        result = asyncio.run(_cleanup_temporary_files_async(max_age_hours))

        logger.info(
            f"Cleaned up {result['files_deleted']} temporary files, freed {result['space_freed_mb']:.2f} MB"
        )
        return result

    except Exception as e:
        logger.error(f"Temporary file cleanup failed: {str(e)}")
        raise


@celery_app.task(
    bind=True, name="secureops.tasks.cleanup_tasks.archive_old_vulnerabilities"
)
def archive_old_vulnerabilities(self, retention_days: int = 90):
    """
    Archive old resolved vulnerabilities to reduce database size.

    Args:
        retention_days: Number of days to retain vulnerabilities before archiving
    """
    logger.info(
        f"Starting archival of vulnerabilities older than {retention_days} days"
    )

    try:
        import asyncio

        result = asyncio.run(_archive_old_vulnerabilities_async(retention_days))

        logger.info(f"Archived {result['archived_count']} vulnerabilities")
        return result

    except Exception as e:
        logger.error(f"Vulnerability archival failed: {str(e)}")
        raise


@celery_app.task(bind=True, name="secureops.tasks.cleanup_tasks.cleanup_log_files")
def cleanup_log_files(self, retention_days: int = 14):
    """
    Clean up old log files to prevent disk space issues.

    Args:
        retention_days: Number of days to retain log files
    """
    logger.info(f"Starting cleanup of log files older than {retention_days} days")

    try:
        import asyncio

        result = asyncio.run(_cleanup_log_files_async(retention_days))

        logger.info(
            f"Cleaned up {result['files_deleted']} log files, freed {result['space_freed_mb']:.2f} MB"
        )
        return result

    except Exception as e:
        logger.error(f"Log file cleanup failed: {str(e)}")
        raise


@celery_app.task(bind=True, name="secureops.tasks.cleanup_tasks.database_maintenance")
def database_maintenance(self):
    """
    Perform database maintenance operations like VACUUM and ANALYZE.
    """
    logger.info("Starting database maintenance")

    try:
        import asyncio

        result = asyncio.run(_database_maintenance_async())

        logger.info("Database maintenance completed successfully")
        return result

    except Exception as e:
        logger.error(f"Database maintenance failed: {str(e)}")
        raise


@celery_app.task(
    bind=True, name="secureops.tasks.cleanup_tasks.cleanup_docker_resources"
)
def cleanup_docker_resources(self):
    """
    Clean up unused Docker containers, images, and volumes.
    """
    logger.info("Starting Docker resource cleanup")

    try:
        import asyncio

        result = asyncio.run(_cleanup_docker_resources_async())

        logger.info(
            f"Docker cleanup completed - removed {result.get('containers_removed', 0)} containers, {result.get('images_removed', 0)} images"
        )
        return result

    except Exception as e:
        logger.error(f"Docker cleanup failed: {str(e)}")
        raise


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


async def _cleanup_old_scan_jobs_async(retention_days: int) -> Dict[str, Any]:
    """Clean up old scan jobs and associated data."""
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)

    try:
<<<<<<< HEAD
        async with AsyncSessionLocal() as db:
=======
        async with async_session() as db:
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
            from sqlalchemy import and_, delete, select

            # First, get the scan jobs to be deleted
            jobs_query = select(ScanJob).where(
                and_(
                    ScanJob.created_at < cutoff_date,
                    ScanJob.status.in_(["completed", "failed"]),
                )
            )

            result = await db.execute(jobs_query)
            jobs_to_delete = result.scalars().all()

            deleted_jobs = len(jobs_to_delete)
            deleted_vulnerabilities = 0

            # Delete associated vulnerabilities first
            for job in jobs_to_delete:
                vuln_delete_query = delete(Vulnerability).where(
                    Vulnerability.scan_job_id == job.id
                )
                vuln_result = await db.execute(vuln_delete_query)
                deleted_vulnerabilities += vuln_result.rowcount

            # Delete the scan jobs
            jobs_delete_query = delete(ScanJob).where(
                and_(
                    ScanJob.created_at < cutoff_date,
                    ScanJob.status.in_(["completed", "failed"]),
                )
            )

            await db.execute(jobs_delete_query)
            await db.commit()

            # Clean up associated temporary files
            temp_files_cleaned = await _cleanup_scan_temp_files(jobs_to_delete)

            return {
                "status": "completed",
                "deleted_jobs": deleted_jobs,
                "deleted_vulnerabilities": deleted_vulnerabilities,
                "temp_files_cleaned": temp_files_cleaned,
                "cutoff_date": cutoff_date.isoformat(),
            }

    except Exception as e:
        logger.error(f"Error cleaning up old scan jobs: {str(e)}")
        raise


async def _cleanup_temporary_files_async(max_age_hours: int) -> Dict[str, Any]:
    """Clean up temporary files."""
    cutoff_time = datetime.now() - timedelta(hours=max_age_hours)

    files_deleted = 0
    space_freed = 0

    try:
        # Define directories to clean
        temp_directories = [
            tempfile.gettempdir(),
            "/tmp/secureops" if os.path.exists("/tmp/secureops") else None,
            (
                settings.TEMP_DIR
                if hasattr(settings, "TEMP_DIR") and settings.TEMP_DIR
                else None
            ),
        ]

        temp_directories = [d for d in temp_directories if d and os.path.exists(d)]

        for temp_dir in temp_directories:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)

                    try:
                        # Check if file is old enough to delete
                        if os.path.getmtime(file_path) < cutoff_time.timestamp():
                            # Check if it's a SecureOps temporary file
                            if _is_secureops_temp_file(file_path):
                                file_size = os.path.getsize(file_path)
                                os.remove(file_path)
                                files_deleted += 1
                                space_freed += file_size

                    except (OSError, IOError) as e:
                        logger.warning(
                            f"Could not delete temporary file {file_path}: {str(e)}"
                        )
                        continue

        return {
            "status": "completed",
            "files_deleted": files_deleted,
            "space_freed_mb": space_freed / (1024 * 1024),
            "cutoff_time": cutoff_time.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error cleaning up temporary files: {str(e)}")
        raise


async def _archive_old_vulnerabilities_async(retention_days: int) -> Dict[str, Any]:
    """Archive old resolved vulnerabilities."""
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)

    try:
<<<<<<< HEAD
        async with AsyncSessionLocal() as db:
=======
        async with async_session() as db:
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
            from sqlalchemy import and_, select, update

            # Find vulnerabilities to archive
            vulns_query = select(Vulnerability).where(
                and_(
                    Vulnerability.status.in_(
                        ["resolved", "false_positive", "accepted_risk"]
                    ),
                    Vulnerability.resolved_at < cutoff_date,
                    Vulnerability.archived == False,
                )
            )

            result = await db.execute(vulns_query)
            vulnerabilities_to_archive = result.scalars().all()

            archived_count = 0

            # Create archive records
            for vuln in vulnerabilities_to_archive:
                # Export vulnerability data for archival
                archive_data = await _create_vulnerability_archive(vuln)

                # Store in archive storage (could be file system, S3, etc.)
                await _store_vulnerability_archive(vuln.id, archive_data)

                # Mark as archived in database
                vuln.archived = True
                vuln.archived_at = datetime.now(timezone.utc)
                archived_count += 1

            await db.commit()

            return {
                "status": "completed",
                "archived_count": archived_count,
                "cutoff_date": cutoff_date.isoformat(),
            }

    except Exception as e:
        logger.error(f"Error archiving vulnerabilities: {str(e)}")
        raise


async def _cleanup_log_files_async(retention_days: int) -> Dict[str, Any]:
    """Clean up old log files."""
    cutoff_time = datetime.now() - timedelta(days=retention_days)

    files_deleted = 0
    space_freed = 0

    try:
        # Define log directories
        log_directories = [
            "/var/log/secureops" if os.path.exists("/var/log/secureops") else None,
            (
                settings.LOG_DIR
                if hasattr(settings, "LOG_DIR") and settings.LOG_DIR
                else None
            ),
            "./logs" if os.path.exists("./logs") else None,
        ]

        log_directories = [d for d in log_directories if d and os.path.exists(d)]

        for log_dir in log_directories:
            for root, dirs, files in os.walk(log_dir):
                for file in files:
                    if file.endswith((".log", ".log.gz", ".log.bz2")):
                        file_path = os.path.join(root, file)

                        try:
                            if os.path.getmtime(file_path) < cutoff_time.timestamp():
                                file_size = os.path.getsize(file_path)
                                os.remove(file_path)
                                files_deleted += 1
                                space_freed += file_size

                        except (OSError, IOError) as e:
                            logger.warning(
                                f"Could not delete log file {file_path}: {str(e)}"
                            )
                            continue

        return {
            "status": "completed",
            "files_deleted": files_deleted,
            "space_freed_mb": space_freed / (1024 * 1024),
            "cutoff_time": cutoff_time.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error cleaning up log files: {str(e)}")
        raise


async def _database_maintenance_async() -> Dict[str, Any]:
    """Perform database maintenance operations."""
    try:
<<<<<<< HEAD
        async with AsyncSessionLocal() as db:
=======
        async with async_session() as db:
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
            from sqlalchemy import text

            operations_performed = []

            # PostgreSQL specific operations
            if db.bind.dialect.name == "postgresql":
                # VACUUM to reclaim storage
                await db.execute(text("VACUUM"))
                operations_performed.append("vacuum")

                # ANALYZE to update statistics
                await db.execute(text("ANALYZE"))
                operations_performed.append("analyze")

                # REINDEX critical tables
                critical_tables = [
                    "vulnerabilities",
                    "scan_jobs",
                    "pipelines",
                    "alerts",
                ]
                for table in critical_tables:
                    try:
                        await db.execute(text(f"REINDEX TABLE {table}"))
                        operations_performed.append(f"reindex_{table}")
                    except Exception as e:
                        logger.warning(f"Could not reindex table {table}: {str(e)}")

            # SQLite specific operations
            elif db.bind.dialect.name == "sqlite":
                await db.execute(text("VACUUM"))
                operations_performed.append("vacuum")

                await db.execute(text("ANALYZE"))
                operations_performed.append("analyze")

            await db.commit()

            return {
                "status": "completed",
                "operations_performed": operations_performed,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    except Exception as e:
        logger.error(f"Error performing database maintenance: {str(e)}")
        raise


async def _cleanup_docker_resources_async() -> Dict[str, Any]:
    """Clean up unused Docker resources."""
    try:
        import subprocess

        results = {
            "status": "completed",
            "containers_removed": 0,
            "images_removed": 0,
            "volumes_removed": 0,
            "space_reclaimed": 0,
        }

        # Remove stopped containers older than 24 hours
        try:
            cmd = ["docker", "container", "prune", "-f", "--filter", "until=24h"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                # Parse output to get count
                output_lines = result.stdout.split("\n")
                for line in output_lines:
                    if "Total reclaimed space" in line:
                        # Extract space information
                        pass
                results["containers_removed"] = _parse_docker_prune_output(
                    result.stdout, "containers"
                )

        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
        ) as e:
            logger.warning(f"Could not prune Docker containers: {str(e)}")

        # Remove unused images
        try:
            cmd = ["docker", "image", "prune", "-f", "--filter", "until=24h"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                results["images_removed"] = _parse_docker_prune_output(
                    result.stdout, "images"
                )

        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
        ) as e:
            logger.warning(f"Could not prune Docker images: {str(e)}")

        # Remove unused volumes
        try:
            cmd = ["docker", "volume", "prune", "-f"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                results["volumes_removed"] = _parse_docker_prune_output(
                    result.stdout, "volumes"
                )

        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
        ) as e:
            logger.warning(f"Could not prune Docker volumes: {str(e)}")

        return results

    except Exception as e:
        logger.error(f"Error cleaning up Docker resources: {str(e)}")
        raise


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
            (
                settings.CACHE_DIR
                if hasattr(settings, "CACHE_DIR") and settings.CACHE_DIR
                else None
            ),
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
                        logger.warning(
                            f"Could not delete cache file {file_path}: {str(e)}"
                        )

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
        "created_at": (
            vulnerability.created_at.isoformat() if vulnerability.created_at else None
        ),
        "resolved_at": (
            vulnerability.resolved_at.isoformat() if vulnerability.resolved_at else None
        ),
        "archived_at": datetime.now(timezone.utc).isoformat(),
    }


async def _store_vulnerability_archive(
    vulnerability_id: int, archive_data: Dict[str, Any]
):
    """Store vulnerability archive data."""
    try:
        # Create archive directory if it doesn't exist
        archive_dir = Path(
            settings.ARCHIVE_DIR
            if hasattr(settings, "ARCHIVE_DIR")
            else "/tmp/secureops_archive"
        )
        archive_dir.mkdir(parents=True, exist_ok=True)

        # Store as JSON file
        archive_file = (
            archive_dir
            / f"vulnerability_{vulnerability_id}_{datetime.now().strftime('%Y%m%d')}.json"
        )

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
