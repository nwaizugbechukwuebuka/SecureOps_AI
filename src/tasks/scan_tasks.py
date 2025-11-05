"""
Security Scan Background Tasks

This module contains Celery tasks for running security scans asynchronously.
Handles orchestration of different scanners, result processing, and notifications.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

<<<<<<< HEAD
from celery.utils.log import get_task_logger

from src.api.database import AsyncSessionLocal, get_db
from src.api.models.pipeline import Pipeline, ScanJob
from src.api.models.vulnerability import Vulnerability
from src.api.services.alert_service import AlertService
from src.scanners.common import ScannerType, SeverityLevel, orchestrator
from src.scanners.threat_detection import ThreatDetectionEngine
from src.api.utils.config import settings
from src.api.utils.logger import get_logger

# Import the main Celery app
from src.tasks.celery_app import app as celery_app
=======
from celery import Celery
from celery.utils.log import get_task_logger

from ..api.database import async_session, get_db
from ..api.models.pipeline import Pipeline, ScanJob
from ..api.models.vulnerability import Vulnerability
from ..api.services.alert_service import AlertService
from ..scanners.common import ScannerType, SeverityLevel, orchestrator
from ..utils.config import settings
from ..utils.logger import get_logger

# Initialize Celery app
celery_app = Celery(
    "secureops",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max
    task_soft_time_limit=3000,  # 50 minutes soft limit
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_disable_rate_limits=True,
    task_routes={
        "secureops.tasks.scan_tasks.*": {"queue": "scan_queue"},
        "secureops.tasks.alert_tasks.*": {"queue": "alert_queue"},
        "secureops.tasks.cleanup_tasks.*": {"queue": "cleanup_queue"},
    },
)
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

logger = get_task_logger(__name__)


@celery_app.task(bind=True, name="secureops.tasks.scan_tasks.run_security_scan")
def run_security_scan(
    self,
    pipeline_id: int,
    scan_job_id: int,
    target_path: str,
    scanner_types: List[str],
    scan_config: Dict[str, Any] = None,
):
    """
    Run a comprehensive security scan using specified scanners.

    Args:
        pipeline_id: ID of the pipeline requesting the scan
        scan_job_id: ID of the scan job
        target_path: Path to scan (repository, directory, or file)
        scanner_types: List of scanner types to run
        scan_config: Additional configuration for scanners
    """
    logger.info(f"Starting security scan for pipeline {pipeline_id}, job {scan_job_id}")

    try:
        # Update scan job status
        asyncio.run(_update_scan_job_status(scan_job_id, "running"))

        # Run the scan asynchronously
        results = asyncio.run(
            _execute_security_scan(
                pipeline_id=pipeline_id,
                scan_job_id=scan_job_id,
                target_path=target_path,
                scanner_types=scanner_types,
                scan_config=scan_config or {},
            )
        )

        # Update scan job with results
        asyncio.run(_finalize_scan_job(scan_job_id, results, "completed"))

        # Trigger alerts if needed
        asyncio.run(_process_scan_alerts(pipeline_id, results))

        logger.info(f"Security scan completed for pipeline {pipeline_id}")
        return {
            "status": "completed",
            "total_findings": len(results),
            "critical_findings": len(
                [r for r in results if r["severity"] == "critical"]
            ),
            "high_findings": len([r for r in results if r["severity"] == "high"]),
        }

    except Exception as e:
        logger.error(f"Security scan failed for pipeline {pipeline_id}: {str(e)}")
        asyncio.run(_update_scan_job_status(scan_job_id, "failed", str(e)))
        raise


@celery_app.task(bind=True, name="secureops.tasks.scan_tasks.run_targeted_scan")
def run_targeted_scan(
    self,
    scan_job_id: int,
    target_path: str,
    scanner_type: str,
    scan_config: Dict[str, Any] = None,
):
    """
    Run a targeted scan with a specific scanner.

    Args:
        scan_job_id: ID of the scan job
        target_path: Path to scan
        scanner_type: Specific scanner type to run
        scan_config: Scanner-specific configuration
    """
    logger.info(f"Starting targeted scan with {scanner_type} for job {scan_job_id}")

    try:
        # Update scan job status
        asyncio.run(_update_scan_job_status(scan_job_id, "running"))

        # Run the targeted scan
        results = asyncio.run(
            _execute_targeted_scan(
                scan_job_id=scan_job_id,
                target_path=target_path,
                scanner_type=scanner_type,
                scan_config=scan_config or {},
            )
        )

        # Update scan job with results
        asyncio.run(_finalize_scan_job(scan_job_id, results, "completed"))

        logger.info(f"Targeted scan completed for job {scan_job_id}")
        return {
            "status": "completed",
            "scanner_type": scanner_type,
            "findings_count": len(results),
        }

    except Exception as e:
        logger.error(f"Targeted scan failed for job {scan_job_id}: {str(e)}")
        asyncio.run(_update_scan_job_status(scan_job_id, "failed", str(e)))
        raise


@celery_app.task(
    bind=True, name="secureops.tasks.scan_tasks.continuous_monitoring_scan"
)
def continuous_monitoring_scan(
    self, pipeline_id: int, monitoring_config: Dict[str, Any]
):
    """
    Run continuous monitoring scans for a pipeline.

    Args:
        pipeline_id: ID of the pipeline to monitor
        monitoring_config: Configuration for monitoring
    """
    logger.info(f"Starting continuous monitoring for pipeline {pipeline_id}")

    try:
        # Get pipeline information
        pipeline_info = asyncio.run(_get_pipeline_info(pipeline_id))
        if not pipeline_info:
            raise ValueError(f"Pipeline {pipeline_id} not found")

        # Create scan job for monitoring
        scan_job_id = asyncio.run(
            _create_monitoring_scan_job(pipeline_id, monitoring_config)
        )

        # Run monitoring scans
        results = asyncio.run(
            _execute_monitoring_scan(
                pipeline_id=pipeline_id,
                scan_job_id=scan_job_id,
                monitoring_config=monitoring_config,
            )
        )

        # Process results and alerts
        asyncio.run(_process_monitoring_results(pipeline_id, scan_job_id, results))

        logger.info(f"Continuous monitoring completed for pipeline {pipeline_id}")
        return {
            "status": "completed",
            "findings_count": len(results),
            "next_scan_scheduled": monitoring_config.get("next_scan_time"),
        }

    except Exception as e:
        logger.error(
            f"Continuous monitoring failed for pipeline {pipeline_id}: {str(e)}"
        )
        raise


async def _execute_security_scan(
    pipeline_id: int,
    scan_job_id: int,
    target_path: str,
    scanner_types: List[str],
    scan_config: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Execute comprehensive security scan with multiple scanners."""
    all_results = []

<<<<<<< HEAD

=======
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    try:
        # Convert scanner type strings to ScannerType enums
        scanner_type_enums = []
        for scanner_type in scanner_types:
            try:
                scanner_type_enums.append(ScannerType(scanner_type))
            except ValueError:
                logger.warning(f"Unknown scanner type: {scanner_type}")

        # Run orchestrated scan
        summaries, results = await orchestrator.run_comprehensive_scan(
            target=target_path, scanner_types=scanner_type_enums, **scan_config
        )

        # Process results
        for summary, result_list in zip(summaries, results):
            for result in result_list:
                result_dict = {
                    "scanner_type": result.scanner_type.value,
                    "rule_id": result.rule_id,
                    "title": result.title,
                    "description": result.description,
                    "severity": result.severity.value,
                    "confidence": result.confidence,
                    "file_path": result.file_path,
                    "line_number": result.line_number,
                    "column_number": result.column_number,
                    "code_snippet": result.code_snippet,
                    "cve_id": result.cve_id,
                    "cwe_id": result.cwe_id,
                    "cvss_score": result.cvss_score,
                    "remediation": result.remediation,
                    "references": result.references,
<<<<<<< HEAD
                    "meta_data": result.meta_data,
=======
                    "metadata": result.metadata,
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
                all_results.append(result_dict)

<<<<<<< HEAD
        # --- AI Threat Detection Integration ---
        ai_engine = ThreatDetectionEngine()
        ai_threats = await ai_engine.analyze_events(all_results)
        for threat in ai_threats:
            # Mark as AI-detected and append to results
            threat_result = {
                "scanner_type": "ai_threat_detection",
                "rule_id": threat.get("event", {}).get("rule_id", "AI-THREAT"),
                "title": threat.get("event", {}).get("title", "AI-Detected Threat"),
                "description": threat.get("details", "AI/ML anomaly detected."),
                "severity": threat.get("threat_level", "high"),
                "confidence": 1.0,
                "file_path": threat.get("event", {}).get("file_path"),
                "line_number": threat.get("event", {}).get("line_number"),
                "column_number": threat.get("event", {}).get("column_number"),
                "code_snippet": threat.get("event", {}).get("code_snippet"),
                "cve_id": threat.get("event", {}).get("cve_id"),
                "cwe_id": threat.get("event", {}).get("cwe_id"),
                "cvss_score": threat.get("risk_score", 0),
                "remediation": "Review and investigate AI-detected threat.",
                "references": [],
                "meta_data": {"ai_anomaly_score": threat.get("anomaly_score")},
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            all_results.append(threat_result)

=======
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
        # Store vulnerabilities in database
        await _store_scan_results(pipeline_id, scan_job_id, all_results)

        return all_results

    except Exception as e:
        logger.error(f"Error executing security scan: {str(e)}")
        raise


async def _execute_targeted_scan(
    scan_job_id: int, target_path: str, scanner_type: str, scan_config: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Execute targeted scan with specific scanner."""
    try:
        scanner_type_enum = ScannerType(scanner_type)

        # Get specific scanner
        scanner = orchestrator.get_scanner(scanner_type_enum)
        if not scanner:
            raise ValueError(f"Scanner {scanner_type} not available")

        # Run scan
        summary, results = await scanner.scan(target_path, **scan_config)

        # Process results
        processed_results = []
        for result in results:
            result_dict = {
                "scanner_type": result.scanner_type.value,
                "rule_id": result.rule_id,
                "title": result.title,
                "description": result.description,
                "severity": result.severity.value,
                "confidence": result.confidence,
                "file_path": result.file_path,
                "line_number": result.line_number,
                "column_number": result.column_number,
                "code_snippet": result.code_snippet,
                "cve_id": result.cve_id,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
                "remediation": result.remediation,
                "references": result.references,
<<<<<<< HEAD
                "meta_data": result.meta_data,
=======
                "metadata": result.metadata,
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            processed_results.append(result_dict)

        return processed_results

    except Exception as e:
        logger.error(f"Error executing targeted scan: {str(e)}")
        raise


async def _execute_monitoring_scan(
    pipeline_id: int, scan_job_id: int, monitoring_config: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Execute monitoring scan with lightweight checks."""
    try:
        # Get pipeline info to determine what to monitor
        pipeline_info = await _get_pipeline_info(pipeline_id)
        target_path = pipeline_info.get("repository_url") or pipeline_info.get(
            "target_path"
        )

        if not target_path:
            raise ValueError("No target path available for monitoring")

        # Run lightweight scans (typically secrets and policy checks)
        monitoring_scanners = [ScannerType.SECRET, ScannerType.POLICY]

        # Add container scanning if Docker files are present
        if _has_docker_files(target_path):
            monitoring_scanners.append(ScannerType.CONTAINER)

        summaries, results = await orchestrator.run_comprehensive_scan(
            target=target_path, scanner_types=monitoring_scanners, **monitoring_config
        )

        # Process and filter results (only new or changed issues)
        processed_results = []
        for summary, result_list in zip(summaries, results):
            for result in result_list:
                # Check if this is a new issue
                if await _is_new_vulnerability(pipeline_id, result):
                    result_dict = {
                        "scanner_type": result.scanner_type.value,
                        "rule_id": result.rule_id,
                        "title": result.title,
                        "description": result.description,
                        "severity": result.severity.value,
                        "confidence": result.confidence,
                        "file_path": result.file_path,
                        "line_number": result.line_number,
<<<<<<< HEAD
                        "meta_data": result.meta_data,
=======
                        "metadata": result.metadata,
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                    processed_results.append(result_dict)

        return processed_results

    except Exception as e:
        logger.error(f"Error executing monitoring scan: {str(e)}")
        raise


async def _store_scan_results(
    pipeline_id: int, scan_job_id: int, results: List[Dict[str, Any]]
):
    """Store scan results as vulnerabilities in database."""
    try:
<<<<<<< HEAD
        async with AsyncSessionLocal() as db:
=======
        async with async_session() as db:
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
            for result in results:
                vulnerability = Vulnerability(
                    pipeline_id=pipeline_id,
                    scan_job_id=scan_job_id,
                    scanner_type=result["scanner_type"],
                    rule_id=result["rule_id"],
                    title=result["title"],
                    description=result["description"],
                    severity=result["severity"],
                    confidence=result["confidence"],
                    file_path=result.get("file_path"),
                    line_number=result.get("line_number"),
                    column_number=result.get("column_number"),
                    code_snippet=result.get("code_snippet"),
                    cve_id=result.get("cve_id"),
                    cwe_id=result.get("cwe_id"),
                    cvss_score=result.get("cvss_score"),
                    remediation=result.get("remediation"),
                    references=result.get("references", []),
<<<<<<< HEAD
                    meta_data=result.get("meta_data", {}),
=======
                    metadata=result.get("metadata", {}),
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
                    status="open",
                    created_at=datetime.fromisoformat(
                        result["created_at"].replace("Z", "+00:00")
                    ),
                )
                db.add(vulnerability)

            await db.commit()
            logger.info(
                f"Stored {len(results)} vulnerabilities for pipeline {pipeline_id}"
            )

    except Exception as e:
        logger.error(f"Error storing scan results: {str(e)}")
        raise


async def _update_scan_job_status(
    scan_job_id: int, status: str, error_message: str = None
):
    """Update scan job status in database."""
    try:
<<<<<<< HEAD
        async with AsyncSessionLocal() as db:
=======
        async with async_session() as db:
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
            scan_job = await db.get(ScanJob, scan_job_id)
            if scan_job:
                scan_job.status = status
                if error_message:
                    scan_job.error_message = error_message
                if status in ["completed", "failed"]:
                    scan_job.completed_at = datetime.now(timezone.utc)

                await db.commit()
                logger.info(f"Updated scan job {scan_job_id} status to {status}")

    except Exception as e:
        logger.error(f"Error updating scan job status: {str(e)}")
        raise


async def _finalize_scan_job(
    scan_job_id: int, results: List[Dict[str, Any]], status: str
):
    """Finalize scan job with results summary."""
    try:
<<<<<<< HEAD
        async with AsyncSessionLocal() as db:
=======
        async with async_session() as db:
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
            scan_job = await db.get(ScanJob, scan_job_id)
            if scan_job:
                scan_job.status = status
                scan_job.completed_at = datetime.now(timezone.utc)

                # Calculate summary statistics
                total_findings = len(results)
                critical_findings = len(
                    [r for r in results if r["severity"] == "critical"]
                )
                high_findings = len([r for r in results if r["severity"] == "high"])
                medium_findings = len([r for r in results if r["severity"] == "medium"])
                low_findings = len([r for r in results if r["severity"] == "low"])

<<<<<<< HEAD
                # Extract AI-detected threats for summary
                ai_threats = [r for r in results if r["scanner_type"] == "ai_threat_detection"]
                ai_threat_count = len(ai_threats)
                ai_critical_count = len([t for t in ai_threats if t["severity"] == "critical"])
                ai_high_count = len([t for t in ai_threats if t["severity"] == "high"])
                ai_medium_count = len([t for t in ai_threats if t["severity"] == "medium"])
                ai_low_count = len([t for t in ai_threats if t["severity"] == "low"])

=======
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
                scan_job.results_summary = {
                    "total_findings": total_findings,
                    "critical_findings": critical_findings,
                    "high_findings": high_findings,
                    "medium_findings": medium_findings,
                    "low_findings": low_findings,
                    "scanners_used": list(set(r["scanner_type"] for r in results)),
<<<<<<< HEAD
                    "ai_threats": ai_threats,
                    "ai_threat_summary": {
                        "count": ai_threat_count,
                        "critical": ai_critical_count,
                        "high": ai_high_count,
                        "medium": ai_medium_count,
                        "low": ai_low_count,
                    } if ai_threat_count > 0 else {},
=======
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
                }

                await db.commit()
                logger.info(
                    f"Finalized scan job {scan_job_id} with {total_findings} findings"
                )

    except Exception as e:
        logger.error(f"Error finalizing scan job: {str(e)}")
        raise


async def _process_scan_alerts(pipeline_id: int, results: List[Dict[str, Any]]):
    """Process scan results and trigger alerts if needed."""
    try:
        # Get pipeline configuration
        pipeline_info = await _get_pipeline_info(pipeline_id)
        if not pipeline_info:
            return

        alert_config = pipeline_info.get("alert_config", {})
        if not alert_config.get("enabled", True):
            return

        # Check if alerts should be triggered
        critical_count = len([r for r in results if r["severity"] == "critical"])
        high_count = len([r for r in results if r["severity"] == "high"])

        should_alert = critical_count >= alert_config.get(
            "critical_threshold", 1
        ) or high_count >= alert_config.get("high_threshold", 5)

        if should_alert:
            # Create alert using AlertService
            alert_service = AlertService()
            await alert_service.create_scan_alert(
                pipeline_id=pipeline_id,
                severity="high" if critical_count > 0 else "medium",
                title=f"Security scan found {critical_count + high_count} high-severity issues",
                description=f"Pipeline {pipeline_info['name']} scan completed with {critical_count} critical and {high_count} high severity findings",
                metadata={
                    "scan_results_summary": {
                        "critical": critical_count,
                        "high": high_count,
                        "total": len(results),
                    }
                },
            )

            logger.info(
                f"Created alert for pipeline {pipeline_id} due to {critical_count + high_count} high-severity findings"
            )

    except Exception as e:
        logger.error(f"Error processing scan alerts: {str(e)}")


async def _process_monitoring_results(
    pipeline_id: int, scan_job_id: int, results: List[Dict[str, Any]]
):
    """Process monitoring scan results and handle notifications."""
    try:
        if not results:
            logger.info(
                f"No new issues found in monitoring scan for pipeline {pipeline_id}"
            )
            return

        # Store results
        await _store_scan_results(pipeline_id, scan_job_id, results)

        # Create monitoring alert if new issues found
        critical_count = len([r for r in results if r["severity"] == "critical"])
        high_count = len([r for r in results if r["severity"] == "high"])

        if critical_count > 0 or high_count > 0:
            alert_service = AlertService()
            await alert_service.create_monitoring_alert(
                pipeline_id=pipeline_id,
                severity="high" if critical_count > 0 else "medium",
                title=f"Monitoring detected {len(results)} new security issues",
                description=f"Continuous monitoring found {critical_count} critical and {high_count} high severity new issues",
                metadata={
                    "monitoring_results": {
                        "new_issues": len(results),
                        "critical": critical_count,
                        "high": high_count,
                    }
                },
            )

            logger.info(f"Created monitoring alert for pipeline {pipeline_id}")

    except Exception as e:
        logger.error(f"Error processing monitoring results: {str(e)}")


# Utility functions


async def _get_pipeline_info(pipeline_id: int) -> Optional[Dict[str, Any]]:
    """Get pipeline information from database."""
    try:
<<<<<<< HEAD
        async with AsyncSessionLocal() as db:
=======
        async with async_session() as db:
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
            pipeline = await db.get(Pipeline, pipeline_id)
            if pipeline:
                return {
                    "id": pipeline.id,
                    "name": pipeline.name,
                    "repository_url": pipeline.repository_url,
                    "target_path": getattr(pipeline, "target_path", None),
                    "alert_config": (
                        pipeline.configuration.get("alerts", {})
                        if pipeline.configuration
                        else {}
                    ),
                }
        return None

    except Exception as e:
        logger.error(f"Error getting pipeline info: {str(e)}")
        return None


async def _create_monitoring_scan_job(
    pipeline_id: int, monitoring_config: Dict[str, Any]
) -> int:
    """Create a scan job for monitoring."""
    try:
<<<<<<< HEAD
        async with AsyncSessionLocal() as db:
=======
        async with async_session() as db:
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
            scan_job = ScanJob(
                pipeline_id=pipeline_id,
                job_type="monitoring",
                status="pending",
                configuration=monitoring_config,
                created_at=datetime.now(timezone.utc),
            )
            db.add(scan_job)
            await db.flush()
            scan_job_id = scan_job.id
            await db.commit()

            return scan_job_id

    except Exception as e:
        logger.error(f"Error creating monitoring scan job: {str(e)}")
        raise


def _has_docker_files(target_path: str) -> bool:
    """Check if target path contains Docker files."""
    try:
        if not os.path.exists(target_path):
            return False

        docker_files = [
            "Dockerfile",
            "Containerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
        ]

        for root, dirs, files in os.walk(target_path):
            for file in files:
                if file in docker_files or file.startswith("Dockerfile."):
                    return True

        return False

    except Exception:
        return False


async def _is_new_vulnerability(pipeline_id: int, scan_result) -> bool:
    """Check if a vulnerability is new (not seen in previous scans)."""
    try:
<<<<<<< HEAD
        async with AsyncSessionLocal() as db:
=======
        async with async_session() as db:
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
            # Create a hash of the vulnerability for comparison
            vuln_hash = f"{scan_result.rule_id}:{scan_result.file_path}:{scan_result.line_number}"

            # Check if we've seen this vulnerability before (in last 30 days)
            from sqlalchemy import text

            query = text(
                """
                SELECT COUNT(*) FROM vulnerabilities 
                WHERE pipeline_id = :pipeline_id 
                AND rule_id = :rule_id 
                AND file_path = :file_path 
                AND line_number = :line_number
                AND created_at > NOW() - INTERVAL '30 days'
            """
            )

            result = await db.execute(
                query,
                {
                    "pipeline_id": pipeline_id,
                    "rule_id": scan_result.rule_id,
                    "file_path": scan_result.file_path,
                    "line_number": scan_result.line_number,
                },
            )

            count = result.scalar()
            return count == 0  # It's new if we haven't seen it before

    except Exception as e:
        logger.error(f"Error checking if vulnerability is new: {str(e)}")
        return True  # Assume it's new if we can't check
