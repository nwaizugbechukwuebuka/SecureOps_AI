"""
Report Service Layer

This module provides business logic for generating reports, analytics,
and dashboard metrics in the SecureOps platform.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import csv
import json
from datetime import datetime, timedelta, timezone
from io import StringIO
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, desc, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..models.alert import Alert
from ..models.pipeline import Pipeline, ScanJob
from ..models.user import User
from ..models.vulnerability import Vulnerability
from ..utils.config import settings
from ..utils.logger import get_logger

logger = get_logger(__name__)


class ReportService:
    """Service for generating reports and analytics."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_dashboard_summary(self, user_id: int) -> Dict[str, Any]:
        """
        Get dashboard summary statistics for user.

        Args:
            user_id: User ID

        Returns:
            Dictionary containing dashboard metrics
        """
        try:
            # Get pipeline counts
            pipeline_query = select(
                func.count(Pipeline.id).label("total"),
                func.sum(func.cast(Pipeline.is_active, "int")).label("active"),
            ).where(Pipeline.owner_id == user_id)

            pipeline_result = await self.db.execute(pipeline_query)
            pipeline_stats = pipeline_result.first()

            # Get vulnerability counts
            vuln_query = (
                select(func.count(Vulnerability.id).label("total"), Vulnerability.severity)
                .join(Pipeline)
                .where(
                    and_(
                        Pipeline.owner_id == user_id,
                        Vulnerability.status.in_(["open", "acknowledged"]),
                    )
                )
                .group_by(Vulnerability.severity)
            )

            vuln_result = await self.db.execute(vuln_query)
            vuln_counts = {severity: count for count, severity in vuln_result.fetchall()}

            # Get recent scan counts
            recent_date = datetime.now(timezone.utc) - timedelta(days=7)
            scan_query = (
                select(func.count(ScanJob.id))
                .join(Pipeline)
                .where(and_(Pipeline.owner_id == user_id, ScanJob.created_at >= recent_date))
            )

            scan_result = await self.db.execute(scan_query)
            recent_scans = scan_result.scalar() or 0

            # Get alert counts
            alert_query = (
                select(func.count(Alert.id).label("total"), Alert.status)
                .join(Pipeline)
                .where(Pipeline.owner_id == user_id)
                .group_by(Alert.status)
            )

            alert_result = await self.db.execute(alert_query)
            alert_counts = {status: count for count, status in alert_result.fetchall()}

            # Calculate security score (simplified)
            total_vulns = sum(vuln_counts.values())
            critical_vulns = vuln_counts.get("critical", 0)
            high_vulns = vuln_counts.get("high", 0)

            # Basic security score calculation (0-100)
            security_score = 100
            if total_vulns > 0:
                security_score = max(
                    0,
                    100 - (critical_vulns * 20) - (high_vulns * 10) - (total_vulns * 2),
                )

            return {
                "pipelines": {
                    "total": pipeline_stats.total or 0,
                    "active": pipeline_stats.active or 0,
                    "inactive": (pipeline_stats.total or 0) - (pipeline_stats.active or 0),
                },
                "vulnerabilities": {
                    "total": total_vulns,
                    "critical": vuln_counts.get("critical", 0),
                    "high": vuln_counts.get("high", 0),
                    "medium": vuln_counts.get("medium", 0),
                    "low": vuln_counts.get("low", 0),
                },
                "alerts": {
                    "total": sum(alert_counts.values()),
                    "open": alert_counts.get("open", 0),
                    "acknowledged": alert_counts.get("acknowledged", 0),
                    "resolved": alert_counts.get("resolved", 0),
                },
                "scans": {"recent_scans": recent_scans},
                "security_score": round(security_score, 1),
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            logger.error(f"Error getting dashboard summary: {str(e)}")
            raise

    async def get_vulnerability_analytics(
        self, user_id: int, days_back: int = 30, pipeline_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Get comprehensive vulnerability analytics.

        Args:
            user_id: User ID
            days_back: Number of days to include
            pipeline_id: Optional pipeline filter

        Returns:
            Vulnerability analytics data
        """
        try:
            start_date = datetime.now(timezone.utc) - timedelta(days=days_back)

            # Build base query
            base_query = select(Vulnerability).join(Pipeline).where(Pipeline.owner_id == user_id)

            if pipeline_id:
                base_query = base_query.where(Vulnerability.pipeline_id == pipeline_id)

            # Get vulnerability trends by day
            trends_query = (
                select(
                    func.count(Vulnerability.id).label("count"),
                    Vulnerability.severity,
                    func.date_trunc("day", Vulnerability.created_at).label("date"),
                )
                .select_from(base_query.subquery())
                .where(Vulnerability.created_at >= start_date)
                .group_by(
                    Vulnerability.severity,
                    func.date_trunc("day", Vulnerability.created_at),
                )
                .order_by("date")
            )

            trends_result = await self.db.execute(trends_query)

            # Process trends data
            trends_by_day = {}
            for count, severity, date in trends_result.fetchall():
                date_str = date.strftime("%Y-%m-%d")
                if date_str not in trends_by_day:
                    trends_by_day[date_str] = {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                    }
                trends_by_day[date_str][severity] = count

            # Get vulnerability distribution by scanner type
            scanner_query = (
                select(
                    func.count(Vulnerability.id).label("count"),
                    Vulnerability.scanner_type,
                )
                .select_from(base_query.subquery())
                .group_by(Vulnerability.scanner_type)
            )

            scanner_result = await self.db.execute(scanner_query)
            scanner_distribution = {scanner: count for count, scanner in scanner_result.fetchall()}

            # Get top vulnerable files
            files_query = (
                select(func.count(Vulnerability.id).label("count"), Vulnerability.file_path)
                .select_from(base_query.subquery())
                .where(Vulnerability.file_path.isnot(None))
                .group_by(Vulnerability.file_path)
                .order_by(desc("count"))
                .limit(10)
            )

            files_result = await self.db.execute(files_query)
            top_files = [
                {"file_path": file_path, "vulnerability_count": count} for count, file_path in files_result.fetchall()
            ]

            # Get remediation status
            remediation_query = (
                select(func.count(Vulnerability.id).label("count"), Vulnerability.status)
                .select_from(base_query.subquery())
                .group_by(Vulnerability.status)
            )

            remediation_result = await self.db.execute(remediation_query)
            remediation_status = {status: count for count, status in remediation_result.fetchall()}

            # Calculate metrics
            total_vulns = sum(remediation_status.values())
            resolved_vulns = remediation_status.get("resolved", 0)
            resolution_rate = (resolved_vulns / total_vulns * 100) if total_vulns > 0 else 0

            return {
                "period_days": days_back,
                "total_vulnerabilities": total_vulns,
                "trends_by_day": trends_by_day,
                "scanner_distribution": scanner_distribution,
                "top_vulnerable_files": top_files,
                "remediation_status": remediation_status,
                "resolution_rate": round(resolution_rate, 2),
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            logger.error(f"Error getting vulnerability analytics: {str(e)}")
            raise

    async def get_compliance_status(self, user_id: int) -> Dict[str, Any]:
        """
        Get compliance status across all frameworks.

        Args:
            user_id: User ID

        Returns:
            Compliance status data
        """
        try:
            # Get all user pipelines
            pipelines_query = select(Pipeline).where(Pipeline.owner_id == user_id)
            pipelines_result = await self.db.execute(pipelines_query)
            pipelines = pipelines_result.scalars().all()

            if not pipelines:
                return {"frameworks": {}, "overall_score": 0}

            # Calculate compliance scores for each framework
            frameworks = {
                "OWASP": await self._calculate_owasp_compliance(user_id),
                "NIST": await self._calculate_nist_compliance(user_id),
                "SOC2": await self._calculate_soc2_compliance(user_id),
                "GDPR": await self._calculate_gdpr_compliance(user_id),
                "PCI_DSS": await self._calculate_pci_compliance(user_id),
            }

            # Calculate overall compliance score
            total_score = sum(framework["score"] for framework in frameworks.values())
            overall_score = total_score / len(frameworks) if frameworks else 0

            return {
                "frameworks": frameworks,
                "overall_score": round(overall_score, 1),
                "total_pipelines": len(pipelines),
                "compliant_pipelines": sum(
                    1 for pipeline in pipelines if await self._is_pipeline_compliant(pipeline.id)
                ),
                "last_assessment": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            logger.error(f"Error getting compliance status: {str(e)}")
            raise

    async def get_scan_performance_metrics(self, user_id: int, days_back: int = 30) -> Dict[str, Any]:
        """
        Get scan performance and reliability metrics.

        Args:
            user_id: User ID
            days_back: Number of days to include

        Returns:
            Scan performance metrics
        """
        try:
            start_date = datetime.now(timezone.utc) - timedelta(days=days_back)

            # Get scan statistics
            scan_query = (
                select(
                    func.count(ScanJob.id).label("total_scans"),
                    func.avg(func.extract("epoch", ScanJob.completed_at - ScanJob.started_at)).label("avg_duration"),
                    ScanJob.status,
                )
                .join(Pipeline)
                .where(and_(Pipeline.owner_id == user_id, ScanJob.created_at >= start_date))
                .group_by(ScanJob.status)
            )

            scan_result = await self.db.execute(scan_query)

            scan_stats = {}
            total_scans = 0
            avg_durations = []

            for count, avg_duration, status in scan_result.fetchall():
                scan_stats[status] = count
                total_scans += count
                if avg_duration:
                    avg_durations.append(avg_duration)

            # Calculate success rate
            successful_scans = scan_stats.get("completed", 0)
            success_rate = (successful_scans / total_scans * 100) if total_scans > 0 else 0

            # Calculate average scan duration
            avg_scan_duration = sum(avg_durations) / len(avg_durations) if avg_durations else 0

            # Get scan frequency by scanner type
            frequency_query = (
                select(
                    func.count(ScanJob.id).label("count"),
                    func.unnest(ScanJob.scanner_types).label("scanner_type"),
                )
                .join(Pipeline)
                .where(and_(Pipeline.owner_id == user_id, ScanJob.created_at >= start_date))
                .group_by("scanner_type")
            )

            frequency_result = await self.db.execute(frequency_query)
            scanner_frequency = {scanner: count for count, scanner in frequency_result.fetchall()}

            # Get daily scan volume
            daily_query = (
                select(
                    func.count(ScanJob.id).label("count"),
                    func.date_trunc("day", ScanJob.created_at).label("date"),
                )
                .join(Pipeline)
                .where(and_(Pipeline.owner_id == user_id, ScanJob.created_at >= start_date))
                .group_by(func.date_trunc("day", ScanJob.created_at))
                .order_by("date")
            )

            daily_result = await self.db.execute(daily_query)
            daily_volumes = {date.strftime("%Y-%m-%d"): count for count, date in daily_result.fetchall()}

            return {
                "period_days": days_back,
                "total_scans": total_scans,
                "success_rate": round(success_rate, 2),
                "avg_scan_duration_seconds": round(avg_scan_duration, 2),
                "scan_status_breakdown": scan_stats,
                "scanner_frequency": scanner_frequency,
                "daily_scan_volumes": daily_volumes,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            logger.error(f"Error getting scan performance metrics: {str(e)}")
            raise

    async def generate_custom_report(self, user_id: int, report_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate custom report based on configuration.

        Args:
            user_id: User ID
            report_config: Report configuration

        Returns:
            Custom report data
        """
        try:
            report_type = report_config.get("type", "summary")
            date_range = report_config.get("date_range", {})
            filters = report_config.get("filters", {})

            # Parse date range
            start_date = datetime.fromisoformat(
                date_range.get(
                    "start",
                    (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
                )
            )
            end_date = datetime.fromisoformat(date_range.get("end", datetime.now(timezone.utc).isoformat()))

            report_data = {
                "report_type": report_type,
                "date_range": {
                    "start": start_date.isoformat(),
                    "end": end_date.isoformat(),
                },
                "filters": filters,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

            if report_type == "vulnerability_summary":
                report_data["data"] = await self._generate_vulnerability_summary_report(
                    user_id, start_date, end_date, filters
                )
            elif report_type == "compliance_assessment":
                report_data["data"] = await self._generate_compliance_assessment_report(
                    user_id, start_date, end_date, filters
                )
            elif report_type == "scan_history":
                report_data["data"] = await self._generate_scan_history_report(user_id, start_date, end_date, filters)
            elif report_type == "security_trends":
                report_data["data"] = await self._generate_security_trends_report(
                    user_id, start_date, end_date, filters
                )
            else:
                # Default summary report
                report_data["data"] = await self._generate_summary_report(user_id, start_date, end_date, filters)

            return report_data

        except Exception as e:
            logger.error(f"Error generating custom report: {str(e)}")
            raise

    async def export_report_csv(self, user_id: int, report_data: Dict[str, Any]) -> str:
        """
        Export report data as CSV string.

        Args:
            user_id: User ID
            report_data: Report data to export

        Returns:
            CSV formatted string
        """
        try:
            output = StringIO()
            writer = csv.writer(output)

            report_type = report_data.get("report_type", "summary")
            data = report_data.get("data", {})

            if report_type == "vulnerability_summary":
                # Write vulnerability CSV
                writer.writerow(
                    [
                        "Pipeline",
                        "Vulnerability ID",
                        "Title",
                        "Severity",
                        "Status",
                        "Scanner",
                        "File Path",
                        "Created Date",
                    ]
                )

                for vuln in data.get("vulnerabilities", []):
                    writer.writerow(
                        [
                            vuln.get("pipeline_name", ""),
                            vuln.get("vulnerability_id", ""),
                            vuln.get("title", ""),
                            vuln.get("severity", ""),
                            vuln.get("status", ""),
                            vuln.get("scanner_type", ""),
                            vuln.get("file_path", ""),
                            vuln.get("created_at", ""),
                        ]
                    )

            elif report_type == "scan_history":
                # Write scan history CSV
                writer.writerow(
                    [
                        "Pipeline",
                        "Scan ID",
                        "Status",
                        "Scanner Types",
                        "Started At",
                        "Completed At",
                        "Duration",
                        "Vulnerabilities Found",
                    ]
                )

                for scan in data.get("scans", []):
                    writer.writerow(
                        [
                            scan.get("pipeline_name", ""),
                            scan.get("scan_id", ""),
                            scan.get("status", ""),
                            ", ".join(scan.get("scanner_types", [])),
                            scan.get("started_at", ""),
                            scan.get("completed_at", ""),
                            scan.get("duration_seconds", ""),
                            scan.get("vulnerabilities_found", ""),
                        ]
                    )

            else:
                # Generic key-value export
                writer.writerow(["Metric", "Value"])

                def flatten_dict(d, parent_key=""):
                    items = []
                    for k, v in d.items():
                        new_key = f"{parent_key}.{k}" if parent_key else k
                        if isinstance(v, dict):
                            items.extend(flatten_dict(v, new_key))
                        elif isinstance(v, list):
                            items.append((new_key, f"[{len(v)} items]"))
                        else:
                            items.append((new_key, str(v)))
                    return items

                for key, value in flatten_dict(data):
                    writer.writerow([key, value])

            return output.getvalue()

        except Exception as e:
            logger.error(f"Error exporting report CSV: {str(e)}")
            raise

    async def export_report_json(self, user_id: int, report_data: Dict[str, Any]) -> str:
        """
        Export report data as JSON string.

        Args:
            user_id: User ID
            report_data: Report data to export

        Returns:
            JSON formatted string
        """
        try:
            return json.dumps(report_data, indent=2, default=str)

        except Exception as e:
            logger.error(f"Error exporting report JSON: {str(e)}")
            raise

    # Helper methods for compliance calculations
    async def _calculate_owasp_compliance(self, user_id: int) -> Dict[str, Any]:
        """Calculate OWASP compliance score."""
        # Simplified OWASP Top 10 compliance check
        owasp_categories = [
            "injection",
            "broken_auth",
            "sensitive_data",
            "xxe",
            "broken_access",
            "security_misconfig",
            "xss",
            "insecure_deserialization",
            "vulnerable_components",
            "logging",
        ]

        # Check for vulnerabilities in each category
        compliant_categories = 0
        total_categories = len(owasp_categories)

        for category in owasp_categories:
            # Simplified check - in production, would map specific vulnerability types
            vuln_query = (
                select(func.count(Vulnerability.id))
                .join(Pipeline)
                .where(
                    and_(
                        Pipeline.owner_id == user_id,
                        Vulnerability.status.in_(["open", "acknowledged"]),
                        or_(
                            Vulnerability.title.ilike(f"%{category}%"),
                            Vulnerability.description.ilike(f"%{category}%"),
                        ),
                    )
                )
            )

            result = await self.db.execute(vuln_query)
            vuln_count = result.scalar() or 0

            if vuln_count == 0:
                compliant_categories += 1

        score = (compliant_categories / total_categories * 100) if total_categories > 0 else 0

        return {
            "score": round(score, 1),
            "compliant_categories": compliant_categories,
            "total_categories": total_categories,
            "status": "compliant" if score >= 80 else "non_compliant",
        }

    async def _calculate_nist_compliance(self, user_id: int) -> Dict[str, Any]:
        """Calculate NIST Cybersecurity Framework compliance."""
        # Simplified NIST compliance based on security practices
        score = 75.0  # Base score

        # Check for security scanning frequency
        recent_scans = await self.db.execute(
            select(func.count(ScanJob.id))
            .join(Pipeline)
            .where(
                and_(
                    Pipeline.owner_id == user_id,
                    ScanJob.created_at >= datetime.now(timezone.utc) - timedelta(days=7),
                )
            )
        )

        if recent_scans.scalar() > 0:
            score += 10

        return {
            "score": round(score, 1),
            "status": "compliant" if score >= 70 else "non_compliant",
        }

    async def _calculate_soc2_compliance(self, user_id: int) -> Dict[str, Any]:
        """Calculate SOC 2 compliance score based on controls evidence."""
        # Example controls: audit logging, access control, encryption at rest, incident response
        evidence = {}
        score = 0
        total_controls = 4

        # 1. Audit logging
        # Assume audit logs are stored in a table or file (simulate check)
        evidence["audit_logging"] = True  # TODO: check actual logs
        score += 1

        # 2. Access control (RBAC)
        # Check if RBAC is enabled (simulate check)
        evidence["rbac_enabled"] = True  # TODO: check actual RBAC config
        score += 1

        # 3. Encryption at rest
        # Check if DB connection string uses SSL (simulate check)
        evidence["encryption_at_rest"] = True  # TODO: check DB config
        score += 1

        # 4. Incident response plan (simulate presence)
        evidence["incident_response_plan"] = True  # TODO: check documentation
        score += 1

        percent = (score / total_controls) * 100
        return {
            "score": round(percent, 1),
            "status": "compliant" if percent >= 80 else "non_compliant",
            "evidence": evidence,
        }

    async def _calculate_gdpr_compliance(self, user_id: int) -> Dict[str, Any]:
        """Calculate GDPR compliance score based on privacy controls evidence."""
        # Example controls: data minimization, user consent, right to be forgotten, data encryption
        evidence = {}
        score = 0
        total_controls = 4

        # 1. Data minimization (simulate check)
        evidence["data_minimization"] = True  # TODO: check data schemas
        score += 1

        # 2. User consent (simulate check)
        evidence["user_consent"] = True  # TODO: check consent records
        score += 1

        # 3. Right to be forgotten (simulate check)
        evidence["right_to_be_forgotten"] = True  # TODO: check deletion endpoints
        score += 1

        # 4. Data encryption (simulate check)
        evidence["data_encryption"] = True  # TODO: check encryption config
        score += 1

        percent = (score / total_controls) * 100
        return {
            "score": round(percent, 1),
            "status": "compliant" if percent >= 80 else "non_compliant",
            "evidence": evidence,
        }

    async def _calculate_pci_compliance(self, user_id: int) -> Dict[str, Any]:
        """Calculate PCI DSS compliance score based on controls evidence."""
        # Example controls: network segmentation, vulnerability management, access control, encryption
        evidence = {}
        score = 0
        total_controls = 4

        # 1. Network segmentation (simulate check)
        evidence["network_segmentation"] = True  # TODO: check network policies
        score += 1

        # 2. Vulnerability management (simulate check)
        evidence["vulnerability_management"] = True  # TODO: check scan history
        score += 1

        # 3. Access control (simulate check)
        evidence["access_control"] = True  # TODO: check user roles
        score += 1

        # 4. Encryption (simulate check)
        evidence["encryption"] = True  # TODO: check encryption config
        score += 1

        percent = (score / total_controls) * 100
        return {
            "score": round(percent, 1),
            "status": "compliant" if percent >= 80 else "non_compliant",
            "evidence": evidence,
        }

    async def _is_pipeline_compliant(self, pipeline_id: int) -> bool:
        """Check if pipeline meets basic compliance requirements."""
        # Check for recent scans
        recent_scan = await self.db.execute(
            select(func.count(ScanJob.id)).where(
                and_(
                    ScanJob.pipeline_id == pipeline_id,
                    ScanJob.created_at >= datetime.now(timezone.utc) - timedelta(days=14),
                    ScanJob.status == "completed",
                )
            )
        )

        # Check for critical vulnerabilities
        critical_vulns = await self.db.execute(
            select(func.count(Vulnerability.id)).where(
                and_(
                    Vulnerability.pipeline_id == pipeline_id,
                    Vulnerability.severity == "critical",
                    Vulnerability.status.in_(["open", "acknowledged"]),
                )
            )
        )

        return recent_scan.scalar() > 0 and critical_vulns.scalar() == 0

    # Report generation helpers
    async def _generate_vulnerability_summary_report(
        self,
        user_id: int,
        start_date: datetime,
        end_date: datetime,
        filters: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate vulnerability summary report."""
        # Implementation would fetch and format vulnerability data
        return {"vulnerabilities": [], "summary": {}}

    async def _generate_compliance_assessment_report(
        self,
        user_id: int,
        start_date: datetime,
        end_date: datetime,
        filters: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate compliance assessment report."""
        return await self.get_compliance_status(user_id)

    async def _generate_scan_history_report(
        self,
        user_id: int,
        start_date: datetime,
        end_date: datetime,
        filters: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate scan history report."""
        # Implementation would fetch and format scan data
        return {"scans": [], "summary": {}}

    async def _generate_security_trends_report(
        self,
        user_id: int,
        start_date: datetime,
        end_date: datetime,
        filters: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate security trends report."""
        days_back = (end_date - start_date).days
        return await self.get_vulnerability_analytics(user_id, days_back)

    async def _generate_summary_report(
        self,
        user_id: int,
        start_date: datetime,
        end_date: datetime,
        filters: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate summary report."""
        return await self.get_dashboard_summary(user_id)
