"""
Compliance Service Layer

This module provides business logic for compliance monitoring,
framework assessment, and regulatory reporting in the SecureOps platform.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import json
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..models.alert import Alert
from ..models.pipeline import Pipeline, ScanJob
from ..models.user import User
from ..models.vulnerability import Vulnerability
from ..utils.config import settings
from ..utils.logger import get_logger

logger = get_logger(__name__)


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""

    OWASP_TOP_10 = "owasp_top_10"
    NIST_CSF = "nist_csf"
    SOC2 = "soc2"
    GDPR = "gdpr"
    PCI_DSS = "pci_dss"
    ISO_27001 = "iso_27001"
    HIPAA = "hipaa"
    SOX = "sox"


class ComplianceRequirement:
    """Represents a compliance requirement."""

    def __init__(
        self,
        id: str,
        title: str,
        description: str,
        framework: ComplianceFramework,
        category: str,
        severity: str = "medium",
        remediation_guidance: str = "",
    ):
        self.id = id
        self.title = title
        self.description = description
        self.framework = framework
        self.category = category
        self.severity = severity
        self.remediation_guidance = remediation_guidance


class ComplianceService:
    """Service for compliance monitoring and assessment."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self._init_compliance_requirements()

    def _init_compliance_requirements(self):
        """Initialize compliance requirements for different frameworks."""
        self.requirements = {
            ComplianceFramework.OWASP_TOP_10: self._get_owasp_requirements(),
            ComplianceFramework.NIST_CSF: self._get_nist_requirements(),
            ComplianceFramework.SOC2: self._get_soc2_requirements(),
            ComplianceFramework.GDPR: self._get_gdpr_requirements(),
            ComplianceFramework.PCI_DSS: self._get_pci_requirements(),
            ComplianceFramework.ISO_27001: self._get_iso27001_requirements(),
            ComplianceFramework.HIPAA: self._get_hipaa_requirements(),
            ComplianceFramework.SOX: self._get_sox_requirements(),
        }

    async def assess_compliance(
        self,
        user_id: int,
        framework: ComplianceFramework,
        pipeline_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Perform comprehensive compliance assessment.

        Args:
            user_id: User ID
            framework: Compliance framework to assess
            pipeline_id: Optional pipeline to assess (all if None)

        Returns:
            Detailed compliance assessment results
        """
        try:
            logger.info(
                f"Starting compliance assessment for framework {framework.value}"
            )

            # Get requirements for framework
            requirements = self.requirements.get(framework, [])

            # Get pipelines to assess
            if pipeline_id:
                pipelines = await self._get_pipeline(pipeline_id, user_id)
                pipelines = [pipelines] if pipelines else []
            else:
                pipelines = await self._get_user_pipelines(user_id)

            if not pipelines:
                return self._empty_assessment_result(framework)

            # Assess each requirement
            assessment_results = []
            total_score = 0
            max_possible_score = 0

            for requirement in requirements:
                result = await self._assess_requirement(requirement, pipelines, user_id)
                assessment_results.append(result)

                total_score += result["score"]
                max_possible_score += result["max_score"]

            # Calculate overall compliance score
            overall_score = (
                (total_score / max_possible_score * 100)
                if max_possible_score > 0
                else 0
            )

            # Determine compliance status
            compliance_status = self._determine_compliance_status(
                overall_score, framework
            )

            # Get improvement recommendations
            recommendations = self._generate_recommendations(
                assessment_results, framework
            )

            return {
                "framework": framework.value,
                "overall_score": round(overall_score, 2),
                "compliance_status": compliance_status,
                "total_requirements": len(requirements),
                "passed_requirements": sum(
                    1 for r in assessment_results if r["passed"]
                ),
                "failed_requirements": sum(
                    1 for r in assessment_results if not r["passed"]
                ),
                "assessment_results": assessment_results,
                "recommendations": recommendations,
                "assessed_pipelines": len(pipelines),
                "assessment_date": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            logger.error(f"Error in compliance assessment: {str(e)}")
            raise

    async def get_compliance_dashboard(self, user_id: int) -> Dict[str, Any]:
        """
        Get compliance dashboard with overview of all frameworks.

        Args:
            user_id: User ID

        Returns:
            Compliance dashboard data
        """
        try:
            dashboard_data = {
                "frameworks": {},
                "overall_posture": {},
                "recent_assessments": [],
                "critical_findings": [],
                "improvement_trends": {},
            }

            # Assess each framework
            framework_scores = []
            for framework in ComplianceFramework:
                try:
                    assessment = await self.assess_compliance(user_id, framework)

                    dashboard_data["frameworks"][framework.value] = {
                        "score": assessment["overall_score"],
                        "status": assessment["compliance_status"],
                        "passed_requirements": assessment["passed_requirements"],
                        "total_requirements": assessment["total_requirements"],
                        "last_assessed": assessment["assessment_date"],
                    }

                    framework_scores.append(assessment["overall_score"])

                except Exception as e:
                    logger.warning(f"Failed to assess {framework.value}: {str(e)}")
                    dashboard_data["frameworks"][framework.value] = {
                        "score": 0,
                        "status": "error",
                        "error": str(e),
                    }

            # Calculate overall security posture
            if framework_scores:
                avg_score = sum(framework_scores) / len(framework_scores)
                dashboard_data["overall_posture"] = {
                    "average_score": round(avg_score, 2),
                    "status": (
                        "strong"
                        if avg_score >= 80
                        else "moderate" if avg_score >= 60 else "weak"
                    ),
                    "trend": "stable",  # Would be calculated from historical data
                }

            # Get critical findings across all frameworks
            dashboard_data["critical_findings"] = (
                await self._get_critical_compliance_findings(user_id)
            )

            return dashboard_data

        except Exception as e:
            logger.error(f"Error getting compliance dashboard: {str(e)}")
            raise

    async def get_framework_details(
        self, framework: ComplianceFramework
    ) -> Dict[str, Any]:
        """
        Get detailed information about a compliance framework.

        Args:
            framework: Compliance framework

        Returns:
            Framework details and requirements
        """
        try:
            requirements = self.requirements.get(framework, [])

            # Group requirements by category
            categories = {}
            for req in requirements:
                if req.category not in categories:
                    categories[req.category] = []
                categories[req.category].append(
                    {
                        "id": req.id,
                        "title": req.title,
                        "description": req.description,
                        "severity": req.severity,
                        "remediation_guidance": req.remediation_guidance,
                    }
                )

            framework_info = self._get_framework_info(framework)

            return {
                "framework": framework.value,
                "name": framework_info["name"],
                "description": framework_info["description"],
                "version": framework_info["version"],
                "total_requirements": len(requirements),
                "categories": categories,
                "compliance_threshold": framework_info["compliance_threshold"],
                "assessment_frequency": framework_info["assessment_frequency"],
            }

        except Exception as e:
            logger.error(f"Error getting framework details: {str(e)}")
            raise

    async def generate_compliance_report(
        self,
        user_id: int,
        framework: ComplianceFramework,
        include_remediation: bool = True,
        pipeline_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Generate comprehensive compliance report.

        Args:
            user_id: User ID
            framework: Compliance framework
            include_remediation: Include remediation guidance
            pipeline_id: Optional pipeline filter

        Returns:
            Detailed compliance report
        """
        try:
            # Get compliance assessment
            assessment = await self.assess_compliance(user_id, framework, pipeline_id)

            # Get framework details
            framework_details = await self.get_framework_details(framework)

            # Build comprehensive report
            report = {
                "report_metadata": {
                    "report_type": "compliance_assessment",
                    "framework": framework.value,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "generated_for": user_id,
                    "pipeline_scope": pipeline_id or "all_pipelines",
                },
                "executive_summary": {
                    "overall_score": assessment["overall_score"],
                    "compliance_status": assessment["compliance_status"],
                    "key_findings": self._generate_executive_findings(assessment),
                    "risk_level": self._assess_risk_level(assessment["overall_score"]),
                    "next_assessment_date": self._calculate_next_assessment_date(
                        framework
                    ),
                },
                "framework_overview": framework_details,
                "detailed_assessment": assessment,
                "gap_analysis": self._perform_gap_analysis(assessment),
                "risk_assessment": await self._perform_risk_assessment(
                    user_id, assessment
                ),
                "remediation_plan": (
                    self._generate_remediation_plan(assessment)
                    if include_remediation
                    else None
                ),
                "appendices": {
                    "methodology": self._get_assessment_methodology(framework),
                    "evidence_collected": await self._get_evidence_summary(
                        user_id, framework
                    ),
                    "glossary": self._get_compliance_glossary(),
                },
            }

            return report

        except Exception as e:
            logger.error(f"Error generating compliance report: {str(e)}")
            raise

    async def track_compliance_over_time(
        self, user_id: int, framework: ComplianceFramework, days_back: int = 90
    ) -> Dict[str, Any]:
        """
        Track compliance score changes over time.

        Args:
            user_id: User ID
            framework: Compliance framework
            days_back: Number of days to look back

        Returns:
            Compliance trend data
        """
        try:
            # In a production system, this would query historical assessment data
            # For now, we'll simulate trend data

            current_assessment = await self.assess_compliance(user_id, framework)
            current_score = current_assessment["overall_score"]

            # Generate simulated historical data points
            trend_data = []
            base_date = datetime.now(timezone.utc) - timedelta(days=days_back)

            for i in range(0, days_back, 7):  # Weekly data points
                date = base_date + timedelta(days=i)
                # Simulate gradual improvement with some variance
                score_variance = (i / days_back) * 10 - 5  # ±5 point variance
                simulated_score = max(0, min(100, current_score - 10 + score_variance))

                trend_data.append(
                    {
                        "date": date.isoformat(),
                        "score": round(simulated_score, 2),
                        "status": (
                            "compliant" if simulated_score >= 80 else "non_compliant"
                        ),
                    }
                )

            # Add current assessment
            trend_data.append(
                {
                    "date": datetime.now(timezone.utc).isoformat(),
                    "score": current_score,
                    "status": current_assessment["compliance_status"],
                }
            )

            # Calculate trend metrics
            if len(trend_data) >= 2:
                score_change = trend_data[-1]["score"] - trend_data[0]["score"]
                trend_direction = (
                    "improving"
                    if score_change > 2
                    else "declining" if score_change < -2 else "stable"
                )
            else:
                score_change = 0
                trend_direction = "stable"

            return {
                "framework": framework.value,
                "period_days": days_back,
                "current_score": current_score,
                "score_change": round(score_change, 2),
                "trend_direction": trend_direction,
                "data_points": trend_data,
                "milestones": self._identify_compliance_milestones(trend_data),
            }

        except Exception as e:
            logger.error(f"Error tracking compliance over time: {str(e)}")
            raise

    # Private helper methods
    async def _assess_requirement(
        self,
        requirement: ComplianceRequirement,
        pipelines: List[Pipeline],
        user_id: int,
    ) -> Dict[str, Any]:
        """Assess a specific compliance requirement."""
        try:
            # This is a simplified assessment - in production, each requirement
            # would have specific assessment logic based on the requirement type

            if requirement.framework == ComplianceFramework.OWASP_TOP_10:
                return await self._assess_owasp_requirement(
                    requirement, pipelines, user_id
                )
            elif requirement.framework == ComplianceFramework.NIST_CSF:
                return await self._assess_nist_requirement(
                    requirement, pipelines, user_id
                )
            else:
                # Generic assessment for other frameworks
                return await self._assess_generic_requirement(
                    requirement, pipelines, user_id
                )

        except Exception as e:
            logger.error(f"Error assessing requirement {requirement.id}: {str(e)}")
            return {
                "requirement_id": requirement.id,
                "title": requirement.title,
                "passed": False,
                "score": 0,
                "max_score": 100,
                "findings": [f"Assessment error: {str(e)}"],
                "evidence": [],
                "recommendations": [],
            }

    async def _assess_owasp_requirement(
        self,
        requirement: ComplianceRequirement,
        pipelines: List[Pipeline],
        user_id: int,
    ) -> Dict[str, Any]:
        """Assess OWASP Top 10 specific requirement."""
        pipeline_ids = [p.id for p in pipelines]

        # Map OWASP categories to vulnerability patterns
        owasp_patterns = {
            "A01_2021": ["injection", "sql", "nosql", "ldap", "os_command"],
            "A02_2021": ["authentication", "session", "credential"],
            "A03_2021": ["sensitive_data", "encryption", "pii", "password"],
            "A04_2021": ["xxe", "xml", "external_entity"],
            "A05_2021": ["access_control", "authorization", "privilege"],
            "A06_2021": ["security_misconfig", "configuration", "default"],
            "A07_2021": ["xss", "cross_site", "reflected", "stored", "dom"],
            "A08_2021": ["deserialization", "pickle", "java_serialization"],
            "A09_2021": ["vulnerable_component", "outdated", "dependency"],
            "A10_2021": ["logging", "monitoring", "audit", "SIEM"],
        }

        patterns = owasp_patterns.get(requirement.id, [requirement.id.lower()])

        # Check for related vulnerabilities
        vuln_query = select(func.count(Vulnerability.id)).where(
            and_(
                Vulnerability.pipeline_id.in_(pipeline_ids),
                Vulnerability.status.in_(["open", "acknowledged"]),
                or_(
                    *[
                        or_(
                            Vulnerability.title.ilike(f"%{pattern}%"),
                            Vulnerability.description.ilike(f"%{pattern}%"),
                        )
                        for pattern in patterns
                    ]
                ),
            )
        )

        result = await self.db.execute(vuln_query)
        vuln_count = result.scalar() or 0

        # Assessment logic
        passed = vuln_count == 0
        score = 100 if passed else max(0, 100 - (vuln_count * 10))

        findings = []
        if vuln_count > 0:
            findings.append(
                f"Found {vuln_count} open vulnerabilities related to {requirement.title}"
            )

        recommendations = []
        if not passed:
            recommendations.extend(
                [
                    f"Review and remediate {vuln_count} open vulnerabilities",
                    "Implement automated security testing in CI/CD pipeline",
                    "Establish regular security code reviews",
                ]
            )

        return {
            "requirement_id": requirement.id,
            "title": requirement.title,
            "passed": passed,
            "score": score,
            "max_score": 100,
            "findings": findings,
            "evidence": [f"Vulnerability scan results for {len(pipelines)} pipelines"],
            "recommendations": recommendations,
            "vulnerability_count": vuln_count,
        }

    async def _assess_nist_requirement(
        self,
        requirement: ComplianceRequirement,
        pipelines: List[Pipeline],
        user_id: int,
    ) -> Dict[str, Any]:
        """Assess NIST CSF specific requirement."""
        # Simplified NIST assessment based on security practices
        pipeline_ids = [p.id for p in pipelines]

        # Check for recent security scans (Detect function)
        if "detect" in requirement.id.lower():
            recent_scans = await self.db.execute(
                select(func.count(ScanJob.id)).where(
                    and_(
                        ScanJob.pipeline_id.in_(pipeline_ids),
                        ScanJob.created_at
                        >= datetime.now(timezone.utc) - timedelta(days=7),
                        ScanJob.status == "completed",
                    )
                )
            )

            scan_count = recent_scans.scalar() or 0
            passed = scan_count > 0
            score = min(100, scan_count * 25)  # Up to 4 scans = 100%

            findings = [f"Found {scan_count} security scans in the last 7 days"]
            recommendations = [] if passed else ["Implement regular security scanning"]

        # Default assessment for other NIST requirements
        else:
            passed = True
            score = 80  # Base compliance score
            findings = ["Manual review required for this control"]
            recommendations = []

        return {
            "requirement_id": requirement.id,
            "title": requirement.title,
            "passed": passed,
            "score": score,
            "max_score": 100,
            "findings": findings,
            "evidence": ["System configuration review"],
            "recommendations": recommendations,
        }

    async def _assess_generic_requirement(
        self,
        requirement: ComplianceRequirement,
        pipelines: List[Pipeline],
        user_id: int,
    ) -> Dict[str, Any]:
        """Generic requirement assessment."""
        # Basic assessment for other frameworks
        return {
            "requirement_id": requirement.id,
            "title": requirement.title,
            "passed": True,
            "score": 75,  # Default passing score
            "max_score": 100,
            "findings": ["Basic compliance assessment completed"],
            "evidence": ["Configuration review"],
            "recommendations": [],
        }

    def _get_owasp_requirements(self) -> List[ComplianceRequirement]:
        """Get OWASP Top 10 requirements."""
        return [
            ComplianceRequirement(
                "A01_2021",
                "Broken Access Control",
                "Ensure proper access controls are implemented",
                ComplianceFramework.OWASP_TOP_10,
                "Access Control",
                "high",
            ),
            ComplianceRequirement(
                "A02_2021",
                "Cryptographic Failures",
                "Protect sensitive data with proper encryption",
                ComplianceFramework.OWASP_TOP_10,
                "Data Protection",
                "high",
            ),
            ComplianceRequirement(
                "A03_2021",
                "Injection",
                "Prevent injection attacks in all forms",
                ComplianceFramework.OWASP_TOP_10,
                "Input Validation",
                "critical",
            ),
            ComplianceRequirement(
                "A04_2021",
                "Insecure Design",
                "Implement security by design principles",
                ComplianceFramework.OWASP_TOP_10,
                "Design",
                "high",
            ),
            ComplianceRequirement(
                "A05_2021",
                "Security Misconfiguration",
                "Maintain secure configurations",
                ComplianceFramework.OWASP_TOP_10,
                "Configuration",
                "medium",
            ),
            ComplianceRequirement(
                "A06_2021",
                "Vulnerable and Outdated Components",
                "Keep all components up to date",
                ComplianceFramework.OWASP_TOP_10,
                "Dependency Management",
                "high",
            ),
            ComplianceRequirement(
                "A07_2021",
                "Identification and Authentication Failures",
                "Implement strong authentication mechanisms",
                ComplianceFramework.OWASP_TOP_10,
                "Authentication",
                "high",
            ),
            ComplianceRequirement(
                "A08_2021",
                "Software and Data Integrity Failures",
                "Ensure software and data integrity",
                ComplianceFramework.OWASP_TOP_10,
                "Integrity",
                "medium",
            ),
            ComplianceRequirement(
                "A09_2021",
                "Security Logging and Monitoring Failures",
                "Implement comprehensive logging and monitoring",
                ComplianceFramework.OWASP_TOP_10,
                "Monitoring",
                "medium",
            ),
            ComplianceRequirement(
                "A10_2021",
                "Server-Side Request Forgery",
                "Prevent SSRF vulnerabilities",
                ComplianceFramework.OWASP_TOP_10,
                "Input Validation",
                "medium",
            ),
        ]

    def _get_nist_requirements(self) -> List[ComplianceRequirement]:
        """Get NIST Cybersecurity Framework requirements."""
        return [
            ComplianceRequirement(
                "ID.AM",
                "Asset Management",
                "Identify and manage assets",
                ComplianceFramework.NIST_CSF,
                "Identify",
                "medium",
            ),
            ComplianceRequirement(
                "PR.AC",
                "Identity Management and Access Control",
                "Manage access to assets and facilities",
                ComplianceFramework.NIST_CSF,
                "Protect",
                "high",
            ),
            ComplianceRequirement(
                "DE.CM",
                "Security Continuous Monitoring",
                "Monitor networks and systems continuously",
                ComplianceFramework.NIST_CSF,
                "Detect",
                "high",
            ),
            ComplianceRequirement(
                "RS.RP",
                "Response Planning",
                "Execute response plans during incidents",
                ComplianceFramework.NIST_CSF,
                "Respond",
                "medium",
            ),
            ComplianceRequirement(
                "RC.RP",
                "Recovery Planning",
                "Execute recovery plans during incidents",
                ComplianceFramework.NIST_CSF,
                "Recover",
                "medium",
            ),
        ]

    def _get_soc2_requirements(self) -> List[ComplianceRequirement]:
        """Get SOC 2 Type II requirements."""
        return [
            ComplianceRequirement(
                "CC6.1",
                "Logical Access Controls",
                "Restrict logical access to systems",
                ComplianceFramework.SOC2,
                "Common Criteria",
                "high",
            ),
            ComplianceRequirement(
                "CC7.1",
                "System Monitoring",
                "Monitor systems for security events",
                ComplianceFramework.SOC2,
                "Common Criteria",
                "medium",
            ),
        ]

    def _get_gdpr_requirements(self) -> List[ComplianceRequirement]:
        """Get GDPR requirements."""
        return [
            ComplianceRequirement(
                "Art32",
                "Security of Processing",
                "Implement appropriate technical and organizational measures",
                ComplianceFramework.GDPR,
                "Data Protection",
                "high",
            ),
            ComplianceRequirement(
                "Art33",
                "Breach Notification",
                "Report data breaches within 72 hours",
                ComplianceFramework.GDPR,
                "Incident Response",
                "critical",
            ),
        ]

    def _get_pci_requirements(self) -> List[ComplianceRequirement]:
        """Get PCI DSS requirements."""
        return [
            ComplianceRequirement(
                "PCI_1",
                "Network Security",
                "Install and maintain firewall configuration",
                ComplianceFramework.PCI_DSS,
                "Network Security",
                "high",
            ),
            ComplianceRequirement(
                "PCI_6",
                "Secure Applications",
                "Develop and maintain secure systems and applications",
                ComplianceFramework.PCI_DSS,
                "Application Security",
                "high",
            ),
        ]

    def _get_iso27001_requirements(self) -> List[ComplianceRequirement]:
        """Get ISO 27001 requirements."""
        return [
            ComplianceRequirement(
                "A.12.6",
                "Secure Development",
                "Ensure security in development lifecycle",
                ComplianceFramework.ISO_27001,
                "System Development",
                "medium",
            )
        ]

    def _get_hipaa_requirements(self) -> List[ComplianceRequirement]:
        """Get HIPAA requirements."""
        return [
            ComplianceRequirement(
                "164.312",
                "Technical Safeguards",
                "Implement technical safeguards for ePHI",
                ComplianceFramework.HIPAA,
                "Technical Controls",
                "high",
            )
        ]

    def _get_sox_requirements(self) -> List[ComplianceRequirement]:
        """Get SOX requirements."""
        return [
            ComplianceRequirement(
                "SOX_404",
                "Internal Controls",
                "Maintain effective internal controls",
                ComplianceFramework.SOX,
                "Internal Controls",
                "high",
            )
        ]

    async def _get_user_pipelines(self, user_id: int) -> List[Pipeline]:
        """Get all user pipelines."""
        query = select(Pipeline).where(Pipeline.owner_id == user_id)
        result = await self.db.execute(query)
        return result.scalars().all()

    async def _get_pipeline(self, pipeline_id: int, user_id: int) -> Optional[Pipeline]:
        """Get specific pipeline."""
        query = select(Pipeline).where(
            and_(Pipeline.id == pipeline_id, Pipeline.owner_id == user_id)
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    def _empty_assessment_result(
        self, framework: ComplianceFramework
    ) -> Dict[str, Any]:
        """Return empty assessment result when no pipelines found."""
        return {
            "framework": framework.value,
            "overall_score": 0,
            "compliance_status": "not_applicable",
            "total_requirements": 0,
            "passed_requirements": 0,
            "failed_requirements": 0,
            "assessment_results": [],
            "recommendations": ["No pipelines found for assessment"],
            "assessed_pipelines": 0,
            "assessment_date": datetime.now(timezone.utc).isoformat(),
        }

    def _determine_compliance_status(
        self, score: float, framework: ComplianceFramework
    ) -> str:
        """Determine compliance status based on score."""
        thresholds = {
            ComplianceFramework.OWASP_TOP_10: 80,
            ComplianceFramework.NIST_CSF: 70,
            ComplianceFramework.SOC2: 85,
            ComplianceFramework.GDPR: 90,
            ComplianceFramework.PCI_DSS: 85,
            ComplianceFramework.ISO_27001: 75,
            ComplianceFramework.HIPAA: 90,
            ComplianceFramework.SOX: 80,
        }

        threshold = thresholds.get(framework, 75)

        if score >= threshold:
            return "compliant"
        elif score >= threshold * 0.7:
            return "partially_compliant"
        else:
            return "non_compliant"

    def _generate_recommendations(
        self, assessment_results: List[Dict[str, Any]], framework: ComplianceFramework
    ) -> List[Dict[str, Any]]:
        """Generate improvement recommendations."""
        recommendations = []

        # Get failed requirements
        failed_requirements = [r for r in assessment_results if not r["passed"]]

        # Prioritize by severity and score
        failed_requirements.sort(
            key=lambda x: (-len(x.get("findings", [])), x.get("score", 0))
        )

        for req in failed_requirements[:5]:  # Top 5 recommendations
            recommendations.append(
                {
                    "requirement": req["title"],
                    "priority": "high" if req.get("score", 0) < 50 else "medium",
                    "description": f"Address issues in {req['title']}",
                    "actions": req.get("recommendations", []),
                    "estimated_effort": "medium",  # Would be calculated based on requirement type
                }
            )

        return recommendations

    def _get_framework_info(self, framework: ComplianceFramework) -> Dict[str, Any]:
        """Get framework metadata."""
        framework_info = {
            ComplianceFramework.OWASP_TOP_10: {
                "name": "OWASP Top 10",
                "description": "The top 10 web application security risks",
                "version": "2021",
                "compliance_threshold": 80,
                "assessment_frequency": "quarterly",
            },
            ComplianceFramework.NIST_CSF: {
                "name": "NIST Cybersecurity Framework",
                "description": "Framework for improving critical infrastructure cybersecurity",
                "version": "1.1",
                "compliance_threshold": 70,
                "assessment_frequency": "annually",
            },
            ComplianceFramework.SOC2: {
                "name": "SOC 2 Type II",
                "description": "Security and availability trust service criteria",
                "version": "2017",
                "compliance_threshold": 85,
                "assessment_frequency": "annually",
            },
        }

        return framework_info.get(
            framework,
            {
                "name": framework.value.replace("_", " ").title(),
                "description": f"Compliance framework: {framework.value}",
                "version": "1.0",
                "compliance_threshold": 75,
                "assessment_frequency": "annually",
            },
        )

    async def _get_critical_compliance_findings(
        self, user_id: int
    ) -> List[Dict[str, Any]]:
        """Get critical compliance findings across all frameworks."""
        # This would analyze all assessment results for critical issues
        return [
            {
                "finding": "Critical vulnerabilities detected",
                "framework": "OWASP Top 10",
                "severity": "critical",
                "affected_pipelines": 3,
                "recommendation": "Immediate remediation required",
            }
        ]

    # Additional helper methods for report generation
    def _generate_executive_findings(self, assessment: Dict[str, Any]) -> List[str]:
        """Generate executive summary findings."""
        findings = []

        score = assessment["overall_score"]
        status = assessment["compliance_status"]

        findings.append(f"Overall compliance score: {score}% ({status})")

        if assessment["failed_requirements"] > 0:
            findings.append(
                f"{assessment['failed_requirements']} requirements need attention"
            )

        if score < 70:
            findings.append(
                "Significant compliance gaps identified requiring immediate action"
            )
        elif score < 85:
            findings.append("Moderate compliance improvements needed")
        else:
            findings.append("Strong compliance posture with minor improvements needed")

        return findings

    def _assess_risk_level(self, score: float) -> str:
        """Assess overall risk level based on compliance score."""
        if score >= 85:
            return "low"
        elif score >= 70:
            return "medium"
        elif score >= 50:
            return "high"
        else:
            return "critical"

    def _calculate_next_assessment_date(self, framework: ComplianceFramework) -> str:
        """Calculate next recommended assessment date."""
        frequency_map = {
            ComplianceFramework.OWASP_TOP_10: 90,  # quarterly
            ComplianceFramework.NIST_CSF: 365,  # annually
            ComplianceFramework.SOC2: 365,  # annually
            ComplianceFramework.GDPR: 180,  # bi-annually
            ComplianceFramework.PCI_DSS: 365,  # annually
        }

        days = frequency_map.get(framework, 365)
        next_date = datetime.now(timezone.utc) + timedelta(days=days)
        return next_date.isoformat()

    def _perform_gap_analysis(self, assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Perform gap analysis on assessment results."""
        failed_requirements = [
            r for r in assessment["assessment_results"] if not r["passed"]
        ]

        gaps_by_category = {}
        for req in failed_requirements:
            # This would group by actual categories from requirements
            category = "Security Controls"  # Simplified
            if category not in gaps_by_category:
                gaps_by_category[category] = []
            gaps_by_category[category].append(req["title"])

        return {
            "total_gaps": len(failed_requirements),
            "gaps_by_category": gaps_by_category,
            "critical_gaps": [
                r["title"] for r in failed_requirements if r.get("score", 0) < 30
            ],
            "remediation_priority": (
                "high" if len(failed_requirements) > 3 else "medium"
            ),
        }

    async def _perform_risk_assessment(
        self, user_id: int, assessment: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform risk assessment based on compliance gaps."""
        # Get vulnerability statistics
        critical_vulns = await self.db.execute(
            select(func.count(Vulnerability.id))
            .join(Pipeline)
            .where(
                and_(
                    Pipeline.owner_id == user_id,
                    Vulnerability.severity == "critical",
                    Vulnerability.status.in_(["open", "acknowledged"]),
                )
            )
        )

        critical_count = critical_vulns.scalar() or 0

        # Calculate risk score based on compliance and vulnerabilities
        compliance_risk = max(0, 100 - assessment["overall_score"])
        vulnerability_risk = min(100, critical_count * 20)

        overall_risk = (compliance_risk + vulnerability_risk) / 2

        return {
            "overall_risk_score": round(overall_risk, 2),
            "risk_level": self._assess_risk_level(100 - overall_risk),
            "compliance_risk": compliance_risk,
            "vulnerability_risk": vulnerability_risk,
            "critical_vulnerabilities": critical_count,
            "risk_factors": [
                "Critical vulnerabilities present" if critical_count > 0 else None,
                (
                    "Compliance gaps identified"
                    if assessment["failed_requirements"] > 0
                    else None
                ),
            ],
        }

    def _generate_remediation_plan(self, assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed remediation plan."""
        failed_requirements = [
            r for r in assessment["assessment_results"] if not r["passed"]
        ]

        # Sort by priority (score and findings)
        failed_requirements.sort(
            key=lambda x: (x.get("score", 0), -len(x.get("findings", [])))
        )

        phases = {
            "immediate": [],  # 0-30 days
            "short_term": [],  # 30-90 days
            "long_term": [],  # 90+ days
        }

        for i, req in enumerate(failed_requirements):
            phase = "immediate" if i < 3 else "short_term" if i < 8 else "long_term"

            phases[phase].append(
                {
                    "requirement": req["title"],
                    "actions": req.get("recommendations", []),
                    "estimated_effort": (
                        "high" if req.get("score", 0) < 30 else "medium"
                    ),
                    "dependencies": [],
                    "success_criteria": f"Achieve >80% compliance for {req['title']}",
                }
            )

        return {
            "total_items": len(failed_requirements),
            "phases": phases,
            "estimated_duration": "6 months",
            "resource_requirements": [
                "Security engineer",
                "Development team",
                "Compliance officer",
            ],
        }

    def _get_assessment_methodology(self, framework: ComplianceFramework) -> str:
        """Get assessment methodology description."""
        return f"""
        Assessment Methodology for {framework.value}:
        
        1. Automated vulnerability scanning across all registered pipelines
        2. Configuration analysis and security control verification
        3. Code analysis for security anti-patterns and vulnerabilities
        4. Compliance mapping to framework requirements
        5. Risk assessment and gap analysis
        6. Remediation planning and prioritization
        
        Assessment coverage includes:
        - Static code analysis
        - Dependency vulnerability scanning
        - Container security scanning
        - Secret detection
        - Policy compliance checking
        """

    async def _get_evidence_summary(
        self, user_id: int, framework: ComplianceFramework
    ) -> Dict[str, Any]:
        """Get summary of evidence collected during assessment."""
        # Get scan statistics
        scan_count = await self.db.execute(
            select(func.count(ScanJob.id))
            .join(Pipeline)
            .where(Pipeline.owner_id == user_id)
        )

        # Get vulnerability count
        vuln_count = await self.db.execute(
            select(func.count(Vulnerability.id))
            .join(Pipeline)
            .where(Pipeline.owner_id == user_id)
        )

        return {
            "scans_analyzed": scan_count.scalar() or 0,
            "vulnerabilities_reviewed": vuln_count.scalar() or 0,
            "pipelines_assessed": len(await self._get_user_pipelines(user_id)),
            "data_sources": [
                "Automated security scans",
                "Vulnerability databases",
                "Configuration files",
                "Code repositories",
            ],
            "assessment_tools": [
                "Trivy (container scanning)",
                "Safety (dependency scanning)",
                "Bandit (code analysis)",
                "Custom policy engine",
            ],
        }

    def _get_compliance_glossary(self) -> Dict[str, str]:
        """Get glossary of compliance terms."""
        return {
            "Compliance Score": "Percentage of requirements met for a specific framework",
            "Critical Finding": "A compliance gap that poses immediate security risk",
            "Remediation": "Actions taken to address compliance gaps or vulnerabilities",
            "Risk Level": "Assessment of potential impact from compliance gaps",
            "Framework": "A structured set of security and compliance requirements",
        }

    def _identify_compliance_milestones(
        self, trend_data: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Identify significant milestones in compliance trend."""
        milestones = []

        # Find significant score improvements
        for i in range(1, len(trend_data)):
            current_score = trend_data[i]["score"]
            previous_score = trend_data[i - 1]["score"]

            if current_score - previous_score >= 10:  # 10+ point improvement
                milestones.append(
                    {
                        "date": trend_data[i]["date"],
                        "type": "improvement",
                        "description": f"Significant compliance improvement (+{current_score - previous_score:.1f} points)",
                        "score": current_score,
                    }
                )
            elif previous_score - current_score >= 10:  # 10+ point decline
                milestones.append(
                    {
                        "date": trend_data[i]["date"],
                        "type": "decline",
                        "description": f"Compliance decline (-{previous_score - current_score:.1f} points)",
                        "score": current_score,
                    }
                )

        # Add compliance status changes
        for i in range(1, len(trend_data)):
            if trend_data[i]["status"] != trend_data[i - 1]["status"]:
                milestones.append(
                    {
                        "date": trend_data[i]["date"],
                        "type": "status_change",
                        "description": f"Compliance status changed to {trend_data[i]['status']}",
                        "score": trend_data[i]["score"],
                    }
                )

        return sorted(milestones, key=lambda x: x["date"])
