from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from ..models import Alert, SecurityEvent, User
from ..utils.logger import logger

class AnalyticsService:
    """Service for security analytics and threat pattern analysis"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def get_security_overview(self, days: int = 30) -> Dict[str, Any]:
        """Get comprehensive security overview"""
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            # Get alerts in date range
            alerts = self.db.query(Alert).filter(
                Alert.created_at >= start_date,
                Alert.created_at <= end_date
            ).all()
            
            # Get security events in date range
            events = self.db.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= start_date,
                SecurityEvent.timestamp <= end_date
            ).all()
            
            # Calculate metrics
            total_alerts = len(alerts)
            total_events = len(events)
            
            # Alert severity breakdown
            severity_counts = defaultdict(int)
            for alert in alerts:
                severity_counts[alert.severity] += 1
            
            # Alert status breakdown
            status_counts = defaultdict(int)
            for alert in alerts:
                status_counts[alert.status] += 1
            
            # Top alert sources
            source_counts = defaultdict(int)
            for alert in alerts:
                if alert.source:
                    source_counts[alert.source] += 1
            
            # Calculate trends
            previous_period_start = start_date - timedelta(days=days)
            previous_alerts = self.db.query(Alert).filter(
                Alert.created_at >= previous_period_start,
                Alert.created_at < start_date
            ).count()
            
            alert_trend = ((total_alerts - previous_alerts) / max(previous_alerts, 1)) * 100
            
            return {
                "period_days": days,
                "total_alerts": total_alerts,
                "total_events": total_events,
                "alert_trend_percentage": round(alert_trend, 2),
                "severity_breakdown": dict(severity_counts),
                "status_breakdown": dict(status_counts),
                "top_sources": dict(sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:5]),
                "critical_alerts": severity_counts.get("critical", 0),
                "unacknowledged_alerts": status_counts.get("active", 0),
                "resolved_alerts": status_counts.get("resolved", 0) + status_counts.get("acknowledged", 0)
            }
            
        except Exception as e:
            logger.error(f"Error getting security overview: {str(e)}")
            raise
    
    def get_threat_patterns(self, days: int = 30) -> Dict[str, Any]:
        """Analyze threat patterns and trends"""
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            alerts = self.db.query(Alert).filter(
                Alert.created_at >= start_date,
                Alert.created_at <= end_date
            ).all()
            
            # Group alerts by source and analyze patterns
            source_patterns = defaultdict(lambda: {
                "count": 0,
                "severities": defaultdict(int),
                "ips": set(),
                "first_seen": None,
                "last_seen": None
            })
            
            for alert in alerts:
                source = alert.source or "unknown"
                pattern = source_patterns[source]
                
                pattern["count"] += 1
                pattern["severities"][alert.severity] += 1
                
                if alert.ip_address:
                    pattern["ips"].add(alert.ip_address)
                
                if pattern["first_seen"] is None or alert.created_at < pattern["first_seen"]:
                    pattern["first_seen"] = alert.created_at
                
                if pattern["last_seen"] is None or alert.created_at > pattern["last_seen"]:
                    pattern["last_seen"] = alert.created_at
            
            # Convert to serializable format
            patterns = {}
            for source, data in source_patterns.items():
                patterns[source] = {
                    "count": data["count"],
                    "severities": dict(data["severities"]),
                    "unique_ips": len(data["ips"]),
                    "first_seen": data["first_seen"].isoformat() if data["first_seen"] else None,
                    "last_seen": data["last_seen"].isoformat() if data["last_seen"] else None,
                    "duration_hours": (
                        (data["last_seen"] - data["first_seen"]).total_seconds() / 3600
                        if data["first_seen"] and data["last_seen"] else 0
                    )
                }
            
            # Identify trending threats
            trending_threats = []
            for source, data in patterns.items():
                if data["count"] >= 5:  # Threshold for trending
                    trending_threats.append({
                        "source": source,
                        "alert_count": data["count"],
                        "threat_score": self._calculate_threat_score(data),
                        "severity_distribution": data["severities"]
                    })
            
            # Sort by threat score
            trending_threats.sort(key=lambda x: x["threat_score"], reverse=True)
            
            return {
                "analysis_period": f"{days} days",
                "total_patterns": len(patterns),
                "threat_patterns": patterns,
                "trending_threats": trending_threats[:10],  # Top 10
                "analysis_timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error analyzing threat patterns: {str(e)}")
            raise
    
    def get_daily_alert_trends(self, days: int = 30) -> List[Dict[str, Any]]:
        """Get daily alert trends for charting"""
        try:
            end_date = datetime.utcnow().replace(hour=23, minute=59, second=59, microsecond=999999)
            start_date = end_date - timedelta(days=days-1)
            start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
            
            # Get all alerts in range
            alerts = self.db.query(Alert).filter(
                Alert.created_at >= start_date,
                Alert.created_at <= end_date
            ).all()
            
            # Group by day and severity
            daily_data = defaultdict(lambda: {
                "date": None,
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            })
            
            # Generate all dates in range
            current_date = start_date.date()
            while current_date <= end_date.date():
                date_str = current_date.strftime('%Y-%m-%d')
                daily_data[date_str]["date"] = date_str
                current_date += timedelta(days=1)
            
            # Populate with actual data
            for alert in alerts:
                date_str = alert.created_at.date().strftime('%Y-%m-%d')
                daily_data[date_str]["total"] += 1
                daily_data[date_str][alert.severity] += 1
            
            # Convert to list and sort by date
            trends = list(daily_data.values())
            trends.sort(key=lambda x: x["date"])
            
            return trends
            
        except Exception as e:
            logger.error(f"Error getting daily alert trends: {str(e)}")
            raise
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get real-time security metrics"""
        try:
            now = datetime.utcnow()
            
            # Active alerts
            active_alerts = self.db.query(Alert).filter(
                Alert.status == "active"
            ).count()
            
            # Critical alerts in last 24 hours
            critical_alerts_24h = self.db.query(Alert).filter(
                Alert.severity == "critical",
                Alert.created_at >= now - timedelta(hours=24)
            ).count()
            
            # Total users
            total_users = self.db.query(User).count()
            
            # Active users (logged in within last 30 days)
            active_users = self.db.query(User).filter(
                User.last_login >= now - timedelta(days=30)
            ).count()
            
            # Alerts by status in last 7 days
            week_ago = now - timedelta(days=7)
            week_alerts = self.db.query(Alert).filter(
                Alert.created_at >= week_ago
            ).all()
            
            status_counts = defaultdict(int)
            for alert in week_alerts:
                status_counts[alert.status] += 1
            
            # Calculate resolution rate
            total_week_alerts = len(week_alerts)
            resolved_alerts = status_counts.get("resolved", 0) + status_counts.get("acknowledged", 0)
            resolution_rate = (resolved_alerts / max(total_week_alerts, 1)) * 100
            
            return {
                "active_alerts": active_alerts,
                "critical_alerts_24h": critical_alerts_24h,
                "total_users": total_users,
                "active_users": active_users,
                "resolution_rate": round(resolution_rate, 2),
                "alerts_last_7_days": total_week_alerts,
                "status_distribution": dict(status_counts),
                "last_updated": now.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting security metrics: {str(e)}")
            raise
    
    def get_top_threats(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top threats based on recent activity"""
        try:
            # Look at last 30 days
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            
            alerts = self.db.query(Alert).filter(
                Alert.created_at >= thirty_days_ago
            ).all()
            
            # Group by source and calculate threat scores
            threat_data = defaultdict(lambda: {
                "source": None,
                "alert_count": 0,
                "severity_scores": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "unique_ips": set(),
                "last_seen": None
            })
            
            severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
            
            for alert in alerts:
                source = alert.source or "unknown"
                data = threat_data[source]
                
                data["source"] = source
                data["alert_count"] += 1
                data["severity_scores"][alert.severity] += 1
                
                if alert.ip_address:
                    data["unique_ips"].add(alert.ip_address)
                
                if data["last_seen"] is None or alert.created_at > data["last_seen"]:
                    data["last_seen"] = alert.created_at
            
            # Calculate threat scores and convert to list
            threats = []
            for source, data in threat_data.items():
                # Calculate weighted threat score
                threat_score = sum(
                    count * severity_weights[severity]
                    for severity, count in data["severity_scores"].items()
                )
                
                threats.append({
                    "source": source,
                    "threat_score": threat_score,
                    "alert_count": data["alert_count"],
                    "unique_ips": len(data["unique_ips"]),
                    "severity_breakdown": dict(data["severity_scores"]),
                    "last_seen": data["last_seen"].isoformat() if data["last_seen"] else None
                })
            
            # Sort by threat score and return top threats
            threats.sort(key=lambda x: x["threat_score"], reverse=True)
            return threats[:limit]
            
        except Exception as e:
            logger.error(f"Error getting top threats: {str(e)}")
            raise
    
    def _calculate_threat_score(self, pattern_data: Dict[str, Any]) -> float:
        """Calculate threat score based on pattern data"""
        try:
            base_score = pattern_data["count"]
            
            # Weight by severity
            severity_weights = {"critical": 4.0, "high": 2.5, "medium": 1.5, "low": 1.0}
            severity_multiplier = sum(
                count * severity_weights.get(severity, 1.0)
                for severity, count in pattern_data["severities"].items()
            ) / max(pattern_data["count"], 1)
            
            # Factor in IP diversity (more IPs = higher threat)
            ip_factor = min(pattern_data["unique_ips"] / 5.0, 2.0) + 1.0
            
            # Time factor (recent activity is higher threat)
            hours_since_last = pattern_data.get("duration_hours", 0)
            time_factor = max(0.5, 2.0 - (hours_since_last / 24.0))
            
            threat_score = base_score * severity_multiplier * ip_factor * time_factor
            return round(threat_score, 2)
            
        except Exception as e:
            logger.error(f"Error calculating threat score: {str(e)}")
            return 0.0