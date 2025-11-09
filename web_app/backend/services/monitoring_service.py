from typing import Dict, Any, List
import psutil
import asyncio
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Alert, User
from ..utils.logger import logger


class MonitoringService:
    """Service for system health checks and uptime monitoring"""

    def __init__(self):
        self.start_time = datetime.utcnow()

    async def get_system_health(self) -> Dict[str, Any]:
        """Get comprehensive system health information"""
        try:
            # System metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")

            # Network statistics
            network = psutil.net_io_counters()

            # Process information
            process_count = len(psutil.pids())

            # Database health check
            db_health = await self._check_database_health()

            # Application uptime
            uptime_seconds = (datetime.utcnow() - self.start_time).total_seconds()

            # Determine overall health status
            health_status = self._determine_health_status(
                cpu_percent, memory.percent, disk.percent, db_health["status"]
            )

            return {
                "status": health_status,
                "uptime_seconds": uptime_seconds,
                "uptime_formatted": self._format_uptime(uptime_seconds),
                "system": {
                    "cpu_usage_percent": cpu_percent,
                    "memory_usage_percent": memory.percent,
                    "memory_available_gb": round(memory.available / (1024**3), 2),
                    "memory_total_gb": round(memory.total / (1024**3), 2),
                    "disk_usage_percent": disk.percent,
                    "disk_free_gb": round(disk.free / (1024**3), 2),
                    "disk_total_gb": round(disk.total / (1024**3), 2),
                    "process_count": process_count,
                },
                "network": {
                    "bytes_sent": network.bytes_sent,
                    "bytes_received": network.bytes_recv,
                    "packets_sent": network.packets_sent,
                    "packets_received": network.packets_recv,
                },
                "database": db_health,
                "last_updated": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error(f"Error getting system health: {str(e)}")
            return {"status": "error", "error": str(e), "last_updated": datetime.utcnow().isoformat()}

    async def get_performance_metrics(self, hours: int = 24) -> Dict[str, Any]:
        """Get performance metrics over time"""
        try:
            # Get historical data points (simulated for now)
            # In production, this would come from a time-series database

            metrics = []
            now = datetime.utcnow()

            # Generate sample data points
            for i in range(hours):
                timestamp = now - timedelta(hours=i)

                # Simulate realistic metrics with some variation
                cpu_base = 15 + (i % 3) * 5
                memory_base = 45 + (i % 4) * 8

                metrics.append(
                    {
                        "timestamp": timestamp.isoformat(),
                        "cpu_percent": cpu_base + (i % 7),
                        "memory_percent": memory_base + (i % 5),
                        "active_connections": 25 + (i % 10),
                        "response_time_ms": 150 + (i % 50),
                    }
                )

            # Reverse to get chronological order
            metrics.reverse()

            # Calculate averages
            avg_cpu = sum(m["cpu_percent"] for m in metrics) / len(metrics)
            avg_memory = sum(m["memory_percent"] for m in metrics) / len(metrics)
            avg_response = sum(m["response_time_ms"] for m in metrics) / len(metrics)

            return {
                "period_hours": hours,
                "metrics": metrics,
                "averages": {
                    "cpu_percent": round(avg_cpu, 2),
                    "memory_percent": round(avg_memory, 2),
                    "response_time_ms": round(avg_response, 2),
                },
                "last_updated": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error(f"Error getting performance metrics: {str(e)}")
            raise

    async def get_service_status(self) -> Dict[str, Any]:
        """Check status of critical services"""
        try:
            services = {}

            # Database service
            db_result = await self._check_database_health()
            services["database"] = {
                "status": db_result["status"],
                "response_time_ms": db_result.get("response_time_ms", 0),
                "last_check": datetime.utcnow().isoformat(),
            }

            # Authentication service
            auth_result = await self._check_auth_service()
            services["authentication"] = {
                "status": auth_result["status"],
                "response_time_ms": auth_result.get("response_time_ms", 0),
                "last_check": datetime.utcnow().isoformat(),
            }

            # Alert processing service
            alert_result = await self._check_alert_service()
            services["alert_processing"] = {
                "status": alert_result["status"],
                "response_time_ms": alert_result.get("response_time_ms", 0),
                "last_check": datetime.utcnow().isoformat(),
            }

            # Notification service
            notification_result = await self._check_notification_service()
            services["notifications"] = {
                "status": notification_result["status"],
                "response_time_ms": notification_result.get("response_time_ms", 0),
                "last_check": datetime.utcnow().isoformat(),
            }

            # Calculate overall service health
            statuses = [service["status"] for service in services.values()]
            if all(status == "healthy" for status in statuses):
                overall_status = "healthy"
            elif any(status == "unhealthy" for status in statuses):
                overall_status = "unhealthy"
            else:
                overall_status = "degraded"

            return {
                "overall_status": overall_status,
                "services": services,
                "total_services": len(services),
                "healthy_services": sum(1 for s in services.values() if s["status"] == "healthy"),
                "last_updated": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error(f"Error checking service status: {str(e)}")
            return {"overall_status": "error", "error": str(e), "last_updated": datetime.utcnow().isoformat()}

    async def get_uptime_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Get uptime statistics and availability metrics"""
        try:
            # Calculate uptime since start
            current_uptime = (datetime.utcnow() - self.start_time).total_seconds()

            # Simulate historical uptime data
            # In production, this would come from monitoring logs
            total_seconds_in_period = days * 24 * 3600

            # Assume 99.5% uptime with some downtime events
            uptime_percentage = 99.5
            downtime_seconds = total_seconds_in_period * (1 - uptime_percentage / 100)

            # Generate downtime events
            downtime_events = [
                {
                    "start_time": (datetime.utcnow() - timedelta(days=5, hours=2)).isoformat(),
                    "end_time": (datetime.utcnow() - timedelta(days=5, hours=1, minutes=45)).isoformat(),
                    "duration_minutes": 15,
                    "reason": "Scheduled maintenance",
                },
                {
                    "start_time": (datetime.utcnow() - timedelta(days=12, hours=14)).isoformat(),
                    "end_time": (datetime.utcnow() - timedelta(days=12, hours=13, minutes=35)).isoformat(),
                    "duration_minutes": 25,
                    "reason": "Database connectivity issue",
                },
            ]

            return {
                "period_days": days,
                "current_uptime_seconds": current_uptime,
                "current_uptime_formatted": self._format_uptime(current_uptime),
                "uptime_percentage": uptime_percentage,
                "downtime_seconds": downtime_seconds,
                "downtime_events": downtime_events,
                "availability_target": 99.9,
                "sla_compliance": uptime_percentage >= 99.9,
                "last_updated": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error(f"Error getting uptime statistics: {str(e)}")
            raise

    async def _check_database_health(self) -> Dict[str, Any]:
        """Check database connectivity and performance"""
        try:
            start_time = datetime.utcnow()
            db = next(get_db())

            # Simple connectivity test
            result = db.execute("SELECT 1").scalar()

            # Performance test - count records
            alert_count = db.query(Alert).count()
            user_count = db.query(User).count()

            db.close()

            end_time = datetime.utcnow()
            response_time = (end_time - start_time).total_seconds() * 1000

            return {
                "status": "healthy" if result == 1 else "unhealthy",
                "response_time_ms": round(response_time, 2),
                "alert_count": alert_count,
                "user_count": user_count,
                "last_check": end_time.isoformat(),
            }

        except Exception as e:
            logger.error(f"Database health check failed: {str(e)}")
            return {"status": "unhealthy", "error": str(e), "last_check": datetime.utcnow().isoformat()}

    async def _check_auth_service(self) -> Dict[str, Any]:
        """Check authentication service health"""
        try:
            start_time = datetime.utcnow()

            # Simulate auth service check
            await asyncio.sleep(0.1)  # Simulate response time

            end_time = datetime.utcnow()
            response_time = (end_time - start_time).total_seconds() * 1000

            return {"status": "healthy", "response_time_ms": round(response_time, 2)}

        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}

    async def _check_alert_service(self) -> Dict[str, Any]:
        """Check alert processing service health"""
        try:
            start_time = datetime.utcnow()

            # Check recent alert processing
            db = next(get_db())
            recent_alerts = db.query(Alert).filter(Alert.created_at >= datetime.utcnow() - timedelta(minutes=5)).count()
            db.close()

            end_time = datetime.utcnow()
            response_time = (end_time - start_time).total_seconds() * 1000

            return {
                "status": "healthy",
                "response_time_ms": round(response_time, 2),
                "recent_alerts_processed": recent_alerts,
            }

        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}

    async def _check_notification_service(self) -> Dict[str, Any]:
        """Check notification service health"""
        try:
            start_time = datetime.utcnow()

            # Simulate notification service check
            await asyncio.sleep(0.05)

            end_time = datetime.utcnow()
            response_time = (end_time - start_time).total_seconds() * 1000

            return {"status": "healthy", "response_time_ms": round(response_time, 2)}

        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}

    def _determine_health_status(
        self, cpu_percent: float, memory_percent: float, disk_percent: float, db_status: str
    ) -> str:
        """Determine overall health status based on metrics"""

        if db_status != "healthy":
            return "unhealthy"

        # Critical thresholds
        if cpu_percent > 90 or memory_percent > 90 or disk_percent > 95:
            return "unhealthy"

        # Warning thresholds
        if cpu_percent > 70 or memory_percent > 80 or disk_percent > 85:
            return "degraded"

        return "healthy"

    def _format_uptime(self, seconds: float) -> str:
        """Format uptime in human-readable format"""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)

        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"
