from typing import Any, Callable, Dict
import asyncio
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import User, Alert, SecurityEvent
from ..utils.logger import logger, security_logger
from ..utils.notifications import notification_manager


class BackgroundTaskManager:
    """Manages background tasks and scheduled jobs"""

    def __init__(self):
        self.tasks: Dict[str, asyncio.Task] = {}
        self.running = False

    async def start(self):
        """Start the background task manager"""
        self.running = True
        logger.info("Background task manager started")

        # Start periodic tasks
        self.tasks["system_health_check"] = asyncio.create_task(self.periodic_system_health_check())
        self.tasks["cleanup_old_logs"] = asyncio.create_task(self.periodic_cleanup())
        self.tasks["alert_digest"] = asyncio.create_task(self.periodic_alert_digest())

    async def stop(self):
        """Stop the background task manager"""
        self.running = False
        logger.info("Stopping background task manager")

        # Cancel all running tasks
        for task_name, task in self.tasks.items():
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    logger.info(f"Task {task_name} cancelled")

        self.tasks.clear()

    async def periodic_system_health_check(self):
        """Periodic system health monitoring"""
        while self.running:
            try:
                await self.run_system_health_check()
                # Run every 5 minutes
                await asyncio.sleep(300)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in system health check: {str(e)}")
                await asyncio.sleep(60)  # Shorter retry interval on error

    async def periodic_cleanup(self):
        """Periodic cleanup of old data"""
        while self.running:
            try:
                await self.cleanup_old_data()
                # Run daily at 2 AM (sleep for 24 hours)
                await asyncio.sleep(86400)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic cleanup: {str(e)}")
                await asyncio.sleep(3600)  # Retry in 1 hour on error

    async def periodic_alert_digest(self):
        """Send periodic alert digests to administrators"""
        while self.running:
            try:
                await self.send_alert_digest()
                # Run every hour
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in alert digest: {str(e)}")
                await asyncio.sleep(600)  # Retry in 10 minutes on error

    async def run_system_health_check(self):
        """Check system health and generate alerts if needed"""
        try:
            db = next(get_db())

            # Check database connectivity
            db.execute("SELECT 1")

            # Check recent alert volume
            recent_alerts = db.query(Alert).filter(Alert.created_at >= datetime.utcnow() - timedelta(hours=1)).count()

            if recent_alerts > 10:  # Alert threshold
                await self.create_system_alert(
                    title="High Alert Volume",
                    description=f"Detected {recent_alerts} alerts in the last hour",
                    severity="medium",
                    source="system_monitor",
                )

            # Check for critical unacknowledged alerts
            critical_alerts = (
                db.query(Alert)
                .filter(
                    Alert.severity == "critical",
                    Alert.status == "active",
                    Alert.created_at <= datetime.utcnow() - timedelta(minutes=30),
                )
                .count()
            )

            if critical_alerts > 0:
                await self.create_system_alert(
                    title="Unacknowledged Critical Alerts",
                    description=f"{critical_alerts} critical alerts require attention",
                    severity="high",
                    source="system_monitor",
                )

            db.close()
            security_logger.log_system_event("system_health_check", "completed", {"status": "healthy"})

        except Exception as e:
            logger.error(f"System health check failed: {str(e)}")
            security_logger.log_system_event("system_health_check", "failed", {"error": str(e)})

    async def cleanup_old_data(self):
        """Clean up old logs and data"""
        try:
            db = next(get_db())

            # Clean up old alerts (keep for 90 days)
            cutoff_date = datetime.utcnow() - timedelta(days=90)
            old_alerts = db.query(Alert).filter(
                Alert.created_at < cutoff_date, Alert.status.in_(["acknowledged", "resolved"])
            )
            deleted_alerts = old_alerts.count()
            old_alerts.delete()

            # Clean up old security events (keep for 180 days)
            event_cutoff_date = datetime.utcnow() - timedelta(days=180)
            old_events = db.query(SecurityEvent).filter(SecurityEvent.timestamp < event_cutoff_date)
            deleted_events = old_events.count()
            old_events.delete()

            db.commit()
            db.close()

            logger.info(f"Cleanup completed: {deleted_alerts} alerts, {deleted_events} events deleted")

        except Exception as e:
            logger.error(f"Cleanup task failed: {str(e)}")

    async def send_alert_digest(self):
        """Send hourly alert digest to administrators"""
        try:
            db = next(get_db())

            # Get alerts from the last hour
            hour_ago = datetime.utcnow() - timedelta(hours=1)
            recent_alerts = db.query(Alert).filter(Alert.created_at >= hour_ago).all()

            if not recent_alerts:
                db.close()
                return

            # Get admin users
            admin_users = db.query(User).filter(User.role == "admin").all()
            admin_emails = [user.email for user in admin_users if user.email]

            if not admin_emails:
                db.close()
                return

            # Categorize alerts by severity
            alert_counts = {}
            for alert in recent_alerts:
                alert_counts[alert.severity] = alert_counts.get(alert.severity, 0) + 1

            # Send digest email
            subject = f"Hourly Alert Digest - {len(recent_alerts)} new alerts"

            message = f"""
Security Alert Digest - Last Hour

Total Alerts: {len(recent_alerts)}

Breakdown by Severity:
"""

            for severity, count in sorted(alert_counts.items()):
                message += f"  {severity.title()}: {count}\n"

            message += f"\nTime Period: {hour_ago.strftime('%Y-%m-%d %H:%M')} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC"

            # Send to all admin users
            for email in admin_emails:
                notification_manager.send_user_notification(email, subject, message, "info")

            db.close()

        except Exception as e:
            logger.error(f"Alert digest task failed: {str(e)}")

    async def create_system_alert(self, title: str, description: str, severity: str, source: str):
        """Create a system-generated alert"""
        try:
            db = next(get_db())

            # Check if similar alert already exists (avoid spam)
            existing_alert = (
                db.query(Alert)
                .filter(
                    Alert.title == title,
                    Alert.created_at >= datetime.utcnow() - timedelta(hours=1),
                    Alert.status == "active",
                )
                .first()
            )

            if existing_alert:
                db.close()
                return

            # Create new alert
            alert = Alert(title=title, description=description, severity=severity, source=source, status="active")

            db.add(alert)
            db.commit()
            db.refresh(alert)
            db.close()

            # Send notification
            await notification_manager.send_security_alert(title, description, severity, source=source)

            security_logger.log_security_event(
                "system_alert_created", severity, title, {"source": source, "alert_id": alert.id}
            )

        except Exception as e:
            logger.error(f"Failed to create system alert: {str(e)}")


# Task execution functions for individual background jobs


async def process_security_scan(scan_id: str, scan_params: Dict[str, Any]):
    """Process a security scan in the background"""
    try:
        logger.info(f"Starting security scan {scan_id}")

        # Simulate scan processing
        await asyncio.sleep(10)  # Placeholder for actual scan logic

        # Store results (placeholder)
        results = {
            "scan_id": scan_id,
            "status": "completed",
            "vulnerabilities_found": 3,
            "threats_detected": 1,
            "completion_time": datetime.utcnow().isoformat(),
        }

        logger.info(f"Security scan {scan_id} completed: {results}")

        return results

    except Exception as e:
        logger.error(f"Security scan {scan_id} failed: {str(e)}")
        raise


async def generate_compliance_report(report_id: str, report_params: Dict[str, Any]):
    """Generate compliance report in the background"""
    try:
        logger.info(f"Generating compliance report {report_id}")

        # Simulate report generation
        await asyncio.sleep(30)  # Placeholder for actual report logic

        report_data = {
            "report_id": report_id,
            "status": "completed",
            "compliance_score": 85,
            "total_checks": 50,
            "passed_checks": 42,
            "failed_checks": 8,
            "generation_time": datetime.utcnow().isoformat(),
        }

        logger.info(f"Compliance report {report_id} completed")

        return report_data

    except Exception as e:
        logger.error(f"Compliance report {report_id} failed: {str(e)}")
        raise


async def process_threat_intelligence(data: Dict[str, Any]):
    """Process threat intelligence data in the background"""
    try:
        logger.info("Processing threat intelligence data")

        # Simulate threat intelligence processing
        await asyncio.sleep(5)

        # Analyze for new threats
        threats_detected = 2  # Placeholder

        if threats_detected > 0:
            # Create alerts for detected threats
            db = next(get_db())

            for i in range(threats_detected):
                alert = Alert(
                    title=f"Threat Intelligence Alert #{i+1}",
                    description="New threat pattern detected in intelligence feeds",
                    severity="medium",
                    source="threat_intelligence",
                    status="active",
                )
                db.add(alert)

            db.commit()
            db.close()

            logger.info(f"Created {threats_detected} alerts from threat intelligence")

    except Exception as e:
        logger.error(f"Threat intelligence processing failed: {str(e)}")
        raise


# Global background task manager instance
task_manager = BackgroundTaskManager()
