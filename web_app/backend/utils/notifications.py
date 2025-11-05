from typing import List, Dict, Any, Optional
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import requests
import json
import asyncio
from ..config import get_settings

settings = get_settings()

class EmailNotificationService:
    """Service for sending email notifications"""
    
    def __init__(self):
        self.smtp_server = settings.SMTP_SERVER
        self.smtp_port = settings.SMTP_PORT
        self.username = settings.SMTP_USERNAME
        self.password = settings.SMTP_PASSWORD
        self.use_tls = settings.SMTP_USE_TLS
        self.from_email = settings.FROM_EMAIL
    
    def send_email(
        self, 
        to_emails: List[str], 
        subject: str, 
        body: str, 
        html_body: str = None,
        cc_emails: List[str] = None,
        bcc_emails: List[str] = None
    ) -> bool:
        """Send email notification"""
        try:
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = self.from_email
            message["To"] = ", ".join(to_emails)
            
            if cc_emails:
                message["Cc"] = ", ".join(cc_emails)
            
            # Add text part
            text_part = MIMEText(body, "plain")
            message.attach(text_part)
            
            # Add HTML part if provided
            if html_body:
                html_part = MIMEText(html_body, "html")
                message.attach(html_part)
            
            # Create SMTP session
            context = ssl.create_default_context()
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls(context=context)
                
                if self.username and self.password:
                    server.login(self.username, self.password)
                
                # Combine all recipients
                all_recipients = to_emails[:]
                if cc_emails:
                    all_recipients.extend(cc_emails)
                if bcc_emails:
                    all_recipients.extend(bcc_emails)
                
                server.sendmail(self.from_email, all_recipients, message.as_string())
            
            return True
            
        except Exception as e:
            print(f"Failed to send email: {str(e)}")
            return False
    
    def send_security_alert(
        self, 
        recipients: List[str], 
        alert_title: str, 
        alert_description: str,
        severity: str,
        source: str = None
    ) -> bool:
        """Send security alert email"""
        subject = f"🚨 Security Alert: {alert_title}"
        
        # Create text body
        text_body = f"""
Security Alert Notification

Alert: {alert_title}
Severity: {severity.upper()}
Description: {alert_description}
Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
"""
        
        if source:
            text_body += f"Source: {source}\n"
        
        text_body += """
Please review this alert immediately and take appropriate action.

---
SecureOps AI Security System
"""
        
        # Create HTML body
        severity_color = {
            'critical': '#dc2626',
            'high': '#ea580c',
            'medium': '#d97706',
            'low': '#65a30d'
        }.get(severity.lower(), '#6b7280')
        
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        .alert-container {{
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
        }}
        .alert-header {{
            background-color: {severity_color};
            color: white;
            padding: 15px;
            border-radius: 6px 6px 0 0;
            margin: -20px -20px 20px -20px;
        }}
        .alert-content {{
            line-height: 1.6;
        }}
        .alert-details {{
            background-color: #f9fafb;
            padding: 15px;
            border-radius: 6px;
            margin: 15px 0;
        }}
    </style>
</head>
<body>
    <div class="alert-container">
        <div class="alert-header">
            <h2>🚨 Security Alert: {alert_title}</h2>
        </div>
        <div class="alert-content">
            <div class="alert-details">
                <p><strong>Severity:</strong> <span style="color: {severity_color}; font-weight: bold;">{severity.upper()}</span></p>
                <p><strong>Description:</strong> {alert_description}</p>
                <p><strong>Time:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
"""
        
        if source:
            html_body += f"                <p><strong>Source:</strong> {source}</p>\n"
        
        html_body += """
            </div>
            <p>Please review this alert immediately and take appropriate action.</p>
            <p><strong>Next Steps:</strong></p>
            <ul>
                <li>Log into the SecureOps AI dashboard</li>
                <li>Review the full alert details</li>
                <li>Implement necessary security measures</li>
                <li>Acknowledge the alert once resolved</li>
            </ul>
        </div>
    </div>
</body>
</html>
"""
        
        return self.send_email(recipients, subject, text_body, html_body)

class SlackNotificationService:
    """Service for sending Slack notifications"""
    
    def __init__(self):
        self.webhook_url = settings.SLACK_WEBHOOK_URL
        self.channel = settings.SLACK_CHANNEL
        self.bot_name = "SecureOps AI"
    
    def send_message(
        self, 
        message: str, 
        channel: str = None,
        username: str = None,
        icon_emoji: str = ":shield:",
        attachments: List[Dict] = None
    ) -> bool:
        """Send Slack message"""
        if not self.webhook_url:
            return False
        
        try:
            payload = {
                "text": message,
                "username": username or self.bot_name,
                "icon_emoji": icon_emoji,
                "channel": channel or self.channel
            }
            
            if attachments:
                payload["attachments"] = attachments
            
            response = requests.post(
                self.webhook_url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"Failed to send Slack message: {str(e)}")
            return False
    
    def send_security_alert(
        self, 
        alert_title: str, 
        alert_description: str,
        severity: str,
        source: str = None
    ) -> bool:
        """Send security alert to Slack"""
        
        # Choose emoji and color based on severity
        severity_config = {
            'critical': {'emoji': ':rotating_light:', 'color': 'danger'},
            'high': {'emoji': ':warning:', 'color': 'warning'},
            'medium': {'emoji': ':large_orange_diamond:', 'color': '#ff9900'},
            'low': {'emoji': ':information_source:', 'color': 'good'}
        }
        
        config = severity_config.get(severity.lower(), severity_config['medium'])
        
        message = f"{config['emoji']} *Security Alert*"
        
        attachment = {
            "color": config['color'],
            "fields": [
                {
                    "title": "Alert",
                    "value": alert_title,
                    "short": True
                },
                {
                    "title": "Severity",
                    "value": severity.upper(),
                    "short": True
                },
                {
                    "title": "Description",
                    "value": alert_description,
                    "short": False
                },
                {
                    "title": "Time",
                    "value": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "short": True
                }
            ]
        }
        
        if source:
            attachment["fields"].append({
                "title": "Source",
                "value": source,
                "short": True
            })
        
        return self.send_message(message, attachments=[attachment])

class NotificationManager:
    """Central notification manager"""
    
    def __init__(self):
        self.email_service = EmailNotificationService()
        self.slack_service = SlackNotificationService()
    
    async def send_security_alert(
        self, 
        alert_title: str, 
        alert_description: str,
        severity: str,
        recipients: Optional[Dict[str, List[str]]] = None,
        source: str = None
    ):
        """Send security alert via multiple channels"""
        
        tasks = []
        
        # Send email notifications
        if recipients and recipients.get('email'):
            task = asyncio.create_task(
                self._send_email_alert(
                    recipients['email'],
                    alert_title,
                    alert_description,
                    severity,
                    source
                )
            )
            tasks.append(task)
        
        # Send Slack notifications
        if recipients and recipients.get('slack') or settings.ENABLE_SLACK_NOTIFICATIONS:
            task = asyncio.create_task(
                self._send_slack_alert(
                    alert_title,
                    alert_description,
                    severity,
                    source
                )
            )
            tasks.append(task)
        
        # Wait for all notifications to complete
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _send_email_alert(self, recipients, title, description, severity, source):
        """Send email alert asynchronously"""
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                self.email_service.send_security_alert,
                recipients, title, description, severity, source
            )
        except Exception as e:
            print(f"Failed to send email alert: {str(e)}")
    
    async def _send_slack_alert(self, title, description, severity, source):
        """Send Slack alert asynchronously"""
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                self.slack_service.send_security_alert,
                title, description, severity, source
            )
        except Exception as e:
            print(f"Failed to send Slack alert: {str(e)}")
    
    def send_user_notification(
        self,
        user_email: str,
        subject: str,
        message: str,
        notification_type: str = "info"
    ) -> bool:
        """Send notification to a specific user"""
        
        # Add notification type emoji
        emoji_map = {
            'info': 'ℹ️',
            'success': '✅',
            'warning': '⚠️',
            'error': '❌'
        }
        
        email_subject = f"{emoji_map.get(notification_type, '')} {subject}"
        
        return self.email_service.send_email(
            [user_email],
            email_subject,
            message
        )

# Create global notification manager instance
notification_manager = NotificationManager()