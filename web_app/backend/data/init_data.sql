-- Initial seed data for SecureOps AI
-- This file contains default data to populate the database on first setup

-- Insert default admin user (password: admin123 - should be changed in production)
INSERT OR IGNORE INTO users (
    username, 
    email, 
    hashed_password, 
    full_name, 
    role, 
    is_active, 
    created_at
) VALUES (
    'admin',
    'admin@secureops.ai',
    '$2b$12$LQv3c1yqBwMVc.q.Ag8U4eN5.8.5.5.5.5.5.5.5.5.5.5.5.5.5.5.5',
    'System Administrator',
    'admin',
    1,
    datetime('now')
);

-- Insert default demo user (password: demo123)
INSERT OR IGNORE INTO users (
    username, 
    email, 
    hashed_password, 
    full_name, 
    role, 
    is_active, 
    created_at
) VALUES (
    'demo',
    'demo@secureops.ai',
    '$2b$12$LQv3c1yqBwMVc.q.Ag8U4eN5.8.8.8.8.8.8.8.8.8.8.8.8.8.8.8.8',
    'Demo User',
    'user',
    1,
    datetime('now')
);

-- Insert sample security alerts
INSERT OR IGNORE INTO alerts (
    title,
    description,
    severity,
    source,
    ip_address,
    status,
    created_at
) VALUES 
    (
        'Brute Force Attack Detected',
        'Multiple failed login attempts detected from IP 192.168.1.100',
        'high',
        'auth_monitor',
        '192.168.1.100',
        'active',
        datetime('now', '-2 hours')
    ),
    (
        'Suspicious Network Traffic',
        'Unusual outbound traffic pattern detected on port 443',
        'medium',
        'network_monitor',
        '10.0.0.50',
        'active',
        datetime('now', '-4 hours')
    ),
    (
        'Malware Detection',
        'Potential malware detected in uploaded file: document.exe',
        'critical',
        'antivirus',
        '192.168.1.75',
        'acknowledged',
        datetime('now', '-1 day')
    ),
    (
        'Unauthorized Access Attempt',
        'Access attempt to restricted endpoint from unknown device',
        'high',
        'access_control',
        '203.0.113.10',
        'active',
        datetime('now', '-6 hours')
    ),
    (
        'SQL Injection Attempt',
        'Potential SQL injection detected in web form submission',
        'high',
        'web_application_firewall',
        '198.51.100.25',
        'resolved',
        datetime('now', '-12 hours')
    );

-- Insert sample security events
INSERT OR IGNORE INTO security_events (
    event_type,
    description,
    source_ip,
    user_agent,
    severity,
    timestamp
) VALUES 
    (
        'login_attempt',
        'Failed login attempt for user admin',
        '192.168.1.100',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'medium',
        datetime('now', '-3 hours')
    ),
    (
        'file_upload',
        'File upload: suspicious.exe (blocked)',
        '192.168.1.75',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'high',
        datetime('now', '-5 hours')
    ),
    (
        'api_access',
        'API endpoint access: /admin/users',
        '10.0.0.25',
        'curl/7.68.0',
        'low',
        datetime('now', '-1 hour')
    ),
    (
        'data_export',
        'Large data export initiated by user demo',
        '192.168.1.200',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'medium',
        datetime('now', '-8 hours')
    );

-- Insert sample automation tasks
INSERT OR IGNORE INTO automation_tasks (
    name,
    description,
    task_type,
    schedule,
    parameters,
    is_active,
    created_at
) VALUES 
    (
        'Daily Security Scan',
        'Automated daily vulnerability scan of all network assets',
        'security_scan',
        '0 2 * * *',
        '{"scan_type": "full", "targets": ["192.168.1.0/24"], "report_email": "admin@secureops.ai"}',
        1,
        datetime('now', '-3 days')
    ),
    (
        'Log Analysis',
        'Automated analysis of security logs for threat patterns',
        'log_analysis',
        '0 */4 * * *',
        '{"log_sources": ["firewall", "ids", "auth"], "alert_threshold": "medium"}',
        1,
        datetime('now', '-2 days')
    ),
    (
        'Backup Integrity Check',
        'Verify integrity of security database backups',
        'backup_check',
        '0 6 * * 0',
        '{"backup_location": "/var/backups/secureops", "retention_days": 30}',
        1,
        datetime('now', '-1 day')
    );

-- Insert sample notifications
INSERT OR IGNORE INTO notifications (
    user_id,
    title,
    message,
    type,
    is_read,
    created_at
) VALUES 
    (
        1,
        'Welcome to SecureOps AI',
        'Your security operations platform is ready. Start by reviewing the dashboard.',
        'info',
        0,
        datetime('now', '-1 hour')
    ),
    (
        1,
        'Critical Alert Triggered',
        'A critical security alert requires immediate attention.',
        'alert',
        0,
        datetime('now', '-30 minutes')
    ),
    (
        2,
        'Account Setup Complete',
        'Your demo account has been successfully configured.',
        'success',
        1,
        datetime('now', '-2 hours')
    );

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_automation_tasks_is_active ON automation_tasks(is_active);

-- Insert application settings
CREATE TABLE IF NOT EXISTS app_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO app_settings (key, value, description) VALUES 
    ('app_name', 'SecureOps AI', 'Application name'),
    ('app_version', '1.0.0', 'Current application version'),
    ('alert_retention_days', '90', 'Days to retain resolved alerts'),
    ('log_retention_days', '180', 'Days to retain security logs'),
    ('max_failed_logins', '5', 'Maximum failed login attempts before lockout'),
    ('session_timeout_minutes', '60', 'Session timeout in minutes'),
    ('enable_notifications', 'true', 'Enable email/slack notifications'),
    ('security_scan_interval', '24', 'Hours between automated security scans'),
    ('threat_intel_update_interval', '6', 'Hours between threat intelligence updates'),
    ('backup_retention_days', '30', 'Days to retain database backups');

-- Create audit log table for compliance
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    resource TEXT,
    details TEXT,
    ip_address TEXT,
    user_agent TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);

-- Insert sample audit log entries
INSERT OR IGNORE INTO audit_logs (user_id, action, resource, details, ip_address) VALUES 
    (1, 'login', 'auth', '{"success": true}', '192.168.1.10'),
    (1, 'create_alert', 'alerts', '{"alert_id": 1, "severity": "high"}', '192.168.1.10'),
    (2, 'login', 'auth', '{"success": true}', '192.168.1.20'),
    (1, 'view_users', 'users', '{"count": 2}', '192.168.1.10'),
    (1, 'update_settings', 'settings', '{"key": "alert_retention_days", "old_value": "60", "new_value": "90"}', '192.168.1.10');

-- Commit all changes
COMMIT;