# SecureOps API Reference

## Overview

The SecureOps API is a RESTful web service that provides comprehensive DevSecOps pipeline monitoring and security compliance management. This document provides detailed information about all available endpoints, request/response formats, and authentication mechanisms.

**Base URL:** `https://api.secureops.example.com/api/v1`

**API Version:** v1

**Content Type:** `application/json`

## Authentication

All API endpoints require authentication using Bearer tokens (JWT).

### Headers

```http
Authorization: Bearer <your_jwt_token>
Content-Type: application/json
```

### Token Management

#### Login
```http
POST /auth/login
Content-Type: application/x-www-form-urlencoded

username=user@example.com&password=your_password
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": {
    "id": 1,
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe"
  }
}
```

#### Refresh Token
```http
POST /auth/refresh

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

## Error Handling

The API uses conventional HTTP response codes to indicate success or failure.

### Error Response Format

```json
{
  "detail": "Error message",
  "type": "error_type",
  "code": "ERROR_CODE"
}
```

### HTTP Status Codes

- `200` - OK
- `201` - Created
- `204` - No Content
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `422` - Unprocessable Entity
- `429` - Too Many Requests
- `500` - Internal Server Error

## Pagination

List endpoints support pagination using limit and offset parameters.

### Query Parameters

- `limit` (integer, default: 20, max: 100) - Number of items to return
- `offset` (integer, default: 0) - Number of items to skip

### Response Format

```json
{
  "items": [...],
  "total": 150,
  "limit": 20,
  "offset": 0,
  "has_next": true,
  "has_prev": false
}
```

## Authentication Endpoints

### User Registration

```http
POST /auth/register

{
  "email": "user@example.com",
  "password": "secure_password",
  "first_name": "John",
  "last_name": "Doe"
}
```

### Password Reset

```http
POST /auth/reset-password

{
  "email": "user@example.com"
}
```

### Change Password

```http
POST /auth/change-password

{
  "current_password": "old_password",
  "new_password": "new_secure_password"
}
```

### Email Verification

```http
POST /auth/verify-email

{
  "token": "verification_token"
}
```

## User Management

### Get Current User

```http
GET /users/me
```

**Response:**
```json
{
  "id": 1,
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "is_active": true,
  "is_verified": true,
  "created_at": "2023-01-15T10:00:00Z",
  "last_login": "2023-01-20T14:30:00Z",
  "roles": ["user"],
  "permissions": ["read:pipelines", "write:pipelines"]
}
```

### Update User Profile

```http
PATCH /users/me

{
  "first_name": "Jane",
  "last_name": "Smith",
  "phone": "+1234567890",
  "timezone": "UTC"
}
```

### List Users (Admin Only)

```http
GET /users?limit=20&offset=0&search=john&is_active=true
```

## Pipeline Management

### List Pipelines

```http
GET /pipelines?platform=github&status=active&limit=20&offset=0
```

**Query Parameters:**
- `platform` - Filter by platform (github, gitlab, jenkins, azure_devops)
- `status` - Filter by status (active, paused, failed, archived)
- `search` - Search in name and description
- `created_after` - Filter by creation date (ISO 8601)
- `created_before` - Filter by creation date (ISO 8601)

**Response:**
```json
{
  "items": [
    {
      "id": 1,
      "name": "Frontend CI/CD",
      "description": "React application deployment pipeline",
      "platform": "github",
      "status": "active",
      "repository_url": "https://github.com/company/frontend",
      "branch": "main",
      "webhook_url": "https://api.github.com/repos/company/frontend/hooks/123",
      "created_at": "2023-01-15T10:00:00Z",
      "updated_at": "2023-01-20T14:30:00Z",
      "last_run": "2023-01-20T14:00:00Z",
      "next_run": "2023-01-20T16:00:00Z",
      "success_rate": 95.5,
      "total_runs": 156,
      "config": {
        "triggers": ["push", "pull_request"],
        "environment": "production",
        "notifications": true
      }
    }
  ],
  "total": 25,
  "limit": 20,
  "offset": 0
}
```

### Create Pipeline

```http
POST /pipelines

{
  "name": "Backend API Pipeline",
  "description": "Node.js API deployment and security scanning",
  "platform": "github",
  "repository_url": "https://github.com/company/backend-api",
  "branch": "main",
  "webhook_secret": "webhook_secret_key",
  "config": {
    "triggers": ["push", "pull_request"],
    "environment": "production",
    "notifications": true,
    "security_scans": ["trivy", "safety", "bandit"],
    "compliance_checks": ["owasp_top_10", "soc2"]
  }
}
```

### Get Pipeline Details

```http
GET /pipelines/{pipeline_id}
```

### Update Pipeline

```http
PATCH /pipelines/{pipeline_id}

{
  "name": "Updated Pipeline Name",
  "description": "Updated description",
  "config": {
    "notifications": false,
    "security_scans": ["trivy", "safety"]
  }
}
```

### Delete Pipeline

```http
DELETE /pipelines/{pipeline_id}
```

### Trigger Pipeline

```http
POST /pipelines/{pipeline_id}/trigger

{
  "branch": "feature/new-feature",
  "commit_sha": "abc123def456",
  "force": false
}
```

**Response:**
```json
{
  "execution_id": "exec_789",
  "status": "running",
  "started_at": "2023-01-20T15:00:00Z",
  "estimated_duration": 300
}
```

### Get Pipeline Logs

```http
GET /pipelines/{pipeline_id}/logs?execution_id=exec_789&limit=100&offset=0
```

### Pause/Resume Pipeline

```http
POST /pipelines/{pipeline_id}/pause
POST /pipelines/{pipeline_id}/resume
```

### Pipeline Statistics

```http
GET /pipelines/stats?period=30d&platform=github
```

**Response:**
```json
{
  "total": 25,
  "active": 20,
  "paused": 3,
  "failed": 2,
  "by_platform": {
    "github": 15,
    "gitlab": 7,
    "jenkins": 3
  },
  "success_rate": 94.2,
  "avg_execution_time": 420,
  "recent_executions": [
    {
      "date": "2023-01-20",
      "count": 12,
      "success": 11,
      "failed": 1
    }
  ]
}
```

## Alert Management

### List Alerts

```http
GET /alerts?severity=high&status=open&source=trivy&limit=20&offset=0
```

**Query Parameters:**
- `severity` - Filter by severity (critical, high, medium, low)
- `status` - Filter by status (open, acknowledged, resolved)
- `source` - Filter by scanner source
- `pipeline_id` - Filter by pipeline
- `created_after` - Filter by creation date
- `created_before` - Filter by creation date

**Response:**
```json
{
  "items": [
    {
      "id": 1,
      "title": "Critical Vulnerability in OpenSSL",
      "description": "CVE-2023-1234: Buffer overflow vulnerability in OpenSSL",
      "severity": "critical",
      "status": "open",
      "source": "trivy",
      "pipeline_id": 1,
      "vulnerability_id": "CVE-2023-1234",
      "created_at": "2023-01-20T10:00:00Z",
      "updated_at": "2023-01-20T10:00:00Z",
      "acknowledged_at": null,
      "resolved_at": null,
      "acknowledged_by": null,
      "resolved_by": null,
      "metadata": {
        "package": "openssl",
        "version": "1.1.1k",
        "fixed_version": "1.1.1l",
        "cvss_score": 9.8,
        "scanner": "trivy"
      }
    }
  ],
  "total": 45,
  "limit": 20,
  "offset": 0
}
```

### Create Alert

```http
POST /alerts

{
  "title": "Security Alert",
  "description": "Detailed description of the security issue",
  "severity": "high",
  "source": "manual",
  "pipeline_id": 1,
  "vulnerability_id": "CUSTOM-001",
  "metadata": {
    "custom_field": "value"
  }
}
```

### Update Alert

```http
PATCH /alerts/{alert_id}

{
  "title": "Updated Alert Title",
  "severity": "medium"
}
```

### Acknowledge Alert

```http
POST /alerts/{alert_id}/acknowledge

{
  "note": "Investigating this issue"
}
```

### Resolve Alert

```http
POST /alerts/{alert_id}/resolve

{
  "resolution_note": "Fixed by updating to version 1.2.3",
  "resolution_type": "fixed"
}
```

### Bulk Operations

```http
POST /alerts/bulk-action

{
  "alert_ids": [1, 2, 3],
  "action": "acknowledge",
  "note": "Bulk acknowledgment for similar issues"
}
```

### Alert Statistics

```http
GET /alerts/stats?period=30d
```

**Response:**
```json
{
  "total": 156,
  "open": 45,
  "acknowledged": 78,
  "resolved": 33,
  "by_severity": {
    "critical": 5,
    "high": 23,
    "medium": 78,
    "low": 50
  },
  "by_source": {
    "trivy": 89,
    "safety": 34,
    "bandit": 23,
    "manual": 10
  },
  "trend": {
    "daily": [5, 8, 12, 3, 7, 15, 9],
    "weekly": [45, 52, 38, 41]
  }
}
```

## Vulnerability Management

### List Vulnerabilities

```http
GET /vulnerabilities?severity=high&status=open&package=openssl&limit=20&offset=0
```

**Query Parameters:**
- `severity` - Filter by CVSS severity
- `status` - Filter by status (open, fixed, ignored)
- `package` - Filter by package name
- `cve_id` - Filter by CVE identifier
- `scanner` - Filter by scanner source
- `discovered_after` - Filter by discovery date

**Response:**
```json
{
  "items": [
    {
      "id": 1,
      "cve_id": "CVE-2023-1234",
      "title": "OpenSSL Buffer Overflow",
      "description": "Buffer overflow vulnerability in OpenSSL library",
      "severity": "critical",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "status": "open",
      "package": "openssl",
      "version": "1.1.1k",
      "fixed_version": "1.1.1l",
      "scanner": "trivy",
      "discovered_at": "2023-01-20T10:00:00Z",
      "first_seen": "2023-01-20T10:00:00Z",
      "last_seen": "2023-01-22T14:30:00Z",
      "affected_pipelines": [1, 3, 7],
      "references": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234",
        "https://www.openssl.org/news/secadv/20230214.txt"
      ],
      "metadata": {
        "ecosystem": "alpine",
        "introduced": "0",
        "fixed": "1.1.1l-r0"
      }
    }
  ],
  "total": 89,
  "limit": 20,
  "offset": 0
}
```

### Get Vulnerability Details

```http
GET /vulnerabilities/{vulnerability_id}
```

### Update Vulnerability Status

```http
PATCH /vulnerabilities/{vulnerability_id}

{
  "status": "ignored",
  "reason": "False positive - not exploitable in our environment",
  "notes": "Reviewed by security team"
}
```

### Export Vulnerabilities

```http
GET /vulnerabilities/export?format=csv&severity=high,critical&status=open
```

**Query Parameters:**
- `format` - Export format (csv, json, xlsx)
- All vulnerability filter parameters

### Vulnerability Statistics

```http
GET /vulnerabilities/stats?period=30d
```

## Compliance Management

### Get Compliance Overview

```http
GET /compliance?framework=owasp_top_10
```

**Query Parameters:**
- `framework` - Filter by compliance framework
- `status` - Filter by control status
- `category` - Filter by control category

**Response:**
```json
{
  "overall_score": 85.5,
  "trend": 3.2,
  "frameworks": {
    "owasp_top_10": {
      "score": 85.5,
      "passed": 8,
      "failed": 2,
      "last_assessment": "2023-01-20T10:00:00Z"
    },
    "nist_csf": {
      "score": 78.0,
      "passed": 84,
      "failed": 24,
      "last_assessment": "2023-01-19T15:00:00Z"
    }
  },
  "controls": {
    "passed": 92,
    "failed": 26,
    "warnings": 12,
    "not_applicable": 5
  },
  "categories": {
    "access_control": {
      "score": 90,
      "passed": 18,
      "total": 20
    },
    "cryptography": {
      "score": 75,
      "passed": 15,
      "total": 20
    }
  },
  "recent_issues": [
    {
      "control_id": "A02_2021",
      "framework": "owasp_top_10",
      "description": "Cryptographic Failures detected",
      "severity": "high",
      "status": "failed"
    }
  ]
}
```

### List Compliance Frameworks

```http
GET /compliance/frameworks
```

**Response:**
```json
{
  "owasp_top_10": {
    "name": "OWASP Top 10",
    "description": "Top 10 Web Application Security Risks",
    "version": "2021",
    "controls_count": 10,
    "categories": ["injection", "broken_auth", "sensitive_data"]
  },
  "nist_csf": {
    "name": "NIST Cybersecurity Framework",
    "description": "Comprehensive cybersecurity guidelines",
    "version": "1.1",
    "controls_count": 108,
    "categories": ["identify", "protect", "detect", "respond", "recover"]
  }
}
```

### Update Control Status

```http
PATCH /compliance/controls/{control_id}

{
  "status": "acknowledged",
  "note": "Control acknowledged pending remediation",
  "target_date": "2023-02-01T00:00:00Z"
}
```

### Run Compliance Assessment

```http
POST /compliance/assess

{
  "framework": "owasp_top_10",
  "scope": "full",
  "include_pipelines": [1, 2, 3]
}
```

**Response:**
```json
{
  "assessment_id": "assessment_123",
  "status": "running",
  "framework": "owasp_top_10",
  "started_at": "2023-01-20T15:00:00Z",
  "estimated_duration": 300
}
```

### Generate Compliance Report

```http
POST /compliance/report

{
  "framework": "owasp_top_10",
  "format": "pdf",
  "include_remediation": true,
  "include_trends": true,
  "date_range": {
    "start": "2023-01-01T00:00:00Z",
    "end": "2023-01-31T23:59:59Z"
  }
}
```

**Response:**
```json
{
  "report_id": "report_456",
  "status": "generating",
  "format": "pdf",
  "framework": "owasp_top_10",
  "created_at": "2023-01-20T16:00:00Z",
  "download_url": "/compliance/report/report_456"
}
```

### Download Compliance Report

```http
GET /compliance/report/{report_id}
```

## Scanning Management

### Trigger Security Scan

```http
POST /scanning/trigger

{
  "pipeline_id": 1,
  "scanners": ["trivy", "safety", "bandit"],
  "target": {
    "type": "repository",
    "url": "https://github.com/company/app",
    "branch": "main",
    "commit": "abc123"
  },
  "config": {
    "deep_scan": true,
    "include_dev_dependencies": false
  }
}
```

**Response:**
```json
{
  "scan_id": "scan_789",
  "status": "started",
  "pipeline_id": 1,
  "scanners": ["trivy", "safety", "bandit"],
  "started_at": "2023-01-20T16:30:00Z",
  "estimated_duration": 180
}
```

### Get Scan Results

```http
GET /scanning/results?pipeline_id=1&scanner=trivy&status=completed&limit=20&offset=0
```

**Response:**
```json
{
  "items": [
    {
      "scan_id": "scan_789",
      "pipeline_id": 1,
      "scanner": "trivy",
      "status": "completed",
      "started_at": "2023-01-20T16:30:00Z",
      "completed_at": "2023-01-20T16:33:00Z",
      "duration": 180,
      "target": {
        "type": "repository",
        "url": "https://github.com/company/app",
        "branch": "main",
        "commit": "abc123"
      },
      "summary": {
        "total_vulnerabilities": 15,
        "critical": 1,
        "high": 4,
        "medium": 7,
        "low": 3
      },
      "artifacts": [
        {
          "type": "report",
          "format": "json",
          "url": "/scanning/results/scan_789/report.json"
        }
      ]
    }
  ],
  "total": 45,
  "limit": 20,
  "offset": 0
}
```

### Get Scan Details

```http
GET /scanning/results/{scan_id}
```

### List Available Scanners

```http
GET /scanning/scanners
```

**Response:**
```json
{
  "scanners": [
    {
      "id": "trivy",
      "name": "Trivy",
      "description": "Container vulnerability scanner",
      "version": "0.35.0",
      "supported_targets": ["container", "filesystem", "repository"],
      "supported_formats": ["json", "table", "sarif"]
    },
    {
      "id": "safety",
      "name": "Safety",
      "description": "Python dependency scanner",
      "version": "2.3.1",
      "supported_targets": ["python_requirements", "python_environment"],
      "supported_formats": ["json", "text"]
    }
  ]
}
```

## Dashboard and Metrics

### Get Dashboard Overview

```http
GET /dashboard/overview
```

**Response:**
```json
{
  "summary": {
    "total_pipelines": 25,
    "active_pipelines": 20,
    "total_alerts": 156,
    "open_alerts": 45,
    "critical_vulnerabilities": 5,
    "compliance_score": 85.5
  },
  "recent_activity": [
    {
      "id": 1,
      "type": "pipeline_run",
      "pipeline_id": 1,
      "pipeline_name": "Frontend CI/CD",
      "status": "success",
      "timestamp": "2023-01-20T16:45:00Z"
    }
  ],
  "alerts_by_severity": {
    "critical": 5,
    "high": 23,
    "medium": 78,
    "low": 50
  },
  "compliance_trends": [
    {
      "date": "2023-01-20",
      "score": 85.5
    }
  ]
}
```

### Get Metrics

```http
GET /dashboard/metrics?period=7d&metrics=pipeline_success_rate,vulnerability_count
```

**Query Parameters:**
- `period` - Time period (1d, 7d, 30d, 90d)
- `metrics` - Comma-separated list of metrics to include
- `start_date` - Custom start date (ISO 8601)
- `end_date` - Custom end date (ISO 8601)

### Get Activity Feed

```http
GET /dashboard/activity?type=alert&limit=20&offset=0
```

**Query Parameters:**
- `type` - Filter by activity type (alert, pipeline, scan, compliance)
- `user_id` - Filter by user
- `since` - Filter by timestamp

## Settings Management

### Get Settings

```http
GET /settings
```

**Response:**
```json
{
  "security": {
    "mfa_enabled": false,
    "session_timeout": 30,
    "password_policy": "strong"
  },
  "notifications": {
    "email_enabled": true,
    "webhook_enabled": false,
    "severity_threshold": "medium"
  },
  "integrations": {
    "github": {
      "enabled": true,
      "webhook_configured": true
    }
  },
  "scanning": {
    "auto_scan": true,
    "scan_schedule": "daily",
    "enabled_scanners": ["trivy", "safety", "bandit"]
  }
}
```

### Update Settings

```http
PUT /settings

{
  "security": {
    "session_timeout": 60,
    "password_policy": "complex"
  },
  "notifications": {
    "email_enabled": true,
    "severity_threshold": "high"
  }
}
```

### Test Integration

```http
POST /settings/test/{integration_type}

{
  "token": "integration_token",
  "url": "https://api.service.com",
  "timeout": 30
}
```

## Rate Limiting

The API implements rate limiting to ensure fair usage:

- **Unauthenticated requests:** 100 requests per hour per IP
- **Authenticated requests:** 1000 requests per hour per user
- **Admin requests:** 5000 requests per hour per user

Rate limit headers are included in responses:

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1642694400
```

## Webhooks

### Pipeline Webhooks

SecureOps can receive webhooks from various CI/CD platforms:

#### GitHub
```http
POST /pipelines/webhook/github
X-GitHub-Event: push
X-Hub-Signature-256: sha256=signature

{
  "action": "push",
  "repository": {
    "full_name": "company/repo"
  },
  "commits": [...]
}
```

#### GitLab
```http
POST /pipelines/webhook/gitlab
X-Gitlab-Event: Push Hook
X-Gitlab-Token: token

{
  "event_name": "push",
  "project": {
    "path_with_namespace": "company/repo"
  }
}
```

### Alert Webhooks

Configure outgoing webhooks for alerts:

```json
{
  "url": "https://your-service.com/webhook",
  "events": ["alert.created", "alert.resolved"],
  "severity_filter": ["critical", "high"],
  "secret": "webhook_secret"
}
```

## WebSocket Events

Real-time updates are available via WebSocket connection:

**Connection:** `wss://api.secureops.example.com/ws?token=your_jwt_token`

### Event Types

- `pipeline.status_changed`
- `alert.created`
- `alert.updated`
- `scan.completed`
- `compliance.updated`

### Event Format

```json
{
  "type": "alert.created",
  "payload": {
    "alert": {
      "id": 123,
      "title": "New Security Alert",
      "severity": "high"
    }
  },
  "timestamp": "2023-01-20T17:00:00Z"
}
```

## SDKs and Libraries

Official SDKs are available for popular programming languages:

- **Python:** `pip install secureops-sdk`
- **JavaScript/Node.js:** `npm install @secureops/sdk`
- **Go:** `go get github.com/secureops/go-sdk`
- **Java:** Maven/Gradle dependency available

### Example Usage (Python)

```python
from secureops import SecureOpsClient

client = SecureOpsClient(
    base_url="https://api.secureops.example.com",
    token="your_jwt_token"
)

# Get pipelines
pipelines = client.pipelines.list(platform="github")

# Create alert
alert = client.alerts.create(
    title="Security Issue",
    severity="high",
    description="Detailed description"
)

# Get compliance status
compliance = client.compliance.get_overview()
```

## Changelog

### v1.2.0 (2023-01-20)
- Added compliance automation endpoints
- Enhanced vulnerability filtering
- Improved WebSocket event handling

### v1.1.0 (2023-01-10)
- Added bulk operations for alerts
- Enhanced pipeline statistics
- Added webhook signature verification

### v1.0.0 (2023-01-01)
- Initial API release
- Core pipeline, alert, and compliance endpoints
- Authentication and authorization

## Support

For API support and questions:

- **Documentation:** https://docs.secureops.example.com
- **Support Email:** support@secureops.example.com
- **GitHub Issues:** https://github.com/secureops/api/issues
- **Discord Community:** https://discord.gg/secureops
