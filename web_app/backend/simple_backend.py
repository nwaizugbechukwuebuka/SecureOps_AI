"""
Simple FastAPI server for SecureOps AI
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from fastapi.responses import HTMLResponse, RedirectResponse
import os
import uvicorn
from datetime import datetime

# Simple FastAPI app for development
app = FastAPI(title="SecureOps AI Backend", version="1.0.0")

# Configure CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3010", "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for development (replace with database in production)
users_db = {
    "admin": {
        "id": 1,
        "username": "admin",
        "email": "admin@secureops.ai",
        "full_name": "System Administrator",
        "is_admin": True,
        "is_active": True,
        "created_at": datetime.utcnow(),
        "hashed_password": "$2b$12$5/K8S7oRjQqE9X2qHv3k5efKlYiK6UgKR1FN9UqP7yXf2yZz6JgYm",  # admin123
    }
}

security_analytics_data = {
    "total_events": 1247,
    "critical_events": 23,
    "high_events": 156,
    "medium_events": 543,
    "low_events": 525,
    "threat_trends": [
        {"date": "2024-10-28", "threats": 12},
        {"date": "2024-10-29", "threats": 19},
        {"date": "2024-10-30", "threats": 8},
        {"date": "2024-10-31", "threats": 24},
        {"date": "2024-11-01", "threats": 15},
    ],
    "top_threats": [
        {"name": "Brute Force Attack", "count": 45, "severity": "high"},
        {"name": "SQL Injection", "count": 23, "severity": "critical"},
        {"name": "XSS Attempt", "count": 18, "severity": "medium"},
        {"name": "Port Scan", "count": 67, "severity": "low"},
    ],
    "geographic_data": [
        {"country": "US", "threats": 89},
        {"country": "CN", "threats": 67},
        {"country": "RU", "threats": 45},
        {"country": "DE", "threats": 23},
    ],
}

# Mock authentication (for development only)


def verify_token(token: str = None):
    return users_db["admin"]  # Always return admin for development


# Root route to redirect to docs


@app.get("/", response_class=RedirectResponse)
async def root():
    return RedirectResponse(url="/docs")


@app.get("/api", response_class=HTMLResponse)
async def api_info():
    return """
    <html>
        <head><title>SecureOps AI Backend API</title></head>
        <body>
            <h1>SecureOps AI Backend API</h1>
            <p>Backend is running successfully!</p>
            <p><a href="/docs">View API Documentation</a></p>
            <p><strong>Available Endpoints:</strong></p>
            <ul>
                <li>GET /api/health - Health check</li>
                <li>POST /api/auth/login - Authentication</li>
                <li>GET /api/auth/me - Current user info</li>
                <li>GET /api/analytics/security - Security analytics</li>
                <li>GET /api/system/health - System health metrics</li>
            </ul>
        </body>
    </html>
    """


# Health check endpoint


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


# Authentication endpoints


@app.post("/api/auth/login")
async def login(credentials: dict):
    username = credentials.get("username")
    password = credentials.get("password")

    if username == "admin" and password == "admin123":
        return {"access_token": "dev-token-12345", "token_type": "bearer"}
    elif username == "demo" and password == "demo123":
        return {"access_token": "dev-token-67890", "token_type": "bearer"}
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/api/auth/me")
async def get_current_user():
    return users_db["admin"]


# Security Analytics endpoints


@app.get("/api/analytics/security")
async def get_security_analytics():
    return security_analytics_data


@app.get("/api/security-events")
async def get_security_events():
    return [
        {
            "id": 1,
            "event_type": "brute_force",
            "severity": "high",
            "source_ip": "192.168.1.100",
            "target_ip": "10.0.0.1",
            "description": "Multiple failed login attempts detected",
            "timestamp": datetime.utcnow().isoformat(),
        },
        {
            "id": 2,
            "event_type": "port_scan",
            "severity": "medium",
            "source_ip": "203.0.113.45",
            "target_ip": "10.0.0.5",
            "description": "Port scanning activity detected",
            "timestamp": datetime.utcnow().isoformat(),
        },
    ]


# System Health endpoints


@app.get("/api/system/health")
async def get_system_health():
    import psutil

    return {
        "cpu_usage": psutil.cpu_percent(interval=0.1),
        "memory_usage": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage("/").percent if os.name != "nt" else psutil.disk_usage("C:").percent,
        "network_io": {"bytes_sent": 1024000, "bytes_recv": 2048000},
        "active_connections": 12,
        "redis_status": "healthy",
        "celery_status": "healthy",
        "database_status": "healthy",
    }


# User management endpoints


@app.get("/api/users")
async def get_users():
    return [users_db["admin"]]


@app.post("/api/users")
async def create_user(user_data: dict):
    return {"message": "User created successfully", "id": len(users_db) + 1}


# Automation endpoints


@app.get("/api/automation/tasks")
async def get_automation_tasks():
    return [
        {
            "id": 1,
            "task_name": "Security Scan",
            "task_type": "vulnerability_scan",
            "status": "completed",
            "created_at": datetime.utcnow().isoformat(),
            "completed_at": datetime.utcnow().isoformat(),
            "result": {"vulnerabilities_found": 3, "status": "success"},
        }
    ]


@app.post("/api/automation/tasks")
async def create_automation_task(task_data: dict):
    return {
        "id": 2,
        "task_name": task_data.get("task_name", "New Task"),
        "task_type": task_data.get("task_type", "generic"),
        "status": "pending",
        "created_at": datetime.utcnow().isoformat(),
    }


# Notifications endpoints


@app.get("/api/notifications")
async def get_notifications():
    return [
        {
            "id": 1,
            "title": "Security Alert",
            "message": "Unusual login activity detected",
            "type": "warning",
            "is_read": False,
            "created_at": datetime.utcnow().isoformat(),
        }
    ]


# Logs endpoints


@app.get("/api/logs")
async def get_logs():
    return [
        {
            "timestamp": datetime.utcnow().isoformat(),
            "level": "INFO",
            "source": "auth.py",
            "message": "User admin logged in successfully",
        },
        {
            "timestamp": datetime.utcnow().isoformat(),
            "level": "WARNING",
            "source": "security.py",
            "message": "Failed login attempt detected",
        },
    ]


# Additional service status endpoints


@app.get("/api/celery/status")
async def get_celery_status():
    return {"active_workers": 3, "pending_tasks": 5, "completed_tasks": 142, "failed_tasks": 2}


@app.get("/api/redis/data")
async def get_redis_data():
    return {
        "connected_clients": 8,
        "used_memory_human": "2.5MB",
        "total_commands_processed": 1547,
        "keyspace_hits": 892,
        "keyspace_misses": 34,
    }


@app.get("/api/prometheus/metrics")
async def get_prometheus_metrics():
    return {
        "http_requests_total": 2547,
        "http_request_duration_seconds": 0.245,
        "database_connections_active": 12,
        "memory_usage_bytes": 256000000,
        "cpu_usage_percent": 23.4,
    }


if __name__ == "__main__":
    print("🚀 Starting SecureOps AI Development Backend...")
    print("🌐 Backend API will be available at http://localhost:8010")
    print("📚 API Documentation at http://localhost:8010/docs")

    uvicorn.run("simple_backend:app", host="0.0.0.0", port=8010, reload=True, log_level="info")
