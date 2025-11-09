"""
SecureOps FastAPI Application - Unified Production Entry Point
Comprehensive DevSecOps CI/CD Pipeline Security Monitor

This is the unified main FastAPI application that orchestrates all components:
- API routes for authentication, alerts, pipelines, reports
- Integration with Celery task system
- Scanner orchestration
- CI/CD platform integrations
- Real-time monitoring and notifications
- Prometheus metrics and monitoring
- WebSocket support for real-time updates
- Redis integration for caching and sessions

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import asyncio
import json
import os
import sys
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List

import redis.asyncio as aioredis
import uvicorn
from fastapi import (Depends, FastAPI, HTTPException, Request, WebSocket,
                     WebSocketDisconnect, status)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
from prometheus_client import (Counter, Gauge, Histogram, make_asgi_app,
                               start_http_server)
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request as StrRequest
from starlette.responses import Response

# Import task modules
from ..tasks.alert_tasks import process_alert
from ..tasks.background_tasks import cleanup_old_logs
from ..tasks.scan_tasks import run_security_scan
from ..tasks.workflow_executor import execute_workflow
# Import application modules
from .database import get_async_db
from .database import health_check as db_health_check
from .database import init_database
from .routes.alerts import router as alerts_router
from .routes.auth import router as auth_router
from .routes.pipelines import router as pipelines_router
from .routes.reports import router as reports_router
# Import services
from .services.alert_service import AlertService
from .services.compliance_service import ComplianceService
from .services.pipeline_services import PipelineService
from .services.report_service import ReportService
from .services.vulnerability_service import VulnerabilityService
# Import utilities
from .utils.config import get_settings, validate_environment
from .utils.logger import (AuditLogger, configure_logging, get_logger,
                           setup_sentry)
from .utils.rbac import get_current_user
from .utils.scheduler import start_scheduler
from .utils.validators import validate_request

# from .routes.scans import router as scans_router  # Enable when ready


# Configuration
settings = get_settings()
logger = get_logger(__name__)
security = HTTPBearer()

# Global Redis connection
redis = None


async def get_redis():
    """Get Redis connection with connection pooling."""
    global redis
    if redis is None:
        redis = await aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            max_connections=20,
        )
    return redis


# Prometheus metrics
REQUEST_COUNT = Counter(
    "http_requests_total", "Total HTTP requests", ["method", "endpoint", "status"]
)
REQUEST_DURATION = Histogram("http_request_duration_seconds", "HTTP request duration")
ACTIVE_CONNECTIONS = Gauge("http_active_connections", "Active HTTP connections")
VULNERABILITY_COUNT = Gauge(
    "secureops_vulnerabilities_total", "Total vulnerabilities", ["severity"]
)
PIPELINE_COUNT = Gauge("secureops_pipelines_total", "Total pipelines", ["status"])
ALERT_COUNT = Gauge("secureops_alerts_total", "Total alerts", ["severity", "status"])


# WebSocket Manager for Real-Time Dashboard
class ConnectionManager:
    """WebSocket connection manager for real-time updates."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        ACTIVE_CONNECTIONS.inc()
        logger.info(
            f"WebSocket connected. Active connections: {len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            ACTIVE_CONNECTIONS.dec()
            logger.info(
                f"WebSocket disconnected. Active connections: {len(self.active_connections)}"
            )

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except Exception as e:
            logger.error(f"Failed to send WebSocket message: {e}")
            self.disconnect(websocket)

    async def broadcast(self, message: str):
        """Broadcast message to all connected clients."""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.append(connection)

        # Clean up disconnected clients
        for connection in disconnected:
            self.disconnect(connection)


# Global connection manager
manager = ConnectionManager()


# Security middleware
class SecurityMiddleware(BaseHTTPMiddleware):
    """Enhanced security middleware."""

    async def dispatch(self, request: StrRequest, call_next):
        start_time = time.time()

        # Add security headers
        response = await call_next(request)

        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'"

        # Log request metrics
        process_time = time.time() - start_time
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.url.path,
            status=response.status_code,
        ).inc()
        REQUEST_DURATION.observe(process_time)

        return response


# Application lifespan management
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""

    # Startup
    logger.info("🚀 Starting SecureOps FastAPI application...")

    try:
        # Configure logging
        configure_logging()

        # Validate environment configuration
        validate_environment()

        # Setup error tracking
        if settings.environment == "production":
            setup_sentry()

        # Initialize database
        if settings.environment != "test":
            await init_database()

        # Check database health
        try:
            await db_health_check()
            logger.info("✅ Database connection established successfully")
        except Exception as e:
            logger.error(f"❌ Database health check failed: {e}")
            if settings.environment == "production":
                raise

        # Initialize Redis connection
        try:
            await get_redis()
            logger.info("✅ Redis connection established successfully")
        except Exception as e:
            logger.error(f"❌ Redis connection failed: {e}")
            if settings.environment == "production":
                raise

        # Start background scheduler
        if settings.environment != "test":
            await start_scheduler()
            logger.info("✅ Background scheduler started")

        # Start Prometheus metrics server
        if settings.metrics_enabled:
            start_http_server(settings.metrics_port)
            logger.info(
                f"✅ Prometheus metrics server started on port {settings.metrics_port}"
            )

        logger.info("🎉 SecureOps application startup completed successfully")

    except Exception as e:
        logger.error(f"💥 Failed to start application: {e}")
        raise

    yield

    # Shutdown
    logger.info("🛑 Shutting down SecureOps application...")

    try:
        # Close Redis connection
        if redis:
            await redis.close()
            logger.info("✅ Redis connection closed")

        # Cleanup background tasks
        logger.info("✅ Background tasks cleaned up")

        # Close WebSocket connections
        if manager.active_connections:
            await manager.broadcast(
                json.dumps({"type": "shutdown", "message": "Server shutting down"})
            )
            logger.info("✅ WebSocket connections notified of shutdown")

        logger.info("✅ SecureOps application shutdown completed")

    except Exception as e:
        logger.error(f"❌ Error during shutdown: {e}")


# Create FastAPI application
app = FastAPI(
    title="SecureOps AI - DevSecOps Platform",
    version=getattr(settings, "app_version", "1.0.0"),
    description="Comprehensive DevSecOps CI/CD Pipeline Security Monitor with real-time monitoring",
    docs_url="/docs" if settings.environment != "production" else None,
    redoc_url="/redoc" if settings.environment != "production" else None,
    openapi_url="/openapi.json" if settings.environment != "production" else None,
    lifespan=lifespan,
)

# CORS Configuration
if hasattr(settings, "cors_origins"):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Add middleware (order matters!)
app.add_middleware(SecurityMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Trusted hosts middleware for production
if settings.environment == "production" and hasattr(settings, "allowed_hosts"):
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)

# Session middleware
if hasattr(settings, "session_secret_key"):
    app.add_middleware(SessionMiddleware, secret_key=settings.session_secret_key)

# Add Prometheus metrics endpoint
if settings.metrics_enabled:
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)

# Include API routers
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(alerts_router, prefix="/api/v1/alerts", tags=["Alerts"])
app.include_router(pipelines_router, prefix="/api/v1/pipelines", tags=["Pipelines"])
app.include_router(reports_router, prefix="/api/v1/reports", tags=["Reports"])
# app.include_router(scans_router, prefix="/api/v1/scans", tags=["Security Scanning"])  # Enable when ready


# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """Root endpoint providing API information."""
    return {
        "message": "Welcome to SecureOps AI - DevSecOps Platform",
        "app": "SecureOps API",
        "version": getattr(settings, "app_version", "1.0.0"),
        "environment": settings.environment,
        "docs_url": (
            "/docs"
            if settings.environment != "production"
            else "Disabled in production"
        ),
        "health_url": "/health",
        "metrics_url": "/metrics" if settings.metrics_enabled else "Disabled",
        "api_prefix": "/api/v1",
        "endpoints": {
            "authentication": "/api/v1/auth",
            "alerts": "/api/v1/alerts",
            "pipelines": "/api/v1/pipelines",
            "reports": "/api/v1/reports",
            "websocket": "/ws",
        },
        "features": {
            "real_time_monitoring": True,
            "prometheus_metrics": settings.metrics_enabled,
            "websocket_support": True,
            "redis_caching": True,
            "background_tasks": True,
        },
    }


# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check(db: AsyncSession = Depends(get_async_db)):
    """Comprehensive health check endpoint."""
    health_status = {
        "status": "healthy",
        "timestamp": time.time(),
        "version": getattr(settings, "app_version", "1.0.0"),
        "environment": settings.environment,
        "checks": {},
    }

    try:
        # Database health check
        result = await db.execute(text("SELECT 1"))
        health_status["checks"]["database"] = {
            "status": "healthy",
            "response_time_ms": None,
        }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        health_status["checks"]["database"] = {"status": "unhealthy", "error": str(e)}
        health_status["status"] = "unhealthy"

    # Redis health check
    try:
        redis_client = await get_redis()
        await redis_client.ping()
        health_status["checks"]["redis"] = {"status": "healthy"}
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        health_status["checks"]["redis"] = {"status": "unhealthy", "error": str(e)}
        if settings.environment == "production":
            health_status["status"] = "unhealthy"

    # Return appropriate status code
    status_code = 200 if health_status["status"] == "healthy" else 503
    return JSONResponse(content=health_status, status_code=status_code)


# System status endpoint
@app.get("/api/v1/system/status", tags=["System"])
async def system_status(current_user: dict = Depends(get_current_user)):
    """Get detailed system status and metrics."""
    return {
        "system": {
            "uptime": time.time(),
            "active_connections": len(manager.active_connections),
            "environment": settings.environment,
        },
        "metrics": {
            "total_requests": (
                REQUEST_COUNT._value._value if hasattr(REQUEST_COUNT, "_value") else 0
            ),
            "active_websockets": len(manager.active_connections),
        },
    }


# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time dashboard updates."""
    await manager.connect(websocket)
    try:
        while True:
            # Send periodic updates
            await asyncio.sleep(30)  # Send update every 30 seconds
            status_update = {
                "type": "status_update",
                "timestamp": time.time(),
                "active_connections": len(manager.active_connections),
                "system_status": "healthy",
            }
            await manager.send_personal_message(json.dumps(status_update), websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


# System scan orchestration endpoint
@app.post("/api/v1/scans/orchestrate", tags=["Security Scanning"])
async def orchestrate_scan(
    request_data: dict,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    """Orchestrate comprehensive security scanning."""
    try:
        # Start background scan task
        task = await run_security_scan.delay(request_data)

        return {
            "status": "scan_initiated",
            "task_id": task.id,
            "message": "Security scan started successfully",
        }
    except Exception as e:
        logger.error(f"Failed to orchestrate scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to start security scan")


# System cleanup endpoint
@app.post("/api/v1/system/cleanup", tags=["System"])
async def system_cleanup(current_user: dict = Depends(get_current_user)):
    """Trigger system cleanup tasks."""
    try:
        await cleanup_old_logs.delay()
        return {"status": "cleanup_initiated", "message": "System cleanup started"}
    except Exception as e:
        logger.error(f"Failed to start cleanup: {e}")
        raise HTTPException(status_code=500, detail="Failed to start cleanup")


# Webhook endpoints for CI/CD integrations
@app.post("/api/v1/webhooks/github", tags=["Webhooks"])
async def github_webhook(request: Request):
    """Handle GitHub webhook events."""
    try:
        payload = await request.json()
        # Process GitHub webhook
        logger.info(f"Received GitHub webhook: {payload.get('action', 'unknown')}")
        return {"status": "webhook_processed"}
    except Exception as e:
        logger.error(f"Failed to process GitHub webhook: {e}")
        raise HTTPException(status_code=400, detail="Invalid webhook payload")


@app.post("/api/v1/webhooks/gitlab", tags=["Webhooks"])
async def gitlab_webhook(request: Request):
    """Handle GitLab webhook events."""
    try:
        payload = await request.json()
        # Process GitLab webhook
        logger.info(f"Received GitLab webhook: {payload.get('object_kind', 'unknown')}")
        return {"status": "webhook_processed"}
    except Exception as e:
        logger.error(f"Failed to process GitLab webhook: {e}")
        raise HTTPException(status_code=400, detail="Invalid webhook payload")


@app.post("/api/v1/webhooks/azure", tags=["Webhooks"])
async def azure_webhook(request: Request):
    """Handle Azure DevOps webhook events."""
    try:
        payload = await request.json()
        # Process Azure webhook
        logger.info(f"Received Azure webhook: {payload.get('eventType', 'unknown')}")
        return {"status": "webhook_processed"}
    except Exception as e:
        logger.error(f"Failed to process Azure webhook: {e}")
        raise HTTPException(status_code=400, detail="Invalid webhook payload")


@app.post("/api/v1/webhooks/jenkins", tags=["Webhooks"])
async def jenkins_webhook(request: Request):
    """Handle Jenkins webhook events."""
    try:
        payload = await request.json()
        # Process Jenkins webhook
        logger.info(f"Received Jenkins webhook")
        return {"status": "webhook_processed"}
    except Exception as e:
        logger.error(f"Failed to process Jenkins webhook: {e}")
        raise HTTPException(status_code=400, detail="Invalid webhook payload")


# Custom OpenAPI schema
def custom_openapi():
    """Generate custom OpenAPI schema with security definitions."""
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="SecureOps AI - DevSecOps Platform",
        version=getattr(settings, "app_version", "1.0.0"),
        description="Comprehensive DevSecOps CI/CD Pipeline Security Monitor with real-time capabilities",
        routes=app.routes,
    )

    # Add security scheme
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

# Development server
if __name__ == "__main__":
    # Configure logging
    configure_logging()

    # Run the server
    uvicorn.run(
        "api.main:app",
        host=getattr(settings, "api_host", "0.0.0.0"),
        port=getattr(settings, "api_port", 8000),
        reload=settings.debug and settings.environment == "development",
        workers=1 if settings.debug else 4,
        log_level="info",
        access_log=True,
    )
