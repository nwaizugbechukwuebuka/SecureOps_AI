"""
SecureOps FastAPI Application - DevSecOps CI/CD Pipeline Monitor
Main application entry point with comprehensive security monitoring.
"""

import asyncio
import os
import sys
import time
from contextlib import asynccontextmanager
import json
from typing import List, Dict, Any

import uvicorn
import redis.asyncio as aioredis
from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    make_asgi_app,
    start_http_server,
)

# Import application modules
from .database import get_async_db
from .database import health_check as db_health_check
from .database import init_database
from .routes.alerts import router as alerts_router
from .routes.auth import router as auth_router
from .routes.pipelines import router as pipelines_router
from .routes.reports import router as reports_router
from .utils.config import get_settings, validate_environment
from .utils.logger import (
    LoggerMiddleware,
    audit_logger,
    configure_logging,
    get_logger,
    log_shutdown_info,
    log_startup_info,
    security_logger,
    setup_sentry,
)
from .utils.scheduler import celery_health_check, setup_periodic_tasks

# Configuration
settings = get_settings()
logger = get_logger(__name__)
security = HTTPBearer()

# Redis connection (for rate limiting)
redis = None

async def get_redis():
    global redis
    if redis is None:
        redis = await aioredis.from_url(settings.redis_url, encoding="utf-8", decode_responses=True)
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


# --- WebSocket Manager for Real-Time Dashboard ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.subscriptions: Dict[WebSocket, List[str]] = {}

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        self.subscriptions[websocket] = []

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if websocket in self.subscriptions:
            del self.subscriptions[websocket]

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        await websocket.send_text(json.dumps(message))

    async def broadcast(self, message: dict, channel: str = None):
        for connection in self.active_connections:
            if channel is None or channel in self.subscriptions.get(connection, []):
                try:
                    await connection.send_text(json.dumps(message))
                except Exception:
                    pass

    def subscribe(self, websocket: WebSocket, channels: List[str]):
        self.subscriptions[websocket] = channels

manager = ConnectionManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management."""
    # Startup
    logger.info("Starting SecureOps application...")

    try:
        # Validate environment configuration
        validate_environment()

        # Setup error tracking
        setup_sentry()

        # Initialize database
        if settings.environment != "test":
            init_database()

        # Check database health
        db_health = await db_health_check()
        if not db_health.get("database_connected"):
            logger.error("Database connection failed during startup")
            if settings.is_production():
                raise RuntimeError("Database connection required in production")

        # Setup background tasks
        setup_periodic_tasks()

        # Start Prometheus metrics server if enabled
        if settings.prometheus_metrics_enabled:
            try:
                start_http_server(settings.prometheus_metrics_port)
                logger.info(
                    f"Prometheus metrics server started on port {settings.prometheus_metrics_port}"
                )
            except Exception as e:
                logger.warning(f"Failed to start Prometheus metrics server: {e}")

        # Log startup completion
        log_startup_info()
        logger.info("SecureOps application started successfully")

        yield

    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise

    # Shutdown
    logger.info("Shutting down SecureOps application...")
    log_shutdown_info()
    logger.info("SecureOps application shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="SecureOps API",
    description="""
    SecureOps - DevSecOps CI/CD Pipeline Security Monitor
    
    A comprehensive security monitoring platform that continuously scans CI/CD pipelines 
    for vulnerabilities, misconfigurations, exposed secrets, and compliance issues.
    """,
    version=getattr(settings, "app_version", "1.0.0"),
    docs_url=settings.docs_url,
    redoc_url=settings.redoc_url,
    openapi_url="/api/v1/openapi.json",
    lifespan=lifespan,
)

# Add security middleware
try:
    from .middleware.security import SecurityHeadersMiddleware, RateLimitMiddleware
    
    # Add security headers
    app.add_middleware(SecurityHeadersMiddleware)
    
    # Add rate limiting (if Redis is available)
    if hasattr(settings, 'redis_url'):
        app.add_middleware(RateLimitMiddleware, redis_url=settings.redis_url, default_rate_limit=100)
        
except ImportError:
    logger.warning("Security middleware not available")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=getattr(settings, 'cors_origins', ["http://localhost:3000", "http://localhost:80"]),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With"],
    expose_headers=["Content-Disposition"],
    max_age=86400,
)

# --- WebSocket Endpoint for Dashboard ---
@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
            except Exception:
                continue
            if msg.get("type") == "subscribe":
                channels = msg.get("channels", [])
                manager.subscribe(websocket, channels)
                await manager.send_personal_message({"type": "subscribed", "channels": channels}, websocket)
            elif msg.get("type") == "ping":
                await manager.send_personal_message({"type": "heartbeat"}, websocket)
            # Add more message types as needed
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


# --- Example: Function to emit events to dashboard ---
async def emit_dashboard_event(event_type: str, payload: Any, channel: str):
    await manager.broadcast({"type": event_type, "payload": payload, "channel": channel}, channel=channel)


# Include routers
app.include_router(
    auth_router, prefix="/api/v1/auth", tags=["Authentication"]
)
app.include_router(
    alerts_router, prefix="/api/v1/alerts", tags=["Alerts"]
)
app.include_router(
    pipelines_router, prefix="/api/v1/pipelines", tags=["Pipelines"]
)
app.include_router(
    reports_router, prefix="/api/v1/reports", tags=["Reports"]
)

# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """Root endpoint providing API information."""
    return {
        "message": "Welcome to SecureOps AI - DevSecOps Platform",
        "app": "SecureOps API",
        "version": getattr(settings, "app_version", "1.0.0"),
        "docs_url": "/docs",
        "health_url": "/health",
        "api_prefix": "/api/v1",
        "endpoints": {
            "authentication": "/api/v1/auth",
            "alerts": "/api/v1/alerts", 
            "pipelines": "/api/v1/pipelines",
            "reports": "/api/v1/reports"
        }
    }

# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint for container health checks."""
    return {
        "status": "ok",
        "app": "SecureOps API", 
        "version": getattr(settings, "app_version", "1.0.0")
    }

# Mount Prometheus metrics
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

if __name__ == "__main__":
    # Configure logging
    configure_logging()

    # Run the server
    uvicorn.run(
        "src.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
        access_log=True,
    )