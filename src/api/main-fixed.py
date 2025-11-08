"""
SecureOps FastAPI Application - DevSecOps CI/CD Pipeline Monitor
Main application entry point with comprehensive security monitoring.
"""

import asyncio
import os
import sys
import time
import json
from contextlib import asynccontextmanager
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
    get_logger,
    setup_sentry,
    configure_logging,
    log_api_request,
    log_security_event,
)

# Initialize settings and logger
settings = get_settings()
logger = get_logger(__name__)

# Global Redis connection
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

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        ACTIVE_CONNECTIONS.inc()

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            ACTIVE_CONNECTIONS.dec()

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except Exception:
            self.disconnect(websocket)

    async def broadcast(self, message: str):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.append(connection)
        
        # Clean up disconnected connections
        for conn in disconnected:
            self.disconnect(conn)


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
        try:
            await db_health_check()
            logger.info("Database connection established successfully")
        except Exception as e:
            logger.error(f"Database health check failed: {e}")

        # Initialize Redis connection
        try:
            await get_redis()
            logger.info("Redis connection established successfully")
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")

        logger.info("SecureOps application startup completed")

    except Exception as e:
        logger.error(f"Application startup failed: {e}")
        raise

    yield

    # Shutdown
    logger.info("Shutting down SecureOps application...")
    
    # Close Redis connection
    if redis:
        await redis.close()
    
    logger.info("SecureOps application shutdown completed")


# Create FastAPI application
app = FastAPI(
    title="SecureOps AI - DevSecOps Platform",
    description="Comprehensive DevSecOps CI/CD Pipeline Security Monitor with AI-powered threat detection",
    version=getattr(settings, "app_version", "1.0.0"),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
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
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Add compression middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Add trusted host middleware for production
if settings.environment == "production":
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=getattr(settings, 'allowed_hosts', ["localhost", "127.0.0.1"]),
    )


# --- Request/Response Middleware ---
@app.middleware("http")
async def track_requests(request: Request, call_next):
    """Track API requests for metrics and logging."""
    start_time = time.time()
    method = request.method
    path = request.url.path
    
    response = await call_next(request)
    
    process_time = time.time() - start_time
    status_code = response.status_code
    
    # Update Prometheus metrics
    REQUEST_COUNT.labels(method=method, endpoint=path, status=status_code).inc()
    REQUEST_DURATION.observe(process_time)
    
    # Log API request
    log_api_request(
        method=method,
        path=path,
        status_code=status_code,
        response_time=process_time,
        user_agent=request.headers.get("user-agent", ""),
        ip_address=request.client.host if request.client else "unknown",
    )
    
    # Add custom headers
    response.headers["X-Process-Time"] = str(process_time)
    response.headers["X-SecureOps-Version"] = getattr(settings, "app_version", "1.0.0")
    
    return response


# --- Include Routers ---
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

# --- WebSocket Endpoints ---
@app.websocket("/ws/dashboard")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time dashboard updates."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            
            # Echo back for now (implement real-time data later)
            await manager.send_personal_message(f"Echo: {data}", websocket)
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("WebSocket client disconnected")


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint for real-time alert notifications."""
    await manager.connect(websocket)
    try:
        while True:
            # Send real-time alerts (implement actual alert streaming)
            await asyncio.sleep(30)  # Send updates every 30 seconds
            
            # Mock alert data (replace with real data)
            alert_data = {
                "type": "security_alert",
                "severity": "medium",
                "message": "New vulnerability detected in pipeline",
                "timestamp": time.time()
            }
            
            await manager.send_personal_message(
                json.dumps(alert_data), websocket
            )
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("Alert WebSocket client disconnected")


# --- Error Handlers ---
@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    """Custom 404 handler."""
    return JSONResponse(
        status_code=404,
        content={
            "error": "Not Found",
            "message": f"The requested resource {request.url.path} was not found",
            "timestamp": time.time()
        }
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: Exception):
    """Custom 500 handler."""
    logger.error(f"Internal server error: {exc}")
    
    log_security_event(
        event_type="internal_server_error",
        severity="high",
        details={
            "path": request.url.path,
            "method": request.method,
            "error": str(exc)
        }
    )
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An internal error occurred while processing your request",
            "timestamp": time.time()
        }
    )


# Custom OpenAPI schema
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title="SecureOps AI API",
        version=getattr(settings, "app_version", "1.0.0"),
        description="Comprehensive DevSecOps CI/CD Pipeline Security Monitor",
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