"""
SecureOps FastAPI Application - DevSecOps CI/CD Pipeline Monitor
Main application entry point with comprehensive security monitoring.
"""

import asyncio
import os
import sys
import time
from contextlib import asynccontextmanager
<<<<<<< HEAD
import json
from typing import List, Dict, Any

import uvicorn
import redis.asyncio as aioredis
from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
=======

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
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
<<<<<<< HEAD
=======

# Import routes
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
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

<<<<<<< HEAD
# Redis connection (for rate limiting)
redis = None

async def get_redis():
    global redis
    if redis is None:
        redis = await aioredis.from_url(settings.redis_url, encoding="utf-8", decode_responses=True)
    return redis

=======
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
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


<<<<<<< HEAD
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


=======
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
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
<<<<<<< HEAD
    """,
    version=getattr(settings, "app_version", "1.0.0"),
=======
    
    ## Features
    
    * **Multi-Platform Integration**: Supports GitHub Actions, GitLab CI, Jenkins, and Azure DevOps
    * **Comprehensive Scanning**: Vulnerability, secret, dependency, and container security scanning
    * **Real-time Monitoring**: Continuous pipeline monitoring with instant alerts
    * **Compliance Tracking**: OWASP, NIST, SOC2, and GDPR compliance monitoring
    * **Advanced Analytics**: Security metrics, trends, and risk scoring
    * **Intelligent Alerting**: Smart alert management with escalation and notification
    
    ## Security Scanners
    
    * **Bandit**: Python security linting
    * **Safety**: Python dependency vulnerability scanning
    * **Semgrep**: Multi-language static analysis
    * **Trivy**: Container and filesystem vulnerability scanning
    * **Custom Policy Checkers**: Compliance and configuration validation
    
    ## Authentication
    
    All endpoints require authentication via JWT tokens or API keys.
    """,
    version=settings.app_version,
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    docs_url=settings.docs_url,
    redoc_url=settings.redoc_url,
    openapi_url="/api/v1/openapi.json",
    lifespan=lifespan,
)

<<<<<<< HEAD
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
=======
# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_credentials,
    allow_methods=settings.cors_methods,
    allow_headers=settings.cors_headers,
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=(
        ["*"] if settings.debug else ["localhost", "127.0.0.1", settings.api_host]
    ),
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

# Add custom logging middleware
app.add_middleware(LoggerMiddleware)


# Add Prometheus metrics middleware
@app.middleware("http")
async def prometheus_middleware(request: Request, call_next):
    """Middleware to collect Prometheus metrics."""
    start_time = time.time()

    ACTIVE_CONNECTIONS.inc()

    try:
        response = await call_next(request)

        # Record metrics
        duration = time.time() - start_time
        REQUEST_DURATION.observe(duration)
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.url.path,
            status=response.status_code,
        ).inc()

        return response

    finally:
        ACTIVE_CONNECTIONS.dec()


# Security middleware
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Security middleware for additional protection."""

    # Security headers
    response = await call_next(request)

    # Add security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Remove server header for security
    if "server" in response.headers:
        del response.headers["server"]

    return response


# Rate limiting middleware (basic implementation)
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Basic rate limiting middleware."""

    # Skip rate limiting for health checks and static files
    skip_paths = ["/health", "/metrics", "/docs", "/redoc", "/openapi.json"]
    if any(request.url.path.startswith(path) for path in skip_paths):
        return await call_next(request)

    # Get client IP
    client_ip = request.client.host if request.client else "unknown"

    # TODO: Implement proper rate limiting with Redis
    # This is a placeholder for demonstration

    return await call_next(request)


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with proper logging."""

    logger.warning(
        "HTTP exception occurred",
        status_code=exc.status_code,
        detail=exc.detail,
        path=request.url.path,
        method=request.method,
    )

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.detail,
            "error_code": exc.status_code,
            "timestamp": time.time(),
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions with proper logging and error tracking."""

    logger.error(
        "Unhandled exception occurred",
        error=str(exc),
        error_type=type(exc).__name__,
        path=request.url.path,
        method=request.method,
        exc_info=True,
    )

    # In development, return detailed error info
    if settings.debug:
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": "Internal server error",
                "error": str(exc),
                "error_type": type(exc).__name__,
                "timestamp": time.time(),
            },
        )
    else:
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": "Internal server error",
                "timestamp": time.time(),
            },
        )
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3


# Include routers
app.include_router(
<<<<<<< HEAD
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

=======
    auth_router, prefix=f"{settings.api_prefix}/auth", tags=["Authentication"]
)

app.include_router(
    pipelines_router, prefix=f"{settings.api_prefix}/pipelines", tags=["Pipelines"]
)

app.include_router(
    alerts_router, prefix=f"{settings.api_prefix}/alerts", tags=["Alerts"]
)

app.include_router(
    reports_router, prefix=f"{settings.api_prefix}/reports", tags=["Reports"]
)

# Mount Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


# Health check endpoints
@app.get("/health", tags=["Health"])
async def health_check():
    """
    Comprehensive health check endpoint.

    Returns the health status of all application components.
    """
    start_time = time.time()

    health_status = {
        "status": "healthy",
        "timestamp": time.time(),
        "version": settings.app_version,
        "environment": settings.environment,
        "components": {},
    }

    # Database health check
    try:
        db_health = await db_health_check()
        health_status["components"]["database"] = db_health
    except Exception as e:
        health_status["components"]["database"] = {
            "status": "unhealthy",
            "error": str(e),
        }
        health_status["status"] = "unhealthy"

    # Celery health check
    try:
        celery_health = celery_health_check()
        health_status["components"]["task_queue"] = celery_health
    except Exception as e:
        health_status["components"]["task_queue"] = {
            "status": "unhealthy",
            "error": str(e),
        }
        # Don't fail overall health if Celery is down in development
        if settings.is_production():
            health_status["status"] = "unhealthy"

    # Response time
    health_status["response_time_ms"] = (time.time() - start_time) * 1000

    # Return appropriate status code
    status_code = 200 if health_status["status"] == "healthy" else 503

    return JSONResponse(status_code=status_code, content=health_status)


@app.get("/health/ready", tags=["Health"])
async def readiness_check():
    """
    Kubernetes readiness probe endpoint.

    Returns 200 if the application is ready to serve traffic.
    """
    try:
        # Check database connection
        db_health = await db_health_check()
        if not db_health.get("database_connected"):
            raise HTTPException(status_code=503, detail="Database not ready")

        return {"status": "ready", "timestamp": time.time()}

    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        raise HTTPException(status_code=503, detail="Application not ready")


@app.get("/health/live", tags=["Health"])
async def liveness_check():
    """
    Kubernetes liveness probe endpoint.

    Returns 200 if the application is alive and running.
    """
    return {"status": "alive", "timestamp": time.time()}


@app.get("/version", tags=["Information"])
async def get_version():
    """Get application version and build information."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "debug": settings.debug,
        "timestamp": time.time(),
    }


@app.get("/", tags=["Information"])
async def root():
    """Root endpoint with API information."""
    return {
        "message": "Welcome to SecureOps API",
        "description": "DevSecOps CI/CD Pipeline Security Monitor",
        "version": settings.app_version,
        "docs_url": settings.docs_url,
        "health_url": "/health",
        "timestamp": time.time(),
    }


# Custom OpenAPI schema
def custom_openapi():
    """Generate custom OpenAPI schema with security information."""
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="SecureOps API",
        version=settings.app_version,
        description=app.description,
        routes=app.routes,
    )

    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
        "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
    }

    # Apply security to all endpoints
    for path in openapi_schema["paths"]:
        for method in openapi_schema["paths"][path]:
            if method not in ["options"]:  # Skip OPTIONS method
                if "security" not in openapi_schema["paths"][path][method]:
                    openapi_schema["paths"][path][method]["security"] = [
                        {"BearerAuth": []},
                        {"ApiKeyAuth": []},
                    ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# Security logging endpoints (for audit trails)
@app.post("/api/v1/security/events", tags=["Security"])
async def log_security_event(request: Request):
    """Log security events for audit trails."""
    try:
        event_data = await request.json()

        security_logger.log(
            "security_event_received",
            event_type=event_data.get("type"),
            severity=event_data.get("severity"),
            source=event_data.get("source"),
            details=event_data.get("details", {}),
            timestamp=time.time(),
        )

        return {"success": True, "message": "Security event logged"}

    except Exception as e:
        logger.error(f"Failed to log security event: {e}")
        raise HTTPException(status_code=400, detail="Invalid security event data")


# Webhook endpoints for CI/CD integrations
@app.post("/webhooks/github", tags=["Webhooks"])
async def github_webhook(request: Request):
    """Handle GitHub webhook events."""
    from .services.pipeline_services import handle_github_webhook

    try:
        headers = dict(request.headers)
        payload = await request.json()

        result = await handle_github_webhook(headers, payload)

        audit_logger.user_action(
            user_id=None,
            username="github-webhook",
            action="webhook_received",
            resource_type="pipeline",
            ip_address=request.client.host if request.client else None,
            success=True,
            details={"event_type": headers.get("x-github-event")},
        )

        return result

    except Exception as e:
        logger.error(f"GitHub webhook processing failed: {e}")
        raise HTTPException(status_code=400, detail="Webhook processing failed")


@app.post("/webhooks/gitlab", tags=["Webhooks"])
async def gitlab_webhook(request: Request):
    """Handle GitLab webhook events."""
    from .services.pipeline_services import handle_gitlab_webhook

    try:
        headers = dict(request.headers)
        payload = await request.json()

        result = await handle_gitlab_webhook(headers, payload)

        audit_logger.user_action(
            user_id=None,
            username="gitlab-webhook",
            action="webhook_received",
            resource_type="pipeline",
            ip_address=request.client.host if request.client else None,
            success=True,
            details={"event_type": headers.get("x-gitlab-event")},
        )

        return result

    except Exception as e:
        logger.error(f"GitLab webhook processing failed: {e}")
        raise HTTPException(status_code=400, detail="Webhook processing failed")


@app.post("/webhooks/jenkins", tags=["Webhooks"])
async def jenkins_webhook(request: Request):
    """Handle Jenkins webhook events."""
    from .services.pipeline_services import handle_jenkins_webhook

    try:
        headers = dict(request.headers)
        payload = await request.json()

        result = await handle_jenkins_webhook(headers, payload)

        audit_logger.user_action(
            user_id=None,
            username="jenkins-webhook",
            action="webhook_received",
            resource_type="pipeline",
            ip_address=request.client.host if request.client else None,
            success=True,
        )

        return result

    except Exception as e:
        logger.error(f"Jenkins webhook processing failed: {e}")
        raise HTTPException(status_code=400, detail="Webhook processing failed")


@app.post("/webhooks/azure", tags=["Webhooks"])
async def azure_webhook(request: Request):
    """Handle Azure DevOps webhook events."""
    from .services.pipeline_services import handle_azure_webhook

    try:
        headers = dict(request.headers)
        payload = await request.json()

        result = await handle_azure_webhook(headers, payload)

        audit_logger.user_action(
            user_id=None,
            username="azure-webhook",
            action="webhook_received",
            resource_type="pipeline",
            ip_address=request.client.host if request.client else None,
            success=True,
            details={"event_type": headers.get("x-vss-activityid")},
        )

        return result

    except Exception as e:
        logger.error(f"Azure DevOps webhook processing failed: {e}")
        raise HTTPException(status_code=400, detail="Webhook processing failed")


# Development server
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
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
<<<<<<< HEAD
    )
=======
    )
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
