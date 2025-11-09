"""
SecureOps AI Backend - Main Application
Clean FastAPI application with modular router architecture
"""

from datetime import datetime
import os
import logging
from contextlib import asynccontextmanager
from typing import Dict, Any, List

# FastAPI imports
from fastapi import FastAPI, HTTPException, status, WebSocket, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware

# Database imports
from database import engine, Base, init_database
from config import settings

# Router imports - Enhanced Security Versions
from routers.auth_enhanced import router as auth_router
from routers.users_enhanced import router as users_router
from routers.dashboard_enhanced import router as dashboard_router

# Enhanced security imports
from utils.audit_logger import SecurityLogger
from models_enhanced import Base as EnhancedBase

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()), format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("SecureOps-AI")

# Initialize security logger
security_logger = SecurityLogger()

# Application lifecycle


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events"""

    # Startup
    logger.info("🚀 Starting SecureOps AI Backend with Enhanced Security...")

    # Create database tables
    try:
        # Create both original and enhanced tables
        Base.metadata.create_all(bind=engine)
        EnhancedBase.metadata.create_all(bind=engine)
        logger.info("✅ Database tables created successfully")

        # Initialize database and create default users if they don't exist
        init_database()
        logger.info("✅ Database and default users initialized")

        # Log application startup
        await security_logger.log_system_event(
            "application_startup", "SecureOps AI backend started with enhanced security features", risk_level="low"
        )

    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        raise

    logger.info(f"🔐 SecureOps AI Backend started on {settings.host}:{settings.port}")
    logger.info("🛡️ Security features: JWT+MFA, RBAC, Audit Logging, Rate Limiting")

    yield  # Application runs here

    # Shutdown
    logger.info("🛑 Shutting down SecureOps AI Backend...")
    await security_logger.log_system_event(
        "application_shutdown", "SecureOps AI backend shutdown gracefully", risk_level="low"
    )


# Create FastAPI application
app = FastAPI(
    title="SecureOps AI - Enterprise Security Platform",
    description="Advanced security operations platform with comprehensive audit logging and RBAC",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
    # Enhanced security parameters
    swagger_ui_parameters={
        "persistAuthorization": True,
        "displayRequestDuration": True,
    },
)

# Enhanced Security Middleware

# Security headers middleware


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)

    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    # Content Security Policy
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "media-src 'self'; "
        "frame-src 'none';"
    )
    response.headers["Content-Security-Policy"] = csp

    return response


# Request logging middleware


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    """Log all requests for security monitoring"""
    start_time = datetime.now()

    # Get client IP (consider proxy headers)
    client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")

    response = await call_next(request)

    process_time = (datetime.now() - start_time).total_seconds()

    # Log security-sensitive requests
    sensitive_paths = ["/auth/", "/users/", "/admin/"]
    if any(path in str(request.url) for path in sensitive_paths):
        await security_logger.log_api_access(
            request.method,
            str(request.url.path),
            response.status_code,
            client_ip,
            user_id=getattr(request.state, "user_id", None),
            risk_level="medium" if response.status_code >= 400 else "low",
        )

    return response


# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=[
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "*.localhost",
    ],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

# Global exception handler


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code, content={"success": False, "message": exc.detail, "status_code": exc.status_code}
    )


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Enhanced global exception handler with security logging"""

    # Log security incidents
    await security_logger.log_security_incident(
        "application_error",
        f"Unhandled exception: {str(exc)}",
        request_details={
            "method": request.method,
            "url": str(request.url),
            "client_ip": request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown"),
        },
        risk_level="high",
    )

    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "message": "Internal server error",
            "status_code": 500,
            "error_id": datetime.now().isoformat(),
        },
    )


# Health and Status Endpoints


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring and connection testing"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "SecureOps AI Backend",
        "version": "2.0.0",
        "environment": os.getenv("ENVIRONMENT", "development"),
    }


@app.get("/security-status")
async def security_status():
    """Security status endpoint"""
    return {
        "security_features": {
            "authentication": "JWT with MFA",
            "authorization": "Role-Based Access Control (RBAC)",
            "audit_logging": "Comprehensive",
            "rate_limiting": "Enabled",
            "encryption": "TLS/HTTPS",
            "session_management": "Secure cookies",
            "password_policy": "Enterprise-grade",
        },
        "compliance": {
            "security_headers": "Enabled",
            "csp": "Enabled",
            "cors": "Configured",
            "trusted_hosts": "Enabled",
        },
        "monitoring": {"request_logging": "Enabled", "security_events": "Enabled", "audit_trail": "Enabled"},
    }


# Include enhanced routers
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(users_router, prefix="/users", tags=["User Management"])
app.include_router(dashboard_router, prefix="/dashboard", tags=["Security Dashboard"])

# Root endpoint


@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "SecureOps AI - Enterprise Security Platform API",
        "version": "2.0.0",
        "documentation": "/api/docs",
        "security_status": "/security-status",
        "health": "/health",
        "endpoints": {"authentication": "/auth", "user_management": "/users", "security_dashboard": "/dashboard"},
        "features": [
            "JWT Authentication with MFA",
            "Role-Based Access Control (RBAC)",
            "Comprehensive Audit Logging",
            "Rate Limiting & Brute Force Protection",
            "Enterprise Security Headers",
            "Real-time Security Monitoring",
        ],
    }


# WebSocket manager for real-time updates


class ConnectionManager:
    """Manage WebSocket connections for real-time updates"""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, data: Dict[str, Any]):
        """Broadcast data to all connected clients"""
        if not self.active_connections:
            return

        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(data)
            except Exception as e:
                logger.error(f"Failed to send data to WebSocket: {e}")
                disconnected.append(connection)

        # Remove disconnected clients
        for connection in disconnected:
            self.disconnect(connection)


# WebSocket manager instance
manager = ConnectionManager()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(websocket)

    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        manager.disconnect(websocket)


# Development server
if __name__ == "__main__":
    import uvicorn

    # Configure uvicorn logging
    log_config = uvicorn.config.LOGGING_CONFIG
    log_config["formatters"]["default"]["fmt"] = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    log_config["formatters"]["access"]["fmt"] = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Run the application
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_config=log_config,
        access_log=True,
    )
