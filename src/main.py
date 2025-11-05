"""
Main entry point for SecureOps FastAPI application.
Handles middleware, routes, and async startup/shutdown events.
"""
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.base import RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from src.api.utils.config import get_settings
from src.api.utils.logger import get_logger

settings = get_settings()
logger = get_logger(__name__)

# Import route modules (to be implemented in Phase 3)
# from .api.routes_health import router as health_router
# from .api.routes_security import router as security_router
# from .api.routes_automation import router as automation_router
# from .api.routes_workflow import router as workflow_router

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    debug=settings.debug,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS

# CORS Best Practices: restrict origins in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins if hasattr(settings, 'cors_origins') else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With"],
    expose_headers=["Content-Disposition"],
    max_age=86400,
)

# Secure HTTP Headers Middleware
class SecureHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

app.add_middleware(SecureHeadersMiddleware)

# Session Middleware (if needed)
app.add_middleware(SessionMiddleware, secret_key="super-secret-key")

# Example: Add custom middleware for logging, security, etc.
# class CustomMiddleware(BaseHTTPMiddleware):
#     async def dispatch(self, request, call_next):
#         # Custom logic here
#         response = await call_next(request)
#         return response
# app.add_middleware(CustomMiddleware)

# Include routers (uncomment as implemented)
# app.include_router(health_router, prefix="/health", tags=["Health"])
# app.include_router(security_router, prefix="/security", tags=["Security"])
# app.include_router(automation_router, prefix="/automation", tags=["Automation"])
# app.include_router(workflow_router, prefix="/workflow", tags=["Workflow"])

@app.on_event("startup")
async def on_startup():
    logger.info("SecureOps FastAPI app starting up...")
    # Async DB, Redis, Sentry, etc. initialization here
    # await init_db()
    # await init_redis()
    # await init_sentry()
    pass

@app.on_event("shutdown")
async def on_shutdown():
    logger.info("SecureOps FastAPI app shutting down...")
    # Async cleanup here
    # await close_db()
    # await close_redis()
    pass

@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "app": settings.app_name, "version": settings.app_version}
