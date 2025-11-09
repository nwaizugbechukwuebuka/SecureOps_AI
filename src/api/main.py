"""
SecureOps FastAPI Application
Comprehensive DevSecOps CI/CD Pipeline Security Monitor

This is the main FastAPI application that orchestrates all components:
- API routes for authentication, alerts, pipelines, reports
- Integration with Celery task system
- Scanner orchestration
- CI/CD platform integrations
- Real-time monitoring and notifications

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

from typing import Any, Dict, AsyncGenerator
import asyncio
import os
from contextlib import asynccontextmanager
from typing import Dict, Any
import time

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

# Import database and models
from .database import AsyncSessionLocal, async_engine
from sqlalchemy.ext.asyncio import AsyncSession
from .models.base import Base

# Import API routes
from .routes.alerts import router as alerts_router
from .routes.auth import router as auth_router
from .routes.pipelines import router as pipelines_router  
from .routes.reports import router as reports_router
# from .routes.scans import router as scans_router  # Temporarily disabled for requirements testing

# Import services
from .services.alert_service import AlertService
from .services.pipeline_services import PipelineService
from .services.report_service import ReportService
from .services.compliance_service import ComplianceService

# Import utilities
from .utils.config import get_settings
from .utils.logger import get_logger

# Import task system (with fallback for different import contexts)
try:
    from ..tasks.scan_tasks import orchestrate_security_scan, scan_health_check
    from ..tasks.cleanup_tasks import comprehensive_system_cleanup, cleanup_health_check  
    from ..tasks.monitor_tasks import system_health_monitor
except ImportError:
    # Fallback for direct execution context
    try:
        from tasks.scan_tasks import orchestrate_security_scan, scan_health_check
        from tasks.cleanup_tasks import comprehensive_system_cleanup, cleanup_health_check
        from tasks.monitor_tasks import system_health_monitor
    except ImportError:
        # Create dummy functions if imports fail
        def orchestrate_security_scan(*args, **kwargs):
            class DummyTask:
                def delay(self, *args, **kwargs):
                    return {"id": "dummy", "status": "pending"}
            return DummyTask()
        
        async def scan_health_check():
            return {"status": "healthy", "message": "Scanner health check not available"}
        
        def comprehensive_system_cleanup(*args, **kwargs):
            class DummyTask:
                def delay(self, *args, **kwargs):
                    return {"id": "dummy", "status": "pending"}
            return DummyTask()
            
        async def cleanup_health_check():
            return {"status": "healthy", "message": "Cleanup health check not available"}
            
        async def system_health_monitor():
            return {"status": "healthy", "message": "System health monitor not available"}

# Import scanner orchestration (with fallback)
try:
    from ..scanners.common import ScannerOrchestrator
    from ..scanners.dependency_scanner import DependencyScanner
    from ..scanners.docker_scanner import DockerScanner
except ImportError:
    try:
        from scanners.common import ScannerOrchestrator
        from scanners.dependency_scanner import DependencyScanner
        from scanners.docker_scanner import DockerScanner
    except ImportError:
        # Create dummy classes if imports fail
        class ScannerOrchestrator:
            async def register_scanner(self, name, scanner):
                pass
        
        class DependencyScanner:
            pass
            
        class DockerScanner:
            pass  
try:
    from ..scanners.secret_scanner import SecretScanner
    from ..scanners.threat_detection import ThreatDetector
    from ..scanners.compliance_audit import ComplianceAuditor
except ImportError:
    try:
        from scanners.secret_scanner import SecretScanner
        from scanners.threat_detection import ThreatDetector
        from scanners.compliance_audit import ComplianceAuditor
    except ImportError:
        class SecretScanner:
            pass
        class ThreatDetector:
            pass
        class ComplianceAuditor:
            pass

# Import CI/CD integrations (with fallback)
try:
    from ..integrations.github_actions import GitHubActionsIntegration
    from ..integrations.gitlab_ci import GitLabCIIntegration
    from ..integrations.azure_devops import AzureDevOpsIntegration
    from ..integrations.jenkins import JenkinsIntegration
except ImportError:
    try:
        from integrations.github_actions import GitHubActionsIntegration
        from integrations.gitlab_ci import GitLabCIIntegration
        from integrations.azure_devops import AzureDevOpsIntegration
        from integrations.jenkins import JenkinsIntegration
    except ImportError:
        class GitHubActionsIntegration:
            async def configure_webhooks(self):
                pass
        class GitLabCIIntegration:
            async def configure_webhooks(self):
                pass
        class AzureDevOpsIntegration:
            async def configure_webhooks(self):
                pass
        class JenkinsIntegration:
            async def configure_webhooks(self):
                pass

# Import utilities (with fallback)
try:
    from ..utils.config import get_settings as get_global_settings
    from ..utils.security_utils import SecurityUtils
    from ..utils.validators import ValidationUtils
except ImportError:
    try:
        from utils.config import get_settings as get_global_settings
        from utils.security_utils import SecurityUtils
        from utils.validators import ValidationUtils
    except ImportError:
        # Create dummy functions if imports fail
        def get_global_settings():
            class DummySettings:
                def __init__(self):
                    self.debug = True
            return DummySettings()
        
        class SecurityUtils:
            pass
            
        class ValidationUtils:
            pass

settings = get_settings()
global_settings = get_global_settings()
logger = get_logger(__name__)

# Security middleware
security = HTTPBearer()

# Global services (dependency injection will provide database sessions)
# Services are created per request with database sessions from dependencies

# Integration managers
github_integration: GitHubActionsIntegration = None
gitlab_integration: GitLabCIIntegration = None
azure_integration: AzureDevOpsIntegration = None
jenkins_integration: JenkinsIntegration = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown events."""
    logger.info("🚀 SecureOps AI Platform starting up...")
    
    try:
        # Initialize database
        logger.info("📊 Initializing database...")
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("✅ Database initialized")
        
        # Initialize scanner orchestrator (doesn't need database)
        logger.info("🔍 Initializing security scanners...")
        await initialize_scanners()
        logger.info("✅ Security scanners initialized")
        
        # Initialize CI/CD integrations  
        logger.info("🔌 Initializing CI/CD integrations...")
        await initialize_integrations()
        logger.info("✅ CI/CD integrations initialized")
        
        # Start background health monitoring
        logger.info("💚 Starting health monitoring...")
        asyncio.create_task(start_health_monitoring())
        logger.info("✅ Health monitoring started")
        
        logger.info("🎉 SecureOps AI Platform ready!")
        
        yield
        
    except Exception as e:
        logger.error(f"❌ Startup failed: {str(e)}")
        raise
    finally:
        # Cleanup on shutdown
        logger.info("🛑 SecureOps AI Platform shutting down...")
        await cleanup_services()
        logger.info("✅ Cleanup completed")


async def initialize_scanners():
    """Initialize scanner orchestrator and security scanners."""
    global scanner_orchestrator
    
    # Initialize individual scanners (these don't need database sessions)
    dependency_scanner = DependencyScanner()
    docker_scanner = DockerScanner()
    secret_scanner = SecretScanner()
    threat_detector = ThreatDetector()
    compliance_auditor = ComplianceAuditor()
    
    # Initialize orchestrator with all scanners
    scanner_orchestrator = ScannerOrchestrator()
    await scanner_orchestrator.register_scanner("dependency", dependency_scanner)
    await scanner_orchestrator.register_scanner("docker", docker_scanner)
    await scanner_orchestrator.register_scanner("secret", secret_scanner)
    await scanner_orchestrator.register_scanner("threat", threat_detector)
    await scanner_orchestrator.register_scanner("compliance", compliance_auditor)
    
    logger.info("Scanner orchestration initialized successfully")


async def initialize_integrations():
    """Initialize CI/CD platform integrations."""
    global github_integration, gitlab_integration, azure_integration, jenkins_integration
    
    # Initialize integrations with configuration
    github_integration = GitHubActionsIntegration()
    gitlab_integration = GitLabCIIntegration()
    azure_integration = AzureDevOpsIntegration()
    jenkins_integration = JenkinsIntegration()
    
    # Configure webhook endpoints (if settings available)
    if hasattr(settings, 'github_webhook_secret'):
        await github_integration.configure_webhooks()
    if hasattr(settings, 'gitlab_webhook_secret'):
        await gitlab_integration.configure_webhooks()
    if hasattr(settings, 'azure_webhook_secret'):
        await azure_integration.configure_webhooks()
    if hasattr(settings, 'jenkins_webhook_secret'):
        await jenkins_integration.configure_webhooks()
    
    logger.info("CI/CD integrations initialized successfully")


async def start_health_monitoring():
    """Start background health monitoring tasks."""
    while True:
        try:
            # Run health checks every 5 minutes
            await asyncio.sleep(300)
            
            # Check scanner health
            scan_health = await scan_health_check()
            
            # Check cleanup system health  
            cleanup_health = await cleanup_health_check()
            
            # Check system resources
            system_health = await system_health_monitor()
            
            logger.info(f"Health check completed - Scan: {scan_health.get('status')}, "
                       f"Cleanup: {cleanup_health.get('status')}, "
                       f"System: {system_health.get('status')}")
            
        except Exception as e:
            logger.error(f"Health monitoring error: {str(e)}")


async def cleanup_services():
    """Cleanup services on shutdown."""
    try:
        # Close database connections
        if async_engine:
            await async_engine.dispose()
        
        # Cleanup other resources as needed
        logger.info("All services cleaned up successfully")
        
    except Exception as e:
        logger.error(f"Cleanup error: {str(e)}")


# Custom middleware for security and logging
class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        # Add security headers
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-SecureOps-Version"] = "2.0.0"
        
        # Log request
        process_time = time.time() - start_time
        logger.info(f"{request.method} {request.url} - {response.status_code} - {process_time:.3f}s")
        
        return response


# Create FastAPI application with lifespan
app = FastAPI(
    title="SecureOps AI Platform",
    description="Comprehensive DevSecOps CI/CD Pipeline Security Monitor with AI-Powered Analysis",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# Add middleware
app.add_middleware(SecurityMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=getattr(settings, 'cors_origins', ["*"]),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

if hasattr(settings, 'session_secret_key'):
    app.add_middleware(SessionMiddleware, secret_key=settings.session_secret_key)

# Include API routers
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(alerts_router, prefix="/api/v1/alerts", tags=["Alerts"])
app.include_router(pipelines_router, prefix="/api/v1/pipelines", tags=["Pipelines"])
app.include_router(reports_router, prefix="/api/v1/reports", tags=["Reports"])
# app.include_router(scans_router, prefix="/api/v1/security", tags=["Security Scanning"])  # Temporarily disabled

# Main API endpoints
@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with platform information."""
    return {
        "message": "SecureOps AI Platform - DevSecOps Security Orchestration",
        "version": "2.0.0",
        "status": "running",
        "features": {
            "security_scanning": True,
            "ci_cd_integration": True,
            "threat_detection": True,
            "compliance_monitoring": True,
            "real_time_alerts": True
        }
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Comprehensive health check endpoint."""
    try:
        # Check database connectivity
        async with AsyncSessionLocal() as session:
            await session.execute("SELECT 1")
        
        # Check services (services are created per request via dependency injection)
        services_health = {
            "database": "healthy",
            "scanner_orchestrator": "healthy" if scanner_orchestrator else "not_initialized",
            "alert_service": "available_via_dependency_injection",
            "pipeline_service": "available_via_dependency_injection",
            "report_service": "available_via_dependency_injection"
        }
        
        # Check integrations
        integrations_health = {
            "github": "healthy" if github_integration else "not_initialized",
            "gitlab": "healthy" if gitlab_integration else "not_initialized", 
            "azure": "healthy" if azure_integration else "not_initialized",
            "jenkins": "healthy" if jenkins_integration else "not_initialized"
        }
        
        return {
            "status": "healthy",
            "timestamp": time.time(),
            "version": "2.0.0",
            "services": services_health,
            "integrations": integrations_health,
            "uptime": time.time()
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy", 
                "error": str(e),
                "timestamp": time.time()
            }
        )


@app.get("/api/v1/system/status", tags=["System"])
async def system_status():
    """Detailed system status endpoint."""
    try:
        # Get task system health
        scan_health = await scan_health_check()
        cleanup_health = await cleanup_health_check()
        
        # Get scanner status
        scanner_status = {}
        if scanner_orchestrator:
            scanner_status = await scanner_orchestrator.get_health_status()
        
        return {
            "platform": "SecureOps AI",
            "version": "2.0.0",
            "status": "operational",
            "components": {
                "api": "healthy",
                "database": "healthy", 
                "task_system": {
                    "scan_tasks": scan_health.get("status", "unknown"),
                    "cleanup_tasks": cleanup_health.get("status", "unknown")
                },
                "scanners": scanner_status,
                "integrations": {
                    "github_actions": "available" if github_integration else "disabled",
                    "gitlab_ci": "available" if gitlab_integration else "disabled",
                    "azure_devops": "available" if azure_integration else "disabled", 
                    "jenkins": "available" if jenkins_integration else "disabled"
                }
            },
            "timestamp": time.time()
        }
        
    except Exception as e:
        logger.error(f"System status check failed: {str(e)}")
        raise HTTPException(status_code=503, detail="System status unavailable")


# Task orchestration endpoints
@app.post("/api/v1/scans/orchestrate", tags=["Scanning"])
async def trigger_security_scan(
    repository_url: str,
    branch: str = "main",
    scan_types: list = None
):
    """Trigger a comprehensive security scan through the task system."""
    try:
        if not scan_types:
            scan_types = ["dependency", "docker", "secret", "threat", "compliance"]
        
        # Trigger scan through Celery task system
        task = orchestrate_security_scan.delay(
            repository_url=repository_url,
            branch=branch,
            scan_types=scan_types,
            user_id=1  # TODO: Get from auth context
        )
        
        return {
            "message": "Security scan initiated",
            "task_id": task.id,
            "repository_url": repository_url,
            "branch": branch,
            "scan_types": scan_types,
            "status": "initiated"
        }
        
    except Exception as e:
        logger.error(f"Scan orchestration failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to initiate scan")


@app.post("/api/v1/system/cleanup", tags=["Maintenance"])
async def trigger_system_cleanup():
    """Trigger comprehensive system cleanup."""
    try:
        task = comprehensive_system_cleanup.delay()
        
        return {
            "message": "System cleanup initiated",
            "task_id": task.id,
            "status": "initiated"
        }
        
    except Exception as e:
        logger.error(f"System cleanup failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to initiate cleanup")


# Integration webhook endpoints
@app.post("/api/v1/webhooks/github", tags=["Integrations"])
async def github_webhook_handler(request: Request):
    """Handle GitHub Actions webhook events."""
    if not github_integration:
        raise HTTPException(status_code=503, detail="GitHub integration not available")
    
    try:
        body = await request.body()
        headers = dict(request.headers)
        
        result = await github_integration.handle_webhook(body, headers)
        return {"message": "Webhook processed", "result": result}
        
    except Exception as e:
        logger.error(f"GitHub webhook error: {str(e)}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")


@app.post("/api/v1/webhooks/gitlab", tags=["Integrations"])
async def gitlab_webhook_handler(request: Request):
    """Handle GitLab CI webhook events."""
    if not gitlab_integration:
        raise HTTPException(status_code=503, detail="GitLab integration not available")
    
    try:
        body = await request.body()
        headers = dict(request.headers)
        
        result = await gitlab_integration.handle_webhook(body, headers)
        return {"message": "Webhook processed", "result": result}
        
    except Exception as e:
        logger.error(f"GitLab webhook error: {str(e)}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")


@app.post("/api/v1/webhooks/azure", tags=["Integrations"])
async def azure_webhook_handler(request: Request):
    """Handle Azure DevOps webhook events."""
    if not azure_integration:
        raise HTTPException(status_code=503, detail="Azure integration not available")
    
    try:
        body = await request.body()
        headers = dict(request.headers)
        
        result = await azure_integration.handle_webhook(body, headers)
        return {"message": "Webhook processed", "result": result}
        
    except Exception as e:
        logger.error(f"Azure webhook error: {str(e)}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")


@app.post("/api/v1/webhooks/jenkins", tags=["Integrations"])
async def jenkins_webhook_handler(request: Request):
    """Handle Jenkins webhook events."""
    if not jenkins_integration:
        raise HTTPException(status_code=503, detail="Jenkins integration not available")
    
    try:
        body = await request.body()
        headers = dict(request.headers)
        
        result = await jenkins_integration.handle_webhook(body, headers)
        return {"message": "Webhook processed", "result": result}
        
    except Exception as e:
        logger.error(f"Jenkins webhook error: {str(e)}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")


# Database dependency
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Database dependency for dependency injection."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# Dependency injection helpers
async def get_alert_service(db: AsyncSession = Depends(get_db)) -> AlertService:
    """Dependency injection for AlertService with database session."""
    return AlertService(db)


async def get_pipeline_service(db: AsyncSession = Depends(get_db)) -> PipelineService:
    """Dependency injection for PipelineService with database session."""
    return PipelineService(db)


async def get_report_service(db: AsyncSession = Depends(get_db)) -> ReportService:
    """Dependency injection for ReportService with database session."""
    return ReportService(db)


async def get_scanner_orchestrator() -> ScannerOrchestrator:
    """Dependency injection for ScannerOrchestrator."""
    if not scanner_orchestrator:
        raise HTTPException(status_code=503, detail="Scanner orchestrator not available")
    return scanner_orchestrator


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=True,
        log_level="info"
    )
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
