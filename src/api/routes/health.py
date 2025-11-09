"""Health check routes for SecureOps API."""

from datetime import datetime
from fastapi import APIRouter
from ..utils.logger import get_logger

router = APIRouter()
logger = get_logger(__name__)


def check_database_connection():
    """Check database connection health"""
    # Mock database health check
    return {"status": "healthy", "response_time": 0.05}


def check_redis_connection():
    """Check Redis connection health"""
    # Mock Redis health check
    return {"status": "healthy", "response_time": 0.02}


def check_external_services():
    """Check external services health"""
    # Mock external services health check
    return {"trivy": "healthy", "github": "healthy"}


def check_system_readiness():
    """Check system readiness"""
    # Mock system readiness check
    return {"ready": True, "checks": {"database": True, "migrations": True, "cache": True}}


@router.get("/health", tags=["Health"])
def health_check():
    """Basic health check endpoint"""
    return {"status": "healthy", "version": "2.0.0", "timestamp": datetime.now().isoformat()}


@router.get("/health/detailed", tags=["Health"])
def health_detailed():
    """Detailed health check with component status"""
    db_health = check_database_connection()
    redis_health = check_redis_connection()
    external_health = check_external_services()

    return {
        "status": "healthy",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat(),
        "services": {"database": db_health, "redis": redis_health, "external": external_health},
    }


@router.get("/ready", tags=["Health"])
def readiness_check():
    """Readiness probe endpoint"""
    readiness = check_system_readiness()
    return readiness


@router.get("/alive", tags=["Health"])
def liveness_check():
    """Liveness probe endpoint"""
    import time

    return {"alive": True, "uptime": int(time.time())}
