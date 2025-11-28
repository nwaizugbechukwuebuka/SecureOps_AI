from fastapi import FastAPI
from app.core.config import settings
from app.core.logging_config import setup_logging
from app.api import health, auth, scans, ai_analysis
from app.middleware.auth_middleware import AuthMiddleware

setup_logging()

app = FastAPI(title="SecureOps Web App", version="1.0.0")

app.add_middleware(AuthMiddleware)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(ai_analysis.router)
