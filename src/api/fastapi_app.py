from __future__ import annotations

import logging
import os
import time
from typing import Callable, Any

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from ai_engine.model_loader import load_or_train_model
from ai_engine.llm_security_agent import LLMSecurityAgent
from security.secrets_manager import SecretsManager

from api.routes.healthcheck import router as health_router
from api.routes.scan_routes import router as scan_router
from api.routes.ai_routes import router as ai_router

LOG = logging.getLogger("secureops.api")


# ----------------------------
# Sentry Integration
# ----------------------------
def _init_sentry(dsn: str | None) -> None:
    if not dsn:
        return
    try:
        import sentry_sdk
        from sentry_sdk.integrations.starlette import StarletteIntegration

        sentry_sdk.init(
            dsn=dsn,
            integrations=[StarletteIntegration()],
            traces_sample_rate=0.0,
        )
        LOG.info("Sentry initialized")
    except Exception:
        LOG.exception("Failed to initialize Sentry")
        

# ----------------------------
# Prometheus Metrics Middleware
# FIX: isolated registry to prevent duplicate timeseries errors
# ----------------------------
def _prometheus_middleware_factory(app: FastAPI) -> Callable[..., Any]:
    try:
        from prometheus_client import (
            Counter,
            Histogram,
            CONTENT_TYPE_LATEST,
            generate_latest,
            CollectorRegistry,
        )
    except ImportError:
        LOG.debug("prometheus_client not installed; metrics disabled")
        return lambda request, call_next: call_next(request)

    # FIX: Create a *local* registry so pytest reloads do NOT duplicate metrics
    registry = CollectorRegistry()

    request_count = Counter(
        "secureops_http_requests_total",
        "Total HTTP requests",
        ["method", "path", "status"],
        registry=registry,
    )

    request_latency = Histogram(
        "secureops_http_request_seconds",
        "HTTP request latency seconds",
        ["method", "path"],
        registry=registry,
    )

    async def _middleware(request: Request, call_next) -> Response:
        start = time.time()
        resp = await call_next(request)
        elapsed = time.time() - start

        try:
            request_count.labels(
                method=request.method,
                path=request.url.path,
                status=str(resp.status_code),
            ).inc()

            request_latency.labels(
                method=request.method,
                path=request.url.path,
            ).observe(elapsed)

        except Exception:
            LOG.debug(
                "Failed to update Prometheus metrics for %s %s",
                request.method,
                request.url.path,
            )

        return resp

    # /metrics endpoint served from *this local registry*
    def metrics_endpoint() -> Response:
        data = generate_latest(registry)
        return Response(content=data, media_type=CONTENT_TYPE_LATEST)

    app.add_api_route("/metrics", metrics_endpoint, methods=["GET"])
    LOG.info("Prometheus metrics endpoint mounted at /metrics")

    return _middleware


# ----------------------------
# Application Factory
# ----------------------------
def create_app() -> FastAPI:
    app = FastAPI(title="SecureOps_AI", version="0.1.0")

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Prometheus Middleware
    prometheus_enabled = os.environ.get("PROMETHEUS_ENABLED", "true").lower() in {
        "1", "true", "yes"
    }

    if prometheus_enabled:
        mw = _prometheus_middleware_factory(app)
        app.middleware("http")(mw)

    # Startup logic
    @app.on_event("startup")
    async def startup() -> None:
        LOG.info("App startup: loading model, secrets, agent")
        app.state.model = load_or_train_model()
        app.state.secrets = SecretsManager.load()
        app.state.llm = LLMSecurityAgent()
        _init_sentry(os.environ.get("SENTRY_DSN"))

    # Shutdown logic
    @app.on_event("shutdown")
    async def shutdown() -> None:
        LOG.info("App shutdown")

    # Routers
    app.include_router(health_router, prefix="/health")
    app.include_router(scan_router, prefix="/scan")
    app.include_router(ai_router, prefix="/ai")

    return app
