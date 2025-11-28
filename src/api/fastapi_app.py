"""FastAPI application factory and basic wiring.

Features added:
- Optional Sentry initialization via SENTRY_DSN env var
- Prometheus metrics middleware and /metrics endpoint when available
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from ai_engine.llm_security_agent import LLMSecurityAgent
from ai_engine.model_loader import load_or_train_model
from api.routes.ai_routes import router as ai_router
from api.routes.healthcheck import router as health_router
from api.routes.scan_routes import router as scan_router
from security.secrets_manager import SecretsManager

LOG = logging.getLogger("secureops.api")


def _init_sentry(dsn: str | None) -> None:
    if not dsn:
        return
    try:
        import sentry_sdk
        from sentry_sdk.integrations.starlette import StarletteIntegration

        sentry_sdk.init(
            dsn,
            integrations=[StarletteIntegration()],
            traces_sample_rate=0.0,
        )
        LOG.info("Sentry initialized")
    except Exception:
        LOG.exception("Failed to initialize Sentry (sentry_sdk not available)")


def _prometheus_middleware_factory(app: FastAPI) -> Callable[..., Any]:
    try:
        from prometheus_client import (
            CONTENT_TYPE_LATEST,
            Counter,
            Histogram,
            generate_latest,
        )
    except Exception:  # pragma: no cover - optional dependency
        LOG.debug("prometheus_client not installed; metrics disabled")
        return lambda request, call_next: call_next(request)

    request_count = Counter(
        "secureops_http_requests_total",
        "Total HTTP requests",
        ["method", "path", "status"],
    )
    request_latency = Histogram(
        "secureops_http_request_seconds",
        "HTTP request latency seconds",
        ["method", "path"],
    )

    async def _middleware(request: Request, call_next) -> None:
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

    # attach generate_latest for the /metrics endpoint
    def metrics_endpoint() -> Response:
        data = generate_latest()
        return Response(content=data, media_type=CONTENT_TYPE_LATEST)

    # expose the endpoint on the app
    app.add_api_route("/metrics", metrics_endpoint, methods=["GET"])
    LOG.info("Prometheus metrics endpoint mounted at /metrics")
    return _middleware


def create_app() -> FastAPI:
    app = FastAPI(title="SecureOps_AI", version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/", tags=["info"])
    async def root():
        return {"message": "Welcome to SecureOps_AI API. See /docs for API documentation."}

    @app.on_event("startup")
    async def startup() -> None:
        LOG.info("App startup: loading model and secrets")
        app.state.model = load_or_train_model()
        app.state.secrets = SecretsManager.load()
        app.state.llm = LLMSecurityAgent()

        # Initialize Sentry if configured
        _init_sentry(os.environ.get("SENTRY_DSN"))

        # Mount Prometheus middleware if enabled
        prometheus_env = os.environ.get("PROMETHEUS_ENABLED", "true")
        prometheus_enabled = prometheus_env.lower() in ("1", "true", "yes")
        if prometheus_enabled:
            mw = _prometheus_middleware_factory(app)
            # add as dependency middleware for request processing
            app.middleware("http")(mw)

    @app.on_event("shutdown")
    async def shutdown() -> None:
        LOG.info("App shutdown")

    app.include_router(health_router, prefix="/health")
    app.include_router(scan_router, prefix="/scan")
    app.include_router(ai_router, prefix="/ai")

    return app


__all__ = ["create_app"]
