"""Metrics routes for SecureOps API."""

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse
from ..utils.logger import get_logger

router = APIRouter()
logger = get_logger(__name__)


def generate_metrics():
    """Generate application metrics in Prometheus format"""
    metrics = """
# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",status="200"} 100
# HELP http_request_duration_seconds HTTP request duration
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{le="0.1"} 95
http_request_duration_seconds_bucket{le="0.5"} 99
http_request_duration_seconds_bucket{le="1.0"} 100
http_request_duration_seconds_bucket{le="+Inf"} 100
http_request_duration_seconds_sum 50.0
http_request_duration_seconds_count 100
# HELP app_info Application information
# TYPE app_info gauge
app_info{version="2.0.0",name="SecureOps_AI"} 1
    """
    return metrics.strip()


def generate_prometheus_metrics():
    """Generate Prometheus format metrics"""
    return "# Prometheus metrics here\n" + generate_metrics()


@router.get("/metrics", tags=["Metrics"])
def metrics_endpoint(request: Request):
    """Get application metrics in Prometheus format"""
    accept_header = request.headers.get("Accept", "")
    
    if "text/plain" in accept_header:
        metrics_text = generate_prometheus_metrics()
    else:
        metrics_text = generate_metrics()
    
    return PlainTextResponse(
        content=metrics_text,
        media_type="text/plain; version=0.0.4"
    )


@router.get("/metrics/prometheus", tags=["Metrics"])
def prometheus_metrics():
    """Get metrics in Prometheus format"""
    metrics_text = generate_prometheus_metrics()
    return PlainTextResponse(
        content=metrics_text,
        media_type="text/plain; version=0.0.4"
    )