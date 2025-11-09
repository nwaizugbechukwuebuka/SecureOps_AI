"""
Rate limiting and security middleware for SecureOps API
"""

import time
import json
from typing import Dict, Optional
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import redis.asyncio as aioredis


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using Redis backend."""

    def __init__(self, app, redis_url: str, default_rate_limit: int = 100):
        super().__init__(app)
        self.redis_url = redis_url
        self.default_rate_limit = default_rate_limit
        self.redis_client = None

    async def get_redis_client(self):
        if self.redis_client is None:
            self.redis_client = await aioredis.from_url(
                self.redis_url, decode_responses=True
            )
        return self.redis_client

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"

        # Skip rate limiting for health checks
        if request.url.path in ["/health", "/metrics"]:
            return await call_next(request)

        try:
            redis_client = await self.get_redis_client()

            # Create rate limit key
            rate_limit_key = f"rate_limit:{client_ip}"

            # Get current request count
            current_requests = await redis_client.get(rate_limit_key)

            if current_requests is None:
                # First request in time window
                await redis_client.setex(rate_limit_key, 60, 1)  # 1 minute window
                current_requests = 1
            else:
                current_requests = int(current_requests)

                # Check if rate limit exceeded
                if current_requests >= self.default_rate_limit:
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={
                            "detail": "Rate limit exceeded. Please try again later."
                        },
                    )

                # Increment counter
                await redis_client.incr(rate_limit_key)

            # Add rate limit headers to response
            response = await call_next(request)
            response.headers["X-RateLimit-Limit"] = str(self.default_rate_limit)
            response.headers["X-RateLimit-Remaining"] = str(
                self.default_rate_limit - current_requests
            )
            response.headers["X-RateLimit-Reset"] = str(int(time.time()) + 60)

            return response

        except Exception as e:
            # If Redis is unavailable, allow request but log error
            print(f"Rate limiting error: {e}")
            return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enhanced security headers middleware."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Security headers
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self' cdn.jsdelivr.net; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), "
            "payment=(), usb=(), magnetometer=(), gyroscope=()"
        )

        return response
