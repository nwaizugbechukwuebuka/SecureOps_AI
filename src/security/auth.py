from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import HTTPException, Security
from fastapi.security.api_key import APIKeyHeader

from security.crypto import verify_hmac_token

"""Token-based authentication dependency for FastAPI."""


LOG = logging.getLogger("secureops.security.auth")

API_KEY_HEADER = "X-API-Token"
api_key_header = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)


def get_secret_key() -> str:
    return os.environ.get("SECUREOPS_SECRET", "dev-secret")


async def require_token(api_key: Optional[str] = Security(api_key_header)) -> str:
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API token")
    payload = "secureops-client"
    if not verify_hmac_token(api_key, get_secret_key(), payload):
        LOG.warning("Invalid token provided")
        raise HTTPException(status_code=403, detail="Invalid token")
    return api_key


__all__ = ["require_token", "api_key_header"]
