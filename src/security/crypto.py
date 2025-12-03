from __future__ import annotations

import base64
import hashlib
import hmac
import os

"""Cryptographic utilities: HMAC token generation and verification."""


def generate_hmac_token(secret: str, payload: str) -> str:
    key = secret.encode("utf8")
    sig = hmac.new(key, payload.encode("utf8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode("utf8")


def verify_hmac_token(token: str, secret: str, payload: str) -> bool:
    expected = generate_hmac_token(secret, payload)
    return hmac.compare_digest(expected, token)


def random_base64(nbytes: int = 24) -> str:
    return base64.urlsafe_b64encode(os.urandom(nbytes)).decode("utf8")


__all__ = ["generate_hmac_token", "verify_hmac_token", "random_base64"]
