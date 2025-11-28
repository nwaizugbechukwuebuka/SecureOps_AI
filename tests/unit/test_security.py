import sys
from pathlib import Path

# Ensure src is importable when running tests from repository root
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from security.crypto import generate_hmac_token, verify_hmac_token


def test_hmac_generate_and_verify():
    secret = "test-secret"
    payload = "secureops-client"
    token = generate_hmac_token(secret, payload)
    assert isinstance(token, str)
    assert verify_hmac_token(token, secret, payload) is True


def test_hmac_token_generation_and_verify():
    secret = "test-secret"
    payload = "client-id"
    token = generate_hmac_token(secret, payload)
    assert isinstance(token, str) and len(token) > 0
    # verify_hmac_token expects (token, secret, payload)
    assert verify_hmac_token(token, secret, payload)
