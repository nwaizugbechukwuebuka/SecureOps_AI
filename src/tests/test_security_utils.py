"""
Pytest suite for SecurityUtils.
"""
import pytest
from secureops_ai.src.utils.security_utils import SecurityUtils

def test_encrypt_decrypt():
    utils = SecurityUtils()
    data = b"secret-data"
    token = utils.encrypt(data)
    decrypted = utils.decrypt(token)
    assert decrypted == data

def test_hash_sha256():
    data = b"test"
    hash1 = SecurityUtils.hash_sha256(data)
    hash2 = SecurityUtils.hash_sha256(data)
    assert hash1 == hash2
    assert len(hash1) == 64
