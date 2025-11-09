"""
Security utilities for encryption, decryption, and hashing in SecureOps.
"""

import base64
import hashlib
from typing import Any

from cryptography.fernet import Fernet


class SecurityUtils:
    """
    Provides encryption, decryption, and hashing utilities.
    """

    def __init__(self, key: bytes = None):
        self.key = key or Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def encrypt(self, data: bytes) -> bytes:
        return self.cipher.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        return self.cipher.decrypt(token)

    @staticmethod
    def hash_sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def encode_base64(data: bytes) -> str:
        return base64.b64encode(data).decode()

    @staticmethod
    def decode_base64(data: str) -> bytes:
        return base64.b64decode(data)
