"""
Pytest suite for SecurityUtils.

This module tests the security utilities including:
- Encryption and decryption functionality
- SHA256 hashing operations
- Base64 encoding and decoding
- Error handling and edge cases
"""

import pytest
from cryptography.fernet import InvalidToken

from utils.security_utils import SecurityUtils


class TestSecurityUtils:
    """Test the SecurityUtils class functionality."""

    def test_encrypt_decrypt_basic(self):
        """Test basic encryption and decryption."""
        utils = SecurityUtils()
        data = b"secret-data"
        token = utils.encrypt(data)
        decrypted = utils.decrypt(token)
        assert decrypted == data

    def test_encrypt_decrypt_different_instances(self):
        """Test encryption with one instance and decryption with another using same key."""
        # Create first instance and encrypt
        utils1 = SecurityUtils()
        key = utils1.key
        data = b"secret-message"
        token = utils1.encrypt(data)
        
        # Create second instance with same key and decrypt
        utils2 = SecurityUtils(key)
        decrypted = utils2.decrypt(token)
        assert decrypted == data

    def test_encrypt_decrypt_empty_data(self):
        """Test encryption and decryption of empty data."""
        utils = SecurityUtils()
        data = b""
        token = utils.encrypt(data)
        decrypted = utils.decrypt(token)
        assert decrypted == data

    def test_encrypt_decrypt_unicode_data(self):
        """Test encryption and decryption of unicode text."""
        utils = SecurityUtils()
        text = "Hello, 世界! 🔒"
        data = text.encode('utf-8')
        token = utils.encrypt(data)
        decrypted = utils.decrypt(token)
        assert decrypted.decode('utf-8') == text

    def test_decrypt_invalid_token(self):
        """Test decryption with invalid token raises appropriate error."""
        utils = SecurityUtils()
        invalid_token = b"invalid-token-data"
        
        with pytest.raises(Exception):  # Should raise InvalidToken or similar
            utils.decrypt(invalid_token)

    def test_encrypt_large_data(self):
        """Test encryption and decryption of larger data."""
        utils = SecurityUtils()
        # Create 1KB of test data
        data = b"A" * 1024
        token = utils.encrypt(data)
        decrypted = utils.decrypt(token)
        assert decrypted == data

    def test_hash_sha256_basic(self):
        """Test basic SHA256 hashing."""
        data = b"test"
        hash1 = SecurityUtils.hash_sha256(data)
        hash2 = SecurityUtils.hash_sha256(data)
        assert hash1 == hash2
        assert len(hash1) == 64
        assert isinstance(hash1, str)

    def test_hash_sha256_different_data(self):
        """Test that different data produces different hashes."""
        data1 = b"test1"
        data2 = b"test2"
        hash1 = SecurityUtils.hash_sha256(data1)
        hash2 = SecurityUtils.hash_sha256(data2)
        assert hash1 != hash2

    def test_hash_sha256_empty_data(self):
        """Test hashing of empty data."""
        data = b""
        hash_result = SecurityUtils.hash_sha256(data)
        assert len(hash_result) == 64
        # Known SHA256 hash of empty string
        assert hash_result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_hash_sha256_known_values(self):
        """Test hashing with known expected values."""
        # Test with known SHA256 values
        test_cases = [
            (b"hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
            (b"test", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
        ]
        
        for data, expected_hash in test_cases:
            actual_hash = SecurityUtils.hash_sha256(data)
            assert actual_hash == expected_hash

    def test_encode_base64_basic(self):
        """Test basic Base64 encoding."""
        data = b"hello world"
        encoded = SecurityUtils.encode_base64(data)
        assert encoded == "aGVsbG8gd29ybGQ="
        assert isinstance(encoded, str)

    def test_decode_base64_basic(self):
        """Test basic Base64 decoding."""
        encoded = "aGVsbG8gd29ybGQ="
        decoded = SecurityUtils.decode_base64(encoded)
        assert decoded == b"hello world"
        assert isinstance(decoded, bytes)

    def test_encode_decode_base64_roundtrip(self):
        """Test Base64 encoding and decoding roundtrip."""
        original_data = b"This is a test message with special chars: !@#$%^&*()"
        encoded = SecurityUtils.encode_base64(original_data)
        decoded = SecurityUtils.decode_base64(encoded)
        assert decoded == original_data

    def test_encode_base64_empty_data(self):
        """Test Base64 encoding of empty data."""
        data = b""
        encoded = SecurityUtils.encode_base64(data)
        assert encoded == ""

    def test_decode_base64_empty_data(self):
        """Test Base64 decoding of empty string."""
        encoded = ""
        decoded = SecurityUtils.decode_base64(encoded)
        assert decoded == b""

    def test_encode_base64_binary_data(self):
        """Test Base64 encoding of binary data."""
        # Create some binary data
        binary_data = bytes(range(256))
        encoded = SecurityUtils.encode_base64(binary_data)
        decoded = SecurityUtils.decode_base64(encoded)
        assert decoded == binary_data

    def test_decode_base64_invalid_data(self):
        """Test Base64 decoding with invalid data."""
        invalid_base64 = "invalid-base64-data!"
        
        with pytest.raises(Exception):  # Should raise binascii.Error or similar
            SecurityUtils.decode_base64(invalid_base64)

    def test_security_utils_with_custom_key(self):
        """Test SecurityUtils with custom encryption key."""
        from cryptography.fernet import Fernet
        
        # Generate a custom key
        custom_key = Fernet.generate_key()
        utils = SecurityUtils(custom_key)
        
        # Test encryption/decryption works with custom key
        data = b"custom-key-test"
        token = utils.encrypt(data)
        decrypted = utils.decrypt(token)
        assert decrypted == data
        assert utils.key == custom_key

    def test_multiple_encryption_instances_isolation(self):
        """Test that multiple SecurityUtils instances are properly isolated."""
        utils1 = SecurityUtils()
        utils2 = SecurityUtils()
        
        # Keys should be different
        assert utils1.key != utils2.key
        
        # Data encrypted by one should not be decryptable by the other
        data = b"isolation-test"
        token1 = utils1.encrypt(data)
        
        with pytest.raises(Exception):
            utils2.decrypt(token1)


# Legacy test functions for backward compatibility
def test_encrypt_decrypt():
    """Legacy test function for backward compatibility."""
    utils = SecurityUtils()
    data = b"secret-data"
    token = utils.encrypt(data)
    decrypted = utils.decrypt(token)
    assert decrypted == data


def test_hash_sha256():
    """Legacy test function for backward compatibility."""
    data = b"test"
    hash1 = SecurityUtils.hash_sha256(data)
    hash2 = SecurityUtils.hash_sha256(data)
    assert hash1 == hash2
    assert len(hash1) == 64
