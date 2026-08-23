"""Unit tests for the encryption service."""

from __future__ import annotations

from datetime import timedelta

import jwt
import pytest
from pydantic import SecretStr

from ohev.config import AppConfig, EncryptionKeyConfig
from ohev.encryption.encryption_service import EncryptionService

# Use secrets >= 32 bytes to satisfy HMAC key length requirements (RFC 7518)
PRIMARY_SECRET = "primary-secret-key-at-least-32-bytes-long"
OLD_SECRET = "old-secret-key-at-least-32-bytes-long!!"


@pytest.fixture
def config() -> AppConfig:
    """Create a test configuration with encryption keys."""
    return AppConfig(
        encryption_key=EncryptionKeyConfig(id="primary", value=SecretStr(PRIMARY_SECRET)),
        decryption_keys=[
            EncryptionKeyConfig(id="old-key", value=SecretStr(OLD_SECRET)),
        ],
    )


@pytest.fixture
def service(config: AppConfig) -> EncryptionService:
    """Create an encryption service instance."""
    return EncryptionService(config)


class TestEncryptionServiceInit:
    """Tests for EncryptionService initialization."""

    def test_encryption_key_id(self, service: EncryptionService) -> None:
        assert service.encryption_key_id == "primary"

    def test_decryption_key_ids_includes_encryption_key(self, service: EncryptionService) -> None:
        ids = service.decryption_key_ids
        assert "primary" in ids
        assert "old-key" in ids

    def test_get_decryption_key_not_found(self, service: EncryptionService) -> None:
        with pytest.raises(ValueError, match="Key ID 'unknown' not found"):
            service._get_decryption_key("unknown")


class TestJwsTokens:
    """Tests for JWS token creation and verification."""

    def test_create_and_verify_jws_token(self, service: EncryptionService) -> None:
        payload = {"user_id": "123", "role": "admin"}
        token = service.create_jws_token(payload)

        decoded = service.verify_jws_token(token)
        assert decoded["user_id"] == "123"
        assert decoded["role"] == "admin"
        assert "iat" in decoded
        assert "exp" in decoded

    def test_jws_token_contains_kid_header(self, service: EncryptionService) -> None:
        token = service.create_jws_token({"test": "data"})
        header = jwt.get_unverified_header(token)
        assert header["kid"] == "primary"

    def test_jws_token_custom_expiration(self, service: EncryptionService) -> None:
        token = service.create_jws_token({"test": "data"}, expires_in=timedelta(days=7))
        decoded = service.verify_jws_token(token)
        # Check expiration is roughly 7 days from now
        assert decoded["exp"] - decoded["iat"] == 7 * 24 * 60 * 60

    def test_verify_jws_with_old_key(self, config: AppConfig) -> None:
        # Create a token with the old key
        old_service = EncryptionService(
            AppConfig(
                encryption_key=EncryptionKeyConfig(id="old-key", value=SecretStr(OLD_SECRET)),
            )
        )
        token = old_service.create_jws_token({"data": "test"})

        # Verify with service that has old key in decryption keys
        service = EncryptionService(config)
        decoded = service.verify_jws_token(token)
        assert decoded["data"] == "test"

    def test_verify_jws_invalid_format(self, service: EncryptionService) -> None:
        with pytest.raises(ValueError, match="Invalid JWT token format"):
            service.verify_jws_token("not-a-valid-token")

    def test_verify_jws_without_kid_uses_encryption_key(self, service: EncryptionService) -> None:
        # Create a token without kid header by directly encoding
        payload = {"data": "test", "iat": 1234567890, "exp": 9999999999}
        secret = PRIMARY_SECRET
        token = jwt.encode(payload, secret, algorithm="HS256")

        # Should use the encryption key (primary) for verification
        decoded = service.verify_jws_token(token)
        assert decoded["data"] == "test"

    def test_verify_jws_unknown_key(self, service: EncryptionService) -> None:
        # Create a token with an unknown key
        other_service = EncryptionService(
            AppConfig(
                encryption_key=EncryptionKeyConfig(
                    id="unknown-key",
                    value=SecretStr("unknown-secret-at-least-32-bytes-long"),
                ),
            )
        )
        token = other_service.create_jws_token({"data": "test"})

        with pytest.raises(ValueError, match="Key ID 'unknown-key' not found"):
            service.verify_jws_token(token)

    def test_verify_jws_wrong_secret(self, service: EncryptionService) -> None:
        # Create a token with same key ID but different secret
        other_service = EncryptionService(
            AppConfig(
                encryption_key=EncryptionKeyConfig(
                    id="primary",
                    value=SecretStr("wrong-secret-at-least-32-bytes-long!!"),
                ),
            )
        )
        token = other_service.create_jws_token({"data": "test"})

        with pytest.raises(jwt.InvalidTokenError):
            service.verify_jws_token(token)


class TestJweTokens:
    """Tests for JWE token creation and decryption."""

    def test_create_and_decrypt_jwe_token(self, service: EncryptionService) -> None:
        payload = {"sensitive": "data", "count": 42}
        token = service.create_jwe_token(payload)

        decoded = service.decrypt_jwe_token(token)
        assert decoded["sensitive"] == "data"
        assert decoded["count"] == 42
        assert "iat" in decoded

    def test_jwe_token_with_expiration(self, service: EncryptionService) -> None:
        token = service.create_jwe_token({"test": "data"}, expires_in=timedelta(hours=2))
        decoded = service.decrypt_jwe_token(token)
        assert "exp" in decoded

    def test_jwe_token_without_expiration(self, service: EncryptionService) -> None:
        token = service.create_jwe_token({"test": "data"})
        decoded = service.decrypt_jwe_token(token)
        assert "exp" not in decoded

    def test_decrypt_jwe_with_old_key(self, config: AppConfig) -> None:
        # Create a token with the old key
        old_service = EncryptionService(
            AppConfig(
                encryption_key=EncryptionKeyConfig(id="old-key", value=SecretStr(OLD_SECRET)),
            )
        )
        token = old_service.create_jwe_token({"secret": "value"})

        # Decrypt with service that has old key in decryption keys
        service = EncryptionService(config)
        decoded = service.decrypt_jwe_token(token)
        assert decoded["secret"] == "value"

    def test_decrypt_jwe_invalid_format(self, service: EncryptionService) -> None:
        with pytest.raises(ValueError, match="Invalid JWE token format"):
            service.decrypt_jwe_token("not-a-valid-jwe")

    def test_decrypt_jwe_unknown_key(self, service: EncryptionService) -> None:
        # Create a token with an unknown key
        other_service = EncryptionService(
            AppConfig(
                encryption_key=EncryptionKeyConfig(
                    id="unknown-key",
                    value=SecretStr("unknown-secret-at-least-32-bytes-long"),
                ),
            )
        )
        token = other_service.create_jwe_token({"data": "test"})

        with pytest.raises(ValueError, match="Key ID 'unknown-key' not found"):
            service.decrypt_jwe_token(token)


class TestEncryptDecryptValue:
    """Tests for simple value encryption/decryption."""

    def test_encrypt_and_decrypt_value(self, service: EncryptionService) -> None:
        plaintext = "my secret password"
        ciphertext = service.encrypt_value(plaintext)

        assert ciphertext != plaintext
        decrypted = service.decrypt_value(ciphertext)
        assert decrypted == plaintext

    def test_encrypt_decrypt_unicode(self, service: EncryptionService) -> None:
        plaintext = "こんにちは世界 🌍 مرحبا"
        ciphertext = service.encrypt_value(plaintext)
        decrypted = service.decrypt_value(ciphertext)
        assert decrypted == plaintext

    def test_encrypt_decrypt_empty_string(self, service: EncryptionService) -> None:
        plaintext = ""
        ciphertext = service.encrypt_value(plaintext)
        decrypted = service.decrypt_value(ciphertext)
        assert decrypted == plaintext

    def test_encrypt_decrypt_long_string(self, service: EncryptionService) -> None:
        plaintext = "x" * 100000
        ciphertext = service.encrypt_value(plaintext)
        decrypted = service.decrypt_value(ciphertext)
        assert decrypted == plaintext

    def test_decrypt_with_rotated_key(self, config: AppConfig) -> None:
        # Encrypt with old key
        old_service = EncryptionService(
            AppConfig(
                encryption_key=EncryptionKeyConfig(id="old-key", value=SecretStr(OLD_SECRET)),
            )
        )
        ciphertext = old_service.encrypt_value("secret data")

        # Decrypt with new service (old key in decryption_keys)
        new_service = EncryptionService(config)
        decrypted = new_service.decrypt_value(ciphertext)
        assert decrypted == "secret data"


class TestGetEncryptionService:
    """Tests for the singleton getter."""

    def test_get_encryption_service_returns_cached_instance(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ohev.encryption.encryption_service import get_encryption_service

        get_encryption_service.cache_clear()

        monkeypatch.setenv("OHEV_ENCRYPTION_KEY_VALUE", "test-secret")

        service1 = get_encryption_service()
        service2 = get_encryption_service()
        assert service1 is service2

        get_encryption_service.cache_clear()
