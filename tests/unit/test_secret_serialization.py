"""Unit tests for the §13 secret-serialization standard.

Covers :mod:`openhands.ev2.util.secret_serialization` — the
context-driven ``SecretStr``/secret-map encryption, exposure, and redaction
rules shared by every secret-bearing field across the codebase.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr

from openhands.ev2.config import AppConfig, EncryptionKeyConfig
from openhands.ev2.encryption.encryption_service import EncryptionService
from openhands.ev2.util import secret_serialization as ser
from openhands.ev2.util.secret_serialization import (
    decrypt_secret_map,
    dump_secret_map,
    dump_secret_str,
    encrypt_secret_map,
    encryption_service_from_context,
    expose_secrets_from_context,
    load_secret_str,
)

# Secrets >= 32 bytes to satisfy HMAC key length requirements (RFC 7518).
PRIMARY_SECRET = "primary-secret-key-at-least-32-bytes-long"


@pytest.fixture
def service() -> EncryptionService:
    """A real :class:`EncryptionService` over a test key."""
    config = AppConfig(
        encryption_key=EncryptionKeyConfig(id="primary", value=SecretStr(PRIMARY_SECRET)),
        idp={
            "url": "https://idp.example.com",
            "client_id": "test-client",
            "client_secret": SecretStr("test-secret"),
        },
    )
    return EncryptionService(config)


def _ctx(**kwargs: Any) -> dict[str, Any]:
    """A fake ``SerializationInfo``-like object carrying a context dict."""

    class _Info:
        def __init__(self, context: Any) -> None:
            self.context = context

    return _Info(kwargs or None)  # type: ignore[arg-type]


class TestEncryptionServiceFromContext:
    def test_none_info(self) -> None:
        assert encryption_service_from_context(None) is None

    def test_no_context(self) -> None:
        assert encryption_service_from_context(_ctx()) is None

    def test_context_without_service(self) -> None:
        assert encryption_service_from_context(_ctx(expose_secrets=True)) is None

    def test_context_with_service(self, service: EncryptionService) -> None:
        assert encryption_service_from_context(_ctx(encryption_service=service)) is service

    def test_bad_context_type_ignored(self) -> None:
        assert encryption_service_from_context(_ctx(encryption_service="nope")) is None


class TestExposeSecretsFromContext:
    def test_missing_flag(self) -> None:
        assert expose_secrets_from_context(None) is False
        assert expose_secrets_from_context(_ctx()) is False

    def test_truthy_flag(self) -> None:
        assert expose_secrets_from_context(_ctx(expose_secrets=True)) is True


class TestDumpSecretStr:
    def test_redacts_without_context(self) -> None:
        assert dump_secret_str(SecretStr("hunter2")) == "**********"
        assert dump_secret_str(SecretStr("hunter2"), None) == "**********"
        assert dump_secret_str(SecretStr("hunter2"), _ctx()) == "**********"

    def test_exposes_when_requested(self) -> None:
        assert dump_secret_str(SecretStr("hunter2"), _ctx(expose_secrets=True)) == "hunter2"

    def test_encryption_wins_over_exposure(self, service: EncryptionService) -> None:
        dumped = dump_secret_str(
            SecretStr("hunter2"),
            _ctx(expose_secrets=True, encryption_service=service),
        )
        assert dumped != "hunter2"
        assert service.decrypt_value(dumped) == "hunter2"


class TestLoadSecretStr:
    def test_plain_without_service(self) -> None:
        assert load_secret_str(SecretStr("plain")) == "plain"
        assert load_secret_str(SecretStr("plain"), _ctx()) == "plain"

    def test_decrypts_ciphertext(self, service: EncryptionService) -> None:
        ciphertext = service.encrypt_value("top-secret")
        assert (
            load_secret_str(SecretStr(ciphertext), _ctx(encryption_service=service)) == "top-secret"
        )


class TestDumpSecretMap:
    def test_none_values(self) -> None:
        assert dump_secret_map(None) is None

    def test_redacts_all(self) -> None:
        dumped = dump_secret_map({"a": SecretStr("one"), "b": SecretStr("two")})
        assert dumped == {"a": "**********", "b": "**********"}

    def test_encrypts_all(self, service: EncryptionService) -> None:
        dumped = dump_secret_map({"a": SecretStr("one")}, _ctx(encryption_service=service))
        assert dumped is not None
        assert service.decrypt_value(dumped["a"]) == "one"


class TestEncryptSecretMap:
    def test_none_values(self, service: EncryptionService) -> None:
        assert encrypt_secret_map(service, None) == {}

    def test_encrypts_with_service(self, service: EncryptionService) -> None:
        out = encrypt_secret_map(service, {"a": SecretStr("v")})
        # The stored value must never equal the plaintext and must round-trip.
        assert out["a"] != "v"
        assert service.decrypt_value(out["a"]) == "v"

    def test_stores_plaintext_without_service(self) -> None:
        out = encrypt_secret_map(None, {"a": SecretStr("v")})
        assert out == {"a": "v"}


class TestDecryptSecretMap:
    def test_none_values(self, service: EncryptionService) -> None:
        assert decrypt_secret_map(service, None) == {}

    def test_decrypts_with_service(self, service: EncryptionService) -> None:
        ciphertext = service.encrypt_value("v")
        out = decrypt_secret_map(service, {"a": ciphertext})
        assert out["a"].get_secret_value() == "v"

    def test_plaintext_without_service(self) -> None:
        out = decrypt_secret_map(None, {"a": "plain"})
        assert out["a"].get_secret_value() == "plain"


class TestSecretStrContextRoundTrip:
    """End-to-end: encrypt on dump, decrypt on load through the same context."""

    def test_model_dump_and_validate(self, service: EncryptionService) -> None:
        from openhands.ev2.secret.secret_schemas import SecretProviderRead, StaticSecretCreate

        create = StaticSecretCreate(name="API_KEY", value="plain")
        # A plain ``SecretStr`` payload is never dumped as plaintext — it has
        # no field serializer, so pydantic masks it (defaults are fail-closed).
        assert create.model_dump(mode="json")["value"] == "**********"

        # Provider read masks data values through the serializer.
        read = SecretProviderRead(
            id="00000000-0000-0000-0000-000000000001",
            kind="static",
            creator_id="00000000-0000-0000-0000-000000000002",
            data={"token": "not-yet-masked"},
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
        )
        assert read.model_dump(mode="json")["data"]["token"] == "**********"

    def test_rejects_invalid_static_name(self) -> None:
        import openhands.ev2.secret.secret_schemas as schemas

        with pytest.raises(ValueError):
            schemas._validate_name("lowercase")


class TestMappingContextObject:
    """Contexts may arrive as a generic Mapping rather than a dict."""

    def test_mapping_context(self, service: EncryptionService) -> None:
        from collections.abc import Mapping

        class _Mapping(Mapping[str, Any]):
            def __init__(self, source: dict[str, Any]) -> None:
                self._source = source

            def __getitem__(self, key: str) -> Any:
                return self._source[key]

            def __iter__(self):
                return iter(self._source)

            def __len__(self) -> int:
                return len(self._source)

        mapping = _Mapping({"expose_secrets": True, "encryption_service": service})

        class _Info:
            context = mapping

        # Encryption wins regardless of the container type.
        dumped = dump_secret_str(SecretStr("v"), _Info())
        assert dumped != "v"
        assert dumped != "**********"
        assert ser.encryption_service_from_context(_Info()) is service
        assert service.decrypt_value(dumped) == "v"
