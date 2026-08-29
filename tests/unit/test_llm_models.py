"""Unit tests for the LLM ORM models' SDK materialization methods."""

from __future__ import annotations

import time
import uuid

import pytest
from pydantic import SecretStr

from openhands.ev2.config import AppConfig, EncryptionKeyConfig
from openhands.ev2.encryption.encryption_service import EncryptionService
from openhands.ev2.llm.llm_models import StoredLLM, StoredProviderConnection

_TEST_SECRET = "test-secret-key-at-least-32-bytes-long"


@pytest.fixture
def enc() -> EncryptionService:
    return EncryptionService(
        AppConfig(
            encryption_key=EncryptionKeyConfig(id="k", value=SecretStr(_TEST_SECRET)),
            idp={
                "url": "https://idp.example.com",
                "client_id": "c",
                "client_secret": SecretStr("s"),
            },
        )
    )


def _conn(**overrides) -> StoredProviderConnection:
    defaults: dict = {
        "user_id": uuid.uuid4(),
        "display_name": "my-conn",
        "provider": "custom",
        "api_key": None,
        "base_url": "https://real.example.com",
        "enable_proxy": False,
    }
    defaults.update(overrides)
    return StoredProviderConnection(**defaults)


class TestStoredProviderConnectionToSDK:
    def test_id_is_stringified(self, enc: EncryptionService) -> None:
        conn = _conn()
        # Simulate a server-assigned id (init=False column).
        object.__setattr__(conn, "id", uuid.UUID("12345678-1234-5678-1234-456789abcdef"))
        sdk = conn.to_provider_connection(enc)
        assert sdk.id == "12345678-1234-5678-1234-456789abcdef"

    def test_api_key_decrypted(self, enc: EncryptionService) -> None:
        conn = _conn(api_key=enc.encrypt_value("super-secret"))
        object.__setattr__(conn, "id", uuid.uuid4())
        sdk = conn.to_provider_connection(enc)
        assert sdk.api_key_value() == "super-secret"

    def test_api_key_none_when_unset(self, enc: EncryptionService) -> None:
        conn = _conn(api_key=None)
        object.__setattr__(conn, "id", uuid.uuid4())
        sdk = conn.to_provider_connection(enc)
        assert sdk.api_key_value() is None

    def test_base_url_stored_when_proxy_disabled(self, enc: EncryptionService) -> None:
        conn = _conn(enable_proxy=False, base_url="https://real.example.com")
        object.__setattr__(conn, "id", uuid.uuid4())
        sdk = conn.to_provider_connection(enc, proxy_url="https://proxy.example.com")
        assert sdk.base_url == "https://real.example.com"

    def test_base_url_proxy_when_enabled(self, enc: EncryptionService) -> None:
        conn = _conn(enable_proxy=True, base_url="https://real.example.com")
        object.__setattr__(conn, "id", uuid.uuid4())
        sdk = conn.to_provider_connection(enc, proxy_url="https://proxy.example.com/x")
        assert sdk.base_url == "https://proxy.example.com/x"

    def test_timestamps_unix_seconds(self, enc: EncryptionService) -> None:
        conn = _conn()
        object.__setattr__(conn, "id", uuid.uuid4())
        sdk = conn.to_provider_connection(enc)
        assert isinstance(sdk.created_at, int)
        assert isinstance(sdk.updated_at, int)
        assert abs(sdk.created_at - int(time.time())) < 60


class TestStoredLLMToSDK:
    def _sdk_conn(self, enc: EncryptionService, *, api_key: str | None = "k") -> object:
        conn = _conn(api_key=enc.encrypt_value(api_key) if api_key else None)
        object.__setattr__(conn, "id", uuid.uuid4())
        return conn.to_provider_connection(enc)

    def test_model_sourced_from_row(self, enc: EncryptionService) -> None:
        sdk_conn = self._sdk_conn(enc)
        llm = StoredLLM(
            user_id=uuid.uuid4(),
            provider_connection_id=uuid.uuid4(),
            model="gpt-4o",
            display_name="m",
            config={},
        )
        sdk_llm = llm.to_llm(sdk_conn)
        assert sdk_llm.model == "gpt-4o"

    def test_connection_fields_take_precedence(self, enc: EncryptionService) -> None:
        sdk_conn = self._sdk_conn(enc)
        # config blob carries stale values that must be overridden by the connection.
        llm = StoredLLM(
            user_id=uuid.uuid4(),
            provider_connection_id=uuid.uuid4(),
            model="gpt-4o",
            display_name="m",
            config={"api_key": "stale", "base_url": "stale", "provider_connection_id": "stale"},
        )
        sdk_llm = llm.to_llm(sdk_conn)
        assert sdk_llm.base_url == sdk_conn.base_url
        assert sdk_llm.provider_connection_id == sdk_conn.id

    def test_config_fields_applied(self, enc: EncryptionService) -> None:
        sdk_conn = self._sdk_conn(enc)
        llm = StoredLLM(
            user_id=uuid.uuid4(),
            provider_connection_id=uuid.uuid4(),
            model="gpt-4o",
            display_name="m",
            config={"num_retries": 1, "temperature": 0.25},
        )
        sdk_llm = llm.to_llm(sdk_conn)
        assert sdk_llm.num_retries == 1
        assert sdk_llm.temperature == 0.25
