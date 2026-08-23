"""Unit tests for application configuration."""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from ohev.config import AppConfig, EncryptionKeyConfig


class TestEncryptionKeyConfig:
    """Tests for EncryptionKeyConfig model."""

    def test_default_id(self) -> None:
        key = EncryptionKeyConfig(value=SecretStr("secret"))
        assert key.id == "default"

    def test_custom_id(self) -> None:
        key = EncryptionKeyConfig(id="my-key", value=SecretStr("secret"))
        assert key.id == "my-key"

    def test_value_is_secret(self) -> None:
        key = EncryptionKeyConfig(value=SecretStr("my-secret-value"))
        assert isinstance(key.value, SecretStr)
        assert key.value.get_secret_value() == "my-secret-value"

    def test_serialize_hides_value_by_default(self) -> None:
        key = EncryptionKeyConfig(value=SecretStr("secret"))
        data = key.model_dump()
        assert data["value"] == "**********"

    def test_serialize_exposes_value_with_context(self) -> None:
        key = EncryptionKeyConfig(value=SecretStr("secret"))
        data = key.model_dump(context={"expose_secrets": True})
        assert data["value"] == "secret"


class TestAppConfig:
    """Tests for AppConfig model."""

    def test_encryption_key_auto_added_to_decryption_keys(self) -> None:
        config = AppConfig(
            encryption_key=EncryptionKeyConfig(id="primary", value=SecretStr("secret")),
        )
        assert len(config.decryption_keys) == 1
        assert config.decryption_keys[0].id == "primary"

    def test_encryption_key_not_duplicated_if_present(self) -> None:
        enc_key = EncryptionKeyConfig(id="primary", value=SecretStr("secret"))
        config = AppConfig(
            encryption_key=enc_key,
            decryption_keys=[enc_key],
        )
        assert len(config.decryption_keys) == 1
        assert config.decryption_keys[0].id == "primary"

    def test_encryption_key_prepended_to_existing_decryption_keys(self) -> None:
        config = AppConfig(
            encryption_key=EncryptionKeyConfig(id="new", value=SecretStr("new-secret")),
            decryption_keys=[
                EncryptionKeyConfig(id="old-1", value=SecretStr("old-1")),
                EncryptionKeyConfig(id="old-2", value=SecretStr("old-2")),
            ],
        )
        assert len(config.decryption_keys) == 3
        assert config.decryption_keys[0].id == "new"
        assert config.decryption_keys[1].id == "old-1"
        assert config.decryption_keys[2].id == "old-2"

    def test_decryption_keys_with_matching_id_not_duplicated(self) -> None:
        config = AppConfig(
            encryption_key=EncryptionKeyConfig(id="shared", value=SecretStr("secret")),
            decryption_keys=[
                EncryptionKeyConfig(id="other", value=SecretStr("other")),
                EncryptionKeyConfig(id="shared", value=SecretStr("secret")),
            ],
        )
        assert len(config.decryption_keys) == 2
        ids = [k.id for k in config.decryption_keys]
        assert ids.count("shared") == 1


class TestGetConfig:
    """Tests for get_config function."""

    def test_loads_from_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Clear the lru_cache before test
        from ohev.config import get_config

        get_config.cache_clear()

        monkeypatch.setenv("OHEV_ENCRYPTION_KEY_VALUE", "env-secret")
        monkeypatch.setenv("OHEV_ENCRYPTION_KEY_ID", "env-key")

        config = get_config()
        assert config.encryption_key.id == "env-key"
        assert config.encryption_key.value.get_secret_value() == "env-secret"

        # Clean up
        get_config.cache_clear()

    def test_loads_decryption_keys_from_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from ohev.config import get_config

        get_config.cache_clear()

        monkeypatch.setenv("OHEV_ENCRYPTION_KEY_VALUE", "primary")
        monkeypatch.setenv("OHEV_DECRYPTION_KEYS_0_ID", "old-key")
        monkeypatch.setenv("OHEV_DECRYPTION_KEYS_0_VALUE", "old-secret")

        config = get_config()
        # encryption_key (default id) + old-key
        assert len(config.decryption_keys) == 2
        ids = [k.id for k in config.decryption_keys]
        assert "default" in ids
        assert "old-key" in ids

        get_config.cache_clear()
