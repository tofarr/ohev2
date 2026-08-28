"""Unit tests for application configuration."""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from openhands.ev2.config import AppConfig, EncryptionKeyConfig


def _cfg(**overrides: object) -> AppConfig:
    """Shorthand for tests that only vary a few fields.

    Supplies the required IdP fields and an encryption key so tests can focus
    on the field under test.
    """
    defaults: dict[str, object] = {
        "idp": {
            "url": "https://idp.example.com",
            "client_id": "test-client",
            "client_secret": SecretStr("test-secret"),
        },
        "encryption_key": EncryptionKeyConfig(
            id="primary", value=SecretStr("test-secret-at-least-32-bytes-long!!")
        ),
    }
    defaults.update(overrides)
    return AppConfig(**defaults)  # type: ignore[arg-type]


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
        config = _cfg(
            encryption_key=EncryptionKeyConfig(id="primary", value=SecretStr("secret")),
        )
        assert len(config.decryption_keys) == 1
        assert config.decryption_keys[0].id == "primary"

    def test_encryption_key_not_duplicated_if_present(self) -> None:
        enc_key = EncryptionKeyConfig(id="primary", value=SecretStr("secret"))
        config = _cfg(
            encryption_key=enc_key,
            decryption_keys=[enc_key],
        )
        assert len(config.decryption_keys) == 1
        assert config.decryption_keys[0].id == "primary"

    def test_encryption_key_prepended_to_existing_decryption_keys(self) -> None:
        config = _cfg(
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
        config = _cfg(
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
        from openhands.ev2.config import get_config

        get_config.cache_clear()
        monkeypatch.setenv("OHEV_IDP_URL", "https://idp.example.com")
        monkeypatch.setenv("OHEV_IDP_CLIENT_ID", "env-client")
        monkeypatch.setenv("OHEV_IDP_CLIENT_SECRET", "env-secret")

        monkeypatch.setenv("OHEV_ENCRYPTION_KEY_VALUE", "env-secret")
        monkeypatch.setenv("OHEV_ENCRYPTION_KEY_ID", "env-key")

        config = get_config()
        assert config.encryption_key.id == "env-key"
        assert config.encryption_key.value.get_secret_value() == "env-secret"

        # Clean up
        get_config.cache_clear()

    def test_loads_decryption_keys_from_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from openhands.ev2.config import get_config

        get_config.cache_clear()
        monkeypatch.setenv("OHEV_IDP_URL", "https://idp.example.com")
        monkeypatch.setenv("OHEV_IDP_CLIENT_ID", "env-client")
        monkeypatch.setenv("OHEV_IDP_CLIENT_SECRET", "env-secret")

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


class TestAuthConfig:
    """Tests for the federated OAuth (auth) config fields."""

    def test_idp_required_fields(self) -> None:
        config = _cfg()
        assert config.idp.url == "https://idp.example.com"
        assert config.idp.client_id == "test-client"
        assert config.idp.client_secret.get_secret_value() == "test-secret"

    def test_idp_optional_oidc_fields_default_none(self) -> None:
        config = _cfg()
        assert config.idp.user_id_field is None
        assert config.idp.email_field is None
        assert config.idp.role_field is None

    def test_idp_drift_tolerance_default(self) -> None:
        config = _cfg()
        assert config.idp.expire_drift_tolerance >= 0

    def test_idp_scopes_default(self) -> None:
        config = _cfg()
        assert config.idp.scopes
        assert all(isinstance(s, str) for s in config.idp.scopes)

    def test_idp_paths_default(self) -> None:
        config = _cfg()
        assert config.idp.authorize_path
        assert config.idp.token_path

    def test_cleanup_interval_default(self) -> None:
        config = _cfg()
        assert config.cleanup_interval >= 0

    def test_idp_delete_expired_seconds_default(self) -> None:
        config = _cfg()
        assert config.idp.delete_expired_seconds > 0

    def test_idp_access_token_expires_in_default(self) -> None:
        config = _cfg()
        assert config.idp.access_token_expires_in > 0

    def test_idp_refresh_token_expires_in_default(self) -> None:
        config = _cfg()
        assert config.idp.refresh_token_expires_in > 0

    def test_idp_refresh_lock_timeout_default(self) -> None:
        config = _cfg()
        assert config.idp.refresh_lock_timeout_seconds > 0

    def test_missing_idp_url_raises(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            AppConfig(  # type: ignore[call-arg]
                idp={"client_id": "c", "client_secret": SecretStr("s")},
            )

    def test_loads_auth_fields_from_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from openhands.ev2.config import get_config

        get_config.cache_clear()
        monkeypatch.setenv("OHEV_IDP_URL", "https://idp.example.com")
        monkeypatch.setenv("OHEV_IDP_CLIENT_ID", "env-client")
        monkeypatch.setenv("OHEV_IDP_CLIENT_SECRET", "env-secret")
        monkeypatch.setenv("OHEV_ENCRYPTION_KEY_VALUE", "primary")
        monkeypatch.setenv("OHEV_IDP_USER_ID_FIELD", "oid")
        monkeypatch.setenv("OHEV_IDP_EMAIL_FIELD", "mail")
        monkeypatch.setenv("OHEV_IDP_EXPIRE_DRIFT_TOLERANCE", "120")
        monkeypatch.setenv("OHEV_CLEANUP_INTERVAL", "600")
        monkeypatch.setenv("OHEV_IDP_DELETE_EXPIRED_SECONDS", "7200")
        config = get_config()
        assert config.idp.user_id_field == "oid"
        assert config.idp.email_field == "mail"
        assert config.idp.expire_drift_tolerance == 120
        assert config.cleanup_interval == 600
        assert config.idp.delete_expired_seconds == 7200
        get_config.cache_clear()
