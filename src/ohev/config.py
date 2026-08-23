"""Application configuration loaded from environment variables.

Uses the OpenHands SDK env_parser to populate Pydantic models from
environment variables with a structured prefix scheme.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Self, cast

from openhands.agent_server.env_parser import from_env
from pydantic import BaseModel, Field, SecretStr, field_serializer, model_validator


class EncryptionKeyConfig(BaseModel):
    """Configuration for a single encryption/decryption key."""

    id: str = "default"
    value: SecretStr

    @field_serializer("value")
    def serialize_value(self, value: SecretStr, info: Any) -> str:
        if info.context and info.context.get("expose_secrets"):
            return value.get_secret_value()
        return str(value)


class AppConfig(BaseModel):
    """Root application configuration.

    The encryption_key is used for encrypting new data.
    The decryption_keys list contains all keys that can decrypt data,
    enabling key rotation without breaking existing encrypted values.
    The encryption_key is automatically included in decryption_keys.
    """

    encryption_key: EncryptionKeyConfig
    decryption_keys: list[EncryptionKeyConfig] = Field(default_factory=list)
    database_url: str = Field(
        default="postgresql+asyncpg://ohev:ohev@localhost:5432/ohev",
        description="Async SQLAlchemy database URL.",
    )

    @model_validator(mode="after")
    def ensure_encryption_key_in_decryption_keys(self) -> Self:
        """Ensure the encryption key is present in decryption_keys."""
        enc_key_id = self.encryption_key.id
        if not any(k.id == enc_key_id for k in self.decryption_keys):
            self.decryption_keys = [self.encryption_key, *self.decryption_keys]
        return self


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    """Load and cache the application configuration from environment.

    Environment variables are parsed with the 'OHEV' prefix:
      - OHEV_ENCRYPTION_KEY_ID
      - OHEV_ENCRYPTION_KEY_VALUE
      - OHEV_DECRYPTION_KEYS_0_ID
      - OHEV_DECRYPTION_KEYS_0_VALUE
      - OHEV_DECRYPTION_KEYS_1_ID
      - OHEV_DECRYPTION_KEYS_1_VALUE
      ...
    """
    return cast(AppConfig, from_env(AppConfig, "OHEV"))
