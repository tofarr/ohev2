"""Tests for MCP server config ORM materialization."""

from __future__ import annotations

import uuid

import pytest
from pydantic import SecretStr

from openhands.ev2.config import AppConfig, EncryptionKeyConfig
from openhands.ev2.encryption.encryption_service import EncryptionService
from openhands.ev2.mcp_server_config.mcp_server_config_models import (
    MCPServerConfig,
    decrypt_json_blob,
    encrypt_json_blob,
)

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


def test_json_blob_helpers_round_trip(enc: EncryptionService) -> None:
    ciphertext = encrypt_json_blob(enc, {"A": "secret"})
    assert ciphertext is not None
    assert "secret" not in ciphertext
    assert decrypt_json_blob(enc, ciphertext) == {"A": "secret"}


def test_to_mcp_server_decrypts_secret_fields(enc: EncryptionService) -> None:
    config = MCPServerConfig(
        user_id=uuid.uuid4(),
        display_name="filesystem",
        transport="stdio",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        env=encrypt_json_blob(enc, {"TOKEN": "env-secret"}),
        headers=encrypt_json_blob(enc, {"X-Token": "header-secret"}),
        auth=encrypt_json_blob(enc, {"strategy": "bearer", "value": "bearer-secret"}),
    )
    object.__setattr__(config, "id", uuid.uuid4())

    server = config.to_mcp_server(enc)

    assert server.command == "npx"
    assert server.env is not None
    assert server.env["TOKEN"].get_secret_value() == "env-secret"
    assert server.headers is not None
    assert server.headers["X-Token"].get_secret_value() == "header-secret"
    assert server.auth is not None
    dumped = server.model_dump(mode="json")
    assert dumped["env"] == {"TOKEN": "**********"}
    assert dumped["auth"] == {"strategy": "bearer", "value": "**********"}
