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
from openhands.ev2.mcp_server_config.mcp_server_config_security import MCPServerConfigAccess
from openhands.ev2.mcp_server_config.mcp_server_config_service import mcp_proxy_url_for
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import AllSearchFilter, NoneSearchFilter

_TEST_SECRET = "test-secret-key-at-least-32-bytes-long"


@pytest.fixture
def app_config() -> AppConfig:
    return AppConfig(
        encryption_key=EncryptionKeyConfig(id="k", value=SecretStr(_TEST_SECRET)),
        idp={
            "url": "https://idp.example.com",
            "client_id": "c",
            "client_secret": SecretStr("s"),
        },
        base_url="https://api.example.com",
    )


@pytest.fixture
def enc(app_config: AppConfig) -> EncryptionService:
    return EncryptionService(app_config)


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


def test_mcp_access_filter_branches() -> None:
    access = MCPServerConfigAccess()

    create_filter = access.to_search_filter(None, Action.CREATE)
    assert isinstance(create_filter, AllSearchFilter)

    denied_filter = access.to_search_filter(None, Action.READ)
    assert isinstance(denied_filter, NoneSearchFilter)

    user_id = uuid.uuid4()
    update_filter = access.to_search_filter(user_id, Action.UPDATE)
    assert update_filter.matches(object()) is True
    assert update_filter.sql_condition() is not None


def test_mcp_proxy_url_for(app_config: AppConfig) -> None:
    config_id = uuid.uuid4()
    url = mcp_proxy_url_for(config_id, config=app_config)
    assert url == f"https://api.example.com/mcp/{config_id}"


def test_to_mcp_server_uses_proxy_url_when_enabled(enc: EncryptionService) -> None:
    config_id = uuid.uuid4()
    config = MCPServerConfig(
        user_id=uuid.uuid4(),
        display_name="proxied-server",
        url="https://original.example.com/mcp",
        transport="sse",
        enable_proxy=True,
    )
    object.__setattr__(config, "id", config_id)

    proxy_url = "https://api.example.com/mcp/" + str(config_id)

    # With use_proxy=True (the default), the proxy URL is substituted.
    server_proxied = config.to_mcp_server(enc, proxy_url=proxy_url, use_proxy=True)
    assert server_proxied.url == proxy_url

    # With use_proxy=False, the stored URL is used (for the proxy endpoint itself).
    server_direct = config.to_mcp_server(enc, proxy_url=proxy_url, use_proxy=False)
    assert server_direct.url == "https://original.example.com/mcp"


def test_to_mcp_server_ignores_proxy_when_disabled(enc: EncryptionService) -> None:
    config = MCPServerConfig(
        user_id=uuid.uuid4(),
        display_name="direct-server",
        url="https://direct.example.com/mcp",
        transport="sse",
        enable_proxy=False,
    )
    object.__setattr__(config, "id", uuid.uuid4())

    # Even if a proxy_url is provided, enable_proxy=False means it's not used.
    server = config.to_mcp_server(
        enc, proxy_url="https://api.example.com/mcp/ignored", use_proxy=True
    )
    assert server.url == "https://direct.example.com/mcp"
