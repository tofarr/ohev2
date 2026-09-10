"""Unit tests for MCP server config services."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import make_principal

from openhands.ev2.mcp_server_config.mcp_server_config_models import MCPServerConfig
from openhands.ev2.mcp_server_config.mcp_server_config_schemas import (
    MCPServerConfigCreate,
    MCPServerConfigUpdate,
)
from openhands.ev2.mcp_server_config.mcp_server_config_service import (
    MCPServerConfigNotFoundError,
    MCPServerConfigService,
    MCPServerConfigValidationError,
)
from openhands.ev2.util.search_filter import AllSearchFilter


async def _seed_user(
    session: AsyncSession,
    *,
    email: str = "mcp@example.com",
    username: str = "mcp",
) -> uuid.UUID:
    user = await make_principal(session, email=email, username=username)
    await session.flush()
    return user.id


@pytest.fixture
def service(session: AsyncSession) -> MCPServerConfigService:
    return MCPServerConfigService(session, AllSearchFilter[MCPServerConfig]())


def _stdio_payload(**overrides: object) -> MCPServerConfigCreate:
    data: dict[str, object] = {
        "display_name": "filesystem",
        "transport": "stdio",
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    }
    data.update(overrides)
    return MCPServerConfigCreate.model_validate(data)


class TestMCPServerConfigService:
    async def test_create_encrypts_and_materializes(
        self,
        service: MCPServerConfigService,
    ) -> None:
        user_id = await _seed_user(service._session)
        config = await service.create(
            _stdio_payload(
                env={"TOKEN": "env-secret"},
                headers={"X-Token": "header-secret"},
                auth={"strategy": "bearer", "value": "bearer-secret"},
            ),
            creator_id=user_id,
        )

        assert config.env is not None and "env-secret" not in config.env
        assert config.headers is not None and "header-secret" not in config.headers
        assert config.auth is not None and "bearer-secret" not in config.auth
        server = config.to_mcp_server(service._enc)
        assert server.env is not None
        assert server.env["TOKEN"].get_secret_value() == "env-secret"
        read = service.to_read(config)
        assert read.env == {"TOKEN": "**********"}
        assert read.auth == {"strategy": "bearer", "value": "**********"}

    async def test_blank_display_name_rejected(self) -> None:
        with pytest.raises(ValidationError):
            MCPServerConfigCreate(display_name="   ", transport="http", url="https://mcp.test")
        with pytest.raises(ValidationError):
            MCPServerConfigUpdate(display_name="   ")

    async def test_create_invalid_config_rejected(self) -> None:
        with pytest.raises(ValidationError):
            MCPServerConfigCreate(display_name="bad", transport="stdio")

    async def test_update_revalidates_config(
        self,
        service: MCPServerConfigService,
    ) -> None:
        user_id = await _seed_user(service._session)
        config = await service.create(_stdio_payload(), creator_id=user_id)

        updated = await service.update(
            config.id,
            MCPServerConfigUpdate(display_name="remote", transport="http", url="https://mcp.test"),
        )

        assert updated.display_name == "remote"
        assert updated.transport == "http"
        assert updated.url == "https://mcp.test"

    async def test_update_invalid_merged_config_raises(
        self,
        service: MCPServerConfigService,
    ) -> None:
        user_id = await _seed_user(service._session)
        config = await service.create(_stdio_payload(), creator_id=user_id)

        with pytest.raises(MCPServerConfigValidationError):
            await service.update(config.id, MCPServerConfigUpdate(command=None))

    async def test_delete(self, service: MCPServerConfigService) -> None:
        user_id = await _seed_user(service._session)
        config = await service.create(_stdio_payload(), creator_id=user_id)
        await service.delete(config.id)

        with pytest.raises(MCPServerConfigNotFoundError):
            await service.get(config.id)
