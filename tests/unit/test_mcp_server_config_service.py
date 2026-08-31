"""Unit tests for MCP server config services and permissions."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import assign_role, make_principal

from openhands.ev2.mcp_server_config.mcp_server_config_models import MCPServerConfig
from openhands.ev2.mcp_server_config.mcp_server_config_schemas import (
    MCPServerConfigCreate,
    MCPServerConfigUpdate,
)
from openhands.ev2.mcp_server_config.mcp_server_config_security import MCPServerConfigAccess
from openhands.ev2.mcp_server_config.mcp_server_config_service import (
    MCPServerConfigNotFoundError,
    MCPServerConfigService,
    MCPServerConfigValidationError,
)
from openhands.ev2.mcp_server_config.role_mcp_server_config_permission_service import (
    RoleMCPServerConfigPermissionConflictError,
    RoleMCPServerConfigPermissionOrphanError,
    RoleMCPServerConfigPermissionService,
    _classify_integrity_error,
)
from openhands.ev2.security.security_models import Action
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
            user_id=user_id,
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
        config = await service.create(_stdio_payload(), user_id=user_id)

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
        config = await service.create(_stdio_payload(), user_id=user_id)

        with pytest.raises(MCPServerConfigValidationError):
            await service.update(config.id, MCPServerConfigUpdate(command=None))

    async def test_delete(self, service: MCPServerConfigService) -> None:
        user_id = await _seed_user(service._session)
        config = await service.create(_stdio_payload(), user_id=user_id)
        await service.delete(config.id)

        with pytest.raises(MCPServerConfigNotFoundError):
            await service.get(config.id)


class TestMCPServerConfigAccess:
    async def test_read_filter_uses_role_grants(self, session: AsyncSession) -> None:
        owner_id = await _seed_user(session)
        granted_user = await _seed_user(
            session,
            email="reader@example.com",
            username="reader",
        )
        service = MCPServerConfigService(session, AllSearchFilter[MCPServerConfig]())
        visible = await service.create(_stdio_payload(display_name="visible"), user_id=owner_id)
        hidden = await service.create(_stdio_payload(display_name="hidden"), user_id=owner_id)
        role = await assign_role(
            session,
            granted_user,
            {"mcp_server_config_permission": MCPServerConfigAccess()},
            role_name="mcp-reader",
        )
        await RoleMCPServerConfigPermissionService(session).create(
            role_id=role.id,
            mcp_server_config_id=visible.id,
            read_enabled=True,
        )
        await session.flush()

        read_filter = MCPServerConfigAccess().to_search_filter(granted_user, Action.READ)
        scoped = MCPServerConfigService(session, read_filter)
        rows, _next = await scoped.search(limit=10)

        assert [row.id for row in rows] == [visible.id]
        with pytest.raises(MCPServerConfigNotFoundError):
            await scoped.get(hidden.id)


class TestRoleMCPServerConfigPermissionErrors:
    def test_classifies_unique_constraint(self) -> None:
        role_id = uuid.uuid4()
        config_id = uuid.uuid4()
        exc = IntegrityError(
            "stmt",
            {},
            Exception("unique constraint role_mcp_server_config_permissions"),
        )

        result = _classify_integrity_error(exc, role_id, config_id)

        assert isinstance(result, RoleMCPServerConfigPermissionConflictError)

    def test_classifies_missing_mcp_config_foreign_key(self) -> None:
        role_id = uuid.uuid4()
        config_id = uuid.uuid4()
        exc = IntegrityError("stmt", {}, Exception("foreign key mcp_server_config_id"))

        result = _classify_integrity_error(exc, role_id, config_id)

        assert isinstance(result, RoleMCPServerConfigPermissionOrphanError)
        assert str(config_id) in str(result)

    def test_classifies_missing_role_foreign_key(self) -> None:
        role_id = uuid.uuid4()
        config_id = uuid.uuid4()
        exc = IntegrityError("stmt", {}, Exception("foreign key role_id"))

        result = _classify_integrity_error(exc, role_id, config_id)

        assert isinstance(result, RoleMCPServerConfigPermissionOrphanError)
        assert str(role_id) in str(result)
