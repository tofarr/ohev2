"""Service layer for MCP server configuration resources."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.encryption.encryption_service import EncryptionService, get_encryption_service
from openhands.ev2.mcp_server_config.mcp_server_config_models import (
    MCPServerConfig,
    encrypt_json_blob,
)
from openhands.ev2.mcp_server_config.mcp_server_config_schemas import (
    MCPServerConfigBatchCreate,
    MCPServerConfigBatchDelete,
    MCPServerConfigBatchOp,
    MCPServerConfigBatchUpdate,
    MCPServerConfigCreate,
    MCPServerConfigRead,
    MCPServerConfigSearchFilter,
    MCPServerConfigUpdate,
    mcp_payload_to_plain_dict,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter


class MCPServerConfigNotFoundError(Exception):
    """Raised when an MCP server config id does not exist or is out of scope."""


class MCPServerConfigPermissionScopeError(Exception):
    """Raised when a payload falls outside the principal's permission scope."""


class MCPServerConfigValidationError(Exception):
    """Raised when SDK ``MCPServer`` validation fails."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted."""


class MCPServerConfigService:
    """CRUD over :class:`MCPServerConfig`."""

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[MCPServerConfig] = ALL,
        *,
        encryption_service: EncryptionService | None = None,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter
        self._enc = encryption_service or get_encryption_service()

    def to_read(self, config: MCPServerConfig) -> MCPServerConfigRead:
        """Return a masked API representation for *config*."""
        server_data = config.to_mcp_server(self._enc).model_dump(mode="json")
        return MCPServerConfigRead(
            id=config.id,
            user_id=config.user_id,
            display_name=config.display_name,
            url=server_data.get("url"),
            transport=server_data.get("transport"),
            command=server_data.get("command"),
            args=server_data.get("args"),
            env=server_data.get("env"),
            cwd=server_data.get("cwd"),
            description=server_data.get("description"),
            icon=server_data.get("icon"),
            timeout=server_data.get("timeout"),
            sse_read_timeout=server_data.get("sse_read_timeout"),
            keep_alive=server_data.get("keep_alive"),
            headers=server_data.get("headers"),
            auth=server_data.get("auth"),
            enabled=bool(server_data.get("enabled", True)),
            created_at=config.created_at,
            updated_at=config.updated_at,
        )

    async def create(
        self,
        payload: MCPServerConfigCreate,
        *,
        user_id: uuid.UUID,
    ) -> MCPServerConfig:
        """Create an MCP server configuration, encrypting secret-bearing fields."""
        data = self._normalized_mcp_data(mcp_payload_to_plain_dict(payload))
        config = MCPServerConfig(
            user_id=user_id,
            display_name=payload.display_name,
            **self._stored_kwargs(data),
        )
        if not self._perm_filter.matches(config):
            raise MCPServerConfigPermissionScopeError(payload.display_name)
        self._session.add(config)
        await self._session.flush()
        await self._session.refresh(config)
        return config

    async def get(self, config_id: uuid.UUID) -> MCPServerConfig:
        """Retrieve an MCP server config by id, scoped by ``perm_filter``."""
        stmt = self._perm_filter.filter_sql(
            select(MCPServerConfig).where(MCPServerConfig.id == config_id)
        )
        result = await self._session.execute(stmt)
        config = result.scalar_one_or_none()
        if config is None:
            raise MCPServerConfigNotFoundError(str(config_id))
        return config

    async def get_many(self, config_ids: list[uuid.UUID]) -> list[MCPServerConfig | None]:
        """Retrieve configs by ids, positionally aligned with ``None`` for misses."""
        if not config_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(MCPServerConfig).where(MCPServerConfig.id.in_(config_ids))
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, MCPServerConfig] = {row.id: row for row in result.scalars().all()}
        return [by_id.get(config_id) for config_id in config_ids]

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: MCPServerConfigSearchFilter | None = None,
    ) -> tuple[list[MCPServerConfig], uuid.UUID | None]:
        """Search configs ordered by id, keyed-pagination via cursor."""
        stmt = self._perm_filter.filter_sql(select(MCPServerConfig).order_by(MCPServerConfig.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(MCPServerConfig.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        next_cursor = rows[-1].id if len(rows) == limit else None
        return rows, next_cursor

    async def count(self, search_filter: MCPServerConfigSearchFilter | None = None) -> int:
        """Count configs visible to the service's permission filter."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(MCPServerConfig))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def update(
        self,
        config_id: uuid.UUID,
        payload: MCPServerConfigUpdate,
    ) -> MCPServerConfig:
        """Partially update an MCP server config and revalidate it with the SDK."""
        config = await self.get(config_id)
        if "display_name" in payload.model_fields_set and payload.display_name is not None:
            config.display_name = payload.display_name
        current = config.to_plain_mcp_dict(self._enc)
        current.update(mcp_payload_to_plain_dict(payload, exclude_unset=True))
        data = self._normalized_mcp_data(current)
        self._apply_stored_kwargs(config, data)
        await self._session.flush()
        await self._session.refresh(config)
        return config

    async def delete(self, config_id: uuid.UUID) -> None:
        """Delete an MCP server config."""
        config = await self.get(config_id)
        await self._session.delete(config)
        await self._session.flush()

    async def apply_batch(
        self,
        operations: list[MCPServerConfigBatchOp],
        perm_filters: dict[Action, SearchFilter[MCPServerConfig] | None],
        *,
        user_id: uuid.UUID,
    ) -> list[MCPServerConfig | None]:
        """Apply create/update/delete operations in one caller-owned transaction."""
        results: list[MCPServerConfig | None] = []
        for op in operations:
            if isinstance(op, MCPServerConfigBatchCreate):
                results.append(await self._batch_create(op, perm_filters, user_id=user_id))
            elif isinstance(op, MCPServerConfigBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, MCPServerConfigBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: MCPServerConfigBatchCreate,
        perm_filters: dict[Action, SearchFilter[MCPServerConfig] | None],
        *,
        user_id: uuid.UUID,
    ) -> MCPServerConfig:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        return await MCPServerConfigService(
            self._session,
            filt,
            encryption_service=self._enc,
        ).create(op.data, user_id=user_id)

    async def _batch_update(
        self,
        op: MCPServerConfigBatchUpdate,
        perm_filters: dict[Action, SearchFilter[MCPServerConfig] | None],
    ) -> MCPServerConfig:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await MCPServerConfigService(
            self._session,
            filt,
            encryption_service=self._enc,
        ).update(op.id, op.data)

    async def _batch_delete(
        self,
        op: MCPServerConfigBatchDelete,
        perm_filters: dict[Action, SearchFilter[MCPServerConfig] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await MCPServerConfigService(
            self._session,
            filt,
            encryption_service=self._enc,
        ).delete(op.id)

    @staticmethod
    def _normalized_mcp_data(data: dict[str, Any]) -> dict[str, Any]:
        from openhands.sdk.mcp.config import MCPServer

        try:
            server = MCPServer.model_validate(data)
        except Exception as exc:
            raise MCPServerConfigValidationError(str(exc)) from exc
        out = server.model_dump(
            mode="json",
            context={"expose_secrets": "plaintext"},
            exclude_none=True,
        )
        out["enabled"] = server.enabled
        return out

    def _stored_kwargs(self, data: dict[str, Any]) -> dict[str, Any]:
        return {
            "url": data.get("url"),
            "transport": data.get("transport"),
            "command": data.get("command"),
            "args": data.get("args"),
            "env": encrypt_json_blob(self._enc, data.get("env")),
            "cwd": data.get("cwd"),
            "description": data.get("description"),
            "icon": data.get("icon"),
            "timeout": data.get("timeout"),
            "sse_read_timeout": data.get("sse_read_timeout"),
            "keep_alive": data.get("keep_alive"),
            "headers": encrypt_json_blob(self._enc, data.get("headers")),
            "auth": encrypt_json_blob(self._enc, data.get("auth")),
            "enabled": bool(data.get("enabled", True)),
        }

    def _apply_stored_kwargs(self, config: MCPServerConfig, data: dict[str, Any]) -> None:
        for field, value in self._stored_kwargs(data).items():
            setattr(config, field, value)


__all__ = [
    "BatchPermissionDeniedError",
    "MCPServerConfigNotFoundError",
    "MCPServerConfigPermissionScopeError",
    "MCPServerConfigService",
    "MCPServerConfigValidationError",
]
