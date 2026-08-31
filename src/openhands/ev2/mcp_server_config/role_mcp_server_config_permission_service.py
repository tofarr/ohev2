"""Service layer for role-MCP-server-config permission grants."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.mcp_server_config.mcp_server_config_models import (
    RoleMCPServerConfigPermission,
)
from openhands.ev2.mcp_server_config.role_mcp_server_config_permission_schemas import (
    RoleMCPServerConfigPermissionBatchCreate,
    RoleMCPServerConfigPermissionBatchDelete,
    RoleMCPServerConfigPermissionBatchOp,
    RoleMCPServerConfigPermissionBatchUpdate,
    RoleMCPServerConfigPermissionSearchFilter,
    RoleMCPServerConfigPermissionUpdate,
)


class RoleMCPServerConfigPermissionNotFoundError(Exception):
    """Raised when a role-MCP-server-config grant id does not exist."""


class RoleMCPServerConfigPermissionConflictError(Exception):
    """Raised when a grant already exists for a role/config pair."""


class RoleMCPServerConfigPermissionOrphanError(Exception):
    """Raised when the referenced role or MCP config does not exist."""


class RoleMCPServerConfigPermissionService:
    """CRUD operations over role-MCP-server-config grants."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        role_id: uuid.UUID,
        mcp_server_config_id: uuid.UUID,
        read_enabled: bool = False,
        update_enabled: bool = False,
        delete_enabled: bool = False,
    ) -> RoleMCPServerConfigPermission:
        """Grant a role access to an MCP server config."""
        link = RoleMCPServerConfigPermission(
            role_id=role_id,
            mcp_server_config_id=mcp_server_config_id,
            read_enabled=read_enabled,
            update_enabled=update_enabled,
            delete_enabled=delete_enabled,
        )
        self._session.add(link)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_integrity_error(exc, role_id, mcp_server_config_id) from exc
        await self._session.refresh(link)
        return link

    async def get(
        self, role_mcp_server_config_permission_id: uuid.UUID
    ) -> RoleMCPServerConfigPermission:
        """Retrieve a grant by id."""
        link = await self._session.get(
            RoleMCPServerConfigPermission,
            role_mcp_server_config_permission_id,
        )
        if link is None:
            raise RoleMCPServerConfigPermissionNotFoundError(
                str(role_mcp_server_config_permission_id)
            )
        return link

    async def get_many(
        self,
        role_mcp_server_config_permission_ids: list[uuid.UUID],
    ) -> list[RoleMCPServerConfigPermission | None]:
        """Retrieve grants by ids, positionally aligned."""
        if not role_mcp_server_config_permission_ids:
            return []
        stmt = select(RoleMCPServerConfigPermission).where(
            RoleMCPServerConfigPermission.id.in_(role_mcp_server_config_permission_ids)
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, RoleMCPServerConfigPermission] = {
            link.id: link for link in result.scalars().all()
        }
        return [by_id.get(link_id) for link_id in role_mcp_server_config_permission_ids]

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: RoleMCPServerConfigPermissionSearchFilter | None = None,
    ) -> tuple[list[RoleMCPServerConfigPermission], uuid.UUID | None]:
        """Search grants ordered by id, keyed-pagination via cursor."""
        stmt = select(RoleMCPServerConfigPermission).order_by(RoleMCPServerConfigPermission.id)
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(RoleMCPServerConfigPermission.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        links = list(result.scalars().all())
        next_cursor = links[-1].id if len(links) == limit else None
        return links, next_cursor

    async def count(
        self,
        search_filter: RoleMCPServerConfigPermissionSearchFilter | None = None,
    ) -> int:
        """Total grant count, optionally narrowed by *search_filter*."""
        stmt = select(func.count()).select_from(RoleMCPServerConfigPermission)
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def update(
        self,
        role_mcp_server_config_permission_id: uuid.UUID,
        payload: RoleMCPServerConfigPermissionUpdate,
    ) -> RoleMCPServerConfigPermission:
        """Toggle grant flags."""
        link = await self.get(role_mcp_server_config_permission_id)
        if payload.read_enabled is not None:
            link.read_enabled = payload.read_enabled
        if payload.update_enabled is not None:
            link.update_enabled = payload.update_enabled
        if payload.delete_enabled is not None:
            link.delete_enabled = payload.delete_enabled
        await self._session.flush()
        await self._session.refresh(link)
        return link

    async def delete(self, role_mcp_server_config_permission_id: uuid.UUID) -> None:
        """Delete a grant."""
        link = await self.get(role_mcp_server_config_permission_id)
        await self._session.delete(link)
        await self._session.flush()

    async def apply_batch(
        self,
        operations: list[RoleMCPServerConfigPermissionBatchOp],
    ) -> list[RoleMCPServerConfigPermission | None]:
        """Apply create/update/delete operations in one caller-owned transaction."""
        results: list[RoleMCPServerConfigPermission | None] = []
        for op in operations:
            if isinstance(op, RoleMCPServerConfigPermissionBatchCreate):
                d = op.data
                results.append(
                    await self.create(
                        role_id=d.role_id,
                        mcp_server_config_id=d.mcp_server_config_id,
                        read_enabled=d.read_enabled,
                        update_enabled=d.update_enabled,
                        delete_enabled=d.delete_enabled,
                    )
                )
            elif isinstance(op, RoleMCPServerConfigPermissionBatchUpdate):
                results.append(await self.update(op.id, op.data))
            elif isinstance(op, RoleMCPServerConfigPermissionBatchDelete):
                await self.delete(op.id)
                results.append(None)
        return results


def _classify_integrity_error(
    exc: IntegrityError,
    role_id: uuid.UUID,
    mcp_server_config_id: uuid.UUID,
) -> Exception:
    message = str(getattr(exc, "orig", exc)).lower()
    if "uq_role_mcp_server_config_permissions_role_id_config_id" in message or (
        "unique constraint" in message and "role_mcp_server_config_permissions" in message
    ):
        return RoleMCPServerConfigPermissionConflictError(f"{role_id}/{mcp_server_config_id}")
    if "foreign key" in message or "fk_" in message:
        if "mcp_server_config_id" in message and "role_id" not in message:
            return RoleMCPServerConfigPermissionOrphanError(
                f"mcp_server_config {mcp_server_config_id} does not exist"
            )
        return RoleMCPServerConfigPermissionOrphanError(f"role {role_id} does not exist")
    return RoleMCPServerConfigPermissionConflictError(f"{role_id}/{mcp_server_config_id}")


__all__ = [
    "RoleMCPServerConfigPermissionConflictError",
    "RoleMCPServerConfigPermissionNotFoundError",
    "RoleMCPServerConfigPermissionOrphanError",
    "RoleMCPServerConfigPermissionService",
]
