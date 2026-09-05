"""Service layer for role-MCP-server-config permission grants.

The link table is a governed resource of its own
(``mcp_server_config_grant_permission`` on :class:`Role`): the service holds
the effective ``perm_filter`` and scopes every read/write through it
(AGENTS.md §9 — authorization enforced in services, not just routers).
Managing grants is deliberately *not* implied by ``role_permission`` update —
a principal who may edit a role's metadata must not be able to grant that
role access to arbitrary MCP server configs (that would be privilege
escalation / credential exfiltration).
"""

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
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter


class RoleMCPServerConfigPermissionNotFoundError(Exception):
    """Raised when a role-MCP-server-config grant id does not exist."""


class RoleMCPServerConfigPermissionConflictError(Exception):
    """Raised when a grant already exists for a role/config pair."""


class RoleMCPServerConfigPermissionOrphanError(Exception):
    """Raised when the referenced role or MCP config does not exist."""


class RoleMCPServerConfigPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted to the principal."""


class RoleMCPServerConfigPermissionService:
    """CRUD operations over role-MCP-server-config grants.

    Constructed per request with the request-scoped session and the principal's
    effective ``perm_filter`` (reduced from
    ``mcp_server_config_grant_permission``); it holds no other mutable state.
    """

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[RoleMCPServerConfigPermission] = ALL,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(
        self,
        *,
        role_id: uuid.UUID,
        mcp_server_config_id: uuid.UUID,
        read_enabled: bool = False,
        update_enabled: bool = False,
        delete_enabled: bool = False,
    ) -> RoleMCPServerConfigPermission:
        """Grant a role access to an MCP server config. Raises on duplicate or
        orphan FK, and :class:`RoleMCPServerConfigPermissionScopeError` if the
        grant falls outside the principal's create scope."""
        link = RoleMCPServerConfigPermission(
            role_id=role_id,
            mcp_server_config_id=mcp_server_config_id,
            read_enabled=read_enabled,
            update_enabled=update_enabled,
            delete_enabled=delete_enabled,
        )
        if not self._perm_filter.matches(link):
            raise RoleMCPServerConfigPermissionScopeError(f"{role_id}/{mcp_server_config_id}")
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
        """Retrieve a grant by id, scoped by ``perm_filter``.

        Raises :class:`RoleMCPServerConfigPermissionNotFoundError` if the
        grant is missing or out of the principal's scope (so callers return
        404 without leaking existence).
        """
        stmt = self._perm_filter.filter_sql(
            select(RoleMCPServerConfigPermission).where(
                RoleMCPServerConfigPermission.id == role_mcp_server_config_permission_id
            )
        )
        result = await self._session.execute(stmt)
        link = result.scalar_one_or_none()
        if link is None:
            raise RoleMCPServerConfigPermissionNotFoundError(
                str(role_mcp_server_config_permission_id)
            )
        return link

    async def get_many(
        self,
        role_mcp_server_config_permission_ids: list[uuid.UUID],
    ) -> list[RoleMCPServerConfigPermission | None]:
        """Retrieve grants by ids, scoped by ``perm_filter``; positionally
        aligned, ``None`` where missing or out of scope."""
        if not role_mcp_server_config_permission_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(RoleMCPServerConfigPermission).where(
                RoleMCPServerConfigPermission.id.in_(role_mcp_server_config_permission_ids)
            )
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
        """Search grants ordered by id, keyed-pagination via cursor, scoped by
        ``perm_filter``."""
        stmt = self._perm_filter.filter_sql(
            select(RoleMCPServerConfigPermission).order_by(RoleMCPServerConfigPermission.id)
        )
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
        """Total grant count, scoped by ``perm_filter`` and the optional
        *search_filter*."""
        stmt = self._perm_filter.filter_sql(
            select(func.count()).select_from(RoleMCPServerConfigPermission)
        )
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def update(
        self,
        role_mcp_server_config_permission_id: uuid.UUID,
        payload: RoleMCPServerConfigPermissionUpdate,
    ) -> RoleMCPServerConfigPermission:
        """Toggle grant flags. Raises if missing or out of the principal's
        scope."""
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
        """Delete a grant. Raises if missing or out of the principal's scope."""
        link = await self.get(role_mcp_server_config_permission_id)
        await self._session.delete(link)
        await self._session.flush()

    async def apply_batch(
        self,
        operations: list[RoleMCPServerConfigPermissionBatchOp],
        perm_filters: dict[Action, SearchFilter[RoleMCPServerConfigPermission] | None],
    ) -> list[RoleMCPServerConfigPermission | None]:
        """Apply create/update/delete operations in one caller-owned transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic). Returns
        results aligned with *operations*: the grant for create/update,
        ``None`` for delete.
        """
        results: list[RoleMCPServerConfigPermission | None] = []
        for op in operations:
            if isinstance(op, RoleMCPServerConfigPermissionBatchCreate):
                filt = perm_filters.get(Action.CREATE)
                if filt is None:
                    raise BatchPermissionDeniedError("create")
                d = op.data
                results.append(
                    await RoleMCPServerConfigPermissionService(self._session, filt).create(
                        role_id=d.role_id,
                        mcp_server_config_id=d.mcp_server_config_id,
                        read_enabled=d.read_enabled,
                        update_enabled=d.update_enabled,
                        delete_enabled=d.delete_enabled,
                    )
                )
            elif isinstance(op, RoleMCPServerConfigPermissionBatchUpdate):
                filt = perm_filters.get(Action.UPDATE)
                if filt is None:
                    raise BatchPermissionDeniedError("update")
                results.append(
                    await RoleMCPServerConfigPermissionService(self._session, filt).update(
                        op.id, op.data
                    )
                )
            elif isinstance(op, RoleMCPServerConfigPermissionBatchDelete):
                filt = perm_filters.get(Action.DELETE)
                if filt is None:
                    raise BatchPermissionDeniedError("delete")
                await RoleMCPServerConfigPermissionService(self._session, filt).delete(op.id)
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
    "BatchPermissionDeniedError",
    "RoleMCPServerConfigPermissionConflictError",
    "RoleMCPServerConfigPermissionNotFoundError",
    "RoleMCPServerConfigPermissionOrphanError",
    "RoleMCPServerConfigPermissionScopeError",
    "RoleMCPServerConfigPermissionService",
]
