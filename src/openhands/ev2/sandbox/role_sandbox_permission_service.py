"""Service layer for the role-sandbox-permission grant feature.

CRUD for the per-role grant link table between :class:`Role` and
:class:`Sandbox`. Mirrors ``role_secret_permission_service``: the link table is
a governed resource of its own (``sandbox_grant_permission`` on :class:`Role`)
and the service scopes every read/write through the principal's effective
``perm_filter`` (AGENTS.md §9, §11.1).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.sandbox.role_sandbox_permission_schemas import (
    RoleSandboxPermissionBatchCreate,
    RoleSandboxPermissionBatchDelete,
    RoleSandboxPermissionBatchOp,
    RoleSandboxPermissionBatchUpdate,
    RoleSandboxPermissionSearchFilter,
    RoleSandboxPermissionUpdate,
)
from openhands.ev2.sandbox.sandbox_models import RoleSandboxPermission
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter


class RoleSandboxPermissionNotFoundError(Exception):
    """Raised when a role-sandbox-permission grant id does not exist."""


class RoleSandboxPermissionConflictError(Exception):
    """Raised when a grant already exists for the (role_id, sandbox_id) pair."""


class RoleSandboxPermissionOrphanError(Exception):
    """Raised when the referenced role or sandbox does not exist."""


class RoleSandboxPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class RoleSandboxPermissionService:
    """CRUD operations over role-sandbox-permission grants.

    Constructed per request with the request-scoped session and the principal's
    effective ``perm_filter`` (reduced from ``sandbox_grant_permission``); it
    holds no other mutable state.
    """

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[RoleSandboxPermission] = ALL,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(
        self,
        *,
        role_id: uuid.UUID,
        sandbox_id: uuid.UUID,
        read_enabled: bool = False,
        update_enabled: bool = False,
        delete_enabled: bool = False,
    ) -> RoleSandboxPermission:
        """Grant a role access to a sandbox. Raises on duplicate or orphan FK,
        and :class:`RoleSandboxPermissionScopeError` if the grant falls outside
        the principal's create scope."""
        link = RoleSandboxPermission(
            role_id=role_id,
            sandbox_id=sandbox_id,
            read_enabled=read_enabled,
            update_enabled=update_enabled,
            delete_enabled=delete_enabled,
        )
        if not self._perm_filter.matches(link):
            raise RoleSandboxPermissionScopeError(f"{role_id}/{sandbox_id}")
        self._session.add(link)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_integrity_error(exc, role_id, sandbox_id) from exc
        await self._session.refresh(link)
        return link

    async def get(self, role_sandbox_permission_id: uuid.UUID) -> RoleSandboxPermission:
        """Retrieve a grant by id, scoped by ``perm_filter``.

        Raises :class:`RoleSandboxPermissionNotFoundError` if the grant is
        missing or out of the principal's scope (so callers return 404 without
        leaking existence).
        """
        stmt = self._perm_filter.filter_sql(
            select(RoleSandboxPermission).where(
                RoleSandboxPermission.id == role_sandbox_permission_id
            )
        )
        result = await self._session.execute(stmt)
        link = result.scalar_one_or_none()
        if link is None:
            raise RoleSandboxPermissionNotFoundError(str(role_sandbox_permission_id))
        return link

    async def get_many(
        self, role_sandbox_permission_ids: list[uuid.UUID]
    ) -> list[RoleSandboxPermission | None]:
        """Retrieve grants by ids, scoped by ``perm_filter``; positionally
        aligned, ``None`` where missing or out of scope."""
        if not role_sandbox_permission_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(RoleSandboxPermission).where(
                RoleSandboxPermission.id.in_(role_sandbox_permission_ids)
            )
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, RoleSandboxPermission] = {
            link.id: link for link in result.scalars().all()
        }
        return [by_id.get(lid) for lid in role_sandbox_permission_ids]

    async def search_role_sandbox_permissions(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: RoleSandboxPermissionSearchFilter | None = None,
    ) -> tuple[list[RoleSandboxPermission], uuid.UUID | None]:
        """Search grants ordered by id, keyed-pagination via cursor, scoped by
        ``perm_filter``."""
        stmt = self._perm_filter.filter_sql(
            select(RoleSandboxPermission).order_by(RoleSandboxPermission.id)
        )
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(RoleSandboxPermission.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        links = list(result.scalars().all())
        next_cursor = links[-1].id if len(links) == limit else None
        return links, next_cursor

    async def count(self, search_filter: RoleSandboxPermissionSearchFilter | None = None) -> int:
        """Total grant count, scoped by ``perm_filter`` and the optional
        *search_filter*."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(RoleSandboxPermission))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def update(
        self, role_sandbox_permission_id: uuid.UUID, payload: RoleSandboxPermissionUpdate
    ) -> RoleSandboxPermission:
        """Toggle the read/update/delete flags on a grant. Raises if missing or
        out of the principal's scope."""
        link = await self.get(role_sandbox_permission_id)
        if payload.read_enabled is not None:
            link.read_enabled = payload.read_enabled
        if payload.update_enabled is not None:
            link.update_enabled = payload.update_enabled
        if payload.delete_enabled is not None:
            link.delete_enabled = payload.delete_enabled
        await self._session.flush()
        await self._session.refresh(link)
        return link

    async def delete(self, role_sandbox_permission_id: uuid.UUID) -> None:
        """Delete a grant. Raises :class:`RoleSandboxPermissionNotFoundError` if missing."""
        link = await self.get(role_sandbox_permission_id)
        await self._session.delete(link)
        await self._session.flush()

    async def apply_batch(
        self,
        operations: list[RoleSandboxPermissionBatchOp],
        perm_filters: dict[Action, SearchFilter[RoleSandboxPermission] | None],
    ) -> list[RoleSandboxPermission | None]:
        """Apply a mix of create/update/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation. No commit is performed — the
        caller commits once after the whole batch succeeds (atomic). Returns
        results aligned with *operations*: the grant for create/update,
        ``None`` for delete.
        """
        results: list[RoleSandboxPermission | None] = []
        for op in operations:
            if isinstance(op, RoleSandboxPermissionBatchCreate):
                filt = perm_filters.get(Action.CREATE)
                if filt is None:
                    raise BatchPermissionDeniedError("create")
                d = op.data
                results.append(
                    await RoleSandboxPermissionService(self._session, filt).create(
                        role_id=d.role_id,
                        sandbox_id=d.sandbox_id,
                        read_enabled=d.read_enabled,
                        update_enabled=d.update_enabled,
                        delete_enabled=d.delete_enabled,
                    )
                )
            elif isinstance(op, RoleSandboxPermissionBatchUpdate):
                filt = perm_filters.get(Action.UPDATE)
                if filt is None:
                    raise BatchPermissionDeniedError("update")
                results.append(
                    await RoleSandboxPermissionService(self._session, filt).update(op.id, op.data)
                )
            elif isinstance(op, RoleSandboxPermissionBatchDelete):
                filt = perm_filters.get(Action.DELETE)
                if filt is None:
                    raise BatchPermissionDeniedError("delete")
                await RoleSandboxPermissionService(self._session, filt).delete(op.id)
                results.append(None)
        return results


def _classify_integrity_error(
    exc: IntegrityError,
    role_id: uuid.UUID,
    sandbox_id: uuid.UUID,
) -> Exception:
    """Map an IntegrityError to a duplicate vs orphan failure.

    A violation of ``uq_role_sandbox_perm_role_id_sandbox_id`` means the
    grant already exists; a foreign-key violation means the referenced role or
    sandbox is missing.
    """
    message = str(getattr(exc, "orig", exc)).lower()
    if "uq_role_sandbox_perm_role_id_sandbox_id" in message or (
        "unique constraint" in message and "role_sandbox_permissions" in message
    ):
        return RoleSandboxPermissionConflictError(f"{role_id}/{sandbox_id}")
    if "foreign key" in message or "fk_" in message:
        if "sandbox_id" in message and "role_id" not in message:
            return RoleSandboxPermissionOrphanError(f"sandbox {sandbox_id} does not exist")
        return RoleSandboxPermissionOrphanError(f"role {role_id} does not exist")
    return RoleSandboxPermissionConflictError(f"{role_id}/{sandbox_id}")


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted to the principal."""


__all__ = [
    "BatchPermissionDeniedError",
    "RoleSandboxPermission",
    "RoleSandboxPermissionConflictError",
    "RoleSandboxPermissionNotFoundError",
    "RoleSandboxPermissionOrphanError",
    "RoleSandboxPermissionScopeError",
    "RoleSandboxPermissionService",
]
