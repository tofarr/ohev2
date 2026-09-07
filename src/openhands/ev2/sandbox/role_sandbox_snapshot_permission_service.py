"""Service layer for the role-sandbox-snapshot-permission grant feature.

CRUD for the per-role grant link table between :class:`Role` and
:class:`SandboxSnapshot`. Mirrors ``role_secret_permission_service``: the link
table is a governed resource of its own (``sandbox_snapshot_grant_permission``
on :class:`Role`) and the service scopes every read/write through the
principal's effective ``perm_filter`` (AGENTS.md §9, §11.1).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.sandbox.role_sandbox_snapshot_permission_schemas import (
    RoleSandboxSnapshotPermissionBatchCreate,
    RoleSandboxSnapshotPermissionBatchDelete,
    RoleSandboxSnapshotPermissionBatchOp,
    RoleSandboxSnapshotPermissionBatchUpdate,
    RoleSandboxSnapshotPermissionSearchFilter,
    RoleSandboxSnapshotPermissionUpdate,
)
from openhands.ev2.sandbox.sandbox_models import RoleSandboxSnapshotPermission
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter


class RoleSandboxSnapshotPermissionNotFoundError(Exception):
    """Raised when a role-sandbox-snapshot-permission grant id does not exist."""


class RoleSandboxSnapshotPermissionConflictError(Exception):
    """Raised when a grant already exists for the (role_id, sandbox_snapshot_id) pair."""


class RoleSandboxSnapshotPermissionOrphanError(Exception):
    """Raised when the referenced role or sandbox snapshot does not exist."""


class RoleSandboxSnapshotPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class RoleSandboxSnapshotPermissionService:
    """CRUD operations over role-sandbox-snapshot-permission grants.

    Constructed per request with the request-scoped session and the principal's
    effective ``perm_filter`` (reduced from ``sandbox_snapshot_grant_permission``).
    """

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[RoleSandboxSnapshotPermission] = ALL,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(
        self,
        *,
        role_id: uuid.UUID,
        sandbox_snapshot_id: uuid.UUID,
        read_enabled: bool = False,
        update_enabled: bool = False,
        delete_enabled: bool = False,
    ) -> RoleSandboxSnapshotPermission:
        """Grant a role access to a sandbox snapshot. Raises on duplicate or
        orphan FK, and :class:`RoleSandboxSnapshotPermissionScopeError` if the
        grant falls outside the principal's create scope."""
        link = RoleSandboxSnapshotPermission(
            role_id=role_id,
            sandbox_snapshot_id=sandbox_snapshot_id,
            read_enabled=read_enabled,
            update_enabled=update_enabled,
            delete_enabled=delete_enabled,
        )
        if not self._perm_filter.matches(link):
            raise RoleSandboxSnapshotPermissionScopeError(f"{role_id}/{sandbox_snapshot_id}")
        self._session.add(link)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_integrity_error(exc, role_id, sandbox_snapshot_id) from exc
        await self._session.refresh(link)
        return link

    async def get(
        self, role_sandbox_snapshot_permission_id: uuid.UUID
    ) -> RoleSandboxSnapshotPermission:
        """Retrieve a grant by id, scoped by ``perm_filter``.

        Raises :class:`RoleSandboxSnapshotPermissionNotFoundError` if the grant
        is missing or out of the principal's scope.
        """
        stmt = self._perm_filter.filter_sql(
            select(RoleSandboxSnapshotPermission).where(
                RoleSandboxSnapshotPermission.id == role_sandbox_snapshot_permission_id
            )
        )
        result = await self._session.execute(stmt)
        link = result.scalar_one_or_none()
        if link is None:
            raise RoleSandboxSnapshotPermissionNotFoundError(
                str(role_sandbox_snapshot_permission_id)
            )
        return link

    async def get_many(
        self, role_sandbox_snapshot_permission_ids: list[uuid.UUID]
    ) -> list[RoleSandboxSnapshotPermission | None]:
        """Retrieve grants by ids, scoped by ``perm_filter``; positionally
        aligned, ``None`` where missing or out of scope."""
        if not role_sandbox_snapshot_permission_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(RoleSandboxSnapshotPermission).where(
                RoleSandboxSnapshotPermission.id.in_(role_sandbox_snapshot_permission_ids)
            )
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, RoleSandboxSnapshotPermission] = {
            link.id: link for link in result.scalars().all()
        }
        return [by_id.get(lid) for lid in role_sandbox_snapshot_permission_ids]

    async def search_role_sandbox_snapshot_permissions(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: RoleSandboxSnapshotPermissionSearchFilter | None = None,
    ) -> tuple[list[RoleSandboxSnapshotPermission], uuid.UUID | None]:
        """Search grants ordered by id, keyed-pagination via cursor, scoped by
        ``perm_filter``."""
        stmt = self._perm_filter.filter_sql(
            select(RoleSandboxSnapshotPermission).order_by(RoleSandboxSnapshotPermission.id)
        )
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(RoleSandboxSnapshotPermission.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        links = list(result.scalars().all())
        next_cursor = links[-1].id if len(links) == limit else None
        return links, next_cursor

    async def count(
        self, search_filter: RoleSandboxSnapshotPermissionSearchFilter | None = None
    ) -> int:
        """Total grant count, scoped by ``perm_filter`` and the optional
        *search_filter*."""
        stmt = self._perm_filter.filter_sql(
            select(func.count()).select_from(RoleSandboxSnapshotPermission)
        )
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def update(
        self,
        role_sandbox_snapshot_permission_id: uuid.UUID,
        payload: RoleSandboxSnapshotPermissionUpdate,
    ) -> RoleSandboxSnapshotPermission:
        """Toggle the read/update/delete flags on a grant. Raises if missing or
        out of the principal's scope."""
        link = await self.get(role_sandbox_snapshot_permission_id)
        if payload.read_enabled is not None:
            link.read_enabled = payload.read_enabled
        if payload.update_enabled is not None:
            link.update_enabled = payload.update_enabled
        if payload.delete_enabled is not None:
            link.delete_enabled = payload.delete_enabled
        await self._session.flush()
        await self._session.refresh(link)
        return link

    async def delete(self, role_sandbox_snapshot_permission_id: uuid.UUID) -> None:
        """Delete a grant. Raises
        :class:`RoleSandboxSnapshotPermissionNotFoundError` if missing."""
        link = await self.get(role_sandbox_snapshot_permission_id)
        await self._session.delete(link)
        await self._session.flush()

    async def apply_batch(
        self,
        operations: list[RoleSandboxSnapshotPermissionBatchOp],
        perm_filters: dict[Action, SearchFilter[RoleSandboxSnapshotPermission] | None],
    ) -> list[RoleSandboxSnapshotPermission | None]:
        """Apply a mix of create/update/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation. No commit is performed — the
        caller commits once after the whole batch succeeds (atomic). Returns
        results aligned with *operations*: the grant for create/update,
        ``None`` for delete.
        """
        results: list[RoleSandboxSnapshotPermission | None] = []
        for op in operations:
            if isinstance(op, RoleSandboxSnapshotPermissionBatchCreate):
                filt = perm_filters.get(Action.CREATE)
                if filt is None:
                    raise BatchPermissionDeniedError("create")
                d = op.data
                results.append(
                    await RoleSandboxSnapshotPermissionService(self._session, filt).create(
                        role_id=d.role_id,
                        sandbox_snapshot_id=d.sandbox_snapshot_id,
                        read_enabled=d.read_enabled,
                        update_enabled=d.update_enabled,
                        delete_enabled=d.delete_enabled,
                    )
                )
            elif isinstance(op, RoleSandboxSnapshotPermissionBatchUpdate):
                filt = perm_filters.get(Action.UPDATE)
                if filt is None:
                    raise BatchPermissionDeniedError("update")
                results.append(
                    await RoleSandboxSnapshotPermissionService(self._session, filt).update(
                        op.id, op.data
                    )
                )
            elif isinstance(op, RoleSandboxSnapshotPermissionBatchDelete):
                filt = perm_filters.get(Action.DELETE)
                if filt is None:
                    raise BatchPermissionDeniedError("delete")
                await RoleSandboxSnapshotPermissionService(self._session, filt).delete(op.id)
                results.append(None)
        return results


def _classify_integrity_error(
    exc: IntegrityError,
    role_id: uuid.UUID,
    sandbox_snapshot_id: uuid.UUID,
) -> Exception:
    """Map an IntegrityError to a duplicate vs orphan failure.

    A violation of ``uq_role_sandbox_snap_perm_role_sandbox_snap``
    means the grant already exists; a foreign-key violation means the referenced
    role or sandbox snapshot is missing.
    """
    message = str(getattr(exc, "orig", exc)).lower()
    if "uq_role_sandbox_snap_perm_role_sandbox_snap" in message or (
        "unique constraint" in message and "role_sandbox_snapshot_permissions" in message
    ):
        return RoleSandboxSnapshotPermissionConflictError(f"{role_id}/{sandbox_snapshot_id}")
    if "foreign key" in message or "fk_" in message:
        if "sandbox_snapshot_id" in message and "role_id" not in message:
            return RoleSandboxSnapshotPermissionOrphanError(
                f"sandbox snapshot {sandbox_snapshot_id} does not exist"
            )
        return RoleSandboxSnapshotPermissionOrphanError(f"role {role_id} does not exist")
    return RoleSandboxSnapshotPermissionConflictError(f"{role_id}/{sandbox_snapshot_id}")


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted to the principal."""


__all__ = [
    "BatchPermissionDeniedError",
    "RoleSandboxSnapshotPermission",
    "RoleSandboxSnapshotPermissionConflictError",
    "RoleSandboxSnapshotPermissionNotFoundError",
    "RoleSandboxSnapshotPermissionOrphanError",
    "RoleSandboxSnapshotPermissionScopeError",
    "RoleSandboxSnapshotPermissionService",
]
