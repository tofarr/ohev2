"""Service layer for the role-secret-permission grant feature (the ``role_secret_permissions`` table).

CRUD for the per-role grant link table between :class:`Role` and
:class:`Secret`. Unlike the immutable ``user_roles`` link, a ``role_secret_permissions``
row is mutable: :meth:`update` toggles the ``read_enabled`` /
``update_enabled`` / ``delete_enabled`` flags to change what the role may do
with the secret without dropping and re-creating the grant.

The link table is a governed resource of its own (``secret_grant_permission``
on :class:`Role`): the service holds the effective ``perm_filter`` and scopes
every read/write through it (AGENTS.md §9 — authorization enforced in
services, not just routers). Managing grants is deliberately *not* implied by
``role_permission`` update — a principal who may edit a role's metadata must
not be able to grant that role access to arbitrary secrets (that would be
privilege escalation / secret exfiltration).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.secret.role_secret_permission_schemas import (
    RoleSecretPermissionBatchCreate,
    RoleSecretPermissionBatchDelete,
    RoleSecretPermissionBatchOp,
    RoleSecretPermissionBatchUpdate,
    RoleSecretPermissionSearchFilter,
    RoleSecretPermissionUpdate,
)
from openhands.ev2.secret.secret_models import RoleSecretPermission
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter


class RoleSecretPermissionNotFoundError(Exception):
    """Raised when a role-secret-permission grant id does not exist."""


class RoleSecretPermissionConflictError(Exception):
    """Raised when a grant already exists for the (role_id, secret_id) pair."""


class RoleSecretPermissionOrphanError(Exception):
    """Raised when the referenced role or secret does not exist."""


class RoleSecretPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted to the principal."""


class RoleSecretPermissionService:
    """CRUD operations over role-secret-permission grants.

    Constructed per request with the request-scoped session and the principal's
    effective ``perm_filter`` (reduced from ``secret_grant_permission``); it
    holds no other mutable state.
    """

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[RoleSecretPermission] = ALL,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(
        self,
        *,
        role_id: uuid.UUID,
        secret_id: uuid.UUID,
        read_enabled: bool = False,
        update_enabled: bool = False,
        delete_enabled: bool = False,
    ) -> RoleSecretPermission:
        """Grant a role access to a secret. Raises on duplicate or orphan FK,
        and :class:`RoleSecretPermissionScopeError` if the grant falls outside
        the principal's create scope."""
        link = RoleSecretPermission(
            role_id=role_id,
            secret_id=secret_id,
            read_enabled=read_enabled,
            update_enabled=update_enabled,
            delete_enabled=delete_enabled,
        )
        if not self._perm_filter.matches(link):
            raise RoleSecretPermissionScopeError(f"{role_id}/{secret_id}")
        self._session.add(link)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_integrity_error(exc, role_id, secret_id) from exc
        await self._session.refresh(link)
        return link

    async def get(self, role_secret_permission_id: uuid.UUID) -> RoleSecretPermission:
        """Retrieve a grant by id, scoped by ``perm_filter``.

        Raises :class:`RoleSecretPermissionNotFoundError` if the grant is
        missing or out of the principal's scope (so callers return 404 without
        leaking existence).
        """
        stmt = self._perm_filter.filter_sql(
            select(RoleSecretPermission).where(RoleSecretPermission.id == role_secret_permission_id)
        )
        result = await self._session.execute(stmt)
        link = result.scalar_one_or_none()
        if link is None:
            raise RoleSecretPermissionNotFoundError(str(role_secret_permission_id))
        return link

    async def get_many(
        self, role_secret_permission_ids: list[uuid.UUID]
    ) -> list[RoleSecretPermission | None]:
        """Retrieve grants by ids, scoped by ``perm_filter``; positionally
        aligned, ``None`` where missing or out of scope."""
        if not role_secret_permission_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(RoleSecretPermission).where(
                RoleSecretPermission.id.in_(role_secret_permission_ids)
            )
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, RoleSecretPermission] = {
            link.id: link for link in result.scalars().all()
        }
        return [by_id.get(lid) for lid in role_secret_permission_ids]

    async def search_role_secret_permissions(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: RoleSecretPermissionSearchFilter | None = None,
    ) -> tuple[list[RoleSecretPermission], uuid.UUID | None]:
        """Search grants ordered by id, keyed-pagination via cursor, scoped by
        ``perm_filter``."""
        stmt = self._perm_filter.filter_sql(
            select(RoleSecretPermission).order_by(RoleSecretPermission.id)
        )
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(RoleSecretPermission.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        links = list(result.scalars().all())
        next_cursor = links[-1].id if len(links) == limit else None
        return links, next_cursor

    async def count(self, search_filter: RoleSecretPermissionSearchFilter | None = None) -> int:
        """Total grant count, scoped by ``perm_filter`` and the optional
        *search_filter*."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(RoleSecretPermission))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def update(
        self, role_secret_permission_id: uuid.UUID, payload: RoleSecretPermissionUpdate
    ) -> RoleSecretPermission:
        """Toggle the read/update/delete flags on a grant. Raises if missing or
        out of the principal's scope."""
        link = await self.get(role_secret_permission_id)
        if payload.read_enabled is not None:
            link.read_enabled = payload.read_enabled
        if payload.update_enabled is not None:
            link.update_enabled = payload.update_enabled
        if payload.delete_enabled is not None:
            link.delete_enabled = payload.delete_enabled
        await self._session.flush()
        await self._session.refresh(link)
        return link

    async def delete(self, role_secret_permission_id: uuid.UUID) -> None:
        """Delete a grant. Raises :class:`RoleSecretPermissionNotFoundError` if missing."""
        link = await self.get(role_secret_permission_id)
        await self._session.delete(link)
        await self._session.flush()

    async def apply_batch(
        self,
        operations: list[RoleSecretPermissionBatchOp],
        perm_filters: dict[Action, SearchFilter[RoleSecretPermission] | None],
    ) -> list[RoleSecretPermission | None]:
        """Apply a mix of create/update/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic). Returns
        results aligned with *operations*: the grant for create/update,
        ``None`` for delete.
        """
        results: list[RoleSecretPermission | None] = []
        for op in operations:
            if isinstance(op, RoleSecretPermissionBatchCreate):
                filt = perm_filters.get(Action.CREATE)
                if filt is None:
                    raise BatchPermissionDeniedError("create")
                d = op.data
                results.append(
                    await RoleSecretPermissionService(self._session, filt).create(
                        role_id=d.role_id,
                        secret_id=d.secret_id,
                        read_enabled=d.read_enabled,
                        update_enabled=d.update_enabled,
                        delete_enabled=d.delete_enabled,
                    )
                )
            elif isinstance(op, RoleSecretPermissionBatchUpdate):
                filt = perm_filters.get(Action.UPDATE)
                if filt is None:
                    raise BatchPermissionDeniedError("update")
                results.append(
                    await RoleSecretPermissionService(self._session, filt).update(op.id, op.data)
                )
            elif isinstance(op, RoleSecretPermissionBatchDelete):
                filt = perm_filters.get(Action.DELETE)
                if filt is None:
                    raise BatchPermissionDeniedError("delete")
                await RoleSecretPermissionService(self._session, filt).delete(op.id)
                results.append(None)
        return results


def _classify_integrity_error(
    exc: IntegrityError,
    role_id: uuid.UUID,
    secret_id: uuid.UUID,
) -> Exception:
    """Map an IntegrityError to a duplicate vs orphan failure.

    A violation of ``uq_role_secret_permissions_role_id_secret_id`` means the grant
    already exists; a foreign-key violation means the referenced role or
    secret is missing. asyncpg surfaces the constraint name in the message.
    """
    message = str(getattr(exc, "orig", exc)).lower()
    if "uq_role_secret_permissions_role_id_secret_id" in message or (
        "unique constraint" in message and "role_secret_permissions" in message
    ):
        return RoleSecretPermissionConflictError(f"{role_id}/{secret_id}")
    if "foreign key" in message or "fk_" in message:
        if "secret_id" in message and "role_id" not in message:
            return RoleSecretPermissionOrphanError(f"secret {secret_id} does not exist")
        return RoleSecretPermissionOrphanError(f"role {role_id} does not exist")
    return RoleSecretPermissionConflictError(f"{role_id}/{secret_id}")


__all__ = [
    "BatchPermissionDeniedError",
    "RoleSecretPermission",
    "RoleSecretPermissionConflictError",
    "RoleSecretPermissionNotFoundError",
    "RoleSecretPermissionOrphanError",
    "RoleSecretPermissionScopeError",
    "RoleSecretPermissionService",
]
