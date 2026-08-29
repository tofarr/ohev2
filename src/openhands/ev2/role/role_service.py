"""Service layer for the role feature.

Services contain business logic; repositories contain data access. This module
exposes a thin ``RoleService`` over SQLAlchemy async sessions per AGENTS.md §4.
The service holds the effective ``perm_filter`` (the search filter from the
centralized permission checker) as a field, set at construction, that scopes
the SQL to rows the principal is allowed to see/modify; :meth:`create` validates
the incoming item against it in memory (AGENTS.md §9 — authorization enforced
in services, not just routers).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.role.role_models import Role
from openhands.ev2.role.role_schemas import (
    RoleBatchCreate,
    RoleBatchDelete,
    RoleBatchOp,
    RoleBatchUpdate,
    RoleCreate,
    RoleSearchFilter,
    RoleUpdate,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL_SEARCH_FILTER, SearchFilter


class RoleNotFoundError(Exception):
    """Raised when a role id does not exist."""


class RoleNameConflictError(Exception):
    """Raised when a create/update collides with an existing name."""


class RolePermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted to the principal."""


class RoleService:
    """CRUD operations over roles.

    The service is constructed per request with the request-scoped session and
    the principal's effective ``perm_filter``; it holds no other mutable state.
    """

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[Role] = ALL_SEARCH_FILTER,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(self, payload: RoleCreate) -> Role:
        """Create a role. Raises RoleNameConflictError on duplicate name.

        Raises :class:`RolePermissionScopeError` if the prospective role does
        not satisfy the service's ``perm_filter`` (the principal's create scope).
        """
        role = Role(
            name=payload.name,
            user_permission=payload.user_permission,
            role_permission=payload.role_permission,
            user_role_permission=payload.user_role_permission,
            api_key_permission=payload.api_key_permission,
            oauth_client_permission=payload.oauth_client_permission,
            cors_origin_permission=payload.cors_origin_permission,
            provider_connection_permission=payload.provider_connection_permission,
            llm_permission=payload.llm_permission,
            feature_flag_permission=payload.feature_flag_permission,
            feature_flag_role_permission=payload.feature_flag_role_permission,
        )
        if not self._perm_filter.matches(role):
            raise RolePermissionScopeError(str(payload.name))
        self._session.add(role)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_integrity_error(exc, payload) from exc
        await self._session.refresh(role)
        return role

    async def get(self, role_id: uuid.UUID) -> Role:
        """Retrieve a role by id, scoped by ``perm_filter``.

        Raises :class:`RoleNotFoundError` if the role is missing or out of the
        principal's scope (so callers return 404 without leaking existence).
        """
        stmt = self._perm_filter.filter_sql(select(Role).where(Role.id == role_id))
        result = await self._session.execute(stmt)
        role = result.scalar_one_or_none()
        if role is None:
            raise RoleNotFoundError(str(role_id))
        return role

    async def get_many(
        self,
        role_ids: list[uuid.UUID],
    ) -> list[Role | None]:
        """Retrieve roles by ids in a single query, scoped by ``perm_filter``.

        Returns a list positionally aligned with *role_ids*: the i-th entry is
        the :class:`Role` for ``role_ids[i]`` or ``None`` when missing/out of
        scope. Duplicate ids are preserved. An empty *role_ids* yields an empty
        list without hitting the DB.
        """
        if not role_ids:
            return []
        stmt = self._perm_filter.filter_sql(select(Role).where(Role.id.in_(role_ids)))
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, Role] = {r.id: r for r in result.scalars().all()}
        return [by_id.get(rid) for rid in role_ids]

    async def search_roles(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: RoleSearchFilter | None = None,
    ) -> tuple[list[Role], uuid.UUID | None]:
        """Search roles ordered by id, keyed-pagination via cursor.

        The service's ``perm_filter`` scopes the SQL to rows the principal may
        see; the optional *search_filter* (from query params) is ANDed on top.
        Returns (roles, next_cursor). next_cursor is None when exhausted.
        """
        stmt = self._perm_filter.filter_sql(select(Role).order_by(Role.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(Role.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        roles = list(result.scalars().all())
        next_cursor = roles[-1].id if len(roles) == limit else None
        return roles, next_cursor

    async def update(self, role_id: uuid.UUID, payload: RoleUpdate) -> Role:
        """Partially update a role. Raises on missing/scoped-out role or name conflict."""
        role = await self.get(role_id)
        if payload.name is not None:
            role.name = payload.name
        if payload.user_permission is not None:
            role.user_permission = payload.user_permission
        if payload.role_permission is not None:
            role.role_permission = payload.role_permission
        if payload.user_role_permission is not None:
            role.user_role_permission = payload.user_role_permission
        if payload.api_key_permission is not None:
            role.api_key_permission = payload.api_key_permission
        if payload.oauth_client_permission is not None:
            role.oauth_client_permission = payload.oauth_client_permission
        if payload.cors_origin_permission is not None:
            role.cors_origin_permission = payload.cors_origin_permission
        if payload.provider_connection_permission is not None:
            role.provider_connection_permission = payload.provider_connection_permission
        if payload.llm_permission is not None:
            role.llm_permission = payload.llm_permission
        if payload.feature_flag_permission is not None:
            role.feature_flag_permission = payload.feature_flag_permission
        if payload.feature_flag_role_permission is not None:
            role.feature_flag_role_permission = payload.feature_flag_role_permission
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_integrity_error(exc, payload) from exc
        await self._session.refresh(role)
        return role

    async def delete(self, role_id: uuid.UUID) -> None:
        """Delete a role. Raises RoleNotFoundError if missing or out of scope."""
        role = await self.get(role_id)
        await self._session.delete(role)
        await self._session.flush()

    async def apply_batch(
        self,
        operations: list[RoleBatchOp],
        perm_filters: dict[Action, SearchFilter[Role] | None],
    ) -> list[Role | None]:
        """Apply a mix of create/update/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic). Returns
        results aligned with *operations*: the role for create/update, ``None``
        for delete.
        """
        results: list[Role | None] = []
        for op in operations:
            if isinstance(op, RoleBatchCreate):
                results.append(await self._batch_create(op, perm_filters))
            elif isinstance(op, RoleBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, RoleBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: RoleBatchCreate,
        perm_filters: dict[Action, SearchFilter[Role] | None],
    ) -> Role:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        return await RoleService(self._session, filt).create(op.data)

    async def _batch_update(
        self,
        op: RoleBatchUpdate,
        perm_filters: dict[Action, SearchFilter[Role] | None],
    ) -> Role:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await RoleService(self._session, filt).update(op.id, op.data)

    async def _batch_delete(
        self,
        op: RoleBatchDelete,
        perm_filters: dict[Action, SearchFilter[Role] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await RoleService(self._session, filt).delete(op.id)

    async def count(
        self,
        search_filter: RoleSearchFilter | None = None,
    ) -> int:
        """Total role count, scoped by the service's ``perm_filter`` and the
        optional *search_filter* (the same query-param filter the collection
        endpoint accepts)."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(Role))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())


def _classify_integrity_error(
    exc: IntegrityError,
    payload: RoleCreate | RoleUpdate,
) -> Exception:
    """Map a unique-constraint IntegrityError to the right domain conflict.

    asyncpg does not expose a structured constraint name on the DBAPI
    exception; the constraint name appears in the error message
    (``... violates unique constraint "..."``). Match by it so callers see
    ``RoleNameConflictError``.
    """
    _ = str(getattr(exc, "orig", exc)).lower()
    return RoleNameConflictError(getattr(payload, "name", None) or "")


__all__ = [
    "BatchPermissionDeniedError",
    "Role",
    "RoleNameConflictError",
    "RoleNotFoundError",
    "RolePermissionScopeError",
    "RoleService",
]
