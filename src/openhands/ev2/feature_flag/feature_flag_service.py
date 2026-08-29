"""Service layer for the feature_flag feature.

CRUD over :class:`FeatureFlag` (governed by the ``feature_flag_permission``
role column) and :class:`FeatureFlagRole` (the per-role override link table,
governed by the ``feature_flag_role_permission`` role column). Services contain
business logic; the effective ``perm_filter`` is held as a field, set at
construction, so search/update/delete SQL and create payloads are scoped to the
principal (AGENTS.md §9 — authorization enforced in services, not just routers).

Feature-flag ids are caller-supplied strings; the service surfaces a
:class:`FeatureFlagConflictError` on a duplicate id (primary-key collision).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.feature_flag.feature_flag_models import FeatureFlag, FeatureFlagRole
from openhands.ev2.feature_flag.feature_flag_schemas import (
    FeatureFlagBatchCreate,
    FeatureFlagBatchDelete,
    FeatureFlagBatchOp,
    FeatureFlagBatchUpdate,
    FeatureFlagCreate,
    FeatureFlagRoleBatchCreate,
    FeatureFlagRoleBatchDelete,
    FeatureFlagRoleBatchOp,
    FeatureFlagRoleCreate,
    FeatureFlagRoleSearchFilter,
    FeatureFlagSearchFilter,
    FeatureFlagUpdate,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL_SEARCH_FILTER, SearchFilter

# ---------------------------------------------------------------------- #
# Errors
# ---------------------------------------------------------------------- #


class FeatureFlagNotFoundError(Exception):
    """Raised when a feature flag id does not exist (or is out of scope)."""


class FeatureFlagConflictError(Exception):
    """Raised when a create collides with an existing id."""


class FeatureFlagPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class FeatureFlagRoleNotFoundError(Exception):
    """Raised when a feature-flag role override id does not exist."""


class FeatureFlagRoleConflictError(Exception):
    """Raised when an override already exists for the (feature_flag_id, role_id) pair."""


class FeatureFlagRoleOrphanError(Exception):
    """Raised when the referenced feature flag or role does not exist."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted to the principal."""


# ---------------------------------------------------------------------- #
# Feature flag service
# ---------------------------------------------------------------------- #


class FeatureFlagService:
    """CRUD operations over feature flags.

    The service is constructed per request with the request-scoped session and
    the principal's effective ``perm_filter``; it holds no other mutable state.
    """

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[FeatureFlag] = ALL_SEARCH_FILTER,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(self, payload: FeatureFlagCreate) -> FeatureFlag:
        """Create a feature flag.

        Raises :class:`FeatureFlagPermissionScopeError` if the prospective flag
        does not satisfy the service's ``perm_filter`` (the principal's create
        scope), and :class:`FeatureFlagConflictError` on a duplicate id.
        """
        flag = FeatureFlag(
            id=payload.id,
            enabled=payload.enabled,
            description=payload.description,
        )
        if not self._perm_filter.matches(flag):
            raise FeatureFlagPermissionScopeError(str(payload.id))
        self._session.add(flag)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_flag_integrity_error(exc, payload.id) from exc
        await self._session.refresh(flag)
        return flag

    async def get(self, flag_id: str) -> FeatureFlag:
        """Retrieve a feature flag by id, scoped by ``perm_filter``.

        Raises :class:`FeatureFlagNotFoundError` if the flag is missing or out
        of the principal's scope (so callers return 404 without leaking
        existence).
        """
        stmt = self._perm_filter.filter_sql(select(FeatureFlag).where(FeatureFlag.id == flag_id))
        result = await self._session.execute(stmt)
        flag = result.scalar_one_or_none()
        if flag is None:
            raise FeatureFlagNotFoundError(str(flag_id))
        return flag

    async def get_many(self, flag_ids: list[str]) -> list[FeatureFlag | None]:
        """Retrieve feature flags by ids in a single query, scoped by ``perm_filter``.

        Returns a list positionally aligned with *flag_ids*: the i-th entry is
        the :class:`FeatureFlag` for ``flag_ids[i]`` or ``None`` when
        missing/out of scope. Duplicate ids are preserved. An empty
        *flag_ids* yields an empty list without hitting the DB.
        """
        if not flag_ids:
            return []
        stmt = self._perm_filter.filter_sql(select(FeatureFlag).where(FeatureFlag.id.in_(flag_ids)))
        result = await self._session.execute(stmt)
        by_id: dict[str, FeatureFlag] = {f.id: f for f in result.scalars().all()}
        return [by_id.get(fid) for fid in flag_ids]

    async def search(
        self,
        *,
        cursor: str | None = None,
        limit: int = 50,
        search_filter: FeatureFlagSearchFilter | None = None,
    ) -> tuple[list[FeatureFlag], str | None]:
        """Search feature flags ordered by id, keyed-pagination via cursor.

        The service's ``perm_filter`` scopes the SQL to rows the principal may
        see; the optional *search_filter* (from query params) is ANDed on top.
        Returns (flags, next_cursor). next_cursor is None when exhausted.
        """
        stmt = self._perm_filter.filter_sql(select(FeatureFlag).order_by(FeatureFlag.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(FeatureFlag.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        flags = list(result.scalars().all())
        next_cursor = flags[-1].id if len(flags) == limit else None
        return flags, next_cursor

    async def update(self, flag_id: str, payload: FeatureFlagUpdate) -> FeatureFlag:
        """Partially update a feature flag. Raises on missing/scoped-out flag."""
        flag = await self.get(flag_id)
        if payload.enabled is not None:
            flag.enabled = payload.enabled
        if payload.description is not None:
            flag.description = payload.description
        await self._session.flush()
        await self._session.refresh(flag)
        return flag

    async def delete(self, flag_id: str) -> None:
        """Delete a feature flag. Cascades to its role overrides.

        Raises :class:`FeatureFlagNotFoundError` if missing or out of scope.
        """
        flag = await self.get(flag_id)
        await self._session.delete(flag)
        await self._session.flush()

    async def count(self, search_filter: FeatureFlagSearchFilter | None = None) -> int:
        """Total feature-flag count, scoped by the service's ``perm_filter`` and
        the optional *search_filter* (the same query-param filter the collection
        endpoint accepts)."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(FeatureFlag))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def apply_batch(
        self,
        operations: list[FeatureFlagBatchOp],
        perm_filters: dict[Action, SearchFilter[FeatureFlag] | None],
    ) -> list[FeatureFlag | None]:
        """Apply a mix of create/update/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic). Returns
        results aligned with *operations*: the flag for create/update, ``None``
        for delete.
        """
        results: list[FeatureFlag | None] = []
        for op in operations:
            if isinstance(op, FeatureFlagBatchCreate):
                results.append(await self._batch_create(op, perm_filters))
            elif isinstance(op, FeatureFlagBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, FeatureFlagBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: FeatureFlagBatchCreate,
        perm_filters: dict[Action, SearchFilter[FeatureFlag] | None],
    ) -> FeatureFlag:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        return await FeatureFlagService(self._session, filt).create(op.data)

    async def _batch_update(
        self,
        op: FeatureFlagBatchUpdate,
        perm_filters: dict[Action, SearchFilter[FeatureFlag] | None],
    ) -> FeatureFlag:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await FeatureFlagService(self._session, filt).update(op.id, op.data)

    async def _batch_delete(
        self,
        op: FeatureFlagBatchDelete,
        perm_filters: dict[Action, SearchFilter[FeatureFlag] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await FeatureFlagService(self._session, filt).delete(op.id)


def _classify_flag_integrity_error(exc: IntegrityError, flag_id: str) -> Exception:
    """Map an IntegrityError on feature_flags to a duplicate-id conflict.

    A primary-key violation means the id already exists
    (:class:`FeatureFlagConflictError`); anything else is treated as a conflict
    for surfacing (there are no other unique constraints on this table).
    """
    return FeatureFlagConflictError(flag_id)


# ---------------------------------------------------------------------- #
# Feature flag role override service
# ---------------------------------------------------------------------- #


class FeatureFlagRoleService:
    """CRUD over the ``feature_flag_roles`` link table (per-role overrides).

    Overrides are immutable; there is no update — delete and re-create to
    change (mirroring ``user_roles``). The service takes a ``perm_filter`` so
    the override rows are scoped to the principal's
    ``feature_flag_role_permission`` grant.
    """

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[FeatureFlagRole] = ALL_SEARCH_FILTER,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(self, payload: FeatureFlagRoleCreate) -> FeatureFlagRole:
        """Attach a role override to a feature flag.

        Raises :class:`FeatureFlagRoleConflictError` on a duplicate
        ``(feature_flag_id, role_id)`` pair, and
        :class:`FeatureFlagRoleOrphanError` if the feature flag or role does
        not exist.
        """
        link = FeatureFlagRole(
            feature_flag_id=payload.feature_flag_id,
            role_id=payload.role_id,
        )
        if not self._perm_filter.matches(link):
            raise FeatureFlagRoleOrphanError(str(payload.feature_flag_id))
        self._session.add(link)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_override_integrity_error(
                exc, payload.feature_flag_id, payload.role_id
            ) from exc
        await self._session.refresh(link)
        return link

    async def get(self, override_id: uuid.UUID) -> FeatureFlagRole:
        """Retrieve an override by id, scoped by ``perm_filter``.

        Raises :class:`FeatureFlagRoleNotFoundError` if missing or out of scope.
        """
        stmt = self._perm_filter.filter_sql(
            select(FeatureFlagRole).where(FeatureFlagRole.id == override_id)
        )
        result = await self._session.execute(stmt)
        link = result.scalar_one_or_none()
        if link is None:
            raise FeatureFlagRoleNotFoundError(str(override_id))
        return link

    async def get_many(self, override_ids: list[uuid.UUID]) -> list[FeatureFlagRole | None]:
        """Retrieve overrides by ids in a single query, scoped by ``perm_filter``.

        Returns a list positionally aligned with *override_ids*: the i-th entry
        is the :class:`FeatureFlagRole` for ``override_ids[i]`` or ``None`` when
        missing/out of scope. Duplicate ids are preserved. An empty
        *override_ids* yields an empty list without hitting the DB.
        """
        if not override_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(FeatureFlagRole).where(FeatureFlagRole.id.in_(override_ids))
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, FeatureFlagRole] = {link.id: link for link in result.scalars().all()}
        return [by_id.get(oid) for oid in override_ids]

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: FeatureFlagRoleSearchFilter | None = None,
    ) -> tuple[list[FeatureFlagRole], uuid.UUID | None]:
        """Search overrides ordered by id, keyed-pagination via cursor.

        The service's ``perm_filter`` scopes the SQL to rows the principal may
        see; the optional *search_filter* (from query params) is ANDed on top.
        Returns (overrides, next_cursor). next_cursor is None when exhausted.
        """
        stmt = self._perm_filter.filter_sql(select(FeatureFlagRole).order_by(FeatureFlagRole.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(FeatureFlagRole.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        links = list(result.scalars().all())
        next_cursor = links[-1].id if len(links) == limit else None
        return links, next_cursor

    async def delete(self, override_id: uuid.UUID) -> None:
        """Delete an override. Raises if missing or out of scope."""
        link = await self.get(override_id)
        await self._session.delete(link)
        await self._session.flush()

    async def count(self, search_filter: FeatureFlagRoleSearchFilter | None = None) -> int:
        """Total override count, scoped by the service's ``perm_filter`` and the
        optional *search_filter*."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(FeatureFlagRole))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def apply_batch(
        self,
        operations: list[FeatureFlagRoleBatchOp],
        perm_filters: dict[Action, SearchFilter[FeatureFlagRole] | None],
    ) -> list[FeatureFlagRole | None]:
        """Apply a mix of create/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic). Returns
        results aligned with *operations*: the created override for create ops,
        ``None`` for delete ops.
        """
        results: list[FeatureFlagRole | None] = []
        for op in operations:
            if isinstance(op, FeatureFlagRoleBatchCreate):
                results.append(await self._batch_create(op, perm_filters))
            elif isinstance(op, FeatureFlagRoleBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: FeatureFlagRoleBatchCreate,
        perm_filters: dict[Action, SearchFilter[FeatureFlagRole] | None],
    ) -> FeatureFlagRole:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        return await FeatureFlagRoleService(self._session, filt).create(op.data)

    async def _batch_delete(
        self,
        op: FeatureFlagRoleBatchDelete,
        perm_filters: dict[Action, SearchFilter[FeatureFlagRole] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await FeatureFlagRoleService(self._session, filt).delete(op.id)


def _classify_override_integrity_error(
    exc: IntegrityError,
    feature_flag_id: str,
    role_id: uuid.UUID,
) -> Exception:
    """Map an IntegrityError to a duplicate vs orphan failure.

    A violation of the ``uq_feature_flag_roles_flag_id_role_id`` unique
    constraint means the override already exists
    (:class:`FeatureFlagRoleConflictError``); a foreign-key violation means the
    referenced feature flag or role is missing
    (:class:`FeatureFlagRoleOrphanError``). asyncpg surfaces the constraint name
    in the error message; distinguish by it.
    """
    message = str(getattr(exc, "orig", exc)).lower()
    if "uq_feature_flag_roles_flag_id_role_id" in message or (
        "unique constraint" in message and "feature_flag_roles" in message
    ):
        return FeatureFlagRoleConflictError(f"{feature_flag_id}/{role_id}")
    if "foreign key" in message or "fk_" in message:
        if "role_id" in message and "feature_flag_id" not in message:
            return FeatureFlagRoleOrphanError(f"role {role_id} does not exist")
        return FeatureFlagRoleOrphanError(f"feature flag {feature_flag_id} does not exist")
    # Default to conflict for any unrecognized integrity error on this table.
    return FeatureFlagRoleConflictError(f"{feature_flag_id}/{role_id}")


__all__ = [
    "BatchPermissionDeniedError",
    "FeatureFlagConflictError",
    "FeatureFlagNotFoundError",
    "FeatureFlagPermissionScopeError",
    "FeatureFlagRoleConflictError",
    "FeatureFlagRoleNotFoundError",
    "FeatureFlagRoleOrphanError",
    "FeatureFlagRoleService",
    "FeatureFlagService",
]
