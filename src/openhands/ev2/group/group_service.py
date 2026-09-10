"""Service layer for the group feature.

CRUD over :class:`Group` (governed by the ``group_permission`` role column)
and :class:`GroupUser` (the ``group_users`` membership link table, governed by
``group_user_permission``). Services contain business logic; the effective
``perm_filter`` is held as a field, set at construction, so search/update/
delete SQL and create payloads are scoped to the principal (AGENTS.md §9 —
authorization enforced in services, not just routers).

``creator_id`` on both resources is the authenticated principal; it is passed
into the service from the router (never read from the payload) so a principal
can only create groups/memberships attributed to themselves.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.group.group_models import Group, GroupUser
from openhands.ev2.group.group_schemas import (
    GroupBatchCreate,
    GroupBatchDelete,
    GroupBatchOp,
    GroupBatchUpdate,
    GroupCreate,
    GroupSearchFilter,
    GroupUpdate,
    GroupUserBatchCreate,
    GroupUserBatchDelete,
    GroupUserBatchOp,
    GroupUserCreate,
    GroupUserSearchFilter,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter

# ---------------------------------------------------------------------- #
# Errors
# ---------------------------------------------------------------------- #


class GroupNotFoundError(Exception):
    """Raised when a group id does not exist (or is out of scope)."""


class GroupPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class GroupUserNotFoundError(Exception):
    """Raised when a group-user membership id does not exist."""


class GroupUserConflictError(Exception):
    """Raised when a membership already exists for the (group_id, user_id) pair."""


class GroupUserOrphanError(Exception):
    """Raised when the referenced group or user does not exist."""


class GroupUserPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted to the principal."""


# ---------------------------------------------------------------------- #
# Group service
# ---------------------------------------------------------------------- #


class GroupService:
    """CRUD operations over groups.

    Constructed per request with the request-scoped session and the principal's
    effective ``perm_filter``; it holds no other mutable state.
    """

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[Group] = ALL,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(self, payload: GroupCreate, *, creator_id: uuid.UUID) -> Group:
        """Create a group.

        Raises :class:`GroupPermissionScopeError` if the prospective group does
        not satisfy the service's ``perm_filter`` (the principal's create scope).
        """
        group = Group(
            name=payload.name,
            description=payload.description,
            creator_id=creator_id,
        )
        if not self._perm_filter.matches(group):
            raise GroupPermissionScopeError(str(payload.name))
        self._session.add(group)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_group_integrity_error(exc, payload.name) from exc
        await self._session.refresh(group)
        return group

    async def get(self, group_id: uuid.UUID) -> Group:
        """Retrieve a group by id, scoped by ``perm_filter``.

        Raises :class:`GroupNotFoundError` if the group is missing or out of the
        principal's scope (so callers return 404 without leaking existence).
        """
        stmt = self._perm_filter.filter_sql(select(Group).where(Group.id == group_id))
        result = await self._session.execute(stmt)
        group = result.scalar_one_or_none()
        if group is None:
            raise GroupNotFoundError(str(group_id))
        return group

    async def get_many(self, group_ids: list[uuid.UUID]) -> list[Group | None]:
        """Retrieve groups by ids in a single query, scoped by ``perm_filter``.

        Returns a list positionally aligned with *group_ids*: the i-th entry is
        the :class:`Group` for ``group_ids[i]`` or ``None`` when missing/out of
        scope. Duplicate ids are preserved. An empty *group_ids* yields an empty
        list without hitting the DB.
        """
        if not group_ids:
            return []
        stmt = self._perm_filter.filter_sql(select(Group).where(Group.id.in_(group_ids)))
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, Group] = {g.id: g for g in result.scalars().all()}
        return [by_id.get(gid) for gid in group_ids]

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: GroupSearchFilter | None = None,
    ) -> tuple[list[Group], uuid.UUID | None]:
        """Search groups ordered by id, keyed-pagination via cursor.

        The service's ``perm_filter`` scopes the SQL to rows the principal may
        see; the optional *search_filter* (from query params) is ANDed on top.
        Returns (groups, next_cursor). next_cursor is None when exhausted.
        """
        stmt = self._perm_filter.filter_sql(select(Group).order_by(Group.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(Group.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        groups = list(result.scalars().all())
        next_cursor = groups[-1].id if len(groups) == limit else None
        return groups, next_cursor

    async def update(self, group_id: uuid.UUID, payload: GroupUpdate) -> Group:
        """Partially update a group. Raises on missing/scoped-out group."""
        group = await self.get(group_id)
        if payload.name is not None:
            group.name = payload.name
        if payload.description is not None:
            group.description = payload.description
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_group_integrity_error(exc, payload.name or "") from exc
        await self._session.refresh(group)
        return group

    async def delete(self, group_id: uuid.UUID) -> None:
        """Delete a group. Raises GroupNotFoundError if missing or out of scope."""
        group = await self.get(group_id)
        await self._session.delete(group)
        await self._session.flush()

    async def count(self, search_filter: GroupSearchFilter | None = None) -> int:
        """Total group count, scoped by ``perm_filter`` and the optional filter."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(Group))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def apply_batch(
        self,
        operations: list[GroupBatchOp],
        perm_filters: dict[Action, SearchFilter[Group] | None],
        *,
        creator_id: uuid.UUID,
    ) -> list[Group | None]:
        """Apply a mix of create/update/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic). Returns
        results aligned with *operations*: the group for create/update, ``None``
        for delete.
        """
        results: list[Group | None] = []
        for op in operations:
            if isinstance(op, GroupBatchCreate):
                results.append(await self._batch_create(op, perm_filters, creator_id=creator_id))
            elif isinstance(op, GroupBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, GroupBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: GroupBatchCreate,
        perm_filters: dict[Action, SearchFilter[Group] | None],
        *,
        creator_id: uuid.UUID,
    ) -> Group:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        return await GroupService(self._session, filt).create(op.data, creator_id=creator_id)

    async def _batch_update(
        self,
        op: GroupBatchUpdate,
        perm_filters: dict[Action, SearchFilter[Group] | None],
    ) -> Group:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await GroupService(self._session, filt).update(op.id, op.data)

    async def _batch_delete(
        self,
        op: GroupBatchDelete,
        perm_filters: dict[Action, SearchFilter[Group] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await GroupService(self._session, filt).delete(op.id)


def _classify_group_integrity_error(exc: IntegrityError, name: str) -> Exception:
    """Map an IntegrityError on the groups table to a domain failure.

    asyncpg surfaces the constraint name in the error message; there is no
    unique constraint on ``groups`` today, so any integrity error is unexpected
    and surfaced as a generic conflict keyed on the name.
    """
    _ = str(getattr(exc, "orig", exc)).lower()
    return GroupPermissionScopeError(name)


# ---------------------------------------------------------------------- #
# GroupUser service
# ---------------------------------------------------------------------- #


class GroupUserService:
    """CRUD operations over group-user memberships.

    The ``group_users`` link table is a governed resource of its own
    (``group_user_permission``): managing membership is deliberately *not*
    implied by ``group_permission`` update (AGENTS.md §11.1).
    """

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[GroupUser] = ALL,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(
        self,
        payload: GroupUserCreate,
        *,
        creator_id: uuid.UUID,
    ) -> GroupUser:
        """Add a user to a group. Raises GroupUserConflictError on duplicate,
        GroupUserOrphanError if the group or user does not exist, and
        GroupUserPermissionScopeError if the membership falls outside the
        principal's create scope."""
        link = GroupUser(
            group_id=payload.group_id,
            user_id=payload.user_id,
            creator_id=creator_id,
        )
        if not self._perm_filter.matches(link):
            raise GroupUserPermissionScopeError(f"{payload.group_id}/{payload.user_id}")
        self._session.add(link)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_group_user_integrity_error(
                exc, payload.group_id, payload.user_id
            ) from exc
        await self._session.refresh(link)
        return link

    async def get(self, group_user_id: uuid.UUID) -> GroupUser:
        """Retrieve a membership by id, scoped by ``perm_filter``.

        Raises :class:`GroupUserNotFoundError` if the membership is missing or
        out of the principal's scope (so callers return 404 without leaking
        existence).
        """
        stmt = self._perm_filter.filter_sql(select(GroupUser).where(GroupUser.id == group_user_id))
        result = await self._session.execute(stmt)
        link = result.scalar_one_or_none()
        if link is None:
            raise GroupUserNotFoundError(str(group_user_id))
        return link

    async def get_many(self, group_user_ids: list[uuid.UUID]) -> list[GroupUser | None]:
        """Retrieve memberships by ids in a single query, scoped by ``perm_filter``.

        Returns a list positionally aligned with *group_user_ids*: the i-th
        entry is the :class:`GroupUser` for ``group_user_ids[i]`` or ``None``
        when missing/out of scope. Duplicate ids are preserved. An empty
        *group_user_ids* yields an empty list without hitting the DB.
        """
        if not group_user_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(GroupUser).where(GroupUser.id.in_(group_user_ids))
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, GroupUser] = {link.id: link for link in result.scalars().all()}
        return [by_id.get(lid) for lid in group_user_ids]

    async def search_group_users(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: GroupUserSearchFilter | None = None,
    ) -> tuple[list[GroupUser], uuid.UUID | None]:
        """Search memberships ordered by id, keyed-pagination via cursor.

        The service's ``perm_filter`` scopes the SQL to rows the principal may
        see; the optional *search_filter* (from query params) is ANDed on top.
        Returns (memberships, next_cursor). next_cursor is None when exhausted.
        """
        stmt = self._perm_filter.filter_sql(select(GroupUser).order_by(GroupUser.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(GroupUser.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        links = list(result.scalars().all())
        next_cursor = links[-1].id if len(links) == limit else None
        return links, next_cursor

    async def count(self, search_filter: GroupUserSearchFilter | None = None) -> int:
        """Total membership count, scoped by ``perm_filter`` and the optional filter."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(GroupUser))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def delete(self, group_user_id: uuid.UUID) -> None:
        """Delete a membership. Raises GroupUserNotFoundError if missing or out
        of the principal's scope."""
        link = await self.get(group_user_id)
        await self._session.delete(link)
        await self._session.flush()

    async def apply_batch(
        self,
        operations: list[GroupUserBatchOp],
        perm_filters: dict[Action, SearchFilter[GroupUser] | None],
        *,
        creator_id: uuid.UUID,
    ) -> list[GroupUser | None]:
        """Apply a mix of create/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic). Returns
        results aligned with *operations*: the created :class:`GroupUser` for
        create ops, ``None`` for delete ops.
        """
        results: list[GroupUser | None] = []
        for op in operations:
            if isinstance(op, GroupUserBatchCreate):
                filt = perm_filters.get(Action.CREATE)
                if filt is None:
                    raise BatchPermissionDeniedError("create")
                link = await GroupUserService(self._session, filt).create(
                    op.data, creator_id=creator_id
                )
                results.append(link)
            elif isinstance(op, GroupUserBatchDelete):
                filt = perm_filters.get(Action.DELETE)
                if filt is None:
                    raise BatchPermissionDeniedError("delete")
                await GroupUserService(self._session, filt).delete(op.id)
                results.append(None)
        return results


def _classify_group_user_integrity_error(
    exc: IntegrityError,
    group_id: uuid.UUID,
    user_id: uuid.UUID,
) -> Exception:
    """Map an IntegrityError to a duplicate vs orphan failure.

    A violation of the ``uq_group_users_group_id_user_id`` unique constraint
    means the membership already exists (``GroupUserConflictError``); a
    foreign-key violation means the referenced group or user is missing
    (``GroupUserOrphanError``). asyncpg surfaces the constraint name in the
    error message; distinguish by it.
    """
    message = str(getattr(exc, "orig", exc)).lower()
    if "uq_group_users_group_id_user_id" in message or (
        "unique constraint" in message and "group_users" in message
    ):
        return GroupUserConflictError(f"{group_id}/{user_id}")
    if "foreign key" in message or "fk_" in message:
        if "user_id" in message and "group_id" not in message:
            return GroupUserOrphanError(f"user {user_id} does not exist")
        return GroupUserOrphanError(f"group {group_id} does not exist")
    # Default to conflict for any unrecognized integrity error on this table.
    return GroupUserConflictError(f"{group_id}/{user_id}")
