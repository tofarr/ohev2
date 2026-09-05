"""Service layer for per-user secret permissions.

CRUD for the per-user grant link table between :class:`Secret` and
:class:`User`. A ``user_secret_permissions`` row is mutable: :meth:`update`
toggles the ``read_enabled`` / ``update_enabled`` / ``delete_enabled`` flags to
change what the user may do with the secret without dropping and re-creating
the grant.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.secret.secret_models import UserSecretPermission
from openhands.ev2.secret.user_secret_permission_schemas import (
    UserSecretPermissionBatchCreate,
    UserSecretPermissionBatchDelete,
    UserSecretPermissionBatchOp,
    UserSecretPermissionBatchUpdate,
    UserSecretPermissionSearchFilter,
    UserSecretPermissionUpdate,
)


class UserSecretPermissionNotFoundError(Exception):
    """Raised when a user-secret grant id does not exist."""


class UserSecretPermissionConflictError(Exception):
    """Raised when a grant already exists for the (user_id, secret_id) pair."""


class UserSecretPermissionOrphanError(Exception):
    """Raised when the referenced secret or user does not exist."""


class UserSecretPermissionService:
    """CRUD operations over user-secret grants."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        user_id: uuid.UUID,
        secret_id: uuid.UUID,
        read_enabled: bool = False,
        update_enabled: bool = False,
        delete_enabled: bool = False,
    ) -> UserSecretPermission:
        """Grant a user access to a secret. Raises on duplicate or orphan FK."""
        link = UserSecretPermission(
            user_id=user_id,
            secret_id=secret_id,
            read_enabled=read_enabled,
            update_enabled=update_enabled,
            delete_enabled=delete_enabled,
        )
        self._session.add(link)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_integrity_error(exc, secret_id, user_id) from exc
        await self._session.refresh(link)
        return link

    async def get(self, user_secret_permission_id: uuid.UUID) -> UserSecretPermission:
        """Retrieve a grant by id. Raises if missing."""
        link = await self._session.get(UserSecretPermission, user_secret_permission_id)
        if link is None:
            raise UserSecretPermissionNotFoundError(str(user_secret_permission_id))
        return link

    async def get_many(
        self, user_secret_permission_ids: list[uuid.UUID]
    ) -> list[UserSecretPermission | None]:
        """Retrieve grants by ids, positionally aligned; ``None`` where missing."""
        if not user_secret_permission_ids:
            return []
        stmt = select(UserSecretPermission).where(
            UserSecretPermission.id.in_(user_secret_permission_ids)
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, UserSecretPermission] = {
            link.id: link for link in result.scalars().all()
        }
        return [by_id.get(lid) for lid in user_secret_permission_ids]

    async def search_user_secret_permissions(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: UserSecretPermissionSearchFilter | None = None,
    ) -> tuple[list[UserSecretPermission], uuid.UUID | None]:
        """Search grants ordered by id, keyed-pagination via cursor."""
        stmt = select(UserSecretPermission).order_by(UserSecretPermission.id)
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(UserSecretPermission.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        links = list(result.scalars().all())
        next_cursor = links[-1].id if len(links) == limit else None
        return links, next_cursor

    async def count(self, search_filter: UserSecretPermissionSearchFilter | None = None) -> int:
        """Total grant count, optionally narrowed by *search_filter*."""
        stmt = select(func.count()).select_from(UserSecretPermission)
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def update(
        self, user_secret_permission_id: uuid.UUID, payload: UserSecretPermissionUpdate
    ) -> UserSecretPermission:
        """Toggle the read/update/delete flags on a grant. Raises if missing."""
        link = await self.get(user_secret_permission_id)
        if payload.read_enabled is not None:
            link.read_enabled = payload.read_enabled
        if payload.update_enabled is not None:
            link.update_enabled = payload.update_enabled
        if payload.delete_enabled is not None:
            link.delete_enabled = payload.delete_enabled
        await self._session.flush()
        await self._session.refresh(link)
        return link

    async def delete(self, user_secret_permission_id: uuid.UUID) -> None:
        """Delete a grant. Raises if missing."""
        link = await self.get(user_secret_permission_id)
        await self._session.delete(link)
        await self._session.flush()

    async def apply_batch(
        self, operations: list[UserSecretPermissionBatchOp]
    ) -> list[UserSecretPermission | None]:
        """Apply a mix of create/update/delete operations in one transaction."""
        results: list[UserSecretPermission | None] = []
        for op in operations:
            if isinstance(op, UserSecretPermissionBatchCreate):
                d = op.data
                results.append(
                    await self.create(
                        user_id=d.user_id,
                        secret_id=d.secret_id,
                        read_enabled=d.read_enabled,
                        update_enabled=d.update_enabled,
                        delete_enabled=d.delete_enabled,
                    )
                )
            elif isinstance(op, UserSecretPermissionBatchUpdate):
                results.append(await self.update(op.id, op.data))
            elif isinstance(op, UserSecretPermissionBatchDelete):
                await self.delete(op.id)
                results.append(None)
        return results


def _classify_integrity_error(
    exc: IntegrityError,
    secret_id: uuid.UUID,
    user_id: uuid.UUID,
) -> Exception:
    """Map an IntegrityError to a duplicate vs orphan failure."""
    message = str(getattr(exc, "orig", exc)).lower()
    if "uq_user_secret_permissions_user_id_secret_id" in message or (
        "unique constraint" in message and "user_secret_permissions" in message
    ):
        return UserSecretPermissionConflictError(f"{user_id}/{secret_id}")
    if "foreign key" in message or "fk_" in message:
        if "user_id" in message and "secret_id" not in message:
            return UserSecretPermissionOrphanError(f"user {user_id} does not exist")
        return UserSecretPermissionOrphanError(f"secret {secret_id} does not exist")
    return UserSecretPermissionConflictError(f"{user_id}/{secret_id}")


__all__ = [
    "UserSecretPermission",
    "UserSecretPermissionConflictError",
    "UserSecretPermissionNotFoundError",
    "UserSecretPermissionOrphanError",
    "UserSecretPermissionService",
]
