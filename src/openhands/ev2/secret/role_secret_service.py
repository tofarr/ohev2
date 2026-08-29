"""Service layer for the role-secret grant feature (the ``role_secrets`` table).

CRUD for the per-role grant link table between :class:`Role` and
:class:`Secret`. Unlike the immutable ``user_roles`` link, a ``role_secrets``
row is mutable: :meth:`update` toggles the ``read_enabled`` /
``update_enabled`` / ``delete_enabled`` flags to change what the role may do
with the secret without dropping and re-creating the grant.

The service does not take a ``perm_filter`` because the link table has no
resource policy of its own; authorization is enforced at the router via the
``role`` resource (managing a role's secret grants requires ``UPDATE`` on the
role, mirroring how ``user_roles`` management requires ``UPDATE`` on the
role). See AGENTS.md §9 — authorization in services, but the link has no
policy column to reduce.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.secret.role_secret_schemas import (
    RoleSecretBatchCreate,
    RoleSecretBatchDelete,
    RoleSecretBatchOp,
    RoleSecretBatchUpdate,
    RoleSecretSearchFilter,
    RoleSecretUpdate,
)
from openhands.ev2.secret.secret_models import RoleSecret


class RoleSecretNotFoundError(Exception):
    """Raised when a role-secret grant id does not exist."""


class RoleSecretConflictError(Exception):
    """Raised when a grant already exists for the (role_id, secret_id) pair."""


class RoleSecretOrphanError(Exception):
    """Raised when the referenced role or secret does not exist."""


class RoleSecretService:
    """CRUD operations over role-secret grants."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        role_id: uuid.UUID,
        secret_id: uuid.UUID,
        read_enabled: bool = False,
        update_enabled: bool = False,
        delete_enabled: bool = False,
    ) -> RoleSecret:
        """Grant a role access to a secret. Raises on duplicate or orphan FK."""
        link = RoleSecret(
            role_id=role_id,
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
            raise _classify_integrity_error(exc, role_id, secret_id) from exc
        await self._session.refresh(link)
        return link

    async def get(self, role_secret_id: uuid.UUID) -> RoleSecret:
        """Retrieve a grant by id. Raises :class:`RoleSecretNotFoundError` if missing."""
        link = await self._session.get(RoleSecret, role_secret_id)
        if link is None:
            raise RoleSecretNotFoundError(str(role_secret_id))
        return link

    async def get_many(self, role_secret_ids: list[uuid.UUID]) -> list[RoleSecret | None]:
        """Retrieve grants by ids, positionally aligned; ``None`` where missing."""
        if not role_secret_ids:
            return []
        stmt = select(RoleSecret).where(RoleSecret.id.in_(role_secret_ids))
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, RoleSecret] = {link.id: link for link in result.scalars().all()}
        return [by_id.get(lid) for lid in role_secret_ids]

    async def search_role_secrets(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: RoleSecretSearchFilter | None = None,
    ) -> tuple[list[RoleSecret], uuid.UUID | None]:
        """Search grants ordered by id, keyed-pagination via cursor."""
        stmt = select(RoleSecret).order_by(RoleSecret.id)
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(RoleSecret.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        links = list(result.scalars().all())
        next_cursor = links[-1].id if len(links) == limit else None
        return links, next_cursor

    async def count(self, search_filter: RoleSecretSearchFilter | None = None) -> int:
        """Total grant count, optionally narrowed by *search_filter*."""
        stmt = select(func.count()).select_from(RoleSecret)
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def update(self, role_secret_id: uuid.UUID, payload: RoleSecretUpdate) -> RoleSecret:
        """Toggle the read/update/delete flags on a grant. Raises if missing."""
        link = await self.get(role_secret_id)
        if payload.read_enabled is not None:
            link.read_enabled = payload.read_enabled
        if payload.update_enabled is not None:
            link.update_enabled = payload.update_enabled
        if payload.delete_enabled is not None:
            link.delete_enabled = payload.delete_enabled
        await self._session.flush()
        await self._session.refresh(link)
        return link

    async def delete(self, role_secret_id: uuid.UUID) -> None:
        """Delete a grant. Raises :class:`RoleSecretNotFoundError` if missing."""
        link = await self.get(role_secret_id)
        await self._session.delete(link)
        await self._session.flush()

    async def apply_batch(self, operations: list[RoleSecretBatchOp]) -> list[RoleSecret | None]:
        """Apply a mix of create/update/delete operations in one transaction.

        No commit is performed — the caller commits once after the whole batch
        succeeds (atomic). Returns results aligned with *operations*: the
        grant for create/update, ``None`` for delete.
        """
        results: list[RoleSecret | None] = []
        for op in operations:
            if isinstance(op, RoleSecretBatchCreate):
                d = op.data
                results.append(
                    await self.create(
                        role_id=d.role_id,
                        secret_id=d.secret_id,
                        read_enabled=d.read_enabled,
                        update_enabled=d.update_enabled,
                        delete_enabled=d.delete_enabled,
                    )
                )
            elif isinstance(op, RoleSecretBatchUpdate):
                results.append(await self.update(op.id, op.data))
            elif isinstance(op, RoleSecretBatchDelete):
                await self.delete(op.id)
                results.append(None)
        return results


def _classify_integrity_error(
    exc: IntegrityError,
    role_id: uuid.UUID,
    secret_id: uuid.UUID,
) -> Exception:
    """Map an IntegrityError to a duplicate vs orphan failure.

    A violation of ``uq_role_secrets_role_id_secret_id`` means the grant
    already exists; a foreign-key violation means the referenced role or
    secret is missing. asyncpg surfaces the constraint name in the message.
    """
    message = str(getattr(exc, "orig", exc)).lower()
    if "uq_role_secrets_role_id_secret_id" in message or (
        "unique constraint" in message and "role_secrets" in message
    ):
        return RoleSecretConflictError(f"{role_id}/{secret_id}")
    if "foreign key" in message or "fk_" in message:
        if "secret_id" in message and "role_id" not in message:
            return RoleSecretOrphanError(f"secret {secret_id} does not exist")
        return RoleSecretOrphanError(f"role {role_id} does not exist")
    return RoleSecretConflictError(f"{role_id}/{secret_id}")


__all__ = [
    "RoleSecret",
    "RoleSecretConflictError",
    "RoleSecretNotFoundError",
    "RoleSecretOrphanError",
    "RoleSecretService",
]
