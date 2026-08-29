"""Service layer for the secret feature (the ``secrets`` table).

The service holds the effective ``perm_filter`` (the search filter from the
centralized permission checker) as a field, set at construction, that scopes
search/get/update/delete SQL to secrets the principal may act on. For
``SecretAccess`` policies that filter is a :class:`SecretAccessFilter` keyed on
the action's ``role_secrets`` flag; for ``Permitted`` it is everything.

The ``value`` is encrypted at rest via the encryption service (AGENTS.md §9)
and decrypted only when materializing a :class:`SecretRead` DTO. ``user_id``
is set to the creating principal and never taken from the payload, so a
secret's provenance is trustworthy.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.encryption.encryption_service import EncryptionService, get_encryption_service
from openhands.ev2.secret.secret_models import Secret
from openhands.ev2.secret.secret_schemas import (
    SecretBatchCreate,
    SecretBatchDelete,
    SecretBatchOp,
    SecretBatchUpdate,
    SecretCreate,
    SecretRead,
    SecretSearchFilter,
    SecretUpdate,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL_SEARCH_FILTER, SearchFilter


class SecretNotFoundError(Exception):
    """Raised when a secret id does not exist or is out of scope."""


class SecretCodeConflictError(Exception):
    """Raised when a create/update collides with an existing code."""


class SecretPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted to the principal."""


class SecretService:
    """CRUD operations over secrets.

    Constructed per request with the request-scoped session, the principal's
    effective ``perm_filter``, and (optionally) an encryption service for
    at-rest value encryption. It holds no other mutable state.
    """

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[Secret] = ALL_SEARCH_FILTER,
        *,
        encryption_service: EncryptionService | None = None,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter
        self._enc = encryption_service or get_encryption_service()

    def to_read(self, secret: Secret) -> SecretRead:
        """Materialize a :class:`SecretRead`, decrypting the at-rest value."""
        return SecretRead(
            id=secret.id,
            code=secret.code,
            value=self._enc.decrypt_value(secret.value),
            description=secret.description,
            user_id=secret.user_id,
            created_at=secret.created_at,
            updated_at=secret.updated_at,
        )

    async def create(self, payload: SecretCreate, *, user_id: uuid.UUID) -> Secret:
        """Create a secret. Raises :class:`SecretCodeConflictError` on a duplicate code.

        The value is encrypted at rest before persistence. ``user_id`` is set to
        the creating principal, never read from the payload.
        """
        secret = Secret(
            code=payload.code,
            value=self._enc.encrypt_value(payload.value.get_secret_value()),
            description=payload.description,
            user_id=user_id,
        )
        if not self._perm_filter.matches(secret):
            raise SecretPermissionScopeError(str(payload.code))
        self._session.add(secret)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_integrity_error(exc, payload) from exc
        await self._session.refresh(secret)
        return secret

    async def get(self, secret_id: uuid.UUID) -> Secret:
        """Retrieve a secret by id, scoped by ``perm_filter``.

        Raises :class:`SecretNotFoundError` if missing or out of scope (so
        callers return 404 without leaking existence).
        """
        stmt = self._perm_filter.filter_sql(select(Secret).where(Secret.id == secret_id))
        result = await self._session.execute(stmt)
        secret = result.scalar_one_or_none()
        if secret is None:
            raise SecretNotFoundError(str(secret_id))
        return secret

    async def get_many(self, secret_ids: list[uuid.UUID]) -> list[Secret | None]:
        """Retrieve secrets by ids in a single query, scoped by ``perm_filter``.

        Returns a list positionally aligned with *secret_ids*; ``None`` where
        missing or out of scope. An empty *secret_ids* yields an empty list.
        """
        if not secret_ids:
            return []
        stmt = self._perm_filter.filter_sql(select(Secret).where(Secret.id.in_(secret_ids)))
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, Secret] = {s.id: s for s in result.scalars().all()}
        return [by_id.get(sid) for sid in secret_ids]

    async def search_secrets(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: SecretSearchFilter | None = None,
    ) -> tuple[list[Secret], uuid.UUID | None]:
        """Search secrets ordered by id, keyed-pagination via cursor."""
        stmt = self._perm_filter.filter_sql(select(Secret).order_by(Secret.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(Secret.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        secrets = list(result.scalars().all())
        next_cursor = secrets[-1].id if len(secrets) == limit else None
        return secrets, next_cursor

    async def update(self, secret_id: uuid.UUID, payload: SecretUpdate) -> Secret:
        """Partially update a secret. Raises on missing/scoped-out secret or code conflict."""
        secret = await self.get(secret_id)
        if payload.code is not None:
            secret.code = payload.code
        if payload.value is not None:
            secret.value = self._enc.encrypt_value(payload.value.get_secret_value())
        if payload.description is not None:
            secret.description = payload.description
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_integrity_error(exc, payload) from exc
        await self._session.refresh(secret)
        return secret

    async def delete(self, secret_id: uuid.UUID) -> None:
        """Delete a secret. Raises :class:`SecretNotFoundError` if missing/out of scope."""
        secret = await self.get(secret_id)
        await self._session.delete(secret)
        await self._session.flush()

    async def apply_batch(
        self,
        operations: list[SecretBatchOp],
        perm_filters: dict[Action, SearchFilter[Secret] | None],
        *,
        user_id: uuid.UUID,
    ) -> list[Secret | None]:
        """Apply a mix of create/update/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic). Returns
        results aligned with *operations*: the secret for create/update,
        ``None`` for delete.
        """
        results: list[Secret | None] = []
        for op in operations:
            if isinstance(op, SecretBatchCreate):
                results.append(await self._batch_create(op, perm_filters, user_id=user_id))
            elif isinstance(op, SecretBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, SecretBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: SecretBatchCreate,
        perm_filters: dict[Action, SearchFilter[Secret] | None],
        *,
        user_id: uuid.UUID,
    ) -> Secret:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        return await SecretService(self._session, filt, encryption_service=self._enc).create(
            op.data, user_id=user_id
        )

    async def _batch_update(
        self,
        op: SecretBatchUpdate,
        perm_filters: dict[Action, SearchFilter[Secret] | None],
    ) -> Secret:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await SecretService(self._session, filt, encryption_service=self._enc).update(
            op.id, op.data
        )

    async def _batch_delete(
        self,
        op: SecretBatchDelete,
        perm_filters: dict[Action, SearchFilter[Secret] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await SecretService(self._session, filt, encryption_service=self._enc).delete(op.id)

    async def count(self, search_filter: SecretSearchFilter | None = None) -> int:
        """Total secret count, scoped by ``perm_filter`` and the optional filter."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(Secret))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())


def _classify_integrity_error(
    exc: IntegrityError, payload: SecretCreate | SecretUpdate
) -> Exception:
    """Map a unique-constraint IntegrityError to a code conflict.

    The only unique column on ``secrets`` is ``code`` (and the primary key), so
    any unique violation here is a code collision.
    """
    _ = str(getattr(exc, "orig", exc)).lower()
    return SecretCodeConflictError(getattr(payload, "code", None) or "")


__all__ = [
    "BatchPermissionDeniedError",
    "Secret",
    "SecretCodeConflictError",
    "SecretNotFoundError",
    "SecretPermissionScopeError",
    "SecretService",
]
