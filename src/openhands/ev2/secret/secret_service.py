"""Service layer for the typed secret feature.

Two services live here:

* :class:`SecretService` — CRUD over the ``secrets`` umbrella table. It holds
  the effective ``perm_filter`` (the search filter from the centralized
  permission checker) as a field, set at construction, that scopes
  search/get/update/delete SQL to secrets the principal may act on. The
  ``value`` is encrypted at rest via the encryption service (AGENTS.md §9) and
  stored in a type-specific detail row (``static_secret_details``); it is never
  returned by this service — :meth:`to_read` omits the value. The ``creator_id``
  of the creating principal is recorded on the secret row.

* :class:`SecretValueService` — the read-only reveal projection behind
  ``/secret-values``. It takes two filters (read-access + value-permission) and
  ANDs them, so a secret is revealed only when *both* admit it (defense in
  depth, AGENTS.md §12). It loads the detail row, decrypts, and returns
  :class:`SecretValueRead`.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.encryption.encryption_service import EncryptionService, get_encryption_service
from openhands.ev2.secret.secret_models import (
    Secret,
    SecretType,
    StaticSecretDetail,
)
from openhands.ev2.secret.secret_schemas import (
    SecretBatchCreate,
    SecretBatchDelete,
    SecretBatchOp,
    SecretBatchUpdate,
    SecretCreate,
    SecretRead,
    SecretSearchFilter,
    SecretUpdate,
    SecretValueRead,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, AndSearchFilter, SearchFilter


class SecretNotFoundError(Exception):
    """Raised when a secret id does not exist or is out of scope."""


class SecretCodeConflictError(Exception):
    """Raised when a create/update collides with an existing code."""


class SecretPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted to the principal."""


class SecretValueTypeError(Exception):
    """Raised when a value is supplied for a secret whose type cannot hold one.

    ``value`` is allowed only for ``type='static'`` secrets; supplying it on an
    oauth secret (which has no detail table yet) is a 422 client error.
    """


class SecretValueNotFoundError(Exception):
    """Raised when a reveal target has no decryptable detail row.

    A static secret missing its ``static_secret_details`` row is a data
    integrity break; an oauth secret has no detail table yet. Both surface as
    404 from the reveal endpoints.
    """


class SecretService:
    """CRUD operations over secrets.

    Constructed per request with the request-scoped session, the principal's
    effective ``perm_filter``, and (optionally) an encryption service for
    at-rest value encryption. It holds no other mutable state.
    """

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[Secret] = ALL,
        *,
        encryption_service: EncryptionService | None = None,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter
        self._enc = encryption_service or get_encryption_service()

    def to_read(self, secret: Secret) -> SecretRead:
        """Materialize a metadata-only :class:`SecretRead` (no value)."""
        return SecretRead(
            id=secret.id,
            code=secret.code,
            type=secret.type,
            description=secret.description,
            creator_id=secret.creator_id,
            created_at=secret.created_at,
            updated_at=secret.updated_at,
        )

    async def create(self, payload: SecretCreate, *, creator_id: uuid.UUID) -> Secret:
        """Create a secret. Raises :class:`SecretCodeConflictError` on a duplicate code.

        For ``type='static'`` the value is encrypted at rest and stored in a
        :class:`StaticSecretDetail` row. The ``creator_id`` of the creating
        principal is recorded on the secret for ownership-based access control.
        """
        secret = Secret(
            code=payload.code,
            type=payload.type,
            description=payload.description,
            creator_id=creator_id,
        )
        if not self._perm_filter.matches(secret):
            raise SecretPermissionScopeError(str(payload.code))
        self._session.add(secret)
        try:
            await self._session.flush()
            if payload.type == SecretType.STATIC:
                self._session.add(self._make_static_detail(secret.id, payload))
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_integrity_error(exc, payload) from exc
        await self._session.refresh(secret)
        return secret

    def _make_static_detail(
        self, secret_id: uuid.UUID, payload: SecretCreate
    ) -> StaticSecretDetail:
        value = payload.value.get_secret_value() if payload.value is not None else ""
        return StaticSecretDetail(
            secret_id=secret_id,
            value=self._enc.encrypt_value(value),
        )

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
        """Partially update a secret. Raises on missing/scoped-out secret or code conflict.

        If ``payload.value`` is set and the secret's type is ``oauth``, raises
        :class:`SecretValueTypeError` (422). For ``static`` the detail row's
        value is re-encrypted and upserted.
        """
        secret = await self.get(secret_id)
        if payload.code is not None:
            secret.code = payload.code
        if payload.value is not None:
            await self._apply_value_update(secret, payload.value)
        if payload.description is not None:
            secret.description = payload.description
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_integrity_error(exc, payload) from exc
        await self._session.refresh(secret)
        return secret

    async def _apply_value_update(self, secret: Secret, value: object) -> None:
        if secret.type == SecretType.OAUTH:
            raise SecretValueTypeError(str(secret.id))
        await self._upsert_static_detail(secret.id, value)

    async def _upsert_static_detail(self, secret_id: uuid.UUID, value: object) -> None:
        plaintext = getattr(value, "get_secret_value", lambda: str(value))()
        detail = await self._load_static_detail(secret_id)
        ciphertext = self._enc.encrypt_value(plaintext)
        if detail is None:
            self._session.add(StaticSecretDetail(secret_id=secret_id, value=ciphertext))
        else:
            detail.value = ciphertext

    async def _load_static_detail(self, secret_id: uuid.UUID) -> StaticSecretDetail | None:
        result = await self._session.execute(
            select(StaticSecretDetail).where(StaticSecretDetail.secret_id == secret_id)
        )
        return result.scalar_one_or_none()

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
        creator_id: uuid.UUID,
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
                results.append(await self._batch_create(op, perm_filters, creator_id=creator_id))
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
        creator_id: uuid.UUID,
    ) -> Secret:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        return await SecretService(self._session, filt, encryption_service=self._enc).create(
            op.data, creator_id=creator_id
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


class SecretValueService:
    """Read-only reveal projection behind ``/secret-values``.

    Constructed per request with the request-scoped session, the read-access
    filter (``secret_permission`` READ) and the value-reveal filter
    (``secret_value_permission``). The two filters are ANDed so a secret is
    revealed only when *both* admit it (defense in depth, AGENTS.md §12). It
    loads the type-specific detail row, decrypts, and returns
    :class:`SecretValueRead`.
    """

    def __init__(
        self,
        session: AsyncSession,
        read_filter: SearchFilter[Secret],
        value_filter: SearchFilter[Secret],
        *,
        encryption_service: EncryptionService | None = None,
    ) -> None:
        self._session = session
        self._read_filter = read_filter
        self._value_filter = value_filter
        self._enc = encryption_service or get_encryption_service()

    def _combined(self) -> SearchFilter[Secret]:
        return AndSearchFilter(filters=[self._read_filter, self._value_filter])

    async def get(self, secret_id: uuid.UUID) -> SecretValueRead:
        """Reveal one secret by id. 404 (via :class:`SecretValueNotFoundError`) if
        not both-admitted or missing a detail row."""
        stmt = self._combined().filter_sql(select(Secret).where(Secret.id == secret_id))
        secret = (await self._session.execute(stmt)).scalar_one_or_none()
        if secret is None:
            raise SecretValueNotFoundError(str(secret_id))
        plaintext = await self._decrypt_value(secret)
        return self._to_value_read(secret, plaintext)

    async def get_many(self, secret_ids: list[uuid.UUID]) -> list[SecretValueRead | None]:
        """Reveal secrets by ids in a single query, scoped by the combined filter.

        Returns a list positionally aligned with *secret_ids*; ``None`` where
        missing, out of scope, or missing a detail row. An empty input yields
        an empty list.
        """
        if not secret_ids:
            return []
        stmt = self._combined().filter_sql(select(Secret).where(Secret.id.in_(secret_ids)))
        secrets = list((await self._session.execute(stmt)).scalars().all())
        by_id = {s.id: s for s in secrets}
        results: list[SecretValueRead | None] = []
        for sid in secret_ids:
            secret = by_id.get(sid)
            if secret is None:
                results.append(None)
                continue
            plaintext = await self._decrypt_value_or_none(secret)
            results.append(None if plaintext is None else self._to_value_read(secret, plaintext))
        return results

    async def search_values(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: SecretSearchFilter | None = None,
    ) -> tuple[list[SecretValueRead], uuid.UUID | None]:
        """Reveal secrets ordered by id, keyed-pagination via cursor."""
        stmt = self._combined().filter_sql(select(Secret).order_by(Secret.id))
        stmt = self._apply_optional_filter(stmt, search_filter)
        if cursor is not None:
            stmt = stmt.where(Secret.id > cursor)
        stmt = stmt.limit(limit)
        secrets = list((await self._session.execute(stmt)).scalars().all())
        reads = await self._materialize_values(secrets)
        next_cursor = secrets[-1].id if len(secrets) == limit else None
        return reads, next_cursor

    def _apply_optional_filter(
        self,
        stmt: Select[Any],
        search_filter: SecretSearchFilter | None,
    ) -> Select[Any]:
        if search_filter is None:
            return stmt
        return search_filter.filter_sql(stmt)

    async def _materialize_values(self, secrets: list[Secret]) -> list[SecretValueRead]:
        reads: list[SecretValueRead] = []
        for secret in secrets:
            plaintext = await self._decrypt_value_or_none(secret)
            if plaintext is None:
                continue
            reads.append(self._to_value_read(secret, plaintext))
        return reads

    def _to_value_read(self, secret: Secret, plaintext: str) -> SecretValueRead:
        return SecretValueRead(
            id=secret.id,
            code=secret.code,
            type=secret.type,
            value=plaintext,
        )

    async def _decrypt_value(self, secret: Secret) -> str:
        if secret.type == SecretType.OAUTH:
            raise SecretValueNotFoundError(str(secret.id))
        detail = await self._load_static_detail(secret.id)
        if detail is None:
            raise SecretValueNotFoundError(str(secret.id))
        return self._enc.decrypt_value(detail.value)

    async def _decrypt_value_or_none(self, secret: Secret) -> str | None:
        if secret.type == SecretType.OAUTH:
            return None
        detail = await self._load_static_detail(secret.id)
        if detail is None:
            return None
        return self._enc.decrypt_value(detail.value)

    async def _load_static_detail(self, secret_id: uuid.UUID) -> StaticSecretDetail | None:
        result = await self._session.execute(
            select(StaticSecretDetail).where(StaticSecretDetail.secret_id == secret_id)
        )
        return result.scalar_one_or_none()


def _classify_integrity_error(
    exc: IntegrityError, payload: SecretCreate | SecretUpdate
) -> Exception:
    """Map a unique-constraint IntegrityError to a code conflict.

    The only unique column on ``secrets`` is ``code`` (and the primary key), so
    any unique violation here is a code collision.
    """
    _ = str(getattr(exc, "orig", exc)).lower()
    return SecretCodeConflictError(getattr(payload, "code", None) or "")
