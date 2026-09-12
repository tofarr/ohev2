"""SQL-backed secrets service — the default :class:`SecretsService`.

This module is intentionally isolated from :mod:`secret_service` so the
SQLAlchemy machinery is only imported when the SQL implementation is selected
(other implementations — AWS Secrets Manager, 1Password, ... — live in their
own modules and are wired via the ``secrets_service_class`` config).

``SqlSecretsService`` maintains its own ORM models (:mod:`sql_secrets_models`)
and translates rows to the provider-neutral Pydantic
:class:`openhands.ev2.secret.secret_models.Secret` before returning. Values
are encrypted at rest via the encryption service (AGENTS.md §9) in the
``static_secret_details`` table.

Session scoping: every operation runs in a session from
:func:`get_session_factory`. A contextvar carries the in-flight session so an
enclosing :meth:`apply_batch` shares one session — and one commit — across
its operations, preserving the atomic batch contract (AGENTS.md §3); a
standalone operation is its own outermost scope and commits by itself.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import ClassVar

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.db import get_session_factory
from openhands.ev2.encryption.encryption_service import get_encryption_service
from openhands.ev2.secret.secret_models import Secret, SecretType
from openhands.ev2.secret.secret_schemas import (
    SecretBatchOp,
    SecretCreate,
    SecretUpdate,
)
from openhands.ev2.secret.secret_service import (
    SecretCodeConflictError,
    SecretNotFoundError,
    SecretsService,
)
from openhands.ev2.secret.sql_secrets_models import SqlSecret, SqlStaticSecretDetail
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter


class SqlSecretsService(SecretsService):
    """PostgreSQL-backed secrets service (the default implementation)."""

    # The in-flight session for the current async context, if any. A ClassVar
    # (not a pydantic field): it is per-async-context mutable state, not
    # configuration.
    _session_var: ClassVar[ContextVar[AsyncSession | None]] = ContextVar(
        "sql_secrets_service_session", default=None
    )

    @classmethod
    @asynccontextmanager
    async def _session_scope(cls) -> AsyncIterator[AsyncSession]:
        """Yield the in-flight session, or open one and commit it on exit.

        Nested scopes reuse the outermost session without committing, so a
        batch (the outermost scope) commits exactly once; a standalone
        operation is its own outermost scope and commits by itself. Any
        exception rolls the session back before propagating.
        """
        existing = cls._session_var.get()
        if existing is not None:
            yield existing
            return
        async with get_session_factory()() as session:
            token = cls._session_var.set(session)
            try:
                yield session
                await session.commit()
            except BaseException:
                await session.rollback()
                raise
            finally:
                cls._session_var.reset(token)

    async def apply_batch(
        self,
        operations: list[SecretBatchOp],
        perm_filters: dict[Action, SearchFilter[Secret] | None],
        *,
        creator_id: uuid.UUID,
    ) -> list[Secret | None]:
        """Apply the batch in one session/commit so any failure rolls back all ops."""
        async with self._session_scope():
            return await super().apply_batch(operations, perm_filters, creator_id=creator_id)

    async def update_secret(
        self,
        secret_id: uuid.UUID,
        payload: SecretUpdate,
        *,
        perm_filter: SearchFilter[Secret] = ALL,
    ) -> Secret:
        # One session for the scope check + the mutation: the scope-check fetch
        # populates the identity map _update_secret re-uses, so the row cannot
        # vanish between the two (see the assert in _update_secret).
        async with self._session_scope():
            return await super().update_secret(secret_id, payload, perm_filter=perm_filter)

    async def delete_secret(
        self, secret_id: uuid.UUID, *, perm_filter: SearchFilter[Secret] = ALL
    ) -> None:
        # Same single-session invariant as update_secret.
        async with self._session_scope():
            await super().delete_secret(secret_id, perm_filter=perm_filter)

    # ------------------------------------------------------------------ #
    # Provider hooks.
    # ------------------------------------------------------------------ #
    async def _list_secrets(self) -> list[Secret]:
        async with self._session_scope() as session:
            result = await session.execute(select(SqlSecret))
            return [self._to_model(row) for row in result.scalars().all()]

    async def _get_secret(self, secret_id: uuid.UUID) -> Secret:
        async with self._session_scope() as session:
            row = await session.get(SqlSecret, secret_id)
            if row is None:
                raise SecretNotFoundError(str(secret_id))
            return self._to_model(row)

    async def _create_secret(self, secret: Secret, payload: SecretCreate) -> Secret:
        async with self._session_scope() as session:
            row = SqlSecret(
                code=secret.code,
                type=secret.type,
                description=secret.description,
                creator_id=secret.creator_id,
            )
            # The base minted the id and timestamps on the pre-persistence
            # model; persist them as given so model and row agree.
            row.id = secret.id
            row.created_at = secret.created_at
            row.updated_at = secret.updated_at
            session.add(row)
            try:
                await session.flush()
                if payload.type == SecretType.STATIC:
                    session.add(self._static_detail(secret.id, payload))
                    await session.flush()
            except IntegrityError as exc:
                raise _classify_integrity_error(exc, payload.code) from exc
            return secret

    async def _update_secret(self, secret: Secret, payload: SecretUpdate) -> Secret:
        async with self._session_scope() as session:
            row = await session.get(SqlSecret, secret.id)
            # update_secret wraps the scope check + mutation in one session, so
            # the scope-check fetch already populated the identity map.
            assert row is not None
            if payload.code is not None:
                row.code = payload.code
            if payload.description is not None:
                row.description = payload.description
            if payload.value is not None:
                await self._upsert_static_detail(
                    session, secret.id, payload.value.get_secret_value()
                )
            try:
                await session.flush()
            except IntegrityError as exc:
                raise _classify_integrity_error(exc, payload.code) from exc
            await session.refresh(row)
            return self._to_model(row)

    async def _delete_secret(self, secret_id: uuid.UUID) -> None:
        async with self._session_scope() as session:
            row = await session.get(SqlSecret, secret_id)
            # Same single-session invariant as _update_secret.
            assert row is not None
            await session.delete(row)
            await session.flush()

    async def _decrypt_value(self, secret: Secret) -> str | None:
        async with self._session_scope() as session:
            detail = await self._load_static_detail(session, secret.id)
            if detail is None:
                return None
            return get_encryption_service().decrypt_value(detail.value)

    # ------------------------------------------------------------------ #
    # Internal helpers.
    # ------------------------------------------------------------------ #
    @staticmethod
    def _to_model(row: SqlSecret) -> Secret:
        return Secret(
            id=row.id,
            code=row.code,
            type=row.type,
            description=row.description,
            creator_id=row.creator_id,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _static_detail(secret_id: uuid.UUID, payload: SecretCreate) -> SqlStaticSecretDetail:
        value = payload.value.get_secret_value() if payload.value is not None else ""
        return SqlStaticSecretDetail(
            secret_id=secret_id,
            value=get_encryption_service().encrypt_value(value),
        )

    @staticmethod
    async def _load_static_detail(
        session: AsyncSession, secret_id: uuid.UUID
    ) -> SqlStaticSecretDetail | None:
        result = await session.execute(
            select(SqlStaticSecretDetail).where(SqlStaticSecretDetail.secret_id == secret_id)
        )
        return result.scalar_one_or_none()

    async def _upsert_static_detail(
        self, session: AsyncSession, secret_id: uuid.UUID, plaintext: str
    ) -> None:
        ciphertext = get_encryption_service().encrypt_value(plaintext)
        detail = await self._load_static_detail(session, secret_id)
        if detail is None:
            session.add(SqlStaticSecretDetail(secret_id=secret_id, value=ciphertext))
        else:
            detail.value = ciphertext


def _classify_integrity_error(exc: IntegrityError, code: str | None) -> Exception:
    """Map a unique-constraint IntegrityError to a code conflict.

    The only unique column on ``secrets`` is ``code`` (and the primary key), so
    any unique violation here is a code collision.
    """
    _ = str(getattr(exc, "orig", exc)).lower()
    return SecretCodeConflictError(code or "")
