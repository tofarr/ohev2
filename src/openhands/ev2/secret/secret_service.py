"""Service layer for the secret feature: a pluggable secrets control plane.

The secret control plane is supplied by a polymorphic :class:`SecretsService`
implementation selected at startup via the ``secrets_service_class`` config
attribute (a fully qualified class name), mirroring the sandbox control plane
(:mod:`openhands.ev2.sandbox.sandbox_service`). The service is constructed
once via ``AppConfig.get_secrets_service`` and held as an async context
manager tied to the server lifespan; every request resolves the same
instance from ``app.state.secrets_service`` and passes its own permission
filters, so authorization stays per-principal.

Implementations exchange the Pydantic :class:`Secret` model — never an ORM
row — so a provider backed by an external store (AWS Secrets Manager,
1Password, ...) drops in without leaking client types. The default
implementation is :class:`SqlSecretsService` (in
:mod:`openhands.ev2.secret.sql_secrets_service`), which maintains its own
SQLAlchemy models and translates to Pydantic internally. Concrete
implementations live in their own modules and are only imported when selected
via :func:`resolve_secrets_service_class`.

The generic CRUD + reveal helpers are implemented here over the provider
hooks and shared by every implementation:

* metadata CRUD scopes every read/write through the principal's
  ``perm_filter`` (in-memory, like the sandbox surface);
* the ``/secret-values`` reveal projection ANDs the read-access filter
  (``secret_permission``) with the value-reveal filter
  (``secret_value_permission``), so a secret is revealed only when *both*
  admit it (defense in depth, AGENTS.md §12). A failing reveal is a
  :class:`SecretValueNotFoundError` (404, not 403) so existence is not
  leaked.

Providers with transactional stores override :meth:`SecretsService.apply_batch`
to bracket the base implementation's per-op dispatch in a single transaction
(the default SQL implementation commits exactly once per batch, preserving
the atomic no-partial-application contract of AGENTS.md §3).
"""

from __future__ import annotations

import importlib
import uuid
from abc import ABC, abstractmethod
from typing import Any

from openhands.sdk.utils.models import DiscriminatedUnionMixin

from openhands.ev2.secret.secret_models import Secret
from openhands.ev2.secret.secret_schemas import (
    SecretBatchCreate,
    SecretBatchDelete,
    SecretBatchOp,
    SecretBatchUpdate,
    SecretCreate,
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


class SecretValueNotFoundError(Exception):
    """Raised when a reveal target is missing, not both-admitted, or has no value.

    Surfaces as 404 from the reveal endpoints (not 403) so existence is not
    leaked.
    """


class SecretsService(DiscriminatedUnionMixin, ABC):
    """Abstract base for the secret control plane.

    Concrete subclasses provide provider-specific persistence behind the
    hooks at the bottom of this class; the public methods are shared and
    enforce authorization (via per-call permission filters) and the
    value-reveal invariants uniformly. The service is created once at startup
    and held as an async context manager for the server's lifetime.
    """

    # ------------------------------------------------------------------ #
    # Async context manager (server lifecycle). Concrete subclasses hold
    # provider clients; ``__aenter__`` acquires them and ``aclose`` releases.
    # ------------------------------------------------------------------ #
    async def __aenter__(self) -> SecretsService:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: Any,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Release any provider resources. Default is a no-op."""
        return None

    # ------------------------------------------------------------------ #
    # Generic public metadata CRUD (built on the provider hooks below).
    # ------------------------------------------------------------------ #
    async def list_secrets(self, *, perm_filter: SearchFilter[Secret] = ALL) -> list[Secret]:
        """Return every secret the principal may see (unordered)."""
        secrets = await self._list_secrets()
        return [secret for secret in secrets if perm_filter.matches(secret)]

    async def search_secrets(
        self,
        *,
        perm_filter: SearchFilter[Secret] = ALL,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: SecretSearchFilter | None = None,
    ) -> tuple[list[Secret], uuid.UUID | None]:
        """Search secrets ordered by id, keyed-pagination via cursor."""
        secrets = await self.list_secrets(perm_filter=perm_filter)
        if search_filter is not None:
            secrets = [s for s in secrets if search_filter.matches(s)]
        secrets.sort(key=lambda secret: secret.id)
        if cursor is not None:
            secrets = [s for s in secrets if s.id > cursor]
        page = secrets[:limit]
        next_cursor = page[-1].id if len(page) == limit else None
        return page, next_cursor

    async def count(
        self,
        *,
        perm_filter: SearchFilter[Secret] = ALL,
        search_filter: SecretSearchFilter | None = None,
    ) -> int:
        """Total secret count, scoped by the filters."""
        secrets = await self.list_secrets(perm_filter=perm_filter)
        if search_filter is not None:
            secrets = [s for s in secrets if search_filter.matches(s)]
        return len(secrets)

    async def get_secret(
        self,
        secret_id: uuid.UUID,
        *,
        perm_filter: SearchFilter[Secret] = ALL,
    ) -> Secret:
        """Retrieve a secret by id, scoped by ``perm_filter``.

        Raises :class:`SecretNotFoundError` if missing or out of scope (so
        callers return 404 without leaking existence).
        """
        secret = await self._get_secret(secret_id)
        if not perm_filter.matches(secret):
            raise SecretNotFoundError(str(secret_id))
        return secret

    async def get_secrets(
        self,
        secret_ids: list[uuid.UUID],
        *,
        perm_filter: SearchFilter[Secret] = ALL,
    ) -> list[Secret | None]:
        """Retrieve secrets by ids, scoped by ``perm_filter``.

        Returns a list positionally aligned with *secret_ids*; ``None`` where
        missing or out of scope. An empty *secret_ids* yields an empty list.
        """
        if not secret_ids:
            return []
        secrets = await self.list_secrets(perm_filter=perm_filter)
        by_id = {secret.id: secret for secret in secrets}
        return [by_id.get(sid) for sid in secret_ids]

    async def create_secret(
        self,
        payload: SecretCreate,
        *,
        creator_id: uuid.UUID,
        perm_filter: SearchFilter[Secret] = ALL,
    ) -> Secret:
        """Create a secret. Raises on out-of-scope payload or provider conflict.

        The pre-persistence model built by :meth:`_secret_from_create` is
        checked against ``perm_filter`` (the principal's create scope) before
        anything is persisted. The ``creator_id`` of the creating principal is
        recorded for ownership-based access control.
        """
        secret = self._secret_from_create(payload, creator_id=creator_id)
        if not perm_filter.matches(secret):
            raise SecretPermissionScopeError(str(payload.code))
        return await self._create_secret(secret, payload)

    def _secret_from_create(self, payload: SecretCreate, *, creator_id: uuid.UUID) -> Secret:
        """Build the provider-neutral model from a create payload.

        Providers persist the returned model as-is (its id and timestamps are
        already minted); a provider may override to enrich it with
        provider-specific fields.
        """
        return Secret(
            code=payload.code,
            description=payload.description,
            creator_id=creator_id,
        )

    async def update_secret(
        self,
        secret_id: uuid.UUID,
        payload: SecretUpdate,
        *,
        perm_filter: SearchFilter[Secret] = ALL,
    ) -> Secret:
        """Partially update a secret, scoped by ``perm_filter``.

        Raises :class:`SecretNotFoundError` when missing or out of scope.
        """
        secret = await self.get_secret(secret_id, perm_filter=perm_filter)
        return await self._update_secret(secret, payload)

    async def delete_secret(
        self,
        secret_id: uuid.UUID,
        *,
        perm_filter: SearchFilter[Secret] = ALL,
    ) -> None:
        """Delete a secret, scoped by ``perm_filter``."""
        await self.get_secret(secret_id, perm_filter=perm_filter)
        await self._delete_secret(secret_id)

    async def apply_batch(
        self,
        operations: list[SecretBatchOp],
        perm_filters: dict[Action, SearchFilter[Secret] | None],
        *,
        creator_id: uuid.UUID,
    ) -> list[Secret | None]:
        """Apply a mix of create/update/delete operations.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). Returns results aligned with
        *operations*: the secret for create/update, ``None`` for delete.
        Providers with transactional stores override this to run the whole
        batch in one transaction (atomic, no partial application).
        """
        return [
            await self._apply_batch_op(op, perm_filters, creator_id=creator_id) for op in operations
        ]

    async def _apply_batch_op(
        self,
        op: SecretBatchOp,
        perm_filters: dict[Action, SearchFilter[Secret] | None],
        *,
        creator_id: uuid.UUID,
    ) -> Secret | None:
        if isinstance(op, SecretBatchCreate):
            filt = self._require_action(perm_filters, Action.CREATE, "create")
            return await self.create_secret(op.data, creator_id=creator_id, perm_filter=filt)
        if isinstance(op, SecretBatchUpdate):
            filt = self._require_action(perm_filters, Action.UPDATE, "update")
            return await self.update_secret(op.id, op.data, perm_filter=filt)
        if isinstance(op, SecretBatchDelete):
            filt = self._require_action(perm_filters, Action.DELETE, "delete")
            await self.delete_secret(op.id, perm_filter=filt)
            return None
        raise TypeError(f"Unknown secret batch op: {type(op).__name__}")

    @staticmethod
    def _require_action(
        perm_filters: dict[Action, SearchFilter[Any] | None],
        action: Action,
        label: str,
    ) -> SearchFilter[Any]:
        filt = perm_filters.get(action)
        if filt is None:
            raise BatchPermissionDeniedError(label)
        return filt

    # ------------------------------------------------------------------ #
    # Value reveal (the ``/secret-values`` projection, AGENTS.md §12). A
    # secret is revealed only when *both* the read-access filter and the
    # value-reveal filter admit it.
    # ------------------------------------------------------------------ #
    @staticmethod
    def _reveal_filter(
        read_filter: SearchFilter[Secret], value_filter: SearchFilter[Secret]
    ) -> SearchFilter[Secret]:
        return AndSearchFilter(filters=[read_filter, value_filter])

    async def get_secret_value(
        self,
        secret_id: uuid.UUID,
        *,
        read_filter: SearchFilter[Secret],
        value_filter: SearchFilter[Secret],
    ) -> SecretValueRead:
        """Reveal one secret by id. 404 (via :class:`SecretValueNotFoundError`)
        if missing, not both-admitted, or without a revealable value."""
        try:
            secret = await self.get_secret(
                secret_id, perm_filter=self._reveal_filter(read_filter, value_filter)
            )
        except SecretNotFoundError as exc:
            raise SecretValueNotFoundError(str(secret_id)) from exc
        plaintext = await self._require_plaintext(secret)
        return self._to_value_read(secret, plaintext)

    async def get_secret_values(
        self,
        secret_ids: list[uuid.UUID],
        *,
        read_filter: SearchFilter[Secret],
        value_filter: SearchFilter[Secret],
    ) -> list[SecretValueRead | None]:
        """Reveal secrets by ids, scoped by the combined filter.

        Returns a list positionally aligned with *secret_ids*; ``None`` where
        missing, out of scope, or without a revealable value. An empty input
        yields an empty list.
        """
        if not secret_ids:
            return []
        secrets = await self.get_secrets(
            secret_ids, perm_filter=self._reveal_filter(read_filter, value_filter)
        )
        results: list[SecretValueRead | None] = []
        for secret in secrets:
            if secret is None:
                results.append(None)
                continue
            plaintext = await self._reveal_plaintext(secret)
            results.append(None if plaintext is None else self._to_value_read(secret, plaintext))
        return results

    async def search_secret_values(
        self,
        *,
        read_filter: SearchFilter[Secret],
        value_filter: SearchFilter[Secret],
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: SecretSearchFilter | None = None,
    ) -> tuple[list[SecretValueRead], uuid.UUID | None]:
        """Reveal secrets ordered by id, keyed-pagination via cursor.

        Secrets without a revealable value are skipped (a page may therefore
        carry fewer than ``limit`` items).
        """
        page, next_cursor = await self.search_secrets(
            perm_filter=self._reveal_filter(read_filter, value_filter),
            cursor=cursor,
            limit=limit,
            search_filter=search_filter,
        )
        items: list[SecretValueRead] = []
        for secret in page:
            plaintext = await self._reveal_plaintext(secret)
            if plaintext is not None:
                items.append(self._to_value_read(secret, plaintext))
        return items, next_cursor

    async def _require_plaintext(self, secret: Secret) -> str:
        plaintext = await self._reveal_plaintext(secret)
        if plaintext is None:
            raise SecretValueNotFoundError(str(secret.id))
        return plaintext

    async def _reveal_plaintext(self, secret: Secret) -> str | None:
        """Plaintext for *secret*, or ``None`` when it has no revealable value.

        The decrypt step itself is the provider hook.
        """
        return await self._decrypt_value(secret)

    @staticmethod
    def _to_value_read(secret: Secret, plaintext: str) -> SecretValueRead:
        return SecretValueRead(
            id=secret.id,
            code=secret.code,
            value=plaintext,
        )

    # ------------------------------------------------------------------ #
    # Provider hooks (overridden by implementations).
    # ------------------------------------------------------------------ #
    @abstractmethod
    async def _list_secrets(self) -> list[Secret]:
        """Return all secrets known to the provider (unfiltered)."""

    @abstractmethod
    async def _get_secret(self, secret_id: uuid.UUID) -> Secret:
        """Return a secret, raising ``SecretNotFoundError`` if absent."""

    @abstractmethod
    async def _create_secret(self, secret: Secret, payload: SecretCreate) -> Secret:
        """Persist a freshly-built secret (and its value payload, when static)."""

    @abstractmethod
    async def _update_secret(self, secret: Secret, payload: SecretUpdate) -> Secret:
        """Apply a partial update to an existing secret and return the result."""

    @abstractmethod
    async def _delete_secret(self, secret_id: uuid.UUID) -> None:
        """Remove a secret (and its value) from the provider."""

    @abstractmethod
    async def _decrypt_value(self, secret: Secret) -> str | None:
        """Return the plaintext value for a static secret, or ``None`` if absent."""


def resolve_secrets_service_class(fqcn: str) -> type[SecretsService]:
    """Resolve a fully qualified class name to a ``SecretsService`` subclass."""
    module_name, _, class_name = fqcn.rpartition(".")
    if not module_name or not class_name:
        raise ValueError(f"Invalid secrets_service class name: {fqcn!r}")
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise ValueError(f"Cannot import secrets_service module {module_name!r}") from exc
    candidate = getattr(module, class_name, None)
    if not (isinstance(candidate, type) and issubclass(candidate, SecretsService)):
        raise TypeError(f"{fqcn!r} is not a SecretsService subclass.")
    return candidate
