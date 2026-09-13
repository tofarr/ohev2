"""Retrieval-only secret provider ABC.

A :class:`SecretProvider` exposes read paths only — there are no create/update/
delete hooks on the provider itself. External integrations (AWS Secrets
Manager, 1Password, future OAuth access keys) implement this ABC and *only*
this ABC: customers who run an external vault administer it in their own
console/CLI, and the value this API adds is retrieval (with permission gating),
not a second admin surface.

Providers are governed CRUD rows in ``secret_providers`` (``kind`` + ``data``
resolve to a concrete implementation at request time, per the provider lookup
in :mod:`secret_provider_registry`). Implementations are constructed lazily on
first use and reused thereafter (a per-row connection cache); because they are
read-only there is no explicit cleanup on shutdown.

Every method receives the caller's :class:`AsyncSession` so implementations
participate in the caller's transaction (per-test savepoints, batch commits).
Providers that do not need the database may ignore it.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.secret.secret_value import SecretValue


class SecretProvider(ABC):
    """Abstract base for a retrieval-only secret source."""

    @abstractmethod
    async def get(
        self,
        session: AsyncSession,
        provider_id: uuid.UUID,
        internal_id: str,
    ) -> SecretValue | None:
        """Return the secret with *internal_id* for *provider_id*, or ``None``.

        Secret ids are unique within a provider.
        """

    @abstractmethod
    async def batch_get(
        self,
        session: AsyncSession,
        provider_ids: list[uuid.UUID],
        internal_ids: list[str],
    ) -> list[SecretValue | None]:
        """Return secrets positionally aligned with ``(provider_ids, internal_ids)``.

        The i-th result is the secret for ``(provider_ids[i], internal_ids[i])``
        or ``None`` when missing. An empty input yields an empty list.
        """

    @abstractmethod
    async def search(
        self,
        session: AsyncSession,
        provider_id: uuid.UUID,
        *,
        limit: int = 50,
        cursor: str | None = None,
    ) -> tuple[list[SecretValue], str | None]:
        """Return a page of secrets for *provider_id*, ordered by internal id.

        *cursor* is an opaque string cursor; the returned second element is the
        next cursor, or ``None`` when no more results remain.
        """


class SecretProviderNotFoundError(Exception):
    """Raised when a requested secret id is missing or out of scope."""


class SecretProviderSearch:
    """Convenience grouping of a provider id plus its resolved implementation."""

    def __init__(self, provider_id: uuid.UUID, provider: SecretProvider) -> None:
        self.provider_id = provider_id
        self.provider = provider
