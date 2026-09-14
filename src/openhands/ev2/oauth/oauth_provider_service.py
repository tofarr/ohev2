"""Service layer for the governed :class:`OAuthProvider` resource.

Follows the ``routers → services → repositories → models`` layering (§4).
The sensitive ``client_secret`` is encrypted at rest — JWE ciphertext on
create/update, decrypted-then-masked on read (§13).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.encryption.encryption_service import EncryptionService, get_encryption_service
from openhands.ev2.oauth.oauth_provider_models import OAuthProvider
from openhands.ev2.oauth.oauth_provider_schemas import (
    OAuthProviderBatchCreate,
    OAuthProviderBatchDelete,
    OAuthProviderBatchOp,
    OAuthProviderBatchUpdate,
    OAuthProviderCreate,
    OAuthProviderRead,
    OAuthProviderSearchFilter,
    OAuthProviderUpdate,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter

_MASKED_SECRET = "**********"


class OAuthProviderNotFoundError(Exception):
    """Raised when a provider does not exist or is out of scope."""


class OAuthProviderNameConflictError(Exception):
    """Raised when a create/update collides with an existing name."""


class OAuthProviderPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted."""


class OAuthProviderService:
    """CRUD over :class:`OAuthProvider` rows, scoped by ``perm_filter``."""

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[OAuthProvider] = ALL,
        *,
        encryption_service: EncryptionService | None = None,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter
        self._enc = encryption_service or get_encryption_service()

    def to_read(self, provider: OAuthProvider) -> OAuthProviderRead:
        """Build the API read model; ``client_secret`` is masked."""
        return OAuthProviderRead(
            id=provider.id,
            name=provider.name,
            creator_id=provider.creator_id,
            url=provider.url,
            client_id=provider.client_id,
            client_secret=_MASKED_SECRET,
            scopes=list(provider.scopes),
            user_id_field=provider.user_id_field,
            email_field=provider.email_field,
            role_field=provider.role_field,
            expire_drift_tolerance=provider.expire_drift_tolerance,
            authorize_path=provider.authorize_path,
            token_path=provider.token_path,
            refresh_path=provider.refresh_path,
            revocation_path=provider.revocation_path,
            access_token_expires_in=provider.access_token_expires_in,
            refresh_token_expires_in=provider.refresh_token_expires_in,
            enabled=provider.enabled,
            created_at=provider.created_at,
            updated_at=provider.updated_at,
        )

    def _encrypt_secret(self, value: str) -> str:
        return self._enc.encrypt_value(value)

    async def create(
        self,
        payload: OAuthProviderCreate,
        *,
        creator_id: uuid.UUID,
    ) -> OAuthProvider:
        """Create an OAuth provider, encrypting ``client_secret`` at rest."""
        provider = OAuthProvider(
            creator_id=creator_id,
            name=payload.name,
            url=payload.url,
            client_id=payload.client_id,
            client_secret=self._encrypt_secret(payload.client_secret.get_secret_value()),
            scopes=list(payload.scopes),
            user_id_field=payload.user_id_field,
            email_field=payload.email_field,
            role_field=payload.role_field,
            expire_drift_tolerance=payload.expire_drift_tolerance,
            authorize_path=payload.authorize_path,
            token_path=payload.token_path,
            refresh_path=payload.refresh_path,
            revocation_path=payload.revocation_path,
            access_token_expires_in=payload.access_token_expires_in,
            refresh_token_expires_in=payload.refresh_token_expires_in,
            enabled=payload.enabled,
        )
        if not self._perm_filter.matches(provider):
            raise OAuthProviderPermissionScopeError(payload.name)
        self._session.add(provider)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            raise OAuthProviderNameConflictError(payload.name) from exc
        await self._session.refresh(provider)
        return provider

    async def get(self, provider_id: uuid.UUID) -> OAuthProvider:
        """Retrieve a provider by id, scoped by ``perm_filter``."""
        stmt = self._perm_filter.filter_sql(
            select(OAuthProvider).where(OAuthProvider.id == provider_id)
        )
        result = await self._session.execute(stmt)
        provider = result.scalar_one_or_none()
        if provider is None:
            raise OAuthProviderNotFoundError(str(provider_id))
        return provider

    async def get_many(self, provider_ids: list[uuid.UUID]) -> list[OAuthProvider | None]:
        """Retrieve providers by ids, positionally aligned with ``None`` for misses."""
        if not provider_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(OAuthProvider).where(OAuthProvider.id.in_(provider_ids))
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, OAuthProvider] = {row.id: row for row in result.scalars().all()}
        return [by_id.get(pid) for pid in provider_ids]

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: OAuthProviderSearchFilter | None = None,
    ) -> tuple[list[OAuthProvider], uuid.UUID | None]:
        """Search providers ordered by id, keyed-pagination via cursor."""
        stmt = self._perm_filter.filter_sql(select(OAuthProvider).order_by(OAuthProvider.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(OAuthProvider.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        next_cursor = rows[-1].id if len(rows) == limit else None
        return rows, next_cursor

    async def count(self, search_filter: OAuthProviderSearchFilter | None = None) -> int:
        """Count providers visible to the service's permission filter."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(OAuthProvider))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def update(
        self,
        provider_id: uuid.UUID,
        payload: OAuthProviderUpdate,
    ) -> OAuthProvider:
        """Partially update an OAuth provider."""
        provider = await self.get(provider_id)
        updates = payload.model_dump(exclude_unset=True)
        for field, value in updates.items():
            if value is None:
                continue
            if field == "client_secret":
                provider.client_secret = self._encrypt_secret(value.get_secret_value())
            elif field == "scopes":
                provider.scopes = list(value)
            else:
                setattr(provider, field, value)
        await self._flush_update(provider, payload.name, str(provider_id))
        return provider

    async def _flush_update(
        self, provider: OAuthProvider, name: str | None, provider_id: str
    ) -> None:
        """Flush an update, mapping integrity errors to conflict."""
        try:
            await self._session.flush()
        except IntegrityError as exc:
            raise OAuthProviderNameConflictError(name or provider_id) from exc
        await self._session.refresh(provider)

    async def delete(self, provider_id: uuid.UUID) -> None:
        """Delete an OAuth provider.

        Fails with a scope error if the provider has sessions
        (``ondelete=RESTRICT`` on ``oauth_sessions.oauth_provider_id``).
        """
        provider = await self.get(provider_id)
        try:
            await self._session.delete(provider)
            await self._session.flush()
        except IntegrityError as exc:
            raise OAuthProviderPermissionScopeError(str(provider_id)) from exc

    async def apply_batch(
        self,
        operations: list[OAuthProviderBatchOp],
        perm_filters: dict[Action, SearchFilter[OAuthProvider] | None],
        *,
        creator_id: uuid.UUID,
    ) -> list[OAuthProvider | None]:
        """Apply create/update/delete operations in one caller-owned transaction."""
        results: list[OAuthProvider | None] = []
        for op in operations:
            if isinstance(op, OAuthProviderBatchCreate):
                results.append(await self._batch_create(op, perm_filters, creator_id=creator_id))
            elif isinstance(op, OAuthProviderBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, OAuthProviderBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: OAuthProviderBatchCreate,
        perm_filters: dict[Action, SearchFilter[OAuthProvider] | None],
        *,
        creator_id: uuid.UUID,
    ) -> OAuthProvider:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        return await OAuthProviderService(self._session, filt, encryption_service=self._enc).create(
            op.data, creator_id=creator_id
        )

    async def _batch_update(
        self,
        op: OAuthProviderBatchUpdate,
        perm_filters: dict[Action, SearchFilter[OAuthProvider] | None],
    ) -> OAuthProvider:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await OAuthProviderService(self._session, filt, encryption_service=self._enc).update(
            op.id, op.data
        )

    async def _batch_delete(
        self,
        op: OAuthProviderBatchDelete,
        perm_filters: dict[Action, SearchFilter[OAuthProvider] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await OAuthProviderService(self._session, filt, encryption_service=self._enc).delete(op.id)
