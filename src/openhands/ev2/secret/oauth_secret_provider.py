"""The ``kind="oauth"`` :class:`SecretProvider` implementation (sub-issue #145).

Resolves an :class:`OAuthSession` by composite id and returns the lazily-
refreshed access token as the :class:`SecretValue`. The composite id is
``{oauth_provider_id}/{oauth_session_id}`` — the provider id in the
``/secret-values`` path is the governed ``SecretProvider`` row (kind
``oauth``), and the ``internal_id`` encodes both the ``OAuthProvider`` and the
``OAuthSession``.

The caller must have ``USE`` on the parent ``SecretProvider`` (the single gate
from §12.1, checked by the ``/secret-values`` projection). The per-session
USE check is on the ``OAuthSession`` governed entity; here we rely on the
caller having USE on the ``SecretProvider`` (the single gate).
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.encryption.encryption_service import EncryptionService
from openhands.ev2.oauth.oauth_provider_models import OAuthProvider
from openhands.ev2.oauth.oauth_session_models import OAuthSession
from openhands.ev2.oauth.oauth_session_service import (
    OAuthProviderError,
    OAuthSessionService,
    OAuthSessionUnrecoverableError,
    RefreshLockTimeoutError,
)
from openhands.ev2.secret.secret_provider import SecretProvider
from openhands.ev2.secret.secret_value import SecretValue
from openhands.ev2.util.search_filter import ALL


class OAuthSecretsProvider(SecretProvider):
    """Retrieval-only provider exposing per-user OAuth access tokens as secrets.

    ``internal_id`` is ``{oauth_provider_id}/{oauth_session_id}``. A session
    that is unrecoverable (refresh token expired) with ``tolerate_invalid``
    yields ``None`` (omitted); with ``tolerate_invalid=false`` it also yields
    ``None`` here (the error is swallowed at the provider level so the
    ``/secret-values`` projection returns ``None`` for that entry, matching the
    batch semantics).
    """

    def __init__(self, enc: EncryptionService) -> None:
        self._enc = enc

    async def get(
        self,
        session: AsyncSession,
        provider_id: uuid.UUID,
        internal_id: str,
    ) -> SecretValue | None:
        parsed = _split_internal_id(internal_id)
        if parsed is None:
            return None
        oauth_provider_id, oauth_session_id = parsed
        oauth_session = await self._resolve_session(session, oauth_session_id)
        if oauth_session is None:
            return None
        provider = await session.get(OAuthProvider, oauth_provider_id)
        if provider is None or not provider.enabled:
            return None
        access_token = await self._resolve_token(session, oauth_session, provider)
        if access_token is None:
            return None
        return SecretValue.make(
            provider_id=provider_id,
            internal_id=internal_id,
            name=_derive_name(provider, oauth_session),
            value=access_token,
            valid_at=oauth_session.created_at,
            expires_at=oauth_session.access_token_expires_at,
        )

    async def _resolve_token(
        self,
        session: AsyncSession,
        oauth_session: OAuthSession,
        provider: OAuthProvider,
    ) -> str | None:
        """Get a valid access token, swallowing unrecoverable errors."""
        service = OAuthSessionService(session, encryption_service=self._enc)
        try:
            return await service.get_valid_access_token(oauth_session, provider)
        except (OAuthSessionUnrecoverableError, OAuthProviderError, RefreshLockTimeoutError):
            return None
        finally:
            await service.aclose()

    async def batch_get(
        self,
        session: AsyncSession,
        provider_ids: list[uuid.UUID],
        internal_ids: list[str],
    ) -> list[SecretValue | None]:
        if not internal_ids:
            return []
        if len(provider_ids) != len(internal_ids):
            raise ValueError("provider_ids and internal_ids must have equal length")
        results: list[SecretValue | None] = []
        for pid, iid in zip(provider_ids, internal_ids, strict=True):
            results.append(await self.get(session, pid, iid))
        return results

    async def search(
        self,
        session: AsyncSession,
        provider_id: uuid.UUID,
        *,
        limit: int = 50,
        cursor: str | None = None,
    ) -> tuple[list[SecretValue], str | None]:
        service = OAuthSessionService(session, ALL, encryption_service=self._enc)
        try:
            cursor_uuid = uuid.UUID(cursor) if cursor is not None else None
            oauth_sessions, next_cursor = await service.search(cursor=cursor_uuid, limit=limit)
        finally:
            await service.aclose()
        values: list[SecretValue] = []
        for oauth_session in oauth_sessions:
            value = await self._try_resolve_search_value(session, provider_id, oauth_session)
            if value is not None:
                values.append(value)
        next_cursor_str = (
            str(next_cursor) if next_cursor is not None and len(values) == limit else None
        )
        return values, next_cursor_str

    async def _try_resolve_search_value(
        self,
        session: AsyncSession,
        provider_id: uuid.UUID,
        oauth_session: OAuthSession,
    ) -> SecretValue | None:
        """Resolve a single session to a SecretValue for search, skipping failures."""
        provider = await session.get(OAuthProvider, oauth_session.oauth_provider_id)
        if provider is None or not provider.enabled:
            return None
        token = await self._resolve_token(session, oauth_session, provider)
        if token is None:
            return None
        internal_id = f"{oauth_session.oauth_provider_id}/{oauth_session.id}"
        return SecretValue.make(
            provider_id=provider_id,
            internal_id=internal_id,
            name=_derive_name(provider, oauth_session),
            value=token,
            valid_at=oauth_session.created_at,
            expires_at=oauth_session.access_token_expires_at,
        )

    async def _resolve_session(
        self,
        session: AsyncSession,
        session_id: uuid.UUID,
    ) -> OAuthSession | None:
        result = await session.execute(select(OAuthSession).where(OAuthSession.id == session_id))
        return result.scalar_one_or_none()


def _split_internal_id(internal_id: str) -> tuple[uuid.UUID, uuid.UUID] | None:
    """Parse ``{oauth_provider_id}/{oauth_session_id}``."""
    provider_str, sep, session_str = internal_id.partition("/")
    if not sep or not session_str:
        return None
    try:
        return uuid.UUID(provider_str), uuid.UUID(session_str)
    except ValueError:
        return None


def _derive_name(provider: OAuthProvider, oauth_session: OAuthSession) -> str:
    """Derive an env-var-compatible name for the secret."""
    base = provider.name.upper().replace("-", "_").replace(" ", "_")
    base = "".join(c for c in base if c.isalnum() or c == "_")
    if not base or not base[0].isalpha():
        base = f"OAUTH_{base}"
    return f"{base}_TOKEN"
