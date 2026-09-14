"""Unit tests for the ``kind="oauth"`` SecretProvider (sub-issue #145).

Tests that the provider resolves an OAuthSession's access token via the
composite id ``{oauth_provider_id}/{oauth_session_id}`` and returns it as a
SecretValue.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import make_principal

from openhands.ev2.encryption.encryption_service import get_encryption_service
from openhands.ev2.oauth.oauth_provider_models import OAuthProvider
from openhands.ev2.oauth.oauth_session_models import OAuthSession
from openhands.ev2.secret.oauth_secret_provider import OAuthSecretsProvider


async def _seed_user(session: AsyncSession) -> uuid.UUID:
    """Create a test user directly in the DB."""
    user = await make_principal(
        session, email="oauth-secrets-test@example.com", username="oauth-secrets-test"
    )
    return user.id


async def _seed_provider_and_session(
    session: AsyncSession, user_id: uuid.UUID
) -> tuple[OAuthProvider, OAuthSession]:
    enc = get_encryption_service()
    now = datetime.now(UTC)
    provider = OAuthProvider(
        name="github-secrets-test",
        creator_id=user_id,
        url="https://github.com/login/oauth",
        client_id="cid",
        client_secret=enc.encrypt_value("secret"),
        scopes=["repo"],
        expire_drift_tolerance=60,
        access_token_expires_in=900,
        refresh_token_expires_in=2_592_000,
    )
    session.add(provider)
    await session.flush()
    oauth_session = OAuthSession(
        oauth_provider_id=provider.id,
        creator_id=user_id,
        access_token=enc.encrypt_value("ghp_12345"),
        refresh_token=enc.encrypt_value("refresh_token_value"),
        access_token_expires_at=now + timedelta(hours=1),
        refresh_token_expires_at=now + timedelta(days=30),
    )
    session.add(oauth_session)
    await session.flush()
    return provider, oauth_session


@pytest.mark.asyncio
class TestOAuthSecretsProvider:
    async def test_get_returns_access_token(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider, oauth_session = await _seed_provider_and_session(session, user_id)
        secrets_provider = OAuthSecretsProvider(get_encryption_service())
        internal_id = f"{provider.id}/{oauth_session.id}"
        secret_value = await secrets_provider.get(session, provider.id, internal_id)
        assert secret_value is not None
        assert secret_value.value == "ghp_12345"
        assert secret_value.internal_id == internal_id

    async def test_get_invalid_internal_id_returns_none(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider, _ = await _seed_provider_and_session(session, user_id)
        secrets_provider = OAuthSecretsProvider(get_encryption_service())
        result = await secrets_provider.get(session, provider.id, "not-a-valid-id")
        assert result is None

    async def test_get_nonexistent_session_returns_none(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider, _ = await _seed_provider_and_session(session, user_id)
        secrets_provider = OAuthSecretsProvider(get_encryption_service())
        internal_id = f"{provider.id}/{uuid.uuid4()}"
        result = await secrets_provider.get(session, provider.id, internal_id)
        assert result is None

    async def test_get_disabled_provider_returns_none(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider, oauth_session = await _seed_provider_and_session(session, user_id)
        provider.enabled = False
        await session.flush()
        secrets_provider = OAuthSecretsProvider(get_encryption_service())
        internal_id = f"{provider.id}/{oauth_session.id}"
        result = await secrets_provider.get(session, provider.id, internal_id)
        assert result is None

    async def test_get_disabled_session_returns_none(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider, oauth_session = await _seed_provider_and_session(session, user_id)
        oauth_session.enabled = False
        await session.flush()
        secrets_provider = OAuthSecretsProvider(get_encryption_service())
        internal_id = f"{provider.id}/{oauth_session.id}"
        result = await secrets_provider.get(session, provider.id, internal_id)
        assert result is None

    async def test_batch_get(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider, oauth_session = await _seed_provider_and_session(session, user_id)
        secrets_provider = OAuthSecretsProvider(get_encryption_service())
        internal_id = f"{provider.id}/{oauth_session.id}"
        results = await secrets_provider.batch_get(session, [provider.id], [internal_id])
        assert len(results) == 1
        assert results[0] is not None
        assert results[0].value == "ghp_12345"

    async def test_batch_get_empty(self, session: AsyncSession) -> None:
        secrets_provider = OAuthSecretsProvider(get_encryption_service())
        results = await secrets_provider.batch_get(session, [], [])
        assert results == []

    async def test_search_returns_tokens(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider, _oauth_session = await _seed_provider_and_session(session, user_id)
        secrets_provider = OAuthSecretsProvider(get_encryption_service())
        values, _next_cursor = await secrets_provider.search(session, provider.id)
        assert len(values) >= 1
        assert any(v.value == "ghp_12345" for v in values)

    async def test_derive_name(self, session: AsyncSession, user_id: uuid.UUID) -> None:
        user_id = await _seed_user(session)
        provider, oauth_session = await _seed_provider_and_session(session, user_id)
        secrets_provider = OAuthSecretsProvider(get_encryption_service())
        internal_id = f"{provider.id}/{oauth_session.id}"
        result = await secrets_provider.get(session, provider.id, internal_id)
        assert result is not None
        assert "GITHUB_SECRETS_TEST_TOKEN" in result.name or "TOKEN" in result.name

    async def test_batch_get_mismatched_lengths_raises(self, session: AsyncSession) -> None:
        secrets_provider = OAuthSecretsProvider(get_encryption_service())
        with pytest.raises(ValueError, match="equal length"):
            await secrets_provider.batch_get(session, [uuid.uuid4()], ["id1", "id2"])

    async def test_get_nonexistent_provider_returns_none(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        _provider, oauth_session = await _seed_provider_and_session(session, user_id)
        secrets_provider = OAuthSecretsProvider(get_encryption_service())
        internal_id = f"{uuid.uuid4()}/{oauth_session.id}"
        result = await secrets_provider.get(session, uuid.uuid4(), internal_id)
        assert result is None

    async def test_get_malformed_uuid_in_internal_id_returns_none(
        self, session: AsyncSession
    ) -> None:
        user_id = await _seed_user(session)
        provider, _oauth_session = await _seed_provider_and_session(session, user_id)
        secrets_provider = OAuthSecretsProvider(get_encryption_service())
        result = await secrets_provider.get(session, provider.id, "not-a-uuid/also-not-a-uuid")
        assert result is None

    async def test_search_with_disabled_provider_skips(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider, _oauth_session = await _seed_provider_and_session(session, user_id)
        provider.enabled = False
        await session.flush()
        secrets_provider = OAuthSecretsProvider(get_encryption_service())
        values, _ = await secrets_provider.search(session, provider.id)
        assert all(v is not None for v in values)
        assert len(values) == 0
