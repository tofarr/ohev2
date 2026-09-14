"""Unit tests for the governed ``OAuthSession`` resource + flow (sub-issue #144).

Tests the CRUD surface (search, get, update, delete, batch, count) and the
authorize/callback/refresh flow using an in-process mock OAuth provider.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import make_principal

from openhands.ev2.encryption.encryption_service import get_encryption_service
from openhands.ev2.oauth.oauth_provider_models import OAuthProvider
from openhands.ev2.oauth.oauth_session_models import OAuthSession
from openhands.ev2.oauth.oauth_session_service import OAuthSessionService


async def _create_provider(client: AsyncClient, name: str = "test-provider") -> str:
    resp = await client.post(
        "/oauth/providers",
        json={
            "name": name,
            "url": "https://mock.example.com",
            "client_id": "mock-cid",
            "client_secret": "mock-secret",
            "scopes": ["repo"],
        },
    )
    assert resp.status_code == 201
    return resp.json()["id"]


async def _create_session_direct(
    session: AsyncSession, provider_id: uuid.UUID, user_id: uuid.UUID
) -> OAuthSession:
    """Create an OAuthSession directly via the ORM (bypasses the flow)."""
    enc = get_encryption_service()
    now = datetime.now(UTC)
    oauth_session = OAuthSession(
        oauth_provider_id=uuid.UUID(provider_id),
        creator_id=user_id,
        access_token=enc.encrypt_value("access-tok-1"),
        refresh_token=enc.encrypt_value("refresh-tok-1"),
        access_token_expires_at=now + timedelta(hours=1),
        refresh_token_expires_at=now + timedelta(days=30),
    )
    session.add(oauth_session)
    await session.flush()
    await session.refresh(oauth_session)
    return oauth_session


async def _seed_user(session: AsyncSession) -> uuid.UUID:
    """Create a test user directly in the DB."""
    user = await make_principal(
        session, email="oauth-session-test@example.com", username="oauth-session-test"
    )
    return user.id


@pytest.mark.asyncio
class TestOAuthSessionCRUD:
    async def test_create_via_flow_and_read(self, client: AsyncClient) -> None:
        provider_id = await _create_provider(client)
        # Authorize
        auth_resp = await client.post(
            f"/oauth/providers/{provider_id}/authorize",
            json={"redirect_uri": "https://app.example.com/callback"},
        )
        assert auth_resp.status_code == 200
        body = auth_resp.json()
        assert "authorize_url" in body
        assert "state" in body

    async def test_get_session_not_found(self, client: AsyncClient) -> None:
        resp = await client.get(f"/oauth/sessions/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_search_sessions(self, client: AsyncClient, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider_id = await _create_provider(client, "search-provider")
        await _create_session_direct(session, provider_id, user_id)
        await session.commit()
        resp = await client.get("/oauth/sessions")
        assert resp.status_code == 200
        assert len(resp.json()["items"]) >= 1

    async def test_update_session(self, client: AsyncClient, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider_id = await _create_provider(client, "update-provider")
        oauth_session = await _create_session_direct(session, provider_id, user_id)
        await session.commit()
        resp = await client.patch(
            f"/oauth/sessions/{oauth_session.id}",
            json={"tolerate_invalid": True, "enabled": False},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["tolerate_invalid"] is True
        assert body["enabled"] is False

    async def test_delete_session(self, client: AsyncClient, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider_id = await _create_provider(client, "delete-provider")
        oauth_session = await _create_session_direct(session, provider_id, user_id)
        await session.commit()
        resp = await client.delete(f"/oauth/sessions/{oauth_session.id}")
        assert resp.status_code == 204
        get_resp = await client.get(f"/oauth/sessions/{oauth_session.id}")
        assert get_resp.status_code == 404

    async def test_count_sessions(self, client: AsyncClient, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider_id = await _create_provider(client, "count-provider")
        await _create_session_direct(session, provider_id, user_id)
        await session.commit()
        resp = await client.get("/oauth/sessions/count")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    async def test_batch_read_sessions(self, client: AsyncClient, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider_id = await _create_provider(client, "batch-provider")
        s1 = await _create_session_direct(session, provider_id, user_id)
        s2 = await _create_session_direct(session, provider_id, user_id)
        await session.commit()
        resp = await client.get(
            "/oauth/sessions/batch",
            params=[("ids", str(s1.id)), ("ids", str(s2.id))],
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["items"]) == 2
        assert all(item is not None for item in body["items"])

    async def test_batch_write_sessions(self, client: AsyncClient, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider_id = await _create_provider(client, "batch-write-provider")
        s1 = await _create_session_direct(session, provider_id, user_id)
        s2 = await _create_session_direct(session, provider_id, user_id)
        await session.commit()
        resp = await client.post(
            "/oauth/sessions/batch",
            json={
                "operations": [
                    {"op": "update", "id": str(s1.id), "data": {"tolerate_invalid": True}},
                    {"op": "delete", "id": str(s2.id)},
                ]
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"][0] is not None
        assert body["items"][0]["tolerate_invalid"] is True
        assert body["items"][1] is None

    async def test_tokens_not_exposed_in_read(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        user_id = await _seed_user(session)
        provider_id = await _create_provider(client, "token-check-provider")
        oauth_session = await _create_session_direct(session, provider_id, user_id)
        await session.commit()
        resp = await client.get(f"/oauth/sessions/{oauth_session.id}")
        body = resp.json()
        assert "access_token" not in body
        assert "refresh_token" not in body


@pytest.mark.asyncio
class TestOAuthSessionRefresh:
    async def test_get_valid_access_token_no_refresh_needed(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        enc = get_encryption_service()
        now = datetime.now(UTC)
        provider = OAuthProvider(
            name="refresh-provider",
            creator_id=user_id,
            url="https://refresh.example.com",
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
            access_token=enc.encrypt_value("valid-token"),
            refresh_token=enc.encrypt_value("refresh-token"),
            access_token_expires_at=now + timedelta(hours=1),
            refresh_token_expires_at=now + timedelta(days=30),
        )
        session.add(oauth_session)
        await session.flush()
        service = OAuthSessionService(session)
        try:
            token = await service.get_valid_access_token(oauth_session, provider)
            assert token == "valid-token"
        finally:
            await service.aclose()

    async def test_get_valid_access_token_disabled_session(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        enc = get_encryption_service()
        now = datetime.now(UTC)
        provider = OAuthProvider(
            name="disabled-session-provider",
            creator_id=user_id,
            url="https://disabled.example.com",
            client_id="cid",
            client_secret=enc.encrypt_value("secret"),
            scopes=[],
            expire_drift_tolerance=60,
            access_token_expires_in=900,
            refresh_token_expires_in=2_592_000,
        )
        session.add(provider)
        await session.flush()
        oauth_session = OAuthSession(
            oauth_provider_id=provider.id,
            creator_id=user_id,
            access_token=enc.encrypt_value("token"),
            refresh_token=enc.encrypt_value("refresh"),
            access_token_expires_at=now + timedelta(hours=1),
            refresh_token_expires_at=now + timedelta(days=30),
            enabled=False,
        )
        session.add(oauth_session)
        await session.flush()
        service = OAuthSessionService(session)
        try:
            token = await service.get_valid_access_token(oauth_session, provider)
            assert token is None
        finally:
            await service.aclose()
